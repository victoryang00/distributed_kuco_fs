/*
  Bento: Safe Rust file systems in the kernel
  Copyright (C) 2020 Samantha Miller, Kaiyuan Zhang, Danyang Zhuo, Tom
      Anderson, Ang Chen, University of Washington
  Copyright (C) 2001-2008  Miklos Szeredi <miklos@szeredi.hu>

  This program can be distributed under the terms of the GNU GPL.
  See the file COPYING.
*/

#include "bento_i.h"

#include <linux/init.h>
#include <linux/module.h>
#include <linux/poll.h>
#include <linux/sched/signal.h>
#include <linux/uio.h>
#include <linux/miscdevice.h>
#include <linux/pagemap.h>
#include <linux/file.h>
#include <linux/slab.h>
#include <linux/pipe_fs_i.h>
#include <linux/swap.h>
#include <linux/splice.h>
#include <linux/sched.h>

static struct kmem_cache *bento_req_cachep;

static void bento_request_init(struct bento_req *req, struct page **pages,
			      struct bento_page_desc *page_descs,
			      unsigned npages)
{
	memset(req, 0, sizeof(*req));
	memset(pages, 0, sizeof(*pages) * npages);
	memset(page_descs, 0, sizeof(*page_descs) * npages);
	INIT_LIST_HEAD(&req->list);
	INIT_LIST_HEAD(&req->intr_entry);
	init_waitqueue_head(&req->waitq);
	refcount_set(&req->count, 1);
	req->pages = pages;
	req->page_descs = page_descs;
	req->max_pages = npages;
	__set_bit(FR_PENDING, &req->flags);
}

static struct bento_req *__bento_request_alloc(unsigned npages, gfp_t flags)
{
	struct bento_req *req = kmem_cache_alloc(bento_req_cachep, flags);
	if (req) {
		struct page **pages;
		struct bento_page_desc *page_descs;

		if (npages <= BENTO_REQ_INLINE_PAGES) {
			pages = req->inline_pages;
			page_descs = req->inline_page_descs;
		} else {
			pages = kmalloc(sizeof(struct page *) * npages, flags);
			page_descs = kmalloc(sizeof(struct bento_page_desc) *
					     npages, flags);
		}

		if (!pages || !page_descs) {
			kfree(pages);
			kfree(page_descs);
			kmem_cache_free(bento_req_cachep, req);
			return NULL;
		}

		bento_request_init(req, pages, page_descs, npages);
	}
	return req;
}

struct bento_req *bento_request_alloc(unsigned npages)
{
	return __bento_request_alloc(npages, GFP_KERNEL);
}

struct bento_req *bento_request_alloc_nofs(unsigned npages)
{
	return __bento_request_alloc(npages, GFP_NOFS);
}

void bento_request_free(struct bento_req *req)
{
	if (req->pages != req->inline_pages) {
		kfree(req->pages);
		kfree(req->page_descs);
	}
	kmem_cache_free(bento_req_cachep, req);
}

void __bento_get_request(struct bento_req *req)
{
	refcount_inc(&req->count);
}

static void bento_req_init_context(struct bento_conn *fc, struct bento_req *req)
{
	req->in.h.uid = from_kuid_munged(&init_user_ns, current_fsuid());
	req->in.h.gid = from_kgid_munged(&init_user_ns, current_fsgid());
	req->in.h.pid = pid_nr_ns(task_pid(current), fc->pid_ns);
}

void bento_set_initialized(struct bento_conn *fc)
{
	/* Make sure stores before this are seen on another CPU */
	smp_wmb();
	fc->initialized = 1;
}

static bool bento_block_alloc(struct bento_conn *fc)
{
	return !fc->initialized;
}

static struct bento_req *__bento_get_req(struct bento_conn *fc, unsigned npages,
				       bool for_background)
{
	struct bento_req *req;
	int err;
	atomic_inc(&fc->num_waiting);

	if (bento_block_alloc(fc)) {
		err = -EINTR;
		goto out;
	}
	/* Matches smp_wmb() in bento_set_initialized() */
	smp_rmb();

	err = -ENOTCONN;
	if (!fc->connected)
		goto out;

	err = -ECONNREFUSED;
	if (fc->conn_error)
		goto out;

	req = bento_request_alloc(npages);
	err = -ENOMEM;
	if (!req) {
		goto out;
	}

	bento_req_init_context(fc, req);
	__set_bit(FR_WAITING, &req->flags);

	return req;

 out:
	atomic_dec(&fc->num_waiting);
	return ERR_PTR(err);
}

struct bento_req *bento_get_req(struct bento_conn *fc, unsigned npages)
{
	return __bento_get_req(fc, npages, false);
}

/*
 * Return request in bento_file->reserved_req.  However that may
 * currently be in use.  If that is the case, wait for it to become
 * available.
 */
static struct bento_req *get_reserved_req(struct bento_conn *fc,
					 struct file *file)
{
	struct bento_req *req = NULL;
	struct bento_file *ff = file->private_data;

	do {
		wait_event(fc->reserved_req_waitq, ff->reserved_req);
		spin_lock(&fc->lock);
		if (ff->reserved_req) {
			req = ff->reserved_req;
			ff->reserved_req = NULL;
			req->stolen_file = get_file(file);
		}
		spin_unlock(&fc->lock);
	} while (!req);

	return req;
}

/*
 * Put stolen request back into bento_file->reserved_req
 */
static void put_reserved_req(struct bento_conn *fc, struct bento_req *req)
{
	struct file *file = req->stolen_file;
	struct bento_file *ff = file->private_data;

	spin_lock(&fc->lock);
	bento_request_init(req, req->pages, req->page_descs, req->max_pages);
	BUG_ON(ff->reserved_req);
	ff->reserved_req = req;
	wake_up_all(&fc->reserved_req_waitq);
	spin_unlock(&fc->lock);
	fput(file);
}

/*
 * Gets a requests for a file operation, always succeeds
 *
 * This is used for sending the FLUSH request, which must get to
 * userspace, due to POSIX locks which may need to be unlocked.
 *
 * If allocation fails due to OOM, use the reserved request in
 * bento_file.
 *
 * This is very unlikely to deadlock accidentally, since the
 * filesystem should not have it's own file open.  If deadlock is
 * intentional, it can still be broken by "aborting" the filesystem.
 */
struct bento_req *bento_get_req_nofail_nopages(struct bento_conn *fc,
					     struct file *file)
{
	struct bento_req *req;

	atomic_inc(&fc->num_waiting);
	wait_event(fc->blocked_waitq, fc->initialized);
	/* Matches smp_wmb() in bento_set_initialized() */
	smp_rmb();
	req = bento_request_alloc(0);
	if (!req)
		req = get_reserved_req(fc, file);

	bento_req_init_context(fc, req);
	__set_bit(FR_WAITING, &req->flags);
	__clear_bit(FR_BACKGROUND, &req->flags);
	return req;
}

void bento_put_request(struct bento_conn *fc, struct bento_req *req)
{
	if (refcount_dec_and_test(&req->count)) {
		if (test_bit(FR_BACKGROUND, &req->flags)) {
			/*
			 * We get here in the unlikely case that a background
			 * request was allocated but not sent
			 */
			spin_lock(&fc->lock);
			if (!fc->blocked)
				wake_up(&fc->blocked_waitq);
			spin_unlock(&fc->lock);
		}

		if (test_bit(FR_WAITING, &req->flags)) {
			__clear_bit(FR_WAITING, &req->flags);
			atomic_dec(&fc->num_waiting);
		}

		if (req->stolen_file)
			put_reserved_req(fc, req);
		else
			bento_request_free(req);
	}
}

void bento_queue_forget(struct bento_conn *fc, struct bento_forget_link *forget,
		       u64 nodeid, u64 nlookup)
{
	struct bento_in inarg;
	struct bento_out outarg;
	struct fuse_forget_in forget_in = {
		.nlookup = nlookup,
	};
	inarg.h.opcode = FUSE_FORGET;
	inarg.h.nodeid = nodeid;
	inarg.numargs = 1;
	inarg.args[0].size = sizeof(struct fuse_forget_in);
	inarg.args[0].value = &forget_in;
	outarg.numargs = 0;

	down_read(&fc->fslock);
	fc->dispatch(fc->fs_ptr, FUSE_FORGET, &inarg, &outarg);
	up_read(&fc->fslock);
}

/*
 * Abort all requests.
 *
 * Emergency exit in case of a malicious or accidental deadlock, or just a hung
 * filesystem.
 *
 * The same effect is usually achievable through killing the filesystem daemon
 * and all users of the filesystem.  The exception is the combination of an
 * asynchronous request and the tricky deadlock (see
 * Documentation/filesystems/fuse.txt).
 *
 * Aborting requests under I/O goes as follows: 1: Separate out unlocked
 * requests, they should be finished off immediately.  Locked requests will be
 * finished after unlock; see unlock_request(). 2: Finish off the unlocked
 * requests.  It is possible that some request will finish before we can.  This
 * is OK, the request will in that case be removed from the list before we touch
 * it.
 */
void bento_abort_conn(struct bento_conn *fc)
{
	struct bento_iqueue *fiq = &fc->iq;

	spin_lock(&fc->lock);
	if (fc->connected) {
		fc->connected = 0;
		fc->blocked = 0;
		bento_set_initialized(fc);

		spin_lock(&fiq->waitq.lock);
		fiq->connected = 0;
		spin_unlock(&fiq->waitq.lock);
		spin_unlock(&fc->lock);

	} else {
		spin_unlock(&fc->lock);
	}
}

int __init bento_dev_init(void)
{
	int err = -ENOMEM;
	bento_req_cachep = kmem_cache_create("bento_request",
					    sizeof(struct bento_req),
					    0, 0, NULL);
	if (!bento_req_cachep)
		goto out;

	return 0;

 out:
	return err;
}

void bento_dev_cleanup(void)
{
	kmem_cache_destroy(bento_req_cachep);
}
