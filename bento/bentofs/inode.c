/*
  Bento: Safe Rust file systems in the kernel
  Copyright (C) 2020  Samantha Miller, Kaiyuan Zhang, Danyang Zhuo, Tom
      Anderson, Ang Chen, University of Washington
  Copyright (C) 2001-2008  Miklos Szeredi <miklos@szeredi.hu>

  This program can be distributed under the terms of the GNU GPL.
  See the file COPYING.
*/

#include "bento_i.h"

#include <linux/pagemap.h>
#include <linux/slab.h>
#include <linux/file.h>
#include <linux/seq_file.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/parser.h>
#include <linux/statfs.h>
#include <linux/random.h>
#include <linux/sched.h>
#include <linux/exportfs.h>
#include <linux/posix_acl.h>
#include <linux/pid_namespace.h>

MODULE_AUTHOR("Samantha Miller <sm237@cs.washington.edu>");
MODULE_DESCRIPTION("File Operations for Bento");
MODULE_LICENSE("GPL");

static struct kmem_cache *bento_inode_cachep;
struct list_head bento_conn_list;
DEFINE_MUTEX(bento_mutex);

static struct bento_fs_type *file_systems;
static DEFINE_RWLOCK(bento_fs_lock);

#define BENTO_SUPER_MAGIC 0x65735546

#define BENTO_DEFAULT_BLKSIZE 512

struct bento_mount_data {
	int fd;
	unsigned rootmode;
	kuid_t user_id;
	kgid_t group_id;
	unsigned fd_present:1;
	unsigned rootmode_present:1;
	unsigned user_id_present:1;
	unsigned group_id_present:1;
	unsigned default_permissions:1;
	unsigned allow_other:1;
	unsigned max_read;
	unsigned blksize;
	char *name;
	char *devname;
};

struct bento_forget_link *bento_alloc_forget(void)
{
	return kzalloc(sizeof(struct bento_forget_link), GFP_KERNEL);
}

static struct inode *bento_alloc_inode(struct super_block *sb)
{
	struct inode *inode;
	struct bento_inode *fi;

	inode = kmem_cache_alloc(bento_inode_cachep, GFP_KERNEL);
	if (!inode)
		return NULL;

	fi = get_bento_inode(inode);
	fi->i_time = 0;
	fi->nodeid = 0;
	fi->nlookup = 0;
	fi->attr_version = 0;
	fi->writectr = 0;
	fi->orig_ino = 0;
	fi->state = 0;
	INIT_LIST_HEAD(&fi->write_files);
	INIT_LIST_HEAD(&fi->queued_writes);
	INIT_LIST_HEAD(&fi->writepages);
	init_waitqueue_head(&fi->page_waitq);
	mutex_init(&fi->mutex);
	fi->forget = bento_alloc_forget();
	if (!fi->forget) {
		kmem_cache_free(bento_inode_cachep, inode);
		return NULL;
	}

	return inode;
}

static void bento_i_callback(struct rcu_head *head)
{
	struct inode *inode = container_of(head, struct inode, i_rcu);
	kmem_cache_free(bento_inode_cachep, inode);
}

static void bento_destroy_inode(struct inode *inode)
{
	struct bento_inode *fi = get_bento_inode(inode);
	BUG_ON(!list_empty(&fi->write_files));
	BUG_ON(!list_empty(&fi->queued_writes));
	mutex_destroy(&fi->mutex);
	kfree(fi->forget);
	call_rcu(&inode->i_rcu, bento_i_callback);
}

static void bento_evict_inode(struct inode *inode)
{
	truncate_inode_pages_final(&inode->i_data);
	clear_inode(inode);
	if (inode->i_sb->s_flags & SB_ACTIVE) {
		struct bento_conn *fc = get_bento_conn(inode);
		struct bento_inode *fi = get_bento_inode(inode);
		bento_queue_forget(fc, fi->forget, fi->nodeid, fi->nlookup);
		fi->forget = NULL;
	}
}

static int bento_remount_fs(struct super_block *sb, int *flags, char *data)
{
	sync_filesystem(sb);
	if (*flags & SB_MANDLOCK)
		return -EINVAL;

	return 0;
}

/*
 * ino_t is 32-bits on 32-bit arch. We have to squash the 64-bit value down
 * so that it will fit.
 */
static ino_t bento_squash_ino(u64 ino64)
{
	ino_t ino = (ino_t) ino64;
	if (sizeof(ino_t) < sizeof(u64))
		ino ^= ino64 >> (sizeof(u64) - sizeof(ino_t)) * 8;
	return ino;
}

void bento_change_attributes_common(struct inode *inode, struct fuse_attr *attr,
				   u64 attr_valid)
{
	struct bento_conn *fc = get_bento_conn(inode);
	struct bento_inode *fi = get_bento_inode(inode);

	fi->attr_version = ++fc->attr_version;
	fi->i_time = attr_valid;

	inode->i_ino     = bento_squash_ino(attr->ino);
	inode->i_mode    = (inode->i_mode & S_IFMT) | (attr->mode & 07777);
	set_nlink(inode, attr->nlink);
	inode->i_uid     = make_kuid(&init_user_ns, attr->uid);
	inode->i_gid     = make_kgid(&init_user_ns, attr->gid);
	inode->i_blocks  = attr->blocks;
	inode->i_atime.tv_sec   = attr->atime;
	inode->i_atime.tv_nsec  = attr->atimensec;
	/* mtime from server may be stale due to local buffered write */
	if (!fc->writeback_cache || !S_ISREG(inode->i_mode) ||
			(attr->mtime > inode->i_mtime.tv_sec ||
			 (attr->mtime == inode->i_mtime.tv_sec &&
			  attr->mtimensec > inode->i_mtime.tv_nsec))) {
		inode->i_mtime.tv_sec   = attr->mtime;
		inode->i_mtime.tv_nsec  = attr->mtimensec;
		inode->i_ctime.tv_sec   = attr->ctime;
		inode->i_ctime.tv_nsec  = attr->ctimensec;
	}

	if (attr->blksize != 0)
		inode->i_blkbits = ilog2(attr->blksize);
	else
		inode->i_blkbits = inode->i_sb->s_blocksize_bits;

	/*
	 * Don't set the sticky bit in i_mode, unless we want the VFS
	 * to check permissions.  This prevents failures due to the
	 * check in may_delete().
	 */
	fi->orig_i_mode = inode->i_mode;
	if (!fc->default_permissions)
		inode->i_mode &= ~S_ISVTX;

	fi->orig_ino = attr->ino;
}

void bento_change_attributes(struct inode *inode, struct fuse_attr *attr,
			    u64 attr_valid, u64 attr_version)
{
	struct bento_conn *fc = get_bento_conn(inode);
	struct bento_inode *fi = get_bento_inode(inode);
	bool is_wb = fc->writeback_cache;
	loff_t oldsize;
	struct timespec64 old_mtime;

	spin_lock(&fc->lock);
	if ((attr_version != 0 && fi->attr_version > attr_version) ||
	    test_bit(BENTO_I_SIZE_UNSTABLE, &fi->state)) {
		spin_unlock(&fc->lock);
		return;
	}

	old_mtime = inode->i_mtime;
	bento_change_attributes_common(inode, attr, attr_valid);

	oldsize = inode->i_size;
	/*
	 * In case of writeback_cache enabled, the cached writes beyond EOF
	 * extend local i_size without keeping userspace server in sync. So,
	 * attr->size coming from server can be stale. We cannot trust it.
	 */
	if (!is_wb || !S_ISREG(inode->i_mode) || attr->size > oldsize)
		i_size_write(inode, attr->size);
	spin_unlock(&fc->lock);

	if (!is_wb && S_ISREG(inode->i_mode)) {
		bool inval = false;

		if (oldsize != attr->size) {
			truncate_pagecache(inode, attr->size);
			inval = true;
		} else if (fc->auto_inval_data) {
			struct timespec64 new_mtime = {
				.tv_sec = attr->mtime,
				.tv_nsec = attr->mtimensec,
			};

			/*
			 * Auto inval mode also checks and invalidates if mtime
			 * has changed.
			 */
			if (!timespec64_equal(&old_mtime, &new_mtime))
				inval = true;
		}

		if (inval)
			invalidate_inode_pages2(inode->i_mapping);
	}
}

static void bento_init_inode(struct inode *inode, struct fuse_attr *attr)
{
	inode->i_mode = attr->mode & S_IFMT;
	inode->i_size = attr->size;
	inode->i_mtime.tv_sec  = attr->mtime;
	inode->i_mtime.tv_nsec = attr->mtimensec;
	inode->i_ctime.tv_sec  = attr->ctime;
	inode->i_ctime.tv_nsec = attr->ctimensec;
	if (S_ISREG(inode->i_mode)) {
		bento_init_common(inode);
		bento_init_file_inode(inode);
	} else if (S_ISDIR(inode->i_mode))
		bento_init_dir(inode);
	else if (S_ISLNK(inode->i_mode))
		bento_init_symlink(inode);
	else if (S_ISCHR(inode->i_mode) || S_ISBLK(inode->i_mode) ||
		 S_ISFIFO(inode->i_mode) || S_ISSOCK(inode->i_mode)) {
		bento_init_common(inode);
		init_special_inode(inode, inode->i_mode,
				   new_decode_dev(attr->rdev));
	} else
		BUG();
}

int bento_inode_eq(struct inode *inode, void *_nodeidp)
{
	u64 nodeid = *(u64 *) _nodeidp;
	if (get_node_id(inode) == nodeid)
		return 1;
	else
		return 0;
}

static int bento_inode_set(struct inode *inode, void *_nodeidp)
{
	u64 nodeid = *(u64 *) _nodeidp;
	get_bento_inode(inode)->nodeid = nodeid;
	return 0;
}

struct inode *bento_iget(struct super_block *sb, u64 nodeid,
			int generation, struct fuse_attr *attr,
			u64 attr_valid, u64 attr_version)
{
	struct inode *inode;
	struct bento_inode *fi;
	struct bento_conn *fc = get_bento_conn_super(sb);

 retry:
	inode = iget5_locked(sb, nodeid, bento_inode_eq, bento_inode_set, &nodeid);
	if (!inode)
		return NULL;

	if ((inode->i_state & I_NEW)) {
		inode->i_flags |= S_NOATIME;
		if (!fc->writeback_cache || !S_ISREG(attr->mode))
			inode->i_flags |= S_NOCMTIME;
		inode->i_generation = generation;
		bento_init_inode(inode, attr);
		unlock_new_inode(inode);
	} else if ((inode->i_mode ^ attr->mode) & S_IFMT) {
		/* Inode has changed type, any I/O on the old should fail */
		make_bad_inode(inode);
		iput(inode);
		goto retry;
	}

	fi = get_bento_inode(inode);
	spin_lock(&fc->lock);
	fi->nlookup++;
	spin_unlock(&fc->lock);
	bento_change_attributes(inode, attr, attr_valid, attr_version);

	return inode;
}

int bento_reverse_inval_inode(struct super_block *sb, u64 nodeid,
			     loff_t offset, loff_t len)
{
	struct inode *inode;
	pgoff_t pg_start;
	pgoff_t pg_end;

	inode = ilookup5(sb, nodeid, bento_inode_eq, &nodeid);
	if (!inode)
		return -ENOENT;

	bento_invalidate_attr(inode);
	forget_all_cached_acls(inode);
	if (offset >= 0) {
		pg_start = offset >> PAGE_SHIFT;
		if (len <= 0)
			pg_end = -1;
		else
			pg_end = (offset + len - 1) >> PAGE_SHIFT;
		invalidate_inode_pages2_range(inode->i_mapping,
					      pg_start, pg_end);
	}
	iput(inode);
	return 0;
}

void bento_lock_inode(struct inode *inode)
{
	if (!get_bento_conn(inode)->parallel_dirops)
		mutex_lock(&get_bento_inode(inode)->mutex);
}

void bento_unlock_inode(struct inode *inode)
{
	if (!get_bento_conn(inode)->parallel_dirops)
		mutex_unlock(&get_bento_inode(inode)->mutex);
}

static void bento_umount_begin(struct super_block *sb)
{
	bento_abort_conn(get_bento_conn_super(sb));
}

static void bento_send_destroy(struct bento_conn *fc)
{
	struct bento_req *req = fc->destroy_req;
	if (req && fc->conn_init) {
		fc->destroy_req = NULL;
		down_read(&fc->fslock);
		fc->dispatch(fc->fs_ptr, FUSE_DESTROY, &req->in, &req->out);
		up_read(&fc->fslock);
		bento_put_request(fc, req);
	}
}

static void bento_put_super(struct super_block *sb)
{
	struct bento_conn *fc = get_bento_conn_super(sb);

	bento_send_destroy(fc);

	bento_abort_conn(fc);
	mutex_lock(&bento_mutex);
	list_del(&fc->entry);
	mutex_unlock(&bento_mutex);

	bento_conn_put(fc);
}

static void convert_bento_statfs(struct kstatfs *stbuf, struct fuse_kstatfs *attr)
{
	stbuf->f_type    = BENTO_SUPER_MAGIC;
	stbuf->f_bsize   = attr->bsize;
	stbuf->f_frsize  = attr->frsize;
	stbuf->f_blocks  = attr->blocks;
	stbuf->f_bfree   = attr->bfree;
	stbuf->f_bavail  = attr->bavail;
	stbuf->f_files   = attr->files;
	stbuf->f_ffree   = attr->ffree;
	stbuf->f_namelen = attr->namelen;
	/* fsid is left zero */
}

static int bento_statfs(struct dentry *dentry, struct kstatfs *buf)
{
	struct super_block *sb = dentry->d_sb;
	struct bento_conn *fc = get_bento_conn_super(sb);
	struct fuse_statfs_out outarg;
	struct bento_in in;
	struct bento_out out;
	int err;

	if (!bento_allow_current_process(fc)) {
		buf->f_type = BENTO_SUPER_MAGIC;
		return 0;
	}

	memset(&outarg, 0, sizeof(outarg));
	in.numargs = 0;
        in.h.opcode = FUSE_STATFS;
        in.h.nodeid = get_node_id(d_inode(dentry));
        out.numargs = 1;
        out.args[0].size = sizeof(outarg);
        out.args[0].value = &outarg;
	down_read(&fc->fslock);
	err = fc->dispatch(fc->fs_ptr, FUSE_STATFS, &in, &out);
	up_read(&fc->fslock);
	if (!err)
		convert_bento_statfs(buf, &outarg.st);
	return err;
}

enum {
	OPT_FD,
	OPT_NAME,
	OPT_DEVNAME,
	OPT_ROOTMODE,
	OPT_USER_ID,
	OPT_GROUP_ID,
	OPT_DEFAULT_PERMISSIONS,
	OPT_ALLOW_OTHER,
	OPT_MAX_READ,
	OPT_BLKSIZE,
	OPT_ERR
};

static const match_table_t tokens = {
	{OPT_FD,			"fd=%u"},
	{OPT_NAME,			"name=%s"},
	{OPT_DEVNAME,			"devname=%s"},
	{OPT_ROOTMODE,			"rootmode=%o"},
	{OPT_USER_ID,			"user_id=%u"},
	{OPT_GROUP_ID,			"group_id=%u"},
	{OPT_DEFAULT_PERMISSIONS,	"default_permissions"},
	{OPT_ALLOW_OTHER,		"allow_other"},
	{OPT_MAX_READ,			"max_read=%u"},
	{OPT_BLKSIZE,			"blksize=%u"},
	{OPT_ERR,			NULL}
};

static int bento_match_uint(substring_t *s, unsigned int *res)
{
	int err = -ENOMEM;
	char *buf = match_strdup(s);
	if (buf) {
		err = kstrtouint(buf, 10, res);
		kfree(buf);
	}
	return err;
}

static int parse_bento_opt(char *opt, struct bento_mount_data *d, int is_bdev)
{
	char *p;
	memset(d, 0, sizeof(struct bento_mount_data));
	d->max_read = ~0;
	d->blksize = BENTO_DEFAULT_BLKSIZE;

	while ((p = strsep(&opt, ",")) != NULL) {
		int token;
		int value;
		unsigned uv;
		substring_t args[MAX_OPT_ARGS];
		if (!*p)
			continue;

		token = match_token(p, tokens, args);
		switch (token) {
		case OPT_FD:
			if (match_int(&args[0], &value))
				return 0;
			d->fd = value;
			d->fd_present = 1;
			break;

		case OPT_NAME:
			d->name = match_strdup(&args[0]);
			break;

		case OPT_DEVNAME:
			d->devname = match_strdup(&args[0]);
			break;

		case OPT_ROOTMODE:
			if (match_octal(&args[0], &value))
				return 0;
			if (!bento_valid_type(value))
				return 0;
			d->rootmode = value;
			d->rootmode_present = 1;
			break;

		case OPT_USER_ID:
			if (bento_match_uint(&args[0], &uv))
				return 0;
			d->user_id = make_kuid(current_user_ns(), uv);
			if (!uid_valid(d->user_id))
				return 0;
			d->user_id_present = 1;
			break;

		case OPT_GROUP_ID:
			if (bento_match_uint(&args[0], &uv))
				return 0;
			d->group_id = make_kgid(current_user_ns(), uv);
			if (!gid_valid(d->group_id))
				return 0;
			d->group_id_present = 1;
			break;

		case OPT_DEFAULT_PERMISSIONS:
			d->default_permissions = 1;
			break;

		case OPT_ALLOW_OTHER:
			d->allow_other = 1;
			break;

		case OPT_MAX_READ:
			if (match_int(&args[0], &value))
				return 0;
			d->max_read = value;
			break;

		case OPT_BLKSIZE:
			if (!is_bdev || match_int(&args[0], &value))
				return 0;
			d->blksize = value;
			break;

		default:
			return 0;
		}
	}

	if (!d->rootmode_present ||
	    !d->user_id_present || !d->group_id_present)
		return 0;

	return 1;
}

static int bento_show_options(struct seq_file *m, struct dentry *root)
{
	struct super_block *sb = root->d_sb;
	struct bento_conn *fc = get_bento_conn_super(sb);

	seq_printf(m, ",user_id=%u", from_kuid_munged(&init_user_ns, fc->user_id));
	seq_printf(m, ",group_id=%u", from_kgid_munged(&init_user_ns, fc->group_id));
	if (fc->default_permissions)
		seq_puts(m, ",default_permissions");
	if (fc->allow_other)
		seq_puts(m, ",allow_other");
	if (fc->max_read != ~0)
		seq_printf(m, ",max_read=%u", fc->max_read);
	if (sb->s_bdev && sb->s_blocksize != BENTO_DEFAULT_BLKSIZE)
		seq_printf(m, ",blksize=%lu", sb->s_blocksize);
	return 0;
}

static void bento_iqueue_init(struct bento_iqueue *fiq)
{
	memset(fiq, 0, sizeof(struct bento_iqueue));
	init_waitqueue_head(&fiq->waitq);
	INIT_LIST_HEAD(&fiq->pending);
	INIT_LIST_HEAD(&fiq->interrupts);
	fiq->forget_list_tail = &fiq->forget_list_head;
	fiq->connected = 1;
}

void bento_conn_init(struct bento_conn *fc)
{
	memset(fc, 0, sizeof(*fc));
	spin_lock_init(&fc->lock);
	init_rwsem(&fc->killsb);
	init_rwsem(&fc->fslock);
	refcount_set(&fc->count, 1);
	atomic_set(&fc->dev_count, 1);
	init_waitqueue_head(&fc->blocked_waitq);
	init_waitqueue_head(&fc->reserved_req_waitq);
	bento_iqueue_init(&fc->iq);
	INIT_LIST_HEAD(&fc->bg_queue);
	INIT_LIST_HEAD(&fc->entry);
	INIT_LIST_HEAD(&fc->devices);
	atomic_set(&fc->num_waiting, 0);
	fc->khctr = 0;
	fc->polled_files = RB_ROOT;
	fc->blocked = 0;
	fc->initialized = 0;
	fc->connected = 1;
	fc->attr_version = 1;
	get_random_bytes(&fc->scramble_key, sizeof(fc->scramble_key));
	fc->pid_ns = get_pid_ns(task_active_pid_ns(current));
}

void bento_conn_put(struct bento_conn *fc)
{
	if (refcount_dec_and_test(&fc->count)) {
		if (fc->destroy_req)
			bento_request_free(fc->destroy_req);
		put_pid_ns(fc->pid_ns);
		fc->release(fc);
	}
}

struct bento_conn *bento_conn_get(struct bento_conn *fc)
{
	refcount_inc(&fc->count);
	return fc;
}

static struct inode *bento_get_root_inode(struct super_block *sb, unsigned mode)
{
	struct fuse_attr attr;
	memset(&attr, 0, sizeof(attr));

	attr.mode = mode;
	attr.ino = FUSE_ROOT_ID;
	attr.nlink = 1;
	return bento_iget(sb, 1, 0, &attr, 0, 0);
}

struct bento_inode_handle {
	u64 nodeid;
	u32 generation;
};

static struct dentry *bento_get_dentry(struct super_block *sb,
				      struct bento_inode_handle *handle)
{
	struct bento_conn *fc = get_bento_conn_super(sb);
	struct inode *inode;
	struct dentry *entry;
	int err = -ESTALE;

	if (handle->nodeid == 0)
		goto out_err;

	inode = ilookup5(sb, handle->nodeid, bento_inode_eq, &handle->nodeid);
	if (!inode) {
		struct fuse_entry_out outarg;
		const struct qstr name = QSTR_INIT(".", 1);

		if (!fc->export_support)
			goto out_err;

		err = bento_lookup_name(sb, handle->nodeid, &name, &outarg,
				       &inode);
		if (err && err != -ENOENT)
			goto out_err;
		if (err || !inode) {
			err = -ESTALE;
			goto out_err;
		}
		err = -EIO;
		if (get_node_id(inode) != handle->nodeid)
			goto out_iput;
	}
	err = -ESTALE;
	if (inode->i_generation != handle->generation)
		goto out_iput;

	entry = d_obtain_alias(inode);
	if (!IS_ERR(entry) && get_node_id(inode) != FUSE_ROOT_ID)
		bento_invalidate_entry_cache(entry);

	return entry;

 out_iput:
	iput(inode);
 out_err:
	return ERR_PTR(err);
}

static int bento_encode_fh(struct inode *inode, u32 *fh, int *max_len,
			   struct inode *parent)
{
	int len = parent ? 6 : 3;
	u64 nodeid;
	u32 generation;

	if (*max_len < len) {
		*max_len = len;
		return  FILEID_INVALID;
	}

	nodeid = get_bento_inode(inode)->nodeid;
	generation = inode->i_generation;

	fh[0] = (u32)(nodeid >> 32);
	fh[1] = (u32)(nodeid & 0xffffffff);
	fh[2] = generation;

	if (parent) {
		nodeid = get_bento_inode(parent)->nodeid;
		generation = parent->i_generation;

		fh[3] = (u32)(nodeid >> 32);
		fh[4] = (u32)(nodeid & 0xffffffff);
		fh[5] = generation;
	}

	*max_len = len;
	return parent ? 0x82 : 0x81;
}

static struct dentry *bento_fh_to_dentry(struct super_block *sb,
		struct fid *fid, int fh_len, int fh_type)
{
	struct bento_inode_handle handle;

	if ((fh_type != 0x81 && fh_type != 0x82) || fh_len < 3)
		return NULL;

	handle.nodeid = (u64) fid->raw[0] << 32;
	handle.nodeid |= (u64) fid->raw[1];
	handle.generation = fid->raw[2];
	return bento_get_dentry(sb, &handle);
}

static struct dentry *bento_fh_to_parent(struct super_block *sb,
		struct fid *fid, int fh_len, int fh_type)
{
	struct bento_inode_handle parent;

	if (fh_type != 0x82 || fh_len < 6)
		return NULL;

	parent.nodeid = (u64) fid->raw[3] << 32;
	parent.nodeid |= (u64) fid->raw[4];
	parent.generation = fid->raw[5];
	return bento_get_dentry(sb, &parent);
}

static struct dentry *bento_get_parent(struct dentry *child)
{
	struct inode *child_inode = d_inode(child);
	struct bento_conn *fc = get_bento_conn(child_inode);
	struct inode *inode;
	struct dentry *parent;
	struct fuse_entry_out outarg;
	const struct qstr name = QSTR_INIT("..", 2);
	int err;

	if (!fc->export_support)
		return ERR_PTR(-ESTALE);

	err = bento_lookup_name(child_inode->i_sb, get_node_id(child_inode),
			       &name, &outarg, &inode);
	if (err) {
		if (err == -ENOENT)
			return ERR_PTR(-ESTALE);
		return ERR_PTR(err);
	}

	parent = d_obtain_alias(inode);
	if (!IS_ERR(parent) && get_node_id(inode) != FUSE_ROOT_ID)
		bento_invalidate_entry_cache(parent);

	return parent;
}

static const struct export_operations bento_export_operations = {
	.fh_to_dentry	= bento_fh_to_dentry,
	.fh_to_parent	= bento_fh_to_parent,
	.encode_fh	= bento_encode_fh,
	.get_parent	= bento_get_parent,
};

static const struct super_operations bento_super_operations = {
	.alloc_inode    = bento_alloc_inode,
	.destroy_inode  = bento_destroy_inode,
	.evict_inode	= bento_evict_inode,
	.write_inode	= bento_write_inode,
	.drop_inode	= generic_delete_inode,
	.remount_fs	= bento_remount_fs,
	.put_super	= bento_put_super,
	.umount_begin	= bento_umount_begin,
	.statfs		= bento_statfs,
	.show_options	= bento_show_options,
};

static void process_init_reply(struct bento_conn *fc, struct bento_req *req)
{
	struct fuse_init_out *arg = &req->misc.init_out;

	if (req->out.h.error || arg->major != BENTO_KERNEL_VERSION)
		fc->conn_error = 1;
	else {
		unsigned long ra_pages;

		ra_pages = arg->max_readahead / PAGE_SIZE;
		if (!(arg->flags & FUSE_POSIX_LOCKS))
			fc->no_lock = 1;
		if (arg->minor >= 17) {
			if (!(arg->flags & FUSE_FLOCK_LOCKS))
				fc->no_flock = 1;
		} else {
			if (!(arg->flags & FUSE_POSIX_LOCKS))
				fc->no_flock = 1;
		}
		if (arg->flags & FUSE_ATOMIC_O_TRUNC)
			fc->atomic_o_trunc = 1;
		if (arg->minor >= 9) {
			/* LOOKUP has dependency on proto version */
			if (arg->flags & FUSE_EXPORT_SUPPORT)
				fc->export_support = 1;
		}
		if (arg->flags & FUSE_BIG_WRITES)
			fc->big_writes = 1;
		if (arg->flags & FUSE_DONT_MASK)
			fc->dont_mask = 1;
		if (arg->flags & FUSE_AUTO_INVAL_DATA)
			fc->auto_inval_data = 1;
		if (arg->flags & FUSE_ASYNC_DIO)
			fc->async_dio = 1;
		if (arg->flags & FUSE_WRITEBACK_CACHE)
			fc->writeback_cache = 1;
		if (arg->flags & FUSE_PARALLEL_DIROPS)
			fc->parallel_dirops = 1;
		if (arg->flags & FUSE_HANDLE_KILLPRIV)
			fc->handle_killpriv = 1;
		if (arg->time_gran && arg->time_gran <= 1000000000)
			fc->sb->s_time_gran = arg->time_gran;
		if ((arg->flags & FUSE_POSIX_ACL)) {
			fc->default_permissions = 1;
			fc->posix_acl = 1;
			fc->sb->s_xattr = bento_acl_xattr_handlers;
		}

		fc->sb->s_bdi->ra_pages =
				min(fc->sb->s_bdi->ra_pages, ra_pages);
		fc->minor = arg->minor;
		fc->max_write = arg->max_write;
		fc->max_write = max_t(unsigned, 4096, fc->max_write);
		fc->conn_init = 1;
	}
	bento_set_initialized(fc);
	wake_up_all(&fc->blocked_waitq);
}

static void bento_send_init(struct bento_conn *fc, const char *devname,
		struct bento_req *req)
{
	struct bento_init_in *arg = &req->misc.init_in;

	arg->major = BENTO_KERNEL_VERSION;
	arg->minor = BENTO_KERNEL_MINOR_VERSION;
	arg->max_readahead = fc->sb->s_bdi->ra_pages * PAGE_SIZE;
	arg->flags |= FUSE_ASYNC_READ | FUSE_POSIX_LOCKS | FUSE_ATOMIC_O_TRUNC |
		FUSE_EXPORT_SUPPORT | FUSE_BIG_WRITES | FUSE_DONT_MASK |
		FUSE_SPLICE_WRITE | FUSE_SPLICE_MOVE | FUSE_SPLICE_READ |
		FUSE_FLOCK_LOCKS | FUSE_HAS_IOCTL_DIR | FUSE_AUTO_INVAL_DATA |
		FUSE_DO_READDIRPLUS | FUSE_READDIRPLUS_AUTO | FUSE_ASYNC_DIO |
		FUSE_WRITEBACK_CACHE | FUSE_NO_OPEN_SUPPORT |
		FUSE_PARALLEL_DIROPS | FUSE_HANDLE_KILLPRIV | FUSE_POSIX_ACL;
	arg->devname = devname;
	req->in.h.opcode = FUSE_INIT;
	req->in.numargs = 1;
	req->in.args[0].size = sizeof(*arg);
	req->in.args[0].value = arg;
	req->out.numargs = 1;
	/* Variable length argument used for backward compatibility
	   with interface version < 7.5.  Rest of init_out is zeroed
	   by do_get_request(), so a short reply is not a problem */
	req->out.argvar = 1;
	req->out.args[0].size = sizeof(struct fuse_init_out);
	req->out.args[0].value = &req->misc.init_out;
	down_read(&fc->fslock);
	fc->dispatch(fc->fs_ptr, FUSE_INIT, &req->in, &req->out);
	up_read(&fc->fslock);
	process_init_reply(fc, req);
}

static void bento_free_conn(struct bento_conn *fc)
{
	WARN_ON(!list_empty(&fc->devices));
	kfree_rcu(fc, rcu);
}

static struct bento_fs_type **find_bento_fs(const char *name, unsigned len)
{
	struct bento_fs_type **p;
	for (p = &file_systems; *p; p = &(*p)->next) {
		if (strncmp((*p)->name, name, len) == 0 &&
		    !(*p)->name[len])
			break;
	}
	return p;
}

static int bento_fill_super(struct super_block *sb, void *data, int silent)
{
	struct bento_conn *fc;
	struct inode *root;
	struct bento_mount_data d;
	struct dentry *root_dentry;
	struct bento_req *init_req;
	int err;
	int is_bdev = sb->s_bdev != NULL;
	struct bento_fs_type **fs_type;

	err = -EINVAL;
	if (sb->s_flags & SB_MANDLOCK)
		goto err;

	sb->s_flags &= ~(SB_NOSEC | SB_I_VERSION);

	if (!parse_bento_opt(data, &d, is_bdev))
		goto err;

	if (is_bdev) {
#ifdef CONFIG_BLOCK
		err = -EINVAL;
		if (!sb_set_blocksize(sb, d.blksize))
			goto err;
#endif
	} else {
		sb->s_blocksize = PAGE_SIZE;
		sb->s_blocksize_bits = PAGE_SHIFT;
	}
	sb->s_magic = BENTO_SUPER_MAGIC;
	sb->s_op = &bento_super_operations;
	sb->s_xattr = bento_xattr_handlers;
	sb->s_maxbytes = MAX_LFS_FILESIZE;
	sb->s_time_gran = 1;
	sb->s_export_op = &bento_export_operations;

	fc = kmalloc(sizeof(*fc), GFP_KERNEL);
	err = -ENOMEM;
	if (!fc)
		goto err;

	bento_conn_init(fc);
	fc->release = bento_free_conn;

	fc->dev = sb->s_dev;
	fc->sb = sb;

	/* Handle umasking inside the bento code */
	if (sb->s_flags & SB_POSIXACL)
		fc->dont_mask = 1;
	sb->s_flags |= SB_POSIXACL;

	fc->default_permissions = d.default_permissions;
	fc->allow_other = d.allow_other;
	fc->user_id = d.user_id;
	fc->group_id = d.group_id;
	fc->max_read = max_t(unsigned, 4096, d.max_read);

	read_lock(&bento_fs_lock);
	fs_type = find_bento_fs(d.name, strlen(d.name));
	if (!*fs_type) {
		read_unlock(&bento_fs_lock);
		goto err_put_conn;
	} else {
		fc->fs_ptr = (*fs_type)->fs;
		fc->dispatch = (*fs_type)->dispatch;
	}
	read_unlock(&bento_fs_lock);

	/* Used by get_root_inode() */
	sb->s_fs_info = fc;

	err = -ENOMEM;
	root = bento_get_root_inode(sb, d.rootmode);
	sb->s_d_op = &bento_root_dentry_operations;
	root_dentry = d_make_root(root);
	if (!root_dentry)
		goto err_put_conn;
	/* Root dentry doesn't have .d_revalidate */
	sb->s_d_op = &bento_dentry_operations;

	init_req = bento_request_alloc(0);
	if (!init_req)
		goto err_put_root;
	__set_bit(FR_BACKGROUND, &init_req->flags);

	fc->destroy_req = bento_request_alloc(0);
	if (!fc->destroy_req)
		goto err_free_init_req;

	mutex_lock(&bento_mutex);

	list_add_tail(&fc->entry, &bento_conn_list);
	sb->s_root = root_dentry;
	mutex_unlock(&bento_mutex);
	/*
	 * atomic_dec_and_test() in fput() provides the necessary
	 * memory barrier for file->private_data to be visible on all
	 * CPUs after this
	 */

	bento_send_init(fc, d.devname, init_req);

	return 0;

 err_free_init_req:
	bento_request_free(init_req);
 err_put_root:
	dput(root_dentry);
 err_put_conn:
	bento_conn_put(fc);
 err:
	return err;
}

int register_bento_fs(const void* fs, char *fs_name, const void* dispatch)
{
	int res = 0;
	struct bento_fs_type ** p;
	struct bento_fs_type *fs_type;

        fs_type = kzalloc(sizeof(struct bento_fs_type), GFP_KERNEL);
	fs_type->fs = fs;
	fs_type->name = fs_name;
	fs_type->dispatch = dispatch;
	fs_type->next = NULL;

	BUG_ON(strchr(fs_type->name, '.'));

	write_lock(&bento_fs_lock);
	p = find_bento_fs(fs_type->name, strlen(fs_type->name));
	if (*p)
		res = -EBUSY;
	else
		*p = fs_type;
	write_unlock(&bento_fs_lock);
	return res;
}
EXPORT_SYMBOL(register_bento_fs);

int reregister_bento_fs(const void* fs, char *fs_name, const void* dispatch)
{
	int res = 0;
	struct bento_fs_type ** p;
	struct bento_fs_type *fs_type;
	struct list_head *ptr;
	struct bento_conn *conn;
	struct super_block *sb;
	void *state_ptr;
	struct bento_in inarg;
	struct bento_out outarg;

	write_lock(&bento_fs_lock);
	p = find_bento_fs(fs_name, strlen(fs_name));
	fs_type = *p;
	for (ptr = bento_conn_list.next; ptr != &bento_conn_list; ptr = ptr->next) {
		conn = list_entry(ptr, struct bento_conn, entry);
		if (conn->fs_ptr == fs_type->fs) {
			sb = conn->sb;
			break;
		}
	}
	down_write(&conn->fslock);
	// Reset no_ops in case the new version implements more functions
	conn->no_open = 0;
	conn->no_fsync = 0;
	conn->no_fsyncdir = 0;
	conn->no_flush = 0;
	conn->no_setxattr = 0;
	conn->no_getxattr = 0;
	conn->no_listxattr = 0;
	conn->no_removexattr = 0;
	conn->no_lock = 0;
	conn->no_access = 0;
	conn->no_create = 0;
	conn->no_interrupt = 0;
	conn->no_bmap = 0;
	conn->no_poll = 0;
	conn->no_flock = 0;


	inarg.numargs = 1;
        inarg.h.opcode = BENTO_UPDATE_PREPARE;
        inarg.h.nodeid = 0;
        outarg.numargs = 1;
	inarg.args[0].value = fs;
	fs_type->dispatch(fs_type->fs, BENTO_UPDATE_PREPARE, &inarg, &outarg);
	state_ptr = outarg.args[0].value;

	fs_type->fs = fs;
	fs_type->dispatch = dispatch;

	memset(&inarg, 0, sizeof(inarg));
	memset(&outarg, 0, sizeof(outarg));
	inarg.numargs = 1;
        inarg.h.opcode = BENTO_UPDATE_TRANSFER;
        inarg.h.nodeid = 0;
	inarg.args[0].size = sizeof(state_ptr);
	inarg.args[0].value = state_ptr;
        outarg.numargs = 0;
	fs_type->dispatch(fs_type->fs, BENTO_UPDATE_TRANSFER, &inarg, &outarg);

	conn->fs_ptr = fs;
	conn->dispatch = dispatch;
	fs_type->fs = fs;
	fs_type->dispatch = dispatch;
	up_write(&conn->fslock);
	write_unlock(&bento_fs_lock);
	return res;
}
EXPORT_SYMBOL(reregister_bento_fs);

int unregister_bento_fs(char *fs_name)
{
	struct bento_fs_type ** tmp;
	struct bento_fs_type *fs_type;

	write_lock(&bento_fs_lock);
	tmp = &file_systems;
	while (*tmp) {
		if (strncmp((*tmp)->name, fs_name, strlen(fs_name)) == 0) {
			fs_type = *tmp;
			*tmp = (*tmp)->next;
			kfree(fs_type);
			write_unlock(&bento_fs_lock);
			synchronize_rcu();
			return 0;
		}
		tmp = &(*tmp)->next;
	}
	write_unlock(&bento_fs_lock);

	return -EINVAL;
}

EXPORT_SYMBOL(unregister_bento_fs);

static struct dentry *bento_mount(struct file_system_type *fs_type,
		       int flags, const char *dev_name,
		       void *raw_data)
{
	return mount_nodev(fs_type, flags, raw_data, bento_fill_super);
}

static void bento_kill_sb_anon(struct super_block *sb)
{
	struct bento_conn *fc = get_bento_conn_super(sb);

	if (fc) {
		down_write(&fc->killsb);
		fc->sb = NULL;
		up_write(&fc->killsb);
	}

	kill_anon_super(sb);
}

static struct file_system_type bento_fs_type = {
	.owner		= THIS_MODULE,
	.name		= "bento",
	.fs_flags	= FS_HAS_SUBTYPE,
	.mount		= bento_mount,
	.kill_sb	= bento_kill_sb_anon,
};
MODULE_ALIAS_FS("bento");

#ifdef CONFIG_BLOCK
static struct dentry *bento_mount_blk(struct file_system_type *fs_type,
			   int flags, const char *dev_name,
			   void *raw_data)
{
	struct dentry *retval;
	char *opts = kmalloc(strlen((char *) raw_data) + strlen(dev_name) + 10, GFP_KERNEL);
	strcpy(opts, raw_data);
	strcat(opts, ",devname=");
	strcat(opts, dev_name);
	retval = mount_bdev(fs_type, flags, dev_name, opts, bento_fill_super);
	kfree(opts);
	return retval;
}

static void bento_kill_sb_blk(struct super_block *sb)
{
	struct bento_conn *fc = get_bento_conn_super(sb);

	if (fc) {
		down_write(&fc->killsb);
		fc->sb = NULL;
		up_write(&fc->killsb);
	}

	kill_block_super(sb);
}

static struct file_system_type bentoblk_fs_type = {
	.owner		= THIS_MODULE,
	.name		= "bentoblk",
	.mount		= bento_mount_blk,
	.kill_sb	= bento_kill_sb_blk,
	.fs_flags	= FS_REQUIRES_DEV | FS_HAS_SUBTYPE,
};
MODULE_ALIAS_FS("bentoblk");

static inline int register_bentoblk(void)
{
	return register_filesystem(&bentoblk_fs_type);
}

static inline void unregister_bentoblk(void)
{
	unregister_filesystem(&bentoblk_fs_type);
}
#else
static inline int register_bentoblk(void)
{
	return 0;
}

static inline void unregister_bentoblk(void)
{
}
#endif

static void bento_inode_init_once(void *foo)
{
	struct inode *inode = foo;

	inode_init_once(inode);
}

static int __init bento_fs_init(void)
{
	int err;

	bento_inode_cachep = kmem_cache_create("bento_inode",
			sizeof(struct bento_inode), 0,
			SLAB_HWCACHE_ALIGN|SLAB_ACCOUNT|SLAB_RECLAIM_ACCOUNT,
			bento_inode_init_once);
	err = -ENOMEM;
	if (!bento_inode_cachep)
		goto out;

	err = register_bentoblk();
	if (err)
		goto out2;

	err = register_filesystem(&bento_fs_type);
	if (err)
		goto out3;

	return 0;

 out3:
	unregister_bentoblk();
 out2:
	kmem_cache_destroy(bento_inode_cachep);
 out:
	return err;
}

static void bento_fs_cleanup(void)
{
	unregister_filesystem(&bento_fs_type);
	unregister_bentoblk();

	/*
	 * Make sure all delayed rcu free inodes are flushed before we
	 * destroy cache.
	 */
	rcu_barrier();
	kmem_cache_destroy(bento_inode_cachep);
}

static int __init bento_init(void)
{
	int res;

	printk(KERN_INFO "bento init (API version %i.%i)\n",
	       BENTO_KERNEL_VERSION, BENTO_KERNEL_MINOR_VERSION);

	INIT_LIST_HEAD(&bento_conn_list);
	res = bento_fs_init();

	if (res)
		goto err;

	res = bento_dev_init();
	if (res)
		goto err_fs_cleanup;


	return 0;

 err_fs_cleanup:
	bento_fs_cleanup();
 err:
	return res;
}

static void __exit bento_exit(void)
{
	bento_fs_cleanup();
	bento_dev_cleanup();
}

module_init(bento_init);
module_exit(bento_exit);
