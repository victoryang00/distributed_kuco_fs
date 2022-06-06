/*
  Bento: Safe Rust file systems in the kernel
  Copyright (C) 2020 Samantha Miller, Kaiyuan Zhang, Danyang Zhuo, Tom
      Anderson, Ang Chen, University of Washington
  Copyright (C) 2001-2008  Miklos Szeredi <miklos@szeredi.hu>

  This program can be distributed under the terms of the GNU GPL.
  See the file COPYING.
*/

#include "bento_i.h"

#include <linux/pagemap.h>
#include <linux/file.h>
#include <linux/sched.h>
#include <linux/namei.h>
#include <linux/slab.h>
#include <linux/xattr.h>
#include <linux/posix_acl.h>

union bento_dentry {
	u64 time;
	struct rcu_head rcu;
};

struct user_namespace init_us = {
	.uid_map = {
		.nr_extents = 1,
		{
			.extent[0] = {
				.first = 0,
				.lower_first = 0,
				.count = 4294967295U,
			},
		},
	},
	.gid_map = {
		.nr_extents = 1,
		{
			.extent[0] = {
				.first = 0,
				.lower_first = 0,
				.count = 4294967295U,
			},
		},
	},
	.projid_map = {
		.nr_extents = 1,
		{
			.extent[0] = {
				.first = 0,
				.lower_first = 0,
				.count = 4294967295U,
			},
		},
	},
	.ns.count = REFCOUNT_INIT(3),
	.owner = GLOBAL_ROOT_UID,
	.group = GLOBAL_ROOT_GID,
	.ns.inum = 0xEFFFFFFDU,
	.flags = USERNS_INIT_FLAGS,
};

static inline void bento_dentry_settime(struct dentry *entry, u64 time)
{
	((union bento_dentry *) entry->d_fsdata)->time = time;
}

static inline u64 bento_dentry_time(struct dentry *entry)
{
	return ((union bento_dentry *) entry->d_fsdata)->time;
}

/*
 * Bento caches dentries and attributes with separate timeout.  The
 * time in jiffies until the dentry/attributes are valid is stored in
 * dentry->d_fsdata and bento_inode->i_time respectively.
 */

/*
 * Calculate the time in jiffies until a dentry/attributes are valid
 */
static u64 time_to_jiffies(u64 sec, u32 nsec)
{
	if (sec || nsec) {
		struct timespec64 ts = {
			sec,
			min_t(u32, nsec, NSEC_PER_SEC - 1)
		};

		return get_jiffies_64() + timespec64_to_jiffies(&ts);
	} else
		return 0;
}

/*
 * Set dentry and possibly attribute timeouts from the lookup/mk*
 * replies
 */
static void bento_change_entry_timeout(struct dentry *entry,
				      struct fuse_entry_out *o)
{
	bento_dentry_settime(entry,
		time_to_jiffies(o->entry_valid, o->entry_valid_nsec));
}

static u64 attr_timeout(struct fuse_attr_out *o)
{
	return time_to_jiffies(o->attr_valid, o->attr_valid_nsec);
}

static u64 entry_attr_timeout(struct fuse_entry_out *o)
{
	return time_to_jiffies(o->attr_valid, o->attr_valid_nsec);
}

/*
 * Mark the attributes as stale, so that at the next call to
 * ->getattr() they will be fetched from userspace
 */
void bento_invalidate_attr(struct inode *inode)
{
	get_bento_inode(inode)->i_time = 0;
}

/**
 * Mark the attributes as stale due to an atime change.  Avoid the invalidate if
 * atime is not used.
 */
void bento_invalidate_atime(struct inode *inode)
{
	if (!IS_RDONLY(inode))
		bento_invalidate_attr(inode);
}

/*
 * Just mark the entry as stale, so that a next attempt to look it up
 * will result in a new lookup call to userspace
 *
 * This is called when a dentry is about to become negative and the
 * timeout is unknown (unlink, rmdir, rename and in some cases
 * lookup)
 */
void bento_invalidate_entry_cache(struct dentry *entry)
{
	bento_dentry_settime(entry, 0);
}

/*
 * Same as bento_invalidate_entry_cache(), but also try to remove the
 * dentry from the hash
 */
static void bento_invalidate_entry(struct dentry *entry)
{
	d_invalidate(entry);
	bento_invalidate_entry_cache(entry);
}

static void bento_lookup_init(struct bento_conn *fc, struct bento_in *inarg,
			     struct bento_out *outarg,
                             u64 nodeid, const struct qstr *name,
                             struct fuse_entry_out *outentry)
{
        memset(outentry, 0, sizeof(struct fuse_entry_out));
        inarg->h.opcode = FUSE_LOOKUP;
        inarg->h.nodeid = nodeid;
        inarg->numargs = 1;
        inarg->args[0].size = name->len + 1;
        inarg->args[0].value = name->name;
        outarg->numargs = 1;
        outarg->args[0].size = sizeof(struct fuse_entry_out);
        outarg->args[0].value = outentry;
}


u64 bento_get_attr_version(struct bento_conn *fc)
{
	u64 curr_version;

	/*
	 * The spin lock isn't actually needed on 64bit archs, but we
	 * don't yet care too much about such optimizations.
	 */
	spin_lock(&fc->lock);
	curr_version = fc->attr_version;
	spin_unlock(&fc->lock);

	return curr_version;
}

/*
 * Check whether the dentry is still valid
 *
 * If the entry validity timeout has expired and the dentry is
 * positive, try to redo the lookup.  If the lookup results in a
 * different inode, then let the VFS invalidate the dentry and redo
 * the lookup once more.  If the lookup results in the same inode,
 * then refresh the attributes, timeouts and mark the dentry valid.
 */
static int bento_dentry_revalidate(struct dentry *entry, unsigned int flags)
{
	struct inode *inode;
	struct dentry *parent;
	struct bento_conn *fc;
	struct bento_inode *fi;
	int ret;

	inode = d_inode_rcu(entry);
	if (inode && is_bad_inode(inode))
		goto invalid;
	else if (time_before64(bento_dentry_time(entry), get_jiffies_64()) ||
		 (flags & LOOKUP_REVAL)) {
		struct fuse_entry_out outentry;
		struct bento_in inarg;
		struct bento_out outarg;
		struct bento_forget_link *forget;
		u64 attr_version;

		/* For negative dentries, always do a fresh lookup */
		if (!inode)
			goto invalid;

		ret = -ECHILD;
		if (flags & LOOKUP_RCU)
			goto out;

		fc = get_bento_conn(inode);

		forget = bento_alloc_forget();
		ret = -ENOMEM;
		if (!forget)
			goto out;

		attr_version = bento_get_attr_version(fc);

		parent = dget_parent(entry);
		bento_lookup_init(fc, &inarg, &outarg, get_node_id(d_inode(parent)),
                                 &entry->d_name, &outentry);
		down_read(&fc->fslock);
		ret = fc->dispatch(fc->fs_ptr, FUSE_LOOKUP, &inarg, &outarg);
		up_read(&fc->fslock);
		dput(parent);
		/* Zero nodeid is same as -ENOENT */
		if (!ret && !outentry.nodeid)
			ret = -ENOENT;
		if (!ret) {
			fi = get_bento_inode(inode);
			if (outentry.nodeid != get_node_id(inode)) {
				bento_queue_forget(fc, forget, outentry.nodeid, 1);
				goto invalid;
			}
			spin_lock(&fc->lock);
			fi->nlookup++;
			spin_unlock(&fc->lock);
		}
		kfree(forget);
		if (ret == -ENOMEM)
			goto out;
		if (ret || (outentry.attr.mode ^ inode->i_mode) & S_IFMT)
			goto invalid;

		forget_all_cached_acls(inode);
		bento_change_attributes(inode, &outentry.attr,
				       entry_attr_timeout(&outentry),
				       attr_version);
		bento_change_entry_timeout(entry, &outentry);
	}
	ret = 1;
out:
	return ret;

invalid:
	ret = 0;
	goto out;
}

static int invalid_nodeid(u64 nodeid)
{
	return !nodeid || nodeid == FUSE_ROOT_ID;
}

static int bento_dentry_init(struct dentry *dentry)
{
	dentry->d_fsdata = kzalloc(sizeof(union bento_dentry), GFP_KERNEL);

	return dentry->d_fsdata ? 0 : -ENOMEM;
}
static void bento_dentry_release(struct dentry *dentry)
{
	union bento_dentry *fd = dentry->d_fsdata;

	kfree_rcu(fd, rcu);
}

const struct dentry_operations bento_dentry_operations = {
	.d_revalidate	= bento_dentry_revalidate,
	.d_init		= bento_dentry_init,
	.d_release	= bento_dentry_release,
};

const struct dentry_operations bento_root_dentry_operations = {
	.d_init		= bento_dentry_init,
	.d_release	= bento_dentry_release,
};

int bento_valid_type(int m)
{
	return S_ISREG(m) || S_ISDIR(m) || S_ISLNK(m) || S_ISCHR(m) ||
		S_ISBLK(m) || S_ISFIFO(m) || S_ISSOCK(m);
}

int bento_lookup_name(struct super_block *sb, u64 nodeid, const struct qstr *name,
		     struct fuse_entry_out *outentry, struct inode **inode)
{
	struct bento_conn *fc = get_bento_conn_super(sb);
	struct bento_forget_link *forget;
	u64 attr_version;
	int err;
	struct bento_in inarg;
	struct bento_out outarg;
	

	*inode = NULL;
	err = -ENAMETOOLONG;
	if (name->len > BENTO_NAME_MAX)
		goto out;


	forget = bento_alloc_forget();
	err = -ENOMEM;
	if (!forget)
		goto out;

	attr_version = bento_get_attr_version(fc);

	bento_lookup_init(fc, &inarg, &outarg, nodeid, name, outentry);
	down_read(&fc->fslock);
	err = fc->dispatch(fc->fs_ptr, FUSE_LOOKUP, &inarg, &outarg);
	up_read(&fc->fslock);
	/* Zero nodeid is same as -ENOENT, but with valid timeout */
	if (err || !outentry->nodeid)
		goto out_put_forget;

	err = -EIO;
	if (!outentry->nodeid)
		goto out_put_forget;
	if (!bento_valid_type(outentry->attr.mode))
		goto out_put_forget;

	*inode = bento_iget(sb, outentry->nodeid, outentry->generation,
			   &outentry->attr, entry_attr_timeout(outentry),
			   attr_version);
	err = -ENOMEM;
	if (!*inode) {
		bento_queue_forget(fc, forget, outentry->nodeid, 1);
		goto out;
	}
	err = 0;

 out_put_forget:
	kfree(forget);
 out:
	return err;
}

static struct dentry *bento_lookup(struct inode *dir, struct dentry *entry,
				  unsigned int flags)
{
	int err;
	struct fuse_entry_out outarg;
	struct inode *inode;
	struct dentry *newent;
	bool outarg_valid = true;

	bento_lock_inode(dir);
	err = bento_lookup_name(dir->i_sb, get_node_id(dir), &entry->d_name,
			       &outarg, &inode);
	bento_unlock_inode(dir);
	if (err == -ENOENT) {
		outarg_valid = false;
		err = 0;
	}
	if (err)
		goto out_err;

	err = -EIO;
	if (inode && get_node_id(inode) == FUSE_ROOT_ID)
		goto out_iput;

	newent = d_splice_alias(inode, entry);
	err = PTR_ERR(newent);
	if (IS_ERR(newent))
		goto out_err;

	entry = newent ? newent : entry;
	if (outarg_valid)
		bento_change_entry_timeout(entry, &outarg);
	else
		bento_invalidate_entry_cache(entry);

	return newent;

 out_iput:
	iput(inode);
 out_err:
	return ERR_PTR(err);
}

/*
 * Atomic create+open operation
 *
 * If the filesystem doesn't support this, then fall back to separate
 * 'mknod' + 'open' requests.
 */
static int bento_create_open(struct inode *dir, struct dentry *entry,
			    struct file *file, unsigned flags,
			    umode_t mode, int *opened)
{
	int err;
	struct inode *inode;
	struct bento_conn *fc = get_bento_conn(dir);
	struct bento_forget_link *forget;
	struct fuse_create_in inarg;
	struct fuse_open_out outopen;
	struct fuse_entry_out outentry;
	struct bento_in in;
	struct bento_out out;
	struct bento_file *ff;

	/* Userspace expects S_IFREG in create mode */
	BUG_ON((mode & S_IFMT) != S_IFREG);

	forget = bento_alloc_forget();
	err = -ENOMEM;
	if (!forget)
		goto out_err;

	err = -ENOMEM;
	ff = bento_file_alloc(fc);
	if (!ff)
		goto out_put_forget_req;

	if (!fc->dont_mask)
		mode &= ~current_umask();

	flags &= ~O_NOCTTY;
	memset(&inarg, 0, sizeof(inarg));
	memset(&outentry, 0, sizeof(outentry));
	inarg.flags = flags;
	inarg.mode = mode;
	inarg.umask = current_umask();
	in.h.opcode = FUSE_CREATE;
        in.h.nodeid = get_node_id(dir);
        in.numargs = 2;
        in.args[0].size = sizeof(inarg);
        in.args[0].value = &inarg;
        in.args[1].size = entry->d_name.len + 1;
        in.args[1].value = entry->d_name.name;
        out.numargs = 2;
        out.args[0].size = sizeof(outentry);
        out.args[0].value = &outentry;
        out.args[1].size = sizeof(outopen);
        out.args[1].value = &outopen;
	down_read(&fc->fslock);
	err = fc->dispatch(fc->fs_ptr, FUSE_CREATE, &in, &out);
	up_read(&fc->fslock);
	if (err)
		goto out_free_ff;

	err = -EIO;
	if (!S_ISREG(outentry.attr.mode) || invalid_nodeid(outentry.nodeid))
		goto out_free_ff;

	ff->fh = outopen.fh;
	ff->nodeid = outentry.nodeid;
	ff->open_flags = outopen.open_flags;
	inode = bento_iget(dir->i_sb, outentry.nodeid, outentry.generation,
			  &outentry.attr, entry_attr_timeout(&outentry), 0);
	if (!inode) {
		flags &= ~(O_CREAT | O_EXCL | O_TRUNC);
		bento_sync_release(ff, flags);
		bento_queue_forget(fc, forget, outentry.nodeid, 1);
		err = -ENOMEM;
		goto out_err;
	}
	kfree(forget);
	d_instantiate(entry, inode);
	bento_change_entry_timeout(entry, &outentry);
	bento_invalidate_attr(dir);
	err = finish_open(file, entry, generic_file_open);
	if (err) {
		bento_sync_release(ff, flags);
	} else {
		file->private_data = ff;
		bento_finish_open(inode, file);
	}
	return err;

out_free_ff:
	bento_file_free(ff);
out_put_forget_req:
	kfree(forget);
out_err:
	return err;
}
static int bento_mknod(struct user_namespace *us,struct inode *, struct dentry *, umode_t, unsigned int);
static int bento_atomic_open(struct inode *dir, struct dentry *entry,
			    struct file *file, unsigned flags,
			    umode_t mode)
{
	int err;
	struct bento_conn *fc = get_bento_conn(dir);
	struct dentry *res = NULL;

	if (d_in_lookup(entry)) {
		res = bento_lookup(dir, entry, 0);
		if (IS_ERR(res))
			return PTR_ERR(res);

		if (res)
			entry = res;
	}

	if (!(flags & O_CREAT) || d_really_is_positive(entry))
		goto no_open;

	if (fc->no_create)
		goto mknod;

	err = bento_create_open(dir, entry, file, flags, mode, (void *)0);
	if (err == -ENOSYS) {
		fc->no_create = 1;
		goto mknod;
	}
out_dput:
	dput(res);
	return err;

mknod:
	err = bento_mknod(&init_us, dir, entry, mode, 0);
	if (err)
		goto out_dput;
no_open:
	return finish_no_open(file, res);
}

/*
 * Code shared between mknod, mkdir, symlink and link
 */
static int create_new_entry(struct bento_conn *fc, struct bento_args *args,
			    struct inode *dir, struct dentry *entry,
			    umode_t mode)
{
	struct fuse_entry_out outarg;
	struct inode *inode;
	struct bento_forget_link *forget;
	int err = 0;
	struct bento_in in;
	struct bento_out out;

	forget = bento_alloc_forget();
	if (!forget)
		return -ENOMEM;

	memset(&outarg, 0, sizeof(outarg));

	in.h.opcode = args->in.h.opcode;
	in.numargs = args->in.numargs;
        in.args[0].size = args->in.args[0].size;
        in.args[0].value = args->in.args[0].value;
        in.args[1].size = args->in.args[1].size;
        in.args[1].value = args->in.args[1].value;
	in.h.nodeid = get_node_id(dir);
        out.numargs = 1;
        out.args[0].size = sizeof(outarg);
        out.args[0].value = &outarg;
 
	down_read(&fc->fslock);
	err = fc->dispatch(fc->fs_ptr, args->in.h.opcode, &in, &out);
	up_read(&fc->fslock);
	if (err)
		goto out_put_forget_req;

	err = -EIO;
	if (invalid_nodeid(outarg.nodeid))
		goto out_put_forget_req;

	if ((outarg.attr.mode ^ mode) & S_IFMT)
		goto out_put_forget_req;

	inode = bento_iget(dir->i_sb, outarg.nodeid, outarg.generation,
			  &outarg.attr, entry_attr_timeout(&outarg), 0);
	if (!inode) {
		bento_queue_forget(fc, forget, outarg.nodeid, 1);
		return -ENOMEM;
	}
	kfree(forget);

	d_instantiate(entry, inode);

	bento_change_entry_timeout(entry, &outarg);
	bento_invalidate_attr(dir);
	return 0;

 out_put_forget_req:
	kfree(forget);
	return err;
}

static int bento_mknod(struct user_namespace *us,struct inode *dir, struct dentry *entry, umode_t mode,unsigned int rdev)
{
	struct fuse_mknod_in inarg;
	struct bento_conn *fc = get_bento_conn(dir);
	BENTO_ARGS(args);

	if (!fc->dont_mask)
		mode &= ~current_umask();

	memset(&inarg, 0, sizeof(inarg));
	inarg.mode = mode;
	inarg.rdev = new_encode_dev(rdev);
	inarg.umask = current_umask();
	args.in.h.opcode = FUSE_MKNOD;
	args.in.numargs = 2;
	args.in.args[0].size = sizeof(inarg);
	args.in.args[0].value = &inarg;
	args.in.args[1].size = entry->d_name.len + 1;
	args.in.args[1].value = entry->d_name.name;
	return create_new_entry(fc, &args, dir, entry, mode);
}

static int bento_create(struct user_namespace *us, struct inode *dir, struct dentry *entry, umode_t mode,
		       bool excl)
{
	return bento_mknod(us, dir, entry, mode, 0);
}

static int bento_mkdir(struct user_namespace *us, struct inode *dir, struct dentry *entry, umode_t mode)
{
	struct fuse_mkdir_in inarg;
	struct bento_conn *fc = get_bento_conn(dir);
	BENTO_ARGS(args);

	if (!fc->dont_mask)
		mode &= ~current_umask();

	memset(&inarg, 0, sizeof(inarg));
	inarg.mode = mode;
	inarg.umask = current_umask();
	args.in.h.opcode = FUSE_MKDIR;
	args.in.numargs = 2;
	args.in.args[0].size = sizeof(inarg);
	args.in.args[0].value = &inarg;
	args.in.args[1].size = entry->d_name.len + 1;
	args.in.args[1].value = entry->d_name.name;
	return create_new_entry(fc, &args, dir, entry, S_IFDIR);
}

static int bento_symlink(struct user_namespace *us, struct inode *dir, struct dentry *entry,
			const char *link)
{
	struct bento_conn *fc = get_bento_conn(dir);
	unsigned len = strlen(link) + 1;
	BENTO_ARGS(args);

	args.in.h.opcode = FUSE_SYMLINK;
	args.in.numargs = 2;
	args.in.args[0].size = entry->d_name.len + 1;
	args.in.args[0].value = entry->d_name.name;
	args.in.args[1].size = len;
	args.in.args[1].value = link;
	return create_new_entry(fc, &args, dir, entry, S_IFLNK);
}

void bento_update_ctime(struct inode *inode)
{
	if (!IS_NOCMTIME(inode)) {
		inode->i_ctime = current_time(inode);
		mark_inode_dirty_sync(inode);
	}
}

static int bento_unlink(struct inode *dir, struct dentry *entry)
{
	int err;
	struct bento_conn *fc = get_bento_conn(dir);
	struct bento_in in;
	struct bento_out out;
	in.h.opcode = FUSE_UNLINK;
        in.h.nodeid = get_node_id(dir);
        in.numargs = 1;
        in.args[0].size = entry->d_name.len + 1;
        in.args[0].value = entry->d_name.name;
	out.numargs = 0;
	down_read(&fc->fslock);
	err = fc->dispatch(fc->fs_ptr, FUSE_UNLINK, &in, &out);
	up_read(&fc->fslock);
	if (!err) {
		struct inode *inode = d_inode(entry);
		struct bento_inode *fi = get_bento_inode(inode);

		spin_lock(&fc->lock);
		fi->attr_version = ++fc->attr_version;
		/*
		 * If i_nlink == 0 then unlink doesn't make sense, yet this can
		 * happen if userspace filesystem is careless.  It would be
		 * difficult to enforce correct nlink usage so just ignore this
		 * condition here
		 */
		if (inode->i_nlink > 0)
			drop_nlink(inode);
		spin_unlock(&fc->lock);
		bento_invalidate_attr(inode);
		bento_invalidate_attr(dir);
		bento_invalidate_entry_cache(entry);
		bento_update_ctime(inode);
	} else if (err == -EINTR)
		bento_invalidate_entry(entry);
	return err;
}

static int bento_rmdir(struct inode *dir, struct dentry *entry)
{
	int err;
	struct bento_conn *fc = get_bento_conn(dir);
	struct bento_in in;
	struct bento_out out;
	in.h.opcode = FUSE_RMDIR;
        in.h.nodeid = get_node_id(dir);
        in.numargs = 1;
        in.args[0].size = entry->d_name.len + 1;
        in.args[0].value = entry->d_name.name;
	out.numargs = 0;

	down_read(&fc->fslock);
	err = fc->dispatch(fc->fs_ptr, FUSE_RMDIR, &in, &out);
	up_read(&fc->fslock);
	if (!err) {
		clear_nlink(d_inode(entry));
		bento_invalidate_attr(dir);
		bento_invalidate_entry_cache(entry);
	} else if (err == -EINTR)
		bento_invalidate_entry(entry);
	return err;
}

static int bento_rename_common(struct inode *olddir, struct dentry *oldent,
			      struct inode *newdir, struct dentry *newent,
			      unsigned int flags, int opcode, size_t argsize)
{
	int err;
	struct fuse_rename2_in inarg;
	struct bento_conn *fc = get_bento_conn(olddir);
	struct bento_in in;
	struct bento_out out;

	memset(&inarg, 0, argsize);
	inarg.newdir = get_node_id(newdir);
	inarg.flags = flags;
        in.h.opcode = opcode;
        in.h.nodeid = get_node_id(olddir);
        in.numargs = 3;
        in.args[0].size = argsize;
        in.args[0].value = &inarg;
        in.args[1].size = oldent->d_name.len + 1;
        in.args[1].value = oldent->d_name.name;
        in.args[2].size = newent->d_name.len + 1;
        in.args[2].value = newent->d_name.name;

	down_read(&fc->fslock);
	err = fc->dispatch(fc->fs_ptr, opcode, &in, &out);
	up_read(&fc->fslock);
	if (!err) {
		/* ctime changes */
		bento_invalidate_attr(d_inode(oldent));
		bento_update_ctime(d_inode(oldent));

		if (flags & RENAME_EXCHANGE) {
			bento_invalidate_attr(d_inode(newent));
			bento_update_ctime(d_inode(newent));
		}

		bento_invalidate_attr(olddir);
		if (olddir != newdir)
			bento_invalidate_attr(newdir);

		/* newent will end up negative */
		if (!(flags & RENAME_EXCHANGE) && d_really_is_positive(newent)) {
			bento_invalidate_attr(d_inode(newent));
			bento_invalidate_entry_cache(newent);
			bento_update_ctime(d_inode(newent));
		}
	} else if (err == -EINTR) {
		/* If request was interrupted, DEITY only knows if the
		   rename actually took place.  If the invalidation
		   fails (e.g. some process has CWD under the renamed
		   directory), then there can be inconsistency between
		   the dcache and the real filesystem.  Tough luck. */
		bento_invalidate_entry(oldent);
		if (d_really_is_positive(newent))
			bento_invalidate_entry(newent);
	}

	return err;
}

static int bento_rename2(struct user_namespace *us, struct inode *olddir, struct dentry *oldent,
			struct inode *newdir, struct dentry *newent,
			unsigned int flags)
{
	struct bento_conn *fc = get_bento_conn(olddir);
	int err;

	if (flags & ~(RENAME_NOREPLACE | RENAME_EXCHANGE))
		return -EINVAL;

	if (flags) {
		if (fc->no_rename2 || fc->minor < 23)
			return -EINVAL;

		err = bento_rename_common(olddir, oldent, newdir, newent, flags,
					 FUSE_RENAME2,
					 sizeof(struct fuse_rename2_in));
		if (err == -ENOSYS) {
			fc->no_rename2 = 1;
			err = -EINVAL;
		}
	} else {
		err = bento_rename_common(olddir, oldent, newdir, newent, 0,
					 FUSE_RENAME,
					 sizeof(struct fuse_rename_in));
	}

	return err;
}

static int bento_link(struct dentry *entry, struct inode *newdir,
		     struct dentry *newent)
{
	int err;
	struct fuse_link_in inarg;
	struct inode *inode = d_inode(entry);
	struct bento_conn *fc = get_bento_conn(inode);
	BENTO_ARGS(args);

	memset(&inarg, 0, sizeof(inarg));
	inarg.oldnodeid = get_node_id(inode);
	args.in.h.opcode = FUSE_LINK;
	args.in.numargs = 2;
	args.in.args[0].size = sizeof(inarg);
	args.in.args[0].value = &inarg;
	args.in.args[1].size = newent->d_name.len + 1;
	args.in.args[1].value = newent->d_name.name;
	err = create_new_entry(fc, &args, newdir, newent, inode->i_mode);
	/* Contrary to "normal" filesystems it can happen that link
	   makes two "logical" inodes point to the same "physical"
	   inode.  We invalidate the attributes of the old one, so it
	   will reflect changes in the backing inode (link count,
	   etc.)
	*/
	if (!err) {
		struct bento_inode *fi = get_bento_inode(inode);

		spin_lock(&fc->lock);
		fi->attr_version = ++fc->attr_version;
		inc_nlink(inode);
		spin_unlock(&fc->lock);
		bento_invalidate_attr(inode);
		bento_update_ctime(inode);
	} else if (err == -EINTR) {
		bento_invalidate_attr(inode);
	}
	return err;
}

static void bento_fillattr(struct inode *inode, struct fuse_attr *attr,
			  struct kstat *stat)
{
	unsigned int blkbits;
	struct bento_conn *fc = get_bento_conn(inode);

	/* see the comment in bento_change_attributes() */
	if (fc->writeback_cache && S_ISREG(inode->i_mode)) {
		attr->size = i_size_read(inode);
		attr->mtime = inode->i_mtime.tv_sec;
		attr->mtimensec = inode->i_mtime.tv_nsec;
		attr->ctime = inode->i_ctime.tv_sec;
		attr->ctimensec = inode->i_ctime.tv_nsec;
	}

	stat->dev = inode->i_sb->s_dev;
	stat->ino = attr->ino;
	stat->mode = (inode->i_mode & S_IFMT) | (attr->mode & 07777);
	stat->nlink = attr->nlink;
	stat->uid = make_kuid(&init_user_ns, attr->uid);
	stat->gid = make_kgid(&init_user_ns, attr->gid);
	stat->rdev = inode->i_rdev;
	stat->atime.tv_sec = attr->atime;
	stat->atime.tv_nsec = attr->atimensec;
	stat->mtime.tv_sec = attr->mtime;
	stat->mtime.tv_nsec = attr->mtimensec;
	stat->ctime.tv_sec = attr->ctime;
	stat->ctime.tv_nsec = attr->ctimensec;
	stat->size = attr->size;
	stat->blocks = attr->blocks;

	if (attr->blksize != 0)
		blkbits = ilog2(attr->blksize);
	else
		blkbits = inode->i_sb->s_blocksize_bits;

	stat->blksize = 1 << blkbits;
}

static int bento_do_getattr(struct inode *inode, struct kstat *stat,
			   struct file *file)
{
	int err;
	struct fuse_getattr_in inarg;
	struct fuse_attr_out outarg;
	struct bento_conn *fc = get_bento_conn(inode);
	u64 attr_version;
	struct bento_in bento_inarg;
	struct bento_out bento_outarg;

	attr_version = bento_get_attr_version(fc);

	memset(&inarg, 0, sizeof(inarg));
	memset(&outarg, 0, sizeof(outarg));
	/* Directories have separate file-handle space */
	if (file && S_ISREG(inode->i_mode)) {
		struct bento_file *ff = file->private_data;

		inarg.getattr_flags |= FUSE_GETATTR_FH;
		inarg.fh = ff->fh;
	}
	bento_inarg.h.opcode = FUSE_GETATTR;
        bento_inarg.h.nodeid = get_node_id(inode);
        bento_inarg.numargs = 1;
        bento_inarg.args[0].size = sizeof(inarg);
        bento_inarg.args[0].value = &inarg;
        bento_outarg.numargs = 1;
        bento_outarg.args[0].size = sizeof(outarg);
        bento_outarg.args[0].value = &outarg;
	down_read(&fc->fslock);
	err = fc->dispatch(fc->fs_ptr, FUSE_GETATTR, &bento_inarg, &bento_outarg);
	up_read(&fc->fslock);
	if (!err) {
		if ((inode->i_mode ^ outarg.attr.mode) & S_IFMT) {
			make_bad_inode(inode);
			err = -EIO;
		} else {
			bento_change_attributes(inode, &outarg.attr,
					       attr_timeout(&outarg),
					       attr_version);
			if (stat)
				bento_fillattr(inode, &outarg.attr, stat);
		}
	}
	return err;
}

static int bento_update_get_attr(struct inode *inode, struct file *file,
				struct kstat *stat)
{
	struct bento_inode *fi = get_bento_inode(inode);
	int err = 0;

	if (time_before64(fi->i_time, get_jiffies_64())) {
		forget_all_cached_acls(inode);
		err = bento_do_getattr(inode, stat, file);
	} else if (stat) {
		generic_fillattr(&init_us, inode, stat);
		stat->mode = fi->orig_i_mode;
		stat->ino = fi->orig_ino;
	}

	return err;
}

int bento_update_attributes(struct inode *inode, struct file *file)
{
	return bento_update_get_attr(inode, file, NULL);
}

int bento_reverse_inval_entry(struct super_block *sb, u64 parent_nodeid,
			     u64 child_nodeid, struct qstr *name)
{
	int err = -ENOTDIR;
	struct inode *parent;
	struct dentry *dir;
	struct dentry *entry;

	parent = ilookup5(sb, parent_nodeid, bento_inode_eq, &parent_nodeid);
	if (!parent)
		return -ENOENT;

	inode_lock(parent);
	if (!S_ISDIR(parent->i_mode))
		goto unlock;

	err = -ENOENT;
	dir = d_find_alias(parent);
	if (!dir)
		goto unlock;

	name->hash = full_name_hash(dir, name->name, name->len);
	entry = d_lookup(dir, name);
	dput(dir);
	if (!entry)
		goto unlock;

	bento_invalidate_attr(parent);
	bento_invalidate_entry(entry);

	if (child_nodeid != 0 && d_really_is_positive(entry)) {
		inode_lock(d_inode(entry));
		if (get_node_id(d_inode(entry)) != child_nodeid) {
			err = -ENOENT;
			goto badentry;
		}
		if (d_mountpoint(entry)) {
			err = -EBUSY;
			goto badentry;
		}
		if (d_is_dir(entry)) {
			shrink_dcache_parent(entry);
			if (!simple_empty(entry)) {
				err = -ENOTEMPTY;
				goto badentry;
			}
			d_inode(entry)->i_flags |= S_DEAD;
		}
		dont_mount(entry);
		clear_nlink(d_inode(entry));
		err = 0;
 badentry:
		inode_unlock(d_inode(entry));
		if (!err)
			d_delete(entry);
	} else {
		err = 0;
	}
	dput(entry);

 unlock:
	inode_unlock(parent);
	iput(parent);
	return err;
}

/*
 * Calling into a user-controlled filesystem gives the filesystem
 * daemon ptrace-like capabilities over the current process.  This
 * means, that the filesystem daemon is able to record the exact
 * filesystem operations performed, and can also control the behavior
 * of the requester process in otherwise impossible ways.  For example
 * it can delay the operation for arbitrary length of time allowing
 * DoS against the requester.
 *
 * For this reason only those processes can call into the filesystem,
 * for which the owner of the mount has ptrace privilege.  This
 * excludes processes started by other users, suid or sgid processes.
 */
int bento_allow_current_process(struct bento_conn *fc)
{
	const struct cred *cred;

	if (fc->allow_other)
		return 1;

	cred = current_cred();
	if (uid_eq(cred->euid, fc->user_id) &&
	    uid_eq(cred->suid, fc->user_id) &&
	    uid_eq(cred->uid,  fc->user_id) &&
	    gid_eq(cred->egid, fc->group_id) &&
	    gid_eq(cred->sgid, fc->group_id) &&
	    gid_eq(cred->gid,  fc->group_id))
		return 1;

	return 0;
}

static int bento_access(struct inode *inode, int mask)
{
	struct bento_conn *fc = get_bento_conn(inode);
	struct fuse_access_in inarg;
	struct bento_in in;
	struct bento_out out;
	int err;

	BUG_ON(mask & MAY_NOT_BLOCK);

	if (fc->no_access)
		return 0;

	memset(&inarg, 0, sizeof(inarg));
	inarg.mask = mask & (MAY_READ | MAY_WRITE | MAY_EXEC);
	in.h.opcode = FUSE_ACCESS;
        in.h.nodeid = get_node_id(inode);
        in.numargs = 1;
        in.args[0].size = sizeof(inarg);
        in.args[0].value = &inarg;
	down_read(&fc->fslock);
	err = fc->dispatch(fc->fs_ptr, FUSE_ACCESS, &in, &out);
	up_read(&fc->fslock);
	if (err == -ENOSYS) {
		fc->no_access = 1;
		err = 0;
	}
	return err;
}

static int bento_perm_getattr(struct inode *inode, int mask)
{
	if (mask & MAY_NOT_BLOCK)
		return -ECHILD;

	forget_all_cached_acls(inode);
	return bento_do_getattr(inode, NULL, NULL);
}

/*
 * Check permission.  The two basic access models of Bento are:
 *
 * 1) Local access checking ('default_permissions' mount option) based
 * on file mode.  This is the plain old disk filesystem permission
 * modell.
 *
 * 2) "Remote" access checking, where server is responsible for
 * checking permission in each inode operation.  An exception to this
 * is if ->permission() was invoked from sys_access() in which case an
 * access request is sent.  Execute permission is still checked
 * locally based on file mode.
 */
static int bento_permission(struct user_namespace* us, struct inode *inode, int mask)
{
	struct bento_conn *fc = get_bento_conn(inode);
	bool refreshed = false;
	int err = 0;

	if (!bento_allow_current_process(fc))
		return -EACCES;

	/*
	 * If attributes are needed, refresh them before proceeding
	 */
	if (fc->default_permissions ||
	    ((mask & MAY_EXEC) && S_ISREG(inode->i_mode))) {
		struct bento_inode *fi = get_bento_inode(inode);

		if (time_before64(fi->i_time, get_jiffies_64())) {
			refreshed = true;

			err = bento_perm_getattr(inode, mask);
			if (err) {
				return err;
			}
		}
	}

	if (fc->default_permissions) {
		err = generic_permission(us ,inode, mask);

		/* If permission is denied, try to refresh file
		   attributes.  This is also needed, because the root
		   node will at first have no permissions */
		if (err == -EACCES && !refreshed) {
			err = bento_perm_getattr(inode, mask);
			if (!err)
				err = generic_permission(us, inode, mask);
		}

		/* Note: the opposite of the above test does not
		   exist.  So if permissions are revoked this won't be
		   noticed immediately, only after the attribute
		   timeout has expired */
	} else if (mask & (MAY_ACCESS | MAY_CHDIR)) {
		err = bento_access(inode, mask);
	} else if ((mask & MAY_EXEC) && S_ISREG(inode->i_mode)) {
		if (!(inode->i_mode & S_IXUGO)) {
			if (refreshed)
				return -EACCES;

			err = bento_perm_getattr(inode, mask);
			if (!err && !(inode->i_mode & S_IXUGO))
				return -EACCES;
		}
	}
	return err;
}

static int parse_dirfile(char *buf, size_t nbytes, struct file *file,
			 struct dir_context *ctx)
{
	while (nbytes >= FUSE_NAME_OFFSET) {
		struct fuse_dirent *dirent = (struct fuse_dirent *) buf;
		size_t reclen = FUSE_DIRENT_SIZE(dirent);
		if (!dirent->namelen || dirent->namelen > BENTO_NAME_MAX)
			return -EIO;
		if (reclen > nbytes)
			break;
		if (memchr(dirent->name, '/', dirent->namelen) != NULL)
			return -EIO;

		if (!dir_emit(ctx, dirent->name, dirent->namelen,
			       dirent->ino, dirent->type))
			break;

		buf += reclen;
		nbytes -= reclen;
		ctx->pos = dirent->off;
	}

	return 0;
}

static int bento_readdir(struct file *file, struct dir_context *ctx)
{
	int err;
	size_t nbytes;
	struct page *page;
	struct inode *inode = file_inode(file);
	struct bento_conn *fc = get_bento_conn(inode);
	struct bento_req *req;
	char *buf;
	struct bento_buffer send_buf;
	struct bento_in in;
	struct bento_out out;
	struct fuse_read_in inarg;

	if (is_bad_inode(inode))
		return -EIO;

	req = bento_request_alloc(1);
	if (IS_ERR(req))
		return PTR_ERR(req);

	page = alloc_page(GFP_KERNEL);
	if (!page) {
		bento_put_request(fc, req);
		return -ENOMEM;
	}

	req->out.argpages = 1;
	req->num_pages = 1;
	req->pages[0] = page;
	req->page_descs[0].length = PAGE_SIZE;

	buf = kmap(page);
	bento_lock_inode(inode);
	send_buf.ptr = buf;
	send_buf.bufsize = PAGE_SIZE;
	send_buf.drop = false;
	bento_read_fill(&in, &out, &inarg, &send_buf, file, ctx->pos, PAGE_SIZE, FUSE_READDIR);
	down_read(&fc->fslock);
	err = fc->dispatch(fc->fs_ptr, FUSE_READDIR, &in, &out);
	up_read(&fc->fslock);
	nbytes = out.args[0].size;
	bento_unlock_inode(inode);
	bento_request_free(req);
	if (!err) {
		err = parse_dirfile(page_address(page), nbytes, file, ctx);
	}

	kunmap(page);
	__free_page(page);
	bento_invalidate_atime(inode);
	return err;
}

static const char *bento_get_link(struct dentry *dentry,
				 struct inode *inode,
				 struct delayed_call *done)
{
	struct bento_conn *fc = get_bento_conn(inode);
	char *link;
	ssize_t ret;
	struct bento_buffer buf;
	struct bento_in in;
	struct bento_out out;

	if (!dentry)
		return ERR_PTR(-ECHILD);

	link = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!link)
		return ERR_PTR(-ENOMEM);

	buf.ptr = link;
	buf.bufsize = PAGE_SIZE -1;
	buf.drop = false;

	out.page_zeroing = 1;
        out.argpages = 1;
        in.h.opcode = FUSE_READLINK;
        in.h.nodeid = get_node_id(inode);
        out.argvar = 1;
        out.numargs = 1;
        out.args[0].size = PAGE_SIZE - 1;
	out.args[0].value = &buf;

	down_read(&fc->fslock);
	ret = fc->dispatch(fc->fs_ptr, FUSE_READLINK, &in, &out);
	up_read(&fc->fslock);
	if (ret < 0) {
		kfree(link);
		link = ERR_PTR(ret);
	} else {
		link[ret] = '\0';
		set_delayed_call(done, kfree_link, link);
	}
	bento_invalidate_atime(inode);
	return link;
}

static int bento_dir_open(struct inode *inode, struct file *file)
{
	return bento_open_common(inode, file, true);
}

static int bento_dir_release(struct inode *inode, struct file *file)
{
	bento_release_common(file, FUSE_RELEASEDIR);

	return 0;
}

static int bento_dir_fsync(struct file *file, loff_t start, loff_t end,
			  int datasync)
{
	return bento_fsync_common(file, start, end, datasync, 1);
}

static long bento_dir_ioctl(struct file *file, unsigned int cmd,
			    unsigned long arg)
{
	struct bento_conn *fc = get_bento_conn(file->f_mapping->host);

	/* FUSE_IOCTL_DIR only supported for API version >= 7.18 */
	if (fc->minor < 18)
		return -ENOTTY;

	return bento_ioctl_common(file, cmd, arg, FUSE_IOCTL_DIR);
}

static long bento_dir_compat_ioctl(struct file *file, unsigned int cmd,
				   unsigned long arg)
{
	struct bento_conn *fc = get_bento_conn(file->f_mapping->host);

	if (fc->minor < 18)
		return -ENOTTY;

	return bento_ioctl_common(file, cmd, arg,
				 FUSE_IOCTL_COMPAT | FUSE_IOCTL_DIR);
}

static bool update_mtime(unsigned ivalid, bool trust_local_mtime)
{
	/* Always update if mtime is explicitly set  */
	if (ivalid & ATTR_MTIME_SET)
		return true;

	/* Or if kernel i_mtime is the official one */
	if (trust_local_mtime)
		return true;

	/* If it's an open(O_TRUNC) or an ftruncate(), don't update */
	if ((ivalid & ATTR_SIZE) && (ivalid & (ATTR_OPEN | ATTR_FILE)))
		return false;

	/* In all other cases update */
	return true;
}

static void iattr_to_fattr(struct iattr *iattr, struct fuse_setattr_in *arg,
			   bool trust_local_cmtime)
{
	unsigned ivalid = iattr->ia_valid;

	if (ivalid & ATTR_MODE)
		arg->valid |= FATTR_MODE,   arg->mode = iattr->ia_mode;
	if (ivalid & ATTR_UID)
		arg->valid |= FATTR_UID,    arg->uid = from_kuid(&init_user_ns, iattr->ia_uid);
	if (ivalid & ATTR_GID)
		arg->valid |= FATTR_GID,    arg->gid = from_kgid(&init_user_ns, iattr->ia_gid);
	if (ivalid & ATTR_SIZE)
		arg->valid |= FATTR_SIZE,   arg->size = iattr->ia_size;
	if (ivalid & ATTR_ATIME) {
		arg->valid |= FATTR_ATIME;
		arg->atime = iattr->ia_atime.tv_sec;
		arg->atimensec = iattr->ia_atime.tv_nsec;
		if (!(ivalid & ATTR_ATIME_SET))
			arg->valid |= FATTR_ATIME_NOW;
	}
	if ((ivalid & ATTR_MTIME) && update_mtime(ivalid, trust_local_cmtime)) {
		arg->valid |= FATTR_MTIME;
		arg->mtime = iattr->ia_mtime.tv_sec;
		arg->mtimensec = iattr->ia_mtime.tv_nsec;
		if (!(ivalid & ATTR_MTIME_SET) && !trust_local_cmtime)
			arg->valid |= FATTR_MTIME_NOW;
	}
	if ((ivalid & ATTR_CTIME) && trust_local_cmtime) {
		arg->valid |= FATTR_CTIME;
		arg->ctime = iattr->ia_ctime.tv_sec;
		arg->ctimensec = iattr->ia_ctime.tv_nsec;
	}
}

/*
 * Prevent concurrent writepages on inode
 *
 * This is done by adding a negative bias to the inode write counter
 * and waiting for all pending writes to finish.
 */
void bento_set_nowrite(struct inode *inode)
{
	struct bento_conn *fc = get_bento_conn(inode);
	struct bento_inode *fi = get_bento_inode(inode);

	BUG_ON(!inode_is_locked(inode));

	spin_lock(&fc->lock);
	BUG_ON(fi->writectr < 0);
	fi->writectr += BENTO_NOWRITE;
	spin_unlock(&fc->lock);
	wait_event(fi->page_waitq, fi->writectr == BENTO_NOWRITE);
}

/*
 * Allow writepages on inode
 *
 * Remove the bias from the writecounter and send any queued
 * writepages.
 */
static void __bento_release_nowrite(struct inode *inode)
{
	struct bento_inode *fi = get_bento_inode(inode);

	BUG_ON(fi->writectr != BENTO_NOWRITE);
	fi->writectr = 0;
	bento_flush_writepages(inode);
}

void bento_release_nowrite(struct inode *inode)
{
	struct bento_conn *fc = get_bento_conn(inode);

	spin_lock(&fc->lock);
	__bento_release_nowrite(inode);
	spin_unlock(&fc->lock);
}

/*
 * Flush inode->i_mtime to the server
 */
int bento_flush_times(struct inode *inode, struct bento_file *ff)
{
	struct bento_conn *fc = get_bento_conn(inode);
	struct fuse_setattr_in inarg;
	struct fuse_attr_out outarg;
	struct bento_in bento_inarg;
	struct bento_out bento_outarg;
        int err;

	memset(&inarg, 0, sizeof(inarg));
	memset(&outarg, 0, sizeof(outarg));

	inarg.valid = FATTR_MTIME;
	inarg.mtime = inode->i_mtime.tv_sec;
	inarg.mtimensec = inode->i_mtime.tv_nsec;
	if (fc->minor >= 23) {
		inarg.valid |= FATTR_CTIME;
		inarg.ctime = inode->i_ctime.tv_sec;
		inarg.ctimensec = inode->i_ctime.tv_nsec;
	}
	if (ff) {
		inarg.valid |= FATTR_FH;
		inarg.fh = ff->fh;
	}

	bento_inarg.h.opcode = FUSE_SETATTR;
        bento_inarg.h.nodeid = get_node_id(inode);
        bento_inarg.numargs = 1;
        bento_inarg.args[0].size = sizeof(inarg);
        bento_inarg.args[0].value = &inarg;
        bento_outarg.numargs = 1;
        bento_outarg.args[0].size = sizeof(outarg);
        bento_outarg.args[0].value = &outarg;
	down_read(&fc->fslock);
	err = fc->dispatch(fc->fs_ptr, FUSE_SETATTR, &bento_inarg,
			&bento_outarg);
	up_read(&fc->fslock);
	return err;
}

/*
 * Set attributes, and at the same time refresh them.
 *
 * Truncation is slightly complicated, because the 'truncate' request
 * may fail, in which case we don't want to touch the mapping.
 * vmtruncate() doesn't allow for this case, so do the rlimit checking
 * and the actual truncation by hand.
 */
int bento_do_setattr(struct dentry *dentry, struct iattr *attr,
		    struct file *file)
{
	struct inode *inode = d_inode(dentry);
	struct bento_conn *fc = get_bento_conn(inode);
	struct bento_inode *fi = get_bento_inode(inode);
	struct fuse_setattr_in inarg;
	struct fuse_attr_out outarg;
	struct bento_in bento_inarg;
	struct bento_out bento_outarg;
	bool is_truncate = false;
	bool is_wb = fc->writeback_cache;
	loff_t oldsize;
	int err;
	bool trust_local_cmtime = is_wb && S_ISREG(inode->i_mode);

	if (!fc->default_permissions)
		attr->ia_valid |= ATTR_FORCE;

	err = setattr_prepare(&init_us, dentry, attr);
	if (err)
		return err;

	if (attr->ia_valid & ATTR_OPEN) {
		if (fc->atomic_o_trunc)
			return 0;
		file = NULL;
	}

	if (attr->ia_valid & ATTR_SIZE)
		is_truncate = true;

	if (is_truncate) {
		bento_set_nowrite(inode);
		set_bit(BENTO_I_SIZE_UNSTABLE, &fi->state);
		if (trust_local_cmtime && attr->ia_size != inode->i_size)
			attr->ia_valid |= ATTR_MTIME | ATTR_CTIME;
	}

	memset(&inarg, 0, sizeof(inarg));
	memset(&outarg, 0, sizeof(outarg));
	iattr_to_fattr(attr, &inarg, trust_local_cmtime);
	if (file) {
		struct bento_file *ff = file->private_data;
		inarg.valid |= FATTR_FH;
		inarg.fh = ff->fh;
	}
	if (attr->ia_valid & ATTR_SIZE) {
		/* For mandatory locking in truncate */
		inarg.valid |= FATTR_LOCKOWNER;
		inarg.lock_owner = bento_lock_owner_id(fc, current->files);
	}
	bento_inarg.h.opcode = FUSE_SETATTR;
        bento_inarg.h.nodeid = get_node_id(inode);
        bento_inarg.numargs = 1;
        bento_inarg.args[0].size = sizeof(inarg);
        bento_inarg.args[0].value = &inarg;
        bento_outarg.numargs = 1;
        bento_outarg.args[0].size = sizeof(outarg);
        bento_outarg.args[0].value = &outarg;
	down_read(&fc->fslock);
	err = fc->dispatch(fc->fs_ptr, FUSE_SETATTR, &bento_inarg,
			&bento_outarg);
	up_read(&fc->fslock);
	if (err) {
		if (err == -EINTR)
			bento_invalidate_attr(inode);
		goto error;
	}

	if ((inode->i_mode ^ outarg.attr.mode) & S_IFMT) {
		make_bad_inode(inode);
		err = -EIO;
		goto error;
	}

	spin_lock(&fc->lock);
	/* the kernel maintains i_mtime locally */
	if (trust_local_cmtime) {
		if (attr->ia_valid & ATTR_MTIME)
			inode->i_mtime = attr->ia_mtime;
		if (attr->ia_valid & ATTR_CTIME)
			inode->i_ctime = attr->ia_ctime;
		/* FIXME: clear I_DIRTY_SYNC? */
	}

	bento_change_attributes_common(inode, &outarg.attr,
				      attr_timeout(&outarg));
	oldsize = inode->i_size;
	/* see the comment in bento_change_attributes() */
	if (!is_wb || is_truncate || !S_ISREG(inode->i_mode))
		i_size_write(inode, outarg.attr.size);

	if (is_truncate) {
		/* NOTE: this may release/reacquire fc->lock */
		__bento_release_nowrite(inode);
	}
	spin_unlock(&fc->lock);

	/*
	 * Only call invalidate_inode_pages2() after removing
	 * BENTO_NOWRITE, otherwise bento_launder_page() would deadlock.
	 */
	if ((is_truncate || !is_wb) &&
	    S_ISREG(inode->i_mode) && oldsize != outarg.attr.size) {
		truncate_pagecache(inode, outarg.attr.size);
		invalidate_inode_pages2(inode->i_mapping);
	}

	clear_bit(BENTO_I_SIZE_UNSTABLE, &fi->state);
	return 0;

error:
	if (is_truncate)
		bento_release_nowrite(inode);

	clear_bit(BENTO_I_SIZE_UNSTABLE, &fi->state);
	return err;
}

static int bento_setattr(struct user_namespace *us, struct dentry *entry, struct iattr *attr)
{
	struct inode *inode = d_inode(entry);
	struct bento_conn *fc = get_bento_conn(inode);
	struct file *file = (attr->ia_valid & ATTR_FILE) ? attr->ia_file : NULL;
	int ret;

	if (!bento_allow_current_process(get_bento_conn(inode)))
		return -EACCES;

	if (attr->ia_valid & (ATTR_KILL_SUID | ATTR_KILL_SGID)) {
		attr->ia_valid &= ~(ATTR_KILL_SUID | ATTR_KILL_SGID |
				    ATTR_MODE);

		/*
		 * The only sane way to reliably kill suid/sgid is to do it in
		 * the userspace filesystem
		 *
		 * This should be done on write(), truncate() and chown().
		 */
		if (!fc->handle_killpriv) {
			/*
			 * ia_mode calculation may have used stale i_mode.
			 * Refresh and recalculate.
			 */
			ret = bento_do_getattr(inode, NULL, file);
			if (ret)
				return ret;

			attr->ia_mode = inode->i_mode;
			if (inode->i_mode & S_ISUID) {
				attr->ia_valid |= ATTR_MODE;
				attr->ia_mode &= ~S_ISUID;
			}
			if ((inode->i_mode & (S_ISGID | S_IXGRP)) == (S_ISGID | S_IXGRP)) {
				attr->ia_valid |= ATTR_MODE;
				attr->ia_mode &= ~S_ISGID;
			}
		}
	}
	if (!attr->ia_valid)
		return 0;

	ret = bento_do_setattr(entry, attr, file);
	if (!ret) {
		/*
		 * If filesystem supports acls it may have updated acl xattrs in
		 * the filesystem, so forget cached acls for the inode.
		 */
		if (fc->posix_acl)
			forget_all_cached_acls(inode);

		/* Directory mode changed, may need to revalidate access */
		if (d_is_dir(entry) && (attr->ia_valid & ATTR_MODE))
			bento_invalidate_entry_cache(entry);
	}
	return ret;
}

static int bento_getattr(struct user_namespace* us, const struct path *path, struct kstat *stat,
			u32 request_mask, unsigned int flags)
{
	struct inode *inode = d_inode(path->dentry);
	struct bento_conn *fc = get_bento_conn(inode);

	if (!bento_allow_current_process(fc))
		return -EACCES;

	return bento_update_get_attr(inode, NULL, stat);
}

static const struct inode_operations bento_dir_inode_operations = {
	.lookup		= bento_lookup,
	.mkdir		= bento_mkdir,
	.symlink	= bento_symlink,
	.unlink		= bento_unlink,
	.rmdir		= bento_rmdir,
	.rename		= bento_rename2,
	.link		= bento_link,
	.setattr	= bento_setattr,
	.create		= bento_create,
	.atomic_open	= bento_atomic_open,
	.mknod		= bento_mknod,
	.permission	= bento_permission,
	.getattr	= bento_getattr,
	.listxattr	= bento_listxattr,
	.get_acl	= bento_get_acl,
	.set_acl	= bento_set_acl,
};

static const struct file_operations bento_dir_operations = {
	.llseek		= generic_file_llseek,
	.read		= generic_read_dir,
	.iterate_shared	= bento_readdir,
	.open		= bento_dir_open,
	.release	= bento_dir_release,
	.fsync		= bento_dir_fsync,
	.unlocked_ioctl	= bento_dir_ioctl,
	.compat_ioctl	= bento_dir_compat_ioctl,
};

static const struct inode_operations bento_common_inode_operations = {
	.setattr	= bento_setattr,
	.permission	= bento_permission,
	.getattr	= bento_getattr,
	.listxattr	= bento_listxattr,
	.get_acl	= bento_get_acl,
	.set_acl	= bento_set_acl,
};

static const struct inode_operations bento_symlink_inode_operations = {
	.setattr	= bento_setattr,
	.get_link	= bento_get_link,
	.getattr	= bento_getattr,
	.listxattr	= bento_listxattr,
};

void bento_init_common(struct inode *inode)
{
	inode->i_op = &bento_common_inode_operations;
}

void bento_init_dir(struct inode *inode)
{
	inode->i_op = &bento_dir_inode_operations;
	inode->i_fop = &bento_dir_operations;
}

void bento_init_symlink(struct inode *inode)
{
	inode->i_op = &bento_symlink_inode_operations;
}
