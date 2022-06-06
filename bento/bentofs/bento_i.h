/*
  Bento: Safe Rust file systems in the kernel
  Copyright (C) 2020  Samantha Miller, Kaiyuan Zhang, Danyang Zhuo, Tom
      Anderson, Ang Chen, University of Washington
  Copyright (C) 2001-2008  Miklos Szeredi <miklos@szeredi.hu>


  This program can be distributed under the terms of the GNU GPL.
  See the file COPYING.
*/

#ifndef _FS_BENTO_I_H
#define _FS_BENTO_I_H

#include <linux/fuse.h>
#include <linux/fs.h>
#include <linux/mount.h>
#include <linux/wait.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/mm.h>
#include <linux/backing-dev.h>
#include <linux/mutex.h>
#include <linux/rwsem.h>
#include <linux/rbtree.h>
#include <linux/poll.h>
#include <linux/workqueue.h>
#include <linux/kref.h>
#include <linux/xattr.h>
#include <linux/pid_namespace.h>
#include <linux/refcount.h>

/** Max number of pages that can be used in a single read request */
#define BENTO_MAX_PAGES_PER_REQ 32

/** Bias for fi->writectr, meaning new writepages must not be sent */
#define BENTO_NOWRITE INT_MIN

/** It could be as large as PATH_MAX, but would that have any uses? */
#define BENTO_NAME_MAX 1024

/** Number of dentries for each connection in the control filesystem */
#define BENTO_CTL_NUM_DENTRIES 5

/** Number of page pointers embedded in bento_req */
#define BENTO_REQ_INLINE_PAGES 1

#define BENTO_KERNEL_VERSION 1
#define BENTO_KERNEL_MINOR_VERSION 0

#define BENTO_UPDATE_PREPARE 8192
#define BENTO_UPDATE_TRANSFER 8193

/** List of active connections */
extern struct list_head bento_conn_list;

/** Global mutex protecting bento_conn_list and the control filesystem */
extern struct mutex bento_mutex;

/** Module parameters */
//extern unsigned max_user_bgreq;
//extern unsigned max_user_congthresh;

/* One forget request */
struct bento_forget_link {
	struct fuse_forget_one forget_one;
	struct bento_forget_link *next;
};

/** BENTO inode */
struct bento_inode {
	/** Inode data */
	struct inode inode;

	/** Unique ID, which identifies the inode between userspace
	 * and kernel */
	u64 nodeid;

	/** Number of lookups on this inode */
	u64 nlookup;

	/** The request used for sending the FORGET message */
	struct bento_forget_link *forget;

	/** Time in jiffies until the file attributes are valid */
	u64 i_time;

	/** The sticky bit in inode->i_mode may have been removed, so
	    preserve the original mode */
	umode_t orig_i_mode;

	/** 64 bit inode number */
	u64 orig_ino;

	/** Version of last attribute change */
	u64 attr_version;

	/** Files usable in writepage.  Protected by fc->lock */
	struct list_head write_files;

	/** Writepages pending on truncate or fsync */
	struct list_head queued_writes;

	/** Number of sent writes, a negative bias (BENTO_NOWRITE)
	 * means more writes are blocked */
	int writectr;

	/** Waitq for writepage completion */
	wait_queue_head_t page_waitq;

	/** List of writepage requestst (pending or sent) */
	struct list_head writepages;

	/** Miscellaneous bits describing inode state */
	unsigned long state;

	/** Lock for serializing lookup and readdir for back compatibility*/
	struct mutex mutex;
};

/** BENTO inode state bits */
enum {
	/** Advise readdirplus  */
	BENTO_I_ADVISE_RDPLUS,
	/** Initialized with readdirplus */
	BENTO_I_INIT_RDPLUS,
	/** An operation changing file size is in progress  */
	BENTO_I_SIZE_UNSTABLE,
};

struct bento_conn;

/** BENTO specific file data */
struct bento_file {
	/** Fuse connection for this file */
	struct bento_conn *fc;

	/** Request reserved for flush and release */
	struct bento_req *reserved_req;

	/** Kernel file handle guaranteed to be unique */
	u64 kh;

	/** File handle used by userspace */
	u64 fh;

	/** Node id of this file */
	u64 nodeid;

	/** Refcount */
	refcount_t count;

	/** FOPEN_* flags returned by open */
	u32 open_flags;

	/** Entry on inode's write_files list */
	struct list_head write_entry;

	/** RB node to be linked on bento_conn->polled_files */
	struct rb_node polled_node;

	/** Wait queue head for poll */
	wait_queue_head_t poll_wait;

	/** Has flock been performed on this file? */
	bool flock:1;
};

/** One input argument of a request */
struct bento_in_arg {
	unsigned size;
	const void *value;
};

/** The request input */
struct bento_in {
	/** The request header */
	struct fuse_in_header h;

	/** True if the data for the last argument is in req->pages */
	unsigned argpages:1;

	/** Number of arguments */
	unsigned numargs;

	/** Array of arguments */
	struct bento_in_arg args[3];
};

/** One output argument of a request */
struct bento_arg {
	unsigned size;
	void *value;
};

/** The request output */
struct bento_out {
	/** Header returned from userspace */
	struct fuse_out_header h;

	/*
	 * The following bitfields are not changed during the request
	 * processing
	 */

	/** Last argument is variable length (can be shorter than
	    arg->size) */
	unsigned argvar:1;

	/** Last argument is a list of pages to copy data to */
	unsigned argpages:1;

	/** Zero partially or not copied pages */
	unsigned page_zeroing:1;

	/** Pages may be replaced with new ones */
	unsigned page_replace:1;

	/** Number or arguments */
	unsigned numargs;

	/** Array of arguments */
	struct bento_arg args[2];
};

/** BENTO page descriptor */
struct bento_page_desc {
	unsigned int length;
	unsigned int offset;
};

struct bento_args {
	struct {
		struct {
			uint32_t opcode;
			uint64_t nodeid;
		} h;
		unsigned numargs;
		struct bento_in_arg args[3];

	} in;
	struct {
		unsigned argvar:1;
		unsigned numargs;
		struct bento_arg args[2];
	} out;
};

#define BENTO_ARGS(args) struct bento_args args = {}

/** The request IO state (for asynchronous processing) */
struct bento_io_priv {
	struct kref refcnt;
	int async;
	spinlock_t lock;
	unsigned reqs;
	ssize_t bytes;
	size_t size;
	__u64 offset;
	bool write;
	bool should_dirty;
	int err;
	struct kiocb *iocb;
	struct completion *done;
	bool blocking;
};

#define BENTO_IO_PRIV_SYNC(i) \
{					\
	.refcnt = KREF_INIT(1),		\
	.async = 0,			\
	.iocb = i,			\
}

/**
 * Request flags
 *
 * FR_ISREPLY:		set if the request has reply
 * FR_FORCE:		force sending of the request even if interrupted
 * FR_BACKGROUND:	request is sent in the background
 * FR_WAITING:		request is counted as "waiting"
 * FR_ABORTED:		the request was aborted
 * FR_INTERRUPTED:	the request has been interrupted
 * FR_LOCKED:		data is being copied to/from the request
 * FR_PENDING:		request is not yet in userspace
 * FR_SENT:		request is in userspace, waiting for an answer
 * FR_FINISHED:		request is finished
 * FR_PRIVATE:		request is on private list
 */
enum bento_req_flag {
	FR_ISREPLY,
	FR_FORCE,
	FR_BACKGROUND,
	FR_WAITING,
	FR_ABORTED,
	FR_INTERRUPTED,
	FR_LOCKED,
	FR_PENDING,
	FR_SENT,
	FR_FINISHED,
	FR_PRIVATE,
};

struct bento_init_in {
	uint32_t	major;
	uint32_t	minor;
	uint32_t	max_readahead;
	uint32_t	flags;
	const char	*devname;
};

/**
 * A request to the client
 *
 * .waitq.lock protects the following fields:
 *   - FR_ABORTED
 *   - FR_LOCKED (may also be modified under fc->lock, tested under both)
 */
struct bento_req {
	/** This can be on either pending processing or io lists in
	    bento_conn */
	struct list_head list;

	/** Entry on the interrupts list  */
	struct list_head intr_entry;

	/** refcount */
	refcount_t count;

	/** Unique ID for the interrupt request */
	u64 intr_unique;

	/* Request flags, updated with test/set/clear_bit() */
	unsigned long flags;

	/** The request input */
	struct bento_in in;

	/** The request output */
	struct bento_out out;

	/** Used to wake up the task waiting for completion of request*/
	wait_queue_head_t waitq;

	/** Data for asynchronous requests */
	union {
		struct {
			struct fuse_release_in in;
			struct inode *inode;
		} release;
		struct bento_init_in init_in;
		struct fuse_init_out init_out;
		struct cuse_init_in cuse_init_in;
		struct {
			struct fuse_read_in in;
			u64 attr_ver;
		} read;
		struct {
			struct fuse_write_in in;
			struct fuse_write_out out;
			struct bento_req *next;
		} write;
		struct fuse_notify_retrieve_in retrieve_in;
	} misc;

	/** page vector */
	struct page **pages;

	/** page-descriptor vector */
	struct bento_page_desc *page_descs;

	/** size of the 'pages' array */
	unsigned max_pages;

	/** inline page vector */
	struct page *inline_pages[BENTO_REQ_INLINE_PAGES];

	/** inline page-descriptor vector */
	struct bento_page_desc inline_page_descs[BENTO_REQ_INLINE_PAGES];

	/** number of pages in vector */
	unsigned num_pages;

	/** File used in the request (or NULL) */
	struct bento_file *ff;

	/** Inode used in the request or NULL */
	struct inode *inode;

	/** AIO control block */
	struct bento_io_priv *io;

	/** Link on fi->writepages */
	struct list_head writepages_entry;

	/** Request completion callback */
	void (*end)(struct bento_conn *, struct bento_req *);

	/** Request is stolen from bento_file->reserved_req */
	struct file *stolen_file;
};

struct bento_iqueue {
	/** Connection established */
	unsigned connected;

	/** Readers of the connection are waiting on this */
	wait_queue_head_t waitq;

	/** The next unique request id */
	u64 reqctr;

	/** The list of pending requests */
	struct list_head pending;

	/** Pending interrupts */
	struct list_head interrupts;

	/** Queue of pending forgets */
	struct bento_forget_link forget_list_head;
	struct bento_forget_link *forget_list_tail;

	/** Batching of FORGET requests (positive indicates FORGET batch) */
	int forget_batch;

	/** O_ASYNC requests */
	struct fasync_struct *fasync;
};

struct bento_buffer {
	char *ptr;
	size_t bufsize;
	bool drop;
};

struct bento_fs_type {
	const char *name;
	const void *fs;
	int (*dispatch) (const void *, uint32_t, struct bento_in *,
			struct bento_out *);
	struct bento_fs_type *next;
};

/**
 * A Fuse connection.
 *
 * This structure is created, when the filesystem is mounted, and is
 * destroyed, when the client device is closed and the filesystem is
 * unmounted.
 */
struct bento_conn {
	/** Lock protecting accessess to  members of this structure */
	spinlock_t lock;

	/** Refcount */
	refcount_t count;

	/** Number of bento_dev's */
	atomic_t dev_count;

	struct rcu_head rcu;

	/** The user id for this mount */
	kuid_t user_id;

	/** The group id for this mount */
	kgid_t group_id;

	/** The pid namespace for this mount */
	struct pid_namespace *pid_ns;

	/** Maximum read size */
	unsigned max_read;

	/** Maximum write size */
	unsigned max_write;

	/** Input queue */
	struct bento_iqueue iq;

	/** The next unique kernel file handle */
	u64 khctr;

	/** rbtree of bento_files waiting for poll events indexed by ph */
	struct rb_root polled_files;

	/** The list of background requests set aside for later queuing */
	struct list_head bg_queue;

	/** Flag indicating that INIT reply has been received. Allocating
	 * any bento request will be suspended until the flag is set */
	int initialized;

	/** Flag indicating if connection is blocked.  This will be
	    the case before the INIT reply is received, and if there
	    are too many outstading backgrounds requests */
	int blocked;

	/** waitq for blocked connection */
	wait_queue_head_t blocked_waitq;

	/** waitq for reserved requests */
	wait_queue_head_t reserved_req_waitq;

	/** Connection established, cleared on umount, connection
	    abort and device release */
	unsigned connected;

	/** Connection failed (version mismatch).  Cannot race with
	    setting other bitfields since it is only set once in INIT
	    reply, before any other request, and never cleared */
	unsigned conn_error:1;

	/** Connection successful.  Only set in INIT */
	unsigned conn_init:1;

	/** Do readpages asynchronously?  Only set in INIT */
	unsigned async_read:1;

	/** Do not send separate SETATTR request before open(O_TRUNC)  */
	unsigned atomic_o_trunc:1;

	/** Filesystem supports NFS exporting.  Only set in INIT */
	unsigned export_support:1;

	/** write-back cache policy (default is write-through) */
	unsigned writeback_cache:1;

	/** allow parallel lookups and readdir (default is serialized) */
	unsigned parallel_dirops:1;

	/** handle fs handles killing suid/sgid/cap on write/chown/trunc */
	unsigned handle_killpriv:1;

	/*
	 * The following bitfields are only for optimization purposes
	 * and hence races in setting them will not cause malfunction
	 */

	/** Is open/release not implemented by fs? */
	unsigned no_open:1;

	/** Is fsync not implemented by fs? */
	unsigned no_fsync:1;

	/** Is fsyncdir not implemented by fs? */
	unsigned no_fsyncdir:1;

	/** Is flush not implemented by fs? */
	unsigned no_flush:1;

	/** Is setxattr not implemented by fs? */
	unsigned no_setxattr:1;

	/** Is getxattr not implemented by fs? */
	unsigned no_getxattr:1;

	/** Is listxattr not implemented by fs? */
	unsigned no_listxattr:1;

	/** Is removexattr not implemented by fs? */
	unsigned no_removexattr:1;

	/** Are posix file locking primitives not implemented by fs? */
	unsigned no_lock:1;

	/** Is access not implemented by fs? */
	unsigned no_access:1;

	/** Is create not implemented by fs? */
	unsigned no_create:1;

	/** Is interrupt not implemented by fs? */
	unsigned no_interrupt:1;

	/** Is bmap not implemented by fs? */
	unsigned no_bmap:1;

	/** Is poll not implemented by fs? */
	unsigned no_poll:1;

	/** Do multi-page cached writes */
	unsigned big_writes:1;

	/** Don't apply umask to creation modes */
	unsigned dont_mask:1;

	/** Are BSD file locking primitives not implemented by fs? */
	unsigned no_flock:1;

	/** Is fallocate not implemented by fs? */
	unsigned no_fallocate:1;

	/** Is rename with flags implemented by fs? */
	unsigned no_rename2:1;

	/** Use enhanced/automatic page cache invalidation. */
	unsigned auto_inval_data:1;

	/** Does the filesystem support readdirplus? */
	unsigned do_readdirplus:1;

	/** Does the filesystem want adaptive readdirplus? */
	unsigned readdirplus_auto:1;

	/** Does the filesystem support asynchronous direct-IO submission? */
	unsigned async_dio:1;

	/** Is lseek not implemented by fs? */
	unsigned no_lseek:1;

	/** Does the filesystem support posix acls? */
	unsigned posix_acl:1;

	/** Check permissions based on the file mode or not? */
	unsigned default_permissions:1;

	/** Allow other than the mounter user to access the filesystem ? */
	unsigned allow_other:1;

	/** The number of requests waiting for completion */
	atomic_t num_waiting;

	/** Negotiated minor version */
	unsigned minor;

	/** Entry on the bento_conn_list */
	struct list_head entry;

	/** Device ID from super block */
	dev_t dev;

	/** Dentries in the control filesystem */
	struct dentry *ctl_dentry[BENTO_CTL_NUM_DENTRIES];

	/** number of dentries used in the above array */
	int ctl_ndents;

	/** Key for lock owner ID scrambling */
	u32 scramble_key[4];

	/** Reserved request for the DESTROY message */
	struct bento_req *destroy_req;

	/** Version counter for attribute changes */
	u64 attr_version;

	/** Called on final put */
	void (*release)(struct bento_conn *);

	/** Super block for this connection. */
	struct super_block *sb;

	/** Read/write semaphore to hold when accessing sb. */
	struct rw_semaphore killsb;

	/** Read/write semaphore to hold when accessing the fs */
	struct rw_semaphore fslock;

	const void *fs_ptr;

	int (*dispatch) (const void *, uint32_t, struct bento_in *,
			struct bento_out *);

	/** List of device instances belonging to this connection */
	struct list_head devices;
};

static inline struct bento_conn *get_bento_conn_super(struct super_block *sb)
{
	return sb->s_fs_info;
}

static inline struct bento_conn *get_bento_conn(struct inode *inode)
{
	return get_bento_conn_super(inode->i_sb);
}

static inline struct bento_inode *get_bento_inode(struct inode *inode)
{
	return container_of(inode, struct bento_inode, inode);
}

static inline u64 get_node_id(struct inode *inode)
{
	return get_bento_inode(inode)->nodeid;
}

/** Device operations */
extern const struct file_operations bento_dev_operations;

extern const struct dentry_operations bento_dentry_operations;
extern const struct dentry_operations bento_root_dentry_operations;

/**
 * Inode to nodeid comparison.
 */
int bento_inode_eq(struct inode *inode, void *_nodeidp);

/**
 * Get a filled in inode
 */
struct inode *bento_iget(struct super_block *sb, u64 nodeid,
			int generation, struct fuse_attr *attr,
			u64 attr_valid, u64 attr_version);

int bento_lookup_name(struct super_block *sb, u64 nodeid, const struct qstr *name,
		     struct fuse_entry_out *outarg, struct inode **inode);

/**
 * Send FORGET command
 */
void bento_queue_forget(struct bento_conn *fc, struct bento_forget_link *forget,
		       u64 nodeid, u64 nlookup);

struct bento_forget_link *bento_alloc_forget(void);

/**
 * Initialize READ or READDIR request
 */
void bento_read_fill(struct bento_in *in, struct bento_out *out, struct fuse_read_in *inarg,
                    struct bento_buffer* buf, struct file *file, loff_t pos, size_t count, int opcode);
void bento_read_fill_old(struct bento_req *req, struct file *file,
		    loff_t pos, size_t count, int opcode);

/**
 * Send OPEN or OPENDIR request
 */
int bento_open_common(struct inode *inode, struct file *file, bool isdir);

struct bento_file *bento_file_alloc(struct bento_conn *fc);
void bento_file_free(struct bento_file *ff);
void bento_finish_open(struct inode *inode, struct file *file);

void bento_sync_release(struct bento_file *ff, int flags);

/**
 * Send RELEASE or RELEASEDIR request
 */
void bento_release_common(struct file *file, int opcode);

/**
 * Send FSYNC or FSYNCDIR request
 */
int bento_fsync_common(struct file *file, loff_t start, loff_t end,
		      int datasync, int isdir);

/**
 * Initialize file operations on a regular file
 */
void bento_init_file_inode(struct inode *inode);

/**
 * Initialize inode operations on regular files and special files
 */
void bento_init_common(struct inode *inode);

/**
 * Initialize inode and file operations on a directory
 */
void bento_init_dir(struct inode *inode);

/**
 * Initialize inode operations on a symlink
 */
void bento_init_symlink(struct inode *inode);

/**
 * Change attributes of an inode
 */
void bento_change_attributes(struct inode *inode, struct fuse_attr *attr,
			    u64 attr_valid, u64 attr_version);

void bento_change_attributes_common(struct inode *inode, struct fuse_attr *attr,
				   u64 attr_valid);

/**
 * Initialize the client device
 */
int bento_dev_init(void);

/**
 * Cleanup the client device
 */
void bento_dev_cleanup(void);

/**
 * Allocate a request
 */
struct bento_req *bento_request_alloc(unsigned npages);

struct bento_req *bento_request_alloc_nofs(unsigned npages);

/**
 * Free a request
 */
void bento_request_free(struct bento_req *req);

/**
 * Get a request, may fail with -ENOMEM,
 * caller should specify # elements in req->pages[] explicitly
 */
struct bento_req *bento_get_req(struct bento_conn *fc, unsigned npages);

/*
 * Increment reference count on request
 */
void __bento_get_request(struct bento_req *req);

/**
 * Gets a requests for a file operation, always succeeds
 */
struct bento_req *bento_get_req_nofail_nopages(struct bento_conn *fc,
					     struct file *file);

/**
 * Decrement reference count of a request.  If count goes to zero free
 * the request.
 */
void bento_put_request(struct bento_conn *fc, struct bento_req *req);

/* Abort all requests */
void bento_abort_conn(struct bento_conn *fc);

/**
 * Invalidate inode attributes
 */
void bento_invalidate_attr(struct inode *inode);

void bento_invalidate_entry_cache(struct dentry *entry);

void bento_invalidate_atime(struct inode *inode);

/**
 * Acquire reference to bento_conn
 */
struct bento_conn *bento_conn_get(struct bento_conn *fc);

/**
 * Initialize bento_conn
 */
void bento_conn_init(struct bento_conn *fc);

/**
 * Release reference to bento_conn
 */
void bento_conn_put(struct bento_conn *fc);

/**
 * Is file type valid?
 */
int bento_valid_type(int m);

/**
 * Is current process allowed to perform filesystem operation?
 */
int bento_allow_current_process(struct bento_conn *fc);

u64 bento_lock_owner_id(struct bento_conn *fc, fl_owner_t id);

void bento_update_ctime(struct inode *inode);

int bento_update_attributes(struct inode *inode, struct file *file);

void bento_flush_writepages(struct inode *inode);

void bento_set_nowrite(struct inode *inode);
void bento_release_nowrite(struct inode *inode);

u64 bento_get_attr_version(struct bento_conn *fc);

/**
 * File-system tells the kernel to invalidate cache for the given node id.
 */
int bento_reverse_inval_inode(struct super_block *sb, u64 nodeid,
			     loff_t offset, loff_t len);

/**
 * File-system tells the kernel to invalidate parent attributes and
 * the dentry matching parent/name.
 *
 * If the child_nodeid is non-zero and:
 *    - matches the inode number for the dentry matching parent/name,
 *    - is not a mount point
 *    - is a file or oan empty directory
 * then the dentry is unhashed (d_delete()).
 */
int bento_reverse_inval_entry(struct super_block *sb, u64 parent_nodeid,
			     u64 child_nodeid, struct qstr *name);

int bento_do_open(struct bento_conn *fc, u64 nodeid, struct file *file,
		 bool isdir);

/**
 * bento_direct_io() flags
 */

/** If set, it is WRITE; otherwise - READ */
#define BENTO_DIO_WRITE (1 << 0)

/** CUSE pass bento_direct_io() a file which f_mapping->host is not from BENTO */
#define BENTO_DIO_CUSE  (1 << 1)

ssize_t bento_direct_io(struct bento_io_priv *io, struct iov_iter *iter,
		       loff_t *ppos, int flags);
long bento_do_ioctl(struct file *file, unsigned int cmd, unsigned long arg,
		   unsigned int flags);
long bento_ioctl_common(struct file *file, unsigned int cmd,
		       unsigned long arg, unsigned int flags);
unsigned bento_file_poll(struct file *file, poll_table *wait);
int bento_dev_release(struct inode *inode, struct file *file);

bool bento_write_update_size(struct inode *inode, loff_t pos);

int bento_flush_times(struct inode *inode, struct bento_file *ff);
int bento_write_inode(struct inode *inode, struct writeback_control *wbc);

int bento_do_setattr(struct dentry *dentry, struct iattr *attr,
		    struct file *file);

void bento_set_initialized(struct bento_conn *fc);

void bento_unlock_inode(struct inode *inode);
void bento_lock_inode(struct inode *inode);

int bento_setxattr(struct inode *inode, const char *name, const void *value,
		  size_t size, int flags);
ssize_t bento_getxattr(struct inode *inode, const char *name, void *value,
		      size_t size);
ssize_t bento_listxattr(struct dentry *entry, char *list, size_t size);
int bento_removexattr(struct inode *inode, const char *name);
extern const struct xattr_handler *bento_xattr_handlers[];
extern const struct xattr_handler *bento_acl_xattr_handlers[];

struct posix_acl;
struct posix_acl *bento_get_acl(struct inode *inode, int type,bool keepalive);
int bento_set_acl(struct user_namespace *,struct inode *inode, struct posix_acl *acl, int type);

#define BENTO_MAX_MAX_PAGES 256
#define BENTO_DEFAULT_MAX_PAGES_PER_REQ 32

/* room needed in buffer to accommodate header */
#define BENTO_BUFFER_HEADER_SIZE 0x1000

#endif /* _FS_BENTO_I_H */
