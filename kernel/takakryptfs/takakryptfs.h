#ifndef TAKAKRYPTFS_H
#define TAKAKRYPTFS_H

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/mutex.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/atomic.h>
#include <linux/time.h>
#include <linux/cred.h>
#include <linux/path.h>
#include <linux/parser.h>
#include <linux/seq_file.h>
#include <linux/file.h>
#include <linux/writeback.h>
#include <linux/mpage.h>
#include <linux/pagemap.h>
#include <linux/string.h>
#include <linux/statfs.h>

/* Module information */
#define TAKAKRYPTFS_MODULE_NAME    "takakryptfs"
#define TAKAKRYPTFS_VERSION        "1.0.0"
#define TAKAKRYPTFS_AUTHOR         "Takakrypt Development Team"
#define TAKAKRYPTFS_DESCRIPTION    "Takakrypt Stackable Cryptographic Filesystem"

/* Filesystem constants */
#define TAKAKRYPTFS_MAGIC          0x54414B41  /* "TAKA" */
#define TAKAKRYPTFS_MAX_PATH_LEN   4096

/* Mount options */
enum takakryptfs_mount_opt {
    TAKAKRYPTFS_OPT_LOWERDIR,
    TAKAKRYPTFS_OPT_POLICY,
    TAKAKRYPTFS_OPT_READONLY,
    TAKAKRYPTFS_OPT_DEBUG,
    TAKAKRYPTFS_OPT_ERR
};

/* Mount context structure */
struct takakryptfs_mount_ctx {
    char *lower_path;             /* Underlying filesystem path */
    char *policy_name;            /* Applied policy name */
    struct path lower_root;       /* Lower filesystem root */
    bool readonly;                /* Read-only mount */
    int debug_level;              /* Debug verbosity */
};

/* Superblock private data */
struct takakryptfs_sb_info {
    struct super_block *lower_sb; /* Lower filesystem superblock */
    struct takakryptfs_mount_ctx ctx; /* Mount context */
    spinlock_t stats_lock;        /* Statistics lock */
    atomic_t active_files;        /* Number of active files */
    
    /* Statistics */
    struct {
        atomic64_t files_opened;
        atomic64_t files_encrypted;
        atomic64_t files_decrypted;
        atomic64_t bytes_encrypted;
        atomic64_t bytes_decrypted;
        atomic64_t policy_lookups;
        atomic64_t cache_hits;
        atomic64_t cache_misses;
    } stats;
};

/* Inode private data */
struct takakryptfs_inode_info {
    struct inode *lower_inode;    /* Lower filesystem inode */
    struct inode vfs_inode;       /* VFS inode */
    
    /* Encryption metadata */
    bool encrypted;               /* File is encrypted */
    bool encrypt_file;            /* File should be encrypted on write */
    bool policy_checked;          /* Policy has been evaluated */
    char policy_name[64];         /* Applied policy name */
    char key_id[64];              /* Encryption key ID */
    
    /* File format information */
    bool has_header;              /* File has encryption header */
    size_t header_size;           /* Size of encryption header */
    
    /* Synchronization */
    struct mutex encrypt_mutex;   /* Encryption operation mutex */
    atomic_t refcount;            /* Reference count */
};

/* File private data */
struct takakryptfs_file_info {
    struct file *lower_file;      /* Lower filesystem file */
    struct takakryptfs_inode_info *inode_info; /* Inode information */
    
    /* File state */
    bool read_access;             /* File opened for reading */
    bool write_access;            /* File opened for writing */
    bool header_read;             /* Encryption header has been read */
    
    /* Statistics */
    atomic64_t bytes_read;        /* Bytes read from this file */
    atomic64_t bytes_written;     /* Bytes written to this file */
};

/* Directory private data */
struct takakryptfs_dir_info {
    struct file *lower_dir;       /* Lower filesystem directory */
    struct list_head entries;     /* Cached directory entries */
    struct mutex entries_mutex;   /* Directory entries mutex */
    bool entries_cached;          /* Directory entries are cached */
};

/* Policy evaluation result */
struct takakryptfs_policy_result {
    bool allow_access;            /* Access is allowed */
    bool encrypt_file;            /* File should be encrypted */
    char policy_name[64];         /* Applied policy name */
    char key_id[64];              /* Encryption key ID */
    char reason[256];             /* Decision reason */
};

/* Function declarations */

/* main.c */
extern struct file_system_type takakryptfs_type;

/* super.c */
extern const struct super_operations takakryptfs_sops;
extern struct kmem_cache *takakryptfs_inode_cache;
int takakryptfs_fill_super_legacy(struct super_block *sb, struct takakryptfs_mount_ctx *ctx, int silent);
void takakryptfs_kill_super(struct super_block *sb);
int takakryptfs_show_options(struct seq_file *m, struct dentry *root);
int takakryptfs_statfs(struct dentry *dentry, struct kstatfs *buf);

/* inode.c */
extern const struct inode_operations takakryptfs_file_iops;
extern const struct inode_operations takakryptfs_dir_iops;
extern const struct inode_operations takakryptfs_symlink_iops;
struct inode *takakryptfs_get_inode(struct super_block *sb, struct inode *lower_inode);
void takakryptfs_init_inode(struct inode *inode, struct inode *lower_inode);
int takakryptfs_getattr(struct user_namespace *mnt_userns, const struct path *path,
                        struct kstat *stat, u32 request_mask, unsigned int flags);
int takakryptfs_setattr(struct user_namespace *mnt_userns, struct dentry *dentry,
                        struct iattr *attr);

/* file.c */
extern const struct file_operations takakryptfs_file_fops;
int takakryptfs_open(struct inode *inode, struct file *file);
int takakryptfs_release(struct inode *inode, struct file *file);
ssize_t takakryptfs_read_iter(struct kiocb *iocb, struct iov_iter *iter);
ssize_t takakryptfs_write_iter(struct kiocb *iocb, struct iov_iter *iter);
loff_t takakryptfs_llseek(struct file *file, loff_t offset, int whence);

/* dir.c */
extern const struct file_operations takakryptfs_dir_fops;
int takakryptfs_readdir(struct file *file, struct dir_context *ctx);
int takakryptfs_dir_open(struct inode *inode, struct file *file);
int takakryptfs_dir_release(struct inode *inode, struct file *file);

/* crypto.c */
int takakryptfs_encrypt_data(const void *plaintext, size_t plaintext_len,
                             const char *key_id, void **ciphertext, size_t *ciphertext_len);
int takakryptfs_decrypt_data(const void *ciphertext, size_t ciphertext_len,
                             const char *key_id, void **plaintext, size_t *plaintext_len);
bool takakryptfs_is_encrypted_file(struct file *file);
int takakryptfs_read_encryption_header(struct file *file, void *header, size_t header_size);
int takakryptfs_write_encryption_header(struct file *file, const void *header, size_t header_size);
int takakryptfs_crypto_init(void);
void takakryptfs_crypto_exit(void);

/* mount.c */
int takakryptfs_validate_mount_ctx(struct takakryptfs_mount_ctx *ctx);
void takakryptfs_free_mount_ctx(struct takakryptfs_mount_ctx *ctx);
int takakryptfs_setup_lower_path(struct takakryptfs_mount_ctx *ctx);

/* policy.c */
int takakryptfs_evaluate_policy(struct file *file, struct takakryptfs_policy_result *result);
int takakryptfs_check_file_access(struct file *file, int mask);
bool takakryptfs_should_encrypt_file(struct inode *inode, const char *filepath);
int takakryptfs_policy_init(void);
void takakryptfs_policy_exit(void);

/* Missing function declarations from inode.c */
struct dentry *takakryptfs_lookup(struct inode *dir, struct dentry *dentry, unsigned int flags);
int takakryptfs_create(struct user_namespace *mnt_userns, struct inode *dir, 
                       struct dentry *dentry, umode_t mode, bool excl);
int takakryptfs_mkdir(struct user_namespace *mnt_userns, struct inode *dir,
                      struct dentry *dentry, umode_t mode);
int takakryptfs_rmdir(struct inode *dir, struct dentry *dentry);
int takakryptfs_unlink(struct inode *dir, struct dentry *dentry);
int takakryptfs_symlink(struct user_namespace *mnt_userns, struct inode *dir,
                        struct dentry *dentry, const char *symname);
int takakryptfs_link(struct dentry *old_dentry, struct inode *dir, struct dentry *new_dentry);
int takakryptfs_rename(struct user_namespace *mnt_userns, struct inode *old_dir,
                       struct dentry *old_dentry, struct inode *new_dir,
                       struct dentry *new_dentry, unsigned int flags);
const char *takakryptfs_get_link(struct dentry *dentry, struct inode *inode,
                                 struct delayed_call *done);
int takakryptfs_readpage(struct file *file, struct page *page);
int takakryptfs_writepage(struct page *page, struct writeback_control *wbc);
void takakryptfs_readahead(struct readahead_control *rac);

/* Address space operations */
extern const struct address_space_operations takakryptfs_aops;

/* Helper macros */
#define takakryptfs_inode_to_private(inode) \
    container_of(inode, struct takakryptfs_inode_info, vfs_inode)

#define takakryptfs_sb_to_private(sb) \
    ((struct takakryptfs_sb_info *)(sb)->s_fs_info)

#define takakryptfs_dentry_to_lower(dentry) \
    ((dentry)->d_fsdata)

#define takakryptfs_file_to_lower(file) \
    (((struct takakryptfs_file_info *)(file)->private_data)->lower_file)

/* Debug macros */
#define takakryptfs_debug(fmt, ...) \
    pr_debug("takakryptfs: " fmt, ##__VA_ARGS__)

#define takakryptfs_info(fmt, ...) \
    pr_info("takakryptfs: " fmt, ##__VA_ARGS__)

#define takakryptfs_warn(fmt, ...) \
    pr_warn("takakryptfs: " fmt, ##__VA_ARGS__)

#define takakryptfs_error(fmt, ...) \
    pr_err("takakryptfs: " fmt, ##__VA_ARGS__)

/* Statistics helpers */
static inline void takakryptfs_inc_stat(atomic64_t *stat)
{
    atomic64_inc(stat);
}

static inline void takakryptfs_add_stat(atomic64_t *stat, long val)
{
    atomic64_add(val, stat);
}

#endif /* TAKAKRYPTFS_H */