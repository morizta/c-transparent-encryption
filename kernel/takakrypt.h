#ifndef TAKAKRYPT_H
#define TAKAKRYPT_H

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/security.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>
#include <net/sock.h>
#include <linux/mutex.h>
#include <linux/list.h>
#include <linux/hash.h>
#include <linux/workqueue.h>
#include <linux/spinlock.h>
#include <linux/atomic.h>
#include <linux/time.h>
#include <linux/cred.h>
#include <linux/path.h>

/* Module information */
#define TAKAKRYPT_MODULE_NAME    "takakrypt"
#define TAKAKRYPT_VERSION        "1.0.0"
#define TAKAKRYPT_AUTHOR         "Takakrypt Development Team"
#define TAKAKRYPT_DESCRIPTION    "Transparent Encryption Kernel Module"

/* Communication protocol */
#define TAKAKRYPT_NETLINK_FAMILY 31
#define TAKAKRYPT_MAX_MSG_SIZE   65536
#define TAKAKRYPT_MAX_PATH_LEN   4096

/* Operation types */
enum takakrypt_operation {
    TAKAKRYPT_OP_CHECK_POLICY = 1,
    TAKAKRYPT_OP_ENCRYPT      = 2,
    TAKAKRYPT_OP_DECRYPT      = 3,
    TAKAKRYPT_OP_GET_STATUS   = 4,
    TAKAKRYPT_OP_SET_CONFIG   = 5,
    TAKAKRYPT_OP_HEALTH_CHECK = 6
};

/* Response status codes */
enum takakrypt_status {
    TAKAKRYPT_STATUS_SUCCESS        = 0,
    TAKAKRYPT_STATUS_DENIED         = 1,
    TAKAKRYPT_STATUS_ERROR          = 2,
    TAKAKRYPT_STATUS_NOT_FOUND      = 3,
    TAKAKRYPT_STATUS_INVALID_REQUEST = 4,
    TAKAKRYPT_STATUS_TIMEOUT        = 5,
    TAKAKRYPT_STATUS_NO_AGENT       = 6
};

/* File operations that trigger encryption */
enum takakrypt_file_op {
    TAKAKRYPT_FILE_OP_READ   = 1,
    TAKAKRYPT_FILE_OP_WRITE  = 2,
    TAKAKRYPT_FILE_OP_CREATE = 3,
    TAKAKRYPT_FILE_OP_DELETE = 4,
    TAKAKRYPT_FILE_OP_OPEN   = 5
};

/* Request header structure */
struct takakrypt_msg_header {
    uint32_t magic;           /* Magic number for validation */
    uint32_t version;         /* Protocol version */
    uint32_t operation;       /* Operation type */
    uint32_t sequence;        /* Sequence number */
    uint32_t payload_size;    /* Size of payload data */
    uint32_t flags;           /* Request flags */
    uint64_t timestamp;       /* Request timestamp */
} __packed;

/* Context information for policy evaluation */
struct takakrypt_context {
    uint32_t uid;             /* User ID */
    uint32_t gid;             /* Group ID */
    uint32_t pid;             /* Process ID */
    uint32_t ppid;            /* Parent process ID */
    uint32_t file_operation;  /* File operation type */
    char process_name[TASK_COMM_LEN];  /* Process name */
    char filepath[TAKAKRYPT_MAX_PATH_LEN]; /* File path */
    uint64_t file_size;       /* File size */
    uint32_t file_mode;       /* File permissions */
} __packed;

/* Policy check request */
struct takakrypt_policy_request {
    struct takakrypt_msg_header header;
    struct takakrypt_context context;
    uint32_t request_id;      /* Unique request ID */
} __packed;

/* Policy check response */
struct takakrypt_policy_response {
    struct takakrypt_msg_header header;
    uint32_t status;          /* Response status */
    uint32_t allow;           /* 1 if allowed, 0 if denied */
    uint32_t request_id;      /* Matching request ID */
    char policy_name[64];     /* Applied policy name */
    char key_id[64];          /* Encryption key ID */
    char reason[256];         /* Decision reason */
} __packed;

/* Encryption/Decryption request */
struct takakrypt_crypto_request {
    struct takakrypt_msg_header header;
    struct takakrypt_context context;
    uint32_t request_id;
    char key_id[64];
    uint32_t data_length;
    uint8_t data[];           /* Variable length data */
} __packed;

/* Simplified encryption request */
struct takakrypt_encrypt_request {
    struct takakrypt_msg_header header;
    uint32_t key_id_len;
    uint32_t data_len;
    /* Followed by key_id string and data */
} __packed;

/* Encryption/Decryption response */
struct takakrypt_crypto_response {
    struct takakrypt_msg_header header;
    uint32_t status;
    uint32_t request_id;
    uint32_t data_len;
    /* Followed by encrypted/decrypted data */
} __packed;

/* Status information */
struct takakrypt_status_info {
    uint32_t module_loaded;
    uint32_t agent_connected;
    uint64_t requests_processed;
    uint64_t requests_allowed;
    uint64_t requests_denied;
    uint64_t encryption_ops;
    uint64_t decryption_ops;
    uint64_t cache_hits;
    uint64_t cache_misses;
    uint32_t active_files;
    uint64_t uptime_seconds;
} __packed;

/* Configuration structure */
struct takakrypt_config {
    uint32_t enabled;
    uint32_t debug_level;
    uint32_t cache_timeout;
    uint32_t request_timeout;
    uint32_t max_file_size;
    uint32_t max_concurrent_ops;
} __packed;

/* Cache entry for policy decisions */
struct takakrypt_cache_entry {
    struct hlist_node node;
    char filepath[TAKAKRYPT_MAX_PATH_LEN];
    uint32_t uid;
    uint32_t pid;
    uint32_t allow;
    char policy_name[64];
    char key_id[64];
    unsigned long timestamp;
    atomic_t refcount;
};

/* File context for tracking encrypted files */
struct takakrypt_file_context {
    struct list_head list;
    struct file *file;
    char filepath[TAKAKRYPT_MAX_PATH_LEN];
    char key_id[64];
    uint32_t encrypted;
    uint32_t policy_checked;
    spinlock_t lock;
    atomic_t refcount;
};

/* Global module state */
struct takakrypt_state {
    struct sock *netlink_sock;    /* Netlink socket */
    uint32_t agent_pid;           /* User-space agent PID */
    atomic_t sequence_counter;    /* Request sequence counter */
    
    /* Statistics */
    struct takakrypt_status_info stats;
    spinlock_t stats_lock;
    
    /* Configuration */
    struct takakrypt_config config;
    struct mutex config_lock;
    
    /* Policy decision cache */
    struct hlist_head *policy_cache;
    uint32_t cache_size;
    spinlock_t cache_lock;
    
    /* Active file contexts */
    struct list_head file_contexts;
    spinlock_t file_contexts_lock;
    
    /* Work queue for async operations */
    struct workqueue_struct *workqueue;
    
    /* Module status */
    atomic_t module_active;
    unsigned long start_time;
};

/* Function prototypes */

/* Module initialization and cleanup - declared in main.c */

/* Netlink communication */
int takakrypt_netlink_init(void);
void takakrypt_netlink_cleanup(void);
int takakrypt_send_request(struct takakrypt_msg_header *msg, size_t msg_size);
void takakrypt_netlink_recv(struct sk_buff *skb);
int takakrypt_send_request_and_wait(struct takakrypt_msg_header *msg, 
                                    size_t msg_size, void *response, 
                                    size_t response_size);

/* VFS hooks */
int takakrypt_file_open(struct inode *inode, struct file *file);
ssize_t takakrypt_file_read(struct file *file, char __user *buf, size_t count, loff_t *ppos);
ssize_t takakrypt_file_write(struct file *file, const char __user *buf, size_t count, loff_t *ppos);
int takakrypt_file_release(struct inode *inode, struct file *file);

/* Policy evaluation */
int takakrypt_check_policy(struct file *file, uint32_t operation);
struct takakrypt_cache_entry *takakrypt_cache_lookup(const char *filepath, uint32_t uid, uint32_t pid);
void takakrypt_cache_insert(const char *filepath, uint32_t uid, uint32_t pid, 
                           uint32_t allow, const char *policy_name, const char *key_id);
void takakrypt_cache_cleanup(void);
void takakrypt_cache_get_stats(uint32_t *total_entries, uint32_t *expired_entries);

/* File context management */
struct takakrypt_file_context *takakrypt_get_file_context(struct file *file);
void takakrypt_put_file_context(struct takakrypt_file_context *ctx);
void takakrypt_cleanup_file_contexts(void);
void takakrypt_get_file_contexts_stats(uint32_t *total_files, uint32_t *encrypted_files);

/* Utility functions */
int takakrypt_get_file_path(struct file *file, char *buf, size_t buf_size);
uint32_t takakrypt_hash_string(const char *str);
void takakrypt_update_stats(uint32_t operation, uint32_t result);

/* Proc filesystem interface */
int takakrypt_proc_init(void);
void takakrypt_proc_cleanup(void);

/* Debug and logging */
#define TAKAKRYPT_LOG_LEVEL_DEBUG 4
#define TAKAKRYPT_LOG_LEVEL_INFO  3
#define TAKAKRYPT_LOG_LEVEL_WARN  2
#define TAKAKRYPT_LOG_LEVEL_ERROR 1

extern uint32_t takakrypt_debug_level;

#define takakrypt_debug(fmt, ...) \
    do { \
        if (takakrypt_debug_level >= TAKAKRYPT_LOG_LEVEL_DEBUG) \
            printk(KERN_DEBUG TAKAKRYPT_MODULE_NAME ": " fmt, ##__VA_ARGS__); \
    } while (0)

#define takakrypt_info(fmt, ...) \
    do { \
        if (takakrypt_debug_level >= TAKAKRYPT_LOG_LEVEL_INFO) \
            printk(KERN_INFO TAKAKRYPT_MODULE_NAME ": " fmt, ##__VA_ARGS__); \
    } while (0)

#define takakrypt_warn(fmt, ...) \
    do { \
        if (takakrypt_debug_level >= TAKAKRYPT_LOG_LEVEL_WARN) \
            printk(KERN_WARNING TAKAKRYPT_MODULE_NAME ": " fmt, ##__VA_ARGS__); \
    } while (0)

#define takakrypt_error(fmt, ...) \
    do { \
        if (takakrypt_debug_level >= TAKAKRYPT_LOG_LEVEL_ERROR) \
            printk(KERN_ERR TAKAKRYPT_MODULE_NAME ": " fmt, ##__VA_ARGS__); \
    } while (0)

/* Magic numbers and constants */
#define TAKAKRYPT_MSG_MAGIC      0x54414B41  /* "TAKA" */
#define TAKAKRYPT_PROTOCOL_VERSION 1
#define TAKAKRYPT_CACHE_HASH_BITS  8
#define TAKAKRYPT_CACHE_SIZE      (1 << TAKAKRYPT_CACHE_HASH_BITS)
#define TAKAKRYPT_CACHE_TIMEOUT   (5 * 60 * HZ)  /* 5 minutes */
#define TAKAKRYPT_REQUEST_TIMEOUT (30 * HZ)      /* 30 seconds */

/* VFS hooks function declarations */
ssize_t takakrypt_read_iter(struct kiocb *iocb, struct iov_iter *iter);
ssize_t takakrypt_write_iter(struct kiocb *iocb, struct iov_iter *iter);
int takakrypt_file_open(struct inode *inode, struct file *file);
int takakrypt_file_release(struct inode *inode, struct file *file);

/* Original file operations storage (external declaration) */
extern const struct file_operations *original_file_ops;
extern struct file_operations takakrypt_hooked_fops;

/* Encryption/decryption functions */
int takakrypt_encrypt_data(const char *data, size_t data_len, const char *key_id, char **encrypted_data);
int takakrypt_decrypt_data(const char *encrypted_data, size_t data_len, const char *key_id, char **decrypted_data);
int takakrypt_query_policy_for_encryption(struct file *file, struct takakrypt_file_context *ctx);

/* VFS hook management */
int takakrypt_install_file_hooks(struct file *file);
void takakrypt_remove_file_hooks(struct file *file);
int takakrypt_install_global_hooks(void);
void takakrypt_remove_global_hooks(void);
int takakrypt_should_intercept_file(struct file *file);

/* Global state instance */
extern struct takakrypt_state *takakrypt_global_state;

#endif /* TAKAKRYPT_H */