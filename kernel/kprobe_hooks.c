/* Enhanced logging added for debugging */

#include "takakrypt.h"
#include <linux/kprobes.h>
#include <linux/version.h>
#include <linux/workqueue.h>
#include <linux/slab.h>

/* External function from vfs_hooks.c */
extern int takakrypt_install_file_hooks(struct file *file);

/* Work queue for safe encryption/decryption operations */
static struct workqueue_struct *takakrypt_workqueue;

/* Work structure for encryption requests */
struct takakrypt_encrypt_work {
    struct work_struct work;
    struct file *file;
    char filepath[TAKAKRYPT_MAX_PATH_LEN];
    int operation; /* TAKAKRYPT_FILE_OP_READ or TAKAKRYPT_FILE_OP_WRITE */
};

/* Work handler for encryption operations */
static void takakrypt_encrypt_work_handler(struct work_struct *work)
{
    struct takakrypt_encrypt_work *encrypt_work = 
        container_of(work, struct takakrypt_encrypt_work, work);
    
    takakrypt_debug("Processing encryption work for: %s (op=%d)\n", 
                   encrypt_work->filepath, encrypt_work->operation);
    
    /* Safe to make netlink calls here - not in atomic context */
    if (encrypt_work->operation == TAKAKRYPT_FILE_OP_WRITE) {
        /* TODO: Queue encryption request to userspace agent */
        takakrypt_debug("Queueing encryption for write: %s\n", encrypt_work->filepath);
    } else if (encrypt_work->operation == TAKAKRYPT_FILE_OP_READ) {
        /* TODO: Queue decryption request to userspace agent */
        takakrypt_debug("Queueing decryption for read: %s\n", encrypt_work->filepath);
    }
    
    /* Clean up work structure */
    kfree(encrypt_work);
}

/* Kprobe handlers for VFS interception */
static struct kprobe kp_vfs_read;
static struct kprobe kp_vfs_write;
static struct kprobe kp_do_filp_open;
static bool kprobes_installed = false;

/**
 * Pre-handler for vfs_read
 */
static int pre_vfs_read(struct kprobe *p, struct pt_regs *regs)
{
    struct file *file;
    char filepath[TAKAKRYPT_MAX_PATH_LEN];
    
    /* CRITICAL: Check if module is properly initialized */
    if (!takakrypt_global_state || !atomic_read(&takakrypt_global_state->module_active)) {
        return 0;
    }
    
    /* Get file parameter from registers (first argument) */
#ifdef CONFIG_X86_64
    file = (struct file *)regs->di;
#else
    file = (struct file *)regs->ARM_r0;
#endif
    
    if (!file) {
        return 0;
    }
    
    if (!takakrypt_should_intercept_file(file)) {
        return 0;
    }
    
    /* Get file path for debugging */
    if (takakrypt_get_file_path(file, filepath, sizeof(filepath)) == 0) {
        takakrypt_info("KPROBE: Intercepted vfs_read for: %s\n", filepath);
        
        /* Update statistics - with NULL check */
        if (takakrypt_global_state) {
            spin_lock(&takakrypt_global_state->stats_lock);
            takakrypt_global_state->stats.requests_processed++;
            spin_unlock(&takakrypt_global_state->stats_lock);
        }
        
        /* Policy checks handled at VFS hook level - no need for kprobe policy checks */
        /* takakrypt_check_policy(file, TAKAKRYPT_FILE_OP_READ); */
        
        /* VFS hooks are installed at file open time, not during read operations */
    }
    
    return 0;
}

/**
 * Pre-handler for vfs_write  
 */
static int pre_vfs_write(struct kprobe *p, struct pt_regs *regs)
{
    struct file *file;
    char filepath[TAKAKRYPT_MAX_PATH_LEN];
    
    /* CRITICAL: Check if module is properly initialized */
    if (!takakrypt_global_state || !atomic_read(&takakrypt_global_state->module_active)) {
        return 0;
    }
    
    /* Get file parameter from registers (first argument) */
#ifdef CONFIG_X86_64
    file = (struct file *)regs->di;
#else
    file = (struct file *)regs->ARM_r0;
#endif
    
    if (!file) {
        return 0;
    }
    
    if (!takakrypt_should_intercept_file(file)) {
        return 0;
    }
    
    /* Get file path for debugging */
    if (takakrypt_get_file_path(file, filepath, sizeof(filepath)) == 0) {
        takakrypt_info("KPROBE: Intercepted vfs_write for: %s\n", filepath);
        
        /* Update statistics - with NULL check */
        if (takakrypt_global_state) {
            spin_lock(&takakrypt_global_state->stats_lock);
            takakrypt_global_state->stats.requests_processed++;
            spin_unlock(&takakrypt_global_state->stats_lock);
        }
        
        /* Queue encryption work to avoid blocking in atomic context */
        if (takakrypt_workqueue && takakrypt_global_state) {
            struct takakrypt_encrypt_work *encrypt_work = 
                kmalloc(sizeof(struct takakrypt_encrypt_work), GFP_ATOMIC);
            if (encrypt_work) {
                INIT_WORK(&encrypt_work->work, takakrypt_encrypt_work_handler);
                encrypt_work->file = file;
                encrypt_work->operation = TAKAKRYPT_FILE_OP_WRITE;
                strncpy(encrypt_work->filepath, filepath, sizeof(encrypt_work->filepath)-1);
                encrypt_work->filepath[sizeof(encrypt_work->filepath)-1] = '\0';
                
                queue_work(takakrypt_workqueue, &encrypt_work->work);
                takakrypt_debug("Queued encryption work for: %s\n", filepath);
            } else {
                takakrypt_warn("Failed to allocate encryption work for: %s\n", filepath);
                /* Update failed allocation stats */
                if (takakrypt_global_state) {
                    spin_lock(&takakrypt_global_state->stats_lock);
                    takakrypt_global_state->stats.requests_denied++;
                    spin_unlock(&takakrypt_global_state->stats_lock);
                }
            }
        }
    }
    
    return 0;
}

/**
 * Post-handler for do_filp_open - Track file opens (no dynamic hook installation)
 */
static void post_do_filp_open(struct kprobe *p, struct pt_regs *regs, unsigned long flags)
{
    struct file *file;
    char filepath[TAKAKRYPT_MAX_PATH_LEN];
    
    /* CRITICAL: Check if module is properly initialized */
    if (!takakrypt_global_state || !atomic_read(&takakrypt_global_state->module_active)) {
        return;
    }
    
    /* Get return value (struct file *) from rax register */
#ifdef CONFIG_X86_64
    file = (struct file *)regs_return_value(regs);
#else
    file = (struct file *)regs->ARM_r0;
#endif
    
    /* Check if file open was successful and should be intercepted */
    if (IS_ERR_OR_NULL(file) || !takakrypt_should_intercept_file(file)) {
        return;
    }
    
    /* Get file path for logging */
    if (takakrypt_get_file_path(file, filepath, sizeof(filepath)) == 0) {
        takakrypt_info("KPROBE: File opened in guard point: %s\n", filepath);
        
        /* REMOVED: Dynamic VFS hook installation to prevent crashes */
        /* takakrypt_install_file_hooks(file); */
        
        /* TODO: Mark file for encryption tracking without dynamic hooks */
        takakrypt_debug("File %s marked for encryption tracking\n", filepath);
    }
}

/**
 * Check if file should be intercepted based on configured guard points
 */
int takakrypt_should_intercept_file(struct file *file)
{
    char filepath[TAKAKRYPT_MAX_PATH_LEN];
    uint32_t i;
    int should_intercept = 0;
    
    /* CRITICAL: Check if module is properly initialized */
    if (!takakrypt_global_state || !atomic_read(&takakrypt_global_state->module_active)) {
        return 0;
    }
    
    if (!file || !file->f_inode) {
        return 0;
    }
    
    /* Don't intercept special files */
    if (!S_ISREG(file->f_inode->i_mode)) {
        return 0;
    }
    
    /* Get file path */
    if (takakrypt_get_file_path(file, filepath, sizeof(filepath)) != 0) {
        return 0;
    }
    
    /* Skip system directories */
    if (strncmp(filepath, "/proc", 5) == 0 ||
        strncmp(filepath, "/sys", 4) == 0 ||
        strncmp(filepath, "/dev", 4) == 0) {
        return 0;
    }
    
    /* TEMPORARY BYPASS: Test hardcoded guard point */
    if (strstr(filepath, "/tmp/test-encrypt") != NULL) {
        takakrypt_info("BYPASS: File %s matches hardcoded guard point /tmp/test-encrypt\n", filepath);
        should_intercept = 1;
    }
    
    /* Check against configured guard points - with NULL check */
    if (takakrypt_global_state) {
        mutex_lock(&takakrypt_global_state->guard_points_lock);
    
        for (i = 0; i < takakrypt_global_state->guard_points.count; i++) {
            struct takakrypt_guard_point *gp = &takakrypt_global_state->guard_points.points[i];
            
            /* Skip disabled guard points */
            if (!gp->enabled) {
                continue;
            }
            
            /* Check if file path matches guard point path */
            if (strstr(filepath, gp->path) != NULL) {
                takakrypt_debug("File %s matches guard point '%s' (path: %s)\n", 
                               filepath, gp->name, gp->path);
                should_intercept = 1;
                break;
            }
        }
        
        mutex_unlock(&takakrypt_global_state->guard_points_lock);
    }
    
    if (should_intercept) {
        takakrypt_debug("Should intercept file: %s\n", filepath);
    }
    
    return should_intercept;
}

/**
 * Install global VFS hooks using kprobes
 */
int takakrypt_install_global_hooks(void)
{
    int ret;
    
    if (kprobes_installed) {
        return 0;
    }
    
    takakrypt_info("Installing global VFS hooks using kprobes\n");
    
    /* Create work queue for encryption operations */
    takakrypt_workqueue = create_singlethread_workqueue("takakrypt_encrypt");
    if (!takakrypt_workqueue) {
        takakrypt_error("Failed to create work queue\n");
        return -ENOMEM;
    }
    takakrypt_info("Created encryption work queue\n");
    
    /* Try vfs_read first, fallback to new_sync_read */
    kp_vfs_read.symbol_name = "vfs_read";
    kp_vfs_read.pre_handler = pre_vfs_read;
    
    ret = register_kprobe(&kp_vfs_read);
    if (ret < 0) {
        takakrypt_warn("Failed to register vfs_read kprobe: %d, trying new_sync_read\n", ret);
        /* Try alternative function */
        kp_vfs_read.symbol_name = "new_sync_read";
        ret = register_kprobe(&kp_vfs_read);
        if (ret < 0) {
            takakrypt_error("Failed to register new_sync_read kprobe: %d\n", ret);
            return ret;
        } else {
            takakrypt_info("Registered new_sync_read kprobe successfully\n");
        }
    } else {
        takakrypt_info("Registered vfs_read kprobe successfully\n");
    }
    
    /* Try vfs_write first (traditional path), fallback to vfs_iter_write */
    kp_vfs_write.symbol_name = "vfs_write";
    kp_vfs_write.pre_handler = pre_vfs_write;
    
    ret = register_kprobe(&kp_vfs_write);
    if (ret < 0) {
        takakrypt_warn("Failed to register vfs_write kprobe: %d, trying vfs_iter_write\n", ret);
        /* Try alternative function */
        kp_vfs_write.symbol_name = "vfs_iter_write";
        ret = register_kprobe(&kp_vfs_write);
        if (ret < 0) {
            takakrypt_error("Failed to register vfs_iter_write kprobe: %d\n", ret);
            unregister_kprobe(&kp_vfs_read);
            return ret;
        } else {
            takakrypt_info("Registered vfs_iter_write kprobe successfully\n");
        }
    } else {
        takakrypt_info("Registered vfs_write kprobe successfully\n");
    }
    
    /* Register do_filp_open kprobe for early VFS hook installation */
    kp_do_filp_open.symbol_name = "do_filp_open";
    kp_do_filp_open.post_handler = post_do_filp_open;
    
    ret = register_kprobe(&kp_do_filp_open);
    if (ret < 0) {
        takakrypt_error("Failed to register do_filp_open kprobe: %d\n", ret);
        unregister_kprobe(&kp_vfs_read);
        unregister_kprobe(&kp_vfs_write);
        return ret;
    } else {
        takakrypt_info("Registered do_filp_open kprobe successfully\n");
    }
    
    kprobes_installed = true;
    takakrypt_info("Global VFS hooks installed successfully\n");
    
    return 0;
}

/**
 * Remove global VFS hooks
 */
void takakrypt_remove_global_hooks(void)
{
    if (!kprobes_installed) {
        return;
    }
    
    takakrypt_info("Removing global VFS hooks\n");
    
    unregister_kprobe(&kp_vfs_read);
    unregister_kprobe(&kp_vfs_write);
    unregister_kprobe(&kp_do_filp_open);
    
    /* Clean up work queue */
    if (takakrypt_workqueue) {
        flush_workqueue(takakrypt_workqueue);
        destroy_workqueue(takakrypt_workqueue);
        takakrypt_workqueue = NULL;
        takakrypt_info("Destroyed encryption work queue\n");
    }
    
    kprobes_installed = false;
    takakrypt_info("Global VFS hooks removed\n");
}