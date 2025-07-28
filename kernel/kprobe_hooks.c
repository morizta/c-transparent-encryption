/* Enhanced logging added for debugging */

#include "takakrypt.h"
#include <linux/kprobes.h>
#include <linux/version.h>

/* External function from vfs_hooks.c */
extern int takakrypt_install_file_hooks(struct file *file);

/* Kprobe handlers for VFS interception */
static struct kprobe kp_vfs_read;
static struct kprobe kp_vfs_write;
static bool kprobes_installed = false;

/**
 * Pre-handler for vfs_read
 */
static int pre_vfs_read(struct kprobe *p, struct pt_regs *regs)
{
    struct file *file;
    char filepath[TAKAKRYPT_MAX_PATH_LEN];
    
    /* Always log that kprobe was triggered */
    takakrypt_info("KPROBE: vfs_read intercepted\n");
    
    /* Get file parameter from registers (first argument) */
#ifdef CONFIG_X86_64
    file = (struct file *)regs->di;
#else
    file = (struct file *)regs->ARM_r0;
#endif
    
    if (!file) {
        takakrypt_debug("KPROBE: vfs_read - no file pointer\n");
        return 0;
    }
    
    if (!takakrypt_should_intercept_file(file)) {
        return 0;
    }
    
    /* Get file path for debugging */
    if (takakrypt_get_file_path(file, filepath, sizeof(filepath)) == 0) {
        takakrypt_info("KPROBE: Intercepted vfs_read for: %s\n", filepath);
        
        /* Update statistics */
        spin_lock(&takakrypt_global_state->stats_lock);
        takakrypt_global_state->stats.requests_processed++;
        spin_unlock(&takakrypt_global_state->stats_lock);
        
        /* Check policy */
        takakrypt_check_policy(file, TAKAKRYPT_FILE_OP_READ);
        
        /* Install VFS hooks for this file */
        takakrypt_install_file_hooks(file);
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
    
    /* Always log that kprobe was triggered */
    takakrypt_info("KPROBE: vfs_write intercepted\n");
    
    /* Get file parameter from registers (first argument) */
#ifdef CONFIG_X86_64
    file = (struct file *)regs->di;
#else
    file = (struct file *)regs->ARM_r0;
#endif
    
    if (!file) {
        takakrypt_debug("KPROBE: vfs_write - no file pointer\n");
        return 0;
    }
    
    if (!takakrypt_should_intercept_file(file)) {
        return 0;
    }
    
    /* Get file path for debugging */
    if (takakrypt_get_file_path(file, filepath, sizeof(filepath)) == 0) {
        takakrypt_info("KPROBE: Intercepted vfs_write for: %s\n", filepath);
        
        /* Update statistics */
        spin_lock(&takakrypt_global_state->stats_lock);
        takakrypt_global_state->stats.requests_processed++;
        spin_unlock(&takakrypt_global_state->stats_lock);
        
        /* Check policy */
        takakrypt_check_policy(file, TAKAKRYPT_FILE_OP_WRITE);
        
        /* Install VFS hooks for this file */
        takakrypt_install_file_hooks(file);
    }
    
    return 0;
}

/**
 * Check if file should be intercepted
 */
int takakrypt_should_intercept_file(struct file *file)
{
    char filepath[TAKAKRYPT_MAX_PATH_LEN];
    
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
    
    /* Only intercept files in test directory for now */
    if (strstr(filepath, "/tmp/takakrypt-test") != NULL) {
        return 1;
    }
    
    return 0;
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
    
    /* Try vfs_write first, fallback to new_sync_write */
    kp_vfs_write.symbol_name = "vfs_write";
    kp_vfs_write.pre_handler = pre_vfs_write;
    
    ret = register_kprobe(&kp_vfs_write);
    if (ret < 0) {
        takakrypt_warn("Failed to register vfs_write kprobe: %d, trying new_sync_write\n", ret);
        /* Try alternative function */
        kp_vfs_write.symbol_name = "new_sync_write";
        ret = register_kprobe(&kp_vfs_write);
        if (ret < 0) {
            takakrypt_error("Failed to register new_sync_write kprobe: %d\n", ret);
            unregister_kprobe(&kp_vfs_read);
            return ret;
        } else {
            takakrypt_info("Registered new_sync_write kprobe successfully\n");
        }
    } else {
        takakrypt_info("Registered vfs_write kprobe successfully\n");
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
    
    kprobes_installed = false;
    takakrypt_info("Global VFS hooks removed\n");
}