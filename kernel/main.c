/* Enhanced logging added for debugging */

#include "takakrypt.h"

/* Module parameters */
static uint32_t debug_level = TAKAKRYPT_LOG_LEVEL_INFO;
module_param(debug_level, uint, 0644);
MODULE_PARM_DESC(debug_level, "Debug level (1=error, 2=warn, 3=info, 4=debug)");

static uint32_t cache_timeout = 300; /* 5 minutes */
module_param(cache_timeout, uint, 0644);
MODULE_PARM_DESC(cache_timeout, "Policy cache timeout in seconds");

static uint32_t max_file_size = 100 * 1024 * 1024; /* 100MB */
module_param(max_file_size, uint, 0644);
MODULE_PARM_DESC(max_file_size, "Maximum file size for encryption (bytes)");

/* Global state */
struct takakrypt_state *takakrypt_global_state = NULL;
uint32_t takakrypt_debug_level = TAKAKRYPT_LOG_LEVEL_INFO;

/* Original file operations storage */
const struct file_operations *original_file_ops = NULL;
struct file_operations takakrypt_hooked_fops;

/**
 * takakrypt_init_state - Initialize global module state
 */
static int takakrypt_init_state(void)
{
    int i;
    
    takakrypt_global_state = kzalloc(sizeof(struct takakrypt_state), GFP_KERNEL);
    if (!takakrypt_global_state) {
        takakrypt_error("Failed to allocate global state\n");
        return -ENOMEM;
    }
    
    /* Initialize configuration */
    takakrypt_global_state->config.enabled = 1;
    takakrypt_global_state->config.debug_level = debug_level;
    takakrypt_global_state->config.cache_timeout = cache_timeout;
    takakrypt_global_state->config.request_timeout = 30;
    takakrypt_global_state->config.max_file_size = max_file_size;
    takakrypt_global_state->config.max_concurrent_ops = 100;
    
    /* Initialize locks */
    mutex_init(&takakrypt_global_state->config_lock);
    mutex_init(&takakrypt_global_state->guard_points_lock);
    spin_lock_init(&takakrypt_global_state->stats_lock);
    spin_lock_init(&takakrypt_global_state->cache_lock);
    spin_lock_init(&takakrypt_global_state->file_contexts_lock);
    
    /* Initialize guard points */
    takakrypt_global_state->guard_points.count = 0;
    
    /* Initialize lists */
    INIT_LIST_HEAD(&takakrypt_global_state->file_contexts);
    
    /* Initialize cache */
    takakrypt_global_state->cache_size = TAKAKRYPT_CACHE_SIZE;
    takakrypt_global_state->policy_cache = kzalloc(
        sizeof(struct hlist_head) * TAKAKRYPT_CACHE_SIZE, GFP_KERNEL);
    if (!takakrypt_global_state->policy_cache) {
        takakrypt_error("Failed to allocate policy cache\n");
        kfree(takakrypt_global_state);
        return -ENOMEM;
    }
    
    for (i = 0; i < TAKAKRYPT_CACHE_SIZE; i++) {
        INIT_HLIST_HEAD(&takakrypt_global_state->policy_cache[i]);
    }
    
    /* Initialize atomic variables */
    atomic_set(&takakrypt_global_state->sequence_counter, 1);
    atomic_set(&takakrypt_global_state->module_active, 1);
    
    /* Initialize statistics */
    memset(&takakrypt_global_state->stats, 0, sizeof(struct takakrypt_status_info));
    takakrypt_global_state->stats.module_loaded = 1;
    takakrypt_global_state->start_time = jiffies;
    
    /* Create workqueue */
    takakrypt_global_state->workqueue = create_singlethread_workqueue("takakrypt_wq");
    if (!takakrypt_global_state->workqueue) {
        takakrypt_error("Failed to create workqueue\n");
        kfree(takakrypt_global_state->policy_cache);
        kfree(takakrypt_global_state);
        return -ENOMEM;
    }
    
    takakrypt_debug_level = debug_level;
    takakrypt_info("Global state initialized successfully\n");
    
    return 0;
}

/**
 * takakrypt_cleanup_state - Cleanup global module state
 */
static void takakrypt_cleanup_state(void)
{
    if (!takakrypt_global_state)
        return;
        
    atomic_set(&takakrypt_global_state->module_active, 0);
    
    /* Destroy workqueue */
    if (takakrypt_global_state->workqueue) {
        destroy_workqueue(takakrypt_global_state->workqueue);
    }
    
    /* Cleanup cache */
    takakrypt_cache_cleanup();
    
    /* Cleanup file contexts */
    takakrypt_cleanup_file_contexts();
    
    /* Free policy cache */
    if (takakrypt_global_state->policy_cache) {
        kfree(takakrypt_global_state->policy_cache);
    }
    
    /* Free global state */
    kfree(takakrypt_global_state);
    takakrypt_global_state = NULL;
    
    takakrypt_info("Global state cleaned up\n");
}

/**
 * takakrypt_install_hooks - Install VFS hooks
 */
static int takakrypt_install_hooks(void)
{
    /* Initialize VFS hooks system */
    takakrypt_info("Initializing VFS hooks for transparent encryption\n");
    takakrypt_info("VFS hooks will intercept file operations on protected paths\n");
    takakrypt_info("Supported operations: read_iter, write_iter, open, release\n");
    
    /* VFS hooks are now implemented and will be installed per-file as needed */
    takakrypt_info("VFS hooks ready - files will be hooked on first access\n");
    
    return 0;
}

/**
 * takakrypt_remove_hooks - Remove VFS hooks
 */
static void takakrypt_remove_hooks(void)
{
    takakrypt_info("VFS hooks would be removed here\n");
    
    /* Restore original file operations if they were hooked */
    if (original_file_ops) {
        /* Restore operations */
        original_file_ops = NULL;
    }
}

/**
 * takakrypt_health_check - Perform module health check
 */
static int takakrypt_health_check(void)
{
    if (!takakrypt_global_state) {
        takakrypt_error("Global state not initialized\n");
        return -EINVAL;
    }
    
    if (!atomic_read(&takakrypt_global_state->module_active)) {
        takakrypt_error("Module not active\n");
        return -EINVAL;
    }
    
    if (!takakrypt_global_state->netlink_sock) {
        takakrypt_warn("Netlink socket not initialized\n");
        return -ENOTCONN;
    }
    
    takakrypt_debug("Health check passed\n");
    return 0;
}

/**
 * takakrypt_init_module - Module initialization function
 */
static int __init takakrypt_init_module(void)
{
    int ret;
    
    printk(KERN_INFO TAKAKRYPT_MODULE_NAME ": Loading Takakrypt Transparent Encryption Module v" TAKAKRYPT_VERSION "\n");
    
    /* Initialize global state */
    ret = takakrypt_init_state();
    if (ret) {
        takakrypt_error("Failed to initialize global state: %d\n", ret);
        return ret;
    }
    
    /* Initialize netlink communication */
    ret = takakrypt_netlink_init();
    if (ret) {
        takakrypt_error("Failed to initialize netlink: %d\n", ret);
        goto cleanup_state;
    }
    
    /* Initialize proc filesystem interface */
    ret = takakrypt_proc_init();
    if (ret) {
        takakrypt_error("Failed to initialize proc interface: %d\n", ret);
        goto cleanup_netlink;
    }
    
    /* Install VFS hooks */
    ret = takakrypt_install_hooks();
    if (ret) {
        takakrypt_error("Failed to install VFS hooks: %d\n", ret);
        goto cleanup_proc;
    }
    
    /* Install global kprobe hooks */
    ret = takakrypt_install_global_hooks();
    if (ret) {
        takakrypt_warn("Failed to install global hooks: %d\n", ret);
        /* Continue - this is not fatal */
    }
    
    /* Perform initial health check */
    ret = takakrypt_health_check();
    if (ret) {
        takakrypt_warn("Initial health check failed: %d\n", ret);
        /* Continue loading - agent might not be running yet */
    }
    
    takakrypt_info("Module loaded successfully\n");
    takakrypt_info("Waiting for user-space agent connection...\n");
    
    return 0;

cleanup_proc:
    takakrypt_proc_cleanup();
cleanup_netlink:
    takakrypt_netlink_cleanup();
cleanup_state:
    takakrypt_cleanup_state();
    return ret;
}

/**
 * takakrypt_cleanup_module - Module cleanup function
 */
static void __exit takakrypt_cleanup_module(void)
{
    takakrypt_info("Unloading Takakrypt Transparent Encryption Module\n");
    
    /* Remove VFS hooks */
    takakrypt_remove_hooks();
    
    /* Remove global hooks */
    takakrypt_remove_global_hooks();
    
    /* Cleanup proc interface */
    takakrypt_proc_cleanup();
    
    /* Cleanup netlink communication */
    takakrypt_netlink_cleanup();
    
    /* Cleanup global state */
    takakrypt_cleanup_state();
    
    printk(KERN_INFO TAKAKRYPT_MODULE_NAME ": Module unloaded successfully\n");
}

/* Module metadata */
MODULE_LICENSE("GPL");
MODULE_AUTHOR(TAKAKRYPT_AUTHOR);
MODULE_DESCRIPTION(TAKAKRYPT_DESCRIPTION);
MODULE_VERSION(TAKAKRYPT_VERSION);
MODULE_ALIAS("takakrypt");

/* Module entry points */
module_init(takakrypt_init_module);
module_exit(takakrypt_cleanup_module);

/* Export symbols for other kernel modules if needed */
EXPORT_SYMBOL(takakrypt_global_state);
EXPORT_SYMBOL(takakrypt_send_request_and_wait);