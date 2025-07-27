#include "takakryptfs.h"

MODULE_AUTHOR(TAKAKRYPTFS_AUTHOR);
MODULE_DESCRIPTION(TAKAKRYPTFS_DESCRIPTION);
MODULE_LICENSE("GPL");
MODULE_VERSION(TAKAKRYPTFS_VERSION);

/* Forward declarations */
static struct dentry *takakryptfs_mount(struct file_system_type *fs_type, int flags,
                                        const char *dev_name, void *data);

/**
 * takakryptfs_parse_options - Parse mount options string
 * @options: Options string to parse
 * @ctx: Mount context to fill
 * 
 * Returns: 0 on success, negative error code on failure
 */
static int takakryptfs_parse_options(char *options, struct takakryptfs_mount_ctx *ctx)
{
    char *opt, *val;
    
    if (!ctx) {
        return -EINVAL;
    }
    
    /* Set defaults */
    ctx->lower_path = NULL;
    ctx->policy_name = NULL;
    ctx->readonly = false;
    ctx->debug_level = 0;
    
    if (!options) {
        takakryptfs_error("No mount options provided\n");
        return -EINVAL;
    }
    
    takakryptfs_debug("Parsing mount options: %s\n", options);
    
    /* Parse options */
    while ((opt = strsep(&options, ",")) != NULL) {
        if (!*opt) {
            continue;
        }
        
        val = strchr(opt, '=');
        if (val) {
            *val++ = '\0';
        }
        
        if (strcmp(opt, "lowerdir") == 0) {
            if (!val || strlen(val) == 0) {
                takakryptfs_error("Empty lowerdir parameter\n");
                return -EINVAL;
            }
            kfree(ctx->lower_path);
            ctx->lower_path = kstrdup(val, GFP_KERNEL);
            if (!ctx->lower_path) {
                return -ENOMEM;
            }
            takakryptfs_debug("Lower directory: %s\n", ctx->lower_path);
            
        } else if (strcmp(opt, "policy") == 0) {
            if (!val || strlen(val) == 0) {
                takakryptfs_error("Empty policy parameter\n");
                return -EINVAL;
            }
            kfree(ctx->policy_name);
            ctx->policy_name = kstrdup(val, GFP_KERNEL);
            if (!ctx->policy_name) {
                return -ENOMEM;
            }
            takakryptfs_debug("Policy name: %s\n", ctx->policy_name);
            
        } else if (strcmp(opt, "readonly") == 0) {
            ctx->readonly = true;
            takakryptfs_debug("Read-only mount enabled\n");
            
        } else if (strcmp(opt, "debug") == 0) {
            if (val) {
                if (kstrtoint(val, 10, &ctx->debug_level) != 0) {
                    takakryptfs_warn("Invalid debug level: %s\n", val);
                    ctx->debug_level = 1;
                }
            } else {
                ctx->debug_level = 1;
            }
            takakryptfs_debug("Debug level: %d\n", ctx->debug_level);
            
        } else {
            takakryptfs_warn("Unknown mount option: %s\n", opt);
        }
    }
    
    return 0;
}

/**
 * takakryptfs_mount - Mount the filesystem
 * @fs_type: Filesystem type
 * @flags: Mount flags
 * @dev_name: Device name (unused for stackable filesystem)
 * @data: Mount options string
 * 
 * Returns: Root dentry on success, ERR_PTR on failure
 */
static struct dentry *takakryptfs_mount(struct file_system_type *fs_type, int flags,
                                        const char *dev_name, void *data)
{
    struct takakryptfs_mount_ctx ctx;
    struct super_block *sb;
    struct dentry *root_dentry;
    int ret;
    
    takakryptfs_info("Mounting takakryptfs\n");
    
    /* Initialize mount context */
    memset(&ctx, 0, sizeof(ctx));
    
    /* Parse mount options */
    ret = takakryptfs_parse_options((char *)data, &ctx);
    if (ret) {
        takakryptfs_error("Failed to parse mount options: %d\n", ret);
        goto err_free_ctx;
    }
    
    /* Validate mount context */
    ret = takakryptfs_validate_mount_ctx(&ctx);
    if (ret) {
        takakryptfs_error("Mount context validation failed: %d\n", ret);
        goto err_free_ctx;
    }
    
    /* Set up lower path */
    ret = takakryptfs_setup_lower_path(&ctx);
    if (ret) {
        takakryptfs_error("Failed to setup lower path: %d\n", ret);
        goto err_free_ctx;
    }
    
    /* Get superblock */
    sb = sget(fs_type, NULL, set_anon_super, flags, NULL);
    if (IS_ERR(sb)) {
        ret = PTR_ERR(sb);
        takakryptfs_error("Failed to get superblock: %d\n", ret);
        goto err_free_ctx;
    }
    
    /* Fill superblock - using legacy API */
    ret = takakryptfs_fill_super_legacy(sb, &ctx, flags & SB_SILENT);
    if (ret) {
        deactivate_locked_super(sb);
        goto err_free_ctx;
    }
    
    /* Get root dentry */
    root_dentry = dget(sb->s_root);
    
    takakryptfs_info("Mount successful: %s -> %s (policy: %s)\n",
                     ctx.lower_path, dev_name, ctx.policy_name);
    
    /* Don't free context here - it's copied to superblock */
    return root_dentry;
    
err_free_ctx:
    takakryptfs_free_mount_ctx(&ctx);
    return ERR_PTR(ret);
}

/**
 * takakryptfs_kill_sb - Kill superblock during unmount
 * @sb: Super block to kill
 */
static void takakryptfs_kill_sb(struct super_block *sb)
{
    takakryptfs_info("Unmounting takakryptfs\n");
    
    /* Call standard kill routine */
    kill_anon_super(sb);
}

/* Filesystem type structure */
struct file_system_type takakryptfs_type = {
    .owner = THIS_MODULE,
    .name = TAKAKRYPTFS_MODULE_NAME,
    .mount = takakryptfs_mount,
    .kill_sb = takakryptfs_kill_sb,
    .fs_flags = 0, /* No special flags needed for stackable filesystem */
};

/**
 * takakryptfs_init - Module initialization
 * 
 * Returns: 0 on success, negative error code on failure
 */
static int __init takakryptfs_init(void)
{
    int ret;
    
    takakryptfs_info("Initializing %s v%s\n", TAKAKRYPTFS_DESCRIPTION, TAKAKRYPTFS_VERSION);
    
    /* Initialize crypto subsystem */
    ret = takakryptfs_crypto_init();
    if (ret) {
        takakryptfs_error("Failed to initialize crypto subsystem: %d\n", ret);
        return ret;
    }
    
    /* Initialize policy subsystem */
    ret = takakryptfs_policy_init();
    if (ret) {
        takakryptfs_error("Failed to initialize policy subsystem: %d\n", ret);
        goto err_crypto_exit;
    }
    
    /* Register filesystem type */
    ret = register_filesystem(&takakryptfs_type);
    if (ret) {
        takakryptfs_error("Failed to register filesystem: %d\n", ret);
        goto err_policy_exit;
    }
    
    takakryptfs_info("Takakrypt stackable filesystem registered successfully\n");
    takakryptfs_info("Usage: mount -t takakryptfs -o lowerdir=/path,policy=name none /mountpoint\n");
    
    return 0;
    
err_policy_exit:
    takakryptfs_policy_exit();
err_crypto_exit:
    takakryptfs_crypto_exit();
    return ret;
}

/**
 * takakryptfs_exit - Module cleanup
 */
static void __exit takakryptfs_exit(void)
{
    takakryptfs_info("Unloading %s v%s\n", TAKAKRYPTFS_DESCRIPTION, TAKAKRYPTFS_VERSION);
    
    /* Unregister filesystem type */
    unregister_filesystem(&takakryptfs_type);
    
    /* Clean up subsystems */
    takakryptfs_policy_exit();
    takakryptfs_crypto_exit();
    
    takakryptfs_info("Takakrypt stackable filesystem unregistered\n");
}

module_init(takakryptfs_init);
module_exit(takakryptfs_exit);