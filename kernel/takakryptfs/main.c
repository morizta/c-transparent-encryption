#include "takakryptfs.h"

MODULE_AUTHOR(TAKAKRYPTFS_AUTHOR);
MODULE_DESCRIPTION(TAKAKRYPTFS_DESCRIPTION);
MODULE_LICENSE("GPL");
MODULE_VERSION(TAKAKRYPTFS_VERSION);

/* Forward declarations */
static int takakryptfs_parse_param(struct fs_context *fc, struct fs_parameter *param);
static int takakryptfs_get_tree(struct fs_context *fc);
static void takakryptfs_free_fc(struct fs_context *fc);
static int takakryptfs_init_fs_context(struct fs_context *fc);

/* Filesystem context operations */
static const struct fs_context_operations takakryptfs_context_ops = {
    .parse_param = takakryptfs_parse_param,
    .get_tree = takakryptfs_get_tree,
    .free = takakryptfs_free_fc,
};

/* Mount parameter specifications */
static const struct fs_parameter_spec takakryptfs_param_specs[] = {
    fsparam_string("lowerdir", TAKAKRYPTFS_OPT_LOWERDIR),
    fsparam_string("policy", TAKAKRYPTFS_OPT_POLICY), 
    fsparam_flag("readonly", TAKAKRYPTFS_OPT_READONLY),
    fsparam_u32("debug", TAKAKRYPTFS_OPT_DEBUG),
    {}
};

/**
 * takakryptfs_parse_param - Parse mount parameters
 * @fc: Filesystem context
 * @param: Parameter to parse
 * 
 * Returns: 0 on success, negative error code on failure
 */
static int takakryptfs_parse_param(struct fs_context *fc, struct fs_parameter *param)
{
    struct takakryptfs_mount_ctx *ctx = fc->fs_private;
    struct fs_parse_result result;
    int opt;
    
    takakryptfs_debug("Parsing mount parameter: %s=%s\n", 
                      param->key, param->string ? param->string : "(null)");
    
    opt = fs_parse(fc, takakryptfs_param_specs, param, &result);
    if (opt < 0) {
        takakryptfs_error("Unknown mount option: %s\n", param->key);
        return opt;
    }
    
    switch (opt) {
    case TAKAKRYPTFS_OPT_LOWERDIR:
        if (!param->string || strlen(param->string) == 0) {
            takakryptfs_error("Empty lowerdir parameter\n");
            return -EINVAL;
        }
        kfree(ctx->lower_path);
        ctx->lower_path = kstrdup(param->string, GFP_KERNEL);
        if (!ctx->lower_path) {
            return -ENOMEM;
        }
        takakryptfs_debug("Lower directory: %s\n", ctx->lower_path);
        break;
        
    case TAKAKRYPTFS_OPT_POLICY:
        if (!param->string || strlen(param->string) == 0) {
            takakryptfs_error("Empty policy parameter\n");
            return -EINVAL;
        }
        kfree(ctx->policy_name);
        ctx->policy_name = kstrdup(param->string, GFP_KERNEL);
        if (!ctx->policy_name) {
            return -ENOMEM;
        }
        takakryptfs_debug("Policy name: %s\n", ctx->policy_name);
        break;
        
    case TAKAKRYPTFS_OPT_READONLY:
        ctx->readonly = true;
        takakryptfs_debug("Read-only mount enabled\n");
        break;
        
    case TAKAKRYPTFS_OPT_DEBUG:
        ctx->debug_level = result.uint_32;
        takakryptfs_debug("Debug level: %d\n", ctx->debug_level);
        break;
        
    default:
        takakryptfs_error("Unhandled mount option: %d\n", opt);
        return -EINVAL;
    }
    
    return 0;
}

/**
 * takakryptfs_validate_mount_options - Validate mount context
 * @ctx: Mount context to validate
 * 
 * Returns: 0 if valid, negative error code if invalid
 */
static int takakryptfs_validate_mount_options(struct takakryptfs_mount_ctx *ctx)
{
    if (!ctx->lower_path) {
        takakryptfs_error("Missing required lowerdir parameter\n");
        return -EINVAL;
    }
    
    if (!ctx->policy_name) {
        takakryptfs_warn("No policy specified, using default policy\n");
        ctx->policy_name = kstrdup("default", GFP_KERNEL);
        if (!ctx->policy_name) {
            return -ENOMEM;
        }
    }
    
    takakryptfs_info("Mount options validated: lowerdir=%s, policy=%s, readonly=%s\n",
                     ctx->lower_path, ctx->policy_name, ctx->readonly ? "yes" : "no");
    
    return 0;
}

/**
 * takakryptfs_get_tree - Build filesystem tree
 * @fc: Filesystem context
 * 
 * Returns: 0 on success, negative error code on failure
 */
static int takakryptfs_get_tree(struct fs_context *fc)
{
    struct takakryptfs_mount_ctx *ctx = fc->fs_private;
    int ret;
    
    takakryptfs_debug("Building filesystem tree\n");
    
    /* Validate mount options */
    ret = takakryptfs_validate_mount_options(ctx);
    if (ret) {
        return ret;
    }
    
    /* Resolve lower directory path */
    ret = kern_path(ctx->lower_path, LOOKUP_FOLLOW, &ctx->lower_root);
    if (ret) {
        takakryptfs_error("Failed to resolve lower directory: %s (%d)\n", 
                          ctx->lower_path, ret);
        return ret;
    }
    
    /* Verify lower directory is a directory */
    if (!d_is_dir(ctx->lower_root.dentry)) {
        takakryptfs_error("Lower path is not a directory: %s\n", ctx->lower_path);
        path_put(&ctx->lower_root);
        return -ENOTDIR;
    }
    
    /* Get super block using the generic helper */
    return get_tree_nodev(fc, takakryptfs_fill_super);
}

/**
 * takakryptfs_free_fc - Free filesystem context
 * @fc: Filesystem context to free
 */
static void takakryptfs_free_fc(struct fs_context *fc)
{
    struct takakryptfs_mount_ctx *ctx = fc->fs_private;
    
    if (ctx) {
        takakryptfs_debug("Freeing filesystem context\n");
        takakryptfs_free_mount_ctx(ctx);
        kfree(ctx);
    }
}

/**
 * takakryptfs_init_fs_context - Initialize filesystem context
 * @fc: Filesystem context
 * 
 * Returns: 0 on success, negative error code on failure
 */
static int takakryptfs_init_fs_context(struct fs_context *fc)
{
    struct takakryptfs_mount_ctx *ctx;
    
    takakryptfs_debug("Initializing filesystem context\n");
    
    ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
    if (!ctx) {
        return -ENOMEM;
    }
    
    /* Set default values */
    ctx->readonly = false;
    ctx->debug_level = 0;
    
    fc->fs_private = ctx;
    fc->ops = &takakryptfs_context_ops;
    
    takakryptfs_debug("Filesystem context initialized\n");
    return 0;
}

/* Filesystem type structure */
struct file_system_type takakryptfs_type = {
    .owner = THIS_MODULE,
    .name = TAKAKRYPTFS_MODULE_NAME,
    .init_fs_context = takakryptfs_init_fs_context,
    .parameters = takakryptfs_param_specs,
    .kill_sb = takakryptfs_kill_super,
    .fs_flags = FS_REQUIRES_DEV | FS_ALLOW_IDMAP,
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
    
    /* Register filesystem type */
    ret = register_filesystem(&takakryptfs_type);
    if (ret) {
        takakryptfs_error("Failed to register filesystem: %d\n", ret);
        return ret;
    }
    
    takakryptfs_info("Takakrypt stackable filesystem registered successfully\n");
    takakryptfs_info("Usage: mount -t takakryptfs -o lowerdir=/path,policy=name takakryptfs /mountpoint\n");
    
    return 0;
}

/**
 * takakryptfs_exit - Module cleanup
 */
static void __exit takakryptfs_exit(void)
{
    takakryptfs_info("Unloading %s v%s\n", TAKAKRYPTFS_DESCRIPTION, TAKAKRYPTFS_VERSION);
    
    /* Unregister filesystem type */
    unregister_filesystem(&takakryptfs_type);
    
    takakryptfs_info("Takakrypt stackable filesystem unregistered\n");
}

module_init(takakryptfs_init);
module_exit(takakryptfs_exit);