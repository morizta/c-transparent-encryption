#include "takakryptfs.h"

/**
 * takakryptfs_free_mount_ctx - Free mount context resources
 * @ctx: Mount context to free
 */
void takakryptfs_free_mount_ctx(struct takakryptfs_mount_ctx *ctx)
{
    if (!ctx) {
        return;
    }
    
    takakryptfs_debug("Freeing mount context\n");
    
    /* Free allocated strings */
    kfree(ctx->lower_path);
    ctx->lower_path = NULL;
    
    kfree(ctx->policy_name);
    ctx->policy_name = NULL;
    
    /* Release lower root path */
    if (ctx->lower_root.dentry) {
        path_put(&ctx->lower_root);
        memset(&ctx->lower_root, 0, sizeof(ctx->lower_root));
    }
}

/**
 * takakryptfs_validate_mount_ctx - Validate mount context
 * @ctx: Mount context to validate
 * 
 * Returns: 0 if valid, negative error code if invalid
 */
int takakryptfs_validate_mount_ctx(struct takakryptfs_mount_ctx *ctx)
{
    struct path lower_path;
    int ret;
    
    if (!ctx) {
        return -EINVAL;
    }
    
    /* Check required parameters */
    if (!ctx->lower_path) {
        takakryptfs_error("Missing required lowerdir parameter\n");
        return -EINVAL;
    }
    
    /* Validate lower directory exists and is accessible */
    ret = kern_path(ctx->lower_path, LOOKUP_FOLLOW, &lower_path);
    if (ret) {
        takakryptfs_error("Cannot access lower directory '%s': %d\n", 
                          ctx->lower_path, ret);
        return ret;
    }
    
    /* Check if lower path is a directory */
    if (!d_is_dir(lower_path.dentry)) {
        takakryptfs_error("Lower path is not a directory: %s\n", ctx->lower_path);
        path_put(&lower_path);
        return -ENOTDIR;
    }
    
    /* Check permissions */
    if (!inode_permission(&init_user_ns, d_inode(lower_path.dentry), MAY_READ)) {
        if (!ctx->readonly && 
            !inode_permission(&init_user_ns, d_inode(lower_path.dentry), MAY_WRITE)) {
            takakryptfs_warn("Lower directory may not be writable: %s\n", ctx->lower_path);
        }
    } else {
        takakryptfs_error("Lower directory is not readable: %s\n", ctx->lower_path);
        path_put(&lower_path);
        return -EACCES;
    }
    
    path_put(&lower_path);
    
    /* Set default policy if not specified */
    if (!ctx->policy_name) {
        ctx->policy_name = kstrdup("default", GFP_KERNEL);
        if (!ctx->policy_name) {
            return -ENOMEM;
        }
        takakryptfs_debug("Using default policy\n");
    }
    
    /* Validate policy name */
    if (strlen(ctx->policy_name) == 0 || strlen(ctx->policy_name) > 63) {
        takakryptfs_error("Invalid policy name length: %zu\n", strlen(ctx->policy_name));
        return -EINVAL;
    }
    
    /* Check for invalid characters in policy name */
    if (strpbrk(ctx->policy_name, " \t\n\r/\\")) {
        takakryptfs_error("Policy name contains invalid characters: %s\n", ctx->policy_name);
        return -EINVAL;
    }
    
    takakryptfs_debug("Mount context validation successful\n");
    takakryptfs_debug("  Lower directory: %s\n", ctx->lower_path);
    takakryptfs_debug("  Policy: %s\n", ctx->policy_name);
    takakryptfs_debug("  Read-only: %s\n", ctx->readonly ? "yes" : "no");
    takakryptfs_debug("  Debug level: %d\n", ctx->debug_level);
    
    return 0;
}

/**
 * takakryptfs_check_lower_fs_compatibility - Check if lower filesystem is compatible
 * @lower_sb: Lower filesystem superblock
 * 
 * Returns: 0 if compatible, negative error code if incompatible
 */
static int takakryptfs_check_lower_fs_compatibility(struct super_block *lower_sb)
{
    /* Check if lower filesystem supports extended attributes */
    if (!(lower_sb->s_xattr)) {
        takakryptfs_warn("Lower filesystem does not support extended attributes\n");
        /* This is a warning, not an error - we can still work without xattrs */
    }
    
    /* Check block size compatibility */
    if (lower_sb->s_blocksize < 512) {
        takakryptfs_error("Lower filesystem block size too small: %lu\n", lower_sb->s_blocksize);
        return -EINVAL;
    }
    
    /* Check if lower filesystem supports required operations */
    if (!lower_sb->s_op) {
        takakryptfs_error("Lower filesystem has no superblock operations\n");
        return -EINVAL;
    }
    
    /* Check filesystem type - warn about known problematic types */
    if (lower_sb->s_magic == 0x9fa0) {  /* PROC_SUPER_MAGIC */
        takakryptfs_error("Cannot mount over procfs\n");
        return -EINVAL;
    }
    
    if (lower_sb->s_magic == 0x62656572) {  /* SYSFS_MAGIC */
        takakryptfs_error("Cannot mount over sysfs\n");
        return -EINVAL;
    }
    
    if (lower_sb->s_magic == 0x1373) {  /* DEVFS_SUPER_MAGIC */
        takakryptfs_error("Cannot mount over devfs\n");
        return -EINVAL;
    }
    
    takakryptfs_debug("Lower filesystem compatibility check passed\n");
    takakryptfs_debug("  Filesystem magic: 0x%lx\n", lower_sb->s_magic);
    takakryptfs_debug("  Block size: %lu\n", lower_sb->s_blocksize);
    takakryptfs_debug("  Max file size: %lld\n", lower_sb->s_maxbytes);
    
    return 0;
}

/**
 * takakryptfs_setup_lower_path - Set up lower filesystem path
 * @ctx: Mount context
 * 
 * Returns: 0 on success, negative error code on failure
 */
int takakryptfs_setup_lower_path(struct takakryptfs_mount_ctx *ctx)
{
    int ret;
    
    if (!ctx || !ctx->lower_path) {
        return -EINVAL;
    }
    
    /* Resolve the lower directory path */
    ret = kern_path(ctx->lower_path, LOOKUP_FOLLOW | LOOKUP_DIRECTORY, &ctx->lower_root);
    if (ret) {
        takakryptfs_error("Failed to resolve lower directory path '%s': %d\n", 
                          ctx->lower_path, ret);
        return ret;
    }
    
    /* Verify it's a directory */
    if (!d_is_dir(ctx->lower_root.dentry)) {
        takakryptfs_error("Lower path is not a directory: %s\n", ctx->lower_path);
        path_put(&ctx->lower_root);
        return -ENOTDIR;
    }
    
    /* Check lower filesystem compatibility */
    ret = takakryptfs_check_lower_fs_compatibility(ctx->lower_root.dentry->d_sb);
    if (ret) {
        path_put(&ctx->lower_root);
        return ret;
    }
    
    takakryptfs_debug("Lower path setup successful: %s\n", ctx->lower_path);
    return 0;
}

/**
 * takakryptfs_copy_mount_ctx - Copy mount context
 * @dst: Destination context
 * @src: Source context
 * 
 * Returns: 0 on success, negative error code on failure
 */
int takakryptfs_copy_mount_ctx(struct takakryptfs_mount_ctx *dst, 
                               const struct takakryptfs_mount_ctx *src)
{
    if (!dst || !src) {
        return -EINVAL;
    }
    
    /* Initialize destination */
    memset(dst, 0, sizeof(*dst));
    
    /* Copy string fields */
    if (src->lower_path) {
        dst->lower_path = kstrdup(src->lower_path, GFP_KERNEL);
        if (!dst->lower_path) {
            return -ENOMEM;
        }
    }
    
    if (src->policy_name) {
        dst->policy_name = kstrdup(src->policy_name, GFP_KERNEL);
        if (!dst->policy_name) {
            kfree(dst->lower_path);
            return -ENOMEM;
        }
    }
    
    /* Copy simple fields */
    dst->readonly = src->readonly;
    dst->debug_level = src->debug_level;
    
    /* Note: lower_root path is not copied - it needs to be resolved separately */
    
    return 0;
}

/**
 * takakryptfs_mount_show_stats - Show mount statistics
 * @ctx: Mount context
 * @m: Sequence file for output
 * 
 * Returns: 0 on success
 */
int takakryptfs_mount_show_stats(struct takakryptfs_mount_ctx *ctx, struct seq_file *m)
{
    if (!ctx) {
        return -EINVAL;
    }
    
    seq_printf(m, "takakryptfs mount statistics:\n");
    seq_printf(m, "  Lower directory: %s\n", ctx->lower_path ? ctx->lower_path : "(null)");
    seq_printf(m, "  Policy: %s\n", ctx->policy_name ? ctx->policy_name : "(null)");
    seq_printf(m, "  Read-only: %s\n", ctx->readonly ? "yes" : "no");
    seq_printf(m, "  Debug level: %d\n", ctx->debug_level);
    
    if (ctx->lower_root.dentry && ctx->lower_root.dentry->d_sb) {
        struct super_block *lower_sb = ctx->lower_root.dentry->d_sb;
        seq_printf(m, "  Lower filesystem:\n");
        seq_printf(m, "    Magic: 0x%lx\n", lower_sb->s_magic);
        seq_printf(m, "    Block size: %lu\n", lower_sb->s_blocksize);
        seq_printf(m, "    Max file size: %lld\n", lower_sb->s_maxbytes);
    }
    
    return 0;
}