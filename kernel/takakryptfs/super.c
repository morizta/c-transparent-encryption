#include "takakryptfs.h"

/**
 * takakryptfs_alloc_inode - Allocate a new inode
 * @sb: Super block
 * 
 * Returns: Allocated inode or NULL on failure
 */
static struct inode *takakryptfs_alloc_inode(struct super_block *sb)
{
    struct takakryptfs_inode_info *inode_info;
    
    inode_info = kmem_cache_alloc(takakryptfs_inode_cache, GFP_KERNEL);
    if (!inode_info) {
        return NULL;
    }
    
    /* Initialize inode info structure */
    memset(inode_info, 0, sizeof(*inode_info));
    inode_info->lower_inode = NULL;
    inode_info->encrypted = false;
    inode_info->encrypt_file = false;
    inode_info->policy_checked = false;
    inode_info->has_header = false;
    inode_info->header_size = 0;
    mutex_init(&inode_info->encrypt_mutex);
    atomic_set(&inode_info->refcount, 1);
    
    takakryptfs_debug("Allocated new inode\n");
    return &inode_info->vfs_inode;
}

/**
 * takakryptfs_destroy_inode - Destroy an inode
 * @inode: Inode to destroy
 */
static void takakryptfs_destroy_inode(struct inode *inode)
{
    struct takakryptfs_inode_info *inode_info = takakryptfs_inode_to_private(inode);
    
    takakryptfs_debug("Destroying inode\n");
    
    /* Release lower inode reference */
    if (inode_info->lower_inode) {
        iput(inode_info->lower_inode);
    }
    
    /* Clean up mutex */
    mutex_destroy(&inode_info->encrypt_mutex);
    
    /* Free the inode info structure */
    kmem_cache_free(takakryptfs_inode_cache, inode_info);
}

/**
 * takakryptfs_evict_inode - Evict an inode from memory
 * @inode: Inode to evict
 */
static void takakryptfs_evict_inode(struct inode *inode)
{
    takakryptfs_debug("Evicting inode\n");
    
    /* Clear inode data */
    truncate_inode_pages_final(&inode->i_data);
    clear_inode(inode);
}

/**
 * takakryptfs_put_super - Release superblock resources
 * @sb: Super block to release
 */
static void takakryptfs_put_super(struct super_block *sb)
{
    struct takakryptfs_sb_info *sb_info = takakryptfs_sb_to_private(sb);
    
    takakryptfs_info("Releasing superblock resources\n");
    
    if (sb_info) {
        /* Release lower superblock reference */
        if (sb_info->lower_sb) {
            deactivate_super(sb_info->lower_sb);
        }
        
        /* Free mount context */
        takakryptfs_free_mount_ctx(&sb_info->ctx);
        
        /* Free superblock info */
        kfree(sb_info);
        sb->s_fs_info = NULL;
    }
}

/**
 * takakryptfs_statfs - Get filesystem statistics
 * @dentry: Dentry for the filesystem
 * @buf: Buffer to fill with statistics
 * 
 * Returns: 0 on success, negative error code on failure
 */
int takakryptfs_statfs(struct dentry *dentry, struct kstatfs *buf)
{
    struct takakryptfs_sb_info *sb_info;
    struct dentry *lower_dentry;
    int ret;
    
    sb_info = takakryptfs_sb_to_private(dentry->d_sb);
    lower_dentry = takakryptfs_dentry_to_lower(dentry);
    
    if (!lower_dentry || !lower_dentry->d_sb || !lower_dentry->d_sb->s_op) {
        return -ENODEV;
    }
    
    /* Get statistics from lower filesystem */
    if (lower_dentry->d_sb->s_op->statfs) {
        ret = lower_dentry->d_sb->s_op->statfs(lower_dentry, buf);
        if (ret) {
            return ret;
        }
    } else {
        /* Fallback to generic statistics */
        memset(buf, 0, sizeof(*buf));
        buf->f_type = TAKAKRYPTFS_MAGIC;
    }
    
    /* Override filesystem type */
    buf->f_type = TAKAKRYPTFS_MAGIC;
    
    takakryptfs_debug("Filesystem statistics: blocks=%llu, free=%llu\n",
                      (unsigned long long)buf->f_blocks,
                      (unsigned long long)buf->f_bavail);
    
    return 0;
}

/**
 * takakryptfs_show_options - Show mount options
 * @m: Sequence file for output
 * @root: Root dentry
 * 
 * Returns: 0 on success
 */
int takakryptfs_show_options(struct seq_file *m, struct dentry *root)
{
    struct takakryptfs_sb_info *sb_info = takakryptfs_sb_to_private(root->d_sb);
    struct takakryptfs_mount_ctx *ctx = &sb_info->ctx;
    
    if (ctx->lower_path) {
        seq_printf(m, ",lowerdir=%s", ctx->lower_path);
    }
    
    if (ctx->policy_name) {
        seq_printf(m, ",policy=%s", ctx->policy_name);
    }
    
    if (ctx->readonly) {
        seq_puts(m, ",readonly");
    }
    
    if (ctx->debug_level > 0) {
        seq_printf(m, ",debug=%d", ctx->debug_level);
    }
    
    return 0;
}

/**
 * takakryptfs_remount_fs - Remount filesystem with new options
 * @sb: Super block
 * @flags: New mount flags
 * @data: Mount options string
 * 
 * Returns: 0 on success, negative error code on failure
 */
static int takakryptfs_remount_fs(struct super_block *sb, int *flags, char *data)
{
    takakryptfs_info("Remount requested with flags=0x%x, data=%s\n", *flags, data ? data : "(null)");
    
    /* For now, don't allow remounting with different options */
    /* This could be enhanced later to support option changes */
    
    return 0;
}

/* Superblock operations */
const struct super_operations takakryptfs_sops = {
    .alloc_inode = takakryptfs_alloc_inode,
    .destroy_inode = takakryptfs_destroy_inode,
    .evict_inode = takakryptfs_evict_inode,
    .put_super = takakryptfs_put_super,
    .statfs = takakryptfs_statfs,
    .remount_fs = takakryptfs_remount_fs,
    .show_options = takakryptfs_show_options,
};

/* Inode cache for efficient allocation */
struct kmem_cache *takakryptfs_inode_cache;

/**
 * takakryptfs_init_inode_cache - Initialize inode cache
 * 
 * Returns: 0 on success, negative error code on failure
 */
static int takakryptfs_init_inode_cache(void)
{
    takakryptfs_inode_cache = kmem_cache_create("takakryptfs_inode_cache",
                                                sizeof(struct takakryptfs_inode_info),
                                                0,
                                                SLAB_RECLAIM_ACCOUNT | SLAB_MEM_SPREAD,
                                                NULL);
    if (!takakryptfs_inode_cache) {
        takakryptfs_error("Failed to create inode cache\n");
        return -ENOMEM;
    }
    
    takakryptfs_debug("Inode cache created\n");
    return 0;
}

/**
 * takakryptfs_destroy_inode_cache - Destroy inode cache
 */
static void takakryptfs_destroy_inode_cache(void)
{
    if (takakryptfs_inode_cache) {
        kmem_cache_destroy(takakryptfs_inode_cache);
        takakryptfs_inode_cache = NULL;
        takakryptfs_debug("Inode cache destroyed\n");
    }
}

/**
 * takakryptfs_fill_super_legacy - Fill superblock structure (legacy API)
 * @sb: Super block to fill
 * @ctx: Mount context
 * @silent: Whether to suppress error messages
 * 
 * Returns: 0 on success, negative error code on failure
 */
int takakryptfs_fill_super_legacy(struct super_block *sb, struct takakryptfs_mount_ctx *ctx, int silent)
{
    struct takakryptfs_sb_info *sb_info;
    struct inode *root_inode;
    struct dentry *root_dentry;
    struct inode *lower_root_inode;
    int ret;
    
    takakryptfs_debug("Filling superblock\n");
    
    /* Initialize inode cache if not already done */
    if (!takakryptfs_inode_cache) {
        ret = takakryptfs_init_inode_cache();
        if (ret) {
            return ret;
        }
    }
    
    /* Allocate superblock info */
    sb_info = kzalloc(sizeof(*sb_info), GFP_KERNEL);
    if (!sb_info) {
        return -ENOMEM;
    }
    
    /* Copy mount context */
    sb_info->ctx = *ctx;
    sb_info->lower_sb = ctx->lower_root.dentry->d_sb;
    
    /* Initialize statistics */
    spin_lock_init(&sb_info->stats_lock);
    atomic_set(&sb_info->active_files, 0);
    atomic64_set(&sb_info->stats.files_opened, 0);
    atomic64_set(&sb_info->stats.files_encrypted, 0);
    atomic64_set(&sb_info->stats.files_decrypted, 0);
    atomic64_set(&sb_info->stats.bytes_encrypted, 0);
    atomic64_set(&sb_info->stats.bytes_decrypted, 0);
    atomic64_set(&sb_info->stats.policy_lookups, 0);
    atomic64_set(&sb_info->stats.cache_hits, 0);
    atomic64_set(&sb_info->stats.cache_misses, 0);
    
    /* Set up superblock */
    sb->s_fs_info = sb_info;
    sb->s_op = &takakryptfs_sops;
    sb->s_magic = TAKAKRYPTFS_MAGIC;
    sb->s_maxbytes = sb_info->lower_sb->s_maxbytes;
    sb->s_blocksize = sb_info->lower_sb->s_blocksize;
    sb->s_blocksize_bits = sb_info->lower_sb->s_blocksize_bits;
    sb->s_time_gran = sb_info->lower_sb->s_time_gran;
    
    /* Set filesystem flags */
    if (ctx->readonly) {
        sb->s_flags |= SB_RDONLY;
    }
    
    /* Get lower root inode */
    lower_root_inode = d_inode(ctx->lower_root.dentry);
    if (!lower_root_inode) {
        takakryptfs_error("Lower root inode not found\n");
        ret = -ENOENT;
        goto err_free_sb_info;
    }
    
    /* Create root inode */
    root_inode = takakryptfs_get_inode(sb, lower_root_inode);
    if (!root_inode) {
        takakryptfs_error("Failed to create root inode\n");
        ret = -ENOMEM;
        goto err_free_sb_info;
    }
    
    /* Create root dentry */
    root_dentry = d_make_root(root_inode);
    if (!root_dentry) {
        takakryptfs_error("Failed to create root dentry\n");
        ret = -ENOMEM;
        goto err_free_sb_info;
    }
    
    /* Set lower dentry for root */
    root_dentry->d_fsdata = dget(ctx->lower_root.dentry);
    
    /* Set superblock root */
    sb->s_root = root_dentry;
    
    takakryptfs_info("Superblock filled successfully: lowerdir=%s, policy=%s\n",
                     ctx->lower_path, ctx->policy_name);
    
    return 0;
    
err_free_sb_info:
    kfree(sb_info);
    sb->s_fs_info = NULL;
    return ret;
}

/**
 * takakryptfs_kill_super - Kill superblock during unmount
 * @sb: Super block to kill
 */
void takakryptfs_kill_super(struct super_block *sb)
{
    takakryptfs_info("Killing superblock\n");
    
    /* Call generic kill_anon_super to handle cleanup */
    kill_anon_super(sb);
    
    /* Clean up inode cache if this is the last filesystem instance */
    /* Note: This is simplified - in production, we'd track active instances */
    takakryptfs_destroy_inode_cache();
}

/* Module initialization/cleanup for super.c */
int __init takakryptfs_super_init(void)
{
    return takakryptfs_init_inode_cache();
}

void takakryptfs_super_exit(void)
{
    takakryptfs_destroy_inode_cache();
}