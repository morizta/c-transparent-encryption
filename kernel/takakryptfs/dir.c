#include "takakryptfs.h"

/**
 * takakryptfs_dir_open - Open a directory
 * @inode: Directory inode
 * @file: File structure for the directory
 * 
 * Returns: 0 on success, negative error code on failure
 */
int takakryptfs_dir_open(struct inode *inode, struct file *file)
{
    struct takakryptfs_dir_info *dir_info;
    struct dentry *lower_dentry;
    struct file *lower_file;
    int ret;
    
    takakryptfs_debug("Opening directory: inode %lu\n", inode->i_ino);
    
    /* Allocate directory info structure */
    dir_info = kzalloc(sizeof(*dir_info), GFP_KERNEL);
    if (!dir_info) {
        takakryptfs_error("Failed to allocate directory info\n");
        return -ENOMEM;
    }
    
    /* Get lower dentry */
    lower_dentry = (struct dentry *)file->f_path.dentry->d_fsdata;
    if (!lower_dentry) {
        takakryptfs_error("No lower dentry found for directory\n");
        kfree(dir_info);
        return -ENOENT;
    }
    
    /* Get superblock info for lower mount */
    struct takakryptfs_sb_info *sb_info = takakryptfs_sb_to_private(inode->i_sb);
    if (!sb_info) {
        takakryptfs_error("No superblock info found for directory\n");
        kfree(dir_info);
        return -EINVAL;
    }
    
    /* Open lower directory */
    lower_file = dentry_open(&(struct path){ .dentry = lower_dentry,
                                            .mnt = sb_info->ctx.lower_root.mnt },
                             file->f_flags, current_cred());
    if (IS_ERR(lower_file)) {
        ret = PTR_ERR(lower_file);
        takakryptfs_error("Failed to open lower directory: %d\n", ret);
        kfree(dir_info);
        return ret;
    }
    
    /* Initialize directory info */
    dir_info->lower_dir = lower_file;
    INIT_LIST_HEAD(&dir_info->entries);
    mutex_init(&dir_info->entries_mutex);
    dir_info->entries_cached = false;
    
    /* Set file private data */
    file->private_data = dir_info;
    
    takakryptfs_debug("Directory opened successfully\n");
    
    return 0;
}

/**
 * takakryptfs_dir_release - Release/close a directory
 * @inode: Directory inode
 * @file: File structure for the directory
 * 
 * Returns: 0 on success
 */
int takakryptfs_dir_release(struct inode *inode, struct file *file)
{
    struct takakryptfs_dir_info *dir_info = file->private_data;
    
    takakryptfs_debug("Releasing directory: inode %lu\n", inode->i_ino);
    
    if (dir_info) {
        /* Close lower directory */
        if (dir_info->lower_dir) {
            fput(dir_info->lower_dir);
        }
        
        /* Clean up cached entries */
        mutex_destroy(&dir_info->entries_mutex);
        
        /* Free directory info */
        kfree(dir_info);
        file->private_data = NULL;
    }
    
    return 0;
}

/**
 * takakryptfs_readdir - Read directory entries
 * @file: Directory file
 * @ctx: Directory context for iteration
 * 
 * Returns: 0 on success, negative error code on failure
 */
int takakryptfs_readdir(struct file *file, struct dir_context *ctx)
{
    struct takakryptfs_dir_info *dir_info = file->private_data;
    struct file *lower_file;
    int ret;
    
    if (!dir_info) {
        return -EINVAL;
    }
    
    lower_file = dir_info->lower_dir;
    if (!lower_file) {
        return -EINVAL;
    }
    
    takakryptfs_debug("Reading directory entries at offset %lld\n", ctx->pos);
    
    /* Update lower file position to match upper file */
    lower_file->f_pos = file->f_pos;
    
    /* Read from lower directory */
    if (lower_file->f_op && lower_file->f_op->iterate_shared) {
        ret = lower_file->f_op->iterate_shared(lower_file, ctx);
    } else {
        takakryptfs_error("Lower directory has no iterate operation\n");
        ret = -ENOTDIR;
    }
    
    /* Update upper file position from lower file */
    file->f_pos = lower_file->f_pos;
    
    if (ret >= 0) {
        takakryptfs_debug("Directory read successful\n");
    } else {
        takakryptfs_debug("Directory read failed: %d\n", ret);
    }
    
    return ret;
}

/**
 * takakryptfs_dir_llseek - Seek in directory
 * @file: Directory file
 * @offset: Offset to seek to
 * @whence: How to interpret offset
 * 
 * Returns: New position or negative error code
 */
static loff_t takakryptfs_dir_llseek(struct file *file, loff_t offset, int whence)
{
    struct takakryptfs_dir_info *dir_info = file->private_data;
    loff_t ret;
    
    if (!dir_info || !dir_info->lower_dir) {
        return -EINVAL;
    }
    
    takakryptfs_debug("Seeking in directory to offset %lld (whence=%d)\n", offset, whence);
    
    /* Pass seek to lower directory */
    if (dir_info->lower_dir->f_op && dir_info->lower_dir->f_op->llseek) {
        ret = dir_info->lower_dir->f_op->llseek(dir_info->lower_dir, offset, whence);
    } else {
        ret = default_llseek(file, offset, whence);
    }
    
    if (ret >= 0) {
        /* Update upper file position to match */
        file->f_pos = dir_info->lower_dir->f_pos;
        takakryptfs_debug("Directory seek successful: new position %lld\n", ret);
    } else {
        takakryptfs_debug("Directory seek failed: %lld\n", ret);
    }
    
    return ret;
}

/**
 * takakryptfs_dir_fsync - Sync directory to storage
 * @file: Directory file
 * @start: Start offset
 * @end: End offset  
 * @datasync: Whether to sync only data (not metadata)
 * 
 * Returns: 0 on success, negative error code on failure
 */
static int takakryptfs_dir_fsync(struct file *file, loff_t start, loff_t end, int datasync)
{
    struct takakryptfs_dir_info *dir_info = file->private_data;
    int ret;
    
    if (!dir_info || !dir_info->lower_dir) {
        return -EINVAL;
    }
    
    takakryptfs_debug("Syncing directory (datasync=%d)\n", datasync);
    
    /* Sync lower directory */
    if (dir_info->lower_dir->f_op && dir_info->lower_dir->f_op->fsync) {
        ret = dir_info->lower_dir->f_op->fsync(dir_info->lower_dir, start, end, datasync);
    } else {
        ret = 0; /* No sync operation available */
    }
    
    takakryptfs_debug("Directory sync %s: %d\n", ret ? "failed" : "successful", ret);
    
    return ret;
}

/* Directory file operations */
const struct file_operations takakryptfs_dir_fops = {
    .open = takakryptfs_dir_open,
    .release = takakryptfs_dir_release,
    .read = generic_read_dir,
    .iterate_shared = takakryptfs_readdir,
    .llseek = takakryptfs_dir_llseek,
    .fsync = takakryptfs_dir_fsync,
};