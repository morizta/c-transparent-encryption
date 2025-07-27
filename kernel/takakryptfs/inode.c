#include "takakryptfs.h"

/**
 * takakryptfs_get_inode - Get or create an inode for the upper filesystem
 * @sb: Super block
 * @lower_inode: Lower filesystem inode
 * 
 * Returns: Inode pointer or NULL on failure
 */
struct inode *takakryptfs_get_inode(struct super_block *sb, struct inode *lower_inode)
{
    struct takakryptfs_inode_info *inode_info;
    struct inode *inode;
    
    if (!sb || !lower_inode) {
        return NULL;
    }
    
    /* Allocate new inode */
    inode = new_inode(sb);
    if (!inode) {
        takakryptfs_error("Failed to allocate new inode\n");
        return NULL;
    }
    
    /* Get inode info from allocated inode */
    inode_info = takakryptfs_inode_to_private(inode);
    
    /* Initialize inode info */
    takakryptfs_init_inode(inode, lower_inode);
    
    /* Hold reference to lower inode */
    inode_info->lower_inode = igrab(lower_inode);
    if (!inode_info->lower_inode) {
        iput(inode);
        return NULL;
    }
    
    takakryptfs_debug("Created inode %lu (lower: %lu)\n", 
                      inode->i_ino, lower_inode->i_ino);
    
    return inode;
}

/**
 * takakryptfs_init_inode - Initialize an inode based on lower inode
 * @inode: Upper inode to initialize
 * @lower_inode: Lower inode to copy attributes from
 */
void takakryptfs_init_inode(struct inode *inode, struct inode *lower_inode)
{
    struct takakryptfs_inode_info *inode_info = takakryptfs_inode_to_private(inode);
    
    /* Copy basic attributes from lower inode */
    inode->i_ino = lower_inode->i_ino;
    inode->i_mode = lower_inode->i_mode;
    set_nlink(inode, lower_inode->i_nlink);
    inode->i_uid = lower_inode->i_uid;
    inode->i_gid = lower_inode->i_gid;
    inode->i_size = lower_inode->i_size;
    inode->i_atime = lower_inode->i_atime;
    inode->i_mtime = lower_inode->i_mtime;
    inode->i_ctime = lower_inode->i_ctime;
    inode->i_blocks = lower_inode->i_blocks;
    inode->i_blkbits = lower_inode->i_blkbits;
    
    /* Set appropriate operations based on file type */
    if (S_ISREG(inode->i_mode)) {
        inode->i_op = &takakryptfs_file_iops;
        inode->i_fop = &takakryptfs_file_fops;
        inode->i_mapping->a_ops = &takakryptfs_aops;
    } else if (S_ISDIR(inode->i_mode)) {
        inode->i_op = &takakryptfs_dir_iops;
        inode->i_fop = &takakryptfs_dir_fops;
    } else if (S_ISLNK(inode->i_mode)) {
        inode->i_op = &takakryptfs_symlink_iops;
    } else {
        /* Special files (devices, fifos, etc.) - just copy operations */
        init_special_inode(inode, inode->i_mode, lower_inode->i_rdev);
    }
    
    /* Initialize encryption-specific fields */
    inode_info->encrypted = false;
    inode_info->policy_checked = false;
    inode_info->has_header = false;
    inode_info->header_size = 0;
    memset(inode_info->policy_name, 0, sizeof(inode_info->policy_name));
    memset(inode_info->key_id, 0, sizeof(inode_info->key_id));
    
    takakryptfs_debug("Initialized inode %lu with mode 0%o\n", 
                      inode->i_ino, inode->i_mode);
}

/**
 * takakryptfs_getattr - Get file attributes
 * @mnt_userns: User namespace for the mount
 * @path: Path to the file
 * @stat: Stat structure to fill
 * @request_mask: Requested attributes
 * @flags: Flags for the operation
 * 
 * Returns: 0 on success, negative error code on failure
 */
int takakryptfs_getattr(struct user_namespace *mnt_userns, const struct path *path,
                        struct kstat *stat, u32 request_mask, unsigned int flags)
{
    struct dentry *dentry = path->dentry;
    struct inode *inode = d_inode(dentry);
    struct takakryptfs_inode_info *inode_info = takakryptfs_inode_to_private(inode);
    struct dentry *lower_dentry = (struct dentry *)dentry->d_fsdata;
    struct takakryptfs_sb_info *sb_info = takakryptfs_sb_to_private(dentry->d_sb);
    struct path lower_path = { .dentry = lower_dentry, .mnt = sb_info->ctx.lower_root.mnt };
    int ret;
    
    takakryptfs_debug("Getting attributes for inode %lu\n", inode->i_ino);
    
    /* Get attributes from lower filesystem */
    if (lower_dentry && d_inode(lower_dentry) && 
        d_inode(lower_dentry)->i_op && d_inode(lower_dentry)->i_op->getattr) {
        ret = d_inode(lower_dentry)->i_op->getattr(mnt_userns, &lower_path, 
                                                   stat, request_mask, flags);
        if (ret) {
            return ret;
        }
    } else {
        /* Fallback to generic attributes */
        generic_fillattr(mnt_userns, inode, stat);
    }
    
    /* Adjust size for encrypted files */
    if (S_ISREG(inode->i_mode) && inode_info->encrypted && inode_info->has_header) {
        if (stat->size > inode_info->header_size) {
            stat->size -= inode_info->header_size;
        }
        takakryptfs_debug("Adjusted file size from %lld to %lld (header: %zu)\n",
                          stat->size + inode_info->header_size, stat->size, 
                          inode_info->header_size);
    }
    
    return 0;
}

/**
 * takakryptfs_setattr - Set file attributes
 * @mnt_userns: User namespace for the mount
 * @dentry: Dentry of the file
 * @attr: Attributes to set
 * 
 * Returns: 0 on success, negative error code on failure
 */
int takakryptfs_setattr(struct user_namespace *mnt_userns, struct dentry *dentry,
                        struct iattr *attr)
{
    struct inode *inode = d_inode(dentry);
    struct takakryptfs_inode_info *inode_info = takakryptfs_inode_to_private(inode);
    struct dentry *lower_dentry = (struct dentry *)dentry->d_fsdata;
    struct inode *lower_inode = d_inode(lower_dentry);
    struct iattr lower_attr;
    int ret;
    
    takakryptfs_debug("Setting attributes for inode %lu\n", inode->i_ino);
    
    /* Check permissions */
    ret = setattr_prepare(mnt_userns, dentry, attr);
    if (ret) {
        return ret;
    }
    
    /* Copy attributes for lower filesystem */
    memcpy(&lower_attr, attr, sizeof(lower_attr));
    
    /* Adjust size for encrypted files */
    if ((attr->ia_valid & ATTR_SIZE) && S_ISREG(inode->i_mode) && 
        inode_info->encrypted && inode_info->has_header) {
        lower_attr.ia_size = attr->ia_size + inode_info->header_size;
        takakryptfs_debug("Adjusted truncate size from %lld to %lld\n",
                          attr->ia_size, lower_attr.ia_size);
    }
    
    /* Set attributes on lower inode */
    if (lower_inode && lower_inode->i_op && lower_inode->i_op->setattr) {
        ret = lower_inode->i_op->setattr(mnt_userns, lower_dentry, &lower_attr);
        if (ret) {
            return ret;
        }
    } else {
        ret = simple_setattr(mnt_userns, dentry, attr);
        if (ret) {
            return ret;
        }
    }
    
    /* Update upper inode attributes */
    setattr_copy(mnt_userns, inode, attr);
    
    return 0;
}

/**
 * takakryptfs_permission - Check inode permissions
 * @mnt_userns: User namespace for the mount
 * @inode: Inode to check
 * @mask: Permission mask
 * 
 * Returns: 0 if allowed, negative error code if denied
 */
static int takakryptfs_permission(struct user_namespace *mnt_userns, 
                                  struct inode *inode, int mask)
{
    struct takakryptfs_inode_info *inode_info = takakryptfs_inode_to_private(inode);
    struct inode *lower_inode = inode_info->lower_inode;
    
    takakryptfs_debug("Checking permissions for inode %lu, mask=0x%x\n", 
                      inode->i_ino, mask);
    
    /* Check permissions on lower inode */
    if (lower_inode && lower_inode->i_op && lower_inode->i_op->permission) {
        return lower_inode->i_op->permission(mnt_userns, lower_inode, mask);
    }
    
    /* Fallback to generic permission check */
    return generic_permission(mnt_userns, inode, mask);
}

/* File inode operations */
const struct inode_operations takakryptfs_file_iops = {
    .getattr = takakryptfs_getattr,
    .setattr = takakryptfs_setattr,
    .permission = takakryptfs_permission,
};

/* Directory inode operations */
const struct inode_operations takakryptfs_dir_iops = {
    .lookup = takakryptfs_lookup,
    .create = takakryptfs_create,
    .mkdir = takakryptfs_mkdir,
    .rmdir = takakryptfs_rmdir,
    .unlink = takakryptfs_unlink,
    .symlink = takakryptfs_symlink,
    .link = takakryptfs_link,
    .rename = takakryptfs_rename,
    .getattr = takakryptfs_getattr,
    .setattr = takakryptfs_setattr,
    .permission = takakryptfs_permission,
};

/* Symlink inode operations */
const struct inode_operations takakryptfs_symlink_iops = {
    .get_link = takakryptfs_get_link,
    .getattr = takakryptfs_getattr,
    .setattr = takakryptfs_setattr,
    .permission = takakryptfs_permission,
};

/* Address space operations (for mmap support) */
const struct address_space_operations takakryptfs_aops = {
    .readpage = takakryptfs_readpage,
    .writepage = takakryptfs_writepage,
    .readahead = takakryptfs_readahead,
    .set_page_dirty = __set_page_dirty_nobuffers,
};

/* Directory operations implementation */
struct dentry *takakryptfs_lookup(struct inode *dir, struct dentry *dentry, unsigned int flags)
{
    struct takakryptfs_inode_info *dir_info = takakryptfs_inode_to_private(dir);
    struct inode *lower_dir_inode = dir_info->lower_inode;
    struct dentry *lower_dir_dentry = (struct dentry *)dentry->d_parent->d_fsdata;
    struct dentry *lower_dentry = NULL;
    struct inode *lower_inode = NULL;
    struct inode *inode = NULL;
    
    takakryptfs_debug("Looking up '%s' in directory\n", dentry->d_name.name);
    
    if (!lower_dir_dentry) {
        takakryptfs_error("No lower directory dentry\n");
        return ERR_PTR(-ENOENT);
    }
    
    /* Look up in lower directory */
    inode_lock(lower_dir_inode);
    lower_dentry = lookup_one_len(dentry->d_name.name, lower_dir_dentry, dentry->d_name.len);
    inode_unlock(lower_dir_inode);
    
    if (IS_ERR(lower_dentry)) {
        takakryptfs_debug("Lower lookup failed\n");
        return lower_dentry;
    }
    
    /* If lower dentry exists, create upper inode */
    if (d_really_is_positive(lower_dentry)) {
        lower_inode = d_inode(lower_dentry);
        inode = takakryptfs_get_inode(dir->i_sb, lower_inode);
        if (!inode) {
            dput(lower_dentry);
            return ERR_PTR(-ENOMEM);
        }
    }
    
    /* Set lower dentry for this dentry */
    dentry->d_fsdata = lower_dentry;
    
    takakryptfs_debug("Lookup complete for '%s'\n", dentry->d_name.name);
    
    return d_splice_alias(inode, dentry);
}

int takakryptfs_create(struct user_namespace *mnt_userns, struct inode *dir, 
                       struct dentry *dentry, umode_t mode, bool excl)
{
    takakryptfs_debug("Create operation not yet implemented\n");
    return -ENOSYS;
}

int takakryptfs_mkdir(struct user_namespace *mnt_userns, struct inode *dir,
                      struct dentry *dentry, umode_t mode)
{
    takakryptfs_debug("Mkdir operation not yet implemented\n");
    return -ENOSYS;
}

int takakryptfs_rmdir(struct inode *dir, struct dentry *dentry)
{
    takakryptfs_debug("Rmdir operation not yet implemented\n");
    return -ENOSYS;
}

int takakryptfs_unlink(struct inode *dir, struct dentry *dentry)
{
    takakryptfs_debug("Unlink operation not yet implemented\n");
    return -ENOSYS;
}

int takakryptfs_symlink(struct user_namespace *mnt_userns, struct inode *dir,
                        struct dentry *dentry, const char *symname)
{
    takakryptfs_debug("Symlink operation not yet implemented\n");
    return -ENOSYS;
}

int takakryptfs_link(struct dentry *old_dentry, struct inode *dir, struct dentry *new_dentry)
{
    takakryptfs_debug("Link operation not yet implemented\n");
    return -ENOSYS;
}

int takakryptfs_rename(struct user_namespace *mnt_userns, struct inode *old_dir,
                       struct dentry *old_dentry, struct inode *new_dir,
                       struct dentry *new_dentry, unsigned int flags)
{
    takakryptfs_debug("Rename operation not yet implemented\n");
    return -ENOSYS;
}

const char *takakryptfs_get_link(struct dentry *dentry, struct inode *inode,
                                 struct delayed_call *done)
{
    takakryptfs_debug("Get_link operation not yet implemented\n");
    return ERR_PTR(-ENOSYS);
}

/* Placeholder implementations for address space operations */
int takakryptfs_readpage(struct file *file, struct page *page)
{
    takakryptfs_debug("Readpage operation not yet implemented\n");
    return -ENOSYS;
}

int takakryptfs_writepage(struct page *page, struct writeback_control *wbc)
{
    takakryptfs_debug("Writepage operation not yet implemented\n");
    return -ENOSYS;
}

void takakryptfs_readahead(struct readahead_control *rac)
{
    takakryptfs_debug("Readahead operation not yet implemented\n");
}