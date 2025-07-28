#include "takakryptfs.h"

/**
 * takakryptfs_open - Open a file
 * @inode: Inode being opened
 * @file: File structure
 * 
 * Returns: 0 on success, negative error code on failure
 */
int takakryptfs_open(struct inode *inode, struct file *file)
{
    struct takakryptfs_inode_info *inode_info = takakryptfs_inode_to_private(inode);
    struct takakryptfs_file_info *file_info;
    struct dentry *lower_dentry;
    struct file *lower_file;
    struct takakryptfs_sb_info *sb_info;
    int ret;
    
    takakryptfs_debug("Opening file: inode %lu\n", inode->i_ino);
    
    /* Allocate file info structure */
    file_info = kzalloc(sizeof(*file_info), GFP_KERNEL);
    if (!file_info) {
        takakryptfs_error("Failed to allocate file info\n");
        return -ENOMEM;
    }
    
    /* Get lower dentry */
    lower_dentry = (struct dentry *)file->f_path.dentry->d_fsdata;
    if (!lower_dentry) {
        takakryptfs_error("No lower dentry found\n");
        kfree(file_info);
        return -ENOENT;
    }
    
    /* Get superblock info for lower mount */
    sb_info = takakryptfs_sb_to_private(inode->i_sb);
    if (!sb_info) {
        takakryptfs_error("No superblock info found\n");
        kfree(file_info);
        return -EINVAL;
    }
    
    /* Open lower file */
    lower_file = dentry_open(&(struct path){ .dentry = lower_dentry, 
                                            .mnt = sb_info->ctx.lower_root.mnt },
                             file->f_flags, current_cred());
    if (IS_ERR(lower_file)) {
        ret = PTR_ERR(lower_file);
        takakryptfs_error("Failed to open lower file: %d\n", ret);
        kfree(file_info);
        return ret;
    }
    
    /* Initialize file info */
    file_info->lower_file = lower_file;
    file_info->inode_info = inode_info;
    file_info->read_access = (file->f_mode & FMODE_READ) != 0;
    file_info->write_access = (file->f_mode & FMODE_WRITE) != 0;
    file_info->header_read = false;
    atomic64_set(&file_info->bytes_read, 0);
    atomic64_set(&file_info->bytes_written, 0);
    
    /* Check if file is encrypted and evaluate policy on open */
    if (!inode_info->policy_checked) {
        struct takakryptfs_policy_result policy_result;
        const char *operation;
        
        /* Determine operation type based on access mode */
        if (file_info->write_access) {
            operation = "open_write";
        } else if (file_info->read_access) {
            operation = "open_read";
        } else {
            operation = "open";
        }
        
        /* Evaluate policy for this file and operation */
        ret = takakryptfs_evaluate_policy_v2(lower_file, operation, &policy_result);
        if (ret) {
            takakryptfs_error("Policy evaluation failed: %d\n", ret);
            /* Continue with fallback behavior */
            policy_result.allow_access = true;
            policy_result.encrypt_file = false;
        }
        
        /* Check if access is allowed by policy */
        if (!policy_result.allow_access) {
            takakryptfs_info("File access denied by security rules: %s\n", 
                             policy_result.reason);
            fput(lower_file);
            kfree(file_info);
            return -EACCES;
        }
        
        /* Check if file is already encrypted */
        if (takakryptfs_is_encrypted_file(lower_file)) {
            inode_info->encrypted = true;
            inode_info->has_header = true;
            inode_info->header_size = 92; /* TAKA header size */
            
            /* Use key ID from policy or extract from header */
            if (strlen(policy_result.key_id) > 0) {
                strncpy(inode_info->key_id, policy_result.key_id, 
                        sizeof(inode_info->key_id) - 1);
                inode_info->key_id[sizeof(inode_info->key_id) - 1] = '\0';
            } else {
                snprintf(inode_info->key_id, sizeof(inode_info->key_id),
                         "policy_%s", sb_info->ctx.policy_name);
            }
            
            takakryptfs_debug("File is encrypted with key_id: %s\n", inode_info->key_id);
        } else {
            /* File is not encrypted - check if it should be */
            inode_info->encrypted = false;
            inode_info->has_header = false;
            
            /* Use policy decision for encryption */
            if (policy_result.encrypt_file && file_info->write_access) {
                inode_info->encrypt_file = true;
                
                /* Use key ID from policy */
                if (strlen(policy_result.key_id) > 0) {
                    strncpy(inode_info->key_id, policy_result.key_id, 
                            sizeof(inode_info->key_id) - 1);
                    inode_info->key_id[sizeof(inode_info->key_id) - 1] = '\0';
                } else {
                    snprintf(inode_info->key_id, sizeof(inode_info->key_id),
                             "policy_%s", sb_info->ctx.policy_name);
                }
                
                takakryptfs_debug("New file will be encrypted with key_id: %s (reason: %s)\n", 
                                  inode_info->key_id, policy_result.reason);
            } else {
                inode_info->encrypt_file = false;
                takakryptfs_debug("File will not be encrypted (reason: %s)\n", 
                                  policy_result.reason);
            }
        }
        
        /* Store policy name for reference */
        strncpy(inode_info->policy_name, policy_result.policy_name,
                sizeof(inode_info->policy_name) - 1);
        inode_info->policy_name[sizeof(inode_info->policy_name) - 1] = '\0';
        
        inode_info->policy_checked = true;
    }
    
    /* Set file private data */
    file->private_data = file_info;
    
    /* Update statistics */
    sb_info = takakryptfs_sb_to_private(inode->i_sb);
    if (sb_info) {
        takakryptfs_inc_stat(&sb_info->stats.files_opened);
        atomic_inc(&sb_info->active_files);
    }
    
    takakryptfs_debug("File opened successfully: %s access\n",
                      file_info->read_access ? (file_info->write_access ? "read/write" : "read") :
                      (file_info->write_access ? "write" : "none"));
    
    return 0;
}

/**
 * takakryptfs_release - Release/close a file
 * @inode: Inode being closed
 * @file: File structure
 * 
 * Returns: 0 on success
 */
int takakryptfs_release(struct inode *inode, struct file *file)
{
    struct takakryptfs_file_info *file_info = file->private_data;
    struct takakryptfs_sb_info *sb_info;
    
    takakryptfs_debug("Releasing file: inode %lu\n", inode->i_ino);
    
    if (file_info) {
        /* Log statistics */
        takakryptfs_debug("File stats: %lld bytes read, %lld bytes written\n",
                          atomic64_read(&file_info->bytes_read),
                          atomic64_read(&file_info->bytes_written));
        
        /* Close lower file */
        if (file_info->lower_file) {
            fput(file_info->lower_file);
        }
        
        /* Update active file count */
        sb_info = takakryptfs_sb_to_private(inode->i_sb);
        if (sb_info) {
            atomic_dec(&sb_info->active_files);
        }
        
        /* Free file info */
        kfree(file_info);
        file->private_data = NULL;
    }
    
    return 0;
}

/**
 * takakryptfs_read_iter - Read from file with decryption
 * @iocb: I/O control block
 * @iter: Iterator for data transfer
 * 
 * Returns: Number of bytes read or negative error code
 */
ssize_t takakryptfs_read_iter(struct kiocb *iocb, struct iov_iter *iter)
{
    struct file *file = iocb->ki_filp;
    struct takakryptfs_file_info *file_info = file->private_data;
    struct takakryptfs_inode_info *inode_info;
    struct takakryptfs_sb_info *sb_info;
    ssize_t ret;
    size_t count = iov_iter_count(iter);
    void *buffer = NULL;
    void *decrypted = NULL;
    size_t decrypted_len;
    loff_t lower_pos;
    
    if (!file_info) {
        return -EINVAL;
    }
    
    inode_info = file_info->inode_info;
    sb_info = takakryptfs_sb_to_private(file->f_inode->i_sb);
    
    takakryptfs_debug("Reading %zu bytes from offset %lld (encrypted=%d)\n", 
                      count, iocb->ki_pos, inode_info->encrypted);
    
    /* Check if file is encrypted */
    if (inode_info->encrypted && inode_info->has_header) {
        /* For encrypted files, we need to handle the header offset */
        size_t total_size;
        loff_t file_size = i_size_read(file_info->lower_file->f_inode);
        
        /* Check if reading beyond decrypted file size */
        if (iocb->ki_pos >= file_size - inode_info->header_size) {
            return 0; /* EOF */
        }
        
        /* Calculate how much encrypted data to read */
        lower_pos = iocb->ki_pos + inode_info->header_size;
        total_size = min_t(size_t, count, file_size - lower_pos);
        
        /* Allocate buffer for encrypted data */
        buffer = kmalloc(total_size, GFP_KERNEL);
        if (!buffer) {
            return -ENOMEM;
        }
        
        /* Read encrypted data from lower file */
        ret = kernel_read(file_info->lower_file, buffer, total_size, &lower_pos);
        if (ret <= 0) {
            kfree(buffer);
            return ret;
        }
        
        /* Decrypt the data */
        takakryptfs_info("TAKAKRYPTFS: Starting decryption, buffer_size=%zd, key_id=%s\n", 
                         ret, inode_info->key_id);
        ret = takakryptfs_decrypt_data(buffer, ret, inode_info->key_id,
                                       &decrypted, &decrypted_len);
        kfree(buffer);
        
        if (ret) {
            takakryptfs_error("Failed to decrypt data: %zd\n", ret);
            return ret;
        }
        takakryptfs_info("TAKAKRYPTFS: Decryption complete, decrypted_len=%zu\n", decrypted_len);
        
        /* Copy decrypted data to user buffer */
        ret = copy_to_iter(decrypted, decrypted_len, iter);
        kfree(decrypted);
        
        /* Update file position */
        iocb->ki_pos += ret;
        
    } else {
        /* For non-encrypted files, pass through to lower file */
        iocb->ki_filp = file_info->lower_file;
        ret = file_info->lower_file->f_op->read_iter(iocb, iter);
        iocb->ki_filp = file;
    }
    
    if (ret > 0) {
        /* Update statistics */
        atomic64_add(ret, &file_info->bytes_read);
        if (sb_info && inode_info->encrypted) {
            takakryptfs_inc_stat(&sb_info->stats.files_decrypted);
            takakryptfs_add_stat(&sb_info->stats.bytes_decrypted, ret);
        }
        
        takakryptfs_debug("Read %zd bytes successfully\n", ret);
    } else if (ret < 0) {
        takakryptfs_debug("Read failed: %zd\n", ret);
    }
    
    return ret;
}

/**
 * takakryptfs_write_iter - Write to file with encryption
 * @iocb: I/O control block
 * @iter: Iterator for data transfer
 * 
 * Returns: Number of bytes written or negative error code
 */
ssize_t takakryptfs_write_iter(struct kiocb *iocb, struct iov_iter *iter)
{
    struct file *file = iocb->ki_filp;
    struct takakryptfs_file_info *file_info = file->private_data;
    struct takakryptfs_inode_info *inode_info;
    struct takakryptfs_sb_info *sb_info;
    ssize_t ret;
    size_t count = iov_iter_count(iter);
    void *buffer = NULL;
    void *encrypted = NULL;
    size_t encrypted_len;
    loff_t lower_pos;
    bool need_header = false;
    
    if (!file_info) {
        return -EINVAL;
    }
    
    inode_info = file_info->inode_info;
    sb_info = takakryptfs_sb_to_private(file->f_inode->i_sb);
    
    takakryptfs_debug("Writing %zu bytes to offset %lld (encrypted=%d)\n", 
                      count, iocb->ki_pos, inode_info->encrypted);
    
    /* Check if file should be encrypted */
    if (inode_info->encrypted || (inode_info->policy_checked && inode_info->encrypt_file)) {
        /* Allocate buffer for plaintext data */
        buffer = kmalloc(count, GFP_KERNEL);
        if (!buffer) {
            return -ENOMEM;
        }
        
        /* Copy data from user iterator */
        ret = copy_from_iter(buffer, count, iter);
        if (ret != count) {
            kfree(buffer);
            return ret < 0 ? ret : -EFAULT;
        }
        
        /* Check if we need to write header (new file or truncated) */
        if (!inode_info->has_header && iocb->ki_pos == 0) {
            need_header = true;
            inode_info->header_size = 92; /* TAKA header size */
        }
        
        /* Encrypt the data */
        ret = takakryptfs_encrypt_data(buffer, count, inode_info->key_id,
                                       &encrypted, &encrypted_len);
        kfree(buffer);
        
        if (ret) {
            takakryptfs_error("Failed to encrypt data: %zd\n", ret);
            return ret;
        }
        
        /* Calculate position in lower file (account for header) */
        lower_pos = iocb->ki_pos + (inode_info->has_header ? inode_info->header_size : 0);
        
        /* Write encrypted data to lower file */
        ret = kernel_write(file_info->lower_file, encrypted, encrypted_len, &lower_pos);
        kfree(encrypted);
        
        if (ret > 0) {
            /* Update file position based on plaintext bytes written */
            iocb->ki_pos += count;
            ret = count; /* Return plaintext size to user */
            
            /* Mark that file now has header and is encrypted */
            if (need_header) {
                inode_info->has_header = true;
                inode_info->encrypted = true;
            }
        }
        
    } else {
        /* For non-encrypted files, pass through to lower file */
        iocb->ki_filp = file_info->lower_file;
        ret = file_info->lower_file->f_op->write_iter(iocb, iter);
        iocb->ki_filp = file;
    }
    
    if (ret > 0) {
        /* Update statistics */
        atomic64_add(ret, &file_info->bytes_written);
        if (sb_info && inode_info->encrypted) {
            takakryptfs_inc_stat(&sb_info->stats.files_encrypted);
            takakryptfs_add_stat(&sb_info->stats.bytes_encrypted, ret);
        }
        
        takakryptfs_debug("Wrote %zd bytes successfully\n", ret);
    } else if (ret < 0) {
        takakryptfs_debug("Write failed: %zd\n", ret);
    }
    
    return ret;
}

/**
 * takakryptfs_llseek - Seek in file
 * @file: File to seek in
 * @offset: Offset to seek to
 * @whence: How to interpret offset
 * 
 * Returns: New file position or negative error code
 */
loff_t takakryptfs_llseek(struct file *file, loff_t offset, int whence)
{
    struct takakryptfs_file_info *file_info = file->private_data;
    loff_t ret;
    
    if (!file_info || !file_info->lower_file) {
        return -EINVAL;
    }
    
    takakryptfs_debug("Seeking to offset %lld (whence=%d)\n", offset, whence);
    
    /* Pass seek to lower file */
    ret = file_info->lower_file->f_op->llseek(file_info->lower_file, offset, whence);
    
    if (ret >= 0) {
        /* Update upper file position to match */
        file->f_pos = file_info->lower_file->f_pos;
        takakryptfs_debug("Seek successful: new position %lld\n", ret);
    } else {
        takakryptfs_debug("Seek failed: %lld\n", ret);
    }
    
    return ret;
}

/**
 * takakryptfs_fsync - Sync file data to storage
 * @file: File to sync
 * @start: Start offset
 * @end: End offset
 * @datasync: Whether to sync only data (not metadata)
 * 
 * Returns: 0 on success, negative error code on failure
 */
static int takakryptfs_fsync(struct file *file, loff_t start, loff_t end, int datasync)
{
    struct takakryptfs_file_info *file_info = file->private_data;
    int ret;
    
    if (!file_info || !file_info->lower_file) {
        return -EINVAL;
    }
    
    takakryptfs_debug("Syncing file from %lld to %lld (datasync=%d)\n", 
                      start, end, datasync);
    
    /* Sync lower file */
    if (file_info->lower_file->f_op && file_info->lower_file->f_op->fsync) {
        ret = file_info->lower_file->f_op->fsync(file_info->lower_file, start, end, datasync);
    } else {
        ret = 0; /* No sync operation available */
    }
    
    takakryptfs_debug("Sync %s: %d\n", ret ? "failed" : "successful", ret);
    
    return ret;
}

/**
 * takakryptfs_mmap - Memory map file
 * @file: File to map
 * @vma: Virtual memory area
 * 
 * Returns: 0 on success, negative error code on failure
 */
static int takakryptfs_mmap(struct file *file, struct vm_area_struct *vma)
{
    struct takakryptfs_file_info *file_info = file->private_data;
    
    if (!file_info) {
        return -EINVAL;
    }
    
    takakryptfs_debug("Memory mapping file (encrypted files not yet supported)\n");
    
    /* For now, deny mmap on encrypted files */
    if (file_info->inode_info && file_info->inode_info->encrypted) {
        takakryptfs_warn("Memory mapping not supported for encrypted files\n");
        return -ENODEV;
    }
    
    /* For unencrypted files, use generic mmap */
    return generic_file_mmap(file, vma);
}

/* File operations structure */
const struct file_operations takakryptfs_file_fops = {
    .open = takakryptfs_open,
    .release = takakryptfs_release,
    .read_iter = takakryptfs_read_iter,
    .write_iter = takakryptfs_write_iter,
    .llseek = takakryptfs_llseek,
    .fsync = takakryptfs_fsync,
    .mmap = takakryptfs_mmap,
    .splice_read = generic_file_splice_read,
    .splice_write = iter_file_splice_write,
};