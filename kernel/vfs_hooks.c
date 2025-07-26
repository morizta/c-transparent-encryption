#include "takakrypt.h"

/**
 * takakrypt_get_file_path - Extract full file path from file structure
 * @file: File structure pointer
 * @buf: Buffer to store the path
 * @buf_size: Size of the buffer
 * 
 * Returns: 0 on success, negative error code on failure
 */
int takakrypt_get_file_path(struct file *file, char *buf, size_t buf_size)
{
    char *path_buf, *path_str;
    struct path *path;
    int ret = 0;
    
    if (!file || !buf || buf_size == 0) {
        return -EINVAL;
    }
    
    path = &file->f_path;
    if (!path->dentry || !path->mnt) {
        takakrypt_debug("Invalid path in file structure\n");
        return -EINVAL;
    }
    
    /* Allocate temporary buffer for path construction */
    path_buf = kmalloc(PATH_MAX, GFP_KERNEL);
    if (!path_buf) {
        takakrypt_error("Failed to allocate path buffer\n");
        return -ENOMEM;
    }
    
    /* Get the full path */
    path_str = d_path(path, path_buf, PATH_MAX);
    if (IS_ERR(path_str)) {
        ret = PTR_ERR(path_str);
        takakrypt_debug("Failed to get path string: %d\n", ret);
        goto cleanup;
    }
    
    /* Copy to output buffer */
    if (strlen(path_str) >= buf_size) {
        takakrypt_warn("Path too long: %zu >= %zu\n", strlen(path_str), buf_size);
        ret = -ENAMETOOLONG;
        goto cleanup;
    }
    
    strncpy(buf, path_str, buf_size - 1);
    buf[buf_size - 1] = '\0';
    
    takakrypt_debug("Extracted file path: %s\n", buf);

cleanup:
    kfree(path_buf);
    return ret;
}

/**
 * takakrypt_get_process_info - Get current process information
 * @ctx: Context structure to fill
 */
static void takakrypt_get_process_info(struct takakrypt_context *ctx)
{
    struct task_struct *task = current;
    const struct cred *cred;
    
    if (!ctx || !task) {
        return;
    }
    
    /* Get credentials */
    cred = current_cred();
    if (cred) {
        ctx->uid = from_kuid(&init_user_ns, cred->uid);
        ctx->gid = from_kgid(&init_user_ns, cred->gid);
    } else {
        ctx->uid = 0;
        ctx->gid = 0;
    }
    
    /* Get process information */
    ctx->pid = task->pid;
    ctx->ppid = task->parent ? task->parent->pid : 0;
    
    /* Copy process name (comm is limited to TASK_COMM_LEN) */
    get_task_comm(ctx->process_name, task);
    
    takakrypt_debug("Process info: pid=%u, ppid=%u, uid=%u, gid=%u, comm=%s\n",
                   ctx->pid, ctx->ppid, ctx->uid, ctx->gid, ctx->process_name);
}

/**
 * takakrypt_check_policy - Check if file access should be allowed
 * @file: File being accessed
 * @operation: Type of operation being performed
 * 
 * Returns: 0 if allowed, negative error code if denied
 */
int takakrypt_check_policy(struct file *file, uint32_t operation)
{
    struct takakrypt_context ctx;
    struct takakrypt_cache_entry *cache_entry;
    char filepath[TAKAKRYPT_MAX_PATH_LEN];
    int ret;
    
    if (!file) {
        return -EINVAL;
    }
    
    /* Check if module is active */
    if (!atomic_read(&takakrypt_global_state->module_active)) {
        takakrypt_debug("Module not active, allowing operation\n");
        return 0;
    }
    
    /* Get file path */
    ret = takakrypt_get_file_path(file, filepath, sizeof(filepath));
    if (ret) {
        takakrypt_debug("Failed to get file path, allowing operation\n");
        return 0; /* Allow operation if we can't get path */
    }
    
    /* Prepare context */
    memset(&ctx, 0, sizeof(ctx));
    strncpy(ctx.filepath, filepath, sizeof(ctx.filepath) - 1);
    ctx.file_operation = operation;
    takakrypt_get_process_info(&ctx);
    
    /* Get file information */
    if (file->f_inode) {
        ctx.file_size = i_size_read(file->f_inode);
        ctx.file_mode = file->f_inode->i_mode;
    }
    
    /* Check cache first */
    cache_entry = takakrypt_cache_lookup(filepath, ctx.uid, ctx.pid);
    if (cache_entry) {
        takakrypt_debug("Cache hit for %s: allow=%u\n", filepath, cache_entry->allow);
        spin_lock(&takakrypt_global_state->stats_lock);
        takakrypt_global_state->stats.cache_hits++;
        spin_unlock(&takakrypt_global_state->stats_lock);
        
        ret = cache_entry->allow ? 0 : -EACCES;
        goto update_stats;
    }
    
    /* Cache miss - need to query user-space agent */
    takakrypt_debug("Cache miss for %s, querying agent\n", filepath);
    spin_lock(&takakrypt_global_state->stats_lock);
    takakrypt_global_state->stats.cache_misses++;
    spin_unlock(&takakrypt_global_state->stats_lock);
    
    /* For now, allow all operations (agent communication will be implemented) */
    takakrypt_debug("Agent communication not yet implemented, allowing operation\n");
    ret = 0;
    
    /* Cache the decision (temporarily allowing all) */
    takakrypt_cache_insert(filepath, ctx.uid, ctx.pid, 1, "default", "default-key");

update_stats:
    /* Update statistics */
    spin_lock(&takakrypt_global_state->stats_lock);
    takakrypt_global_state->stats.requests_processed++;
    if (ret == 0) {
        takakrypt_global_state->stats.requests_allowed++;
    } else {
        takakrypt_global_state->stats.requests_denied++;
    }
    spin_unlock(&takakrypt_global_state->stats_lock);
    
    return ret;
}

/**
 * takakrypt_file_open - Hook for file open operations
 * @inode: Inode being opened
 * @file: File structure
 * 
 * Returns: 0 on success, negative error code on failure
 */
int takakrypt_file_open(struct inode *inode, struct file *file)
{
    struct takakrypt_file_context *ctx;
    int ret;
    
    takakrypt_debug("File open hook called\n");
    
    /* Check policy for file open */
    ret = takakrypt_check_policy(file, TAKAKRYPT_FILE_OP_OPEN);
    if (ret) {
        takakrypt_info("File open denied by policy\n");
        return ret;
    }
    
    /* Create file context for tracking */
    ctx = takakrypt_get_file_context(file);
    if (!ctx) {
        takakrypt_warn("Failed to create file context\n");
        /* Continue without context - not a fatal error */
    }
    
    takakrypt_debug("File open allowed\n");
    return 0;
}

/**
 * takakrypt_read_iter - Hook for file read operations (modern interface)
 * @iocb: I/O control block
 * @iter: Iterator for data transfer
 * 
 * Returns: Number of bytes read, or negative error code
 */
ssize_t takakrypt_read_iter(struct kiocb *iocb, struct iov_iter *iter)
{
    struct file *file = iocb->ki_filp;
    struct takakrypt_file_context *ctx;
    ssize_t ret;
    char *buffer = NULL;
    size_t count = iov_iter_count(iter);
    
    takakrypt_debug("Read_iter hook called: count=%zu, pos=%lld\n", count, iocb->ki_pos);
    
    /* Check policy for file read */
    ret = takakrypt_check_policy(file, TAKAKRYPT_FILE_OP_READ);
    if (ret) {
        takakrypt_info("File read denied by policy\n");
        return ret;
    }
    
    /* Call original read operation first */
    if (original_file_ops && original_file_ops->read_iter) {
        ret = original_file_ops->read_iter(iocb, iter);
        if (ret <= 0) {
            return ret; /* Error or EOF */
        }
    } else {
        takakrypt_warn("No original read_iter operation available\n");
        return -ENOSYS;
    }
    
    /* Get file context to check if decryption is needed */
    ctx = takakrypt_get_file_context(file);
    if (ctx && ctx->encrypted) {
        takakrypt_debug("File is encrypted, decryption needed\n");
        
        /* Allocate buffer for decryption */
        buffer = kmalloc(ret, GFP_KERNEL);
        if (!buffer) {
            takakrypt_error("Failed to allocate decryption buffer\n");
            goto cleanup;
        }
        
        /* Copy data from iterator for decryption */
        if (copy_from_iter(buffer, ret, iter) != ret) {
            takakrypt_error("Failed to copy data from iterator\n");
            ret = -EFAULT;
            goto cleanup;
        }
        
        /* TODO: Send to agent for decryption via netlink */
        ret = takakrypt_decrypt_data(buffer, ret, ctx->key_id, &buffer);
        if (ret < 0) {
            takakrypt_error("Decryption failed: %ld\n", ret);
            goto cleanup;
        }
        
        /* Copy decrypted data back to iterator */
        if (copy_to_iter(buffer, ret, iter) != ret) {
            takakrypt_error("Failed to copy decrypted data to iterator\n");
            ret = -EFAULT;
            goto cleanup;
        }
        
        spin_lock(&takakrypt_global_state->stats_lock);
        takakrypt_global_state->stats.decryption_ops++;
        spin_unlock(&takakrypt_global_state->stats_lock);
        
        takakrypt_debug("File decrypted successfully: %zu bytes\n", ret);
    }
    
cleanup:
    if (buffer) {
        kfree(buffer);
    }
    if (ctx) {
        takakrypt_put_file_context(ctx);
    }
    
    return ret;
}

/**
 * takakrypt_write_iter - Hook for file write operations (modern interface)
 * @iocb: I/O control block
 * @iter: Iterator for data transfer
 * 
 * Returns: Number of bytes written, or negative error code
 */
ssize_t takakrypt_write_iter(struct kiocb *iocb, struct iov_iter *iter)
{
    struct file *file = iocb->ki_filp;
    struct takakrypt_file_context *ctx;
    ssize_t ret;
    char *buffer = NULL;
    char *encrypted_buffer = NULL;
    size_t count = iov_iter_count(iter);
    
    takakrypt_debug("Write_iter hook called: count=%zu, pos=%lld\n", count, iocb->ki_pos);
    
    /* Check policy for file write */
    ret = takakrypt_check_policy(file, TAKAKRYPT_FILE_OP_WRITE);
    if (ret) {
        takakrypt_info("File write denied by policy\n");
        return ret;
    }
    
    /* Get file context */
    ctx = takakrypt_get_file_context(file);
    if (ctx) {
        /* Check if file should be encrypted */
        if (!ctx->policy_checked) {
            /* Query policy engine to determine if encryption is needed */
            ret = takakrypt_query_policy_for_encryption(file, ctx);
            if (ret < 0) {
                takakrypt_warn("Failed to query encryption policy, defaulting to encrypt\n");
                ctx->encrypted = 1;
            } else {
                ctx->encrypted = ret;
            }
            ctx->policy_checked = 1;
            strncpy(ctx->key_id, "policy-key-1", sizeof(ctx->key_id) - 1);
            takakrypt_debug("Policy check complete: encrypted=%u, key_id=%s\n", 
                           ctx->encrypted, ctx->key_id);
        }
        
        if (ctx->encrypted) {
            takakrypt_debug("File requires encryption, encrypting data\n");
            
            /* Allocate buffer for original data */
            buffer = kmalloc(count, GFP_KERNEL);
            if (!buffer) {
                takakrypt_error("Failed to allocate encryption buffer\n");
                ret = -ENOMEM;
                goto cleanup;
            }
            
            /* Copy data from iterator */
            if (copy_from_iter(buffer, count, iter) != count) {
                takakrypt_error("Failed to copy data from iterator\n");
                ret = -EFAULT;
                goto cleanup;
            }
            
            /* Encrypt the data via agent */
            ret = takakrypt_encrypt_data(buffer, count, ctx->key_id, &encrypted_buffer);
            if (ret < 0) {
                takakrypt_error("Encryption failed: %ld\n", ret);
                goto cleanup;
            }
            
            /* Create new iterator with encrypted data */
            iov_iter_kvec(iter, WRITE, &(struct kvec){encrypted_buffer, ret}, 1, ret);
            
            spin_lock(&takakrypt_global_state->stats_lock);
            takakrypt_global_state->stats.encryption_ops++;
            spin_unlock(&takakrypt_global_state->stats_lock);
            
            takakrypt_debug("File encrypted successfully: %zu -> %zu bytes\n", count, ret);
        }
    }
    
    /* Call original write operation with (possibly encrypted) data */
    if (original_file_ops && original_file_ops->write_iter) {
        ret = original_file_ops->write_iter(iocb, iter);
    } else {
        takakrypt_warn("No original write_iter operation available\n");
        ret = -ENOSYS;
        goto cleanup;
    }
    
cleanup:
    if (buffer) {
        kfree(buffer);
    }
    if (encrypted_buffer) {
        kfree(encrypted_buffer);
    }
    if (ctx) {
        takakrypt_put_file_context(ctx);
    }
    
    return ret;
}

/**
 * takakrypt_file_release - Hook for file close operations
 * @inode: Inode being closed
 * @file: File structure
 * 
 * Returns: 0 on success
 */
int takakrypt_file_release(struct inode *inode, struct file *file)
{
    struct takakrypt_file_context *ctx;
    
    takakrypt_debug("File release hook called\n");
    
    /* Get and release file context */
    ctx = takakrypt_get_file_context(file);
    if (ctx) {
        takakrypt_debug("Releasing file context for encrypted file\n");
        /* Decrement reference count twice - once for get, once for release */
        takakrypt_put_file_context(ctx);
        takakrypt_put_file_context(ctx);
    }
    
    return 0;
}

/**
 * takakrypt_should_intercept - Determine if file should be intercepted
 * @file: File structure to check
 * 
 * Returns: 1 if should intercept, 0 otherwise
 */
static int takakrypt_should_intercept(struct file *file)
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
    
    /* Skip our own module files */
    if (strstr(filepath, "takakrypt") != NULL) {
        return 0;
    }
    
    takakrypt_debug("File %s should be intercepted\n", filepath);
    return 1;
}

/* File operations are declared globally in main.c and defined in takakrypt.h */

/**
 * takakrypt_install_file_hooks - Install hooks for specific file
 * @file: File to hook
 * 
 * Replaces file operations with our hooked versions for transparent encryption
 */
int takakrypt_install_file_hooks(struct file *file)
{
    if (!takakrypt_should_intercept(file)) {
        return 0;
    }
    
    takakrypt_debug("Installing VFS hooks for file\n");
    
    /* Save original file operations if not already saved */
    if (!original_file_ops && file->f_op) {
        original_file_ops = file->f_op;
        
        /* Initialize our hooked operations based on original */
        takakrypt_hooked_fops = *original_file_ops;
        
        /* Replace key operations with our hooks */
        takakrypt_hooked_fops.read_iter = takakrypt_read_iter;
        takakrypt_hooked_fops.write_iter = takakrypt_write_iter;
        takakrypt_hooked_fops.open = takakrypt_file_open;
        takakrypt_hooked_fops.release = takakrypt_file_release;
        
        takakrypt_info("VFS hooks initialized with original operations\n");
    }
    
    /* Replace file operations atomically */
    if (original_file_ops) {
        file->f_op = &takakrypt_hooked_fops;
        takakrypt_debug("File operations replaced with hooked versions\n");
    }
    
    return 0;
}

/**
 * Global VFS hook installation - intercept all file opens
 * This is called during module initialization
 */
static const struct file_operations *original_default_fops = NULL;

/**
 * Hooked file open that installs our hooks
 */
static int takakrypt_hooked_open(struct inode *inode, struct file *file)
{
    int ret = 0;
    
    /* Call original open first if it exists */
    if (original_default_fops && original_default_fops->open) {
        ret = original_default_fops->open(inode, file);
        if (ret) {
            return ret;
        }
    }
    
    /* Install our hooks for this file */
    takakrypt_install_file_hooks(file);
    
    /* Call our own open hook */
    return takakrypt_file_open(inode, file);
}

/**
 * takakrypt_remove_file_hooks - Remove hooks for specific file
 * @file: File to unhook
 */
void takakrypt_remove_file_hooks(struct file *file)
{
    takakrypt_debug("Removing file hooks\n");
    
    /* Restore original file operations if they were hooked */
    if (original_file_ops && file->f_op == &takakrypt_hooked_fops) {
        file->f_op = original_file_ops;
        takakrypt_debug("Original file operations restored\n");
    }
}

/**
 * takakrypt_query_policy_for_encryption - Query agent for encryption policy
 * @file: File being accessed
 * @ctx: File context to update
 * 
 * Returns: 1 if encryption required, 0 if not, negative error code on failure
 */
int takakrypt_query_policy_for_encryption(struct file *file, struct takakrypt_file_context *ctx)
{
    char filepath[TAKAKRYPT_MAX_PATH_LEN];
    int ret;
    
    /* Get file path */
    ret = takakrypt_get_file_path(file, filepath, sizeof(filepath));
    if (ret) {
        takakrypt_debug("Failed to get file path for policy query\n");
        return ret;
    }
    
    takakrypt_debug("Querying policy for file: %s\n", filepath);
    
    /* TODO: Send netlink message to agent for policy evaluation */
    /* For now, implement simple logic based on file path */
    
    /* Check if file is in a test directory */
    if (strstr(filepath, "/tmp/takakrypt-test") != NULL) {
        /* Check file extension */
        if (strstr(filepath, ".txt") != NULL || strstr(filepath, ".doc") != NULL) {
            takakrypt_debug("File matches encryption policy: %s\n", filepath);
            return 1; /* Encrypt */
        }
    }
    
    takakrypt_debug("File does not match encryption policy: %s\n", filepath);
    return 0; /* Don't encrypt */
}

/**
 * takakrypt_encrypt_data - Encrypt data via agent
 * @data: Data to encrypt
 * @data_len: Length of data
 * @key_id: Key ID to use for encryption
 * @encrypted_data: Output pointer for encrypted data
 * 
 * Returns: Length of encrypted data, or negative error code
 */
int takakrypt_encrypt_data(const char *data, size_t data_len, const char *key_id, char **encrypted_data)
{
    size_t encrypted_len;
    char *encrypted_buf;
    
    takakrypt_debug("Encrypting %zu bytes with key %s\n", data_len, key_id);
    
    /* TODO: Send encryption request to agent via netlink */
    /* For now, implement simple mock encryption (just copy + header) */
    
    /* Allocate buffer for "encrypted" data (original + simple header) */
    encrypted_len = data_len + 32; /* 32 bytes for mock header */
    encrypted_buf = kmalloc(encrypted_len, GFP_KERNEL);
    if (!encrypted_buf) {
        takakrypt_error("Failed to allocate encryption buffer\n");
        return -ENOMEM;
    }
    
    /* Mock encryption: add header + copy data */
    snprintf(encrypted_buf, 32, "TAKAKRYPT_ENC_%s_", key_id);
    memcpy(encrypted_buf + 32, data, data_len);
    
    *encrypted_data = encrypted_buf;
    
    takakrypt_debug("Mock encryption complete: %zu -> %zu bytes\n", data_len, encrypted_len);
    return encrypted_len;
}

/**
 * takakrypt_decrypt_data - Decrypt data via agent
 * @encrypted_data: Encrypted data
 * @data_len: Length of encrypted data
 * @key_id: Key ID used for encryption
 * @decrypted_data: Output pointer for decrypted data
 * 
 * Returns: Length of decrypted data, or negative error code
 */
int takakrypt_decrypt_data(const char *encrypted_data, size_t data_len, const char *key_id, char **decrypted_data)
{
    size_t decrypted_len;
    char *decrypted_buf;
    char *plain_buf;
    
    takakrypt_debug("Decrypting %zu bytes with key %s\n", data_len, key_id);
    
    /* TODO: Send decryption request to agent via netlink */
    /* For now, implement simple mock decryption (remove header) */
    
    /* Check if data has our mock encryption header */
    if (data_len < 32 || strncmp(encrypted_data, "TAKAKRYPT_ENC_", 14) != 0) {
        /* Data is not encrypted, return as-is */
        plain_buf = kmalloc(data_len, GFP_KERNEL);
        if (!plain_buf) {
            return -ENOMEM;
        }
        memcpy(plain_buf, encrypted_data, data_len);
        *decrypted_data = plain_buf;
        return data_len;
    }
    
    /* Remove mock header and return original data */
    decrypted_len = data_len - 32;
    decrypted_buf = kmalloc(decrypted_len, GFP_KERNEL);
    if (!decrypted_buf) {
        takakrypt_error("Failed to allocate decryption buffer\n");
        return -ENOMEM;
    }
    
    memcpy(decrypted_buf, encrypted_data + 32, decrypted_len);
    *decrypted_data = decrypted_buf;
    
    takakrypt_debug("Mock decryption complete: %zu -> %zu bytes\n", data_len, decrypted_len);
    return decrypted_len;
}