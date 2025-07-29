/* Enhanced logging added for debugging */

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
        takakrypt_error("POLICY_CHECK: NULL file pointer\n");
        return -EINVAL;
    }
    
    /* Check if module is active */
    if (!atomic_read(&takakrypt_global_state->module_active)) {
        takakrypt_debug("POLICY_CHECK: Module not active, allowing operation\n");
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
    
    /* Query user-space agent via netlink */
    takakrypt_info("POLICY_CHECK: Sending policy request to agent for %s\n", filepath);
    
    struct takakrypt_policy_response response;
    ret = takakrypt_send_policy_request(&ctx, &response, sizeof(response));
    if (ret == 0) {
        takakrypt_info("POLICY_CHECK: Agent response: allow=%u, reason='%s'\n", 
                       response.allow, response.reason);
        
        /* Cache the decision from agent */
        takakrypt_cache_insert(filepath, ctx.uid, ctx.pid, response.allow, 
                              response.policy_name, response.key_id);
        
        ret = response.allow ? 0 : -EACCES;
    } else {
        takakrypt_error("POLICY_CHECK: Failed to get agent response: %d, defaulting to DENY\n", ret);
        
        /* Cache failed decision as deny */
        takakrypt_cache_insert(filepath, ctx.uid, ctx.pid, 0, "error", "no-key");
        ret = -EACCES;
    }

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
        takakrypt_debug("WRITE_ITER: Got file context for write operation\n");
        /* Check if file should be encrypted */
        if (!ctx->policy_checked) {
            takakrypt_info("WRITE_ITER: Policy not yet checked, querying encryption policy\n");
            /* Query policy engine to determine if encryption is needed */
            ret = takakrypt_query_policy_for_encryption(file, ctx);
            if (ret < 0) {
                takakrypt_warn("WRITE_ITER: Failed to query encryption policy, defaulting to encrypt\n");
                ctx->encrypted = 1;
            } else {
                ctx->encrypted = ret;
            }
            ctx->policy_checked = 1;
            strncpy(ctx->key_id, "policy-key-1", sizeof(ctx->key_id) - 1);
            takakrypt_info("WRITE_ITER: Policy check complete: encrypted=%u, key_id=%s\n", 
                           ctx->encrypted, ctx->key_id);
        } else {
            takakrypt_debug("WRITE_ITER: Policy already checked: encrypted=%u\n", ctx->encrypted);
        }
        
        if (ctx->encrypted) {
            takakrypt_info("WRITE_ITER: File requires encryption - STARTING ENCRYPTION PROCESS\n");
            
            /* Allocate buffer for original data */
            buffer = kmalloc(count, GFP_KERNEL);
            if (!buffer) {
                takakrypt_error("WRITE_ITER: Failed to allocate encryption buffer\n");
                ret = -ENOMEM;
                goto cleanup;
            }
            
            /* Copy data from iterator */
            if (copy_from_iter(buffer, count, iter) != count) {
                takakrypt_error("WRITE_ITER: Failed to copy data from iterator\n");
                ret = -EFAULT;
                goto cleanup;
            }
            
            takakrypt_info("WRITE_ITER: About to encrypt %zu bytes with key %s\n", count, ctx->key_id);
            
            /* Encrypt the data via agent */
            ret = takakrypt_encrypt_data(buffer, count, ctx->key_id, &encrypted_buffer);
            if (ret < 0) {
                takakrypt_error("WRITE_ITER: Encryption failed: %ld\n", ret);
                goto cleanup;
            }
            
            takakrypt_info("WRITE_ITER: Encryption succeeded: %zu -> %ld bytes\n", count, ret);
            
            /* Create new iterator with encrypted data */
            iov_iter_kvec(iter, WRITE, &(struct kvec){encrypted_buffer, ret}, 1, ret);
            
            spin_lock(&takakrypt_global_state->stats_lock);
            takakrypt_global_state->stats.encryption_ops++;
            spin_unlock(&takakrypt_global_state->stats_lock);
            
            takakrypt_info("WRITE_ITER: File encrypted successfully: %zu -> %ld bytes\n", count, ret);
        } else {
            takakrypt_info("WRITE_ITER: File does NOT require encryption - writing plaintext\n");
        }
    } else {
        takakrypt_debug("WRITE_ITER: No file context available - writing plaintext\n");
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
    
    takakrypt_debug("ENCRYPTION_POLICY: Starting policy query for encryption\n");
    
    /* Get file path */
    ret = takakrypt_get_file_path(file, filepath, sizeof(filepath));
    if (ret) {
        takakrypt_error("ENCRYPTION_POLICY: Failed to get file path for policy query: %d\n", ret);
        return ret;
    }
    
    takakrypt_info("ENCRYPTION_POLICY: Querying encryption policy for file: %s\n", filepath);
    
    /* TODO: Send netlink message to agent for policy evaluation */
    /* For now, implement simple logic based on file path */
    
    /* Check if file is in a test directory */
    if (strstr(filepath, "/tmp/takakrypt-test") != NULL) {
        takakrypt_info("ENCRYPTION_POLICY: File is in test directory: %s\n", filepath);
        /* Check file extension */
        if (strstr(filepath, ".txt") != NULL || strstr(filepath, ".doc") != NULL) {
            takakrypt_info("ENCRYPTION_POLICY: File matches encryption policy (txt/doc): %s - ENCRYPTING\n", filepath);
            return 1; /* Encrypt */
        } else {
            takakrypt_info("ENCRYPTION_POLICY: File extension does not match (no .txt/.doc): %s - NOT ENCRYPTING\n", filepath);
        }
    } else {
        takakrypt_info("ENCRYPTION_POLICY: File not in test directory: %s - NOT ENCRYPTING\n", filepath);
    }
    
    takakrypt_info("ENCRYPTION_POLICY: File does not match encryption policy: %s\n", filepath);
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
    struct takakrypt_encrypt_request *request;
    struct takakrypt_crypto_response *response;
    size_t key_id_len = strlen(key_id);
    size_t request_size, response_size;
    void *req_buf, *resp_buf;
    int ret;
    
    takakrypt_info("ENCRYPT_DATA: Starting encryption of %zu bytes with key %s\n", data_len, key_id);
    
    if (!data || !key_id || !encrypted_data) {
        takakrypt_error("ENCRYPT_DATA: Invalid parameters\n");
        return -EINVAL;
    }
    
    /* Allocate request buffer */
    request_size = sizeof(struct takakrypt_encrypt_request) + key_id_len + data_len;
    req_buf = kzalloc(request_size, GFP_KERNEL);
    if (!req_buf) {
        return -ENOMEM;
    }
    
    /* Allocate response buffer (max expected size) */
    response_size = sizeof(struct takakrypt_crypto_response) + data_len + 200; /* Extra space for header/tag */
    resp_buf = kzalloc(response_size, GFP_KERNEL);
    if (!resp_buf) {
        kfree(req_buf);
        return -ENOMEM;
    }
    
    /* Build request */
    request = (struct takakrypt_encrypt_request *)req_buf;
    request->header.magic = TAKAKRYPT_MSG_MAGIC;
    request->header.version = TAKAKRYPT_PROTOCOL_VERSION;
    request->header.operation = TAKAKRYPT_OP_ENCRYPT;
    request->header.sequence = atomic_inc_return(&takakrypt_global_state->sequence_counter);
    request->header.payload_size = key_id_len + data_len + 8; /* 8 bytes for lengths */
    request->header.timestamp = ktime_get_real_seconds();
    request->key_id_len = key_id_len;
    request->data_len = data_len;
    
    /* Copy key ID and data */
    memcpy(req_buf + sizeof(struct takakrypt_encrypt_request), key_id, key_id_len);
    memcpy(req_buf + sizeof(struct takakrypt_encrypt_request) + key_id_len, data, data_len);
    
    takakrypt_info("ENCRYPT_DATA: Sending encryption request to agent, sequence=%u\n", request->header.sequence);
    
    /* Send request and wait for response */
    ret = takakrypt_send_request_and_wait(&request->header, request_size, resp_buf, response_size);
    if (ret) {
        takakrypt_error("ENCRYPT_DATA: Failed to send encrypt request: %d\n", ret);
        kfree(req_buf);
        kfree(resp_buf);
        return ret;
    }
    
    takakrypt_info("ENCRYPT_DATA: Received encryption response from agent\n");
    
    /* Parse response */
    response = (struct takakrypt_crypto_response *)resp_buf;
    if (response->header.magic != TAKAKRYPT_MSG_MAGIC ||
        response->header.operation != TAKAKRYPT_OP_ENCRYPT) {
        takakrypt_error("ENCRYPT_DATA: Invalid encrypt response - magic=0x%x, operation=%u\n", 
                       response->header.magic, response->header.operation);
        kfree(req_buf);
        kfree(resp_buf);
        return -EINVAL;
    }
    
    takakrypt_info("ENCRYPT_DATA: Valid encryption response received, data_len=%u\n", response->data_len);
    
    /* Allocate output buffer and copy encrypted data */
    *encrypted_data = kmalloc(response->data_len, GFP_KERNEL);
    if (!*encrypted_data) {
        kfree(req_buf);
        kfree(resp_buf);
        return -ENOMEM;
    }
    
    memcpy(*encrypted_data, resp_buf + sizeof(struct takakrypt_crypto_response), response->data_len);
    
    takakrypt_info("ENCRYPT_DATA: Encryption complete: %zu bytes -> %u bytes\n", data_len, response->data_len);
    
    kfree(req_buf);
    kfree(resp_buf);
    return response->data_len;
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
    struct takakrypt_encrypt_request *request;
    struct takakrypt_crypto_response *response;
    size_t key_id_len = strlen(key_id);
    size_t request_size, response_size;
    void *req_buf, *resp_buf;
    int ret;
    
    takakrypt_debug("Decrypting %zu bytes with key %s\n", data_len, key_id);
    
    /* Check if data might be encrypted (has TAKA header) */
    if (data_len < 4 || memcmp(encrypted_data, "TAKA", 4) != 0) {
        /* Data is not encrypted, return as-is */
        *decrypted_data = kmalloc(data_len, GFP_KERNEL);
        if (!*decrypted_data) {
            return -ENOMEM;
        }
        memcpy(*decrypted_data, encrypted_data, data_len);
        return data_len;
    }
    
    /* Allocate request buffer */
    request_size = sizeof(struct takakrypt_encrypt_request) + key_id_len + data_len;
    req_buf = kzalloc(request_size, GFP_KERNEL);
    if (!req_buf) {
        return -ENOMEM;
    }
    
    /* Allocate response buffer */
    response_size = sizeof(struct takakrypt_crypto_response) + data_len; /* Decrypted should be smaller */
    resp_buf = kzalloc(response_size, GFP_KERNEL);
    if (!resp_buf) {
        kfree(req_buf);
        return -ENOMEM;
    }
    
    /* Build request */
    request = (struct takakrypt_encrypt_request *)req_buf;
    request->header.magic = TAKAKRYPT_MSG_MAGIC;
    request->header.version = TAKAKRYPT_PROTOCOL_VERSION;
    request->header.operation = TAKAKRYPT_OP_DECRYPT;
    request->header.sequence = atomic_inc_return(&takakrypt_global_state->sequence_counter);
    request->header.payload_size = key_id_len + data_len + 8;
    request->header.timestamp = ktime_get_real_seconds();
    request->key_id_len = key_id_len;
    request->data_len = data_len;
    
    /* Copy key ID and encrypted data */
    memcpy(req_buf + sizeof(struct takakrypt_encrypt_request), key_id, key_id_len);
    memcpy(req_buf + sizeof(struct takakrypt_encrypt_request) + key_id_len, encrypted_data, data_len);
    
    /* Send request and wait for response */
    ret = takakrypt_send_request_and_wait(&request->header, request_size, resp_buf, response_size);
    if (ret) {
        takakrypt_error("Failed to send decrypt request: %d\n", ret);
        kfree(req_buf);
        kfree(resp_buf);
        return ret;
    }
    
    /* Parse response */
    response = (struct takakrypt_crypto_response *)resp_buf;
    if (response->header.magic != TAKAKRYPT_MSG_MAGIC ||
        response->header.operation != TAKAKRYPT_OP_DECRYPT) {
        takakrypt_error("Invalid decrypt response\n");
        kfree(req_buf);
        kfree(resp_buf);
        return -EINVAL;
    }
    
    /* Allocate output buffer and copy decrypted data */
    *decrypted_data = kmalloc(response->data_len, GFP_KERNEL);
    if (!*decrypted_data) {
        kfree(req_buf);
        kfree(resp_buf);
        return -ENOMEM;
    }
    
    memcpy(*decrypted_data, resp_buf + sizeof(struct takakrypt_crypto_response), response->data_len);
    
    takakrypt_debug("Decryption complete: %zu bytes -> %u bytes\n", data_len, response->data_len);
    
    kfree(req_buf);
    kfree(resp_buf);
    return response->data_len;
}