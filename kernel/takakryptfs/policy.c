#include "takakryptfs.h"

/**
 * takakryptfs_send_policy_request - Send policy evaluation request via netlink
 * @filepath: File path to evaluate
 * @operation: Operation being performed
 * @result: Structure to store policy evaluation result
 * 
 * Returns: 0 on success, negative error code on failure
 */
static int takakryptfs_send_policy_request(const char *filepath, const char *operation,
                                          struct takakryptfs_policy_result *result)
{
    struct takakrypt_msg_header *request;
    struct takakrypt_msg_header *response;
    size_t request_size, response_size;
    uint32_t uid, gid, pid;
    char *req_buf, *resp_buf;
    int ret;
    
    /* Get current process information */
    uid = from_kuid(&init_user_ns, current_uid());
    gid = from_kgid(&init_user_ns, current_gid());
    pid = current->pid;
    
    /* Calculate request size */
    request_size = sizeof(struct takakrypt_msg_header) + 
                   sizeof(uint32_t) * 3 +  /* uid, gid, pid */
                   strlen(filepath) + 1 +   /* filepath */
                   strlen(operation) + 1;   /* operation */
    
    /* Allocate request buffer */
    req_buf = kzalloc(request_size, GFP_KERNEL);
    if (!req_buf) {
        return -ENOMEM;
    }
    
    /* Allocate response buffer */
    response_size = sizeof(struct takakrypt_msg_header) + 256; /* Extra space for response data */
    resp_buf = kzalloc(response_size, GFP_KERNEL);
    if (!resp_buf) {
        kfree(req_buf);
        return -ENOMEM;
    }
    
    /* Build request */
    request = (struct takakrypt_msg_header *)req_buf;
    request->magic = TAKAKRYPT_MSG_MAGIC;
    request->version = TAKAKRYPT_PROTOCOL_VERSION;
    request->operation = TAKAKRYPT_OP_CHECK_POLICY;
    request->sequence = atomic_inc_return(&takakrypt_global_state->sequence);
    request->payload_size = request_size - sizeof(struct takakrypt_msg_header);
    request->timestamp = ktime_get_real_seconds();
    
    /* Add payload data */
    char *payload = req_buf + sizeof(struct takakrypt_msg_header);
    memcpy(payload, &uid, sizeof(uint32_t));
    payload += sizeof(uint32_t);
    memcpy(payload, &gid, sizeof(uint32_t));
    payload += sizeof(uint32_t);
    memcpy(payload, &pid, sizeof(uint32_t));
    payload += sizeof(uint32_t);
    strcpy(payload, filepath);
    payload += strlen(filepath) + 1;
    strcpy(payload, operation);
    
    /* Send request and wait for response */
    ret = takakrypt_send_request_and_wait(request, request_size, resp_buf, response_size);
    if (ret) {
        takakryptfs_error("Failed to send policy request: %d\n", ret);
        kfree(req_buf);
        kfree(resp_buf);
        return ret;
    }
    
    /* Parse response */
    response = (struct takakrypt_msg_header *)resp_buf;
    if (response->magic != TAKAKRYPT_MSG_MAGIC ||
        response->operation != TAKAKRYPT_OP_CHECK_POLICY) {
        takakryptfs_error("Invalid policy response\n");
        kfree(req_buf);
        kfree(resp_buf);
        return -EINVAL;
    }
    
    /* Extract policy decision from response */
    if (response->payload_size >= sizeof(struct takakryptfs_policy_result)) {
        memcpy(result, resp_buf + sizeof(struct takakrypt_msg_header), 
               sizeof(struct takakryptfs_policy_result));
    } else {
        /* Fallback for smaller response */
        result->allow_access = true;
        result->encrypt_file = false;
        strncpy(result->reason, "Policy engine response too small", 
                sizeof(result->reason) - 1);
    }
    
    takakryptfs_debug("Policy evaluation result: allow=%d, encrypt=%d, reason=%s\n",
                      result->allow_access, result->encrypt_file, result->reason);
    
    kfree(req_buf);
    kfree(resp_buf);
    return 0;
}

/**
 * takakryptfs_evaluate_policy - Evaluate encryption policy for a file using security rules
 * @file: File to evaluate policy for
 * @operation: Operation being performed ("open_read", "open_write", "create", etc.)
 * @result: Structure to store policy evaluation result
 * 
 * Returns: 0 on success, negative error code on failure
 */
int takakryptfs_evaluate_policy_v2(struct file *file, const char *operation,
                                   struct takakryptfs_policy_result *result)
{
    struct takakryptfs_sb_info *sb_info;
    char *filepath;
    char *path_str;
    int ret;
    
    if (!file || !operation || !result) {
        return -EINVAL;
    }
    
    /* Initialize result structure */
    memset(result, 0, sizeof(*result));
    result->allow_access = true; /* Default to allowing access */
    
    /* Get superblock info for policy name */
    sb_info = takakryptfs_sb_to_private(file->f_inode->i_sb);
    if (!sb_info) {
        takakryptfs_error("No superblock info available\n");
        return -EINVAL;
    }
    
    /* Allocate buffer for file path */
    filepath = kmalloc(TAKAKRYPTFS_MAX_PATH_LEN, GFP_KERNEL);
    if (!filepath) {
        return -ENOMEM;
    }
    
    /* Get file path for policy evaluation */
    path_str = d_path(&file->f_path, filepath, TAKAKRYPTFS_MAX_PATH_LEN);
    if (IS_ERR(path_str)) {
        takakryptfs_warn("Failed to get file path for policy evaluation\n");
        strncpy(filepath, "(unknown)", TAKAKRYPTFS_MAX_PATH_LEN - 1);
        filepath[TAKAKRYPTFS_MAX_PATH_LEN - 1] = '\0';
        path_str = filepath;
    }
    
    takakryptfs_debug("Evaluating security rules for file: %s, operation: %s\n", 
                      path_str, operation);
    
    /* Copy policy name to result */
    strncpy(result->policy_name, sb_info->ctx.policy_name, 
            sizeof(result->policy_name) - 1);
    result->policy_name[sizeof(result->policy_name) - 1] = '\0';
    
    /* Send policy evaluation request to user-space agent */
    ret = takakryptfs_send_policy_request(path_str, operation, result);
    if (ret) {
        takakryptfs_warn("Policy evaluation failed, falling back to default policy: %d\n", ret);
        /* Fallback to simple file-based policy */
        ret = takakryptfs_evaluate_policy_fallback(file, result);
    }
    
    /* Update statistics */
    takakryptfs_inc_stat(&sb_info->stats.policy_lookups);
    if (result->allow_access) {
        takakryptfs_inc_stat(&sb_info->stats.cache_hits);
    } else {
        takakryptfs_inc_stat(&sb_info->stats.cache_misses);
    }
    
    /* Free allocated buffer */
    kfree(filepath);
    
    return ret;
}

/**
 * takakryptfs_evaluate_policy - Legacy policy evaluation (fallback)
 */
int takakryptfs_evaluate_policy(struct file *file, struct takakryptfs_policy_result *result)
{
    /* Use the new V2 evaluation with "access" operation */
    return takakryptfs_evaluate_policy_v2(file, "access", result);
}

/**
 * takakryptfs_evaluate_policy_fallback - Fallback policy evaluation
 */
static int takakryptfs_evaluate_policy_fallback(struct file *file, 
                                               struct takakryptfs_policy_result *result)
{
    struct takakryptfs_sb_info *sb_info;
    char *filepath;
    char *path_str;
    
    /* Get superblock info for policy name */
    sb_info = takakryptfs_sb_to_private(file->f_inode->i_sb);
    if (!sb_info) {
        return -EINVAL;
    }
    
    /* Allocate buffer for file path */
    filepath = kmalloc(TAKAKRYPTFS_MAX_PATH_LEN, GFP_KERNEL);
    if (!filepath) {
        return -ENOMEM;
    }
    
    /* Get file path */
    path_str = d_path(&file->f_path, filepath, TAKAKRYPTFS_MAX_PATH_LEN);
    if (IS_ERR(path_str)) {
        strncpy(filepath, "(unknown)", TAKAKRYPTFS_MAX_PATH_LEN - 1);
        filepath[TAKAKRYPTFS_MAX_PATH_LEN - 1] = '\0';
        path_str = filepath;
    }
    
    /* Use simple file extension-based policy as fallback */
    if (takakryptfs_should_encrypt_file(file->f_inode, path_str)) {
        result->encrypt_file = true;
        snprintf(result->key_id, sizeof(result->key_id), "policy-%s-key", 
                 sb_info->ctx.policy_name);
        strncpy(result->reason, "Fallback: File matches encryption policy", 
                sizeof(result->reason) - 1);
        result->reason[sizeof(result->reason) - 1] = '\0';
    } else {
        result->encrypt_file = false;
        strncpy(result->reason, "Fallback: File does not match encryption policy", 
                sizeof(result->reason) - 1);
        result->reason[sizeof(result->reason) - 1] = '\0';
    }
    
    kfree(filepath);
    return 0;
}

/**
 * takakryptfs_check_file_access - Check if file access should be allowed
 * @file: File being accessed
 * @mask: Access mask (MAY_READ, MAY_WRITE, etc.)
 * 
 * Returns: 0 if allowed, negative error code if denied
 */
int takakryptfs_check_file_access(struct file *file, int mask)
{
    struct takakryptfs_policy_result result;
    int ret;
    
    if (!file) {
        return -EINVAL;
    }
    
    takakryptfs_debug("Checking file access: mask=0x%x\n", mask);
    
    /* Evaluate policy for this file */
    ret = takakryptfs_evaluate_policy(file, &result);
    if (ret) {
        takakryptfs_warn("Policy evaluation failed: %d\n", ret);
        return ret;
    }
    
    /* Check if access is allowed */
    if (!result.allow_access) {
        takakryptfs_info("File access denied by policy: %s\n", result.reason);
        return -EACCES;
    }
    
    takakryptfs_debug("File access allowed\n");
    return 0;
}

/**
 * takakryptfs_should_encrypt_file - Determine if file should be encrypted
 * @inode: Inode of the file
 * @filepath: Path of the file
 * 
 * Returns: true if file should be encrypted, false otherwise
 */
bool takakryptfs_should_encrypt_file(struct inode *inode, const char *filepath)
{
    const char *file_ext;
    const char *basename;
    
    if (!inode || !filepath) {
        return false;
    }
    
    /* Only encrypt regular files */
    if (!S_ISREG(inode->i_mode)) {
        return false;
    }
    
    /* Get file basename and extension */
    basename = strrchr(filepath, '/');
    if (basename) {
        basename++; /* Skip the '/' */
    } else {
        basename = filepath;
    }
    
    file_ext = strrchr(basename, '.');
    
    takakryptfs_debug("Checking encryption for file: %s (extension: %s)\n", 
                      basename, file_ext ? file_ext : "(none)");
    
    /* Simple extension-based encryption rules */
    /* TODO: Replace with comprehensive policy engine */
    
    if (file_ext) {
        /* Encrypt common document types */
        if (strcmp(file_ext, ".txt") == 0 ||
            strcmp(file_ext, ".doc") == 0 ||
            strcmp(file_ext, ".docx") == 0 ||
            strcmp(file_ext, ".pdf") == 0 ||
            strcmp(file_ext, ".xls") == 0 ||
            strcmp(file_ext, ".xlsx") == 0 ||
            strcmp(file_ext, ".ppt") == 0 ||
            strcmp(file_ext, ".pptx") == 0) {
            takakryptfs_debug("File matches document encryption policy\n");
            return true;
        }
        
        /* Encrypt database files */
        if (strcmp(file_ext, ".db") == 0 ||
            strcmp(file_ext, ".sqlite") == 0 ||
            strcmp(file_ext, ".mdb") == 0 ||
            strcmp(file_ext, ".accdb") == 0) {
            takakryptfs_debug("File matches database encryption policy\n");
            return true;
        }
    }
    
    /* Check for MySQL/PostgreSQL data files by path */
    if (strstr(filepath, "/mysql/") != NULL ||
        strstr(filepath, "/postgresql/") != NULL ||
        strstr(filepath, "/var/lib/mysql/") != NULL ||
        strstr(filepath, "/var/lib/postgresql/") != NULL) {
        takakryptfs_debug("File matches database path encryption policy\n");
        return true;
    }
    
    /* Check for sensitive configuration files */
    if (strstr(basename, "config") != NULL ||
        strstr(basename, "secret") != NULL ||
        strstr(basename, "password") != NULL ||
        strstr(basename, "key") != NULL) {
        takakryptfs_debug("File matches sensitive file encryption policy\n");
        return true;
    }
    
    takakryptfs_debug("File does not match any encryption policy\n");
    return false;
}

/**
 * takakryptfs_get_policy_info - Get information about the active policy
 * @sb: Superblock to get policy info for
 * @policy_info: Buffer to store policy information
 * @info_size: Size of the policy info buffer
 * 
 * Returns: 0 on success, negative error code on failure
 */
int takakryptfs_get_policy_info(struct super_block *sb, char *policy_info, size_t info_size)
{
    struct takakryptfs_sb_info *sb_info;
    
    if (!sb || !policy_info || info_size == 0) {
        return -EINVAL;
    }
    
    sb_info = takakryptfs_sb_to_private(sb);
    if (!sb_info) {
        return -EINVAL;
    }
    
    /* Format policy information */
    snprintf(policy_info, info_size,
             "Policy: %s\n"
             "Lower directory: %s\n"
             "Read-only: %s\n"
             "Active files: %d\n"
             "Policy lookups: %lld\n"
             "Files encrypted: %lld\n"
             "Files decrypted: %lld\n",
             sb_info->ctx.policy_name ? sb_info->ctx.policy_name : "(none)",
             sb_info->ctx.lower_path ? sb_info->ctx.lower_path : "(none)",
             sb_info->ctx.readonly ? "yes" : "no",
             atomic_read(&sb_info->active_files),
             atomic64_read(&sb_info->stats.policy_lookups),
             atomic64_read(&sb_info->stats.files_encrypted),
             atomic64_read(&sb_info->stats.files_decrypted));
    
    return 0;
}

/**
 * takakryptfs_update_policy - Update policy for a mount
 * @sb: Superblock to update policy for
 * @new_policy_name: New policy name
 * 
 * Returns: 0 on success, negative error code on failure
 */
int takakryptfs_update_policy(struct super_block *sb, const char *new_policy_name)
{
    struct takakryptfs_sb_info *sb_info;
    char *old_policy;
    
    if (!sb || !new_policy_name) {
        return -EINVAL;
    }
    
    sb_info = takakryptfs_sb_to_private(sb);
    if (!sb_info) {
        return -EINVAL;
    }
    
    takakryptfs_info("Updating policy from '%s' to '%s'\n",
                     sb_info->ctx.policy_name ? sb_info->ctx.policy_name : "(none)",
                     new_policy_name);
    
    /* Validate new policy name */
    if (strlen(new_policy_name) == 0 || strlen(new_policy_name) > 63) {
        takakryptfs_error("Invalid policy name length: %zu\n", strlen(new_policy_name));
        return -EINVAL;
    }
    
    /* Check for invalid characters */
    if (strpbrk(new_policy_name, " \t\n\r/\\")) {
        takakryptfs_error("Policy name contains invalid characters: %s\n", new_policy_name);
        return -EINVAL;
    }
    
    /* Update policy name */
    old_policy = sb_info->ctx.policy_name;
    sb_info->ctx.policy_name = kstrdup(new_policy_name, GFP_KERNEL);
    if (!sb_info->ctx.policy_name) {
        sb_info->ctx.policy_name = old_policy; /* Restore old policy */
        return -ENOMEM;
    }
    
    /* Free old policy name */
    kfree(old_policy);
    
    takakryptfs_info("Policy updated successfully to '%s'\n", new_policy_name);
    
    return 0;
}

/**
 * takakryptfs_policy_init - Initialize policy subsystem
 * 
 * Returns: 0 on success, negative error code on failure
 */
int takakryptfs_policy_init(void)
{
    takakryptfs_debug("Initializing policy subsystem\n");
    
    /* TODO: Initialize policy engine resources */
    /* This might include:
     * - Loading policy rules from configuration
     * - Setting up communication with policy server
     * - Initializing policy cache
     */
    
    takakryptfs_info("Policy subsystem initialized\n");
    
    return 0;
}

/**
 * takakryptfs_policy_exit - Cleanup policy subsystem
 */
void takakryptfs_policy_exit(void)
{
    takakryptfs_debug("Cleaning up policy subsystem\n");
    
    /* TODO: Clean up policy engine resources */
    
    takakryptfs_info("Policy subsystem cleaned up\n");
}