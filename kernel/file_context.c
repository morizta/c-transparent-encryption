#include "takakrypt.h"

/**
 * takakrypt_get_file_context - Get or create file context for tracking
 * @file: File structure
 * 
 * Returns: File context structure, or NULL on failure
 */
struct takakrypt_file_context *takakrypt_get_file_context(struct file *file)
{
    struct takakrypt_file_context *ctx, *existing_ctx = NULL;
    char filepath[TAKAKRYPT_MAX_PATH_LEN];
    int ret;
    
    if (!file || !takakrypt_global_state) {
        return NULL;
    }
    
    /* Get file path for identification */
    ret = takakrypt_get_file_path(file, filepath, sizeof(filepath));
    if (ret) {
        takakrypt_debug("Failed to get file path for context\n");
        return NULL;
    }
    
    /* Search for existing context first */
    spin_lock(&takakrypt_global_state->file_contexts_lock);
    list_for_each_entry(ctx, &takakrypt_global_state->file_contexts, list) {
        if (ctx->file == file || strcmp(ctx->filepath, filepath) == 0) {
            existing_ctx = ctx;
            atomic_inc(&existing_ctx->refcount);
            break;
        }
    }
    spin_unlock(&takakrypt_global_state->file_contexts_lock);
    
    if (existing_ctx) {
        takakrypt_debug("Found existing file context for %s\n", filepath);
        return existing_ctx;
    }
    
    /* Create new context */
    ctx = kzalloc(sizeof(struct takakrypt_file_context), GFP_KERNEL);
    if (!ctx) {
        takakrypt_error("Failed to allocate file context\n");
        return NULL;
    }
    
    /* Initialize context */
    ctx->file = file;
    strncpy(ctx->filepath, filepath, sizeof(ctx->filepath) - 1);
    ctx->filepath[sizeof(ctx->filepath) - 1] = '\0';
    ctx->encrypted = 0;
    ctx->policy_checked = 0;
    memset(ctx->key_id, 0, sizeof(ctx->key_id));
    spin_lock_init(&ctx->lock);
    atomic_set(&ctx->refcount, 1);
    INIT_LIST_HEAD(&ctx->list);
    
    /* Add to global list */
    spin_lock(&takakrypt_global_state->file_contexts_lock);
    list_add_tail(&ctx->list, &takakrypt_global_state->file_contexts);
    takakrypt_global_state->stats.active_files++;
    spin_unlock(&takakrypt_global_state->file_contexts_lock);
    
    takakrypt_debug("Created new file context for %s\n", filepath);
    return ctx;
}

/**
 * takakrypt_put_file_context - Release reference to file context
 * @ctx: File context to release
 */
void takakrypt_put_file_context(struct takakrypt_file_context *ctx)
{
    if (!ctx) {
        return;
    }
    
    if (atomic_dec_and_test(&ctx->refcount)) {
        takakrypt_debug("Releasing file context for %s\n", ctx->filepath);
        
        /* Remove from global list */
        spin_lock(&takakrypt_global_state->file_contexts_lock);
        list_del(&ctx->list);
        if (takakrypt_global_state->stats.active_files > 0) {
            takakrypt_global_state->stats.active_files--;
        }
        spin_unlock(&takakrypt_global_state->file_contexts_lock);
        
        /* Free the context */
        kfree(ctx);
    }
}

/**
 * takakrypt_find_file_context - Find file context by file pointer
 * @file: File structure to search for
 * 
 * Returns: File context if found, NULL otherwise
 */
struct takakrypt_file_context *takakrypt_find_file_context(struct file *file)
{
    struct takakrypt_file_context *ctx;
    
    if (!file || !takakrypt_global_state) {
        return NULL;
    }
    
    spin_lock(&takakrypt_global_state->file_contexts_lock);
    list_for_each_entry(ctx, &takakrypt_global_state->file_contexts, list) {
        if (ctx->file == file) {
            atomic_inc(&ctx->refcount);
            spin_unlock(&takakrypt_global_state->file_contexts_lock);
            return ctx;
        }
    }
    spin_unlock(&takakrypt_global_state->file_contexts_lock);
    
    return NULL;
}

/**
 * takakrypt_find_file_context_by_path - Find file context by file path
 * @filepath: File path to search for
 * 
 * Returns: File context if found, NULL otherwise
 */
struct takakrypt_file_context *takakrypt_find_file_context_by_path(const char *filepath)
{
    struct takakrypt_file_context *ctx;
    
    if (!filepath || !takakrypt_global_state) {
        return NULL;
    }
    
    spin_lock(&takakrypt_global_state->file_contexts_lock);
    list_for_each_entry(ctx, &takakrypt_global_state->file_contexts, list) {
        if (strcmp(ctx->filepath, filepath) == 0) {
            atomic_inc(&ctx->refcount);
            spin_unlock(&takakrypt_global_state->file_contexts_lock);
            return ctx;
        }
    }
    spin_unlock(&takakrypt_global_state->file_contexts_lock);
    
    return NULL;
}

/**
 * takakrypt_update_file_context - Update file context encryption settings
 * @ctx: File context to update
 * @encrypted: Whether file should be encrypted
 * @key_id: Encryption key ID
 * 
 * Returns: 0 on success, negative error code on failure
 */
int takakrypt_update_file_context(struct takakrypt_file_context *ctx, 
                                 uint32_t encrypted, const char *key_id)
{
    if (!ctx) {
        return -EINVAL;
    }
    
    spin_lock(&ctx->lock);
    
    ctx->encrypted = encrypted;
    ctx->policy_checked = 1;
    
    if (key_id) {
        strncpy(ctx->key_id, key_id, sizeof(ctx->key_id) - 1);
        ctx->key_id[sizeof(ctx->key_id) - 1] = '\0';
    } else {
        memset(ctx->key_id, 0, sizeof(ctx->key_id));
    }
    
    spin_unlock(&ctx->lock);
    
    takakrypt_debug("Updated file context for %s: encrypted=%u, key_id=%s\n",
                   ctx->filepath, encrypted, key_id ? key_id : "none");
    
    return 0;
}

/**
 * takakrypt_is_file_encrypted - Check if file is marked as encrypted
 * @ctx: File context to check
 * 
 * Returns: 1 if encrypted, 0 otherwise
 */
int takakrypt_is_file_encrypted(struct takakrypt_file_context *ctx)
{
    int encrypted;
    
    if (!ctx) {
        return 0;
    }
    
    spin_lock(&ctx->lock);
    encrypted = ctx->encrypted;
    spin_unlock(&ctx->lock);
    
    return encrypted;
}

/**
 * takakrypt_get_file_key_id - Get encryption key ID for file
 * @ctx: File context
 * @key_id: Buffer to store key ID
 * @key_id_size: Size of key ID buffer
 * 
 * Returns: 0 on success, negative error code on failure
 */
int takakrypt_get_file_key_id(struct takakrypt_file_context *ctx, 
                             char *key_id, size_t key_id_size)
{
    if (!ctx || !key_id || key_id_size == 0) {
        return -EINVAL;
    }
    
    spin_lock(&ctx->lock);
    strncpy(key_id, ctx->key_id, key_id_size - 1);
    key_id[key_id_size - 1] = '\0';
    spin_unlock(&ctx->lock);
    
    return 0;
}

/**
 * takakrypt_cleanup_file_contexts - Clean up all file contexts
 */
void takakrypt_cleanup_file_contexts(void)
{
    struct takakrypt_file_context *ctx, *tmp;
    int total_contexts = 0;
    
    if (!takakrypt_global_state) {
        return;
    }
    
    takakrypt_info("Cleaning up file contexts\n");
    
    spin_lock(&takakrypt_global_state->file_contexts_lock);
    
    list_for_each_entry_safe(ctx, tmp, &takakrypt_global_state->file_contexts, list) {
        list_del(&ctx->list);
        total_contexts++;
        
        /* Force cleanup regardless of reference count (module unloading) */
        atomic_set(&ctx->refcount, 0);
        kfree(ctx);
    }
    
    takakrypt_global_state->stats.active_files = 0;
    
    spin_unlock(&takakrypt_global_state->file_contexts_lock);
    
    takakrypt_info("Cleaned up %d file contexts\n", total_contexts);
}

/**
 * takakrypt_cleanup_stale_contexts - Clean up contexts for closed files
 */
void takakrypt_cleanup_stale_contexts(void)
{
    struct takakrypt_file_context *ctx, *tmp;
    int stale_contexts = 0;
    
    if (!takakrypt_global_state) {
        return;
    }
    
    spin_lock(&takakrypt_global_state->file_contexts_lock);
    
    list_for_each_entry_safe(ctx, tmp, &takakrypt_global_state->file_contexts, list) {
        /* Check if file is still valid */
        if (!ctx->file || atomic_read(&ctx->refcount) == 1) {
            /* Only our reference remains, file likely closed */
            list_del(&ctx->list);
            stale_contexts++;
            
            if (takakrypt_global_state->stats.active_files > 0) {
                takakrypt_global_state->stats.active_files--;
            }
            
            /* Decrement reference count to free */
            if (atomic_dec_and_test(&ctx->refcount)) {
                kfree(ctx);
            }
        }
    }
    
    spin_unlock(&takakrypt_global_state->file_contexts_lock);
    
    if (stale_contexts > 0) {
        takakrypt_debug("Cleaned up %d stale file contexts\n", stale_contexts);
    }
}

/**
 * takakrypt_get_file_contexts_stats - Get file context statistics
 * @total_contexts: Output parameter for total contexts
 * @encrypted_contexts: Output parameter for encrypted contexts
 */
void takakrypt_get_file_contexts_stats(uint32_t *total_contexts, uint32_t *encrypted_contexts)
{
    struct takakrypt_file_context *ctx;
    uint32_t total = 0, encrypted = 0;
    
    if (!takakrypt_global_state) {
        if (total_contexts) *total_contexts = 0;
        if (encrypted_contexts) *encrypted_contexts = 0;
        return;
    }
    
    spin_lock(&takakrypt_global_state->file_contexts_lock);
    
    list_for_each_entry(ctx, &takakrypt_global_state->file_contexts, list) {
        total++;
        
        spin_lock(&ctx->lock);
        if (ctx->encrypted) {
            encrypted++;
        }
        spin_unlock(&ctx->lock);
    }
    
    spin_unlock(&takakrypt_global_state->file_contexts_lock);
    
    if (total_contexts) *total_contexts = total;
    if (encrypted_contexts) *encrypted_contexts = encrypted;
}

/**
 * takakrypt_invalidate_file_context - Invalidate file context by path
 * @filepath: File path to invalidate
 */
void takakrypt_invalidate_file_context(const char *filepath)
{
    struct takakrypt_file_context *ctx, *tmp;
    
    if (!filepath || !takakrypt_global_state) {
        return;
    }
    
    takakrypt_debug("Invalidating file context for %s\n", filepath);
    
    spin_lock(&takakrypt_global_state->file_contexts_lock);
    
    list_for_each_entry_safe(ctx, tmp, &takakrypt_global_state->file_contexts, list) {
        if (strcmp(ctx->filepath, filepath) == 0) {
            list_del(&ctx->list);
            
            if (takakrypt_global_state->stats.active_files > 0) {
                takakrypt_global_state->stats.active_files--;
            }
            
            /* Decrement reference and free if no other references */
            if (atomic_dec_and_test(&ctx->refcount)) {
                kfree(ctx);
            }
            
            break;
        }
    }
    
    spin_unlock(&takakrypt_global_state->file_contexts_lock);
}