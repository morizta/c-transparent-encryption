/* Enhanced logging added for debugging */

#include "takakrypt.h"

#define TAKAKRYPT_PROC_DIR "takakrypt"

static struct proc_dir_entry *takakrypt_proc_dir = NULL;
static struct proc_dir_entry *takakrypt_proc_status = NULL;
static struct proc_dir_entry *takakrypt_proc_config = NULL;
static struct proc_dir_entry *takakrypt_proc_cache = NULL;
static struct proc_dir_entry *takakrypt_proc_files = NULL;

/**
 * takakrypt_proc_status_show - Show module status information
 * @m: Sequence file
 * @v: Unused
 * 
 * Returns: 0 on success
 */
static int takakrypt_proc_status_show(struct seq_file *m, void *v)
{
    struct takakrypt_status_info stats;
    uint32_t total_cache, expired_cache;
    uint32_t total_files, encrypted_files;
    unsigned long uptime;
    
    if (!takakrypt_global_state) {
        seq_printf(m, "Module not initialized\n");
        return 0;
    }
    
    /* Get current statistics */
    spin_lock(&takakrypt_global_state->stats_lock);
    stats = takakrypt_global_state->stats;
    spin_unlock(&takakrypt_global_state->stats_lock);
    
    uptime = (jiffies - takakrypt_global_state->start_time) / HZ;
    
    /* Get cache statistics */
    takakrypt_cache_get_stats(&total_cache, &expired_cache);
    
    /* Get file context statistics */
    takakrypt_get_file_contexts_stats(&total_files, &encrypted_files);
    
    seq_printf(m, "Takakrypt Transparent Encryption Module Status\n");
    seq_printf(m, "==============================================\n\n");
    
    seq_printf(m, "Module Information:\n");
    seq_printf(m, "  Version: %s\n", TAKAKRYPT_VERSION);
    seq_printf(m, "  Loaded: %s\n", stats.module_loaded ? "Yes" : "No");
    seq_printf(m, "  Active: %s\n", atomic_read(&takakrypt_global_state->module_active) ? "Yes" : "No");
    seq_printf(m, "  Uptime: %lu seconds\n", uptime);
    seq_printf(m, "\n");
    
    seq_printf(m, "Agent Connection:\n");
    seq_printf(m, "  Connected: %s\n", stats.agent_connected ? "Yes" : "No");
    seq_printf(m, "  Agent PID: %u\n", takakrypt_global_state->agent_pid);
    seq_printf(m, "\n");
    
    seq_printf(m, "Request Statistics:\n");
    seq_printf(m, "  Total Processed: %llu\n", stats.requests_processed);
    seq_printf(m, "  Allowed: %llu\n", stats.requests_allowed);
    seq_printf(m, "  Denied: %llu\n", stats.requests_denied);
    seq_printf(m, "  Denial Rate: %llu%%\n", 
               stats.requests_processed > 0 ? 
               (stats.requests_denied * 100) / stats.requests_processed : 0);
    seq_printf(m, "\n");
    
    seq_printf(m, "Cryptographic Operations:\n");
    seq_printf(m, "  Encryptions: %llu\n", stats.encryption_ops);
    seq_printf(m, "  Decryptions: %llu\n", stats.decryption_ops);
    seq_printf(m, "  Total Crypto Ops: %llu\n", stats.encryption_ops + stats.decryption_ops);
    seq_printf(m, "\n");
    
    seq_printf(m, "Cache Performance:\n");
    seq_printf(m, "  Cache Hits: %llu\n", stats.cache_hits);
    seq_printf(m, "  Cache Misses: %llu\n", stats.cache_misses);
    seq_printf(m, "  Hit Rate: %llu%%\n",
               (stats.cache_hits + stats.cache_misses) > 0 ?
               (stats.cache_hits * 100) / (stats.cache_hits + stats.cache_misses) : 0);
    seq_printf(m, "  Cached Entries: %u\n", total_cache);
    seq_printf(m, "  Expired Entries: %u\n", expired_cache);
    seq_printf(m, "\n");
    
    seq_printf(m, "File Tracking:\n");
    seq_printf(m, "  Active Files: %u\n", stats.active_files);
    seq_printf(m, "  Total Contexts: %u\n", total_files);
    seq_printf(m, "  Encrypted Files: %u\n", encrypted_files);
    seq_printf(m, "\n");
    
    return 0;
}

/**
 * takakrypt_proc_status_open - Open status proc file
 */
static int takakrypt_proc_status_open(struct inode *inode, struct file *file)
{
    return single_open(file, takakrypt_proc_status_show, NULL);
}

static const struct proc_ops takakrypt_proc_status_ops = {
    .proc_open = takakrypt_proc_status_open,
    .proc_read = seq_read,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
};

/**
 * takakrypt_proc_config_show - Show module configuration
 * @m: Sequence file
 * @v: Unused
 * 
 * Returns: 0 on success
 */
static int takakrypt_proc_config_show(struct seq_file *m, void *v)
{
    struct takakrypt_config config;
    
    if (!takakrypt_global_state) {
        seq_printf(m, "Module not initialized\n");
        return 0;
    }
    
    mutex_lock(&takakrypt_global_state->config_lock);
    config = takakrypt_global_state->config;
    mutex_unlock(&takakrypt_global_state->config_lock);
    
    seq_printf(m, "Takakrypt Module Configuration\n");
    seq_printf(m, "==============================\n\n");
    
    seq_printf(m, "Runtime Settings:\n");
    seq_printf(m, "  Enabled: %s\n", config.enabled ? "Yes" : "No");
    seq_printf(m, "  Debug Level: %u\n", config.debug_level);
    seq_printf(m, "  Cache Timeout: %u seconds\n", config.cache_timeout);
    seq_printf(m, "  Request Timeout: %u seconds\n", config.request_timeout);
    seq_printf(m, "\n");
    
    seq_printf(m, "Limits:\n");
    seq_printf(m, "  Max File Size: %u bytes\n", config.max_file_size);
    seq_printf(m, "  Max Concurrent Ops: %u\n", config.max_concurrent_ops);
    seq_printf(m, "\n");
    
    return 0;
}

/**
 * takakrypt_proc_config_open - Open config proc file
 */
static int takakrypt_proc_config_open(struct inode *inode, struct file *file)
{
    return single_open(file, takakrypt_proc_config_show, NULL);
}

static const struct proc_ops takakrypt_proc_config_ops = {
    .proc_open = takakrypt_proc_config_open,
    .proc_read = seq_read,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
};

/**
 * takakrypt_proc_cache_show - Show cache information
 * @m: Sequence file
 * @v: Unused
 * 
 * Returns: 0 on success
 */
static int takakrypt_proc_cache_show(struct seq_file *m, void *v)
{
    struct takakrypt_cache_entry *entry;
    uint32_t total_entries, expired_entries;
    int i, bucket_count;
    
    if (!takakrypt_global_state || !takakrypt_global_state->policy_cache) {
        seq_printf(m, "Cache not initialized\n");
        return 0;
    }
    
    takakrypt_cache_get_stats(&total_entries, &expired_entries);
    
    seq_printf(m, "Policy Cache Information\n");
    seq_printf(m, "========================\n\n");
    
    seq_printf(m, "Cache Statistics:\n");
    seq_printf(m, "  Total Entries: %u\n", total_entries);
    seq_printf(m, "  Expired Entries: %u\n", expired_entries);
    seq_printf(m, "  Cache Size: %u buckets\n", TAKAKRYPT_CACHE_SIZE);
    seq_printf(m, "  Load Factor: %u%%\n", 
               (total_entries * 100) / TAKAKRYPT_CACHE_SIZE);
    seq_printf(m, "\n");
    
    seq_printf(m, "Cache Entries:\n");
    seq_printf(m, "%-50s %-8s %-8s %-12s %-20s %-10s\n",
               "File Path", "UID", "PID", "Allow", "Policy", "Age (s)");
    seq_printf(m, "%s\n", "------------------------------------------------------------------------------");
    
    spin_lock(&takakrypt_global_state->cache_lock);
    
    for (i = 0; i < TAKAKRYPT_CACHE_SIZE; i++) {
        bucket_count = 0;
        hlist_for_each_entry(entry, &takakrypt_global_state->policy_cache[i], node) {
            unsigned long age = (jiffies - entry->timestamp) / HZ;
            const char *allow_str = entry->allow ? "Allow" : "Deny";
            char truncated_path[51];
            
            /* Truncate long paths */
            if (strlen(entry->filepath) > 50) {
                strncpy(truncated_path, entry->filepath, 47);
                strcpy(truncated_path + 47, "...");
            } else {
                strcpy(truncated_path, entry->filepath);
            }
            
            seq_printf(m, "%-50s %-8u %-8u %-12s %-20s %-10lu\n",
                       truncated_path, entry->uid, entry->pid, 
                       allow_str, entry->policy_name, age);
            
            bucket_count++;
            if (bucket_count > 10) { /* Limit output per bucket */
                seq_printf(m, "  ... (%d more entries in this bucket)\n", 
                          bucket_count - 10);
                break;
            }
        }
    }
    
    spin_unlock(&takakrypt_global_state->cache_lock);
    
    return 0;
}

/**
 * takakrypt_proc_cache_open - Open cache proc file
 */
static int takakrypt_proc_cache_open(struct inode *inode, struct file *file)
{
    return single_open(file, takakrypt_proc_cache_show, NULL);
}

static const struct proc_ops takakrypt_proc_cache_ops = {
    .proc_open = takakrypt_proc_cache_open,
    .proc_read = seq_read,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
};

/**
 * takakrypt_proc_files_show - Show active file contexts
 * @m: Sequence file
 * @v: Unused
 * 
 * Returns: 0 on success
 */
static int takakrypt_proc_files_show(struct seq_file *m, void *v)
{
    struct takakrypt_file_context *ctx;
    uint32_t total_files, encrypted_files;
    int count = 0;
    
    if (!takakrypt_global_state) {
        seq_printf(m, "Module not initialized\n");
        return 0;
    }
    
    takakrypt_get_file_contexts_stats(&total_files, &encrypted_files);
    
    seq_printf(m, "Active File Contexts\n");
    seq_printf(m, "====================\n\n");
    
    seq_printf(m, "File Statistics:\n");
    seq_printf(m, "  Total Files: %u\n", total_files);
    seq_printf(m, "  Encrypted Files: %u\n", encrypted_files);
    seq_printf(m, "  Unencrypted Files: %u\n", total_files - encrypted_files);
    seq_printf(m, "\n");
    
    seq_printf(m, "Active Files:\n");
    seq_printf(m, "%-60s %-10s %-20s %-8s\n",
               "File Path", "Encrypted", "Key ID", "RefCount");
    seq_printf(m, "%s\n", "--------------------------------------------------------------------------------");
    
    spin_lock(&takakrypt_global_state->file_contexts_lock);
    
    list_for_each_entry(ctx, &takakrypt_global_state->file_contexts, list) {
        const char *encrypted_str;
        char truncated_path[61];
        char key_id[21];
        
        spin_lock(&ctx->lock);
        encrypted_str = ctx->encrypted ? "Yes" : "No";
        
        /* Truncate long paths */
        if (strlen(ctx->filepath) > 60) {
            strncpy(truncated_path, ctx->filepath, 57);
            strcpy(truncated_path + 57, "...");
        } else {
            strcpy(truncated_path, ctx->filepath);
        }
        
        /* Truncate long key IDs */
        if (strlen(ctx->key_id) > 20) {
            strncpy(key_id, ctx->key_id, 17);
            strcpy(key_id + 17, "...");
        } else {
            strcpy(key_id, ctx->key_id);
        }
        
        spin_unlock(&ctx->lock);
        
        seq_printf(m, "%-60s %-10s %-20s %-8d\n",
                   truncated_path, encrypted_str, key_id,
                   atomic_read(&ctx->refcount));
        
        count++;
        if (count > 100) { /* Limit output */
            seq_printf(m, "  ... (%d more files)\n", total_files - count);
            break;
        }
    }
    
    spin_unlock(&takakrypt_global_state->file_contexts_lock);
    
    return 0;
}

/**
 * takakrypt_proc_files_open - Open files proc file
 */
static int takakrypt_proc_files_open(struct inode *inode, struct file *file)
{
    return single_open(file, takakrypt_proc_files_show, NULL);
}

static const struct proc_ops takakrypt_proc_files_ops = {
    .proc_open = takakrypt_proc_files_open,
    .proc_read = seq_read,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
};

/**
 * takakrypt_proc_init - Initialize proc filesystem interface
 * 
 * Returns: 0 on success, negative error code on failure
 */
int takakrypt_proc_init(void)
{
    takakrypt_info("Initializing proc filesystem interface\n");
    
    /* Create main directory */
    takakrypt_proc_dir = proc_mkdir(TAKAKRYPT_PROC_DIR, NULL);
    if (!takakrypt_proc_dir) {
        takakrypt_error("Failed to create proc directory\n");
        return -ENOMEM;
    }
    
    /* Create status file */
    takakrypt_proc_status = proc_create("status", 0444, takakrypt_proc_dir,
                                       &takakrypt_proc_status_ops);
    if (!takakrypt_proc_status) {
        takakrypt_error("Failed to create proc status file\n");
        goto cleanup_dir;
    }
    
    /* Create config file */
    takakrypt_proc_config = proc_create("config", 0444, takakrypt_proc_dir,
                                       &takakrypt_proc_config_ops);
    if (!takakrypt_proc_config) {
        takakrypt_error("Failed to create proc config file\n");
        goto cleanup_status;
    }
    
    /* Create cache file */
    takakrypt_proc_cache = proc_create("cache", 0444, takakrypt_proc_dir,
                                      &takakrypt_proc_cache_ops);
    if (!takakrypt_proc_cache) {
        takakrypt_error("Failed to create proc cache file\n");
        goto cleanup_config;
    }
    
    /* Create files file */
    takakrypt_proc_files = proc_create("files", 0444, takakrypt_proc_dir,
                                      &takakrypt_proc_files_ops);
    if (!takakrypt_proc_files) {
        takakrypt_error("Failed to create proc files file\n");
        goto cleanup_cache;
    }
    
    takakrypt_info("Proc filesystem interface initialized\n");
    takakrypt_info("Available at: /proc/%s/{status,config,cache,files}\n", 
                   TAKAKRYPT_PROC_DIR);
    
    return 0;

cleanup_cache:
    proc_remove(takakrypt_proc_cache);
cleanup_config:
    proc_remove(takakrypt_proc_config);
cleanup_status:
    proc_remove(takakrypt_proc_status);
cleanup_dir:
    proc_remove(takakrypt_proc_dir);
    return -ENOMEM;
}

/**
 * takakrypt_proc_cleanup - Cleanup proc filesystem interface
 */
void takakrypt_proc_cleanup(void)
{
    takakrypt_info("Cleaning up proc filesystem interface\n");
    
    if (takakrypt_proc_files) {
        proc_remove(takakrypt_proc_files);
        takakrypt_proc_files = NULL;
    }
    
    if (takakrypt_proc_cache) {
        proc_remove(takakrypt_proc_cache);
        takakrypt_proc_cache = NULL;
    }
    
    if (takakrypt_proc_config) {
        proc_remove(takakrypt_proc_config);
        takakrypt_proc_config = NULL;
    }
    
    if (takakrypt_proc_status) {
        proc_remove(takakrypt_proc_status);
        takakrypt_proc_status = NULL;
    }
    
    if (takakrypt_proc_dir) {
        proc_remove(takakrypt_proc_dir);
        takakrypt_proc_dir = NULL;
    }
    
    takakrypt_info("Proc filesystem interface cleaned up\n");
}