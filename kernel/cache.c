#include "takakrypt.h"

/**
 * takakrypt_hash_string - Simple hash function for strings
 * @str: String to hash
 * 
 * Returns: Hash value
 */
uint32_t takakrypt_hash_string(const char *str)
{
    uint32_t hash = 5381;
    int c;
    
    while ((c = *str++)) {
        hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
    }
    
    return hash;
}

/**
 * takakrypt_cache_hash - Generate cache hash for lookup key
 * @filepath: File path
 * @uid: User ID
 * @pid: Process ID
 * 
 * Returns: Hash value within cache size bounds
 */
static uint32_t takakrypt_cache_hash(const char *filepath, uint32_t uid, uint32_t pid)
{
    uint32_t hash;
    
    hash = takakrypt_hash_string(filepath);
    hash ^= uid << 16;
    hash ^= pid << 8;
    
    return hash & (TAKAKRYPT_CACHE_SIZE - 1);
}

/**
 * takakrypt_cache_entry_matches - Check if cache entry matches lookup key
 * @entry: Cache entry to check
 * @filepath: File path to match
 * @uid: User ID to match
 * @pid: Process ID to match
 * 
 * Returns: 1 if matches, 0 otherwise
 */
static int takakrypt_cache_entry_matches(struct takakrypt_cache_entry *entry,
                                        const char *filepath, uint32_t uid, uint32_t pid)
{
    return (entry->uid == uid &&
            entry->pid == pid &&
            strcmp(entry->filepath, filepath) == 0);
}

/**
 * takakrypt_cache_entry_expired - Check if cache entry has expired
 * @entry: Cache entry to check
 * 
 * Returns: 1 if expired, 0 otherwise
 */
static int takakrypt_cache_entry_expired(struct takakrypt_cache_entry *entry)
{
    unsigned long timeout = TAKAKRYPT_CACHE_TIMEOUT;
    
    /* Use configured timeout if available */
    if (takakrypt_global_state) {
        mutex_lock(&takakrypt_global_state->config_lock);
        timeout = takakrypt_global_state->config.cache_timeout * HZ;
        mutex_unlock(&takakrypt_global_state->config_lock);
    }
    
    return time_after(jiffies, entry->timestamp + timeout);
}

/**
 * takakrypt_cache_lookup - Look up policy decision in cache
 * @filepath: File path
 * @uid: User ID
 * @pid: Process ID
 * 
 * Returns: Cache entry if found and valid, NULL otherwise
 */
struct takakrypt_cache_entry *takakrypt_cache_lookup(const char *filepath, uint32_t uid, uint32_t pid)
{
    struct takakrypt_cache_entry *entry;
    struct hlist_head *head;
    uint32_t hash;
    
    if (!takakrypt_global_state || !takakrypt_global_state->policy_cache) {
        return NULL;
    }
    
    hash = takakrypt_cache_hash(filepath, uid, pid);
    head = &takakrypt_global_state->policy_cache[hash];
    
    spin_lock(&takakrypt_global_state->cache_lock);
    
    hlist_for_each_entry(entry, head, node) {
        if (takakrypt_cache_entry_matches(entry, filepath, uid, pid)) {
            /* Check if entry has expired */
            if (takakrypt_cache_entry_expired(entry)) {
                takakrypt_debug("Cache entry expired for %s\n", filepath);
                
                /* Remove expired entry */
                hlist_del(&entry->node);
                spin_unlock(&takakrypt_global_state->cache_lock);
                
                /* Free the entry (assuming no other references) */
                if (atomic_dec_and_test(&entry->refcount)) {
                    kfree(entry);
                }
                
                return NULL;
            }
            
            /* Increment reference count */
            atomic_inc(&entry->refcount);
            spin_unlock(&takakrypt_global_state->cache_lock);
            
            takakrypt_debug("Cache hit for %s (uid=%u, pid=%u): allow=%u\n",
                           filepath, uid, pid, entry->allow);
            return entry;
        }
    }
    
    spin_unlock(&takakrypt_global_state->cache_lock);
    
    takakrypt_debug("Cache miss for %s (uid=%u, pid=%u)\n", filepath, uid, pid);
    return NULL;
}

/**
 * takakrypt_cache_insert - Insert policy decision into cache
 * @filepath: File path
 * @uid: User ID
 * @pid: Process ID
 * @allow: Whether access is allowed (1) or denied (0)
 * @policy_name: Name of applied policy
 * @key_id: Encryption key ID
 */
void takakrypt_cache_insert(const char *filepath, uint32_t uid, uint32_t pid,
                           uint32_t allow, const char *policy_name, const char *key_id)
{
    struct takakrypt_cache_entry *entry, *existing;
    struct hlist_head *head;
    uint32_t hash;
    
    if (!takakrypt_global_state || !takakrypt_global_state->policy_cache) {
        return;
    }
    
    if (!filepath || !policy_name || !key_id) {
        takakrypt_error("Invalid parameters for cache insert\n");
        return;
    }
    
    /* Allocate new cache entry */
    entry = kzalloc(sizeof(struct takakrypt_cache_entry), GFP_KERNEL);
    if (!entry) {
        takakrypt_error("Failed to allocate cache entry\n");
        return;
    }
    
    /* Initialize entry */
    strncpy(entry->filepath, filepath, sizeof(entry->filepath) - 1);
    entry->filepath[sizeof(entry->filepath) - 1] = '\0';
    
    strncpy(entry->policy_name, policy_name, sizeof(entry->policy_name) - 1);
    entry->policy_name[sizeof(entry->policy_name) - 1] = '\0';
    
    strncpy(entry->key_id, key_id, sizeof(entry->key_id) - 1);
    entry->key_id[sizeof(entry->key_id) - 1] = '\0';
    
    entry->uid = uid;
    entry->pid = pid;
    entry->allow = allow;
    entry->timestamp = jiffies;
    atomic_set(&entry->refcount, 1);
    
    hash = takakrypt_cache_hash(filepath, uid, pid);
    head = &takakrypt_global_state->policy_cache[hash];
    
    spin_lock(&takakrypt_global_state->cache_lock);
    
    /* Check if entry already exists */
    hlist_for_each_entry(existing, head, node) {
        if (takakrypt_cache_entry_matches(existing, filepath, uid, pid)) {
            /* Update existing entry */
            existing->allow = allow;
            existing->timestamp = jiffies;
            strncpy(existing->policy_name, policy_name, sizeof(existing->policy_name) - 1);
            strncpy(existing->key_id, key_id, sizeof(existing->key_id) - 1);
            
            spin_unlock(&takakrypt_global_state->cache_lock);
            
            /* Free the new entry since we updated existing */
            kfree(entry);
            
            takakrypt_debug("Updated cache entry for %s (uid=%u, pid=%u)\n",
                           filepath, uid, pid);
            return;
        }
    }
    
    /* Insert new entry */
    hlist_add_head(&entry->node, head);
    spin_unlock(&takakrypt_global_state->cache_lock);
    
    takakrypt_debug("Inserted cache entry for %s (uid=%u, pid=%u): allow=%u\n",
                   filepath, uid, pid, allow);
}

/**
 * takakrypt_cache_remove - Remove entry from cache
 * @filepath: File path
 * @uid: User ID
 * @pid: Process ID
 */
void takakrypt_cache_remove(const char *filepath, uint32_t uid, uint32_t pid)
{
    struct takakrypt_cache_entry *entry;
    struct hlist_head *head;
    uint32_t hash;
    
    if (!takakrypt_global_state || !takakrypt_global_state->policy_cache) {
        return;
    }
    
    hash = takakrypt_cache_hash(filepath, uid, pid);
    head = &takakrypt_global_state->policy_cache[hash];
    
    spin_lock(&takakrypt_global_state->cache_lock);
    
    hlist_for_each_entry(entry, head, node) {
        if (takakrypt_cache_entry_matches(entry, filepath, uid, pid)) {
            hlist_del(&entry->node);
            spin_unlock(&takakrypt_global_state->cache_lock);
            
            takakrypt_debug("Removed cache entry for %s (uid=%u, pid=%u)\n",
                           filepath, uid, pid);
            
            /* Decrement reference and free if no references */
            if (atomic_dec_and_test(&entry->refcount)) {
                kfree(entry);
            }
            
            return;
        }
    }
    
    spin_unlock(&takakrypt_global_state->cache_lock);
}

/**
 * takakrypt_cache_invalidate_user - Invalidate all cache entries for a user
 * @uid: User ID
 */
void takakrypt_cache_invalidate_user(uint32_t uid)
{
    struct takakrypt_cache_entry *entry;
    struct hlist_node *tmp;
    int i;
    
    if (!takakrypt_global_state || !takakrypt_global_state->policy_cache) {
        return;
    }
    
    takakrypt_debug("Invalidating cache entries for user %u\n", uid);
    
    spin_lock(&takakrypt_global_state->cache_lock);
    
    for (i = 0; i < TAKAKRYPT_CACHE_SIZE; i++) {
        hlist_for_each_entry_safe(entry, tmp, &takakrypt_global_state->policy_cache[i], node) {
            if (entry->uid == uid) {
                hlist_del(&entry->node);
                
                /* Decrement reference and free if no references */
                if (atomic_dec_and_test(&entry->refcount)) {
                    kfree(entry);
                }
            }
        }
    }
    
    spin_unlock(&takakrypt_global_state->cache_lock);
}

/**
 * takakrypt_cache_invalidate_process - Invalidate all cache entries for a process
 * @pid: Process ID
 */
void takakrypt_cache_invalidate_process(uint32_t pid)
{
    struct takakrypt_cache_entry *entry;
    struct hlist_node *tmp;
    int i;
    
    if (!takakrypt_global_state || !takakrypt_global_state->policy_cache) {
        return;
    }
    
    takakrypt_debug("Invalidating cache entries for process %u\n", pid);
    
    spin_lock(&takakrypt_global_state->cache_lock);
    
    for (i = 0; i < TAKAKRYPT_CACHE_SIZE; i++) {
        hlist_for_each_entry_safe(entry, tmp, &takakrypt_global_state->policy_cache[i], node) {
            if (entry->pid == pid) {
                hlist_del(&entry->node);
                
                /* Decrement reference and free if no references */
                if (atomic_dec_and_test(&entry->refcount)) {
                    kfree(entry);
                }
            }
        }
    }
    
    spin_unlock(&takakrypt_global_state->cache_lock);
}

/**
 * takakrypt_cache_cleanup - Clean up all cache entries
 */
void takakrypt_cache_cleanup(void)
{
    struct takakrypt_cache_entry *entry;
    struct hlist_node *tmp;
    int i, total_entries = 0;
    
    if (!takakrypt_global_state || !takakrypt_global_state->policy_cache) {
        return;
    }
    
    takakrypt_info("Cleaning up policy cache\n");
    
    spin_lock(&takakrypt_global_state->cache_lock);
    
    for (i = 0; i < TAKAKRYPT_CACHE_SIZE; i++) {
        hlist_for_each_entry_safe(entry, tmp, &takakrypt_global_state->policy_cache[i], node) {
            hlist_del(&entry->node);
            total_entries++;
            
            /* Force free regardless of reference count (module unloading) */
            atomic_set(&entry->refcount, 0);
            kfree(entry);
        }
    }
    
    spin_unlock(&takakrypt_global_state->cache_lock);
    
    takakrypt_info("Cleaned up %d cache entries\n", total_entries);
}

/**
 * takakrypt_cache_cleanup_expired - Clean up expired cache entries
 */
void takakrypt_cache_cleanup_expired(void)
{
    struct takakrypt_cache_entry *entry;
    struct hlist_node *tmp;
    int i, expired_entries = 0;
    
    if (!takakrypt_global_state || !takakrypt_global_state->policy_cache) {
        return;
    }
    
    spin_lock(&takakrypt_global_state->cache_lock);
    
    for (i = 0; i < TAKAKRYPT_CACHE_SIZE; i++) {
        hlist_for_each_entry_safe(entry, tmp, &takakrypt_global_state->policy_cache[i], node) {
            if (takakrypt_cache_entry_expired(entry)) {
                hlist_del(&entry->node);
                expired_entries++;
                
                /* Decrement reference and free if no references */
                if (atomic_dec_and_test(&entry->refcount)) {
                    kfree(entry);
                }
            }
        }
    }
    
    spin_unlock(&takakrypt_global_state->cache_lock);
    
    if (expired_entries > 0) {
        takakrypt_debug("Cleaned up %d expired cache entries\n", expired_entries);
    }
}

/**
 * takakrypt_cache_get_stats - Get cache statistics
 * @total_entries: Output parameter for total entries
 * @expired_entries: Output parameter for expired entries
 */
void takakrypt_cache_get_stats(uint32_t *total_entries, uint32_t *expired_entries)
{
    struct takakrypt_cache_entry *entry;
    int i;
    uint32_t total = 0, expired = 0;
    
    if (!takakrypt_global_state || !takakrypt_global_state->policy_cache) {
        if (total_entries) *total_entries = 0;
        if (expired_entries) *expired_entries = 0;
        return;
    }
    
    spin_lock(&takakrypt_global_state->cache_lock);
    
    for (i = 0; i < TAKAKRYPT_CACHE_SIZE; i++) {
        hlist_for_each_entry(entry, &takakrypt_global_state->policy_cache[i], node) {
            total++;
            if (takakrypt_cache_entry_expired(entry)) {
                expired++;
            }
        }
    }
    
    spin_unlock(&takakrypt_global_state->cache_lock);
    
    if (total_entries) *total_entries = total;
    if (expired_entries) *expired_entries = expired;
}

/**
 * takakrypt_cache_put_entry - Release reference to cache entry
 * @entry: Cache entry to release
 */
void takakrypt_cache_put_entry(struct takakrypt_cache_entry *entry)
{
    if (!entry) {
        return;
    }
    
    if (atomic_dec_and_test(&entry->refcount)) {
        takakrypt_debug("Freeing cache entry for %s\n", entry->filepath);
        kfree(entry);
    }
}