/* Enhanced logging added for debugging */

#include "takakrypt.h"

/* Forward declarations */
static void takakrypt_handle_status_request(struct takakrypt_msg_header *msg_header, uint32_t pid);
static void takakrypt_handle_config_update(struct takakrypt_msg_header *msg_header, void *payload);
static void takakrypt_handle_health_check(struct takakrypt_msg_header *msg_header, uint32_t pid);

/* Netlink socket for kernel-userspace communication */
static struct sock *takakrypt_nl_sock = NULL;
static DEFINE_MUTEX(netlink_mutex);

/* Pending requests tracking */
struct pending_request {
    struct list_head list;
    uint32_t sequence;
    wait_queue_head_t wait_queue;
    void *response_data;
    size_t response_size;
    int response_status;
    unsigned long timestamp;
    atomic_t completed;
};

static LIST_HEAD(pending_requests);
static DEFINE_SPINLOCK(pending_requests_lock);

/* Request timeout handler */
static void takakrypt_request_timeout_handler(struct work_struct *work);
static DECLARE_DELAYED_WORK(timeout_work, takakrypt_request_timeout_handler);

/**
 * takakrypt_cleanup_expired_requests - Clean up expired pending requests
 */
static void takakrypt_cleanup_expired_requests(void)
{
    struct pending_request *req, *tmp;
    unsigned long now = jiffies;
    unsigned long timeout = TAKAKRYPT_REQUEST_TIMEOUT;
    
    spin_lock(&pending_requests_lock);
    list_for_each_entry_safe(req, tmp, &pending_requests, list) {
        if (time_after(now, req->timestamp + timeout)) {
            takakrypt_warn("Request %u timed out\n", req->sequence);
            
            /* Mark as completed with timeout error */
            req->response_status = -ETIMEDOUT;
            atomic_set(&req->completed, 1);
            wake_up(&req->wait_queue);
            
            list_del(&req->list);
            kfree(req);
        }
    }
    spin_unlock(&pending_requests_lock);
}

/**
 * takakrypt_request_timeout_handler - Periodic timeout handler
 * @work: Work structure
 */
static void takakrypt_request_timeout_handler(struct work_struct *work)
{
    takakrypt_cleanup_expired_requests();
    
    /* Reschedule if module is active */
    if (atomic_read(&takakrypt_global_state->module_active)) {
        schedule_delayed_work(&timeout_work, TAKAKRYPT_REQUEST_TIMEOUT / 2);
    }
}

/**
 * takakrypt_create_pending_request - Create a new pending request
 * @sequence: Request sequence number
 * 
 * Returns: Pointer to pending request structure, or NULL on failure
 */
static struct pending_request *takakrypt_create_pending_request(uint32_t sequence)
{
    struct pending_request *req;
    
    req = kzalloc(sizeof(struct pending_request), GFP_KERNEL);
    if (!req) {
        takakrypt_error("Failed to allocate pending request\n");
        return NULL;
    }
    
    req->sequence = sequence;
    init_waitqueue_head(&req->wait_queue);
    req->timestamp = jiffies;
    atomic_set(&req->completed, 0);
    
    spin_lock(&pending_requests_lock);
    list_add_tail(&req->list, &pending_requests);
    spin_unlock(&pending_requests_lock);
    
    takakrypt_debug("Created pending request %u\n", sequence);
    return req;
}

/**
 * takakrypt_find_pending_request - Find pending request by sequence number
 * @sequence: Request sequence number
 * 
 * Returns: Pointer to pending request, or NULL if not found
 */
static struct pending_request *takakrypt_find_pending_request(uint32_t sequence)
{
    struct pending_request *req;
    
    spin_lock(&pending_requests_lock);
    list_for_each_entry(req, &pending_requests, list) {
        if (req->sequence == sequence) {
            spin_unlock(&pending_requests_lock);
            return req;
        }
    }
    spin_unlock(&pending_requests_lock);
    
    return NULL;
}

/**
 * takakrypt_complete_pending_request - Complete a pending request
 * @sequence: Request sequence number
 * @data: Response data
 * @size: Response data size
 * @status: Response status
 */
static void takakrypt_complete_pending_request(uint32_t sequence, void *data, size_t size, int status)
{
    struct pending_request *req;
    
    req = takakrypt_find_pending_request(sequence);
    if (!req) {
        takakrypt_warn("Received response for unknown request %u\n", sequence);
        return;
    }
    
    /* Store response data */
    if (data && size > 0) {
        req->response_data = kmalloc(size, GFP_KERNEL);
        if (req->response_data) {
            memcpy(req->response_data, data, size);
            req->response_size = size;
        } else {
            takakrypt_error("Failed to allocate response data\n");
            status = -ENOMEM;
        }
    }
    
    req->response_status = status;
    atomic_set(&req->completed, 1);
    wake_up(&req->wait_queue);
    
    takakrypt_debug("Completed pending request %u with status %d\n", sequence, status);
}

/**
 * takakrypt_wait_for_response - Wait for response to a request
 * @req: Pending request structure
 * @timeout_ms: Timeout in milliseconds
 * 
 * Returns: 0 on success, negative error code on failure
 */
static int takakrypt_wait_for_response(struct pending_request *req, int timeout_ms)
{
    int ret;
    long timeout_jiffies = msecs_to_jiffies(timeout_ms);
    
    ret = wait_event_timeout(req->wait_queue, 
                           atomic_read(&req->completed), 
                           timeout_jiffies);
    
    if (ret == 0) {
        takakrypt_warn("Request %u timed out after %d ms\n", req->sequence, timeout_ms);
        return -ETIMEDOUT;
    }
    
    return req->response_status;
}

/**
 * takakrypt_cleanup_pending_request - Clean up pending request
 * @req: Pending request to clean up
 */
static void takakrypt_cleanup_pending_request(struct pending_request *req)
{
    if (!req) {
        return;
    }
    
    spin_lock(&pending_requests_lock);
    list_del(&req->list);
    spin_unlock(&pending_requests_lock);
    
    if (req->response_data) {
        kfree(req->response_data);
    }
    
    kfree(req);
}

/**
 * takakrypt_netlink_recv - Handle incoming netlink messages
 * @skb: Socket buffer containing the message
 */
void takakrypt_netlink_recv(struct sk_buff *skb)
{
    struct nlmsghdr *nlh;
    struct takakrypt_msg_header *msg_header;
    void *payload;
    uint32_t pid;
    
    if (!skb) {
        takakrypt_error("Received NULL socket buffer\n");
        return;
    }
    
    nlh = nlmsg_hdr(skb);
    if (!nlh) {
        takakrypt_error("Invalid netlink message header\n");
        return;
    }
    
    pid = NETLINK_CB(skb).portid;
    takakrypt_debug("Received netlink message from PID %u\n", pid);
    
    /* Validate message size */
    if (nlmsg_len(nlh) < sizeof(struct takakrypt_msg_header)) {
        takakrypt_error("Message too small: %d bytes\n", nlmsg_len(nlh));
        return;
    }
    
    msg_header = (struct takakrypt_msg_header *)nlmsg_data(nlh);
    
    /* Validate magic number and version */
    if (msg_header->magic != TAKAKRYPT_MSG_MAGIC) {
        takakrypt_error("Invalid message magic: 0x%08x\n", msg_header->magic);
        return;
    }
    
    if (msg_header->version != TAKAKRYPT_PROTOCOL_VERSION) {
        takakrypt_error("Unsupported protocol version: %u\n", msg_header->version);
        return;
    }
    
    /* Update agent PID if this is the first message */
    if (takakrypt_global_state->agent_pid == 0) {
        takakrypt_global_state->agent_pid = pid;
        takakrypt_global_state->stats.agent_connected = 1;
        takakrypt_info("User-space agent connected (PID: %u)\n", pid);
    }
    
    /* Get payload data */
    payload = NULL;
    if (msg_header->payload_size > 0) {
        if (nlmsg_len(nlh) < sizeof(struct takakrypt_msg_header) + msg_header->payload_size) {
            takakrypt_error("Payload size mismatch\n");
            return;
        }
        payload = (char *)msg_header + sizeof(struct takakrypt_msg_header);
    }
    
    takakrypt_debug("Processing message: op=%u, seq=%u, payload_size=%u\n",
                   msg_header->operation, msg_header->sequence, msg_header->payload_size);
    
    /* Process the message based on operation type */
    switch (msg_header->operation) {
        case TAKAKRYPT_OP_CHECK_POLICY:
            /* This is a response to a policy check request */
            takakrypt_complete_pending_request(msg_header->sequence, payload, 
                                             msg_header->payload_size, 0);
            break;
            
        case TAKAKRYPT_OP_ENCRYPT:
        case TAKAKRYPT_OP_DECRYPT:
            /* Response to encryption/decryption request */
            takakrypt_complete_pending_request(msg_header->sequence, payload,
                                             msg_header->payload_size, 0);
            break;
            
        case TAKAKRYPT_OP_GET_STATUS:
            /* Status request from user-space */
            takakrypt_handle_status_request(msg_header, pid);
            break;
            
        case TAKAKRYPT_OP_SET_CONFIG:
            /* Configuration update from user-space */
            takakrypt_handle_config_update(msg_header, payload);
            break;
            
        case TAKAKRYPT_OP_HEALTH_CHECK:
            /* Health check from user-space */
            takakrypt_handle_health_check(msg_header, pid);
            break;
            
        default:
            takakrypt_warn("Unknown operation: %u\n", msg_header->operation);
            break;
    }
}

/**
 * takakrypt_send_request - Send request to user-space agent
 * @msg: Message to send
 * @msg_size: Size of message
 * 
 * Returns: 0 on success, negative error code on failure
 */
int takakrypt_send_request(struct takakrypt_msg_header *msg, size_t msg_size)
{
    struct sk_buff *skb;
    struct nlmsghdr *nlh;
    int ret;
    
    if (!takakrypt_nl_sock) {
        takakrypt_error("Netlink socket not initialized\n");
        return -ENOTCONN;
    }
    
    if (takakrypt_global_state->agent_pid == 0) {
        takakrypt_debug("No agent connected\n");
        return -ENOTCONN;
    }
    
    /* Allocate socket buffer */
    skb = nlmsg_new(msg_size, GFP_KERNEL);
    if (!skb) {
        takakrypt_error("Failed to allocate socket buffer\n");
        return -ENOMEM;
    }
    
    /* Add netlink header */
    nlh = nlmsg_put(skb, 0, 0, NLMSG_DONE, msg_size, 0);
    if (!nlh) {
        takakrypt_error("Failed to add netlink header\n");
        kfree_skb(skb);
        return -EMSGSIZE;
    }
    
    /* Copy message data */
    memcpy(nlmsg_data(nlh), msg, msg_size);
    
    /* Send message */
    mutex_lock(&netlink_mutex);
    ret = nlmsg_unicast(takakrypt_nl_sock, skb, takakrypt_global_state->agent_pid);
    mutex_unlock(&netlink_mutex);
    
    if (ret < 0) {
        takakrypt_error("Failed to send netlink message: %d\n", ret);
        return ret;
    }
    
    takakrypt_debug("Sent message to agent: op=%u, seq=%u, size=%zu\n",
                   msg->operation, msg->sequence, msg_size);
    
    return 0;
}

/**
 * takakrypt_send_policy_request - Send policy check request
 * @context: Context information
 * @response: Buffer to store response
 * @response_size: Size of response buffer
 * 
 * Returns: 0 on success, negative error code on failure
 */
int takakrypt_send_policy_request(struct takakrypt_context *context,
                                 struct takakrypt_policy_response *response,
                                 size_t response_size)
{
    struct takakrypt_policy_request request;
    struct pending_request *pending_req;
    uint32_t sequence;
    int ret;
    
    if (!context || !response) {
        return -EINVAL;
    }
    
    /* Generate sequence number */
    sequence = atomic_inc_return(&takakrypt_global_state->sequence_counter);
    
    /* Prepare request */
    memset(&request, 0, sizeof(request));
    request.header.magic = TAKAKRYPT_MSG_MAGIC;
    request.header.version = TAKAKRYPT_PROTOCOL_VERSION;
    request.header.operation = TAKAKRYPT_OP_CHECK_POLICY;
    request.header.sequence = sequence;
    request.header.payload_size = sizeof(struct takakrypt_context);
    request.header.timestamp = ktime_get_real_seconds();
    request.context = *context;
    request.request_id = sequence;
    
    /* Create pending request */
    pending_req = takakrypt_create_pending_request(sequence);
    if (!pending_req) {
        return -ENOMEM;
    }
    
    /* Send request */
    ret = takakrypt_send_request(&request.header, sizeof(request));
    if (ret) {
        takakrypt_cleanup_pending_request(pending_req);
        return ret;
    }
    
    /* Wait for response */
    ret = takakrypt_wait_for_response(pending_req, 5000); /* 5 second timeout */
    if (ret == 0 && pending_req->response_data && pending_req->response_size >= sizeof(*response)) {
        memcpy(response, pending_req->response_data, 
               min(response_size, pending_req->response_size));
    }
    
    /* Cleanup */
    takakrypt_cleanup_pending_request(pending_req);
    
    return ret;
}

/**
 * takakrypt_handle_status_request - Handle status request from user-space
 * @msg_header: Message header
 * @pid: Process ID of requester
 */
static void takakrypt_handle_status_request(struct takakrypt_msg_header *msg_header, uint32_t pid)
{
    struct {
        struct takakrypt_msg_header header;
        struct takakrypt_status_info status;
    } response;
    
    takakrypt_debug("Handling status request from PID %u\n", pid);
    
    /* Prepare response */
    memset(&response, 0, sizeof(response));
    response.header.magic = TAKAKRYPT_MSG_MAGIC;
    response.header.version = TAKAKRYPT_PROTOCOL_VERSION;
    response.header.operation = TAKAKRYPT_OP_GET_STATUS;
    response.header.sequence = msg_header->sequence;
    response.header.payload_size = sizeof(struct takakrypt_status_info);
    response.header.timestamp = ktime_get_real_seconds();
    
    /* Fill status information */
    spin_lock(&takakrypt_global_state->stats_lock);
    response.status = takakrypt_global_state->stats;
    response.status.uptime_seconds = (jiffies - takakrypt_global_state->start_time) / HZ;
    spin_unlock(&takakrypt_global_state->stats_lock);
    
    /* Send response */
    takakrypt_send_request(&response.header, sizeof(response));
}

/**
 * takakrypt_handle_config_update - Handle guard point configuration update
 * @msg_header: Message header
 * @payload: Guard point configuration data
 */
static void takakrypt_handle_config_update(struct takakrypt_msg_header *msg_header, void *payload)
{
    uint32_t *count_ptr;
    uint8_t *data;
    uint32_t count, i;
    uint32_t offset = 0;
    
    takakrypt_info("Handling guard point configuration update\n");
    
    if (!payload || msg_header->payload_size < 4) {
        takakrypt_error("Invalid guard point configuration payload\n");
        return;
    }
    
    data = (uint8_t *)payload;
    
    /* Parse guard point count (first 4 bytes) */
    count_ptr = (uint32_t *)data;
    count = *count_ptr;
    offset += 4;
    
    takakrypt_info("Received %u guard points from agent\n", count);
    
    if (count > TAKAKRYPT_MAX_GUARD_POINTS) {
        takakrypt_error("Too many guard points: %u > %u\n", count, TAKAKRYPT_MAX_GUARD_POINTS);
        return;
    }
    
    /* Update guard points configuration */
    mutex_lock(&takakrypt_global_state->guard_points_lock);
    takakrypt_global_state->guard_points.count = count;
    
    /* Parse each guard point */
    for (i = 0; i < count && offset < msg_header->payload_size; i++) {
        uint32_t name_len, path_len;
        
        /* Parse name length and name */
        if (offset + 4 > msg_header->payload_size) break;
        name_len = *(uint32_t *)(data + offset);
        offset += 4;
        
        if (offset + name_len > msg_header->payload_size || name_len >= TAKAKRYPT_MAX_GP_NAME_LEN) break;
        memcpy(takakrypt_global_state->guard_points.points[i].name, data + offset, name_len);
        takakrypt_global_state->guard_points.points[i].name[name_len] = '\0';
        offset += name_len;
        
        /* Parse path length and path */
        if (offset + 4 > msg_header->payload_size) break;
        path_len = *(uint32_t *)(data + offset);
        offset += 4;
        
        if (offset + path_len > msg_header->payload_size || path_len >= TAKAKRYPT_MAX_GP_PATH_LEN) break;
        memcpy(takakrypt_global_state->guard_points.points[i].path, data + offset, path_len);
        takakrypt_global_state->guard_points.points[i].path[path_len] = '\0';
        offset += path_len;
        
        /* Parse enabled flag */
        if (offset + 1 > msg_header->payload_size) break;
        takakrypt_global_state->guard_points.points[i].enabled = data[offset];
        offset += 1;
        
        takakrypt_info("Guard point %u: name='%s', path='%s', enabled=%u\n", 
                      i, takakrypt_global_state->guard_points.points[i].name,
                      takakrypt_global_state->guard_points.points[i].path,
                      takakrypt_global_state->guard_points.points[i].enabled);
    }
    
    mutex_unlock(&takakrypt_global_state->guard_points_lock);
    
    takakrypt_info("Guard point configuration updated successfully (%u points)\n", count);
}

/**
 * takakrypt_handle_health_check - Handle health check request
 * @msg_header: Message header
 * @pid: Process ID of requester
 */
static void takakrypt_handle_health_check(struct takakrypt_msg_header *msg_header, uint32_t pid)
{
    struct takakrypt_msg_header response;
    
    takakrypt_debug("Handling health check from PID %u\n", pid);
    
    /* Prepare response */
    memset(&response, 0, sizeof(response));
    response.magic = TAKAKRYPT_MSG_MAGIC;
    response.version = TAKAKRYPT_PROTOCOL_VERSION;
    response.operation = TAKAKRYPT_OP_HEALTH_CHECK;
    response.sequence = msg_header->sequence;
    response.payload_size = 0;
    response.timestamp = ktime_get_real_seconds();
    
    /* Send response */
    takakrypt_send_request(&response, sizeof(response));
}

/**
 * takakrypt_netlink_init - Initialize netlink communication
 * 
 * Returns: 0 on success, negative error code on failure
 */
int takakrypt_netlink_init(void)
{
    struct netlink_kernel_cfg cfg = {
        .input = takakrypt_netlink_recv,
    };
    
    takakrypt_info("Initializing netlink communication\n");
    
    /* Create netlink socket */
    takakrypt_nl_sock = netlink_kernel_create(&init_net, TAKAKRYPT_NETLINK_FAMILY, &cfg);
    if (!takakrypt_nl_sock) {
        takakrypt_error("Failed to create netlink socket\n");
        return -ENOMEM;
    }
    
    takakrypt_global_state->netlink_sock = takakrypt_nl_sock;
    
    /* Start timeout handler */
    schedule_delayed_work(&timeout_work, TAKAKRYPT_REQUEST_TIMEOUT / 2);
    
    takakrypt_info("Netlink communication initialized (family: %d)\n", TAKAKRYPT_NETLINK_FAMILY);
    
    return 0;
}

/**
 * takakrypt_netlink_cleanup - Cleanup netlink communication
 */
void takakrypt_netlink_cleanup(void)
{
    takakrypt_info("Cleaning up netlink communication\n");
    
    /* Cancel timeout handler */
    cancel_delayed_work_sync(&timeout_work);
    
    /* Clean up pending requests */
    takakrypt_cleanup_expired_requests();
    
    /* Close netlink socket */
    if (takakrypt_nl_sock) {
        netlink_kernel_release(takakrypt_nl_sock);
        takakrypt_nl_sock = NULL;
        takakrypt_global_state->netlink_sock = NULL;
    }
    
    /* Reset agent connection */
    takakrypt_global_state->agent_pid = 0;
    takakrypt_global_state->stats.agent_connected = 0;
    
    takakrypt_info("Netlink communication cleaned up\n");
}

/**
 * takakrypt_send_request_and_wait - Send request to userspace and wait for response
 * @msg: Message header to send
 * @msg_size: Size of the message
 * @response: Buffer for response data
 * @response_size: Size of response buffer
 * 
 * Returns 0 on success, negative error code on failure
 */
int takakrypt_send_request_and_wait(struct takakrypt_msg_header *msg, 
                                    size_t msg_size, void *response, 
                                    size_t response_size)
{
    struct pending_request *pending_req;
    int ret;
    
    takakrypt_info("NETLINK_SEND: Starting request sequence=%u, operation=%u, size=%zu\n", 
                   msg->sequence, msg->operation, msg_size);
    
    if (!msg || !response) {
        takakrypt_error("NETLINK_SEND: Invalid parameters\n");
        return -EINVAL;
    }
    
    /* Check if agent is connected */
    if (takakrypt_global_state->agent_pid == 0) {
        takakrypt_error("NETLINK_SEND: No agent connected for request\n");
        return -ENOTCONN;
    }
    
    takakrypt_info("NETLINK_SEND: Agent is connected (PID=%u)\n", takakrypt_global_state->agent_pid);
    
    /* Create pending request */
    pending_req = takakrypt_create_pending_request(msg->sequence);
    if (!pending_req) {
        return -ENOMEM;
    }
    
    /* Send request */
    takakrypt_info("NETLINK_SEND: Sending request to agent\n");
    ret = takakrypt_send_request(msg, msg_size);
    if (ret) {
        takakrypt_error("NETLINK_SEND: Failed to send request: %d\n", ret);
        takakrypt_cleanup_pending_request(pending_req);
        return ret;
    }
    
    takakrypt_info("NETLINK_SEND: Request sent, waiting for response (5 second timeout)\n");
    
    /* Wait for response */
    ret = takakrypt_wait_for_response(pending_req, 5000); /* 5 second timeout */
    if (ret == 0 && pending_req->response_data && pending_req->response_size > 0) {
        size_t copy_size = min(response_size, pending_req->response_size);
        takakrypt_info("NETLINK_SEND: Received response: %zu bytes\n", pending_req->response_size);
        memcpy(response, pending_req->response_data, copy_size);
    } else {
        takakrypt_error("NETLINK_SEND: Failed to get response: ret=%d, data=%p, size=%zu\n", 
                       ret, pending_req->response_data, pending_req->response_size);
    }
    
    /* Cleanup */
    takakrypt_cleanup_pending_request(pending_req);
    
    return ret;
}
EXPORT_SYMBOL(takakrypt_send_request_and_wait);