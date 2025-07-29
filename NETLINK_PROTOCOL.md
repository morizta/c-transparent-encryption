# Takakrypt Netlink Communication Protocol

## Overview
Takakrypt uses Linux netlink sockets for bidirectional communication between the kernel module and userspace agent. This document details the complete protocol specification, message formats, and communication patterns.

## Protocol Specifications

### Netlink Family Configuration
- **Family Name**: "takakrypt" 
- **Family ID**: Dynamically assigned (typically 31)
- **Protocol Type**: NETLINK_GENERIC
- **Maximum Message Size**: 8192 bytes
- **Multicast Groups**: None (unicast only)

### Socket Configuration
- **Kernel Socket**: Created during module initialization
- **Userspace Socket**: Created by agent on startup
- **Address Family**: AF_NETLINK
- **Socket Type**: SOCK_RAW
- **Protocol**: NETLINK_GENERIC

## Message Structure

### Common Header Format
All netlink messages use a common header structure for consistency:

```c
struct takakrypt_msg_header {
    uint32_t magic;      // TAKAKRYPT_MSG_MAGIC (0x54414B41 = "TAKA")
    uint32_t version;    // Protocol version (currently 1)
    uint32_t operation;  // Operation type (see Operation Types)
    uint32_t sequence;   // Unique sequence number for request/response matching
    uint32_t payload_size; // Size of data following this header
    uint32_t status;     // Status code (0 = success, others = error codes)
    uint64_t timestamp;  // Message timestamp (nanoseconds since epoch)
} __packed;
```

**Header Size**: 32 bytes (fixed)
**Alignment**: Packed structure, no padding
**Byte Order**: Little-endian (host byte order)

### Operation Types
```c
enum takakrypt_operation {
    TAKAKRYPT_OP_HEALTH_CHECK    = 0,  // Agent connectivity test
    TAKAKRYPT_OP_POLICY_CHECK    = 1,  // File access policy evaluation
    TAKAKRYPT_OP_ENCRYPT         = 2,  // File encryption request
    TAKAKRYPT_OP_DECRYPT         = 3,  // File decryption request
    TAKAKRYPT_OP_KEY_REQUEST     = 4,  // Encryption key request
    TAKAKRYPT_OP_CONFIG_UPDATE   = 5,  // Guard point configuration
    TAKAKRYPT_OP_AUDIT_EVENT     = 6,  // Security audit logging
    TAKAKRYPT_OP_STATUS_REQUEST  = 7,  // System status query
};
```

### Status Codes
```c
enum takakrypt_status {
    TAKAKRYPT_SUCCESS           = 0,   // Operation successful
    TAKAKRYPT_ERROR_INVALID     = 1,   // Invalid request parameters
    TAKAKRYPT_ERROR_DENIED      = 2,   // Access denied by policy
    TAKAKRYPT_ERROR_NOT_FOUND   = 3,   // Resource not found (key, policy, etc.)
    TAKAKRYPT_ERROR_CRYPTO      = 4,   // Cryptographic operation failed
    TAKAKRYPT_ERROR_MEMORY      = 5,   // Memory allocation failed
    TAKAKRYPT_ERROR_TIMEOUT     = 6,   // Operation timed out
    TAKAKRYPT_ERROR_NETWORK     = 7,   // Network communication error
    TAKAKRYPT_ERROR_INTERNAL    = 8,   // Internal system error
};
```

## Message Types and Formats

### 1. Health Check Messages

**Purpose**: Verify agent connectivity and responsiveness
**Direction**: Kernel → Agent → Kernel

**Request Format**:
```c
struct takakrypt_health_request {
    struct takakrypt_msg_header header;
    // No additional payload
};
```

**Response Format**:
```c
struct takakrypt_health_response {
    struct takakrypt_msg_header header;
    uint32_t agent_version;      // Agent software version
    uint32_t uptime_seconds;     // Agent uptime in seconds
    uint32_t active_workers;     // Number of active worker threads
    uint32_t processed_requests; // Total processed requests
};
```

### 2. Policy Check Messages

**Purpose**: Evaluate security policy for file access
**Direction**: Kernel → Agent → Kernel

**Request Format**:
```c
struct takakrypt_policy_request {
    struct takakrypt_msg_header header;
    uint32_t pid;                // Process ID requesting access
    uint32_t uid;                // User ID of requesting process
    uint32_t gid;                // Group ID of requesting process
    uint32_t action;             // Requested action (read/write/delete)
    uint32_t path_len;           // Length of file path string
    uint32_t process_len;        // Length of process name string
    uint32_t cwd_len;            // Length of current working directory
    // Variable payload: file_path + process_name + cwd
};
```

**Response Format**:
```c
struct takakrypt_policy_response {
    struct takakrypt_msg_header header;
    uint32_t allow_access;       // 1 = allow, 0 = deny
    uint32_t encrypt_file;       // 1 = encrypt, 0 = plaintext
    uint32_t audit_action;       // 1 = log this action, 0 = no logging
    uint32_t key_id_len;         // Length of encryption key identifier
    uint32_t policy_len;         // Length of matched policy name
    uint32_t reason_len;         // Length of decision reason string
    // Variable payload: key_id + policy_name + reason
};
```

### 3. Encryption Messages

**Purpose**: Encrypt file data using specified algorithm and key
**Direction**: Kernel → Agent → Kernel

**Request Format**:
```c
struct takakrypt_encrypt_request {
    struct takakrypt_msg_header header;
    uint32_t algorithm;          // Encryption algorithm identifier
    uint32_t data_len;           // Length of plaintext data
    uint32_t key_id_len;         // Length of key identifier
    uint32_t metadata_len;       // Length of additional metadata
    // Variable payload: key_id + metadata + plaintext_data
};
```

**Response Format**:
```c
struct takakrypt_encrypt_response {
    struct takakrypt_msg_header header;
    uint32_t encrypted_len;      // Length of encrypted data (including TAKA header)
    uint32_t iv_len;             // Length of initialization vector
    uint32_t tag_len;            // Length of authentication tag
    // Variable payload: encrypted_data_with_taka_header
};
```

### 4. Decryption Messages

**Purpose**: Decrypt file data using specified key
**Direction**: Kernel → Agent → Kernel

**Request Format**:
```c
struct takakrypt_decrypt_request {
    struct takakrypt_msg_header header;
    uint32_t algorithm;          // Encryption algorithm used
    uint32_t encrypted_len;      // Length of encrypted data
    uint32_t key_id_len;         // Length of key identifier
    uint32_t iv_len;             // Length of initialization vector
    uint32_t tag_len;            // Length of authentication tag
    // Variable payload: key_id + iv + tag + encrypted_data
};
```

**Response Format**:
```c
struct takakrypt_decrypt_response {
    struct takakrypt_msg_header header;
    uint32_t plaintext_len;      // Length of decrypted plaintext
    uint32_t checksum;           // Data integrity checksum
    // Variable payload: plaintext_data
};
```

### 5. Configuration Update Messages

**Purpose**: Send guard point configuration to kernel
**Direction**: Agent → Kernel → Agent

**Request Format**:
```c
struct takakrypt_config_request {
    struct takakrypt_msg_header header;
    uint32_t guard_point_count;  // Number of guard points
    uint32_t total_data_len;     // Total length of all guard point data
    // Variable payload: serialized_guard_points
};
```

**Guard Point Serialization Format**:
```c
struct guard_point_entry {
    uint32_t enabled;            // 1 = enabled, 0 = disabled
    uint32_t name_len;           // Length of guard point name
    uint32_t path_len;           // Length of guard point path
    uint32_t policy_len;         // Length of policy name
    // Variable data: name + path + policy
};
```

**Response Format**:
```c
struct takakrypt_config_response {
    struct takakrypt_msg_header header;
    uint32_t configured_count;   // Number of guard points successfully configured
    uint32_t error_count;        // Number of configuration errors
    // No variable payload for configuration responses
};
```

## Communication Patterns

### 1. Request-Response Pattern
Most operations follow a synchronous request-response pattern:

```
Kernel                           Agent
  |                                |
  |-- Request (seq=123) --------->|
  |                                | (Process request)
  |<-------- Response (seq=123) --|
  |                                |
```

**Timing**: 5-second timeout for all requests
**Sequence Matching**: Responses must match request sequence numbers
**Error Handling**: Non-zero status codes indicate errors

### 2. Configuration Push Pattern
Agent-initiated configuration updates:

```
Agent                            Kernel
  |                                |
  |-- Config Update -------------->|
  |                                | (Apply configuration)
  |<-------- Acknowledgment ------|
  |                                |
```

**Frequency**: On startup and configuration changes
**Validation**: Kernel validates guard point formats
**Atomicity**: All guard points applied or none

### 3. Health Monitoring Pattern
Periodic connectivity verification:

```
Kernel                           Agent
  |                                |
  |-- Health Check --------------->|
  |<-------- Status Response -----|
  |                                |
  (Every 60 seconds)
```

**Interval**: 60-second health check interval
**Failure Handling**: Agent marked as disconnected after 3 failed checks
**Recovery**: Automatic reconnection on agent restart

## Protocol Implementation Details

### Kernel-Side Implementation

**File**: `kernel/netlink.c`

**Key Functions**:
- `takakrypt_netlink_init()`: Initialize netlink family and sockets
- `takakrypt_send_request()`: Send request message to agent
- `takakrypt_send_request_and_wait()`: Synchronous request-response
- `takakrypt_netlink_recv()`: Handle incoming messages from agent
- `takakrypt_netlink_cleanup()`: Cleanup netlink resources

**Socket Management**:
```c
static struct sock *takakrypt_netlink_sock = NULL;
static struct netlink_kernel_cfg netlink_cfg = {
    .input = takakrypt_netlink_recv,
    .flags = NL_CFG_F_NONROOT_RECV,
};
```

**Message Sending**:
```c
int takakrypt_send_request(struct takakrypt_msg_header *msg, size_t msg_size) {
    struct sk_buff *skb;
    struct nlmsghdr *nlh;
    int ret;
    
    // Allocate socket buffer
    skb = nlmsg_new(msg_size, GFP_KERNEL);
    if (!skb) return -ENOMEM;
    
    // Setup netlink header
    nlh = nlmsg_put(skb, 0, 0, 0, msg_size, 0);
    if (!nlh) {
        kfree_skb(skb);
        return -EMSGSIZE;
    }
    
    // Copy message data
    memcpy(nlmsg_data(nlh), msg, msg_size);
    
    // Send to agent
    ret = netlink_unicast(takakrypt_netlink_sock, skb, 
                         takakrypt_global_state->agent_pid, 0);
    return ret > 0 ? 0 : ret;
}
```

### Userspace Implementation

**File**: `pkg/netlink/client_linux.go`

**Key Functions**:
- `NewNetlinkClient()`: Create and initialize netlink client
- `Connect()`: Establish connection to kernel
- `SendMessage()`: Send message to kernel
- `ReceiveMessage()`: Receive message from kernel
- `SendConfigUpdate()`: Send guard point configuration

**Socket Creation**:
```go
func (c *LinuxNetlinkClient) Connect() error {
    // Create netlink socket
    sock, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW, syscall.NETLINK_GENERIC)
    if err != nil {
        return fmt.Errorf("failed to create netlink socket: %v", err)
    }
    
    // Bind to local address
    addr := &syscall.SockaddrNetlink{
        Family: syscall.AF_NETLINK,
        Pid:    uint32(os.Getpid()),
    }
    
    err = syscall.Bind(sock, addr)
    if err != nil {
        syscall.Close(sock)
        return fmt.Errorf("failed to bind netlink socket: %v", err)
    }
    
    c.socket = sock
    c.pid = uint32(os.Getpid())
    return nil
}
```

**Message Serialization**:
```go
func SerializePolicyCheckResponse(response *PolicyCheckResponse) ([]byte, error) {
    buffer := make([]byte, 32) // Header size
    
    // Serialize header
    binary.LittleEndian.PutUint32(buffer[0:4], TAKAKRYPT_MSG_MAGIC)
    binary.LittleEndian.PutUint32(buffer[4:8], 1) // Version
    binary.LittleEndian.PutUint32(buffer[8:12], uint32(response.Header.Operation))
    binary.LittleEndian.PutUint32(buffer[12:16], response.Header.Sequence)
    
    // Calculate payload size
    payloadSize := 24 + len(response.KeyID) + len(response.PolicyName) + len(response.Reason)
    binary.LittleEndian.PutUint32(buffer[16:20], uint32(payloadSize))
    
    // Serialize response data
    responseData := make([]byte, payloadSize)
    binary.LittleEndian.PutUint32(responseData[0:4], response.AllowAccess)
    binary.LittleEndian.PutUint32(responseData[4:8], response.EncryptFile)
    binary.LittleEndian.PutUint32(responseData[8:12], response.AuditAction)
    // ... continue serialization
    
    return append(buffer, responseData...), nil
}
```

## Error Handling and Recovery

### Connection Failures
- **Agent Startup**: Kernel waits for agent connection before processing requests
- **Agent Crash**: Kernel detects disconnection, denies file operations
- **Network Errors**: Retry mechanism with exponential backoff
- **Message Corruption**: Validate magic numbers and checksums

### Protocol Violations
- **Invalid Messages**: Log error and drop malformed messages
- **Sequence Mismatches**: Track pending requests, timeout orphaned requests
- **Version Incompatibility**: Negotiate protocol version on connection
- **Buffer Overflows**: Enforce maximum message sizes

### Recovery Mechanisms
- **Automatic Reconnection**: Agent attempts reconnection every 30 seconds
- **State Synchronization**: Resend configuration after reconnection
- **Graceful Degradation**: Deny operations when agent unavailable
- **Logging**: Comprehensive logging of all protocol events

## Security Considerations

### Message Authentication
- **Magic Numbers**: Prevent accidental message processing
- **Sequence Numbers**: Prevent replay attacks
- **Checksums**: Detect message corruption
- **Size Validation**: Prevent buffer overflow attacks

### Access Control
- **Process Validation**: Verify agent process identity
- **Socket Permissions**: Restrict netlink socket access
- **Capability Checks**: Ensure proper kernel privileges
- **Rate Limiting**: Prevent denial-of-service attacks

### Data Protection
- **Sensitive Data**: Encrypt key material in messages
- **Memory Clearing**: Zero sensitive buffers after use
- **Kernel Memory**: Protect against userspace access
- **Audit Trail**: Log all security-relevant protocol events

## Performance Optimization

### Message Batching
- **Multiple Operations**: Batch multiple requests when possible
- **Configuration Updates**: Send all guard points in single message
- **Bulk Encryption**: Process multiple files in single request

### Buffer Management
- **Pre-allocation**: Pre-allocate common message buffers
- **Memory Pooling**: Reuse buffers for common operations
- **Zero-copy**: Minimize data copying between kernel/userspace
- **Streaming**: Handle large files in chunks

### Protocol Efficiency
- **Compact Encoding**: Use binary encoding vs. text protocols
- **Optional Fields**: Skip unused fields in messages
- **Compression**: Compress large payloads when beneficial
- **Caching**: Cache frequent responses (policy decisions, keys)

This protocol documentation provides complete technical specifications for implementing, debugging, and optimizing Takakrypt's netlink communication system.