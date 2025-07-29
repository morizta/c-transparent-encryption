# Takakrypt Transparent Encryption Flow Documentation

## Overview
This document details the complete encryption and decryption flow in Takakrypt, from VFS interception to final file storage and retrieval.

## Write Path (File Encryption Flow)

### Phase 1: VFS Interception
```
User Application writes data
         ↓
    VFS Layer (vfs_write_iter)
         ↓
  Takakrypt kprobe hook intercepts
         ↓
    takakrypt_write_iter()
```

**Code Location**: `kernel/vfs_hooks.c:takakrypt_write_iter()`

**Process**:
1. **Hook Activation**: Kprobe triggers when any process calls `vfs_write_iter()`
2. **Context Capture**: Extract file path, process info, user context
3. **Guard Point Check**: Call `takakrypt_should_intercept_file(file_path)`
4. **Decision Point**: If file matches guard point → proceed to policy check

### Phase 2: Policy Evaluation Request
```
Kernel determines file needs policy check
         ↓
    Create policy request structure
         ↓
    Send netlink message to userspace agent
         ↓
    Wait for policy decision response
```

**Code Location**: `kernel/vfs_hooks.c:takakrypt_check_policy()`

**Message Structure**:
```c
struct takakrypt_policy_request {
    struct takakrypt_msg_header header;  // 32 bytes
    uint32_t pid;                        // Process ID
    uint32_t uid;                        // User ID  
    uint32_t gid;                        // Group ID
    uint32_t path_len;                   // File path length
    uint32_t process_len;                // Process name length
    // Variable data: file_path + process_name
};
```

**Netlink Protocol**:
- **Family**: TAKAKRYPT_NETLINK_FAMILY (31)
- **Operation**: TAKAKRYPT_OP_POLICY_CHECK (1)
- **Sequence**: Unique request identifier
- **Timeout**: 5 seconds for response

### Phase 3: Userspace Policy Processing
```
Agent receives policy request via netlink
         ↓
    Parse request (file path, process, user)
         ↓
    Evaluate security rules in order
         ↓
    Determine: permit/deny/encrypt + key_id
         ↓
    Send policy response back to kernel
```

**Code Location**: `pkg/agent/request_handler.go:handlePolicyCheck()`

**Policy Evaluation Steps**:
1. **Resource Set Matching**: Check if file path matches any guard point patterns
2. **Process Set Matching**: Check if current process is in authorized process sets
3. **User Set Matching**: Check if current user is in authorized user sets  
4. **Rule Evaluation**: Apply first matching security rule
5. **Effect Determination**: Combine effects (permit + applykey + audit)

**Response Structure**:
```go
type PolicyCheckResponseData struct {
    AllowAccess  uint32  // 1 = allow, 0 = deny
    EncryptFile  uint32  // 1 = encrypt, 0 = plaintext
    KeyIDLen     uint32  // Length of key identifier
    ReasonLen    uint32  // Length of reason string
    PolicyLen    uint32  // Length of policy name
    // Variable data: key_id + reason + policy_name
}
```

### Phase 4: Encryption Decision Processing
```
Kernel receives policy response
         ↓
    Parse response (allow + encrypt flags)
         ↓
    If encrypt=true → proceed to encryption
         ↓
    If encrypt=false → allow normal write
```

**Code Location**: `kernel/vfs_hooks.c` (policy response handling)

**Decision Matrix**:
- `allow=0, encrypt=0`: **DENY ACCESS** (return -EACCES)
- `allow=1, encrypt=0`: **ALLOW PLAINTEXT** (normal write)
- `allow=1, encrypt=1`: **ENCRYPT FILE** (proceed to Phase 5)

### Phase 5: File Encryption Request
```
Kernel decides to encrypt file
         ↓
    Extract original data from write operation
         ↓
    Create encryption request with data + key_id
         ↓
    Send netlink message to agent for encryption
         ↓
    Wait for encrypted data response
```

**Code Location**: `kernel/vfs_hooks.c:takakrypt_encrypt_data()`

**Encryption Request Structure**:
```c
struct takakrypt_encrypt_request {
    struct takakrypt_msg_header header;  // 32 bytes
    uint32_t data_len;                   // Original data length
    uint32_t key_id_len;                 // Key identifier length
    // Variable data: key_id + original_data
};
```

### Phase 6: Userspace Encryption Processing  
```
Agent receives encryption request
         ↓
    Extract key_id and original data
         ↓
    Generate/retrieve encryption key
         ↓
    Create TAKA file format structure
         ↓
    Encrypt data using AES-256-GCM
         ↓
    Send encrypted data back to kernel
```

**Code Location**: `internal/crypto/file_encryption.go:EncryptData()`

**TAKA File Format Creation**:
1. **Magic Header**: "TAKA" signature (4 bytes)
2. **Metadata**: Version, algorithm, sizes (60 bytes)
3. **Key Identifier**: Variable length string
4. **IV Generation**: Random initialization vector
5. **Encryption**: AES-256-GCM with authentication tag
6. **Assembly**: Header + metadata + IV + tag + encrypted_data

**Encryption Response Structure**:
```go
type CryptoResponseData struct {
    Status        uint32  // 0 = success, error code otherwise
    EncryptedLen  uint32  // Length of encrypted data
    // Variable data: encrypted_data_with_taka_header
}
```

### Phase 7: VFS Data Replacement
```
Kernel receives encrypted data
         ↓
    Validate response and extract encrypted data
         ↓
    Replace original write data with encrypted data
         ↓
    Continue with normal VFS write operation
         ↓
    Encrypted data written to underlying filesystem
```

**Code Location**: `kernel/vfs_hooks.c` (iov_iter manipulation)

**Data Replacement Process**:
1. **Response Validation**: Check magic, status, data length
2. **Memory Management**: Allocate kernel buffer for encrypted data
3. **Data Copy**: Copy encrypted data from netlink response
4. **iov_iter Replacement**: Replace original `iov_iter` with encrypted version
5. **VFS Continuation**: Allow normal write path to continue with encrypted data

---

## Read Path (File Decryption Flow)

### Phase 1: VFS Interception
```
User Application reads file
         ↓
    VFS Layer (vfs_read_iter)
         ↓
  Takakrypt kprobe hook intercepts
         ↓
    takakrypt_read_iter()
```

**Code Location**: `kernel/vfs_hooks.c:takakrypt_read_iter()`

**Process**:
1. **Hook Activation**: Kprobe triggers on `vfs_read_iter()` calls
2. **File Analysis**: Read first 64 bytes to check for TAKA header
3. **Magic Detection**: Look for "TAKA" signature at file beginning
4. **Decision Point**: If TAKA found → decrypt, else → normal read

### Phase 2: TAKA Header Parsing
```
File contains TAKA magic signature
         ↓
    Read and parse TAKA header (64 bytes)
         ↓
    Extract: algorithm, key_id, IV, tag, data_size
         ↓
    Validate header integrity and version
```

**Code Location**: `kernel/vfs_hooks.c` (TAKA header parsing)

**Header Validation**:
- **Magic Check**: Verify "TAKA" signature
- **Version Check**: Ensure compatible format version
- **Algorithm Check**: Verify supported encryption algorithm
- **Size Validation**: Ensure lengths are reasonable
- **Checksum**: Verify header integrity

### Phase 3: Policy Check for Decryption
```
Valid TAKA file detected
         ↓
    Create policy request for read access
         ↓
    Send netlink message to agent
         ↓
    Wait for authorization decision
```

**Similar to Write Path Phase 2**, but with:
- **Operation**: TAKAKRYPT_OP_POLICY_CHECK (1)
- **Action**: "read" instead of "write"
- **Purpose**: Verify user/process authorized to decrypt

### Phase 4: Decryption Request
```
Policy allows decryption access
         ↓
    Read encrypted data from file
         ↓
    Create decryption request with encrypted_data + key_id
         ↓
    Send netlink message to agent
         ↓
    Wait for decrypted plaintext response
```

**Code Location**: `kernel/vfs_hooks.c:takakrypt_decrypt_data()`

**Decryption Request Structure**:
```c
struct takakrypt_decrypt_request {
    struct takakrypt_msg_header header;  // 32 bytes
    uint32_t encrypted_len;              // Encrypted data length
    uint32_t key_id_len;                 // Key identifier length
    uint32_t iv_len;                     // IV length
    uint32_t tag_len;                    // Auth tag length
    // Variable data: key_id + iv + tag + encrypted_data
};
```

### Phase 5: Userspace Decryption Processing
```
Agent receives decryption request
         ↓
    Extract key_id, IV, tag, encrypted_data
         ↓
    Retrieve decryption key using key_id
         ↓
    Perform AES-256-GCM decryption
         ↓
    Verify authentication tag
         ↓
    Send plaintext data back to kernel
```

**Code Location**: `internal/crypto/file_encryption.go:DecryptData()`

**Decryption Process**:
1. **Key Retrieval**: Get encryption key using key_id
2. **Algorithm Setup**: Initialize AES-256-GCM cipher
3. **IV Application**: Set initialization vector
4. **Decryption**: Decrypt data in streaming fashion
5. **Authentication**: Verify GCM authentication tag
6. **Validation**: Ensure decrypted size matches expected

### Phase 6: VFS Data Replacement
```
Kernel receives decrypted data
         ↓
    Validate plaintext response
         ↓
    Replace file read data with decrypted plaintext
         ↓
    Return plaintext to user application
         ↓
    User sees decrypted content transparently
```

**Data Replacement Process**:
1. **Response Validation**: Check status and data integrity
2. **Size Verification**: Ensure plaintext matches expected size
3. **Memory Management**: Handle kernel/userspace data transfer
4. **User Buffer**: Copy plaintext to user application buffer
5. **Transparent Return**: Application receives plaintext as if file was never encrypted

---

## Error Handling and Edge Cases

### Network Communication Failures
- **Timeout Handling**: 5-second timeout for all netlink operations
- **Agent Disconnection**: Kernel detects agent failure, denies operations
- **Message Corruption**: Validate message integrity, return errors
- **Buffer Overflow**: Enforce maximum message sizes

### Encryption/Decryption Failures
- **Key Not Found**: Return access denied error
- **Algorithm Unsupported**: Fall back to denial or alternative
- **Authentication Failure**: Detect tampering, deny access
- **Memory Allocation**: Handle OOM conditions gracefully

### Policy Evaluation Failures
- **Configuration Errors**: Log and apply default deny policy
- **Rule Conflicts**: First-match-wins resolution
- **Set Membership**: Handle user/process detection failures
- **Path Matching**: Support wildcards and pattern failures

### File System Edge Cases
- **Partial Writes**: Handle incomplete encryption operations
- **Concurrent Access**: Manage multiple readers/writers
- **File Truncation**: Handle size changes during encryption
- **Symbolic Links**: Follow links or operate on link files

---

## Performance Optimizations

### Caching Strategies
- **Policy Decisions**: Cache recent policy evaluations (5-minute TTL)
- **Encryption Keys**: Cache derived keys in memory
- **File Detection**: Cache TAKA header detection results
- **Process Information**: Cache process/user resolution

### Fast Path Optimizations
- **Early Exit**: Quick rejection for non-guard-point files
- **Header Caching**: Avoid re-reading TAKA headers
- **Buffer Reuse**: Reuse allocated buffers for common operations
- **Batch Operations**: Group multiple small operations

### Memory Management
- **Zero-Copy**: Minimize data copying between kernel/userspace
- **Streaming**: Process large files in chunks
- **Cleanup**: Automatic cleanup of failed operations
- **Pressure Handling**: Graceful degradation under memory pressure

---

## Security Considerations

### Threat Model
- **Privileged Escalation**: Kernel module runs with root privileges
- **Data Leakage**: Prevent plaintext leakage in kernel memory
- **Key Exposure**: Secure key handling in userspace
- **Bypass Attempts**: Prevent direct filesystem access

### Cryptographic Security
- **Algorithm Choice**: AES-256-GCM for authenticated encryption
- **Key Derivation**: PBKDF2 or Argon2 for key strengthening
- **IV Generation**: Cryptographically secure random IVs
- **Authentication**: Mandatory integrity verification

### Access Control Security
- **Process Validation**: Verify process identity and permissions
- **User Authorization**: Enforce user-based access controls
- **Path Traversal**: Prevent directory traversal attacks
- **Time-of-Check vs Time-of-Use**: Minimize TOCTOU windows

This flow documentation provides the complete technical details of how Takakrypt achieves transparent encryption through VFS interception, policy evaluation, and cryptographic operations.