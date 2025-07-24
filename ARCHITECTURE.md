# Transparent Encryption Architecture

## System Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    Application Layer                        │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │
│  │  Process A  │  │  Process B  │  │  Process C  │         │
│  └─────────────┘  └─────────────┘  └─────────────┘         │
└─────────────────────────┬───────────────────────────────────┘
                          │ Standard File I/O
┌─────────────────────────▼───────────────────────────────────┐
│                File System Interceptor                      │
│  ┌─────────────────────────────────────────────────────────┐│
│  │            Kernel Module (C)                           ││
│  │  - VFS Hook Integration                                ││
│  │  - File Operation Interception                        ││
│  │  - Permission Checking                                 ││
│  └─────────────────────────────────────────────────────────┘│
└─────────────────────────┬───────────────────────────────────┘
                          │ IPC/Socket Communication
┌─────────────────────────▼───────────────────────────────────┐
│                  Encryption Agent (Go)                      │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │
│  │Policy Engine│  │Crypto Engine│  │ KMS Client  │         │
│  └─────────────┘  └─────────────┘  └─────────────┘         │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │
│  │Config Mgr   │  │ Cache Mgr   │  │Logger/Audit │         │
│  └─────────────┘  └─────────────┘  └─────────────┘         │
└─────────────────────────┬───────────────────────────────────┘
                          │ HTTPS/gRPC
┌─────────────────────────▼───────────────────────────────────┐
│                 External KMS System                         │
│  - Key Management                                           │
│  - Policy Distribution                                      │
│  - Audit Logging                                           │
└─────────────────────────────────────────────────────────────┘
```

## Component Details

### 1. File System Interceptor (Kernel Module - C)

**Purpose**: Intercept file I/O operations transparently

**Key Functions**:
- Hook into VFS (Virtual File System) layer
- Identify files within guard points
- Route encryption/decryption requests to user-space agent
- Handle file metadata and permissions

**Implementation Approach**:
```c
// Pseudo-code structure
struct file_operations takakrypt_fops = {
    .open = takakrypt_open,
    .read = takakrypt_read,
    .write = takakrypt_write,
    .release = takakrypt_release,
};

// Guard point checking
bool is_guarded_file(const char *path) {
    // Check against configured guard points
    // Return true if file should be encrypted
}
```

### 2. Encryption Agent (User-space - Go)

**Purpose**: Handle encryption logic, policy evaluation, and KMS integration

**Core Modules**:

#### Policy Engine
```go
type Policy struct {
    Name          string
    Algorithm     string
    UserSets      []string
    ProcessSets   []string
    ResourceSets  []string
    GuardPoints   []GuardPoint
}

type PolicyEngine struct {
    policies map[string]*Policy
    cache    *PolicyCache
}

func (pe *PolicyEngine) EvaluateAccess(ctx Context) (*Policy, error) {
    // Evaluate user, process, resource against policies
    // Return applicable policy or deny access
}
```

#### Crypto Engine
```go
type CryptoEngine struct {
    keyCache map[string]*EncryptionKey
    kms      KMSClient
}

func (ce *CryptoEngine) Encrypt(data []byte, policy *Policy) ([]byte, error) {
    key := ce.getKey(policy.KeyID)
    return aes.GCMEncrypt(data, key)
}

func (ce *CryptoEngine) Decrypt(data []byte, policy *Policy) ([]byte, error) {
    key := ce.getKey(policy.KeyID)
    return aes.GCMDecrypt(data, key)
}
```

#### KMS Integration
```go
type KMSClient interface {
    GetKey(keyID string) (*EncryptionKey, error)
    GetPolicy(policyID string) (*Policy, error)
    RefreshPolicies() error
}

type ThalesKMSClient struct {
    endpoint string
    auth     AuthProvider
    cache    *TTLCache
}
```

## Guard Points Design

### Configuration Structure
```yaml
guard_points:
  - name: "sensitive_documents"
    path: "/home/*/Documents/Confidential"
    recursive: true
    policy: "document_encryption"
    include_patterns:
      - "*.doc"
      - "*.pdf"
      - "*.xls"
    exclude_patterns:
      - "*.tmp"
      - ".DS_Store"

  - name: "database_files"
    path: "/var/lib/database"
    recursive: true
    policy: "database_encryption"
    process_whitelist:
      - "mysqld"
      - "postgres"
```

### Guard Point Evaluation Logic
```go
type GuardPoint struct {
    Name             string
    Path             string
    Recursive        bool
    Policy           string
    IncludePatterns  []string
    ExcludePatterns  []string
    ProcessWhitelist []string
}

func (gp *GuardPoint) Matches(filepath string, process string) bool {
    // Check path matching
    // Check process whitelist
    // Check include/exclude patterns
    return matchResult
}
```

## Policy Management

### Policy Types

#### 1. User-Set Policies
```yaml
user_sets:
  finance_team:
    users: ["john.doe", "jane.smith"]
    groups: ["finance", "accounting"]
    policy: "financial_data_encryption"

  executives:
    users: ["ceo", "cfo", "cto"]
    policy: "executive_encryption"
```

#### 2. Process-Set Policies
```yaml
process_sets:
  trusted_applications:
    processes: ["word.exe", "excel.exe", "acrobat.exe"]
    policy: "office_document_encryption"
    
  database_engines:
    processes: ["mysqld", "postgres", "oracle"]
    policy: "database_encryption"
```

#### 3. Resource-Set Policies
```yaml
resource_sets:
  financial_documents:
    file_patterns: ["*budget*", "*financial*", "*.xls"]
    policy: "financial_encryption"
    
  source_code:
    file_patterns: ["*.go", "*.c", "*.cpp", "*.h"]
    directories: ["/src", "/code"]
    policy: "source_code_encryption"
```

## Communication Protocols

### Kernel ↔ User-space Communication
```c
// Netlink socket or character device
struct takakrypt_request {
    uint32_t operation;  // ENCRYPT, DECRYPT, CHECK_POLICY
    uint32_t pid;        // Process ID
    uint32_t uid;        // User ID
    char filepath[PATH_MAX];
    uint32_t data_length;
    uint8_t data[];
};

struct takakrypt_response {
    uint32_t status;     // SUCCESS, DENIED, ERROR
    uint32_t data_length;
    uint8_t data[];
};
```

### Agent ↔ KMS Communication
```go
// gRPC or REST API
type KMSRequest struct {
    KeyID      string
    PolicyID   string
    Context    RequestContext
    Signature  string  // Request authentication
}

type KMSResponse struct {
    Key        []byte
    Policy     *Policy
    TTL        time.Duration
    Status     ResponseStatus
}
```

## Security Measures

### 1. Key Security
- Keys never stored in plaintext
- Memory protection for key data
- Secure key wiping after use
- Hardware security module integration

### 2. Policy Integrity
- Digital signatures on policy updates
- Tamper detection mechanisms
- Rollback protection
- Audit logging for policy changes

### 3. Access Control
- Principle of least privilege
- Process isolation
- Secure IPC channels
- Certificate-based authentication

## Performance Considerations

### 1. Caching Strategy
```go
type CacheManager struct {
    keyCache    *LRUCache    // Encrypted keys with TTL
    policyCache *LRUCache    // Policy decisions
    fileCache   *FileCache   // File metadata
}
```

### 2. Optimization Techniques
- Lazy encryption (encrypt on first write)
- Background key rotation
- Batch policy evaluations
- Memory-mapped file operations

## Deployment Architecture

### Single Host Deployment
```
┌─────────────────────────────────────┐
│            Target Host              │
│  ┌─────────────────────────────────┐│
│  │      Kernel Module              ││
│  └─────────────────────────────────┘│
│  ┌─────────────────────────────────┐│
│  │    Encryption Agent             ││
│  │  - Policy Engine                ││
│  │  - Crypto Engine                ││
│  │  - KMS Client                   ││
│  └─────────────────────────────────┘│
│  ┌─────────────────────────────────┐│
│  │   Configuration Files           ││
│  │  - guard_points.yaml            ││
│  │  - policies.yaml                ││
│  └─────────────────────────────────┘│
└─────────────────────────────────────┘
```

---
*Architecture Document*
*Created: 2025-07-23*
*Status: Design Phase*