# Takakrypt System Guide: Hybrid Go+C Architecture

## System Overview

Takakrypt is a transparent file encryption system that uses a **hybrid architecture**:
- **C Kernel Module**: Intercepts file operations at the VFS layer
- **Go User-Space Agent**: Handles encryption, policy evaluation, and key management

## Architecture Components

```
┌─────────────────────────────────────────────────────────────┐
│                    USER SPACE                               │
├─────────────────────────────────────────────────────────────┤
│  Applications (vim, cat, cp, etc.)                         │
│           ↕ (normal file I/O)                              │
├─────────────────────────────────────────────────────────────┤
│                   KERNEL SPACE                             │
│  ┌─────────────────────────────────────────────────────────┐│
│  │              VFS Layer                                  ││
│  │  ┌─────────────────────────────────────────────────────┐││
│  │  │        Takakrypt Kernel Module (C)                  │││
│  │  │  • File operation interception                     │││
│  │  │  • Policy decision caching                         │││
│  │  │  • Netlink communication                           │││
│  │  └─────────────────────────────────────────────────────┘││
│  └─────────────────────────────────────────────────────────┘│
│           ↕ (netlink socket)                               │
├─────────────────────────────────────────────────────────────┤
│                   USER SPACE                               │
│  ┌─────────────────────────────────────────────────────────┐│
│  │           Takakrypt Agent (Go)                          ││
│  │  • Policy engine                                       ││
│  │  • Encryption/decryption                              ││
│  │  • Key management                                      ││
│  │  • KMS integration                                     ││
│  └─────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────┘
```

## Configuration System

### Main Configuration File: `/etc/takakrypt/config.yaml`

```yaml
# Guard Points - Define protected directories
guard_points:
  - name: "sensitive_documents"
    path: "/home/*/Documents/Confidential"
    recursive: true
    include_patterns:
      - "*.doc"
      - "*.pdf" 
      - "*.txt"
    exclude_patterns:
      - "*.log"
      - "*.tmp"
    policy: "document_encryption"
    enabled: true

  - name: "finance_data"
    path: "/opt/finance/data"
    recursive: true
    include_patterns: ["*"]
    policy: "high_security_encryption"
    enabled: true

# User Sets - Group users with similar access rights
user_sets:
  finance_team:
    name: "finance_team"
    users: ["alice", "bob", "carol"]
    uids: [1001, 1002, 1003]
    groups: ["finance"]
    gids: [2001]

  executives:
    name: "executives"
    users: ["ceo", "cfo"]
    uids: [1010, 1011]

  it_admins:
    name: "it_admins"
    users: ["admin", "sysop"]
    uids: [1000, 1020]

# Process Sets - Define trusted applications
process_sets:
  office_apps:
    name: "office_apps"
    processes: ["libreoffice", "vim", "nano"]
    paths: ["/usr/bin/libreoffice*", "/usr/bin/vim", "/usr/bin/nano"]

  backup_tools:
    name: "backup_tools"
    processes: ["rsync", "tar", "backup-script"]
    paths: ["/usr/bin/rsync", "/bin/tar", "/opt/backup/backup-script"]

# Resource Sets - File pattern groups
resource_sets:
  sensitive_docs:
    name: "sensitive_docs"
    patterns: ["*confidential*", "*secret*", "*.classified"]
    extensions: [".doc", ".pdf", ".xlsx"]

# Policies - Define encryption rules
policies:
  document_encryption:
    name: "document_encryption"
    algorithm: "AES-256-GCM"
    key_size: 256
    user_sets: ["finance_team", "executives"]
    process_sets: ["office_apps"]
    resource_sets: ["sensitive_docs"]
    require_all_sets: false  # OR logic: any set match allows access
    enabled: true

  high_security_encryption:
    name: "high_security_encryption"
    algorithm: "AES-256-GCM"
    key_size: 256
    user_sets: ["finance_team"]
    process_sets: ["office_apps", "backup_tools"]
    require_all_sets: true   # AND logic: all sets must match
    audit_level: "detailed"
    enabled: true

# Agent Configuration
agent:
  socket_path: "/var/run/takakrypt.sock"
  log_level: "info"
  log_path: "/var/log/takakrypt/agent.log"
  audit_log_path: "/var/log/takakrypt/audit.log"
  max_cache_size: 10000
  cache_cleanup_interval: "5m"
  worker_threads: 8
  max_request_size: 1048576  # 1MB
  request_timeout: "30s"
  enable_metrics: true

# KMS Configuration
kms:
  endpoint: "https://kms.company.com"
  auth_method: "certificate"
  certificate_path: "/etc/takakrypt/certs/client.crt"
  key_path: "/etc/takakrypt/certs/client.key"
  timeout: "10s"
  retry_attempts: 3
  key_cache_ttl: "1h"
  policy_cache_ttl: "15m"
```

## How to Build and Run

### 1. Build User-Space Components (Go)

```bash
# Build the main agent
make build-agent

# Or manually:
go build -o build/bin/takakrypt-agent cmd/takakrypt-agent/main.go

# Build CLI tools
go build -o build/bin/takakrypt-cli cmd/takakrypt-cli/main.go
go build -o build/bin/test-user-access cmd/test-user-access/main.go
```

### 2. Build Kernel Module (C)

```bash
# Build kernel module
make build-kernel

# Or manually:
cd kernel/
make
```

### 3. System Installation

```bash
# Install everything (requires root)
sudo make install

# Or step by step:

# 1. Install kernel module
sudo make install-kernel

# 2. Install user-space binaries
sudo make install-user

# 3. Install configuration
sudo mkdir -p /etc/takakrypt
sudo cp configs/example.yaml /etc/takakrypt/config.yaml

# 4. Install systemd service
sudo cp scripts/takakrypt.service /etc/systemd/system/
sudo systemctl daemon-reload
```

### 4. Running the System

#### Step 1: Load Kernel Module
```bash
# Load the kernel module
sudo modprobe takakrypt
# or
sudo insmod kernel/takakrypt.ko

# Verify it's loaded
lsmod | grep takakrypt
dmesg | tail  # Check for loading messages
```

#### Step 2: Start User-Space Agent
```bash
# Start as systemd service
sudo systemctl start takakrypt-cte
sudo systemctl enable takakrypt-cte

# Or run manually (for testing)
sudo /usr/local/bin/takakrypt-agent -config /etc/takakrypt/config.yaml

# Run in foreground with debug
sudo /usr/local/bin/takakrypt-agent -config /etc/takakrypt/config.yaml -debug
```

#### Step 3: Verify System Status
```bash
# Check service status
sudo systemctl status takakrypt-cte

# Check kernel module status
cat /proc/takakrypt/status

# Check agent logs
sudo journalctl -u takakrypt -f

# Check if netlink communication works
sudo /usr/local/bin/takakrypt-cli status
```

## Testing the System

### 1. Basic Functionality Test

```bash
# Create test directory
sudo mkdir -p /tmp/takakrypt-test
sudo chown $USER:$USER /tmp/takakrypt-test

# Create test configuration
cat > /tmp/test-config.yaml << EOF
guard_points:
  - name: "test_guard"
    path: "/tmp/takakrypt-test"
    recursive: true
    include_patterns: ["*.txt", "*.doc"]
    exclude_patterns: ["*.log"]
    policy: "test_policy"
    enabled: true

user_sets:
  test_users:
    name: "test_users"
    users: ["$USER"]
    uids: [$(id -u)]

policies:
  test_policy:
    name: "test_policy"
    algorithm: "AES-256-GCM"
    user_sets: ["test_users"]
    enabled: true

agent:
  socket_path: "/tmp/takakrypt-test.sock"
  log_level: "debug"
  worker_threads: 2

kms:
  endpoint: "mock://localhost"
  auth_method: "none"
EOF

# Start agent with test config
sudo /usr/local/bin/takakrypt-agent -config /tmp/test-config.yaml &
AGENT_PID=$!

# Test file operations
echo "This should be encrypted" > /tmp/takakrypt-test/secret.txt
echo "This should NOT be encrypted" > /tmp/takakrypt-test/debug.log

# Read files back
cat /tmp/takakrypt-test/secret.txt  # Should work and show plaintext
cat /tmp/takakrypt-test/debug.log   # Should show plaintext (not encrypted)

# Check what's actually on disk (raw encrypted data)
sudo hexdump -C /tmp/takakrypt-test/secret.txt | head -5

# Cleanup
kill $AGENT_PID
```

### 2. Multi-User Test

```bash
# Create test users (if they don't exist)
sudo useradd -m testuser1
sudo useradd -m testuser2

# Test as different users
sudo -u testuser1 echo "User1's secret" > /tmp/takakrypt-test/user1.txt
sudo -u testuser2 echo "User2's secret" > /tmp/takakrypt-test/user2.txt

# Try cross-user access
sudo -u testuser1 cat /tmp/takakrypt-test/user2.txt  # Should work if same user set
sudo -u nobody cat /tmp/takakrypt-test/user1.txt     # Should fail
```

### 3. Performance Test

```bash
# Test encryption throughput
time dd if=/dev/zero of=/tmp/takakrypt-test/large.txt bs=1M count=100

# Test policy decision performance
/usr/local/bin/takakrypt-cli benchmark -files 1000 -path /tmp/takakrypt-test
```

## Monitoring and Debugging

### 1. Real-time Monitoring

```bash
# Watch kernel module statistics
watch -n 1 cat /proc/takakrypt/status

# Monitor agent activity
tail -f /var/log/takakrypt/agent.log

# Watch audit logs
tail -f /var/log/takakrypt/audit.log

# Monitor system calls
sudo strace -e trace=openat,read,write -p $(pgrep takakrypt-agent)
```

### 2. Debug Information

```bash
# Kernel module debug info
cat /proc/takakrypt/cache     # Cache statistics
cat /proc/takakrypt/files     # Active file contexts
echo 1 | sudo tee /sys/module/takakrypt/parameters/debug_level

# Agent debug
sudo /usr/local/bin/takakrypt-agent -config /etc/takakrypt/config.yaml -debug -foreground

# Test specific policy evaluation
/usr/local/bin/takakrypt-cli test-policy -file /path/to/test -user $(id -u)
```

### 3. Troubleshooting Common Issues

```bash
# Kernel module won't load
dmesg | grep takakrypt        # Check error messages
modinfo kernel/takakrypt.ko   # Check module info

# Agent won't start
sudo /usr/local/bin/takakrypt-agent -config /etc/takakrypt/config.yaml -validate
journalctl -u takakrypt --since "1 hour ago"

# Files not being encrypted
/usr/local/bin/takakrypt-cli debug -file /path/to/file
cat /proc/takakrypt/status    # Check operation counters

# Permission denied errors
ls -la /var/run/takakrypt.sock
ps aux | grep takakrypt-agent
```

## System Integration Flow

### File Write Operation:
1. **Application** calls `write()` on a file
2. **VFS** routes to filesystem
3. **Takakrypt kernel module** intercepts via VFS hooks
4. **Kernel module** checks policy cache or queries agent via netlink
5. **Go agent** evaluates policy (user sets, process sets, patterns)
6. **Go agent** encrypts data if policy requires it
7. **Kernel module** writes encrypted data to disk
8. **Application** receives success response

### File Read Operation:
1. **Application** calls `read()` on a file
2. **VFS** routes to filesystem 
3. **Takakrypt kernel module** intercepts and checks file context
4. **Kernel module** reads encrypted data from disk
5. **Go agent** decrypts data if file is encrypted and user authorized
6. **Kernel module** returns plaintext to application
7. **Application** receives decrypted data transparently

This hybrid approach provides the performance benefits of kernel-space interception with the flexibility and safety of user-space policy and crypto operations.