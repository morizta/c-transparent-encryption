# Takakrypt Transparent Encryption Testing Guide

## Overview
This guide provides comprehensive testing procedures for the Takakrypt transparent encryption system, covering unit tests, integration tests, and system validation.

## Prerequisites

### System Requirements
- Linux kernel 4.x or later with development headers
- Go 1.21 or later
- Root access for kernel module operations
- At least 2GB RAM for testing
- 1GB free disk space

### Required Packages
```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install -y build-essential linux-headers-$(uname -r) golang git

# RHEL/CentOS/Fedora
sudo yum install -y kernel-devel-$(uname -r) golang git make gcc

# Check installations
make check-deps
```

## Quick Start Testing

### 1. Build the System
```bash
# Clone and enter the project directory
cd /path/to/c-transparent-encryption

# Build everything
make clean
make build

# Check build status
ls -la build/bin/
ls -la kernel/*.ko
```

### 2. Basic Kernel Module Test
```bash
# Test kernel module loading (requires root)
sudo make -C kernel test-load

# Check module status
sudo make -C kernel status

# View kernel logs
sudo dmesg | grep takakrypt | tail -20
```

### 3. Unit Tests
```bash
# Run Go unit tests
make test-go

# Run specific package tests
go test -v ./internal/crypto/
go test -v ./internal/policy/
go test -v ./internal/config/
```

## Detailed Testing Procedures

### Phase 1: Component Testing

#### 1.1 Configuration Parser Test
```bash
# Create test configuration
cat > /tmp/test-config.yaml << 'EOF'
guard_points:
  - name: "test_documents"
    path: "/tmp/test-encrypt"
    recursive: true
    policy: "test_policy"
    enabled: true

policies:
  test_policy:
    algorithm: "AES-256-GCM"
    key_size: 256
    audit_level: "debug"
    enabled: true

kms:
  endpoint: "mock://localhost"
  auth_method: "token"
  timeout: "10s"

agent:
  log_level: "debug"
  worker_threads: 2
EOF

# Test configuration loading
go run cmd/test-config/main.go -config /tmp/test-config.yaml
```

#### 1.2 Encryption Engine Test
```go
// Create test file: cmd/test-crypto/main.go
package main

import (
    "fmt"
    "log"
    "github.com/takakrypt/c-transparent-encryption/internal/crypto"
)

func main() {
    engine := crypto.NewEncryptionEngine()
    
    // Generate test key
    key, err := engine.GenerateKey("AES-256-GCM", "test-key-1")
    if err != nil {
        log.Fatal(err)
    }
    
    // Test encryption
    plaintext := []byte("This is a test file content for transparent encryption")
    result, err := engine.Encrypt(plaintext, "test-key-1")
    if err != nil {
        log.Fatal(err)
    }
    
    fmt.Printf("Encrypted %d bytes -> %d bytes\n", len(plaintext), len(result.Ciphertext))
    
    // Test decryption
    decrypted, err := engine.Decrypt(&crypto.DecryptionRequest{
        Ciphertext: result.Ciphertext,
        Nonce:      result.Nonce,
        Algorithm:  result.Algorithm,
        KeyID:      result.KeyID,
        Version:    result.Version,
    })
    if err != nil {
        log.Fatal(err)
    }
    
    fmt.Printf("Decrypted: %s\n", string(decrypted))
    
    if string(decrypted) == string(plaintext) {
        fmt.Println("✅ Encryption/Decryption test PASSED")
    } else {
        fmt.Println("❌ Encryption/Decryption test FAILED")
    }
}
```

#### 1.3 Policy Engine Test
```bash
# Create test directory structure
sudo mkdir -p /tmp/test-encrypt/{documents,images,code}
sudo chmod 777 /tmp/test-encrypt -R

# Create test files
echo "Confidential document" > /tmp/test-encrypt/documents/secret.txt
echo "Public document" > /tmp/test-encrypt/documents/public.txt
echo "Source code" > /tmp/test-encrypt/code/main.go

# Test policy evaluation (create test program)
go run cmd/test-policy/main.go
```

### Phase 2: Kernel Module Testing

#### 2.1 Module Load/Unload Test
```bash
# Run automated load/unload test
sudo make -C kernel test-load

# Manual testing
sudo insmod kernel/takakrypt.ko debug_level=4
lsmod | grep takakrypt
sudo rmmod takakrypt

# Check for memory leaks
sudo dmesg | grep -i "memory leak"
```

#### 2.2 Proc Interface Test
```bash
# Load module
sudo insmod kernel/takakrypt.ko

# Test proc files
cat /proc/takakrypt/status
cat /proc/takakrypt/config
cat /proc/takakrypt/cache
cat /proc/takakrypt/files

# Monitor in real-time
watch -n 1 cat /proc/takakrypt/status
```

#### 2.3 Netlink Communication Test
```bash
# Create netlink test program
cat > cmd/test-netlink/main.go << 'EOF'
package main

import (
    "context"
    "fmt"
    "log"
    "time"
    "github.com/takakrypt/c-transparent-encryption/pkg/netlink"
)

func main() {
    client, err := netlink.NewClient()
    if err != nil {
        log.Fatal(err)
    }
    
    ctx := context.Background()
    if err := client.Connect(ctx); err != nil {
        log.Fatal(err)
    }
    defer client.Disconnect()
    
    fmt.Println("Connected to kernel module")
    
    // Send health check
    if err := client.SendHealthCheck(); err != nil {
        log.Printf("Health check failed: %v", err)
    } else {
        fmt.Println("✅ Health check passed")
    }
    
    // Send status request
    resp, err := client.SendStatusRequest()
    if err != nil {
        log.Printf("Status request failed: %v", err)
    } else {
        fmt.Printf("✅ Status response received: %+v\n", resp)
    }
}
EOF

# Run test
go run cmd/test-netlink/main.go
```

### Phase 3: Integration Testing

#### 3.1 End-to-End Test Setup
```bash
# 1. Create test environment
sudo mkdir -p /opt/takakrypt-test
sudo chmod 777 /opt/takakrypt-test

# 2. Install the system
sudo make install

# 3. Create test configuration
sudo cp configs/example.yaml /etc/takakrypt/config.yaml
sudo sed -i 's|/home/\*/Documents/Confidential|/opt/takakrypt-test|g' /etc/takakrypt/config.yaml

# 4. Start services
sudo make start

# 5. Check status
sudo make status
```

#### 3.2 File Encryption Test
```bash
# Create test script
cat > /tmp/test-encryption.sh << 'EOF'
#!/bin/bash
set -e

TEST_DIR="/opt/takakrypt-test"
TEST_FILE="$TEST_DIR/test-document.txt"

echo "=== Takakrypt File Encryption Test ==="

# Create test file
echo "This is a confidential document" > $TEST_FILE
echo "Created test file: $TEST_FILE"

# Check initial state
echo "Initial file content:"
cat $TEST_FILE

# Wait for encryption (if automatic)
sleep 2

# Try to read file (should trigger policy check)
echo "Reading file after policy application:"
cat $TEST_FILE

# Check kernel module statistics
echo "Kernel module statistics:"
cat /proc/takakrypt/status | grep -E "(requests_processed|encryption_ops|cache_hits)"

# Check if file is tracked
echo "Tracked files:"
cat /proc/takakrypt/files | grep -E "$TEST_FILE|Total Files"

echo "=== Test Complete ==="
EOF

chmod +x /tmp/test-encryption.sh
sudo /tmp/test-encryption.sh
```

#### 3.3 Performance Test
```bash
# Create performance test script
cat > /tmp/perf-test.sh << 'EOF'
#!/bin/bash

TEST_DIR="/opt/takakrypt-test"
NUM_FILES=100
FILE_SIZE="1M"

echo "=== Performance Test ==="
echo "Creating $NUM_FILES files of size $FILE_SIZE each..."

# Create test files
for i in $(seq 1 $NUM_FILES); do
    dd if=/dev/urandom of="$TEST_DIR/test-$i.dat" bs=$FILE_SIZE count=1 2>/dev/null
done

# Record start time
START=$(date +%s.%N)

# Read all files (triggers encryption/decryption)
for i in $(seq 1 $NUM_FILES); do
    cat "$TEST_DIR/test-$i.dat" > /dev/null
done

# Record end time
END=$(date +%s.%N)
DURATION=$(echo "$END - $START" | bc)

echo "Time to process $NUM_FILES files: $DURATION seconds"
echo "Average time per file: $(echo "scale=3; $DURATION / $NUM_FILES" | bc) seconds"

# Show statistics
echo ""
echo "Module statistics:"
cat /proc/takakrypt/status | grep -E "(cache_hits|cache_misses|encryption_ops|decryption_ops)"

# Cleanup
rm -f $TEST_DIR/test-*.dat
EOF

chmod +x /tmp/perf-test.sh
sudo /tmp/perf-test.sh
```

### Phase 4: Stress Testing

#### 4.1 Concurrent Access Test
```bash
# Create concurrent test
cat > /tmp/concurrent-test.sh << 'EOF'
#!/bin/bash

TEST_DIR="/opt/takakrypt-test"
THREADS=10
OPS_PER_THREAD=100

echo "=== Concurrent Access Test ==="
echo "Running $THREADS threads with $OPS_PER_THREAD operations each"

# Worker function
worker() {
    local id=$1
    local file="$TEST_DIR/thread-$id.txt"
    
    for i in $(seq 1 $OPS_PER_THREAD); do
        echo "Thread $id operation $i" > "$file"
        cat "$file" > /dev/null
    done
    
    echo "Thread $id completed"
}

# Start workers
for i in $(seq 1 $THREADS); do
    worker $i &
done

# Wait for completion
wait

echo "All threads completed"
echo ""
echo "Cache statistics:"
cat /proc/takakrypt/cache | head -20
EOF

chmod +x /tmp/concurrent-test.sh
sudo /tmp/concurrent-test.sh
```

#### 4.2 Memory Leak Test
```bash
# Monitor memory usage
cat > /tmp/memory-test.sh << 'EOF'
#!/bin/bash

echo "=== Memory Leak Test ==="

# Get initial memory usage
INITIAL_MEM=$(cat /proc/meminfo | grep MemFree | awk '{print $2}')
echo "Initial free memory: $INITIAL_MEM kB"

# Run intensive operations
for i in {1..1000}; do
    echo "Iteration $i"
    echo "Test data $i" > /opt/takakrypt-test/mem-test-$i.txt
    cat /opt/takakrypt-test/mem-test-$i.txt > /dev/null
    rm -f /opt/takakrypt-test/mem-test-$i.txt
done

# Get final memory usage
FINAL_MEM=$(cat /proc/meminfo | grep MemFree | awk '{print $2}')
echo "Final free memory: $FINAL_MEM kB"

# Calculate difference
DIFF=$((INITIAL_MEM - FINAL_MEM))
echo "Memory difference: $DIFF kB"

# Check kernel module memory
echo ""
echo "Module information:"
lsmod | grep takakrypt
EOF

chmod +x /tmp/memory-test.sh
sudo /tmp/memory-test.sh
```

### Phase 5: Security Testing

#### 5.1 Access Control Test
```bash
# Test as different users
cat > /tmp/access-test.sh << 'EOF'
#!/bin/bash

echo "=== Access Control Test ==="

# Create test users
sudo useradd -m testuser1 2>/dev/null || true
sudo useradd -m testuser2 2>/dev/null || true

# Create protected file as root
echo "Confidential data" > /opt/takakrypt-test/protected.txt
chmod 600 /opt/takakrypt-test/protected.txt

# Try to access as different users
echo "Access as testuser1:"
sudo -u testuser1 cat /opt/takakrypt-test/protected.txt 2>&1 || echo "Access denied (expected)"

echo ""
echo "Policy decisions in cache:"
cat /proc/takakrypt/cache | grep -i denied || echo "No denied entries"

# Cleanup
sudo userdel testuser1 2>/dev/null || true
sudo userdel testuser2 2>/dev/null || true
EOF

chmod +x /tmp/access-test.sh
sudo /tmp/access-test.sh
```

## Troubleshooting

### Common Issues

1. **Module won't load**
   ```bash
   # Check kernel version compatibility
   uname -r
   ls /lib/modules/$(uname -r)/build/
   
   # Check dmesg for errors
   sudo dmesg | tail -50
   ```

2. **Agent won't start**
   ```bash
   # Check if port is in use
   sudo netstat -tlnp | grep 9090
   
   # Check agent logs
   sudo journalctl -u takakrypt-agent -f
   ```

3. **No encryption happening**
   ```bash
   # Verify guard points
   cat /etc/takakrypt/config.yaml | grep -A5 guard_points
   
   # Check if files match patterns
   ls -la /opt/takakrypt-test/
   ```

### Debug Mode

Enable debug mode for detailed logging:
```bash
# Kernel module debug
sudo rmmod takakrypt
sudo insmod kernel/takakrypt.ko debug_level=4

# Agent debug
sudo systemctl stop takakrypt-agent
sudo /usr/local/sbin/takakrypt-agent -config /etc/takakrypt/config.yaml -log-level debug
```

## Cleanup

After testing, clean up the system:
```bash
# Stop services
sudo make stop

# Uninstall
sudo make uninstall

# Remove test files
sudo rm -rf /opt/takakrypt-test
sudo rm -f /tmp/test-*.sh

# Clean build
make clean
```

## Test Checklist

- [ ] Build system compiles without errors
- [ ] Kernel module loads/unloads cleanly
- [ ] Proc interface provides statistics
- [ ] Agent starts and connects to kernel
- [ ] Configuration parsing works correctly
- [ ] Encryption/decryption functions properly
- [ ] Policy engine evaluates correctly
- [ ] Cache performs efficiently
- [ ] System handles concurrent access
- [ ] No memory leaks detected
- [ ] Access control enforced properly
- [ ] Performance meets requirements (<1ms policy decisions)

---
*Testing Guide v1.0.0*
*Last Updated: 2025-07-24*