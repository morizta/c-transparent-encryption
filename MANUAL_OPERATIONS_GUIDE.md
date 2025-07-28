# Takakrypt Manual Operations Guide

## Agent Management

### Starting the Agent

#### Method 1: Direct Start (Foreground)
```bash
# Start agent in foreground with debug logging
cd /home/ntoi/c-transparent-encryption
sudo ./build/bin/takakrypt-agent -config configs/test-config.yaml -log-level debug

# Or with specific configuration
sudo ./build/bin/takakrypt-agent -config configs/security-rules-test.yaml -log-level info
```

#### Method 2: Background Start
```bash
# Start agent in background
cd /home/ntoi/c-transparent-encryption
sudo ./build/bin/takakrypt-agent -config configs/test-config.yaml -log-level debug &

# Get the process ID
AGENT_PID=$!
echo "Agent started with PID: $AGENT_PID"
```

#### Method 3: Start with Logging
```bash
# Start with output redirected to log file
sudo ./build/bin/takakrypt-agent -config configs/test-config.yaml -log-level debug > /tmp/takakrypt-agent.log 2>&1 &
```

### Checking Agent Status

```bash
# Check if agent is running
ps aux | grep takakrypt-agent | grep -v grep

# Check kernel module connection
cat /proc/takakrypt/status | grep -A5 "Agent Connection"

# Check agent logs (if logging to file)
tail -f /tmp/takakrypt-agent.log

# Check if agent is connected to kernel netlink
cat /proc/takakrypt/status | head -20
```

### Stopping the Agent

#### Method 1: Kill by Process Name
```bash
# Find and kill agent process
sudo pkill -f takakrypt-agent

# Or more specific
sudo pkill -f "takakrypt-agent.*config"
```

#### Method 2: Kill by PID (if you saved it)
```bash
# If you have the PID from starting
sudo kill $AGENT_PID

# Force kill if needed
sudo kill -9 $AGENT_PID
```

#### Method 3: Kill All Related Processes
```bash
# Kill all takakrypt processes
sudo pkill takakrypt
```

### Restarting the Agent

```bash
# Complete restart procedure
echo "Stopping existing agent..."
sudo pkill -f takakrypt-agent
sleep 2

echo "Starting new agent..."
cd /home/ntoi/c-transparent-encryption
sudo ./build/bin/takakrypt-agent -config configs/test-config.yaml -log-level debug &

echo "Agent restarted. Checking status..."
sleep 3
cat /proc/takakrypt/status | grep -A3 "Agent Connection"
```

## Manual File Testing

### Setup Test Environment

```bash
# Ensure test directory exists
mkdir -p /tmp/takakrypt-user-test
chmod 755 /tmp/takakrypt-user-test

# Check current user
whoami && id
```

### Testing File Read Operations

#### Test 1: Read Existing Files
```bash
# Read files that should be allowed
echo "=== Reading admin file ==="
cat /tmp/takakrypt-user-test/admin-secret.txt

echo "=== Reading shared file ==="
cat /tmp/takakrypt-user-test/shared.txt

echo "=== Reading user1 file ==="
cat /tmp/takakrypt-user-test/user1-file.txt
```

#### Test 2: Read Files with Different Extensions
```bash
# Test pattern matching
echo "=== Reading .txt file (should work) ==="
cat /tmp/takakrypt-user-test/admin-secret.txt

echo "=== Reading .log file (should work but not encrypted) ==="
cat /tmp/takakrypt-user-test/test.log
```

#### Test 3: Monitor Kernel Activity During Reads
```bash
# In one terminal, monitor kernel status
watch -n 1 'cat /proc/takakrypt/status | head -25'

# In another terminal, read files
cat /tmp/takakrypt-user-test/admin-secret.txt
cat /tmp/takakrypt-user-test/shared.txt
```

### Testing File Write Operations

#### Test 1: Create New Files
```bash
# Create new .txt file (should be encrypted)
echo "This is a new secret document created on $(date)" > /tmp/takakrypt-user-test/new-secret-$(date +%s).txt

# Create new .log file (should not be encrypted)
echo "Log entry created on $(date)" > /tmp/takakrypt-user-test/new-log-$(date +%s).log

# List all files
ls -la /tmp/takakrypt-user-test/
```

#### Test 2: Append to Existing Files
```bash
# Append to existing file
echo "Additional secret information added on $(date)" >> /tmp/takakrypt-user-test/admin-secret.txt

# Read back to verify
cat /tmp/takakrypt-user-test/admin-secret.txt
```

#### Test 3: Edit Files with Text Editors
```bash
# Edit with nano (if available)
nano /tmp/takakrypt-user-test/admin-secret.txt

# Or edit with vi
vi /tmp/takakrypt-user-test/admin-secret.txt

# Or simple echo edit
echo "Edited content on $(date)" > /tmp/takakrypt-user-test/edit-test.txt
cat /tmp/takakrypt-user-test/edit-test.txt
```

### Advanced File Testing

#### Test 1: Large File Operations
```bash
# Create a larger file
dd if=/dev/urandom of=/tmp/takakrypt-user-test/large-file.txt bs=1024 count=100

# Read it back
head -c 100 /tmp/takakrypt-user-test/large-file.txt | hexdump -C
```

#### Test 2: File Operations Monitoring
```bash
# Start monitoring script
cat > /tmp/monitor-takakrypt.sh << 'EOF'
#!/bin/bash
echo "=== Monitoring Takakrypt Activity ==="
while true; do
    clear
    echo "Time: $(date)"
    echo ""
    cat /proc/takakrypt/status | head -25
    echo ""
    echo "Active files in test directory:"
    ls -la /tmp/takakrypt-user-test/ | tail -10
    echo ""
    echo "Press Ctrl+C to stop monitoring"
    sleep 2
done
EOF

chmod +x /tmp/monitor-takakrypt.sh
/tmp/monitor-takakrypt.sh
```

#### Test 3: Cross-User File Access (if possible)
```bash
# Test file permissions
echo "Testing file created by ntoi:"
echo "File created by ntoi user" > /tmp/takakrypt-user-test/ntoi-file.txt
ls -la /tmp/takakrypt-user-test/ntoi-file.txt

# Try to access with different permissions
chmod 644 /tmp/takakrypt-user-test/ntoi-file.txt
cat /tmp/takakrypt-user-test/ntoi-file.txt
```

## Troubleshooting Commands

### Check System Status
```bash
# Check kernel module
lsmod | grep takakrypt

# Check kernel module status
cat /proc/takakrypt/status

# Check if agent process exists
ps aux | grep takakrypt-agent

# Check netlink communication
cat /proc/takakrypt/status | grep -E "(Agent|Connection|Statistics)"
```

### Debug Mode Testing
```bash
# Start agent with maximum debugging
sudo ./build/bin/takakrypt-agent -config configs/test-config.yaml -log-level debug -v

# Check kernel logs
sudo dmesg | grep takakrypt | tail -20

# Monitor real-time kernel messages
sudo dmesg -w | grep takakrypt
```

### Performance Testing
```bash
# Create performance test script
cat > /tmp/perf-test.sh << 'EOF'
#!/bin/bash
echo "=== Performance Test ==="
START=$(date +%s.%N)

# Create 10 files
for i in {1..10}; do
    echo "Test file $i content $(date)" > /tmp/takakrypt-user-test/perf-test-$i.txt
done

# Read all files
for i in {1..10}; do
    cat /tmp/takakrypt-user-test/perf-test-$i.txt > /dev/null
done

END=$(date +%s.%N)
DURATION=$(echo "$END - $START" | bc -l)
echo "Total time for 20 operations: $DURATION seconds"

# Show statistics
echo ""
cat /proc/takakrypt/status | grep -E "(Request Statistics|Cache Performance)"

# Cleanup
rm -f /tmp/takakrypt-user-test/perf-test-*.txt
EOF

chmod +x /tmp/perf-test.sh
/tmp/perf-test.sh
```

## Complete Test Workflow

### Full System Test
```bash
#!/bin/bash
echo "=== Complete Takakrypt System Test ==="

# 1. Start agent
echo "1. Starting agent..."
cd /home/ntoi/c-transparent-encryption
sudo pkill -f takakrypt-agent 2>/dev/null
sleep 1
sudo ./build/bin/takakrypt-agent -config configs/test-config.yaml -log-level debug &
sleep 3

# 2. Check connection
echo "2. Checking agent connection..."
cat /proc/takakrypt/status | grep -A3 "Agent Connection"

# 3. Test file operations
echo "3. Testing file operations..."
echo "Secret data $(date)" > /tmp/takakrypt-user-test/test-write.txt
cat /tmp/takakrypt-user-test/test-write.txt

# 4. Check statistics
echo "4. Final statistics..."
cat /proc/takakrypt/status | grep -E "(Request Statistics|Cryptographic Operations)"

echo "=== Test Complete ==="
```

## Notes

- **Root privileges required**: Agent needs root to communicate with kernel module
- **Configuration path**: Use absolute paths for config files
- **Log monitoring**: Use `tail -f` to monitor real-time activity
- **Process cleanup**: Always stop agent cleanly to avoid resource leaks
- **File patterns**: Only .txt, .doc, .pdf files are encrypted by default (.log files are excluded)
- **Guard points**: Files must be in configured guard point directories to be processed