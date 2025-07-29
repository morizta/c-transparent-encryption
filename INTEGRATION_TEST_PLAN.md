# Takakrypt Integration Test Plan

## Overview
This test plan validates the end-to-end functionality of Takakrypt transparent encryption system, including kernel module, userspace agent, policy evaluation, and encryption/decryption operations.

## Prerequisites
- [ ] System running Linux kernel 5.x+ 
- [ ] Root/sudo access for kernel module operations
- [ ] Go 1.21+ installed
- [ ] Build tools (make, gcc)
- [ ] Test configuration file (test-config.yaml)

## Test Categories

### 1. Build and Installation Tests
- [ ] Clean build: `make clean && make build`
- [ ] Verify binaries created in `build/bin/`
- [ ] Kernel module build successful
- [ ] No compilation errors or warnings

### 2. Agent Lifecycle Tests
- [ ] Agent starts successfully with config
- [ ] Agent connects to kernel module via netlink
- [ ] Agent handles SIGTERM gracefully
- [ ] Agent restarts without issues
- [ ] PID file created/removed properly

### 3. Kernel Module Tests  
- [ ] Module loads: `sudo make -C kernel load`
- [ ] Module appears in lsmod
- [ ] VFS hooks registered (check dmesg)
- [ ] Module unloads cleanly
- [ ] No kernel panics or warnings

### 4. Basic Encryption Tests
#### Test 4.1: Simple file encryption
```bash
# Create test directory under guard point
sudo mkdir -p /test/sensitive
# Write file - should encrypt
echo "secret data" | sudo tee /test/sensitive/test.txt
# Read file - should decrypt transparently  
sudo cat /test/sensitive/test.txt
# Verify file is encrypted on disk
sudo xxd /test/sensitive/test.txt | head -n 5  # Should show TAKA header
```

#### Test 4.2: Non-guard point files
```bash
# Write file outside guard point
echo "public data" > /tmp/public.txt
# Should NOT be encrypted
xxd /tmp/public.txt  # Should show plaintext
```

### 5. Process-Based Access Control Tests
#### Test 5.1: Authorized process (vim)
```bash
# As authorized user, edit with vim
sudo -u testuser vim /test/sensitive/secret.txt
# Should be able to read/write
```

#### Test 5.2: Unauthorized process  
```bash
# Use unauthorized editor
sudo -u testuser emacs /test/sensitive/secret.txt
# Should be denied access
```

#### Test 5.3: Database process restrictions
```bash
# Create database files
sudo mkdir -p /test/database
sudo touch /test/database/data.db

# MariaDB process should access
sudo -u mysql mariadb --execute "SELECT * FROM test" 

# Other processes should be denied
sudo cat /test/database/data.db  # Should fail
```

### 6. User-Based Access Control Tests
#### Test 6.1: Authorized user
```bash
# Login as authorized user (alice)
sudo -u alice cat /test/sensitive/userfile.txt
# Should succeed
```

#### Test 6.2: Unauthorized user
```bash
# Login as unauthorized user  
sudo -u bob cat /test/sensitive/userfile.txt
# Should be denied
```

### 7. Policy Evaluation Tests
#### Test 7.1: Rule ordering
- Create overlapping rules with different effects
- Verify first matching rule wins
- Test exclusion rules (marked with "E")

#### Test 7.2: Dynamic policy updates
- Modify test-config.yaml
- Reload agent configuration
- Verify new policies take effect

### 8. Encryption Algorithm Tests
#### Test 8.1: AES-256-GCM
- Configure policy with AES-256-GCM
- Write file and verify encryption
- Read file and verify decryption

#### Test 8.2: ChaCha20-Poly1305  
- Configure policy with ChaCha20-Poly1305
- Write file and verify encryption
- Read file and verify decryption

### 9. Performance Tests
#### Test 9.1: Large file handling
```bash
# Create 100MB file
dd if=/dev/urandom of=/test/sensitive/large.bin bs=1M count=100
# Time the operation
# Verify encryption completed
```

#### Test 9.2: Concurrent access
- Multiple processes reading/writing simultaneously
- Verify no corruption or deadlocks

### 10. Error Handling Tests
#### Test 10.1: Agent crash recovery
- Kill agent process abruptly
- Attempt file operations (should fail safely)
- Restart agent and verify recovery

#### Test 10.2: Invalid configurations
- Provide malformed config file
- Verify graceful error handling
- Check appropriate error messages

## Test Execution Steps

### Setup
1. Build the system: `make clean && make build`
2. Create test configuration from example
3. Install kernel module: `sudo make -C kernel load`
4. Start agent: `sudo ./build/bin/takakrypt-agent -config test-config.yaml`

### Execution
1. Run through each test category sequentially
2. Document any failures with logs
3. Capture dmesg output for kernel issues
4. Check agent logs for errors

### Cleanup  
1. Stop agent: `sudo pkill takakrypt-agent`
2. Unload kernel module: `sudo make -C kernel unload`
3. Remove test files and directories

## Expected Results
- All build tests pass without errors
- Agent lifecycle operations work smoothly
- Encryption/decryption is transparent to authorized users/processes
- Unauthorized access is properly denied
- No system instability or crashes

## Troubleshooting Commands
```bash
# Check kernel module status
lsmod | grep takakrypt
dmesg | tail -50

# Check agent status
ps aux | grep takakrypt-agent
sudo journalctl -u takakrypt-agent -n 50

# Monitor netlink communication  
sudo tcpdump -i any -nn 'proto 16'  # Netlink protocol

# Check file encryption
xxd /path/to/file | head -20  # Look for TAKA header
```

## Success Criteria
- [ ] All test categories pass
- [ ] No kernel warnings or errors
- [ ] Agent remains stable under load
- [ ] Policies correctly enforced
- [ ] Files properly encrypted/decrypted