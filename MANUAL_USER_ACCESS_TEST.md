# Manual User Access Testing Guide for Takakrypt

This guide shows how to manually test user access control for the transparent encryption system.

## Prerequisites

1. Three test users exist: `ntoi`, `testuser1`, `testuser2`
2. Test directory created: `/tmp/takakrypt-user-test`
3. Configuration file: `/tmp/takakrypt-user-test-config.yaml`

## Step 1: Check Current Users

```bash
# Verify all users exist
cat /etc/passwd | grep -E "^(ntoi|testuser1|testuser2):" | cut -d: -f1,3

# Check current user
whoami
id
```

## Step 2: Create Test Environment

```bash
# Create test directory (as root or with sudo)
sudo mkdir -p /tmp/takakrypt-user-test
sudo chmod 777 /tmp/takakrypt-user-test

# Create test files as different users
echo "Admin only file" > /tmp/takakrypt-user-test/admin-secret.txt
echo "User1 document" > /tmp/takakrypt-user-test/user1-file.txt
echo "User2 document" > /tmp/takakrypt-user-test/user2-file.txt
echo "Shared document" > /tmp/takakrypt-user-test/shared.txt
echo "Should be excluded" > /tmp/takakrypt-user-test/test.log

# Set permissions
chmod 644 /tmp/takakrypt-user-test/*.txt
chmod 644 /tmp/takakrypt-user-test/*.log

# List files
ls -la /tmp/takakrypt-user-test/
```

## Step 3: Test Configuration Loading

```bash
# From project directory
cd /home/ntoi/c-transparent-encryption

# Test configuration parsing
go run ./cmd/test-user-access/main.go /tmp/takakrypt-user-test-config.yaml

# Expected output:
# - Should show 3 user sets (admin_users, test_users, denied_users)
# - Should show 1 guard point for /tmp/takakrypt-user-test
# - Should show include patterns: *.txt, *.doc
```

## Step 4: Run User Access Simulation

```bash
# Run the simulation test
go run ./cmd/simulate-user-access/main.go /tmp/takakrypt-user-test-config.yaml

# This will show:
# - Which users can access which files
# - Why access is allowed or denied
# - Guard point and pattern matching results
```

## Step 5: Manual File Access Tests (as different users)

### Option A: Using sudo (if you have sudo privileges)

```bash
# Test as ntoi (admin user)
echo "=== Testing as ntoi (UID 1000) ==="
cat /tmp/takakrypt-user-test/admin-secret.txt
cat /tmp/takakrypt-user-test/shared.txt

# Test as testuser1 (if sudo is available)
echo "=== Testing as testuser1 (UID 1001) ==="
sudo -u testuser1 cat /tmp/takakrypt-user-test/user1-file.txt
sudo -u testuser1 cat /tmp/takakrypt-user-test/shared.txt

# Test as testuser2
echo "=== Testing as testuser2 (UID 1002) ==="
sudo -u testuser2 cat /tmp/takakrypt-user-test/user2-file.txt
sudo -u testuser2 cat /tmp/takakrypt-user-test/shared.txt
```

### Option B: Using su (requires user passwords)

```bash
# Switch to testuser1
su - testuser1
cat /tmp/takakrypt-user-test/user1-file.txt
cat /tmp/takakrypt-user-test/shared.txt
exit

# Switch to testuser2
su - testuser2
cat /tmp/takakrypt-user-test/user2-file.txt
cat /tmp/takakrypt-user-test/shared.txt
exit
```

### Option C: Using runuser (as root)

```bash
# As root user
sudo -i

# Test as different users
runuser -u testuser1 -- cat /tmp/takakrypt-user-test/user1-file.txt
runuser -u testuser2 -- cat /tmp/takakrypt-user-test/user2-file.txt
exit
```

## Step 6: Test with Full System (when kernel module is loaded)

```bash
# Build the system
make clean && make build

# Load kernel module (requires root)
sudo insmod kernel/takakrypt.ko debug_level=4

# Check module is loaded
lsmod | grep takakrypt

# Start the agent with test config
sudo ./build/bin/takakrypt-agent -config /tmp/takakrypt-user-test-config.yaml -log-level debug

# In another terminal, monitor kernel logs
sudo dmesg -w | grep takakrypt

# Now test file access - the kernel module should intercept
cat /tmp/takakrypt-user-test/admin-secret.txt

# Check proc interface
cat /proc/takakrypt/status
cat /proc/takakrypt/cache
```

## Step 7: Verify Policy Enforcement

Check these scenarios:

1. **Authorized User + Valid File**: Should ALLOW
   - ntoi accessing *.txt files in guard point
   - testuser1/2 accessing *.txt files in guard point

2. **Unauthorized User + Valid File**: Should DENY
   - Unknown user (UID 9999) accessing any file
   - User not in any user set

3. **Authorized User + Invalid File**: Should DENY
   - Any user accessing *.log files (not in include patterns)
   - Any user accessing files outside guard point

4. **File Pattern Matching**:
   - *.txt files should be allowed
   - *.doc files should be allowed
   - *.log files should be denied
   - Other extensions should be denied

## Step 8: Check Audit Logs

```bash
# If agent is running, check logs
sudo journalctl -u takakrypt-agent -f

# Or check agent log file directly (if configured)
tail -f /var/log/takakrypt/agent.log

# Check for policy decisions
grep "policy decision" /var/log/takakrypt/agent.log
grep "access denied" /var/log/takakrypt/agent.log
```

## Expected Results Summary

| User | File | Expected Result | Reason |
|------|------|----------------|---------|
| ntoi | /tmp/takakrypt-user-test/admin-secret.txt | ALLOW | User in admin_users, file matches pattern |
| testuser1 | /tmp/takakrypt-user-test/user1-file.txt | ALLOW | User in test_users, file matches pattern |
| testuser2 | /tmp/takakrypt-user-test/user2-file.txt | ALLOW | User in test_users, file matches pattern |
| any user | /tmp/takakrypt-user-test/test.log | DENY | .log not in include patterns |
| unknown | any file | DENY | User not in any user set |
| ntoi | /home/ntoi/document.txt | DENY | File outside guard point |

## Troubleshooting

1. **Permission Denied**: Check file permissions with `ls -la`
2. **User Not Found**: Verify user exists with `id username`
3. **Module Not Loaded**: Check with `lsmod | grep takakrypt`
4. **Agent Not Running**: Check with `ps aux | grep takakrypt-agent`
5. **Config Errors**: Validate with test tools before running agent

## Cleanup

```bash
# Stop agent
sudo pkill takakrypt-agent

# Unload kernel module
sudo rmmod takakrypt

# Remove test files
rm -rf /tmp/takakrypt-user-test
rm /tmp/takakrypt-user-test-config.yaml
```