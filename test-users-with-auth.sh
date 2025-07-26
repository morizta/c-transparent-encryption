#!/bin/bash

# Test User Access Control with Authentication
# Tests different users with actual login sessions

echo "=== Takakrypt User Access Control Test (with Authentication) ==="
echo "This will test each user: ntoi, testuser1, testuser2"
echo ""

# Function to test a user with password
test_user_with_password() {
    local username=$1
    echo "Testing user: $username"
    echo "You will be prompted for $username's password"
    
    # Record stats before test
    local before_processed=$(cat /proc/takakrypt/status | grep "Total Processed:" | awk '{print $3}')
    local before_allowed=$(cat /proc/takakrypt/status | grep "Allowed:" | awk '{print $2}')
    
    # Test file paths
    local test_file="/tmp/takakrypt-test/${username}-secure.txt"
    local test_doc="/tmp/takakrypt-test/${username}-document.doc"
    local test_log="/tmp/takakrypt-test/${username}-debug.log"
    
    echo "  Testing as $username (you'll need to enter the password)..."
    
    # Test 1: Create encrypted file (.txt)
    echo "  1. Creating .txt file (should be encrypted)..."
    if su "$username" -c "echo 'Confidential data from $username' > '$test_file'" 2>/dev/null; then
        echo "     ✓ .txt file created: $test_file"
        
        # Read it back
        if su "$username" -c "cat '$test_file'" 2>/dev/null; then
            echo "     ✓ .txt file read successfully"
        else
            echo "     ✗ .txt file read failed"
        fi
    else
        echo "     ✗ .txt file creation failed"
    fi
    
    # Test 2: Create encrypted document (.doc)
    echo "  2. Creating .doc file (should be encrypted)..."
    if su "$username" -c "echo 'Document data from $username' > '$test_doc'" 2>/dev/null; then
        echo "     ✓ .doc file created: $test_doc"
    else
        echo "     ✗ .doc file creation failed"
    fi
    
    # Test 3: Create non-encrypted file (.log)
    echo "  3. Creating .log file (should NOT be encrypted)..."
    if su "$username" -c "echo 'Log data from $username' > '$test_log'" 2>/dev/null; then
        echo "     ✓ .log file created: $test_log"
    else
        echo "     ✗ .log file creation failed"
    fi
    
    # Show file ownership
    echo "  4. File ownership verification:"
    for file in "$test_file" "$test_doc" "$test_log"; do
        if [ -f "$file" ]; then
            ls -la "$file" | awk '{printf "     %s: owner=%s, group=%s, perms=%s\n", $9, $3, $4, $1}'
        fi
    done
    
    # Calculate operations performed
    local after_processed=$(cat /proc/takakrypt/status | grep "Total Processed:" | awk '{print $3}')
    local after_allowed=$(cat /proc/takakrypt/status | grep "Allowed:" | awk '{print $2}')
    
    local operations=$((after_processed - before_processed))
    local allowed_ops=$((after_allowed - before_allowed))
    
    echo "  5. VFS Statistics for $username:"
    echo "     Operations intercepted: $operations"
    echo "     Operations allowed: $allowed_ops"
    
    # Show user info from system
    local uid=$(id -u "$username" 2>/dev/null)
    local gid=$(id -g "$username" 2>/dev/null)
    local groups=$(id -G "$username" 2>/dev/null | tr ' ' ',')
    echo "     User info: UID=$uid, GID=$gid, Groups=[$groups]"
    
    echo ""
}

# Function to show kernel debug info
show_kernel_debug() {
    echo "=== Kernel Module Debug Information ==="
    echo "Recent kernel messages (if available):"
    
    # Try different methods to get kernel messages
    if command -v journalctl >/dev/null 2>&1; then
        echo "From systemd journal:"
        sudo journalctl -k --since "5 minutes ago" | grep -i takakrypt | tail -10 2>/dev/null || echo "No recent takakrypt messages"
    fi
    
    if [ -r /var/log/kern.log ]; then
        echo "From kern.log:"
        sudo tail -20 /var/log/kern.log | grep -i takakrypt 2>/dev/null || echo "No takakrypt messages in kern.log"
    fi
    
    echo ""
}

# Function to test policy matching
test_policy_matching() {
    echo "=== Policy Matching Test ==="
    echo "Testing how different users map to user_sets in the configuration:"
    echo ""
    
    echo "Configuration mapping:"
    echo "  admin_users: ntoi (UID 1000)"
    echo "  test_users: testuser1 (UID 1001), testuser2 (UID 1002)"
    echo "  all_users: all three users"
    echo ""
    
    echo "Policy 'test_policy' allows: admin_users OR test_users"
    echo "Policy 'user_policy' allows: all_users"
    echo ""
    
    echo "Expected behavior:"
    echo "  - All users should be able to create files (policy allows)"
    echo "  - .txt, .doc, .pdf files should be encrypted"
    echo "  - .log, .tmp files should NOT be encrypted"
    echo "  - VFS hooks should intercept all operations"
    echo ""
}

# Main execution
main() {
    # Verify kernel module is loaded
    if [ ! -r /proc/takakrypt/status ]; then
        echo "Error: Takakrypt kernel module not loaded or not accessible"
        exit 1
    fi
    
    # Setup test directory
    mkdir -p /tmp/takakrypt-test
    chmod 777 /tmp/takakrypt-test
    
    echo "Initial kernel module statistics:"
    cat /proc/takakrypt/status | head -20
    echo ""
    
    # Show policy mapping
    test_policy_matching
    
    # Test each user
    echo "=== Individual User Testing ==="
    echo "You will be prompted for each user's password..."
    echo ""
    
    # Test ntoi (admin user)
    test_user_with_password "ntoi"
    
    # Test testuser1 (test user)
    test_user_with_password "testuser1"
    
    # Test testuser2 (test user)  
    test_user_with_password "testuser2"
    
    # Show final statistics
    echo "=== Final Results ==="
    cat /proc/takakrypt/status
    echo ""
    
    # Show kernel debug info
    show_kernel_debug
    
    echo "=== Test Summary ==="
    echo "Check the statistics above to verify:"
    echo "1. Each user's operations were intercepted by VFS hooks"
    echo "2. Policy engine correctly identified users by UID"
    echo "3. File types were properly classified for encryption"
    echo "4. User sets (admin_users, test_users, all_users) worked correctly"
    echo ""
    
    echo "Files created during test:"
    ls -la /tmp/takakrypt-test/ | grep -E "(ntoi|testuser1|testuser2)"
}

# Verify users exist
echo "Checking user accounts..."
for user in ntoi testuser1 testuser2; do
    if id "$user" >/dev/null 2>&1; then
        echo "  ✓ $user exists"
    else
        echo "  ✗ $user does not exist"
        echo "    Create with: sudo useradd -m $user && sudo passwd $user"
        exit 1
    fi
done
echo ""

# Run main test
main