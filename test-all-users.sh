#!/bin/bash

# Comprehensive User Access Test using sudo
SUDO_PASS="Primasys2012"

echo "=== Takakrypt User Access Test (All Users) ==="
echo ""

# Function to test a user
test_user() {
    local username=$1
    local uid=$(id -u "$username" 2>/dev/null)
    
    echo "Testing user: $username (UID: $uid)"
    
    # Get stats before
    local before_processed=$(cat /proc/takakrypt/status | grep "Total Processed:" | awk '{print $3}')
    
    # Test different file types
    echo "  Creating files as $username..."
    
    # Encrypted file types (.txt, .doc, .pdf)
    echo "$SUDO_PASS" | sudo -S -u "$username" bash -c "
        echo 'Confidential data from $username' > /tmp/takakrypt-test/${username}-confidential.txt
        echo 'Document from $username' > /tmp/takakrypt-test/${username}-document.doc  
        echo 'PDF content from $username' > /tmp/takakrypt-test/${username}-report.pdf
    " 2>/dev/null
    
    # Non-encrypted file types (.log, .tmp)
    echo "$SUDO_PASS" | sudo -S -u "$username" bash -c "
        echo 'Log entry from $username' > /tmp/takakrypt-test/${username}-debug.log
        echo 'Temp data from $username' > /tmp/takakrypt-test/${username}-temp.tmp
    " 2>/dev/null
    
    # Read files back
    echo "  Reading files as $username..."
    echo "$SUDO_PASS" | sudo -S -u "$username" bash -c "
        cat /tmp/takakrypt-test/${username}-confidential.txt > /dev/null 2>&1
        cat /tmp/takakrypt-test/${username}-document.doc > /dev/null 2>&1
        cat /tmp/takakrypt-test/${username}-debug.log > /dev/null 2>&1
    " 2>/dev/null
    
    # Get stats after
    local after_processed=$(cat /proc/takakrypt/status | grep "Total Processed:" | awk '{print $3}')
    local operations=$((after_processed - before_processed))
    
    echo "  Results for $username:"
    echo "    VFS operations intercepted: $operations"
    
    # Show created files
    echo "    Files created:"
    ls -la /tmp/takakrypt-test/ | grep "^-.*$username" | while read line; do
        echo "      $line"
    done
    
    echo ""
}

# Function to analyze policy mapping
analyze_policy_mapping() {
    echo "=== Policy Analysis ==="
    echo "Based on config file:"
    echo "  admin_users (ntoi): Can access test_policy"  
    echo "  test_users (testuser1, testuser2): Can access test_policy"
    echo "  all_users (everyone): Can access user_policy"
    echo ""
    echo "Guard point '/tmp/takakrypt-test' uses 'test_policy'"
    echo "Expected: All users should have access since test_policy allows admin_users OR test_users"
    echo ""
}

# Function to test cross-user access
test_cross_user_access() {
    echo "=== Cross-User Access Test ==="
    
    # Create file as ntoi
    echo "Creating file as ntoi..."
    echo "ntoi's private data" > /tmp/takakrypt-test/ntoi-private.txt
    chown ntoi:ntoi /tmp/takakrypt-test/ntoi-private.txt
    chmod 600 /tmp/takakrypt-test/ntoi-private.txt
    
    # Try to access as testuser1
    echo "Attempting to access ntoi's file as testuser1..."
    local result=$(echo "$SUDO_PASS" | sudo -S -u testuser1 cat /tmp/takakrypt-test/ntoi-private.txt 2>&1)
    if echo "$result" | grep -q "Permission denied"; then
        echo "  ✓ File system correctly denied access"
    elif echo "$result" | grep -q "ntoi's private data"; then
        echo "  ! testuser1 can read ntoi's file (unexpected)"
    else
        echo "  ? Unexpected result: $result"
    fi
    
    echo ""
}

# Main execution
main() {
    # Setup
    mkdir -p /tmp/takakrypt-test
    chmod 777 /tmp/takakrypt-test
    
    echo "Initial statistics:"
    cat /proc/takakrypt/status | head -20
    echo ""
    
    # Analyze policy
    analyze_policy_mapping
    
    # Test each user
    echo "=== Individual User Tests ==="
    test_user "ntoi"
    test_user "testuser1" 
    test_user "testuser2"
    
    # Cross-user access test
    test_cross_user_access
    
    # Final statistics
    echo "=== Final Statistics ==="
    cat /proc/takakrypt/status
    echo ""
    
    # Summary
    echo "=== Summary ==="
    echo "Files created by each user:"
    echo ""
    echo "ntoi files:"
    ls -la /tmp/takakrypt-test/ | grep "ntoi" | head -5
    echo ""
    echo "testuser1 files:"
    ls -la /tmp/takakrypt-test/ | grep "testuser1" | head -5  
    echo ""
    echo "testuser2 files:"
    ls -la /tmp/takakrypt-test/ | grep "testuser2" | head -5
    echo ""
    
    echo "User Access Control Test Complete!"
}

# Run the test
main