#!/bin/bash

# Test User Access Control for Takakrypt
# Tests different users against the policy engine

echo "=== Takakrypt User Access Control Test ==="
echo "Testing users: ntoi (admin), testuser1, testuser2 (test users)"
echo ""

# Check if test users exist
echo "1. Checking test user accounts..."
for user in ntoi testuser1 testuser2; do
    if id "$user" >/dev/null 2>&1; then
        uid=$(id -u "$user")
        groups=$(id -G "$user" | tr ' ' ',')
        echo "  ✓ $user (UID: $uid, Groups: $groups)"
    else
        echo "  ✗ $user does not exist"
        echo "    To create: sudo useradd -m $user"
    fi
done
echo ""

# Function to test file access for a user
test_user_access() {
    local username=$1
    local test_file="/tmp/takakrypt-test/${username}-test.txt"
    
    echo "Testing $username..."
    
    # Record stats before test
    local before_processed=$(cat /proc/takakrypt/status | grep "Total Processed:" | awk '{print $3}')
    
    if id "$username" >/dev/null 2>&1; then
        # Test as the specific user
        echo "  Creating file as $username: $test_file"
        sudo -u "$username" bash -c "echo 'Test data for $username' > '$test_file'" 2>/dev/null
        
        if [ -f "$test_file" ]; then
            echo "  ✓ File created successfully"
            
            # Test reading the file
            echo "  Reading file as $username..."
            content=$(sudo -u "$username" cat "$test_file" 2>/dev/null)
            if [ "$content" = "Test data for $username" ]; then
                echo "  ✓ File read successfully: '$content'"
            else
                echo "  ✗ File read failed or content mismatch"
            fi
            
            # Check file permissions and ownership
            local file_info=$(ls -la "$test_file")
            echo "  File info: $file_info"
        else
            echo "  ✗ File creation failed (might be denied by policy)"
        fi
    else
        echo "  ✗ User $username does not exist - skipping test"
    fi
    
    # Record stats after test
    local after_processed=$(cat /proc/takakrypt/status | grep "Total Processed:" | awk '{print $3}')
    local operations=$((after_processed - before_processed))
    echo "  VFS operations intercepted: $operations"
    echo ""
}

# Function to check kernel module statistics
show_stats() {
    echo "Current Takakrypt Statistics:"
    cat /proc/takakrypt/status | head -25
    echo ""
}

# Function to test cross-user access
test_cross_user_access() {
    echo "4. Testing cross-user file access..."
    
    # Create file as ntoi, try to access as testuser1
    local ntoi_file="/tmp/takakrypt-test/ntoi-private.txt"
    echo "  Creating private file as ntoi..."
    echo "This is ntoi's private data" > "$ntoi_file"
    chmod 600 "$ntoi_file"  # Only ntoi can read/write
    
    echo "  Attempting to read ntoi's file as testuser1..."
    if id testuser1 >/dev/null 2>&1; then
        local result=$(sudo -u testuser1 cat "$ntoi_file" 2>&1)
        if echo "$result" | grep -q "Permission denied"; then
            echo "  ✓ Access properly denied by file system permissions"
        else
            echo "  ! Access allowed or other result: $result"
        fi
    else
        echo "  ✗ testuser1 does not exist"
    fi
    echo ""
}

# Function to test different file types
test_file_types() {
    echo "5. Testing different file types (policy should only encrypt .txt, .doc, .pdf)..."
    
    local user="ntoi"
    if id "$user" >/dev/null 2>&1; then
        # Test encrypted file types
        for ext in txt doc pdf; do
            local file="/tmp/takakrypt-test/test.$ext"
            echo "  Testing .$ext file..."
            sudo -u "$user" bash -c "echo 'Data for .$ext file' > '$file'"
            if [ -f "$file" ]; then
                echo "    ✓ .$ext file created (should be encrypted)"
            fi
        done
        
        # Test non-encrypted file types
        for ext in log tmp json; do
            local file="/tmp/takakrypt-test/test.$ext"
            echo "  Testing .$ext file..."
            sudo -u "$user" bash -c "echo 'Data for .$ext file' > '$file'"
            if [ -f "$file" ]; then
                echo "    ✓ .$ext file created (should NOT be encrypted)"
            fi
        done
    fi
    echo ""
}

# Function to simulate different UIDs
test_uid_access() {
    echo "6. Testing UID-based access (current implementation)..."
    echo "  Note: Current kernel module sees all operations as current process UID"
    echo "  Real UID detection would require VFS hooks to extract file->f_cred->uid"
    
    # Show current process info that kernel module would see
    echo "  Current process UID: $(id -u)"
    echo "  Current process GID: $(id -g)"
    echo "  Current process name: $(ps -o comm= -p $$)"
    echo ""
}

# Main test execution
main() {
    echo "Starting user access control tests..."
    echo "Test directory: /tmp/takakrypt-test"
    echo ""
    
    # Ensure test directory exists and is accessible
    mkdir -p /tmp/takakrypt-test
    chmod 755 /tmp/takakrypt-test
    
    # Show initial statistics
    echo "0. Initial Statistics:"
    show_stats
    
    # Test each user
    echo "2. Testing individual user access..."
    test_user_access "ntoi"
    test_user_access "testuser1" 
    test_user_access "testuser2"
    
    # Show updated statistics
    echo "3. Updated Statistics:"
    show_stats
    
    # Test cross-user access
    test_cross_user_access
    
    # Test file types
    test_file_types
    
    # Test UID detection
    test_uid_access
    
    echo "=== Test Summary ==="
    echo "Check the statistics above to verify:"
    echo "1. VFS operations were intercepted for each user"
    echo "2. Policy checks were performed" 
    echo "3. Different users triggered different policy evaluations"
    echo ""
    echo "Final Statistics:"
    show_stats
}

# Check if script is run with proper permissions
if [ ! -r /proc/takakrypt/status ]; then
    echo "Error: Cannot read /proc/takakrypt/status"
    echo "Make sure the takakrypt kernel module is loaded"
    exit 1
fi

# Run main test
main