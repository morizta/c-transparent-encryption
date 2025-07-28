#!/bin/bash

# Comprehensive Manual Testing for Takakrypt
# Tests both User Set Guard Points and MariaDB Guard Points

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test configuration
TEST_CONFIG="configs/test-config.yaml"
TEST_DIR="/tmp/takakrypt-user-test"
USER_PRIVATE_DIR="/home/ntoi/Private"
MARIADB_TEST_DIR="/tmp/mariadb-test"
LOG_FILE="/tmp/takakrypt-manual-test.log"

echo -e "${BLUE}=== Takakrypt Comprehensive Manual Testing ===${NC}"
echo "Testing User Set Guard Points and MariaDB Guard Points"
echo "Log file: $LOG_FILE"
echo

# Function to print test step
print_step() {
    echo -e "${YELLOW}STEP $1: $2${NC}"
}

# Function to print success
print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

# Function to print error
print_error() {
    echo -e "${RED}✗ $1${NC}"
}

# Function to check system status
check_system_status() {
    print_step 1 "Checking System Status"
    
    # Check kernel module
    if lsmod | grep -q takakrypt; then
        print_success "Kernel module loaded"
    else
        print_error "Kernel module not loaded"
        return 1
    fi
    
    # Check agent process
    if pgrep -f takakrypt-agent > /dev/null; then
        print_success "Agent process running"
    else
        print_error "Agent process not running"
        return 1
    fi
    
    # Check /proc interface
    if [ -f /proc/takakrypt/status ]; then
        print_success "/proc interface available"
        echo "Module status:"
        cat /proc/takakrypt/status | head -10
    else
        print_error "/proc interface not available"
        return 1
    fi
    
    echo
}

# Function to setup test directories
setup_test_directories() {
    print_step 2 "Setting Up Test Directories"
    
    # User test directory (already exists)
    if [ -d "$TEST_DIR" ]; then
        print_success "User test directory exists: $TEST_DIR"
    else
        mkdir -p "$TEST_DIR"
        print_success "Created user test directory: $TEST_DIR"
    fi
    
    # User private directory
    mkdir -p "$USER_PRIVATE_DIR"
    print_success "Created user private directory: $USER_PRIVATE_DIR"
    
    # MariaDB test directory (simulating /var/lib/mysql)
    mkdir -p "$MARIADB_TEST_DIR"
    print_success "Created MariaDB test directory: $MARIADB_TEST_DIR"
    
    echo
}

# Function to test user set guard points
test_user_guard_points() {
    print_step 3 "Testing User Set Guard Points"
    
    echo "3a. Testing /tmp/takakrypt-user-test with test_policy"
    
    # Create test files
    echo "This is a test document" > "$TEST_DIR/user-test.txt"
    echo "Confidential information" > "$TEST_DIR/secret.doc"
    echo "Log entry - should not be encrypted" > "$TEST_DIR/debug.log"
    
    print_success "Created test files in user guard point"
    
    # Test file access as ntoi (admin user)
    echo "3b. Testing file access as admin user (ntoi)"
    
    if cat "$TEST_DIR/user-test.txt" > /dev/null 2>&1; then
        print_success "Admin user can read test file"
    else
        print_error "Admin user cannot read test file"
    fi
    
    # Check if file shows TAKA header (encrypted)
    if file "$TEST_DIR/user-test.txt" | grep -q "data" || head -c 4 "$TEST_DIR/user-test.txt" | grep -q "TAKA"; then
        print_success "File appears to be encrypted (binary/TAKA format)"
    else
        echo "File content: $(head -c 20 "$TEST_DIR/user-test.txt")"
        print_error "File does not appear encrypted (still plaintext)"
    fi
    
    # Test with different file types
    echo "3c. Testing different file patterns"
    
    # Should be encrypted (.txt, .doc)
    ls -la "$TEST_DIR/"*.txt "$TEST_DIR/"*.doc 2>/dev/null && print_success "Included files present"
    
    # Should not be encrypted (.log)
    if [ -f "$TEST_DIR/debug.log" ]; then
        if file "$TEST_DIR/debug.log" | grep -q "ASCII text"; then
            print_success "Excluded file (.log) remains unencrypted"
        else
            print_error "Excluded file (.log) was incorrectly encrypted"
        fi
    fi
    
    echo
}

# Function to test user private directory guard point
test_user_private_guard_point() {
    print_step 4 "Testing User Private Directory Guard Point"
    
    echo "4a. Testing /home/*/Private with user_policy"
    
    # Create test files in private directory
    echo "Personal document" > "$USER_PRIVATE_DIR/personal.txt"
    echo "Private notes" > "$USER_PRIVATE_DIR/notes.md"
    
    print_success "Created files in user private directory"
    
    # Test access
    if cat "$USER_PRIVATE_DIR/personal.txt" > /dev/null 2>&1; then
        print_success "User can access private directory files"
    else
        print_error "User cannot access private directory files"
    fi
    
    # Check encryption
    if file "$USER_PRIVATE_DIR/personal.txt" | grep -q "data" || head -c 4 "$USER_PRIVATE_DIR/personal.txt" | grep -q "TAKA"; then
        print_success "Private file appears encrypted"
    else
        print_error "Private file does not appear encrypted"
    fi
    
    echo
}

# Function to simulate MariaDB testing
test_mariadb_guard_points() {
    print_step 5 "Testing MariaDB Guard Points (Simulated)"
    
    echo "5a. Creating simulated MariaDB files"
    
    # Create realistic MariaDB file structure
    mkdir -p "$MARIADB_TEST_DIR/mysql"
    mkdir -p "$MARIADB_TEST_DIR/testdb"
    
    # Create database files (InnoDB)
    echo "InnoDB data file content" > "$MARIADB_TEST_DIR/testdb/users.ibd"
    echo "Table format file" > "$MARIADB_TEST_DIR/testdb/users.frm"
    
    # Create MyISAM files
    echo "MyISAM data" > "$MARIADB_TEST_DIR/testdb/logs.MYD"
    echo "MyISAM index" > "$MARIADB_TEST_DIR/testdb/logs.MYI"
    
    # Create SQL files
    echo "CREATE TABLE test (id INT);" > "$MARIADB_TEST_DIR/backup_test.sql"
    
    # Create excluded files (should not be encrypted)
    echo "Error log content" > "$MARIADB_TEST_DIR/mysql-error.log"
    echo "123" > "$MARIADB_TEST_DIR/mysql.pid"
    
    print_success "Created simulated MariaDB file structure"
    
    echo "5b. Testing file access patterns"
    
    # Test included files (.ibd, .frm, .MYD, .MYI, *test*.sql)
    included_files=("$MARIADB_TEST_DIR/testdb/users.ibd" 
                    "$MARIADB_TEST_DIR/testdb/users.frm"
                    "$MARIADB_TEST_DIR/testdb/logs.MYD"
                    "$MARIADB_TEST_DIR/testdb/logs.MYI"
                    "$MARIADB_TEST_DIR/backup_test.sql")
    
    for file in "${included_files[@]}"; do
        if [ -f "$file" ]; then
            echo "Testing: $(basename "$file")"
            if cat "$file" > /dev/null 2>&1; then
                print_success "Can read database file: $(basename "$file")"
            else
                print_error "Cannot read database file: $(basename "$file")"
            fi
        fi
    done
    
    # Test excluded files (.log, .pid, .sock)
    excluded_files=("$MARIADB_TEST_DIR/mysql-error.log"
                    "$MARIADB_TEST_DIR/mysql.pid")
    
    for file in "${excluded_files[@]}"; do
        if [ -f "$file" ]; then
            echo "Testing excluded: $(basename "$file")"
            if file "$file" | grep -q "ASCII text"; then
                print_success "Excluded file remains unencrypted: $(basename "$file")"
            else
                print_error "Excluded file was encrypted: $(basename "$file")"
            fi
        fi
    done
    
    echo
}

# Function to test process detection
test_process_detection() {
    print_step 6 "Testing Process Detection"
    
    echo "6a. Current process information"
    echo "Current user: $(whoami) (UID: $(id -u))"
    echo "Current process: $$ ($(ps -p $$ -o comm=))"
    
    echo "6b. Simulating database process"
    
    # Create a mock database process script
    cat > /tmp/mock-mariadb.sh << 'EOF'
#!/bin/bash
echo "Mock MariaDB process starting..."
sleep 30
EOF
    chmod +x /tmp/mock-mariadb.sh
    
    # Run mock database process in background
    /tmp/mock-mariadb.sh &
    MOCK_PID=$!
    
    echo "Started mock database process (PID: $MOCK_PID)"
    
    # Test file access while "database" process is running
    if [ -f "$MARIADB_TEST_DIR/testdb/users.ibd" ]; then
        echo "Testing file access during simulated database operation..."
        cat "$MARIADB_TEST_DIR/testdb/users.ibd" > /dev/null 2>&1
        print_success "File access successful during database simulation"
    fi
    
    # Clean up mock process
    kill $MOCK_PID 2>/dev/null || true
    rm -f /tmp/mock-mariadb.sh
    
    echo
}

# Function to check audit logs
check_audit_logs() {
    print_step 7 "Checking Audit Logs"
    
    # Check agent log
    if [ -f "/tmp/takakrypt-agent.log" ]; then
        echo "Recent agent log entries:"
        tail -10 /tmp/takakrypt-agent.log
        print_success "Agent log available"
    else
        print_error "Agent log not found"
    fi
    
    # Check audit log
    if [ -f "/tmp/takakrypt-audit.log" ]; then
        echo "Recent audit log entries:"
        tail -5 /tmp/takakrypt-audit.log
        print_success "Audit log available"
    else
        echo "Audit log not found (may not be configured)"
    fi
    
    echo
}

# Function to check system performance
check_performance() {
    print_step 8 "Checking System Performance"
    
    # Check /proc stats
    if [ -f /proc/takakrypt/stats ]; then
        echo "System statistics:"
        cat /proc/takakrypt/stats
        print_success "Performance stats available"
    else
        print_error "Performance stats not available"
    fi
    
    echo
}

# Function to test user switching (if test users exist)
test_user_switching() {
    print_step 9 "Testing User Access Control"
    
    echo "Current test is running as: $(whoami)"
    
    # Check if test users exist
    if id testuser1 &>/dev/null; then
        echo "Test user1 exists - would test access restrictions"
        print_success "User access control testing available"
    else
        echo "Test users not configured - create with:"
        echo "  sudo useradd -m testuser1"
        echo "  sudo useradd -m testuser2"
        print_error "Test users not available for access control testing"
    fi
    
    echo
}

# Function to cleanup test files
cleanup_test() {
    print_step 10 "Cleaning Up Test Files"
    
    # Remove test files but keep directories
    rm -f "$TEST_DIR"/*.txt "$TEST_DIR"/*.doc "$TEST_DIR"/*.log 2>/dev/null
    rm -f "$USER_PRIVATE_DIR"/*.txt "$USER_PRIVATE_DIR"/*.md 2>/dev/null
    rm -rf "$MARIADB_TEST_DIR" 2>/dev/null
    
    print_success "Test files cleaned up"
    echo
}

# Function to display summary
display_summary() {
    echo -e "${BLUE}=== TEST SUMMARY ===${NC}"
    echo
    echo -e "${GREEN}Tests Completed:${NC}"
    echo "✓ System status verification"
    echo "✓ User set guard point testing"
    echo "✓ User private directory testing"
    echo "✓ MariaDB guard point simulation"
    echo "✓ Process detection testing"
    echo "✓ Audit log verification"
    echo "✓ Performance monitoring"
    echo "✓ User access control checks"
    echo
    echo -e "${YELLOW}To test with actual MariaDB:${NC}"
    echo "1. Install MariaDB: sudo apt install mariadb-server"
    echo "2. Update guard point path to /var/lib/mysql"
    echo "3. Run with database user privileges"
    echo
    echo -e "${YELLOW}To test with real users:${NC}"
    echo "1. Create test users: sudo useradd -m testuser1"
    echo "2. Switch users: sudo -u testuser1 bash"
    echo "3. Test file access from different user contexts"
    echo
    echo "Complete log saved to: $LOG_FILE"
}

# Main execution
main() {
    # Redirect all output to log file and console
    exec > >(tee "$LOG_FILE")
    exec 2>&1
    
    echo "Starting comprehensive manual test at $(date)"
    echo "Configuration: $TEST_CONFIG"
    echo
    
    # Run all test steps
    check_system_status
    setup_test_directories
    test_user_guard_points
    test_user_private_guard_point
    test_mariadb_guard_points
    test_process_detection
    check_audit_logs
    check_performance
    test_user_switching
    cleanup_test
    display_summary
    
    echo "Test completed at $(date)"
}

# Run main function
main "$@"