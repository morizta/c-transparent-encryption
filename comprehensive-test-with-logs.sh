#!/bin/bash

# Comprehensive Takakrypt Test with Full Logging
# All output captured to logs for analysis

set -e

# Configuration
LOG_DIR="/tmp/takakrypt-test-logs"
MAIN_LOG="$LOG_DIR/main-test.log"
KERNEL_LOG="$LOG_DIR/kernel-messages.log"
AGENT_LOG="$LOG_DIR/agent.log"
STATUS_LOG="$LOG_DIR/status-snapshots.log"
VFS_LOG="$LOG_DIR/vfs-operations.log"
ERROR_LOG="$LOG_DIR/errors.log"

# Test directories
TEST_DIR="/tmp/takakrypt-user-test"
TEST_DIR2="/tmp/takakrypt-test"
PRIVATE_DIR="/home/ntoi/Private"
MARIADB_DIR="/tmp/mariadb-test"

# Colors for console output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Setup logging
setup_logging() {
    mkdir -p "$LOG_DIR"
    rm -f "$LOG_DIR"/*.log
    
    echo "=== Takakrypt Comprehensive Test Started at $(date) ===" | tee "$MAIN_LOG"
    echo "Log directory: $LOG_DIR" | tee -a "$MAIN_LOG"
    echo "Password: Primasys2012" > "$LOG_DIR/auth.txt"
    echo "" | tee -a "$MAIN_LOG"
}

# Log function
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1" | tee -a "$MAIN_LOG"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1" | tee -a "$MAIN_LOG"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a "$MAIN_LOG" | tee -a "$ERROR_LOG"
}

log_step() {
    echo -e "${BLUE}[STEP $1]${NC} $2" | tee -a "$MAIN_LOG"
}

# Capture kernel messages
capture_kernel_messages() {
    echo "=== Kernel Messages at $(date) ===" >> "$KERNEL_LOG"
    echo "Primasys2012" | sudo -S dmesg | grep -i takakrypt >> "$KERNEL_LOG" 2>/dev/null || echo "No takakrypt messages" >> "$KERNEL_LOG"
    echo "" >> "$KERNEL_LOG"
}

# Capture system status
capture_status() {
    local step="$1"
    echo "=== Status Snapshot: $step at $(date) ===" >> "$STATUS_LOG"
    
    # Kernel module status
    echo "--- Kernel Module ---" >> "$STATUS_LOG"
    echo "Primasys2012" | sudo -S lsmod | grep takakrypt >> "$STATUS_LOG" 2>/dev/null || echo "Module not loaded" >> "$STATUS_LOG"
    
    # Process status
    echo "--- Agent Processes ---" >> "$STATUS_LOG"
    ps aux | grep takakrypt | grep -v grep >> "$STATUS_LOG" 2>/dev/null || echo "No agent processes" >> "$STATUS_LOG"
    
    # Proc interface
    echo "--- Proc Interface ---" >> "$STATUS_LOG"
    if [ -d /proc/takakrypt ]; then
        echo "Primasys2012" | sudo -S cat /proc/takakrypt/status >> "$STATUS_LOG" 2>/dev/null || echo "Cannot read status" >> "$STATUS_LOG"
    else
        echo "Proc interface not available" >> "$STATUS_LOG"
    fi
    
    echo "" >> "$STATUS_LOG"
}

# Step 1: Check initial system state
test_initial_state() {
    log_step 1 "Checking Initial System State"
    
    capture_kernel_messages
    capture_status "Initial"
    
    # Check if kernel module is loaded
    if echo "Primasys2012" | sudo -S lsmod | grep -q takakrypt; then
        log_info "Kernel module already loaded"
    else
        log_warn "Kernel module not loaded"
    fi
    
    # Check for running agents
    if pgrep -f takakrypt-agent > /dev/null; then
        log_info "Agent processes already running"
        echo "Primasys2012" | sudo -S pkill takakrypt-agent
        log_info "Killed existing agents"
    fi
}

# Step 2: Load kernel module
test_load_kernel() {
    log_step 2 "Loading Kernel Module"
    
    if [ -f kernel/takakrypt.ko ]; then
        echo "Primasys2012" | sudo -S insmod kernel/takakrypt.ko >> "$MAIN_LOG" 2>&1
        if [ $? -eq 0 ]; then
            log_info "Kernel module loaded successfully"
        else
            log_error "Failed to load kernel module"
            echo "Primasys2012" | sudo -S dmesg | tail -5 >> "$ERROR_LOG"
        fi
    else
        log_error "Kernel module not found: kernel/takakrypt.ko"
        return 1
    fi
    
    capture_kernel_messages
    capture_status "After kernel load"
}

# Step 3: Setup test directories
test_setup_directories() {
    log_step 3 "Setting Up Test Directories"
    
    mkdir -p "$TEST_DIR" "$TEST_DIR2" "$PRIVATE_DIR" "$MARIADB_DIR" >> "$MAIN_LOG" 2>&1
    log_info "Created test directories"
    
    # List directory permissions
    echo "=== Directory Permissions ===" >> "$MAIN_LOG"
    ls -la "$TEST_DIR" "$TEST_DIR2" "$PRIVATE_DIR" "$MARIADB_DIR" >> "$MAIN_LOG" 2>&1
}

# Step 4: Start agent
test_start_agent() {
    log_step 4 "Starting Takakrypt Agent"
    
    if [ -f build/bin/takakrypt-agent ]; then
        # Start agent in background with output to log
        echo "Primasys2012" | sudo -S build/bin/takakrypt-agent --config configs/test-config.yaml --log-level debug > "$AGENT_LOG" 2>&1 &
        AGENT_PID=$!
        echo "Agent PID: $AGENT_PID" >> "$MAIN_LOG"
        
        # Wait for agent to start
        sleep 5
        
        if ps -p $AGENT_PID > /dev/null; then
            log_info "Agent started with PID $AGENT_PID"
        else
            log_error "Agent failed to start"
            cat "$AGENT_LOG" >> "$ERROR_LOG"
        fi
    else
        log_error "Agent binary not found: build/bin/takakrypt-agent"
        return 1
    fi
    
    capture_status "After agent start"
}

# Step 5: Test VFS hooks with various file operations
test_vfs_hooks() {
    log_step 5 "Testing VFS Hooks"
    
    echo "=== VFS Hook Tests ===" >> "$VFS_LOG"
    
    # Test 1: Simple file write
    echo "--- Test 1: Simple write to $TEST_DIR2 ---" >> "$VFS_LOG"
    echo "Test data for VFS hooks" > "$TEST_DIR2/vfs-test.txt" 2>> "$VFS_LOG"
    
    # Check if file was intercepted
    if [ -f "$TEST_DIR2/vfs-test.txt" ]; then
        file "$TEST_DIR2/vfs-test.txt" >> "$VFS_LOG"
        head -c 20 "$TEST_DIR2/vfs-test.txt" | xxd >> "$VFS_LOG"
    fi
    
    # Test 2: Write as root
    echo "--- Test 2: Root write ---" >> "$VFS_LOG"
    echo "Primasys2012" | sudo -S sh -c "echo 'Root test data' > $TEST_DIR2/root-test.txt" 2>> "$VFS_LOG"
    
    # Test 3: Different file types
    echo "--- Test 3: Different file types ---" >> "$VFS_LOG"
    echo "Document content" > "$TEST_DIR2/test.doc" 2>> "$VFS_LOG"
    echo "Text content" > "$TEST_DIR2/test.txt" 2>> "$VFS_LOG"
    echo "Log content" > "$TEST_DIR2/test.log" 2>> "$VFS_LOG"
    
    # Test 4: Direct syscall test
    echo "--- Test 4: Direct syscall test ---" >> "$VFS_LOG"
    if [ -f ./test-write ]; then
        echo "Primasys2012" | sudo -S ./test-write >> "$VFS_LOG" 2>&1
    fi
    
    # Capture kernel messages after VFS tests
    capture_kernel_messages
    
    # Check all created files
    echo "--- File Analysis ---" >> "$VFS_LOG"
    for file in "$TEST_DIR2"/*; do
        if [ -f "$file" ]; then
            echo "File: $file" >> "$VFS_LOG"
            file "$file" >> "$VFS_LOG"
            ls -la "$file" >> "$VFS_LOG"
            echo "First 50 bytes:" >> "$VFS_LOG"
            head -c 50 "$file" | xxd >> "$VFS_LOG"
            echo "" >> "$VFS_LOG"
        fi
    done
}

# Step 6: Test agent communication
test_agent_communication() {
    log_step 6 "Testing Agent Communication"
    
    echo "=== Agent Communication Tests ===" >> "$VFS_LOG"
    
    # Test netlink connection
    if [ -f ./test-netlink ]; then
        echo "--- Netlink Test ---" >> "$VFS_LOG"
        echo "Primasys2012" | sudo -S ./test-netlink >> "$VFS_LOG" 2>&1
    fi
    
    # Test direct encryption
    if [ -f ./test-encryption ]; then
        echo "--- Encryption Test ---" >> "$VFS_LOG"
        echo "Primasys2012" | sudo -S ./test-encryption >> "$VFS_LOG" 2>&1
    fi
    
    capture_status "After communication tests"
}

# Step 7: Test policy evaluation
test_policy_evaluation() {
    log_step 7 "Testing Policy Evaluation"
    
    echo "=== Policy Evaluation Tests ===" >> "$VFS_LOG"
    
    # Create files in different guard point directories
    echo "Policy test in user test dir" > "$TEST_DIR/policy-test.txt"
    echo "Policy test in private dir" > "$PRIVATE_DIR/private-test.txt" 2>/dev/null || log_warn "Cannot write to private dir"
    echo "Database file simulation" > "$MARIADB_DIR/test.ibd"
    
    # Check if any files got encrypted
    for dir in "$TEST_DIR" "$PRIVATE_DIR" "$MARIADB_DIR"; do
        if [ -d "$dir" ]; then
            echo "--- Directory: $dir ---" >> "$VFS_LOG"
            for file in "$dir"/*; do
                if [ -f "$file" ]; then
                    echo "File: $file" >> "$VFS_LOG"
                    file "$file" >> "$VFS_LOG"
                    head -c 10 "$file" | xxd >> "$VFS_LOG"
                fi
            done
        fi
    done
    
    capture_kernel_messages
}

# Step 8: Performance and statistics
test_performance() {
    log_step 8 "Collecting Performance Data"
    
    echo "=== Performance Statistics ===" >> "$STATUS_LOG"
    
    # Get final status
    capture_status "Final"
    
    # Get cache statistics
    if [ -f /proc/takakrypt/cache ]; then
        echo "--- Cache Statistics ---" >> "$STATUS_LOG"
        echo "Primasys2012" | sudo -S cat /proc/takakrypt/cache >> "$STATUS_LOG" 2>/dev/null
    fi
    
    # Get file contexts
    if [ -f /proc/takakrypt/files ]; then
        echo "--- File Contexts ---" >> "$STATUS_LOG"
        echo "Primasys2012" | sudo -S cat /proc/takakrypt/files >> "$STATUS_LOG" 2>/dev/null
    fi
}

# Step 9: Cleanup and summary
test_cleanup() {
    log_step 9 "Cleanup and Summary"
    
    # Kill agent
    if [ -n "$AGENT_PID" ] && ps -p $AGENT_PID > /dev/null; then
        echo "Primasys2012" | sudo -S kill $AGENT_PID
        log_info "Agent stopped"
    fi
    
    # Capture final kernel messages
    capture_kernel_messages
    
    # Create summary
    echo "=== TEST SUMMARY ===" >> "$MAIN_LOG"
    echo "Test completed at $(date)" >> "$MAIN_LOG"
    echo "Logs available in: $LOG_DIR" >> "$MAIN_LOG"
    echo "- Main log: $MAIN_LOG" >> "$MAIN_LOG"
    echo "- Kernel messages: $KERNEL_LOG" >> "$MAIN_LOG"
    echo "- Agent log: $AGENT_LOG" >> "$MAIN_LOG"
    echo "- Status snapshots: $STATUS_LOG" >> "$MAIN_LOG"
    echo "- VFS operations: $VFS_LOG" >> "$MAIN_LOG"
    echo "- Errors: $ERROR_LOG" >> "$MAIN_LOG"
    
    # Log file sizes
    echo "--- Log file sizes ---" >> "$MAIN_LOG"
    ls -lh "$LOG_DIR"/*.log >> "$MAIN_LOG"
    
    log_info "All logs saved to $LOG_DIR"
    log_info "Test completed. Logs ready for analysis."
}

# Main execution
main() {
    setup_logging
    
    test_initial_state
    test_load_kernel
    test_setup_directories
    test_start_agent
    test_vfs_hooks
    test_agent_communication
    test_policy_evaluation
    test_performance
    test_cleanup
    
    echo ""
    echo -e "${GREEN}=== TEST COMPLETE ===${NC}"
    echo "All output logged to: $LOG_DIR"
    echo "Main log: $MAIN_LOG"
    echo ""
    echo "Run the following to analyze results:"
    echo "  cat $MAIN_LOG"
    echo "  cat $VFS_LOG"
    echo "  cat $STATUS_LOG"
}

# Run main function
main "$@"