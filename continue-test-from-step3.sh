#!/bin/bash

# Continue test from step 3 - module already loaded
set -e

LOG_DIR="/tmp/takakrypt-test-logs"
MAIN_LOG="$LOG_DIR/main-test.log"
AGENT_LOG="$LOG_DIR/agent.log"
VFS_LOG="$LOG_DIR/vfs-operations.log"
STATUS_LOG="$LOG_DIR/status-snapshots.log"
KERNEL_LOG="$LOG_DIR/kernel-messages.log"

# Test directories
TEST_DIR="/tmp/takakrypt-user-test"
TEST_DIR2="/tmp/takakrypt-test"
PRIVATE_DIR="/home/ntoi/Private"
MARIADB_DIR="/tmp/mariadb-test"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1" | tee -a "$MAIN_LOG"
}

log_step() {
    echo -e "${BLUE}[STEP $1]${NC} $2" | tee -a "$MAIN_LOG"
}

capture_status() {
    local step="$1"
    echo "=== Status Snapshot: $step at $(date) ===" >> "$STATUS_LOG"
    echo "Primasys2012" | sudo -S cat /proc/takakrypt/status >> "$STATUS_LOG" 2>/dev/null
    echo "" >> "$STATUS_LOG"
}

capture_kernel_messages() {
    echo "=== Kernel Messages at $(date) ===" >> "$KERNEL_LOG"
    echo "Primasys2012" | sudo -S dmesg | grep -i takakrypt >> "$KERNEL_LOG" 2>/dev/null
    echo "" >> "$KERNEL_LOG"
}

echo "Continuing test from step 3..." | tee -a "$MAIN_LOG"

# Step 3: Setup test directories
log_step 3 "Setting Up Test Directories"
mkdir -p "$TEST_DIR" "$TEST_DIR2" "$PRIVATE_DIR" "$MARIADB_DIR"
log_info "Created test directories"

# Step 4: Start agent (kill any existing first)
log_step 4 "Starting Fresh Agent"
echo "Primasys2012" | sudo -S pkill takakrypt-agent || true
sleep 2

echo "Primasys2012" | sudo -S build/bin/takakrypt-agent --config configs/test-config.yaml --log-level debug > "$AGENT_LOG" 2>&1 &
AGENT_PID=$!
echo "Agent PID: $AGENT_PID" | tee -a "$MAIN_LOG"

sleep 5
capture_status "After agent restart"

# Step 5: Test VFS hooks
log_step 5 "Testing VFS Hooks"
echo "=== VFS Hook Tests at $(date) ===" >> "$VFS_LOG"

# Create files in the monitored directories
echo "Test 1: Writing to $TEST_DIR2" | tee -a "$VFS_LOG"
echo "This should trigger VFS hooks" > "$TEST_DIR2/hook-test.txt"
file "$TEST_DIR2/hook-test.txt" >> "$VFS_LOG"

echo "Test 2: Writing different file types" | tee -a "$VFS_LOG"
echo "Document data" > "$TEST_DIR2/test.doc" 
echo "Text data" > "$TEST_DIR2/test.txt"
echo "Log data" > "$TEST_DIR2/test.log"

# Analyze created files
echo "--- File Analysis ---" >> "$VFS_LOG"
for f in "$TEST_DIR2"/*; do
    if [ -f "$f" ]; then
        echo "File: $f" >> "$VFS_LOG"
        file "$f" >> "$VFS_LOG"
        ls -la "$f" >> "$VFS_LOG"
        echo "First 20 bytes (hex):" >> "$VFS_LOG"
        head -c 20 "$f" | xxd >> "$VFS_LOG"
        echo "First 20 bytes (text):" >> "$VFS_LOG"
        head -c 20 "$f" >> "$VFS_LOG"
        echo "" >> "$VFS_LOG"
    fi
done

capture_kernel_messages
capture_status "After VFS tests"

# Step 6: Test with existing test programs
log_step 6 "Running Built-in Tests"

if [ -f ./test-write ]; then
    echo "=== test-write output ===" >> "$VFS_LOG"
    echo "Primasys2012" | sudo -S ./test-write >> "$VFS_LOG" 2>&1
    
    # Check the file it created
    if [ -f /tmp/takakrypt-test/write-test.txt ]; then
        echo "--- test-write file analysis ---" >> "$VFS_LOG"
        file /tmp/takakrypt-test/write-test.txt >> "$VFS_LOG"
        head -c 50 /tmp/takakrypt-test/write-test.txt | xxd >> "$VFS_LOG"
    fi
fi

if [ -f ./test-encryption ]; then
    echo "=== test-encryption output ===" >> "$VFS_LOG"
    echo "Primasys2012" | sudo -S ./test-encryption >> "$VFS_LOG" 2>&1
fi

capture_kernel_messages
capture_status "After built-in tests"

# Step 7: Check cache and file contexts
log_step 7 "Analyzing Cache and Contexts"

echo "=== Cache Analysis ===" >> "$VFS_LOG"
if [ -f /proc/takakrypt/cache ]; then
    echo "Primasys2012" | sudo -S cat /proc/takakrypt/cache >> "$VFS_LOG" 2>/dev/null
fi

echo "=== File Contexts ===" >> "$VFS_LOG"
if [ -f /proc/takakrypt/files ]; then
    echo "Primasys2012" | sudo -S cat /proc/takakrypt/files >> "$VFS_LOG" 2>/dev/null
fi

echo "=== Config ===" >> "$VFS_LOG"
if [ -f /proc/takakrypt/config ]; then
    echo "Primasys2012" | sudo -S cat /proc/takakrypt/config >> "$VFS_LOG" 2>/dev/null
fi

capture_status "Final status"

# Summary
log_step 8 "Test Summary"
echo "=== FINAL SUMMARY ===" | tee -a "$MAIN_LOG"
echo "Test completed at $(date)" | tee -a "$MAIN_LOG"
echo "" | tee -a "$MAIN_LOG"
echo "Key findings from logs:" | tee -a "$MAIN_LOG"

# Show final status
echo "Final system status:" | tee -a "$MAIN_LOG"
echo "Primasys2012" | sudo -S cat /proc/takakrypt/status | tee -a "$MAIN_LOG"

echo "" | tee -a "$MAIN_LOG"
echo "Logs available for analysis:" | tee -a "$MAIN_LOG"
echo "- Main: $MAIN_LOG" | tee -a "$MAIN_LOG"
echo "- VFS operations: $VFS_LOG" | tee -a "$MAIN_LOG"
echo "- Status snapshots: $STATUS_LOG" | tee -a "$MAIN_LOG"
echo "- Agent output: $AGENT_LOG" | tee -a "$MAIN_LOG"
echo "- Kernel messages: $KERNEL_LOG" | tee -a "$MAIN_LOG"

log_info "Test completed - all logs ready for analysis"