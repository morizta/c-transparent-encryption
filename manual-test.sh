#!/bin/bash
# Manual test script for Takakrypt with test-config.yaml

set -e

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
CONFIG_FILE="configs/test-config.yaml"
TEST_DIR="/tmp/takakrypt-test"
AGENT_LOG="/tmp/takakrypt-agent.log"
AUDIT_LOG="/tmp/takakrypt-audit.log"

echo -e "${BLUE}=== Takakrypt Manual Test Script ===${NC}"
echo "Using configuration: $CONFIG_FILE"
echo ""

# Step 1: Check prerequisites
echo -e "${YELLOW}Step 1: Checking prerequisites...${NC}"

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}Error: This script must be run as root (sudo)${NC}"
    exit 1
fi

# Check if test users exist
if ! id -u testuser1 >/dev/null 2>&1; then
    echo -e "${YELLOW}Creating testuser1...${NC}"
    useradd -m testuser1
fi

if ! id -u testuser2 >/dev/null 2>&1; then
    echo -e "${YELLOW}Creating testuser2...${NC}"
    useradd -m testuser2
fi

# Check if Go agent is built
if [ ! -f "build/bin/takakrypt-agent" ]; then
    echo -e "${YELLOW}Building Takakrypt agent...${NC}"
    make build-agent
fi

echo -e "${GREEN}Prerequisites OK${NC}"
echo ""

# Step 2: Setup test environment
echo -e "${YELLOW}Step 2: Setting up test environment...${NC}"

# Create test directory
mkdir -p $TEST_DIR
chmod 755 $TEST_DIR

# Create user private directories
mkdir -p /home/ntoi/Private
mkdir -p /home/testuser1/Private
mkdir -p /home/testuser2/Private
chown ntoi:ntoi /home/ntoi/Private
chown testuser1:testuser1 /home/testuser1/Private
chown testuser2:testuser2 /home/testuser2/Private

# Clean up old logs
rm -f $AGENT_LOG $AUDIT_LOG

echo -e "${GREEN}Test environment ready${NC}"
echo ""

# Step 3: Check kernel module
echo -e "${YELLOW}Step 3: Checking kernel module...${NC}"

if lsmod | grep -q takakrypt; then
    echo "Kernel module already loaded"
else
    echo "Loading kernel module..."
    cd kernel && make load && cd ..
fi

# Verify kernel module
if [ -f "/proc/takakrypt/status" ]; then
    echo -e "${GREEN}Kernel module loaded successfully${NC}"
    echo "Module status:"
    cat /proc/takakrypt/status | head -10
else
    echo -e "${RED}Warning: Kernel module not loaded properly${NC}"
    echo "Continuing with user-space testing only..."
fi
echo ""

# Step 4: Start the agent
echo -e "${YELLOW}Step 4: Starting Takakrypt agent...${NC}"

# Kill any existing agent
pkill -f takakrypt-agent || true
sleep 1

# Start agent in background
echo "Starting agent with config: $CONFIG_FILE"
./build/bin/takakrypt-agent -config $CONFIG_FILE > $AGENT_LOG 2>&1 &
AGENT_PID=$!

# Wait for agent to start
sleep 2

# Check if agent is running
if ps -p $AGENT_PID > /dev/null; then
    echo -e "${GREEN}Agent started successfully (PID: $AGENT_PID)${NC}"
else
    echo -e "${RED}Failed to start agent!${NC}"
    echo "Last 20 lines of agent log:"
    tail -20 $AGENT_LOG
    exit 1
fi
echo ""

# Step 5: Create test files
echo -e "${YELLOW}Step 5: Creating test files...${NC}"

# Create files as different users
echo "Creating files in $TEST_DIR..."
echo "Secret document by ntoi" > $TEST_DIR/admin-secret.txt
chown ntoi:ntoi $TEST_DIR/admin-secret.txt

sudo -u testuser1 bash -c "echo 'TestUser1 confidential data' > $TEST_DIR/user1-data.txt"
sudo -u testuser2 bash -c "echo 'TestUser2 private information' > $TEST_DIR/user2-data.txt"

# Create files that should NOT be encrypted
echo "Debug log information" > $TEST_DIR/debug.log
echo "Temporary file" > $TEST_DIR/temp.tmp

# Create files in user private directories
sudo -u ntoi bash -c "echo 'Admin private document' > /home/ntoi/Private/private.txt"
sudo -u testuser1 bash -c "echo 'User1 private file' > /home/testuser1/Private/personal.txt"

echo -e "${GREEN}Test files created${NC}"
echo ""

# Step 6: Test encryption
echo -e "${YELLOW}Step 6: Testing encryption...${NC}"

# Function to check if file is encrypted
check_encrypted() {
    local file=$1
    if hexdump -C "$file" 2>/dev/null | head -1 | grep -q "54 41 4b 41"; then
        echo -e "${GREEN}✓ $file is encrypted (TAKA magic found)${NC}"
        return 0
    else
        echo -e "${RED}✗ $file is NOT encrypted${NC}"
        return 1
    fi
}

# Wait a moment for encryption to happen
sleep 2

# Check encryption status
echo "Checking encryption status..."
check_encrypted "$TEST_DIR/admin-secret.txt"
check_encrypted "$TEST_DIR/user1-data.txt"
check_encrypted "$TEST_DIR/user2-data.txt"
check_encrypted "$TEST_DIR/debug.log" || true  # Should NOT be encrypted
check_encrypted "$TEST_DIR/temp.tmp" || true   # Should NOT be encrypted
echo ""

# Step 7: Test access control
echo -e "${YELLOW}Step 7: Testing access control...${NC}"

# Test reading files as different users
echo "Testing file access:"

# ntoi should be able to read all files
echo -n "ntoi reading admin-secret.txt: "
if sudo -u ntoi cat $TEST_DIR/admin-secret.txt >/dev/null 2>&1; then
    echo -e "${GREEN}✓ Success${NC}"
else
    echo -e "${RED}✗ Failed${NC}"
fi

# testuser1 reading their own file
echo -n "testuser1 reading user1-data.txt: "
if sudo -u testuser1 cat $TEST_DIR/user1-data.txt >/dev/null 2>&1; then
    echo -e "${GREEN}✓ Success${NC}"
else
    echo -e "${RED}✗ Failed${NC}"
fi

# testuser1 reading testuser2's file
echo -n "testuser1 reading user2-data.txt: "
if sudo -u testuser1 cat $TEST_DIR/user2-data.txt >/dev/null 2>&1; then
    echo -e "${GREEN}✓ Success${NC}"
else
    echo -e "${RED}✗ Failed${NC}"
fi

# Unknown user trying to read files
echo -n "nobody reading admin-secret.txt: "
if sudo -u nobody cat $TEST_DIR/admin-secret.txt >/dev/null 2>&1; then
    echo -e "${RED}✗ Unexpected success (should fail)${NC}"
else
    echo -e "${GREEN}✓ Correctly denied${NC}"
fi
echo ""

# Step 8: Show logs
echo -e "${YELLOW}Step 8: Recent log entries...${NC}"

echo "Agent log (last 10 lines):"
tail -10 $AGENT_LOG | grep -v "^$"
echo ""

if [ -f "$AUDIT_LOG" ]; then
    echo "Audit log (last 10 lines):"
    tail -10 $AUDIT_LOG | grep -v "^$"
else
    echo "No audit log found yet"
fi
echo ""

# Step 9: Interactive testing
echo -e "${YELLOW}Step 9: Interactive testing${NC}"
echo "The system is now running. You can test manually:"
echo ""
echo "1. Create new files in $TEST_DIR:"
echo "   echo 'test' > $TEST_DIR/newfile.txt"
echo ""
echo "2. Check encryption:"
echo "   hexdump -C $TEST_DIR/newfile.txt | head -5"
echo ""
echo "3. Test as different users:"
echo "   sudo -u testuser1 cat $TEST_DIR/newfile.txt"
echo ""
echo "4. Monitor logs:"
echo "   tail -f $AGENT_LOG"
echo ""
echo "5. Check kernel module status:"
echo "   cat /proc/takakrypt/status"
echo ""
echo -e "${BLUE}Press Ctrl+C to stop the test and cleanup${NC}"

# Trap to cleanup on exit
cleanup() {
    echo ""
    echo -e "${YELLOW}Cleaning up...${NC}"
    
    # Kill agent
    if [ ! -z "$AGENT_PID" ] && ps -p $AGENT_PID > /dev/null; then
        echo "Stopping agent..."
        kill $AGENT_PID 2>/dev/null || true
        sleep 1
        kill -9 $AGENT_PID 2>/dev/null || true
    fi
    
    # Optional: Remove test files
    read -p "Remove test files? (y/N) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        rm -rf $TEST_DIR
        rm -f $AGENT_LOG $AUDIT_LOG
        echo "Test files removed"
    fi
    
    echo -e "${GREEN}Cleanup complete${NC}"
    exit 0
}

trap cleanup INT TERM

# Keep script running
while true; do
    sleep 1
done