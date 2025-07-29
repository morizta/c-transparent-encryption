#!/bin/bash
# Test script to verify kernel-agent communication

set -e

echo "=== Takakrypt Kernel-Agent Communication Test ==="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
   echo -e "${RED}Please run as root (sudo)${NC}"
   exit 1
fi

echo -e "${YELLOW}1. Checking kernel module status...${NC}"
if lsmod | grep -q takakrypt; then
    echo -e "${GREEN}✓ Kernel modules loaded:${NC}"
    lsmod | grep takakrypt
else
    echo -e "${RED}✗ Kernel modules not loaded${NC}"
    echo "Loading kernel modules..."
    cd kernel && make load && cd ..
    sleep 2
fi

echo -e "\n${YELLOW}2. Checking for existing agent process...${NC}"
if pgrep -f takakrypt-agent > /dev/null; then
    echo -e "${YELLOW}Found existing agent process, stopping it...${NC}"
    pkill -f takakrypt-agent || true
    sleep 2
fi

echo -e "\n${YELLOW}3. Starting agent with test configuration...${NC}"
if [ ! -f "configs/test-config.yaml" ]; then
    echo -e "${RED}✗ Test configuration not found${NC}"
    exit 1
fi

# Start agent in background with logging
echo "Starting agent..."
./build/bin/takakrypt-agent -config configs/test-config.yaml > agent_test.log 2>&1 &
AGENT_PID=$!

# Give agent time to start
sleep 3

echo -e "\n${YELLOW}4. Verifying agent is running...${NC}"
if ps -p $AGENT_PID > /dev/null; then
    echo -e "${GREEN}✓ Agent running with PID: $AGENT_PID${NC}"
    
    # Check agent log for connection status
    if grep -q "Connected to kernel module" agent_test.log 2>/dev/null; then
        echo -e "${GREEN}✓ Agent connected to kernel module${NC}"
    elif grep -q "netlink" agent_test.log 2>/dev/null; then
        echo -e "${YELLOW}Agent log contains netlink messages:${NC}"
        grep "netlink" agent_test.log | head -5
    else
        echo -e "${YELLOW}Recent agent log:${NC}"
        tail -10 agent_test.log
    fi
else
    echo -e "${RED}✗ Agent failed to start${NC}"
    echo "Agent error log:"
    cat agent_test.log
    exit 1
fi

echo -e "\n${YELLOW}5. Testing kernel-agent communication...${NC}"
# Create test directory and file
TEST_DIR="/tmp/takakrypt_test_$$"
mkdir -p $TEST_DIR

# Write a test file (this should trigger kernel hooks)
echo "Test data for encryption" > $TEST_DIR/test.txt

# Check if any netlink messages were logged
sleep 2
if grep -q "Received.*request" agent_test.log 2>/dev/null; then
    echo -e "${GREEN}✓ Kernel-agent communication detected${NC}"
    echo "Recent communication log:"
    grep -E "(Received|Sending|request|response)" agent_test.log | tail -10
else
    echo -e "${YELLOW}No communication detected yet${NC}"
fi

echo -e "\n${YELLOW}6. Checking kernel workqueue...${NC}"
if ps aux | grep -q "\[takakrypt_wq\]"; then
    echo -e "${GREEN}✓ Kernel workqueue is running${NC}"
fi

echo -e "\n${YELLOW}7. Cleanup...${NC}"
# Stop agent
kill $AGENT_PID 2>/dev/null || true
rm -rf $TEST_DIR

echo -e "\n${YELLOW}=== Test Summary ===${NC}"
echo "Agent log saved to: agent_test.log"
echo "To view full log: cat agent_test.log"
echo ""
echo "Next steps:"
echo "1. Check if guard points are configured correctly in test-config.yaml"
echo "2. Ensure test directories match guard point paths"
echo "3. Review agent log for any connection errors"