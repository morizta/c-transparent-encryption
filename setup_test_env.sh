#!/bin/bash
# Setup test environment for Takakrypt

set -e

echo "=== Setting up Takakrypt Test Environment ==="

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

echo -e "${YELLOW}1. Creating guard point directories...${NC}"
# Create all guard point directories from test-config.yaml
mkdir -p /tmp/takakrypt-user-test
mkdir -p /home/ntoi/Private
mkdir -p /var/lib/mysql

# Set permissions
chmod 755 /tmp/takakrypt-user-test
chown ntoi:ntoi /home/ntoi/Private
chmod 700 /home/ntoi/Private

echo -e "${GREEN}✓ Guard point directories created${NC}"

echo -e "\n${YELLOW}2. Creating test users if they don't exist...${NC}"
# Create test users
if ! id testuser1 &>/dev/null; then
    useradd -m testuser1
    echo -e "${GREEN}✓ Created testuser1${NC}"
else
    echo "testuser1 already exists"
fi

if ! id testuser2 &>/dev/null; then
    useradd -m testuser2
    echo -e "${GREEN}✓ Created testuser2${NC}"
else
    echo "testuser2 already exists"
fi

# Add users to fuse group as per config
usermod -a -G fuse testuser1 2>/dev/null || true
usermod -a -G fuse testuser2 2>/dev/null || true

echo -e "\n${YELLOW}3. Creating resource set directories...${NC}"
# Create directories for resource sets
mkdir -p /admin-doc
mkdir -p /testuser1-doc
mkdir -p /testuser2-doc
mkdir -p /public

# Set ownership
chown ntoi:ntoi /admin-doc
chown testuser1:testuser1 /testuser1-doc
chown testuser2:testuser2 /testuser2-doc
chmod 755 /public

echo -e "${GREEN}✓ Resource directories created${NC}"

echo -e "\n${YELLOW}4. Verifying kernel module...${NC}"
if lsmod | grep -q takakrypt; then
    echo -e "${GREEN}✓ Kernel modules loaded${NC}"
else
    echo -e "${YELLOW}Loading kernel modules...${NC}"
    cd kernel && make load && cd ..
    sleep 2
fi

echo -e "\n${YELLOW}5. Starting agent with valid environment...${NC}"
# Kill any existing agent
pkill -f takakrypt-agent 2>/dev/null || true
sleep 1

# Start agent
./build/bin/takakrypt-agent -config configs/test-config.yaml > setup_test.log 2>&1 &
AGENT_PID=$!
sleep 3

# Check if agent started successfully
if ps -p $AGENT_PID > /dev/null; then
    echo -e "${GREEN}✓ Agent started successfully (PID: $AGENT_PID)${NC}"
    
    # Check for guard points
    if grep -q "Guard point configuration sent" setup_test.log; then
        echo -e "${GREEN}✓ Guard points configured${NC}"
    fi
else
    echo -e "${RED}✗ Agent failed to start${NC}"
    echo "Error log:"
    tail -20 setup_test.log
    exit 1
fi

echo -e "\n${YELLOW}6. Running basic encryption test...${NC}"
# Test encryption
TEST_FILE="/tmp/takakrypt-user-test/setup_test.txt"
echo "Testing encryption setup" | sudo -u ntoi tee "$TEST_FILE" > /dev/null

# Give time for encryption
sleep 2

# Check if encrypted
if xxd "$TEST_FILE" 2>/dev/null | head -n 1 | grep -q "TAKA"; then
    echo -e "${GREEN}✅ ENCRYPTION IS WORKING!${NC}"
else
    echo -e "${YELLOW}⚠ File not encrypted yet${NC}"
    # Check agent logs
    echo "Recent agent activity:"
    grep -E "(request|policy|encrypt)" setup_test.log | tail -5
fi

echo -e "\n${YELLOW}=== Setup Complete ===${NC}"
echo "Agent PID: $AGENT_PID"
echo "Log file: setup_test.log"
echo ""
echo "To stop the agent: sudo kill $AGENT_PID"
echo "To monitor logs: tail -f setup_test.log"
echo ""
echo "Next steps:"
echo "1. Run encryption tests: sudo ./test_encryption_flow.sh"
echo "2. Check kernel messages: sudo dmesg | grep takakrypt"
echo "3. View agent status: cat /proc/takakrypt/status"