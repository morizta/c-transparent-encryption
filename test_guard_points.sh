#!/bin/bash
# Test script to debug guard point issues

set -e

echo "=== Takakrypt Guard Point Debug Test ==="

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

echo -e "${YELLOW}1. Checking kernel module proc entries...${NC}"
if [ -f /proc/takakrypt/status ]; then
    echo -e "${GREEN}✓ Found /proc/takakrypt/status:${NC}"
    cat /proc/takakrypt/status
else
    echo -e "${RED}✗ No /proc/takakrypt/status found${NC}"
fi

echo -e "\n${YELLOW}2. Checking guard points in kernel...${NC}"
if [ -f /proc/takakrypt/guard_points ]; then
    echo -e "${GREEN}✓ Guard points loaded:${NC}"
    cat /proc/takakrypt/guard_points
else
    echo -e "${YELLOW}No /proc/takakrypt/guard_points found${NC}"
fi

echo -e "\n${YELLOW}3. Starting agent with debug logging...${NC}"
# Kill any existing agent
pkill -f takakrypt-agent 2>/dev/null || true
sleep 1

# Start agent with debug output
echo "Starting agent..."
./build/bin/takakrypt-agent -config configs/test-config.yaml > guard_point_test.log 2>&1 &
AGENT_PID=$!
sleep 3

echo -e "\n${YELLOW}4. Checking agent guard point configuration...${NC}"
grep -E "(guard|Guard)" guard_point_test.log | head -10 || echo "No guard point logs found"

echo -e "\n${YELLOW}5. Testing write operations with detailed kernel logging...${NC}"
# Enable debug logging if possible
echo 4 > /sys/module/takakrypt/parameters/debug_level 2>/dev/null || true

# Test different paths
TEST_PATHS=(
    "/tmp/takakrypt-user-test/test1.txt"
    "/tmp/test2.txt"
    "/home/ntoi/Private/test3.txt"
)

for path in "${TEST_PATHS[@]}"; do
    echo -e "\n${YELLOW}Testing path: $path${NC}"
    # Create directory if needed
    mkdir -p $(dirname "$path")
    
    # Write test file
    echo "test data" > "$path"
    
    # Check kernel log for this specific file
    dmesg | tail -20 | grep -i "$(basename $path)" || echo "No kernel messages for $(basename $path)"
    
    # Check if encrypted
    if xxd "$path" 2>/dev/null | head -n 1 | grep -q "TAKA"; then
        echo -e "${GREEN}✓ File encrypted${NC}"
    else
        echo -e "${RED}✗ File NOT encrypted${NC}"
    fi
done

echo -e "\n${YELLOW}6. Checking kernel debug messages...${NC}"
dmesg | tail -50 | grep -E "(guard|Guard|intercept|should_intercept)" || echo "No guard point messages"

echo -e "\n${YELLOW}7. Cleanup...${NC}"
kill $AGENT_PID 2>/dev/null || true

echo -e "\n${YELLOW}=== Debug Summary ===${NC}"
echo "1. Check if guard points are properly sent to kernel"
echo "2. Verify path matching logic in kernel"
echo "3. Review agent log: cat guard_point_test.log"
echo "4. Check kernel messages: dmesg | grep takakrypt"