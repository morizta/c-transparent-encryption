#!/bin/bash
# Debug script for guard point path matching

set -e

echo "=== Debugging Guard Point Path Matching ==="

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

echo -e "${YELLOW}1. Enabling maximum debug logging...${NC}"
echo 4 > /sys/module/takakrypt/parameters/debug_level

echo -e "\n${YELLOW}2. Testing exact guard point path...${NC}"
TEST_PATH="/tmp/takakrypt-user-test"
mkdir -p "$TEST_PATH"

echo "Writing to: $TEST_PATH/debug.txt"
echo "guard point test" > "$TEST_PATH/debug.txt"

echo -e "\n${YELLOW}3. Checking kernel messages for this file...${NC}"
sleep 1
dmesg | tail -30 | grep -E "(debug.txt|should_intercept|guard.*point|intercept.*tmp)" || echo "No debug messages found"

echo -e "\n${YELLOW}4. Testing direct strstr logic...${NC}"
# Create a simple test to verify path matching logic
cat << 'EOF' > /tmp/path_test.c
#include <stdio.h>
#include <string.h>

int main() {
    char guard_path[] = "/tmp/takakrypt-user-test";
    char file_path[] = "/tmp/takakrypt-user-test/debug.txt";
    
    printf("Guard path: %s\n", guard_path);
    printf("File path: %s\n", file_path);
    
    if (strstr(file_path, guard_path) != NULL) {
        printf("MATCH: strstr found guard path in file path\n");
        return 0;
    } else {
        printf("NO MATCH: strstr did not find guard path in file path\n");
        return 1;
    }
}
EOF

gcc -o /tmp/path_test /tmp/path_test.c
echo "C strstr test result:"
/tmp/path_test

echo -e "\n${YELLOW}5. Forcing kernel debug output...${NC}"
# Try different paths to see what gets intercepted
for path in "/tmp/test.txt" "/var/tmp/test.txt" "/home/ntoi/test.txt"; do
    echo -e "\nTesting: $path"
    echo "test" > "$path"
    sleep 0.5
    
    # Check for intercept messages
    if dmesg | tail -10 | grep -q "should_intercept"; then
        echo -e "${GREEN}Found should_intercept message${NC}"
        dmesg | tail -10 | grep "should_intercept"
    else
        echo "No should_intercept debug found"
    fi
done

echo -e "\n${YELLOW}6. Checking if guard points are loaded in kernel...${NC}"
# Look for guard point configuration messages
dmesg | grep -E "(Received.*guard|Guard point.*name=|guard point configuration)" | tail -10

echo -e "\n${YELLOW}7. Verifying agent is processing requests...${NC}"
if ps aux | grep -q "[t]akakrypt-agent"; then
    echo "Agent is running"
    
    # Check agent stats
    if [ -f setup_test.log ]; then
        echo "Recent agent stats:"
        tail -5 setup_test.log | grep "statistics"
    fi
else
    echo -e "${RED}Agent is not running!${NC}"
fi

echo -e "\n${YELLOW}8. Manual kernel function test...${NC}"
# Check if we can trigger debug output by writing to specific files
echo "Creating test file in exact guard point path..."
echo "manual test" > "/tmp/takakrypt-user-test/manual.txt"

# Wait and check for kernel messages
sleep 1
echo "Recent kernel debug messages:"
dmesg | tail -20 | grep -E "(takakrypt|debug)" | grep -v "vfs_read intercepted" | tail -10

echo -e "\n${YELLOW}=== Debug Summary ===${NC}"
echo "1. Check if 'should_intercept' debug messages appear"
echo "2. Verify guard points are loaded with correct paths"  
echo "3. Confirm C strstr logic works as expected"
echo ""
echo "Cleanup:"
rm -f /tmp/path_test /tmp/path_test.c