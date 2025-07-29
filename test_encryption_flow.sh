#!/bin/bash
# Test script for end-to-end encryption flow

set -e

echo "=== Takakrypt End-to-End Encryption Test ==="

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

# Test configuration
GUARD_POINT="/tmp/takakrypt-user-test"
TEST_USER="ntoi"  # Using actual system user from config
TEST_FILE="secret_document.txt"
TEST_CONTENT="This is highly confidential information that should be encrypted!"

echo -e "${YELLOW}1. Setting up test environment...${NC}"
# Create guard point directory
mkdir -p "$GUARD_POINT"
chown $TEST_USER:$TEST_USER "$GUARD_POINT"
echo -e "${GREEN}✓ Created guard point: $GUARD_POINT${NC}"

echo -e "\n${YELLOW}2. Starting Takakrypt agent...${NC}"
# Kill any existing agent
pkill -f takakrypt-agent 2>/dev/null || true
sleep 1

# Start agent in background
./build/bin/takakrypt-agent -config configs/test-config.yaml > encryption_test.log 2>&1 &
AGENT_PID=$!
sleep 3

# Verify agent is running
if ps -p $AGENT_PID > /dev/null; then
    echo -e "${GREEN}✓ Agent running with PID: $AGENT_PID${NC}"
else
    echo -e "${RED}✗ Agent failed to start${NC}"
    cat encryption_test.log
    exit 1
fi

echo -e "\n${YELLOW}3. Testing file encryption on write...${NC}"
# Write a file as the test user - should trigger encryption
sudo -u $TEST_USER bash -c "echo '$TEST_CONTENT' > '$GUARD_POINT/$TEST_FILE'"
echo -e "${GREEN}✓ File written: $GUARD_POINT/$TEST_FILE${NC}"

# Give kernel time to process
sleep 2

echo -e "\n${YELLOW}4. Checking if file is encrypted on disk...${NC}"
# Read raw file content to check for encryption
if xxd "$GUARD_POINT/$TEST_FILE" | head -n 5 | grep -q "TAKA"; then
    echo -e "${GREEN}✓ File is encrypted! Found TAKA header:${NC}"
    xxd "$GUARD_POINT/$TEST_FILE" | head -n 5
else
    echo -e "${YELLOW}⚠ File might not be encrypted. Raw content:${NC}"
    xxd "$GUARD_POINT/$TEST_FILE" | head -n 5
fi

echo -e "\n${YELLOW}5. Testing transparent decryption on read...${NC}"
# Read file as authorized user - should decrypt transparently
DECRYPTED_CONTENT=$(sudo -u $TEST_USER cat "$GUARD_POINT/$TEST_FILE")
echo "Decrypted content: $DECRYPTED_CONTENT"

if [ "$DECRYPTED_CONTENT" = "$TEST_CONTENT" ]; then
    echo -e "${GREEN}✓ Transparent decryption successful!${NC}"
else
    echo -e "${RED}✗ Decryption failed or content mismatch${NC}"
    echo "Expected: $TEST_CONTENT"
    echo "Got: $DECRYPTED_CONTENT"
fi

echo -e "\n${YELLOW}6. Checking agent logs for encryption activity...${NC}"
if grep -E "(encryption|decrypt|policy|request)" encryption_test.log | tail -10; then
    echo -e "${GREEN}✓ Found encryption activity in logs${NC}"
else
    echo -e "${YELLOW}Recent agent log:${NC}"
    tail -20 encryption_test.log
fi

echo -e "\n${YELLOW}7. Testing multiple file operations...${NC}"
# Test multiple files
for i in {1..3}; do
    FILE="test_file_$i.txt"
    sudo -u $TEST_USER bash -c "echo 'Test data $i' > '$GUARD_POINT/$FILE'"
    echo -e "Created: $FILE"
done

# Check if all are encrypted
ENCRYPTED_COUNT=0
for i in {1..3}; do
    FILE="test_file_$i.txt"
    if xxd "$GUARD_POINT/$FILE" 2>/dev/null | head -n 1 | grep -q "TAKA"; then
        ((ENCRYPTED_COUNT++))
    fi
done
echo -e "${GREEN}✓ Encrypted $ENCRYPTED_COUNT out of 3 files${NC}"

echo -e "\n${YELLOW}8. Testing append operation...${NC}"
# Test append to encrypted file
sudo -u $TEST_USER bash -c "echo 'Additional secret data' >> '$GUARD_POINT/$TEST_FILE'"
APPENDED_CONTENT=$(sudo -u $TEST_USER cat "$GUARD_POINT/$TEST_FILE")
echo "Content after append: $APPENDED_CONTENT"

echo -e "\n${YELLOW}9. Cleanup...${NC}"
# Stop agent
kill $AGENT_PID 2>/dev/null || true
wait $AGENT_PID 2>/dev/null || true
echo -e "${GREEN}✓ Agent stopped${NC}"

# Clean up test files but preserve logs
rm -rf "$GUARD_POINT"

echo -e "\n${YELLOW}=== Test Summary ===${NC}"
echo "Agent log saved to: encryption_test.log"
echo "To view detailed logs: cat encryption_test.log | grep -E '(encryption|decrypt|policy)'"
echo ""

# Final check
if [ "$DECRYPTED_CONTENT" = "$TEST_CONTENT" ]; then
    echo -e "${GREEN}✅ ENCRYPTION TEST PASSED${NC}"
    exit 0
else
    echo -e "${RED}❌ ENCRYPTION TEST FAILED${NC}"
    echo "Check logs for details"
    exit 1
fi