#!/bin/bash

# Test script for mount-based transparent encryption

set -e

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}=== Takakrypt Mount-Based Encryption Test ===${NC}"

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}Please run as root${NC}"
    exit 1
fi

# Configuration
MOUNT_POINT="/mnt/takakrypt-test"
LOWER_DIR="/tmp/takakrypt-lower"
TEST_FILE="test-encryption.txt"
TEST_DATA="This is sensitive data that should be encrypted automatically!"

# Clean up from previous runs
echo -e "${YELLOW}1. Cleaning up previous test environment...${NC}"
umount $MOUNT_POINT 2>/dev/null || true
rmmod takakryptfs 2>/dev/null || true
rmmod takakrypt 2>/dev/null || true
rm -rf $LOWER_DIR $MOUNT_POINT

# Create directories
echo -e "${YELLOW}2. Creating test directories...${NC}"
mkdir -p $LOWER_DIR $MOUNT_POINT

# Load kernel modules
echo -e "${YELLOW}3. Loading kernel modules...${NC}"
cd kernel
make
insmod takakrypt.ko debug_level=3
cd takakryptfs
make
insmod takakryptfs.ko
cd ../..

# Start the agent
echo -e "${YELLOW}4. Starting takakrypt agent...${NC}"
killall takakrypt-agent 2>/dev/null || true
./build/bin/takakrypt-agent -config configs/test.yaml &
AGENT_PID=$!
sleep 2

# Mount the filesystem
echo -e "${YELLOW}5. Mounting takakryptfs...${NC}"
mount -t takakryptfs -o lowerdir=$LOWER_DIR,policy=test_policy $LOWER_DIR $MOUNT_POINT

# Check mount
if ! mount | grep -q takakryptfs; then
    echo -e "${RED}ERROR: Failed to mount takakryptfs${NC}"
    kill $AGENT_PID 2>/dev/null || true
    exit 1
fi

echo -e "${GREEN}Successfully mounted takakryptfs at $MOUNT_POINT${NC}"

# Test encryption
echo -e "${YELLOW}6. Testing transparent encryption...${NC}"

# Write data to the mount point
echo -e "   Writing: '$TEST_DATA'"
echo "$TEST_DATA" > $MOUNT_POINT/$TEST_FILE

# Read data through the mount point (should be decrypted)
echo -e "   Reading through mount point:"
READ_DATA=$(cat $MOUNT_POINT/$TEST_FILE)
echo -e "   Got: '$READ_DATA'"

# Check if data matches
if [ "$READ_DATA" = "$TEST_DATA" ]; then
    echo -e "${GREEN}   ✓ Data read correctly through mount point${NC}"
else
    echo -e "${RED}   ✗ Data mismatch!${NC}"
fi

# Check the actual file in lower directory (should be encrypted)
echo -e "${YELLOW}7. Checking encrypted file in lower directory...${NC}"
if [ -f "$LOWER_DIR/$TEST_FILE" ]; then
    # Check for TAKA magic signature
    MAGIC=$(od -N 4 -t x1 $LOWER_DIR/$TEST_FILE | head -1 | awk '{print $2$3$4$5}')
    if [ "$MAGIC" = "54414b41" ]; then
        echo -e "${GREEN}   ✓ File is encrypted (TAKA magic found)${NC}"
        echo -e "   File size: $(stat -c%s $LOWER_DIR/$TEST_FILE) bytes"
        echo -e "   First 32 bytes (hex):"
        od -N 32 -t x1 $LOWER_DIR/$TEST_FILE
    else
        echo -e "${RED}   ✗ File is NOT encrypted (no TAKA magic)${NC}"
    fi
else
    echo -e "${RED}   ✗ File not found in lower directory${NC}"
fi

# Test multiple files
echo -e "${YELLOW}8. Testing multiple files...${NC}"
for i in {1..3}; do
    echo "Secret data $i" > $MOUNT_POINT/secret$i.txt
done

# List files
echo -e "   Files in mount point:"
ls -la $MOUNT_POINT/

# Cleanup
echo -e "${YELLOW}9. Cleaning up...${NC}"
umount $MOUNT_POINT
kill $AGENT_PID 2>/dev/null || true
rmmod takakryptfs
rmmod takakrypt

echo -e "${GREEN}=== Test completed ===${NC}"