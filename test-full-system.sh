#!/bin/bash
# Full system test for Takakrypt with kernel module and agent

set -e

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
CONFIG_FILE="configs/test-config.yaml"
TEST_DIR="/tmp/takakrypt-test"
MOUNT_DIR="/mnt/takakrypt-test"
AGENT_LOG="/tmp/takakrypt-agent.log"
AUDIT_LOG="/tmp/takakrypt-audit.log"

echo -e "${BLUE}=== Takakrypt Full System Test ===${NC}"
echo ""

# Check root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}Error: Run with sudo${NC}"
    exit 1
fi

# Step 1: Build everything
echo -e "${YELLOW}Step 1: Building components...${NC}"

# Build kernel modules
echo "Building kernel modules..."
cd kernel && make clean && make && cd ..
if [ -f "kernel/takakrypt.ko" ] && [ -f "kernel/takakryptfs/takakryptfs.ko" ]; then
    echo -e "${GREEN}✓ Kernel modules built${NC}"
else
    echo -e "${RED}Failed to build kernel modules${NC}"
    exit 1
fi

# Build agent
echo "Building agent..."
make build-agent
if [ -f "build/bin/takakrypt-agent" ]; then
    echo -e "${GREEN}✓ Agent built${NC}"
else
    echo -e "${RED}Failed to build agent${NC}"
    exit 1
fi
echo ""

# Step 2: Setup test users
echo -e "${YELLOW}Step 2: Setting up test users...${NC}"
for user in testuser1 testuser2; do
    if ! id -u $user >/dev/null 2>&1; then
        useradd -m $user
        echo "$user:password" | chpasswd
        echo "Created user: $user"
    fi
done
echo -e "${GREEN}✓ Test users ready${NC}"
echo ""

# Step 3: Load kernel modules
echo -e "${YELLOW}Step 3: Loading kernel modules...${NC}"

# Unload if already loaded
rmmod takakryptfs 2>/dev/null || true
rmmod takakrypt 2>/dev/null || true
sleep 1

# Load main module first
echo "Loading takakrypt.ko..."
insmod kernel/takakrypt.ko debug_level=1
if lsmod | grep -q takakrypt; then
    echo -e "${GREEN}✓ Main kernel module loaded${NC}"
else
    echo -e "${RED}Failed to load main kernel module${NC}"
    dmesg | tail -20
    exit 1
fi

# Load filesystem module
echo "Loading takakryptfs.ko..."
insmod kernel/takakryptfs/takakryptfs.ko
if lsmod | grep -q takakryptfs; then
    echo -e "${GREEN}✓ Filesystem module loaded${NC}"
else
    echo -e "${RED}Failed to load filesystem module${NC}"
    dmesg | tail -20
    exit 1
fi

# Verify proc interface
if [ -f "/proc/takakrypt/status" ]; then
    echo -e "${GREEN}✓ Proc interface available${NC}"
    cat /proc/takakrypt/status
else
    echo -e "${RED}Proc interface not found${NC}"
fi
echo ""

# Step 4: Start agent
echo -e "${YELLOW}Step 4: Starting agent...${NC}"

# Kill any existing agent
pkill -f takakrypt-agent || true
sleep 1

# Clear old logs
rm -f $AGENT_LOG $AUDIT_LOG

# Start agent
echo "Starting agent with debug logging..."
./build/bin/takakrypt-agent -config $CONFIG_FILE > $AGENT_LOG 2>&1 &
AGENT_PID=$!
sleep 3

if ps -p $AGENT_PID > /dev/null; then
    echo -e "${GREEN}✓ Agent running (PID: $AGENT_PID)${NC}"
    
    # Check if agent connected to kernel
    if cat /proc/takakrypt/status | grep -q "agent_connected.*1"; then
        echo -e "${GREEN}✓ Agent connected to kernel module${NC}"
    else
        echo -e "${YELLOW}⚠ Agent not yet connected to kernel${NC}"
    fi
else
    echo -e "${RED}Agent failed to start${NC}"
    echo "Last 50 lines of log:"
    tail -50 $AGENT_LOG
    exit 1
fi
echo ""

# Step 5: Create test directories
echo -e "${YELLOW}Step 5: Setting up test directories...${NC}"

# Create directories
mkdir -p $TEST_DIR
mkdir -p $MOUNT_DIR
chmod 755 $TEST_DIR $MOUNT_DIR

# Create lower directory for mount
mkdir -p ${TEST_DIR}_lower
echo -e "${GREEN}✓ Test directories created${NC}"
echo ""

# Step 6: Mount takakryptfs
echo -e "${YELLOW}Step 6: Mounting takakryptfs...${NC}"

# Mount the filesystem
echo "Mounting takakryptfs on $MOUNT_DIR..."
mount -t takakryptfs ${TEST_DIR}_lower $MOUNT_DIR -o policy=test_policy

if mount | grep -q takakryptfs; then
    echo -e "${GREEN}✓ Takakryptfs mounted successfully${NC}"
    mount | grep takakryptfs
else
    echo -e "${RED}Failed to mount takakryptfs${NC}"
    dmesg | tail -20
    exit 1
fi
echo ""

# Step 7: Test encryption
echo -e "${YELLOW}Step 7: Testing encryption on mounted filesystem...${NC}"

# Create test files in mounted directory
echo "Creating test files..."
echo "Admin secret data" > $MOUNT_DIR/admin-secret.txt
echo "Test document content" > $MOUNT_DIR/test-doc.txt
echo "Debug log - should not encrypt" > $MOUNT_DIR/debug.log

# Create files as different users
sudo -u testuser1 bash -c "echo 'User1 data' > $MOUNT_DIR/user1.txt"
sudo -u testuser2 bash -c "echo 'User2 data' > $MOUNT_DIR/user2.txt"

echo -e "${GREEN}✓ Test files created${NC}"
echo ""

# Step 8: Verify encryption
echo -e "${YELLOW}Step 8: Verifying encryption...${NC}"

# Function to check encryption
check_file() {
    local file=$1
    local lower_file="${TEST_DIR}_lower/$(basename $file)"
    
    echo -n "Checking $file: "
    
    # Check if lower file exists and is encrypted
    if [ -f "$lower_file" ]; then
        if hexdump -C "$lower_file" 2>/dev/null | head -1 | grep -q "54 41 4b 41"; then
            echo -e "${GREEN}✓ Encrypted (TAKA magic found in lower file)${NC}"
            # Show first few bytes
            echo "  Lower file header:"
            hexdump -C "$lower_file" | head -3 | sed 's/^/  /'
        else
            echo -e "${YELLOW}⚠ Not encrypted${NC}"
        fi
    else
        echo -e "${RED}✗ Lower file not found${NC}"
    fi
    
    # Try to read through mount point
    echo -n "  Read through mount: "
    if cat "$file" >/dev/null 2>&1; then
        echo -e "${GREEN}✓ Success${NC}"
        echo "  Content: $(cat $file | head -1)"
    else
        echo -e "${RED}✗ Failed${NC}"
    fi
    echo ""
}

# Check each file
for f in admin-secret.txt test-doc.txt user1.txt user2.txt debug.log; do
    check_file "$MOUNT_DIR/$f"
done

# Step 9: Test access control
echo -e "${YELLOW}Step 9: Testing access control...${NC}"

test_access() {
    local user=$1
    local file=$2
    local expect=$3
    
    echo -n "  $user accessing $(basename $file): "
    if sudo -u $user cat "$file" >/dev/null 2>&1; then
        if [ "$expect" = "allow" ]; then
            echo -e "${GREEN}✓ Allowed (expected)${NC}"
        else
            echo -e "${RED}✗ Allowed (should be denied)${NC}"
        fi
    else
        if [ "$expect" = "deny" ]; then
            echo -e "${GREEN}✓ Denied (expected)${NC}"
        else
            echo -e "${RED}✗ Denied (should be allowed)${NC}"
        fi
    fi
}

echo "Testing user access:"
test_access ntoi "$MOUNT_DIR/admin-secret.txt" allow
test_access testuser1 "$MOUNT_DIR/user1.txt" allow
test_access testuser1 "$MOUNT_DIR/user2.txt" allow  # Same user set
test_access nobody "$MOUNT_DIR/admin-secret.txt" deny
echo ""

# Step 10: Performance test
echo -e "${YELLOW}Step 10: Performance test...${NC}"

echo "Writing 10MB file..."
time dd if=/dev/zero of=$MOUNT_DIR/large.txt bs=1M count=10 2>&1 | grep -E "copied|records"

echo "Reading 10MB file..."
time dd if=$MOUNT_DIR/large.txt of=/dev/null 2>&1 | grep -E "copied|records"
echo ""

# Step 11: Show system status
echo -e "${YELLOW}Step 11: System status...${NC}"

echo "Kernel module statistics:"
cat /proc/takakrypt/status | head -20

echo ""
echo "Cache statistics:"
cat /proc/takakrypt/cache 2>/dev/null || echo "Cache info not available"

echo ""
echo "Active files:"
cat /proc/takakrypt/files 2>/dev/null || echo "No active files"

echo ""
echo "Recent agent logs:"
tail -20 $AGENT_LOG | grep -v "^$"
echo ""

# Step 12: Interactive
echo -e "${BLUE}=== System is running ===${NC}"
echo ""
echo "You can now test manually:"
echo "1. Create files: echo 'test' > $MOUNT_DIR/newfile.txt"
echo "2. Check encryption: hexdump -C ${TEST_DIR}_lower/newfile.txt | head"
echo "3. Monitor: watch -n 1 cat /proc/takakrypt/status"
echo "4. Logs: tail -f $AGENT_LOG"
echo ""
echo -e "${YELLOW}Press Ctrl+C to stop and cleanup${NC}"

# Cleanup function
cleanup() {
    echo ""
    echo -e "${YELLOW}Cleaning up...${NC}"
    
    # Unmount
    umount $MOUNT_DIR 2>/dev/null || true
    
    # Kill agent
    [ ! -z "$AGENT_PID" ] && kill $AGENT_PID 2>/dev/null || true
    
    # Unload modules
    rmmod takakryptfs 2>/dev/null || true
    rmmod takakrypt 2>/dev/null || true
    
    # Optional cleanup
    read -p "Remove test files? (y/N) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        rm -rf $TEST_DIR ${TEST_DIR}_lower $MOUNT_DIR
        rm -f $AGENT_LOG $AUDIT_LOG
    fi
    
    echo -e "${GREEN}Cleanup complete${NC}"
}

trap cleanup INT TERM EXIT

# Keep running
while true; do
    sleep 1
done