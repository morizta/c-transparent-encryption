#!/bin/bash

echo "=== Takakrypt Manual Operations Validation ==="
echo "Testing procedures from MANUAL_OPERATIONS_GUIDE.md"
echo ""

# Test 1: Check build status
echo "1. Checking Build Status:"
echo "   Agent binary: $(ls -la build/bin/takakrypt-agent 2>/dev/null | awk '{print $9, $5, "bytes"}' || echo 'NOT FOUND')"
echo "   Kernel module: $(ls -la kernel/takakrypt.ko 2>/dev/null | awk '{print $9, $5, "bytes"}' || echo 'NOT FOUND')"
echo "   Test configs: $(ls -la configs/test-config.yaml 2>/dev/null | awk '{print $9}' || echo 'NOT FOUND')"
echo ""

# Test 2: Agent status check (without sudo)
echo "2. Checking Current Agent Status:"
AGENT_RUNNING=$(ps aux | grep takakrypt-agent | grep -v grep | head -1)
if [ -n "$AGENT_RUNNING" ]; then
    echo "   ✅ Agent is running: $AGENT_RUNNING"
else
    echo "   ❌ No agent running"
fi
echo ""

# Test 3: File operations test
echo "3. Testing File Operations:"
TEST_DIR="/tmp/takakrypt-user-test"
mkdir -p "$TEST_DIR"

# Test write operations
echo "   Writing test files..."
echo "Test data from $(whoami) at $(date)" > "$TEST_DIR/manual-test.txt"
echo "Log entry from $(whoami) at $(date)" > "$TEST_DIR/manual-test.log"
echo "Document content from $(whoami)" > "$TEST_DIR/manual-test.doc"

# Test read operations
echo "   Reading test files:"
echo "     .txt file: $(cat $TEST_DIR/manual-test.txt | head -c 50)..."
echo "     .log file: $(cat $TEST_DIR/manual-test.log | head -c 50)..."
echo "     .doc file: $(cat $TEST_DIR/manual-test.doc | head -c 50)..."

echo ""

# Test 4: Directory structure check
echo "4. Test Directory Contents:"
ls -la "$TEST_DIR/" | head -10
echo ""

# Test 5: Configuration validation
echo "5. Configuration Files Available:"
for config in configs/*.yaml; do
    if [ -f "$config" ]; then
        echo "   ✅ $config ($(wc -l < $config) lines)"
    fi
done
echo ""

# Test 6: Kernel module status (if accessible)
echo "6. Kernel Module Status:"
if [ -r /proc/takakrypt/status ]; then
    echo "   ✅ Kernel module accessible"
    cat /proc/takakrypt/status | head -5 | sed 's/^/   /'
else
    echo "   ❌ Kernel module not accessible (may not be loaded or need sudo)"
fi
echo ""

# Test 7: Network/system info
echo "7. System Information:"
echo "   User: $(whoami) ($(id))"
echo "   Working directory: $(pwd)"
echo "   Go version: $(go version 2>/dev/null || echo 'not available')"
echo ""

echo "=== Manual Operations Guide Validation Complete ==="
echo ""
echo "📋 Next Steps for Manual Testing:"
echo "   1. Load kernel module: sudo insmod kernel/takakrypt.ko"
echo "   2. Start agent: sudo ./build/bin/takakrypt-agent -config configs/test-config.yaml -log-level debug"
echo "   3. Test file operations in /tmp/takakrypt-user-test/"
echo "   4. Monitor with: cat /proc/takakrypt/status"
echo "   5. Stop agent: sudo pkill -f takakrypt-agent"
echo ""
echo "See MANUAL_OPERATIONS_GUIDE.md for detailed instructions."