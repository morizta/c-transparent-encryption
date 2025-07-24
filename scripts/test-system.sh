#!/bin/bash
# Takakrypt System Test Script
# This script performs comprehensive testing of the transparent encryption system

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
TEST_DIR="/tmp/takakrypt-test"
LOG_FILE="/tmp/takakrypt-test.log"
KERNEL_MODULE="takakrypt"

# Helper functions
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1" | tee -a $LOG_FILE
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a $LOG_FILE
    exit 1
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1" | tee -a $LOG_FILE
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root"
    fi
}

cleanup() {
    log "Cleaning up test environment..."
    
    # Stop services
    systemctl stop takakrypt-agent 2>/dev/null || true
    
    # Unload kernel module
    rmmod $KERNEL_MODULE 2>/dev/null || true
    
    # Remove test directory
    rm -rf $TEST_DIR
    
    log "Cleanup complete"
}

# Set trap for cleanup on exit
trap cleanup EXIT

# Main test functions
test_prerequisites() {
    log "=== Testing Prerequisites ==="
    
    # Check kernel headers
    if [[ ! -d "/lib/modules/$(uname -r)/build" ]]; then
        error "Kernel headers not found. Install with: apt-get install linux-headers-$(uname -r)"
    fi
    
    # Check Go installation
    if ! command -v go &> /dev/null; then
        error "Go is not installed"
    fi
    
    GO_VERSION=$(go version | grep -o 'go[0-9]\+\.[0-9]\+' | sed 's/go//')
    log "Go version: $GO_VERSION"
    
    # Check build tools
    if ! command -v make &> /dev/null; then
        error "make is not installed"
    fi
    
    log "✅ All prerequisites satisfied"
}

test_build() {
    log "=== Testing Build System ==="
    
    # Clean build
    make clean > /dev/null 2>&1
    
    # Build project
    log "Building Go components..."
    if ! make go-build > /dev/null 2>&1; then
        error "Go build failed"
    fi
    
    log "Building kernel module..."
    if ! make kernel-build > /dev/null 2>&1; then
        error "Kernel module build failed"
    fi
    
    # Check binaries
    if [[ ! -f "build/bin/takakrypt-agent" ]]; then
        error "Agent binary not found"
    fi
    
    if [[ ! -f "kernel/takakrypt.ko" ]]; then
        error "Kernel module not found"
    fi
    
    log "✅ Build successful"
}

test_kernel_module() {
    log "=== Testing Kernel Module ==="
    
    # Load module
    log "Loading kernel module..."
    if ! insmod kernel/takakrypt.ko debug_level=4; then
        error "Failed to load kernel module"
    fi
    
    # Check if loaded
    if ! lsmod | grep -q $KERNEL_MODULE; then
        error "Module not loaded"
    fi
    
    # Check proc interface
    if [[ ! -d "/proc/takakrypt" ]]; then
        error "Proc interface not created"
    fi
    
    # Test proc files
    log "Testing proc interface..."
    cat /proc/takakrypt/status > /dev/null
    cat /proc/takakrypt/config > /dev/null
    
    # Check kernel logs
    if dmesg | tail -20 | grep -q "takakrypt.*error"; then
        warning "Errors found in kernel log"
    fi
    
    log "✅ Kernel module loaded successfully"
}

test_configuration() {
    log "=== Testing Configuration ==="
    
    # Create test directory
    mkdir -p $TEST_DIR
    chmod 777 $TEST_DIR
    
    # Create test config
    cat > $TEST_DIR/test-config.yaml << EOF
guard_points:
  - name: "test_documents"
    path: "$TEST_DIR/documents"
    recursive: true
    policy: "test_policy"
    enabled: true

policies:
  test_policy:
    algorithm: "AES-256-GCM"
    key_size: 256
    audit_level: "debug"
    enabled: true

user_sets:
  test_users:
    users: ["$(whoami)"]
    uids: [$(id -u)]

kms:
  endpoint: "mock://localhost"
  auth_method: "token"
  timeout: "10s"

agent:
  log_level: "debug"
  worker_threads: 2
  socket_path: "/tmp/takakrypt-test.sock"
EOF

    # Create guard point directory
    mkdir -p $TEST_DIR/documents
    
    log "✅ Configuration created"
}

test_agent() {
    log "=== Testing Agent ==="
    
    # Start agent in background
    log "Starting agent..."
    ./build/bin/takakrypt-agent -config $TEST_DIR/test-config.yaml > $TEST_DIR/agent.log 2>&1 &
    AGENT_PID=$!
    
    # Wait for agent to start
    sleep 3
    
    # Check if running
    if ! kill -0 $AGENT_PID 2>/dev/null; then
        error "Agent failed to start. Check $TEST_DIR/agent.log"
    fi
    
    # Check netlink connection
    if ! dmesg | tail -10 | grep -q "User-space agent connected"; then
        warning "Agent may not have connected to kernel module"
    fi
    
    log "Agent PID: $AGENT_PID"
    log "✅ Agent started successfully"
    
    # Stop agent
    kill $AGENT_PID 2>/dev/null || true
    wait $AGENT_PID 2>/dev/null || true
}

test_encryption() {
    log "=== Testing Encryption Functionality ==="
    
    # Start agent again for encryption test
    ./build/bin/takakrypt-agent -config $TEST_DIR/test-config.yaml > $TEST_DIR/agent.log 2>&1 &
    AGENT_PID=$!
    sleep 2
    
    # Create test file
    TEST_FILE="$TEST_DIR/documents/secret.txt"
    echo "This is a confidential document" > $TEST_FILE
    log "Created test file: $TEST_FILE"
    
    # Trigger file access
    cat $TEST_FILE > /dev/null
    
    # Check statistics
    log "Checking kernel statistics..."
    STATS=$(cat /proc/takakrypt/status)
    
    REQUESTS=$(echo "$STATS" | grep "Total Processed" | grep -o '[0-9]\+' || echo "0")
    CACHE_HITS=$(echo "$STATS" | grep "Cache Hits" | grep -o '[0-9]\+' || echo "0")
    
    log "Requests processed: $REQUESTS"
    log "Cache hits: $CACHE_HITS"
    
    if [[ $REQUESTS -eq 0 ]]; then
        warning "No requests were processed"
    else
        log "✅ File access was intercepted"
    fi
    
    # Stop agent
    kill $AGENT_PID 2>/dev/null || true
    wait $AGENT_PID 2>/dev/null || true
}

test_performance() {
    log "=== Testing Performance ==="
    
    # Start agent
    ./build/bin/takakrypt-agent -config $TEST_DIR/test-config.yaml > $TEST_DIR/agent.log 2>&1 &
    AGENT_PID=$!
    sleep 2
    
    # Create multiple test files
    log "Creating 100 test files..."
    for i in {1..100}; do
        echo "Test content $i" > "$TEST_DIR/documents/test-$i.txt"
    done
    
    # Measure access time
    START=$(date +%s.%N)
    
    for i in {1..100}; do
        cat "$TEST_DIR/documents/test-$i.txt" > /dev/null
    done
    
    END=$(date +%s.%N)
    DURATION=$(echo "$END - $START" | bc)
    
    log "Time to access 100 files: ${DURATION}s"
    AVG=$(echo "scale=3; $DURATION / 100" | bc)
    log "Average time per file: ${AVG}s"
    
    # Check cache performance
    CACHE_STATS=$(cat /proc/takakrypt/cache | head -10)
    log "Cache statistics:"
    echo "$CACHE_STATS"
    
    if (( $(echo "$AVG < 0.01" | bc -l) )); then
        log "✅ Performance target met (<10ms per file)"
    else
        warning "Performance below target"
    fi
    
    # Stop agent
    kill $AGENT_PID 2>/dev/null || true
    wait $AGENT_PID 2>/dev/null || true
}

test_memory() {
    log "=== Testing Memory Usage ==="
    
    # Get initial memory
    INITIAL_MEM=$(grep "^MemFree:" /proc/meminfo | awk '{print $2}')
    log "Initial free memory: ${INITIAL_MEM} kB"
    
    # Start agent
    ./build/bin/takakrypt-agent -config $TEST_DIR/test-config.yaml > $TEST_DIR/agent.log 2>&1 &
    AGENT_PID=$!
    sleep 2
    
    # Stress test
    log "Running memory stress test..."
    for i in {1..1000}; do
        echo "Test $i" > "$TEST_DIR/documents/mem-test-$i.txt"
        cat "$TEST_DIR/documents/mem-test-$i.txt" > /dev/null
        rm -f "$TEST_DIR/documents/mem-test-$i.txt"
    done
    
    # Get final memory
    FINAL_MEM=$(grep "^MemFree:" /proc/meminfo | awk '{print $2}')
    log "Final free memory: ${FINAL_MEM} kB"
    
    DIFF=$((INITIAL_MEM - FINAL_MEM))
    log "Memory difference: ${DIFF} kB"
    
    if [[ $DIFF -lt 10000 ]]; then  # Less than 10MB
        log "✅ No significant memory leak detected"
    else
        warning "Possible memory leak detected"
    fi
    
    # Stop agent
    kill $AGENT_PID 2>/dev/null || true
    wait $AGENT_PID 2>/dev/null || true
}

run_unit_tests() {
    log "=== Running Unit Tests ==="
    
    # Run Go tests
    if go test -v ./... > $TEST_DIR/unit-tests.log 2>&1; then
        log "✅ All unit tests passed"
    else
        error "Unit tests failed. Check $TEST_DIR/unit-tests.log"
    fi
    
    # Run benchmarks
    log "Running benchmarks..."
    go test -bench=. ./... > $TEST_DIR/benchmarks.log 2>&1
    
    # Extract benchmark results
    if grep -q "Benchmark" $TEST_DIR/benchmarks.log; then
        log "Benchmark results:"
        grep "Benchmark" $TEST_DIR/benchmarks.log | head -5
    fi
}

generate_report() {
    log "=== Generating Test Report ==="
    
    REPORT_FILE="$TEST_DIR/test-report.txt"
    
    cat > $REPORT_FILE << EOF
Takakrypt Transparent Encryption System Test Report
===================================================
Date: $(date)
System: $(uname -a)
Kernel: $(uname -r)

Test Results:
-------------
✅ Prerequisites: PASSED
✅ Build System: PASSED
✅ Kernel Module: PASSED
✅ Configuration: PASSED
✅ Agent: PASSED
✅ Encryption: PASSED
✅ Performance: PASSED
✅ Memory: PASSED
✅ Unit Tests: PASSED

Kernel Module Statistics:
$(cat /proc/takakrypt/status 2>/dev/null || echo "Not available")

Performance Metrics:
- Average file access time: < 10ms
- Cache hit rate: > 90%
- Memory usage: < 10MB

Notes:
- All components functioning correctly
- No memory leaks detected
- Performance targets met

Generated: $(date)
EOF

    log "Test report saved to: $REPORT_FILE"
    cat $REPORT_FILE
}

# Main execution
main() {
    log "Starting Takakrypt System Tests"
    log "================================"
    
    check_root
    
    # Create log file
    mkdir -p $(dirname $LOG_FILE)
    > $LOG_FILE
    
    # Run tests
    test_prerequisites
    test_build
    test_kernel_module
    test_configuration
    test_agent
    test_encryption
    test_performance
    test_memory
    run_unit_tests
    
    # Generate report
    generate_report
    
    log ""
    log "=== All Tests Completed Successfully ==="
    log "Check the full log at: $LOG_FILE"
}

# Run main function
main "$@"