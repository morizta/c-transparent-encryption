#!/bin/bash

# Comprehensive Takakrypt System Test
# Tests all major components: agent, kernel module, encryption, and policies

set -e
echo "=== Takakrypt Comprehensive System Test ==="
echo "Starting at $(date)"
echo

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test result tracking
TESTS_PASSED=0
TESTS_FAILED=0
TOTAL_TESTS=0

# Function to print test results
print_test_result() {
    local test_name="$1"
    local result="$2"
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    
    if [ "$result" = "PASS" ]; then
        echo -e "${GREEN}✅ PASS${NC}: $test_name"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        echo -e "${RED}❌ FAIL${NC}: $test_name"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
}

# Test 1: Build System
echo -e "${BLUE}=== Test 1: Build System ===${NC}"
if make all >/dev/null 2>&1; then
    print_test_result "Build system compilation" "PASS"
else
    print_test_result "Build system compilation" "FAIL"
fi

# Test 2: Kernel Module Status
echo -e "${BLUE}=== Test 2: Kernel Module Status ===${NC}"
if lsmod | grep -q takakrypt; then
    print_test_result "Takakrypt kernel module loaded" "PASS"
    echo "Module info: $(lsmod | grep takakrypt)"
else
    print_test_result "Takakrypt kernel module loaded" "FAIL"
fi

# Test 3: Kernel Module Status via /proc
if [ -f /proc/takakrypt/status ]; then
    print_test_result "/proc/takakrypt/status exists" "PASS"
    echo "Status excerpt:"
    head -10 /proc/takakrypt/status | sed 's/^/  /'
else
    print_test_result "/proc/takakrypt/status exists" "FAIL"
fi

# Test 4: Agent Binary
echo -e "${BLUE}=== Test 3: Agent Testing ===${NC}"
if [ -x ./build/bin/takakrypt-agent ]; then
    print_test_result "Agent binary exists and executable" "PASS"
else
    print_test_result "Agent binary exists and executable" "FAIL"
fi

# Test 5: Configuration Validation
echo -e "${BLUE}=== Test 4: Configuration Validation ===${NC}"
if [ -x ./build/bin/test-config-validation ]; then
    if ./build/bin/test-config-validation -config configs/test-config.yaml >/dev/null 2>&1; then
        print_test_result "Configuration validation" "PASS"
    else
        print_test_result "Configuration validation" "FAIL"
    fi
else
    print_test_result "Configuration validation" "SKIP - no validator"
fi

# Test 6: Real Encryption Engine Test
echo -e "${BLUE}=== Test 5: Real Encryption Engine ===${NC}"
if [ -x ./build/bin/test-real-encryption ]; then
    if ./build/bin/test-real-encryption >/dev/null 2>&1; then
        print_test_result "Real AES-256-GCM encryption test" "PASS"
    else
        print_test_result "Real AES-256-GCM encryption test" "FAIL"
    fi
else
    echo -e "${YELLOW}⚠️  SKIP${NC}: test-real-encryption binary not found"
fi

# Test 7: Policy Engine Test
echo -e "${BLUE}=== Test 6: Policy Engine ===${NC}"
if [ -x ./build/bin/test-user-access ]; then
    if ./build/bin/test-user-access configs/test-config.yaml >/dev/null 2>&1; then
        print_test_result "Policy engine access control" "PASS"
    else
        print_test_result "Policy engine access control" "FAIL"
    fi
else
    echo -e "${YELLOW}⚠️  SKIP${NC}: test-user-access binary not found"
fi

# Test 8: Database Process Detection
echo -e "${BLUE}=== Test 7: Database Process Detection ===${NC}"
if [ -x ./build/bin/test-process-detection ]; then
    if ./build/bin/test-process-detection >/dev/null 2>&1; then
        print_test_result "Database process detection" "PASS"
    else
        print_test_result "Database process detection" "FAIL"
    fi
else
    echo -e "${YELLOW}⚠️  SKIP${NC}: test-process-detection binary not found"
fi

# Test 9: Agent Startup Test
echo -e "${BLUE}=== Test 8: Agent Startup ===${NC}"
# Start agent in background for 5 seconds
timeout 5s ./build/bin/takakrypt-agent -config configs/test-config.yaml >/dev/null 2>&1 &
AGENT_PID=$!
sleep 2

if kill -0 $AGENT_PID 2>/dev/null; then
    print_test_result "Agent startup and initial run" "PASS"
    kill $AGENT_PID 2>/dev/null || true
else
    print_test_result "Agent startup and initial run" "FAIL"
fi

# Test 10: Netlink Communication
echo -e "${BLUE}=== Test 9: Netlink Communication ===${NC}"
if [ -x ./build/bin/test-simple-netlink ]; then
    if ./build/bin/test-simple-netlink >/dev/null 2>&1; then
        print_test_result "Basic netlink socket creation" "PASS"
    else
        print_test_result "Basic netlink socket creation" "FAIL"
    fi
else
    echo -e "${YELLOW}⚠️  SKIP${NC}: test-simple-netlink binary not found"
fi

# Test 11: File System Components
echo -e "${BLUE}=== Test 10: File System Components ===${NC}"
if [ -f kernel/takakryptfs/takakryptfs.ko ]; then
    print_test_result "Takakryptfs module compiled" "PASS"
else
    print_test_result "Takakryptfs module compiled" "FAIL"
fi

# Test 12: Test Directory Structure
echo -e "${BLUE}=== Test 11: Test Environment ===${NC}"
TEST_DIR="/tmp/takakrypt-user-test"
if [ -d "$TEST_DIR" ]; then
    print_test_result "Test directory structure exists" "PASS"
    echo "Test directories:"
    find "$TEST_DIR" -type d | sed 's/^/  /'
else
    print_test_result "Test directory structure exists" "FAIL"
fi

# Test 13: Security Rules Configuration
echo -e "${BLUE}=== Test 12: Security Rules Configuration ===${NC}"
if grep -q "security_rules:" configs/test-config.yaml; then
    print_test_result "Security rules configuration present" "PASS"
    RULE_COUNT=$(grep -c "order:" configs/test-config.yaml)
    echo "  Security rules found: $RULE_COUNT"
else
    print_test_result "Security rules configuration present" "FAIL"
fi

# System Status Summary
echo
echo -e "${BLUE}=== System Status Summary ===${NC}"
echo "Kernel module uptime: $(awk '/Module Uptime/ {print $3 " " $4}' /proc/takakrypt/status 2>/dev/null || echo "N/A")"
echo "Agent connection status: $(awk '/Agent PID/ {print $3}' /proc/takakrypt/status 2>/dev/null || echo "N/A")"
echo "Total requests processed: $(awk '/Processed/ {print $3}' /proc/takakrypt/status 2>/dev/null || echo "N/A")"

# Final Results
echo
echo -e "${BLUE}=== Test Results Summary ===${NC}"
echo -e "Total Tests: $TOTAL_TESTS"
echo -e "${GREEN}Passed: $TESTS_PASSED${NC}"
echo -e "${RED}Failed: $TESTS_FAILED${NC}"

if [ $TESTS_FAILED -eq 0 ]; then
    echo
    echo -e "${GREEN}🎉 ALL TESTS PASSED! System is functioning correctly.${NC}"
    echo -e "${GREEN}✅ Takakrypt transparent encryption system ready for operation${NC}"
    exit 0
else
    echo
    echo -e "${YELLOW}⚠️  $TESTS_FAILED tests failed. System may need attention.${NC}"
    echo -e "${BLUE}💡 Check individual test results above for details${NC}"
    exit 1
fi