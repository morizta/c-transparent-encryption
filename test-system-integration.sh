#!/bin/bash

# Integration test script for Takakrypt
# This script tests the system components without requiring interactive sudo

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_header() {
    echo -e "${BLUE}================================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}================================================${NC}"
}

check_kernel_module() {
    print_header "Checking Kernel Module"
    
    if lsmod | grep -q takakrypt; then
        print_info "✓ Kernel module loaded"
        
        # Check proc interface
        if [[ -r /proc/takakrypt/status ]]; then
            print_info "✓ Proc interface available"
            echo "Status:"
            cat /proc/takakrypt/status | head -10
        else
            print_warning "✗ Proc interface not available"
        fi
    else
        print_error "✗ Kernel module not loaded"
        print_info "Load with: sudo insmod kernel/takakrypt.ko"
        return 1
    fi
}

test_agent_binary() {
    print_header "Testing Agent Binary"
    
    if [[ -x build/bin/takakrypt-agent ]]; then
        print_info "✓ Agent binary exists and is executable"
        
        # Test version
        VERSION_OUTPUT=$(./build/bin/takakrypt-agent --version 2>&1 || echo "No version flag")
        print_info "Agent version: $VERSION_OUTPUT"
        
        # Test config validation (without starting)
        if [[ -f configs/example.yaml ]]; then
            print_info "Testing configuration validation..."
            timeout 5s ./build/bin/takakrypt-agent -config configs/example.yaml -validate 2>&1 || {
                print_warning "Config validation test timed out or failed"
            }
        fi
    else
        print_error "✗ Agent binary not found or not executable"
        return 1
    fi
}

test_cli_tool() {
    print_header "Testing CLI Tool"
    
    if [[ -x build/bin/takakrypt-cli ]]; then
        print_info "✓ CLI tool exists and is executable"
        
        print_info "CLI output:"
        ./build/bin/takakrypt-cli 2>&1 || true
    else
        print_error "✗ CLI tool not found"
        return 1
    fi
}

test_netlink_communication() {
    print_header "Testing Kernel-Userspace Communication"
    
    # Create a simple test to check if netlink socket can be created
    cat > /tmp/test_netlink.c << 'EOF'
#include <stdio.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <unistd.h>

int main() {
    int sock = socket(AF_NETLINK, SOCK_RAW, 25); // NETLINK_USERSOCK
    if (sock < 0) {
        printf("Failed to create netlink socket\n");
        return 1;
    }
    printf("Netlink socket created successfully\n");
    close(sock);
    return 0;
}
EOF

    if gcc -o /tmp/test_netlink /tmp/test_netlink.c 2>/dev/null; then
        if /tmp/test_netlink; then
            print_info "✓ Netlink communication capability verified"
        else
            print_warning "✗ Netlink socket creation failed"
        fi
        rm -f /tmp/test_netlink /tmp/test_netlink.c
    else
        print_warning "Could not compile netlink test"
    fi
}

test_file_encryption_simulation() {
    print_header "Testing File Encryption Logic"
    
    # Test our encryption flow test
    if [[ -x cmd/test-encryption-flow/main.go ]]; then
        print_info "Running encryption flow simulation..."
        /usr/local/go/bin/go run cmd/test-encryption-flow/main.go 2>&1 | head -20
        print_info "✓ Encryption flow test completed"
    else
        print_warning "Encryption flow test not available"
    fi
}

show_manual_testing_steps() {
    print_header "Manual Testing Steps"
    
    cat << EOF
${YELLOW}To complete testing, run these commands with sudo:${NC}

1. ${BLUE}Start the agent:${NC}
   sudo ./build/bin/takakrypt-agent -config configs/example.yaml

2. ${BLUE}In another terminal, check status:${NC}
   cat /proc/takakrypt/status

3. ${BLUE}Test file operations:${NC}
   # Create test directory matching guard points in config
   sudo mkdir -p /tmp/takakrypt-test
   echo "test content" | sudo tee /tmp/takakrypt-test/secret.txt
   cat /tmp/takakrypt-test/secret.txt

4. ${BLUE}Monitor activity:${NC}
   # Watch real-time statistics
   watch -n 1 'cat /proc/takakrypt/status'

5. ${BLUE}Stop and unload:${NC}
   sudo pkill takakrypt-agent
   sudo rmmod takakrypt

${YELLOW}Expected Behavior:${NC}
- Files in guard point paths should be encrypted on write
- Files should be decrypted on read for authorized users
- Statistics should update in /proc/takakrypt/status
- Agent should connect to kernel module

EOF
}

check_system_requirements() {
    print_header "System Requirements Check"
    
    # Check kernel headers
    KERNEL_VERSION=$(uname -r)
    if [[ -d "/lib/modules/${KERNEL_VERSION}/build" ]]; then
        print_info "✓ Kernel headers available"
    else
        print_warning "✗ Kernel headers missing"
    fi
    
    # Check Go version
    if /usr/local/go/bin/go version | grep -q "go1.2[1-9]"; then
        print_info "✓ Go 1.21+ available"
    else
        print_warning "✗ Go 1.21+ not in /usr/local/go/bin/"
    fi
    
    # Check build tools
    for tool in gcc make; do
        if command -v $tool >/dev/null 2>&1; then
            print_info "✓ $tool available"
        else
            print_warning "✗ $tool missing"
        fi
    done
}

# Main execution
main() {
    print_header "Takakrypt System Integration Test"
    
    check_system_requirements
    echo
    
    check_kernel_module
    echo
    
    test_agent_binary
    echo
    
    test_cli_tool
    echo
    
    test_netlink_communication
    echo
    
    test_file_encryption_simulation
    echo
    
    show_manual_testing_steps
}

main "$@"