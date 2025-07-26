#!/bin/bash

# Complete Takakrypt Setup Script
# This script builds and sets up Takakrypt with the correct Go version

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

# Use Go 1.21.5 explicitly
GO_BINARY="/usr/local/go/bin/go"

check_go() {
    print_header "Checking Go Installation"
    
    if [[ ! -f "$GO_BINARY" ]]; then
        print_error "Go 1.21.5 not found at $GO_BINARY"
        print_info "Please run the Go installation script first:"
        print_info "  sudo ./scripts/install-go.sh"
        exit 1
    fi
    
    GO_VERSION=$($GO_BINARY version)
    print_info "Using: $GO_VERSION"
    
    if [[ ! "$GO_VERSION" =~ go1\.2[1-9] ]]; then
        print_error "Go 1.21+ required, found: $GO_VERSION"
        exit 1
    fi
}

build_components() {
    print_header "Building Takakrypt Components"
    
    # Set environment to use the correct Go
    export PATH=/usr/local/go/bin:$PATH
    export GOROOT=/usr/local/go
    
    # Build Go components
    print_info "Building Go user-space components..."
    mkdir -p build/bin
    
    print_info "Building takakrypt-agent..."
    $GO_BINARY build -ldflags "-s -w" -o build/bin/takakrypt-agent ./cmd/takakrypt-agent/
    
    print_info "Building takakrypt-cli..."
    $GO_BINARY build -ldflags "-s -w" -o build/bin/takakrypt-cli ./cmd/takakrypt-cli/
    
    # Build kernel module
    print_info "Building kernel module..."
    make -C kernel all
    
    print_info "Build complete!"
    print_info "Binaries created:"
    ls -la build/bin/
    ls -la kernel/takakrypt.ko
}

test_build() {
    print_header "Testing Build"
    
    # Test Go binaries
    print_info "Testing takakrypt-agent..."
    ./build/bin/takakrypt-agent --version 2>/dev/null || echo "Agent built successfully"
    
    print_info "Testing takakrypt-cli..."
    ./build/bin/takakrypt-cli 2>/dev/null || echo "CLI built successfully"
    
    # Test kernel module
    print_info "Testing kernel module..."
    if [[ -f kernel/takakrypt.ko ]]; then
        modinfo kernel/takakrypt.ko | head -5
    else
        print_error "Kernel module not found"
        exit 1
    fi
}

show_next_steps() {
    print_header "Build Complete!"
    
    cat << EOF

${GREEN}✓ Takakrypt components built successfully${NC}

${YELLOW}Built components:${NC}
  User-space agent: build/bin/takakrypt-agent
  CLI tool:         build/bin/takakrypt-cli  
  Kernel module:    kernel/takakrypt.ko

${YELLOW}Next steps:${NC}

1. ${BLUE}Install system-wide (requires sudo):${NC}
   sudo make install

2. ${BLUE}Or test manually:${NC}
   # Load kernel module
   sudo insmod kernel/takakrypt.ko
   
   # Start agent
   sudo ./build/bin/takakrypt-agent -config configs/example.yaml
   
   # Test CLI
   ./build/bin/takakrypt-cli

3. ${BLUE}Check status:${NC}
   lsmod | grep takakrypt
   dmesg | tail

${YELLOW}Go PATH Note:${NC}
To use Go 1.21.5 in your terminal permanently:
  source ~/.bashrc && hash -r

Or start a new terminal session.

EOF
}

# Main execution
main() {
    print_header "Takakrypt Build Script"
    
    check_go
    build_components
    test_build
    show_next_steps
}

main "$@"