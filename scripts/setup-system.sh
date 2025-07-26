#!/bin/bash

# Takakrypt System Setup Script
# This script sets up the complete Takakrypt transparent encryption system

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/takakrypt"
LOG_DIR="/var/log/takakrypt"
SYSTEMD_DIR="/etc/systemd/system"

print_header() {
    echo -e "${BLUE}================================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}================================================${NC}"
}

print_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root"
        exit 1
    fi
}

check_dependencies() {
    print_header "Checking Dependencies"
    
    # Check for Go
    if ! command -v go &> /dev/null; then
        print_error "Go is not installed. Please install Go 1.21 or later."
        exit 1
    fi
    print_info "Go version: $(go version)"
    
    # Check for kernel headers
    KERNEL_VERSION=$(uname -r)
    if [[ ! -d "/lib/modules/${KERNEL_VERSION}/build" ]]; then
        print_error "Kernel headers not found. Please install kernel headers for ${KERNEL_VERSION}"
        print_info "Ubuntu/Debian: apt install linux-headers-${KERNEL_VERSION}"
        print_info "RHEL/CentOS: yum install kernel-devel-${KERNEL_VERSION}"
        exit 1
    fi
    print_info "Kernel headers found for ${KERNEL_VERSION}"
    
    # Check for build tools
    for tool in make gcc; do
        if ! command -v $tool &> /dev/null; then
            print_error "$tool is not installed"
            exit 1
        fi
    done
    print_info "Build tools available"
}

build_components() {
    print_header "Building Components"
    
    cd "$PROJECT_DIR"
    
    # Build Go components
    print_info "Building Go user-space components..."
    make go-build || {
        print_error "Failed to build Go components"
        exit 1
    }
    
    # Build kernel module
    print_info "Building kernel module..."
    make kernel-build || {
        print_error "Failed to build kernel module"
        exit 1
    }
    
    print_info "All components built successfully"
}

install_components() {
    print_header "Installing Components"
    
    # Create directories
    print_info "Creating directories..."
    mkdir -p "$INSTALL_DIR"
    mkdir -p "$CONFIG_DIR"
    mkdir -p "$LOG_DIR"
    
    # Install binaries
    print_info "Installing binaries..."
    cp "$PROJECT_DIR/build/bin/takakrypt-agent" "$INSTALL_DIR/"
    cp "$PROJECT_DIR/build/bin/takakrypt-cli" "$INSTALL_DIR/" 2>/dev/null || print_warning "takakrypt-cli not found, skipping"
    chmod +x "$INSTALL_DIR/takakrypt-agent"
    chmod +x "$INSTALL_DIR/takakrypt-cli" 2>/dev/null || true
    
    # Install kernel module
    print_info "Installing kernel module..."
    KERNEL_VERSION=$(uname -r)
    MODULE_DIR="/lib/modules/${KERNEL_VERSION}/extra"
    mkdir -p "$MODULE_DIR"
    cp "$PROJECT_DIR/kernel/takakrypt.ko" "$MODULE_DIR/"
    depmod -a
    
    # Install configuration
    print_info "Installing configuration..."
    if [[ ! -f "$CONFIG_DIR/config.yaml" ]]; then
        cp "$PROJECT_DIR/configs/example.yaml" "$CONFIG_DIR/config.yaml"
        print_info "Installed default configuration to $CONFIG_DIR/config.yaml"
    else
        print_warning "Configuration already exists at $CONFIG_DIR/config.yaml"
    fi
    
    # Install systemd service
    print_info "Installing systemd service..."
    cat > "$SYSTEMD_DIR/takakrypt-cte.service" << EOF
[Unit]
Description=Takakrypt CTE (C Transparent Encryption) Agent
After=network.target

[Service]
Type=simple
ExecStart=$INSTALL_DIR/takakrypt-agent -config $CONFIG_DIR/config.yaml
Restart=always
RestartSec=5
User=root
Group=root

# Security settings
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$LOG_DIR $CONFIG_DIR /tmp

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    print_info "Systemd service installed as takakrypt-cte"
    
    # Set permissions
    chown -R root:root "$CONFIG_DIR"
    chown -R root:root "$LOG_DIR"
    chmod 750 "$CONFIG_DIR"
    chmod 750 "$LOG_DIR"
    chmod 640 "$CONFIG_DIR/config.yaml"
}

start_system() {
    print_header "Starting Takakrypt System"
    
    # Load kernel module
    print_info "Loading kernel module..."
    if lsmod | grep -q takakrypt; then
        print_warning "Kernel module already loaded"
    else
        modprobe takakrypt
        print_info "Kernel module loaded successfully"
    fi
    
    # Start and enable service
    print_info "Starting takakrypt-cte service..."
    systemctl enable takakrypt-cte
    systemctl start takakrypt-cte
    
    # Wait a moment for startup
    sleep 2
    
    # Check status
    if systemctl is-active --quiet takakrypt-cte; then
        print_info "Takakrypt CTE service started successfully"
    else
        print_error "Failed to start takakrypt-cte service"
        print_info "Check logs: journalctl -u takakrypt-cte"
        exit 1
    fi
}

verify_installation() {
    print_header "Verifying Installation"
    
    # Check kernel module
    if lsmod | grep -q takakrypt; then
        print_info "✓ Kernel module loaded"
    else
        print_error "✗ Kernel module not loaded"
        return 1
    fi
    
    # Check service
    if systemctl is-active --quiet takakrypt-cte; then
        print_info "✓ Agent service running"
    else
        print_error "✗ Agent service not running"
        return 1
    fi
    
    # Check proc interface
    if [[ -r /proc/takakrypt/status ]]; then
        print_info "✓ Proc interface available"
        print_info "Status: $(cat /proc/takakrypt/status | head -1)"
    else
        print_warning "✗ Proc interface not available"
    fi
    
    # Check socket
    if [[ -S /var/run/takakrypt.sock ]]; then
        print_info "✓ Agent socket available"
    else
        print_warning "✗ Agent socket not found"
    fi
    
    print_info "Installation verification complete"
}

run_test() {
    print_header "Running Basic Test"
    
    # Create test directory
    TEST_DIR="/tmp/takakrypt-install-test"
    mkdir -p "$TEST_DIR"
    
    # Create test file
    echo "This is a test file for Takakrypt" > "$TEST_DIR/test.txt"
    echo "This is a log file" > "$TEST_DIR/test.log"
    
    print_info "Created test files in $TEST_DIR"
    print_info "- test.txt (should be encrypted if guard point configured)"
    print_info "- test.log (should remain unencrypted)"
    
    # Check if CLI tool is available
    if command -v takakrypt-cli &> /dev/null; then
        print_info "Testing with CLI tool..."
        takakrypt-cli status || print_warning "CLI test failed"
    fi
    
    print_info "Test files created. Configure guard points to test encryption."
    print_info "Example: Add guard point for '$TEST_DIR' with pattern '*.txt'"
}

show_next_steps() {
    print_header "Installation Complete!"
    
    cat << EOF

${GREEN}✓ Takakrypt has been successfully installed and started${NC}

${YELLOW}Next Steps:${NC}

1. ${BLUE}Configure guard points:${NC}
   Edit: $CONFIG_DIR/config.yaml
   Add guard points for directories you want to protect

2. ${BLUE}Test the system:${NC}
   # Create a test guard point
   # Add files to protected directories
   # Verify encryption is working

3. ${BLUE}Monitor the system:${NC}
   systemctl status takakrypt-cte      # Service status
   journalctl -u takakrypt-cte -f      # Live logs
   cat /proc/takakrypt/status          # Kernel module status

4. ${BLUE}Configuration files:${NC}
   Config:  $CONFIG_DIR/config.yaml
   Logs:    $LOG_DIR/
   Service: $SYSTEMD_DIR/takakrypt-cte.service

5. ${BLUE}Commands:${NC}
   systemctl start/stop/restart takakrypt-cte
   takakrypt-cli status
   modprobe takakrypt / rmmod takakrypt

${YELLOW}Documentation:${NC}
   See SYSTEM_GUIDE.md for complete usage instructions
   See ENCRYPTION_FLOW_TEST_RESULTS.md for test examples

EOF
}

# Main execution
main() {
    print_header "Takakrypt System Installation"
    
    check_root
    check_dependencies
    build_components
    install_components
    start_system
    verify_installation
    run_test
    show_next_steps
}

# Handle command line arguments
case "${1:-install}" in
    "install")
        main
        ;;
    "uninstall")
        print_header "Uninstalling Takakrypt CTE"
        systemctl stop takakrypt-cte 2>/dev/null || true
        systemctl disable takakrypt-cte 2>/dev/null || true
        rmmod takakrypt 2>/dev/null || true
        rm -f "$INSTALL_DIR/takakrypt-agent"
        rm -f "$INSTALL_DIR/takakrypt-cli"
        rm -f "$SYSTEMD_DIR/takakrypt-cte.service"
        print_info "Takakrypt CTE uninstalled (configuration preserved)"
        ;;
    "status")
        print_header "Takakrypt Status"
        verify_installation
        ;;
    "help")
        echo "Usage: $0 [install|uninstall|status|help]"
        echo "  install   - Install and start Takakrypt (default)"
        echo "  uninstall - Stop and remove Takakrypt"
        echo "  status    - Check system status"
        echo "  help      - Show this help"
        ;;
    *)
        print_error "Unknown command: $1"
        echo "Use '$0 help' for usage information"
        exit 1
        ;;
esac