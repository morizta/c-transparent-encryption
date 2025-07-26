#!/bin/bash

# Go Installation Script for Takakrypt
# Installs Go 1.21+ if not already installed

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

# Detect architecture
ARCH=$(uname -m)
case $ARCH in
    x86_64)
        GO_ARCH="amd64"
        ;;
    aarch64|arm64)
        GO_ARCH="arm64"
        ;;
    armv6l)
        GO_ARCH="armv6l"
        ;;
    *)
        print_error "Unsupported architecture: $ARCH"
        exit 1
        ;;
esac

# Go version to install
GO_VERSION="1.21.5"
GO_TARBALL="go${GO_VERSION}.linux-${GO_ARCH}.tar.gz"
GO_URL="https://golang.org/dl/${GO_TARBALL}"

check_existing_go() {
    if command -v go &> /dev/null; then
        CURRENT_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
        print_info "Found existing Go version: $CURRENT_VERSION"
        
        # Check if version is sufficient (1.21+)
        if [[ "$(printf '%s\n' "1.21" "$CURRENT_VERSION" | sort -V | head -n1)" == "1.21" ]]; then
            print_info "Go version $CURRENT_VERSION is sufficient (>= 1.21)"
            return 0
        else
            print_warning "Go version $CURRENT_VERSION is too old (< 1.21)"
            return 1
        fi
    else
        print_info "Go not found, will install Go $GO_VERSION"
        return 1
    fi
}

install_go() {
    print_header "Installing Go $GO_VERSION"
    
    # Create temporary directory
    TEMP_DIR=$(mktemp -d)
    cd "$TEMP_DIR"
    
    # Download Go
    print_info "Downloading Go $GO_VERSION for $GO_ARCH..."
    if command -v wget &> /dev/null; then
        wget -q "$GO_URL"
    elif command -v curl &> /dev/null; then
        curl -sL "$GO_URL" -o "$GO_TARBALL"
    else
        print_error "Neither wget nor curl found. Please install one of them."
        exit 1
    fi
    
    # Verify download
    if [[ ! -f "$GO_TARBALL" ]]; then
        print_error "Failed to download Go tarball"
        exit 1
    fi
    
    print_info "Download complete: $(ls -lh $GO_TARBALL | awk '{print $5}')"
    
    # Remove existing Go installation
    if [[ -d "/usr/local/go" ]]; then
        print_info "Removing existing Go installation..."
        sudo rm -rf /usr/local/go
    fi
    
    # Extract Go
    print_info "Installing Go to /usr/local/go..."
    sudo tar -C /usr/local -xzf "$GO_TARBALL"
    
    # Cleanup
    cd /
    rm -rf "$TEMP_DIR"
    
    print_info "Go $GO_VERSION installed successfully"
}

setup_environment() {
    print_header "Setting up Go Environment"
    
    # Check if Go is already in PATH
    if echo "$PATH" | grep -q "/usr/local/go/bin"; then
        print_info "Go is already in PATH"
        return 0
    fi
    
    # Add Go to PATH in multiple shell profiles
    SHELLS=("$HOME/.bashrc" "$HOME/.bash_profile" "$HOME/.profile" "$HOME/.zshrc")
    
    GO_PATH_EXPORT='export PATH=$PATH:/usr/local/go/bin'
    
    for shell_file in "${SHELLS[@]}"; do
        if [[ -f "$shell_file" ]]; then
            if ! grep -q "/usr/local/go/bin" "$shell_file"; then
                print_info "Adding Go to PATH in $shell_file"
                echo "" >> "$shell_file"
                echo "# Go programming language" >> "$shell_file"
                echo "$GO_PATH_EXPORT" >> "$shell_file"
            else
                print_info "Go already configured in $shell_file"
            fi
        fi
    done
    
    # Set for current session
    export PATH=$PATH:/usr/local/go/bin
    
    print_info "Go environment configured"
    print_warning "You may need to restart your shell or run: source ~/.bashrc"
}

verify_installation() {
    print_header "Verifying Go Installation"
    
    # Set PATH for verification
    export PATH=$PATH:/usr/local/go/bin
    
    if command -v go &> /dev/null; then
        GO_VERSION_INSTALLED=$(go version)
        print_info "✓ $GO_VERSION_INSTALLED"
        
        # Test Go workspace
        print_info "Testing Go workspace..."
        TEMP_DIR=$(mktemp -d)
        cd "$TEMP_DIR"
        
        # Create a simple test program
        cat > hello.go << 'EOF'
package main

import "fmt"

func main() {
    fmt.Println("Go is working correctly!")
}
EOF
        
        # Test compilation and execution
        if go run hello.go &> /dev/null; then
            print_info "✓ Go compilation and execution working"
        else
            print_error "✗ Go compilation test failed"
            return 1
        fi
        
        # Cleanup
        cd /
        rm -rf "$TEMP_DIR"
        
        print_info "Go installation verified successfully"
        return 0
    else
        print_error "Go installation verification failed"
        return 1
    fi
}

# Package manager installation (alternative method)
install_via_package_manager() {
    print_header "Installing Go via Package Manager"
    
    if command -v apt &> /dev/null; then
        # Ubuntu/Debian
        print_info "Detected apt package manager (Ubuntu/Debian)"
        sudo apt update
        sudo apt install -y golang-go
        
    elif command -v yum &> /dev/null; then
        # RHEL/CentOS
        print_info "Detected yum package manager (RHEL/CentOS)"
        sudo yum install -y golang
        
    elif command -v dnf &> /dev/null; then
        # Fedora
        print_info "Detected dnf package manager (Fedora)"
        sudo dnf install -y golang
        
    elif command -v pacman &> /dev/null; then
        # Arch Linux
        print_info "Detected pacman package manager (Arch Linux)"
        sudo pacman -S --noconfirm go
        
    else
        print_warning "No supported package manager found"
        return 1
    fi
    
    print_info "Go installed via package manager"
}

show_manual_instructions() {
    cat << EOF

${YELLOW}Manual Installation Instructions:${NC}

If the automatic installation fails, you can install Go manually:

1. ${BLUE}Download Go:${NC}
   wget https://golang.org/dl/go${GO_VERSION}.linux-${GO_ARCH}.tar.gz

2. ${BLUE}Extract and install:${NC}
   sudo rm -rf /usr/local/go
   sudo tar -C /usr/local -xzf go${GO_VERSION}.linux-${GO_ARCH}.tar.gz

3. ${BLUE}Add to PATH:${NC}
   echo 'export PATH=\$PATH:/usr/local/go/bin' >> ~/.bashrc
   source ~/.bashrc

4. ${BLUE}Verify:${NC}
   go version

${YELLOW}Alternative - Package Manager:${NC}
   Ubuntu/Debian: sudo apt install golang-go
   RHEL/CentOS:   sudo yum install golang
   Fedora:        sudo dnf install golang
   Arch Linux:    sudo pacman -S go

EOF
}

# Main execution
main() {
    print_header "Go Installation for Takakrypt"
    
    # Check if Go is already installed and sufficient
    if check_existing_go; then
        print_info "Go is already properly installed"
        exit 0
    fi
    
    # Ask user for installation preference
    echo
    echo "Choose installation method:"
    echo "1) Download and install latest Go from official source (recommended)"
    echo "2) Install via system package manager (may be older version)"
    echo "3) Show manual installation instructions"
    echo
    read -p "Enter choice [1-3] (default: 1): " choice
    choice=${choice:-1}
    
    case $choice in
        1)
            install_go
            setup_environment
            verify_installation
            ;;
        2)
            install_via_package_manager
            if ! verify_installation; then
                print_warning "Package manager version may be too old"
                print_info "Consider using option 1 for latest version"
            fi
            ;;
        3)
            show_manual_instructions
            exit 0
            ;;
        *)
            print_error "Invalid choice"
            exit 1
            ;;
    esac
    
    if verify_installation; then
        print_header "Installation Complete!"
        echo
        print_info "Go has been successfully installed"
        print_info "You can now run: sudo ./scripts/setup-system.sh"
        echo
        print_warning "If you see 'command not found', restart your shell or run:"
        print_warning "source ~/.bashrc"
    else
        print_error "Installation failed"
        show_manual_instructions
        exit 1
    fi
}

# Handle command line arguments
case "${1:-install}" in
    "install")
        main
        ;;
    "verify")
        verify_installation
        ;;
    "help")
        echo "Usage: $0 [install|verify|help]"
        echo "  install - Install Go (default)"
        echo "  verify  - Verify existing Go installation"
        echo "  help    - Show this help"
        ;;
    *)
        print_error "Unknown command: $1"
        echo "Use '$0 help' for usage information"
        exit 1
        ;;
esac