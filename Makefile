# Takakrypt Transparent Encryption System Makefile

PROJECT_NAME := takakrypt
VERSION := 1.0.0
AUTHOR := Takakrypt Development Team

# Go build variables
GO_VERSION := 1.21
GOOS := $(shell go env GOOS)
GOARCH := $(shell go env GOARCH)
GO_BUILD_FLAGS := -ldflags "-X main.version=$(VERSION) -X main.buildTime=$(shell date -u +%Y-%m-%dT%H:%M:%SZ)"

# Build directories
BUILD_DIR := build
BIN_DIR := $(BUILD_DIR)/bin
PKG_DIR := $(BUILD_DIR)/pkg
DIST_DIR := $(BUILD_DIR)/dist

# Installation directories
INSTALL_PREFIX ?= /usr/local
INSTALL_BIN_DIR := $(INSTALL_PREFIX)/bin
INSTALL_SBIN_DIR := $(INSTALL_PREFIX)/sbin
INSTALL_ETC_DIR := /etc/takakrypt
INSTALL_VAR_DIR := /var/lib/takakrypt
INSTALL_LOG_DIR := /var/log/takakrypt
INSTALL_RUN_DIR := /var/run/takakrypt
INSTALL_SERVICE_DIR := /etc/systemd/system

# Binaries to build
AGENT_BINARY := takakrypt-agent
CLI_BINARY := takakrypt-cli

# Default target
all: build

# Build all components
build: go-build kernel-build

# Build Go components
go-build: check-go-version $(BIN_DIR)/$(AGENT_BINARY) $(BIN_DIR)/$(CLI_BINARY)

# Build kernel module
kernel-build:
	@echo "Building kernel module..."
	$(MAKE) -C kernel all

# Build the agent binary
$(BIN_DIR)/$(AGENT_BINARY): cmd/takakrypt-agent/main.go $(shell find internal pkg -name '*.go' 2>/dev/null)
	@echo "Building $(AGENT_BINARY)..."
	@mkdir -p $(BIN_DIR)
	go build $(GO_BUILD_FLAGS) -o $(BIN_DIR)/$(AGENT_BINARY) ./cmd/takakrypt-agent

# Build the CLI binary
$(BIN_DIR)/$(CLI_BINARY): cmd/takakrypt-cli/main.go $(shell find internal pkg -name '*.go' 2>/dev/null)
	@echo "Building $(CLI_BINARY)..."
	@mkdir -p $(BIN_DIR)
	go build $(GO_BUILD_FLAGS) -o $(BIN_DIR)/$(CLI_BINARY) ./cmd/takakrypt-cli

# Create CLI command (placeholder)
cmd/takakrypt-cli/main.go:
	@echo "Creating CLI placeholder..."
	@mkdir -p cmd/takakrypt-cli
	@cat > cmd/takakrypt-cli/main.go << 'EOF'
package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Printf("Takakrypt CLI v%s\n", "$(VERSION)")
	fmt.Println("CLI tool for managing Takakrypt transparent encryption")
	fmt.Println("This is a placeholder - full implementation coming soon")
	os.Exit(0)
}
EOF

# Clean build artifacts
clean: clean-go clean-kernel
	@echo "Cleaning build directory..."
	rm -rf $(BUILD_DIR)

clean-go:
	@echo "Cleaning Go build artifacts..."
	go clean -cache -testcache -modcache
	rm -rf $(BIN_DIR)

clean-kernel:
	@echo "Cleaning kernel module..."
	$(MAKE) -C kernel clean

# Install everything
install: install-go install-kernel install-config install-service

# Install Go binaries
install-go: go-build
	@echo "Installing Go binaries..."
	@if [ "$(shell id -u)" != "0" ]; then \
		echo "Error: Installation requires root privileges"; \
		exit 1; \
	fi
	mkdir -p $(INSTALL_SBIN_DIR)
	cp $(BIN_DIR)/$(AGENT_BINARY) $(INSTALL_SBIN_DIR)/
	chmod 755 $(INSTALL_SBIN_DIR)/$(AGENT_BINARY)
	@if [ -f $(BIN_DIR)/$(CLI_BINARY) ]; then \
		mkdir -p $(INSTALL_BIN_DIR); \
		cp $(BIN_DIR)/$(CLI_BINARY) $(INSTALL_BIN_DIR)/; \
		chmod 755 $(INSTALL_BIN_DIR)/$(CLI_BINARY); \
	fi

# Install kernel module
install-kernel: kernel-build
	@echo "Installing kernel module..."
	$(MAKE) -C kernel install

# Install configuration files
install-config:
	@echo "Installing configuration files..."
	@if [ "$(shell id -u)" != "0" ]; then \
		echo "Error: Installation requires root privileges"; \
		exit 1; \
	fi
	mkdir -p $(INSTALL_ETC_DIR)
	cp -n configs/example.yaml $(INSTALL_ETC_DIR)/config.yaml 2>/dev/null || true
	chmod 644 $(INSTALL_ETC_DIR)/config.yaml
	mkdir -p $(INSTALL_VAR_DIR)
	mkdir -p $(INSTALL_LOG_DIR)
	mkdir -p $(INSTALL_RUN_DIR)
	chown root:root $(INSTALL_VAR_DIR) $(INSTALL_LOG_DIR) $(INSTALL_RUN_DIR)
	chmod 755 $(INSTALL_VAR_DIR) $(INSTALL_LOG_DIR) $(INSTALL_RUN_DIR)

# Install systemd service
install-service: install-go
	@echo "Installing systemd service..."
	@if [ "$(shell id -u)" != "0" ]; then \
		echo "Error: Installation requires root privileges"; \
		exit 1; \
	fi
	@cat > $(INSTALL_SERVICE_DIR)/takakrypt-agent.service << 'EOF'
[Unit]
Description=Takakrypt Transparent Encryption Agent
Documentation=man:takakrypt-agent(8)
After=network.target

[Service]
Type=simple
User=root
Group=root
ExecStart=$(INSTALL_SBIN_DIR)/$(AGENT_BINARY) -config $(INSTALL_ETC_DIR)/config.yaml
ExecReload=/bin/kill -HUP $$MAINPID
Restart=on-failure
RestartSec=5
PIDFile=$(INSTALL_RUN_DIR)/agent.pid

# Security settings
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$(INSTALL_VAR_DIR) $(INSTALL_LOG_DIR) $(INSTALL_RUN_DIR)

[Install]
WantedBy=multi-user.target
EOF
	chmod 644 $(INSTALL_SERVICE_DIR)/takakrypt-agent.service
	systemctl daemon-reload

# Uninstall everything
uninstall: uninstall-service uninstall-go uninstall-kernel uninstall-config

uninstall-go:
	@echo "Uninstalling Go binaries..."
	@if [ "$(shell id -u)" != "0" ]; then \
		echo "Error: Uninstallation requires root privileges"; \
		exit 1; \
	fi
	rm -f $(INSTALL_SBIN_DIR)/$(AGENT_BINARY)
	rm -f $(INSTALL_BIN_DIR)/$(CLI_BINARY)

uninstall-kernel:
	@echo "Uninstalling kernel module..."
	$(MAKE) -C kernel uninstall

uninstall-config:
	@echo "Uninstalling configuration..."
	@if [ "$(shell id -u)" != "0" ]; then \
		echo "Error: Uninstallation requires root privileges"; \
		exit 1; \
	fi
	@echo "Keeping user configuration files in $(INSTALL_ETC_DIR)"
	@echo "Keeping user data in $(INSTALL_VAR_DIR)"
	@echo "Keeping logs in $(INSTALL_LOG_DIR)"
	@echo "To fully remove: rm -rf $(INSTALL_ETC_DIR) $(INSTALL_VAR_DIR) $(INSTALL_LOG_DIR) $(INSTALL_RUN_DIR)"

uninstall-service:
	@echo "Uninstalling systemd service..."
	@if [ "$(shell id -u)" != "0" ]; then \
		echo "Error: Uninstallation requires root privileges"; \
		exit 1; \
	fi
	systemctl stop takakrypt-agent || true
	systemctl disable takakrypt-agent || true
	rm -f $(INSTALL_SERVICE_DIR)/takakrypt-agent.service
	systemctl daemon-reload

# Start/stop services
start:
	@echo "Starting Takakrypt services..."
	@if [ "$(shell id -u)" != "0" ]; then \
		echo "Error: Service management requires root privileges"; \
		exit 1; \
	fi
	$(MAKE) -C kernel load
	systemctl start takakrypt-agent
	systemctl status takakrypt-agent --no-pager

stop:
	@echo "Stopping Takakrypt services..."
	@if [ "$(shell id -u)" != "0" ]; then \
		echo "Error: Service management requires root privileges"; \
		exit 1; \
	fi
	systemctl stop takakrypt-agent || true
	$(MAKE) -C kernel unload

restart: stop start

enable:
	@echo "Enabling Takakrypt services..."
	@if [ "$(shell id -u)" != "0" ]; then \
		echo "Error: Service management requires root privileges"; \
		exit 1; \
	fi
	systemctl enable takakrypt-agent

disable:
	@echo "Disabling Takakrypt services..."
	@if [ "$(shell id -u)" != "0" ]; then \
		echo "Error: Service management requires root privileges"; \
		exit 1; \
	fi
	systemctl disable takakrypt-agent

# Status and monitoring
status:
	@echo "=== Takakrypt System Status ==="
	@echo ""
	@echo "--- Kernel Module ---"
	@$(MAKE) -C kernel status
	@echo ""
	@echo "--- Agent Service ---"
	@if systemctl is-active --quiet takakrypt-agent; then \
		echo "Status: RUNNING"; \
		systemctl status takakrypt-agent --no-pager -l; \
	else \
		echo "Status: NOT RUNNING"; \
	fi
	@echo ""
	@echo "--- Configuration ---"
	@if [ -f $(INSTALL_ETC_DIR)/config.yaml ]; then \
		echo "Config file: $(INSTALL_ETC_DIR)/config.yaml"; \
		echo "Config size: $$(wc -l < $(INSTALL_ETC_DIR)/config.yaml) lines"; \
	else \
		echo "Config file: NOT FOUND"; \
	fi

# Testing
test: test-go test-kernel

test-go:
	@echo "Running Go tests..."
	go test -v ./...

test-kernel:
	@echo "Testing kernel module..."
	$(MAKE) -C kernel test-load

# Development targets
dev: clean build
	@echo "Development build complete"

dev-install: dev uninstall install
	@echo "Development install complete"

# Package creation
package: build
	@echo "Creating package..."
	@mkdir -p $(DIST_DIR)
	tar -czf $(DIST_DIR)/takakrypt-$(VERSION)-$(GOOS)-$(GOARCH).tar.gz \
		-C $(BUILD_DIR) bin/ \
		-C .. kernel/ \
		-C .. configs/ \
		-C .. README.md \
		-C .. LICENSE
	@echo "Package created: $(DIST_DIR)/takakrypt-$(VERSION)-$(GOOS)-$(GOARCH).tar.gz"

# Dependency management
deps:
	@echo "Updating Go dependencies..."
	go mod tidy
	go mod download

# Code quality
lint:
	@echo "Running Go linter..."
	@if which golangci-lint > /dev/null 2>&1; then \
		golangci-lint run; \
	else \
		echo "golangci-lint not found, install with: go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest"; \
	fi

fmt:
	@echo "Formatting Go code..."
	go fmt ./...

vet:
	@echo "Running go vet..."
	go vet ./...

# Check dependencies
check-deps: check-go-version check-kernel-deps

check-go-version:
	@echo "Checking Go version..."
	@GO_CURR_VERSION=$$(go version | grep -o 'go[0-9]\+\.[0-9]\+' | sed 's/go//'); \
	GO_MIN_VERSION=$$(echo $(GO_VERSION) | sed 's/go//'); \
	if [ "$$(printf '%s\n' "$$GO_MIN_VERSION" "$$GO_CURR_VERSION" | sort -V | head -n1)" != "$$GO_MIN_VERSION" ]; then \
		echo "Error: Go $(GO_VERSION) or later required, found go$$GO_CURR_VERSION"; \
		exit 1; \
	else \
		echo "Go version OK: go$$GO_CURR_VERSION"; \
	fi

check-kernel-deps:
	@echo "Checking kernel dependencies..."
	$(MAKE) -C kernel check-deps

# Help
help:
	@echo "Takakrypt Transparent Encryption System"
	@echo "======================================="
	@echo ""
	@echo "Build targets:"
	@echo "  all          - Build all components (default)"
	@echo "  build        - Build all components"
	@echo "  go-build     - Build Go components only"
	@echo "  kernel-build - Build kernel module only"
	@echo "  clean        - Clean all build artifacts"
	@echo ""
	@echo "Installation targets:"
	@echo "  install      - Install all components (requires root)"
	@echo "  uninstall    - Uninstall all components (requires root)"
	@echo ""
	@echo "Service management:"
	@echo "  start        - Start all services (requires root)"
	@echo "  stop         - Stop all services (requires root)"
	@echo "  restart      - Restart all services (requires root)"
	@echo "  enable       - Enable services at boot (requires root)"
	@echo "  disable      - Disable services at boot (requires root)"
	@echo "  status       - Show system status"
	@echo ""
	@echo "Testing and quality:"
	@echo "  test         - Run all tests"
	@echo "  lint         - Run code linter"
	@echo "  fmt          - Format code"
	@echo "  vet          - Run go vet"
	@echo ""
	@echo "Development:"
	@echo "  dev          - Development build"
	@echo "  dev-install  - Development install cycle"
	@echo "  deps         - Update dependencies"
	@echo "  package      - Create distribution package"
	@echo ""
	@echo "Utilities:"
	@echo "  check-deps   - Check build dependencies"
	@echo "  help         - Show this help"
	@echo ""
	@echo "Examples:"
	@echo "  make                    # Build everything"
	@echo "  sudo make install       # Install system-wide"
	@echo "  sudo make start         # Start services"
	@echo "  make status            # Check status"
	@echo "  make dev               # Development build"

# Declare phony targets
.PHONY: all build go-build kernel-build clean clean-go clean-kernel
.PHONY: install install-go install-kernel install-config install-service
.PHONY: uninstall uninstall-go uninstall-kernel uninstall-config uninstall-service
.PHONY: start stop restart enable disable status
.PHONY: test test-go test-kernel
.PHONY: dev dev-install package deps lint fmt vet
.PHONY: check-deps check-go-version check-kernel-deps help