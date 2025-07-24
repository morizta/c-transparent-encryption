# Takakrypt Kernel Module Makefile

# Module information
MODULE_NAME := takakrypt
VERSION := 1.0.0

# Kernel build directory - try to detect automatically
KDIR ?= /lib/modules/$(shell uname -r)/build

# If KDIR doesn't exist, try common alternatives
ifeq ($(wildcard $(KDIR)),)
    KDIR := /usr/src/linux-headers-$(shell uname -r)
endif
ifeq ($(wildcard $(KDIR)),)
    KDIR := /usr/src/kernels/$(shell uname -r)
endif

# Build directory
PWD := $(shell pwd)

# Source files
obj-m := $(MODULE_NAME).o
$(MODULE_NAME)-objs := main.o vfs_hooks.o netlink.o cache.o file_context.o proc.o

# Compiler flags
ccflags-y := -DTAKAKRYPT_VERSION=\"$(VERSION)\"
ccflags-y += -Wall -Wextra -Werror
ccflags-y += -DDEBUG

# Installation directories
INSTALL_MOD_DIR ?= /lib/modules/$(shell uname -r)/extra
INSTALL_INC_DIR ?= /usr/include/takakrypt

# Default target
all: modules

# Build the kernel module
modules:
	@echo "Building Takakrypt kernel module v$(VERSION)"
	@echo "Using kernel build directory: $(KDIR)"
	@if [ ! -d "$(KDIR)" ]; then \
		echo "Error: Kernel build directory not found: $(KDIR)"; \
		echo "Please install kernel headers or set KDIR manually"; \
		exit 1; \
	fi
	$(MAKE) -C $(KDIR) M=$(PWD) modules

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts"
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	rm -f *.ur-safe

# Install the module
install: modules
	@echo "Installing Takakrypt kernel module"
	@if [ "$(shell id -u)" != "0" ]; then \
		echo "Error: Installation requires root privileges"; \
		exit 1; \
	fi
	mkdir -p $(INSTALL_MOD_DIR)
	cp $(MODULE_NAME).ko $(INSTALL_MOD_DIR)/
	mkdir -p $(INSTALL_INC_DIR)
	cp takakrypt.h $(INSTALL_INC_DIR)/
	depmod -a
	@echo "Module installed to $(INSTALL_MOD_DIR)"
	@echo "Header installed to $(INSTALL_INC_DIR)"

# Uninstall the module
uninstall:
	@echo "Uninstalling Takakrypt kernel module"
	@if [ "$(shell id -u)" != "0" ]; then \
		echo "Error: Uninstallation requires root privileges"; \
		exit 1; \
	fi
	rm -f $(INSTALL_MOD_DIR)/$(MODULE_NAME).ko
	rm -rf $(INSTALL_INC_DIR)
	depmod -a
	@echo "Module uninstalled"

# Load the module
load: modules
	@echo "Loading Takakrypt kernel module"
	@if [ "$(shell id -u)" != "0" ]; then \
		echo "Error: Loading module requires root privileges"; \
		exit 1; \
	fi
	@if lsmod | grep -q "^$(MODULE_NAME)"; then \
		echo "Module already loaded"; \
	else \
		insmod $(MODULE_NAME).ko; \
		echo "Module loaded successfully"; \
	fi
	@echo "Module status:"
	@lsmod | grep $(MODULE_NAME) || echo "Module not found in lsmod output"

# Unload the module
unload:
	@echo "Unloading Takakrypt kernel module"
	@if [ "$(shell id -u)" != "0" ]; then \
		echo "Error: Unloading module requires root privileges"; \
		exit 1; \
	fi
	@if lsmod | grep -q "^$(MODULE_NAME)"; then \
		rmmod $(MODULE_NAME); \
		echo "Module unloaded successfully"; \
	else \
		echo "Module not currently loaded"; \
	fi

# Reload the module (unload + load)
reload: unload load

# Show module information
modinfo: modules
	@echo "Module information:"
	modinfo $(MODULE_NAME).ko

# Show module status
status:
	@echo "=== Module Status ==="
	@if lsmod | grep -q "^$(MODULE_NAME)"; then \
		echo "Status: LOADED"; \
		lsmod | grep $(MODULE_NAME); \
	else \
		echo "Status: NOT LOADED"; \
	fi
	@echo ""
	@echo "=== Kernel Messages ==="
	@if [ -r /var/log/kern.log ]; then \
		tail -n 20 /var/log/kern.log | grep -i takakrypt || echo "No recent kernel messages found"; \
	else \
		dmesg | grep -i takakrypt | tail -n 20 || echo "No kernel messages found"; \
	fi
	@echo ""
	@echo "=== Proc Interface ==="
	@if [ -d /proc/takakrypt ]; then \
		echo "Proc interface available at /proc/takakrypt"; \
		ls -la /proc/takakrypt/; \
	else \
		echo "Proc interface not available"; \
	fi

# Development helpers
dev-build: clean modules
	@echo "Development build complete"

dev-install: dev-build unload install load
	@echo "Development install complete"

# Testing targets
test-load: modules
	@echo "Testing module load/unload cycle"
	@if [ "$(shell id -u)" != "0" ]; then \
		echo "Error: Testing requires root privileges"; \
		exit 1; \
	fi
	@echo "1. Loading module..."
	sudo insmod $(MODULE_NAME).ko
	@echo "2. Checking if loaded..."
	lsmod | grep $(MODULE_NAME)
	@echo "3. Waiting 2 seconds..."
	sleep 2
	@echo "4. Unloading module..."
	sudo rmmod $(MODULE_NAME)
	@echo "5. Test completed successfully"

# Check dependencies
check-deps:
	@echo "Checking build dependencies:"
	@echo -n "Kernel headers: "
	@if [ -d "$(KDIR)" ]; then \
		echo "OK ($(KDIR))"; \
	else \
		echo "MISSING"; \
		echo "  Please install kernel headers:"; \
		echo "  Ubuntu/Debian: apt-get install linux-headers-\$$(uname -r)"; \
		echo "  RHEL/CentOS:   yum install kernel-devel-\$$(uname -r)"; \
		exit 1; \
	fi
	@echo -n "Build tools: "
	@if which make gcc > /dev/null 2>&1; then \
		echo "OK"; \
	else \
		echo "MISSING"; \
		echo "  Please install build-essential or development tools"; \
		exit 1; \
	fi
	@echo "All dependencies satisfied"

# Help target
help:
	@echo "Takakrypt Kernel Module Build System"
	@echo "===================================="
	@echo ""
	@echo "Targets:"
	@echo "  all          - Build the module (default)"
	@echo "  modules      - Build the module"
	@echo "  clean        - Clean build artifacts"
	@echo "  install      - Install module and headers (requires root)"
	@echo "  uninstall    - Remove installed module and headers (requires root)"
	@echo "  load         - Load the module (requires root)"
	@echo "  unload       - Unload the module (requires root)"
	@echo "  reload       - Unload and reload the module (requires root)"
	@echo "  modinfo      - Show module information"
	@echo "  status       - Show module status and recent logs"
	@echo "  check-deps   - Check build dependencies"
	@echo "  test-load    - Test load/unload cycle (requires root)"
	@echo "  help         - Show this help message"
	@echo ""
	@echo "Development targets:"
	@echo "  dev-build    - Clean build for development"
	@echo "  dev-install  - Full development cycle (build, unload, install, load)"
	@echo ""
	@echo "Variables:"
	@echo "  KDIR         - Kernel build directory (auto-detected: $(KDIR))"
	@echo "  VERSION      - Module version ($(VERSION))"
	@echo ""
	@echo "Examples:"
	@echo "  make                    # Build the module"
	@echo "  make install            # Install the module"
	@echo "  sudo make load          # Load the module"
	@echo "  make status            # Check module status"
	@echo "  make KDIR=/custom/path  # Use custom kernel directory"

# Declare phony targets
.PHONY: all modules clean install uninstall load unload reload modinfo status help
.PHONY: dev-build dev-install test-load check-deps