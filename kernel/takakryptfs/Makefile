# Takakrypt Stackable Filesystem Makefile

# Module name
MODULE_NAME := takakryptfs

# Object files
obj-m += $(MODULE_NAME).o
$(MODULE_NAME)-objs := main_legacy.o super.o mount.o inode.o file.o dir.o crypto.o policy.o

# Kernel build directory
KERNEL_BUILD := /lib/modules/$(shell uname -r)/build

# Default target
all: modules

# Build kernel modules
modules:
	@echo "Building Takakrypt stackable filesystem module..."
	@echo "Copying symbols from parent module..."
	@cp ../Module.symvers . 2>/dev/null || true
	$(MAKE) -C $(KERNEL_BUILD) M=$(PWD) KBUILD_EXTRA_SYMBOLS=../Module.symvers modules

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	$(MAKE) -C $(KERNEL_BUILD) M=$(PWD) clean
	rm -f *.symvers *.order *.markers

# Install module
install: modules
	@echo "Installing Takakrypt stackable filesystem module..."
	$(MAKE) -C $(KERNEL_BUILD) M=$(PWD) modules_install
	depmod -a

# Uninstall module
uninstall:
	@echo "Uninstalling Takakrypt stackable filesystem module..."
	rm -f /lib/modules/$(shell uname -r)/extra/$(MODULE_NAME).ko
	depmod -a

# Load module
load:
	@echo "Loading Takakrypt stackable filesystem module..."
	sudo insmod $(MODULE_NAME).ko

# Unload module
unload:
	@echo "Unloading Takakrypt stackable filesystem module..."
	sudo rmmod $(MODULE_NAME)

# Reload module
reload: unload load

# Show module info
info:
	@echo "Module information:"
	modinfo $(MODULE_NAME).ko

# Check if module is loaded
status:
	@echo "Module status:"
	@lsmod | grep $(MODULE_NAME) || echo "Module not loaded"

# Test mount (requires root)
test-mount:
	@echo "Testing mount..."
	@if [ ! -d /tmp/takakrypt-lower ]; then mkdir -p /tmp/takakrypt-lower; fi
	@if [ ! -d /tmp/takakrypt-mount ]; then mkdir -p /tmp/takakrypt-mount; fi
	@echo "Test file content" > /tmp/takakrypt-lower/test.txt
	sudo mount -t takakryptfs -o lowerdir=/tmp/takakrypt-lower,policy=test_policy takakryptfs /tmp/takakrypt-mount
	@echo "Mount successful. Test with:"
	@echo "  ls -la /tmp/takakrypt-mount/"
	@echo "  cat /tmp/takakrypt-mount/test.txt"
	@echo "Unmount with: sudo umount /tmp/takakrypt-mount"

# Unmount test
test-umount:
	@echo "Unmounting test filesystem..."
	sudo umount /tmp/takakrypt-mount || true

# Full test cycle
test: modules load test-mount

# Development targets
dev-clean: unload clean

dev-build: clean modules

dev-test: dev-build load test-mount

# Debug targets
debug-load:
	@echo "Loading module with debug output..."
	sudo insmod $(MODULE_NAME).ko
	sudo dmesg | tail -20

debug-unload:
	@echo "Unloading module..."
	sudo rmmod $(MODULE_NAME)
	sudo dmesg | tail -10

# Help
help:
	@echo "Takakrypt Stackable Filesystem Build System"
	@echo ""
	@echo "Targets:"
	@echo "  all, modules    - Build kernel module"
	@echo "  clean          - Clean build artifacts"
	@echo "  install        - Install module to system"
	@echo "  uninstall      - Remove module from system"
	@echo "  load           - Load module into kernel"
	@echo "  unload         - Unload module from kernel"
	@echo "  reload         - Unload and reload module"
	@echo "  info           - Show module information"
	@echo "  status         - Check if module is loaded"
	@echo "  test-mount     - Create test mount"
	@echo "  test-umount    - Unmount test filesystem"
	@echo "  test           - Full test cycle (build + load + mount)"
	@echo "  dev-clean      - Development clean (unload + clean)"
	@echo "  dev-build      - Development build (clean + build)"
	@echo "  dev-test       - Development test (build + load + mount)"
	@echo "  debug-load     - Load with debug output"
	@echo "  debug-unload   - Unload with debug output"
	@echo "  help           - Show this help"
	@echo ""
	@echo "Example usage:"
	@echo "  make               # Build module"
	@echo "  make dev-test      # Full development test"
	@echo "  make test-mount    # Test mounting"

.PHONY: all modules clean install uninstall load unload reload info status \
        test-mount test-umount test dev-clean dev-build dev-test \
        debug-load debug-unload help