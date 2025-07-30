# Takakrypt Development Commands & Utilities

## Module Development
```bash
# Build kernel module
make -s

# Reload kernel module (from kernel/ directory)
echo 'Primasys2012' | sudo -S rmmod takakrypt && echo 'Primasys2012' | sudo -S insmod takakrypt.ko

# Load module only
echo 'Primasys2012' | sudo -S insmod takakrypt.ko

# Remove module only
echo 'Primasys2012' | sudo -S rmmod takakrypt
```

## Agent Management
```bash
# Stop agent
pkill -f takakrypt-agent

# Start agent
./takakrypt-agent
```

## Testing & Debugging
```bash
# Check kernel logs
dmesg | tail -20

# Check module status
lsmod | grep takakrypt
```