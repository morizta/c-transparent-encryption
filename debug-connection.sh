#!/bin/bash

echo "=== Takakrypt Connection Debug ==="
echo

echo "1. Kernel Module Status:"
if lsmod | grep -q takakrypt; then
    echo "✓ Kernel module loaded"
    echo "Module details:"
    lsmod | grep takakrypt
else
    echo "✗ Kernel module NOT loaded"
    exit 1
fi
echo

echo "2. Proc Interface:"
if [[ -r /proc/takakrypt/status ]]; then
    echo "✓ Proc interface available"
    echo "Agent connection status:"
    grep -E "Agent Connection:|Connected:|Agent PID:" /proc/takakrypt/status
else
    echo "✗ Proc interface not available"
fi
echo

echo "3. Agent Process:"
AGENT_PIDS=$(pgrep -f "takakrypt-agent")
if [[ -n "$AGENT_PIDS" ]]; then
    echo "✓ Agent process(es) running:"
    ps aux | grep takakrypt-agent | grep -v grep
else
    echo "✗ No agent processes found"
fi
echo

echo "4. Socket Files:"
echo "Checking for socket files..."
find /tmp /var/run -name "*takakrypt*" 2>/dev/null | head -10
echo

echo "5. Netlink Test:"
echo "Testing netlink socket creation..."
cat > /tmp/test_netlink_detailed.c << 'EOF'
#include <stdio.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

int main() {
    printf("Testing netlink socket creation...\n");
    
    // Try NETLINK_USERSOCK (25)
    int sock = socket(AF_NETLINK, SOCK_RAW, 25);
    if (sock < 0) {
        printf("NETLINK_USERSOCK failed: %s\n", strerror(errno));
        
        // Try NETLINK_GENERIC
        sock = socket(AF_NETLINK, SOCK_RAW, 16);
        if (sock < 0) {
            printf("NETLINK_GENERIC failed: %s\n", strerror(errno));
            return 1;
        } else {
            printf("NETLINK_GENERIC succeeded\n");
            close(sock);
        }
    } else {
        printf("NETLINK_USERSOCK succeeded\n");
        close(sock);
    }
    return 0;
}
EOF

if gcc -o /tmp/test_netlink_detailed /tmp/test_netlink_detailed.c 2>/dev/null; then
    /tmp/test_netlink_detailed
    rm -f /tmp/test_netlink_detailed /tmp/test_netlink_detailed.c
else
    echo "Could not compile netlink test"
fi
echo

echo "6. File Operation Test:"
echo "Testing if file operations are being intercepted..."
echo "Before writing test file:"
cat /proc/takakrypt/status | grep "Total Processed"

echo "Writing test file..."
echo "test" > /tmp/takakrypt-test/debug-test.txt

echo "After writing test file:"
cat /proc/takakrypt/status | grep "Total Processed"

echo "Reading test file..."
cat /tmp/takakrypt-test/debug-test.txt > /dev/null

echo "After reading test file:"
cat /proc/takakrypt/status | grep "Total Processed"
echo

echo "=== Diagnosis ==="
echo "If 'Total Processed' is still 0, the VFS hooks aren't working."
echo "If 'Agent Connected: No', there's a netlink communication issue."
echo "Check 'sudo dmesg | tail' for kernel module messages."