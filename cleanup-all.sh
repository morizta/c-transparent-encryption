#!/bin/bash

# Cleanup script to terminate all Takakrypt processes and unload kernel module
# This script requires sudo privileges

echo "=== Takakrypt Cleanup Script ==="

# Function to kill processes by pattern
kill_processes() {
    local pattern="$1"
    local signal="$2"
    
    echo "Looking for processes matching: $pattern"
    pids=$(pgrep -f "$pattern" 2>/dev/null)
    
    if [ -n "$pids" ]; then
        echo "Found PIDs: $pids"
        for pid in $pids; do
            echo "Killing PID $pid with signal $signal"
            sudo kill $signal $pid 2>/dev/null || true
        done
        sleep 1
    else
        echo "No processes found matching: $pattern"
    fi
}

# Kill all takakrypt-related processes
echo "=== Killing Takakrypt processes ==="
kill_processes "takakrypt-agent" "-TERM"
kill_processes "takakrypt" "-TERM"

# Wait a moment
sleep 2

# Force kill any remaining processes
echo "=== Force killing remaining processes ==="
kill_processes "takakrypt-agent" "-KILL"
kill_processes "takakrypt" "-KILL"

# Wait for processes to fully terminate
sleep 2

# Check for any remaining processes
remaining=$(pgrep -f "takakrypt" 2>/dev/null)
if [ -n "$remaining" ]; then
    echo "Warning: Some processes still running: $remaining"
    echo "Attempting final cleanup..."
    sudo pkill -9 -f takakrypt 2>/dev/null || true
    sleep 1
fi

# Unload kernel module
echo "=== Unloading kernel module ==="
if lsmod | grep -q takakrypt; then
    echo "Takakrypt module is loaded, removing..."
    sudo rmmod takakrypt 2>/dev/null || {
        echo "Failed to remove module normally, trying force remove..."
        sudo rmmod -f takakrypt 2>/dev/null || {
            echo "Error: Could not remove kernel module"
            echo "You may need to reboot to fully clean up"
        }
    }
else
    echo "Takakrypt module is not loaded"
fi

# Verify cleanup
echo "=== Cleanup verification ==="
remaining_procs=$(pgrep -f "takakrypt" 2>/dev/null)
module_loaded=$(lsmod | grep takakrypt)

if [ -z "$remaining_procs" ] && [ -z "$module_loaded" ]; then
    echo "✓ Cleanup successful - no remaining processes or modules"
else
    echo "⚠ Cleanup incomplete:"
    [ -n "$remaining_procs" ] && echo "  - Remaining processes: $remaining_procs"
    [ -n "$module_loaded" ] && echo "  - Module still loaded: takakrypt"
fi

echo "=== Cleanup complete ==="