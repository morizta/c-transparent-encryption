# Service Name Collision Notice

## Important: Service Name Change

Our Takakrypt C Transparent Encryption (CTE) system has been renamed to avoid conflicts with existing services.

### Original vs New Service Names

| Component | Original Name | New Name | Reason |
|-----------|---------------|----------|---------|
| Systemd Service | `takakrypt` | `takakrypt-cte` | Avoid collision with existing FUSE-based takakrypt |
| Kernel Module | `takakrypt` | `takakrypt` | No collision (kernel module namespace) |
| Binaries | No change | No change | No collision |

### Existing Service Detection

If you see an existing `takakrypt` service on your system:

```bash
sudo systemctl status takakrypt
```

This is likely a **FUSE-based** transparent encryption service that's different from our **VFS-based** implementation.

### Key Differences

| Aspect | Existing takakrypt (FUSE) | Our takakrypt-cte (VFS) |
|--------|---------------------------|-------------------------|
| **Approach** | FUSE filesystem | VFS kernel module |
| **Performance** | User-space overhead | Kernel-space efficiency |
| **Implementation** | FUSE mount points | Direct VFS interception |
| **Service Name** | `takakrypt` | `takakrypt-cte` |

### Using Our System

Always use the `takakrypt-cte` service name:

```bash
# Our service (VFS-based)
sudo systemctl status takakrypt-cte
sudo systemctl start takakrypt-cte
sudo journalctl -u takakrypt-cte -f

# NOT the existing service
sudo systemctl status takakrypt  # ← This is the FUSE-based one
```

### Both Can Coexist

- The existing FUSE-based `takakrypt` service can continue running
- Our VFS-based `takakrypt-cte` service operates independently
- They use different mechanisms and don't conflict
- Choose the one that fits your needs better

### Quick Identification

To identify which service is which:

```bash
# Check existing service
sudo systemctl status takakrypt | grep -i fuse

# Check our service
sudo systemctl status takakrypt-cte | grep -i "CTE\|Transparent"

# Check kernel module (ours)
lsmod | grep takakrypt
cat /proc/takakrypt/status
```

### Migration Note

If you were previously using the FUSE-based takakrypt and want to switch to our VFS-based implementation:

1. **Stop existing service**: `sudo systemctl stop takakrypt`
2. **Install our system**: `sudo ./scripts/setup-system.sh`
3. **Start our service**: `sudo systemctl start takakrypt-cte`
4. **Configure guard points** as needed

Both systems can run simultaneously if needed for testing or migration purposes.