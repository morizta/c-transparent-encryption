# Takakrypt Quick Start Guide

## 🚀 Quick Installation

```bash
# 1. Install and start system (as root)
sudo ./scripts/setup-system.sh

# 2. Check status
sudo systemctl status takakrypt-cte
cat /proc/takakrypt/status
```

## 🔧 Basic Configuration

Edit `/etc/takakrypt/config.yaml`:

```yaml
guard_points:
  - name: "my_secrets"
    path: "/home/user/Documents/Private"
    recursive: true
    include_patterns: ["*.txt", "*.doc", "*.pdf"]
    policy: "encrypt_everything"
    enabled: true

user_sets:
  trusted_users:
    users: ["user", "admin"]
    uids: [1000, 1001]

policies:
  encrypt_everything:
    algorithm: "AES-256-GCM"
    user_sets: ["trusted_users"]
    enabled: true
```

## 🧪 Test It

```bash
# 1. Create test directory
mkdir -p /tmp/test-encryption

# 2. Add guard point in config for /tmp/test-encryption

# 3. Restart service
sudo systemctl restart takakrypt-cte

# 4. Test encryption
echo "secret data" > /tmp/test-encryption/secret.txt
cat /tmp/test-encryption/secret.txt  # Shows: secret data

# 5. Check raw disk content (should be encrypted)
sudo hexdump -C /tmp/test-encryption/secret.txt
```

## 📊 Monitor

```bash
# Service status
sudo systemctl status takakrypt-cte

# Live logs
sudo journalctl -u takakrypt-cte -f

# Kernel module stats
cat /proc/takakrypt/status

# Cache info
cat /proc/takakrypt/cache
```

## 🛠️ Commands

```bash
# System control
sudo systemctl start/stop/restart takakrypt-cte
sudo modprobe takakrypt        # Load kernel module
sudo rmmod takakrypt           # Unload kernel module

# Configuration
sudo vim /etc/takakrypt/config.yaml
sudo systemctl reload takakrypt-cte

# Testing
takakrypt-cli status
takakrypt-cli test-policy -file /path/to/file
```

## 🔄 How It Works

1. **Write**: `echo "data" > /protected/file.txt`
   - Kernel intercepts write
   - Agent encrypts data
   - Encrypted data stored on disk

2. **Read**: `cat /protected/file.txt`
   - Kernel intercepts read
   - Agent decrypts data
   - Plaintext returned to user

3. **Transparent**: Applications see normal files, encryption happens automatically

## 🏗️ Architecture

```
[Application] 
     ↕
[VFS Layer] 
     ↕
[Takakrypt Kernel Module (C)]  ←→ [Takakrypt Agent (Go)]
     ↕                             (Policy + Crypto)
[Filesystem]
```

## 🔍 Troubleshooting

```bash
# Kernel module issues
dmesg | grep takakrypt
lsmod | grep takakrypt

# Agent issues
sudo journalctl -u takakrypt-cte
sudo /usr/local/bin/takakrypt-agent -config /etc/takakrypt/config.yaml -debug

# File not encrypted?
takakrypt-cli debug -file /path/to/file
cat /proc/takakrypt/status
```

## 📁 Key Files

| Path | Purpose |
|------|---------|
| `/etc/takakrypt/config.yaml` | Main configuration |
| `/var/log/takakrypt/` | Log files |
| `/proc/takakrypt/status` | Runtime statistics |
| `/var/run/takakrypt.sock` | Agent communication socket |
| `/lib/modules/*/extra/takakrypt.ko` | Kernel module |

## 🔐 Security Notes

- Run agent as root (required for kernel communication)
- Protect configuration files (contain policy information)
- Monitor audit logs for access attempts
- Keys are managed by KMS (not stored locally)
- Encryption happens transparently at VFS level

For complete documentation, see `SYSTEM_GUIDE.md`.