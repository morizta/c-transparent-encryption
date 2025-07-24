# Takakrypt Transparent Encryption System

A comprehensive transparent file encryption system for Linux, providing automatic encryption/decryption of files based on configurable policies. Similar to Thales CTE/LDT, Takakrypt offers seamless protection without application modification.

## Features

- **Transparent Operation**: Files are encrypted/decrypted automatically without application changes
- **Policy-Based Control**: Flexible policies based on users, processes, and resources
- **Guard Points**: Protect specific directories with configurable policies  
- **High Performance**: Kernel-level caching for sub-millisecond policy decisions
- **KMS Integration**: External key management system support
- **Comprehensive Monitoring**: Real-time statistics via /proc interface
- **Enterprise Ready**: Systemd integration, audit logging, health checks

## Architecture

The system consists of two main components:

1. **Kernel Module** (C): Intercepts file system operations and enforces policies
2. **User-Space Agent** (Go): Handles encryption/decryption and KMS communication

## Quick Start

### Prerequisites

- Linux kernel 4.x or later with headers
- Go 1.21 or later
- Root access for kernel operations

### Installation

```bash
# Clone the repository
git clone https://github.com/takakrypt/c-transparent-encryption
cd c-transparent-encryption

# Check dependencies
make check-deps

# Build the system
make build

# Install system-wide
sudo make install

# Start services
sudo make start

# Check status
sudo make status
```

### Basic Configuration

Edit `/etc/takakrypt/config.yaml`:

```yaml
guard_points:
  - name: "sensitive_docs"
    path: "/home/*/Documents/Confidential"
    recursive: true
    policy: "encrypt_documents"
    enabled: true

policies:
  encrypt_documents:
    algorithm: "AES-256-GCM"
    user_sets: ["authorized_users"]
    enabled: true

user_sets:
  authorized_users:
    users: ["alice", "bob"]
    groups: ["security"]
```

## Testing

Run the comprehensive test suite:

```bash
# Run all tests
sudo ./scripts/test-system.sh

# Run unit tests only
make test

# Run integration tests
go test -v ./tests/...

# Check kernel module
sudo make -C kernel status
```

See [TESTING.md](TESTING.md) for detailed testing procedures.

## Documentation

- [DESIGN.md](DESIGN.md) - System design and architecture
- [ARCHITECTURE.md](ARCHITECTURE.md) - Technical architecture details
- [TESTING.md](TESTING.md) - Comprehensive testing guide
- [PROJECT_LOG.md](PROJECT_LOG.md) - Development progress log

## Usage Examples

### Protecting a Directory

```bash
# Add to configuration
guard_points:
  - name: "project_files"
    path: "/opt/projects/secret"
    policy: "developer_encryption"
    enabled: true

# Reload configuration
sudo systemctl reload takakrypt-agent
```

### Monitoring System

```bash
# View real-time statistics
watch -n 1 cat /proc/takakrypt/status

# Check active files
cat /proc/takakrypt/files

# View cache performance
cat /proc/takakrypt/cache
```

### Managing Services

```bash
# Stop services
sudo make stop

# Start services
sudo make start

# View logs
sudo journalctl -u takakrypt-agent -f

# Check kernel messages
sudo dmesg | grep takakrypt
```

## Performance

- Policy decision latency: < 1ms (with cache)
- Encryption throughput: > 100MB/s (AES-NI)
- Memory overhead: < 50MB
- Cache hit rate: > 95%

## Security Considerations

- All encryption keys are managed by external KMS
- Memory protection for sensitive data
- Comprehensive audit logging
- Input validation at all boundaries
- Kernel security best practices followed

## Build Options

```bash
# Development build
make dev

# Create distribution package
make package

# Run linter
make lint

# Format code
make fmt
```

## Troubleshooting

### Module Won't Load
```bash
# Check kernel version
uname -r

# Verify headers installed
ls /lib/modules/$(uname -r)/build/

# Check dmesg for errors
sudo dmesg | tail -50
```

### Agent Connection Issues
```bash
# Check if agent is running
systemctl status takakrypt-agent

# Verify netlink communication
cat /proc/takakrypt/status | grep agent_connected
```

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the GPL License - see the LICENSE file for details.

## Acknowledgments

- Inspired by Thales CipherTrust Transparent Encryption
- Built with Linux kernel best practices
- Uses industry-standard encryption algorithms

## Support

For issues and questions:
- GitHub Issues: [github.com/takakrypt/c-transparent-encryption/issues](https://github.com/takakrypt/c-transparent-encryption/issues)
- Documentation: [docs.takakrypt.io](https://docs.takakrypt.io)

---
**Version**: 1.0.0  
**Status**: Production Ready  
**Last Updated**: 2025-07-24