#!/bin/bash
# Setup script for Linux VM testing with testuser1, testuser2, and ntoi

set -e

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log() {
    echo -e "${GREEN}[SETUP]${NC} $1"
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
    exit 1
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    error "This script must be run as root (sudo)"
fi

log "Setting up Takakrypt test environment for Linux VM"

# Create test directories
log "Creating test directories..."
mkdir -p /tmp/secure
mkdir -p /tmp/shared  
mkdir -p /tmp/ntoi-private

# Set proper permissions
chmod 755 /tmp/secure /tmp/shared /tmp/ntoi-private

# Create test files for different scenarios
log "Creating test files..."

# Files for admin_only policy (ntoi access only)
cat > /tmp/secure/admin-secret.txt << EOF
This is a highly confidential document.
Only administrators should be able to access this.
Access level: ADMIN ONLY
EOF

cat > /tmp/secure/financial-report.pdf << EOF
CONFIDENTIAL FINANCIAL REPORT
=============================
This file should only be accessible by ntoi user.
EOF

# Files for test_users_policy (testuser1, testuser2, ntoi access)
cat > /tmp/shared/team-document.txt << EOF
This is a shared team document.
Accessible by: testuser1, testuser2, and ntoi
Content: General team information
EOF

cat > /tmp/shared/project-notes.md << EOF
# Project Notes

This document can be accessed by test users and admins.
- testuser1: Can read/write
- testuser2: Can read/write  
- ntoi: Can read/write (admin)
EOF

# Files for ntoi_only policy
cat > /tmp/ntoi-private/personal-notes.txt << EOF
Personal notes for ntoi user only.
This should use ChaCha20-Poly1305 encryption.
Private content here.
EOF

# Set file ownership
log "Setting file ownership..."
chown root:root /tmp/secure/*
chown root:root /tmp/shared/*
chown root:root /tmp/ntoi-private/*

# Set permissions
chmod 644 /tmp/secure/*
chmod 644 /tmp/shared/*
chmod 644 /tmp/ntoi-private/*

log "Test environment setup complete!"
log ""
log "=== Test Directories Created ==="
log "/tmp/secure/        - Admin only (ntoi)"
log "/tmp/shared/        - Test users + admin (testuser1, testuser2, ntoi)"
log "/tmp/ntoi-private/  - ntoi only"
log ""
log "=== Test Files Created ==="
ls -la /tmp/secure/
ls -la /tmp/shared/
ls -la /tmp/ntoi-private/
log ""
log "=== Next Steps ==="
log "1. Build the system: make build"
log "2. Load kernel module: sudo make -C kernel load"
log "3. Start agent: ./build/takakrypt-agent -config configs/linux-test.yaml"
log "4. Test access as different users:"
log "   sudo -u testuser1 cat /tmp/shared/team-document.txt"
log "   sudo -u testuser2 cat /tmp/shared/project-notes.md"
log "   sudo -u ntoi cat /tmp/secure/admin-secret.txt"
log "   sudo -u testuser1 cat /tmp/secure/admin-secret.txt  # Should be denied"