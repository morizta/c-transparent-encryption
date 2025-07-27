#!/bin/bash

# Setup Multi-Guard Point Test Environment
# Creates directory structure and test files for complex access control testing

set -e

echo "🚀 Setting up Multi-Guard Point Test Environment..."
echo "=================================================="

# Test directories
SECURE_DATA_DIR="/tmp/secure-data"
DATABASE_DATA_DIR="/tmp/database-data"
CONFIG_FILE="/tmp/multi-guardpoint-test-config.yaml"

# Clean up existing test environment
echo "🧹 Cleaning up existing test environment..."
sudo rm -rf "$SECURE_DATA_DIR" "$DATABASE_DATA_DIR" 2>/dev/null || true

# Create directory structure
echo "📁 Creating directory structure..."

# Secure data directories
sudo mkdir -p "$SECURE_DATA_DIR"/{ntoi,testuser1,testuser2,shared}
sudo mkdir -p "$DATABASE_DATA_DIR"/{data,config,logs}

# Set ownership and permissions
echo "🔐 Setting up ownership and permissions..."

# Secure data ownership
sudo chown ntoi:ntoi "$SECURE_DATA_DIR"/ntoi
sudo chown 1001:1001 "$SECURE_DATA_DIR"/testuser1 2>/dev/null || echo "Note: testuser1 (UID 1001) may not exist"
sudo chown 1002:1002 "$SECURE_DATA_DIR"/testuser2 2>/dev/null || echo "Note: testuser2 (UID 1002) may not exist"
sudo chown ntoi:ntoi "$SECURE_DATA_DIR"/shared

# Database data ownership (MariaDB user)
sudo chown mysql:mysql "$DATABASE_DATA_DIR"/{data,config,logs} 2>/dev/null || {
    echo "Note: mysql user may not exist, using ntoi as fallback"
    sudo chown ntoi:ntoi "$DATABASE_DATA_DIR"/{data,config,logs}
}

# Set directory permissions
sudo chmod 750 "$SECURE_DATA_DIR"/{ntoi,testuser1,testuser2}
sudo chmod 755 "$SECURE_DATA_DIR"/shared
sudo chmod 750 "$DATABASE_DATA_DIR"/{data,config,logs}

# Create test files for secure data
echo "📄 Creating test files for secure data..."

# ntoi's files
sudo -u ntoi bash -c "cat > '$SECURE_DATA_DIR/ntoi/ntoi-confidential.txt'" << 'EOF'
This is ntoi's confidential document.
Only ntoi should be able to read and write this file.
Contains sensitive administrative information.
Created: $(date)
EOF

sudo -u ntoi bash -c "cat > '$SECURE_DATA_DIR/ntoi/admin-policy.doc'" << 'EOF'
ADMINISTRATIVE POLICY DOCUMENT
==============================
This document contains administrative policies.
ntoi has full access to this document.
Access Level: Administrative
EOF

# testuser1's files
if id testuser1 &>/dev/null; then
    sudo -u testuser1 bash -c "cat > '$SECURE_DATA_DIR/testuser1/testuser1-personal.txt'" << 'EOF'
This is testuser1's personal document.
Only testuser1 and ntoi (admin) should access this.
testuser2 should be DENIED access.
User: testuser1
EOF

    sudo -u testuser1 bash -c "cat > '$SECURE_DATA_DIR/testuser1/user1-project.doc'" << 'EOF'
PROJECT DOCUMENT - testuser1
============================
Personal project information for testuser1.
Access: testuser1 (full), ntoi (admin read/write), testuser2 (DENIED)
EOF
else
    echo "Creating testuser1 files as ntoi (testuser1 doesn't exist)"
    sudo -u ntoi bash -c "cat > '$SECURE_DATA_DIR/testuser1/testuser1-personal.txt'" << 'EOF'
This is testuser1's personal document.
Only testuser1 and ntoi (admin) should access this.
testuser2 should be DENIED access.
User: testuser1
EOF

    sudo -u ntoi bash -c "cat > '$SECURE_DATA_DIR/testuser1/user1-project.doc'" << 'EOF'
PROJECT DOCUMENT - testuser1
============================
Personal project information for testuser1.
Access: testuser1 (full), ntoi (admin read/write), testuser2 (DENIED)
EOF
fi

# testuser2's files
if id testuser2 &>/dev/null; then
    sudo -u testuser2 bash -c "cat > '$SECURE_DATA_DIR/testuser2/testuser2-personal.txt'" << 'EOF'
This is testuser2's personal document.
Only testuser2 and ntoi (admin) should access this.
testuser1 should be DENIED access.
User: testuser2
EOF

    sudo -u testuser2 bash -c "cat > '$SECURE_DATA_DIR/testuser2/user2-notes.doc'" << 'EOF'
PERSONAL NOTES - testuser2
==========================
Personal notes for testuser2.
Access: testuser2 (full), ntoi (admin read/write), testuser1 (DENIED)
EOF
else
    echo "Creating testuser2 files as ntoi (testuser2 doesn't exist)"
    sudo -u ntoi bash -c "cat > '$SECURE_DATA_DIR/testuser2/testuser2-personal.txt'" << 'EOF'
This is testuser2's personal document.
Only testuser2 and ntoi (admin) should access this.
testuser1 should be DENIED access.
User: testuser2
EOF

    sudo -u ntoi bash -c "cat > '$SECURE_DATA_DIR/testuser2/user2-notes.doc'" << 'EOF'
PERSONAL NOTES - testuser2
==========================
Personal notes for testuser2.
Access: testuser2 (full), ntoi (admin read/write), testuser1 (DENIED)
EOF
fi

# Shared files
sudo -u ntoi bash -c "cat > '$SECURE_DATA_DIR/shared/shared-document.txt'" << 'EOF'
SHARED DOCUMENT
===============
This document is shared among all users.
Access: ntoi (full), testuser1 (read), testuser2 (read)
Content: Common information for all users.
EOF

sudo -u ntoi bash -c "cat > '$SECURE_DATA_DIR/shared/common-policy.doc'" << 'EOF'
COMMON POLICY DOCUMENT
======================
Shared policy information.
All users can read this document.
Only admin (ntoi) can modify it.
EOF

# Create database test files
echo "🗄️ Creating database test files..."

# Database data files
sudo bash -c "cat > '$DATABASE_DATA_DIR/data/users.frm'" << 'EOF'
# MariaDB table structure file
# This represents a database table file
# Only MariaDB processes and custom database apps should access this
Table: users
Columns: id, username, email, created_at
EOF

sudo bash -c "cat > '$DATABASE_DATA_DIR/data/orders.ibd'" << 'EOF'
# MariaDB InnoDB data file
# Contains actual database data
# Requires encryption and strict access control
Table: orders
Data: Sensitive customer order information
EOF

sudo bash -c "cat > '$DATABASE_DATA_DIR/data/customers.MYD'" << 'EOF'
# MariaDB MyISAM data file
# Contains customer information
# High security requirement
Table: customers
Data: Personal customer information (PII)
EOF

# Database configuration files
sudo bash -c "cat > '$DATABASE_DATA_DIR/config/my.cnf'" << 'EOF'
[mysqld]
datadir = /tmp/database-data/data
socket = /tmp/database-data/mysql.sock
log-error = /tmp/database-data/logs/error.log
pid-file = /tmp/database-data/mysql.pid

# Security settings
bind-address = 127.0.0.1
skip-networking = false

# Encryption settings
innodb_encrypt_tables = ON
innodb_encrypt_log = ON
EOF

sudo bash -c "cat > '$DATABASE_DATA_DIR/config/security.conf'" << 'EOF'
# Database security configuration
# Only database admins should modify this file

[security]
ssl_cert = /etc/mysql/certs/server-cert.pem
ssl_key = /etc/mysql/certs/server-key.pem
ssl_ca = /etc/mysql/certs/ca-cert.pem

# Access control
secure_auth = ON
local_infile = OFF
EOF

# Copy configuration file
echo "📋 Copying configuration file..."
cp "/home/ntoi/c-transparent-encryption/examples/multi-guardpoint-test-config.yaml" "$CONFIG_FILE"

# Create file listing for verification
echo "📊 Creating file structure summary..."
echo ""
echo "SECURE DATA STRUCTURE:"
echo "======================"
find "$SECURE_DATA_DIR" -type f -exec ls -la {} \; 2>/dev/null || echo "Some files may not be accessible"

echo ""
echo "DATABASE DATA STRUCTURE:"
echo "========================"
find "$DATABASE_DATA_DIR" -type f -exec ls -la {} \; 2>/dev/null || echo "Some files may not be accessible"

echo ""
echo "✅ Multi-Guard Point Test Environment Setup Complete!"
echo ""
echo "Test Scenarios:"
echo "1. ntoi can access both /tmp/secure-data/ntoi and /tmp/secure-data/testuser1 and /tmp/secure-data/testuser2"
echo "2. testuser1 can ONLY access /tmp/secure-data/testuser1 (DENIED from testuser2)"
echo "3. testuser2 can ONLY access /tmp/secure-data/testuser2 (DENIED from testuser1)"
echo "4. MariaDB processes can access /tmp/database-data with encryption"
echo "5. Custom apps can access database data through MariaDB process set"
echo ""
echo "Configuration file: $CONFIG_FILE"
echo "Test with: ./test-multi-guardpoint-access.sh"