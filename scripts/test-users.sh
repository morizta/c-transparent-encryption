#!/bin/bash
# Test script for user-based access control
# Tests access with testuser1, testuser2, and ntoi

set -e

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() {
    echo -e "${GREEN}[TEST]${NC} $1"
}

info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

# Test function
test_access() {
    local user=$1
    local file=$2
    local expected=$3  # "allow" or "deny"
    
    info "Testing $user access to $file (expecting: $expected)"
    
    if sudo -u $user cat $file > /dev/null 2>&1; then
        if [[ "$expected" == "allow" ]]; then
            log "✅ $user can access $file (CORRECT)"
        else
            error "❌ $user can access $file (SHOULD BE DENIED)"
        fi
    else
        if [[ "$expected" == "deny" ]]; then
            log "✅ $user denied access to $file (CORRECT)"
        else
            error "❌ $user denied access to $file (SHOULD BE ALLOWED)"
        fi
    fi
}

log "=== Takakrypt User Access Control Test ==="
log "Testing with users: testuser1, testuser2, ntoi"
log ""

# Wait for agent to be ready
log "Waiting for agent to initialize..."
sleep 2

log "=== Testing Admin-Only Files (ntoi only) ==="
test_access "ntoi" "/tmp/secure/admin-secret.txt" "allow"
test_access "testuser1" "/tmp/secure/admin-secret.txt" "deny"
test_access "testuser2" "/tmp/secure/admin-secret.txt" "deny"

echo ""
log "=== Testing Shared Files (testuser1, testuser2, ntoi) ==="
test_access "testuser1" "/tmp/shared/team-document.txt" "allow"
test_access "testuser2" "/tmp/shared/team-document.txt" "allow"
test_access "ntoi" "/tmp/shared/team-document.txt" "allow"

echo ""
log "=== Testing ntoi Private Files (ntoi only) ==="
test_access "ntoi" "/tmp/ntoi-private/personal-notes.txt" "allow"
test_access "testuser1" "/tmp/ntoi-private/personal-notes.txt" "deny"
test_access "testuser2" "/tmp/ntoi-private/personal-notes.txt" "deny"

echo ""
log "=== Checking Kernel Module Statistics ==="
if [[ -f /proc/takakrypt/status ]]; then
    info "Kernel module statistics:"
    cat /proc/takakrypt/status | grep -E "(Total Processed|Allowed|Denied|Cache Hits)"
else
    warning "Kernel module not loaded or proc interface not available"
fi

echo ""
log "=== Checking Cache Performance ==="
if [[ -f /proc/takakrypt/cache ]]; then
    info "Policy cache entries:"
    cat /proc/takakrypt/cache | head -10
else
    warning "Cache information not available"
fi

echo ""
log "=== Test Summary ==="
info "Access control tests completed"
info "Check the output above for any failed tests (❌)"
log "All ✅ tests indicate correct policy enforcement"