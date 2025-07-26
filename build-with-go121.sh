#!/bin/bash

# Temporary build script using Go 1.21.5

# Set PATH to prioritize new Go
export PATH=/usr/local/go/bin:$PATH

# Clear any cached binary locations
hash -r

echo "Using Go version: $(/usr/local/go/bin/go version)"
echo "Building Takakrypt components..."

# Build using the new Go
/usr/local/go/bin/go build -o build/bin/takakrypt-agent ./cmd/takakrypt-agent/
/usr/local/go/bin/go build -o build/bin/takakrypt-cli ./cmd/takakrypt-cli/

echo "Build complete!"
echo "Binaries created:"
ls -la build/bin/