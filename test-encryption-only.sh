#!/bin/bash
# Test encryption functionality without kernel module

echo "Testing Takakrypt encryption engine..."
echo ""

# Build test program
echo "Building encryption test..."
cat > /tmp/test-encryption.go << 'EOF'
package main

import (
    "fmt"
    "log"
    "encoding/hex"
    "takakrypt/internal/crypto"
)

func main() {
    // Create file encryption engine
    engine := crypto.NewFileEncryptionEngine()
    
    // Test data
    plaintext := []byte("This is secret data that should be encrypted!")
    keyID := "test-key-001"
    
    fmt.Printf("Original data: %s\n", plaintext)
    fmt.Printf("Key ID: %s\n\n", keyID)
    
    // Encrypt
    encrypted, err := engine.EncryptFile(plaintext, keyID)
    if err != nil {
        log.Fatalf("Encryption failed: %v", err)
    }
    
    fmt.Printf("Encrypted size: %d bytes\n", len(encrypted))
    fmt.Printf("First 64 bytes (hex):\n%s\n\n", hex.Dump(encrypted[:64]))
    
    // Check if data is encrypted
    if engine.IsFileEncrypted(encrypted) {
        fmt.Println("✓ File is correctly marked as encrypted")
    } else {
        fmt.Println("✗ File encryption marker not found")
    }
    
    // Get file info
    info, err := engine.GetFileInfo(encrypted)
    if err != nil {
        log.Fatalf("Failed to get file info: %v", err)
    }
    
    fmt.Printf("\nFile Info:\n")
    fmt.Printf("  Encrypted: %v\n", info.Encrypted)
    fmt.Printf("  Algorithm: %s\n", info.Algorithm)
    fmt.Printf("  Key ID: %s\n", info.KeyID)
    fmt.Printf("  Header Size: %d\n", info.HeaderSize)
    fmt.Printf("  Content Size: %d\n", info.ContentSize)
    
    // Decrypt
    decrypted, err := engine.DecryptFile(encrypted, keyID)
    if err != nil {
        log.Fatalf("Decryption failed: %v", err)
    }
    
    fmt.Printf("\nDecrypted data: %s\n", decrypted)
    
    // Verify
    if string(decrypted) == string(plaintext) {
        fmt.Println("\n✓ Encryption/Decryption successful!")
    } else {
        fmt.Println("\n✗ Data mismatch after decryption")
    }
}
EOF

# Run the test
go run /tmp/test-encryption.go