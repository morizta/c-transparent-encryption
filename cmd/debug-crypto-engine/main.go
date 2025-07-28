package main

import (
	"fmt"
	"log"

	"takakrypt/internal/crypto"
)

func main() {
	fmt.Println("=== Debug Crypto Engine ===")

	// Create engine directly
	engine := crypto.NewEncryptionEngine()

	// Test data
	originalData := []byte("Test data")
	keyID := "debug-key"

	fmt.Printf("Original data: %s (%d bytes)\n", string(originalData), len(originalData))

	// Generate key
	key, err := engine.GenerateKey("AES-256-GCM", keyID)
	if err != nil {
		log.Fatalf("Failed to generate key: %v", err)
	}
	engine.SetKey(key)

	fmt.Printf("Key generated: %s, size: %d bytes\n", key.ID, len(key.Data))

	// Encrypt directly with engine
	result, err := engine.Encrypt(originalData, keyID)
	if err != nil {
		log.Fatalf("Encryption failed: %v", err)
	}

	fmt.Printf("Encryption result:\n")
	fmt.Printf("  Algorithm: %s\n", result.Algorithm)
	fmt.Printf("  KeyID: %s\n", result.KeyID)
	fmt.Printf("  Nonce length: %d\n", len(result.Nonce))
	fmt.Printf("  Ciphertext length: %d\n", len(result.Ciphertext))
	fmt.Printf("  Nonce: %x\n", result.Nonce)

	// Try to decrypt
	decryptReq := &crypto.DecryptionRequest{
		Ciphertext: result.Ciphertext,
		Nonce:      result.Nonce,
		Algorithm:  result.Algorithm,
		KeyID:      result.KeyID,
		Version:    result.Version,
	}

	decrypted, err := engine.Decrypt(decryptReq)
	if err != nil {
		fmt.Printf("Direct decryption failed: %v\n", err)
	} else {
		fmt.Printf("Direct decryption successful: %s\n", string(decrypted))
	}
}// Enhanced logging enabled
