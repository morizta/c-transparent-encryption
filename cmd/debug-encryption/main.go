package main

import (
	"fmt"
	"log"

	"takakrypt/internal/crypto"
)

func main() {
	fmt.Println("=== Debug Encryption Issue ===")

	// Create file encryption engine
	fileEngine := crypto.NewFileEncryptionEngine()

	// Test data
	originalData := []byte("Test data")
	keyID := "debug-key"

	fmt.Printf("Original data: %s\n", string(originalData))

	// Encrypt
	encryptedData, err := fileEngine.EncryptFile(originalData, keyID)
	if err != nil {
		log.Fatalf("Encryption failed: %v", err)
	}

	fmt.Printf("Encrypted data size: %d bytes\n", len(encryptedData))

	// Get file info to debug
	fileInfo, err := fileEngine.GetFileInfo(encryptedData)
	if err != nil {
		log.Fatalf("Failed to get file info: %v", err)
	}

	fmt.Printf("File Info - Nonce Size: %d, Tag Size: %d\n", fileInfo.NonceSize, fileInfo.TagSize)
	fmt.Printf("Header Size: %d, Content Size: %d\n", fileInfo.HeaderSize, fileInfo.ContentSize)

	// Parse header manually to debug
	if len(encryptedData) >= 96 {
		header := &crypto.FileHeader{}
		if err := header.Deserialize(encryptedData[:96]); err != nil {
			log.Fatalf("Failed to deserialize header: %v", err)
		}

		fmt.Printf("Header Debug:\n")
		fmt.Printf("  Magic: %s\n", string(header.Magic[:]))
		fmt.Printf("  Algorithm: %d\n", header.Algorithm)
		fmt.Printf("  NonceSize: %d\n", header.NonceSize)
		fmt.Printf("  TagSize: %d\n", header.TagSize)
		fmt.Printf("  KeyID: %s\n", header.GetKeyID())

		nonce := header.GetNonce()
		fmt.Printf("  Nonce length: %d\n", len(nonce))
		fmt.Printf("  Nonce bytes: %x\n", nonce)

		// Extract ciphertext
		ciphertext := encryptedData[96:]
		fmt.Printf("  Ciphertext length: %d\n", len(ciphertext))
		fmt.Printf("  Expected plaintext + tag: %d + %d = %d\n", len(originalData), 16, len(originalData)+16)
	}

	// Try decryption
	fmt.Println("\nAttempting decryption...")
	decryptedData, err := fileEngine.DecryptFile(encryptedData, keyID)
	if err != nil {
		fmt.Printf("Decryption failed: %v\n", err)
	} else {
		fmt.Printf("Decryption successful: %s\n", string(decryptedData))
	}
}