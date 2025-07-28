package main

import (
	"fmt"
	"log"
	"os"

	"takakrypt/internal/crypto"
)

func main() {
	fmt.Println("=== Takakrypt Real AES-256-GCM Encryption Test ===")

	// Create file encryption engine
	fileEngine := crypto.NewFileEncryptionEngine()

	// Test data
	originalData := []byte("This is a test document with sensitive information that should be encrypted using AES-256-GCM algorithm.")
	keyID := "test-policy-key"

	fmt.Printf("Original data (%d bytes): %s\n", len(originalData), string(originalData))
	fmt.Println()

	// Test 1: Encrypt file data
	fmt.Println("=== Test 1: File Encryption ===")
	encryptedData, err := fileEngine.EncryptFile(originalData, keyID)
	if err != nil {
		log.Fatalf("Encryption failed: %v", err)
	}

	fmt.Printf("Encrypted data size: %d bytes\n", len(encryptedData))
	fmt.Printf("Encryption overhead: %d bytes\n", len(encryptedData)-len(originalData))

	// Check if data is recognized as encrypted
	if !fileEngine.IsFileEncrypted(encryptedData) {
		log.Fatal("Encrypted data not recognized as encrypted")
	}
	fmt.Println("✓ Data correctly identified as encrypted")

	// Test 2: Get file info
	fmt.Println("\n=== Test 2: File Info Extraction ===")
	fileInfo, err := fileEngine.GetFileInfo(encryptedData)
	if err != nil {
		log.Fatalf("Failed to get file info: %v", err)
	}

	fmt.Printf("File Info:\n")
	fmt.Printf("  Encrypted: %v\n", fileInfo.Encrypted)
	fmt.Printf("  Algorithm: %s\n", fileInfo.Algorithm)
	fmt.Printf("  Key ID: %s\n", fileInfo.KeyID)
	fmt.Printf("  Version: %d\n", fileInfo.Version)
	fmt.Printf("  Header Size: %d bytes\n", fileInfo.HeaderSize)
	fmt.Printf("  Content Size: %d bytes\n", fileInfo.ContentSize)
	fmt.Printf("  Nonce Size: %d bytes\n", fileInfo.NonceSize)
	fmt.Printf("  Tag Size: %d bytes\n", fileInfo.TagSize)

	// Test 3: Decrypt file data
	fmt.Println("\n=== Test 3: File Decryption ===")
	decryptedData, err := fileEngine.DecryptFile(encryptedData, keyID)
	if err != nil {
		log.Fatalf("Decryption failed: %v", err)
	}

	fmt.Printf("Decrypted data (%d bytes): %s\n", len(decryptedData), string(decryptedData))

	// Verify data integrity
	if string(originalData) != string(decryptedData) {
		log.Fatal("Decrypted data does not match original data")
	}
	fmt.Println("✓ Decrypted data matches original data")

	// Test 4: Handle unencrypted data
	fmt.Println("\n=== Test 4: Unencrypted Data Handling ===")
	plainTextData := []byte("This is plain text data that is not encrypted.")
	
	// Check if recognized as unencrypted
	if fileEngine.IsFileEncrypted(plainTextData) {
		log.Fatal("Plain text data incorrectly identified as encrypted")
	}
	fmt.Println("✓ Plain text data correctly identified as unencrypted")

	// Decrypt should return data as-is
	decryptedPlain, err := fileEngine.DecryptFile(plainTextData, "")
	if err != nil {
		log.Fatalf("Failed to handle plain text data: %v", err)
	}
	if string(plainTextData) != string(decryptedPlain) {
		log.Fatal("Plain text data was modified during decryption")
	}
	fmt.Println("✓ Plain text data returned unchanged")

	// Test 5: Key statistics
	fmt.Println("\n=== Test 5: Key Statistics ===")
	stats := fileEngine.GetKeyStatistics()
	fmt.Printf("Key Statistics:\n")
	for key, value := range stats {
		fmt.Printf("  %s: %v\n", key, value)
	}

	// Test 6: Multiple encryptions with same key
	fmt.Println("\n=== Test 6: Multiple Encryptions ===")
	data1 := []byte("First document content")
	data2 := []byte("Second document content with different length")

	enc1, err := fileEngine.EncryptFile(data1, keyID)
	if err != nil {
		log.Fatalf("First encryption failed: %v", err)
	}

	enc2, err := fileEngine.EncryptFile(data2, keyID)
	if err != nil {
		log.Fatalf("Second encryption failed: %v", err)
	}

	// Decrypt both
	dec1, err := fileEngine.DecryptFile(enc1, keyID)
	if err != nil {
		log.Fatalf("First decryption failed: %v", err)
	}

	dec2, err := fileEngine.DecryptFile(enc2, keyID)
	if err != nil {
		log.Fatalf("Second decryption failed: %v", err)
	}

	if string(data1) != string(dec1) || string(data2) != string(dec2) {
		log.Fatal("Multiple encryption/decryption failed")
	}
	fmt.Println("✓ Multiple encryptions/decryptions successful")

	// Test 7: Cross-contamination test
	fmt.Println("\n=== Test 7: Cross-contamination Test ===")
	// Try to decrypt enc1 data with wrong key ID
	_, err = fileEngine.DecryptFile(enc1, "wrong-key-id")
	if err == nil {
		log.Fatal("Decryption with wrong key should have failed")
	}
	fmt.Printf("✓ Decryption with wrong key correctly failed: %v\n", err)

	// Test 8: Write and read from file
	fmt.Println("\n=== Test 8: File I/O Test ===")
	testFileName := "/tmp/takakrypt-real-encryption-test.bin"
	
	// Write encrypted data to file
	err = os.WriteFile(testFileName, encryptedData, 0644)
	if err != nil {
		log.Fatalf("Failed to write encrypted file: %v", err)
	}
	fmt.Printf("✓ Encrypted data written to %s\n", testFileName)

	// Read and decrypt
	fileData, err := os.ReadFile(testFileName)
	if err != nil {
		log.Fatalf("Failed to read encrypted file: %v", err)
	}

	decryptedFromFile, err := fileEngine.DecryptFile(fileData, keyID)
	if err != nil {
		log.Fatalf("Failed to decrypt file data: %v", err)
	}

	if string(originalData) != string(decryptedFromFile) {
		log.Fatal("File roundtrip failed")
	}
	fmt.Println("✓ File I/O roundtrip successful")

	// Clean up
	os.Remove(testFileName)

	fmt.Println("\n=== All Tests Passed! ===")
	fmt.Println("Real AES-256-GCM encryption implementation is working correctly.")
	fmt.Printf("Encryption adds %d bytes overhead per file.\n", len(encryptedData)-len(originalData))
}// Enhanced logging enabled
