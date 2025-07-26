package main

import (
	"fmt"
	"log"

	"takakrypt/internal/crypto"
)

func main() {
	fmt.Println("=== Debug File Format ===")

	// Create engine directly
	engine := crypto.NewEncryptionEngine()

	// Test data
	originalData := []byte("Test data")
	keyID := "debug-key"

	// Generate key
	key, err := engine.GenerateKey("AES-256-GCM", keyID)
	if err != nil {
		log.Fatalf("Failed to generate key: %v", err)
	}
	engine.SetKey(key)

	// Encrypt directly with engine
	result, err := engine.Encrypt(originalData, keyID)
	if err != nil {
		log.Fatalf("Encryption failed: %v", err)
	}

	fmt.Printf("Engine encryption result:\n")
	fmt.Printf("  Nonce length: %d bytes\n", len(result.Nonce))
	fmt.Printf("  Ciphertext length: %d bytes\n", len(result.Ciphertext))

	// Create file header manually
	header, err := crypto.NewFileHeader(result.Algorithm, result.KeyID, result.Nonce)
	if err != nil {
		log.Fatalf("Failed to create header: %v", err)
	}

	fmt.Printf("Header created:\n")
	fmt.Printf("  NonceSize: %d\n", header.NonceSize)
	fmt.Printf("  TagSize: %d\n", header.TagSize)

	// Serialize header
	headerBytes, err := header.Serialize()
	if err != nil {
		log.Fatalf("Failed to serialize header: %v", err)
	}

	fmt.Printf("  Serialized header length: %d bytes\n", len(headerBytes))

	// Combine header + ciphertext
	fileData := make([]byte, 0, len(headerBytes)+len(result.Ciphertext))
	fileData = append(fileData, headerBytes...)
	fileData = append(fileData, result.Ciphertext...)

	fmt.Printf("Complete file data: %d bytes\n", len(fileData))
	fmt.Printf("  Header: %d bytes\n", len(headerBytes))
	fmt.Printf("  Ciphertext: %d bytes\n", len(result.Ciphertext))

	// Parse back the file
	parsedHeader := &crypto.FileHeader{}
	if err := parsedHeader.Deserialize(fileData[:96]); err != nil {
		log.Fatalf("Failed to parse header: %v", err)
	}

	// Get nonce back
	parsedNonce := parsedHeader.GetNonce()
	fmt.Printf("Parsed nonce length: %d bytes\n", len(parsedNonce))
	fmt.Printf("Original nonce: %x\n", result.Nonce)
	fmt.Printf("Parsed nonce:   %x\n", parsedNonce)

	// Extract ciphertext from file
	fileCiphertext := fileData[96:]
	fmt.Printf("File ciphertext length: %d bytes\n", len(fileCiphertext))

	// Compare
	fmt.Printf("Nonce match: %v\n", string(result.Nonce) == string(parsedNonce))
	fmt.Printf("Ciphertext match: %v\n", string(result.Ciphertext) == string(fileCiphertext))

	// Try decryption with parsed data
	decryptReq := &crypto.DecryptionRequest{
		Ciphertext: fileCiphertext,
		Nonce:      parsedNonce,
		Algorithm:  parsedHeader.GetAlgorithmName(),
		KeyID:      parsedHeader.GetKeyID(),
		Version:    int(parsedHeader.Version),
	}

	decrypted, err := engine.Decrypt(decryptReq)
	if err != nil {
		fmt.Printf("Decryption with file data failed: %v\n", err)
	} else {
		fmt.Printf("Decryption with file data successful: %s\n", string(decrypted))
	}
}