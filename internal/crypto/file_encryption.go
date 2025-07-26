package crypto

import (
	"fmt"
)

// FileEncryptionEngine handles file-level encryption/decryption
type FileEncryptionEngine struct {
	engine *EncryptionEngine
}

// NewFileEncryptionEngine creates a new file encryption engine
func NewFileEncryptionEngine() *FileEncryptionEngine {
	return &FileEncryptionEngine{
		engine: NewEncryptionEngine(),
	}
}

// EncryptFile encrypts file data and returns encrypted data with header
func (fe *FileEncryptionEngine) EncryptFile(data []byte, keyID string) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("cannot encrypt empty data")
	}

	// Get or create encryption key
	key, err := fe.engine.GetKey(keyID)
	if err != nil {
		// If key doesn't exist, create a new AES-256-GCM key
		key, err = fe.engine.GenerateKey("AES-256-GCM", keyID)
		if err != nil {
			return nil, fmt.Errorf("failed to create encryption key: %w", err)
		}
		fe.engine.SetKey(key)
	}

	// Encrypt the data
	result, err := fe.engine.Encrypt(data, keyID)
	if err != nil {
		return nil, fmt.Errorf("encryption failed: %w", err)
	}

	// Create file header
	header, err := NewFileHeader(result.Algorithm, result.KeyID, result.Nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to create file header: %w", err)
	}

	// Serialize header
	headerBytes, err := header.Serialize()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize header: %w", err)
	}

	// Combine header + ciphertext (ciphertext already includes auth tag for GCM)
	encryptedFile := make([]byte, 0, len(headerBytes)+len(result.Ciphertext))
	encryptedFile = append(encryptedFile, headerBytes...)
	encryptedFile = append(encryptedFile, result.Ciphertext...)

	return encryptedFile, nil
}

// DecryptFile decrypts file data by parsing header and decrypting content
func (fe *FileEncryptionEngine) DecryptFile(encryptedData []byte, expectedKeyID string) ([]byte, error) {
	// Check if data is encrypted first (before size check)
	if !IsEncrypted(encryptedData) {
		// Data is not encrypted, return as-is
		return encryptedData, nil
	}

	if len(encryptedData) < HEADER_SIZE {
		return nil, fmt.Errorf("data too short to contain header: %d < %d", len(encryptedData), HEADER_SIZE)
	}

	// Parse header
	header := &FileHeader{}
	if err := header.Deserialize(encryptedData[:HEADER_SIZE]); err != nil {
		return nil, fmt.Errorf("failed to parse header: %w", err)
	}

	// Validate header
	if err := header.Validate(); err != nil {
		return nil, fmt.Errorf("invalid header: %w", err)
	}

	// Check key ID matches (if provided)
	if expectedKeyID != "" && header.GetKeyID() != expectedKeyID {
		return nil, fmt.Errorf("key ID mismatch: expected %s, got %s", expectedKeyID, header.GetKeyID())
	}

	// Extract ciphertext (everything after header)
	ciphertext := encryptedData[HEADER_SIZE:]
	if len(ciphertext) == 0 {
		return nil, fmt.Errorf("no ciphertext found after header")
	}

	// Get decryption key
	key, err := fe.engine.GetKey(header.GetKeyID())
	if err != nil {
		return nil, fmt.Errorf("failed to get decryption key: %w", err)
	}

	// Verify algorithm matches
	if key.Algorithm != header.GetAlgorithmName() {
		return nil, fmt.Errorf("algorithm mismatch: key has %s, file has %s", key.Algorithm, header.GetAlgorithmName())
	}

	// Create decryption request
	decryptReq := &DecryptionRequest{
		Ciphertext: ciphertext,
		Nonce:      header.GetNonce(),
		Algorithm:  header.GetAlgorithmName(),
		KeyID:      header.GetKeyID(),
		Version:    int(header.Version),
	}

	// Decrypt the data
	plaintext, err := fe.engine.Decrypt(decryptReq)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	return plaintext, nil
}

// IsFileEncrypted checks if file data is encrypted by examining the header
func (fe *FileEncryptionEngine) IsFileEncrypted(data []byte) bool {
	return IsEncrypted(data)
}

// GetFileInfo extracts metadata from an encrypted file
func (fe *FileEncryptionEngine) GetFileInfo(encryptedData []byte) (*FileInfo, error) {
	if len(encryptedData) < HEADER_SIZE {
		return nil, fmt.Errorf("data too short to contain header")
	}

	if !IsEncrypted(encryptedData) {
		return &FileInfo{
			Encrypted: false,
		}, nil
	}

	// Parse header
	header := &FileHeader{}
	if err := header.Deserialize(encryptedData[:HEADER_SIZE]); err != nil {
		return nil, fmt.Errorf("failed to parse header: %w", err)
	}

	if err := header.Validate(); err != nil {
		return nil, fmt.Errorf("invalid header: %w", err)
	}

	return &FileInfo{
		Encrypted:    true,
		Algorithm:    header.GetAlgorithmName(),
		KeyID:        header.GetKeyID(),
		Version:      int(header.Version),
		HeaderSize:   HEADER_SIZE,
		ContentSize:  len(encryptedData) - HEADER_SIZE,
		NonceSize:    int(header.NonceSize),
		TagSize:      int(header.TagSize),
	}, nil
}

// FileInfo contains metadata about a file
type FileInfo struct {
	Encrypted   bool
	Algorithm   string
	KeyID       string
	Version     int
	HeaderSize  int
	ContentSize int
	NonceSize   int
	TagSize     int
}

// CreateKeyForPolicy creates a new encryption key for a specific policy
func (fe *FileEncryptionEngine) CreateKeyForPolicy(policyName string, algorithm string) (*EncryptionKey, error) {
	keyID := fmt.Sprintf("policy-%s", policyName)
	key, err := fe.engine.GenerateKey(algorithm, keyID)
	if err != nil {
		return nil, err
	}
	fe.engine.SetKey(key)
	return key, nil
}

// RotateKey creates a new version of an existing key
func (fe *FileEncryptionEngine) RotateKey(keyID string) (*EncryptionKey, error) {
	// Get existing key to preserve algorithm
	oldKey, err := fe.engine.GetKey(keyID)
	if err != nil {
		return nil, fmt.Errorf("cannot rotate non-existent key: %w", err)
	}

	// Create new key with incremented version
	newKey, err := fe.engine.GenerateKey(oldKey.Algorithm, keyID)
	if err != nil {
		return nil, fmt.Errorf("failed to create rotated key: %w", err)
	}

	// Update version
	newKey.Version = oldKey.Version + 1

	// Store the new key
	fe.engine.SetKey(newKey)

	return newKey, nil
}

// GetKeyStatistics returns statistics about encryption keys
func (fe *FileEncryptionEngine) GetKeyStatistics() map[string]interface{} {
	return map[string]interface{}{
		"total_keys":     len(fe.engine.keyCache),
		"key_algorithms": fe.getAlgorithmDistribution(),
	}
}

// getAlgorithmDistribution returns distribution of algorithms in key cache
func (fe *FileEncryptionEngine) getAlgorithmDistribution() map[string]int {
	distribution := make(map[string]int)
	for _, key := range fe.engine.keyCache {
		distribution[key.Algorithm]++
	}
	return distribution
}