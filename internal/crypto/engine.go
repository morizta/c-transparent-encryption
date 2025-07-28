package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
)

// EncryptionEngine handles all cryptographic operations
type EncryptionEngine struct {
	keyCache map[string]*EncryptionKey
}

// EncryptionKey represents an encryption key with metadata
type EncryptionKey struct {
	ID        string
	Data      []byte
	Algorithm string
	KeySize   int
	Version   int
}

// EncryptionResult contains the result of an encryption operation
type EncryptionResult struct {
	Ciphertext []byte
	Nonce      []byte
	Algorithm  string
	KeyID      string
	Version    int
}

// DecryptionRequest contains parameters for decryption
type DecryptionRequest struct {
	Ciphertext []byte
	Nonce      []byte
	Algorithm  string
	KeyID      string
	Version    int
}

// NewEncryptionEngine creates a new encryption engine
func NewEncryptionEngine() *EncryptionEngine {
	return &EncryptionEngine{
		keyCache: make(map[string]*EncryptionKey),
	}
}

// SetKey adds or updates a key in the engine's cache
func (e *EncryptionEngine) SetKey(key *EncryptionKey) {
	e.keyCache[key.ID] = key
}

// GetKey retrieves a key from the cache
func (e *EncryptionEngine) GetKey(keyID string) (*EncryptionKey, error) {
	key, exists := e.keyCache[keyID]
	if !exists {
		return nil, fmt.Errorf("key not found: %s", keyID)
	}
	return key, nil
}

// RemoveKey removes a key from the cache
func (e *EncryptionEngine) RemoveKey(keyID string) {
	delete(e.keyCache, keyID)
}

// Encrypt encrypts data using the specified key and algorithm
func (e *EncryptionEngine) Encrypt(data []byte, keyID string) (*EncryptionResult, error) {
	if len(data) == 0 {
		return nil, errors.New("cannot encrypt empty data")
	}

	key, err := e.GetKey(keyID)
	if err != nil {
		return nil, fmt.Errorf("encryption failed: %w", err)
	}

	switch key.Algorithm {
	case "AES-256-GCM", "AES-128-GCM":
		return e.encryptAESGCM(data, key)
	case "ChaCha20-Poly1305":
		return e.encryptChaCha20Poly1305(data, key)
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", key.Algorithm)
	}
}

// Decrypt decrypts data using the provided decryption request
func (e *EncryptionEngine) Decrypt(req *DecryptionRequest) ([]byte, error) {
	if len(req.Ciphertext) == 0 {
		return nil, errors.New("cannot decrypt empty ciphertext")
	}

	key, err := e.GetKey(req.KeyID)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	// Verify algorithm matches
	if key.Algorithm != req.Algorithm {
		return nil, fmt.Errorf("algorithm mismatch: key has %s, request has %s", key.Algorithm, req.Algorithm)
	}

	switch req.Algorithm {
	case "AES-256-GCM", "AES-128-GCM":
		return e.decryptAESGCM(req.Ciphertext, req.Nonce, key)
	case "ChaCha20-Poly1305":
		return e.decryptChaCha20Poly1305(req.Ciphertext, req.Nonce, key)
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", req.Algorithm)
	}
}

// encryptAESGCM encrypts data using AES-GCM
func (e *EncryptionEngine) encryptAESGCM(data []byte, key *EncryptionKey) (*EncryptionResult, error) {
	block, err := aes.NewCipher(key.Data)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM mode: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, data, nil)

	return &EncryptionResult{
		Ciphertext: ciphertext,
		Nonce:      nonce,
		Algorithm:  key.Algorithm,
		KeyID:      key.ID,
		Version:    key.Version,
	}, nil
}

// decryptAESGCM decrypts data using AES-GCM
func (e *EncryptionEngine) decryptAESGCM(ciphertext, nonce []byte, key *EncryptionKey) ([]byte, error) {
	block, err := aes.NewCipher(key.Data)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM mode: %w", err)
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}

	return plaintext, nil
}

// encryptChaCha20Poly1305 encrypts data using ChaCha20-Poly1305
func (e *EncryptionEngine) encryptChaCha20Poly1305(data []byte, key *EncryptionKey) (*EncryptionResult, error) {
	aead, err := chacha20poly1305.New(key.Data)
	if err != nil {
		return nil, fmt.Errorf("failed to create ChaCha20-Poly1305 cipher: %w", err)
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := aead.Seal(nil, nonce, data, nil)

	return &EncryptionResult{
		Ciphertext: ciphertext,
		Nonce:      nonce,
		Algorithm:  key.Algorithm,
		KeyID:      key.ID,
		Version:    key.Version,
	}, nil
}

// decryptChaCha20Poly1305 decrypts data using ChaCha20-Poly1305
func (e *EncryptionEngine) decryptChaCha20Poly1305(ciphertext, nonce []byte, key *EncryptionKey) ([]byte, error) {
	aead, err := chacha20poly1305.New(key.Data)
	if err != nil {
		return nil, fmt.Errorf("failed to create ChaCha20-Poly1305 cipher: %w", err)
	}

	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}

	return plaintext, nil
}

// GenerateKey generates a new encryption key
func (e *EncryptionEngine) GenerateKey(algorithm string, keyID string) (*EncryptionKey, error) {
	var keySize int
	switch algorithm {
	case "AES-256-GCM", "ChaCha20-Poly1305":
		keySize = 32 // 256 bits
	case "AES-128-GCM":
		keySize = 16 // 128 bits
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", algorithm)
	}

	keyData := make([]byte, keySize)
	if _, err := io.ReadFull(rand.Reader, keyData); err != nil {
		return nil, fmt.Errorf("failed to generate key data: %w", err)
	}

	key := &EncryptionKey{
		ID:        keyID,
		Data:      keyData,
		Algorithm: algorithm,
		KeySize:   keySize * 8, // Convert to bits
		Version:   1,
	}

	e.SetKey(key)
	return key, nil
}

// DeriveKey derives a key from a password using PBKDF2
func (e *EncryptionEngine) DeriveKey(password, salt []byte, algorithm string, keyID string, iterations int) (*EncryptionKey, error) {
	var keySize int
	switch algorithm {
	case "AES-256-GCM", "ChaCha20-Poly1305":
		keySize = 32
	case "AES-128-GCM":
		keySize = 16
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", algorithm)
	}

	if iterations <= 0 {
		iterations = 100000 // Default PBKDF2 iterations
	}

	dk := pbkdf2(password, salt, iterations, keySize, sha256.New)

	key := &EncryptionKey{
		ID:        keyID,
		Data:      dk,
		Algorithm: algorithm,
		KeySize:   keySize * 8,
		Version:   1,
	}

	e.SetKey(key)
	return key, nil
}

// ClearCache clears all cached keys (for security)
func (e *EncryptionEngine) ClearCache() {
	// Securely wipe key data before clearing
	for _, key := range e.keyCache {
		e.wipeKeyData(key.Data)
	}
	e.keyCache = make(map[string]*EncryptionKey)
}

// wipeKeyData securely wipes key data from memory
func (e *EncryptionEngine) wipeKeyData(data []byte) {
	for i := range data {
		data[i] = 0
	}
}

// GetCachedKeyCount returns the number of cached keys
func (e *EncryptionEngine) GetCachedKeyCount() int {
	return len(e.keyCache)
}

// ListCachedKeys returns a list of cached key IDs
func (e *EncryptionEngine) ListCachedKeys() []string {
	keys := make([]string, 0, len(e.keyCache))
	for id := range e.keyCache {
		keys = append(keys, id)
	}
	return keys
}// Enhanced logging enabled
