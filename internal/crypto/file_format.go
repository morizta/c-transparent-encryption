package crypto

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// FileHeader represents the header for encrypted files
// Based on Thales CTE analysis: EROV magic signature with metadata
type FileHeader struct {
	Magic     [4]byte  // "TAKA" magic signature
	Version   uint16   // File format version
	Flags     uint16   // Encryption flags
	Algorithm uint8    // Encryption algorithm ID
	KeySize   uint8    // Key size in bytes
	NonceSize uint8    // Nonce size in bytes
	TagSize   uint8    // Authentication tag size in bytes
	KeyID     [32]byte // Key identifier (SHA-256 hash)
	Nonce     [32]byte // Encryption nonce (first 32 bytes)
	Reserved  [16]byte // Reserved for future use
}

const (
	// File format constants
	TAKAKRYPT_MAGIC    = "TAKA"
	TAKAKRYPT_VERSION  = 1
	HEADER_SIZE        = 92 // Total header size in bytes

	// Algorithm IDs
	ALGO_AES_256_GCM     = 1
	ALGO_AES_128_GCM     = 2
	ALGO_CHACHA20_POLY1305 = 3

	// Encryption flags
	FLAG_COMPRESSED = 1 << 0
	FLAG_SIGNED     = 1 << 1
)

// EncryptedFile represents a complete encrypted file
type EncryptedFile struct {
	Header     FileHeader
	Ciphertext []byte
	Tag        []byte // Authentication tag
}

// NewFileHeader creates a new file header for encryption
func NewFileHeader(algorithm string, keyID string, nonce []byte) (*FileHeader, error) {
	header := &FileHeader{
		Version:   TAKAKRYPT_VERSION,
		NonceSize: uint8(len(nonce)),
		TagSize:   16, // GCM always uses 16-byte tags
	}

	// Set magic signature
	copy(header.Magic[:], TAKAKRYPT_MAGIC)

	// Set algorithm and key size
	switch algorithm {
	case "AES-256-GCM":
		header.Algorithm = ALGO_AES_256_GCM
		header.KeySize = 32
	case "AES-128-GCM":
		header.Algorithm = ALGO_AES_128_GCM
		header.KeySize = 16
	case "ChaCha20-Poly1305":
		header.Algorithm = ALGO_CHACHA20_POLY1305
		header.KeySize = 32
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", algorithm)
	}

	// Set key ID (truncate to 32 bytes if needed)
	keyIDBytes := []byte(keyID)
	if len(keyIDBytes) > 32 {
		keyIDBytes = keyIDBytes[:32]
	}
	copy(header.KeyID[:], keyIDBytes)

	// Set nonce (truncate to 32 bytes if needed)
	if len(nonce) > 32 {
		nonce = nonce[:32]
	}
	copy(header.Nonce[:], nonce)

	return header, nil
}

// Serialize converts the header to binary format
func (h *FileHeader) Serialize() ([]byte, error) {
	buf := new(bytes.Buffer)
	
	// Write all fields in order
	if err := binary.Write(buf, binary.LittleEndian, h.Magic); err != nil {
		return nil, fmt.Errorf("failed to write magic: %w", err)
	}
	if err := binary.Write(buf, binary.LittleEndian, h.Version); err != nil {
		return nil, fmt.Errorf("failed to write version: %w", err)
	}
	if err := binary.Write(buf, binary.LittleEndian, h.Flags); err != nil {
		return nil, fmt.Errorf("failed to write flags: %w", err)
	}
	if err := binary.Write(buf, binary.LittleEndian, h.Algorithm); err != nil {
		return nil, fmt.Errorf("failed to write algorithm: %w", err)
	}
	if err := binary.Write(buf, binary.LittleEndian, h.KeySize); err != nil {
		return nil, fmt.Errorf("failed to write key size: %w", err)
	}
	if err := binary.Write(buf, binary.LittleEndian, h.NonceSize); err != nil {
		return nil, fmt.Errorf("failed to write nonce size: %w", err)
	}
	if err := binary.Write(buf, binary.LittleEndian, h.TagSize); err != nil {
		return nil, fmt.Errorf("failed to write tag size: %w", err)
	}
	if err := binary.Write(buf, binary.LittleEndian, h.KeyID); err != nil {
		return nil, fmt.Errorf("failed to write key ID: %w", err)
	}
	if err := binary.Write(buf, binary.LittleEndian, h.Nonce); err != nil {
		return nil, fmt.Errorf("failed to write nonce: %w", err)
	}
	if err := binary.Write(buf, binary.LittleEndian, h.Reserved); err != nil {
		return nil, fmt.Errorf("failed to write reserved: %w", err)
	}

	return buf.Bytes(), nil
}

// Deserialize parses binary data into a file header
func (h *FileHeader) Deserialize(data []byte) error {
	if len(data) < HEADER_SIZE {
		return fmt.Errorf("data too short for header: %d < %d", len(data), HEADER_SIZE)
	}

	buf := bytes.NewReader(data)
	
	// Read all fields in order
	if err := binary.Read(buf, binary.LittleEndian, &h.Magic); err != nil {
		return fmt.Errorf("failed to read magic: %w", err)
	}
	if err := binary.Read(buf, binary.LittleEndian, &h.Version); err != nil {
		return fmt.Errorf("failed to read version: %w", err)
	}
	if err := binary.Read(buf, binary.LittleEndian, &h.Flags); err != nil {
		return fmt.Errorf("failed to read flags: %w", err)
	}
	if err := binary.Read(buf, binary.LittleEndian, &h.Algorithm); err != nil {
		return fmt.Errorf("failed to read algorithm: %w", err)
	}
	if err := binary.Read(buf, binary.LittleEndian, &h.KeySize); err != nil {
		return fmt.Errorf("failed to read key size: %w", err)
	}
	if err := binary.Read(buf, binary.LittleEndian, &h.NonceSize); err != nil {
		return fmt.Errorf("failed to read nonce size: %w", err)
	}
	if err := binary.Read(buf, binary.LittleEndian, &h.TagSize); err != nil {
		return fmt.Errorf("failed to read tag size: %w", err)
	}
	if err := binary.Read(buf, binary.LittleEndian, &h.KeyID); err != nil {
		return fmt.Errorf("failed to read key ID: %w", err)
	}
	if err := binary.Read(buf, binary.LittleEndian, &h.Nonce); err != nil {
		return fmt.Errorf("failed to read nonce: %w", err)
	}
	if err := binary.Read(buf, binary.LittleEndian, &h.Reserved); err != nil {
		return fmt.Errorf("failed to read reserved: %w", err)
	}

	return nil
}

// Validate checks if the header is valid
func (h *FileHeader) Validate() error {
	// Check magic signature
	if string(h.Magic[:]) != TAKAKRYPT_MAGIC {
		return fmt.Errorf("invalid magic signature: %s", string(h.Magic[:]))
	}

	// Check version
	if h.Version != TAKAKRYPT_VERSION {
		return fmt.Errorf("unsupported version: %d", h.Version)
	}

	// Check algorithm
	switch h.Algorithm {
	case ALGO_AES_256_GCM, ALGO_AES_128_GCM, ALGO_CHACHA20_POLY1305:
		// Valid algorithms
	default:
		return fmt.Errorf("unknown algorithm: %d", h.Algorithm)
	}

	// Check key size matches algorithm
	switch h.Algorithm {
	case ALGO_AES_256_GCM, ALGO_CHACHA20_POLY1305:
		if h.KeySize != 32 {
			return fmt.Errorf("invalid key size for algorithm %d: %d", h.Algorithm, h.KeySize)
		}
	case ALGO_AES_128_GCM:
		if h.KeySize != 16 {
			return fmt.Errorf("invalid key size for algorithm %d: %d", h.Algorithm, h.KeySize)
		}
	}

	return nil
}

// GetAlgorithmName returns the algorithm name as string
func (h *FileHeader) GetAlgorithmName() string {
	switch h.Algorithm {
	case ALGO_AES_256_GCM:
		return "AES-256-GCM"
	case ALGO_AES_128_GCM:
		return "AES-128-GCM"
	case ALGO_CHACHA20_POLY1305:
		return "ChaCha20-Poly1305"
	default:
		return "Unknown"
	}
}

// GetKeyID returns the key ID as string
func (h *FileHeader) GetKeyID() string {
	// Find the null terminator or use the full 32 bytes
	keyIDBytes := h.KeyID[:]
	for i, b := range keyIDBytes {
		if b == 0 {
			keyIDBytes = keyIDBytes[:i]
			break
		}
	}
	return string(keyIDBytes)
}

// GetNonce returns the nonce bytes (truncated to actual size)
func (h *FileHeader) GetNonce() []byte {
	if h.NonceSize > 32 {
		return h.Nonce[:]
	}
	return h.Nonce[:h.NonceSize]
}

// IsEncrypted checks if data starts with a valid Takakrypt header
func IsEncrypted(data []byte) bool {
	if len(data) < 4 {
		return false
	}
	return string(data[:4]) == TAKAKRYPT_MAGIC
}