package netlink

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// TakakryptMessage represents the binary protocol for kernel-userspace communication
type TakakryptMessage struct {
	Header TakakryptHeader
	Data   []byte
}

// TakakryptHeader is the fixed-size header for all messages
type TakakryptHeader struct {
	Magic     uint32 // "TAKA" magic number (0x54414B41)
	Version   uint16 // Protocol version
	Operation uint16 // Operation type
	Sequence  uint32 // Request/response sequence
	DataLen   uint32 // Length of data following header
	Status    uint32 // Status code (for responses)
	Reserved  [8]byte // Reserved for future use
}

const (
	// Protocol constants
	TAKAKRYPT_HEADER_SIZE = 32 // Size of TakakryptHeader in bytes
	MAX_MESSAGE_SIZE      = 1024 * 1024 // 1MB max message size
)

// EncryptionRequestData represents the data portion of an encryption request
type EncryptionRequestData struct {
	KeyIDLen uint32 // Length of key ID string
	DataLen  uint32 // Length of data to encrypt
	// Followed by:
	// KeyID    []byte // Key ID string (KeyIDLen bytes)
	// Data     []byte // Data to encrypt (DataLen bytes)
}

// DecryptionRequestData represents the data portion of a decryption request
type DecryptionRequestData struct {
	KeyIDLen uint32 // Length of key ID string
	DataLen  uint32 // Length of encrypted data
	// Followed by:
	// KeyID    []byte // Key ID string (KeyIDLen bytes)
	// Data     []byte // Encrypted data (DataLen bytes)
}

// PolicyCheckRequestData represents the data portion of a policy check request
type PolicyCheckRequestData struct {
	PathLen   uint32 // Length of file path
	Operation uint32 // File operation type
	UID       uint32 // User ID
	GID       uint32 // Group ID
	PID       uint32 // Process ID
	// Followed by:
	// Path     []byte // File path (PathLen bytes)
}

// SerializeEncryptionRequest creates a binary encryption request
func SerializeEncryptionRequest(seq uint32, keyID string, data []byte) ([]byte, error) {
	if len(keyID) > 255 {
		return nil, fmt.Errorf("key ID too long: %d > 255", len(keyID))
	}
	if len(data) > MAX_MESSAGE_SIZE-TAKAKRYPT_HEADER_SIZE-8-len(keyID) {
		return nil, fmt.Errorf("data too large: %d bytes", len(data))
	}

	// Calculate total data length
	dataLen := 8 + len(keyID) + len(data) // 8 bytes for KeyIDLen+DataLen

	// Create header
	header := TakakryptHeader{
		Magic:     TAKAKRYPT_MSG_MAGIC,
		Version:   TAKAKRYPT_PROTOCOL_VERSION,
		Operation: TAKAKRYPT_OP_ENCRYPT,
		Sequence:  seq,
		DataLen:   uint32(dataLen),
		Status:    0,
	}

	// Serialize header
	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.LittleEndian, header); err != nil {
		return nil, fmt.Errorf("failed to serialize header: %w", err)
	}

	// Serialize data portion
	reqData := EncryptionRequestData{
		KeyIDLen: uint32(len(keyID)),
		DataLen:  uint32(len(data)),
	}
	if err := binary.Write(buf, binary.LittleEndian, reqData); err != nil {
		return nil, fmt.Errorf("failed to serialize request data: %w", err)
	}

	// Append key ID and data
	buf.Write([]byte(keyID))
	buf.Write(data)

	return buf.Bytes(), nil
}

// SerializeDecryptionRequest creates a binary decryption request
func SerializeDecryptionRequest(seq uint32, keyID string, encryptedData []byte) ([]byte, error) {
	if len(keyID) > 255 {
		return nil, fmt.Errorf("key ID too long: %d > 255", len(keyID))
	}
	if len(encryptedData) > MAX_MESSAGE_SIZE-TAKAKRYPT_HEADER_SIZE-8-len(keyID) {
		return nil, fmt.Errorf("encrypted data too large: %d bytes", len(encryptedData))
	}

	// Calculate total data length
	dataLen := 8 + len(keyID) + len(encryptedData) // 8 bytes for KeyIDLen+DataLen

	// Create header
	header := TakakryptHeader{
		Magic:     TAKAKRYPT_MSG_MAGIC,
		Version:   TAKAKRYPT_PROTOCOL_VERSION,
		Operation: TAKAKRYPT_OP_DECRYPT,
		Sequence:  seq,
		DataLen:   uint32(dataLen),
		Status:    0,
	}

	// Serialize header
	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.LittleEndian, header); err != nil {
		return nil, fmt.Errorf("failed to serialize header: %w", err)
	}

	// Serialize data portion
	reqData := DecryptionRequestData{
		KeyIDLen: uint32(len(keyID)),
		DataLen:  uint32(len(encryptedData)),
	}
	if err := binary.Write(buf, binary.LittleEndian, reqData); err != nil {
		return nil, fmt.Errorf("failed to serialize request data: %w", err)
	}

	// Append key ID and encrypted data
	buf.Write([]byte(keyID))
	buf.Write(encryptedData)

	return buf.Bytes(), nil
}

// SerializePolicyCheckRequest creates a binary policy check request
func SerializePolicyCheckRequest(seq uint32, path string, operation, uid, gid, pid uint32) ([]byte, error) {
	if len(path) > 4096 {
		return nil, fmt.Errorf("path too long: %d > 4096", len(path))
	}

	// Calculate total data length
	dataLen := 20 + len(path) // 20 bytes for PathLen+Operation+UID+GID+PID

	// Create header
	header := TakakryptHeader{
		Magic:     TAKAKRYPT_MSG_MAGIC,
		Version:   TAKAKRYPT_PROTOCOL_VERSION,
		Operation: TAKAKRYPT_OP_CHECK_POLICY,
		Sequence:  seq,
		DataLen:   uint32(dataLen),
		Status:    0,
	}

	// Serialize header
	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.LittleEndian, header); err != nil {
		return nil, fmt.Errorf("failed to serialize header: %w", err)
	}

	// Serialize data portion
	reqData := PolicyCheckRequestData{
		PathLen:   uint32(len(path)),
		Operation: operation,
		UID:       uid,
		GID:       gid,
		PID:       pid,
	}
	if err := binary.Write(buf, binary.LittleEndian, reqData); err != nil {
		return nil, fmt.Errorf("failed to serialize request data: %w", err)
	}

	// Append path
	buf.Write([]byte(path))

	return buf.Bytes(), nil
}

// DeserializeMessage parses a binary message into components
func DeserializeMessage(data []byte) (*TakakryptMessage, error) {
	if len(data) < TAKAKRYPT_HEADER_SIZE {
		return nil, fmt.Errorf("message too short: %d < %d", len(data), TAKAKRYPT_HEADER_SIZE)
	}

	// Parse header
	header := TakakryptHeader{}
	buf := bytes.NewReader(data[:TAKAKRYPT_HEADER_SIZE])
	if err := binary.Read(buf, binary.LittleEndian, &header); err != nil {
		return nil, fmt.Errorf("failed to parse header: %w", err)
	}

	// Validate header
	if header.Magic != TAKAKRYPT_MSG_MAGIC {
		return nil, fmt.Errorf("invalid magic: 0x%x", header.Magic)
	}
	if header.Version != TAKAKRYPT_PROTOCOL_VERSION {
		return nil, fmt.Errorf("unsupported version: %d", header.Version)
	}
	if header.DataLen > MAX_MESSAGE_SIZE-TAKAKRYPT_HEADER_SIZE {
		return nil, fmt.Errorf("data length too large: %d", header.DataLen)
	}

	// Extract data portion
	expectedLen := TAKAKRYPT_HEADER_SIZE + int(header.DataLen)
	if len(data) < expectedLen {
		return nil, fmt.Errorf("incomplete message: %d < %d", len(data), expectedLen)
	}

	msgData := data[TAKAKRYPT_HEADER_SIZE:expectedLen]

	return &TakakryptMessage{
		Header: header,
		Data:   msgData,
	}, nil
}

// ParseEncryptionRequest extracts encryption request data
func ParseEncryptionRequest(msg *TakakryptMessage) (keyID string, data []byte, err error) {
	if msg.Header.Operation != TAKAKRYPT_OP_ENCRYPT {
		return "", nil, fmt.Errorf("not an encryption request: %d", msg.Header.Operation)
	}

	if len(msg.Data) < 8 {
		return "", nil, fmt.Errorf("encryption request data too short: %d", len(msg.Data))
	}

	// Parse request data structure
	reqData := EncryptionRequestData{}
	buf := bytes.NewReader(msg.Data[:8])
	if err := binary.Read(buf, binary.LittleEndian, &reqData); err != nil {
		return "", nil, fmt.Errorf("failed to parse encryption request: %w", err)
	}

	// Validate lengths
	expectedLen := 8 + int(reqData.KeyIDLen) + int(reqData.DataLen)
	if len(msg.Data) < expectedLen {
		return "", nil, fmt.Errorf("encryption request data incomplete: %d < %d", len(msg.Data), expectedLen)
	}

	// Extract key ID and data
	keyIDBytes := msg.Data[8 : 8+reqData.KeyIDLen]
	dataBytes := msg.Data[8+reqData.KeyIDLen : 8+reqData.KeyIDLen+reqData.DataLen]

	return string(keyIDBytes), dataBytes, nil
}

// ParseDecryptionRequest extracts decryption request data
func ParseDecryptionRequest(msg *TakakryptMessage) (keyID string, encryptedData []byte, err error) {
	if msg.Header.Operation != TAKAKRYPT_OP_DECRYPT {
		return "", nil, fmt.Errorf("not a decryption request: %d", msg.Header.Operation)
	}

	if len(msg.Data) < 8 {
		return "", nil, fmt.Errorf("decryption request data too short: %d", len(msg.Data))
	}

	// Parse request data structure
	reqData := DecryptionRequestData{}
	buf := bytes.NewReader(msg.Data[:8])
	if err := binary.Read(buf, binary.LittleEndian, &reqData); err != nil {
		return "", nil, fmt.Errorf("failed to parse decryption request: %w", err)
	}

	// Validate lengths
	expectedLen := 8 + int(reqData.KeyIDLen) + int(reqData.DataLen)
	if len(msg.Data) < expectedLen {
		return "", nil, fmt.Errorf("decryption request data incomplete: %d < %d", len(msg.Data), expectedLen)
	}

	// Extract key ID and encrypted data
	keyIDBytes := msg.Data[8 : 8+reqData.KeyIDLen]
	encDataBytes := msg.Data[8+reqData.KeyIDLen : 8+reqData.KeyIDLen+reqData.DataLen]

	return string(keyIDBytes), encDataBytes, nil
}

// SerializeResponse creates a binary response message
func SerializeResponse(seq uint32, operation uint16, status uint32, responseData []byte) ([]byte, error) {
	if len(responseData) > MAX_MESSAGE_SIZE-TAKAKRYPT_HEADER_SIZE {
		return nil, fmt.Errorf("response data too large: %d bytes", len(responseData))
	}

	// Create header
	header := TakakryptHeader{
		Magic:     TAKAKRYPT_MSG_MAGIC,
		Version:   TAKAKRYPT_PROTOCOL_VERSION,
		Operation: operation,
		Sequence:  seq,
		DataLen:   uint32(len(responseData)),
		Status:    status,
	}

	// Serialize header
	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.LittleEndian, header); err != nil {
		return nil, fmt.Errorf("failed to serialize header: %w", err)
	}

	// Append response data
	buf.Write(responseData)

	return buf.Bytes(), nil
}