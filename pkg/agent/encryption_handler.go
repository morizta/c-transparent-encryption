package agent

import (
	"fmt"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"takakrypt/internal/crypto"
	"takakrypt/pkg/netlink"
)

// EncryptionHandler handles encryption/decryption requests from kernel
type EncryptionHandler struct {
	fileEngine *crypto.FileEncryptionEngine
	agent      *Agent
	mu         sync.RWMutex
	
	// Statistics
	encryptionCount uint64
	decryptionCount uint64
	errorCount      uint64
	avgEncTime      time.Duration
	avgDecTime      time.Duration
}

// NewEncryptionHandler creates a new encryption handler
func NewEncryptionHandler(agent *Agent) *EncryptionHandler {
	return &EncryptionHandler{
		fileEngine: crypto.NewFileEncryptionEngine(),
		agent:      agent,
	}
}

// EncryptionRequest represents an encryption request from kernel
type EncryptionRequest struct {
	Data    []byte
	KeyID   string
	Seq     uint32 // Request sequence number
}

// DecryptionRequest represents a decryption request from kernel  
type DecryptionRequest struct {
	Data    []byte
	KeyID   string
	Seq     uint32 // Request sequence number
}

// EncryptionResponse represents response to encryption request
type EncryptionResponse struct {
	EncryptedData []byte
	Success       bool
	ErrorMessage  string
	Seq           uint32 // Response sequence number
}

// DecryptionResponse represents response to decryption request
type DecryptionResponse struct {
	DecryptedData []byte
	Success       bool
	ErrorMessage  string
	Seq           uint32 // Response sequence number
}

// HandleEncryptionRequest processes an encryption request
func (eh *EncryptionHandler) HandleEncryptionRequest(req *EncryptionRequest) *EncryptionResponse {
	start := time.Now()
	
	logrus.WithFields(logrus.Fields{
		"key_id":    req.KeyID,
		"data_size": len(req.Data),
		"seq":       req.Seq,
	}).Debug("Handling encryption request")

	// Validate request
	if len(req.Data) == 0 {
		eh.incrementError()
		return &EncryptionResponse{
			Success:      false,
			ErrorMessage: "empty data provided",
			Seq:          req.Seq,
		}
	}

	if req.KeyID == "" {
		eh.incrementError()
		return &EncryptionResponse{
			Success:      false,
			ErrorMessage: "no key ID provided",
			Seq:          req.Seq,
		}
	}

	// Check if data is already encrypted
	if eh.fileEngine.IsFileEncrypted(req.Data) {
		logrus.WithField("seq", req.Seq).Debug("Data already encrypted, returning as-is")
		return &EncryptionResponse{
			EncryptedData: req.Data,
			Success:       true,
			Seq:           req.Seq,
		}
	}

	// Perform encryption
	encryptedData, err := eh.fileEngine.EncryptFile(req.Data, req.KeyID)
	if err != nil {
		logrus.WithError(err).WithFields(logrus.Fields{
			"key_id": req.KeyID,
			"seq":    req.Seq,
		}).Error("Encryption failed")
		
		eh.incrementError()
		return &EncryptionResponse{
			Success:      false,
			ErrorMessage: fmt.Sprintf("encryption failed: %v", err),
			Seq:          req.Seq,
		}
	}

	// Update statistics
	eh.updateEncryptionStats(time.Since(start))

	logrus.WithFields(logrus.Fields{
		"key_id":          req.KeyID,
		"original_size":   len(req.Data),
		"encrypted_size":  len(encryptedData),
		"duration_ms":     time.Since(start).Milliseconds(),
		"seq":             req.Seq,
	}).Debug("Encryption successful")

	return &EncryptionResponse{
		EncryptedData: encryptedData,
		Success:       true,
		Seq:           req.Seq,
	}
}

// HandleDecryptionRequest processes a decryption request
func (eh *EncryptionHandler) HandleDecryptionRequest(req *DecryptionRequest) *DecryptionResponse {
	start := time.Now()
	
	logrus.WithFields(logrus.Fields{
		"key_id":    req.KeyID,
		"data_size": len(req.Data),
		"seq":       req.Seq,
	}).Debug("Handling decryption request")

	// Validate request
	if len(req.Data) == 0 {
		eh.incrementError()
		return &DecryptionResponse{
			Success:      false,
			ErrorMessage: "empty data provided",
			Seq:          req.Seq,
		}
	}

	// Check if data is actually encrypted
	if !eh.fileEngine.IsFileEncrypted(req.Data) {
		logrus.WithField("seq", req.Seq).Debug("Data not encrypted, returning as-is")
		return &DecryptionResponse{
			DecryptedData: req.Data,
			Success:       true,
			Seq:           req.Seq,
		}
	}

	// Perform decryption
	decryptedData, err := eh.fileEngine.DecryptFile(req.Data, req.KeyID)
	if err != nil {
		logrus.WithError(err).WithFields(logrus.Fields{
			"key_id": req.KeyID,
			"seq":    req.Seq,
		}).Error("Decryption failed")
		
		eh.incrementError()
		return &DecryptionResponse{
			Success:      false,
			ErrorMessage: fmt.Sprintf("decryption failed: %v", err),
			Seq:          req.Seq,
		}
	}

	// Update statistics
	eh.updateDecryptionStats(time.Since(start))

	logrus.WithFields(logrus.Fields{
		"key_id":          req.KeyID,
		"encrypted_size":  len(req.Data),
		"decrypted_size":  len(decryptedData),
		"duration_ms":     time.Since(start).Milliseconds(),
		"seq":             req.Seq,
	}).Debug("Decryption successful")

	return &DecryptionResponse{
		DecryptedData: decryptedData,
		Success:       true,
		Seq:           req.Seq,
	}
}

// GetFileInfo returns information about a file (encrypted or not)
func (eh *EncryptionHandler) GetFileInfo(data []byte) (*crypto.FileInfo, error) {
	return eh.fileEngine.GetFileInfo(data)
}

// CreatePolicyKey creates a new encryption key for a policy
func (eh *EncryptionHandler) CreatePolicyKey(policyName string, algorithm string) (*crypto.EncryptionKey, error) {
	return eh.fileEngine.CreateKeyForPolicy(policyName, algorithm)
}

// RotateKey rotates an existing key
func (eh *EncryptionHandler) RotateKey(keyID string) (*crypto.EncryptionKey, error) {
	return eh.fileEngine.RotateKey(keyID)
}

// GetStatistics returns encryption handler statistics
func (eh *EncryptionHandler) GetStatistics() map[string]interface{} {
	eh.mu.RLock()
	defer eh.mu.RUnlock()

	stats := map[string]interface{}{
		"encryption_operations": eh.encryptionCount,
		"decryption_operations": eh.decryptionCount,
		"error_count":          eh.errorCount,
		"avg_encryption_time_ms": eh.avgEncTime.Milliseconds(),
		"avg_decryption_time_ms": eh.avgDecTime.Milliseconds(),
	}

	// Add key statistics
	keyStats := eh.fileEngine.GetKeyStatistics()
	for k, v := range keyStats {
		stats[k] = v
	}

	return stats
}

// Private helper methods

func (eh *EncryptionHandler) updateEncryptionStats(duration time.Duration) {
	eh.mu.Lock()
	defer eh.mu.Unlock()
	
	eh.encryptionCount++
	
	// Update average encryption time (simple moving average)
	if eh.encryptionCount == 1 {
		eh.avgEncTime = duration
	} else {
		// Weighted average: 90% old, 10% new
		eh.avgEncTime = time.Duration(float64(eh.avgEncTime)*0.9 + float64(duration)*0.1)
	}
}

func (eh *EncryptionHandler) updateDecryptionStats(duration time.Duration) {
	eh.mu.Lock()
	defer eh.mu.Unlock()
	
	eh.decryptionCount++
	
	// Update average decryption time (simple moving average)
	if eh.decryptionCount == 1 {
		eh.avgDecTime = duration
	} else {
		// Weighted average: 90% old, 10% new
		eh.avgDecTime = time.Duration(float64(eh.avgDecTime)*0.9 + float64(duration)*0.1)
	}
}

func (eh *EncryptionHandler) incrementError() {
	eh.mu.Lock()
	defer eh.mu.Unlock()
	eh.errorCount++
}