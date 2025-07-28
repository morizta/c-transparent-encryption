package kms

import (
	"context"
	"time"

	"takakrypt/internal/config"
	"takakrypt/internal/crypto"
)

// KMSClient defines the interface for Key Management System integration
type KMSClient interface {
	// Key Management
	GetKey(ctx context.Context, keyID string) (*crypto.EncryptionKey, error)
	CreateKey(ctx context.Context, req *CreateKeyRequest) (*crypto.EncryptionKey, error)
	RotateKey(ctx context.Context, keyID string) (*crypto.EncryptionKey, error)
	DeleteKey(ctx context.Context, keyID string) error
	ListKeys(ctx context.Context) ([]*KeyInfo, error)

	// Policy Management  
	GetPolicy(ctx context.Context, policyID string) (*config.Policy, error)
	ListPolicies(ctx context.Context) ([]*PolicyInfo, error)
	RefreshPolicies(ctx context.Context) error

	// Health and Status
	HealthCheck(ctx context.Context) error
	GetStatus(ctx context.Context) (*KMSStatus, error)

	// Configuration
	Configure(cfg *config.KMSConfig) error
	Close() error
}

// CreateKeyRequest contains parameters for key creation
type CreateKeyRequest struct {
	KeyID       string            `json:"key_id"`
	Algorithm   string            `json:"algorithm"`
	KeySize     int               `json:"key_size"`
	Usage       []string          `json:"usage"`
	Description string            `json:"description,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
	TTL         time.Duration     `json:"ttl,omitempty"`
}

// KeyInfo contains metadata about a key
type KeyInfo struct {
	ID          string            `json:"id"`
	Algorithm   string            `json:"algorithm"`
	KeySize     int               `json:"key_size"`
	Usage       []string          `json:"usage"`
	Status      string            `json:"status"`
	CreatedAt   time.Time         `json:"created_at"`
	ExpiresAt   *time.Time        `json:"expires_at,omitempty"`
	Description string            `json:"description,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
	Version     int               `json:"version"`
}

// PolicyInfo contains metadata about a policy
type PolicyInfo struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Version     int               `json:"version"`
	Status      string            `json:"status"`
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
	Description string            `json:"description,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// KMSStatus contains status information about the KMS
type KMSStatus struct {
	Available     bool      `json:"available"`
	Version       string    `json:"version"`
	LastContact   time.Time `json:"last_contact"`
	ResponseTime  time.Duration `json:"response_time"`
	ErrorCount    int       `json:"error_count"`
	KeyCount      int       `json:"key_count"`
	PolicyCount   int       `json:"policy_count"`
}

// KMSError represents errors from KMS operations
type KMSError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Details string `json:"details,omitempty"`
}

func (e *KMSError) Error() string {
	if e.Details != "" {
		return e.Code + ": " + e.Message + " (" + e.Details + ")"
	}
	return e.Code + ": " + e.Message
}

// Common KMS error codes
const (
	ErrCodeKeyNotFound      = "KEY_NOT_FOUND"
	ErrCodePolicyNotFound   = "POLICY_NOT_FOUND"
	ErrCodeUnauthorized     = "UNAUTHORIZED"
	ErrCodeInvalidRequest   = "INVALID_REQUEST"
	ErrCodeServiceUnavailable = "SERVICE_UNAVAILABLE"
	ErrCodeQuotaExceeded    = "QUOTA_EXCEEDED"
	ErrCodeKeyExpired       = "KEY_EXPIRED"
	ErrCodeInvalidAlgorithm = "INVALID_ALGORITHM"
)

// NewKMSError creates a new KMS error
func NewKMSError(code, message string) *KMSError {
	return &KMSError{
		Code:    code,
		Message: message,
	}
}

// NewKMSErrorWithDetails creates a new KMS error with details
func NewKMSErrorWithDetails(code, message, details string) *KMSError {
	return &KMSError{
		Code:    code,
		Message: message,
		Details: details,
	}
}// Enhanced logging enabled
