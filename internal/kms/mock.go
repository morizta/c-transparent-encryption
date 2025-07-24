package kms

import (
	"context"
	"fmt"
	"sync"
	"time"

	"takakrypt/internal/config"
	"takakrypt/internal/crypto"
)

// MockKMSClient implements KMSClient interface for testing and development
type MockKMSClient struct {
	mu       sync.RWMutex
	keys     map[string]*crypto.EncryptionKey
	keyInfos map[string]*KeyInfo
	policies map[string]*config.Policy
	policyInfos map[string]*PolicyInfo
	config   *config.KMSConfig
	status   *KMSStatus
	errorRate float64 // For simulating errors (0.0 to 1.0)
}

// NewMockKMSClient creates a new mock KMS client
func NewMockKMSClient() *MockKMSClient {
	mock := &MockKMSClient{
		keys:        make(map[string]*crypto.EncryptionKey),
		keyInfos:    make(map[string]*KeyInfo),
		policies:    make(map[string]*config.Policy),
		policyInfos: make(map[string]*PolicyInfo),
		status: &KMSStatus{
			Available:    true,
			Version:      "Mock-1.0.0",
			LastContact:  time.Now(),
			ResponseTime: 10 * time.Millisecond,
			ErrorCount:   0,
		},
	}

	// Add some default test keys and policies
	mock.addDefaultTestData()
	return mock
}

// Configure configures the mock KMS client
func (m *MockKMSClient) Configure(cfg *config.KMSConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.config = cfg
	return nil
}

// GetKey retrieves a key by ID
func (m *MockKMSClient) GetKey(ctx context.Context, keyID string) (*crypto.EncryptionKey, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.shouldSimulateError() {
		return nil, NewKMSError(ErrCodeServiceUnavailable, "Simulated error")
	}

	key, exists := m.keys[keyID]
	if !exists {
		return nil, NewKMSError(ErrCodeKeyNotFound, fmt.Sprintf("Key %s not found", keyID))
	}

	m.updateStatus()
	return key, nil
}

// CreateKey creates a new key
func (m *MockKMSClient) CreateKey(ctx context.Context, req *CreateKeyRequest) (*crypto.EncryptionKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.shouldSimulateError() {
		return nil, NewKMSError(ErrCodeServiceUnavailable, "Simulated error")
	}

	// Generate key data
	var keySize int
	switch req.Algorithm {
	case "AES-256-GCM", "ChaCha20-Poly1305":
		keySize = 32
	case "AES-128-GCM":
		keySize = 16
	default:
		return nil, NewKMSError(ErrCodeInvalidAlgorithm, fmt.Sprintf("Unsupported algorithm: %s", req.Algorithm))
	}

	keyData := make([]byte, keySize)
	for i := range keyData {
		keyData[i] = byte(i % 256) // Deterministic for testing
	}

	key := &crypto.EncryptionKey{
		ID:        req.KeyID,
		Data:      keyData,
		Algorithm: req.Algorithm,
		KeySize:   req.KeySize,
		Version:   1,
	}

	keyInfo := &KeyInfo{
		ID:          req.KeyID,
		Algorithm:   req.Algorithm,
		KeySize:     req.KeySize,
		Usage:       req.Usage,
		Status:      "active",
		CreatedAt:   time.Now(),
		Description: req.Description,
		Metadata:    req.Metadata,
		Version:     1,
	}

	if req.TTL > 0 {
		expiry := time.Now().Add(req.TTL)
		keyInfo.ExpiresAt = &expiry
	}

	m.keys[req.KeyID] = key
	m.keyInfos[req.KeyID] = keyInfo

	m.updateStatus()
	return key, nil
}

// RotateKey rotates an existing key
func (m *MockKMSClient) RotateKey(ctx context.Context, keyID string) (*crypto.EncryptionKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.shouldSimulateError() {
		return nil, NewKMSError(ErrCodeServiceUnavailable, "Simulated error")
	}

	keyInfo, exists := m.keyInfos[keyID]
	if !exists {
		return nil, NewKMSError(ErrCodeKeyNotFound, fmt.Sprintf("Key %s not found", keyID))
	}

	// Create new version
	newVersion := keyInfo.Version + 1
	keySize := len(m.keys[keyID].Data)
	
	newKeyData := make([]byte, keySize)
	for i := range newKeyData {
		newKeyData[i] = byte((i + newVersion) % 256) // Different data for new version
	}

	newKey := &crypto.EncryptionKey{
		ID:        keyID,
		Data:      newKeyData,
		Algorithm: keyInfo.Algorithm,
		KeySize:   keyInfo.KeySize,
		Version:   newVersion,
	}

	keyInfo.Version = newVersion
	m.keys[keyID] = newKey

	m.updateStatus()
	return newKey, nil
}

// DeleteKey deletes a key
func (m *MockKMSClient) DeleteKey(ctx context.Context, keyID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.shouldSimulateError() {
		return NewKMSError(ErrCodeServiceUnavailable, "Simulated error")
	}

	if _, exists := m.keys[keyID]; !exists {
		return NewKMSError(ErrCodeKeyNotFound, fmt.Sprintf("Key %s not found", keyID))
	}

	delete(m.keys, keyID)
	delete(m.keyInfos, keyID)

	m.updateStatus()
	return nil
}

// ListKeys lists all keys
func (m *MockKMSClient) ListKeys(ctx context.Context) ([]*KeyInfo, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.shouldSimulateError() {
		return nil, NewKMSError(ErrCodeServiceUnavailable, "Simulated error")
	}

	keys := make([]*KeyInfo, 0, len(m.keyInfos))
	for _, keyInfo := range m.keyInfos {
		keys = append(keys, keyInfo)
	}

	m.updateStatus()
	return keys, nil
}

// GetPolicy retrieves a policy by ID
func (m *MockKMSClient) GetPolicy(ctx context.Context, policyID string) (*config.Policy, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.shouldSimulateError() {
		return nil, NewKMSError(ErrCodeServiceUnavailable, "Simulated error")
	}

	policy, exists := m.policies[policyID]
	if !exists {
		return nil, NewKMSError(ErrCodePolicyNotFound, fmt.Sprintf("Policy %s not found", policyID))
	}

	m.updateStatus()
	return policy, nil
}

// ListPolicies lists all policies
func (m *MockKMSClient) ListPolicies(ctx context.Context) ([]*PolicyInfo, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.shouldSimulateError() {
		return nil, NewKMSError(ErrCodeServiceUnavailable, "Simulated error")
	}

	policies := make([]*PolicyInfo, 0, len(m.policyInfos))
	for _, policyInfo := range m.policyInfos {
		policies = append(policies, policyInfo)
	}

	m.updateStatus()
	return policies, nil
}

// RefreshPolicies refreshes policy cache
func (m *MockKMSClient) RefreshPolicies(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.shouldSimulateError() {
		return NewKMSError(ErrCodeServiceUnavailable, "Simulated error")
	}

	// In a real KMS, this would fetch policies from the server
	// For mock, we just update the last contact time
	m.updateStatus()
	return nil
}

// HealthCheck performs a health check
func (m *MockKMSClient) HealthCheck(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.shouldSimulateError() {
		m.status.Available = false
		m.status.ErrorCount++
		return NewKMSError(ErrCodeServiceUnavailable, "Health check failed")
	}

	m.status.Available = true
	m.updateStatus()
	return nil
}

// GetStatus returns KMS status
func (m *MockKMSClient) GetStatus(ctx context.Context) (*KMSStatus, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	m.status.KeyCount = len(m.keys)
	m.status.PolicyCount = len(m.policies)
	
	return m.status, nil
}

// Close closes the client
func (m *MockKMSClient) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	// Clear sensitive data
	for _, key := range m.keys {
		for i := range key.Data {
			key.Data[i] = 0
		}
	}
	
	m.keys = make(map[string]*crypto.EncryptionKey)
	m.keyInfos = make(map[string]*KeyInfo)
	m.policies = make(map[string]*config.Policy)
	m.policyInfos = make(map[string]*PolicyInfo)
	
	return nil
}

// SetErrorRate sets the error simulation rate (0.0 to 1.0)
func (m *MockKMSClient) SetErrorRate(rate float64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.errorRate = rate
}

// Helper methods

func (m *MockKMSClient) shouldSimulateError() bool {
	if m.errorRate <= 0 {
		return false
	}
	// Simple deterministic error simulation
	return time.Now().UnixNano()%100 < int64(m.errorRate*100)
}

func (m *MockKMSClient) updateStatus() {
	m.status.LastContact = time.Now()
	m.status.ResponseTime = time.Duration(5+time.Now().UnixNano()%10) * time.Millisecond
}

func (m *MockKMSClient) addDefaultTestData() {
	// Add test keys
	testKeys := []struct {
		id        string
		algorithm string
		keySize   int
	}{
		{"test-key-aes256", "AES-256-GCM", 256},
		{"test-key-aes128", "AES-128-GCM", 128},
		{"test-key-chacha", "ChaCha20-Poly1305", 256},
	}

	for _, tk := range testKeys {
		req := &CreateKeyRequest{
			KeyID:       tk.id,
			Algorithm:   tk.algorithm,
			KeySize:     tk.keySize,
			Usage:       []string{"encrypt", "decrypt"},
			Description: fmt.Sprintf("Test key for %s", tk.algorithm),
		}
		
		m.CreateKey(context.Background(), req)
	}

	// Add test policies
	testPolicies := map[string]*config.Policy{
		"test-policy-1": {
			Name:      "Test Policy 1",
			Algorithm: "AES-256-GCM",
			KeySize:   256,
			UserSets:  []string{"test-users"},
			Enabled:   true,
		},
		"test-policy-2": {
			Name:      "Test Policy 2", 
			Algorithm: "ChaCha20-Poly1305",
			KeySize:   256,
			ProcessSets: []string{"test-processes"},
			Enabled:   true,
		},
	}

	for id, policy := range testPolicies {
		m.policies[id] = policy
		m.policyInfos[id] = &PolicyInfo{
			ID:        id,
			Name:      policy.Name,
			Version:   1,
			Status:    "active",
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}
	}
}