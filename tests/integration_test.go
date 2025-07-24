package tests

import (
	"context"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
	"time"

	"takakrypt/internal/config"
	"takakrypt/internal/crypto"
	"takakrypt/internal/kms"
	"takakrypt/internal/policy"
)

// TestConfigLoading tests configuration file parsing
func TestConfigLoading(t *testing.T) {
	// Create temporary config file
	configContent := `
guard_points:
  - name: "test_guard"
    path: "/tmp/test"
    recursive: true
    policy: "test_policy"
    enabled: true

policies:
  test_policy:
    algorithm: "AES-256-GCM"
    key_size: 256
    enabled: true

user_sets:
  test_users:
    users: ["testuser"]

kms:
  endpoint: "mock://localhost"
  auth_method: "token"
  timeout: "10s"

agent:
  log_level: "debug"
  worker_threads: 2
`

	tmpFile, err := ioutil.TempFile("", "test-config-*.yaml")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.Write([]byte(configContent)); err != nil {
		t.Fatalf("Failed to write config: %v", err)
	}
	tmpFile.Close()

	// Test loading
	parser := config.NewParser(tmpFile.Name())
	cfg, err := parser.Load()
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// Verify loaded config
	if len(cfg.GuardPoints) != 1 {
		t.Errorf("Expected 1 guard point, got %d", len(cfg.GuardPoints))
	}

	if cfg.GuardPoints[0].Name != "test_guard" {
		t.Errorf("Expected guard point name 'test_guard', got '%s'", cfg.GuardPoints[0].Name)
	}

	if len(cfg.Policies) != 1 {
		t.Errorf("Expected 1 policy, got %d", len(cfg.Policies))
	}

	if cfg.KMS.Endpoint != "mock://localhost" {
		t.Errorf("Expected KMS endpoint 'mock://localhost', got '%s'", cfg.KMS.Endpoint)
	}
}

// TestEncryptionEngine tests the encryption/decryption functionality
func TestEncryptionEngine(t *testing.T) {
	engine := crypto.NewEncryptionEngine()

	// Test key generation
	key, err := engine.GenerateKey("AES-256-GCM", "test-key-1")
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	if key.Algorithm != "AES-256-GCM" {
		t.Errorf("Expected algorithm AES-256-GCM, got %s", key.Algorithm)
	}

	// Test encryption
	plaintext := []byte("This is a test message for encryption")
	result, err := engine.Encrypt(plaintext, "test-key-1")
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	if len(result.Ciphertext) == 0 {
		t.Error("Empty ciphertext returned")
	}

	if len(result.Nonce) == 0 {
		t.Error("Empty nonce returned")
	}

	// Test decryption
	decrypted, err := engine.Decrypt(&crypto.DecryptionRequest{
		Ciphertext: result.Ciphertext,
		Nonce:      result.Nonce,
		Algorithm:  result.Algorithm,
		KeyID:      result.KeyID,
		Version:    result.Version,
	})
	if err != nil {
		t.Fatalf("Failed to decrypt: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("Decrypted text doesn't match: got '%s', want '%s'",
			string(decrypted), string(plaintext))
	}
}

// TestKMSClient tests KMS client functionality
func TestKMSClient(t *testing.T) {
	client := kms.NewMockKMSClient()
	ctx := context.Background()

	// Configure client
	cfg := &config.KMSConfig{
		Endpoint:    "mock://localhost",
		AuthMethod:  "token",
		Timeout:     10 * time.Second,
		KeyCacheTTL: 1 * time.Hour,
	}

	if err := client.Configure(cfg); err != nil {
		t.Fatalf("Failed to configure KMS client: %v", err)
	}

	// Test key creation
	req := &kms.CreateKeyRequest{
		KeyID:     "test-key-2",
		Algorithm: "AES-256-GCM",
		KeySize:   256,
		Usage:     []string{"encrypt", "decrypt"},
	}

	key, err := client.CreateKey(ctx, req)
	if err != nil {
		t.Fatalf("Failed to create key: %v", err)
	}

	if key.ID != "test-key-2" {
		t.Errorf("Expected key ID 'test-key-2', got '%s'", key.ID)
	}

	// Test key retrieval
	retrievedKey, err := client.GetKey(ctx, "test-key-2")
	if err != nil {
		t.Fatalf("Failed to get key: %v", err)
	}

	if retrievedKey.ID != key.ID {
		t.Errorf("Retrieved key ID doesn't match: got '%s', want '%s'",
			retrievedKey.ID, key.ID)
	}

	// Test health check
	if err := client.HealthCheck(ctx); err != nil {
		t.Errorf("Health check failed: %v", err)
	}
}

// TestPolicyEngine tests policy evaluation
func TestPolicyEngine(t *testing.T) {
	// Create test configuration
	cfg := &config.Config{
		GuardPoints: []config.GuardPoint{
			{
				Name:      "test_guard",
				Path:      "/test/path",
				Recursive: true,
				Policy:    "test_policy",
				Enabled:   true,
			},
		},
		Policies: map[string]config.Policy{
			"test_policy": {
				Name:      "Test Policy",
				Algorithm: "AES-256-GCM",
				UserSets:  []string{"test_users"},
				Enabled:   true,
			},
		},
		UserSets: map[string]config.UserSet{
			"test_users": {
				Name:  "Test Users",
				Users: []string{"testuser"},
				UIDs:  []int{1000},
			},
		},
	}

	engine, err := policy.NewEngine(cfg)
	if err != nil {
		t.Fatalf("Failed to create policy engine: %v", err)
	}

	// Test policy evaluation
	ctx := context.Background()
	evalCtx := &policy.EvaluationContext{
		FilePath:    "/test/path/file.txt",
		UserID:      1000,
		ProcessID:   12345,
		ProcessName: "test_process",
		Operation:   "read",
		Timestamp:   time.Now(),
	}

	result, err := engine.EvaluateAccess(ctx, evalCtx)
	if err != nil {
		t.Fatalf("Failed to evaluate access: %v", err)
	}

	if !result.Allow {
		t.Errorf("Expected access to be allowed, but was denied: %s", result.Reason)
	}

	// Test with non-matching user
	evalCtx.UserID = 9999
	result2, err := engine.EvaluateAccess(ctx, evalCtx)
	if err != nil {
		t.Fatalf("Failed to evaluate access: %v", err)
	}

	if result2.Allow {
		t.Errorf("Expected access to be denied for non-matching user, but was allowed")
	}
}

// TestEndToEndEncryption tests the full encryption workflow
func TestEndToEndEncryption(t *testing.T) {
	// Create temporary directory
	tmpDir, err := ioutil.TempDir("", "takakrypt-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create test file
	testFile := filepath.Join(tmpDir, "test-document.txt")
	testContent := []byte("This is a confidential document")
	if err := ioutil.WriteFile(testFile, testContent, 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Setup components
	encEngine := crypto.NewEncryptionEngine()
	kmsClient := kms.NewMockKMSClient()

	// Create and configure policy engine
	cfg := &config.Config{
		GuardPoints: []config.GuardPoint{
			{
				Name:      "test_docs",
				Path:      tmpDir,
				Recursive: true,
				Policy:    "encrypt_all",
				Enabled:   true,
			},
		},
		Policies: map[string]config.Policy{
			"encrypt_all": {
				Name:      "Encrypt All",
				Algorithm: "AES-256-GCM",
				Enabled:   true,
			},
		},
	}

	policyEngine, err := policy.NewEngine(cfg)
	if err != nil {
		t.Fatalf("Failed to create policy engine: %v", err)
	}

	// Evaluate policy
	ctx := context.Background()
	evalCtx := &policy.EvaluationContext{
		FilePath:    testFile,
		UserID:      os.Getuid(),
		ProcessID:   os.Getpid(),
		ProcessName: "test",
		Operation:   "write",
		Timestamp:   time.Now(),
	}

	result, err := policyEngine.EvaluateAccess(ctx, evalCtx)
	if err != nil {
		t.Fatalf("Failed to evaluate policy: %v", err)
	}

	if !result.Allow {
		t.Fatalf("Policy denied access: %s", result.Reason)
	}

	// Create encryption key
	keyReq := &kms.CreateKeyRequest{
		KeyID:     "test-file-key",
		Algorithm: "AES-256-GCM",
		KeySize:   256,
	}

	key, err := kmsClient.CreateKey(ctx, keyReq)
	if err != nil {
		t.Fatalf("Failed to create key: %v", err)
	}

	// Set key in encryption engine
	encEngine.SetKey(key)

	// Encrypt the file content
	encResult, err := encEngine.Encrypt(testContent, key.ID)
	if err != nil {
		t.Fatalf("Failed to encrypt file content: %v", err)
	}

	// Write encrypted content back
	encryptedFile := filepath.Join(tmpDir, "test-document.txt.enc")
	if err := ioutil.WriteFile(encryptedFile, encResult.Ciphertext, 0644); err != nil {
		t.Fatalf("Failed to write encrypted file: %v", err)
	}

	// Read and decrypt
	encryptedContent, err := ioutil.ReadFile(encryptedFile)
	if err != nil {
		t.Fatalf("Failed to read encrypted file: %v", err)
	}

	decrypted, err := encEngine.Decrypt(&crypto.DecryptionRequest{
		Ciphertext: encryptedContent,
		Nonce:      encResult.Nonce,
		Algorithm:  encResult.Algorithm,
		KeyID:      encResult.KeyID,
		Version:    encResult.Version,
	})
	if err != nil {
		t.Fatalf("Failed to decrypt: %v", err)
	}

	if string(decrypted) != string(testContent) {
		t.Errorf("Decrypted content doesn't match: got '%s', want '%s'",
			string(decrypted), string(testContent))
	}
}

// BenchmarkEncryption benchmarks encryption performance
func BenchmarkEncryption(b *testing.B) {
	engine := crypto.NewEncryptionEngine()
	key, _ := engine.GenerateKey("AES-256-GCM", "bench-key")

	// Test with 1KB of data
	data := make([]byte, 1024)
	for i := range data {
		data[i] = byte(i % 256)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := engine.Encrypt(data, key.ID)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkPolicyEvaluation benchmarks policy evaluation performance
func BenchmarkPolicyEvaluation(b *testing.B) {
	cfg := &config.Config{
		GuardPoints: []config.GuardPoint{
			{Name: "test", Path: "/test", Policy: "default", Enabled: true},
		},
		Policies: map[string]config.Policy{
			"default": {Algorithm: "AES-256-GCM", Enabled: true},
		},
	}

	engine, _ := policy.NewEngine(cfg)
	ctx := context.Background()
	evalCtx := &policy.EvaluationContext{
		FilePath:  "/test/file.txt",
		UserID:    1000,
		ProcessID: 12345,
		Operation: "read",
		Timestamp: time.Now(),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := engine.EvaluateAccess(ctx, evalCtx)
		if err != nil {
			b.Fatal(err)
		}
	}
}
