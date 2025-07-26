package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"

	"takakrypt/internal/config"
	"takakrypt/internal/crypto"
	"takakrypt/internal/policy"
	"gopkg.in/yaml.v3"
)

func main() {
	fmt.Println("=== Takakrypt Encryption Flow Debug Test ===")
	fmt.Println()

	// Create test configuration
	cfg := createTestConfig()
	
	// Initialize policy engine
	policyEngine, err := policy.NewEngine(cfg)
	if err != nil {
		fmt.Printf("Error creating policy engine: %v\n", err)
		return
	}

	// Test directory
	testDir := "/tmp/takakrypt-encryption-test"
	os.MkdirAll(testDir, 0755)

	// Test file path
	testFile := filepath.Join(testDir, "sensitive-data.txt")
	
	// Create evaluation context for write
	ctx := &policy.EvaluationContext{
		FilePath:    testFile,
		UserID:      1000, // ntoi
		GroupIDs:    []int{1000},
		ProcessName: "test-app",
		ProcessPath: "/usr/bin/test-app",
		Operation:   "write",
		Timestamp:   time.Now(),
	}

	fmt.Println("=== Policy Evaluation Debug ===")
	fmt.Printf("Evaluating access for:\n")
	fmt.Printf("  File: %s\n", ctx.FilePath)
	fmt.Printf("  User: %d\n", ctx.UserID)
	fmt.Printf("  Operation: %s\n", ctx.Operation)
	fmt.Println()

	// Check policy
	result, err := policyEngine.EvaluateAccess(context.Background(), ctx)
	if err != nil {
		fmt.Printf("Policy evaluation error: %v\n", err)
		return
	}

	fmt.Printf("Policy Result:\n")
	fmt.Printf("  Allow: %v\n", result.Allow)
	fmt.Printf("  Policy: %+v\n", result.Policy)
	fmt.Printf("  Guard Point: %+v\n", result.GuardPoint)
	fmt.Printf("  Reason: %s\n", result.Reason)
	fmt.Printf("  Key ID: %s\n", result.KeyID)

	if result.Policy != nil {
		fmt.Printf("\nPolicy Details:\n")
		fmt.Printf("  Name: %s\n", result.Policy.Name)
		fmt.Printf("  Algorithm: %s\n", result.Policy.Algorithm)
		fmt.Printf("  User Sets: %v\n", result.Policy.UserSets)
		fmt.Printf("  Process Sets: %v\n", result.Policy.ProcessSets)
		fmt.Printf("  Resource Sets: %v\n", result.Policy.ResourceSets)
	}

	// Test encryption
	if result.Allow && result.Policy != nil && result.Policy.Algorithm != "" {
		fmt.Println("\n=== Encryption Test ===")
		fmt.Println("Policy requires encryption!")
		
		cryptoEngine := crypto.NewEncryptionEngine()
		
		// Generate key
		key, err := cryptoEngine.GenerateKey(result.Policy.Algorithm, "test-key-1")
		if err != nil {
			fmt.Printf("Error generating key: %v\n", err)
			return
		}
		fmt.Printf("Generated key: %s\n", key.ID)
		
		// Test encryption
		plaintext := []byte("This is sensitive data")
		encResult, err := cryptoEngine.Encrypt(plaintext, key.ID)
		if err != nil {
			fmt.Printf("Encryption error: %v\n", err)
			return
		}
		
		fmt.Printf("Encryption successful:\n")
		fmt.Printf("  Algorithm: %s\n", encResult.Algorithm)
		fmt.Printf("  Ciphertext length: %d\n", len(encResult.Ciphertext))
		fmt.Printf("  Ciphertext (hex): %s...\n", hex.EncodeToString(encResult.Ciphertext)[:64])
		fmt.Printf("  Nonce (hex): %s\n", hex.EncodeToString(encResult.Nonce))
		
		// Test decryption
		req := &crypto.DecryptionRequest{
			Ciphertext: encResult.Ciphertext,
			Nonce:      encResult.Nonce,
			Algorithm:  encResult.Algorithm,
			KeyID:      encResult.KeyID,
			Version:    encResult.Version,
		}
		
		decrypted, err := cryptoEngine.Decrypt(req)
		if err != nil {
			fmt.Printf("Decryption error: %v\n", err)
			return
		}
		
		fmt.Printf("\nDecryption successful:\n")
		fmt.Printf("  Plaintext: %s\n", string(decrypted))
		fmt.Printf("  Matches original: %v\n", string(decrypted) == string(plaintext))
	} else {
		fmt.Println("\n=== No Encryption Required ===")
		fmt.Printf("Access allowed: %v\n", result.Allow)
		fmt.Printf("Policy exists: %v\n", result.Policy != nil)
		if result.Policy != nil {
			fmt.Printf("Algorithm specified: %v\n", result.Policy.Algorithm != "")
		}
	}

	// Check guard point matching
	fmt.Println("\n=== Guard Point Matching Debug ===")
	for _, gp := range cfg.GuardPoints {
		fmt.Printf("\nGuard Point: %s\n", gp.Name)
		fmt.Printf("  Path: %s\n", gp.Path)
		fmt.Printf("  Include Patterns: %v\n", gp.IncludePatterns)
		fmt.Printf("  Test file: %s\n", testFile)
		fmt.Printf("  File is under guard point: %v\n", isUnderPath(testFile, gp.Path))
		
		// Check pattern matching
		filename := filepath.Base(testFile)
		fmt.Printf("  Filename: %s\n", filename)
		for _, pattern := range gp.IncludePatterns {
			matched, _ := filepath.Match(pattern, filename)
			fmt.Printf("  Matches pattern '%s': %v\n", pattern, matched)
		}
	}
}

func isUnderPath(file, guardPath string) bool {
	rel, err := filepath.Rel(guardPath, file)
	if err != nil {
		return false
	}
	return !filepath.IsAbs(rel) && rel != ".." && !strings.HasPrefix(rel, "../")
}

func createTestConfig() *config.Config {
	return &config.Config{
		GuardPoints: []config.GuardPoint{
			{
				Name:      "test_encryption",
				Path:      "/tmp/takakrypt-encryption-test",
				Recursive: true,
				IncludePatterns: []string{"*.txt", "*.doc"},
				ExcludePatterns: []string{"*.log", "*.tmp"},
				Policy:    "encryption_policy",
				Enabled:   true,
			},
		},
		UserSets: map[string]config.UserSet{
			"authorized_users": {
				Name:  "authorized_users",
				Users: []string{"ntoi", "testuser1", "testuser2"},
				UIDs:  []int{1000, 1001, 1002},
			},
		},
		Policies: map[string]config.Policy{
			"encryption_policy": {
				Name:      "encryption_policy",
				Algorithm: "AES-256-GCM",
				UserSets:  []string{"authorized_users"},
				Enabled:   true,
			},
		},
		Agent: config.AgentConfig{
			SocketPath:    "/tmp/takakrypt.sock",
			LogLevel:      "info",
			WorkerThreads: 4,
		},
		KMS: config.KMSConfig{
			Endpoint:   "mock://localhost",
			AuthMethod: "none",
		},
	}
}

func saveConfig(cfg *config.Config, path string) {
	data, _ := yaml.Marshal(cfg)
	ioutil.WriteFile(path, data, 0644)
}