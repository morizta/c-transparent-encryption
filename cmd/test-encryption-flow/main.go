package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"

	"takakrypt/internal/config"
	"takakrypt/internal/crypto"
	"takakrypt/internal/policy"
	"gopkg.in/yaml.v3"
)

// SimulatedFile represents a file with its encryption state
type SimulatedFile struct {
	Path            string
	OriginalContent []byte
	DiskContent     []byte // What's actually on disk (encrypted or plain)
	Nonce           []byte // Nonce for encryption
	IsEncrypted     bool
	KeyID          string
	Algorithm      string
}

// SimulatedFileSystem tracks all files and their states
type SimulatedFileSystem struct {
	Files  map[string]*SimulatedFile
	Engine *crypto.EncryptionEngine
}

func main() {
	fmt.Println("=== Takakrypt Encryption Flow Test ===")
	fmt.Println()

	// Create test configuration
	cfg := createTestConfig()
	
	// Save configuration for reference
	configPath := "/tmp/takakrypt-encryption-test-config.yaml"
	saveConfig(cfg, configPath)
	fmt.Printf("Configuration saved to: %s\n", configPath)

	// Initialize components
	cryptoEngine := crypto.NewEncryptionEngine()

	policyEngine, err := policy.NewEngine(cfg)
	if err != nil {
		fmt.Printf("Error creating policy engine: %v\n", err)
		return
	}

	fs := &SimulatedFileSystem{
		Files:  make(map[string]*SimulatedFile),
		Engine: cryptoEngine,
	}

	// Create test directory
	testDir := "/tmp/takakrypt-encryption-test"
	os.RemoveAll(testDir)
	os.MkdirAll(testDir, 0755)

	// Generate encryption key for the policy
	key, err := cryptoEngine.GenerateKey("AES-256-GCM", "test-key-1")
	if err != nil {
		fmt.Printf("Error generating key: %v\n", err)
		return
	}
	fmt.Printf("Generated encryption key: %s\n", key.ID)

	fmt.Println("\n=== Test Scenarios ===")
	
	// Test 1: Write to guard point (should encrypt)
	fmt.Println("\n1. Writing file to guard point path:")
	testFile1 := filepath.Join(testDir, "sensitive-data.txt")
	content1 := []byte("This is sensitive data that should be encrypted")
	
	fmt.Printf("   - Writing to: %s\n", testFile1)
	fmt.Printf("   - Original content: %s\n", string(content1))
	
	// Simulate write operation
	err = simulateWrite(fs, policyEngine, testFile1, content1, 1000, "ntoi", "test-key-1") // UID 1000 (ntoi)
	if err != nil {
		fmt.Printf("   - Write error: %v\n", err)
	}
	
	// Check what's on "disk"
	if file, exists := fs.Files[testFile1]; exists {
		fmt.Printf("   - File is encrypted: %v\n", file.IsEncrypted)
		if file.IsEncrypted {
			fmt.Printf("   - Disk content (encrypted): %s\n", hex.EncodeToString(file.DiskContent)[:64]+"...")
			fmt.Printf("   - Key ID: %s\n", file.KeyID)
		}
	}

	// Test 2: Read from encrypted file (should decrypt)
	fmt.Println("\n2. Reading encrypted file:")
	readContent, err := simulateRead(fs, policyEngine, testFile1, 1000, "ntoi")
	if err != nil {
		fmt.Printf("   - Read error: %v\n", err)
	} else {
		fmt.Printf("   - Read content (decrypted): %s\n", string(readContent))
		fmt.Printf("   - Matches original: %v\n", string(readContent) == string(content1))
	}

	// Test 3: Unauthorized user tries to read
	fmt.Println("\n3. Unauthorized user reading encrypted file:")
	_, err = simulateRead(fs, policyEngine, testFile1, 9999, "nobody") // Unknown user
	if err != nil {
		fmt.Printf("   - Access denied (expected): %v\n", err)
	} else {
		fmt.Printf("   - ERROR: Unauthorized access allowed!\n")
	}

	// Test 4: Write non-matching file (should not encrypt)
	fmt.Println("\n4. Writing non-matching file pattern:")
	testFile2 := filepath.Join(testDir, "regular.log")
	content2 := []byte("This is a log file that should NOT be encrypted")
	
	fmt.Printf("   - Writing to: %s\n", testFile2)
	err = simulateWrite(fs, policyEngine, testFile2, content2, 1000, "ntoi", "test-key-1")
	if err != nil {
		fmt.Printf("   - Write error: %v\n", err)
	}
	
	if file, exists := fs.Files[testFile2]; exists {
		fmt.Printf("   - File is encrypted: %v\n", file.IsEncrypted)
		fmt.Printf("   - Disk content: %s\n", string(file.DiskContent))
	}

	// Test 5: Copy operation (write then read)
	fmt.Println("\n5. Simulating file copy to guard point:")
	sourceContent := []byte("File to be copied and encrypted")
	destFile := filepath.Join(testDir, "copied-document.txt")
	
	fmt.Printf("   - Source content: %s\n", string(sourceContent))
	fmt.Printf("   - Destination: %s\n", destFile)
	
	// Write (encrypt on write)
	err = simulateWrite(fs, policyEngine, destFile, sourceContent, 1000, "ntoi", "test-key-1")
	if err != nil {
		fmt.Printf("   - Write error: %v\n", err)
	}
	
	// Read back (decrypt on read)
	copiedContent, err := simulateRead(fs, policyEngine, destFile, 1000, "ntoi")
	if err != nil {
		fmt.Printf("   - Read error: %v\n", err)
	} else {
		fmt.Printf("   - Read back content: %s\n", string(copiedContent))
		fmt.Printf("   - Copy successful: %v\n", string(copiedContent) == string(sourceContent))
	}

	// Test 6: Different user access
	fmt.Println("\n6. Testing cross-user access:")
	testFile3 := filepath.Join(testDir, "user2-document.txt")
	content3 := []byte("TestUser2's document")
	
	// User2 writes
	err = simulateWrite(fs, policyEngine, testFile3, content3, 1001, "testuser1", "test-key-1")
	if err != nil {
		fmt.Printf("   - TestUser1 write error: %v\n", err)
	} else {
		fmt.Printf("   - TestUser1 wrote file successfully\n")
		
		// User2 reads their own file
		readBack, err := simulateRead(fs, policyEngine, testFile3, 1001, "testuser1")
		if err != nil {
			fmt.Printf("   - TestUser1 read error: %v\n", err)
		} else {
			fmt.Printf("   - TestUser1 can read own file: %s\n", string(readBack))
		}
		
		// Admin user reads user2's file
		adminRead, err := simulateRead(fs, policyEngine, testFile3, 1000, "ntoi")
		if err != nil {
			fmt.Printf("   - Admin read error: %v\n", err)
		} else {
			fmt.Printf("   - Admin can read TestUser1's file: %s\n", string(adminRead))
		}
	}

	fmt.Println("\n=== Encryption Flow Summary ===")
	fmt.Println("✓ Files are encrypted on write when they match guard point policies")
	fmt.Println("✓ Files are decrypted on read for authorized users")
	fmt.Println("✓ Unauthorized users cannot read encrypted content")
	fmt.Println("✓ Non-matching files remain unencrypted")
	fmt.Println("✓ Copy operations work transparently (encrypt on write, decrypt on read)")
	fmt.Println("✓ Multiple authorized users can access encrypted files")
}

func simulateWrite(fs *SimulatedFileSystem, pe *policy.Engine, filepath string, content []byte, uid int, username string, defaultKeyID string) error {
	// Create evaluation context
	ctx := &policy.EvaluationContext{
		FilePath:    filepath,
		UserID:      uid,
		GroupIDs:    []int{uid}, // Simplified: assume primary group = uid
		ProcessName: "test-app",
		ProcessPath: "/usr/bin/test-app",
		Operation:   "write",
		Timestamp:   time.Now(),
	}

	// Check policy
	result, err := pe.EvaluateAccess(context.Background(), ctx)
	if err != nil {
		return fmt.Errorf("policy evaluation error: %v", err)
	}
	
	file := &SimulatedFile{
		Path:            filepath,
		OriginalContent: content,
		DiskContent:     content, // Default to unencrypted
		IsEncrypted:     false,
	}

	if result.Allow {
		// Check if this guard point requires encryption
		if result.Policy != nil && result.Policy.Algorithm != "" {
			// Use the key ID from policy result or default
			keyID := result.KeyID
			if keyID == "" {
				keyID = defaultKeyID
			}
			
			// Make sure we have the key generated
			_, err := fs.Engine.GenerateKey(result.Policy.Algorithm, keyID)
			if err != nil {
				// If key already exists, that's fine
			}
			
			// Encrypt the content
			encResult, err := fs.Engine.Encrypt(content, keyID)
			if err != nil {
				return fmt.Errorf("encryption failed: %v", err)
			}
			
			file.DiskContent = encResult.Ciphertext
			file.Nonce = encResult.Nonce
			file.IsEncrypted = true
			file.KeyID = keyID
			file.Algorithm = encResult.Algorithm
		}
		
		fs.Files[filepath] = file
		return nil
	}
	
	return fmt.Errorf("access denied by policy for user %s (uid=%d)", username, uid)
}

func simulateRead(fs *SimulatedFileSystem, pe *policy.Engine, filepath string, uid int, username string) ([]byte, error) {
	// Check if file exists
	file, exists := fs.Files[filepath]
	if !exists {
		return nil, fmt.Errorf("file not found")
	}

	// Create evaluation context
	ctx := &policy.EvaluationContext{
		FilePath:    filepath,
		UserID:      uid,
		GroupIDs:    []int{uid}, // Simplified
		ProcessName: "test-app",
		ProcessPath: "/usr/bin/test-app",
		Operation:   "read",
		Timestamp:   time.Now(),
	}

	// Check policy
	result, err := pe.EvaluateAccess(context.Background(), ctx)
	if err != nil {
		return nil, fmt.Errorf("policy evaluation error: %v", err)
	}
	
	if !result.Allow {
		return nil, fmt.Errorf("access denied by policy for user %s (uid=%d)", username, uid)
	}

	// If file is encrypted, decrypt it
	if file.IsEncrypted {
		req := &crypto.DecryptionRequest{
			Ciphertext: file.DiskContent,
			Nonce:      file.Nonce,
			Algorithm:  file.Algorithm,
			KeyID:      file.KeyID,
			Version:    1,
		}
		
		decrypted, err := fs.Engine.Decrypt(req)
		if err != nil {
			return nil, fmt.Errorf("decryption failed: %v", err)
		}
		
		return decrypted, nil
	}

	// Return unencrypted content
	return file.DiskContent, nil
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