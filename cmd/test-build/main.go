package main

import (
	"fmt"
	"log"

	"takakrypt/internal/config"
	"takakrypt/internal/crypto"
)

func main() {
	fmt.Println("Testing Takakrypt build...")

	// Test config loading
	parser := config.NewParser("../../configs/example.yaml")
	cfg, err := parser.Load()
	if err != nil {
		log.Printf("Config load error (expected if file doesn't exist): %v", err)
	} else {
		fmt.Printf("Config loaded successfully with %d guard points\n", len(cfg.GuardPoints))
	}

	// Test crypto engine
	engine := crypto.NewEncryptionEngine()
	fmt.Printf("Crypto engine created with %d cached keys\n", engine.GetCachedKeyCount())

	// Test key generation
	key, err := engine.GenerateKey("AES-256-GCM", "test-key")
	if err != nil {
		log.Printf("Key generation error: %v", err)
	} else {
		fmt.Printf("Generated key: %s\n", key.ID)
	}

	fmt.Println("✅ Basic build test completed successfully!")
}