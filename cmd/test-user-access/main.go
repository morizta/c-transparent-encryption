package main

import (
	"fmt"
	"os"

	"takakrypt/internal/config"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run main.go <config-path>")
		os.Exit(1)
	}

	configPath := os.Args[1]
	
	// Load configuration using the proper API
	fmt.Printf("Loading configuration from: %s\n", configPath)
	parser := config.NewParser(configPath)
	cfg, err := parser.Load()
	if err != nil {
		fmt.Printf("❌ Failed to load config: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("✅ Configuration loaded successfully!\n\n")

	// Validate that users are properly configured
	fmt.Printf("=== User Access Control Configuration Test ===\n\n")

	// Check guard points
	fmt.Printf("Guard Points (%d configured):\n", len(cfg.GuardPoints))
	for name, gp := range cfg.GuardPoints {
		fmt.Printf("  ✅ %s:\n", name)
		fmt.Printf("     Path: %s\n", gp.Path)
		fmt.Printf("     Policy: %s\n", gp.Policy)
		fmt.Printf("     Recursive: %v\n", gp.Recursive)
		fmt.Printf("     Include: %v\n", gp.IncludePatterns)
		fmt.Printf("     Exclude: %v\n", gp.ExcludePatterns)
		fmt.Printf("\n")
	}

	// Check user sets
	fmt.Printf("User Sets (%d configured):\n", len(cfg.UserSets))
	for name, us := range cfg.UserSets {
		fmt.Printf("  ✅ %s:\n", name)
		fmt.Printf("     Users: %v\n", us.Users)
		fmt.Printf("     UIDs: %v\n", us.UIDs)
		fmt.Printf("     Groups: %v\n", us.Groups)
		fmt.Printf("     Description: %s\n", us.Description)
		fmt.Printf("\n")
	}

	// Check policies
	fmt.Printf("Policies (%d configured):\n", len(cfg.Policies))
	for name, pol := range cfg.Policies {
		fmt.Printf("  ✅ %s:\n", name)
		fmt.Printf("     Algorithm: %s\n", pol.Algorithm)
		fmt.Printf("     Key Size: %d\n", pol.KeySize)
		fmt.Printf("     Enabled: %v\n", pol.Enabled)
		fmt.Printf("\n")
	}

	// Test user scenarios
	fmt.Printf("=== User Access Test Scenarios ===\n\n")
	
	testUsers := []struct {
		name string
		uid  uint32
		user string
	}{
		{"Admin User (ntoi)", 1000, "ntoi"},
		{"Test User 1", 1001, "testuser1"},
		{"Test User 2", 1002, "testuser2"},
		{"Unknown User", 9999, "unknown"},
	}

	for _, tu := range testUsers {
		fmt.Printf("User: %s (UID: %d)\n", tu.name, tu.uid)
		
		// Check if user is in any user set
		found := false
		for setName, us := range cfg.UserSets {
			// Check by username
			for _, username := range us.Users {
				if username == tu.user {
					fmt.Printf("  ✅ Found in user set '%s' by username\n", setName)
					found = true
					break
				}
			}
			// Check by UID
			for _, uid := range us.UIDs {
				if uint32(uid) == tu.uid {
					fmt.Printf("  ✅ Found in user set '%s' by UID\n", setName)
					found = true
					break
				}
			}
		}
		
		if !found {
			fmt.Printf("  ❌ Not found in any user set - access would be DENIED\n")
		}
		fmt.Printf("\n")
	}

	fmt.Printf("=== Test File Scenarios ===\n\n")
	
	testFiles := []struct {
		path        string
		description string
	}{
		{"/tmp/takakrypt-user-test/admin-document.txt", "Admin document (should match guard point)"},
		{"/tmp/takakrypt-user-test/user1-document.txt", "User1 document (should match guard point)"},
		{"/tmp/takakrypt-user-test/confidential-data.txt", "Confidential file (should match resource set)"},
		{"/tmp/takakrypt-user-test/test.log", "Log file (should NOT match - wrong extension)"},
		{"/home/user/document.txt", "File outside guard point (should NOT match)"},
	}

	for _, tf := range testFiles {
		fmt.Printf("File: %s\n", tf.path)
		fmt.Printf("  Description: %s\n", tf.description)
		
		// Check if file matches any guard point
		matchesGuardPoint := false
		for gpName, gp := range cfg.GuardPoints {
			if len(tf.path) >= len(gp.Path) && tf.path[:len(gp.Path)] == gp.Path {
				fmt.Printf("  ✅ Matches guard point: %s\n", gpName)
				matchesGuardPoint = true
				
				// Check include patterns
				matchesPattern := false
				for _, pattern := range gp.IncludePatterns {
					// Simple pattern matching (could be improved)
					if pattern == "*.txt" && len(tf.path) > 4 && tf.path[len(tf.path)-4:] == ".txt" {
						fmt.Printf("  ✅ Matches include pattern: %s\n", pattern)
						matchesPattern = true
					} else if pattern == "*.doc" && len(tf.path) > 4 && tf.path[len(tf.path)-4:] == ".doc" {
						fmt.Printf("  ✅ Matches include pattern: %s\n", pattern)
						matchesPattern = true
					}
				}
				
				if !matchesPattern && len(gp.IncludePatterns) > 0 {
					fmt.Printf("  ❌ Does not match any include patterns\n")
				}
			}
		}
		
		if !matchesGuardPoint {
			fmt.Printf("  ❌ No matching guard point\n")
		}
		fmt.Printf("\n")
	}

	fmt.Printf("🎉 Configuration validation complete!\n")
	fmt.Printf("📋 Summary:\n")
	fmt.Printf("   - Guard Points: %d\n", len(cfg.GuardPoints))
	fmt.Printf("   - User Sets: %d\n", len(cfg.UserSets))
	fmt.Printf("   - Policies: %d\n", len(cfg.Policies))
	fmt.Printf("   - Configuration is valid for user access testing\n")
}// Enhanced logging enabled
