package main

import (
	"fmt"
	"os"

	"takakrypt/internal/config"
)

// Simulate user access testing without requiring actual user switching
func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run main.go <config-path>")
		os.Exit(1)
	}

	configPath := os.Args[1]
	
	// Load configuration
	parser := config.NewParser(configPath)
	cfg, err := parser.Load()
	if err != nil {
		fmt.Printf("❌ Failed to load config: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("🔒 Simulating User Access Control Testing\n\n")

	// Test scenarios
	testScenarios := []struct {
		username string
		uid      uint32
		filepath string
		expected string
		reason   string
	}{
		{
			username: "ntoi", 
			uid:      1000,
			filepath: "/tmp/takakrypt-user-test/admin-document.txt",
			expected: "ALLOW",
			reason:   "User in admin_users set, file matches guard point and pattern",
		},
		{
			username: "testuser1",
			uid:      1001, 
			filepath: "/tmp/takakrypt-user-test/user1-document.txt",
			expected: "ALLOW",
			reason:   "User in test_users set, file matches guard point and pattern",
		},
		{
			username: "testuser2",
			uid:      1002,
			filepath: "/tmp/takakrypt-user-test/user2-document.txt", 
			expected: "ALLOW",
			reason:   "User in test_users set, file matches guard point and pattern",
		},
		{
			username: "testuser1",
			uid:      1001,
			filepath: "/tmp/takakrypt-user-test/admin-document.txt",
			expected: "ALLOW", 
			reason:   "User in test_users set, file matches guard point (cross-user access allowed in same user set)",
		},
		{
			username: "unknown",
			uid:      9999,
			filepath: "/tmp/takakrypt-user-test/admin-document.txt",
			expected: "DENY",
			reason:   "User not in any user set",
		},
		{
			username: "ntoi",
			uid:      1000,
			filepath: "/tmp/takakrypt-user-test/test.log",
			expected: "DENY",
			reason:   "File doesn't match include patterns (*.txt, *.doc only)",
		},
		{
			username: "ntoi", 
			uid:      1000,
			filepath: "/home/ntoi/document.txt",
			expected: "DENY",
			reason:   "File outside guard point directory",
		},
	}

	successCount := 0
	totalTests := len(testScenarios)

	for i, scenario := range testScenarios {
		fmt.Printf("Test %d: %s (UID: %d) accessing %s\n", 
			i+1, scenario.username, scenario.uid, scenario.filepath)
		
		// Check user authorization
		userAuthorized := false
		userSetName := ""
		
		for setName, userSet := range cfg.UserSets {
			// Check by username
			for _, user := range userSet.Users {
				if user == scenario.username {
					userAuthorized = true
					userSetName = setName
					break
				}
			}
			// Check by UID
			for _, uid := range userSet.UIDs {
				if uint32(uid) == scenario.uid {
					userAuthorized = true
					userSetName = setName
					break
				}
			}
			if userAuthorized {
				break
			}
		}

		// Check file authorization
		fileAuthorized := false
		guardPointName := ""
		
		for gpName, guardPoint := range cfg.GuardPoints {
			gpNameStr := fmt.Sprintf("guard_point_%d", gpName)
			// Simple path matching
			if len(scenario.filepath) >= len(guardPoint.Path) && 
			   scenario.filepath[:len(guardPoint.Path)] == guardPoint.Path {
				
				// Check include patterns
				for _, pattern := range guardPoint.IncludePatterns {
					if pattern == "*.txt" && len(scenario.filepath) > 4 && 
					   scenario.filepath[len(scenario.filepath)-4:] == ".txt" {
						fileAuthorized = true
						guardPointName = gpNameStr
						break
					}
					if pattern == "*.doc" && len(scenario.filepath) > 4 && 
					   scenario.filepath[len(scenario.filepath)-4:] == ".doc" {
						fileAuthorized = true
						guardPointName = gpNameStr  
						break
					}
				}
			}
		}

		// Determine final decision
		var decision string
		if userAuthorized && fileAuthorized {
			decision = "ALLOW"
		} else {
			decision = "DENY"
		}

		// Print result
		fmt.Printf("  User Authorization: ")
		if userAuthorized {
			fmt.Printf("✅ ALLOWED (found in user set: %s)\n", userSetName)
		} else {
			fmt.Printf("❌ DENIED (not found in any user set)\n")
		}

		fmt.Printf("  File Authorization: ")
		if fileAuthorized {
			fmt.Printf("✅ ALLOWED (matches guard point: %s)\n", guardPointName)
		} else {
			fmt.Printf("❌ DENIED (no matching guard point or pattern)\n")
		}

		fmt.Printf("  Final Decision: %s\n", decision)
		fmt.Printf("  Expected: %s\n", scenario.expected)
		fmt.Printf("  Reason: %s\n", scenario.reason)

		if decision == scenario.expected {
			fmt.Printf("  ✅ PASS\n")
			successCount++
		} else {
			fmt.Printf("  ❌ FAIL (Expected %s, got %s)\n", scenario.expected, decision)
		}
		fmt.Printf("\n")
	}

	fmt.Printf("=== Test Results Summary ===\n")
	fmt.Printf("Passed: %d/%d tests\n", successCount, totalTests)
	fmt.Printf("Success Rate: %.1f%%\n", float64(successCount)*100.0/float64(totalTests))

	if successCount == totalTests {
		fmt.Printf("🎉 All user access control tests passed!\n")
		fmt.Printf("✅ The policy configuration correctly handles:\n")
		fmt.Printf("   - User-based access control (admin_users, test_users)\n")
		fmt.Printf("   - File pattern matching (*.txt, *.doc)\n")
		fmt.Printf("   - Guard point enforcement (/tmp/takakrypt-user-test)\n")
		fmt.Printf("   - Access denial for unauthorized users and files\n")
	} else {
		fmt.Printf("⚠️  Some tests failed. Review policy configuration.\n")
		os.Exit(1)
	}
}// Enhanced logging enabled
