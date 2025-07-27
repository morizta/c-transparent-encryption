package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/user"
	"strconv"
	"strings"
	"time"

	"takakrypt/internal/config"
	"takakrypt/internal/policy"
	"takakrypt/internal/process"
)

func main() {
	if len(os.Args) < 2 {
		showUsage()
		return
	}

	command := os.Args[1]

	switch command {
	case "test-secure-data":
		testSecureDataAccess()
	case "test-database-access":
		testDatabaseAccess()
	case "test-cross-user-access":
		testCrossUserAccess()
	case "test-all":
		testAll()
	case "validate-config":
		validateConfiguration()
	default:
		showUsage()
	}
}

func showUsage() {
	fmt.Println("Multi-Guard Point Access Control Test")
	fmt.Println("")
	fmt.Println("Usage:")
	fmt.Println("  test-multi-guardpoint test-secure-data     - Test secure data access rules")
	fmt.Println("  test-multi-guardpoint test-database-access - Test database access rules")
	fmt.Println("  test-multi-guardpoint test-cross-user-access - Test cross-user access denial")
	fmt.Println("  test-multi-guardpoint test-all             - Run all tests")
	fmt.Println("  test-multi-guardpoint validate-config      - Validate configuration")
}

func testAll() {
	fmt.Println("🧪 Running All Multi-Guard Point Tests")
	fmt.Println(strings.Repeat("=", 80))

	fmt.Println("\n1. Validating Configuration...")
	validateConfiguration()

	fmt.Println("\n2. Testing Secure Data Access...")
	testSecureDataAccess()

	fmt.Println("\n3. Testing Database Access...")
	testDatabaseAccess()

	fmt.Println("\n4. Testing Cross-User Access...")
	testCrossUserAccess()

	fmt.Println("\n✅ All tests completed!")
}

func validateConfiguration() {
	fmt.Println("📋 Validating Multi-Guard Point Configuration...")
	fmt.Println(strings.Repeat("-", 60))

	configPath := "/tmp/multi-guardpoint-test-config.yaml"
	cfg, err := config.NewParser(configPath).Load()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	fmt.Printf("✅ Configuration loaded successfully\n")
	fmt.Printf("   Policy name: %s\n", cfg.Name)
	fmt.Printf("   Version: %d\n", cfg.Version)
	fmt.Printf("   User sets: %d\n", len(cfg.UserSets))
	fmt.Printf("   Process sets: %d\n", len(cfg.ProcessSets))
	fmt.Printf("   Resource sets: %d\n", len(cfg.ResourceSets))
	fmt.Printf("   Guard points: %d\n", len(cfg.GuardPoints))
	fmt.Printf("   Security rules: %d\n", len(cfg.SecurityRules))

	// Validate user sets
	fmt.Println("\n👥 User Sets:")
	for name, userSet := range cfg.UserSets {
		fmt.Printf("   • %s: users=%v, UIDs=%v\n", name, userSet.Users, userSet.UIDs)
	}

	// Validate process sets
	fmt.Println("\n⚙️  Process Sets:")
	for name, processSet := range cfg.ProcessSets {
		fmt.Printf("   • %s: processes=%v\n", name, processSet.Processes)
	}

	// Validate resource sets
	fmt.Println("\n📁 Resource Sets:")
	for name, resourceSet := range cfg.ResourceSets {
		fmt.Printf("   • %s: directories=%v\n", name, resourceSet.Directories)
	}

	// Validate guard points
	fmt.Println("\n🛡️  Guard Points:")
	for _, gp := range cfg.GuardPoints {
		fmt.Printf("   • %s: path=%s, policy=%s, enabled=%t\n", 
			gp.Name, gp.Path, gp.Policy, gp.Enabled)
	}

	// Show security rules summary
	fmt.Println("\n🔒 Security Rules Summary:")
	for _, rule := range cfg.SecurityRules {
		effect := "UNKNOWN"
		if len(rule.Effects) > 0 {
			effect = strings.ToUpper(rule.Effects[0])
		}
		fmt.Printf("   • Rule %d: %s -> %s (%s)\n", 
			rule.Order, rule.ResourceSet, effect, rule.Description)
	}
}

func testSecureDataAccess() {
	fmt.Println("🔐 Testing Secure Data Access Rules...")
	fmt.Println(strings.Repeat("-", 60))

	// Load configuration
	cfg, err := config.NewParser("/tmp/multi-guardpoint-test-config.yaml").Load()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Create policy engine
	engine, err := policy.NewEngine(cfg)
	if err != nil {
		log.Fatalf("Failed to create policy engine: %v", err)
	}

	// Create process detector
	detector := process.NewProcessDetector()

	// Test scenarios
	testScenarios := []struct {
		description string
		filePath    string
		userID      int
		username    string
		processName string
		operation   string
		expected    bool
	}{
		{
			description: "ntoi accessing own secure data",
			filePath:    "/tmp/secure-data/ntoi/ntoi-confidential.txt",
			userID:      1000,
			username:    "ntoi",
			processName: "bash",
			operation:   "read",
			expected:    true,
		},
		{
			description: "ntoi accessing testuser1 secure data (admin access)",
			filePath:    "/tmp/secure-data/testuser1/testuser1-personal.txt",
			userID:      1000,
			username:    "ntoi",
			processName: "cat",
			operation:   "read",
			expected:    true,
		},
		{
			description: "ntoi accessing testuser2 secure data (admin access)",
			filePath:    "/tmp/secure-data/testuser2/testuser2-personal.txt",
			userID:      1000,
			username:    "ntoi",
			processName: "vim",
			operation:   "write",
			expected:    true,
		},
		{
			description: "testuser1 accessing own secure data",
			filePath:    "/tmp/secure-data/testuser1/user1-project.doc",
			userID:      1001,
			username:    "testuser1",
			processName: "cat",
			operation:   "read",
			expected:    true,
		},
		{
			description: "testuser2 accessing own secure data",
			filePath:    "/tmp/secure-data/testuser2/user2-notes.doc",
			userID:      1002,
			username:    "testuser2",
			processName: "nano",
			operation:   "write",
			expected:    true,
		},
		{
			description: "testuser1 accessing shared data (read only)",
			filePath:    "/tmp/secure-data/shared/shared-document.txt",
			userID:      1001,
			username:    "testuser1",
			processName: "cat",
			operation:   "read",
			expected:    true,
		},
		{
			description: "testuser2 accessing shared data (read only)",
			filePath:    "/tmp/secure-data/shared/common-policy.doc",
			userID:      1002,
			username:    "testuser2",
			processName: "less",
			operation:   "read",
			expected:    true,
		},
	}

	// Run test scenarios
	for i, scenario := range testScenarios {
		fmt.Printf("\n📝 Test %d: %s\n", i+1, scenario.description)
		
		// Get process info
		processInfo, err := detector.GetProcessInfo(os.Getpid())
		if err != nil {
			fmt.Printf("   ⚠️  Warning: Could not get process info: %v\n", err)
			processInfo = &process.ProcessInfo{
				PID:  os.Getpid(),
				Name: scenario.processName,
				Type: process.ProcessTypeShell,
			}
		}

		// Create evaluation context
		evalCtx := &policy.EvaluationContext{
			FilePath:    scenario.filePath,
			UserID:      scenario.userID,
			GroupIDs:    []int{scenario.userID}, // Simplified: use UID as GID
			ProcessID:   processInfo.PID,
			ProcessName: scenario.processName, // Use scenario process name for testing
			ProcessPath: processInfo.Path,
			Operation:   scenario.operation,
			Timestamp:   time.Now(),
		}

		// Evaluate access
		result, err := engine.EvaluateAccessV2(context.Background(), evalCtx)
		if err != nil {
			fmt.Printf("   ❌ Error: %v\n", err)
			continue
		}

		// Check result
		success := result.Allow == scenario.expected
		statusIcon := "✅"
		if !success {
			statusIcon = "❌"
		}

		fmt.Printf("   %s Result: %s (expected: %s)\n", 
			statusIcon, 
			formatBool(result.Allow), 
			formatBool(scenario.expected))
		fmt.Printf("      Reason: %s\n", result.Reason)
		fmt.Printf("      Encrypt: %t\n", result.Encrypt)
		if result.KeyID != "" {
			fmt.Printf("      Key ID: %s\n", result.KeyID)
		}
	}
}

func testDatabaseAccess() {
	fmt.Println("🗄️ Testing Database Access Rules...")
	fmt.Println(strings.Repeat("-", 60))

	// Load configuration
	cfg, err := config.NewParser("/tmp/multi-guardpoint-test-config.yaml").Load()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Create policy engine
	engine, err := policy.NewEngine(cfg)
	if err != nil {
		log.Fatalf("Failed to create policy engine: %v", err)
	}

	// Test scenarios for database access
	testScenarios := []struct {
		description string
		filePath    string
		userID      int
		username    string
		processName string
		operation   string
		expected    bool
	}{
		{
			description: "MariaDB process accessing database data",
			filePath:    "/tmp/database-data/data/users.frm",
			userID:      114, // MySQL user UID
			username:    "mysql",
			processName: "mariadbd",
			operation:   "read",
			expected:    true,
		},
		{
			description: "MariaDB process writing database data",
			filePath:    "/tmp/database-data/data/orders.ibd",
			userID:      114,
			username:    "mysql",
			processName: "mysqld",
			operation:   "write",
			expected:    true,
		},
		{
			description: "Custom Python app accessing database",
			filePath:    "/tmp/database-data/data/customers.MYD",
			userID:      1000,
			username:    "ntoi",
			processName: "python3",
			operation:   "read",
			expected:    true,
		},
		{
			description: "Custom Java app accessing database",
			filePath:    "/tmp/database-data/data/users.frm",
			userID:      1001,
			username:    "testuser1",
			processName: "java",
			operation:   "write",
			expected:    true,
		},
		{
			description: "Admin managing database config",
			filePath:    "/tmp/database-data/config/my.cnf",
			userID:      1000,
			username:    "ntoi",
			processName: "vim",
			operation:   "write",
			expected:    true,
		},
		{
			description: "Unauthorized shell access to database data",
			filePath:    "/tmp/database-data/data/customers.MYD",
			userID:      1001,
			username:    "testuser1",
			processName: "cat",
			operation:   "read",
			expected:    false, // Should be denied
		},
	}

	// Run database test scenarios
	for i, scenario := range testScenarios {
		fmt.Printf("\n📝 Database Test %d: %s\n", i+1, scenario.description)
		
		// Create evaluation context with simulated process info
		evalCtx := &policy.EvaluationContext{
			FilePath:    scenario.filePath,
			UserID:      scenario.userID,
			GroupIDs:    []int{scenario.userID},
			ProcessID:   12345 + i, // Simulated PID
			ProcessName: scenario.processName,
			ProcessPath: fmt.Sprintf("/usr/bin/%s", scenario.processName),
			Operation:   scenario.operation,
			Timestamp:   time.Now(),
		}

		// Evaluate access
		result, err := engine.EvaluateAccessV2(context.Background(), evalCtx)
		if err != nil {
			fmt.Printf("   ❌ Error: %v\n", err)
			continue
		}

		// Check result
		success := result.Allow == scenario.expected
		statusIcon := "✅"
		if !success {
			statusIcon = "❌"
		}

		fmt.Printf("   %s Result: %s (expected: %s)\n", 
			statusIcon, 
			formatBool(result.Allow), 
			formatBool(scenario.expected))
		fmt.Printf("      Reason: %s\n", result.Reason)
		fmt.Printf("      Encrypt: %t\n", result.Encrypt)
		if result.KeyID != "" {
			fmt.Printf("      Key ID: %s\n", result.KeyID)
		}
	}
}

func testCrossUserAccess() {
	fmt.Println("🚫 Testing Cross-User Access Denial...")
	fmt.Println(strings.Repeat("-", 60))

	// Load configuration
	cfg, err := config.NewParser("/tmp/multi-guardpoint-test-config.yaml").Load()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Create policy engine
	engine, err := policy.NewEngine(cfg)
	if err != nil {
		log.Fatalf("Failed to create policy engine: %v", err)
	}

	// Test cross-user access scenarios (should all be DENIED)
	crossUserScenarios := []struct {
		description string
		filePath    string
		userID      int
		username    string
		processName string
		operation   string
		expected    bool // Should be false (denied)
	}{
		{
			description: "testuser1 trying to access testuser2's data (should be DENIED)",
			filePath:    "/tmp/secure-data/testuser2/testuser2-personal.txt",
			userID:      1001,
			username:    "testuser1",
			processName: "cat",
			operation:   "read",
			expected:    false,
		},
		{
			description: "testuser1 trying to write testuser2's data (should be DENIED)",
			filePath:    "/tmp/secure-data/testuser2/user2-notes.doc",
			userID:      1001,
			username:    "testuser1",
			processName: "vim",
			operation:   "write",
			expected:    false,
		},
		{
			description: "testuser2 trying to access testuser1's data (should be DENIED)",
			filePath:    "/tmp/secure-data/testuser1/testuser1-personal.txt",
			userID:      1002,
			username:    "testuser2",
			processName: "less",
			operation:   "read",
			expected:    false,
		},
		{
			description: "testuser2 trying to write testuser1's data (should be DENIED)",
			filePath:    "/tmp/secure-data/testuser1/user1-project.doc",
			userID:      1002,
			username:    "testuser2",
			processName: "nano",
			operation:   "write",
			expected:    false,
		},
		{
			description: "Random user trying to access ntoi's data (should be DENIED)",
			filePath:    "/tmp/secure-data/ntoi/admin-policy.doc",
			userID:      9999,
			username:    "hacker",
			processName: "cat",
			operation:   "read",
			expected:    false,
		},
	}

	// Run cross-user access tests
	for i, scenario := range crossUserScenarios {
		fmt.Printf("\n🚨 Cross-User Test %d: %s\n", i+1, scenario.description)
		
		// Create evaluation context
		evalCtx := &policy.EvaluationContext{
			FilePath:    scenario.filePath,
			UserID:      scenario.userID,
			GroupIDs:    []int{scenario.userID},
			ProcessID:   99000 + i, // Simulated PID
			ProcessName: scenario.processName,
			ProcessPath: fmt.Sprintf("/usr/bin/%s", scenario.processName),
			Operation:   scenario.operation,
			Timestamp:   time.Now(),
		}

		// Evaluate access
		result, err := engine.EvaluateAccessV2(context.Background(), evalCtx)
		if err != nil {
			fmt.Printf("   ❌ Error: %v\n", err)
			continue
		}

		// Check result (should be denied)
		success := result.Allow == scenario.expected
		statusIcon := "✅"
		if !success {
			statusIcon = "❌ SECURITY VIOLATION"
		}

		fmt.Printf("   %s Result: %s (expected: %s)\n", 
			statusIcon, 
			formatBool(result.Allow), 
			formatBool(scenario.expected))
		fmt.Printf("      Reason: %s\n", result.Reason)
		
		if result.Allow && !scenario.expected {
			fmt.Printf("      🚨 CRITICAL: Unauthorized access was allowed!\n")
		}
	}
}

func formatBool(b bool) string {
	if b {
		return "ALLOW"
	}
	return "DENY"
}

func getUserByID(uid int) (string, error) {
	u, err := user.LookupId(strconv.Itoa(uid))
	if err != nil {
		return fmt.Sprintf("uid:%d", uid), err
	}
	return u.Username, nil
}

func checkFileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}