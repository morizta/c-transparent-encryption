package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"strconv"
	"time"

	"takakrypt/internal/config"
	"takakrypt/internal/policy"
)

func main() {
	fmt.Println("=== Takakrypt Security Rules Test ===")

	// Load test configuration
	cfg, err := config.LoadConfig("configs/security-rules-test.yaml")
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Create policy engine
	engine, err := policy.NewEngine(cfg)
	if err != nil {
		log.Fatalf("Failed to create policy engine: %v", err)
	}

	// Test scenarios
	testScenarios := []struct {
		name        string
		filePath    string
		userID      int
		processName string
		processPath string
		operation   string
		expected    string
	}{
		{
			name:        "MySQL process accessing database file",
			filePath:    "/var/lib/mysql/production/users.frm",
			userID:      116, // mysql user
			processName: "mysqld",
			processPath: "/usr/sbin/mysqld",
			operation:   "open_read",
			expected:    "PERMIT + ENCRYPT + AUDIT",
		},
		{
			name:        "DBA admin reading database file",
			filePath:    "/var/lib/mysql/production/users.frm",
			userID:      0, // root
			processName: "bash",
			processPath: "/bin/bash",
			operation:   "open_read",
			expected:    "PERMIT + AUDIT (no encryption for read)",
		},
		{
			name:        "Unauthorized user accessing database",
			filePath:    "/var/lib/mysql/production/users.frm",
			userID:      99999, // denied user
			processName: "cat",
			processPath: "/bin/cat",
			operation:   "open_read",
			expected:    "DENY + AUDIT",
		},
		{
			name:        "Document user accessing sensitive file",
			filePath:    "/home/ntoi/Documents/secret.txt",
			userID:      1000, // ntoi
			processName: "cat",
			processPath: "/bin/cat",
			operation:   "open_read",
			expected:    "PERMIT + ENCRYPT + AUDIT",
		},
		{
			name:        "Log file access (no encryption)",
			filePath:    "/home/ntoi/Documents/debug.log",
			userID:      1000,
			processName: "tail",
			processPath: "/usr/bin/tail",
			operation:   "open_read",
			expected:    "PERMIT (no encryption)",
		},
		{
			name:        "Key operation (always allowed)",
			filePath:    "/var/lib/mysql/production/keys.dat",
			userID:      1001,
			processName: "takakrypt-agent",
			processPath: "/usr/bin/takakrypt-agent",
			operation:   "key_op",
			expected:    "PERMIT + ENCRYPT",
		},
	}

	fmt.Printf("\nRunning %d test scenarios...\n\n", len(testScenarios))

	for i, scenario := range testScenarios {
		fmt.Printf("%d. %s\n", i+1, scenario.name)
		fmt.Printf("   File: %s\n", scenario.filePath)
		fmt.Printf("   User: %d, Process: %s\n", scenario.userID, scenario.processName)
		fmt.Printf("   Operation: %s\n", scenario.operation)

		// Create evaluation context
		evalCtx := &policy.EvaluationContext{
			FilePath:    scenario.filePath,
			UserID:      scenario.userID,
			ProcessID:   12345, // Dummy PID
			ProcessName: scenario.processName,
			ProcessPath: scenario.processPath,
			Operation:   scenario.operation,
			Timestamp:   time.Now(),
		}

		// Evaluate access using V2 rules (when available) or fallback to V1
		result, err := engine.EvaluateAccessV2(context.Background(), evalCtx)
		if err != nil {
			fmt.Printf("   ❌ ERROR: %v\n", err)
			continue
		}

		// Display results
		status := "DENY"
		if result.Allow {
			status = "PERMIT"
		}

		effects := []string{}
		if result.Encrypt {
			effects = append(effects, "ENCRYPT")
		}
		if result.Audit {
			effects = append(effects, "AUDIT")
		}

		if len(effects) > 0 {
			status += " + " + joinStrings(effects, " + ")
		}

		// Check if result matches expectation
		success := "✓"
		if status != scenario.expected {
			success = "❌"
		}

		fmt.Printf("   %s Result: %s\n", success, status)
		fmt.Printf("   Reason: %s\n", result.Reason)
		if result.KeyID != "" {
			fmt.Printf("   Key ID: %s\n", result.KeyID)
		}
		if result.RuleOrder > 0 {
			fmt.Printf("   Matched Rule: %d\n", result.RuleOrder)
		}
		fmt.Printf("   Expected: %s\n", scenario.expected)
		fmt.Println()
	}

	// Test rule ordering
	fmt.Println("=== Rule Ordering Test ===")
	testRuleOrdering(engine)
}

func testRuleOrdering(engine *policy.Engine) {
	// This test demonstrates that rules are evaluated in order
	// and the first match wins
	
	scenarios := []struct {
		desc     string
		userID   int
		expected int // Expected rule order
	}{
		{"Key operation (should match rule 1)", 116, 1},
		{"MySQL user with MySQL process (should match rule 2)", 116, 2},
		{"Root user with admin tool (should match rule 3)", 0, 3},
		{"Denied user (should match rule 4)", 99999, 4},
		{"Random user (should match rule 5)", 5000, 5},
	}

	for _, scenario := range scenarios {
		fmt.Printf("Testing: %s\n", scenario.desc)
		
		evalCtx := &policy.EvaluationContext{
			FilePath:    "/var/lib/mysql/production/test.frm",
			UserID:      scenario.userID,
			ProcessName: getProcessForUser(scenario.userID),
			ProcessPath: getProcessPathForUser(scenario.userID),
			Operation:   getOperationForTest(scenario.userID),
			Timestamp:   time.Now(),
		}

		result, err := engine.EvaluateAccessV2(context.Background(), evalCtx)
		if err != nil {
			fmt.Printf("  ❌ ERROR: %v\n", err)
			continue
		}

		success := "✓"
		if result.RuleOrder != scenario.expected {
			success = "❌"
		}

		fmt.Printf("  %s Matched rule %d (expected %d)\n", 
			success, result.RuleOrder, scenario.expected)
		fmt.Printf("  Reason: %s\n\n", result.Reason)
	}
}

func getProcessForUser(userID int) string {
	switch userID {
	case 116: // mysql
		return "mysqld"
	case 0: // root
		return "bash"
	default:
		return "unknown"
	}
}

func getProcessPathForUser(userID int) string {
	switch userID {
	case 116: // mysql
		return "/usr/sbin/mysqld"
	case 0: // root
		return "/bin/bash"
	default:
		return "/bin/unknown"
	}
}

func getOperationForTest(userID int) string {
	if userID == 116 {
		return "key_op" // This should match rule 1
	}
	return "open_read"
}

func joinStrings(strs []string, sep string) string {
	if len(strs) == 0 {
		return ""
	}
	if len(strs) == 1 {
		return strs[0]
	}
	
	result := strs[0]
	for i := 1; i < len(strs); i++ {
		result += sep + strs[i]
	}
	return result
}// Enhanced logging enabled
