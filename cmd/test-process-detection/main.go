package main

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"takakrypt/internal/process"
)

func main() {
	if len(os.Args) < 2 {
		showUsage()
		return
	}

	detector := process.NewProcessDetector()
	evaluator := process.NewProcessSetEvaluator(detector)

	command := os.Args[1]

	switch command {
	case "scan-databases":
		scanDatabaseProcesses(detector)
	case "analyze-pid":
		if len(os.Args) < 3 {
			fmt.Println("Usage: test-process-detection analyze-pid <PID>")
			return
		}
		pid, err := strconv.Atoi(os.Args[2])
		if err != nil {
			fmt.Printf("Invalid PID: %v\n", err)
			return
		}
		analyzePID(detector, pid)
	case "test-process-sets":
		testProcessSets(evaluator)
	case "scan-all-types":
		scanAllProcessTypes(detector)
	case "benchmark":
		benchmarkDetection(detector)
	default:
		showUsage()
	}
}

func showUsage() {
	fmt.Println("Takakrypt Process Detection Test Tool")
	fmt.Println("")
	fmt.Println("Usage:")
	fmt.Println("  test-process-detection scan-databases       - Scan for all database processes")
	fmt.Println("  test-process-detection analyze-pid <PID>    - Analyze specific process")
	fmt.Println("  test-process-detection test-process-sets    - Test process set matching")
	fmt.Println("  test-process-detection scan-all-types      - Scan for all process types")
	fmt.Println("  test-process-detection benchmark           - Benchmark detection performance")
}

func scanDatabaseProcesses(detector *process.ProcessDetector) {
	fmt.Println("🔍 Scanning for database processes...")
	fmt.Println(strings.Repeat("=", 80))

	start := time.Now()
	databaseProcesses, err := detector.GetDatabaseProcesses()
	duration := time.Since(start)

	if err != nil {
		log.Fatalf("Failed to scan database processes: %v", err)
	}

	fmt.Printf("Found %d database processes (scan took %v)\n\n", len(databaseProcesses), duration)

	for i, processInfo := range databaseProcesses {
		fmt.Printf("🗄️  Database Process #%d\n", i+1)
		fmt.Printf("   PID: %d (PPID: %d)\n", processInfo.PID, processInfo.PPID)
		fmt.Printf("   Name: %s\n", processInfo.Name)
		fmt.Printf("   Path: %s\n", processInfo.Path)
		fmt.Printf("   Type: %s\n", processInfo.Type)
		
		if processInfo.DatabaseType != "" {
			fmt.Printf("   Database Type: %s\n", processInfo.DatabaseType)
		}
		if processInfo.DatabaseVersion != "" {
			fmt.Printf("   Version: %s\n", processInfo.DatabaseVersion)
		}
		
		fmt.Printf("   UID: %d, GID: %d\n", processInfo.UID, processInfo.GID)
		
		if len(processInfo.CommandLine) > 0 {
			fmt.Printf("   Command: %s\n", strings.Join(processInfo.CommandLine, " "))
		}
		
		if len(processInfo.DataPaths) > 0 {
			fmt.Printf("   Data Paths: %v\n", processInfo.DataPaths)
		}
		
		if len(processInfo.ConfigPaths) > 0 {
			fmt.Printf("   Config Paths: %v\n", processInfo.ConfigPaths)
		}
		
		if len(processInfo.ListenPorts) > 0 {
			fmt.Printf("   Listen Ports: %v\n", processInfo.ListenPorts)
		}

		// Show relevant environment variables
		dbEnvVars := []string{}
		for key, value := range processInfo.Environment {
			if isRelevantEnvVar(key) {
				dbEnvVars = append(dbEnvVars, fmt.Sprintf("%s=%s", key, value))
			}
		}
		if len(dbEnvVars) > 0 {
			fmt.Printf("   DB Environment: %v\n", dbEnvVars)
		}

		fmt.Println()
	}

	// Show cache statistics
	cacheStats := detector.GetCacheStats()
	fmt.Printf("Cache Stats: %+v\n", cacheStats)
}

func analyzePID(detector *process.ProcessDetector, pid int) {
	fmt.Printf("🔍 Analyzing process PID %d...\n", pid)
	fmt.Println(strings.Repeat("=", 50))

	start := time.Now()
	processInfo, err := detector.GetProcessInfo(pid)
	duration := time.Since(start)

	if err != nil {
		log.Fatalf("Failed to get process info: %v", err)
	}

	fmt.Printf("Analysis completed in %v\n\n", duration)

	// Basic Information
	fmt.Println("📋 Basic Information:")
	fmt.Printf("   PID: %d\n", processInfo.PID)
	fmt.Printf("   PPID: %d\n", processInfo.PPID)
	fmt.Printf("   Name: %s\n", processInfo.Name)
	fmt.Printf("   Path: %s\n", processInfo.Path)
	fmt.Printf("   Type: %s\n", processInfo.Type)
	fmt.Printf("   UID: %d, GID: %d\n", processInfo.UID, processInfo.GID)
	fmt.Println()

	// Command Line
	if len(processInfo.CommandLine) > 0 {
		fmt.Println("💻 Command Line:")
		for i, arg := range processInfo.CommandLine {
			fmt.Printf("   [%d] %s\n", i, arg)
		}
		fmt.Println()
	}

	// Database Information
	if processInfo.Type != process.ProcessTypeUnknown {
		fmt.Println("🗄️  Database Information:")
		fmt.Printf("   Database Type: %s\n", processInfo.DatabaseType)
		if processInfo.DatabaseVersion != "" {
			fmt.Printf("   Version: %s\n", processInfo.DatabaseVersion)
		}
		
		if len(processInfo.DataPaths) > 0 {
			fmt.Printf("   Data Paths:\n")
			for _, path := range processInfo.DataPaths {
				fmt.Printf("     - %s\n", path)
			}
		}
		
		if len(processInfo.ConfigPaths) > 0 {
			fmt.Printf("   Config Paths:\n")
			for _, path := range processInfo.ConfigPaths {
				fmt.Printf("     - %s\n", path)
			}
		}
		
		if len(processInfo.ListenPorts) > 0 {
			fmt.Printf("   Listen Ports: %v\n", processInfo.ListenPorts)
		}
		fmt.Println()
	}

	// Environment Variables
	if len(processInfo.Environment) > 0 {
		fmt.Println("🌐 Environment Variables:")
		relevantCount := 0
		for key, value := range processInfo.Environment {
			if isRelevantEnvVar(key) {
				fmt.Printf("   %s=%s\n", key, value)
				relevantCount++
			}
		}
		if relevantCount == 0 {
			fmt.Printf("   (No database-relevant environment variables found)\n")
		}
		fmt.Printf("   Total environment variables: %d\n", len(processInfo.Environment))
		fmt.Println()
	}

	// Database Detection Test
	fmt.Println("🔬 Database Detection Test:")
	isDB, dbType, err := detector.IsDatabaseProcess(pid)
	if err != nil {
		fmt.Printf("   Error: %v\n", err)
	} else {
		fmt.Printf("   Is Database Process: %t\n", isDB)
		if isDB {
			fmt.Printf("   Detected Type: %s\n", dbType)
		}
	}
}

func testProcessSets(evaluator *process.ProcessSetEvaluator) {
	fmt.Println("🧪 Testing Process Set Matching...")
	fmt.Println(strings.Repeat("=", 60))

	// Get predefined database process sets
	dbProcessSets := evaluator.GetDatabaseProcessSets()

	// Get all database processes to test against
	detector := process.NewProcessDetector()
	databaseProcesses, err := detector.GetDatabaseProcesses()
	if err != nil {
		log.Fatalf("Failed to get database processes: %v", err)
	}

	if len(databaseProcesses) == 0 {
		fmt.Println("❌ No database processes found to test against")
		return
	}

	fmt.Printf("Testing %d process sets against %d database processes\n\n", 
		len(dbProcessSets), len(databaseProcesses))

	for setName, processSet := range dbProcessSets {
		fmt.Printf("📋 Testing Process Set: %s\n", setName)
		
		matchCount := 0
		for _, dbProcess := range databaseProcesses {
			match, err := evaluator.EvaluateEnhancedProcessSet(dbProcess.PID, processSet)
			if err != nil {
				fmt.Printf("   ❌ Error evaluating PID %d: %v\n", dbProcess.PID, err)
				continue
			}

			if match.Matched {
				matchCount++
				fmt.Printf("   ✅ PID %d (%s, %s) - %s\n", 
					dbProcess.PID, dbProcess.Name, dbProcess.Type, match.MatchReason)
			}
		}
		
		fmt.Printf("   Total matches: %d/%d\n\n", matchCount, len(databaseProcesses))
	}

	// Show cache statistics
	cacheStats := evaluator.GetCacheStats()
	fmt.Printf("Process Set Cache Stats: %+v\n", cacheStats)
}

func benchmarkDetection(detector *process.ProcessDetector) {
	fmt.Println("⚡ Benchmarking Process Detection...")
	fmt.Println(strings.Repeat("=", 50))

	// Get list of PIDs to test with
	testPIDs := []int{1, os.Getpid()} // Always test init and ourselves

	// Add some database processes if available
	if dbProcesses, err := detector.GetDatabaseProcesses(); err == nil {
		for i, dbProcess := range dbProcesses {
			if i >= 3 { // Limit to 3 additional processes
				break
			}
			testPIDs = append(testPIDs, dbProcess.PID)
		}
	}

	fmt.Printf("Testing with %d processes\n\n", len(testPIDs))

	// Benchmark cold cache
	fmt.Println("🧊 Cold Cache Performance:")
	detector.ClearCache()
	start := time.Now()
	for _, pid := range testPIDs {
		_, err := detector.GetProcessInfo(pid)
		if err != nil {
			fmt.Printf("   Warning: Failed to get info for PID %d: %v\n", pid, err)
		}
	}
	coldDuration := time.Since(start)
	fmt.Printf("   Total time: %v\n", coldDuration)
	fmt.Printf("   Average per process: %v\n", coldDuration/time.Duration(len(testPIDs)))

	// Benchmark warm cache
	fmt.Println("\n🔥 Warm Cache Performance:")
	start = time.Now()
	for _, pid := range testPIDs {
		_, err := detector.GetProcessInfo(pid)
		if err != nil {
			fmt.Printf("   Warning: Failed to get info for PID %d: %v\n", pid, err)
		}
	}
	warmDuration := time.Since(start)
	fmt.Printf("   Total time: %v\n", warmDuration)
	fmt.Printf("   Average per process: %v\n", warmDuration/time.Duration(len(testPIDs)))

	// Show speedup
	if warmDuration > 0 {
		speedup := float64(coldDuration) / float64(warmDuration)
		fmt.Printf("   Cache speedup: %.2fx\n", speedup)
	}

	// Show cache statistics
	cacheStats := detector.GetCacheStats()
	fmt.Printf("\nCache Stats: %+v\n", cacheStats)
}

func scanAllProcessTypes(detector *process.ProcessDetector) {
	fmt.Println("🔍 Scanning for all process types...")
	fmt.Println(strings.Repeat("=", 80))

	// Get a sample of processes to classify
	procDir, err := os.Open("/proc")
	if err != nil {
		log.Fatalf("Failed to open /proc: %v", err)
	}
	defer procDir.Close()

	entries, err := procDir.Readdir(100) // Limit to first 100 for demo
	if err != nil {
		log.Fatalf("Failed to read /proc: %v", err)
	}

	processTypeStats := make(map[process.ProcessType]int)
	processExamples := make(map[process.ProcessType][]string)
	totalProcessed := 0

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		// Check if directory name is a PID
		if pid, err := strconv.Atoi(entry.Name()); err == nil {
			processInfo, err := detector.GetProcessInfo(pid)
			if err != nil {
				continue // Skip processes we can't read
			}

			totalProcessed++
			processTypeStats[processInfo.Type]++
			
			// Store examples (max 3 per type)
			if len(processExamples[processInfo.Type]) < 3 {
				example := fmt.Sprintf("PID %d: %s", pid, processInfo.Name)
				if processInfo.Path != "" {
					example += fmt.Sprintf(" (%s)", processInfo.Path)
				}
				processExamples[processInfo.Type] = append(processExamples[processInfo.Type], example)
			}
		}
	}

	fmt.Printf("Processed %d processes\n\n", totalProcessed)

	// Display results by process type
	fmt.Println("📊 Process Type Distribution:")
	fmt.Println(strings.Repeat("-", 60))

	// Sort process types for consistent output
	var sortedTypes []process.ProcessType
	for processType := range processTypeStats {
		sortedTypes = append(sortedTypes, processType)
	}

	// Simple sort by string representation
	for i := 0; i < len(sortedTypes)-1; i++ {
		for j := i + 1; j < len(sortedTypes); j++ {
			if string(sortedTypes[i]) > string(sortedTypes[j]) {
				sortedTypes[i], sortedTypes[j] = sortedTypes[j], sortedTypes[i]
			}
		}
	}

	for _, processType := range sortedTypes {
		count := processTypeStats[processType]
		percentage := float64(count) / float64(totalProcessed) * 100
		
		// Choose emoji based on process type
		var emoji string
		switch processType {
		case process.ProcessTypeMySQL, process.ProcessTypePostgreSQL, process.ProcessTypeMariaDB, process.ProcessTypeMongoDB, process.ProcessTypeRedis:
			emoji = "🗄️"
		case process.ProcessTypeWebServer:
			emoji = "🌐"
		case process.ProcessTypeSystem:
			emoji = "⚙️"
		case process.ProcessTypeShell:
			emoji = "🐚"
		case process.ProcessTypeJava:
			emoji = "☕"
		case process.ProcessTypeNodeJS:
			emoji = "🟢"
		case process.ProcessTypePython:
			emoji = "🐍"
		case process.ProcessTypeDocker:
			emoji = "🐳"
		case process.ProcessTypeKubernetes:
			emoji = "☸️"
		case process.ProcessTypeSecurity:
			emoji = "🔒"
		case process.ProcessTypeDevelopment:
			emoji = "👨‍💻"
		default:
			emoji = "📦"
		}

		fmt.Printf("%s %-20s: %3d processes (%.1f%%)\n", emoji, processType, count, percentage)
		
		// Show examples
		for _, example := range processExamples[processType] {
			fmt.Printf("    • %s\n", example)
		}
		fmt.Println()
	}

	// Show cache statistics
	cacheStats := detector.GetCacheStats()
	fmt.Printf("Cache Stats: %+v\n", cacheStats)
}

func isRelevantEnvVar(key string) bool {
	relevantPrefixes := []string{
		"MYSQL", "POSTGRES", "MARIADB", "MONGO", "REDIS",
		"DB_", "DATABASE_", "SQL_", "PGDATA", "ORACLE",
	}

	upperKey := strings.ToUpper(key)
	for _, prefix := range relevantPrefixes {
		if strings.HasPrefix(upperKey, prefix) {
			return true
		}
	}

	return false
}// Enhanced logging enabled
