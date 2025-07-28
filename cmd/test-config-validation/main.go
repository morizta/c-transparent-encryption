package main

import (
	"flag"
	"fmt"
	"os"

	"takakrypt/internal/config"
)

func main() {
	configPath := flag.String("config", "configs/test-config.yaml", "Path to configuration file")
	flag.Parse()

	// Parse configuration
	parser := config.NewParser(*configPath)
	cfg, err := parser.Load()
	if err != nil {
		fmt.Printf("Configuration validation failed: %v\n", err)
		os.Exit(1)
	}

	// Basic validation
	if len(cfg.GuardPoints) == 0 {
		fmt.Println("Configuration validation failed: No guard points defined")
		os.Exit(1)
	}

	if len(cfg.Policies) == 0 && len(cfg.PoliciesV2) == 0 {
		fmt.Println("Configuration validation failed: No policies defined")
		os.Exit(1)
	}

	fmt.Printf("Configuration validation successful:\n")
	fmt.Printf("  Guard points: %d\n", len(cfg.GuardPoints))
	fmt.Printf("  Policies V1: %d\n", len(cfg.Policies))
	fmt.Printf("  Policies V2: %d\n", len(cfg.PoliciesV2))
	fmt.Printf("  User sets: %d\n", len(cfg.UserSets))
	fmt.Printf("  Process sets: %d\n", len(cfg.ProcessSets))
	fmt.Printf("  Resource sets: %d\n", len(cfg.ResourceSets))
}