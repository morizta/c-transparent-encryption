package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Parser handles configuration file parsing and validation
type Parser struct {
	configPath string
	config     *Config
}

// NewParser creates a new configuration parser
func NewParser(configPath string) *Parser {
	return &Parser{
		configPath: configPath,
	}
}

// Load reads and parses the configuration file
func (p *Parser) Load() (*Config, error) {
	data, err := os.ReadFile(p.configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file %s: %w", p.configPath, err)
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse YAML config: %w", err)
	}

	// Set defaults
	p.setDefaults(&config)

	// Validate configuration
	if err := p.validate(&config); err != nil {
		return nil, fmt.Errorf("configuration validation failed: %w", err)
	}

	p.config = &config
	return &config, nil
}

// setDefaults applies default values to configuration
func (p *Parser) setDefaults(config *Config) {
	// Agent defaults
	if config.Agent.SocketPath == "" {
		config.Agent.SocketPath = "/var/run/takakrypt/agent.sock"
	}
	if config.Agent.LogLevel == "" {
		config.Agent.LogLevel = "info"
	}
	if config.Agent.LogPath == "" {
		config.Agent.LogPath = "/var/log/takakrypt/agent.log"
	}
	if config.Agent.AuditLogPath == "" {
		config.Agent.AuditLogPath = "/var/log/takakrypt/audit.log"
	}
	if config.Agent.MaxCacheSize == 0 {
		config.Agent.MaxCacheSize = 1000
	}
	if config.Agent.CacheCleanupInterval == 0 {
		config.Agent.CacheCleanupInterval = 5 * time.Minute
	}
	if config.Agent.WorkerThreads == 0 {
		config.Agent.WorkerThreads = 4
	}
	if config.Agent.MaxRequestSize == 0 {
		config.Agent.MaxRequestSize = 64 * 1024 * 1024 // 64MB
	}
	if config.Agent.RequestTimeout == 0 {
		config.Agent.RequestTimeout = 30 * time.Second
	}
	if config.Agent.MetricsPort == 0 {
		config.Agent.MetricsPort = 9090
	}

	// KMS defaults
	if config.KMS.Timeout == 0 {
		config.KMS.Timeout = 10 * time.Second
	}
	if config.KMS.RetryAttempts == 0 {
		config.KMS.RetryAttempts = 3
	}
	if config.KMS.KeyCacheTTL == 0 {
		config.KMS.KeyCacheTTL = 1 * time.Hour
	}
	if config.KMS.PolicyCacheTTL == 0 {
		config.KMS.PolicyCacheTTL = 15 * time.Minute
	}

	// Policy defaults
	for name, policy := range config.Policies {
		if policy.Algorithm == "" {
			policy.Algorithm = "AES-256-GCM"
		}
		if policy.KeySize == 0 {
			policy.KeySize = 256
		}
		if policy.KeyRotationInterval == 0 {
			policy.KeyRotationInterval = 24 * time.Hour
		}
		if policy.AuditLevel == "" {
			policy.AuditLevel = "info"
		}
		if !policy.Enabled {
			policy.Enabled = true
		}
		config.Policies[name] = policy
	}

	// GuardPoint defaults
	for i := range config.GuardPoints {
		if !config.GuardPoints[i].Enabled {
			config.GuardPoints[i].Enabled = true
		}
	}
}

// validate performs comprehensive configuration validation
func (p *Parser) validate(config *Config) error {
	var errors []string

	// Validate guard points
	if len(config.GuardPoints) == 0 {
		errors = append(errors, "at least one guard point must be defined")
	}

	for i, gp := range config.GuardPoints {
		if gp.Name == "" {
			errors = append(errors, fmt.Sprintf("guard_points[%d]: name is required", i))
		}
		if gp.Path == "" {
			errors = append(errors, fmt.Sprintf("guard_points[%d]: path is required", i))
		}
		if gp.Policy == "" {
			errors = append(errors, fmt.Sprintf("guard_points[%d]: policy is required", i))
		}

		// Validate path exists or is a valid pattern
		if !strings.Contains(gp.Path, "*") {
			if _, err := os.Stat(gp.Path); os.IsNotExist(err) {
				errors = append(errors, fmt.Sprintf("guard_points[%d]: path %s does not exist", i, gp.Path))
			}
		}

		// Validate policy reference (check both v1 and v2 policies)
		policyExists := false
		if _, exists := config.Policies[gp.Policy]; exists {
			policyExists = true
		}
		// Also check v2 policies
		for _, policyV2 := range config.PoliciesV2 {
			if policyV2.Name == gp.Policy {
				policyExists = true
				break
			}
		}
		if !policyExists {
			errors = append(errors, fmt.Sprintf("guard_points[%d]: referenced policy '%s' does not exist", i, gp.Policy))
		}

		// Validate patterns
		for _, pattern := range gp.IncludePatterns {
			if _, err := filepath.Match(pattern, "test"); err != nil {
				errors = append(errors, fmt.Sprintf("guard_points[%d]: invalid include pattern '%s': %v", i, pattern, err))
			}
		}
		for _, pattern := range gp.ExcludePatterns {
			if _, err := filepath.Match(pattern, "test"); err != nil {
				errors = append(errors, fmt.Sprintf("guard_points[%d]: invalid exclude pattern '%s': %v", i, pattern, err))
			}
		}
	}

	// Validate policies (check both v1 and v2)
	if len(config.Policies) == 0 && len(config.PoliciesV2) == 0 {
		errors = append(errors, "at least one policy must be defined")
	}

	for name, policy := range config.Policies {
		if policy.Name == "" {
			policy.Name = name
		}

		// Validate algorithm
		if !isValidAlgorithm(policy.Algorithm) {
			errors = append(errors, fmt.Sprintf("policy '%s': unsupported algorithm '%s'", name, policy.Algorithm))
		}

		// Validate key size
		if !isValidKeySize(policy.Algorithm, policy.KeySize) {
			errors = append(errors, fmt.Sprintf("policy '%s': invalid key size %d for algorithm %s", name, policy.KeySize, policy.Algorithm))
		}

		// Validate audit level
		if !isValidAuditLevel(policy.AuditLevel) {
			errors = append(errors, fmt.Sprintf("policy '%s': invalid audit level '%s'", name, policy.AuditLevel))
		}

		// Validate referenced sets
		for _, userSet := range policy.UserSets {
			if _, exists := config.UserSets[userSet]; !exists {
				errors = append(errors, fmt.Sprintf("policy '%s': referenced user_set '%s' does not exist", name, userSet))
			}
		}
		for _, processSet := range policy.ProcessSets {
			if _, exists := config.ProcessSets[processSet]; !exists {
				errors = append(errors, fmt.Sprintf("policy '%s': referenced process_set '%s' does not exist", name, processSet))
			}
		}
		for _, resourceSet := range policy.ResourceSets {
			if _, exists := config.ResourceSets[resourceSet]; !exists {
				errors = append(errors, fmt.Sprintf("policy '%s': referenced resource_set '%s' does not exist", name, resourceSet))
			}
		}
	}

	// Validate KMS configuration (optional for testing)
	if config.KMS.Endpoint != "" {
		if config.KMS.AuthMethod == "" {
			errors = append(errors, "KMS auth_method is required when endpoint is specified")
		} else if !isValidAuthMethod(config.KMS.AuthMethod) {
			errors = append(errors, fmt.Sprintf("invalid KMS auth_method '%s'", config.KMS.AuthMethod))
		}
	}

	// Validate user sets
	for name, userSet := range config.UserSets {
		if len(userSet.Users) == 0 && len(userSet.Groups) == 0 && len(userSet.UIDs) == 0 {
			errors = append(errors, fmt.Sprintf("user_set '%s': must specify at least one of users, groups, or uids", name))
		}
	}

	// Validate process sets
	for name, processSet := range config.ProcessSets {
		if len(processSet.Processes) == 0 && len(processSet.ProcessPaths) == 0 && len(processSet.PIDs) == 0 {
			errors = append(errors, fmt.Sprintf("process_set '%s': must specify at least one of processes, process_paths, or pids", name))
		}
	}

	// Validate resource sets
	for name, resourceSet := range config.ResourceSets {
		if len(resourceSet.FilePatterns) == 0 && len(resourceSet.Directories) == 0 && 
		   len(resourceSet.Extensions) == 0 && len(resourceSet.MimeTypes) == 0 {
			errors = append(errors, fmt.Sprintf("resource_set '%s': must specify at least one resource criterion", name))
		}

		// Validate file patterns (use filepath.Match for glob patterns)
		for _, pattern := range resourceSet.FilePatterns {
			if _, err := filepath.Match(pattern, "test"); err != nil {
				errors = append(errors, fmt.Sprintf("resource_set '%s': invalid file pattern '%s': %v", name, pattern, err))
			}
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("validation errors:\n  - %s", strings.Join(errors, "\n  - "))
	}

	return nil
}

// Helper validation functions
func isValidAlgorithm(algorithm string) bool {
	validAlgorithms := []string{"AES-256-GCM", "AES-128-GCM", "ChaCha20-Poly1305"}
	for _, valid := range validAlgorithms {
		if algorithm == valid {
			return true
		}
	}
	return false
}

func isValidKeySize(algorithm string, keySize int) bool {
	switch algorithm {
	case "AES-256-GCM":
		return keySize == 256
	case "AES-128-GCM":
		return keySize == 128
	case "ChaCha20-Poly1305":
		return keySize == 256
	default:
		return false
	}
}

func isValidAuditLevel(level string) bool {
	validLevels := []string{"debug", "info", "warn", "error", "none", "full"}
	for _, valid := range validLevels {
		if level == valid {
			return true
		}
	}
	return false
}

func isValidAuthMethod(method string) bool {
	validMethods := []string{"certificate", "token", "username_password", "mtls"}
	for _, valid := range validMethods {
		if method == valid {
			return true
		}
	}
	return false
}

// Reload reloads the configuration from file
func (p *Parser) Reload() (*Config, error) {
	return p.Load()
}

// GetConfig returns the currently loaded configuration
func (p *Parser) GetConfig() *Config {
	return p.config
}// Enhanced logging enabled
