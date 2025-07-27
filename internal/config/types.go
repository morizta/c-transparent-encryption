package config

import "time"

// Config represents the main configuration structure
type Config struct {
	Name           string                `yaml:"name,omitempty"`           // Policy configuration name
	Version        int                   `yaml:"version,omitempty"`        // Configuration version
	GuardPoints    []GuardPoint          `yaml:"guard_points"`
	Policies       map[string]Policy     `yaml:"policies"`
	PoliciesV2     []PolicyV2            `yaml:"policies_v2,omitempty"`    // New v2 policies with security rules
	SecurityRules  []SecurityRule        `yaml:"security_rules,omitempty"` // Global security rules
	UserSets       map[string]UserSet    `yaml:"user_sets"`
	ProcessSets    map[string]ProcessSet `yaml:"process_sets"`
	ResourceSets   map[string]ResourceSet `yaml:"resource_sets"`
	KMS            KMSConfig             `yaml:"kms"`
	Agent          AgentConfig           `yaml:"agent"`
}

// GuardPoint defines a protected directory or file pattern
type GuardPoint struct {
	Name             string   `yaml:"name"`
	Path             string   `yaml:"path"`
	Recursive        bool     `yaml:"recursive"`
	Policy           string   `yaml:"policy"`
	IncludePatterns  []string `yaml:"include_patterns,omitempty"`
	ExcludePatterns  []string `yaml:"exclude_patterns,omitempty"`
	ProcessWhitelist []string `yaml:"process_whitelist,omitempty"`
	Enabled          bool     `yaml:"enabled"`
}

// Policy defines encryption policies and access rules
type Policy struct {
	Name                string        `yaml:"name"`
	Algorithm           string        `yaml:"algorithm"`
	KeySize             int           `yaml:"key_size"`
	UserSets            []string      `yaml:"user_sets,omitempty"`
	ProcessSets         []string      `yaml:"process_sets,omitempty"`
	ResourceSets        []string      `yaml:"resource_sets,omitempty"`
	RequireAllSets      bool          `yaml:"require_all_sets"`
	KeyRotationInterval time.Duration `yaml:"key_rotation_interval"`
	AuditLevel          string        `yaml:"audit_level"`
	Enabled             bool          `yaml:"enabled"`
}

// UserSet defines groups of users for policy application
type UserSet struct {
	Name        string   `yaml:"name"`
	Users       []string `yaml:"users,omitempty"`
	Groups      []string `yaml:"groups,omitempty"`
	UIDs        []int    `yaml:"uids,omitempty"`
	Description string   `yaml:"description,omitempty"`
}

// ProcessSet defines groups of processes for policy application
type ProcessSet struct {
	Name         string   `yaml:"name"`
	Processes    []string `yaml:"processes,omitempty"`
	ProcessPaths []string `yaml:"process_paths,omitempty"`
	PIDs         []int    `yaml:"pids,omitempty"`
	Description  string   `yaml:"description,omitempty"`
}

// ResourceSet defines groups of resources (files/directories) for policy application
type ResourceSet struct {
	Name         string   `yaml:"name"`
	FilePatterns []string `yaml:"file_patterns,omitempty"`
	Directories  []string `yaml:"directories,omitempty"`
	Extensions   []string `yaml:"extensions,omitempty"`
	MimeTypes    []string `yaml:"mime_types,omitempty"`
	Description  string   `yaml:"description,omitempty"`
}

// KMSConfig defines configuration for Key Management System integration
type KMSConfig struct {
	Endpoint       string            `yaml:"endpoint"`
	AuthMethod     string            `yaml:"auth_method"`
	CertificatePath string           `yaml:"certificate_path,omitempty"`
	KeyPath        string            `yaml:"key_path,omitempty"`
	Username       string            `yaml:"username,omitempty"`
	TokenPath      string            `yaml:"token_path,omitempty"`
	Timeout        time.Duration     `yaml:"timeout"`
	RetryAttempts  int               `yaml:"retry_attempts"`
	KeyCacheTTL    time.Duration     `yaml:"key_cache_ttl"`
	PolicyCacheTTL time.Duration     `yaml:"policy_cache_ttl"`
	Headers        map[string]string `yaml:"headers,omitempty"`
}

// AgentConfig defines configuration for the encryption agent
type AgentConfig struct {
	SocketPath        string        `yaml:"socket_path"`
	LogLevel          string        `yaml:"log_level"`
	LogPath           string        `yaml:"log_path"`
	AuditLogPath      string        `yaml:"audit_log_path"`
	MaxCacheSize      int           `yaml:"max_cache_size"`
	CacheCleanupInterval time.Duration `yaml:"cache_cleanup_interval"`
	WorkerThreads     int           `yaml:"worker_threads"`
	MaxRequestSize    int64         `yaml:"max_request_size"`
	RequestTimeout    time.Duration `yaml:"request_timeout"`
	EnableMetrics     bool          `yaml:"enable_metrics"`
	MetricsPort       int           `yaml:"metrics_port"`
}

// ValidationResult contains configuration validation results
type ValidationResult struct {
	Valid  bool     `json:"valid"`
	Errors []string `json:"errors"`
	Warnings []string `json:"warnings"`
}