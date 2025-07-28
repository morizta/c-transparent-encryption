package process

import (
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"takakrypt/internal/config"
)

// ProcessSetEvaluator handles process set matching with advanced detection
type ProcessSetEvaluator struct {
	detector    *ProcessDetector
	mu          sync.RWMutex
	matchCache  map[string]*ProcessSetMatch
	cacheEnable bool
	cacheTTL    time.Duration
}

// ProcessSetMatch represents the result of process set matching
type ProcessSetMatch struct {
	Matched      bool
	MatchReason  string
	ProcessInfo  *ProcessInfo
	SetName      string
	MatchedRule  string
	CachedAt     time.Time
}

// DatabaseProcessRule represents rules for matching database processes
type DatabaseProcessRule struct {
	DatabaseTypes   []ProcessType `yaml:"database_types"`   // mysql, postgresql, etc.
	MinVersion      string        `yaml:"min_version"`      // Minimum database version
	MaxVersion      string        `yaml:"max_version"`      // Maximum database version
	ConfigPaths     []string      `yaml:"config_paths"`     // Required config file paths
	DataPaths       []string      `yaml:"data_paths"`       // Required data directory paths
	ListenPorts     []int         `yaml:"listen_ports"`     // Required listening ports
	EnvironmentVars []string      `yaml:"environment_vars"` // Required environment variables
}

// EnhancedProcessSet extends the basic ProcessSet with database-specific rules
type EnhancedProcessSet struct {
	config.ProcessSet
	DatabaseRules []DatabaseProcessRule `yaml:"database_rules"`
	ProcessTypes  []ProcessType         `yaml:"process_types"`  // Filter by process type
	ParentPIDs    []int                 `yaml:"parent_pids"`    // Filter by parent process
	ChildrenOf    []string              `yaml:"children_of"`    // Children of named processes
	RequireAll    bool                  `yaml:"require_all"`    // All conditions must match (AND vs OR)
}

// NewProcessSetEvaluator creates a new process set evaluator
func NewProcessSetEvaluator(detector *ProcessDetector) *ProcessSetEvaluator {
	return &ProcessSetEvaluator{
		detector:    detector,
		matchCache:  make(map[string]*ProcessSetMatch),
		cacheEnable: true,
		cacheTTL:    2 * time.Minute, // Shorter TTL for process matching
	}
}

// EvaluateProcessSet checks if a process matches a process set
func (pse *ProcessSetEvaluator) EvaluateProcessSet(pid int, processSet *config.ProcessSet) (*ProcessSetMatch, error) {
	// Create cache key
	cacheKey := fmt.Sprintf("%d:%s", pid, processSet.Name)

	// Check cache first
	if pse.cacheEnable {
		pse.mu.RLock()
		if cached, exists := pse.matchCache[cacheKey]; exists {
			if time.Since(cached.CachedAt) < pse.cacheTTL {
				pse.mu.RUnlock()
				return cached, nil
			}
		}
		pse.mu.RUnlock()
	}

	// Get process information
	processInfo, err := pse.detector.GetProcessInfo(pid)
	if err != nil {
		return &ProcessSetMatch{
			Matched:     false,
			MatchReason: fmt.Sprintf("Failed to get process info: %v", err),
			ProcessInfo: nil,
			SetName:     processSet.Name,
		}, err
	}

	// Perform matching
	match := pse.performMatching(processInfo, processSet)
	match.ProcessInfo = processInfo
	match.SetName = processSet.Name
	match.CachedAt = time.Now()

	// Cache the result
	if pse.cacheEnable {
		pse.mu.Lock()
		pse.matchCache[cacheKey] = match
		pse.mu.Unlock()
	}

	return match, nil
}

// EvaluateEnhancedProcessSet checks if a process matches an enhanced process set
func (pse *ProcessSetEvaluator) EvaluateEnhancedProcessSet(pid int, processSet *EnhancedProcessSet) (*ProcessSetMatch, error) {
	// First check basic process set matching
	match, err := pse.EvaluateProcessSet(pid, &processSet.ProcessSet)
	if err != nil {
		return match, err
	}

	// If basic matching failed and we require all conditions, return failure
	if !match.Matched && processSet.RequireAll {
		return match, nil
	}

	// Get process information if not already available
	if match.ProcessInfo == nil {
		processInfo, err := pse.detector.GetProcessInfo(pid)
		if err != nil {
			return match, err
		}
		match.ProcessInfo = processInfo
	}

	// Perform enhanced matching
	enhancedMatch := pse.performEnhancedMatching(match.ProcessInfo, processSet)

	// Combine results based on RequireAll setting
	if processSet.RequireAll {
		match.Matched = match.Matched && enhancedMatch
	} else {
		match.Matched = match.Matched || enhancedMatch
	}

	if enhancedMatch {
		match.MatchReason += " (enhanced rules matched)"
	}

	return match, nil
}

// performMatching performs basic process set matching
func (pse *ProcessSetEvaluator) performMatching(processInfo *ProcessInfo, processSet *config.ProcessSet) *ProcessSetMatch {
	reasons := []string{}

	// Check process names
	nameMatch := false
	for _, processName := range processSet.Processes {
		if pse.matchesProcessName(processInfo, processName) {
			nameMatch = true
			reasons = append(reasons, fmt.Sprintf("process name '%s'", processName))
			break
		}
	}

	// Check process paths
	pathMatch := false
	for _, processPath := range processSet.ProcessPaths {
		if pse.matchesProcessPath(processInfo, processPath) {
			pathMatch = true
			reasons = append(reasons, fmt.Sprintf("process path '%s'", processPath))
			break
		}
	}

	// Check PIDs
	pidMatch := false
	for _, pid := range processSet.PIDs {
		if processInfo.PID == pid {
			pidMatch = true
			reasons = append(reasons, fmt.Sprintf("PID %d", pid))
			break
		}
	}

	// Determine if matched (OR logic for basic sets)
	matched := nameMatch || pathMatch || pidMatch
	if len(processSet.Processes) == 0 && len(processSet.ProcessPaths) == 0 && len(processSet.PIDs) == 0 {
		matched = true // Empty set matches all
		reasons = append(reasons, "empty set (matches all)")
	}

	reasonStr := "no match"
	if matched {
		reasonStr = "matched: " + strings.Join(reasons, ", ")
	}

	return &ProcessSetMatch{
		Matched:     matched,
		MatchReason: reasonStr,
		MatchedRule: strings.Join(reasons, ", "),
	}
}

// performEnhancedMatching performs enhanced process set matching
func (pse *ProcessSetEvaluator) performEnhancedMatching(processInfo *ProcessInfo, processSet *EnhancedProcessSet) bool {
	matches := []bool{}

	// Check process types
	if len(processSet.ProcessTypes) > 0 {
		typeMatch := false
		for _, processType := range processSet.ProcessTypes {
			if processInfo.Type == processType {
				typeMatch = true
				break
			}
		}
		matches = append(matches, typeMatch)
	}

	// Check parent PIDs
	if len(processSet.ParentPIDs) > 0 {
		parentMatch := false
		for _, parentPID := range processSet.ParentPIDs {
			if processInfo.PPID == parentPID {
				parentMatch = true
				break
			}
		}
		matches = append(matches, parentMatch)
	}

	// Check children of named processes
	if len(processSet.ChildrenOf) > 0 {
		childMatch := pse.checkChildrenOf(processInfo, processSet.ChildrenOf)
		matches = append(matches, childMatch)
	}

	// Check database rules
	if len(processSet.DatabaseRules) > 0 {
		dbMatch := pse.checkDatabaseRules(processInfo, processSet.DatabaseRules)
		matches = append(matches, dbMatch)
	}

	// Return result based on RequireAll setting
	if processSet.RequireAll {
		for _, match := range matches {
			if !match {
				return false
			}
		}
		return len(matches) > 0
	} else {
		for _, match := range matches {
			if match {
				return true
			}
		}
		return false
	}
}

// matchesProcessName checks if process name matches pattern
func (pse *ProcessSetEvaluator) matchesProcessName(processInfo *ProcessInfo, pattern string) bool {
	// Exact match
	if processInfo.Name == pattern {
		return true
	}

	// Wildcard match
	if matched, _ := filepath.Match(pattern, processInfo.Name); matched {
		return true
	}

	// Substring match
	if strings.Contains(processInfo.Name, pattern) {
		return true
	}

	return false
}

// matchesProcessPath checks if process path matches pattern
func (pse *ProcessSetEvaluator) matchesProcessPath(processInfo *ProcessInfo, pattern string) bool {
	// Exact match
	if processInfo.Path == pattern {
		return true
	}

	// Wildcard match
	if matched, _ := filepath.Match(pattern, processInfo.Path); matched {
		return true
	}

	// Prefix match (common for paths)
	if strings.HasPrefix(processInfo.Path, pattern) {
		return true
	}

	// Directory match
	if strings.HasPrefix(processInfo.Path, filepath.Dir(pattern)) {
		return true
	}

	return false
}

// checkChildrenOf checks if process is a child of named processes
func (pse *ProcessSetEvaluator) checkChildrenOf(processInfo *ProcessInfo, parentNames []string) bool {
	if processInfo.PPID == 0 {
		return false // No parent
	}

	// Get parent process info
	parentInfo, err := pse.detector.GetProcessInfo(processInfo.PPID)
	if err != nil {
		return false
	}

	// Check if parent matches any of the named processes
	for _, parentName := range parentNames {
		if pse.matchesProcessName(parentInfo, parentName) {
			return true
		}
	}

	return false
}

// checkDatabaseRules checks if process matches database-specific rules
func (pse *ProcessSetEvaluator) checkDatabaseRules(processInfo *ProcessInfo, rules []DatabaseProcessRule) bool {
	for _, rule := range rules {
		if pse.matchesDatabaseRule(processInfo, &rule) {
			return true
		}
	}
	return false
}

// matchesDatabaseRule checks if process matches a specific database rule
func (pse *ProcessSetEvaluator) matchesDatabaseRule(processInfo *ProcessInfo, rule *DatabaseProcessRule) bool {
	matches := []bool{}

	// Check database types
	if len(rule.DatabaseTypes) > 0 {
		typeMatch := false
		for _, dbType := range rule.DatabaseTypes {
			if processInfo.Type == dbType {
				typeMatch = true
				break
			}
		}
		matches = append(matches, typeMatch)
	}

	// Check config paths
	if len(rule.ConfigPaths) > 0 {
		configMatch := false
		for _, configPath := range rule.ConfigPaths {
			for _, processConfigPath := range processInfo.ConfigPaths {
				if strings.Contains(processConfigPath, configPath) {
					configMatch = true
					break
				}
			}
			if configMatch {
				break
			}
		}
		matches = append(matches, configMatch)
	}

	// Check data paths
	if len(rule.DataPaths) > 0 {
		dataMatch := false
		for _, dataPath := range rule.DataPaths {
			for _, processDataPath := range processInfo.DataPaths {
				if strings.Contains(processDataPath, dataPath) {
					dataMatch = true
					break
				}
			}
			if dataMatch {
				break
			}
		}
		matches = append(matches, dataMatch)
	}

	// Check listening ports
	if len(rule.ListenPorts) > 0 {
		portMatch := false
		for _, rulePort := range rule.ListenPorts {
			for _, processPort := range processInfo.ListenPorts {
				if rulePort == processPort {
					portMatch = true
					break
				}
			}
			if portMatch {
				break
			}
		}
		matches = append(matches, portMatch)
	}

	// Check environment variables
	if len(rule.EnvironmentVars) > 0 {
		envMatch := false
		for _, envVar := range rule.EnvironmentVars {
			if _, exists := processInfo.Environment[envVar]; exists {
				envMatch = true
				break
			}
		}
		matches = append(matches, envMatch)
	}

	// All specified conditions must match for a database rule
	for _, match := range matches {
		if !match {
			return false
		}
	}

	return len(matches) > 0
}

// GetAllProcessSets returns process sets for all supported process types
func (pse *ProcessSetEvaluator) GetAllProcessSets() map[string]*EnhancedProcessSet {
	sets := make(map[string]*EnhancedProcessSet)
	
	// Add database process sets
	for name, set := range pse.GetDatabaseProcessSets() {
		sets[name] = set
	}
	
	// Add application process sets
	for name, set := range pse.GetApplicationProcessSets() {
		sets[name] = set
	}
	
	// Add system process sets
	for name, set := range pse.GetSystemProcessSets() {
		sets[name] = set
	}
	
	return sets
}

// GetDatabaseProcessSets returns process sets specifically designed for database processes
func (pse *ProcessSetEvaluator) GetDatabaseProcessSets() map[string]*EnhancedProcessSet {
	return map[string]*EnhancedProcessSet{
		"mysql_processes": {
			ProcessSet: config.ProcessSet{
				Name:      "mysql_processes",
				Processes: []string{"mysqld", "mysql"},
			},
			DatabaseRules: []DatabaseProcessRule{
				{
					DatabaseTypes: []ProcessType{ProcessTypeMySQL, ProcessTypeMariaDB},
					ListenPorts:   []int{3306, 3307},
				},
			},
			ProcessTypes: []ProcessType{ProcessTypeMySQL, ProcessTypeMariaDB},
			RequireAll:   false,
		},
		"postgresql_processes": {
			ProcessSet: config.ProcessSet{
				Name:      "postgresql_processes",
				Processes: []string{"postgres", "postmaster"},
			},
			DatabaseRules: []DatabaseProcessRule{
				{
					DatabaseTypes: []ProcessType{ProcessTypePostgreSQL},
					ListenPorts:   []int{5432, 5433},
				},
			},
			ProcessTypes: []ProcessType{ProcessTypePostgreSQL},
			RequireAll:   false,
		},
		"mongodb_processes": {
			ProcessSet: config.ProcessSet{
				Name:      "mongodb_processes",
				Processes: []string{"mongod", "mongodb"},
			},
			DatabaseRules: []DatabaseProcessRule{
				{
					DatabaseTypes: []ProcessType{ProcessTypeMongoDB},
					ListenPorts:   []int{27017, 27018, 27019},
				},
			},
			ProcessTypes: []ProcessType{ProcessTypeMongoDB},
			RequireAll:   false,
		},
		"redis_processes": {
			ProcessSet: config.ProcessSet{
				Name:      "redis_processes",
				Processes: []string{"redis-server", "redis"},
			},
			DatabaseRules: []DatabaseProcessRule{
				{
					DatabaseTypes: []ProcessType{ProcessTypeRedis},
					ListenPorts:   []int{6379, 6380},
				},
			},
			ProcessTypes: []ProcessType{ProcessTypeRedis},
			RequireAll:   false,
		},
		"all_database_processes": {
			ProcessSet: config.ProcessSet{
				Name: "all_database_processes",
			},
			ProcessTypes: []ProcessType{
				ProcessTypeMySQL,
				ProcessTypePostgreSQL,
				ProcessTypeMariaDB,
				ProcessTypeMongoDB,
				ProcessTypeRedis,
				ProcessTypeOracle,
			},
			RequireAll: false,
		},
	}
}

// GetApplicationProcessSets returns process sets for application processes
func (pse *ProcessSetEvaluator) GetApplicationProcessSets() map[string]*EnhancedProcessSet {
	return map[string]*EnhancedProcessSet{
		"web_servers": {
			ProcessSet: config.ProcessSet{
				Name:      "web_servers",
				Processes: []string{"nginx", "apache2", "httpd"},
			},
			ProcessTypes: []ProcessType{ProcessTypeWebServer},
			RequireAll:   false,
		},
		"java_applications": {
			ProcessSet: config.ProcessSet{
				Name:      "java_applications",
				Processes: []string{"java", "javaw", "tomcat", "catalina"},
			},
			ProcessTypes: []ProcessType{ProcessTypeJava},
			RequireAll:   false,
		},
		"nodejs_applications": {
			ProcessSet: config.ProcessSet{
				Name:      "nodejs_applications",
				Processes: []string{"node", "nodejs", "npm", "yarn"},
			},
			ProcessTypes: []ProcessType{ProcessTypeNodeJS},
			RequireAll:   false,
		},
		"python_applications": {
			ProcessSet: config.ProcessSet{
				Name:      "python_applications",
				Processes: []string{"python", "python3", "gunicorn", "uwsgi"},
			},
			ProcessTypes: []ProcessType{ProcessTypePython},
			RequireAll:   false,
		},
		"docker_processes": {
			ProcessSet: config.ProcessSet{
				Name:      "docker_processes",
				Processes: []string{"dockerd", "docker", "containerd", "runc"},
			},
			ProcessTypes: []ProcessType{ProcessTypeDocker},
			RequireAll:   false,
		},
		"messaging_systems": {
			ProcessSet: config.ProcessSet{
				Name:      "messaging_systems",
				Processes: []string{"rabbitmq-server", "beam.smp", "kafka"},
			},
			ProcessTypes: []ProcessType{ProcessTypeMessaging},
			RequireAll:   false,
		},
		"development_tools": {
			ProcessSet: config.ProcessSet{
				Name:      "development_tools",
				Processes: []string{"git", "gcc", "make", "cmake", "code", "vim"},
			},
			ProcessTypes: []ProcessType{ProcessTypeDevelopment},
			RequireAll:   false,
		},
		"file_sync_tools": {
			ProcessSet: config.ProcessSet{
				Name:      "file_sync_tools",
				Processes: []string{"dropbox", "syncthing", "rsync"},
			},
			ProcessTypes: []ProcessType{ProcessTypeFileSync},
			RequireAll:   false,
		},
	}
}

// GetSystemProcessSets returns process sets for system processes
func (pse *ProcessSetEvaluator) GetSystemProcessSets() map[string]*EnhancedProcessSet {
	return map[string]*EnhancedProcessSet{
		"shell_processes": {
			ProcessSet: config.ProcessSet{
				Name:      "shell_processes",
				Processes: []string{"bash", "sh", "zsh", "fish"},
			},
			ProcessTypes: []ProcessType{ProcessTypeShell},
			RequireAll:   false,
		},
		"system_critical": {
			ProcessSet: config.ProcessSet{
				Name:      "system_critical",
				Processes: []string{"systemd", "init", "kernel", "sshd"},
				PIDs:      []int{1}, // init process
			},
			ProcessTypes: []ProcessType{ProcessTypeSystem},
			RequireAll:   false,
		},
		"security_tools": {
			ProcessSet: config.ProcessSet{
				Name:      "security_tools",
				Processes: []string{"fail2ban", "auditd", "clamd", "filebeat"},
			},
			ProcessTypes: []ProcessType{ProcessTypeSecurity},
			RequireAll:   false,
		},
		"backup_tools": {
			ProcessSet: config.ProcessSet{
				Name:      "backup_tools",
				Processes: []string{"rsync", "tar", "mysqldump", "pg_dump"},
			},
			ProcessTypes: []ProcessType{ProcessTypeBackup},
			RequireAll:   false,
		},
		"network_tools": {
			ProcessSet: config.ProcessSet{
				Name:      "network_tools",
				Processes: []string{"netstat", "ss", "tcpdump", "curl", "wget"},
			},
			ProcessTypes: []ProcessType{ProcessTypeNetwork},
			RequireAll:   false,
		},
		"vpn_services": {
			ProcessSet: config.ProcessSet{
				Name:      "vpn_services",
				Processes: []string{"openvpn", "wireguard", "strongswan"},
			},
			ProcessTypes: []ProcessType{ProcessTypeVPN},
			RequireAll:   false,
		},
		"kubernetes_components": {
			ProcessSet: config.ProcessSet{
				Name:      "kubernetes_components",
				Processes: []string{"kubelet", "kube-proxy", "kube-apiserver", "etcd"},
			},
			ProcessTypes: []ProcessType{ProcessTypeKubernetes},
			RequireAll:   false,
		},
	}
}

// ClearCache clears the process set match cache
func (pse *ProcessSetEvaluator) ClearCache() {
	pse.mu.Lock()
	defer pse.mu.Unlock()
	pse.matchCache = make(map[string]*ProcessSetMatch)
}

// GetCacheStats returns cache statistics
func (pse *ProcessSetEvaluator) GetCacheStats() map[string]interface{} {
	pse.mu.RLock()
	defer pse.mu.RUnlock()

	return map[string]interface{}{
		"cache_enabled": pse.cacheEnable,
		"cache_size":    len(pse.matchCache),
		"cache_ttl":     pse.cacheTTL,
	}
}// Enhanced logging enabled
