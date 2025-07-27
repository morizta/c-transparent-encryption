package process

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ProcessType represents the type/classification of a process
type ProcessType string

const (
	ProcessTypeUnknown       ProcessType = "unknown"
	ProcessTypeMySQL         ProcessType = "mysql"
	ProcessTypePostgreSQL    ProcessType = "postgresql"
	ProcessTypeMariaDB       ProcessType = "mariadb"
	ProcessTypeOracle        ProcessType = "oracle"
	ProcessTypeMongoDB       ProcessType = "mongodb"
	ProcessTypeRedis         ProcessType = "redis"
	ProcessTypeSystem        ProcessType = "system"
	ProcessTypeUserApp       ProcessType = "user_app"
	ProcessTypeWebServer     ProcessType = "webserver"
	ProcessTypeShell         ProcessType = "shell"
	ProcessTypeJava          ProcessType = "java"
	ProcessTypeNodeJS        ProcessType = "nodejs"
	ProcessTypePython        ProcessType = "python"
	ProcessTypeDocker        ProcessType = "docker"
	ProcessTypeKubernetes    ProcessType = "kubernetes"
	ProcessTypeMessaging     ProcessType = "messaging"
	ProcessTypeCache         ProcessType = "cache"
	ProcessTypeSecurity      ProcessType = "security"
	ProcessTypeBackup        ProcessType = "backup"
	ProcessTypeDevelopment   ProcessType = "development"
	ProcessTypeFileSync      ProcessType = "filesync"
	ProcessTypeMedia         ProcessType = "media"
	ProcessTypeNetwork       ProcessType = "network"
	ProcessTypeVPN           ProcessType = "vpn"
)

// ProcessInfo contains detailed information about a process
type ProcessInfo struct {
	PID         int
	PPID        int
	Name        string
	Path        string
	CommandLine []string
	CmdlineRaw  string
	UID         int
	GID         int
	Username    string
	GroupName   string
	Type        ProcessType
	DatabaseType string
	DatabaseVersion string
	ConfigPaths []string
	DataPaths   []string
	ListenPorts []int
	Environment map[string]string
	CachedAt    time.Time
	TTL         time.Duration
}

// DatabasePattern represents patterns for detecting database processes
type DatabasePattern struct {
	ProcessNames []string
	ExecutablePaths []string
	CommandPatterns []string
	ConfigPaths []string
	DataPaths []string
	DefaultPorts []int
	EnvironmentVars []string
}

// ProcessDetector handles process detection and classification
type ProcessDetector struct {
	mu               sync.RWMutex
	processCache     map[int]*ProcessInfo
	databasePatterns map[ProcessType]*DatabasePattern
	cacheEnabled     bool
	defaultTTL       time.Duration
}

// NewProcessDetector creates a new process detector
func NewProcessDetector() *ProcessDetector {
	detector := &ProcessDetector{
		processCache:     make(map[int]*ProcessInfo),
		databasePatterns: make(map[ProcessType]*DatabasePattern),
		cacheEnabled:     true,
		defaultTTL:       5 * time.Minute,
	}

	detector.initializeDatabasePatterns()
	return detector
}

// initializeDatabasePatterns sets up database detection patterns
func (pd *ProcessDetector) initializeDatabasePatterns() {
	// MySQL/MariaDB patterns
	pd.databasePatterns[ProcessTypeMySQL] = &DatabasePattern{
		ProcessNames: []string{"mysqld", "mysql", "mariadbd", "mariadb"},
		ExecutablePaths: []string{
			"/usr/sbin/mysqld",
			"/usr/bin/mysqld",
			"/usr/local/mysql/bin/mysqld",
			"/opt/mysql/bin/mysqld",
			"/usr/sbin/mariadbd",
			"/usr/bin/mariadbd",
		},
		CommandPatterns: []string{
			"--defaults-file=",
			"--datadir=",
			"--socket=",
			"--pid-file=",
			"--log-error=",
		},
		ConfigPaths: []string{
			"/etc/mysql/",
			"/etc/my.cnf",
			"/etc/mysql/my.cnf",
			"/usr/local/mysql/my.cnf",
			"/opt/mysql/my.cnf",
		},
		DataPaths: []string{
			"/var/lib/mysql/",
			"/usr/local/mysql/data/",
			"/opt/mysql/data/",
			"/data/mysql/",
		},
		DefaultPorts: []int{3306, 3307},
		EnvironmentVars: []string{"MYSQL_ROOT_PASSWORD", "MYSQL_DATABASE", "MYSQL_USER"},
	}

	// PostgreSQL patterns
	pd.databasePatterns[ProcessTypePostgreSQL] = &DatabasePattern{
		ProcessNames: []string{"postgres", "postmaster", "postgresql"},
		ExecutablePaths: []string{
			"/usr/bin/postgres",
			"/usr/local/pgsql/bin/postgres",
			"/opt/postgresql/bin/postgres",
			"/usr/lib/postgresql/*/bin/postgres",
		},
		CommandPatterns: []string{
			"-D",
			"--config-file=",
			"--data-directory=",
			"--hba-file=",
			"--ident-file=",
		},
		ConfigPaths: []string{
			"/etc/postgresql/",
			"/var/lib/postgresql/*/main/",
			"/usr/local/pgsql/data/",
			"/opt/postgresql/data/",
		},
		DataPaths: []string{
			"/var/lib/postgresql/",
			"/usr/local/pgsql/data/",
			"/opt/postgresql/data/",
			"/data/postgresql/",
		},
		DefaultPorts: []int{5432, 5433},
		EnvironmentVars: []string{"POSTGRES_PASSWORD", "POSTGRES_DB", "POSTGRES_USER", "PGDATA"},
	}

	// MariaDB (separate from MySQL for specific detection)
	pd.databasePatterns[ProcessTypeMariaDB] = &DatabasePattern{
		ProcessNames: []string{"mariadbd", "mariadb-server", "mariadb"},
		ExecutablePaths: []string{
			"/usr/sbin/mariadbd",
			"/usr/bin/mariadbd",
			"/usr/local/mariadb/bin/mariadbd",
			"/opt/mariadb/bin/mariadbd",
		},
		CommandPatterns: []string{
			"--defaults-file=",
			"--datadir=",
			"--socket=",
			"--pid-file=",
		},
		ConfigPaths: []string{
			"/etc/mysql/mariadb.conf.d/",
			"/etc/my.cnf.d/",
			"/usr/local/mariadb/my.cnf",
		},
		DataPaths: []string{
			"/var/lib/mysql/",
			"/usr/local/mariadb/data/",
			"/opt/mariadb/data/",
		},
		DefaultPorts: []int{3306, 3307},
		EnvironmentVars: []string{"MARIADB_ROOT_PASSWORD", "MARIADB_DATABASE"},
	}

	// MongoDB patterns
	pd.databasePatterns[ProcessTypeMongoDB] = &DatabasePattern{
		ProcessNames: []string{"mongod", "mongodb", "mongo"},
		ExecutablePaths: []string{
			"/usr/bin/mongod",
			"/usr/local/mongodb/bin/mongod",
			"/opt/mongodb/bin/mongod",
		},
		CommandPatterns: []string{
			"--config",
			"--dbpath",
			"--logpath",
			"--port",
		},
		ConfigPaths: []string{
			"/etc/mongod.conf",
			"/etc/mongodb.conf",
			"/usr/local/mongodb/mongod.conf",
		},
		DataPaths: []string{
			"/var/lib/mongodb/",
			"/data/db/",
			"/usr/local/mongodb/data/",
		},
		DefaultPorts: []int{27017, 27018, 27019},
		EnvironmentVars: []string{"MONGO_INITDB_ROOT_USERNAME", "MONGO_INITDB_ROOT_PASSWORD"},
	}

	// Redis patterns
	pd.databasePatterns[ProcessTypeRedis] = &DatabasePattern{
		ProcessNames: []string{"redis-server", "redis"},
		ExecutablePaths: []string{
			"/usr/bin/redis-server",
			"/usr/local/redis/bin/redis-server",
			"/opt/redis/bin/redis-server",
		},
		CommandPatterns: []string{
			"/etc/redis/redis.conf",
			"--port",
			"--bind",
			"--dir",
		},
		ConfigPaths: []string{
			"/etc/redis/redis.conf",
			"/usr/local/redis/redis.conf",
			"/opt/redis/redis.conf",
		},
		DataPaths: []string{
			"/var/lib/redis/",
			"/data/redis/",
			"/usr/local/redis/data/",
		},
		DefaultPorts: []int{6379, 6380},
		EnvironmentVars: []string{"REDIS_PASSWORD"},
	}
}

// GetProcessInfo retrieves detailed information about a process
func (pd *ProcessDetector) GetProcessInfo(pid int) (*ProcessInfo, error) {
	pd.mu.Lock()
	defer pd.mu.Unlock()

	// Check cache first
	if pd.cacheEnabled {
		if cached, exists := pd.processCache[pid]; exists {
			if time.Since(cached.CachedAt) < cached.TTL {
				return cached, nil
			}
			// Remove expired entry
			delete(pd.processCache, pid)
		}
	}

	// Gather process information
	info, err := pd.gatherProcessInfo(pid)
	if err != nil {
		return nil, err
	}

	// Classify the process
	pd.classifyProcess(info)

	// Cache the result
	if pd.cacheEnabled {
		info.CachedAt = time.Now()
		info.TTL = pd.defaultTTL
		pd.processCache[pid] = info
	}

	return info, nil
}

// gatherProcessInfo collects basic process information from /proc
func (pd *ProcessDetector) gatherProcessInfo(pid int) (*ProcessInfo, error) {
	procPath := fmt.Sprintf("/proc/%d", pid)

	// Check if process exists
	if _, err := os.Stat(procPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("process %d does not exist", pid)
	}

	info := &ProcessInfo{
		PID:         pid,
		Environment: make(map[string]string),
	}

	// Read process name from /proc/pid/comm
	if commData, err := os.ReadFile(filepath.Join(procPath, "comm")); err == nil {
		info.Name = strings.TrimSpace(string(commData))
	}

	// Read command line from /proc/pid/cmdline
	if cmdlineData, err := os.ReadFile(filepath.Join(procPath, "cmdline")); err == nil {
		info.CmdlineRaw = string(cmdlineData)
		// Split on null bytes
		args := strings.Split(string(cmdlineData), "\x00")
		if len(args) > 0 && args[len(args)-1] == "" {
			args = args[:len(args)-1] // Remove empty last element
		}
		info.CommandLine = args
		if len(args) > 0 {
			info.Path = args[0]
		}
	}

	// Read executable path from /proc/pid/exe
	if exePath, err := os.Readlink(filepath.Join(procPath, "exe")); err == nil {
		info.Path = exePath
	}

	// Read status file for UID/GID and PPID
	if statusData, err := os.ReadFile(filepath.Join(procPath, "status")); err == nil {
		pd.parseStatusFile(info, string(statusData))
	}

	// Read environment variables
	if environData, err := os.ReadFile(filepath.Join(procPath, "environ")); err == nil {
		pd.parseEnvironFile(info, string(environData))
	}

	return info, nil
}

// parseStatusFile extracts UID, GID, and PPID from /proc/pid/status
func (pd *ProcessDetector) parseStatusFile(info *ProcessInfo, statusContent string) {
	scanner := bufio.NewScanner(strings.NewReader(statusContent))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "PPid:") {
			if ppid, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "PPid:"))); err == nil {
				info.PPID = ppid
			}
		} else if strings.HasPrefix(line, "Uid:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				if uid, err := strconv.Atoi(fields[1]); err == nil {
					info.UID = uid
				}
			}
		} else if strings.HasPrefix(line, "Gid:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				if gid, err := strconv.Atoi(fields[1]); err == nil {
					info.GID = gid
				}
			}
		}
	}
}

// parseEnvironFile extracts environment variables from /proc/pid/environ
func (pd *ProcessDetector) parseEnvironFile(info *ProcessInfo, environContent string) {
	envVars := strings.Split(environContent, "\x00")
	for _, envVar := range envVars {
		if envVar == "" {
			continue
		}
		parts := strings.SplitN(envVar, "=", 2)
		if len(parts) == 2 {
			info.Environment[parts[0]] = parts[1]
		}
	}
}

// classifyProcess determines the process type and database-specific information
func (pd *ProcessDetector) classifyProcess(info *ProcessInfo) {
	// Default classification
	info.Type = ProcessTypeUnknown

	// Check for database processes
	for dbType, pattern := range pd.databasePatterns {
		if pd.matchesDatabasePattern(info, pattern) {
			info.Type = dbType
			info.DatabaseType = string(dbType)
			pd.extractDatabaseInfo(info, pattern)
			return
		}
	}

	// Check for other common process types
	pd.classifyCommonProcesses(info)
}

// matchesDatabasePattern checks if a process matches a database pattern
func (pd *ProcessDetector) matchesDatabasePattern(info *ProcessInfo, pattern *DatabasePattern) bool {
	// Check process name
	for _, name := range pattern.ProcessNames {
		if info.Name == name || strings.Contains(info.Name, name) {
			return true
		}
	}

	// Check executable path
	for _, path := range pattern.ExecutablePaths {
		if info.Path == path || strings.Contains(info.Path, path) {
			return true
		}
		// Handle wildcards in paths
		if strings.Contains(path, "*") {
			if matched, _ := filepath.Match(path, info.Path); matched {
				return true
			}
		}
	}

	// Check command line arguments
	for _, pattern := range pattern.CommandPatterns {
		for _, arg := range info.CommandLine {
			if strings.Contains(arg, pattern) {
				return true
			}
		}
	}

	// Check environment variables
	for _, envVar := range pattern.EnvironmentVars {
		if _, exists := info.Environment[envVar]; exists {
			return true
		}
	}

	return false
}

// extractDatabaseInfo extracts database-specific information
func (pd *ProcessDetector) extractDatabaseInfo(info *ProcessInfo, pattern *DatabasePattern) {
	// Extract data directories from command line
	for _, arg := range info.CommandLine {
		for _, dataPath := range pattern.DataPaths {
			if strings.Contains(arg, dataPath) {
				info.DataPaths = append(info.DataPaths, arg)
			}
		}
	}

	// Extract config paths from command line
	for _, arg := range info.CommandLine {
		for _, configPath := range pattern.ConfigPaths {
			if strings.Contains(arg, configPath) {
				info.ConfigPaths = append(info.ConfigPaths, arg)
			}
		}
	}

	// Extract listening ports from command line
	for _, arg := range info.CommandLine {
		if strings.Contains(arg, "--port=") || strings.Contains(arg, "-p") {
			// Try to extract port number
			parts := strings.Split(arg, "=")
			if len(parts) == 2 {
				if port, err := strconv.Atoi(parts[1]); err == nil {
					info.ListenPorts = append(info.ListenPorts, port)
				}
			}
		}
	}

	// Add default ports if none found
	if len(info.ListenPorts) == 0 {
		info.ListenPorts = pattern.DefaultPorts
	}

	// Extract version information
	pd.extractDatabaseVersion(info)
}

// extractDatabaseVersion attempts to extract database version
func (pd *ProcessDetector) extractDatabaseVersion(info *ProcessInfo) {
	// Try to get version from command line arguments
	for _, arg := range info.CommandLine {
		if strings.Contains(arg, "version") || strings.Contains(arg, "--version") {
			info.DatabaseVersion = arg
			return
		}
	}

	// Try to get version from executable (this would require running --version)
	// For now, we'll leave this as a placeholder
	info.DatabaseVersion = "unknown"
}

// classifyCommonProcesses classifies non-database processes
func (pd *ProcessDetector) classifyCommonProcesses(info *ProcessInfo) {
	// Check by process name patterns
	processPatterns := map[string]ProcessType{
		// Shell processes
		"bash":      ProcessTypeShell,
		"sh":        ProcessTypeShell,
		"zsh":       ProcessTypeShell,
		"fish":      ProcessTypeShell,
		"csh":       ProcessTypeShell,
		"tcsh":      ProcessTypeShell,
		
		// Web servers
		"apache2":   ProcessTypeWebServer,
		"httpd":     ProcessTypeWebServer,
		"nginx":     ProcessTypeWebServer,
		
		// System processes
		"systemd":   ProcessTypeSystem,
		"kernel":    ProcessTypeSystem,
		"kthread":   ProcessTypeSystem,
		"init":      ProcessTypeSystem,
		"ksoftirq":  ProcessTypeSystem,
		"migration": ProcessTypeSystem,
		"rcu_":      ProcessTypeSystem,
		"sshd":      ProcessTypeSystem,
		"rsyslog":   ProcessTypeSystem,
		"auditd":    ProcessTypeSystem,
		
		// Java applications
		"java":      ProcessTypeJava,
		"javaw":     ProcessTypeJava,
		"tomcat":    ProcessTypeJava,
		"catalina":  ProcessTypeJava,
		
		// Node.js applications
		"node":      ProcessTypeNodeJS,
		"nodejs":    ProcessTypeNodeJS,
		"npm":       ProcessTypeNodeJS,
		"yarn":      ProcessTypeNodeJS,
		
		// Python applications
		"python":    ProcessTypePython,
		"python3":   ProcessTypePython,
		"gunicorn":  ProcessTypePython,
		"uwsgi":     ProcessTypePython,
		"celery":    ProcessTypePython,
		
		// Docker and containers
		"dockerd":      ProcessTypeDocker,
		"docker":       ProcessTypeDocker,
		"containerd":   ProcessTypeDocker,
		"runc":         ProcessTypeDocker,
		"docker-proxy": ProcessTypeDocker,
		
		// Kubernetes
		"kubelet":               ProcessTypeKubernetes,
		"kube-proxy":            ProcessTypeKubernetes,
		"kube-apiserver":        ProcessTypeKubernetes,
		"kube-controller":       ProcessTypeKubernetes,
		"kube-scheduler":        ProcessTypeKubernetes,
		"etcd":                  ProcessTypeKubernetes,
		
		// Messaging and queues
		"rabbitmq":    ProcessTypeMessaging,
		"beam.smp":    ProcessTypeMessaging, // RabbitMQ Erlang VM
		"kafka":       ProcessTypeMessaging,
		
		// Cache systems
		"memcached":     ProcessTypeCache,
		"elasticsearch": ProcessTypeCache,
		
		// Security tools
		"fail2ban":   ProcessTypeSecurity,
		"ossec":      ProcessTypeSecurity,
		"wazuh":      ProcessTypeSecurity,
		"clamd":      ProcessTypeSecurity,
		"freshclam":  ProcessTypeSecurity,
		"clamav":     ProcessTypeSecurity,
		"filebeat":   ProcessTypeSecurity,
		"metricbeat": ProcessTypeSecurity,
		
		// Backup tools
		"rsync":      ProcessTypeBackup,
		"tar":        ProcessTypeBackup,
		"gzip":       ProcessTypeBackup,
		"mysqldump":  ProcessTypeBackup,
		"pg_dump":    ProcessTypeBackup,
		"bacula":     ProcessTypeBackup,
		"amanda":     ProcessTypeBackup,
		
		// Development tools
		"git":     ProcessTypeDevelopment,
		"svn":     ProcessTypeDevelopment,
		"gcc":     ProcessTypeDevelopment,
		"make":    ProcessTypeDevelopment,
		"cmake":   ProcessTypeDevelopment,
		"gradle":  ProcessTypeDevelopment,
		"maven":   ProcessTypeDevelopment,
		"pip":     ProcessTypeDevelopment,
		"code":    ProcessTypeDevelopment, // VS Code
		"idea":    ProcessTypeDevelopment, // IntelliJ
		"eclipse": ProcessTypeDevelopment,
		"vim":     ProcessTypeDevelopment,
		"emacs":   ProcessTypeDevelopment,
		
		// File sync
		"dropbox":    ProcessTypeFileSync,
		"onedrive":   ProcessTypeFileSync,
		"syncthing":  ProcessTypeFileSync,
		"nextcloud":  ProcessTypeFileSync,
		
		// FTP servers
		"vsftpd":      ProcessTypeFileSync,
		"proftpd":     ProcessTypeFileSync,
		"pure-ftpd":   ProcessTypeFileSync,
		"sftp-server": ProcessTypeFileSync,
		
		// Media processes
		"ffmpeg":      ProcessTypeMedia,
		"vlc":         ProcessTypeMedia,
		"gstreamer":   ProcessTypeMedia,
		"pulseaudio":  ProcessTypeMedia,
		"alsa":        ProcessTypeMedia,
		
		// Network tools
		"netstat":   ProcessTypeNetwork,
		"ss":        ProcessTypeNetwork,
		"iftop":     ProcessTypeNetwork,
		"tcpdump":   ProcessTypeNetwork,
		"wireshark": ProcessTypeNetwork,
		"nmap":      ProcessTypeNetwork,
		"curl":      ProcessTypeNetwork,
		"wget":      ProcessTypeNetwork,
		
		// VPN
		"openvpn":    ProcessTypeVPN,
		"wireguard":  ProcessTypeVPN,
		"strongswan": ProcessTypeVPN,
		"ppp":        ProcessTypeVPN,
	}

	// Check exact and partial matches
	for pattern, processType := range processPatterns {
		if info.Name == pattern || strings.Contains(info.Name, pattern) {
			info.Type = processType
			return
		}
	}

	// Check by command line arguments for more specific detection
	pd.classifyByCommandLine(info)

	// Check by executable path
	pd.classifyByPath(info)

	// Default to user application if nothing else matches
	if info.Type == ProcessTypeUnknown {
		info.Type = ProcessTypeUserApp
	}
}

// classifyByCommandLine classifies processes based on command line arguments
func (pd *ProcessDetector) classifyByCommandLine(info *ProcessInfo) {
	if info.Type != ProcessTypeUnknown {
		return // Already classified
	}

	cmdline := strings.Join(info.CommandLine, " ")
	
	// Java application patterns
	if strings.Contains(cmdline, "java") || strings.Contains(cmdline, ".jar") {
		if strings.Contains(cmdline, "catalina") || strings.Contains(cmdline, "tomcat") {
			info.Type = ProcessTypeJava
		} else if strings.Contains(cmdline, "elasticsearch") {
			info.Type = ProcessTypeCache
		} else if strings.Contains(cmdline, "kafka") {
			info.Type = ProcessTypeMessaging
		} else {
			info.Type = ProcessTypeJava
		}
		return
	}
	
	// Python application patterns
	if strings.Contains(cmdline, "python") {
		if strings.Contains(cmdline, "django") || strings.Contains(cmdline, "flask") {
			info.Type = ProcessTypePython
		} else if strings.Contains(cmdline, "celery") {
			info.Type = ProcessTypeMessaging
		} else {
			info.Type = ProcessTypePython
		}
		return
	}
	
	// Node.js application patterns
	if strings.Contains(cmdline, "node") || strings.Contains(cmdline, "npm") {
		info.Type = ProcessTypeNodeJS
		return
	}
	
	// Docker patterns
	if strings.Contains(cmdline, "docker") || strings.Contains(cmdline, "container") {
		info.Type = ProcessTypeDocker
		return
	}
}

// classifyByPath classifies processes based on executable path
func (pd *ProcessDetector) classifyByPath(info *ProcessInfo) {
	if info.Type != ProcessTypeUnknown {
		return // Already classified
	}

	pathPatterns := map[string]ProcessType{
		"/usr/bin/python":     ProcessTypePython,
		"/usr/bin/node":       ProcessTypeNodeJS,
		"/usr/bin/java":       ProcessTypeJava,
		"/usr/sbin/nginx":     ProcessTypeWebServer,
		"/usr/sbin/apache":    ProcessTypeWebServer,
		"/usr/bin/docker":     ProcessTypeDocker,
		"/opt/":               ProcessTypeUserApp, // Custom applications
		"/usr/local/":         ProcessTypeUserApp, // Local installations
	}

	for pattern, processType := range pathPatterns {
		if strings.HasPrefix(info.Path, pattern) {
			info.Type = processType
			return
		}
	}
}

// IsDatabaseProcess checks if a PID belongs to a database process
func (pd *ProcessDetector) IsDatabaseProcess(pid int) (bool, ProcessType, error) {
	info, err := pd.GetProcessInfo(pid)
	if err != nil {
		return false, ProcessTypeUnknown, err
	}

	isDatabaseType := info.Type == ProcessTypeMySQL ||
		info.Type == ProcessTypePostgreSQL ||
		info.Type == ProcessTypeMariaDB ||
		info.Type == ProcessTypeMongoDB ||
		info.Type == ProcessTypeRedis ||
		info.Type == ProcessTypeOracle

	return isDatabaseType, info.Type, nil
}

// GetDatabaseProcesses returns all currently running database processes
func (pd *ProcessDetector) GetDatabaseProcesses() ([]*ProcessInfo, error) {
	var databaseProcesses []*ProcessInfo

	// Read /proc to find all processes
	procDir, err := os.Open("/proc")
	if err != nil {
		return nil, fmt.Errorf("failed to open /proc: %w", err)
	}
	defer procDir.Close()

	entries, err := procDir.Readdir(-1)
	if err != nil {
		return nil, fmt.Errorf("failed to read /proc: %w", err)
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		// Check if directory name is a PID
		if pid, err := strconv.Atoi(entry.Name()); err == nil {
			if isDB, _, err := pd.IsDatabaseProcess(pid); err == nil && isDB {
				if info, err := pd.GetProcessInfo(pid); err == nil {
					databaseProcesses = append(databaseProcesses, info)
				}
			}
		}
	}

	return databaseProcesses, nil
}

// ClearCache clears the process information cache
func (pd *ProcessDetector) ClearCache() {
	pd.mu.Lock()
	defer pd.mu.Unlock()
	pd.processCache = make(map[int]*ProcessInfo)
}

// SetCacheEnabled enables or disables process information caching
func (pd *ProcessDetector) SetCacheEnabled(enabled bool) {
	pd.mu.Lock()
	defer pd.mu.Unlock()
	pd.cacheEnabled = enabled
	if !enabled {
		pd.processCache = make(map[int]*ProcessInfo)
	}
}

// GetCacheStats returns cache statistics
func (pd *ProcessDetector) GetCacheStats() map[string]interface{} {
	pd.mu.RLock()
	defer pd.mu.RUnlock()

	return map[string]interface{}{
		"cache_enabled": pd.cacheEnabled,
		"cache_size":    len(pd.processCache),
		"default_ttl":   pd.defaultTTL,
	}
}