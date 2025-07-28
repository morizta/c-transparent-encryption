package policy

import (
	"context"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"takakrypt/internal/config"
)

// Engine handles policy evaluation and access control decisions
type Engine struct {
	mu           sync.RWMutex
	config       *config.Config
	guardPoints  []*GuardPoint
	compiledPatterns map[string]*regexp.Regexp
	userCache    map[string]*UserInfo
	processCache map[int]*ProcessInfo
	lastUpdate   time.Time
}

// EvaluationContext contains information for policy evaluation
type EvaluationContext struct {
	FilePath    string
	UserID      int
	GroupIDs    []int
	ProcessID   int
	ProcessName string
	ProcessPath string
	Operation   string // "read", "write", "create", "delete"
	Timestamp   time.Time
}

// EvaluationResult contains the result of policy evaluation
type EvaluationResult struct {
	Allow       bool
	Policy      *config.Policy
	PolicyV2    *config.PolicyV2  // New policy with security rules
	GuardPoint  *GuardPoint
	Reason      string
	KeyID       string
	Encrypt     bool             // Whether to encrypt the file
	Audit       bool             // Whether to audit the operation
	RuleOrder   int              // Which rule matched
	CacheHint   time.Duration
}

// GuardPoint represents a compiled guard point with cached patterns
type GuardPoint struct {
	*config.GuardPoint
	PathPattern    *regexp.Regexp
	IncludeRegexps []*regexp.Regexp
	ExcludeRegexps []*regexp.Regexp
}

// UserInfo contains cached user information
type UserInfo struct {
	UID      int
	Username string
	Groups   []string
	GIDs     []int
	HomeDir  string
	CachedAt time.Time
}

// ProcessInfo contains cached process information
type ProcessInfo struct {
	PID         int
	Name        string
	Path        string
	CommandLine []string
	UID         int
	GID         int
	CachedAt    time.Time
}

// NewEngine creates a new policy engine
func NewEngine(cfg *config.Config) (*Engine, error) {
	engine := &Engine{
		config:           cfg,
		compiledPatterns: make(map[string]*regexp.Regexp),
		userCache:        make(map[string]*UserInfo),
		processCache:     make(map[int]*ProcessInfo),
		lastUpdate:       time.Now(),
	}

	if err := engine.compileGuardPoints(); err != nil {
		return nil, fmt.Errorf("failed to compile guard points: %w", err)
	}

	return engine, nil
}

// EvaluateAccess evaluates whether access should be allowed and which policy applies
func (e *Engine) EvaluateAccess(ctx context.Context, evalCtx *EvaluationContext) (*EvaluationResult, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	// Find matching guard point
	guardPoint := e.findMatchingGuardPoint(evalCtx)
	if guardPoint == nil {
		return &EvaluationResult{
			Allow:  true,
			Reason: "file not under guard point protection",
		}, nil
	}

	// Get the policy for this guard point
	policy, exists := e.config.Policies[guardPoint.Policy]
	if !exists {
		return &EvaluationResult{
			Allow:  false,
			Reason: fmt.Sprintf("policy %s not found", guardPoint.Policy),
		}, fmt.Errorf("policy %s referenced by guard point %s not found", guardPoint.Policy, guardPoint.Name)
	}

	if !policy.Enabled {
		return &EvaluationResult{
			Allow:  true,
			Reason: "policy is disabled",
		}, nil
	}

	// Evaluate policy conditions
	result, err := e.evaluatePolicy(ctx, evalCtx, &policy, guardPoint)
	if err != nil {
		return nil, fmt.Errorf("policy evaluation failed: %w", err)
	}

	result.Policy = &policy
	result.GuardPoint = guardPoint
	
	// Generate key ID for encryption
	if result.Allow && (evalCtx.Operation == "write" || evalCtx.Operation == "create") {
		result.KeyID = e.generateKeyID(&policy, guardPoint, evalCtx)
	}

	return result, nil
}

// EvaluateAccessV2 evaluates access using ordered security rules (new implementation)
func (e *Engine) EvaluateAccessV2(ctx context.Context, evalCtx *EvaluationContext) (*EvaluationResult, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	// Find matching guard point
	guardPoint := e.findMatchingGuardPoint(evalCtx)
	if guardPoint == nil {
		return &EvaluationResult{
			Allow:  true,
			Reason: "file not under guard point protection",
		}, nil
	}

	// Check if we have a V2 policy with security rules
	policyV2 := e.findPolicyV2(guardPoint.Policy)
	if policyV2 == nil {
		// Fallback to V1 policy evaluation
		return e.EvaluateAccess(ctx, evalCtx)
	}

	if !policyV2.Enabled {
		return &EvaluationResult{
			Allow:  true,
			Reason: "policy is disabled",
		}, nil
	}

	// Create rule engine for this policy
	ruleEngine := NewRuleEngine(policyV2)
	
	// Build rule evaluation context
	ruleCtx := &RuleEvaluationContext{
		ResourcePath: evalCtx.FilePath,
		ResourceType: "file", // TODO: Detect if directory
		UserID:       evalCtx.UserID,
		ProcessName:  evalCtx.ProcessName,
		ProcessPath:  evalCtx.ProcessPath,
		ProcessID:    evalCtx.ProcessID,
		Operation:    evalCtx.Operation,
	}
	
	// Get user information
	userInfo, err := e.getUserInfo(evalCtx.UserID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}
	ruleCtx.Username = userInfo.Username
	ruleCtx.Groups = userInfo.Groups

	// Evaluate security rules
	decision, err := ruleEngine.EvaluateRules(ruleCtx, e.config)
	if err != nil {
		return nil, fmt.Errorf("rule evaluation failed: %w", err)
	}

	result := &EvaluationResult{
		Allow:      decision.Permitted,
		PolicyV2:   policyV2,
		GuardPoint: guardPoint,
		Reason:     decision.Reason,
		Encrypt:    decision.Encrypt,
		Audit:      decision.Audit,
		RuleOrder:  decision.RuleOrder,
		CacheHint:  5 * time.Minute, // Cache for 5 minutes
	}

	// Generate key ID for encryption
	if result.Allow && result.Encrypt {
		result.KeyID = e.generateKeyIDV2(policyV2, guardPoint, evalCtx)
	}

	return result, nil
}

// findPolicyV2 looks for a V2 policy (with security rules)
func (e *Engine) findPolicyV2(policyName string) *config.PolicyV2 {
	// Search through the v2 policies
	for i := range e.config.PoliciesV2 {
		if e.config.PoliciesV2[i].Name == policyName {
			return &e.config.PoliciesV2[i]
		}
	}
	return nil
}

// generateKeyIDV2 generates a key ID for V2 policies
func (e *Engine) generateKeyIDV2(policy *config.PolicyV2, gp *GuardPoint, evalCtx *EvaluationContext) string {
	return fmt.Sprintf("policy_%s_v%d_key_v%d", policy.Name, policy.Version, policy.KeyVersion)
}

// getUserInfo retrieves user information with caching
func (e *Engine) getUserInfo(uid int) (*UserInfo, error) {
	uidStr := strconv.Itoa(uid)
	
	// Check cache first
	if userInfo, exists := e.userCache[uidStr]; exists {
		// Check if cache is still valid (1 hour TTL)
		if time.Since(userInfo.CachedAt) < time.Hour {
			return userInfo, nil
		}
	}
	
	// Lookup user information
	userInfo, err := e.lookupUser(uid)
	if err != nil {
		return nil, fmt.Errorf("failed to lookup user %d: %w", uid, err)
	}
	
	// Cache the result
	e.userCache[uidStr] = userInfo
	
	return userInfo, nil
}

// lookupUser performs actual user lookup from system
func (e *Engine) lookupUser(uid int) (*UserInfo, error) {
	user, err := user.LookupId(strconv.Itoa(uid))
	if err != nil {
		return nil, err
	}
	
	// Get group information
	groups, err := user.GroupIds()
	if err != nil {
		return nil, err
	}
	
	groupNames := make([]string, 0, len(groups))
	gids := make([]int, 0, len(groups))
	
	for _, gidStr := range groups {
		if gid, err := strconv.Atoi(gidStr); err == nil {
			gids = append(gids, gid)
			
			// Note: user.LookupGroupId doesn't exist, skip group name lookup for now
			// if group, err := user.LookupGroupId(gidStr); err == nil {
			//	groupNames = append(groupNames, group.Name)
			// }
		}
	}
	
	return &UserInfo{
		UID:      uid,
		Username: user.Username,
		Groups:   groupNames,
		GIDs:     gids,
		HomeDir:  user.HomeDir,
		CachedAt: time.Now(),
	}, nil
}

// findMatchingGuardPoint finds the guard point that matches the file path
func (e *Engine) findMatchingGuardPoint(evalCtx *EvaluationContext) *GuardPoint {
	for _, gp := range e.guardPoints {
		if !gp.Enabled {
			continue
		}

		// Check if path matches guard point pattern
		if !e.pathMatches(evalCtx.FilePath, gp) {
			continue
		}

		// Check process whitelist
		if len(gp.ProcessWhitelist) > 0 {
			if !e.processInWhitelist(evalCtx.ProcessName, gp.ProcessWhitelist) {
				continue
			}
		}

		// Check include patterns
		if len(gp.IncludeRegexps) > 0 {
			fileName := filepath.Base(evalCtx.FilePath)
			if !e.matchesAnyPattern(fileName, gp.IncludeRegexps) {
				continue
			}
		}

		// Check exclude patterns
		if len(gp.ExcludeRegexps) > 0 {
			fileName := filepath.Base(evalCtx.FilePath)
			if e.matchesAnyPattern(fileName, gp.ExcludeRegexps) {
				continue
			}
		}

		return gp
	}

	return nil
}

// pathMatches checks if a file path matches a guard point path pattern
func (e *Engine) pathMatches(filePath string, gp *GuardPoint) bool {
	if gp.PathPattern != nil {
		return gp.PathPattern.MatchString(filePath)
	}

	// Fallback to proper path matching
	if gp.Recursive {
		// Ensure the file path is under the guard point path
		// Use filepath.Rel to check if the file is actually under the guard point
		rel, err := filepath.Rel(gp.Path, filePath)
		if err != nil {
			return false
		}
		// File is under guard point if rel doesn't start with ".." and isn't absolute
		return !filepath.IsAbs(rel) && rel != ".." && !strings.HasPrefix(rel, "../")
	}
	
	return filepath.Dir(filePath) == gp.Path
}

// matchesAnyPattern checks if a string matches any of the compiled patterns
func (e *Engine) matchesAnyPattern(str string, patterns []*regexp.Regexp) bool {
	for _, pattern := range patterns {
		if pattern.MatchString(str) {
			return true
		}
	}
	return false
}

// processInWhitelist checks if a process is in the whitelist
func (e *Engine) processInWhitelist(processName string, whitelist []string) bool {
	for _, allowed := range whitelist {
		if processName == allowed {
			return true
		}
		// Support wildcard matching
		if matched, _ := filepath.Match(allowed, processName); matched {
			return true
		}
	}
	return false
}

// evaluatePolicy evaluates the policy conditions
func (e *Engine) evaluatePolicy(ctx context.Context, evalCtx *EvaluationContext, policy *config.Policy, gp *GuardPoint) (*EvaluationResult, error) {
	userInfo, err := e.getUserInfo(evalCtx.UserID)
	if err != nil {
		return &EvaluationResult{
			Allow:  false,
			Reason: fmt.Sprintf("failed to get user info: %v", err),
		}, nil
	}

	processInfo, err := e.getProcessInfo(evalCtx.ProcessID)
	if err != nil {
		// Process info failure is not fatal, continue with limited info
		processInfo = &ProcessInfo{
			PID:  evalCtx.ProcessID,
			Name: evalCtx.ProcessName,
			Path: evalCtx.ProcessPath,
		}
	}

	// Evaluate user sets
	userMatch := e.evaluateUserSets(policy.UserSets, userInfo)
	
	// Evaluate process sets
	processMatch := e.evaluateProcessSets(policy.ProcessSets, processInfo)
	
	// Evaluate resource sets
	resourceMatch := e.evaluateResourceSets(policy.ResourceSets, evalCtx.FilePath)

	// Combine results based on policy logic
	var allow bool
	var reason string

	if policy.RequireAllSets {
		// All specified sets must match
		allow = true
		reasons := []string{}

		if len(policy.UserSets) > 0 && !userMatch {
			allow = false
			reasons = append(reasons, "user not in required user sets")
		}
		if len(policy.ProcessSets) > 0 && !processMatch {
			allow = false
			reasons = append(reasons, "process not in required process sets")
		}
		if len(policy.ResourceSets) > 0 && !resourceMatch {
			allow = false
			reasons = append(reasons, "resource not in required resource sets")
		}

		if allow {
			reason = "all required policy conditions met"
		} else {
			reason = strings.Join(reasons, ", ")
		}
	} else {
		// At least one set must match (OR logic)
		allow = userMatch || processMatch || resourceMatch
		
		if allow {
			reasons := []string{}
			if userMatch {
				reasons = append(reasons, "user set match")
			}
			if processMatch {
				reasons = append(reasons, "process set match")
			}
			if resourceMatch {
				reasons = append(reasons, "resource set match")
			}
			reason = "policy conditions met: " + strings.Join(reasons, ", ")
		} else {
			reason = "no policy conditions matched"
		}
	}

	return &EvaluationResult{
		Allow:     allow,
		Reason:    reason,
		CacheHint: 5 * time.Minute, // Cache policy decisions
	}, nil
}

// evaluateUserSets checks if user matches any of the specified user sets
func (e *Engine) evaluateUserSets(userSets []string, userInfo *UserInfo) bool {
	if len(userSets) == 0 {
		return true // No user restrictions
	}

	for _, setName := range userSets {
		userSet, exists := e.config.UserSets[setName]
		if !exists {
			continue
		}

		// Check username
		for _, username := range userSet.Users {
			if userInfo.Username == username {
				return true
			}
		}

		// Check groups
		for _, group := range userSet.Groups {
			for _, userGroup := range userInfo.Groups {
				if userGroup == group {
					return true
				}
			}
		}

		// Check UIDs
		for _, uid := range userSet.UIDs {
			if userInfo.UID == uid {
				return true
			}
		}
	}

	return false
}

// evaluateProcessSets checks if process matches any of the specified process sets
func (e *Engine) evaluateProcessSets(processSets []string, processInfo *ProcessInfo) bool {
	if len(processSets) == 0 {
		return true // No process restrictions
	}

	for _, setName := range processSets {
		processSet, exists := e.config.ProcessSets[setName]
		if !exists {
			continue
		}

		// Check process names
		for _, processName := range processSet.Processes {
			if processInfo.Name == processName {
				return true
			}
			// Support wildcard matching
			if matched, _ := filepath.Match(processName, processInfo.Name); matched {
				return true
			}
		}

		// Check process paths
		for _, processPath := range processSet.ProcessPaths {
			if strings.HasPrefix(processInfo.Path, processPath) {
				return true
			}
			if matched, _ := filepath.Match(processPath, processInfo.Path); matched {
				return true
			}
		}

		// Check PIDs
		for _, pid := range processSet.PIDs {
			if processInfo.PID == pid {
				return true
			}
		}
	}

	return false
}

// evaluateResourceSets checks if file matches any of the specified resource sets
func (e *Engine) evaluateResourceSets(resourceSets []string, filePath string) bool {
	if len(resourceSets) == 0 {
		return true // No resource restrictions
	}

	fileName := filepath.Base(filePath)
	fileExt := strings.ToLower(filepath.Ext(filePath))

	for _, setName := range resourceSets {
		resourceSet, exists := e.config.ResourceSets[setName]
		if !exists {
			continue
		}

		// Check file patterns
		for _, pattern := range resourceSet.FilePatterns {
			if regex, exists := e.compiledPatterns[pattern]; exists {
				if regex.MatchString(fileName) || regex.MatchString(filePath) {
					return true
				}
			}
		}

		// Check directories
		for _, dir := range resourceSet.Directories {
			if strings.HasPrefix(filePath, dir) {
				return true
			}
		}

		// Check extensions
		for _, ext := range resourceSet.Extensions {
			if strings.ToLower(ext) == fileExt {
				return true
			}
		}

		// MIME type checking would require file content analysis
		// For now, we'll skip MIME type evaluation
	}

	return false
}

// getUserInfoV2 retrieves and caches user information (renamed to avoid conflict)
func (e *Engine) getUserInfoV2(uid int) (*UserInfo, error) {
	uidStr := strconv.Itoa(uid)
	
	// Check cache
	if userInfo, exists := e.userCache[uidStr]; exists {
		if time.Since(userInfo.CachedAt) < 5*time.Minute {
			return userInfo, nil
		}
	}

	// Lookup user information
	userInfo, err := e.lookupUserInfo(uid)
	if err != nil {
		return nil, err
	}

	// Cache the result
	e.userCache[uidStr] = userInfo
	return userInfo, nil
}

// lookupUserInfo looks up user information from the system
func (e *Engine) lookupUserInfo(uid int) (*UserInfo, error) {
	u, err := user.LookupId(strconv.Itoa(uid))
	if err != nil {
		return nil, fmt.Errorf("failed to lookup user %d: %w", uid, err)
	}

	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		return nil, fmt.Errorf("invalid GID %s for user %d: %w", u.Gid, uid, err)
	}

	// Get group memberships (simplified - in production use proper group lookup)
	groups := []string{}
	gids := []int{gid}

	return &UserInfo{
		UID:      uid,
		Username: u.Username,
		Groups:   groups,
		GIDs:     gids,
		HomeDir:  u.HomeDir,
		CachedAt: time.Now(),
	}, nil
}

// getProcessInfo retrieves and caches process information
func (e *Engine) getProcessInfo(pid int) (*ProcessInfo, error) {
	// Check cache
	if processInfo, exists := e.processCache[pid]; exists {
		if time.Since(processInfo.CachedAt) < 1*time.Minute {
			return processInfo, nil
		}
	}

	// Lookup process information
	processInfo, err := e.lookupProcessInfo(pid)
	if err != nil {
		return nil, err
	}

	// Cache the result
	e.processCache[pid] = processInfo
	return processInfo, nil
}

// lookupProcessInfo looks up process information from the system
func (e *Engine) lookupProcessInfo(pid int) (*ProcessInfo, error) {
	// Read from /proc/pid/... on Linux systems
	commPath := fmt.Sprintf("/proc/%d/comm", pid)
	comm, err := os.ReadFile(commPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read process name: %w", err)
	}

	exePath := fmt.Sprintf("/proc/%d/exe", pid)
	exe, err := os.Readlink(exePath)
	if err != nil {
		// Non-fatal, exe might not be accessible
		exe = "unknown"
	}

	return &ProcessInfo{
		PID:      pid,
		Name:     strings.TrimSpace(string(comm)),
		Path:     exe,
		CachedAt: time.Now(),
	}, nil
}

// generateKeyID generates a key ID for encryption
func (e *Engine) generateKeyID(policy *config.Policy, gp *GuardPoint, evalCtx *EvaluationContext) string {
	// Generate key ID based on policy and context
	return fmt.Sprintf("%s_%s_%d", policy.Name, gp.Name, time.Now().Unix()/3600) // Hourly key rotation
}

// compileGuardPoints compiles guard point patterns for efficient matching
func (e *Engine) compileGuardPoints() error {
	e.guardPoints = make([]*GuardPoint, len(e.config.GuardPoints))

	for i, gp := range e.config.GuardPoints {
		// Create a copy to avoid the loop variable pointer issue
		gpCopy := gp
		compiledGP := &GuardPoint{GuardPoint: &gpCopy}

		// Compile path pattern
		if strings.Contains(gp.Path, "*") {
			pathPattern := strings.ReplaceAll(gp.Path, "*", ".*")
			if compiled, err := regexp.Compile(pathPattern); err == nil {
				compiledGP.PathPattern = compiled
			}
		}

		// Compile include patterns
		for _, pattern := range gp.IncludePatterns {
			if compiled, err := regexp.Compile(globToRegex(pattern)); err == nil {
				compiledGP.IncludeRegexps = append(compiledGP.IncludeRegexps, compiled)
				e.compiledPatterns[pattern] = compiled
			}
		}

		// Compile exclude patterns
		for _, pattern := range gp.ExcludePatterns {
			if compiled, err := regexp.Compile(globToRegex(pattern)); err == nil {
				compiledGP.ExcludeRegexps = append(compiledGP.ExcludeRegexps, compiled)
				e.compiledPatterns[pattern] = compiled
			}
		}

		e.guardPoints[i] = compiledGP
	}

	// Compile resource set patterns
	for _, resourceSet := range e.config.ResourceSets {
		for _, pattern := range resourceSet.FilePatterns {
			if _, exists := e.compiledPatterns[pattern]; !exists {
				if compiled, err := regexp.Compile(pattern); err == nil {
					e.compiledPatterns[pattern] = compiled
				}
			}
		}
	}

	return nil
}

// globToRegex converts a glob pattern to a regular expression
func globToRegex(glob string) string {
	regex := strings.ReplaceAll(glob, ".", "\\.")
	regex = strings.ReplaceAll(regex, "*", ".*")
	regex = strings.ReplaceAll(regex, "?", ".")
	return "^" + regex + "$"
}

// UpdateConfiguration updates the policy engine configuration
func (e *Engine) UpdateConfiguration(cfg *config.Config) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.config = cfg
	e.lastUpdate = time.Now()
	
	// Clear caches to force refresh
	e.userCache = make(map[string]*UserInfo)
	e.processCache = make(map[int]*ProcessInfo)
	e.compiledPatterns = make(map[string]*regexp.Regexp)

	return e.compileGuardPoints()
}

// GetConfig returns the current configuration
func (e *Engine) GetConfig() *config.Config {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.config
}

// GetStatistics returns policy engine statistics
func (e *Engine) GetStatistics() map[string]interface{} {
	e.mu.RLock()
	defer e.mu.RUnlock()

	return map[string]interface{}{
		"guard_points_count":    len(e.guardPoints),
		"policies_count":        len(e.config.Policies),
		"user_cache_size":       len(e.userCache),
		"process_cache_size":    len(e.processCache),
		"compiled_patterns":     len(e.compiledPatterns),
		"last_update":          e.lastUpdate,
	}
}

// GetGuardPoints returns the current guard points configuration
func (e *Engine) GetGuardPoints() []*GuardPoint {
	e.mu.RLock()
	defer e.mu.RUnlock()
	
	// Return a copy to prevent external modification
	guardPoints := make([]*GuardPoint, len(e.guardPoints))
	copy(guardPoints, e.guardPoints)
	return guardPoints
}

// Enhanced logging enabled
