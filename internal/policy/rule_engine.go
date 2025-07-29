package policy

import (
	"fmt"
	"path/filepath" 
	"sort"
	"strings"
	
	"takakrypt/internal/config"
)

// RuleEngine handles ordered security rule evaluation
type RuleEngine struct {
	rules []config.SecurityRule
}

// NewRuleEngine creates a new rule engine from a policy
func NewRuleEngine(policy *config.PolicyV2) *RuleEngine {
	// Copy and sort rules by order
	rules := make([]config.SecurityRule, len(policy.SecurityRules))
	copy(rules, policy.SecurityRules)
	
	sort.Slice(rules, func(i, j int) bool {
		return rules[i].Order < rules[j].Order
	})
	
	return &RuleEngine{
		rules: rules,
	}
}

// RuleEvaluationContext contains all information needed for rule evaluation
type RuleEvaluationContext struct {
	// Resource information
	ResourcePath string
	ResourceType string // "file" or "directory"
	
	// User information
	UserID       int
	Username     string
	Groups       []string
	
	// Process information
	ProcessName  string
	ProcessPath  string
	ProcessID    int
	
	// Operation information
	Operation    string   // Kernel operation (open_read, create, etc.)
	Actions      []string // Mapped granular actions
}

// RuleDecision represents the result of rule evaluation
type RuleDecision struct {
	Matched      bool
	RuleOrder    int
	Permitted    bool
	Encrypt      bool
	Audit        bool
	AllowBrowse  bool
	Reason       string
}

// EvaluateRules evaluates all rules in order and returns the first match
func (re *RuleEngine) EvaluateRules(ctx *RuleEvaluationContext, config *config.Config) (*RuleDecision, error) {
	// Map kernel operation to granular actions
	if ctx.Actions == nil {
		ctx.Actions = mapOperationToActions(ctx.Operation)
	}
	
	// Evaluate each rule in order
	for _, rule := range re.rules {
		matched, err := re.evaluateRule(&rule, ctx, config)
		if err != nil {
			return nil, fmt.Errorf("error evaluating rule %d: %w", rule.Order, err)
		}
		
		if matched {
			// First match wins - return decision
			decision := &RuleDecision{
				Matched:     true,
				RuleOrder:   rule.Order,
				Permitted:   rule.IsPermitted(),
				Encrypt:     rule.ShouldEncrypt(),
				Audit:       rule.ShouldAudit(),
				AllowBrowse: rule.Browsing,
				Reason:      fmt.Sprintf("Matched rule %d: %s", rule.Order, rule.Description),
			}
			
			// Check if any required action is allowed
			actionAllowed := false
			for _, action := range ctx.Actions {
				if rule.IsActionAllowed(action) {
					actionAllowed = true
					break
				}
			}
			
			// If action not explicitly allowed, deny
			if !actionAllowed && !rule.IsActionAllowed("all_ops") {
				decision.Permitted = false
				decision.Reason = fmt.Sprintf("Rule %d: Action '%s' not allowed", rule.Order, ctx.Operation)
			}
			
			return decision, nil
		}
	}
	
	// No rule matched - default deny
	return &RuleDecision{
		Matched:   false,
		Permitted: false,
		Reason:    "No matching rule found - default deny",
	}, nil
}

// evaluateRule checks if a single rule matches the context
func (re *RuleEngine) evaluateRule(rule *config.SecurityRule, ctx *RuleEvaluationContext, cfg *config.Config) (bool, error) {
	// Check resource set
	if rule.ResourceSet != "" {
		resourceSet, exists := cfg.ResourceSets[rule.ResourceSet]
		if !exists {
			return false, fmt.Errorf("resource set '%s' not found", rule.ResourceSet)
		}
		
		if !matchesResourceSet(ctx.ResourcePath, &resourceSet) {
			return false, nil
		}
	}
	
	// Check user set
	if rule.UserSet != "" {
		userSet, exists := cfg.UserSets[rule.UserSet]
		if !exists {
			return false, fmt.Errorf("user set '%s' not found", rule.UserSet)
		}
		
		if !matchesUserSet(ctx, &userSet) {
			return false, nil
		}
	}
	
	// Check process set
	if rule.ProcessSet != "" {
		processSet, exists := cfg.ProcessSets[rule.ProcessSet]
		if !exists {
			return false, fmt.Errorf("process set '%s' not found", rule.ProcessSet)
		}
		
		if !matchesProcessSet(ctx, &processSet) {
			return false, nil
		}
	}
	
	// All conditions match
	return true, nil
}

// matchesResourceSet checks if a resource path matches a resource set
func matchesResourceSet(path string, set *config.ResourceSet) bool {
	// Check file patterns
	for _, pattern := range set.FilePatterns {
		if matchesPattern(path, pattern) {
			return true
		}
	}
	
	// Check directories
	for _, dir := range set.Directories {
		if strings.HasPrefix(path, dir) {
			return true
		}
	}
	
	// Check extensions
	for _, ext := range set.Extensions {
		if strings.HasSuffix(path, ext) {
			return true
		}
	}
	
	return false
}

// matchesUserSet checks if user context matches a user set
func matchesUserSet(ctx *RuleEvaluationContext, set *config.UserSet) bool {
	// Check username
	for _, user := range set.Users {
		if ctx.Username == user {
			return true
		}
	}
	
	// Check UIDs
	for _, uid := range set.UIDs {
		if ctx.UserID == uid {
			return true
		}
	}
	
	// Check groups
	for _, group := range set.Groups {
		for _, userGroup := range ctx.Groups {
			if group == userGroup {
				return true
			}
		}
	}
	
	return false
}

// matchesProcessSet checks if process context matches a process set
func matchesProcessSet(ctx *RuleEvaluationContext, set *config.ProcessSet) bool {
	// Use the sophisticated process matching from process package
	// This includes pattern matching, wildcards, and substring matching
	
	// Create a ProcessInfo-like structure for compatibility
	processInfo := &ProcessInfo{
		PID:  ctx.ProcessID,
		Name: ctx.ProcessName,
		Path: ctx.ProcessPath,
	}
	
	// Check process names with pattern matching
	for _, processName := range set.Processes {
		if matchesProcessName(processInfo, processName) {
			return true
		}
	}
	
	// Check process paths with pattern matching  
	for _, processPath := range set.ProcessPaths {
		if matchesProcessPath(processInfo, processPath) {
			return true
		}
	}
	
	// Check PIDs (exact match)
	for _, pid := range set.PIDs {
		if ctx.ProcessID == pid {
			return true
		}
	}
	
	// Empty set matches all processes
	if len(set.Processes) == 0 && len(set.ProcessPaths) == 0 && len(set.PIDs) == 0 {
		return true
	}
	
	return false
}


// matchesProcessName checks if process name matches pattern (from process/sets.go)
func matchesProcessName(processInfo *ProcessInfo, pattern string) bool {
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

// matchesProcessPath checks if process path matches pattern (from process/sets.go)
func matchesProcessPath(processInfo *ProcessInfo, pattern string) bool {
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

// matchesPattern checks if a path matches a pattern (supports wildcards)
func matchesPattern(path, pattern string) bool {
	// Simple wildcard matching - can be enhanced with glob or regex
	if pattern == "*" {
		return true
	}
	
	// Convert simple wildcards to regex-like matching
	pattern = strings.ReplaceAll(pattern, "*", ".*")
	pattern = "^" + pattern + "$"
	
	// For now, use simple string matching
	// TODO: Compile to regex for better performance
	if strings.Contains(pattern, ".*") {
		// Handle wildcard patterns
		parts := strings.Split(pattern, ".*")
		if len(parts) == 2 {
			// Pattern like "*.txt" or "prefix*"
			prefix := strings.TrimPrefix(parts[0], "^")
			suffix := strings.TrimSuffix(parts[1], "$")
			
			if prefix == "" && suffix != "" {
				// Pattern like "*.txt"
				return strings.HasSuffix(path, suffix)
			} else if prefix != "" && suffix == "" {
				// Pattern like "prefix*"
				return strings.HasPrefix(path, prefix)
			}
		}
	}
	
	// Exact match
	return path == strings.Trim(pattern, "^$")
}

// mapOperationToActions maps kernel operations to granular actions
func mapOperationToActions(operation string) []string {
	if actions, exists := config.ActionMapping[operation]; exists {
		return actions
	}
	
	// Default mapping for unknown operations
	switch {
	case strings.Contains(operation, "read"):
		return []string{config.ACTION_READ, config.ACTION_F_RD}
	case strings.Contains(operation, "write"):
		return []string{config.ACTION_WRITE, config.ACTION_F_WR}
	default:
		return []string{operation}
	}
}// Enhanced logging enabled
