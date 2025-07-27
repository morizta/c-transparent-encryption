package config

import "time"

// SecurityRule represents an ordered security rule in a policy
// Based on Thales CTE analysis - rules are evaluated in order with first match wins
type SecurityRule struct {
	Order        int      `yaml:"order"`         // Rule evaluation order (1, 2, 3...)
	ResourceSet  string   `yaml:"resource_set"`  // Resource set name (or empty for all)
	UserSet      string   `yaml:"user_set"`      // User set name (or empty for all)
	ProcessSet   string   `yaml:"process_set"`   // Process set name (or empty for all)
	Actions      []string `yaml:"actions"`       // Actions: read, write, all_ops, key_op, f_rd, f_wr, etc.
	Effects      []string `yaml:"effects"`       // Effects: permit, deny, audit, applykey
	Browsing     bool     `yaml:"browsing"`      // Allow directory browsing
	Description  string   `yaml:"description"`   // Rule description
}

// PolicyV2 extends Policy with ordered security rules
type PolicyV2 struct {
	Name                string          `yaml:"name"`
	Type                string          `yaml:"type"`                    // "live_data_transformation" or "standard"
	Algorithm           string          `yaml:"algorithm"`
	KeySize             int             `yaml:"key_size"`
	SecurityRules       []SecurityRule  `yaml:"security_rules"`          // Ordered rules
	KeyRotationInterval time.Duration   `yaml:"key_rotation_interval"`
	AuditLevel          string          `yaml:"audit_level"`
	Enabled             bool            `yaml:"enabled"`
	Version             int             `yaml:"version"`
	KeyVersion          int             `yaml:"key_version"`
}

// Action constants based on Thales CTE analysis
const (
	// Basic actions
	ACTION_READ     = "read"
	ACTION_WRITE    = "write"
	ACTION_ALL_OPS  = "all_ops"
	ACTION_KEY_OP   = "key_op"
	
	// File operations
	ACTION_F_RD      = "f_rd"      // Read file
	ACTION_F_WR      = "f_wr"      // Write file
	ACTION_F_WR_APP  = "f_wr_app"  // Write file (append)
	ACTION_F_CRE     = "f_cre"     // Create file
	ACTION_F_REN     = "f_ren"     // Rename file
	ACTION_F_LINK    = "f_link"    // Link file
	ACTION_F_RM      = "f_rm"      // Remove file
	ACTION_F_RD_ATT  = "f_rd_att"  // Read file attributes
	ACTION_F_CHG_ATT = "f_chg_att" // Change file attributes
	ACTION_F_RD_SEC  = "f_rd_sec"  // Read file security
	ACTION_F_CHG_SEC = "f_chg_sec" // Change file security
	
	// Directory operations
	ACTION_D_RD      = "d_rd"      // Read directory
	ACTION_D_REN     = "d_ren"     // Rename directory
	ACTION_D_RD_ATT  = "d_rd_att"  // Read directory attributes
	ACTION_D_CHG_ATT = "d_chg_att" // Change directory attributes
	ACTION_D_RD_SEC  = "d_rd_sec"  // Read directory security
	ACTION_D_CHG_SEC = "d_chg_sec" // Change directory security
	ACTION_D_MKDIR   = "d_mkdir"   // Make directory
	ACTION_D_RMDIR   = "d_rmdir"   // Remove directory
)

// Effect constants
const (
	EFFECT_PERMIT   = "permit"   // Allow the operation
	EFFECT_DENY     = "deny"     // Deny the operation
	EFFECT_AUDIT    = "audit"    // Log the operation
	EFFECT_APPLYKEY = "applykey" // Apply encryption/decryption
)

// ActionMapping maps kernel operations to granular actions
var ActionMapping = map[string][]string{
	"open_read":    {ACTION_F_RD, ACTION_READ},
	"open_write":   {ACTION_F_WR, ACTION_WRITE},
	"create":       {ACTION_F_CRE, ACTION_WRITE},
	"unlink":       {ACTION_F_RM},
	"rename":       {ACTION_F_REN},
	"mkdir":        {ACTION_D_MKDIR},
	"rmdir":        {ACTION_D_RMDIR},
	"readdir":      {ACTION_D_RD},
	"getattr":      {ACTION_F_RD_ATT},
	"setattr":      {ACTION_F_CHG_ATT},
	"link":         {ACTION_F_LINK},
}

// IsActionAllowed checks if a specific action is allowed by the rule
func (r *SecurityRule) IsActionAllowed(action string) bool {
	for _, a := range r.Actions {
		if a == action || a == ACTION_ALL_OPS {
			return true
		}
	}
	return false
}

// HasEffect checks if a rule has a specific effect
func (r *SecurityRule) HasEffect(effect string) bool {
	for _, e := range r.Effects {
		if e == effect {
			return true
		}
	}
	return false
}

// ShouldEncrypt returns true if the rule requires encryption
func (r *SecurityRule) ShouldEncrypt() bool {
	return r.HasEffect(EFFECT_APPLYKEY)
}

// ShouldAudit returns true if the rule requires audit logging
func (r *SecurityRule) ShouldAudit() bool {
	return r.HasEffect(EFFECT_AUDIT)
}

// IsPermitted returns true if the rule permits the action
func (r *SecurityRule) IsPermitted() bool {
	return r.HasEffect(EFFECT_PERMIT)
}