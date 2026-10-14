package audit

import (
	"fmt"
	"slices"
	"strings"
)

// Severity represents the severity level of an audit finding.
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityInfo     Severity = "INFO"
)

// Order returns a numeric priority for severity comparison.
// Lower values indicate higher severity (CRITICAL=0, INFO=4).
func (s Severity) Order() int {
	switch s {
	case SeverityCritical:
		return 0
	case SeverityHigh:
		return 1
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 3
	case SeverityInfo:
		return 4
	default:
		return 5
	}
}

// ParseSeverity converts a case-insensitive severity string into a valid Severity constant.
func ParseSeverity(s string) (Severity, error) {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "CRITICAL", "CRIT":
		return SeverityCritical, nil
	case "HIGH":
		return SeverityHigh, nil
	case "MEDIUM", "MED":
		return SeverityMedium, nil
	case "LOW":
		return SeverityLow, nil
	case "INFO", "INFORMATIONAL":
		return SeverityInfo, nil
	default:
		return "", fmt.Errorf("invalid severity %q (expected one of: critical, high, medium, low, info)", s)
	}
}

// Finding represents a single security issue identified in the audit.
type Finding struct {
	ID          string   `json:"id"`              // Unique identifier for the finding type (e.g. SUDO-001)
	Title       string   `json:"title"`           // Short summary
	Description string   `json:"description"`     // Detailed explanation
	Severity    Severity `json:"severity"`        // CRITICAL, HIGH, etc.
	User        string   `json:"user"`            // Affected user/group (if command spec check)
	Runas       string   `json:"runas,omitempty"` // Target runas user/group (if command spec check)
	Host        string   `json:"host"`            // Affected host (if command spec check)
	Command     string   `json:"command"`         // Command path involved (if command spec check)
	Context     string   `json:"context"`         // Location/file/line information if available
	Remediation string   `json:"remediation"`     // How to fix the finding
}

// CountBySeverity returns a map of severity levels to their counts across one or more finding slices.
func CountBySeverity(findingSlices ...[]Finding) map[Severity]int {
	counts := map[Severity]int{
		SeverityCritical: 0,
		SeverityHigh:     0,
		SeverityMedium:   0,
		SeverityLow:      0,
		SeverityInfo:     0,
	}
	for _, findings := range findingSlices {
		for _, f := range findings {
			counts[f.Severity]++
		}
	}
	return counts
}

// HasFindingsAtOrAbove returns true if any finding across the provided slices has a severity
// greater than or equal to the specified threshold (e.g., threshold HIGH matches HIGH and CRITICAL).
func HasFindingsAtOrAbove(threshold Severity, findingSlices ...[]Finding) bool {
	maxOrder := threshold.Order()
	for _, findings := range findingSlices {
		for _, f := range findings {
			if f.Severity.Order() <= maxOrder {
				return true
			}
		}
	}
	return false
}

// SortFindingsBySeverity sorts findings in-place by severity (CRITICAL first).
func SortFindingsBySeverity(findings []Finding) {
	slices.SortStableFunc(findings, func(a, b Finding) int {
		return a.Severity.Order() - b.Severity.Order()
	})
}

// Member represents a user, host, runas user, runas group, or command member.
// Since cvtsudoers represents members as objects like {"username": "name"}, {"userid": 1000},
// {"usergroup": "group"}, {"cmndalias": "ALIAS"}, or {"command": "path"}, we define a unified
// structure covering all fields emitted by cvtsudoers_json.c.
type Member struct {
	Username     string `json:"username,omitempty"`
	UserID       *int   `json:"userid,omitempty"`
	Usergroup    string `json:"usergroup,omitempty"`
	UserGID      *int   `json:"usergid,omitempty"`
	NonUnixGroup string `json:"nonunixgroup,omitempty"`
	NonUnixGID   *int   `json:"nonunixgid,omitempty"`
	Netgroup     string `json:"netgroup,omitempty"`
	Hostname     string `json:"hostname,omitempty"`
	NetworkAddr  string `json:"networkaddr,omitempty"`
	Command      string `json:"command,omitempty"`
	// cvtsudoers emits "cmndalias" for command alias references (see cvtsudoers_json.c).
	// We also retain "commandalias" for backward compatibility with hand-written JSON fixtures.
	CmndAlias    string `json:"cmndalias,omitempty"`
	CommandAlias string `json:"commandalias,omitempty"`
	UserAlias    string `json:"useralias,omitempty"`
	RunasAlias   string `json:"runasalias,omitempty"`
	HostAlias    string `json:"hostalias,omitempty"`
	Negated      bool   `json:"negated,omitempty"`
	// Optional command digest fields emitted by cvtsudoers (can be a string or []string in JSON).
	SHA224 any `json:"sha224,omitempty"`
	SHA256 any `json:"sha256,omitempty"`
	SHA384 any `json:"sha384,omitempty"`
	SHA512 any `json:"sha512,omitempty"`
}

// GetCommandAlias returns the command alias name whether populated via "cmndalias" or "commandalias".
func (m Member) GetCommandAlias() string {
	if m.CmndAlias != "" {
		return m.CmndAlias
	}
	return m.CommandAlias
}

// HasDigest returns true if the command member has a cryptographic digest pinned in sudoers.
func (m Member) HasDigest() bool {
	return m.SHA224 != nil || m.SHA256 != nil || m.SHA384 != nil || m.SHA512 != nil
}

// GetName returns the human-readable principal, host, alias, or command string of the member.
func (m Member) GetName() string {
	if m.Username != "" {
		return m.Username
	}
	if m.UserID != nil {
		return fmt.Sprintf("#%d", *m.UserID)
	}
	if m.Usergroup != "" {
		return "%" + m.Usergroup
	}
	if m.UserGID != nil {
		return fmt.Sprintf("%%#%d", *m.UserGID)
	}
	if m.NonUnixGroup != "" {
		return "%:" + m.NonUnixGroup
	}
	if m.NonUnixGID != nil {
		return fmt.Sprintf("%%:#%d", *m.NonUnixGID)
	}
	if m.Netgroup != "" {
		return "+" + m.Netgroup
	}
	if m.Hostname != "" {
		return m.Hostname
	}
	if m.NetworkAddr != "" {
		return m.NetworkAddr
	}
	if m.Command != "" {
		return m.Command
	}
	if alias := m.GetCommandAlias(); alias != "" {
		return alias
	}
	if m.UserAlias != "" {
		return m.UserAlias
	}
	if m.RunasAlias != "" {
		return m.RunasAlias
	}
	if m.HostAlias != "" {
		return m.HostAlias
	}
	return ""
}

// Option represents a generic key-value flag, string/numeric default, or list operation.
type Option map[string]any

// CmndSpec contains the configuration of a command execution permission.
type CmndSpec struct {
	RunasUsers  []Member `json:"runasusers,omitempty"`
	RunasGroups []Member `json:"runasgroups,omitempty"`
	Options     []Option `json:"Options,omitempty"`  // Tags like {"authenticate": false} (NOPASSWD)
	Commands    []Member `json:"Commands,omitempty"` // Commands and aliases allowed
}

// UserSpec maps user and host bindings to a list of allowed commands (CmndSpecs).
type UserSpec struct {
	UserList  []Member   `json:"User_List"`
	HostList  []Member   `json:"Host_List"`
	CmndSpecs []CmndSpec `json:"Cmnd_Specs"`
}

// DefaultBinding defines options bound to specific users, groups, hosts, or commands.
type DefaultBinding struct {
	Binding []Member `json:"Binding,omitempty"`
	Options []Option `json:"Options"`
}

// SudoersPolicy represents the parsed JSON structure of a sudoers policy.
type SudoersPolicy struct {
	Defaults       []DefaultBinding    `json:"Defaults,omitempty"`
	UserAliases    map[string][]Member `json:"User_Aliases,omitempty"`
	RunasAliases   map[string][]Member `json:"Runas_Aliases,omitempty"`
	HostAliases    map[string][]Member `json:"Host_Aliases,omitempty"`
	CommandAliases map[string][]Member `json:"Command_Aliases,omitempty"`
	UserSpecs      []UserSpec          `json:"User_Specs,omitempty"`
}

// AuditResult gathers all findings from a policy audit and system checks.
type AuditResult struct {
	PolicyFindings []Finding `json:"policy_findings"`
	SystemFindings []Finding `json:"system_findings"`
	SudoVersion    string    `json:"sudo_version,omitempty"`
	Hostname       string    `json:"hostname,omitempty"`
}
