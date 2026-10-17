package audit

import (
	"encoding/json"
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

// ParseSeverity parses a case-insensitive severity string into a Severity constant.
func ParseSeverity(s string) (Severity, bool) {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "CRITICAL", "CRIT":
		return SeverityCritical, true
	case "HIGH":
		return SeverityHigh, true
	case "MEDIUM", "MED":
		return SeverityMedium, true
	case "LOW":
		return SeverityLow, true
	case "INFO", "INFORMATIONAL":
		return SeverityInfo, true
	default:
		return "", false
	}
}

// Finding represents a single security issue identified in the audit.
type Finding struct {
	ID              string   `json:"id"`                         // Unique identifier for the finding type (e.g. SUDO-001)
	Title           string   `json:"title"`                      // Short summary
	Description     string   `json:"description"`                // Detailed explanation
	Severity        Severity `json:"severity"`                   // CRITICAL, HIGH, etc.
	User            string   `json:"user,omitempty"`             // Affected user/group (if command spec check)
	Host            string   `json:"host,omitempty"`             // Affected host (if command spec check)
	Runas           string   `json:"runas,omitempty"`            // Target runas user/group (if command spec check)
	Command         string   `json:"command,omitempty"`          // Command path involved (if command spec check)
	Context         string   `json:"context,omitempty"`          // Location/file information if available
	Line            int      `json:"line,omitempty"`             // Line number in source policy if available
	Remediation     string   `json:"remediation"`                // How to fix the finding
	RemediationCode string   `json:"remediation_code,omitempty"` // Concrete command(s) to run or secure sudoers configuration snippet
	ExploitPoC      string   `json:"exploit_poc,omitempty"`      // Reference command illustrating the capability
	Compliance      []string `json:"compliance,omitempty"`       // Compliance references (e.g. ANSSI-BP-028, CIS)
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

// HasSeverityAtLeast checks whether any finding in the slices meets or exceeds minSeverity.
func HasSeverityAtLeast(minSeverity Severity, findingSlices ...[]Finding) bool {
	threshold := minSeverity.Order()
	for _, findings := range findingSlices {
		for _, f := range findings {
			if f.Severity.Order() <= threshold {
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

// DigestList represents one or more cryptographic digests in cvtsudoers JSON,
// which cvtsudoers serializes as a single string (when 1 digest is present) or a string slice (when >1).
type DigestList []string

// UnmarshalJSON decodes either a single JSON string or a JSON array of strings.
// When cvtsudoers outputs multiple digests of the same algorithm on a single command,
// it emits duplicate JSON keys in the same object, causing encoding/json to invoke
// UnmarshalJSON multiple times on the same DigestList field.
func (d *DigestList) UnmarshalJSON(data []byte) error {
	var single string
	if err := json.Unmarshal(data, &single); err == nil {
		if single != "" {
			*d = append(*d, single)
		}
		return nil
	}
	var slice []string
	if err := json.Unmarshal(data, &slice); err != nil {
		return err
	}
	*d = DigestList(slice)
	return nil
}

// MarshalJSON encodes a single-element DigestList as a JSON string and multiple elements as an array,
// matching the cvtsudoers JSON format.
func (d DigestList) MarshalJSON() ([]byte, error) {
	if len(d) == 1 {
		return json.Marshal(d[0])
	}
	return json.Marshal([]string(d))
}

// Member represents a user, host, runas user, runas group, or command member.
// Since cvtsudoers represents members as objects like {"username": "name"}, {"userid": 0},
// {"usergroup": "group"}, {"cmndalias": "ALIAS"}, or {"command": "path"}, this struct covers all variants.
type Member struct {
	Username     string     `json:"username,omitempty"`
	UserID       *int       `json:"userid,omitempty"`
	Usergroup    string     `json:"usergroup,omitempty"`
	UserGID      *int       `json:"usergid,omitempty"`
	NonUnixGroup string     `json:"nonunixgroup,omitempty"`
	NonUnixGID   *int       `json:"nonunixgid,omitempty"`
	Netgroup     string     `json:"netgroup,omitempty"`
	Hostname     string     `json:"hostname,omitempty"`
	NetworkAddr  string     `json:"networkaddr,omitempty"`
	Command      string     `json:"command,omitempty"`
	CommandAlias string     `json:"cmndalias,omitempty"`
	LegacyAlias  string     `json:"commandalias,omitempty"`
	UserAlias    string     `json:"useralias,omitempty"`
	RunasAlias   string     `json:"runasalias,omitempty"`
	HostAlias    string     `json:"hostalias,omitempty"`
	Negated      bool       `json:"negated,omitempty"`
	SHA224       DigestList `json:"sha224,omitempty"`
	SHA256       DigestList `json:"sha256,omitempty"`
	SHA384       DigestList `json:"sha384,omitempty"`
	SHA512       DigestList `json:"sha512,omitempty"`
	Myself       bool       `json:"-"`
	File         string     `json:"-"`
	Line         int        `json:"-"`
}

// UnmarshalJSON handles both standard cvtsudoers keys ("cmndalias", empty "username" for MYSELF)
// and legacy test fixture keys ("commandalias").
func (m *Member) UnmarshalJSON(data []byte) error {
	type rawMember Member
	var raw rawMember
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	*m = Member(raw)
	if m.CommandAlias == "" && m.LegacyAlias != "" {
		m.CommandAlias = m.LegacyAlias
	}
	m.LegacyAlias = ""

	// Detect {"username": ""} which cvtsudoers emits for MYSELF
	var rawMap map[string]json.RawMessage
	if err := json.Unmarshal(data, &rawMap); err == nil {
		if uRaw, ok := rawMap["username"]; ok {
			var uStr string
			if json.Unmarshal(uRaw, &uStr) == nil && uStr == "" {
				m.Myself = true
			}
		}
	}
	return nil
}

// HasDigests returns true if at least one cryptographic digest is attached to this member.
func (m Member) HasDigests() bool {
	return len(m.SHA224) > 0 || len(m.SHA256) > 0 || len(m.SHA384) > 0 || len(m.SHA512) > 0
}

// HasWeakDigestOnly returns true if the member uses SHA-224 without any stronger digest.
func (m Member) HasWeakDigestOnly() bool {
	return len(m.SHA224) > 0 && len(m.SHA256) == 0 && len(m.SHA384) == 0 && len(m.SHA512) == 0
}

func (m Member) rawName() string {
	if m.Username != "" {
		return m.Username
	}
	if m.Myself {
		return "MYSELF"
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
	if m.CommandAlias != "" {
		return m.CommandAlias
	}
	if m.LegacyAlias != "" {
		return m.LegacyAlias
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

// GetName returns the formatted representation of the member, including a leading "!" if negated.
func (m Member) GetName() string {
	name := m.rawName()
	if name == "" {
		return ""
	}
	if m.Negated {
		return "!" + name
	}
	return name
}

// Option represents a generic key-value flag or string default, or list operation.
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
	File      string     `json:"-"`
	Line      int        `json:"-"`
}

// DefaultBinding defines options bound to specific users, groups, hosts, or commands.
type DefaultBinding struct {
	Binding []Member `json:"Binding,omitempty"`
	Options []Option `json:"Options"`
	File    string   `json:"-"`
	Line    int      `json:"-"`
}

// SudoersPolicy represents the parsed JSON structure of a sudoers policy.
type SudoersPolicy struct {
	Defaults       []DefaultBinding    `json:"Defaults,omitempty"`
	UserAliases    map[string][]Member `json:"User_Aliases,omitempty"`
	RunasAliases   map[string][]Member `json:"Runas_Aliases,omitempty"`
	HostAliases    map[string][]Member `json:"Host_Aliases,omitempty"`
	CommandAliases map[string][]Member `json:"Command_Aliases,omitempty"`
	UserSpecs      []UserSpec          `json:"User_Specs,omitempty"`
	IncludedFiles  []string            `json:"-"`
}

// AuditResult gathers all findings from a policy audit and system checks.
type AuditResult struct {
	PolicyFindings []Finding `json:"policy_findings"`
	SystemFindings []Finding `json:"system_findings"`
	SudoVersion    string    `json:"sudo_version,omitempty"`
	Hostname       string    `json:"hostname,omitempty"`
}
