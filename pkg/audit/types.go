package audit

import (
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path"
	"slices"
	"strings"
	"time"
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
	ID                string   `json:"id"`                           // Unique identifier for the finding type (e.g. SUDO-001)
	Title             string   `json:"title"`                        // Short summary
	Description       string   `json:"description"`                  // Detailed explanation
	Severity          Severity `json:"severity"`                     // CRITICAL, HIGH, etc.
	User              string   `json:"user,omitempty"`               // Affected user/group (if command spec check)
	Host              string   `json:"host,omitempty"`               // Affected host (if command spec check)
	Runas             string   `json:"runas,omitempty"`              // Target runas user/group (if command spec check)
	Tags              string   `json:"tags,omitempty"`               // Sudoers command tags/options (e.g. "NOPASSWD: SETENV:")
	Command           string   `json:"command,omitempty"`            // Command path involved (if command spec check)
	SourceLine        string   `json:"source_line,omitempty"`        // Verbatim parsed source rule line when available
	DefaultsScope     string   `json:"defaults_scope,omitempty"`     // Explicit scoped Defaults directive prefix (e.g. "Defaults@web01", "Defaults:alice")
	InheritedDefaults string   `json:"inherited_defaults,omitempty"` // Applicable Defaults directive(s) modifying rule behavior (e.g. "Defaults !authenticate")
	Context           string   `json:"context,omitempty"`            // Location/file information if available
	Line              int      `json:"line,omitempty"`               // Line number in source policy if available
	Remediation       string   `json:"remediation"`                  // How to fix the finding
	RemediationCode   string   `json:"remediation_code,omitempty"`   // Concrete command(s) to run or secure sudoers configuration snippet
	ExploitPoC        string   `json:"exploit_poc,omitempty"`        // Reference command illustrating the capability
	Compliance        []string `json:"compliance,omitempty"`         // Compliance references (e.g. ANSSI-BP-028, CIS)
	Fingerprint       string   `json:"fingerprint,omitempty"`        // Deterministic baseline identity hash
	Exploitability    string   `json:"exploitability,omitempty"`     // "ACTIVE", "LATENT", "CONSTRAINED", "PATCHED_BACKPORT"
	Suppressed        bool     `json:"suppressed,omitempty"`         // Whether the finding was suppressed by policy config
	SuppressionReason string   `json:"suppression_reason,omitempty"` // Audit rationale when Suppressed is true
}

// AuditOptions configures optional policy-audit behaviors without altering
// default oracle-compatible RunAudit semantics.
type AuditOptions struct {
	DropInMode          bool             // Suppress global missing-Defaults rules for standalone drop-in scans
	SubcommandAwareGTFO bool             // Downgrade pinned non-interactive GTFObins subcommands
	CheckShadowing      bool             // Enable SUDO-CMD-015 last-match-wins shadowing analysis
	Now                 func() time.Time // When non-nil, enables SUDO-CMD-016 expired NOTAFTER auditing
}

// GlobalMissingDefaultRuleIDs lists Defaults audit rule IDs triggered by omitted global
// Defaults that are expected to live in /etc/sudoers rather than standalone drop-ins.
var GlobalMissingDefaultRuleIDs = map[string]bool{
	"SUDO-DEF-001": true,
	"SUDO-DEF-003": true,
	"SUDO-DEF-007": true,
	"SUDO-DEF-008": true,
	"SUDO-DEF-009": true,
	"SUDO-DEF-010": true,
	"SUDO-DEF-011": true,
	"SUDO-DEF-017": true,
}

// ComputeFingerprint computes a stable SHA-256 hex digest identifying a finding across
// line shifts and working-directory changes.
func ComputeFingerprint(f Finding) string {
	ctx := strings.ReplaceAll(strings.TrimSpace(f.Context), "\\", "/")
	baseCtx := ""
	if ctx != "" && !strings.EqualFold(ctx, "stdin") {
		baseCtx = path.Base(ctx)
	}
	payload := strings.Join([]string{
		strings.TrimSpace(f.ID),
		strings.TrimSpace(f.User),
		strings.TrimSpace(f.Host),
		strings.TrimSpace(f.Runas),
		strings.TrimSpace(f.Command),
		strings.TrimSpace(f.Title),
		baseCtx,
	}, "|")
	sum := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(sum[:])
}

// PopulateFingerprints sets Fingerprint via ComputeFingerprint on every finding that
// does not already have one assigned.
func PopulateFingerprints(findings []Finding) {
	for i := range findings {
		if findings[i].Fingerprint == "" {
			findings[i].Fingerprint = ComputeFingerprint(findings[i])
		}
	}
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

// CompareFindings defines a strict, deterministic total ordering for findings:
// highest severity first, then canonical source location, rule ID, rule attributes,
// and descriptive fields so reports are byte-for-byte reproducible regardless of input order.
func CompareFindings(a, b Finding) int {
	return cmp.Or(
		cmp.Compare(a.Severity.Order(), b.Severity.Order()),
		strings.Compare(a.Context, b.Context),
		cmp.Compare(a.Line, b.Line),
		strings.Compare(a.ID, b.ID),
		strings.Compare(a.User, b.User),
		strings.Compare(a.Host, b.Host),
		strings.Compare(a.Runas, b.Runas),
		strings.Compare(a.Tags, b.Tags),
		strings.Compare(a.Command, b.Command),
		strings.Compare(a.Title, b.Title),
		strings.Compare(a.Description, b.Description),
		strings.Compare(a.SourceLine, b.SourceLine),
		strings.Compare(a.DefaultsScope, b.DefaultsScope),
		strings.Compare(a.InheritedDefaults, b.InheritedDefaults),
		strings.Compare(a.Fingerprint, b.Fingerprint),
	)
}

// canonicalRuleTitles maps rule IDs that can have dynamic or variant per-finding titles
// to a stable, canonical rule summary shared across HTML, SARIF, and Fleet summaries.
var canonicalRuleTitles = map[string]string{
	"SUDO-GTFO-001":       "Permitted Binary in GTFObins Catalog",
	"SUDO-GTFO-002":       "Passwordless Permitted Binary in GTFObins Catalog",
	"SUDO-GTFO-003":       "Mitigated Permitted Binary in GTFObins Catalog",
	"SUDO-DEF-001":        "Missing or Empty secure_path Configuration",
	"SUDO-DEF-002":        "Dangerous Path in secure_path Configuration",
	"SUDO-DEF-003":        "Missing or Disabled use_pty",
	"SUDO-DEF-004":        "Dangerous Environment Variables Preserved (env_keep / env_check)",
	"SUDO-DEF-005":        "visiblepw Flag Enabled",
	"SUDO-DEF-006":        "pwfeedback Flag Enabled",
	"SUDO-DEF-007":        "Missing or Disabled noexec",
	"SUDO-DEF-008":        "Missing or Disabled requiretty",
	"SUDO-DEF-009":        "Missing or Weak umask Configuration",
	"SUDO-DEF-010":        "Missing or Disabled ignore_dot",
	"SUDO-DEF-011":        "Missing or Disabled env_reset",
	"SUDO-DEF-012":        "Password Authentication Disabled (!authenticate)",
	"SUDO-DEF-013":        "Environment Override Permitted (setenv)",
	"SUDO-DEF-014":        "Insecure sudoedit Symlink or Directory Configuration",
	"SUDO-DEF-015":        "Weak Sudo Authentication Timeout or Credential Cache Scope",
	"SUDO-DEF-016":        "Deprecated Chroot (runchroot) or Unrestricted Working Directory (runcwd=*)",
	"SUDO-DEF-017":        "Missing or Disabled Sudo Log File (logfile)",
	"SUDO-DEF-018":        "Non-Invoker Password Prompt Enabled (rootpw/targetpw/runaspw)",
	"SUDO-CMD-001":        "Negated Command Policy",
	"SUDO-CMD-002":        "Full Root Privileges Allowed (ALL)",
	"SUDO-CMD-003":        "Passwordless Full Root Privileges Allowed (NOPASSWD: ALL)",
	"SUDO-CMD-004":        "Wildcard in Command Definition",
	"SUDO-CMD-005":        "Passwordless Specific Command Execution Allowed (NOPASSWD)",
	"SUDO-CMD-006":        "Missing Command Argument Restrictions",
	"SUDO-CMD-007":        "Direct Text Editor Execution via Sudo",
	"SUDO-CMD-008":        "Negated User, Host, or Runas Specification",
	"SUDO-CMD-009":        "Dangerous Per-Command Option or Tag",
	"SUDO-CMD-010":        "sudoedit Permitted on Sensitive System File",
	"SUDO-CMD-011":        "Relative or Temporary/Writable Command Path",
	"SUDO-CMD-012":        "Weak Cryptographic Digest on Command (SHA-224)",
	"SUDO-CMD-013":        "Missing or Incomplete SELinux Context Elevation on Administrator Rule",
	"SUDO-CMD-014":        "Directory Execution Permitted in Sudoers",
	"SUDO-CMD-015":        "Shadowed or Overridden Sudoers Rule",
	"SUDO-CMD-016":        "Expired or Inverted Sudoers Validity Window (NOTBEFORE/NOTAFTER)",
	"SUDO-SYS-PERM-012":   "Insecure Permitted Sudo Target Executable Permissions or Ownership",
	"SUDO-SYS-PERM-013":   "Insecure Permitted Sudo Target Parent Directory Permissions or Ownership",
	"SUDO-SYS-PERM-014":   "Sudo Binary Not Restricted to Dedicated Group",
	"SUDO-SYS-ID-001":     "Nonexistent or Orphaned User/Group Referenced in Sudoers",
	"SUDO-SYS-SCRIPT-001": "Privileged Wrapper Script Uses Unsafe PATH or env Shebang",
	"SUDO-SYS-SCRIPT-002": "Privileged Wrapper Script Argument Injection Sink",
	"SUDO-SYS-SCRIPT-003": "Privileged Wrapper Script Sources Untrusted Path or Interpreter",
}

// CanonicalRuleTitle returns a stable, rule-level title for ruleID so summary
// tables and tool metadata do not vary with per-finding dynamic titles.
// Unknown rule IDs fall back to fallbackTitle.
func CanonicalRuleTitle(ruleID, fallbackTitle string) string {
	if title, ok := canonicalRuleTitles[strings.TrimSpace(ruleID)]; ok {
		return title
	}
	return strings.TrimSpace(fallbackTitle)
}

// SortFindingsBySeverity sorts findings in-place by severity (CRITICAL first)
// with deterministic tie-breakers across location, rule ID, and finding fields.
func SortFindingsBySeverity(findings []Finding) {
	slices.SortStableFunc(findings, CompareFindings)
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
	RawLine   string     `json:"-"`
}

// DefaultBinding defines options bound to specific users, groups, hosts, or commands.
type DefaultBinding struct {
	Binding []Member `json:"Binding,omitempty"`
	Options []Option `json:"Options"`
	File    string   `json:"-"`
	Line    int      `json:"-"`
	RawLine string   `json:"-"`
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
