package config

import (
	"fmt"
	"os"
	"path"
	"slices"
	"sort"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"

	"sudo-check/pkg/audit"
)

// Suppression defines a targeted finding suppression with an audit rationale
// and an optional expiration timestamp or date.
type Suppression struct {
	Rule        string `yaml:"rule" json:"rule"`
	User        string `yaml:"user,omitempty" json:"user,omitempty"`
	Host        string `yaml:"host,omitempty" json:"host,omitempty"`
	Command     string `yaml:"command,omitempty" json:"command,omitempty"`
	Context     string `yaml:"context,omitempty" json:"context,omitempty"`
	Fingerprint string `yaml:"fingerprint,omitempty" json:"fingerprint,omitempty"`
	Reason      string `yaml:"reason" json:"reason"`
	Expires     string `yaml:"expires,omitempty" json:"expires,omitempty"` // RFC3339 or YYYY-MM-DD
}

// Config configures compliance profiles, disabled rules, severity overrides,
// scan mode flags, and expiring finding suppressions.
type Config struct {
	Profile           string                    `yaml:"profile,omitempty" json:"profile,omitempty"`
	DisableRules      []string                  `yaml:"disable_rules,omitempty" json:"disable_rules,omitempty"`
	SeverityOverrides map[string]audit.Severity `yaml:"severity_overrides,omitempty" json:"severity_overrides,omitempty"`
	DropInMode        bool                      `yaml:"dropin_mode,omitempty" json:"dropin_mode,omitempty"`
	SubcommandAware   bool                      `yaml:"subcommand_aware,omitempty" json:"subcommand_aware,omitempty"`
	CustomGTFObins    string                    `yaml:"custom_gtfobins,omitempty" json:"custom_gtfobins,omitempty"`
	Suppressions      []Suppression             `yaml:"suppressions,omitempty" json:"suppressions,omitempty"`
}

var (
	// anssiBP028Rules covers ANSSI BP-028 v2.0 recommendations R38-R44.
	anssiBP028Rules = []string{
		"SUDO-DEF-003",
		"SUDO-DEF-007",
		"SUDO-DEF-008",
		"SUDO-DEF-009",
		"SUDO-DEF-010",
		"SUDO-DEF-011",
		"SUDO-CMD-001",
		"SUDO-CMD-002",
		"SUDO-CMD-003",
		"SUDO-CMD-004",
		"SUDO-CMD-006",
		"SUDO-CMD-007",
		"SUDO-CMD-008",
		"SUDO-CMD-014",
		"SUDO-GTFO-001",
		"SUDO-GTFO-002",
		"SUDO-GTFO-003",
		"SUDO-SYS-PERM-008",
		"SUDO-SYS-PERM-009",
		"SUDO-SYS-PERM-010",
		"SUDO-SYS-PERM-014",
	}

	// cis52Rules covers CIS Linux Benchmark section 5.2 sudo controls.
	cis52Rules = []string{
		"SUDO-DEF-003",
		"SUDO-DEF-012",
		"SUDO-DEF-015",
		"SUDO-DEF-017",
		"SUDO-CMD-003",
		"SUDO-CMD-005",
		"SUDO-CMD-014",
		"SUDO-SYS-PERM-001",
		"SUDO-SYS-PERM-002",
		"SUDO-SYS-PERM-003",
		"SUDO-SYS-PERM-004",
		"SUDO-SYS-PERM-005",
		"SUDO-SYS-PERM-006",
		"SUDO-SYS-PERM-007",
		"SUDO-SYS-PERM-008",
		"SUDO-SYS-PERM-009",
		"SUDO-SYS-PERM-010",
		"SUDO-SYS-PERM-011",
		"SUDO-SYS-PERM-012",
		"SUDO-SYS-PERM-013",
	}

	// disaStigRules covers DISA STIG sudo configuration controls.
	disaStigRules = []string{
		"SUDO-DEF-012",
		"SUDO-DEF-015",
		"SUDO-DEF-018",
		"SUDO-CMD-003",
		"SUDO-CMD-005",
		"SUDO-CMD-013",
	}

	// minimalRules covers high-impact CRITICAL/HIGH privilege escalation vectors.
	minimalRules = []string{
		"SUDO-DEF-001",
		"SUDO-DEF-002",
		"SUDO-DEF-004",
		"SUDO-DEF-011",
		"SUDO-DEF-012",
		"SUDO-DEF-013",
		"SUDO-CMD-001",
		"SUDO-CMD-002",
		"SUDO-CMD-003",
		"SUDO-CMD-007",
		"SUDO-CMD-010",
		"SUDO-CMD-011",
		"SUDO-CMD-014",
		"SUDO-GTFO-001",
		"SUDO-GTFO-002",
		"SUDO-SYS-PERM-002",
		"SUDO-SYS-PERM-003",
		"SUDO-SYS-PERM-005",
		"SUDO-SYS-PERM-007",
		"SUDO-SYS-PERM-008",
		"SUDO-SYS-PERM-009",
		"SUDO-SYS-PERM-010",
		"SUDO-SYS-PERM-012",
		"SUDO-SYS-PERM-013",
		"SUDO-SYS-SCRIPT-001",
		"SUDO-SYS-SCRIPT-002",
		"SUDO-SYS-SCRIPT-003",
	}
)

// LoadFile reads a YAML or JSON configuration file from path, unmarshals it,
// normalizes and validates its fields, and returns the resulting Config.
func LoadFile(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %q: %w", path, err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config %q: %w", path, err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("validate config %q: %w", path, err)
	}

	return &cfg, nil
}

// Validate checks configuration values, normalizes severity override keys and values,
// and verifies profile names and suppression definitions.
func (c *Config) Validate() error {
	if c == nil {
		return nil
	}

	if _, err := ProfileRuleFilter(c.Profile); err != nil {
		return fmt.Errorf("invalid profile: %w", err)
	}

	if len(c.SeverityOverrides) > 0 {
		keys := make([]string, 0, len(c.SeverityOverrides))
		for k := range c.SeverityOverrides {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		normalized := make(map[string]audit.Severity, len(c.SeverityOverrides))
		for _, k := range keys {
			normKey := strings.ToUpper(strings.TrimSpace(k))
			if normKey == "" {
				return fmt.Errorf("severity_overrides contains an empty rule ID")
			}
			rawSev := c.SeverityOverrides[k]
			sev, ok := audit.ParseSeverity(string(rawSev))
			if !ok {
				return fmt.Errorf("severity_overrides[%q]: invalid severity %q", k, rawSev)
			}
			normalized[normKey] = sev
		}
		c.SeverityOverrides = normalized
	}

	for i, s := range c.Suppressions {
		if strings.TrimSpace(s.Reason) == "" {
			return fmt.Errorf("suppressions[%d]: reason must not be empty", i)
		}
		if strings.TrimSpace(s.Rule) == "" && strings.TrimSpace(s.Fingerprint) == "" {
			return fmt.Errorf("suppressions[%d]: must specify at least rule or fingerprint", i)
		}
		if exp := strings.TrimSpace(s.Expires); exp != "" {
			if _, err := parseExpiry(exp); err != nil {
				return fmt.Errorf("suppressions[%d]: %w", i, err)
			}
		}
	}

	return nil
}

// ProfileRuleFilter returns the set of enabled rule IDs for a compliance profile.
// When profile is "" or "all" (case-insensitive), nil, nil is returned to indicate
// that all rules are enabled. Unknown profile names return an error.
func ProfileRuleFilter(profile string) (map[string]bool, error) {
	switch strings.ToLower(strings.TrimSpace(profile)) {
	case "", "all":
		return nil, nil
	case "anssi-bp028":
		return toRuleSet(anssiBP028Rules), nil
	case "cis-5.2":
		return toRuleSet(cis52Rules), nil
	case "disa-stig":
		return toRuleSet(disaStigRules), nil
	case "minimal":
		return toRuleSet(minimalRules), nil
	default:
		return nil, fmt.Errorf("unknown compliance profile %q", profile)
	}
}

// Apply clones result, populates missing fingerprints, applies profile filtering,
// disabled rules, severity overrides, and active suppressions relative to now.
// Expired suppressions are returned (deduplicated) without suppressing findings.
// If now is zero, time.Now().UTC() is used.
func Apply(result *audit.AuditResult, cfg *Config, now time.Time) (filtered *audit.AuditResult, suppressed []audit.Finding, expired []Suppression) {
	if result == nil {
		return nil, nil, nil
	}

	clonedPolicy := cloneFindings(result.PolicyFindings)
	clonedSystem := cloneFindings(result.SystemFindings)
	audit.PopulateFingerprints(clonedPolicy)
	audit.PopulateFingerprints(clonedSystem)

	if cfg == nil {
		return &audit.AuditResult{
			PolicyFindings: clonedPolicy,
			SystemFindings: clonedSystem,
			SudoVersion:    result.SudoVersion,
			Hostname:       result.Hostname,
		}, nil, nil
	}

	if now.IsZero() {
		now = time.Now().UTC()
	}

	normProfile := strings.ToLower(strings.TrimSpace(cfg.Profile))
	profileSet, err := ProfileRuleFilter(normProfile)
	if err != nil {
		profileSet = nil
	}

	disabled := make(map[string]bool, len(cfg.DisableRules))
	for _, r := range cfg.DisableRules {
		if norm := strings.ToUpper(strings.TrimSpace(r)); norm != "" {
			disabled[norm] = true
		}
	}

	overrides := normalizeOverrides(cfg.SeverityOverrides)
	activeSuppressions, expired := partitionSuppressions(cfg.Suppressions, now)

	filteredPolicy, supPolicy := filterFindings(clonedPolicy, normProfile, profileSet, disabled, overrides, activeSuppressions)
	filteredSystem, supSystem := filterFindings(clonedSystem, normProfile, profileSet, disabled, overrides, activeSuppressions)

	suppressed = append(suppressed, supPolicy...)
	suppressed = append(suppressed, supSystem...)

	return &audit.AuditResult{
		PolicyFindings: filteredPolicy,
		SystemFindings: filteredSystem,
		SudoVersion:    result.SudoVersion,
		Hostname:       result.Hostname,
	}, suppressed, expired
}

func toRuleSet(ids []string) map[string]bool {
	set := make(map[string]bool, len(ids))
	for _, id := range ids {
		set[id] = true
	}
	return set
}

func cloneFindings(src []audit.Finding) []audit.Finding {
	out := make([]audit.Finding, len(src))
	for i, f := range src {
		f.Compliance = slices.Clone(f.Compliance)
		out[i] = f
	}
	return out
}

func normalizeOverrides(raw map[string]audit.Severity) map[string]audit.Severity {
	if len(raw) == 0 {
		return nil
	}
	keys := make([]string, 0, len(raw))
	for k := range raw {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	out := make(map[string]audit.Severity, len(raw))
	for _, k := range keys {
		normKey := strings.ToUpper(strings.TrimSpace(k))
		if normKey == "" {
			continue
		}
		if sev, ok := audit.ParseSeverity(string(raw[k])); ok {
			out[normKey] = sev
		}
	}
	return out
}

func parseExpiry(raw string) (time.Time, error) {
	exp := strings.TrimSpace(raw)
	if t, err := time.Parse(time.RFC3339, exp); err == nil {
		return t, nil
	}
	if t, err := time.Parse("2006-01-02", exp); err == nil {
		return time.Date(t.Year(), t.Month(), t.Day(), 23, 59, 59, 0, time.UTC), nil
	}
	return time.Time{}, fmt.Errorf("invalid expires %q (expected RFC3339 or YYYY-MM-DD)", raw)
}

func partitionSuppressions(suppressions []Suppression, now time.Time) (active []Suppression, expired []Suppression) {
	seenExpired := make(map[Suppression]bool)
	for _, s := range suppressions {
		if exp := strings.TrimSpace(s.Expires); exp != "" {
			expTime, err := parseExpiry(exp)
			if err != nil {
				continue
			}
			if expTime.Before(now) {
				if !seenExpired[s] {
					seenExpired[s] = true
					expired = append(expired, s)
				}
				continue
			}
		}
		active = append(active, s)
	}
	return active, expired
}

func filterFindings(
	findings []audit.Finding,
	normProfile string,
	profileSet map[string]bool,
	disabled map[string]bool,
	overrides map[string]audit.Severity,
	activeSuppressions []Suppression,
) (kept []audit.Finding, suppressed []audit.Finding) {
	kept = make([]audit.Finding, 0, len(findings))

	for _, f := range findings {
		normID := strings.ToUpper(strings.TrimSpace(f.ID))
		if disabled[normID] {
			continue
		}
		if !ruleAllowedByProfile(normID, f.Severity, normProfile, profileSet) {
			continue
		}
		if overrideSev, ok := overrides[normID]; ok {
			f.Severity = overrideSev
		}

		matched := false
		for _, s := range activeSuppressions {
			if matchesSuppression(f, s) {
				f.Suppressed = true
				f.SuppressionReason = s.Reason
				suppressed = append(suppressed, f)
				matched = true
				break
			}
		}
		if !matched {
			kept = append(kept, f)
		}
	}

	return kept, suppressed
}

func ruleAllowedByProfile(normID string, sev audit.Severity, normProfile string, profileSet map[string]bool) bool {
	if profileSet == nil {
		return true
	}
	if profileSet[normID] {
		return true
	}
	if normProfile == "minimal" && strings.HasPrefix(normID, "CVE-") {
		return sev == audit.SeverityCritical || sev == audit.SeverityHigh
	}
	return false
}

func matchesSuppression(f audit.Finding, s Suppression) bool {
	fp := strings.TrimSpace(s.Fingerprint)
	rule := strings.TrimSpace(s.Rule)
	if fp == "" && rule == "" {
		return false
	}
	if fp != "" && !strings.EqualFold(strings.TrimSpace(f.Fingerprint), fp) {
		return false
	}
	if rule != "" && !strings.EqualFold(strings.TrimSpace(f.ID), rule) {
		return false
	}
	if u := strings.TrimSpace(s.User); u != "" && f.User != u {
		return false
	}
	if h := strings.TrimSpace(s.Host); h != "" && f.Host != h {
		return false
	}
	if cmdPat := strings.TrimSpace(s.Command); cmdPat != "" && !matchGlobOrExact(cmdPat, f.Command) {
		return false
	}
	if ctxPat := strings.TrimSpace(s.Context); ctxPat != "" {
		normCtx := strings.ReplaceAll(f.Context, "\\", "/")
		if normCtx == "" {
			return false
		}
		normPat := strings.ReplaceAll(ctxPat, "\\", "/")
		target := normCtx
		if !strings.Contains(normPat, "/") {
			target = path.Base(normCtx)
		}
		if !matchGlobOrExact(normPat, target) {
			return false
		}
	}
	return true
}

func matchGlobOrExact(pattern, target string) bool {
	if pattern == target {
		return true
	}
	matched, err := path.Match(pattern, target)
	if err != nil {
		return false
	}
	return matched
}
