package config

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"sudo-check/pkg/audit"
)

func TestLoadFile_YAMLAndJSON(t *testing.T) {
	dir := t.TempDir()

	yamlPath := filepath.Join(dir, "sudo-check.yaml")
	yamlContent := `
profile: ANSSI-BP028
disable_rules:
  - SUDO-DEF-005
  - sudo-cmd-008
severity_overrides:
  sudo-def-003: low
  SUDO-CMD-003: crit
dropin_mode: true
subcommand_aware: true
custom_gtfobins: /opt/custom-gtfobins.json
suppressions:
  - rule: SUDO-CMD-001
    user: deploy
    host: ALL
    command: /usr/bin/*
    context: 10-deploy
    reason: Approved deployment automation
    expires: 2027-01-15
  - fingerprint: deadbeef1234
    reason: Ticket SEC-42
    expires: "2027-02-01T12:00:00Z"
`
	if err := os.WriteFile(yamlPath, []byte(yamlContent), 0600); err != nil {
		t.Fatalf("write yaml: %v", err)
	}

	cfg, err := LoadFile(yamlPath)
	if err != nil {
		t.Fatalf("LoadFile(yaml) failed: %v", err)
	}
	if cfg.Profile != "ANSSI-BP028" {
		t.Fatalf("expected Profile ANSSI-BP028, got %q", cfg.Profile)
	}
	if !cfg.DropInMode || !cfg.SubcommandAware || cfg.CustomGTFObins != "/opt/custom-gtfobins.json" {
		t.Fatalf("unexpected boolean/string flags: %+v", cfg)
	}
	if cfg.SeverityOverrides["SUDO-DEF-003"] != audit.SeverityLow {
		t.Fatalf("expected normalized SUDO-DEF-003=LOW, got %q", cfg.SeverityOverrides["SUDO-DEF-003"])
	}
	if cfg.SeverityOverrides["SUDO-CMD-003"] != audit.SeverityCritical {
		t.Fatalf("expected normalized SUDO-CMD-003=CRITICAL, got %q", cfg.SeverityOverrides["SUDO-CMD-003"])
	}
	if len(cfg.Suppressions) != 2 || cfg.Suppressions[0].Expires != "2027-01-15" {
		t.Fatalf("unexpected suppressions parsed: %+v", cfg.Suppressions)
	}

	jsonPath := filepath.Join(dir, "sudo-check.json")
	jsonContent := `{
  "profile": "cis-5.2",
  "disable_rules": ["SUDO-DEF-012"],
  "severity_overrides": {
    "sudo-def-015": "med"
  },
  "suppressions": [
    {
      "rule": "SUDO-CMD-005",
      "reason": "Legacy service account",
      "expires": "2026-12-31T23:59:59Z"
    }
  ]
}`
	if err := os.WriteFile(jsonPath, []byte(jsonContent), 0600); err != nil {
		t.Fatalf("write json: %v", err)
	}

	jcfg, err := LoadFile(jsonPath)
	if err != nil {
		t.Fatalf("LoadFile(json) failed: %v", err)
	}
	if jcfg.Profile != "cis-5.2" {
		t.Fatalf("expected Profile cis-5.2, got %q", jcfg.Profile)
	}
	if jcfg.SeverityOverrides["SUDO-DEF-015"] != audit.SeverityMedium {
		t.Fatalf("expected normalized SUDO-DEF-015=MEDIUM, got %q", jcfg.SeverityOverrides["SUDO-DEF-015"])
	}

	emptyPath := filepath.Join(dir, "empty.yaml")
	if err := os.WriteFile(emptyPath, []byte("# comment only\n"), 0600); err != nil {
		t.Fatalf("write empty yaml: %v", err)
	}
	ecfg, err := LoadFile(emptyPath)
	if err != nil {
		t.Fatalf("LoadFile(empty) failed: %v", err)
	}
	if ecfg.Profile != "" || len(ecfg.Suppressions) != 0 {
		t.Fatalf("expected zero config for empty file, got %+v", ecfg)
	}
}

func TestLoadFile_Errors(t *testing.T) {
	dir := t.TempDir()

	_, err := LoadFile(filepath.Join(dir, "missing.yaml"))
	if err == nil || !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected wrapped os.ErrNotExist, got %v", err)
	}

	badYAML := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(badYAML, []byte("profile: [\nunclosed"), 0600); err != nil {
		t.Fatalf("write bad yaml: %v", err)
	}
	if _, err := LoadFile(badYAML); err == nil {
		t.Fatal("expected parse error for malformed YAML")
	}

	invalidCfg := filepath.Join(dir, "invalid-profile.yaml")
	if err := os.WriteFile(invalidCfg, []byte("profile: nonexistent\n"), 0600); err != nil {
		t.Fatalf("write invalid profile yaml: %v", err)
	}
	if _, err := LoadFile(invalidCfg); err == nil {
		t.Fatal("expected validation error for unknown profile")
	}
}

func TestConfigValidate(t *testing.T) {
	var nilCfg *Config
	if err := nilCfg.Validate(); err != nil {
		t.Fatalf("nil Config.Validate() should succeed, got %v", err)
	}

	emptyCfg := &Config{}
	if err := emptyCfg.Validate(); err != nil {
		t.Fatalf("empty Config.Validate() should succeed, got %v", err)
	}

	tests := []struct {
		name    string
		cfg     Config
		wantErr bool
	}{
		{
			name: "valid full config",
			cfg: Config{
				Profile: "minimal",
				SeverityOverrides: map[string]audit.Severity{
					" sudo-def-001 ": "informational",
				},
				Suppressions: []Suppression{
					{Rule: "SUDO-DEF-001", Reason: "ok", Expires: "2026-11-20"},
					{Fingerprint: "abc123", Reason: "ok", Expires: "2026-11-20T15:04:05+02:00"},
				},
			},
		},
		{
			name:    "unknown profile",
			cfg:     Config{Profile: "pci-dss"},
			wantErr: true,
		},
		{
			name: "empty severity override key",
			cfg: Config{
				SeverityOverrides: map[string]audit.Severity{"   ": audit.SeverityHigh},
			},
			wantErr: true,
		},
		{
			name: "invalid severity override value",
			cfg: Config{
				SeverityOverrides: map[string]audit.Severity{"SUDO-DEF-001": "EXTREME"},
			},
			wantErr: true,
		},
		{
			name: "suppression missing reason",
			cfg: Config{
				Suppressions: []Suppression{{Rule: "SUDO-DEF-001", Reason: "   "}},
			},
			wantErr: true,
		},
		{
			name: "suppression missing rule and fingerprint",
			cfg: Config{
				Suppressions: []Suppression{{User: "alice", Reason: "needed"}},
			},
			wantErr: true,
		},
		{
			name: "suppression invalid expiry",
			cfg: Config{
				Suppressions: []Suppression{{Rule: "SUDO-DEF-001", Reason: "needed", Expires: "11/20/2026"}},
			},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.Validate()
			if tc.wantErr && err == nil {
				t.Fatal("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}

	normCfg := &Config{
		SeverityOverrides: map[string]audit.Severity{
			"sudo-def-001": "med",
		},
	}
	if err := normCfg.Validate(); err != nil {
		t.Fatalf("Validate failed: %v", err)
	}
	if _, exists := normCfg.SeverityOverrides["sudo-def-001"]; exists {
		t.Fatal("expected lowercase key to be replaced with normalized uppercase key")
	}
	if got := normCfg.SeverityOverrides["SUDO-DEF-001"]; got != audit.SeverityMedium {
		t.Fatalf("expected SeverityMedium, got %q", got)
	}
}

func TestProfileRuleFilter(t *testing.T) {
	for _, p := range []string{"", "all", " ALL "} {
		set, err := ProfileRuleFilter(p)
		if err != nil {
			t.Fatalf("ProfileRuleFilter(%q) error: %v", p, err)
		}
		if set != nil {
			t.Fatalf("ProfileRuleFilter(%q) expected nil map, got %v", p, set)
		}
	}

	expected := map[string][]string{
		"anssi-bp028": {
			"SUDO-DEF-003", "SUDO-DEF-007", "SUDO-DEF-008", "SUDO-DEF-009", "SUDO-DEF-010", "SUDO-DEF-011",
			"SUDO-CMD-001", "SUDO-CMD-002", "SUDO-CMD-003", "SUDO-CMD-004", "SUDO-CMD-006", "SUDO-CMD-007",
			"SUDO-CMD-008", "SUDO-CMD-014", "SUDO-GTFO-001", "SUDO-GTFO-002", "SUDO-GTFO-003",
			"SUDO-SYS-PERM-008", "SUDO-SYS-PERM-009", "SUDO-SYS-PERM-010", "SUDO-SYS-PERM-014",
		},
		"cis-5.2": {
			"SUDO-DEF-003", "SUDO-DEF-012", "SUDO-DEF-015", "SUDO-DEF-017",
			"SUDO-CMD-003", "SUDO-CMD-005", "SUDO-CMD-014",
			"SUDO-SYS-PERM-001", "SUDO-SYS-PERM-002", "SUDO-SYS-PERM-003", "SUDO-SYS-PERM-004",
			"SUDO-SYS-PERM-005", "SUDO-SYS-PERM-006", "SUDO-SYS-PERM-007", "SUDO-SYS-PERM-008",
			"SUDO-SYS-PERM-009", "SUDO-SYS-PERM-010", "SUDO-SYS-PERM-011", "SUDO-SYS-PERM-012",
			"SUDO-SYS-PERM-013",
		},
		"disa-stig": {
			"SUDO-DEF-012", "SUDO-DEF-015", "SUDO-DEF-018",
			"SUDO-CMD-003", "SUDO-CMD-005", "SUDO-CMD-013",
		},
		"minimal": {
			"SUDO-DEF-001", "SUDO-DEF-002", "SUDO-DEF-004", "SUDO-DEF-011", "SUDO-DEF-012", "SUDO-DEF-013",
			"SUDO-CMD-001", "SUDO-CMD-002", "SUDO-CMD-003", "SUDO-CMD-007", "SUDO-CMD-010", "SUDO-CMD-011",
			"SUDO-CMD-014", "SUDO-GTFO-001", "SUDO-GTFO-002",
			"SUDO-SYS-PERM-002", "SUDO-SYS-PERM-003", "SUDO-SYS-PERM-005", "SUDO-SYS-PERM-007",
			"SUDO-SYS-PERM-008", "SUDO-SYS-PERM-009", "SUDO-SYS-PERM-010", "SUDO-SYS-PERM-012",
			"SUDO-SYS-PERM-013", "SUDO-SYS-SCRIPT-001", "SUDO-SYS-SCRIPT-002", "SUDO-SYS-SCRIPT-003",
		},
	}

	for profile, rules := range expected {
		set, err := ProfileRuleFilter(" " + profile + " ")
		if err != nil {
			t.Fatalf("ProfileRuleFilter(%q) failed: %v", profile, err)
		}
		if len(set) != len(rules) {
			t.Fatalf("profile %q: expected %d rules, got %d", profile, len(rules), len(set))
		}
		for _, r := range rules {
			if !set[r] {
				t.Fatalf("profile %q missing rule %q", profile, r)
			}
		}
	}

	// Mutating returned map must not affect future calls.
	set1, _ := ProfileRuleFilter("disa-stig")
	set1["SUDO-DEF-001"] = true
	set2, _ := ProfileRuleFilter("disa-stig")
	if set2["SUDO-DEF-001"] {
		t.Fatal("mutating returned profile map affected subsequent ProfileRuleFilter call")
	}

	if _, err := ProfileRuleFilter("unknown-profile"); err == nil {
		t.Fatal("expected error for unknown profile")
	}
}

func TestApply_NilAndBaselineCloning(t *testing.T) {
	filtered, suppressed, expired := Apply(nil, &Config{}, time.Now())
	if filtered != nil || suppressed != nil || expired != nil {
		t.Fatalf("expected all nil for nil result, got %v %v %v", filtered, suppressed, expired)
	}

	orig := &audit.AuditResult{
		SudoVersion: "1.9.15p5",
		Hostname:    "app01",
		PolicyFindings: []audit.Finding{
			{
				ID:         "SUDO-DEF-001",
				Title:      "env_reset disabled",
				Severity:   audit.SeverityHigh,
				Context:    "/etc/sudoers",
				Compliance: []string{"ANSSI"},
			},
		},
		SystemFindings: []audit.Finding{
			{
				ID:       "SUDO-SYS-PERM-002",
				Title:    "World-writable sudoers",
				Severity: audit.SeverityCritical,
			},
		},
	}

	filtered, suppressed, expired = Apply(orig, nil, time.Now())
	if len(suppressed) != 0 || len(expired) != 0 {
		t.Fatalf("expected no suppressed/expired with nil cfg, got %d/%d", len(suppressed), len(expired))
	}
	if filtered.SudoVersion != "1.9.15p5" || filtered.Hostname != "app01" {
		t.Fatalf("metadata not preserved: %+v", filtered)
	}
	if filtered.PolicyFindings[0].Fingerprint == "" || filtered.SystemFindings[0].Fingerprint == "" {
		t.Fatal("expected fingerprints to be populated")
	}
	if orig.PolicyFindings[0].Fingerprint != "" {
		t.Fatal("expected original input result not to be mutated")
	}
	filtered.PolicyFindings[0].Compliance[0] = "MUTATED"
	if orig.PolicyFindings[0].Compliance[0] != "ANSSI" {
		t.Fatal("expected Compliance slice to be cloned independently")
	}
}

func TestApply_ProfilesDisableAndOverrides(t *testing.T) {
	base := &audit.AuditResult{
		PolicyFindings: []audit.Finding{
			{ID: "SUDO-DEF-001", Title: "no env_reset", Severity: audit.SeverityHigh},
			{ID: "SUDO-DEF-003", Title: "no env_keep restriction", Severity: audit.SeverityMedium},
			{ID: "SUDO-CMD-003", Title: "NOPASSWD ALL", Severity: audit.SeverityCritical},
			{ID: "SUDO-CMD-013", Title: "SELinux TYPE/ROLE", Severity: audit.SeverityInfo},
		},
		SystemFindings: []audit.Finding{
			{ID: "SUDO-SYS-PERM-008", Title: "sudoers mode", Severity: audit.SeverityHigh},
			{ID: "SUDO-SYS-SCRIPT-001", Title: "writable script", Severity: audit.SeverityCritical},
			{ID: "CVE-2021-3156", Title: "Baron Samedit", Severity: audit.SeverityCritical},
			{ID: "CVE-2023-27320", Title: "Medium CVE", Severity: audit.SeverityMedium},
		},
	}

	// Minimal profile keeps minimal rules + CRITICAL/HIGH CVEs, applies disable_rules & severity_overrides.
	cfg := &Config{
		Profile:      "minimal",
		DisableRules: []string{" sudo-cmd-003 "},
		SeverityOverrides: map[string]audit.Severity{
			"sudo-def-001":        "crit",
			"sudo-sys-script-001": "high",
		},
	}

	filtered, _, _ := Apply(base, cfg, time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC))
	gotPolicy := map[string]audit.Severity{}
	for _, f := range filtered.PolicyFindings {
		gotPolicy[f.ID] = f.Severity
	}
	wantPolicy := map[string]audit.Severity{
		"SUDO-DEF-001": audit.SeverityCritical,
	}
	if !reflect.DeepEqual(gotPolicy, wantPolicy) {
		t.Fatalf("minimal policy findings mismatch: got %v, want %v", gotPolicy, wantPolicy)
	}

	gotSystem := map[string]audit.Severity{}
	for _, f := range filtered.SystemFindings {
		gotSystem[f.ID] = f.Severity
	}
	wantSystem := map[string]audit.Severity{
		"SUDO-SYS-PERM-008":   audit.SeverityHigh,
		"SUDO-SYS-SCRIPT-001": audit.SeverityHigh,
		"CVE-2021-3156":       audit.SeverityCritical,
	}
	if !reflect.DeepEqual(gotSystem, wantSystem) {
		t.Fatalf("minimal system findings mismatch: got %v, want %v", gotSystem, wantSystem)
	}

	// All profile allows CVEs too, except disabled ones.
	allCfg := &Config{
		Profile:      "all",
		DisableRules: []string{"cve-2023-27320"},
	}
	allFiltered, _, _ := Apply(base, allCfg, time.Now())
	if len(allFiltered.PolicyFindings) != 4 {
		t.Fatalf("expected 4 policy findings with all profile, got %d", len(allFiltered.PolicyFindings))
	}
	if len(allFiltered.SystemFindings) != 3 {
		t.Fatalf("expected 3 system findings with all profile and 1 disabled CVE, got %d", len(allFiltered.SystemFindings))
	}

	// ANSSI excludes CVEs and SUDO-CMD-013, keeps SUDO-DEF-003 and SUDO-SYS-PERM-008.
	anssiFiltered, _, _ := Apply(base, &Config{Profile: "anssi-bp028"}, time.Now())
	if len(anssiFiltered.PolicyFindings) != 2 || len(anssiFiltered.SystemFindings) != 1 {
		t.Fatalf("unexpected ANSSI counts: policy=%d system=%d", len(anssiFiltered.PolicyFindings), len(anssiFiltered.SystemFindings))
	}

	// Unvalidated invalid profile passed directly to Apply falls back safely without panic.
	invalidFiltered, _, _ := Apply(base, &Config{Profile: "invalid"}, time.Time{})
	if len(invalidFiltered.PolicyFindings) != 4 || len(invalidFiltered.SystemFindings) != 4 {
		t.Fatalf("expected fallback to keep findings on unvalidated invalid profile")
	}
}

func TestApply_SuppressionsAndExpirations(t *testing.T) {
	fVim := audit.Finding{
		ID:       "SUDO-GTFO-001",
		Title:    "GTFObins vim",
		Severity: audit.SeverityHigh,
		User:     "deploy",
		Host:     "web01",
		Command:  "/usr/bin/vim",
		Context:  `C:\etc\sudoers.d\10-deploy`,
	}
	fVimFP := audit.ComputeFingerprint(fVim)

	fRegex := audit.Finding{
		ID:       "SUDO-CMD-004",
		Title:    "Regex command",
		Severity: audit.SeverityMedium,
		User:     "ops",
		Host:     "ALL",
		Command:  "^/bin/ls [a-z]$",
		Context:  "/etc/sudoers.d/20-ops",
	}

	fEmptyCtx := audit.Finding{
		ID:       "SUDO-DEF-003",
		Title:    "No context",
		Severity: audit.SeverityMedium,
		Context:  "",
	}

	fBrokenCmd := audit.Finding{
		ID:       "SUDO-CMD-008",
		Title:    "Broken glob literal",
		Severity: audit.SeverityLow,
		Command:  "/usr/bin/[broken",
		Context:  "/etc/sudoers.d/[broken",
	}

	fSystem := audit.Finding{
		ID:       "CVE-2021-3156",
		Title:    "Baron Samedit",
		Severity: audit.SeverityCritical,
	}

	res := &audit.AuditResult{
		PolicyFindings: []audit.Finding{fVim, fRegex, fEmptyCtx, fBrokenCmd},
		SystemFindings: []audit.Finding{fSystem},
	}

	nowSameDay := time.Date(2026, 11, 20, 23, 59, 59, 0, time.UTC)
	expiredDup := Suppression{Rule: "SUDO-DEF-003", Reason: "expired rule", Expires: "2026-11-19"}

	cfg := &Config{
		Suppressions: []Suppression{
			// Active on 2026-11-20 at 23:59:59Z, matches fVim via fingerprint + glob command + basename context.
			{
				Fingerprint: fVimFP,
				User:        "deploy",
				Host:        "web01",
				Command:     "/usr/bin/*",
				Context:     "10-*",
				Reason:      "Approved vim with noexec audit",
				Expires:     "2026-11-20",
			},
			// Active RFC3339, matches fRegex with literal bracket command and slash context.
			{
				Rule:    "sudo-cmd-004",
				Command: "^/bin/ls [a-z]$",
				Context: "/etc/sudoers.d/*",
				Reason:  "Bounded regex",
				Expires: "2026-11-21T00:00:00Z",
			},
			// Must NOT match fEmptyCtx (even with Context: "*").
			{
				Rule:    "SUDO-DEF-003",
				Context: "*",
				Reason:  "Should not match empty context",
			},
			// Fallback exact match on malformed path.Match patterns.
			{
				Rule:    "SUDO-CMD-008",
				Command: "/usr/bin/[broken",
				Context: "/etc/sudoers.d/[broken",
				Reason:  "Exact fallback",
			},
			// Expired by date (duplicated to test deduplication).
			expiredDup,
			expiredDup,
			// Expired by RFC3339.
			{
				Rule:    "CVE-2021-3156",
				Reason:  "Patching window ended",
				Expires: "2026-11-20T23:59:58Z",
			},
			// Unvalidated bad entries must not match anything.
			{
				Reason: "Missing rule and fingerprint",
			},
			{
				Rule:    "CVE-2021-3156",
				Reason:  "Bad expiry format",
				Expires: "invalid-date",
			},
		},
	}

	filtered, suppressed, expired := Apply(res, cfg, nowSameDay)

	if len(expired) != 2 {
		t.Fatalf("expected 2 deduplicated expired suppressions, got %d: %+v", len(expired), expired)
	}
	if len(suppressed) != 3 {
		t.Fatalf("expected 3 suppressed findings, got %d: %+v", len(suppressed), suppressed)
	}
	for _, sf := range suppressed {
		if !sf.Suppressed || sf.SuppressionReason == "" {
			t.Fatalf("expected Suppressed=true and SuppressionReason set, got %+v", sf)
		}
	}
	if len(filtered.PolicyFindings) != 1 || filtered.PolicyFindings[0].ID != "SUDO-DEF-003" {
		t.Fatalf("expected only SUDO-DEF-003 left in PolicyFindings, got %+v", filtered.PolicyFindings)
	}
	if len(filtered.SystemFindings) != 1 || filtered.SystemFindings[0].ID != "CVE-2021-3156" {
		t.Fatalf("expected expired CVE suppression not to suppress CVE-2021-3156, got %+v", filtered.SystemFindings)
	}

	// One second later on 2026-11-21T00:00:00Z, 2026-11-20 expires!
	nextDay := time.Date(2026, 11, 21, 0, 0, 0, 0, time.UTC)
	filteredNext, suppressedNext, expiredNext := Apply(res, cfg, nextDay)
	if len(expiredNext) != 3 {
		t.Fatalf("expected 3 expired suppressions next day, got %d", len(expiredNext))
	}
	if len(suppressedNext) != 2 {
		t.Fatalf("expected 2 suppressed findings next day, got %d", len(suppressedNext))
	}
	if len(filteredNext.PolicyFindings) != 2 {
		t.Fatalf("expected 2 policy findings next day, got %d", len(filteredNext.PolicyFindings))
	}

	// Ensure User/Host/Fingerprint mismatches do not suppress.
	mismatchCfg := &Config{
		Suppressions: []Suppression{
			{Rule: "SUDO-GTFO-001", User: "other", Reason: "wrong user"},
			{Rule: "SUDO-GTFO-001", Host: "other", Reason: "wrong host"},
			{Rule: "SUDO-GTFO-001", Command: "/bin/*", Reason: "wrong cmd"},
			{Fingerprint: "0000", Reason: "wrong fp"},
		},
	}
	noSupFiltered, noSup, _ := Apply(res, mismatchCfg, nowSameDay)
	if len(noSup) != 0 || len(noSupFiltered.PolicyFindings) != 4 {
		t.Fatalf("expected 0 suppressed on mismatches, got %d", len(noSup))
	}
}
