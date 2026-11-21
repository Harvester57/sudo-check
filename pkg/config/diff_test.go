package config

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"sudo-check/pkg/audit"
)

func TestLoadBaselineResult(t *testing.T) {
	dir := t.TempDir()

	validPath := filepath.Join(dir, "baseline.json")
	validJSON := `{
  "sudo_version": "1.9.15p5",
  "hostname": "prod-01",
  "policy_findings": [
    {
      "id": "SUDO-DEF-001",
      "title": "env_reset disabled",
      "description": "desc",
      "severity": "HIGH",
      "context": "/etc/sudoers",
      "remediation": "fix"
    }
  ],
  "system_findings": [
    {
      "id": "CVE-2021-3156",
      "title": "Baron Samedit",
      "description": "desc",
      "severity": "CRITICAL",
      "fingerprint": "preset-fp",
      "remediation": "upgrade"
    }
  ]
}`
	if err := os.WriteFile(validPath, []byte(validJSON), 0600); err != nil {
		t.Fatalf("write valid baseline: %v", err)
	}

	res, err := LoadBaselineResult(validPath)
	if err != nil {
		t.Fatalf("LoadBaselineResult failed: %v", err)
	}
	if res.Hostname != "prod-01" || res.SudoVersion != "1.9.15p5" {
		t.Fatalf("unexpected metadata: %+v", res)
	}
	if res.PolicyFindings[0].Fingerprint == "" {
		t.Fatal("expected missing policy fingerprint to be populated")
	}
	if res.SystemFindings[0].Fingerprint != "preset-fp" {
		t.Fatalf("expected existing fingerprint to be preserved, got %q", res.SystemFindings[0].Fingerprint)
	}

	// Missing file.
	if _, err := LoadBaselineResult(filepath.Join(dir, "missing.json")); err == nil || !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected wrapped os.ErrNotExist, got %v", err)
	}

	// Invalid JSON.
	badPath := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(badPath, []byte("{not json"), 0600); err != nil {
		t.Fatalf("write bad json: %v", err)
	}
	if _, err := LoadBaselineResult(badPath); err == nil {
		t.Fatal("expected JSON parse error")
	}

	// Null JSON.
	nullPath := filepath.Join(dir, "null.json")
	if err := os.WriteFile(nullPath, []byte("null"), 0600); err != nil {
		t.Fatalf("write null json: %v", err)
	}
	if _, err := LoadBaselineResult(nullPath); err == nil {
		t.Fatal("expected error for null baseline JSON")
	}
}

func TestDiffResults_NilInputs(t *testing.T) {
	bothNil := DiffResults(nil, nil)
	if bothNil == nil || bothNil.Added == nil || bothNil.Resolved == nil || bothNil.Unchanged == nil {
		t.Fatalf("expected non-nil DiffResult and non-nil slices, got %+v", bothNil)
	}
	if len(bothNil.Added) != 0 || len(bothNil.Resolved) != 0 || len(bothNil.Unchanged) != 0 {
		t.Fatalf("expected empty diff for nil inputs, got %+v", bothNil)
	}

	sample := &audit.AuditResult{
		SystemFindings: []audit.Finding{
			{ID: "SUDO-SYS-PERM-002", Title: "perm", Severity: audit.SeverityCritical},
		},
		PolicyFindings: []audit.Finding{
			{ID: "SUDO-DEF-003", Title: "env_keep", Severity: audit.SeverityMedium},
		},
	}

	addedOnly := DiffResults(nil, sample)
	if len(addedOnly.Added) != 2 || len(addedOnly.Resolved) != 0 || len(addedOnly.Unchanged) != 0 {
		t.Fatalf("unexpected diff for nil baseline: %+v", addedOnly)
	}
	if addedOnly.Added[0].Fingerprint == "" || addedOnly.Added[1].Fingerprint == "" {
		t.Fatal("expected fingerprints computed on Added findings")
	}

	resolvedOnly := DiffResults(sample, nil)
	if len(resolvedOnly.Resolved) != 2 || len(resolvedOnly.Added) != 0 || len(resolvedOnly.Unchanged) != 0 {
		t.Fatalf("unexpected diff for nil current: %+v", resolvedOnly)
	}
	if resolvedOnly.Resolved[0].Fingerprint == "" || resolvedOnly.Resolved[1].Fingerprint == "" {
		t.Fatal("expected fingerprints computed on Resolved findings")
	}
}

func TestDiffResults_MultisetDuplicatesAndSorting(t *testing.T) {
	dupFinding := audit.Finding{
		ID:         "SUDO-CMD-001",
		Title:      "Wildcard command",
		Severity:   audit.SeverityHigh,
		User:       "ops",
		Host:       "ALL",
		Command:    "/usr/bin/*",
		Context:    "/etc/sudoers.d/10-ops",
		Line:       10,
		Compliance: []string{"ANSSI"},
	}

	resolvedSys := audit.Finding{
		ID:       "SUDO-SYS-PERM-008",
		Title:    "Permissions low",
		Severity: audit.SeverityLow,
	}
	resolvedCrit := audit.Finding{
		ID:       "CVE-2021-3156",
		Title:    "Baron Samedit",
		Severity: audit.SeverityCritical,
	}

	addedMed := audit.Finding{
		ID:       "SUDO-DEF-003",
		Title:    "env_keep",
		Severity: audit.SeverityMedium,
	}
	addedCrit := audit.Finding{
		ID:       "SUDO-CMD-003",
		Title:    "NOPASSWD ALL",
		Severity: audit.SeverityCritical,
		User:     "bob",
	}

	baseline := &audit.AuditResult{
		SystemFindings: []audit.Finding{resolvedSys, resolvedCrit},
		PolicyFindings: []audit.Finding{
			dupFinding, // 1 copy in baseline
		},
	}

	shiftedDup := dupFinding
	shiftedDup.Line = 25
	secondIdenticalDup := dupFinding
	secondIdenticalDup.Line = 40

	current := &audit.AuditResult{
		SystemFindings: []audit.Finding{addedMed},
		PolicyFindings: []audit.Finding{
			shiftedDup,         // matches baseline copy -> Unchanged
			secondIdenticalDup, // second identical fingerprint -> Added!
			addedCrit,
		},
	}

	diff := DiffResults(baseline, current)

	// Unchanged: 1 copy of dupFinding (at new Line 25).
	if len(diff.Unchanged) != 1 {
		t.Fatalf("expected 1 Unchanged, got %d: %+v", len(diff.Unchanged), diff.Unchanged)
	}
	if diff.Unchanged[0].Line != 25 || diff.Unchanged[0].Fingerprint == "" {
		t.Fatalf("expected current shifted finding in Unchanged with fingerprint, got %+v", diff.Unchanged[0])
	}

	// Added: addedCrit (CRITICAL), secondIdenticalDup (HIGH), addedMed (MEDIUM) sorted by severity.
	if len(diff.Added) != 3 {
		t.Fatalf("expected 3 Added (including duplicate finding), got %d: %+v", len(diff.Added), diff.Added)
	}
	if diff.Added[0].ID != "SUDO-CMD-003" || diff.Added[1].ID != "SUDO-CMD-001" || diff.Added[2].ID != "SUDO-DEF-003" {
		t.Fatalf("unexpected Added severity order: %+v", diff.Added)
	}
	if diff.Added[1].Line != 40 || diff.Added[1].Fingerprint != diff.Unchanged[0].Fingerprint {
		t.Fatalf("expected second identical finding in Added with matching fingerprint, got %+v", diff.Added[1])
	}

	// Resolved: resolvedCrit (CRITICAL) before resolvedSys (LOW).
	if len(diff.Resolved) != 2 {
		t.Fatalf("expected 2 Resolved, got %d: %+v", len(diff.Resolved), diff.Resolved)
	}
	if diff.Resolved[0].ID != "CVE-2021-3156" || diff.Resolved[1].ID != "SUDO-SYS-PERM-008" {
		t.Fatalf("unexpected Resolved severity order: %+v", diff.Resolved)
	}

	// Reverse direction: 2 in baseline, 1 in current -> 1 Unchanged, 1 Resolved, 0 Added.
	reverseDiff := DiffResults(
		&audit.AuditResult{PolicyFindings: []audit.Finding{dupFinding, secondIdenticalDup}},
		&audit.AuditResult{PolicyFindings: []audit.Finding{shiftedDup}},
	)
	if len(reverseDiff.Unchanged) != 1 || len(reverseDiff.Resolved) != 1 || len(reverseDiff.Added) != 0 {
		t.Fatalf("unexpected reverse multiset diff: unchanged=%d resolved=%d added=%d",
			len(reverseDiff.Unchanged), len(reverseDiff.Resolved), len(reverseDiff.Added))
	}

	// Original baseline/current fingerprints must remain untouched.
	if baseline.PolicyFindings[0].Fingerprint != "" || current.PolicyFindings[0].Fingerprint != "" {
		t.Fatal("DiffResults must not mutate input Finding.Fingerprint")
	}
}
