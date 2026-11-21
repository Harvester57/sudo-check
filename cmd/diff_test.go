package cmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sudo-check/pkg/audit"
	"sudo-check/pkg/config"
	"testing"
	"unicode"
)

func diffTestResetFlags() {
	outputDir = ""
	formats = "text,sarif,pdf,html"
	gtfoBinsPath = ""
	cvtSudoersPath = ""
	failOn = ""
	noColor = false
	configPath = ""
	profileName = ""
	customGTFObinsPath = ""
	baselinePath = ""
	subcommandAware = false

	for _, name := range []string{
		"output-dir",
		"formats",
		"gtfobins-path",
		"cvtsudoers-path",
		"fail-on",
		"no-color",
		"config",
		"profile",
		"custom-gtfobins",
		"baseline",
		"subcommand-aware",
		"help",
	} {
		if f := rootCmd.PersistentFlags().Lookup(name); f != nil {
			f.Changed = false
		}
		if f := diffCmd.Flags().Lookup(name); f != nil {
			f.Changed = false
		}
	}

	rootCmd.SetOut(nil)
	rootCmd.SetErr(nil)
	rootCmd.SetIn(nil)
}

func diffTestAssertNoEmojis(t *testing.T, s string) {
	t.Helper()
	for _, r := range s {
		if unicode.Is(unicode.So, r) {
			t.Fatalf("unexpected symbol/emoji rune %U in output:\n%s", r, s)
		}
	}
}

func TestDiffCmd_DirectPolicyFingerprintNormalizationAndIncludes(t *testing.T) {
	diffTestResetFlags()
	t.Cleanup(diffTestResetFlags)

	baseDir := t.TempDir()
	oldDir := filepath.Join(baseDir, "old_host")
	newDir := filepath.Join(baseDir, "new_host")
	if err := os.MkdirAll(filepath.Join(oldDir, "sudoers.d"), 0750); err != nil {
		t.Fatalf("mkdir old sudoers.d: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(newDir, "sudoers.d"), 0750); err != nil {
		t.Fatalf("mkdir new sudoers.d: %v", err)
	}

	oldDropin := filepath.Join(oldDir, "sudoers.d", "01_app")
	newDropin := filepath.Join(newDir, "sudoers.d", "01_app")
	if err := os.WriteFile(oldDropin, []byte("svc ALL=(root) /usr/bin/less\n"), 0600); err != nil {
		t.Fatalf("write old drop-in: %v", err)
	}
	if err := os.WriteFile(newDropin, []byte("svc ALL=(root) /usr/bin/less\n"), 0600); err != nil {
		t.Fatalf("write new drop-in: %v", err)
	}

	oldPolicyPath := filepath.Join(oldDir, "old.sudoers")
	oldContent := `Defaults env_reset, use_pty, secure_path="/usr/sbin:/usr/bin:/sbin:/bin"
Defaults logfile="/var/log/sudo.log", log_output, umask=0022
alice ALL=(root) /usr/bin/vim
legacy ALL=(root) NOPASSWD: /usr/bin/find
#includedir sudoers.d
`
	if err := os.WriteFile(oldPolicyPath, []byte(oldContent), 0600); err != nil {
		t.Fatalf("write old.sudoers: %v", err)
	}

	newPolicyPath := filepath.Join(newDir, "new.sudoers")
	newContent := `Defaults env_reset, use_pty, secure_path="/usr/sbin:/usr/bin:/sbin:/bin"
Defaults logfile="/var/log/sudo.log", log_output, umask=0022
# Blank comment shifts line number of alice's rule
alice ALL=(root) /usr/bin/vim
bob ALL=(ALL) NOPASSWD: ALL
#includedir sudoers.d
`
	if err := os.WriteFile(newPolicyPath, []byte(newContent), 0600); err != nil {
		t.Fatalf("write new.sudoers: %v", err)
	}

	var jsonOut bytes.Buffer
	rootCmd.SetOut(&jsonOut)
	rootCmd.SetArgs([]string{"diff", oldPolicyPath, newPolicyPath, "-f", "json"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("diff json failed: %v", err)
	}

	var diff config.DiffResult
	if err := json.Unmarshal(jsonOut.Bytes(), &diff); err != nil {
		t.Fatalf("unmarshal diff JSON failed: %v\nraw:\n%s", err, jsonOut.String())
	}

	hasUser := func(list []audit.Finding, user string) bool {
		for _, f := range list {
			if f.User == user {
				return true
			}
		}
		return false
	}
	hasDropinContext := func(list []audit.Finding, user string) bool {
		for _, f := range list {
			if f.User == user && strings.Contains(f.Context, "01_app") {
				return true
			}
		}
		return false
	}

	if !hasUser(diff.Unchanged, "alice") {
		t.Errorf("expected alice findings in Unchanged across old.sudoers vs new.sudoers, got Unchanged=%+v", diff.Unchanged)
	}
	if hasUser(diff.Added, "alice") || hasUser(diff.Resolved, "alice") {
		t.Errorf("alice should not appear in Added or Resolved across normalized direct policy diff; added=%+v resolved=%+v", diff.Added, diff.Resolved)
	}
	if !hasDropinContext(diff.Unchanged, "svc") {
		t.Errorf("expected included 01_app finding for svc to remain Unchanged with preserved 01_app context, got Unchanged=%+v", diff.Unchanged)
	}
	if !hasUser(diff.Added, "bob") {
		t.Errorf("expected newly added bob rule in Added, got %+v", diff.Added)
	}
	if !hasUser(diff.Resolved, "legacy") {
		t.Errorf("expected removed legacy rule in Resolved, got %+v", diff.Resolved)
	}

	// Verify text output as well.
	diffTestResetFlags()
	var textOut bytes.Buffer
	rootCmd.SetOut(&textOut)
	rootCmd.SetArgs([]string{"diff", oldPolicyPath, newPolicyPath})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("diff text failed: %v", err)
	}
	textStr := textOut.String()
	diffTestAssertNoEmojis(t, textStr)
	for _, want := range []string{"Added:", "Resolved:", "Unchanged:", "Added Findings", "Resolved Findings", "Unchanged Findings", "bob", "legacy", "alice"} {
		if !strings.Contains(textStr, want) {
			t.Errorf("expected %q in diff text output, got:\n%s", want, textStr)
		}
	}
}

func TestDiffCmd_AuditReportJSONAndFailOn(t *testing.T) {
	dir := t.TempDir()
	oldReportPath := filepath.Join(dir, "baseline.json")
	newReportPath := filepath.Join(dir, "current.json")

	oldReport := audit.AuditResult{
		Hostname: "host1",
		PolicyFindings: []audit.Finding{
			{ID: "SUDO-CMD-003", Title: "NOPASSWD ALL", Severity: audit.SeverityCritical, User: "existing", Context: "/etc/sudoers"},
			{ID: "SUDO-DEF-008", Title: "Missing requiretty", Severity: audit.SeverityLow, Context: "/etc/sudoers"},
		},
	}
	newReport := audit.AuditResult{
		Hostname: "host1",
		PolicyFindings: []audit.Finding{
			{ID: "SUDO-CMD-003", Title: "NOPASSWD ALL", Severity: audit.SeverityCritical, User: "existing", Context: "/etc/sudoers"},
			{ID: "SUDO-DEF-001", Title: "Missing secure_path", Severity: audit.SeverityHigh, Context: "/etc/sudoers"},
		},
	}

	oldBytes, _ := json.Marshal(oldReport)
	newBytes, _ := json.Marshal(newReport)
	if err := os.WriteFile(oldReportPath, oldBytes, 0600); err != nil {
		t.Fatalf("write old report: %v", err)
	}
	if err := os.WriteFile(newReportPath, newBytes, 0600); err != nil {
		t.Fatalf("write new report: %v", err)
	}

	// Unchanged CRITICAL must NOT trigger --fail-on CRITICAL when only HIGH was added.
	diffTestResetFlags()
	t.Cleanup(diffTestResetFlags)
	var out1 bytes.Buffer
	rootCmd.SetOut(&out1)
	rootCmd.SetArgs([]string{"diff", oldReportPath, newReportPath, "--fail-on", "CRITICAL"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("expected no fail-on error when only HIGH was added (CRITICAL is unchanged), got: %v", err)
	}

	// Added HIGH MUST trigger --fail-on HIGH with ErrFailOnThreshold.
	diffTestResetFlags()
	var out2 bytes.Buffer
	rootCmd.SetOut(&out2)
	rootCmd.SetArgs([]string{"diff", oldReportPath, newReportPath, "-f", "json", "--fail-on", "HIGH"})
	err := rootCmd.Execute()
	if !errors.Is(err, ErrFailOnThreshold) {
		t.Fatalf("expected ErrFailOnThreshold when newly added finding has severity HIGH, got: %v", err)
	}

	var diff config.DiffResult
	if jsonErr := json.Unmarshal(out2.Bytes(), &diff); jsonErr != nil {
		t.Fatalf("expected JSON diff output before ErrFailOnThreshold return, got decode err: %v", jsonErr)
	}
	if len(diff.Added) != 1 || diff.Added[0].ID != "SUDO-DEF-001" {
		t.Errorf("expected 1 added finding SUDO-DEF-001, got %+v", diff.Added)
	}
	if len(diff.Resolved) != 1 || diff.Resolved[0].ID != "SUDO-DEF-008" {
		t.Errorf("expected 1 resolved finding SUDO-DEF-008, got %+v", diff.Resolved)
	}
	if len(diff.Unchanged) != 1 || diff.Unchanged[0].User != "existing" {
		t.Errorf("expected 1 unchanged finding for existing, got %+v", diff.Unchanged)
	}
}

func TestDiffCmd_CvtsudoersJSONPoliciesAndErrors(t *testing.T) {
	dir := t.TempDir()
	p1 := filepath.Join(dir, "policy1.json")
	p2 := filepath.Join(dir, "policy2.json")

	j1 := `{"Defaults": [{"Options": [{"env_reset": true}]}], "User_Specs": [{"User_List": [{"username": "alice"}], "Host_List": [{"hostname": "ALL"}], "Cmnd_Specs": [{"Commands": [{"command": "/usr/bin/id"}]}]}]}`
	j2 := `{"Defaults": [{"Options": [{"env_reset": true}]}], "User_Specs": [{"User_List": [{"username": "alice"}], "Host_List": [{"hostname": "ALL"}], "Cmnd_Specs": [{"Commands": [{"command": "/usr/bin/id"}, {"command": "/usr/bin/vim"}]}]}]}`
	_ = os.WriteFile(p1, []byte(j1), 0600)
	_ = os.WriteFile(p2, []byte(j2), 0600)

	diffTestResetFlags()
	t.Cleanup(diffTestResetFlags)
	var out bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetArgs([]string{"diff", p1, p2, "-f", "json"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("diff cvtsudoers JSON policies failed: %v", err)
	}
	var diff config.DiffResult
	if err := json.Unmarshal(out.Bytes(), &diff); err != nil {
		t.Fatalf("decode diff JSON failed: %v", err)
	}
	if len(diff.Added) == 0 || len(diff.Unchanged) == 0 {
		t.Errorf("expected both Added and Unchanged findings across cvtsudoers JSON diff, got %+v", diff)
	}

	t.Run("InvalidFailOn", func(t *testing.T) {
		diffTestResetFlags()
		rootCmd.SetArgs([]string{"diff", p1, p2, "--fail-on", "NOPE"})
		if err := rootCmd.Execute(); err == nil || !strings.Contains(err.Error(), "invalid --fail-on severity") {
			t.Fatalf("expected invalid --fail-on error, got: %v", err)
		}
	})

	t.Run("UnsupportedFormat", func(t *testing.T) {
		diffTestResetFlags()
		rootCmd.SetArgs([]string{"diff", p1, p2, "-f", "pdf"})
		if err := rootCmd.Execute(); err == nil || !strings.Contains(err.Error(), "unsupported format") {
			t.Fatalf("expected unsupported format error, got: %v", err)
		}
	})

	t.Run("MultipleFormatsRejected", func(t *testing.T) {
		diffTestResetFlags()
		rootCmd.SetArgs([]string{"diff", p1, p2, "-f", "text,json"})
		if err := rootCmd.Execute(); err == nil || !strings.Contains(err.Error(), "single output format") {
			t.Fatalf("expected single output format error, got: %v", err)
		}
	})

	t.Run("UnrelatedJSONRejected", func(t *testing.T) {
		diffTestResetFlags()
		bad := filepath.Join(dir, "other.json")
		_ = os.WriteFile(bad, []byte(`{"hello":"world"}`), 0600)
		rootCmd.SetArgs([]string{"diff", bad, p2})
		if err := rootCmd.Execute(); err == nil {
			t.Fatal("expected error for unrelated JSON object")
		}
	})

	t.Run("MissingFile", func(t *testing.T) {
		diffTestResetFlags()
		rootCmd.SetArgs([]string{"diff", filepath.Join(dir, "missing.sudoers"), p2})
		if err := rootCmd.Execute(); err == nil {
			t.Fatal("expected error for missing file")
		}
	})
}
