package audit

import (
	"encoding/json"
	"os"
	"strings"
	"sudo-check/pkg/gtfobins"
	"testing"
	"time"
)

// loadTestPolicy loads a JSON policy fixture from testdata/.
func loadTestPolicy(t *testing.T, name string) *SudoersPolicy {
	t.Helper()
	data, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatalf("Failed to read test fixture %s: %v", name, err)
	}
	var policy SudoersPolicy
	if err := json.Unmarshal(data, &policy); err != nil {
		t.Fatalf("Failed to parse test fixture %s: %v", name, err)
	}
	return &policy
}

// requireGTFOClient creates a GTFObins client or fails the test.
func requireGTFOClient(t *testing.T) *gtfobins.Client {
	t.Helper()
	c, err := gtfobins.NewClient()
	if err != nil {
		t.Fatalf("Failed to load GTFObins database: %v", err)
	}
	return c
}

// assertFindingPresent checks that at least one finding with the given ID exists.
func assertFindingPresent(t *testing.T, findings []Finding, id string) {
	t.Helper()
	for _, f := range findings {
		if f.ID == id {
			return
		}
	}
	t.Errorf("Expected finding with ID %s to be present, but it was not found", id)
}

// assertFindingAbsent checks that no finding with the given ID exists.
func assertFindingAbsent(t *testing.T, findings []Finding, id string) {
	t.Helper()
	for _, f := range findings {
		if f.ID == id {
			t.Errorf("Expected finding with ID %s to be absent, but it was found: %s", id, f.Title)
			return
		}
	}
}

// assertFindingSeverity checks that the first finding with the given ID has the expected severity.
func assertFindingSeverity(t *testing.T, findings []Finding, id string, expected Severity) {
	t.Helper()
	for _, f := range findings {
		if f.ID == id {
			if f.Severity != expected {
				t.Errorf("Finding %s: expected severity %s, got %s", id, expected, f.Severity)
			}
			return
		}
	}
	t.Errorf("Finding %s not found - cannot check severity", id)
}

// --- Defaults Audit Tests ---

func TestAuditDefaults(t *testing.T) {
	t.Run("MissingSecurePath", func(t *testing.T) {
		policy := &SudoersPolicy{Defaults: []DefaultBinding{{Options: []Option{{"use_pty": true}}}}}
		findings := AuditDefaults(policy)
		assertFindingPresent(t, findings, "SUDO-DEF-001")
	})

	t.Run("EmptySecurePath", func(t *testing.T) {
		policy := &SudoersPolicy{Defaults: []DefaultBinding{{Options: []Option{{"secure_path": ""}}}}}
		findings := AuditDefaults(policy)
		assertFindingPresent(t, findings, "SUDO-DEF-001")
	})

	t.Run("RelativePathInSecurePath", func(t *testing.T) {
		policy := &SudoersPolicy{Defaults: []DefaultBinding{{Options: []Option{{"secure_path": "/usr/bin:./local:/sbin"}}}}}
		findings := AuditDefaults(policy)
		assertFindingPresent(t, findings, "SUDO-DEF-002")
	})

	t.Run("ValidSecurePath", func(t *testing.T) {
		policy := &SudoersPolicy{Defaults: []DefaultBinding{{Options: []Option{{"secure_path": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}}}}}
		findings := AuditDefaults(policy)
		assertFindingAbsent(t, findings, "SUDO-DEF-001")
		assertFindingAbsent(t, findings, "SUDO-DEF-002")
	})

	t.Run("SecurePathWritableTempTraversalAndSafeTmpfs", func(t *testing.T) {
		for _, badPath := range []string{
			"/usr/bin:/tmp:/sbin",
			"/usr/bin:/tmp/custom:/sbin",
			"/usr/bin:/home/user/bin:/sbin",
			"/usr/bin:/var/tmp:/sbin",
			"/usr/bin:/dev/shm/bin:/sbin",
			"/usr/bin:/run/user/1000/bin:/sbin",
			"/usr/bin:/var/mail:/sbin",
			"/usr/bin:/var/spool/samba:/sbin",
			"/usr/bin/../sbin:/bin",
		} {
			policy := &SudoersPolicy{Defaults: []DefaultBinding{{Options: []Option{{"secure_path": badPath}}}}}
			findings := AuditDefaults(policy)
			assertFindingPresent(t, findings, "SUDO-DEF-002")
		}

		// /tmpfs is NOT /tmp and must NOT be flagged or stripped by sanitizeSecurePath.
		safePolicy := &SudoersPolicy{Defaults: []DefaultBinding{{Options: []Option{{"secure_path": "/usr/sbin:/tmpfs:/tmpfs/bin:/usr/bin"}}}}}
		safeFindings := AuditDefaults(safePolicy)
		assertFindingAbsent(t, safeFindings, "SUDO-DEF-002")

		gotSanitized := sanitizeSecurePath("/usr/sbin:/tmpfs:/tmp:/tmp/foo:/home/user/bin:/usr/bin/../etc:/usr/bin")
		wantSanitized := "/usr/sbin:/tmpfs:/usr/bin"
		if gotSanitized != wantSanitized {
			t.Errorf("sanitizeSecurePath() = %q, want %q", gotSanitized, wantSanitized)
		}
	})

	t.Run("EnvKeepWildcardsAndMacOSAndAdditionalVars", func(t *testing.T) {
		dangerousCases := []string{
			"LD*",
			"*_PRELOAD",
			"*PATH*",
			"DYLD_*",
			"DYLD_INSERT_LIBRARIES",
			"BASH*",
			"HOME",
			"ZDOTDIR",
			"FPATH",
			"OPENSSL_MODULES",
			"GIT_EXTERNAL_DIFF",
			"GIT_CONFIG_PARAMETERS",
			"GIT_CONFIG_GLOBAL",
			"GIT_TEMPLATE_DIR",
		}
		for _, v := range dangerousCases {
			policy := &SudoersPolicy{Defaults: []DefaultBinding{{Options: []Option{
				{"operation": "list_add", "env_keep": []any{v}},
			}}}}
			findings := AuditDefaults(policy)
			assertFindingPresent(t, findings, "SUDO-DEF-004")
		}

		// Safe wildcard patterns must NOT trigger SUDO-DEF-004.
		safePolicy := &SudoersPolicy{Defaults: []DefaultBinding{{Options: []Option{
			{"operation": "list_add", "env_keep": []any{"LC_*", "XDG_*", "LANG", "TERM"}},
		}}}}
		safeFindings := AuditDefaults(safePolicy)
		assertFindingAbsent(t, safeFindings, "SUDO-DEF-004")
	})

	t.Run("EnvDeleteLastMatchWinsLineAttributionAndRemediationCode", func(t *testing.T) {
		// env_delete -= LD_PRELOAD followed by env_delete += LD_PRELOAD must NOT trigger SUDO-DEF-004.
		overridden := &SudoersPolicy{Defaults: []DefaultBinding{
			{File: "/etc/sudoers", Line: 5, Options: []Option{
				{"operation": "list_remove", "env_delete": []string{"LD_PRELOAD"}},
			}},
			{File: "/etc/sudoers", Line: 10, Options: []Option{
				{"operation": "list_add", "env_delete": []string{"LD_PRELOAD"}},
			}},
		}}
		assertFindingAbsent(t, AuditDefaults(overridden), "SUDO-DEF-004")

		// env_delete -= LD_PRELOAD followed by !env_delete resets listRemoved.
		resetPolicy := &SudoersPolicy{Defaults: []DefaultBinding{
			{Options: []Option{{"operation": "list_remove", "env_delete": []string{"LD_PRELOAD"}}}},
			{Options: []Option{{"env_delete": false}}},
		}}
		assertFindingAbsent(t, AuditDefaults(resetPolicy), "SUDO-DEF-004")

		// Line attribution & per-list RemediationCode: safe env_keep on line 5, bad env_delete on line 18 in the SAME file.
		sameFile := &SudoersPolicy{Defaults: []DefaultBinding{
			{File: "/etc/sudoers", Line: 5, Options: []Option{
				{"operation": "list_add", "env_keep": []any{"LANG"}},
			}},
			{File: "/etc/sudoers", Line: 18, Options: []Option{
				{"operation": "list_remove", "env_delete": []string{"LD_PRELOAD"}},
			}},
		}}
		findings := AuditDefaults(sameFile)
		var envFinding *Finding
		for i := range findings {
			if findings[i].ID == "SUDO-DEF-004" {
				envFinding = &findings[i]
				break
			}
		}
		if envFinding == nil {
			t.Fatal("Expected SUDO-DEF-004 finding for env_delete removal")
		}
		if envFinding.Context != "/etc/sudoers" || envFinding.Line != 18 {
			t.Errorf("Expected SUDO-DEF-004 at /etc/sudoers:18, got %s:%d", envFinding.Context, envFinding.Line)
		}
		if !strings.Contains(envFinding.RemediationCode, `Defaults env_delete += "LD_PRELOAD"`) {
			t.Errorf("Expected env_delete += RemediationCode, got %q", envFinding.RemediationCode)
		}

		// Multi-list RemediationCode: env_keep, env_check, and env_delete all triggered.
		multiList := &SudoersPolicy{Defaults: []DefaultBinding{
			{Options: []Option{
				{"operation": "list_add", "env_keep": []any{"LD_PRELOAD"}},
				{"operation": "list_add", "env_check": []any{"PYTHONPATH"}},
				{"operation": "list_remove", "env_delete": []string{"IFS"}},
			}},
		}}
		multiFindings := AuditDefaults(multiList)
		for _, f := range multiFindings {
			if f.ID == "SUDO-DEF-004" {
				if !strings.Contains(f.RemediationCode, `Defaults env_keep -= "LD_PRELOAD"`) ||
					!strings.Contains(f.RemediationCode, `Defaults env_check -= "PYTHONPATH"`) ||
					!strings.Contains(f.RemediationCode, `Defaults env_delete += "IFS"`) {
					t.Errorf("Expected multi-list RemediationCode with env_keep -=, env_check -=, env_delete +=, got %q", f.RemediationCode)
				}
			}
		}
	})

	t.Run("LogfileRule_SUDO_DEF_017", func(t *testing.T) {
		missing := &SudoersPolicy{Defaults: []DefaultBinding{{Options: []Option{{"use_pty": true}}}}}
		assertFindingPresent(t, AuditDefaults(missing), "SUDO-DEF-017")
		assertFindingSeverity(t, AuditDefaults(missing), "SUDO-DEF-017", SeverityLow)

		empty := &SudoersPolicy{Defaults: []DefaultBinding{{Options: []Option{{"logfile": "   "}}}}}
		assertFindingPresent(t, AuditDefaults(empty), "SUDO-DEF-017")

		disabled := &SudoersPolicy{Defaults: []DefaultBinding{
			{Options: []Option{{"logfile": "/var/log/sudo.log"}}},
			{Options: []Option{{"logfile": false}}},
		}}
		assertFindingPresent(t, AuditDefaults(disabled), "SUDO-DEF-017")

		valid := &SudoersPolicy{Defaults: []DefaultBinding{{Options: []Option{{"logfile": "/var/log/sudo.log"}}}}}
		assertFindingAbsent(t, AuditDefaults(valid), "SUDO-DEF-017")
	})

	t.Run("SharedPasswordRules_SUDO_DEF_018", func(t *testing.T) {
		for _, opt := range []string{"rootpw", "targetpw", "runaspw"} {
			p := &SudoersPolicy{Defaults: []DefaultBinding{{Options: []Option{{opt: true}}}}}
			findings := AuditDefaults(p)
			assertFindingPresent(t, findings, "SUDO-DEF-018")
			assertFindingSeverity(t, findings, "SUDO-DEF-018", SeverityMedium)
		}

		// Last-match-wins: rootpw followed by !rootpw must not trigger SUDO-DEF-018.
		overridden := &SudoersPolicy{Defaults: []DefaultBinding{
			{Options: []Option{{"rootpw": true}}},
			{Options: []Option{{"rootpw": false}}},
		}}
		assertFindingAbsent(t, AuditDefaults(overridden), "SUDO-DEF-018")
	})

	t.Run("ScopedDefaultsLastMatchWinsAndFullCoverage", func(t *testing.T) {
		// Defaults:bob !authenticate followed by Defaults:bob authenticate must NOT emit SUDO-DEF-012.
		folded := &SudoersPolicy{Defaults: []DefaultBinding{
			{File: "/etc/sudoers", Line: 10, Binding: []Member{{Username: "bob"}}, Options: []Option{{"authenticate": false}}},
			{File: "/etc/sudoers", Line: 20, Binding: []Member{{Username: "bob"}}, Options: []Option{{"authenticate": true}}},
		}}
		assertFindingAbsent(t, AuditDefaults(folded), "SUDO-DEF-012")

		// Scoped rules covering all newly added checks.
		scopedAll := &SudoersPolicy{Defaults: []DefaultBinding{
			{
				File:    "/etc/sudoers",
				Line:    15,
				Binding: []Member{{Username: "bob"}},
				Options: []Option{
					{"secure_path": false},
					{"pwfeedback": true},
					{"requiretty": false},
					{"umask": "0000"},
					{"ignore_dot": false},
					{"timestamp_timeout": -1},
					{"passwd_timeout": 0},
					{"timestamp_type": "global"},
					{"runchroot": "/srv/chroot"},
					{"runcwd": "*"},
					{"logfile": false},
					{"rootpw": true},
				},
			},
			{
				File:    "/etc/sudoers",
				Line:    30,
				Binding: []Member{{Hostname: "web01"}},
				Options: []Option{
					{"secure_path": "/usr/bin:/tmp"},
					{"umask": false},
				},
			},
		}}
		findings := AuditDefaults(scopedAll)
		for _, id := range []string{
			"SUDO-DEF-001",
			"SUDO-DEF-002",
			"SUDO-DEF-006",
			"SUDO-DEF-008",
			"SUDO-DEF-009",
			"SUDO-DEF-010",
			"SUDO-DEF-015",
			"SUDO-DEF-016",
			"SUDO-DEF-017",
			"SUDO-DEF-018",
		} {
			foundScoped := false
			for _, f := range findings {
				if f.ID == id && (f.User == "bob" || f.User == "web01") {
					foundScoped = true
					if f.RemediationCode == "" {
						t.Errorf("Scoped finding %s has empty RemediationCode", id)
					}
					break
				}
			}
			if !foundScoped {
				t.Errorf("Expected scoped finding %s for bob or web01, not found", id)
			}
		}

		// Verify formatScopedDefaultsDirective picks correct separators.
		if got := formatScopedDefaultsDirective([]Member{{Hostname: "web01"}}, "web01"); got != "Defaults@web01" {
			t.Errorf("host directive = %q, want Defaults@web01", got)
		}
		if got := formatScopedDefaultsDirective([]Member{{Username: "bob"}}, "bob"); got != "Defaults:bob" {
			t.Errorf("user directive = %q, want Defaults:bob", got)
		}
		if got := formatScopedDefaultsDirective([]Member{{Command: "/bin/ls"}}, "/bin/ls"); got != "Defaults!/bin/ls" {
			t.Errorf("cmd directive = %q, want Defaults!/bin/ls", got)
		}
		if got := formatScopedDefaultsDirective([]Member{{RunasAlias: "DB"}}, "DB"); got != "Defaults>DB" {
			t.Errorf("runas directive = %q, want Defaults>DB", got)
		}
	})

	t.Run("MissingUsePty", func(t *testing.T) {
		policy := &SudoersPolicy{Defaults: []DefaultBinding{{Options: []Option{{"secure_path": "/usr/bin"}}}}}
		findings := AuditDefaults(policy)
		assertFindingPresent(t, findings, "SUDO-DEF-003")
	})

	t.Run("DisabledUsePty", func(t *testing.T) {
		policy := &SudoersPolicy{Defaults: []DefaultBinding{{Options: []Option{{"use_pty": false}}}}}
		findings := AuditDefaults(policy)
		assertFindingPresent(t, findings, "SUDO-DEF-003")
	})

	t.Run("EnabledUsePty", func(t *testing.T) {
		policy := &SudoersPolicy{Defaults: []DefaultBinding{{Options: []Option{{"use_pty": true}}}}}
		findings := AuditDefaults(policy)
		assertFindingAbsent(t, findings, "SUDO-DEF-003")
	})

	t.Run("LastMatchWinsOverride", func(t *testing.T) {
		policy := &SudoersPolicy{Defaults: []DefaultBinding{
			{Options: []Option{
				{"use_pty": true},
				{"env_reset": true},
				{"operation": "list_add", "env_keep": []any{"LD_PRELOAD"}},
			}},
			{Options: []Option{
				{"use_pty": false},
				{"env_reset": false},
				{"operation": "list_remove", "env_keep": []any{"LD_PRELOAD"}},
			}},
		}}
		findings := AuditDefaults(policy)
		assertFindingPresent(t, findings, "SUDO-DEF-003")
		assertFindingPresent(t, findings, "SUDO-DEF-011")
		assertFindingAbsent(t, findings, "SUDO-DEF-004")
	})

	t.Run("MultiLineGlobalDefaultsLineTracking", func(t *testing.T) {
		policy := &SudoersPolicy{Defaults: []DefaultBinding{
			{
				File:    "/etc/sudoers",
				Line:    5,
				Options: []Option{{"env_reset": true}},
			},
			{
				File:    "/etc/sudoers",
				Line:    27,
				Options: []Option{{"visiblepw": true}},
			},
		}}
		findings := AuditDefaults(policy)
		foundLine27 := false
		for _, f := range findings {
			if f.ID == "SUDO-DEF-005" && f.Context == "/etc/sudoers" && f.Line == 27 {
				foundLine27 = true
			}
		}
		if !foundLine27 {
			t.Errorf("Expected SUDO-DEF-005 to report exact line 27 on /etc/sudoers, got: %+v", findings)
		}
	})

	t.Run("DangerousEnvKeep", func(t *testing.T) {
		policy := &SudoersPolicy{Defaults: []DefaultBinding{{Options: []Option{
			{"operation": "list_add", "env_keep": []any{"LD_PRELOAD", "SAFE_VAR"}},
		}}}}
		findings := AuditDefaults(policy)
		assertFindingPresent(t, findings, "SUDO-DEF-004")
		assertFindingSeverity(t, findings, "SUDO-DEF-004", SeverityCritical)
	})

	t.Run("DangerousEnvDeleteRemoval", func(t *testing.T) {
		policy := &SudoersPolicy{Defaults: []DefaultBinding{{Options: []Option{
			{"operation": "list_remove", "env_delete": []string{"LD_PRELOAD"}},
		}}}}
		findings := AuditDefaults(policy)
		assertFindingPresent(t, findings, "SUDO-DEF-004")
	})

	t.Run("SafeEnvKeep", func(t *testing.T) {
		policy := &SudoersPolicy{Defaults: []DefaultBinding{{Options: []Option{
			{"operation": "list_assign", "env_keep": []any{"LANG", "LC_ALL", "TERM"}},
		}}}}
		findings := AuditDefaults(policy)
		assertFindingAbsent(t, findings, "SUDO-DEF-004")
	})

	t.Run("VisiblepwEnabled", func(t *testing.T) {
		policy := &SudoersPolicy{Defaults: []DefaultBinding{{Options: []Option{{"visiblepw": true}}}}}
		findings := AuditDefaults(policy)
		assertFindingPresent(t, findings, "SUDO-DEF-005")
	})

	t.Run("VisiblepwDisabled", func(t *testing.T) {
		policy := &SudoersPolicy{Defaults: []DefaultBinding{{Options: []Option{{"visiblepw": false}}}}}
		findings := AuditDefaults(policy)
		assertFindingAbsent(t, findings, "SUDO-DEF-005")
	})

	t.Run("PwfeedbackEnabled", func(t *testing.T) {
		policy := &SudoersPolicy{Defaults: []DefaultBinding{{Options: []Option{{"pwfeedback": true}}}}}
		findings := AuditDefaults(policy)
		assertFindingPresent(t, findings, "SUDO-DEF-006")
	})

	t.Run("MissingNoexec", func(t *testing.T) {
		policy := &SudoersPolicy{Defaults: []DefaultBinding{{Options: []Option{{"use_pty": true}}}}}
		findings := AuditDefaults(policy)
		assertFindingPresent(t, findings, "SUDO-DEF-007")
	})

	t.Run("DisabledNoexec", func(t *testing.T) {
		policy := &SudoersPolicy{Defaults: []DefaultBinding{{Options: []Option{{"noexec": false}}}}}
		findings := AuditDefaults(policy)
		assertFindingPresent(t, findings, "SUDO-DEF-007")
	})

	t.Run("EnabledNoexec", func(t *testing.T) {
		policy := &SudoersPolicy{Defaults: []DefaultBinding{{Options: []Option{{"noexec": true}}}}}
		findings := AuditDefaults(policy)
		assertFindingAbsent(t, findings, "SUDO-DEF-007")
	})

	t.Run("MissingRequiretty", func(t *testing.T) {
		policy := &SudoersPolicy{Defaults: []DefaultBinding{{Options: []Option{{"use_pty": true}}}}}
		findings := AuditDefaults(policy)
		assertFindingPresent(t, findings, "SUDO-DEF-008")
	})

	t.Run("DisabledRequiretty", func(t *testing.T) {
		policy := &SudoersPolicy{Defaults: []DefaultBinding{{Options: []Option{{"requiretty": false}}}}}
		findings := AuditDefaults(policy)
		assertFindingPresent(t, findings, "SUDO-DEF-008")
	})

	t.Run("EnabledRequiretty", func(t *testing.T) {
		policy := &SudoersPolicy{Defaults: []DefaultBinding{{Options: []Option{{"requiretty": true}}}}}
		findings := AuditDefaults(policy)
		assertFindingAbsent(t, findings, "SUDO-DEF-008")
	})

	t.Run("MissingUmask", func(t *testing.T) {
		policy := &SudoersPolicy{Defaults: []DefaultBinding{{Options: []Option{{"use_pty": true}}}}}
		findings := AuditDefaults(policy)
		assertFindingPresent(t, findings, "SUDO-DEF-009")
	})

	t.Run("WeakUmaskString", func(t *testing.T) {
		policy := &SudoersPolicy{Defaults: []DefaultBinding{{Options: []Option{{"umask": "0022"}}}}}
		findings := AuditDefaults(policy)
		assertFindingPresent(t, findings, "SUDO-DEF-009")
	})

	t.Run("WeakUmaskInt", func(t *testing.T) {
		policy := &SudoersPolicy{Defaults: []DefaultBinding{{Options: []Option{{"umask": 18}}}}} // 0022 in octal is 18
		findings := AuditDefaults(policy)
		assertFindingPresent(t, findings, "SUDO-DEF-009")
	})

	t.Run("StrongUmaskString", func(t *testing.T) {
		policy := &SudoersPolicy{Defaults: []DefaultBinding{{Options: []Option{{"umask": "0077"}}}}}
		findings := AuditDefaults(policy)
		assertFindingAbsent(t, findings, "SUDO-DEF-009")
	})

	t.Run("StrongUmaskInt", func(t *testing.T) {
		policy := &SudoersPolicy{Defaults: []DefaultBinding{{Options: []Option{{"umask": 63}}}}} // 0077 in octal is 63
		findings := AuditDefaults(policy)
		assertFindingAbsent(t, findings, "SUDO-DEF-009")
	})

	t.Run("StrongUmaskFloat", func(t *testing.T) {
		policy := &SudoersPolicy{Defaults: []DefaultBinding{{Options: []Option{{"umask": float64(63)}}}}}
		findings := AuditDefaults(policy)
		assertFindingAbsent(t, findings, "SUDO-DEF-009")
	})

	t.Run("MissingIgnoreDot", func(t *testing.T) {
		policy := &SudoersPolicy{Defaults: []DefaultBinding{{Options: []Option{{"use_pty": true}}}}}
		findings := AuditDefaults(policy)
		assertFindingPresent(t, findings, "SUDO-DEF-010")
	})

	t.Run("DisabledIgnoreDot", func(t *testing.T) {
		policy := &SudoersPolicy{Defaults: []DefaultBinding{{Options: []Option{{"ignore_dot": false}}}}}
		findings := AuditDefaults(policy)
		assertFindingPresent(t, findings, "SUDO-DEF-010")
	})

	t.Run("EnabledIgnoreDot", func(t *testing.T) {
		policy := &SudoersPolicy{Defaults: []DefaultBinding{{Options: []Option{{"ignore_dot": true}}}}}
		findings := AuditDefaults(policy)
		assertFindingAbsent(t, findings, "SUDO-DEF-010")
	})

	t.Run("MissingEnvReset", func(t *testing.T) {
		policy := &SudoersPolicy{Defaults: []DefaultBinding{{Options: []Option{{"use_pty": true}}}}}
		findings := AuditDefaults(policy)
		assertFindingPresent(t, findings, "SUDO-DEF-011")
	})

	t.Run("DisabledEnvReset", func(t *testing.T) {
		policy := &SudoersPolicy{Defaults: []DefaultBinding{{Options: []Option{{"env_reset": false}}}}}
		findings := AuditDefaults(policy)
		assertFindingPresent(t, findings, "SUDO-DEF-011")
	})

	t.Run("EnabledEnvReset", func(t *testing.T) {
		policy := &SudoersPolicy{Defaults: []DefaultBinding{{Options: []Option{{"env_reset": true}}}}}
		findings := AuditDefaults(policy)
		assertFindingAbsent(t, findings, "SUDO-DEF-011")
	})

	t.Run("NewDefaultsRules_AuthenticateSetenvSudoeditTimeoutsChroot", func(t *testing.T) {
		policy := &SudoersPolicy{Defaults: []DefaultBinding{{Options: []Option{
			{"authenticate": false},
			{"setenv": true},
			{"sudoedit_follow": true},
			{"timestamp_timeout": "-1"},
			{"passwd_timeout": 0},
			{"timestamp_type": "global"},
			{"runchroot": "/var/chroot"},
			{"runcwd": "*"},
		}}}}
		findings := AuditDefaults(policy)
		assertFindingPresent(t, findings, "SUDO-DEF-012")
		assertFindingPresent(t, findings, "SUDO-DEF-013")
		assertFindingPresent(t, findings, "SUDO-DEF-014")
		assertFindingPresent(t, findings, "SUDO-DEF-015")
		assertFindingPresent(t, findings, "SUDO-DEF-016")
	})

	t.Run("ScopedDefaultsWeakening", func(t *testing.T) {
		policy := &SudoersPolicy{Defaults: []DefaultBinding{{
			Binding: []Member{{Username: "alice"}},
			Options: []Option{
				{"authenticate": false},
				{"env_reset": false},
				{"use_pty": false},
				{"noexec": false},
				{"visiblepw": true},
				{"setenv": true},
				{"sudoedit_follow": true},
				{"operation": "list_add", "env_keep": []any{"GIT_SSH_COMMAND", "BASH_FUNC_myfunc%%"}},
			},
		}}}
		findings := AuditDefaults(policy)
		assertFindingPresent(t, findings, "SUDO-DEF-012")
		assertFindingPresent(t, findings, "SUDO-DEF-011")
		assertFindingPresent(t, findings, "SUDO-DEF-003")
		assertFindingPresent(t, findings, "SUDO-DEF-007")
		assertFindingPresent(t, findings, "SUDO-DEF-005")
		assertFindingPresent(t, findings, "SUDO-DEF-013")
		assertFindingPresent(t, findings, "SUDO-DEF-014")
		assertFindingPresent(t, findings, "SUDO-DEF-004")
	})

	t.Run("CleanPolicy_ZeroFindings", func(t *testing.T) {
		policy := loadTestPolicy(t, "clean_policy.json")
		findings := AuditDefaults(policy)
		if len(findings) != 0 {
			t.Errorf("Expected 0 findings for clean policy defaults, got %d:", len(findings))
			for _, f := range findings {
				t.Errorf("  - %s: %s", f.ID, f.Title)
			}
		}
	})
}

// --- Commands Audit Tests ---

func TestAuditCommands(t *testing.T) {
	gtfoClient := requireGTFOClient(t)

	t.Run("NegatedCommand", func(t *testing.T) {
		policy := &SudoersPolicy{UserSpecs: []UserSpec{{
			UserList: []Member{{Username: "alice"}},
			HostList: []Member{{Hostname: "ALL"}},
			CmndSpecs: []CmndSpec{{
				Commands: []Member{{Command: "/usr/bin/passwd", Negated: true}},
			}},
		}}}
		findings := AuditCommands(policy, gtfoClient)
		assertFindingPresent(t, findings, "SUDO-CMD-001")
		assertFindingSeverity(t, findings, "SUDO-CMD-001", SeverityHigh)
	})

	t.Run("ALLWithPassword", func(t *testing.T) {
		policy := &SudoersPolicy{UserSpecs: []UserSpec{{
			UserList: []Member{{Username: "alice"}},
			HostList: []Member{{Hostname: "ALL"}},
			CmndSpecs: []CmndSpec{{
				Commands: []Member{{Command: "ALL"}},
			}},
		}}}
		findings := AuditCommands(policy, gtfoClient)
		assertFindingPresent(t, findings, "SUDO-CMD-002")
		assertFindingSeverity(t, findings, "SUDO-CMD-002", SeverityHigh)
	})

	t.Run("ALLWithNoPasswd", func(t *testing.T) {
		policy := &SudoersPolicy{UserSpecs: []UserSpec{{
			UserList: []Member{{Username: "alice"}},
			HostList: []Member{{Hostname: "ALL"}},
			CmndSpecs: []CmndSpec{{
				Options:  []Option{{"authenticate": false}},
				Commands: []Member{{Command: "ALL"}},
			}},
		}}}
		findings := AuditCommands(policy, gtfoClient)
		assertFindingPresent(t, findings, "SUDO-CMD-003")
		assertFindingSeverity(t, findings, "SUDO-CMD-003", SeverityCritical)
	})

	t.Run("WildcardCommand", func(t *testing.T) {
		policy := &SudoersPolicy{UserSpecs: []UserSpec{{
			UserList: []Member{{Username: "alice"}},
			HostList: []Member{{Hostname: "ALL"}},
			CmndSpecs: []CmndSpec{{
				Commands: []Member{{Command: "/usr/bin/cat /var/log/*"}},
			}},
		}}}
		findings := AuditCommands(policy, gtfoClient)
		assertFindingPresent(t, findings, "SUDO-CMD-004")
	})

	t.Run("GTFObinsMatch", func(t *testing.T) {
		policy := &SudoersPolicy{UserSpecs: []UserSpec{{
			UserList: []Member{{Username: "alice"}},
			HostList: []Member{{Hostname: "ALL"}},
			CmndSpecs: []CmndSpec{{
				Commands: []Member{{Command: "/usr/bin/find"}},
			}},
		}}}
		findings := AuditCommands(policy, gtfoClient)
		assertFindingPresent(t, findings, "SUDO-GTFO-001")
		assertFindingSeverity(t, findings, "SUDO-GTFO-001", SeverityHigh)
	})

	t.Run("GTFObinsWithNoPasswd", func(t *testing.T) {
		policy := &SudoersPolicy{UserSpecs: []UserSpec{{
			UserList: []Member{{Username: "alice"}},
			HostList: []Member{{Hostname: "ALL"}},
			CmndSpecs: []CmndSpec{{
				Options:  []Option{{"authenticate": false}},
				Commands: []Member{{Command: "/usr/bin/find"}},
			}},
		}}}
		findings := AuditCommands(policy, gtfoClient)
		assertFindingPresent(t, findings, "SUDO-GTFO-002")
		assertFindingSeverity(t, findings, "SUDO-GTFO-002", SeverityCritical)
	})

	t.Run("GTFObinsWithNoExecMitigation", func(t *testing.T) {
		policy := &SudoersPolicy{UserSpecs: []UserSpec{{
			UserList: []Member{{Username: "bob"}},
			HostList: []Member{{Hostname: "ALL"}},
			CmndSpecs: []CmndSpec{{
				Options:  []Option{{"noexec": true}},
				Commands: []Member{{Command: "/usr/bin/find"}},
			}},
		}}}
		findings := AuditCommands(policy, gtfoClient)
		assertFindingPresent(t, findings, "SUDO-GTFO-003")
		assertFindingSeverity(t, findings, "SUDO-GTFO-003", SeverityLow)
	})

	t.Run("GTFObinsConsolidation_OnePerFunction", func(t *testing.T) {
		policy := &SudoersPolicy{UserSpecs: []UserSpec{{
			UserList: []Member{{Username: "alice"}},
			HostList: []Member{{Hostname: "ALL"}},
			CmndSpecs: []CmndSpec{{
				Commands: []Member{{Command: "/usr/bin/bash \"\""}},
			}},
		}}}
		findings := AuditCommands(policy, gtfoClient)
		titlesSeen := make(map[string]bool)
		for _, f := range findings {
			if titlesSeen[f.Title] {
				t.Errorf("Duplicate finding title emitted for bash: %s", f.Title)
			}
			titlesSeen[f.Title] = true
		}
	})

	t.Run("NoPasswdSpecificCommand_NoGTFO", func(t *testing.T) {
		policy := &SudoersPolicy{UserSpecs: []UserSpec{{
			UserList: []Member{{Username: "alice"}},
			HostList: []Member{{Hostname: "ALL"}},
			CmndSpecs: []CmndSpec{{
				Options:  []Option{{"authenticate": false}},
				Commands: []Member{{Command: "/usr/local/bin/my-safe-script"}},
			}},
		}}}
		findings := AuditCommands(policy, gtfoClient)
		assertFindingPresent(t, findings, "SUDO-CMD-005")
		assertFindingSeverity(t, findings, "SUDO-CMD-005", SeverityLow)
	})

	t.Run("CommandAliasResolution_BothCmndaliasAndCommandalias", func(t *testing.T) {
		rawJSON := `{
			"User_Aliases": {
				"ADMINS": [{"username": "alice"}]
			},
			"Host_Aliases": {
				"SERVERS": [{"hostname": "web01"}]
			},
			"Runas_Aliases": {
				"DBUSERS": [{"username": "postgres"}]
			},
			"Command_Aliases": {
				"EDITORS": [
					{"command": "/usr/bin/vim"},
					{"command": "/usr/bin/nano"}
				]
			},
			"User_Specs": [{
				"User_List": [{"useralias": "ADMINS"}],
				"Host_List": [{"hostalias": "SERVERS"}],
				"Cmnd_Specs": [{
					"runasusers": [{"runasalias": "DBUSERS"}],
					"Commands": [{"cmndalias": "EDITORS"}]
				}]
			}]
		}`
		var policy SudoersPolicy
		if err := json.Unmarshal([]byte(rawJSON), &policy); err != nil {
			t.Fatalf("Failed to unmarshal cvtsudoers JSON: %v", err)
		}
		findings := AuditCommands(&policy, gtfoClient)
		hasVim := false
		for _, f := range findings {
			if f.Command == "/usr/bin/vim" && f.User == "alice" && f.Host == "web01" && f.Runas == "postgres" {
				hasVim = true
			}
		}
		if !hasVim {
			t.Errorf("Expected alias resolution for ADMINS, SERVERS, DBUSERS, and cmndalias EDITORS, got findings: %+v", findings)
		}
	})

	t.Run("CircularAliasDepthLimit", func(t *testing.T) {
		policy := loadTestPolicy(t, "circular_alias_policy.json")
		// Alias resolution must terminate on circular definitions instead of recursing forever.
		resolved := resolveCommands(policy.UserSpecs[0].CmndSpecs[0].Commands[0], policy)
		if len(resolved) == 0 || len(resolved) > maxResolveDepth {
			t.Errorf("Expected bounded non-empty resolution of circular command alias, got %d member(s): %+v", len(resolved), resolved)
		}
		// The full command audit must complete without panicking on the circular policy.
		_ = AuditCommands(policy, gtfoClient)
	})

	t.Run("EmptyPolicy", func(t *testing.T) {
		policy := &SudoersPolicy{}
		findings := AuditCommands(policy, gtfoClient)
		if len(findings) != 0 {
			t.Errorf("Expected 0 findings for empty policy, got %d", len(findings))
		}
	})

	t.Run("MissingArgumentRestrictions", func(t *testing.T) {
		policy := &SudoersPolicy{UserSpecs: []UserSpec{{
			UserList: []Member{{Username: "alice"}},
			HostList: []Member{{Hostname: "ALL"}},
			CmndSpecs: []CmndSpec{{
				Commands: []Member{{Command: "/usr/bin/dmesg"}},
			}},
		}}}
		findings := AuditCommands(policy, gtfoClient)
		assertFindingPresent(t, findings, "SUDO-CMD-006")
	})

	t.Run("HasArgumentRestrictions", func(t *testing.T) {
		policy := &SudoersPolicy{UserSpecs: []UserSpec{{
			UserList: []Member{{Username: "alice"}},
			HostList: []Member{{Hostname: "ALL"}},
			CmndSpecs: []CmndSpec{{
				Commands: []Member{
					{Command: "/usr/bin/dmesg \"\""},
					{Command: "/usr/bin/cat /var/log/messages"},
				},
			}},
		}}}
		findings := AuditCommands(policy, gtfoClient)
		assertFindingAbsent(t, findings, "SUDO-CMD-006")
	})

	t.Run("DirectEditorExecution_AndNoFalsePositives", func(t *testing.T) {
		policy := &SudoersPolicy{UserSpecs: []UserSpec{{
			UserList: []Member{{Username: "alice"}},
			HostList: []Member{{Hostname: "ALL"}},
			CmndSpecs: []CmndSpec{{
				Commands: []Member{{Command: "/usr/bin/vim \"\""}},
			}},
		}}}
		findings := AuditCommands(policy, gtfoClient)
		assertFindingPresent(t, findings, "SUDO-CMD-007")

		// Ensure non-editors starting with "vi" or "micro" are NOT flagged as SUDO-CMD-007
		safePolicy := &SudoersPolicy{UserSpecs: []UserSpec{{
			UserList: []Member{{Username: "alice"}},
			HostList: []Member{{Hostname: "ALL"}},
			CmndSpecs: []CmndSpec{{
				Commands: []Member{
					{Command: "/usr/sbin/visudo -c"},
					{Command: "/usr/bin/virsh list"},
					{Command: "/usr/bin/microdnf update"},
				},
			}},
		}}}
		safeFindings := AuditCommands(safePolicy, gtfoClient)
		assertFindingAbsent(t, safeFindings, "SUDO-CMD-007")
	})

	t.Run("NegatedRunasAndUsers_SUDO_CMD_008", func(t *testing.T) {
		policy := &SudoersPolicy{UserSpecs: []UserSpec{{
			UserList: []Member{{Usergroup: "wheel"}, {Username: "bob", Negated: true}},
			HostList: []Member{{Hostname: "ALL"}},
			CmndSpecs: []CmndSpec{{
				RunasUsers: []Member{{Username: "ALL"}, {Username: "root", Negated: true}},
				Commands:   []Member{{Command: "/usr/bin/id \"\""}},
			}},
		}}}
		findings := AuditCommands(policy, gtfoClient)
		assertFindingPresent(t, findings, "SUDO-CMD-008")
	})

	t.Run("CmndSpecOptions_Sudoedit_RelativeAndTempPaths_WeakDigest", func(t *testing.T) {
		policy := &SudoersPolicy{UserSpecs: []UserSpec{{
			UserList: []Member{{Username: "alice"}},
			HostList: []Member{{Hostname: "ALL"}},
			CmndSpecs: []CmndSpec{{
				Options: []Option{
					{"setenv": true},
					{"sudoedit_follow": true},
					{"runchroot": "/srv/jail"},
					{"runcwd": "*"},
				},
				Commands: []Member{
					{Command: "sudoedit /etc/sudoers"},
					{Command: "sudoedit"},
					{Command: "relative/bin/script \"\""},
					{Command: "/tmp/deploy.sh \"\"", SHA224: DigestList{"abcdef"}},
				},
			}},
		}}}
		findings := AuditCommands(policy, gtfoClient)
		assertFindingPresent(t, findings, "SUDO-CMD-009")
		assertFindingPresent(t, findings, "SUDO-CMD-010")
		assertFindingPresent(t, findings, "SUDO-CMD-011")
		assertFindingPresent(t, findings, "SUDO-CMD-012")
	})

	t.Run("CleanPolicy_ZeroFindings", func(t *testing.T) {
		policy := loadTestPolicy(t, "clean_policy.json")
		findings := AuditCommands(policy, gtfoClient)
		if len(findings) != 0 {
			t.Errorf("Expected 0 findings for clean policy commands, got %d:", len(findings))
			for _, f := range findings {
				t.Errorf("  - %s: %s (cmd: %s)", f.ID, f.Title, f.Command)
			}
		}
	})

	t.Run("ResolveEffectiveFlags_GlobalNoexecScopeIsolationAliasAndNegation", func(t *testing.T) {
		// 1. Global Defaults noexec mitigates find (shell) to SUDO-GTFO-003 LOW,
		// while non-shell functions (file-read) remain unmitigated SUDO-GTFO-001.
		globalNoexecPolicy := &SudoersPolicy{
			Defaults: []DefaultBinding{{Options: []Option{{"noexec": true}}}},
			UserSpecs: []UserSpec{{
				UserList:  []Member{{Username: "alice"}},
				HostList:  []Member{{Hostname: "ALL"}},
				CmndSpecs: []CmndSpec{{Commands: []Member{{Command: `/usr/bin/find ""`}}}},
			}},
		}
		globalNoexecFindings := AuditCommands(globalNoexecPolicy, gtfoClient)
		assertFindingPresent(t, globalNoexecFindings, "SUDO-GTFO-003")
		foundMitigatedShell := false
		for _, f := range globalNoexecFindings {
			if f.ID == "SUDO-GTFO-001" && strings.Contains(f.Title, "find (shell)") {
				t.Errorf("Expected global Defaults noexec to mitigate find (shell), got unmitigated %+v", f)
			}
			if f.ID == "SUDO-GTFO-003" && strings.Contains(f.Title, "find (shell)") {
				foundMitigatedShell = true
			}
		}
		if !foundMitigatedShell {
			t.Errorf("Expected SUDO-GTFO-003 for find (shell) under global Defaults noexec, got: %+v", globalNoexecFindings)
		}

		// 2. Defaults:root !authenticate must NOT bleed into alice ALL=(root) /usr/bin/find.
		userScopeIsolation := &SudoersPolicy{
			Defaults: []DefaultBinding{{
				Binding: []Member{{Username: "root"}},
				Options: []Option{{"authenticate": false}},
			}},
			UserSpecs: []UserSpec{{
				UserList: []Member{{Username: "alice"}},
				HostList: []Member{{Hostname: "ALL"}},
				CmndSpecs: []CmndSpec{{
					RunasUsers: []Member{{Username: "root"}},
					Commands:   []Member{{Command: `/usr/bin/find ""`}},
				}},
			}},
		}
		isoFindings := AuditCommands(userScopeIsolation, gtfoClient)
		assertFindingPresent(t, isoFindings, "SUDO-GTFO-001")
		assertFindingAbsent(t, isoFindings, "SUDO-GTFO-002")

		// 3. Defaults:OPS !authenticate expands User_Alias OPS = alice, bob.
		aliasPolicy := &SudoersPolicy{
			UserAliases: map[string][]Member{
				"OPS": {{Username: "alice"}, {Username: "bob"}},
			},
			Defaults: []DefaultBinding{{
				Binding: []Member{{UserAlias: "OPS"}},
				Options: []Option{{"authenticate": false}},
			}},
			UserSpecs: []UserSpec{{
				UserList:  []Member{{Username: "alice"}},
				HostList:  []Member{{Hostname: "ALL"}},
				CmndSpecs: []CmndSpec{{Commands: []Member{{Command: `/usr/bin/find ""`}}}},
			}},
		}
		aliasFindings := AuditCommands(aliasPolicy, gtfoClient)
		assertFindingPresent(t, aliasFindings, "SUDO-GTFO-002")

		// 4. Defaults:ALL, !alice !authenticate excludes alice while still matching bob.
		negatedBinding := &SudoersPolicy{
			Defaults: []DefaultBinding{{
				Binding: []Member{{Username: "ALL"}, {Username: "alice", Negated: true}},
				Options: []Option{{"authenticate": false}},
			}},
			UserSpecs: []UserSpec{
				{
					UserList:  []Member{{Username: "alice"}},
					HostList:  []Member{{Hostname: "ALL"}},
					CmndSpecs: []CmndSpec{{Commands: []Member{{Command: `/usr/bin/find ""`}}}},
				},
				{
					UserList:  []Member{{Username: "bob"}},
					HostList:  []Member{{Hostname: "ALL"}},
					CmndSpecs: []CmndSpec{{Commands: []Member{{Command: `/usr/bin/find ""`}}}},
				},
			},
		}
		negFindings := AuditCommands(negatedBinding, gtfoClient)
		aliceGot001 := false
		bobGot002 := false
		for _, f := range negFindings {
			if f.User == "alice" && f.ID == "SUDO-GTFO-002" {
				t.Errorf("Expected Defaults:ALL, !alice to exclude alice, got %+v", f)
			}
			if f.User == "alice" && f.ID == "SUDO-GTFO-001" {
				aliceGot001 = true
			}
			if f.User == "bob" && f.ID == "SUDO-GTFO-002" {
				bobGot002 = true
			}
		}
		if !aliceGot001 || !bobGot002 {
			t.Errorf("Expected alice SUDO-GTFO-001 (%v) and bob SUDO-GTFO-002 (%v)", aliceGot001, bobGot002)
		}
	})

	t.Run("DirectoryExecution_SUDO_CMD_014", func(t *testing.T) {
		dirPolicy := &SudoersPolicy{UserSpecs: []UserSpec{{
			UserList: []Member{{Username: "alice"}},
			HostList: []Member{{Hostname: "ALL"}},
			CmndSpecs: []CmndSpec{{
				Commands: []Member{{Command: `/usr/bin/ ""`}},
			}},
		}}}
		findings := AuditCommands(dirPolicy, gtfoClient)
		assertFindingPresent(t, findings, "SUDO-CMD-014")
		assertFindingSeverity(t, findings, "SUDO-CMD-014", SeverityHigh)
		assertFindingAbsent(t, findings, "SUDO-CMD-006")

		nopasswdDir := &SudoersPolicy{UserSpecs: []UserSpec{{
			UserList: []Member{{Username: "alice"}},
			HostList: []Member{{Hostname: "ALL"}},
			CmndSpecs: []CmndSpec{{
				Options:  []Option{{"authenticate": false}},
				Commands: []Member{{Command: `/usr/bin/`}},
			}},
		}}}
		critFindings := AuditCommands(nopasswdDir, gtfoClient)
		assertFindingPresent(t, critFindings, "SUDO-CMD-014")
		assertFindingSeverity(t, critFindings, "SUDO-CMD-014", SeverityCritical)
		assertFindingAbsent(t, critFindings, "SUDO-CMD-006")
	})

	t.Run("RegexCommandHandlingAndTokenSplitting", func(t *testing.T) {
		tokens := splitCommandTokens(`^/usr/bin/my prog$ "^arg with spaces$"`)
		if len(tokens) != 2 || tokens[0] != `^/usr/bin/my prog$` || tokens[1] != `"^arg with spaces$"` {
			t.Errorf("splitCommandTokens returned unexpected tokens: %#v", tokens)
		}

		// Anchored absolute regex ^/usr/bin/python3$ "" -> NO SUDO-CMD-011, YES SUDO-GTFO-001.
		pyRegexPolicy := &SudoersPolicy{UserSpecs: []UserSpec{{
			UserList:  []Member{{Username: "alice"}},
			HostList:  []Member{{Hostname: "ALL"}},
			CmndSpecs: []CmndSpec{{Commands: []Member{{Command: `^/usr/bin/python3$ ""`}}}},
		}}}
		pyFindings := AuditCommands(pyRegexPolicy, gtfoClient)
		assertFindingAbsent(t, pyFindings, "SUDO-CMD-011")
		assertFindingAbsent(t, pyFindings, "SUDO-CMD-006")
		assertFindingPresent(t, pyFindings, "SUDO-GTFO-001")

		// Alternation regex ^/usr/bin/(vim|nano)$ "" -> triggers SUDO-CMD-007 and GTFObins for vim & nano.
		edRegexPolicy := &SudoersPolicy{UserSpecs: []UserSpec{{
			UserList:  []Member{{Username: "alice"}},
			HostList:  []Member{{Hostname: "ALL"}},
			CmndSpecs: []CmndSpec{{Commands: []Member{{Command: `^/usr/bin/(vim|nano)$ ""`}}}},
		}}}
		edFindings := AuditCommands(edRegexPolicy, gtfoClient)
		assertFindingAbsent(t, edFindings, "SUDO-CMD-011")
		assertFindingPresent(t, edFindings, "SUDO-CMD-007")
		hasVim, hasNano := false, false
		for _, f := range edFindings {
			if f.ID == "SUDO-GTFO-001" && strings.Contains(f.Title, "vim") {
				hasVim = true
			}
			if f.ID == "SUDO-GTFO-001" && strings.Contains(f.Title, "nano") {
				hasNano = true
			}
		}
		if !hasVim || !hasNano {
			t.Errorf("Expected SUDO-GTFO-001 for both vim (%v) and nano (%v)", hasVim, hasNano)
		}

		// Relative regex ^bin/python3$ "" -> triggers SUDO-CMD-011.
		relRegexPolicy := &SudoersPolicy{UserSpecs: []UserSpec{{
			UserList:  []Member{{Username: "alice"}},
			HostList:  []Member{{Hostname: "ALL"}},
			CmndSpecs: []CmndSpec{{Commands: []Member{{Command: `^bin/python3$ ""`}}}},
		}}}
		assertFindingPresent(t, AuditCommands(relRegexPolicy, gtfoClient), "SUDO-CMD-011")
	})

	t.Run("SudoeditNoPasswdAndExpandedSensitiveTargets", func(t *testing.T) {
		noPasswdEdit := &SudoersPolicy{UserSpecs: []UserSpec{{
			UserList: []Member{{Username: "alice"}},
			HostList: []Member{{Hostname: "ALL"}},
			CmndSpecs: []CmndSpec{{
				Options:  []Option{{"authenticate": false}},
				Commands: []Member{{Command: "sudoedit /etc/myapp/config.conf"}},
			}},
		}}}
		findings := AuditCommands(noPasswdEdit, gtfoClient)
		assertFindingPresent(t, findings, "SUDO-CMD-005")
		assertFindingAbsent(t, findings, "SUDO-CMD-010")
		for _, f := range findings {
			if f.ID == "SUDO-CMD-005" && !strings.Contains(f.RemediationCode, "PASSWD: sudoedit") {
				t.Errorf("Expected PASSWD: sudoedit in RemediationCode, got %q", f.RemediationCode)
			}
		}

		for _, target := range []string{
			"/etc/*",
			"/etc",
			"/etc/nsswitch.conf",
			"/etc/profile.d/custom.sh",
			"/etc/polkit-1/rules.d/10-admin.rules",
			"/var/spool/cron/crontabs/root",
			"/usr/lib/systemd/system/app.service",
			"/lib/systemd/system/app.service",
		} {
			p := &SudoersPolicy{UserSpecs: []UserSpec{{
				UserList:  []Member{{Username: "alice"}},
				HostList:  []Member{{Hostname: "ALL"}},
				CmndSpecs: []CmndSpec{{Commands: []Member{{Command: "sudoedit " + target}}}},
			}}}
			assertFindingPresent(t, AuditCommands(p, gtfoClient), "SUDO-CMD-010")
		}
	})

	t.Run("NoexecImmuneBinariesAndWrapperRemediationAndHiddenNoPasswd", func(t *testing.T) {
		immuneBins := []string{"docker", "podman", "kubectl", "sudo", "su", "bash", "systemctl"}
		for _, bin := range immuneBins {
			p := &SudoersPolicy{UserSpecs: []UserSpec{{
				UserList: []Member{{Username: "alice"}},
				HostList: []Member{{Hostname: "ALL"}},
				CmndSpecs: []CmndSpec{{
					Options:  []Option{{"noexec": true}},
					Commands: []Member{{Command: "/usr/bin/" + bin + ` ""`}},
				}},
			}}}
			findings := AuditCommands(p, gtfoClient)
			assertFindingPresent(t, findings, "SUDO-GTFO-001")
			assertFindingAbsent(t, findings, "SUDO-GTFO-003")

			// Verify wrapper remediation uses PASSWD: EXEC: (never NOEXEC:).
			for _, f := range findings {
				if f.ID == "SUDO-GTFO-001" {
					if !strings.Contains(f.RemediationCode, "PASSWD: EXEC:") {
						t.Errorf("Expected PASSWD: EXEC: in wrapper RemediationCode for %s, got %q", bin, f.RemediationCode)
					}
					if strings.Contains(f.RemediationCode, "NOEXEC:") {
						t.Errorf("Did not expect NOEXEC: in wrapper RemediationCode for %s, got %q", bin, f.RemediationCode)
					}
				}
			}
		}

		// NOPASSWD + NOEXEC on a shell-only non-immune binary (chrt) downgrades all GTFObins
		// findings to SUDO-GTFO-003 AND emits SUDO-CMD-005 so NOPASSWD is not hidden.
		mitigatedNoPasswd := &SudoersPolicy{UserSpecs: []UserSpec{{
			UserList: []Member{{Username: "alice"}},
			HostList: []Member{{Hostname: "ALL"}},
			CmndSpecs: []CmndSpec{{
				Options:  []Option{{"authenticate": false}, {"noexec": true}},
				Commands: []Member{{Command: `/usr/bin/chrt ""`}},
			}},
		}}}
		mnFindings := AuditCommands(mitigatedNoPasswd, gtfoClient)
		assertFindingPresent(t, mnFindings, "SUDO-GTFO-003")
		assertFindingAbsent(t, mnFindings, "SUDO-GTFO-002")
		assertFindingPresent(t, mnFindings, "SUDO-CMD-005")
	})

	t.Run("ImpliedSetenvOnALLClarity", func(t *testing.T) {
		p := &SudoersPolicy{UserSpecs: []UserSpec{{
			UserList: []Member{{Username: "alice"}},
			HostList: []Member{{Hostname: "ALL"}},
			CmndSpecs: []CmndSpec{{
				Options:  []Option{{"setenv": true}},
				Commands: []Member{{Command: "ALL"}},
			}},
		}}}
		findings := AuditCommands(p, gtfoClient)
		foundClarity := false
		for _, f := range findings {
			if f.ID == "SUDO-CMD-009" && strings.Contains(f.Description, "implicitly enables 'SETENV'") {
				foundClarity = true
			}
		}
		if !foundClarity {
			t.Errorf("Expected SUDO-CMD-009 to explain implied SETENV on ALL, got: %+v", findings)
		}
	})
}

// --- SELinux Context Elevation Tests (SUDO-CMD-013) ---

func TestAuditSELinuxContextElevation(t *testing.T) {
	gtfoClient := requireGTFOClient(t)

	t.Run("AllCommandWithoutTypeRole", func(t *testing.T) {
		policy := &SudoersPolicy{UserSpecs: []UserSpec{{
			UserList:  []Member{{Username: "%wheel"}},
			HostList:  []Member{{Hostname: "ALL"}},
			CmndSpecs: []CmndSpec{{Commands: []Member{{Command: "ALL"}}}},
		}}}
		findings := AuditCommands(policy, gtfoClient)
		assertFindingPresent(t, findings, "SUDO-CMD-013")
		assertFindingSeverity(t, findings, "SUDO-CMD-013", SeverityInfo)
	})

	t.Run("AllRunasWithoutTypeRole", func(t *testing.T) {
		policy := &SudoersPolicy{UserSpecs: []UserSpec{{
			UserList:  []Member{{Username: "alice"}},
			HostList:  []Member{{Hostname: "ALL"}},
			CmndSpecs: []CmndSpec{{RunasUsers: []Member{{Username: "ALL"}}, Commands: []Member{{Command: "/usr/bin/systemctl"}}}},
		}}}
		findings := AuditCommands(policy, gtfoClient)
		assertFindingPresent(t, findings, "SUDO-CMD-013")
	})

	t.Run("PartialTypeOnly", func(t *testing.T) {
		policy := &SudoersPolicy{UserSpecs: []UserSpec{{
			UserList:  []Member{{Username: "alice"}},
			HostList:  []Member{{Hostname: "ALL"}},
			CmndSpecs: []CmndSpec{{Options: []Option{{"type": "sysadm_t"}}, Commands: []Member{{Command: "ALL"}}}},
		}}}
		findings := AuditCommands(policy, gtfoClient)
		assertFindingPresent(t, findings, "SUDO-CMD-013")
		for _, f := range findings {
			if f.ID == "SUDO-CMD-013" && f.Title != "Incomplete SELinux Context Elevation on Administrator Rule (TYPE/ROLE)" {
				t.Errorf("Expected incomplete-elevation variant title, got %q", f.Title)
			}
		}
	})

	t.Run("WithTypeRole_NoFinding", func(t *testing.T) {
		policy := &SudoersPolicy{UserSpecs: []UserSpec{{
			UserList:  []Member{{Username: "%wheel"}},
			HostList:  []Member{{Hostname: "ALL"}},
			CmndSpecs: []CmndSpec{{Options: []Option{{"type": "sysadm_t"}, {"role": "sysadm_r"}}, Commands: []Member{{Command: "ALL"}}}},
		}}}
		findings := AuditCommands(policy, gtfoClient)
		assertFindingAbsent(t, findings, "SUDO-CMD-013")
	})

	t.Run("NonAdminRule_NoFinding", func(t *testing.T) {
		policy := &SudoersPolicy{UserSpecs: []UserSpec{{
			UserList:  []Member{{Username: "alice"}},
			HostList:  []Member{{Hostname: "ALL"}},
			CmndSpecs: []CmndSpec{{RunasUsers: []Member{{Username: "root"}}, Commands: []Member{{Command: "/usr/bin/systemctl"}}}},
		}}}
		findings := AuditCommands(policy, gtfoClient)
		assertFindingAbsent(t, findings, "SUDO-CMD-013")
	})

	t.Run("NegatedALL_NoFinding", func(t *testing.T) {
		policy := &SudoersPolicy{UserSpecs: []UserSpec{{
			UserList: []Member{{Username: "alice"}},
			HostList: []Member{{Hostname: "ALL"}},
			CmndSpecs: []CmndSpec{
				{
					RunasUsers: []Member{{Username: "root"}},
					Commands:   []Member{{Command: "ALL", Negated: true}},
				},
				{
					RunasUsers: []Member{{Username: "ALL", Negated: true}},
					Commands:   []Member{{Command: `/usr/bin/id ""`}},
				},
			},
		}}}
		findings := AuditCommands(policy, gtfoClient)
		assertFindingAbsent(t, findings, "SUDO-CMD-013")
	})
}

// --- Version Parsing Tests ---

func TestParseSudoVersion(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
		major   int
		minor   int
		patch   int
		pl      int
	}{
		{"Standard", "1.9.12", false, 1, 9, 12, 0},
		{"WithPatchLevel", "1.8.31p2", false, 1, 8, 31, 2},
		{"OldVersion", "1.8.0", false, 1, 8, 0, 0},
		{"WithTrailingText", "1.9.5p1\n", false, 1, 9, 5, 1},
		{"WithDistroSuffix", "Sudo version 1.8.31 (Debian 10)", false, 1, 8, 31, 0},
		{"WithUbuntuPackage", "1.9.5p1-1ubuntu2", false, 1, 9, 5, 1},
		{"Invalid", "not-a-version", true, 0, 0, 0, 0},
		{"Empty", "", true, 0, 0, 0, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, err := ParseSudoVersion(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Errorf("Expected error for input %q, got nil", tt.input)
				}
				return
			}
			if err != nil {
				t.Fatalf("Unexpected error for input %q: %v", tt.input, err)
			}
			if v.Major != tt.major || v.Minor != tt.minor || v.Patch != tt.patch || v.Pl != tt.pl {
				t.Errorf("Got %d.%d.%dp%d, want %d.%d.%dp%d", v.Major, v.Minor, v.Patch, v.Pl, tt.major, tt.minor, tt.patch, tt.pl)
			}
		})
	}
}

func TestSudoVersionCompare(t *testing.T) {
	tests := []struct {
		name string
		a, b SudoVersion
		want int
	}{
		{"Equal", SudoVersion{Major: 1, Minor: 9, Patch: 12, Pl: 0}, SudoVersion{Major: 1, Minor: 9, Patch: 12, Pl: 0}, 0},
		{"LessMajor", SudoVersion{Major: 1, Minor: 8, Patch: 0, Pl: 0}, SudoVersion{Major: 2, Minor: 0, Patch: 0, Pl: 0}, -1},
		{"GreaterMajor", SudoVersion{Major: 2, Minor: 0, Patch: 0, Pl: 0}, SudoVersion{Major: 1, Minor: 8, Patch: 0, Pl: 0}, 1},
		{"LessMinor", SudoVersion{Major: 1, Minor: 8, Patch: 31, Pl: 2}, SudoVersion{Major: 1, Minor: 9, Patch: 0, Pl: 0}, -1},
		{"GreaterMinor", SudoVersion{Major: 1, Minor: 9, Patch: 0, Pl: 0}, SudoVersion{Major: 1, Minor: 8, Patch: 31, Pl: 2}, 1},
		{"LessPatch", SudoVersion{Major: 1, Minor: 9, Patch: 5, Pl: 0}, SudoVersion{Major: 1, Minor: 9, Patch: 12, Pl: 0}, -1},
		{"GreaterPatch", SudoVersion{Major: 1, Minor: 9, Patch: 12, Pl: 0}, SudoVersion{Major: 1, Minor: 9, Patch: 5, Pl: 0}, 1},
		{"GreaterPl", SudoVersion{Major: 1, Minor: 9, Patch: 12, Pl: 2}, SudoVersion{Major: 1, Minor: 9, Patch: 12, Pl: 1}, 1},
		{"LessPl", SudoVersion{Major: 1, Minor: 8, Patch: 31, Pl: 1}, SudoVersion{Major: 1, Minor: 8, Patch: 31, Pl: 2}, -1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.a.Compare(tt.b)
			if got != tt.want {
				t.Errorf("%v.Compare(%v) = %d, want %d", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func TestAuditSudoVersion(t *testing.T) {
	tests := []struct {
		name          string
		version       string
		checkCVE      string
		expectPresent bool
	}{
		{"CVE-2019-14287_Vulnerable", "1.8.27", "CVE-2019-14287", true},
		{"CVE-2019-14287_Fixed", "1.8.28", "CVE-2019-14287", false},
		{"CVE-2019-18634_Vulnerable", "1.8.25", "CVE-2019-18634", true},
		{"CVE-2019-18634_Fixed", "1.8.31", "CVE-2019-18634", false},
		{"CVE-2021-3156_Vulnerable_17x_First", "1.7.7", "CVE-2021-3156", true},
		{"CVE-2021-3156_Vulnerable_17x_Last", "1.7.10p9", "CVE-2021-3156", true},
		{"CVE-2021-3156_Below_17x", "1.7.6", "CVE-2021-3156", false},
		{"CVE-2021-3156_Vulnerable_18x", "1.8.31p1", "CVE-2021-3156", true},
		{"CVE-2021-3156_Fixed_18x", "1.8.32", "CVE-2021-3156", false},
		{"CVE-2021-3156_Vulnerable_19x", "1.9.5p1", "CVE-2021-3156", true},
		{"CVE-2021-3156_Fixed_19x", "1.9.6", "CVE-2021-3156", false},
		{"CVE-2023-22809_Vulnerable", "1.9.12p1", "CVE-2023-22809", true},
		{"CVE-2023-22809_Fixed", "1.9.12p2", "CVE-2023-22809", false},
		{"CVE-2023-27320_Vulnerable", "1.9.13p1", "CVE-2023-27320", true},
		{"CVE-2023-27320_Fixed", "1.9.13p2", "CVE-2023-27320", false},
		{"CVE-2025-32462_Vulnerable", "1.9.17", "CVE-2025-32462", true},
		{"CVE-2025-32462_Fixed", "1.9.17p1", "CVE-2025-32462", false},
		{"CVE-2025-32463_Vulnerable", "1.9.17", "CVE-2025-32463", true},
		{"CVE-2025-32463_Fixed", "1.9.17p1", "CVE-2025-32463", false},
		{"AllClear_Latest", "1.9.17p2", "CVE-2025-32463", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings, err := AuditSudoVersion(tt.version)
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}
			if tt.expectPresent {
				assertFindingPresent(t, findings, tt.checkCVE)
			} else {
				assertFindingAbsent(t, findings, tt.checkCVE)
			}
		})
	}

	t.Run("EmptyVersion", func(t *testing.T) {
		findings, err := AuditSudoVersion("")
		if err != nil {
			t.Fatalf("Unexpected error for empty version: %v", err)
		}
		if findings != nil {
			t.Errorf("Expected nil findings for empty version, got %d", len(findings))
		}
	})

	t.Run("InvalidVersionReturnsInfoFinding", func(t *testing.T) {
		findings, err := AuditSudoVersion("invalid-ver")
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		assertFindingPresent(t, findings, "SUDO-SYS-001")
	})

	t.Run("CVE_2022_43995_SeverityAndDetails", func(t *testing.T) {
		findings, err := AuditSudoVersion("1.9.12")
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		assertFindingPresent(t, findings, "CVE-2022-43995")
		assertFindingSeverity(t, findings, "CVE-2022-43995", SeverityMedium)
		for _, f := range findings {
			if f.ID == "CVE-2022-43995" {
				if f.Title != "Sudo crypt() Password Prompt Heap Buffer Over-Read" {
					t.Errorf("Unexpected CVE-2022-43995 title: %q", f.Title)
				}
				if !strings.Contains(f.Description, "non-PAM") || !strings.Contains(f.Description, "backport") {
					t.Errorf("Expected non-PAM and distro backport note in CVE-2022-43995 description, got: %q", f.Description)
				}
			}
		}
	})
}

func TestPermissionEvaluators(t *testing.T) {
	t.Run("SudoersFilePermissions_Secure", func(t *testing.T) {
		findings := evaluateSudoersFilePermissions("/etc/sudoers", 0440, 0, 0, true)
		if len(findings) != 0 {
			t.Errorf("Expected 0 findings for 0440 root:root, got %v", findings)
		}
	})

	t.Run("SudoersFilePermissions_Vulnerable", func(t *testing.T) {
		findings := evaluateSudoersFilePermissions("/etc/sudoers", 0666, 1000, 1000, true)
		assertFindingPresent(t, findings, "SUDO-SYS-PERM-002")
		assertFindingPresent(t, findings, "SUDO-SYS-PERM-003")
		assertFindingPresent(t, findings, "SUDO-SYS-PERM-004")
		assertFindingPresent(t, findings, "SUDO-SYS-PERM-005")
		assertFindingPresent(t, findings, "SUDO-SYS-PERM-011")
	})

	t.Run("SudoersDirPermissions_SecureAndVulnerable", func(t *testing.T) {
		secure := evaluateSudoersDirPermissions("/etc/sudoers.d", os.ModeDir|0750, 0, 0, true)
		if len(secure) != 0 {
			t.Errorf("Expected 0 findings for 0750 root:root /etc/sudoers.d, got %+v", secure)
		}

		vuln := evaluateSudoersDirPermissions("/etc/sudoers.d", os.ModeDir|0777, 1000, 1000, true)
		for _, id := range []string{"SUDO-SYS-PERM-002", "SUDO-SYS-PERM-003", "SUDO-SYS-PERM-004", "SUDO-SYS-PERM-005", "SUDO-SYS-PERM-011"} {
			assertFindingPresent(t, vuln, id)
		}
		for _, f := range vuln {
			if !strings.Contains(f.RemediationCode, "chmod 0750 /etc/sudoers.d") {
				t.Errorf("Expected 'chmod 0750 /etc/sudoers.d' in RemediationCode for %s, got %q", f.ID, f.RemediationCode)
			}
			if strings.Contains(f.RemediationCode, "0440") || strings.Contains(f.RemediationCode, "visudo -c -f") {
				t.Errorf("Directory finding %s must NOT suggest 0440 or visudo -c -f, got %q", f.ID, f.RemediationCode)
			}
		}
	})

	t.Run("TargetDirPermissions", func(t *testing.T) {
		clean := evaluateTargetDirPermissions("/usr/local/bin", "/usr/local/bin/app", os.ModeDir|0755, 0, true, false)
		if len(clean) != 0 {
			t.Errorf("Expected 0 findings for 0755 root-owned dir, got %+v", clean)
		}

		nonRoot := evaluateTargetDirPermissions("/opt/custom", "/opt/custom/app", os.ModeDir|0755, 1000, true, false)
		assertFindingPresent(t, nonRoot, "SUDO-SYS-PERM-013")
		assertFindingSeverity(t, nonRoot, "SUDO-SYS-PERM-013", SeverityCritical)

		groupWritable := evaluateTargetDirPermissions("/opt/custom", "/opt/custom/app", os.ModeDir|0775, 0, true, false)
		assertFindingPresent(t, groupWritable, "SUDO-SYS-PERM-013")

		worldWritableNoSticky := evaluateTargetDirPermissions("/opt/custom", "/opt/custom/app", os.ModeDir|0777, 0, true, false)
		assertFindingPresent(t, worldWritableNoSticky, "SUDO-SYS-PERM-013")

		stickyExisting := evaluateTargetDirPermissions("/tmp", "/tmp/existing", os.ModeDir|os.ModeSticky|0777, 0, true, false)
		if len(stickyExisting) != 0 {
			t.Errorf("Expected 0 findings for existing target in root-owned sticky /tmp, got %+v", stickyExisting)
		}

		stickyMissing := evaluateTargetDirPermissions("/tmp", "/tmp/missing", os.ModeDir|os.ModeSticky|0777, 0, true, true)
		assertFindingPresent(t, stickyMissing, "SUDO-SYS-PERM-013")
		assertFindingSeverity(t, stickyMissing, "SUDO-SYS-PERM-013", SeverityCritical)
	})

	t.Run("SudoBinaryPermissions_Secure", func(t *testing.T) {
		findings := evaluateSudoBinaryPermissions("/usr/bin/sudo", os.ModeSetuid|0755, 0, 0, true)
		if len(findings) != 0 {
			t.Errorf("Expected 0 findings for 4755 root:root sudo binary, got %v", findings)
		}
	})

	t.Run("SudoBinaryPermissions_Vulnerable", func(t *testing.T) {
		findings := evaluateSudoBinaryPermissions("/usr/bin/sudo", 0777, 1000, 1000, true)
		assertFindingPresent(t, findings, "SUDO-SYS-PERM-007")
		assertFindingPresent(t, findings, "SUDO-SYS-PERM-008")
		assertFindingPresent(t, findings, "SUDO-SYS-PERM-009")
		assertFindingPresent(t, findings, "SUDO-SYS-PERM-010")
	})

	t.Run("TargetBinaryPermissions", func(t *testing.T) {
		writableFindings := evaluateTargetBinaryPermissions("/usr/local/bin/custom.sh", 0777, 0, true)
		assertFindingPresent(t, writableFindings, "SUDO-SYS-PERM-012")
		assertFindingSeverity(t, writableFindings, "SUDO-SYS-PERM-012", SeverityCritical)

		nonRootFindings := evaluateTargetBinaryPermissions("/usr/local/bin/custom.sh", 0755, 1000, true)
		assertFindingPresent(t, nonRootFindings, "SUDO-SYS-PERM-012")
		assertFindingSeverity(t, nonRootFindings, "SUDO-SYS-PERM-012", SeverityHigh)

		cleanFindings := evaluateTargetBinaryPermissions("/usr/local/bin/custom.sh", 0755, 0, true)
		if len(cleanFindings) != 0 {
			t.Errorf("Expected 0 findings for 0755 root-owned target binary, got %v", cleanFindings)
		}
	})
}

// --- Helper Function Tests ---

func TestTypesAndHelpers(t *testing.T) {
	t.Run("ParseSeverityAndHasSeverityAtLeast", func(t *testing.T) {
		for _, tc := range []struct {
			in   string
			want Severity
			ok   bool
		}{
			{"critical", SeverityCritical, true},
			{"HIGH", SeverityHigh, true},
			{"Med", SeverityMedium, true},
			{"low", SeverityLow, true},
			{"info", SeverityInfo, true},
			{"unknown", "", false},
		} {
			got, ok := ParseSeverity(tc.in)
			if ok != tc.ok || got != tc.want {
				t.Errorf("ParseSeverity(%q) = (%v, %v), want (%v, %v)", tc.in, got, ok, tc.want, tc.ok)
			}
		}

		findings := []Finding{{ID: "1", Severity: SeverityMedium}}
		if !HasSeverityAtLeast(SeverityMedium, findings) {
			t.Error("Expected HasSeverityAtLeast(MEDIUM) to be true")
		}
		if !HasSeverityAtLeast(SeverityLow, findings) {
			t.Error("Expected HasSeverityAtLeast(LOW) to be true")
		}
		if HasSeverityAtLeast(SeverityHigh, findings) {
			t.Error("Expected HasSeverityAtLeast(HIGH) to be false")
		}
	})

	t.Run("MemberGetNameAndDigests", func(t *testing.T) {
		uid := 0
		gid := 27
		ngid := 500
		cases := []struct {
			m    Member
			want string
		}{
			{Member{Username: "alice"}, "alice"},
			{Member{Username: "bob", Negated: true}, "!bob"},
			{Member{Myself: true}, "MYSELF"},
			{Member{UserID: &uid}, "#0"},
			{Member{Usergroup: "sudo"}, "%sudo"},
			{Member{UserGID: &gid}, "%#27"},
			{Member{NonUnixGroup: "ad_admins"}, "%:ad_admins"},
			{Member{NonUnixGID: &ngid}, "%:#500"},
			{Member{Netgroup: "netgrp"}, "+netgrp"},
			{Member{Hostname: "host1"}, "host1"},
			{Member{NetworkAddr: "10.0.0.0/24"}, "10.0.0.0/24"},
			{Member{Command: "/bin/ls"}, "/bin/ls"},
			{Member{CommandAlias: "CMDS"}, "CMDS"},
			{Member{UserAlias: "USERS"}, "USERS"},
			{Member{RunasAlias: "RUNAS"}, "RUNAS"},
			{Member{HostAlias: "HOSTS"}, "HOSTS"},
			{Member{}, ""},
		}
		for _, tc := range cases {
			if got := tc.m.GetName(); got != tc.want {
				t.Errorf("Member%+v.GetName() = %q, want %q", tc.m, got, tc.want)
			}
		}

		var mSingle, mMulti, mMyself Member
		_ = json.Unmarshal([]byte(`{"command": "/bin/ls", "sha256": "abc"}`), &mSingle)
		if !mSingle.HasDigests() || len(mSingle.SHA256) != 1 || mSingle.SHA256[0] != "abc" {
			t.Errorf("Unexpected single digest unmarshal: %+v", mSingle)
		}
		_ = json.Unmarshal([]byte(`{"command": "/bin/ls", "sha256": ["abc", "def"]}`), &mMulti)
		if len(mMulti.SHA256) != 2 {
			t.Errorf("Unexpected multi digest unmarshal: %+v", mMulti)
		}
		_ = json.Unmarshal([]byte(`{"username": ""}`), &mMyself)
		if !mMyself.Myself || mMyself.GetName() != "MYSELF" {
			t.Errorf("Expected MYSELF for empty username JSON, got %+v", mMyself)
		}
	})
}

func TestCountBySeverity(t *testing.T) {
	findings1 := []Finding{
		{ID: "1", Severity: SeverityCritical},
		{ID: "2", Severity: SeverityHigh},
		{ID: "3", Severity: SeverityCritical},
	}
	findings2 := []Finding{
		{ID: "4", Severity: SeverityLow},
		{ID: "5", Severity: SeverityInfo},
	}

	counts := CountBySeverity(findings1, findings2)
	if counts[SeverityCritical] != 2 {
		t.Errorf("Expected 2 critical, got %d", counts[SeverityCritical])
	}
	if counts[SeverityHigh] != 1 {
		t.Errorf("Expected 1 high, got %d", counts[SeverityHigh])
	}
	if counts[SeverityLow] != 1 {
		t.Errorf("Expected 1 low, got %d", counts[SeverityLow])
	}
	if counts[SeverityInfo] != 1 {
		t.Errorf("Expected 1 info, got %d", counts[SeverityInfo])
	}
	if counts[SeverityMedium] != 0 {
		t.Errorf("Expected 0 medium, got %d", counts[SeverityMedium])
	}
}

func TestSortFindingsBySeverity(t *testing.T) {
	findings := []Finding{
		{ID: "info", Severity: SeverityInfo},
		{ID: "crit", Severity: SeverityCritical},
		{ID: "low", Severity: SeverityLow},
		{ID: "high", Severity: SeverityHigh},
		{ID: "med", Severity: SeverityMedium},
	}

	SortFindingsBySeverity(findings)

	expected := []Severity{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInfo}
	for i, f := range findings {
		if f.Severity != expected[i] {
			t.Errorf("Position %d: expected %s, got %s", i, expected[i], f.Severity)
		}
	}
}

// --- Full Integration Test ---

func TestRunAudit_VulnerablePolicy(t *testing.T) {
	gtfoClient := requireGTFOClient(t)
	policy := loadTestPolicy(t, "vulnerable_policy.json")

	findings := RunAudit(policy, gtfoClient)

	expectedIDs := []string{
		"SUDO-DEF-001", // missing secure_path
		"SUDO-DEF-003", // disabled use_pty
		"SUDO-DEF-004", // dangerous env_keep
		"SUDO-DEF-005", // visiblepw
		"SUDO-DEF-006", // pwfeedback
		"SUDO-DEF-007", // missing or disabled noexec
		"SUDO-DEF-008", // missing or disabled requiretty
		"SUDO-DEF-009", // missing or weak umask
		"SUDO-DEF-010", // missing or disabled ignore_dot
		"SUDO-DEF-011", // missing or disabled env_reset
		"SUDO-CMD-001", // negated command
		"SUDO-CMD-003", // ALL + NOPASSWD
		"SUDO-CMD-004", // wildcard
		"SUDO-CMD-006", // missing argument restrictions
		"SUDO-CMD-007", // direct editor execution
	}

	for _, id := range expectedIDs {
		assertFindingPresent(t, findings, id)
	}

	hasGTFO := false
	for _, f := range findings {
		if f.ID == "SUDO-GTFO-001" || f.ID == "SUDO-GTFO-002" || f.ID == "SUDO-GTFO-003" {
			hasGTFO = true
		}
		if f.RemediationCode == "" {
			t.Errorf("Expected non-empty RemediationCode for finding %s (%s)", f.ID, f.Title)
		}
	}
	if !hasGTFO {
		t.Error("Expected GTFObins findings from vulnerable policy")
	}
}

func TestRemediationCodePopulation(t *testing.T) {
	t.Run("ScopedDefaultsAndSecurePathSanitize", func(t *testing.T) {
		policy := &SudoersPolicy{
			Defaults: []DefaultBinding{
				{
					Options: []Option{
						{"secure_path": "/usr/sbin:/tmp:/usr/bin:./bin:"},
					},
				},
				{
					Binding: []Member{{Username: "alice"}},
					Options: []Option{
						{"env_reset": false},
						{"operation": "list_add", "env_keep": []any{"LD_PRELOAD"}},
						{"umask": "0022"},
					},
				},
			},
		}
		findings := AuditDefaults(policy)
		for _, f := range findings {
			if f.RemediationCode == "" {
				t.Errorf("Expected RemediationCode on %s, got empty", f.ID)
			}
			if f.ID == "SUDO-DEF-002" && !strings.Contains(f.RemediationCode, `Defaults secure_path="/usr/sbin:/usr/bin"`) {
				t.Errorf("Expected sanitized secure_path in SUDO-DEF-002 RemediationCode, got %q", f.RemediationCode)
			}
			if f.ID == "SUDO-DEF-004" && !strings.Contains(f.RemediationCode, "Defaults:alice ") {
				t.Errorf("Expected scoped Defaults:alice directive in SUDO-DEF-004 RemediationCode, got %q", f.RemediationCode)
			}
		}
	})

	t.Run("SystemPermissionsAndVersionRemediationCode", func(t *testing.T) {
		sysPerm := evaluateSudoersFilePermissions("/etc/sudoers", 0666, 1000, 1000, true)
		for _, f := range sysPerm {
			if f.RemediationCode == "" {
				t.Errorf("Expected RemediationCode on %s, got empty", f.ID)
			}
		}
		dirPerm := evaluateSudoersDirPermissions("/etc/sudoers.d", os.ModeDir|0777, 1000, 1000, true)
		for _, f := range dirPerm {
			if f.RemediationCode == "" {
				t.Errorf("Expected RemediationCode on %s, got empty", f.ID)
			}
		}
		targetDirPerm := evaluateTargetDirPermissions("/tmp", "/tmp/missing.sh", os.ModeDir|os.ModeSticky|0777, 1000, true, true)
		for _, f := range targetDirPerm {
			if f.RemediationCode == "" {
				t.Errorf("Expected RemediationCode on %s, got empty", f.ID)
			}
		}
		binPerm := evaluateSudoBinaryPermissions("/usr/bin/sudo", 0777, 1000, 1000, true)
		for _, f := range binPerm {
			if f.RemediationCode == "" {
				t.Errorf("Expected RemediationCode on %s, got empty", f.ID)
			}
		}
		targetPerm := evaluateTargetBinaryPermissions("/usr/local/bin/deploy.sh", 0777, 1000, true)
		for _, f := range targetPerm {
			if f.RemediationCode == "" {
				t.Errorf("Expected RemediationCode on %s, got empty", f.ID)
			}
		}
		verFindings, err := AuditSudoVersion("Sudo version 1.8.27")
		if err != nil {
			t.Fatalf("AuditSudoVersion failed: %v", err)
		}
		for _, f := range verFindings {
			if f.RemediationCode == "" {
				t.Errorf("Expected RemediationCode on %s, got empty", f.ID)
			}
		}
	})
}

func TestRunAudit_CleanPolicy(t *testing.T) {
	gtfoClient := requireGTFOClient(t)
	policy := loadTestPolicy(t, "clean_policy.json")

	findings := RunAudit(policy, gtfoClient)
	if len(findings) != 0 {
		t.Errorf("Expected 0 findings for clean policy, got %d:", len(findings))
		for _, f := range findings {
			t.Errorf("  - %s: %s", f.ID, f.Title)
		}
	}
}

func TestRunAuditWithOptions(t *testing.T) {
	gtfoClient := requireGTFOClient(t)

	t.Run("NilPolicySafety", func(t *testing.T) {
		if got := RunAudit(nil, gtfoClient); got != nil {
			t.Errorf("RunAudit(nil) = %+v, want nil", got)
		}
		if got := AuditCommands(nil, gtfoClient); got != nil {
			t.Errorf("AuditCommands(nil) = %+v, want nil", got)
		}
		got := RunAuditWithOptions(nil, gtfoClient, AuditOptions{
			DropInMode:          true,
			SubcommandAwareGTFO: true,
			CheckShadowing:      true,
			Now:                 time.Now,
		})
		if got != nil {
			t.Errorf("RunAuditWithOptions(nil) = %+v, want nil", got)
		}
	})

	t.Run("DropInMode_SuppressesOmittedGlobalDefaultsOnly", func(t *testing.T) {
		cleanDropIn := &SudoersPolicy{
			UserSpecs: []UserSpec{{
				UserList: []Member{{Username: "ops"}},
				HostList: []Member{{Hostname: "ALL"}},
				CmndSpecs: []CmndSpec{{
					Commands: []Member{{Command: `/usr/sbin/reboot ""`}},
				}},
				File: "/etc/sudoers.d/ops",
				Line: 1,
			}},
		}
		defaultFindings := RunAudit(cleanDropIn, gtfoClient)
		for id := range GlobalMissingDefaultRuleIDs {
			assertFindingPresent(t, defaultFindings, id)
		}

		dropInCleanFindings := RunAuditWithOptions(cleanDropIn, gtfoClient, AuditOptions{DropInMode: true})
		if len(dropInCleanFindings) != 0 {
			t.Errorf("Expected 0 findings for clean drop-in under DropInMode, got %d: %+v", len(dropInCleanFindings), dropInCleanFindings)
		}

		mixedDropIn := &SudoersPolicy{
			Defaults: []DefaultBinding{
				{
					File: "/etc/sudoers.d/app",
					Line: 1,
					Options: []Option{
						{"visiblepw": true},
						{"operation": "list_add", "env_keep": []any{"LD_PRELOAD"}},
					},
				},
				{
					File:    "/etc/sudoers.d/app",
					Line:    2,
					Binding: []Member{{Username: "alice"}},
					Options: []Option{{"use_pty": false}},
				},
			},
			UserSpecs: []UserSpec{{
				UserList: []Member{{Username: "alice"}},
				HostList: []Member{{Hostname: "ALL"}},
				CmndSpecs: []CmndSpec{{
					Commands: []Member{{Command: "/usr/bin/find"}},
				}},
				File: "/etc/sudoers.d/app",
				Line: 3,
			}},
		}
		findings := RunAuditWithOptions(mixedDropIn, gtfoClient, AuditOptions{DropInMode: true})
		for _, suppressedID := range []string{
			"SUDO-DEF-001",
			"SUDO-DEF-007",
			"SUDO-DEF-008",
			"SUDO-DEF-009",
			"SUDO-DEF-010",
			"SUDO-DEF-011",
			"SUDO-DEF-017",
		} {
			assertFindingAbsent(t, findings, suppressedID)
		}
		assertFindingPresent(t, findings, "SUDO-DEF-004")
		assertFindingPresent(t, findings, "SUDO-DEF-005")
		assertFindingPresent(t, findings, "SUDO-CMD-006")
		assertFindingPresent(t, findings, "SUDO-GTFO-001")

		foundScopedUsePty := false
		for _, f := range findings {
			if f.ID == "SUDO-DEF-003" {
				if f.User == "" {
					t.Errorf("Expected global omitted SUDO-DEF-003 to be suppressed in DropInMode, got %+v", f)
				}
				if f.User == "alice" {
					foundScopedUsePty = true
				}
			}
		}
		if !foundScopedUsePty {
			t.Errorf("Expected scoped Defaults:alice !use_pty (SUDO-DEF-003) to still fire in DropInMode")
		}

		// Explicit global weakenings inside a drop-in file must still fire.
		explicitWeakDropIn := &SudoersPolicy{
			Defaults: []DefaultBinding{{
				File: "/etc/sudoers.d/weak",
				Line: 1,
				Options: []Option{
					{"use_pty": false},
					{"env_reset": false},
					{"umask": "0022"},
				},
			}},
		}
		explicitFindings := RunAuditWithOptions(explicitWeakDropIn, gtfoClient, AuditOptions{DropInMode: true})
		assertFindingPresent(t, explicitFindings, "SUDO-DEF-003")
		assertFindingPresent(t, explicitFindings, "SUDO-DEF-009")
		assertFindingPresent(t, explicitFindings, "SUDO-DEF-011")
		for _, omittedID := range []string{"SUDO-DEF-001", "SUDO-DEF-007", "SUDO-DEF-008", "SUDO-DEF-010", "SUDO-DEF-017"} {
			assertFindingAbsent(t, explicitFindings, omittedID)
		}
	})

	t.Run("SubcommandAwareGTFO", func(t *testing.T) {
		policy := &SudoersPolicy{
			UserSpecs: []UserSpec{
				{
					UserList: []Member{{Username: "alice"}},
					HostList: []Member{{Hostname: "ALL"}},
					CmndSpecs: []CmndSpec{{
						Commands: []Member{{Command: "/usr/bin/systemctl restart nginx"}},
					}},
				},
				{
					UserList: []Member{{Username: "bob"}},
					HostList: []Member{{Hostname: "ALL"}},
					CmndSpecs: []CmndSpec{{
						Options:  []Option{{"authenticate": false}},
						Commands: []Member{{Command: "/usr/bin/systemctl restart nginx"}},
					}},
				},
				{
					UserList: []Member{{Username: "carol"}},
					HostList: []Member{{Hostname: "ALL"}},
					CmndSpecs: []CmndSpec{{
						Commands: []Member{{Command: "/usr/bin/systemctl status nginx"}},
					}},
				},
				{
					UserList: []Member{{Username: "dave"}},
					HostList: []Member{{Hostname: "ALL"}},
					CmndSpecs: []CmndSpec{{
						Options:  []Option{{"authenticate": false}},
						Commands: []Member{{Command: "/usr/bin/systemctl status nginx"}},
					}},
				},
				{
					UserList: []Member{{Username: "eve"}},
					HostList: []Member{{Hostname: "ALL"}},
					CmndSpecs: []CmndSpec{{
						Commands: []Member{{Command: "/usr/bin/vim /etc/hosts"}},
					}},
				},
				{
					UserList: []Member{{Username: "frank"}},
					HostList: []Member{{Hostname: "ALL"}},
					CmndSpecs: []CmndSpec{{
						Commands: []Member{{Command: "^/usr/bin/systemctl$ restart nginx"}},
					}},
				},
				{
					UserList: []Member{{Username: "grace"}},
					HostList: []Member{{Hostname: "ALL"}},
					CmndSpecs: []CmndSpec{{
						Options:  []Option{{"noexec": true}},
						Commands: []Member{{Command: "/bin/cat /var/log/syslog"}},
					}},
				},
				{
					UserList: []Member{{Username: "henry"}},
					HostList: []Member{{Hostname: "ALL"}},
					CmndSpecs: []CmndSpec{{
						Options:  []Option{{"noexec": true}},
						Commands: []Member{{Command: "/usr/bin/apt-get update"}},
					}},
				},
			},
		}

		// Default RunAudit must remain unchanged (no downgrades, empty Exploitability/Fingerprint).
		baseline := RunAudit(policy, gtfoClient)
		var baseAlice, baseBob int
		for _, f := range baseline {
			if f.Exploitability != "" {
				t.Errorf("Expected empty Exploitability under default RunAudit, got %q on %s (%s)", f.Exploitability, f.ID, f.User)
			}
			if f.Fingerprint != "" {
				t.Errorf("Expected empty Fingerprint under default RunAudit, got %q on %s", f.Fingerprint, f.ID)
			}
			if f.User == "alice" && f.ID == "SUDO-GTFO-001" {
				baseAlice++
				if f.Severity != SeverityHigh {
					t.Errorf("Baseline alice expected HIGH, got %s", f.Severity)
				}
			}
			if f.User == "bob" && f.ID == "SUDO-GTFO-002" {
				baseBob++
				if f.Severity != SeverityCritical {
					t.Errorf("Baseline bob expected CRITICAL, got %s", f.Severity)
				}
			}
		}
		if baseAlice == 0 || baseBob == 0 {
			t.Fatalf("Expected baseline GTFObins findings for alice (%d) and bob (%d)", baseAlice, baseBob)
		}

		// SubcommandAwareGTFO + DropInMode evaluation.
		aware := RunAuditWithOptions(policy, gtfoClient, AuditOptions{
			DropInMode:          true,
			SubcommandAwareGTFO: true,
		})

		counts := map[string]int{}
		for _, f := range aware {
			if !strings.HasPrefix(f.ID, "SUDO-GTFO-") {
				continue
			}
			counts[f.User]++
			switch f.User {
			case "alice":
				if f.ID != "SUDO-GTFO-001" || f.Severity != SeverityLow {
					t.Errorf("alice expected SUDO-GTFO-001 LOW, got %s %s", f.ID, f.Severity)
				}
				if f.Exploitability != "CONSTRAINED" {
					t.Errorf("alice expected Exploitability=CONSTRAINED, got %q", f.Exploitability)
				}
				if !strings.Contains(f.Description, "Subcommand Constraint:") {
					t.Errorf("alice expected constraint rationale in Description, got %q", f.Description)
				}
			case "bob":
				if f.ID != "SUDO-GTFO-002" || f.Severity != SeverityMedium {
					t.Errorf("bob expected SUDO-GTFO-002 MEDIUM, got %s %s", f.ID, f.Severity)
				}
				if f.Exploitability != "CONSTRAINED" {
					t.Errorf("bob expected Exploitability=CONSTRAINED, got %q", f.Exploitability)
				}
				if !strings.Contains(f.Description, "Subcommand Constraint:") {
					t.Errorf("bob expected constraint rationale in Description, got %q", f.Description)
				}
			case "carol":
				if f.ID != "SUDO-GTFO-001" || f.Severity != SeverityHigh || f.Exploitability != "" {
					t.Errorf("carol (systemctl status) expected un-downgraded HIGH with empty Exploitability, got %s %s %q", f.ID, f.Severity, f.Exploitability)
				}
			case "dave":
				if f.ID != "SUDO-GTFO-002" || f.Severity != SeverityCritical || f.Exploitability != "" {
					t.Errorf("dave (NOPASSWD systemctl status) expected un-downgraded CRITICAL with empty Exploitability, got %s %s %q", f.ID, f.Severity, f.Exploitability)
				}
			case "eve":
				if f.ID != "SUDO-GTFO-001" || f.Severity != SeverityHigh || f.Exploitability != "" {
					t.Errorf("eve (vim) expected un-downgraded HIGH with empty Exploitability, got %s %s %q", f.ID, f.Severity, f.Exploitability)
				}
			case "frank":
				if f.ID != "SUDO-GTFO-001" || f.Severity != SeverityHigh || f.Exploitability != "" {
					t.Errorf("frank (regex command) expected un-downgraded HIGH with empty Exploitability, got %s %s %q", f.ID, f.Severity, f.Exploitability)
				}
			case "grace":
				if f.ID != "SUDO-GTFO-001" || f.Severity != SeverityLow || f.Exploitability != "CONSTRAINED" {
					t.Errorf("grace (cat /var/log/syslog) expected SUDO-GTFO-001 LOW CONSTRAINED, got %s %s %q", f.ID, f.Severity, f.Exploitability)
				}
			case "henry":
				if f.ID == "SUDO-GTFO-003" {
					if f.Severity != SeverityLow || f.Exploitability != "" {
						t.Errorf("henry NOEXEC-mitigated finding expected LOW with empty Exploitability, got %s %q", f.Severity, f.Exploitability)
					}
				}
			}
			if f.RemediationCode == "" {
				t.Errorf("Expected non-empty RemediationCode for %s (%s)", f.ID, f.User)
			}
		}

		for _, u := range []string{"alice", "bob", "carol", "dave", "eve", "frank", "grace", "henry"} {
			if counts[u] == 0 {
				t.Errorf("Expected GTFObins findings for user %s", u)
			}
		}
	})

	t.Run("CheckShadowing", func(t *testing.T) {
		policy := &SudoersPolicy{
			UserSpecs: []UserSpec{
				{
					UserList: []Member{{Username: "alice"}},
					HostList: []Member{{Hostname: "ALL"}},
					CmndSpecs: []CmndSpec{{
						Commands: []Member{{Command: `/usr/bin/id ""`}},
					}},
					File: "/etc/sudoers",
					Line: 10,
				},
				{
					UserList: []Member{{Username: "alice"}},
					HostList: []Member{{Hostname: "ALL"}},
					CmndSpecs: []CmndSpec{{
						Options:  []Option{{"authenticate": false}},
						Commands: []Member{{Command: `/usr/bin/id ""`}},
					}},
					File: "/etc/sudoers.d/override",
					Line: 4,
				},
			},
		}

		baseline := RunAudit(policy, gtfoClient)
		assertFindingAbsent(t, baseline, "SUDO-CMD-015")

		withShadowing := RunAuditWithOptions(policy, gtfoClient, AuditOptions{
			DropInMode:     true,
			CheckShadowing: true,
		})
		assertFindingPresent(t, withShadowing, "SUDO-CMD-015")
		assertFindingSeverity(t, withShadowing, "SUDO-CMD-015", SeverityMedium)
	})

	t.Run("TimeWindows_NowOption", func(t *testing.T) {
		fixedNow := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
		policy := &SudoersPolicy{
			UserSpecs: []UserSpec{
				{
					UserList: []Member{{Username: "contractor"}},
					HostList: []Member{{Hostname: "ALL"}},
					CmndSpecs: []CmndSpec{{
						Options: []Option{
							{"notbefore": "20250101000000Z"},
							{"notafter": "20260101000000Z"},
						},
						Commands: []Member{{Command: `/usr/bin/id ""`}},
					}},
					File: "/etc/sudoers.d/contractor",
					Line: 5,
				},
				{
					UserList: []Member{{Username: "tempuser"}},
					HostList: []Member{{Hostname: "ALL"}},
					CmndSpecs: []CmndSpec{{
						Options: []Option{
							{"notbefore": "20270501000000Z"},
							{"notafter": "20270101000000Z"},
						},
						Commands: []Member{{Command: `/usr/bin/id ""`}},
					}},
					File: "/etc/sudoers.d/tempuser",
					Line: 8,
				},
			},
		}

		baseline := RunAudit(policy, gtfoClient)
		assertFindingAbsent(t, baseline, "SUDO-CMD-016")

		withNow := RunAuditWithOptions(policy, gtfoClient, AuditOptions{
			DropInMode: true,
			Now:        func() time.Time { return fixedNow },
		})
		assertFindingPresent(t, withNow, "SUDO-CMD-016")

		var sawExpired, sawInverted bool
		for _, f := range withNow {
			if f.ID == "SUDO-CMD-016" {
				if f.RemediationCode == "" {
					t.Errorf("Expected non-empty RemediationCode on SUDO-CMD-016")
				}
				if f.User == "contractor" && f.Severity == SeverityInfo {
					sawExpired = true
				}
				if f.User == "tempuser" && f.Severity == SeverityLow {
					sawInverted = true
				}
			}
		}
		if !sawExpired || !sawInverted {
			t.Errorf("Expected both expired (%v) and inverted (%v) SUDO-CMD-016 findings", sawExpired, sawInverted)
		}
	})
}

func TestRunAudit_InheritedGTFOBinsDescriptions(t *testing.T) {
	gtfoClient, err := gtfobins.NewClient()
	if err != nil {
		t.Fatalf("Failed to initialize GTFObins client: %v", err)
	}

	policy := &SudoersPolicy{
		UserSpecs: []UserSpec{
			{
				UserList: []Member{{Username: "deploy"}},
				HostList: []Member{{Hostname: "ALL"}},
				CmndSpecs: []CmndSpec{
					{
						RunasUsers: []Member{{Username: "root"}},
						Options:    []Option{{"authenticate": false}},
						Commands: []Member{
							{Command: "/usr/bin/systemctl status nginx.service"},
							{Command: "/usr/bin/vim /etc/hosts"},
						},
					},
					{
						RunasUsers: []Member{{Username: "root"}},
						Commands: []Member{
							{Command: "/usr/bin/systemctl status nginx.service"},
						},
					},
				},
				File: "/etc/sudoers.d/deploy",
				Line: 1,
			},
		},
	}

	findings := RunAudit(policy, gtfoClient)
	var sawInheritedNoPasswdFW, sawInheritedPasswdFW, sawDirectVimShell, sawDirectSystemctlShell bool
	for _, f := range findings {
		if f.Command == "/usr/bin/systemctl status nginx.service" && strings.Contains(f.Title, "(file-write)") {
			if f.ID == "SUDO-GTFO-002" {
				sawInheritedNoPasswdFW = true
				if !strings.Contains(f.Description, "(inherited via less)") || !strings.Contains(f.Description, "if the inherited 'less' behavior can be triggered") {
					t.Errorf("Expected purely inherited NOPASSWD description on systemctl file-write, got: %q", f.Description)
				}
				if strings.Contains(f.Description, "immediate privilege escalation") {
					t.Errorf("Did not expect 'immediate privilege escalation' on purely inherited systemctl file-write: %q", f.Description)
				}
			}
			if f.ID == "SUDO-GTFO-001" {
				sawInheritedPasswdFW = true
				if !strings.Contains(f.Description, "(inherited via less)") {
					t.Errorf("Expected '(inherited via less)' on PASSWD systemctl file-write, got: %q", f.Description)
				}
			}
		}
		if f.Command == "/usr/bin/systemctl status nginx.service" && strings.Contains(f.Title, "(shell)") && f.ID == "SUDO-GTFO-002" {
			sawDirectSystemctlShell = true
			if !strings.Contains(f.Description, "This enables immediate privilege escalation.") {
				t.Errorf("Expected direct shell escalation wording for systemctl (shell), got: %q", f.Description)
			}
		}
		if f.Command == "/usr/bin/vim /etc/hosts" && strings.Contains(f.Title, "(shell)") && f.ID == "SUDO-GTFO-002" {
			sawDirectVimShell = true
			if !strings.Contains(f.Description, "This enables immediate privilege escalation.") {
				t.Errorf("Expected direct shell escalation wording for vim (shell), got: %q", f.Description)
			}
		}
	}

	if !sawInheritedNoPasswdFW || !sawInheritedPasswdFW || !sawDirectVimShell || !sawDirectSystemctlShell {
		t.Errorf("Missing expected findings: inheritedNoPasswdFW=%v inheritedPasswdFW=%v directVim=%v directSystemctlShell=%v",
			sawInheritedNoPasswdFW, sawInheritedPasswdFW, sawDirectVimShell, sawDirectSystemctlShell)
	}
}

func TestFindingTagsPopulatedFromCmndSpecOptions(t *testing.T) {
	gtfoClient, err := gtfobins.NewClient()
	if err != nil {
		t.Fatalf("Failed to load embedded GTFObins DB: %v", err)
	}

	policy := &SudoersPolicy{
		UserSpecs: []UserSpec{
			{
				UserList: []Member{{Username: "deploy"}},
				HostList: []Member{{Hostname: "ALL"}},
				CmndSpecs: []CmndSpec{
					{
						RunasUsers: []Member{{Username: "root"}},
						Options: []Option{
							{"runcwd": "/srv/app"},
							{"authenticate": false},
							{"setenv": true},
						},
						Commands: []Member{{Command: "/usr/bin/systemctl status nginx.service"}},
					},
				},
				File: "/etc/sudoers.d/10-deploy",
				Line: 2,
			},
		},
	}

	findings := RunAudit(policy, gtfoClient)
	wantTags := "CWD=/srv/app NOPASSWD: SETENV:"
	foundGTFO := false
	foundSetenv := false
	for _, f := range findings {
		if f.ID == "SUDO-GTFO-002" && f.Command == "/usr/bin/systemctl status nginx.service" {
			foundGTFO = true
			if f.Tags != wantTags {
				t.Errorf("Expected SUDO-GTFO-002 Tags %q, got %q", wantTags, f.Tags)
			}
		}
		if f.ID == "SUDO-CMD-009" && strings.Contains(f.Title, "SETENV") {
			foundSetenv = true
			if f.Tags != wantTags {
				t.Errorf("Expected SUDO-CMD-009 Tags %q, got %q", wantTags, f.Tags)
			}
		}
	}
	if !foundGTFO || !foundSetenv {
		t.Fatalf("Expected both SUDO-GTFO-002 (%v) and SUDO-CMD-009 (%v) findings", foundGTFO, foundSetenv)
	}
}

func TestFindingSourceLineAndInheritedDefaults(t *testing.T) {
	gtfoClient := requireGTFOClient(t)

	policy := &SudoersPolicy{
		Defaults: []DefaultBinding{
			{
				Options: []Option{{"visiblepw": true}},
				File:    "/etc/sudoers",
				Line:    2,
				RawLine: "Defaults visiblepw",
			},
			{
				Binding: []Member{{Username: "ops"}},
				Options: []Option{{"authenticate": false}},
				File:    "/etc/sudoers.d/ops",
				Line:    1,
				RawLine: "Defaults:ops !authenticate",
			},
			{
				Options: []Option{{"noexec": true}},
				File:    "/etc/sudoers",
				Line:    3,
				RawLine: "Defaults noexec",
			},
		},
		UserSpecs: []UserSpec{
			{
				UserList: []Member{{Username: "ops"}},
				HostList: []Member{{Hostname: "ALL"}},
				CmndSpecs: []CmndSpec{
					{
						RunasUsers: []Member{{Username: "root"}},
						Commands:   []Member{{Command: "/usr/bin/less /var/log/syslog"}},
					},
				},
				File:    "/etc/sudoers.d/ops",
				Line:    2,
				RawLine: "ops ALL=(root) /usr/bin/less /var/log/syslog",
			},
			{
				UserList: []Member{{Username: "deploy"}},
				HostList: []Member{{Hostname: "ALL"}},
				CmndSpecs: []CmndSpec{
					{
						RunasUsers: []Member{{Username: "root"}},
						Options:    []Option{{"authenticate": false}},
						Commands:   []Member{{Command: "/usr/bin/vim /etc/hosts"}},
					},
				},
				File:    "/etc/sudoers.d/deploy",
				Line:    2,
				RawLine: "deploy ALL=(root) NOPASSWD: /usr/bin/vim /etc/hosts",
			},
		},
	}

	findings := RunAudit(policy, gtfoClient)
	var sawVisiblepw, sawMissingSecurePath, sawOpsGTFO002, sawOpsGTFO003, sawDeployGTFO002 bool
	for _, f := range findings {
		switch {
		case f.ID == "SUDO-DEF-005" && f.User == "":
			sawVisiblepw = true
			if f.SourceLine != "Defaults visiblepw" {
				t.Errorf("SUDO-DEF-005 SourceLine = %q, want %q", f.SourceLine, "Defaults visiblepw")
			}
		case f.ID == "SUDO-DEF-001" && f.User == "":
			sawMissingSecurePath = true
			if f.SourceLine != "" {
				t.Errorf("Missing global secure_path should have empty SourceLine, got %q", f.SourceLine)
			}
		case f.ID == "SUDO-GTFO-002" && f.User == "ops":
			sawOpsGTFO002 = true
			if f.SourceLine != "ops ALL=(root) /usr/bin/less /var/log/syslog" {
				t.Errorf("ops SUDO-GTFO-002 SourceLine = %q", f.SourceLine)
			}
			if f.Tags != "" {
				t.Errorf("ops SUDO-GTFO-002 Tags = %q, want empty", f.Tags)
			}
			if f.InheritedDefaults != "Defaults:ops !authenticate" {
				t.Errorf("ops SUDO-GTFO-002 InheritedDefaults = %q, want %q", f.InheritedDefaults, "Defaults:ops !authenticate")
			}
		case f.ID == "SUDO-GTFO-003" && f.User == "ops":
			sawOpsGTFO003 = true
			if f.InheritedDefaults != "Defaults noexec" {
				t.Errorf("ops SUDO-GTFO-003 InheritedDefaults = %q, want %q", f.InheritedDefaults, "Defaults noexec")
			}
		case f.ID == "SUDO-GTFO-002" && f.User == "deploy":
			sawDeployGTFO002 = true
			if f.Tags != "NOPASSWD:" {
				t.Errorf("deploy SUDO-GTFO-002 Tags = %q, want %q", f.Tags, "NOPASSWD:")
			}
			if f.InheritedDefaults != "" {
				t.Errorf("deploy SUDO-GTFO-002 InheritedDefaults = %q, want empty", f.InheritedDefaults)
			}
			if strings.Contains(f.Remediation, "Example exploit command:") {
				t.Errorf("deploy SUDO-GTFO-002 Remediation should not embed legacy exploit prose: %q", f.Remediation)
			}
		}
	}
	if !sawVisiblepw || !sawMissingSecurePath || !sawOpsGTFO002 || !sawOpsGTFO003 || !sawDeployGTFO002 {
		t.Fatalf("Missing expected findings: visiblepw=%v missingSecurePath=%v ops002=%v ops003=%v deploy002=%v",
			sawVisiblepw, sawMissingSecurePath, sawOpsGTFO002, sawOpsGTFO003, sawDeployGTFO002)
	}
}

func TestSortFindingsBySeverity_DeterministicTieBreaking(t *testing.T) {
	a := []Finding{
		{ID: "SUDO-GTFO-002", Severity: SeverityCritical, Context: "/etc/sudoers.d/b", Line: 5, Command: "/usr/bin/vim"},
		{ID: "SUDO-GTFO-002", Severity: SeverityCritical, Context: "/etc/sudoers.d/a", Line: 10, Command: "/usr/bin/less"},
		{ID: "SUDO-GTFO-002", Severity: SeverityCritical, Context: "/etc/sudoers.d/a", Line: 2, Command: "/usr/bin/find"},
		{ID: "SUDO-CMD-003", Severity: SeverityCritical, Context: "/etc/sudoers.d/a", Line: 2, Command: "ALL"},
	}
	b := []Finding{a[3], a[0], a[2], a[1]}

	SortFindingsBySeverity(a)
	SortFindingsBySeverity(b)

	for i := range a {
		if a[i].ID != b[i].ID || a[i].Context != b[i].Context || a[i].Line != b[i].Line || a[i].Command != b[i].Command {
			t.Fatalf("SortFindingsBySeverity produced different orders at index %d: %+v vs %+v", i, a[i], b[i])
		}
	}
	if a[0].Context != "/etc/sudoers.d/a" || a[0].Line != 2 || a[0].ID != "SUDO-CMD-003" {
		t.Errorf("Unexpected first finding after deterministic sort: %+v", a[0])
	}
}

func TestScopedDefaultsFindingsPopulateDefaultsScope(t *testing.T) {
	policy := &SudoersPolicy{
		Defaults: []DefaultBinding{
			{
				Binding: []Member{{Hostname: "web01"}},
				Options: []Option{{"use_pty": false}},
				File:    "/etc/sudoers",
				Line:    1,
			},
			{
				Binding: []Member{{Username: "alice"}},
				Options: []Option{{"authenticate": false}},
				File:    "/etc/sudoers",
				Line:    2,
			},
			{
				Binding: []Member{{Command: "/usr/bin/id"}},
				Options: []Option{{"noexec": false}},
				File:    "/etc/sudoers",
				Line:    3,
			},
		},
	}

	findings := AuditDefaults(policy)
	wantScopes := map[string]string{
		"web01":       "Defaults@web01",
		"alice":       "Defaults:alice",
		"/usr/bin/id": "Defaults!/usr/bin/id",
	}
	seen := make(map[string]bool)
	for _, f := range findings {
		if want, ok := wantScopes[f.User]; ok {
			seen[f.User] = true
			if f.DefaultsScope != want {
				t.Errorf("finding %s for %q has DefaultsScope %q, want %q", f.ID, f.User, f.DefaultsScope, want)
			}
		}
	}
	for user, want := range wantScopes {
		if !seen[user] {
			t.Errorf("expected scoped Defaults finding for %q (%s)", user, want)
		}
	}
}
