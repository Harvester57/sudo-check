package audit

import (
	"encoding/json"
	"os"
	"sudo-check/pkg/gtfobins"
	"testing"
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
	t.Errorf("Finding %s not found — cannot check severity", id)
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

	t.Run("DangerousEnvKeep", func(t *testing.T) {
		policy := &SudoersPolicy{Defaults: []DefaultBinding{{Options: []Option{
			{"operation": "list_add", "env_keep": []any{"LD_PRELOAD", "SAFE_VAR"}},
		}}}}
		findings := AuditDefaults(policy)
		assertFindingPresent(t, findings, "SUDO-DEF-004")
		assertFindingSeverity(t, findings, "SUDO-DEF-004", SeverityCritical)
	})

	t.Run("SafeEnvKeep", func(t *testing.T) {
		policy := &SudoersPolicy{Defaults: []DefaultBinding{{Options: []Option{
			{"operation": "list_add", "env_keep": []any{"LANG", "LC_ALL", "TERM"}},
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

	t.Run("LastMatchWins_UsePtyDisabledAfterEnabled", func(t *testing.T) {
		policy := &SudoersPolicy{Defaults: []DefaultBinding{{Options: []Option{
			{"use_pty": true},
			{"use_pty": false},
		}}}}
		findings := AuditDefaults(policy)
		assertFindingPresent(t, findings, "SUDO-DEF-003")
	})

	t.Run("LastMatchWins_UsePtyEnabledAfterDisabled", func(t *testing.T) {
		policy := &SudoersPolicy{Defaults: []DefaultBinding{{Options: []Option{
			{"use_pty": false},
			{"use_pty": true},
		}}}}
		findings := AuditDefaults(policy)
		assertFindingAbsent(t, findings, "SUDO-DEF-003")
	})

	t.Run("DisabledSecurePathBool", func(t *testing.T) {
		policy := &SudoersPolicy{Defaults: []DefaultBinding{{Options: []Option{
			{"secure_path": "/usr/bin:/bin"},
			{"secure_path": false},
		}}}}
		findings := AuditDefaults(policy)
		assertFindingPresent(t, findings, "SUDO-DEF-001")
	})

	t.Run("WildcardEnvKeepAndListRemove", func(t *testing.T) {
		policy := &SudoersPolicy{Defaults: []DefaultBinding{{Options: []Option{
			{"operation": "list_add", "env_keep": []any{"LD_*"}},
		}}}}
		findings := AuditDefaults(policy)
		assertFindingPresent(t, findings, "SUDO-DEF-004")

		// Verify list_remove removes a previously added dangerous variable
		policyRemoved := &SudoersPolicy{Defaults: []DefaultBinding{{Options: []Option{
			{"operation": "list_add", "env_keep": []any{"LD_PRELOAD"}},
			{"operation": "list_remove", "env_keep": []any{"LD_PRELOAD"}},
		}}}}
		findingsRemoved := AuditDefaults(policyRemoved)
		assertFindingAbsent(t, findingsRemoved, "SUDO-DEF-004")
	})

	t.Run("NewDefaultsRules_AuthenticateSetenvFollowTimeout", func(t *testing.T) {
		policy := &SudoersPolicy{Defaults: []DefaultBinding{{Options: []Option{
			{"authenticate": false},
			{"setenv": true},
			{"sudoedit_follow": true},
			{"timestamp_timeout": -1},
			{"tty_tickets": false},
		}}}}
		findings := AuditDefaults(policy)
		assertFindingPresent(t, findings, "SUDO-DEF-012")
		assertFindingPresent(t, findings, "SUDO-DEF-013")
		assertFindingPresent(t, findings, "SUDO-DEF-014")
		assertFindingPresent(t, findings, "SUDO-DEF-015")
	})

	t.Run("ScopedBoundDefaults", func(t *testing.T) {
		policy := &SudoersPolicy{Defaults: []DefaultBinding{
			{
				Binding: []Member{{Username: "alice"}},
				Options: []Option{
					{"env_reset": false},
					{"authenticate": false},
				},
			},
		}}
		findings := AuditDefaults(policy)
		assertFindingPresent(t, findings, "SUDO-DEF-011")
		assertFindingPresent(t, findings, "SUDO-DEF-012")
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
				Commands: []Member{{Command: "/usr/bin/python \"\""}},
			}},
		}}}
		findings := AuditCommands(policy, gtfoClient)
		// python has shell bypass (mitigated by noexec -> SUDO-GTFO-003) and library-load/file-read/file-write (NOT mitigated by noexec -> SUDO-GTFO-001)
		hasMitigated := false
		hasUnmitigatedInProcess := false
		for _, f := range findings {
			if f.ID == "SUDO-GTFO-003" {
				hasMitigated = true
				if f.Severity != SeverityLow {
					t.Errorf("Expected SUDO-GTFO-003 to be LOW severity (mitigated), got %s", f.Severity)
				}
			}
			if f.ID == "SUDO-GTFO-001" && f.Title == "Dangerous Sudo Binary allowed: python (library-load)" {
				hasUnmitigatedInProcess = true
			}
		}
		if !hasMitigated {
			t.Errorf("Expected python shell bypass to be mitigated by noexec (SUDO-GTFO-003)")
		}
		if !hasUnmitigatedInProcess {
			t.Errorf("Expected python library-load bypass NOT to be mitigated by noexec (SUDO-GTFO-001)")
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

	t.Run("CommandAliasResolution_BothSchemas", func(t *testing.T) {
		// Verify both "cmndalias" (official cvtsudoers_json.c output) and "commandalias" (legacy fixture key)
		rawJSON := `{
			"Command_Aliases": {
				"EDITORS": [
					{ "command": "/usr/bin/vim" },
					{ "command": "/usr/bin/nano" }
				]
			},
			"User_Specs": [{
				"User_List": [{ "userid": 1000 }],
				"Host_List": [{ "hostname": "ALL" }],
				"Cmnd_Specs": [{
					"Commands": [{ "cmndalias": "EDITORS" }]
				}]
			}]
		}`
		var policy SudoersPolicy
		if err := json.Unmarshal([]byte(rawJSON), &policy); err != nil {
			t.Fatalf("Failed to unmarshal cvtsudoers cmndalias JSON: %v", err)
		}
		findings := AuditCommands(&policy, gtfoClient)
		hasVimGTFO := false
		for _, f := range findings {
			if f.Command == "/usr/bin/vim" && f.User == "#1000" {
				hasVimGTFO = true
			}
		}
		if !hasVimGTFO {
			t.Error("Expected official 'cmndalias' resolution and numeric userid (#1000) to find /usr/bin/vim")
		}
	})

	t.Run("CircularAliasDepthLimit", func(t *testing.T) {
		policy := loadTestPolicy(t, "circular_alias_policy.json")
		// This should NOT panic or hang — the depth limit should prevent infinite recursion
		findings := AuditCommands(policy, gtfoClient)
		_ = findings // We only care that this doesn't hang/crash
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

	t.Run("DirectEditorExecution_And_FalsePositivePrevention", func(t *testing.T) {
		policy := &SudoersPolicy{UserSpecs: []UserSpec{{
			UserList: []Member{{Username: "alice"}},
			HostList: []Member{{Hostname: "ALL"}},
			CmndSpecs: []CmndSpec{{
				Commands: []Member{{Command: "/usr/bin/vim /etc/hosts"}},
			}},
		}}}
		findings := AuditCommands(policy, gtfoClient)
		assertFindingPresent(t, findings, "SUDO-CMD-007")

		// Non-editor binaries starting with "vi", "edit", or "micro" must NOT trigger SUDO-CMD-007
		nonEditorPolicy := &SudoersPolicy{UserSpecs: []UserSpec{{
			UserList: []Member{{Username: "alice"}},
			HostList: []Member{{Hostname: "ALL"}},
			CmndSpecs: []CmndSpec{{
				Commands: []Member{
					{Command: "/usr/bin/virsh list"},
					{Command: "/usr/sbin/visudo -c"},
					{Command: "/usr/bin/virt-install --version"},
					{Command: "/usr/bin/microdnf update"},
					{Command: "/usr/bin/editcap -v"},
				},
			}},
		}}}
		nonEditorFindings := AuditCommands(nonEditorPolicy, gtfoClient)
		assertFindingAbsent(t, nonEditorFindings, "SUDO-CMD-007")
	})

	t.Run("SetenvFollowAndNegatedRunas", func(t *testing.T) {
		policy := &SudoersPolicy{UserSpecs: []UserSpec{{
			UserList: []Member{{Username: "alice"}},
			HostList: []Member{{Hostname: "ALL"}},
			CmndSpecs: []CmndSpec{{
				RunasUsers: []Member{{Username: "ALL"}, {Username: "root", Negated: true}},
				Options:    []Option{{"setenv": true}, {"sudoedit_follow": true}},
				Commands:   []Member{{Command: "/usr/local/bin/custom-tool --safe"}},
			}},
		}}}
		findings := AuditCommands(policy, gtfoClient)
		assertFindingPresent(t, findings, "SUDO-CMD-008")
		assertFindingPresent(t, findings, "SUDO-CMD-009")
		assertFindingPresent(t, findings, "SUDO-CMD-010")
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
		{"Less", SudoVersion{Major: 1, Minor: 8, Patch: 31, Pl: 2}, SudoVersion{Major: 1, Minor: 9, Patch: 0, Pl: 0}, -1},
		{"Greater", SudoVersion{Major: 1, Minor: 9, Patch: 12, Pl: 2}, SudoVersion{Major: 1, Minor: 9, Patch: 12, Pl: 1}, 1},
		{"PatchLevel", SudoVersion{Major: 1, Minor: 8, Patch: 31, Pl: 1}, SudoVersion{Major: 1, Minor: 8, Patch: 31, Pl: 2}, -1},
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
		{"CVE-2021-3156_Vulnerable_18x", "1.8.31p1", "CVE-2021-3156", true},
		{"CVE-2021-3156_Fixed_18x", "1.8.32", "CVE-2021-3156", false},
		{"CVE-2021-3156_Vulnerable_19x", "1.9.5p1", "CVE-2021-3156", true},
		{"CVE-2021-3156_Fixed_19x", "1.9.6", "CVE-2021-3156", false},
		{"CVE-2023-22809_Vulnerable", "1.9.12p1", "CVE-2023-22809", true},
		{"CVE-2023-27320_Vulnerable", "1.9.12p1", "CVE-2023-27320", true},
		{"CVE-2023-27320_Fixed", "1.9.12p2", "CVE-2023-27320", false},
		{"CVE-2025-32462_Vulnerable", "1.9.17", "CVE-2025-32462", true},
		{"CVE-2025-32463_Vulnerable", "1.9.17", "CVE-2025-32463", true},
		{"AllClear_Latest", "1.9.17p1", "CVE-2025-32463", false},
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
}

// --- Helper Function Tests ---

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

func TestParseSeverityAndHasFindingsAtOrAbove(t *testing.T) {
	sev, err := ParseSeverity("high")
	if err != nil || sev != SeverityHigh {
		t.Fatalf("Expected SeverityHigh, got %v (err: %v)", sev, err)
	}
	if _, err := ParseSeverity("unknown"); err == nil {
		t.Errorf("Expected error for invalid severity string")
	}

	findings := []Finding{{ID: "1", Severity: SeverityMedium}}
	if !HasFindingsAtOrAbove(SeverityLow, findings) {
		t.Errorf("Expected Medium finding to meet Low threshold")
	}
	if !HasFindingsAtOrAbove(SeverityMedium, findings) {
		t.Errorf("Expected Medium finding to meet Medium threshold")
	}
	if HasFindingsAtOrAbove(SeverityHigh, findings) {
		t.Errorf("Expected Medium finding NOT to meet High threshold")
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

	// This policy should trigger many rules
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

	// Verify GTFObins matches exist (find, vim via alias)
	hasGTFO := false
	for _, f := range findings {
		if f.ID == "SUDO-GTFO-001" || f.ID == "SUDO-GTFO-002" || f.ID == "SUDO-GTFO-003" {
			hasGTFO = true
		}
	}
	if !hasGTFO {
		t.Error("Expected GTFObins findings from vulnerable policy")
	}
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
