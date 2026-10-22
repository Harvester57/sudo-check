package audit

import (
	"encoding/json"
	"os"
	"strings"
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
		dirPerm := evaluateSudoersFilePermissions("/etc/sudoers.d", 0777, 1000, 1000, true)
		for _, f := range dirPerm {
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
