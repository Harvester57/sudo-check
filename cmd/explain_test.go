package cmd

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sudo-check/pkg/audit"
	"testing"
	"unicode"
)

func explainTestResetFlags() {
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

	explainUser = ""
	explainUID = -1
	explainGroups = ""
	explainHost = ""
	explainIPs = ""

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
		if f := explainCmd.Flags().Lookup(name); f != nil {
			f.Changed = false
		}
	}
	for _, name := range []string{"user", "uid", "groups", "host", "ip"} {
		if f := explainCmd.Flags().Lookup(name); f != nil {
			f.Changed = false
		}
	}

	rootCmd.SetOut(nil)
	rootCmd.SetErr(nil)
	rootCmd.SetIn(nil)
}

func explainTestAssertNoEmojis(t *testing.T, s string) {
	t.Helper()
	for _, r := range s {
		if unicode.Is(unicode.So, r) {
			t.Fatalf("unexpected symbol/emoji rune %U in output:\n%s", r, s)
		}
	}
}

func TestExplainCmd_TextOutputRawSudoers(t *testing.T) {
	explainTestResetFlags()
	t.Cleanup(explainTestResetFlags)

	dir := t.TempDir()
	sudoersPath := filepath.Join(dir, "sudoers")
	policyText := `Defaults env_reset, use_pty, secure_path="/usr/sbin:/usr/bin:/sbin:/bin"
Defaults:alice !authenticate
User_Alias OPS = alice, %sre
OPS web01.example.com=(root) SETENV: /usr/bin/vim
%sre 10.20.0.0/16=(www-data) NOEXEC: /usr/bin/chrt ""
alice ALL=(ALL) NOPASSWD: ALL, !/usr/bin/passwd
`
	if err := os.WriteFile(sudoersPath, []byte(policyText), 0600); err != nil {
		t.Fatalf("failed to write sudoers file: %v", err)
	}

	var outBuf bytes.Buffer
	rootCmd.SetOut(&outBuf)
	rootCmd.SetArgs([]string{
		"explain", sudoersPath,
		"--user", "alice",
		"--groups", "%sre, wheel",
		"--host", "web01.example.com",
		"--ip", "10.20.1.5",
	})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("explain command failed: %v", err)
	}

	out := outBuf.String()
	explainTestAssertNoEmojis(t, out)

	expectedTokens := []string{
		"User:   alice",
		"Groups: sre, wheel",
		"Host:   web01.example.com",
		"IPs:    10.20.1.5",
		"Highest Risk: CRITICAL",
		"Effective Defaults:",
		"env_reset = true",
		"use_pty = true",
		"/usr/bin/vim",
		"/usr/bin/chrt",
		"NOPASSWD",
		"NOEXEC",
		"SETENV",
		"ESCALATION PATH",
		"GTFObins:",
		"shell",
		"Denied Commands (1):",
		"/usr/bin/passwd",
		":4",
	}
	for _, tok := range expectedTokens {
		if !strings.Contains(out, tok) {
			t.Errorf("expected %q in explain text output, got:\n%s", tok, out)
		}
	}
}

func TestExplainCmd_JSONOutputAndUIDQuery(t *testing.T) {
	explainTestResetFlags()
	t.Cleanup(explainTestResetFlags)

	dir := t.TempDir()
	jsonPolicyPath := filepath.Join(dir, "policy.json")
	jsonPolicy := `{
  "Defaults": [
    {"Options": [{"env_reset": true}, {"use_pty": true}]}
  ],
  "User_Specs": [
    {
      "User_List": [{"userid": 1050}],
      "Host_List": [{"networkaddr": "192.168.50.0/24"}],
      "Cmnd_Specs": [
        {
          "runasusers": [{"username": "root"}],
          "Options": [{"authenticate": false}],
          "Commands": [{"command": "/usr/bin/find"}]
        }
      ]
    }
  ]
}`
	if err := os.WriteFile(jsonPolicyPath, []byte(jsonPolicy), 0600); err != nil {
		t.Fatalf("failed to write policy.json: %v", err)
	}

	var outBuf bytes.Buffer
	rootCmd.SetOut(&outBuf)
	rootCmd.SetArgs([]string{
		"explain", jsonPolicyPath,
		"--uid", "1050",
		"--ip", "192.168.50.42",
		"-f", "json",
	})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("explain json command failed: %v", err)
	}

	var res audit.ExplainResult
	if err := json.Unmarshal(outBuf.Bytes(), &res); err != nil {
		t.Fatalf("failed to decode JSON output: %v\nraw:\n%s", err, outBuf.String())
	}
	if res.Query.UID == nil || *res.Query.UID != 1050 {
		t.Fatalf("expected Query.UID=1050, got %+v", res.Query.UID)
	}
	if len(res.Query.HostIPs) != 1 || res.Query.HostIPs[0] != "192.168.50.42" {
		t.Fatalf("expected HostIPs=[192.168.50.42], got %v", res.Query.HostIPs)
	}
	if res.HighestRisk != audit.SeverityCritical {
		t.Errorf("expected HighestRisk=CRITICAL, got %s", res.HighestRisk)
	}
	if len(res.AllowedCommands) != 1 || res.AllowedCommands[0].Command != "/usr/bin/find" {
		t.Fatalf("expected /usr/bin/find in AllowedCommands, got %+v", res.AllowedCommands)
	}
	if !res.AllowedCommands[0].EscalationPath || !res.AllowedCommands[0].NoPasswd {
		t.Errorf("expected EscalationPath=true and NoPasswd=true, got %+v", res.AllowedCommands[0])
	}
}

func TestExplainCmd_Errors(t *testing.T) {
	dir := t.TempDir()
	sudoersPath := filepath.Join(dir, "sudoers")
	if err := os.WriteFile(sudoersPath, []byte("alice ALL=(ALL) /usr/bin/id\n"), 0600); err != nil {
		t.Fatalf("failed to write sudoers: %v", err)
	}
	nonPolicyJSON := filepath.Join(dir, "report.json")
	if err := os.WriteFile(nonPolicyJSON, []byte(`{"policy_findings":[]}`), 0600); err != nil {
		t.Fatalf("failed to write non-policy json: %v", err)
	}

	t.Run("MissingPrincipal", func(t *testing.T) {
		explainTestResetFlags()
		t.Cleanup(explainTestResetFlags)
		rootCmd.SetArgs([]string{"explain", sudoersPath})
		if err := rootCmd.Execute(); err == nil || !strings.Contains(err.Error(), "--user") {
			t.Fatalf("expected missing --user error, got: %v", err)
		}
	})

	t.Run("NegativeUID", func(t *testing.T) {
		explainTestResetFlags()
		t.Cleanup(explainTestResetFlags)
		rootCmd.SetArgs([]string{"explain", sudoersPath, "--uid", "-3"})
		if err := rootCmd.Execute(); err == nil || !strings.Contains(err.Error(), "UID") {
			t.Fatalf("expected negative UID error, got: %v", err)
		}
	})

	t.Run("InvalidIP", func(t *testing.T) {
		explainTestResetFlags()
		t.Cleanup(explainTestResetFlags)
		rootCmd.SetArgs([]string{"explain", sudoersPath, "--user", "alice", "--ip", "999.999.1.1"})
		if err := rootCmd.Execute(); err == nil || !strings.Contains(err.Error(), "invalid IP") {
			t.Fatalf("expected invalid IP error, got: %v", err)
		}
	})

	t.Run("UnsupportedFormat", func(t *testing.T) {
		explainTestResetFlags()
		t.Cleanup(explainTestResetFlags)
		rootCmd.SetArgs([]string{"explain", sudoersPath, "--user", "alice", "-f", "html"})
		if err := rootCmd.Execute(); err == nil || !strings.Contains(err.Error(), "unsupported format") {
			t.Fatalf("expected unsupported format error, got: %v", err)
		}
	})

	t.Run("MultipleFormatsRejected", func(t *testing.T) {
		explainTestResetFlags()
		t.Cleanup(explainTestResetFlags)
		rootCmd.SetArgs([]string{"explain", sudoersPath, "--user", "alice", "-f", "text,json"})
		if err := rootCmd.Execute(); err == nil || !strings.Contains(err.Error(), "single output format") {
			t.Fatalf("expected single output format error, got: %v", err)
		}
	})

	t.Run("MissingFile", func(t *testing.T) {
		explainTestResetFlags()
		t.Cleanup(explainTestResetFlags)
		rootCmd.SetArgs([]string{"explain", filepath.Join(dir, "missing.sudoers"), "--user", "alice"})
		if err := rootCmd.Execute(); err == nil {
			t.Fatal("expected error for missing policy file")
		}
	})

	t.Run("NonPolicyJSONRejected", func(t *testing.T) {
		explainTestResetFlags()
		t.Cleanup(explainTestResetFlags)
		rootCmd.SetArgs([]string{"explain", nonPolicyJSON, "--user", "alice"})
		if err := rootCmd.Execute(); err == nil || !strings.Contains(err.Error(), "invalid JSON policy") {
			t.Fatalf("expected invalid JSON policy error, got: %v", err)
		}
	})
}
