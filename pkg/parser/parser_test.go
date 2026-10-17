package parser

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sudo-check/pkg/audit"
	"sudo-check/pkg/gtfobins"
	"testing"
)

func TestIsJSONPolicy(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want bool
	}{
		{"ValidJSON", []byte(`{"Defaults": [{"Options": [{"use_pty": true}]}]}`), true},
		{"ValidJSONWithBOMAndWhitespace", []byte("\xef\xbb\xbf  \n\t {\"User_Specs\": []}"), true},
		{"RawSudoers", []byte("Defaults env_reset\nroot ALL=(ALL:ALL) ALL\n"), false},
		{"Empty", []byte("   "), false},
		{"InvalidJSONBraces", []byte("{not valid json"), false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsJSONPolicy(tc.data); got != tc.want {
				t.Errorf("IsJSONPolicy(%q) = %v, want %v", string(tc.data), got, tc.want)
			}
		})
	}
}

func TestParseDefaultsAndScopes(t *testing.T) {
	input := `
# Global defaults
Defaults env_reset, !visiblepw, !!use_pty, umask=0077, passwd_timeout=1, timestamp_timeout=5
Defaults secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
Defaults env_keep = "LANG LC_ALL", env_keep += "TERM EDITOR", env_keep -= "EDITOR", !env_keep
Defaults env_check = "TZ", env_delete += "LD_PRELOAD", env_keep = ""

# Scoped defaults
Defaults@SRV1, 192.168.1.0/24, 10.0.0.0/255.255.255.0, 2001:db8::1, +net_hosts, !bad.host.local, ALL !requiretty
Defaults:alice, #1000, %wheel, %#1001, %:ad_grp, %:#1002, +net_users, U_ALIAS, !bob, ALL, "" !authenticate
Defaults!/bin/ls, CMND_ALIAS, !/bin/sh, ALL !syslog
Defaults>root, #0, %operator, RUNAS_ALIAS, ALL set_logname
`
	policy, err := ParseString(input)
	if err != nil {
		t.Fatalf("ParseString failed: %v", err)
	}

	if len(policy.Defaults) != 8 {
		t.Fatalf("Expected 8 Defaults bindings, got %d", len(policy.Defaults))
	}

	// Verify line numbers are recorded
	if policy.Defaults[0].Line != 3 {
		t.Errorf("Expected first Defaults on line 3, got %d", policy.Defaults[0].Line)
	}

	// Check host-scoped Defaults binding (index 4)
	hostDef := policy.Defaults[4]
	if len(hostDef.Binding) != 7 {
		t.Fatalf("Expected 7 host bindings, got %d: %+v", len(hostDef.Binding), hostDef.Binding)
	}
	if hostDef.Binding[0].HostAlias != "SRV1" ||
		hostDef.Binding[1].NetworkAddr != "192.168.1.0/24" ||
		hostDef.Binding[2].NetworkAddr != "10.0.0.0/255.255.255.0" ||
		hostDef.Binding[3].NetworkAddr != "2001:db8::1" ||
		hostDef.Binding[4].Netgroup != "net_hosts" ||
		hostDef.Binding[5].Hostname != "bad.host.local" || !hostDef.Binding[5].Negated ||
		hostDef.Binding[6].Hostname != "ALL" {
		t.Errorf("Unexpected host binding members: %+v", hostDef.Binding)
	}

	// Check user-scoped Defaults binding (index 5)
	userDef := policy.Defaults[5]
	if len(userDef.Binding) != 11 {
		t.Fatalf("Expected 11 user bindings, got %d: %+v", len(userDef.Binding), userDef.Binding)
	}
	if userDef.Binding[0].Username != "alice" ||
		userDef.Binding[1].UserID == nil || *userDef.Binding[1].UserID != 1000 ||
		userDef.Binding[2].Usergroup != "wheel" ||
		userDef.Binding[3].UserGID == nil || *userDef.Binding[3].UserGID != 1001 ||
		userDef.Binding[4].NonUnixGroup != "ad_grp" ||
		userDef.Binding[5].NonUnixGID == nil || *userDef.Binding[5].NonUnixGID != 1002 ||
		userDef.Binding[6].Netgroup != "net_users" ||
		userDef.Binding[7].UserAlias != "U_ALIAS" ||
		userDef.Binding[8].Username != "bob" || !userDef.Binding[8].Negated ||
		userDef.Binding[9].Username != "ALL" ||
		!userDef.Binding[10].Myself {
		t.Errorf("Unexpected user binding members: %+v", userDef.Binding)
	}

	// Check command-scoped Defaults binding (index 6)
	cmndDef := policy.Defaults[6]
	if len(cmndDef.Binding) != 4 ||
		cmndDef.Binding[0].Command != "/bin/ls" ||
		cmndDef.Binding[1].CommandAlias != "CMND_ALIAS" ||
		cmndDef.Binding[2].Command != "/bin/sh" || !cmndDef.Binding[2].Negated ||
		cmndDef.Binding[3].Command != "ALL" {
		t.Errorf("Unexpected command binding members: %+v", cmndDef.Binding)
	}

	// Check runas-scoped Defaults binding (index 7)
	runasDef := policy.Defaults[7]
	if len(runasDef.Binding) != 5 ||
		runasDef.Binding[0].Username != "root" ||
		runasDef.Binding[1].UserID == nil || *runasDef.Binding[1].UserID != 0 ||
		runasDef.Binding[2].Usergroup != "operator" ||
		runasDef.Binding[3].RunasAlias != "RUNAS_ALIAS" ||
		runasDef.Binding[4].Username != "ALL" {
		t.Errorf("Unexpected runas binding members: %+v", runasDef.Binding)
	}
}

func TestParseAliasesAndMultiClauses(t *testing.T) {
	input := `
User_Alias ADMINS = alice, %:nonunix_grp, %:#500 : DEVS = bob, !charlie, #-1
Runas_Alias DB_RUNAS = postgres, #26 : APP_RUNAS = www-data
Host_Alias PROD_HOSTS = 2001:db8::1, 10.0.0.1 : DEV_HOSTS = dev1.local
Cmnd_Alias READ_CMDS = sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789 /bin/ls, /bin/chown root:root /tmp/a : EDIT_CMDS = sudoedit /etc/hosts
`
	policy, err := ParseString(input)
	if err != nil {
		t.Fatalf("ParseString failed: %v", err)
	}

	if len(policy.UserAliases) != 2 || len(policy.UserAliases["ADMINS"]) != 3 || len(policy.UserAliases["DEVS"]) != 3 {
		t.Errorf("Unexpected UserAliases: %+v", policy.UserAliases)
	}
	if policy.UserAliases["DEVS"][2].Username != "#-1" {
		t.Errorf("Expected #-1 username token, got %+v", policy.UserAliases["DEVS"][2])
	}
	if len(policy.RunasAliases) != 2 || len(policy.HostAliases) != 2 || len(policy.CommandAliases) != 2 {
		t.Errorf("Unexpected aliases count: runas=%d host=%d cmnd=%d", len(policy.RunasAliases), len(policy.HostAliases), len(policy.CommandAliases))
	}
	if len(policy.CommandAliases["READ_CMDS"][0].SHA256) != 1 {
		t.Errorf("Expected SHA256 digest on READ_CMDS[0], got %+v", policy.CommandAliases["READ_CMDS"][0])
	}
}

func TestParseUserSpecsTagsDigestsAndOptions(t *testing.T) {
	input := `
# Line continuation and inline comments
#1000 ALL = \
    # comment inside continuation
    (root) NOPASSWD : NOEXEC: SETENV: LOG_INPUT: LOG_OUTPUT: FOLLOW: INTERCEPT: MAIL: \
    /usr/bin/python3 "", \
    PASSWD: EXEC: NOSETENV: NOLOG_INPUT: NOLOG_OUTPUT: NOFOLLOW: NOINTERCEPT: NOMAIL: \
    /usr/bin/id # trailing comment

# Multiple host clauses, runas variations, digests, and per-command options
alice srv1 = (:staff) /bin/ls : srv2 = () /bin/cat : srv3 = (:) /bin/echo "hello # world"
bob ALL = (u1 : %#200, %:nonunix, %:#300, %grp, RUNAS_GRP) \
    sha224:0123456789abcdef0123456789abcdef0123456789abcdef01234567, \
    sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789, \
    sha384:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef, \
    sha512:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
    !/bin/sh
eve ALL = ROLE=sysadm_r TYPE=sysadm_t APPARMOR_PROFILE=unconfined PRIVS="basic" LIMITPRIVS="all" CHROOT=/chroot CWD=* TIMEOUT = 1d2h3m4s NOTBEFORE=20250101120000Z NOTAFTER=20260101120000Z /usr/bin/env
`
	policy, err := ParseString(input)
	if err != nil {
		t.Fatalf("ParseString failed: %v", err)
	}

	if len(policy.UserSpecs) != 6 {
		t.Fatalf("Expected 6 UserSpecs, got %d", len(policy.UserSpecs))
	}

	// Spec 0: #1000 ALL = ...
	spec0 := policy.UserSpecs[0]
	if spec0.UserList[0].UserID == nil || *spec0.UserList[0].UserID != 1000 {
		t.Errorf("Expected #1000 UserID, got %+v", spec0.UserList[0])
	}
	if len(spec0.CmndSpecs) != 2 {
		t.Fatalf("Expected 2 CmndSpecs on spec0, got %d", len(spec0.CmndSpecs))
	}
	if len(spec0.CmndSpecs[0].Options) != 8 || len(spec0.CmndSpecs[1].Options) != 8 {
		t.Errorf("Expected 8 tag options on both CmndSpecs, got %d and %d", len(spec0.CmndSpecs[0].Options), len(spec0.CmndSpecs[1].Options))
	}

	// Spec 1, 2, 3: alice on srv1, srv2, srv3
	if !policy.UserSpecs[1].CmndSpecs[0].RunasUsers[0].Myself || policy.UserSpecs[1].CmndSpecs[0].RunasGroups[0].Usergroup != "staff" {
		t.Errorf("Unexpected (:staff) runas: %+v", policy.UserSpecs[1].CmndSpecs[0])
	}
	if !policy.UserSpecs[2].CmndSpecs[0].RunasUsers[0].Myself || len(policy.UserSpecs[2].CmndSpecs[0].RunasGroups) != 0 {
		t.Errorf("Unexpected () runas: %+v", policy.UserSpecs[2].CmndSpecs[0])
	}
	if policy.UserSpecs[3].CmndSpecs[0].Commands[0].Command != `/bin/echo "hello # world"` {
		t.Errorf("Unexpected quoted command with #: %q", policy.UserSpecs[3].CmndSpecs[0].Commands[0].Command)
	}

	// Spec 4: bob with all 4 digest types and negated command
	bobCmd := policy.UserSpecs[4].CmndSpecs[0].Commands[0]
	if !bobCmd.Negated || len(bobCmd.SHA224) != 1 || len(bobCmd.SHA256) != 1 || len(bobCmd.SHA384) != 1 || len(bobCmd.SHA512) != 1 {
		t.Errorf("Expected all 4 digests and Negated=true on bob command, got %+v", bobCmd)
	}

	// Spec 5: eve with per-command options
	eveOpts := policy.UserSpecs[5].CmndSpecs[0].Options
	if len(eveOpts) != 10 {
		t.Errorf("Expected 10 per-command options on eve, got %d: %+v", len(eveOpts), eveOpts)
	}
}

func TestIncludesAndIncludedir(t *testing.T) {
	tmpDir := t.TempDir()

	// Create sudoers.d directory
	sudoersD := filepath.Join(tmpDir, "sudoers.d")
	if err := os.MkdirAll(sudoersD, 0755); err != nil {
		t.Fatalf("Failed to create sudoers.d: %v", err)
	}

	// Files that should be included in lexical order: 01_first, 02_second
	if err := os.WriteFile(filepath.Join(sudoersD, "02_second"), []byte("user2 ALL = /bin/cat\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sudoersD, "01_first"), []byte("user1 ALL = /bin/ls\n"), 0644); err != nil {
		t.Fatal(err)
	}
	// Files that MUST be skipped in includedir (contains '.' or ends with '~' or is a directory)
	if err := os.WriteFile(filepath.Join(sudoersD, "ignored.conf"), []byte("bad1 ALL = ALL\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sudoersD, ".hidden"), []byte("bad2 ALL = ALL\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sudoersD, "backup~"), []byte("bad3 ALL = ALL\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(sudoersD, "subdir"), 0755); err != nil {
		t.Fatal(err)
	}

	// Create hostname-specific include file and circular include files
	hostname, _ := os.Hostname()
	if idx := strings.IndexByte(hostname, '.'); idx != -1 {
		hostname = hostname[:idx]
	}
	hostFile := filepath.Join(tmpDir, "host_"+hostname)
	cycleA := filepath.Join(tmpDir, "cycle_a")
	cycleB := filepath.Join(tmpDir, "cycle_b")

	if err := os.WriteFile(hostFile, []byte("hostuser ALL = /usr/bin/id\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cycleA, []byte("@include cycle_b\ncycleuser_a ALL = /bin/true\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cycleB, []byte("#include cycle_a\ncycleuser_b ALL = /bin/false\n"), 0644); err != nil {
		t.Fatal(err)
	}

	mainFile := filepath.Join(tmpDir, "sudoers")
	absHostFile := strings.ReplaceAll(hostFile, `\`, `/`)
	mainContent := `
Defaults env_reset
#include "` + absHostFile + `"
@include cycle_a
@include nonexistent_file_ignored
#includedir /etc/sudoers.d
@includedir nonexistent_dir_ignored
`
	if err := os.WriteFile(mainFile, []byte(mainContent), 0644); err != nil {
		t.Fatal(err)
	}

	policy, err := ParseFile(mainFile)
	if err != nil {
		t.Fatalf("ParseFile failed: %v", err)
	}

	var users []string
	for _, us := range policy.UserSpecs {
		users = append(users, us.UserList[0].Username)
	}
	wantUsers := []string{"hostuser", "cycleuser_b", "cycleuser_a", "user1", "user2"}
	if !reflect.DeepEqual(users, wantUsers) {
		t.Errorf("Included users = %v, want %v", users, wantUsers)
	}

	if len(policy.IncludedFiles) < 6 {
		t.Errorf("Expected at least 6 IncludedFiles (main + 5 included files), got %d: %v", len(policy.IncludedFiles), policy.IncludedFiles)
	}

	// Verify audit findings preserve exact source file Context across #include and #includedir
	gtfoClient, err := gtfobins.NewClient()
	if err != nil {
		t.Fatalf("Failed to initialize GTFObins client: %v", err)
	}
	incFindings := audit.RunAudit(policy, gtfoClient)
	foundFirstDropin := false
	foundSecondDropin := false
	for _, f := range incFindings {
		if f.User == "user1" && strings.HasSuffix(f.Context, "/sudoers.d/01_first") {
			foundFirstDropin = true
		}
		if f.User == "user2" && strings.HasSuffix(f.Context, "/sudoers.d/02_second") {
			foundSecondDropin = true
		}
	}
	if !foundFirstDropin || !foundSecondDropin {
		t.Errorf("Expected per-file Finding.Context attribution for included drop-ins 01_first and 02_second, got findings: %+v", incFindings)
	}

	// Test ParseReader with raw sudoers content, empty filename, and non-empty filename + baseDir
	rawReaderPolicy, err := ParseReader(strings.NewReader("alice ALL = /bin/ls\\ -la \"arg with \\\"quotes\\\"\"\n"), "", tmpDir)
	if err != nil || len(rawReaderPolicy.UserSpecs) != 1 {
		t.Fatalf("ParseReader with empty filename failed: %v", err)
	}
	rawNamedPolicy, err := ParseReader(strings.NewReader("@include %h_nonexistent\nbob ALL = (\"u:1\" : \"g:1\") TIMEOUT=45 TIMEOUT=invalid /bin/ls\n"), "sudoers", tmpDir)
	if err != nil || len(rawNamedPolicy.UserSpecs) != 1 {
		t.Fatalf("ParseReader with named file failed: %v", err)
	}

	// Also test ParseFile and ParseReader on a JSON policy file
	jsonBytes, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	jsonFile := filepath.Join(tmpDir, "policy.json")
	if err := os.WriteFile(jsonFile, jsonBytes, 0644); err != nil {
		t.Fatal(err)
	}
	fromJSONFile, err := ParseFile(jsonFile)
	if err != nil {
		t.Fatalf("ParseFile on JSON failed: %v", err)
	}
	if len(fromJSONFile.UserSpecs) != len(policy.UserSpecs) {
		t.Errorf("JSON ParseFile UserSpecs = %d, want %d", len(fromJSONFile.UserSpecs), len(policy.UserSpecs))
	}
	fromJSONReader, err := ParseReader(bytes.NewReader(jsonBytes), "policy.json", tmpDir)
	if err != nil {
		t.Fatalf("ParseReader on JSON failed: %v", err)
	}
	if len(fromJSONReader.UserSpecs) != len(policy.UserSpecs) {
		t.Errorf("JSON ParseReader UserSpecs = %d, want %d", len(fromJSONReader.UserSpecs), len(policy.UserSpecs))
	}
}

func TestParseErrors(t *testing.T) {
	errorCases := []struct {
		name  string
		input string
	}{
		{"EmptyInclude", "@include\n"},
		{"EmptyDefaults", "Defaults\n"},
		{"DefaultsMissingOptions", "Defaults:alice\n"},
		{"DefaultsInvalidBinding", "Defaults:   \n"},
		{"DefaultsTrailingCommaInBinding", "Defaults:alice,\n"},
		{"DefaultsEmptyOption", "Defaults env_reset, \n"},
		{"DefaultsOnlyBangOption", "Defaults !\n"},
		{"DefaultsNegatedAssignment", "Defaults !umask=0022\n"},
		{"DefaultsUnterminatedQuote", "Defaults secure_path=\"/bin\n"},
		{"EmptyAlias", "User_Alias\n"},
		{"AliasMissingEquals", "User_Alias ADMINS alice\n"},
		{"AliasInvalidName", "User_Alias ALL = alice\n"},
		{"AliasInvalidCharInName", "User_Alias 123BAD = alice\n"},
		{"AliasEmptyMembers", "User_Alias ADMINS = \n"},
		{"UserAliasEmptyItem", "User_Alias ADMINS = alice, \n"},
		{"RunasAliasEmptyItem", "Runas_Alias RADM = root, \n"},
		{"HostAliasEmptyItem", "Host_Alias HADM = srv1, \n"},
		{"CmndAliasEmptyItem", "Cmnd_Alias CADM = /bin/ls, \n"},
		{"UserSpecMissingEquals", "alice ALL /bin/ls\n"},
		{"UserSpecMissingHostList", "alice = /bin/ls\n"},
		{"UserSpecEmptyRHS", "alice ALL = \n"},
		{"UserSpecEmptyRunasGroup", "alice ALL = (root : g1, ) /bin/ls\n"},
		{"UserSpecEmptyRunasUser", "alice ALL = (u1, ) /bin/ls\n"},
		{"UserSpecEmptyBeforeColon", "alice srv1 = : srv2 = /bin/ls\n"},
		{"UnmatchedCloseParen", "alice ALL = root) /bin/ls\n"},
		{"UnterminatedOpenParen", "alice ALL = (root /bin/ls\n"},
		{"UnterminatedQuoteInCmnd", "alice ALL = /bin/echo \"hello\n"},
		{"DigestWithoutCommand", "alice ALL = sha256:abcdef0123456789\n"},
		{"MissingCommandAfterTag", "alice ALL = NOPASSWD:\n"},
	}

	for _, tc := range errorCases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseString(tc.input); err == nil {
				t.Errorf("Expected error for input %q, but got nil", tc.input)
			}
		})
	}

	if _, err := ParseFile("nonexistent_path_12345.sudoers"); err == nil {
		t.Error("Expected error for nonexistent file in ParseFile")
	}
}

var (
	cvtOnce     bool
	cvtResolved bool
	cvtUseWSL   bool
	cvtBinPath  string
)

// runCvtsudoersOracle invokes local cvtsudoers or wsl /usr/bin/cvtsudoers -f json on input.
func runCvtsudoersOracle(t *testing.T, sudoersInput string) *audit.SudoersPolicy {
	t.Helper()

	if !cvtOnce {
		cvtOnce = true
		if path, err := exec.LookPath("cvtsudoers"); err == nil {
			cvtResolved = true
			cvtBinPath = path
		} else if runtime.GOOS == "windows" {
			if wslPath, err := exec.LookPath("wsl"); err == nil {
				checkCmd := exec.Command(wslPath, "/usr/bin/cvtsudoers", "--version")
				if err := checkCmd.Run(); err == nil {
					cvtResolved = true
					cvtUseWSL = true
					cvtBinPath = wslPath
				}
			}
		}
	}

	if !cvtResolved {
		t.Skip("cvtsudoers not available locally or via WSL; skipping oracle comparison")
	}

	var cmd *exec.Cmd
	if cvtUseWSL {
		cmd = exec.Command(cvtBinPath, "/usr/bin/cvtsudoers", "-f", "json")
	} else {
		cmd = exec.Command(cvtBinPath, "-f", "json")
	}

	normalizedInput := strings.ReplaceAll(sudoersInput, "\r\n", "\n")
	cmd.Stdin = strings.NewReader(normalizedInput)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		t.Fatalf("cvtsudoers failed: %v\nstderr: %s", err, stderr.String())
	}

	if len(bytes.TrimSpace(stdout.Bytes())) == 0 {
		return &audit.SudoersPolicy{}
	}

	var policy audit.SudoersPolicy
	if err := json.Unmarshal(stdout.Bytes(), &policy); err != nil {
		t.Fatalf("Failed to unmarshal cvtsudoers JSON: %v\nJSON:\n%s", err, stdout.String())
	}
	return &policy
}

func normalizePolicyViaJSON(t *testing.T, p *audit.SudoersPolicy) *audit.SudoersPolicy {
	t.Helper()
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("Failed to marshal policy: %v", err)
	}
	var out audit.SudoersPolicy
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("Failed to unmarshal policy: %v", err)
	}
	return &out
}

func stripFindingLines(findings []audit.Finding) []audit.Finding {
	out := make([]audit.Finding, len(findings))
	for i, f := range findings {
		f.Line = 0
		out[i] = f
	}
	return out
}

func TestOracleComparisonWithCvtsudoers(t *testing.T) {
	gtfoClient, err := gtfobins.NewClient()
	if err != nil {
		t.Fatalf("Failed to initialize GTFObins client: %v", err)
	}

	policies := []struct {
		name    string
		sudoers string
	}{
		{
			name: "01_StandardDebianUbuntuDefault",
			sudoers: `
Defaults	env_reset
Defaults	mail_badpass
Defaults	secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
Defaults	use_pty
root	ALL=(ALL:ALL) ALL
%sudo	ALL=(ALL:ALL) ALL
`,
		},
		{
			name: "02_EnvKeepOperationsAndTimeouts",
			sudoers: `
Defaults env_keep = "COLORS DISPLAY HOSTNAME HISTSIZE"
Defaults env_keep += "LD_PRELOAD PYTHONPATH"
Defaults env_keep -= "HISTSIZE"
Defaults env_check = "TERM"
Defaults env_delete -= "IFS"
Defaults passwd_timeout=1, timestamp_timeout=15, umask=0077
`,
		},
		{
			name: "03_ScopedDefaultsAllFourTypes",
			sudoers: `
Defaults@192.168.1.0/24,HOST_ALIAS,!bad.host.local !requiretty
Defaults:alice,#1000,%wheel,%#1001,%:nonunix,%:#1002,+netgrp,USER_ALIAS !authenticate
Defaults!/bin/ls,CMND_ALIAS !syslog
Defaults>root,#0,%wheel,RUNAS_ALIAS set_logname
`,
		},
		{
			name: "04_ComplexAliasesAndMultiDefinitions",
			sudoers: `
User_Alias ADMINS = alice, bob, %wheel : JUNIOR = charlie, !dave, #1005
Runas_Alias DB = postgres, mysql, #26 : WEB = www-data
Host_Alias WEBSERVERS = web01, web02, 10.10.0.0/16 : DBSERVERS = db01.internal, 10.20.0.1
Cmnd_Alias SERVICES = /usr/bin/systemctl restart nginx, /usr/bin/systemctl status nginx : LOGS = /usr/bin/tail -f /var/log/*
ADMINS WEBSERVERS = (WEB) NOPASSWD: SERVICES : DBSERVERS = (DB) PASSWD: LOGS
`,
		},
		{
			name: "05_TagInheritanceAndOverride",
			sudoers: `
alice ALL = NOPASSWD: /bin/ls, /bin/cat, PASSWD: /usr/bin/id, NOEXEC: /usr/bin/find
`,
		},
		{
			name: "06_AllTagsPositiveAndNegative",
			sudoers: `
u1 ALL = NOPASSWD: NOEXEC: SETENV: LOG_INPUT: LOG_OUTPUT: FOLLOW: INTERCEPT: MAIL: /usr/bin/vim
u2 ALL = PASSWD: EXEC: NOSETENV: NOLOG_INPUT: NOLOG_OUTPUT: NOFOLLOW: NOINTERCEPT: NOMAIL: /usr/bin/nano
`,
		},
		{
			name: "07_RunasSpecVariations",
			sudoers: `
u1 ALL = /bin/ls
u2 ALL = (root) /bin/ls
u3 ALL = (:staff) /bin/ls
u4 ALL = (:) /bin/ls
u5 ALL = () /bin/ls
u6 ALL = (u1, u2 : g1, g2) /bin/ls
u7 ALL = (!root : !wheel) /bin/ls
`,
		},
		{
			name: "08_DigestsSingleAndMultiple",
			sudoers: `
dave ALL = (root) sha224:0123456789abcdef0123456789abcdef0123456789abcdef01234567 /usr/bin/id, sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789, sha512:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef /bin/sh
`,
		},
		{
			name: "09_BackslashLineContinuationsAndComments",
			sudoers: `
# Top comment
Defaults env_reset, \
    secure_path="/usr/sbin:/usr/bin:/sbin:/bin", \
    use_pty # inline comment
alice, \
    bob \
    ALL = (root) \
    NOPASSWD: \
    /usr/bin/python3 "", \
    /usr/sbin/reboot "" # end comment
`,
		},
		{
			name: "10_NegatedCommandsAndWildcards",
			sudoers: `
operator ALL = (ALL) ALL, !/usr/bin/su, !/usr/bin/passwd, /usr/bin/cat /var/log/*
`,
		},
		{
			name: "11_SudoeditAndWritablePaths",
			sudoers: `
editor1 ALL = sudoedit /etc/sudoers, sudoedit /var/www/html/index.html, sudoedit
deployer ALL = NOPASSWD: /tmp/deploy.sh, /var/tmp/script.sh ""
`,
		},
		{
			name: "12_HardenedCleanPolicy",
			sudoers: `
Defaults secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
Defaults use_pty, noexec, requiretty, ignore_dot, env_reset, umask=0077
Defaults passwd_timeout=1, timestamp_timeout=5, timestamp_type=tty
admin ALL = (root) /usr/sbin/reboot "", /usr/sbin/shutdown -h now
`,
		},
		{
			name: "13_CommandTimeoutsAndValidityWindow",
			sudoers: `
auditor ALL = TIMEOUT=5m NOTBEFORE=20250101120000Z NOTAFTER=20260101120000Z /usr/bin/journalctl -u ssh
`,
		},
		{
			name: "14_CVE201914287AndGroupRunas",
			sudoers: `
secuser ALL = (ALL, !root, #-1) /usr/bin/id ""
grpuser ALL = (%wheel, +netgrp, %:nonunix, %#200, %:#300 : g1, RUNAS_ALIAS) /usr/bin/whoami ""
`,
		},
		{
			name: "15_ImpliedSetenvOnALLVariations",
			sudoers: `
u1 ALL = ALL
u2 ALL = NOSETENV: ALL
u3 ALL = /bin/ls, ALL
u4 ALL = ALL, /bin/ls
u5 ALL = !ALL
u6 ALL = ALL, NOPASSWD: /bin/ls
`,
		},
		{
			name: "16_ScopedDefaultsInteractionWithCommands",
			sudoers: `
Defaults:passwordless_user !authenticate
Defaults!/usr/bin/find noexec
passwordless_user ALL = /usr/bin/vim
regular_user ALL = /usr/bin/find /var/log -type f
`,
		},
	}

	for _, tc := range policies {
		t.Run(tc.name, func(t *testing.T) {
			cvtPolicy := runCvtsudoersOracle(t, tc.sudoers)
			nativePolicy, err := ParseString(tc.sudoers)
			if err != nil {
				t.Fatalf("ParseString failed: %v", err)
			}

			normCvt := normalizePolicyViaJSON(t, cvtPolicy)
			normNative := normalizePolicyViaJSON(t, nativePolicy)

			if !reflect.DeepEqual(normNative, normCvt) {
				cvtJSON, _ := json.MarshalIndent(normCvt, "", "  ")
				natJSON, _ := json.MarshalIndent(normNative, "", "  ")
				t.Errorf("Policy mismatch between native parser and cvtsudoers:\n--- Native ---\n%s\n--- cvtsudoers ---\n%s", string(natJSON), string(cvtJSON))
			}

			cvtFindings := stripFindingLines(audit.RunAudit(cvtPolicy, gtfoClient))
			nativeFindings := stripFindingLines(audit.RunAudit(nativePolicy, gtfoClient))

			if !reflect.DeepEqual(nativeFindings, cvtFindings) {
				t.Errorf("Audit findings mismatch:\n--- Native (%d) ---\n%+v\n--- cvtsudoers (%d) ---\n%+v",
					len(nativeFindings), nativeFindings, len(cvtFindings), cvtFindings)
			}
		})
	}
}
