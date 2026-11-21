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
	"sync"
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
		{"EmptyJSONObject", []byte(`{}`), true},
		{"EmptyDefaultsArray", []byte(`{"Defaults": []}`), true},
		{"EmptyUserSpecsArray", []byte(`{"User_Specs": []}`), true},
		{"AllValidTopLevelKeys", []byte(`{"Defaults": [], "User_Aliases": {}, "Runas_Aliases": {}, "Host_Aliases": {}, "Command_Aliases": {}, "User_Specs": []}`), true},
		{"ArbitraryJSONObject", []byte(`{"foo": "bar"}`), false},
		{"GTFObinsJSON", []byte(`{"executables": {}}`), false},
		{"AuditReportJSON", []byte(`{"policy_findings": []}`), false},
		{"MixedKnownAndUnknownKeys", []byte(`{"Defaults": [], "foo": "bar"}`), false},
		{"JSONArray", []byte(`[]`), false},
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

func TestResolveIncludePath(t *testing.T) {
	t.Run("OfflineEtcIncludeDoesNotFallBackToHostEtc", func(t *testing.T) {
		tmpDir := t.TempDir()

		got := resolveIncludePath("/etc/sudoers.d", tmpDir)
		want := filepath.Join(tmpDir, "sudoers.d")
		if got == "/etc/sudoers.d" {
			t.Fatalf("resolveIncludePath leaked host path %q for offline baseDir %q", got, tmpDir)
		}
		if got != want {
			t.Errorf("resolveIncludePath(%q, %q) = %q, want %q", "/etc/sudoers.d", tmpDir, got, want)
		}

		gotEtc := resolveIncludePath("/etc", tmpDir)
		wantEtc := filepath.Join(tmpDir, "etc")
		if gotEtc == "/etc" {
			t.Fatalf("resolveIncludePath leaked host path %q for offline baseDir %q", gotEtc, tmpDir)
		}
		if gotEtc != wantEtc {
			t.Errorf("resolveIncludePath(%q, %q) = %q, want %q", "/etc", tmpDir, gotEtc, wantEtc)
		}

		gotMissing := resolveIncludePath("/etc/sudoers.d/missing", tmpDir)
		wantMissing := filepath.Join(tmpDir, "sudoers.d", "missing")
		if gotMissing == "/etc/sudoers.d/missing" {
			t.Fatalf("resolveIncludePath leaked host path %q for offline baseDir %q", gotMissing, tmpDir)
		}
		if gotMissing != wantMissing {
			t.Errorf("resolveIncludePath(%q, %q) = %q, want %q", "/etc/sudoers.d/missing", tmpDir, gotMissing, wantMissing)
		}
	})

	t.Run("OfflineEtcPrefersLocalCandidates", func(t *testing.T) {
		tmpDir := t.TempDir()
		nestedDir := filepath.Join(tmpDir, "sudoers.d")
		if err := os.MkdirAll(nestedDir, 0755); err != nil {
			t.Fatal(err)
		}
		nestedFile := filepath.Join(nestedDir, "01_app")
		if err := os.WriteFile(nestedFile, []byte("alice ALL = /bin/ls\n"), 0644); err != nil {
			t.Fatal(err)
		}
		flatFile := filepath.Join(tmpDir, "02_flat")
		if err := os.WriteFile(flatFile, []byte("bob ALL = /bin/cat\n"), 0644); err != nil {
			t.Fatal(err)
		}

		if got := resolveIncludePath("/etc/sudoers.d/01_app", tmpDir); got != nestedFile {
			t.Errorf("resolveIncludePath nested = %q, want %q", got, nestedFile)
		}
		if got := resolveIncludePath("/etc/sudoers.d/02_flat", tmpDir); got != flatFile {
			t.Errorf("resolveIncludePath flat = %q, want %q", got, flatFile)
		}
	})

	t.Run("LiveEtcNonEtcAbsoluteAndRelativePaths", func(t *testing.T) {
		tmpDir := t.TempDir()
		otherDir := t.TempDir()
		otherFile := filepath.Join(otherDir, "extra_sudoers")
		if err := os.WriteFile(otherFile, []byte("carol ALL = /usr/bin/id\n"), 0644); err != nil {
			t.Fatal(err)
		}

		if got := resolveIncludePath("/etc/sudoers.d", "/etc"); got != "/etc/sudoers.d" {
			t.Errorf("resolveIncludePath live /etc = %q, want %q", got, "/etc/sudoers.d")
		}
		if got := resolveIncludePath(otherFile, tmpDir); got != otherFile {
			t.Errorf("resolveIncludePath external abs = %q, want %q", got, otherFile)
		}
		wantRel := filepath.Join(tmpDir, "sudoers.d")
		if got := resolveIncludePath("sudoers.d", tmpDir); got != wantRel {
			t.Errorf("resolveIncludePath relative = %q, want %q", got, wantRel)
		}
	})
}

func TestIncludedirErrorPropagation(t *testing.T) {
	t.Run("NonDirectoryReturnsError", func(t *testing.T) {
		tmpDir := t.TempDir()
		notADir := filepath.Join(tmpDir, "not_a_dir")
		if err := os.WriteFile(notADir, []byte("alice ALL = /bin/ls\n"), 0644); err != nil {
			t.Fatal(err)
		}
		mainFile := filepath.Join(tmpDir, "sudoers")
		if err := os.WriteFile(mainFile, []byte("@includedir not_a_dir\n"), 0644); err != nil {
			t.Fatal(err)
		}

		_, err := ParseFile(mainFile)
		if err == nil {
			t.Fatal("expected error when @includedir points to a regular file, got nil")
		}
		if !strings.Contains(err.Error(), "failed to read included directory") {
			t.Errorf("unexpected error message: %v", err)
		}
	})

	t.Run("PermissionDeniedReturnsErrorOnUnix", func(t *testing.T) {
		if runtime.GOOS == "windows" || os.Geteuid() == 0 {
			t.Skip("permission-denied includedir test requires non-root Unix environment")
		}
		tmpDir := t.TempDir()
		lockedDir := filepath.Join(tmpDir, "locked_sudoers_d")
		if err := os.MkdirAll(lockedDir, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(lockedDir, 0000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			_ = os.Chmod(lockedDir, 0755)
		})

		mainFile := filepath.Join(tmpDir, "sudoers")
		if err := os.WriteFile(mainFile, []byte("#includedir locked_sudoers_d\n"), 0644); err != nil {
			t.Fatal(err)
		}

		_, err := ParseFile(mainFile)
		if err == nil {
			t.Fatal("expected permission error from unreadable #includedir, got nil")
		}
		if !os.IsPermission(err) {
			t.Errorf("expected permission error, got: %v", err)
		}
	})
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
		{"UserSpecTrailingBackslashInUserList", "00\\ =0\n"},
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

// cvtsudoersOracleConfig captures how the cvtsudoers oracle binary is invoked.
type cvtsudoersOracleConfig struct {
	resolved bool
	useWSL   bool
	binPath  string
}

var (
	cvtResolveOnce sync.Once
	cvtOracle      cvtsudoersOracleConfig
)

// resolveCvtsudoersOracle locates cvtsudoers (directly or via WSL) exactly once,
// safe for concurrent parallel subtests.
func resolveCvtsudoersOracle() {
	cvtResolveOnce.Do(func() {
		if path, err := exec.LookPath("cvtsudoers"); err == nil {
			cvtOracle = cvtsudoersOracleConfig{resolved: true, binPath: path}
			return
		}
		if runtime.GOOS == "windows" {
			if wslPath, err := exec.LookPath("wsl"); err == nil {
				checkCmd := exec.Command(wslPath, "/usr/bin/cvtsudoers", "--version")
				if err := checkCmd.Run(); err == nil {
					cvtOracle = cvtsudoersOracleConfig{resolved: true, useWSL: true, binPath: wslPath}
				}
			}
		}
	})
}

// runCvtsudoersOracle invokes local cvtsudoers or wsl /usr/bin/cvtsudoers -f json on input.
func runCvtsudoersOracle(t *testing.T, sudoersInput string) *audit.SudoersPolicy {
	t.Helper()

	resolveCvtsudoersOracle()

	if !cvtOracle.resolved {
		if os.Getenv("SUDO_CHECK_REQUIRE_ORACLE") == "1" {
			t.Fatalf("cvtsudoers not available locally or via WSL, but SUDO_CHECK_REQUIRE_ORACLE=1 is set")
		}
		t.Skip("cvtsudoers not available locally or via WSL; skipping oracle comparison")
	}

	var cmd *exec.Cmd
	if cvtOracle.useWSL {
		cmd = exec.Command(cvtOracle.binPath, "/usr/bin/cvtsudoers", "-f", "json")
	} else {
		cmd = exec.Command(cvtOracle.binPath, "-f", "json")
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
		f.SourceLine = ""
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
			t.Parallel()
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

func TestParseFileAndReader_AutoDetectSudoLLAndLDIF(t *testing.T) {
	t.Run("SudoLL", func(t *testing.T) {
		tmpDir := t.TempDir()
		sudollInput := strings.Join([]string{
			"Matching Defaults entries for deploy on web01:",
			`    env_reset, !requiretty, secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"`,
			"",
			"User deploy may run the following commands on web01:",
			"",
			"Sudoers entry:",
			"    RunAsUsers: root",
			"    Options: !authenticate",
			"    Commands:",
			"        /usr/bin/systemctl restart nginx",
			"",
			"Sudoers entry:",
			"    RunAsUsers: postgres",
			"    Commands:",
			"        /usr/bin/psql",
		}, "\n") + "\n"

		sudollPath := filepath.Join(tmpDir, "sudo_ll_output.txt")
		if err := os.WriteFile(sudollPath, []byte(sudollInput), 0644); err != nil {
			t.Fatal(err)
		}

		verifySudoLLPolicy := func(t *testing.T, policy *audit.SudoersPolicy, wantFile string) {
			t.Helper()
			wantCmdFile := normalizeSourceFile(wantFile)
			if len(policy.Defaults) != 1 {
				t.Fatalf("expected 1 DefaultBinding, got %d: %+v", len(policy.Defaults), policy.Defaults)
			}
			def := policy.Defaults[0]
			if def.File != wantFile {
				t.Errorf("Defaults[0].File = %q, want %q", def.File, wantFile)
			}
			if len(def.Options) != 3 ||
				def.Options[0]["env_reset"] != true ||
				def.Options[1]["requiretty"] != false ||
				def.Options[2]["secure_path"] != "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" {
				t.Errorf("unexpected Defaults[0].Options: %+v", def.Options)
			}

			if len(policy.UserSpecs) != 2 {
				t.Fatalf("expected 2 UserSpecs, got %d: %+v", len(policy.UserSpecs), policy.UserSpecs)
			}
			spec0 := policy.UserSpecs[0]
			if spec0.File != wantFile {
				t.Errorf("UserSpecs[0].File = %q, want %q", spec0.File, wantFile)
			}
			if len(spec0.UserList) != 1 || spec0.UserList[0].Username != "deploy" || spec0.UserList[0].File != wantFile {
				t.Errorf("unexpected UserSpecs[0].UserList: %+v", spec0.UserList)
			}
			if len(spec0.HostList) != 1 || spec0.HostList[0].Hostname != "web01" || spec0.HostList[0].File != wantFile {
				t.Errorf("unexpected UserSpecs[0].HostList: %+v", spec0.HostList)
			}
			cs0 := spec0.CmndSpecs[0]
			if len(cs0.RunasUsers) != 1 || cs0.RunasUsers[0].Username != "root" {
				t.Errorf("unexpected UserSpecs[0] RunasUsers: %+v", cs0.RunasUsers)
			}
			if len(cs0.Options) != 1 || cs0.Options[0]["authenticate"] != false {
				t.Errorf("unexpected UserSpecs[0] Options: %+v", cs0.Options)
			}
			if len(cs0.Commands) != 1 || cs0.Commands[0].Command != "/usr/bin/systemctl restart nginx" || cs0.Commands[0].File != wantCmdFile {
				t.Errorf("unexpected UserSpecs[0] Commands: %+v", cs0.Commands)
			}

			spec1 := policy.UserSpecs[1]
			if spec1.File != wantFile {
				t.Errorf("UserSpecs[1].File = %q, want %q", spec1.File, wantFile)
			}
			if len(spec1.CmndSpecs[0].RunasUsers) != 1 || spec1.CmndSpecs[0].RunasUsers[0].Username != "postgres" {
				t.Errorf("unexpected UserSpecs[1] RunasUsers: %+v", spec1.CmndSpecs[0].RunasUsers)
			}
			if len(spec1.CmndSpecs[0].Commands) != 1 || spec1.CmndSpecs[0].Commands[0].Command != "/usr/bin/psql" || spec1.CmndSpecs[0].Commands[0].File != wantCmdFile {
				t.Errorf("unexpected UserSpecs[1] Commands: %+v", spec1.CmndSpecs[0].Commands)
			}
		}

		fromFile, err := ParseFile(sudollPath)
		if err != nil {
			t.Fatalf("ParseFile on sudo -ll output failed: %v", err)
		}
		verifySudoLLPolicy(t, fromFile, filepath.ToSlash(sudollPath))

		fromNamedReader, err := ParseReader(strings.NewReader(sudollInput), "host-web01.sudoll", tmpDir)
		if err != nil {
			t.Fatalf("ParseReader (named) on sudo -ll output failed: %v", err)
		}
		verifySudoLLPolicy(t, fromNamedReader, "host-web01.sudoll")

		fromStdinReader, err := ParseReader(strings.NewReader(sudollInput), "", "")
		if err != nil {
			t.Fatalf("ParseReader (empty filename -> stdin) on sudo -ll output failed: %v", err)
		}
		verifySudoLLPolicy(t, fromStdinReader, "stdin")

		fromParseString, err := ParseString(sudollInput)
		if err != nil {
			t.Fatalf("ParseString on sudo -ll output failed: %v", err)
		}
		verifySudoLLPolicy(t, fromParseString, "stdin")
	})

	t.Run("LDIF", func(t *testing.T) {
		tmpDir := t.TempDir()
		ldifInput := strings.Join([]string{
			"version: 1",
			"dn: cn=defaults,ou=SUDOers,dc=example,dc=com",
			"objectClass: sudoRole",
			"cn: defaults",
			"sudoOption: env_reset",
			"sudoOption: !visiblepw",
			"",
			"dn: cn=late_rule,ou=SUDOers,dc=example,dc=com",
			"objectClass: sudoRole",
			"cn: late_rule",
			"sudoUser: second_user",
			"sudoHost: db01",
			"sudoRunAsUser: postgres",
			"sudoCommand: /usr/bin/pg_dump",
			"sudoOrder: 20",
			"",
			"dn: cn=early_rule,ou=SUDOers,dc=example,dc=com",
			"objectClass: sudoRole",
			"cn: early_rule",
			"sudoUser: first_user",
			"sudoHost: app01",
			"sudoRunAsUser: root",
			"sudoOption: !authenticate",
			"sudoCommand: /usr/bin/id",
			"sudoOrder: 5",
		}, "\n") + "\n"

		ldifPath := filepath.Join(tmpDir, "sudoers.ldif")
		if err := os.WriteFile(ldifPath, []byte(ldifInput), 0644); err != nil {
			t.Fatal(err)
		}

		verifyLDIFPolicy := func(t *testing.T, policy *audit.SudoersPolicy, wantFile string) {
			t.Helper()
			wantCmdFile := normalizeSourceFile(wantFile)
			if len(policy.Defaults) != 1 {
				t.Fatalf("expected 1 DefaultBinding, got %d: %+v", len(policy.Defaults), policy.Defaults)
			}
			def := policy.Defaults[0]
			if def.File != wantFile {
				t.Errorf("Defaults[0].File = %q, want %q", def.File, wantFile)
			}
			if len(def.Options) != 2 || def.Options[0]["env_reset"] != true || def.Options[1]["visiblepw"] != false {
				t.Errorf("unexpected Defaults[0].Options: %+v", def.Options)
			}

			if len(policy.UserSpecs) != 2 {
				t.Fatalf("expected 2 UserSpecs, got %d: %+v", len(policy.UserSpecs), policy.UserSpecs)
			}

			// sudoOrder=5 must sort before sudoOrder=20
			spec0 := policy.UserSpecs[0]
			if spec0.File != wantFile {
				t.Errorf("UserSpecs[0].File = %q, want %q", spec0.File, wantFile)
			}
			if len(spec0.UserList) != 1 || spec0.UserList[0].Username != "first_user" || spec0.UserList[0].File != wantFile {
				t.Errorf("expected first_user ordered first, got: %+v", spec0.UserList)
			}
			if len(spec0.HostList) != 1 || spec0.HostList[0].Hostname != "app01" || spec0.HostList[0].File != wantFile {
				t.Errorf("unexpected UserSpecs[0].HostList: %+v", spec0.HostList)
			}
			if len(spec0.CmndSpecs[0].Options) != 1 || spec0.CmndSpecs[0].Options[0]["authenticate"] != false {
				t.Errorf("unexpected UserSpecs[0] Options: %+v", spec0.CmndSpecs[0].Options)
			}
			if len(spec0.CmndSpecs[0].Commands) != 1 || spec0.CmndSpecs[0].Commands[0].Command != "/usr/bin/id" || spec0.CmndSpecs[0].Commands[0].File != wantCmdFile {
				t.Errorf("unexpected UserSpecs[0] Commands: %+v", spec0.CmndSpecs[0].Commands)
			}

			spec1 := policy.UserSpecs[1]
			if spec1.File != wantFile {
				t.Errorf("UserSpecs[1].File = %q, want %q", spec1.File, wantFile)
			}
			if len(spec1.UserList) != 1 || spec1.UserList[0].Username != "second_user" || spec1.UserList[0].File != wantFile {
				t.Errorf("expected second_user ordered second, got: %+v", spec1.UserList)
			}
			if len(spec1.HostList) != 1 || spec1.HostList[0].Hostname != "db01" || spec1.HostList[0].File != wantFile {
				t.Errorf("unexpected UserSpecs[1].HostList: %+v", spec1.HostList)
			}
			if len(spec1.CmndSpecs[0].RunasUsers) != 1 || spec1.CmndSpecs[0].RunasUsers[0].Username != "postgres" {
				t.Errorf("unexpected UserSpecs[1] RunasUsers: %+v", spec1.CmndSpecs[0].RunasUsers)
			}
			if len(spec1.CmndSpecs[0].Commands) != 1 || spec1.CmndSpecs[0].Commands[0].Command != "/usr/bin/pg_dump" || spec1.CmndSpecs[0].Commands[0].File != wantCmdFile {
				t.Errorf("unexpected UserSpecs[1] Commands: %+v", spec1.CmndSpecs[0].Commands)
			}
		}

		fromFile, err := ParseFile(ldifPath)
		if err != nil {
			t.Fatalf("ParseFile on LDIF failed: %v", err)
		}
		verifyLDIFPolicy(t, fromFile, filepath.ToSlash(ldifPath))

		fromNamedReader, err := ParseReader(strings.NewReader(ldifInput), "ldap-export.ldif", tmpDir)
		if err != nil {
			t.Fatalf("ParseReader (named) on LDIF failed: %v", err)
		}
		verifyLDIFPolicy(t, fromNamedReader, "ldap-export.ldif")

		fromStdinReader, err := ParseReader(strings.NewReader(ldifInput), "", "")
		if err != nil {
			t.Fatalf("ParseReader (empty filename -> stdin) on LDIF failed: %v", err)
		}
		verifyLDIFPolicy(t, fromStdinReader, "stdin")

		fromParseString, err := ParseString(ldifInput)
		if err != nil {
			t.Fatalf("ParseString on LDIF failed: %v", err)
		}
		verifyLDIFPolicy(t, fromParseString, "stdin")
	})

	t.Run("RawSudoersAndJSONPreserved", func(t *testing.T) {
		tmpDir := t.TempDir()
		rawSudoers := strings.Join([]string{
			"# Comment that mentions objectClass: sudoRole and User bob may run the following commands on h:",
			"Defaults env_reset, use_pty",
			"alice ALL = (root) NOPASSWD: /usr/bin/id",
		}, "\n") + "\n"

		rawPath := filepath.Join(tmpDir, "sudoers")
		if err := os.WriteFile(rawPath, []byte(rawSudoers), 0644); err != nil {
			t.Fatal(err)
		}

		verifyRaw := func(t *testing.T, p *audit.SudoersPolicy, wantFile string) {
			t.Helper()
			if len(p.Defaults) != 1 || len(p.UserSpecs) != 1 {
				t.Fatalf("unexpected raw sudoers counts: defaults=%d userspecs=%d", len(p.Defaults), len(p.UserSpecs))
			}
			if p.Defaults[0].File != wantFile {
				t.Errorf("raw Defaults[0].File = %q, want %q", p.Defaults[0].File, wantFile)
			}
			if p.UserSpecs[0].File != wantFile || p.UserSpecs[0].UserList[0].Username != "alice" {
				t.Errorf("unexpected raw UserSpecs[0]: %+v", p.UserSpecs[0])
			}
			if p.UserSpecs[0].CmndSpecs[0].Commands[0].Command != "/usr/bin/id" {
				t.Errorf("unexpected raw command: %+v", p.UserSpecs[0].CmndSpecs[0].Commands)
			}
		}

		rawFromFile, err := ParseFile(rawPath)
		if err != nil {
			t.Fatalf("ParseFile on raw sudoers failed: %v", err)
		}
		verifyRaw(t, rawFromFile, filepath.ToSlash(rawPath))

		rawNamedReader, err := ParseReader(strings.NewReader(rawSudoers), "raw.sudoers", tmpDir)
		if err != nil {
			t.Fatalf("ParseReader (named) on raw sudoers failed: %v", err)
		}
		verifyRaw(t, rawNamedReader, "raw.sudoers")

		rawStdinReader, err := ParseReader(strings.NewReader(rawSudoers), "", "")
		if err != nil {
			t.Fatalf("ParseReader (empty filename) on raw sudoers failed: %v", err)
		}
		verifyRaw(t, rawStdinReader, "")

		// Marshal to cvtsudoers-compatible JSON and verify ParseFile / ParseReader (with and without BOM)
		jsonBytes, err := json.Marshal(rawStdinReader)
		if err != nil {
			t.Fatalf("json.Marshal failed: %v", err)
		}
		jsonPath := filepath.Join(tmpDir, "policy.json")
		if err := os.WriteFile(jsonPath, jsonBytes, 0644); err != nil {
			t.Fatal(err)
		}

		jsonFromFile, err := ParseFile(jsonPath)
		if err != nil {
			t.Fatalf("ParseFile on JSON failed: %v", err)
		}
		verifyRaw(t, jsonFromFile, "")

		jsonFromReader, err := ParseReader(bytes.NewReader(jsonBytes), "policy.json", tmpDir)
		if err != nil {
			t.Fatalf("ParseReader on JSON failed: %v", err)
		}
		verifyRaw(t, jsonFromReader, "")

		bomJSON := append([]byte("\xef\xbb\xbf"), jsonBytes...)
		jsonFromBOMReader, err := ParseReader(bytes.NewReader(bomJSON), "", "")
		if err != nil {
			t.Fatalf("ParseReader on BOM JSON failed: %v", err)
		}
		verifyRaw(t, jsonFromBOMReader, "")

		if _, err := ParseReader(nil, "", ""); err == nil {
			t.Error("expected error for nil reader in ParseReader, got nil")
		}
	})
}

func TestParseFileWithOptions_DeterministicHostIncludeExpansion(t *testing.T) {
	tmpDir := t.TempDir()

	localHost, _ := os.Hostname()
	if idx := strings.IndexByte(localHost, '.'); idx != -1 {
		localHost = localHost[:idx]
	}
	if localHost == "" {
		localHost = "localtest"
	}

	if err := os.WriteFile(filepath.Join(tmpDir, "host_"+localHost), []byte("localuser ALL = /usr/bin/id\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "host_web01"), []byte("webuser ALL = /usr/bin/systemctl status nginx\n"), 0644); err != nil {
		t.Fatal(err)
	}
	mainPath := filepath.Join(tmpDir, "sudoers")
	if err := os.WriteFile(mainPath, []byte("#include host_%h\nbaseuser ALL = /usr/bin/ls\n"), 0644); err != nil {
		t.Fatal(err)
	}

	// Offline mode with no Hostname must NOT expand %h using the local machine's hostname.
	offlinePolicy, err := ParseFileWithOptions(mainPath, ParseOptions{Offline: true})
	if err != nil {
		t.Fatalf("ParseFileWithOptions offline failed: %v", err)
	}
	if len(offlinePolicy.UserSpecs) != 1 || offlinePolicy.UserSpecs[0].UserList[0].Username != "baseuser" {
		t.Errorf("expected offline parse to skip %%h include and only parse baseuser, got %+v", offlinePolicy.UserSpecs)
	}

	// Explicit Hostname (FQDN) strips domain to short hostname "web01" and includes host_web01.
	targetedPolicy, err := ParseFileWithOptions(mainPath, ParseOptions{Hostname: "web01.example.com", Offline: true})
	if err != nil {
		t.Fatalf("ParseFileWithOptions with Hostname failed: %v", err)
	}
	if len(targetedPolicy.UserSpecs) != 2 || targetedPolicy.UserSpecs[0].UserList[0].Username != "webuser" {
		t.Errorf("expected targeted offline parse to include webuser from host_web01, got %+v", targetedPolicy.UserSpecs)
	}
}
