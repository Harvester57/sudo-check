package cmd

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sudo-check/pkg/audit"
	"testing"
)

func resetFlags() {
	outputDir = ""
	formats = "text"
	gtfoBinsPath = ""
	cvtSudoersPath = ""
	failOn = ""
	noColor = true
	configPath = ""
	profileName = ""
	customGTFObinsPath = ""
	baselinePath = ""
	subcommandAware = false

	dropInMode = false
	checkShadowing = true
	checkExpiry = false
	fixPatchPath = ""
	scanHost = ""

	sudoersFile = "/etc/sudoers"
	dbOutputPath = "gtfobins.json"
	gtfoBinsDownloadURL = gtfoBinsURL

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
	} {
		if f := rootCmd.PersistentFlags().Lookup(name); f != nil {
			f.Changed = false
		}
		if f := scanCmd.Flags().Lookup(name); f != nil {
			f.Changed = false
		}
		if f := systemCmd.Flags().Lookup(name); f != nil {
			f.Changed = false
		}
	}
	for _, name := range []string{"dropin", "check-shadowing", "check-expiry", "fix-patch", "host"} {
		if f := scanCmd.Flags().Lookup(name); f != nil {
			f.Changed = false
		}
	}
	if f := systemCmd.Flags().Lookup("sudoers-file"); f != nil {
		f.Changed = false
	}
	if f := updateDbCmd.Flags().Lookup("output"); f != nil {
		f.Changed = false
	}

	rootCmd.SetIn(nil)
	rootCmd.SetOut(nil)
	rootCmd.SetErr(nil)
}

func TestVersionCmd(t *testing.T) {
	resetFlags()
	rootCmd.SetArgs([]string{"version"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("version command failed: %v", err)
	}
}

func TestScanCmd_JSONPolicyAndFormats(t *testing.T) {
	resetFlags()
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.json")
	policyJSON := `{
		"Defaults": [
			{"Options": [{"env_reset": true}, {"secure_path": "/usr/bin"}, {"use_pty": true}, {"log_output": true}, {"umask": "0022"}, {"logfile": "/var/log/sudo.log"}]}
		],
		"User_Specs": [
			{
				"User_List": [{"username": "admin"}],
				"Host_List": [{"hostname": "ALL"}],
				"Cmnd_Specs": [
					{
						"runasusers": [{"username": "root"}],
						"Options": [{"authenticate": false}],
						"Commands": [{"command": "ALL"}]
					}
				]
			}
		]
	}`
	if err := os.WriteFile(policyPath, []byte(policyJSON), 0600); err != nil {
		t.Fatalf("failed to write policy.json: %v", err)
	}

	outDir := filepath.Join(dir, "reports")
	rootCmd.SetArgs([]string{
		"scan", policyPath,
		"-o", outDir,
		"-f", "text,json,sarif,html,pdf",
		"--no-color",
	})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("scan command failed: %v", err)
	}

	expectedFiles := []string{"report.txt", "report.json", "report.sarif", "report.html", "report.pdf"}
	for _, name := range expectedFiles {
		p := filepath.Join(outDir, name)
		if _, err := os.Stat(p); err != nil {
			t.Errorf("expected generated report %s to exist: %v", p, err)
		}
	}

	rawJSON, err := os.ReadFile(filepath.Join(outDir, "report.json"))
	if err != nil {
		t.Fatalf("failed to read report.json: %v", err)
	}
	var res audit.AuditResult
	if err := json.Unmarshal(rawJSON, &res); err != nil {
		t.Fatalf("failed to unmarshal report.json: %v", err)
	}
	if res.Hostname != "" {
		t.Errorf("expected offline scan report to have empty hostname, got %q", res.Hostname)
	}
	foundAdmin := false
	for _, f := range res.PolicyFindings {
		if f.User == "admin" && f.Host == "ALL" {
			foundAdmin = true
			break
		}
	}
	if !foundAdmin {
		t.Errorf("expected findings for user 'admin' on host 'ALL' after User_List/Host_List schema fix, got findings: %+v", res.PolicyFindings)
	}
}

func TestScanCmd_RawSudoersAndFailOn(t *testing.T) {
	resetFlags()
	dir := t.TempDir()
	sudoersPath := filepath.Join(dir, "sudoers")
	rawSudoers := `
Defaults env_reset, use_pty, secure_path="/usr/sbin:/usr/bin:/sbin:/bin"
Defaults logfile="/var/log/sudo.log", log_output, umask=0022
deploy ALL=(root) NOPASSWD: /usr/bin/vim
`
	if err := os.WriteFile(sudoersPath, []byte(rawSudoers), 0600); err != nil {
		t.Fatalf("failed to write sudoers file: %v", err)
	}

	outDir := filepath.Join(dir, "out")
	rootCmd.SetArgs([]string{
		"scan", sudoersPath,
		"-o", outDir,
		"-f", "json",
		"--fail-on", "CRITICAL",
	})
	err := rootCmd.Execute()
	if !errors.Is(err, ErrFailOnThreshold) {
		t.Fatalf("expected ErrFailOnThreshold for CRITICAL finding, got: %v", err)
	}

	// Invalid --fail-on value
	resetFlags()
	rootCmd.SetArgs([]string{
		"scan", sudoersPath,
		"--fail-on", "INVALID_SEV",
	})
	if err := rootCmd.Execute(); err == nil || !strings.Contains(err.Error(), "invalid --fail-on severity") {
		t.Fatalf("expected invalid --fail-on error, got: %v", err)
	}
}

func TestScanCmd_Directories(t *testing.T) {
	resetFlags()
	// 1. Directory with raw sudoers drop-ins
	dropinDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dropinDir, "10-admins"), []byte("Defaults use_pty\nadmin ALL=(ALL) /usr/bin/id\n"), 0600); err != nil {
		t.Fatalf("failed to write drop-in: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dropinDir, ".hidden"), []byte("ignored"), 0600); err != nil {
		t.Fatalf("failed to write hidden file: %v", err)
	}
	rootCmd.SetArgs([]string{"scan", dropinDir, "-f", "text", "--no-color"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("scan on drop-in directory failed: %v", err)
	}

	// 1b. Directory with root sudoers + #includedir sudoers.d + standalone extra.sudoers
	resetFlags()
	mixedDir := t.TempDir()
	subDropinDir := filepath.Join(mixedDir, "sudoers.d")
	if err := os.MkdirAll(subDropinDir, 0750); err != nil {
		t.Fatalf("failed to create sudoers.d: %v", err)
	}
	rootSudoersContent := "Defaults env_reset, use_pty, secure_path=\"/usr/bin\"\n#includedir sudoers.d\n"
	if err := os.WriteFile(filepath.Join(mixedDir, "sudoers"), []byte(rootSudoersContent), 0600); err != nil {
		t.Fatalf("failed to write root sudoers: %v", err)
	}
	if err := os.WriteFile(filepath.Join(subDropinDir, "10-alice"), []byte("alice ALL=(root) /usr/bin/find\n"), 0600); err != nil {
		t.Fatalf("failed to write 10-alice: %v", err)
	}
	if err := os.WriteFile(filepath.Join(mixedDir, "standalone.sudoers"), []byte("bob ALL=(root) /usr/bin/vim\n"), 0600); err != nil {
		t.Fatalf("failed to write standalone.sudoers: %v", err)
	}
	mixedOut := filepath.Join(mixedDir, "out")
	rootCmd.SetArgs([]string{"scan", mixedDir, "-o", mixedOut, "-f", "json,html", "--no-color"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("scan on mixed directory failed: %v", err)
	}
	mixedJSONBytes, err := os.ReadFile(filepath.Join(mixedOut, "report.json"))
	if err != nil {
		t.Fatalf("failed to read mixed report.json: %v", err)
	}
	mixedJSON := string(mixedJSONBytes)
	if !strings.Contains(mixedJSON, "10-alice") || !strings.Contains(mixedJSON, "standalone.sudoers") {
		t.Errorf("expected both included 10-alice and standalone.sudoers in report.json, got:\n%s", mixedJSON)
	}
	if strings.Count(mixedJSON, `"Dangerous Sudo Binary allowed: find (shell)"`) != 1 {
		t.Errorf("expected 10-alice not to be audited twice when included via root sudoers")
	}

	// 2. Directory with JSON files (including one malformed JSON skipped with warning)
	resetFlags()
	jsonDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(jsonDir, "valid.json"), []byte(`{"Defaults": [], "User_Specs": []}`), 0600); err != nil {
		t.Fatalf("failed to write valid.json: %v", err)
	}
	if err := os.WriteFile(filepath.Join(jsonDir, "broken.json"), []byte(`{broken`), 0600); err != nil {
		t.Fatalf("failed to write broken.json: %v", err)
	}
	rootCmd.SetArgs([]string{"scan", jsonDir, "-f", "text", "--no-color"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("scan on JSON directory failed: %v", err)
	}

	// 3. Empty directory should return error
	resetFlags()
	emptyDir := t.TempDir()
	rootCmd.SetArgs([]string{"scan", emptyDir})
	if err := rootCmd.Execute(); err == nil {
		t.Fatal("expected error for empty directory")
	}

	// 4. Nonexistent path should return error
	resetFlags()
	rootCmd.SetArgs([]string{"scan", filepath.Join(emptyDir, "missing")})
	if err := rootCmd.Execute(); err == nil {
		t.Fatal("expected error for missing path")
	}
}

func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	origStderr := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create stderr pipe: %v", err)
	}
	os.Stderr = w
	defer func() {
		os.Stderr = origStderr
	}()

	fn()

	_ = w.Close()
	out, err := io.ReadAll(r)
	_ = r.Close()
	if err != nil {
		t.Fatalf("failed to read captured stderr: %v", err)
	}
	return string(out)
}

func TestScanCmd_MixedDirectoryWithNonPolicyJSON(t *testing.T) {
	resetFlags()
	dir := t.TempDir()

	// Non-policy JSON file (no root "sudoers" file present)
	if err := os.WriteFile(filepath.Join(dir, "metadata.json"), []byte(`{"hello":"world"}`), 0600); err != nil {
		t.Fatalf("failed to write metadata.json: %v", err)
	}
	// Valid JSON policy file
	validJSON := `{
		"Defaults": [{"Options": [{"env_reset": true}, {"secure_path": "/usr/bin"}, {"use_pty": true}, {"log_output": true}, {"umask": "0022"}, {"logfile": "/var/log/sudo.log"}]}],
		"User_Specs": [{
			"User_List": [{"username": "charlie"}],
			"Host_List": [{"hostname": "ALL"}],
			"Cmnd_Specs": [{"runasusers": [{"username": "root"}], "Commands": [{"command": "/usr/bin/less"}]}]
		}]
	}`
	if err := os.WriteFile(filepath.Join(dir, "valid_policy.json"), []byte(validJSON), 0600); err != nil {
		t.Fatalf("failed to write valid_policy.json: %v", err)
	}
	// Raw sudoers file that MUST NOT be dropped just because a .json file exists
	rawSudoers := `Defaults env_reset, use_pty, secure_path="/usr/bin", logfile="/var/log/sudo.log", log_output, umask=0022
alice ALL=(root) NOPASSWD: /usr/bin/vim
`
	if err := os.WriteFile(filepath.Join(dir, "app.sudoers"), []byte(rawSudoers), 0600); err != nil {
		t.Fatalf("failed to write app.sudoers: %v", err)
	}

	outDir := filepath.Join(t.TempDir(), "out")
	rootCmd.SetArgs([]string{"scan", dir, "-o", outDir, "-f", "json", "--no-color"})

	var execErr error
	stderrOut := captureStderr(t, func() {
		execErr = rootCmd.Execute()
	})
	if execErr != nil {
		t.Fatalf("scan on mixed directory failed: %v", execErr)
	}
	if !strings.Contains(stderrOut, "metadata.json") || !strings.Contains(stderrOut, "Warning:") {
		t.Errorf("expected warning on stderr for non-policy metadata.json, got:\n%s", stderrOut)
	}

	rawReport, err := os.ReadFile(filepath.Join(outDir, "report.json"))
	if err != nil {
		t.Fatalf("failed to read report.json: %v", err)
	}
	var res audit.AuditResult
	if err := json.Unmarshal(rawReport, &res); err != nil {
		t.Fatalf("failed to unmarshal report.json: %v", err)
	}
	if res.Hostname != "" {
		t.Errorf("expected offline scan hostname to be empty, got %q", res.Hostname)
	}

	foundAlice := false
	foundCharlie := false
	for _, f := range res.PolicyFindings {
		if strings.Contains(f.Context, "metadata.json") {
			t.Errorf("unexpected finding emitted for non-policy JSON file metadata.json: %+v", f)
		}
		if f.User == "alice" && strings.Contains(f.Context, "app.sudoers") {
			foundAlice = true
		}
		if f.User == "charlie" && strings.Contains(f.Context, "valid_policy.json") {
			foundCharlie = true
		}
	}
	if !foundAlice {
		t.Errorf("expected raw app.sudoers findings for user 'alice' not to be dropped in mixed directory; got findings: %+v", res.PolicyFindings)
	}
	if !foundCharlie {
		t.Errorf("expected valid_policy.json findings for user 'charlie' in mixed directory; got findings: %+v", res.PolicyFindings)
	}
}

func TestScanCmd_SingleNonPolicyJSONReturnsError(t *testing.T) {
	resetFlags()
	dir := t.TempDir()
	badJSONPath := filepath.Join(dir, "not_policy.json")
	if err := os.WriteFile(badJSONPath, []byte(`{"foo":"bar"}`), 0600); err != nil {
		t.Fatalf("failed to write not_policy.json: %v", err)
	}

	rootCmd.SetArgs([]string{"scan", badJSONPath, "-f", "text", "--no-color"})
	err := rootCmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "invalid JSON policy") {
		t.Fatalf("expected error containing 'invalid JSON policy', got: %v", err)
	}
}

func TestScanCmd_SkipsDocumentationFilesInDirectory(t *testing.T) {
	resetFlags()
	dir := t.TempDir()

	docFiles := []string{"README", "LICENSE", "NOTICE", "CHANGELOG", "Makefile", "Dockerfile"}
	for _, name := range docFiles {
		content := "# " + name + " documentation file\n"
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0600); err != nil {
			t.Fatalf("failed to write %s: %v", name, err)
		}
	}
	dropinContent := `Defaults env_reset, use_pty, secure_path="/usr/bin", logfile="/var/log/sudo.log", log_output, umask=0022
ops ALL=(root) /usr/bin/vim
`
	if err := os.WriteFile(filepath.Join(dir, "10-ops"), []byte(dropinContent), 0600); err != nil {
		t.Fatalf("failed to write 10-ops: %v", err)
	}

	outDir := filepath.Join(t.TempDir(), "out")
	rootCmd.SetArgs([]string{"scan", dir, "-o", outDir, "-f", "json", "--no-color"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("scan on directory with README failed: %v", err)
	}

	rawReport, err := os.ReadFile(filepath.Join(outDir, "report.json"))
	if err != nil {
		t.Fatalf("failed to read report.json: %v", err)
	}
	var res audit.AuditResult
	if err := json.Unmarshal(rawReport, &res); err != nil {
		t.Fatalf("failed to unmarshal report.json: %v", err)
	}

	foundOps := false
	for _, f := range res.PolicyFindings {
		base := filepath.Base(filepath.FromSlash(f.Context))
		if isIgnoredDocFile(base) {
			t.Errorf("expected documentation file %q to be skipped, but got finding: %+v", base, f)
		}
		if f.User == "ops" && strings.Contains(f.Context, "10-ops") {
			foundOps = true
		}
	}
	if !foundOps {
		t.Errorf("expected findings for drop-in 10-ops, got: %+v", res.PolicyFindings)
	}
}

func TestScanCmd_OfflineReportOmitsHostname(t *testing.T) {
	resetFlags()
	dir := t.TempDir()
	sudoersPath := filepath.Join(dir, "sudoers")
	if err := os.WriteFile(sudoersPath, []byte("alice ALL=(root) /usr/bin/id\n"), 0600); err != nil {
		t.Fatalf("failed to write sudoers: %v", err)
	}

	outDir := filepath.Join(t.TempDir(), "out")
	rootCmd.SetArgs([]string{"scan", sudoersPath, "-o", outDir, "-f", "json", "--no-color"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	rawReport, err := os.ReadFile(filepath.Join(outDir, "report.json"))
	if err != nil {
		t.Fatalf("failed to read report.json: %v", err)
	}
	if strings.Contains(string(rawReport), `"hostname"`) {
		t.Errorf("expected offline scan report.json to omit hostname field, got:\n%s", string(rawReport))
	}
	var res audit.AuditResult
	if err := json.Unmarshal(rawReport, &res); err != nil {
		t.Fatalf("failed to unmarshal report.json: %v", err)
	}
	if res.Hostname != "" {
		t.Errorf("expected result.Hostname == \"\", got %q", res.Hostname)
	}
}

func TestIsUntrustedSudoBinary(t *testing.T) {
	tests := []struct {
		name     string
		findings []audit.Finding
		want     bool
	}{
		{
			name:     "empty findings",
			findings: nil,
			want:     false,
		},
		{
			name:     "unable to access binary only",
			findings: []audit.Finding{{ID: "SUDO-SYS-PERM-006"}},
			want:     false,
		},
		{
			name:     "missing SUID bit only",
			findings: []audit.Finding{{ID: "SUDO-SYS-PERM-007"}},
			want:     false,
		},
		{
			name:     "group writable binary",
			findings: []audit.Finding{{ID: "SUDO-SYS-PERM-008"}},
			want:     true,
		},
		{
			name:     "world writable binary",
			findings: []audit.Finding{{ID: "SUDO-SYS-PERM-009"}},
			want:     true,
		},
		{
			name:     "non-root owned binary",
			findings: []audit.Finding{{ID: "SUDO-SYS-PERM-010"}},
			want:     true,
		},
		{
			name: "missing SUID combined with world writable",
			findings: []audit.Finding{
				{ID: "SUDO-SYS-PERM-007"},
				{ID: "SUDO-SYS-PERM-009"},
			},
			want: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := isUntrustedSudoBinary(tc.findings); got != tc.want {
				t.Errorf("isUntrustedSudoBinary(%+v) = %v, want %v", tc.findings, got, tc.want)
			}
		})
	}
}

func TestParseSudoVersionOutput(t *testing.T) {
	tests := []struct {
		name         string
		output       string
		wantVersion  string
		wantIsSudoRS bool
	}{
		{
			name:         "classic sudo with patchlevel",
			output:       "Sudo version 1.9.15p5\nSudoers policy plugin version 1.9.15p5\n",
			wantVersion:  "1.9.15p5",
			wantIsSudoRS: false,
		},
		{
			name:         "classic sudo without patchlevel",
			output:       "Sudo version 1.9.12\n",
			wantVersion:  "1.9.12",
			wantIsSudoRS: false,
		},
		{
			name:         "sudo-rs release",
			output:       "sudo-rs 0.2.3\n",
			wantVersion:  "sudo-rs 0.2.3",
			wantIsSudoRS: true,
		},
		{
			name:         "sudo-rs prerelease",
			output:       "sudo-rs 0.2.3-rc.1\n",
			wantVersion:  "sudo-rs 0.2.3-rc.1",
			wantIsSudoRS: true,
		},
		{
			name:         "empty output",
			output:       "",
			wantVersion:  "",
			wantIsSudoRS: false,
		},
		{
			name:         "unrecognized output",
			output:       "custom-sudo-wrapper 42\n",
			wantVersion:  "",
			wantIsSudoRS: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotVer, gotRS := parseSudoVersionOutput(tc.output)
			if gotVer != tc.wantVersion || gotRS != tc.wantIsSudoRS {
				t.Errorf("parseSudoVersionOutput(%q) = (%q, %v), want (%q, %v)", tc.output, gotVer, gotRS, tc.wantVersion, tc.wantIsSudoRS)
			}
		})
	}
}

func TestCollectAdditionalIncludedFiles(t *testing.T) {
	baseDir := t.TempDir()
	sudoersPath := filepath.Join(baseDir, "sudoers")
	sudoersDir := filepath.Join(baseDir, "sudoers.d")
	localInclude := filepath.Join(baseDir, "sudoers.local")
	dropinStandard := filepath.Join(sudoersDir, "10-admin")
	dropinDotted := filepath.Join(sudoersDir, "custom.conf")
	dropinNested := filepath.Join(sudoersDir, "nested", "app")
	customDirFile := filepath.Join(baseDir, "corp", "sudoers.d", "app")

	included := []string{
		filepath.ToSlash(sudoersPath),
		filepath.ToSlash(dropinStandard),
		filepath.ToSlash(dropinDotted),
		filepath.ToSlash(dropinNested),
		filepath.ToSlash(localInclude),
		filepath.ToSlash(localInclude), // duplicate
		filepath.ToSlash(customDirFile),
		"",
	}

	got := collectAdditionalIncludedFiles(sudoersPath, sudoersDir, included)
	want := []string{
		filepath.Clean(dropinDotted),
		filepath.Clean(dropinNested),
		filepath.Clean(localInclude),
		filepath.Clean(customDirFile),
	}

	if len(got) != len(want) {
		t.Fatalf("collectAdditionalIncludedFiles() returned %d items (%v), want %d (%v)", len(got), got, len(want), want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("item[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestIsPermissionError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "nil error", err: nil, want: false},
		{name: "os.ErrPermission", err: os.ErrPermission, want: true},
		{name: "permission denied text", err: errors.New("open /etc/sudoers: permission denied"), want: true},
		{name: "unable to open text", err: errors.New("cvtsudoers: unable to open /etc/sudoers"), want: true},
		{name: "syntax error", err: errors.New("sudoers:1: syntax error"), want: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := isPermissionError(tc.err); got != tc.want {
				t.Errorf("isPermissionError(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

func TestSystemCmd_CustomCvtsudoersPathNotFound(t *testing.T) {
	resetFlags()
	dir := t.TempDir()
	sudoersPath := filepath.Join(dir, "sudoers")
	if err := os.WriteFile(sudoersPath, []byte("root ALL=(ALL:ALL) ALL\n"), 0440); err != nil {
		t.Fatalf("failed to write sudoers: %v", err)
	}

	rootCmd.SetArgs([]string{
		"system",
		"--sudoers-file", sudoersPath,
		"--cvtsudoers-path", filepath.Join(dir, "nonexistent-cvtsudoers"),
	})
	err := rootCmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "custom cvtsudoers path not found") {
		t.Fatalf("expected custom cvtsudoers path error, got: %v", err)
	}
}

func TestSystemCmd_NativeParserFallback(t *testing.T) {
	resetFlags()
	dir := t.TempDir()
	sudoersPath := filepath.Join(dir, "sudoers")
	sudoersDir := filepath.Join(dir, "sudoers.d")
	if err := os.MkdirAll(sudoersDir, 0750); err != nil {
		t.Fatalf("failed to create sudoers.d: %v", err)
	}
	localIncludePath := filepath.Join(dir, "sudoers.local")
	if err := os.WriteFile(localIncludePath, []byte("deploy ALL=(root) NOPASSWD: /usr/bin/vim\n"), 0440); err != nil {
		t.Fatalf("failed to write sudoers.local: %v", err)
	}
	content := `Defaults env_reset, use_pty, secure_path="/usr/sbin:/usr/bin:/sbin:/bin"
Defaults logfile="/var/log/sudo.log", log_output, umask=0022
root ALL=(ALL:ALL) ALL
#include sudoers.local
`
	if err := os.WriteFile(sudoersPath, []byte(content), 0440); err != nil {
		t.Fatalf("failed to write sudoers: %v", err)
	}

	t.Setenv("PATH", dir)

	outDir := filepath.Join(dir, "sys-reports")
	rootCmd.SetArgs([]string{
		"system",
		"--sudoers-file", sudoersPath,
		"-o", outDir,
		"-f", "json,text",
		"--no-color",
	})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("system command with native parser fallback failed: %v", err)
	}

	reportPath := filepath.Join(outDir, "report.json")
	rawReport, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatalf("expected system report.json to be created: %v", err)
	}
	var res audit.AuditResult
	if err := json.Unmarshal(rawReport, &res); err != nil {
		t.Fatalf("failed to unmarshal system report.json: %v", err)
	}
	foundIncluded := false
	for _, f := range res.PolicyFindings {
		if f.User == "deploy" && strings.Contains(f.Context, "sudoers.local") && f.Line == 1 {
			foundIncluded = true
			break
		}
	}
	if !foundIncluded {
		t.Errorf("expected custom #include file sudoers.local finding to be tracked with exact file/line, got: %+v", res.PolicyFindings)
	}
	if expectedHost, err := os.Hostname(); err == nil && expectedHost != "" && res.Hostname != expectedHost {
		t.Errorf("expected system report hostname %q, got %q", expectedHost, res.Hostname)
	}
}

func TestUpdateDbCmd(t *testing.T) {
	// 1. Valid response
	resetFlags()
	validPayload := `{"executables": {"vim": {"functions": {"shell": [{"code": "vim -c ':!/bin/sh'", "contexts": {"sudo": {}}}]}}}}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(validPayload))
	}))
	defer srv.Close()

	gtfoBinsDownloadURL = srv.URL
	outFile := filepath.Join(t.TempDir(), "gtfobins.json")
	rootCmd.SetArgs([]string{"update-db", "-p", outFile})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("update-db failed on valid server response: %v", err)
	}
	if _, err := os.Stat(outFile); err != nil {
		t.Errorf("expected updated database file at %s: %v", outFile, err)
	}

	// Also verify scanning with custom --gtfobins-path pointing to the downloaded file
	policyFile := filepath.Join(t.TempDir(), "policy.json")
	_ = os.WriteFile(policyFile, []byte(`{"Defaults": [], "User_Specs": []}`), 0600)
	resetFlags()
	rootCmd.SetArgs([]string{"scan", policyFile, "--gtfobins-path", outFile, "-f", "text", "--no-color"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("scan with custom --gtfobins-path failed: %v", err)
	}

	// 2. Non-200 status
	resetFlags()
	errSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer errSrv.Close()
	gtfoBinsDownloadURL = errSrv.URL
	rootCmd.SetArgs([]string{"update-db", "-p", outFile})
	if err := rootCmd.Execute(); err == nil {
		t.Fatal("expected error for HTTP 500 response")
	}

	// 3. Empty executables map
	resetFlags()
	emptySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"executables": {}}`))
	}))
	defer emptySrv.Close()
	gtfoBinsDownloadURL = emptySrv.URL
	rootCmd.SetArgs([]string{"update-db", "-p", outFile})
	if err := rootCmd.Execute(); err == nil {
		t.Fatal("expected error for empty executables database")
	}
}

func TestScanRealWorldCorpusAllReportFormats(t *testing.T) {
	corpusCategories := []string{"distros", "upstream_regress", "enterprise_cloud"}
	for _, cat := range corpusCategories {
		cat := cat
		t.Run(cat, func(t *testing.T) {
			resetFlags()
			corpusDir := filepath.Join("..", "testdata", "corpus", cat)
			outDir := filepath.Join(t.TempDir(), "reports-"+cat)
			rootCmd.SetArgs([]string{
				"scan",
				corpusDir,
				"-o", outDir,
				"-f", "text,json,sarif,html,pdf",
				"--no-color",
			})
			if err := rootCmd.Execute(); err != nil {
				t.Fatalf("scan failed on corpus category %s: %v", cat, err)
			}

			expectedFiles := []string{
				"report.txt",
				"report.json",
				"report.sarif",
				"report.html",
				"report.pdf",
			}
			for _, f := range expectedFiles {
				info, err := os.Stat(filepath.Join(outDir, f))
				if err != nil {
					t.Errorf("expected report %s for %s: %v", f, cat, err)
				} else if info.Size() == 0 {
					t.Errorf("expected non-empty report %s for %s", f, cat)
				}
			}
		})
	}
}

func readReportJSON(t *testing.T, reportPath string) audit.AuditResult {
	t.Helper()
	raw, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatalf("failed to read %s: %v", reportPath, err)
	}
	var res audit.AuditResult
	if err := json.Unmarshal(raw, &res); err != nil {
		t.Fatalf("failed to unmarshal %s: %v", reportPath, err)
	}
	return res
}

func hasFindingID(findings []audit.Finding, id string) bool {
	for _, f := range findings {
		if f.ID == id {
			return true
		}
	}
	return false
}

func TestScanCmd_Stdin(t *testing.T) {
	t.Run("RawSudoers", func(t *testing.T) {
		resetFlags()
		outDir := filepath.Join(t.TempDir(), "out")
		rootCmd.SetIn(strings.NewReader("deploy ALL=(root) NOPASSWD: /usr/bin/vim\n"))
		rootCmd.SetArgs([]string{"scan", "-", "-o", outDir, "-f", "json", "--no-color"})
		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("scan - (raw sudoers) failed: %v", err)
		}
		res := readReportJSON(t, filepath.Join(outDir, "report.json"))
		found := false
		for _, f := range res.PolicyFindings {
			if f.User == "deploy" && f.Context == "stdin" && f.ID == "SUDO-GTFO-002" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected SUDO-GTFO-002 with Context=stdin for deploy, got: %+v", res.PolicyFindings)
		}
	})

	t.Run("JSONPolicy", func(t *testing.T) {
		resetFlags()
		outDir := filepath.Join(t.TempDir(), "out")
		jsonInput := `{
			"Defaults": [{"Options": [{"env_reset": true}, {"use_pty": true}, {"secure_path": "/usr/bin"}, {"logfile": "/var/log/sudo.log"}, {"log_output": true}, {"umask": "0022"}]}],
			"User_Specs": [{
				"User_List": [{"username": "charlie"}],
				"Host_List": [{"hostname": "ALL"}],
				"Cmnd_Specs": [{"runasusers": [{"username": "root"}], "Commands": [{"command": "/usr/bin/less"}]}]
			}]
		}`
		rootCmd.SetIn(strings.NewReader(jsonInput))
		rootCmd.SetArgs([]string{"scan", "-", "-o", outDir, "-f", "json", "--no-color"})
		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("scan - (JSON policy) failed: %v", err)
		}
		res := readReportJSON(t, filepath.Join(outDir, "report.json"))
		found := false
		for _, f := range res.PolicyFindings {
			if f.User == "charlie" && f.ID == "SUDO-GTFO-001" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected SUDO-GTFO-001 for charlie from JSON stdin, got: %+v", res.PolicyFindings)
		}
	})

	t.Run("LDIFPolicy", func(t *testing.T) {
		resetFlags()
		outDir := filepath.Join(t.TempDir(), "out")
		ldifInput := "dn: cn=ops,ou=SUDOers,dc=example,dc=com\nobjectClass: top\nobjectClass: sudoRole\ncn: ops\nsudoUser: alice\nsudoHost: ALL\nsudoRunAsUser: root\nsudoCommand: /usr/bin/find\n"
		rootCmd.SetIn(strings.NewReader(ldifInput))
		rootCmd.SetArgs([]string{"scan", "-", "-o", outDir, "-f", "json", "--no-color"})
		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("scan - (LDIF policy) failed: %v", err)
		}
		res := readReportJSON(t, filepath.Join(outDir, "report.json"))
		found := false
		for _, f := range res.PolicyFindings {
			if f.User == "alice" && strings.Contains(f.Command, "find") && f.ID == "SUDO-GTFO-001" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected SUDO-GTFO-001 for alice from LDIF stdin, got: %+v", res.PolicyFindings)
		}
	})
}

func TestScanCmd_DropInMode(t *testing.T) {
	dir := t.TempDir()
	dropinPath := filepath.Join(dir, "10-deploy")
	content := "deploy ALL=(root) NOPASSWD: /usr/bin/vim\nalice ALL=(root) /bin/cat\nalice ALL=(root) NOPASSWD: /bin/cat\n"
	if err := os.WriteFile(dropinPath, []byte(content), 0600); err != nil {
		t.Fatalf("failed to write dropin: %v", err)
	}

	// Default mode includes missing global Defaults and shadowing.
	resetFlags()
	defaultOut := filepath.Join(dir, "default-out")
	rootCmd.SetArgs([]string{"scan", dropinPath, "-o", defaultOut, "-f", "json", "--no-color"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("default scan failed: %v", err)
	}
	defaultRes := readReportJSON(t, filepath.Join(defaultOut, "report.json"))
	if !hasFindingID(defaultRes.PolicyFindings, "SUDO-DEF-001") || !hasFindingID(defaultRes.PolicyFindings, "SUDO-DEF-003") {
		t.Fatalf("expected missing global defaults in non-dropin mode, got: %+v", defaultRes.PolicyFindings)
	}
	if !hasFindingID(defaultRes.PolicyFindings, "SUDO-CMD-015") {
		t.Fatalf("expected SUDO-CMD-015 in default mode, got: %+v", defaultRes.PolicyFindings)
	}

	// Drop-in mode suppresses global missing defaults and defaults --check-shadowing to false.
	resetFlags()
	dropinOut := filepath.Join(dir, "dropin-out")
	rootCmd.SetArgs([]string{"scan", dropinPath, "--dropin", "-o", dropinOut, "-f", "json", "--no-color"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("dropin scan failed: %v", err)
	}
	dropinRes := readReportJSON(t, filepath.Join(dropinOut, "report.json"))
	for _, f := range dropinRes.PolicyFindings {
		if audit.GlobalMissingDefaultRuleIDs[f.ID] {
			t.Errorf("expected global missing default rule %s to be suppressed in --dropin mode", f.ID)
		}
		if f.ID == "SUDO-CMD-015" {
			t.Errorf("expected SUDO-CMD-015 to default to disabled in --dropin mode")
		}
	}
	if !hasFindingID(dropinRes.PolicyFindings, "SUDO-GTFO-002") {
		t.Errorf("expected risky command SUDO-GTFO-002 to remain detected in --dropin mode, got: %+v", dropinRes.PolicyFindings)
	}

	// Drop-in mode with explicit --check-shadowing=true still emits SUDO-CMD-015.
	resetFlags()
	dropinShadowOut := filepath.Join(dir, "dropin-shadow-out")
	rootCmd.SetArgs([]string{"scan", dropinPath, "--dropin", "--check-shadowing=true", "-o", dropinShadowOut, "-f", "json", "--no-color"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("dropin scan with explicit --check-shadowing=true failed: %v", err)
	}
	dropinShadowRes := readReportJSON(t, filepath.Join(dropinShadowOut, "report.json"))
	if !hasFindingID(dropinShadowRes.PolicyFindings, "SUDO-CMD-015") {
		t.Errorf("expected SUDO-CMD-015 when --check-shadowing=true is explicitly passed with --dropin")
	}
}

func TestScanCmd_ConfigYAMLAndJSON(t *testing.T) {
	dir := t.TempDir()
	sudoersPath := filepath.Join(dir, "sudoers")
	rawSudoers := `Defaults env_reset, use_pty, secure_path="/usr/bin", logfile="/var/log/sudo.log", log_output, umask=0022
deploy ALL=(root) NOPASSWD: /usr/bin/vim
bob ALL=(root) /usr/bin/less
`
	if err := os.WriteFile(sudoersPath, []byte(rawSudoers), 0600); err != nil {
		t.Fatalf("failed to write sudoers: %v", err)
	}

	// 1. YAML config: disable_rules, severity_overrides, active + expired suppression
	resetFlags()
	yamlCfgPath := filepath.Join(dir, ".sudo-check.yaml")
	yamlCfg := `disable_rules:
  - SUDO-DEF-007
severity_overrides:
  SUDO-GTFO-002: LOW
suppressions:
  - rule: SUDO-GTFO-001
    user: bob
    reason: Approved pager access
    expires: 2099-01-01
  - rule: SUDO-DEF-008
    reason: Temporary TTY exemption
    expires: 2020-01-01
`
	if err := os.WriteFile(yamlCfgPath, []byte(yamlCfg), 0600); err != nil {
		t.Fatalf("failed to write .sudo-check.yaml: %v", err)
	}
	yamlOut := filepath.Join(dir, "yaml-out")
	rootCmd.SetArgs([]string{"scan", sudoersPath, "--config", yamlCfgPath, "-o", yamlOut, "-f", "json", "--no-color"})
	var execErr error
	stderrOut := captureStderr(t, func() {
		execErr = rootCmd.Execute()
	})
	if execErr != nil {
		t.Fatalf("scan with YAML config failed: %v", execErr)
	}
	if !strings.Contains(stderrOut, `Warning: suppression for rule "SUDO-DEF-008" expired on 2020-01-01 (Temporary TTY exemption) and was not applied`) {
		t.Errorf("expected expired suppression warning on stderr, got:\n%s", stderrOut)
	}
	yamlRes := readReportJSON(t, filepath.Join(yamlOut, "report.json"))
	if hasFindingID(yamlRes.PolicyFindings, "SUDO-DEF-007") {
		t.Errorf("expected SUDO-DEF-007 to be disabled by YAML config")
	}
	if !hasFindingID(yamlRes.PolicyFindings, "SUDO-DEF-008") {
		t.Errorf("expected SUDO-DEF-008 not to be suppressed because its suppression expired")
	}
	foundOverridden := false
	for _, f := range yamlRes.PolicyFindings {
		if f.ID == "SUDO-GTFO-001" && f.User == "bob" {
			t.Errorf("expected SUDO-GTFO-001 for bob to be actively suppressed, got: %+v", f)
		}
		if f.ID == "SUDO-GTFO-002" && f.User == "deploy" {
			if f.Severity != audit.SeverityLow {
				t.Errorf("expected SUDO-GTFO-002 severity overridden to LOW, got %s", f.Severity)
			}
			foundOverridden = true
		}
	}
	if !foundOverridden {
		t.Errorf("expected SUDO-GTFO-002 finding for deploy, got: %+v", yamlRes.PolicyFindings)
	}

	// 2. JSON config
	resetFlags()
	jsonCfgPath := filepath.Join(dir, ".sudo-check.json")
	jsonCfg := `{
  "disable_rules": ["SUDO-DEF-008"],
  "severity_overrides": {"SUDO-CMD-007": "LOW"},
  "suppressions": [
    {
      "rule": "SUDO-GTFO-002",
      "user": "deploy",
      "reason": "Legacy automation ticket SEC-99",
      "expires": "2099-12-31T23:59:59Z"
    }
  ]
}`
	if err := os.WriteFile(jsonCfgPath, []byte(jsonCfg), 0600); err != nil {
		t.Fatalf("failed to write .sudo-check.json: %v", err)
	}
	jsonOut := filepath.Join(dir, "json-out")
	rootCmd.SetArgs([]string{"scan", sudoersPath, "--config", jsonCfgPath, "-o", jsonOut, "-f", "json", "--no-color"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("scan with JSON config failed: %v", err)
	}
	jsonRes := readReportJSON(t, filepath.Join(jsonOut, "report.json"))
	if hasFindingID(jsonRes.PolicyFindings, "SUDO-DEF-008") {
		t.Errorf("expected SUDO-DEF-008 to be disabled by JSON config")
	}
	if hasFindingID(jsonRes.PolicyFindings, "SUDO-GTFO-002") {
		t.Errorf("expected SUDO-GTFO-002 to be suppressed by JSON config")
	}
	foundOverrideCMD007 := false
	for _, f := range jsonRes.PolicyFindings {
		if f.ID == "SUDO-CMD-007" {
			if f.Severity != audit.SeverityLow {
				t.Errorf("expected SUDO-CMD-007 severity overridden to LOW, got %s", f.Severity)
			}
			foundOverrideCMD007 = true
		}
	}
	if !foundOverrideCMD007 {
		t.Errorf("expected SUDO-CMD-007 finding in JSON config scan, got: %+v", jsonRes.PolicyFindings)
	}
}

func TestScanCmd_Profile(t *testing.T) {
	dir := t.TempDir()
	sudoersPath := filepath.Join(dir, "sudoers")
	// Missing Defaults triggers SUDO-DEF-001 (in minimal, not anssi-bp028),
	// SUDO-DEF-003 (in anssi-bp028, not minimal), and SUDO-GTFO-002 (in both).
	if err := os.WriteFile(sudoersPath, []byte("deploy ALL=(root) NOPASSWD: /usr/bin/vim\n"), 0600); err != nil {
		t.Fatalf("failed to write sudoers: %v", err)
	}

	resetFlags()
	minimalOut := filepath.Join(dir, "minimal-out")
	rootCmd.SetArgs([]string{"scan", sudoersPath, "--profile", "minimal", "-o", minimalOut, "-f", "json", "--no-color"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("scan --profile minimal failed: %v", err)
	}
	minimalRes := readReportJSON(t, filepath.Join(minimalOut, "report.json"))
	if !hasFindingID(minimalRes.PolicyFindings, "SUDO-DEF-001") || !hasFindingID(minimalRes.PolicyFindings, "SUDO-GTFO-002") {
		t.Errorf("expected SUDO-DEF-001 and SUDO-GTFO-002 under minimal profile, got: %+v", minimalRes.PolicyFindings)
	}
	if hasFindingID(minimalRes.PolicyFindings, "SUDO-DEF-003") {
		t.Errorf("expected SUDO-DEF-003 to be excluded under minimal profile")
	}

	resetFlags()
	anssiOut := filepath.Join(dir, "anssi-out")
	rootCmd.SetArgs([]string{"scan", sudoersPath, "--profile", "anssi-bp028", "-o", anssiOut, "-f", "json", "--no-color"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("scan --profile anssi-bp028 failed: %v", err)
	}
	anssiRes := readReportJSON(t, filepath.Join(anssiOut, "report.json"))
	if !hasFindingID(anssiRes.PolicyFindings, "SUDO-DEF-003") || !hasFindingID(anssiRes.PolicyFindings, "SUDO-GTFO-002") {
		t.Errorf("expected SUDO-DEF-003 and SUDO-GTFO-002 under anssi-bp028 profile, got: %+v", anssiRes.PolicyFindings)
	}
	if hasFindingID(anssiRes.PolicyFindings, "SUDO-DEF-001") {
		t.Errorf("expected SUDO-DEF-001 to be excluded under anssi-bp028 profile")
	}

	resetFlags()
	rootCmd.SetArgs([]string{"scan", sudoersPath, "--profile", "unknown-profile"})
	if err := rootCmd.Execute(); err == nil || !strings.Contains(err.Error(), "invalid profile") {
		t.Fatalf("expected invalid profile error, got: %v", err)
	}
}

func TestScanCmd_Baseline(t *testing.T) {
	dir := t.TempDir()
	sudoersV1 := filepath.Join(dir, "sudoers")
	baseContent := `Defaults env_reset, use_pty, secure_path="/usr/bin", logfile="/var/log/sudo.log", log_output, umask=0022
alice ALL=(root) NOPASSWD: /usr/bin/vim
`
	if err := os.WriteFile(sudoersV1, []byte(baseContent), 0600); err != nil {
		t.Fatalf("failed to write baseline sudoers: %v", err)
	}

	resetFlags()
	baseOut := filepath.Join(dir, "base-out")
	rootCmd.SetArgs([]string{"scan", sudoersV1, "-o", baseOut, "-f", "json", "--no-color"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("baseline scan failed: %v", err)
	}
	baselineFile := filepath.Join(baseOut, "report.json")

	// Unchanged policy against baseline should pass --fail-on HIGH.
	resetFlags()
	unchangedOut := filepath.Join(dir, "unchanged-out")
	rootCmd.SetArgs([]string{"scan", sudoersV1, "--baseline", baselineFile, "--fail-on", "HIGH", "-o", unchangedOut, "-f", "json", "--no-color"})
	var execErr error
	stderrUnchanged := captureStderr(t, func() {
		execErr = rootCmd.Execute()
	})
	if execErr != nil {
		t.Fatalf("expected nil error when no new findings added over baseline, got: %v", execErr)
	}
	if !strings.Contains(stderrUnchanged, "Baseline diff: 0 added, 0 resolved,") {
		t.Errorf("expected baseline diff summary with 0 added on stderr, got:\n%s", stderrUnchanged)
	}

	// Adding a new HIGH/CRITICAL finding should trigger ErrFailOnThreshold.
	sudoersV2 := filepath.Join(dir, "sudoers_v2")
	updatedContent := baseContent + "bob ALL=(root) NOPASSWD: /usr/bin/less\n"
	if err := os.WriteFile(sudoersV2, []byte(updatedContent), 0600); err != nil {
		t.Fatalf("failed to write sudoers_v2: %v", err)
	}
	resetFlags()
	addedOut := filepath.Join(dir, "added-out")
	rootCmd.SetArgs([]string{"scan", sudoersV2, "--baseline", baselineFile, "--fail-on", "HIGH", "-o", addedOut, "-f", "json", "--no-color"})
	stderrAdded := captureStderr(t, func() {
		execErr = rootCmd.Execute()
	})
	if !errors.Is(execErr, ErrFailOnThreshold) {
		t.Fatalf("expected ErrFailOnThreshold when new HIGH/CRITICAL finding added over baseline, got: %v", execErr)
	}
	if !strings.Contains(stderrAdded, "Baseline diff:") || strings.Contains(stderrAdded, "Baseline diff: 0 added,") {
		t.Errorf("expected non-zero added findings in baseline diff summary, got:\n%s", stderrAdded)
	}
}

func TestScanCmd_FixPatch(t *testing.T) {
	dir := t.TempDir()
	rawPath := filepath.Join(dir, "sudoers")
	if err := os.WriteFile(rawPath, []byte("alice ALL=(root) /usr/bin/id\n"), 0600); err != nil {
		t.Fatalf("failed to write sudoers: %v", err)
	}

	resetFlags()
	patchOut := filepath.Join(dir, "hardening.patch")
	outDir := filepath.Join(dir, "reports")
	rootCmd.SetArgs([]string{"scan", rawPath, "--fix-patch", patchOut, "-o", outDir, "-f", "json", "--no-color"})
	var execErr error
	stderrOut := captureStderr(t, func() {
		execErr = rootCmd.Execute()
	})
	if execErr != nil {
		t.Fatalf("scan with --fix-patch failed: %v", execErr)
	}
	if !strings.Contains(stderrOut, patchOut) {
		t.Errorf("expected stderr notice mentioning patch path %s, got:\n%s", patchOut, stderrOut)
	}
	patchBytes, err := os.ReadFile(patchOut)
	if err != nil {
		t.Fatalf("failed to read generated patch: %v", err)
	}
	patchText := string(patchBytes)
	if !strings.Contains(patchText, "--- a/") || !strings.Contains(patchText, "+++ b/") || !strings.Contains(patchText, "+Defaults env_reset") {
		t.Errorf("expected valid unified diff adding Defaults env_reset, got:\n%s", patchText)
	}

	// Reject directory input.
	resetFlags()
	subDir := filepath.Join(dir, "dir")
	if err := os.MkdirAll(subDir, 0750); err != nil {
		t.Fatalf("mkdir failed: %v", err)
	}
	if err := os.WriteFile(filepath.Join(subDir, "10-app"), []byte("alice ALL=(root) /usr/bin/id\n"), 0600); err != nil {
		t.Fatalf("write file failed: %v", err)
	}
	rootCmd.SetArgs([]string{"scan", subDir, "--fix-patch", filepath.Join(dir, "dir.patch"), "-f", "text", "--no-color"})
	if err := rootCmd.Execute(); err == nil || !strings.Contains(err.Error(), "--fix-patch") {
		t.Fatalf("expected explicit --fix-patch error for directory input, got: %v", err)
	}

	// Reject JSON policy input.
	resetFlags()
	jsonPath := filepath.Join(dir, "policy.json")
	if err := os.WriteFile(jsonPath, []byte(`{"Defaults": [], "User_Specs": []}`), 0600); err != nil {
		t.Fatalf("write policy.json failed: %v", err)
	}
	rootCmd.SetArgs([]string{"scan", jsonPath, "--fix-patch", filepath.Join(dir, "json.patch"), "-f", "text", "--no-color"})
	if err := rootCmd.Execute(); err == nil || !strings.Contains(err.Error(), "--fix-patch") {
		t.Fatalf("expected explicit --fix-patch error for JSON input, got: %v", err)
	}
}

func TestScanCmd_CustomGTFObins(t *testing.T) {
	dir := t.TempDir()
	sudoersPath := filepath.Join(dir, "sudoers")
	rawSudoers := `Defaults env_reset, use_pty, secure_path="/usr/bin", logfile="/var/log/sudo.log", log_output, umask=0022
alice ALL=(root) NOPASSWD: /usr/local/bin/corpctl
`
	if err := os.WriteFile(sudoersPath, []byte(rawSudoers), 0600); err != nil {
		t.Fatalf("failed to write sudoers: %v", err)
	}

	overlayPath := filepath.Join(dir, "custom-gtfobins.json")
	overlayJSON := `{
  "executables": {
    "corpctl": {
      "functions": {
        "shell": [
          {
            "code": "sudo corpctl --exec /bin/sh",
            "contexts": {"sudo": null}
          }
        ]
      }
    }
  }
}`
	if err := os.WriteFile(overlayPath, []byte(overlayJSON), 0600); err != nil {
		t.Fatalf("failed to write overlay json: %v", err)
	}

	// Without overlay, custom binary is not in embedded catalog.
	resetFlags()
	baseOut := filepath.Join(dir, "base-out")
	rootCmd.SetArgs([]string{"scan", sudoersPath, "-o", baseOut, "-f", "json", "--no-color"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("scan without custom overlay failed: %v", err)
	}
	baseRes := readReportJSON(t, filepath.Join(baseOut, "report.json"))
	if hasFindingID(baseRes.PolicyFindings, "SUDO-GTFO-002") {
		t.Errorf("did not expect SUDO-GTFO-002 without custom GTFObins overlay")
	}

	// With --custom-gtfobins overlay, custom binary is detected.
	resetFlags()
	overlayOut := filepath.Join(dir, "overlay-out")
	rootCmd.SetArgs([]string{"scan", sudoersPath, "--custom-gtfobins", overlayPath, "-o", overlayOut, "-f", "json", "--no-color"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("scan with --custom-gtfobins failed: %v", err)
	}
	overlayRes := readReportJSON(t, filepath.Join(overlayOut, "report.json"))
	foundCustom := false
	for _, f := range overlayRes.PolicyFindings {
		if f.ID == "SUDO-GTFO-002" && strings.Contains(f.Title, "corpctl") {
			foundCustom = true
			break
		}
	}
	if !foundCustom {
		t.Errorf("expected SUDO-GTFO-002 for custom binary corpctl, got: %+v", overlayRes.PolicyFindings)
	}
}

func TestScanCmd_SubcommandAware(t *testing.T) {
	dir := t.TempDir()
	sudoersPath := filepath.Join(dir, "sudoers")
	rawSudoers := `Defaults env_reset, use_pty, secure_path="/usr/bin", logfile="/var/log/sudo.log", log_output, umask=0022
deploy ALL=(root) /usr/bin/systemctl restart nginx
`
	if err := os.WriteFile(sudoersPath, []byte(rawSudoers), 0600); err != nil {
		t.Fatalf("failed to write sudoers: %v", err)
	}

	// Standard mode: HIGH severity, empty Exploitability.
	resetFlags()
	stdOut := filepath.Join(dir, "std-out")
	rootCmd.SetArgs([]string{"scan", sudoersPath, "-o", stdOut, "-f", "json", "--no-color"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("standard scan failed: %v", err)
	}
	stdRes := readReportJSON(t, filepath.Join(stdOut, "report.json"))
	var stdGTFO *audit.Finding
	for i := range stdRes.PolicyFindings {
		if stdRes.PolicyFindings[i].ID == "SUDO-GTFO-001" && strings.Contains(stdRes.PolicyFindings[i].Title, "systemctl") {
			stdGTFO = &stdRes.PolicyFindings[i]
			break
		}
	}
	if stdGTFO == nil || stdGTFO.Severity != audit.SeverityHigh || stdGTFO.Exploitability != "" {
		t.Fatalf("expected standard systemctl SUDO-GTFO-001 to be HIGH with empty Exploitability, got: %+v", stdGTFO)
	}

	// Subcommand-aware mode: downgraded to LOW / CONSTRAINED.
	resetFlags()
	awareOut := filepath.Join(dir, "aware-out")
	rootCmd.SetArgs([]string{"scan", sudoersPath, "--subcommand-aware", "-o", awareOut, "-f", "json", "--no-color"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("subcommand-aware scan failed: %v", err)
	}
	awareRes := readReportJSON(t, filepath.Join(awareOut, "report.json"))
	var awareGTFO *audit.Finding
	for i := range awareRes.PolicyFindings {
		if awareRes.PolicyFindings[i].ID == "SUDO-GTFO-001" && strings.Contains(awareRes.PolicyFindings[i].Title, "systemctl") {
			awareGTFO = &awareRes.PolicyFindings[i]
			break
		}
	}
	if awareGTFO == nil || awareGTFO.Severity != audit.SeverityLow || awareGTFO.Exploitability != "CONSTRAINED" {
		t.Fatalf("expected subcommand-aware systemctl SUDO-GTFO-001 to be LOW / CONSTRAINED, got: %+v", awareGTFO)
	}
}

func TestScanCmd_ShadowingAndExpiry(t *testing.T) {
	dir := t.TempDir()
	sudoersPath := filepath.Join(dir, "sudoers")
	rawSudoers := `Defaults env_reset, use_pty, secure_path="/usr/bin", logfile="/var/log/sudo.log", log_output, umask=0022
alice ALL=(root) /bin/cat
alice ALL=(root) NOPASSWD: /bin/cat
auditor ALL=(root) NOTBEFORE=20200101000000Z NOTAFTER=20210101000000Z /usr/bin/id
`
	if err := os.WriteFile(sudoersPath, []byte(rawSudoers), 0600); err != nil {
		t.Fatalf("failed to write sudoers: %v", err)
	}

	// Default: --check-shadowing=true, --check-expiry=false.
	resetFlags()
	defaultOut := filepath.Join(dir, "default-out")
	rootCmd.SetArgs([]string{"scan", sudoersPath, "-o", defaultOut, "-f", "json", "--no-color"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("default scan failed: %v", err)
	}
	defaultRes := readReportJSON(t, filepath.Join(defaultOut, "report.json"))
	if !hasFindingID(defaultRes.PolicyFindings, "SUDO-CMD-015") {
		t.Errorf("expected SUDO-CMD-015 by default, got: %+v", defaultRes.PolicyFindings)
	}
	if hasFindingID(defaultRes.PolicyFindings, "SUDO-CMD-016") {
		t.Errorf("did not expect SUDO-CMD-016 when --check-expiry is false")
	}

	// Explicit: --check-shadowing=false --check-expiry=true.
	resetFlags()
	expiryOut := filepath.Join(dir, "expiry-out")
	rootCmd.SetArgs([]string{"scan", sudoersPath, "--check-shadowing=false", "--check-expiry", "-o", expiryOut, "-f", "json", "--no-color"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("expiry scan failed: %v", err)
	}
	expiryRes := readReportJSON(t, filepath.Join(expiryOut, "report.json"))
	if hasFindingID(expiryRes.PolicyFindings, "SUDO-CMD-015") {
		t.Errorf("did not expect SUDO-CMD-015 when --check-shadowing=false")
	}
	if !hasFindingID(expiryRes.PolicyFindings, "SUDO-CMD-016") {
		t.Errorf("expected SUDO-CMD-016 when --check-expiry is enabled, got: %+v", expiryRes.PolicyFindings)
	}
}

func TestScanCmd_LDIFDirectory(t *testing.T) {
	resetFlags()
	dir := t.TempDir()
	ldifPath := filepath.Join(dir, "roles.ldif")
	ldifContent := "dn: cn=dbadmin,ou=SUDOers,dc=example,dc=com\nobjectClass: top\nobjectClass: sudoRole\ncn: dbadmin\nsudoUser: dbops\nsudoHost: ALL\nsudoRunAsUser: root\nsudoCommand: /usr/bin/vim\nsudoOption: !authenticate\n"
	if err := os.WriteFile(ldifPath, []byte(ldifContent), 0600); err != nil {
		t.Fatalf("failed to write roles.ldif: %v", err)
	}

	outDir := filepath.Join(t.TempDir(), "ldif-out")
	rootCmd.SetArgs([]string{"scan", dir, "-o", outDir, "-f", "json", "--no-color"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("scan on LDIF directory failed: %v", err)
	}
	res := readReportJSON(t, filepath.Join(outDir, "report.json"))
	found := false
	for _, f := range res.PolicyFindings {
		if f.User == "dbops" && f.ID == "SUDO-GTFO-002" && strings.Contains(f.Context, "roles.ldif") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected SUDO-GTFO-002 finding from roles.ldif in directory scan, got: %+v", res.PolicyFindings)
	}
}
