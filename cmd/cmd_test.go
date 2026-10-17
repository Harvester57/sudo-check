package cmd

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func resetFlags() {
	outputDir = ""
	formats = "text"
	gtfoBinsPath = ""
	cvtSudoersPath = ""
	failOn = ""
	noColor = true
	sudoersFile = "/etc/sudoers"
	dbOutputPath = "gtfobins.json"
	gtfoBinsDownloadURL = gtfoBinsURL
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
				"Users": [{"username": "admin"}],
				"Hosts": [{"hostname": "ALL"}],
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

func TestSystemCmd_NativeParserFallback(t *testing.T) {
	resetFlags()
	dir := t.TempDir()
	sudoersPath := filepath.Join(dir, "sudoers")
	sudoersDir := filepath.Join(dir, "sudoers.d")
	if err := os.MkdirAll(sudoersDir, 0750); err != nil {
		t.Fatalf("failed to create sudoers.d: %v", err)
	}
	content := `Defaults env_reset, use_pty, secure_path="/usr/sbin:/usr/bin:/sbin:/bin"
Defaults logfile="/var/log/sudo.log", log_output, umask=0022
root ALL=(ALL:ALL) ALL
`
	if err := os.WriteFile(sudoersPath, []byte(content), 0440); err != nil {
		t.Fatalf("failed to write sudoers: %v", err)
	}

	origPath := os.Getenv("PATH")
	t.Setenv("PATH", dir)
	defer os.Setenv("PATH", origPath)

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
	if _, err := os.Stat(filepath.Join(outDir, "report.json")); err != nil {
		t.Errorf("expected system report.json to be created: %v", err)
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
