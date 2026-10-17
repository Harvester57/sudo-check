package gtfobins

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestClient_CheckBinary(t *testing.T) {
	client, err := NewClient()
	if err != nil {
		t.Fatalf("Failed to initialize client: %v", err)
	}

	tests := []struct {
		name        string
		binary      string
		expectMatch bool
		expectShell bool
	}{
		{"KnownBinary_Find", "find", true, true},
		{"KnownBinary_Vim", "vim", true, true},
		{"KnownBinary_Python", "python", true, true},
		{"KnownBinary_Awk", "awk", true, true},
		{"AliasResolution", "mawk", true, true},
		{"NonExistentBinary", "non-existent-binary-xyz", false, false},
		{"EmptyBinary", "   ", false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bypasses := client.CheckBinary(tt.binary)
			if tt.expectMatch && len(bypasses) == 0 {
				t.Errorf("Expected %s to have sudo bypasses, got none", tt.binary)
			}
			if !tt.expectMatch && len(bypasses) > 0 {
				t.Errorf("Expected %s to have no bypasses, got: %v", tt.binary, bypasses)
			}

			if tt.expectMatch && tt.expectShell {
				hasShell := false
				for _, b := range bypasses {
					if b.Function == "shell" {
						hasShell = true
						if b.Code == "" {
							t.Errorf("Expected shell bypass for %s to have a code command", tt.binary)
						}
					}
					if b.Function == "" || b.Code == "" {
						t.Errorf("Expected all bypasses to have non-empty Function and Code, got %v", b)
					}
				}
				if !hasShell {
					t.Errorf("Expected %s to have a 'shell' function bypass under sudo", tt.binary)
				}
			}
		})
	}
}

func TestClient_VersionedAndVariantBinaries(t *testing.T) {
	client, err := NewClient()
	if err != nil {
		t.Fatalf("Failed to initialize client: %v", err)
	}

	binaries := []struct {
		binary      string
		expectShell bool
	}{
		{"python3", true},
		{"python3.11", true},
		{"python2.7", true},
		{"php8.2", true},
		{"perl5.34", true},
		{"ruby3.0", true},
		{"ruby3.1", true},
		{"lua5.4", true},
		{"gcc-12", true},
		{"g++-12", true},
		{"pip3", true},
		{"node18", true},
		{"vim.basic", true},
		{"vim.tiny", true},
		{"vim.nox", true},
		{"vim.gtk3", true},
		{"nvim", true},
		{"neovim", true},
		{"rvim", true},
		{"rview", true},
		{"view", true},
		{"gawk", true},
		{"nawk", true},
		{"original-awk", true},
		{"nc.openbsd", false},
		{"nc.traditional", false},
		{"netcat", false},
		{"ncat", false},
		{"bat", true},
		{"egrep", false},
		{"fgrep", false},
		{"rgrep", false},
	}

	for _, tc := range binaries {
		t.Run(tc.binary, func(t *testing.T) {
			bypasses := client.CheckBinary(tc.binary)
			if len(bypasses) == 0 {
				t.Fatalf("Expected sudo bypasses for %s, got none", tc.binary)
			}
			if tc.expectShell {
				foundShell := false
				for _, b := range bypasses {
					if b.Function == "shell" {
						foundShell = true
						break
					}
				}
				if !foundShell {
					t.Errorf("Expected shell bypass for %s, got functions: %+v", tc.binary, bypasses)
				}
			}
		})
	}
}

func TestNormalizeBinaryName(t *testing.T) {
	if got := NormalizeBinaryName(""); got != nil {
		t.Errorf("Expected nil for empty string, got %v", got)
	}

	cases := []struct {
		input    string
		expected string
	}{
		{"python3.11", "python"},
		{"gcc-12", "gcc"},
		{"vim.basic", "vim"},
		{"nc.openbsd", "nc"},
		{"bat", "batcat"},
		{"g++-12", "gcc"},
		{"foo.custom", "foo"},
	}

	for _, tc := range cases {
		candidates := NormalizeBinaryName(tc.input)
		if len(candidates) == 0 || candidates[0] != tc.input {
			t.Errorf("Expected first candidate for %q to be %q, got %v", tc.input, tc.input, candidates)
		}
		found := false
		for _, c := range candidates {
			if c == tc.expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected %q in candidates for %q, got %v", tc.expected, tc.input, candidates)
		}
	}
}

func TestClient_InheritResolution(t *testing.T) {
	client, err := NewClient()
	if err != nil {
		t.Fatalf("Failed to initialize client: %v", err)
	}

	tests := []struct {
		binary         string
		expectedFrom   string
		expectFunction string
	}{
		{"vim", "python", "shell"},
		{"systemctl", "less", "file-read"},
		{"journalctl", "less", "shell"},
		{"git", "less", "command"},
		{"crontab", "vi", "shell"},
	}

	for _, tc := range tests {
		t.Run(tc.binary, func(t *testing.T) {
			bypasses := client.CheckBinary(tc.binary)
			if len(bypasses) == 0 {
				t.Fatalf("Expected bypasses for %s, got none", tc.binary)
			}

			foundFunc := false
			hasShell := false
			for _, b := range bypasses {
				if b.Function == "inherit" {
					t.Errorf("Expected 'inherit' function to be resolved into concrete functions for %s, not returned directly", tc.binary)
				}
				if b.Function == "shell" {
					hasShell = true
				}
				if b.Function == tc.expectFunction {
					foundFunc = true
					if b.InheritedFrom == "" {
						t.Errorf("Expected InheritedFrom to be populated for %s (%s)", tc.binary, b.Function)
					}
					if !strings.Contains(b.Comment, "Inherits") {
						t.Errorf("Expected Comment to mention inheritance for %s (%s), got %q", tc.binary, b.Function, b.Comment)
					}
					if b.Code == "" {
						t.Errorf("Expected non-empty Code for inherited bypass %s (%s)", tc.binary, b.Function)
					}
				}
			}

			if !hasShell {
				t.Errorf("Expected %s to have a 'shell' bypass (direct or inherited)", tc.binary)
			}
			if !foundFunc {
				t.Errorf("Expected %s to have function %q", tc.binary, tc.expectFunction)
			}
		})
	}
}

func TestClient_Consolidation(t *testing.T) {
	client, err := NewClient()
	if err != nil {
		t.Fatalf("Failed to initialize client: %v", err)
	}

	bypasses := client.CheckBinary("bash")
	if len(bypasses) == 0 {
		t.Fatalf("Expected bypasses for bash, got none")
	}

	seen := make(map[string]bool)
	for i, b := range bypasses {
		if seen[b.Function] {
			t.Errorf("Duplicate function %q in consolidated output for bash", b.Function)
		}
		seen[b.Function] = true

		if i > 0 && bypasses[i-1].Function > b.Function {
			t.Errorf("Expected bypasses to be sorted by Function name: %q > %q", bypasses[i-1].Function, b.Function)
		}

		// bash file-read has 2 techniques in GTFObins; verify they are joined with "\n\n"
		if b.Function == "file-read" {
			if !strings.Contains(b.Code, "\n\n") {
				t.Errorf("Expected consolidated file-read Code for bash to join multiple blocks with \\n\\n, got: %q", b.Code)
			}
			if b.Comment == "" {
				t.Errorf("Expected consolidated file-read Comment for bash to preserve non-empty comment")
			}
		}
	}
}

func TestClient_CustomSudoCodeAndCommentOverrides(t *testing.T) {
	tempDir := t.TempDir()
	tempFile := filepath.Join(tempDir, "gtfobins_custom.json")

	customJSON := `{
		"executables": {
			"custombin": {
				"functions": {
					"shell": [
						{
							"code": "default-code",
							"comment": "default-comment",
							"contexts": {
								"sudo": {
									"code": "sudo-override-code",
									"comment": "sudo-override-comment"
								}
							}
						},
						{
							"code": "second-sudo-code",
							"comment": "second-comment",
							"contexts": {
								"sudo": null
							}
						},
						{
							"code": "suid-only-code",
							"contexts": {
								"suid": null
							}
						}
					]
				}
			}
		}
	}`
	if err := os.WriteFile(tempFile, []byte(customJSON), 0644); err != nil {
		t.Fatalf("Failed to write temp file: %v", err)
	}

	client, err := NewClientFromFile(tempFile)
	if err != nil {
		t.Fatalf("NewClientFromFile failed: %v", err)
	}

	bypasses := client.CheckBinary("custombin")
	if len(bypasses) != 1 {
		t.Fatalf("Expected 1 consolidated bypass for custombin, got %d", len(bypasses))
	}

	b := bypasses[0]
	if b.Function != "shell" {
		t.Errorf("Expected function 'shell', got %q", b.Function)
	}
	expectedCode := "sudo-override-code\n\nsecond-sudo-code"
	if b.Code != expectedCode {
		t.Errorf("Expected Code %q, got %q", expectedCode, b.Code)
	}
	expectedComment := "sudo-override-comment\nsecond-comment"
	if b.Comment != expectedComment {
		t.Errorf("Expected Comment %q, got %q", expectedComment, b.Comment)
	}
}

func TestClient_CircularAliasAndInheritProtection(t *testing.T) {
	tempDir := t.TempDir()
	tempFile := filepath.Join(tempDir, "gtfobins_cycles.json")

	cycleJSON := `{
		"executables": {
			"alias_a": {
				"alias": "alias_b"
			},
			"alias_b": {
				"alias": "alias_a"
			},
			"alias_dangling": {
				"alias": "missing_target"
			},
			"alias_1": { "alias": "alias_2" },
			"alias_2": { "alias": "alias_3" },
			"alias_3": { "alias": "alias_4" },
			"alias_4": { "alias": "alias_5" },
			"alias_5": { "alias": "alias_6" },
			"alias_6": {
				"functions": {
					"shell": [{ "code": "sh", "contexts": { "sudo": null } }]
				}
			},
			"inherit_a": {
				"functions": {
					"inherit": [
						{
							"code": "inherit_a_cmd",
							"comment": "from b",
							"from": "inherit_b",
							"contexts": { "sudo": null }
						}
					]
				}
			},
			"inherit_b": {
				"functions": {
					"inherit": [
						{
							"code": "inherit_b_cmd",
							"from": "inherit_a",
							"contexts": { "sudo": null }
						},
						{
							"code": "empty_from",
							"from": "",
							"contexts": { "sudo": null }
						},
						{
							"code": "no_sudo",
							"from": "leaf_bin",
							"contexts": { "unprivileged": null }
						}
					],
					"shell": [
						{
							"code": "",
							"contexts": { "sudo": { "code": "inherit_b_shell" } }
						}
					]
				}
			},
			"leaf_bin": {
				"functions": {
					"shell": [
						{
							"code": "leaf_sh",
							"contexts": { "sudo": null }
						}
					]
				}
			}
		}
	}`
	if err := os.WriteFile(tempFile, []byte(cycleJSON), 0644); err != nil {
		t.Fatalf("Failed to write temp file: %v", err)
	}

	client, err := NewClientFromFile(tempFile)
	if err != nil {
		t.Fatalf("NewClientFromFile failed: %v", err)
	}

	if got := client.CheckBinary("alias_a"); got != nil {
		t.Errorf("Expected nil for circular alias_a, got %v", got)
	}
	if got := client.CheckBinary("alias_dangling"); got != nil {
		t.Errorf("Expected nil for dangling alias, got %v", got)
	}
	if got := client.CheckBinary("alias_1"); got != nil {
		t.Errorf("Expected nil when alias chain exceeds max depth, got %v", got)
	}

	bypasses := client.CheckBinary("inherit_a")
	if len(bypasses) != 1 {
		t.Fatalf("Expected 1 bypass from inherit_a (via inherit_b's shell without looping), got %v", bypasses)
	}
	if bypasses[0].Function != "shell" || bypasses[0].InheritedFrom != "inherit_b" {
		t.Errorf("Unexpected bypass for inherit_a: %+v", bypasses[0])
	}
}

func TestNewClientFromFile(t *testing.T) {
	tempDir := t.TempDir()
	tempFile := filepath.Join(tempDir, "gtfobins.json")

	// Create a minimal valid GTFObins JSON
	validJSON := `{
		"executables": {
			"mybin": {
				"functions": {
					"shell": [
						{
							"code": "mybin -c 'sh'",
							"contexts": {
								"sudo": null
							}
						}
					]
				}
			}
		}
	}`
	if err := os.WriteFile(tempFile, []byte(validJSON), 0644); err != nil {
		t.Fatalf("Failed to write temp file: %v", err)
	}

	client, err := NewClientFromFile(tempFile)
	if err != nil {
		t.Fatalf("NewClientFromFile failed: %v", err)
	}

	bypasses := client.CheckBinary("mybin")
	if len(bypasses) != 1 {
		t.Errorf("Expected 1 bypass for 'mybin', got %d", len(bypasses))
	} else if bypasses[0].Function != "shell" || bypasses[0].Code != "mybin -c 'sh'" {
		t.Errorf("Unexpected bypass content: %v", bypasses[0])
	}
}

func TestNewClient_MalformedJSON(t *testing.T) {
	tempDir := t.TempDir()
	tempFile := filepath.Join(tempDir, "gtfobins.json")

	malformedJSON := `{ "executables": { "bad": `
	if err := os.WriteFile(tempFile, []byte(malformedJSON), 0644); err != nil {
		t.Fatalf("Failed to write temp file: %v", err)
	}

	_, err := NewClientFromFile(tempFile)
	if err == nil {
		t.Errorf("Expected error when loading malformed JSON, got nil")
	}
}

func TestNewClientFromFile_NotFound(t *testing.T) {
	_, err := NewClientFromFile("non_existent_file.json")
	if err == nil {
		t.Errorf("Expected error when loading non-existent file, got nil")
	}
}
