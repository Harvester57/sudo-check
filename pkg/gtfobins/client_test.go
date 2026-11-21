package gtfobins

import (
	"errors"
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
		{"awk.gnu", "awk"},
		{"tar.gnu", "tar"},
		{"awk.real", "awk"},
		{"gawk.gnu", "awk"},
		{"sh", "dash"},
		{"/bin/sh", "dash"},
		{"sh.static", "dash"},
		{"rbash", "bash"},
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

	excludedCases := []struct {
		input     string
		forbidden string
	}{
		{"tar.sh", "tar"},
		{"/usr/local/sbin/tar.sh", "tar"},
		{"find.sh", "find"},
		{"/usr/local/sbin/find.sh", "find"},
		{"docker.sh", "docker"},
		{"env.py", "env"},
		{"git.sh", "git"},
		{"mount.nfs", "mount"},
		{"mount.cifs", "mount"},
		{"mount.nfs4", "mount"},
		{"mount.fuse", "mount"},
		{"mkfs.ext4", "mkfs"},
		{"foo.custom", "foo"},
		{"tar.bash", "tar"},
		{"awk.pl", "awk"},
		{"ruby.rb", "ruby"},
		{"node.js", "node"},
	}

	for _, tc := range excludedCases {
		candidates := NormalizeBinaryName(tc.input)
		for _, c := range candidates {
			if c == tc.forbidden {
				t.Errorf("Did not expect %q in candidates for %q, got %v", tc.forbidden, tc.input, candidates)
			}
		}
	}
}

func TestClient_ShellVariantsAndNoFalsePositives(t *testing.T) {
	client, err := NewClient()
	if err != nil {
		t.Fatalf("Failed to initialize client: %v", err)
	}

	shellBinaries := []string{
		"sh",
		"/bin/sh",
		"/usr/bin/sh",
		"rbash",
		"/bin/rbash",
		"dash",
		"ash",
		"tar.gnu",
		"awk.real",
	}

	for _, bin := range shellBinaries {
		t.Run("Match_"+bin, func(t *testing.T) {
			bypasses := client.CheckBinary(bin)
			if len(bypasses) == 0 {
				t.Fatalf("Expected sudo bypasses for %s, got none", bin)
			}
			hasShell := false
			for _, b := range bypasses {
				if b.Function == "shell" && b.Code != "" {
					hasShell = true
					break
				}
			}
			if !hasShell {
				t.Errorf("Expected shell bypass for %s, got %+v", bin, bypasses)
			}
		})
	}

	nonMatching := []string{
		"tar.sh",
		"/usr/local/sbin/tar.sh",
		"/usr/local/sbin/find.sh",
		"find.sh",
		"docker.sh",
		"env.py",
		"git.sh",
		"mount.nfs",
		"mount.cifs",
		"mount.nfs4",
		"mount.fuse",
		"tar.custom",
	}

	for _, bin := range nonMatching {
		t.Run("NoMatch_"+bin, func(t *testing.T) {
			if got := client.CheckBinary(bin); got != nil {
				t.Errorf("Expected nil bypasses for %s, got %+v", bin, got)
			}
		})
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

func TestClient_MergeDatabase(t *testing.T) {
	t.Run("NilClientIsNoOp", func(t *testing.T) {
		var nilClient *Client
		nilClient.MergeDatabase(Database{
			Executables: map[string]Executable{
				"corpctl": {
					Functions: map[string][]Exploit{
						"shell": {{Code: "corpctl --shell", Contexts: map[string]any{"sudo": nil}}},
					},
				},
			},
		})
		if got := nilClient.CheckBinary("corpctl"); got != nil {
			t.Fatalf("Expected nil bypasses for nil client, got %+v", got)
		}
	})

	t.Run("EmptyClientInitializesMapAndIsolatesMutations", func(t *testing.T) {
		client := &Client{}
		overlay := Database{
			Executables: map[string]Executable{
				"corpctl": {
					Functions: map[string][]Exploit{
						"shell": {
							{
								Code:    "corpctl --exec /bin/sh",
								Comment: "initial comment",
								Contexts: map[string]any{
									"sudo": map[string]any{
										"code":    "sudo corpctl --exec /bin/sh",
										"comment": "sudo override",
									},
								},
							},
						},
					},
				},
			},
		}

		client.MergeDatabase(overlay)

		// Mutate caller overlay after merge to verify deep-copy isolation.
		overlay.Executables["corpctl"].Functions["shell"][0].Code = "mutated"
		overlay.Executables["corpctl"].Functions["shell"][0].Contexts["sudo"].(map[string]any)["code"] = "mutated-sudo"
		overlay.Executables["corpctl"].Functions["shell"] = append(overlay.Executables["corpctl"].Functions["shell"], Exploit{
			Code:     "extra",
			Contexts: map[string]any{"sudo": nil},
		})

		bypasses := client.CheckBinary("corpctl")
		if len(bypasses) != 1 {
			t.Fatalf("Expected 1 bypass for corpctl, got %d (%+v)", len(bypasses), bypasses)
		}
		if bypasses[0].Code != "sudo corpctl --exec /bin/sh" {
			t.Errorf("Expected isolated sudo code, got %q", bypasses[0].Code)
		}
		if bypasses[0].Comment != "sudo override" {
			t.Errorf("Expected isolated comment, got %q", bypasses[0].Comment)
		}
	})

	t.Run("NewBinaryAndAppendToExistingBinary", func(t *testing.T) {
		client, err := NewClient()
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}

		origFind := client.CheckBinary("find")
		if len(origFind) == 0 {
			t.Fatal("Expected embedded find bypasses")
		}
		var origFindShell string
		for _, b := range origFind {
			if b.Function == "shell" {
				origFindShell = b.Code
				break
			}
		}
		if origFindShell == "" {
			t.Fatal("Expected embedded find shell bypass")
		}

		overlay := Database{
			Executables: map[string]Executable{
				"customtool": {
					Functions: map[string][]Exploit{
						"shell": {
							{
								Code:     "customtool --run /bin/sh",
								Comment:  "Custom enterprise binary",
								Contexts: map[string]any{"sudo": nil},
							},
						},
					},
				},
				"find": {
					Functions: map[string][]Exploit{
						"shell": {
							{
								Code:     "find . -exec /bin/bash \\;",
								Comment:  "Custom appended shell bypass",
								Contexts: map[string]any{"sudo": nil},
							},
						},
						"file-read": {
							{
								Code:     "find /etc/shadow -exec cat {} +",
								Comment:  "Custom appended file-read function",
								Contexts: map[string]any{"sudo": nil},
							},
						},
						"library-load": {
							{
								Code:     "find /tmp/lib.so",
								Comment:  "Custom brand-new function",
								Contexts: map[string]any{"sudo": nil},
							},
						},
					},
				},
				"apt": {
					Functions: map[string][]Exploit{
						"file-read": {
							{
								Code:     "apt show -o Dir::Etc::sourcelist=/etc/shadow",
								Comment:  "Custom apt file-read",
								Contexts: map[string]any{"sudo": nil},
							},
						},
					},
				},
				"customalias": {
					Alias: "customtool",
				},
			},
		}

		client.MergeDatabase(overlay)

		// Verify newly added binary
		customBypasses := client.CheckBinary("customtool")
		if len(customBypasses) != 1 || customBypasses[0].Function != "shell" || customBypasses[0].Code != "customtool --run /bin/sh" {
			t.Errorf("Unexpected bypasses for customtool: %+v", customBypasses)
		}

		// Verify alias targeting newly added binary
		aliasBypasses := client.CheckBinary("customalias")
		if len(aliasBypasses) != 1 || aliasBypasses[0].Code != "customtool --run /bin/sh" {
			t.Errorf("Unexpected bypasses for customalias: %+v", aliasBypasses)
		}

		// Verify existing binary retained original exploits AND gained appended exploits + new function
		findBypasses := client.CheckBinary("find")
		var mergedShell string
		var mergedFileRead string
		var addedLibraryLoad string
		for _, b := range findBypasses {
			switch b.Function {
			case "shell":
				mergedShell = b.Code
			case "file-read":
				mergedFileRead = b.Code
			case "library-load":
				addedLibraryLoad = b.Code
			}
		}
		if !strings.Contains(mergedShell, origFindShell) || !strings.Contains(mergedShell, "find . -exec /bin/bash \\;") {
			t.Errorf("Expected find shell bypass to include both original and appended code, got: %q", mergedShell)
		}
		if !strings.Contains(mergedFileRead, "find /path/to/input-file") || !strings.Contains(mergedFileRead, "find /etc/shadow -exec cat {} +") {
			t.Errorf("Expected find file-read bypass to include both original and appended code, got: %q", mergedFileRead)
		}
		if addedLibraryLoad != "find /tmp/lib.so" {
			t.Errorf("Expected new library-load function on find, got: %q", addedLibraryLoad)
		}

		// Verify aliased binary ("apt" -> "apt-get") retains apt-get exploits AND gains overlay exploits
		aptBypasses := client.CheckBinary("apt")
		hasAptShell := false
		hasAptFileRead := false
		for _, b := range aptBypasses {
			if b.Function == "shell" {
				hasAptShell = true
			}
			if b.Function == "file-read" && strings.Contains(b.Code, "apt show -o Dir::Etc::sourcelist=/etc/shadow") {
				hasAptFileRead = true
			}
		}
		if !hasAptShell || !hasAptFileRead {
			t.Errorf("Expected apt to retain shell from apt-get and gain file-read from overlay, got: %+v", aptBypasses)
		}
	})

	t.Run("UpdateAliasOnExistingEmptyAlias", func(t *testing.T) {
		client := &Client{
			db: Database{
				Executables: map[string]Executable{
					"myalias": {},
					"targetbin": {
						Functions: map[string][]Exploit{
							"shell": {{Code: "targetbin sh", Contexts: map[string]any{"sudo": nil}}},
						},
					},
				},
			},
		}
		client.MergeDatabase(Database{
			Executables: map[string]Executable{
				"myalias": {Alias: "targetbin"},
			},
		})
		bypasses := client.CheckBinary("myalias")
		if len(bypasses) != 1 || bypasses[0].Code != "targetbin sh" {
			t.Errorf("Expected myalias to resolve to targetbin after merge, got %+v", bypasses)
		}
	})
}

func TestClient_MergeOverlayFile(t *testing.T) {
	t.Run("NilClientReturnsError", func(t *testing.T) {
		var nilClient *Client
		if err := nilClient.MergeOverlayFile("overlay.json"); err == nil {
			t.Fatal("Expected error when calling MergeOverlayFile on nil client")
		}
	})

	t.Run("NonExistentFileReturnsWrappedError", func(t *testing.T) {
		client, err := NewClient()
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}
		err = client.MergeOverlayFile(filepath.Join(t.TempDir(), "does_not_exist.json"))
		if err == nil {
			t.Fatal("Expected error for non-existent overlay file")
		}
		if !errors.Is(err, os.ErrNotExist) {
			t.Errorf("Expected wrapped os.ErrNotExist, got: %v", err)
		}
	})

	t.Run("InvalidJSONReturnsError", func(t *testing.T) {
		client, err := NewClient()
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}
		badFile := filepath.Join(t.TempDir(), "bad.json")
		if err := os.WriteFile(badFile, []byte(`{"executables": {`), 0644); err != nil {
			t.Fatalf("Failed to write bad JSON file: %v", err)
		}
		if err := client.MergeOverlayFile(badFile); err == nil {
			t.Fatal("Expected error for invalid JSON overlay file")
		}
	})

	t.Run("EmptyExecutablesMapReturnsError", func(t *testing.T) {
		client, err := NewClient()
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}
		emptyFile := filepath.Join(t.TempDir(), "empty.json")
		if err := os.WriteFile(emptyFile, []byte(`{"executables": {}}`), 0644); err != nil {
			t.Fatalf("Failed to write empty overlay file: %v", err)
		}
		if err := client.MergeOverlayFile(emptyFile); err == nil {
			t.Fatal("Expected error for empty executables map")
		}

		missingKeyFile := filepath.Join(t.TempDir(), "typo.json")
		if err := os.WriteFile(missingKeyFile, []byte(`{"binaries": {"foo": {}}}`), 0644); err != nil {
			t.Fatalf("Failed to write typo overlay file: %v", err)
		}
		if err := client.MergeOverlayFile(missingKeyFile); err == nil {
			t.Fatal("Expected error when executables key is missing")
		}
	})

	t.Run("ValidOverlayFileMergesSuccessfully", func(t *testing.T) {
		client, err := NewClient()
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}
		overlayFile := filepath.Join(t.TempDir(), "overlay.json")
		overlayJSON := `{
			"executables": {
				"internal-runner": {
					"functions": {
						"command": [
							{
								"code": "internal-runner --exec /bin/sh",
								"comment": "Internal tool escalation",
								"contexts": { "sudo": null }
							}
						]
					}
				},
				"tar": {
					"functions": {
						"file-write": [
							{
								"code": "tar -xf evil.tar -C /etc",
								"comment": "Custom archive overwrite",
								"contexts": { "sudo": null }
							}
						]
					}
				}
			}
		}`
		if err := os.WriteFile(overlayFile, []byte(overlayJSON), 0644); err != nil {
			t.Fatalf("Failed to write overlay file: %v", err)
		}

		if err := client.MergeOverlayFile(overlayFile); err != nil {
			t.Fatalf("MergeOverlayFile failed: %v", err)
		}

		runnerBypasses := client.CheckBinary("internal-runner")
		if len(runnerBypasses) != 1 || runnerBypasses[0].Function != "command" || runnerBypasses[0].Code != "internal-runner --exec /bin/sh" {
			t.Errorf("Unexpected bypasses for internal-runner: %+v", runnerBypasses)
		}

		tarBypasses := client.CheckBinary("tar")
		hasShell := false
		hasFileWrite := false
		for _, b := range tarBypasses {
			if b.Function == "shell" {
				hasShell = true
			}
			if b.Function == "file-write" && strings.Contains(b.Code, "tar -xf evil.tar -C /etc") && strings.Contains(b.Code, "tar Pxf") {
				hasFileWrite = true
			}
		}
		if !hasShell || !hasFileWrite {
			t.Errorf("Expected tar to retain original shell bypass and append file-write from overlay, got: %+v", tarBypasses)
		}
	})
}

func TestClient_MultiHopInheritFormattingAndCaveats(t *testing.T) {
	client, err := NewClient()
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}

	bypasses := client.CheckBinary("systemctl")
	byFunc := make(map[string]SudoBypass)
	for _, b := range bypasses {
		byFunc[b.Function] = b
	}

	fw, ok := byFunc["file-write"]
	if !ok {
		t.Fatalf("Expected file-write bypass for systemctl, got: %+v", bypasses)
	}
	if fw.InheritedFrom != "less" {
		t.Errorf("Expected file-write InheritedFrom='less', got %q", fw.InheritedFrom)
	}
	if fw.HasDirect {
		t.Errorf("Expected systemctl file-write HasDirect=false")
	}
	if count := strings.Count(fw.Comment, "Inherits file-write behavior"); count != 1 {
		t.Errorf("Expected single unified inheritance header, got count=%d in:\n%s", count, fw.Comment)
	}
	if !strings.Contains(fw.Comment, "Inherits file-write behavior from less (and transitively via less -> vi).") {
		t.Errorf("Unexpected multi-hop inheritance summary in Comment:\n%s", fw.Comment)
	}
	if strings.Contains(fw.Comment, "`^[`") {
		t.Errorf("Expected inline backticks to be stripped from Comment, got:\n%s", fw.Comment)
	}
	if !strings.Contains(fw.Comment, "'^['") {
		t.Errorf("Expected sanitized '^[' in Comment, got:\n%s", fw.Comment)
	}
	if !strings.Contains(fw.Comment, "LESSSECURE=1") {
		t.Errorf("Expected systemd >= 247 LESSSECURE=1 caveat in Comment:\n%s", fw.Comment)
	}
	if !strings.Contains(fw.Comment, "':e /path/to/file'") {
		t.Errorf("Expected piped less -> vi ':e /path/to/file' note in Comment:\n%s", fw.Comment)
	}
	if !strings.Contains(fw.Code, "# Via less (trigger with systemctl):\nsystemctl\n# From less:\necho DATA | less") {
		t.Errorf("Expected structured '# Via less' PoC header in Code, got:\n%s", fw.Code)
	}
	if !strings.Contains(fw.Code, "# Via less -> vi (trigger with systemctl):\nsystemctl\n# From less:\nless /etc/hosts\nv\n# From vi:\nvi /path/to/output-file") {
		t.Errorf("Expected structured '# Via less -> vi' PoC header in Code, got:\n%s", fw.Code)
	}

	cmdBypass, ok := byFunc["command"]
	if !ok {
		t.Fatalf("Expected command bypass for systemctl, got: %+v", bypasses)
	}
	if !strings.Contains(cmdBypass.Comment, "SETENV or matching env_keep") {
		t.Errorf("Expected env_keep/SETENV caveat on systemctl command bypass, got:\n%s", cmdBypass.Comment)
	}

	shBypass, ok := byFunc["shell"]
	if !ok || !shBypass.HasDirect {
		t.Errorf("Expected systemctl shell bypass to mark HasDirect=true, got: %+v", shBypass)
	}

	vimBypasses := client.CheckBinary("vim")
	for _, b := range vimBypasses {
		if b.Function == "shell" {
			if !strings.Contains(b.Comment, "Inherits shell behavior from python, lua, vi.") {
				t.Errorf("Expected sibling inherits on vim shell without 'transitively', got:\n%s", b.Comment)
			}
		}
	}

	// Verify direct binaries remain unprefixed verbatim code blocks and preserve HasDirect=true
	findBypasses := client.CheckBinary("find")
	for _, b := range findBypasses {
		if b.Function == "shell" {
			if strings.Contains(b.Code, "# Via ") || !b.HasDirect {
				t.Errorf("Expected direct find shell bypass without '# Via' header and HasDirect=true, got: %+v", b)
			}
		}
	}

	// Verify fenced markdown code blocks in comments remain intact while inline backticks convert
	if got := sanitizeGTFOBinsComment("Use `foo` here.\n```\n`keep_me`\n```"); got != "Use 'foo' here.\n```\n`keep_me`\n```" {
		t.Errorf("Unexpected sanitizeGTFOBinsComment result: %q", got)
	}
}
