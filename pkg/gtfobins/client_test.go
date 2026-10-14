package gtfobins

import (
	"os"
	"path/filepath"
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
		{"KnownBinary_Vim", "vim", true, false},
		{"KnownBinary_Python", "python", true, true},
		{"KnownBinary_Awk", "awk", true, true},
		{"AliasResolution", "mawk", true, true}, // Assuming awk aliases to mawk or vice versa in gtfobins. If not, this serves as a general binary check.
		{"NonExistentBinary", "non-existent-binary-xyz", false, false},
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

func TestClient_InheritAndNoExecClassification(t *testing.T) {
	client, err := NewClient()
	if err != nil {
		t.Fatalf("Failed to initialize client: %v", err)
	}

	bypasses := client.CheckBinary("apt-get")
	foundInherit := false
	for _, b := range bypasses {
		if b.Function == "inherit" && b.InheritedFrom == "less" {
			foundInherit = true
			if len(b.InheritedFuncs) == 0 {
				t.Errorf("Expected apt-get inherit from 'less' to resolve inherited functions")
			}
			if !b.IsMitigatedByNoExec() {
				t.Errorf("Expected 'inherit' function to be classified as mitigated by noexec")
			}
		}
	}
	if !foundInherit {
		t.Errorf("Expected apt-get to have an 'inherit' bypass from 'less'")
	}

	libLoad := SudoBypass{Function: "library-load"}
	if libLoad.IsMitigatedByNoExec() {
		t.Errorf("Expected 'library-load' NOT to be mitigated by noexec")
	}
}
