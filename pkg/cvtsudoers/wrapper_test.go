package cvtsudoers

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestNewWrapper_CustomPathNotFound(t *testing.T) {
	_, err := NewWrapper(filepath.Join(t.TempDir(), "nonexistent-cvtsudoers"))
	if err == nil {
		t.Fatal("expected error for nonexistent custom path")
	}
	if !strings.Contains(err.Error(), "custom cvtsudoers path not found") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestNewWrapper_CustomPathValid(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "mock-cvtsudoers")
	if err := os.WriteFile(tmp, []byte("mock"), 0600); err != nil {
		t.Fatalf("failed to write mock file: %v", err)
	}
	w, err := NewWrapper(tmp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if w.GetBinaryPath() != tmp {
		t.Errorf("expected binaryPath %s, got %s", tmp, w.GetBinaryPath())
	}
}

func TestNewWrapper_NotFoundInEmptyPath(t *testing.T) {
	t.Setenv("PATH", t.TempDir())

	w, err := NewWrapper("")
	if runtime.GOOS == "windows" {
		if err == nil {
			t.Errorf("expected error when cvtsudoers is not in PATH on Windows, got wrapper %v", w)
		}
	}
}

func TestNewWrapper_FoundInPath(t *testing.T) {
	dir := t.TempDir()
	binName := "cvtsudoers"
	if runtime.GOOS == "windows" {
		binName = "cvtsudoers.bat"
	}
	binPath := filepath.Join(dir, binName)
	if err := os.WriteFile(binPath, []byte("@echo off\r\n"), 0755); err != nil {
		t.Fatalf("failed to write mock binary: %v", err)
	}
	t.Setenv("PATH", dir)

	w, err := NewWrapper("")
	if err != nil {
		t.Fatalf("expected to find cvtsudoers in PATH, got error: %v", err)
	}
	if w.GetBinaryPath() == "" {
		t.Error("expected non-empty binaryPath")
	}
}

func TestConvertPolicy_ExecutionFailure(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "not-an-executable.txt")
	if err := os.WriteFile(tmp, []byte("not executable"), 0600); err != nil {
		t.Fatalf("failed to write file: %v", err)
	}
	w := &Wrapper{binaryPath: tmp}
	_, err := w.ConvertPolicy("")
	if err == nil {
		t.Fatal("expected error when running non-executable file")
	}
}

func TestConvertPolicy_ValidAndInvalidJSON(t *testing.T) {
	dir := t.TempDir()
	var validBin, invalidBin string
	if runtime.GOOS == "windows" {
		validBin = filepath.Join(dir, "valid.bat")
		if err := os.WriteFile(validBin, []byte("@echo {\"Defaults\": [], \"User_Specs\": []}\r\n"), 0755); err != nil {
			t.Fatalf("failed to write valid.bat: %v", err)
		}
		invalidBin = filepath.Join(dir, "invalid.bat")
		if err := os.WriteFile(invalidBin, []byte("@echo {invalid-json\r\n"), 0755); err != nil {
			t.Fatalf("failed to write invalid.bat: %v", err)
		}
	} else {
		validBin = filepath.Join(dir, "valid.sh")
		if err := os.WriteFile(validBin, []byte("#!/bin/sh\necho '{\"Defaults\": [], \"User_Specs\": []}'\n"), 0755); err != nil {
			t.Fatalf("failed to write valid.sh: %v", err)
		}
		invalidBin = filepath.Join(dir, "invalid.sh")
		if err := os.WriteFile(invalidBin, []byte("#!/bin/sh\necho '{invalid-json'\n"), 0755); err != nil {
			t.Fatalf("failed to write invalid.sh: %v", err)
		}
	}

	wValid := &Wrapper{binaryPath: validBin}
	policy, err := wValid.ConvertPolicy("")
	if err != nil {
		t.Fatalf("expected valid ConvertPolicy, got error: %v", err)
	}
	if policy == nil {
		t.Fatal("expected non-nil policy")
	}

	wInvalid := &Wrapper{binaryPath: invalidBin}
	_, err = wInvalid.ConvertPolicy("/etc/sudoers")
	if err == nil {
		t.Fatal("expected JSON unmarshal error from invalid output")
	}
}

func TestConvertPolicy_EmptyOutput(t *testing.T) {
	dir := t.TempDir()
	var emptyBin, whitespaceBin string
	if runtime.GOOS == "windows" {
		emptyBin = filepath.Join(dir, "empty.bat")
		if err := os.WriteFile(emptyBin, []byte("@echo off\r\n"), 0755); err != nil {
			t.Fatalf("failed to write empty.bat: %v", err)
		}
		whitespaceBin = filepath.Join(dir, "whitespace.bat")
		if err := os.WriteFile(whitespaceBin, []byte("@echo off\r\necho.   \r\n"), 0755); err != nil {
			t.Fatalf("failed to write whitespace.bat: %v", err)
		}
	} else {
		emptyBin = filepath.Join(dir, "empty.sh")
		if err := os.WriteFile(emptyBin, []byte("#!/bin/sh\n"), 0755); err != nil {
			t.Fatalf("failed to write empty.sh: %v", err)
		}
		whitespaceBin = filepath.Join(dir, "whitespace.sh")
		if err := os.WriteFile(whitespaceBin, []byte("#!/bin/sh\nprintf '   \\n\\t \\n'\n"), 0755); err != nil {
			t.Fatalf("failed to write whitespace.sh: %v", err)
		}
	}

	cases := []struct {
		name string
		bin  string
	}{
		{"ZeroBytes", emptyBin},
		{"WhitespaceOnly", whitespaceBin},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := &Wrapper{binaryPath: tc.bin}
			policy, err := w.ConvertPolicy("/etc/sudoers")
			if err != nil {
				t.Fatalf("expected nil error for %s output, got: %v", tc.name, err)
			}
			if policy == nil {
				t.Fatalf("expected non-nil empty SudoersPolicy for %s output", tc.name)
			}
			if len(policy.Defaults) != 0 || len(policy.UserSpecs) != 0 ||
				len(policy.UserAliases) != 0 || len(policy.RunasAliases) != 0 ||
				len(policy.HostAliases) != 0 || len(policy.CommandAliases) != 0 {
				t.Errorf("expected empty SudoersPolicy, got: %+v", policy)
			}
		})
	}
}
