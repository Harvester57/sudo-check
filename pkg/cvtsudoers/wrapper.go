package cvtsudoers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"sudo-check/pkg/audit"
)

// Wrapper is used to find and execute the cvtsudoers binary.
type Wrapper struct {
	binaryPath string
}

// NewWrapper creates a Wrapper, searching for cvtsudoers in standard locations or custom path.
func NewWrapper(customPath string) (*Wrapper, error) {
	if customPath != "" {
		if _, err := os.Stat(customPath); err != nil {
			return nil, fmt.Errorf("custom cvtsudoers path not found: %w", err)
		}
		return &Wrapper{binaryPath: customPath}, nil
	}

	// Search PATH
	path, err := exec.LookPath("cvtsudoers")
	if err == nil {
		return &Wrapper{binaryPath: path}, nil
	}

	// Search common paths (Unix only)
	if runtime.GOOS != "windows" {
		commonPaths := []string{
			"/usr/bin/cvtsudoers",
			"/usr/sbin/cvtsudoers",
			"/usr/local/bin/cvtsudoers",
			"/usr/local/sbin/cvtsudoers",
		}
		for _, p := range commonPaths {
			if _, err := os.Stat(p); err == nil {
				return &Wrapper{binaryPath: p}, nil
			}
		}
	}

	return nil, fmt.Errorf("cvtsudoers binary not found in PATH or standard paths; please install sudo/cvtsudoers or specify its path using --cvtsudoers-path")
}

// ConvertPolicy runs cvtsudoers on a given sudoers file and returns the parsed SudoersPolicy.
func (w *Wrapper) ConvertPolicy(sudoersPath string) (*audit.SudoersPolicy, error) {
	if sudoersPath == "" {
		sudoersPath = "/etc/sudoers"
	}

	// Prepare command: cvtsudoers -e -f json <sudoersPath>
	cmd := exec.Command(w.binaryPath, "-e", "-f", "json", sudoersPath)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("failed to execute cvtsudoers: %w (stderr: %s)", err, stderr.String())
	}

	var policy audit.SudoersPolicy
	if err := json.Unmarshal(stdout.Bytes(), &policy); err != nil {
		return nil, fmt.Errorf("failed to parse cvtsudoers JSON output: %w", err)
	}

	return &policy, nil
}

// GetBinaryPath returns the resolved path to the cvtsudoers binary.
func (w *Wrapper) GetBinaryPath() string {
	return w.binaryPath
}
