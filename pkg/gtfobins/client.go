package gtfobins

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strings"
)

//go:embed database.json
var embeddedDatabase []byte

// ContextDetails stores specific parameters for a context execution (if any).
type ContextDetails struct {
	Code  string `json:"code,omitempty"`
	Shell bool   `json:"shell,omitempty"`
}

// Exploit represents a technique description and how to run it in various contexts.
type Exploit struct {
	Code     string         `json:"code"`
	Comment  string         `json:"comment,omitempty"`
	From     string         `json:"from,omitempty"` // Target binary name when function is "inherit"
	Contexts map[string]any `json:"contexts"`       // e.g., "sudo": null or "sudo": {"code": "..."}
}

// Executable contains the set of functions/exploits mapped to this binary.
type Executable struct {
	Alias     string               `json:"alias,omitempty"`
	Functions map[string][]Exploit `json:"functions,omitempty"`
}

// Database contains all GTFObins executables.
type Database struct {
	Executables map[string]Executable `json:"executables"`
}

// Client is the entry point for querying the GTFObins database.
type Client struct {
	db Database
}

// NewClient initializes a Client with the embedded database.
func NewClient() (*Client, error) {
	var db Database
	if err := json.Unmarshal(embeddedDatabase, &db); err != nil {
		return nil, fmt.Errorf("failed to parse embedded GTFObins database: %w", err)
	}
	return &Client{db: db}, nil
}

// NewClientFromFile initializes a Client using a custom JSON database path.
func NewClientFromFile(path string) (*Client, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read GTFObins file: %w", err)
	}
	var db Database
	if err := json.Unmarshal(data, &db); err != nil {
		return nil, fmt.Errorf("failed to parse GTFObins JSON: %w", err)
	}
	return &Client{db: db}, nil
}

// SudoBypass represents a found bypass method for an executable.
type SudoBypass struct {
	Function       string   // e.g. "shell", "command", "file-read", "file-write", "inherit"
	Code           string   // The payload command
	Comment        string   // Exploitation comment
	InheritedFrom  string   // Populated when Function == "inherit" (e.g. "less", "vi")
	InheritedFuncs []string // Sudo capabilities inherited from InheritedFrom
}

// IsMitigatedByNoExec returns true if this bypass relies on spawning a child process
// (execve/system/popen) and is therefore mitigated when sudo's NOEXEC option is active.
// Note: "library-load", "file-read", "file-write", "privilege-escalation", "upload", and "download"
// occur in-process without spawning a child executable and are NOT mitigated by NOEXEC.
func (b SudoBypass) IsMitigatedByNoExec() bool {
	switch b.Function {
	case "shell", "command", "reverse-shell", "bind-shell", "execute", "inherit":
		return true
	default:
		return false
	}
}

// CheckBinary checks if a binary exists in GTFObins and has any sudo bypass techniques.
// Returns a deterministically ordered list of bypass methods or nil if not vulnerable.
func (c *Client) CheckBinary(name string) []SudoBypass {
	currName := name
	for depth := 0; depth < 5; depth++ {
		exe, exists := c.db.Executables[currName]
		if !exists {
			return nil
		}

		if exe.Alias != "" {
			currName = exe.Alias
			continue
		}

		// Sort function names for deterministic report output across runs.
		funcNames := make([]string, 0, len(exe.Functions))
		for funcName := range exe.Functions {
			funcNames = append(funcNames, funcName)
		}
		slices.Sort(funcNames)

		var bypasses []SudoBypass
		for _, funcName := range funcNames {
			exploits := exe.Functions[funcName]
			for _, exploit := range exploits {
				// Check if "sudo" context exists in contexts
				if val, ok := exploit.Contexts["sudo"]; ok {
					code := exploit.Code
					// If sudo context has specific details (like a custom code block), use it
					if val != nil {
						if m, isMap := val.(map[string]any); isMap {
							if customCode, exists := m["code"].(string); exists && customCode != "" {
								code = customCode
							}
						}
					}

					comment := exploit.Comment
					var inheritedFuncs []string
					if funcName == "inherit" && exploit.From != "" {
						inheritedFuncs = c.resolveInheritedFunctions(exploit.From)
						inheritNote := fmt.Sprintf("Inherits capabilities from '%s'", exploit.From)
						if len(inheritedFuncs) > 0 {
							inheritNote = fmt.Sprintf("Inherits [%s] capabilities from '%s'", strings.Join(inheritedFuncs, ", "), exploit.From)
						}
						if comment != "" {
							comment = comment + " (" + inheritNote + ")"
						} else {
							comment = inheritNote + "."
						}
					}

					bypasses = append(bypasses, SudoBypass{
						Function:       funcName,
						Code:           code,
						Comment:        comment,
						InheritedFrom:  exploit.From,
						InheritedFuncs: inheritedFuncs,
					})
				}
			}
		}
		return bypasses
	}

	return nil
}

// resolveInheritedFunctions returns the sorted list of sudo-capable functions belonging to a target binary.
func (c *Client) resolveInheritedFunctions(target string) []string {
	curr := target
	for depth := 0; depth < 5; depth++ {
		exe, exists := c.db.Executables[curr]
		if !exists {
			return nil
		}
		if exe.Alias != "" {
			curr = exe.Alias
			continue
		}
		var funcs []string
		for fn, exploits := range exe.Functions {
			for _, exp := range exploits {
				if _, ok := exp.Contexts["sudo"]; ok {
					funcs = append(funcs, fn)
					break
				}
			}
		}
		slices.Sort(funcs)
		return funcs
	}
	return nil
}
