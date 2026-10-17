package gtfobins

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
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
	Contexts map[string]any `json:"contexts"` // e.g., "sudo": null or "sudo": {"code": "..."}
	From     string         `json:"from,omitempty"`
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
	Function      string // e.g. "shell", "file-read", "file-write"
	Code          string // The payload command
	Comment       string // Exploitation comment
	InheritedFrom string // Optional source binary name when resolved via "inherit"
}

const (
	maxAliasDepth   = 5
	maxInheritDepth = 5
)

var (
	// versionSuffixRegex matches trailing version numbers such as python3, python3.11, php8.2, perl5.34, gcc-12, node18.
	versionSuffixRegex = regexp.MustCompile(`^([a-zA-Z][a-zA-Z0-9_+]+?)[-._]?[0-9]+(?:\.[0-9]+)*$`)

	// distroVariantRegex matches distribution alternative suffixes such as vim.basic, vim.tiny, nc.openbsd.
	distroVariantRegex = regexp.MustCompile(`^([a-zA-Z0-9_-]+)\.[a-zA-Z][a-zA-Z0-9_-]*$`)

	// binaryVariants maps common distribution alternative names to canonical GTFObins binary names.
	binaryVariants = map[string]string{
		"vim.basic":      "vim",
		"vim.tiny":       "vim",
		"vim.nox":        "vim",
		"vim.gtk":        "vim",
		"vim.gtk3":       "vim",
		"vim.athena":     "vim",
		"nvim":           "vim",
		"neovim":         "vim",
		"rvim":           "vim",
		"rview":          "vim",
		"view":           "vim",
		"vimdiff":        "vim",
		"gawk":           "awk",
		"nawk":           "awk",
		"original-awk":   "awk",
		"mawk":           "awk",
		"nc.openbsd":     "nc",
		"nc.traditional": "nc",
		"netcat":         "nc",
		"ncat":           "nc",
		"pnetcat":        "nc",
		"bat":            "batcat",
		"egrep":          "grep",
		"fgrep":          "grep",
		"rgrep":          "grep",
		"pypy":           "python",
		"pypy3":          "python",
		"ipython":        "python",
		"ipython3":       "python",
		"ash":            "sh",
		"dash":           "sh",
		"mksh":           "ksh",
		"ksh93":          "ksh",
		"pdksh":          "ksh",
		"clang":          "gcc",
		"clang++":        "gcc",
		"cc":             "gcc",
		"c++":            "gcc",
		"g++":            "gcc",
	}
)

// NormalizeBinaryName returns candidate GTFObins binary names in priority order.
// It always starts with the exact binary name, followed by distribution variant mappings
// and version-stripped base names.
func NormalizeBinaryName(name string) []string {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil
	}

	var candidates []string
	seen := make(map[string]bool)
	addCandidate := func(s string) {
		if s != "" && !seen[s] {
			seen[s] = true
			candidates = append(candidates, s)
		}
	}

	addCandidate(name)

	base := filepath.Base(name)
	addCandidate(base)

	if mapped, ok := binaryVariants[base]; ok {
		addCandidate(mapped)
	}

	if m := versionSuffixRegex.FindStringSubmatch(base); len(m) == 2 {
		stripped := strings.TrimRight(m[1], "-._")
		addCandidate(stripped)
		if mapped, ok := binaryVariants[stripped]; ok {
			addCandidate(mapped)
		}
	}

	if m := distroVariantRegex.FindStringSubmatch(base); len(m) == 2 {
		stripped := m[1]
		addCandidate(stripped)
		if mapped, ok := binaryVariants[stripped]; ok {
			addCandidate(mapped)
		}
	}

	return candidates
}

// CheckBinary checks if a binary exists in GTFObins and has any sudo bypass techniques.
// Returns a consolidated list of bypass methods (at most one per unique Function) or nil if not vulnerable.
func (c *Client) CheckBinary(name string) []SudoBypass {
	return c.checkBinaryInternal(name, make(map[string]bool), 0)
}

func (c *Client) checkBinaryInternal(name string, inheritVisited map[string]bool, inheritDepth int) []SudoBypass {
	if inheritDepth >= maxInheritDepth {
		return nil
	}

	currName, found := c.lookupCandidate(name)
	if !found {
		return nil
	}

	aliasVisited := make(map[string]bool)
	var targetExe Executable
	foundTarget := false

	for depth := 0; depth < maxAliasDepth; depth++ {
		if aliasVisited[currName] {
			return nil
		}
		aliasVisited[currName] = true

		resolvedName, exists := c.lookupCandidate(currName)
		if !exists {
			return nil
		}
		currName = resolvedName
		exe := c.db.Executables[currName]

		if exe.Alias != "" {
			currName = exe.Alias
			continue
		}

		targetExe = exe
		foundTarget = true
		break
	}

	if !foundTarget || inheritVisited[currName] {
		return nil
	}

	nextVisited := make(map[string]bool, len(inheritVisited)+1)
	for k, v := range inheritVisited {
		nextVisited[k] = v
	}
	nextVisited[currName] = true

	// Sort function names for deterministic processing; process direct functions before "inherit".
	funcNames := make([]string, 0, len(targetExe.Functions))
	hasInherit := false
	for fn := range targetExe.Functions {
		if fn == "inherit" {
			hasInherit = true
			continue
		}
		funcNames = append(funcNames, fn)
	}
	sort.Strings(funcNames)

	var rawBypasses []SudoBypass
	for _, funcName := range funcNames {
		for _, exploit := range targetExe.Functions[funcName] {
			code, comment, ok := extractSudoCodeAndComment(exploit)
			if !ok {
				continue
			}
			rawBypasses = append(rawBypasses, SudoBypass{
				Function: funcName,
				Code:     code,
				Comment:  comment,
			})
		}
	}

	if hasInherit {
		for _, exploit := range targetExe.Functions["inherit"] {
			if exploit.From == "" {
				continue
			}
			parentCode, parentComment, ok := extractSudoCodeAndComment(exploit)
			if !ok {
				continue
			}

			inheritedBypasses := c.checkBinaryInternal(exploit.From, nextVisited, inheritDepth+1)
			for _, child := range inheritedBypasses {
				combinedCode := child.Code
				if parentCode != "" && child.Code != "" && parentCode != child.Code {
					combinedCode = parentCode + "\n" + child.Code
				} else if parentCode != "" && child.Code == "" {
					combinedCode = parentCode
				}

				inheritNote := fmt.Sprintf("Inherits %s behavior from %s.", child.Function, exploit.From)
				commentParts := []string{inheritNote}
				if parentComment != "" {
					commentParts = append(commentParts, parentComment)
				}
				if child.Comment != "" {
					commentParts = append(commentParts, child.Comment)
				}

				rawBypasses = append(rawBypasses, SudoBypass{
					Function:      child.Function,
					Code:          combinedCode,
					Comment:       joinUniqueNonEmptyLines(commentParts),
					InheritedFrom: exploit.From,
				})
			}
		}
	}

	return consolidateBypasses(rawBypasses)
}

func (c *Client) lookupCandidate(name string) (string, bool) {
	for _, candidate := range NormalizeBinaryName(name) {
		if _, exists := c.db.Executables[candidate]; exists {
			return candidate, true
		}
	}
	return "", false
}

func extractSudoCodeAndComment(exploit Exploit) (string, string, bool) {
	val, ok := exploit.Contexts["sudo"]
	if !ok {
		return "", "", false
	}
	code := exploit.Code
	comment := exploit.Comment
	if val != nil {
		if m, isMap := val.(map[string]any); isMap {
			if customCode, exists := m["code"].(string); exists && customCode != "" {
				code = customCode
			}
			if customComment, exists := m["comment"].(string); exists && customComment != "" {
				comment = customComment
			}
		}
	}
	return code, comment, true
}

func consolidateBypasses(bypasses []SudoBypass) []SudoBypass {
	if len(bypasses) == 0 {
		return nil
	}

	type group struct {
		codes         []string
		codeSeen      map[string]bool
		comments      []string
		inheritedFrom string
	}

	groups := make(map[string]*group)
	var funcNames []string

	for _, b := range bypasses {
		g, exists := groups[b.Function]
		if !exists {
			g = &group{
				codeSeen:      make(map[string]bool),
				inheritedFrom: b.InheritedFrom,
			}
			groups[b.Function] = g
			funcNames = append(funcNames, b.Function)
		} else if g.inheritedFrom == "" && b.InheritedFrom != "" {
			g.inheritedFrom = b.InheritedFrom
		}

		if b.Code != "" && !g.codeSeen[b.Code] {
			g.codeSeen[b.Code] = true
			g.codes = append(g.codes, b.Code)
		}
		if b.Comment != "" {
			g.comments = append(g.comments, b.Comment)
		}
	}

	sort.Strings(funcNames)

	result := make([]SudoBypass, 0, len(funcNames))
	for _, fn := range funcNames {
		g := groups[fn]
		result = append(result, SudoBypass{
			Function:      fn,
			Code:          strings.Join(g.codes, "\n\n"),
			Comment:       joinUniqueNonEmptyLines(g.comments),
			InheritedFrom: g.inheritedFrom,
		})
	}

	return result
}

func joinUniqueNonEmptyLines(parts []string) string {
	var unique []string
	seen := make(map[string]bool)
	for _, part := range parts {
		for _, line := range strings.Split(part, "\n") {
			if line == "" {
				continue
			}
			if !seen[line] {
				seen[line] = true
				unique = append(unique, line)
			}
		}
	}
	return strings.Join(unique, "\n")
}
