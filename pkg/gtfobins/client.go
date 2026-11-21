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

// MergeDatabase merges custom executable definitions onto the client's loaded catalog.
// Existing binaries have new functions/exploits appended; new binaries are added directly.
func (c *Client) MergeDatabase(overlay Database) {
	if c == nil {
		return
	}
	if c.db.Executables == nil {
		c.db.Executables = make(map[string]Executable, len(overlay.Executables))
	}
	for name, overlayExe := range overlay.Executables {
		existing, exists := c.db.Executables[name]
		if !exists {
			c.db.Executables[name] = cloneExecutable(overlayExe)
			continue
		}
		if overlayExe.Alias != "" {
			existing.Alias = overlayExe.Alias
		}
		if len(overlayExe.Functions) > 0 {
			if existing.Functions == nil {
				existing.Functions = make(map[string][]Exploit, len(overlayExe.Functions))
			}
			for fn, exploits := range overlayExe.Functions {
				if exploits == nil {
					if _, ok := existing.Functions[fn]; !ok {
						existing.Functions[fn] = nil
					}
					continue
				}
				for _, exploit := range exploits {
					existing.Functions[fn] = append(existing.Functions[fn], cloneExploit(exploit))
				}
				if len(exploits) == 0 {
					if _, ok := existing.Functions[fn]; !ok {
						existing.Functions[fn] = []Exploit{}
					}
				}
			}
		}
		c.db.Executables[name] = existing
	}
}

// MergeOverlayFile loads a custom JSON catalog overlay and merges it onto the embedded catalog.
func (c *Client) MergeOverlayFile(path string) error {
	if c == nil {
		return fmt.Errorf("cannot merge GTFObins overlay into nil client")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read GTFObins overlay file: %w", err)
	}
	var overlay Database
	if err := json.Unmarshal(data, &overlay); err != nil {
		return fmt.Errorf("failed to parse GTFObins overlay JSON: %w", err)
	}
	if len(overlay.Executables) == 0 {
		return fmt.Errorf("GTFObins overlay file %q contains no executables", path)
	}
	c.MergeDatabase(overlay)
	return nil
}

func cloneExecutable(exe Executable) Executable {
	return Executable{
		Alias:     exe.Alias,
		Functions: cloneFunctions(exe.Functions),
	}
}

func cloneFunctions(fns map[string][]Exploit) map[string][]Exploit {
	if fns == nil {
		return nil
	}
	cloned := make(map[string][]Exploit, len(fns))
	for fn, exploits := range fns {
		if exploits == nil {
			cloned[fn] = nil
			continue
		}
		copied := make([]Exploit, len(exploits))
		for i, exploit := range exploits {
			copied[i] = cloneExploit(exploit)
		}
		cloned[fn] = copied
	}
	return cloned
}

func cloneExploit(exploit Exploit) Exploit {
	cloned := exploit
	if exploit.Contexts != nil {
		cloned.Contexts = make(map[string]any, len(exploit.Contexts))
		for k, v := range exploit.Contexts {
			cloned.Contexts[k] = cloneContextValue(v)
		}
	}
	return cloned
}

func cloneContextValue(v any) any {
	switch val := v.(type) {
	case map[string]any:
		cp := make(map[string]any, len(val))
		for k, item := range val {
			cp[k] = cloneContextValue(item)
		}
		return cp
	case []any:
		cp := make([]any, len(val))
		for i, item := range val {
			cp[i] = cloneContextValue(item)
		}
		return cp
	case []string:
		return append([]string(nil), val...)
	case map[string]string:
		cp := make(map[string]string, len(val))
		for k, item := range val {
			cp[k] = item
		}
		return cp
	default:
		return v
	}
}

// SudoBypass represents a found bypass method for an executable.
type SudoBypass struct {
	Function      string // e.g. "shell", "file-read", "file-write"
	Code          string // The payload command
	Comment       string // Exploitation comment
	InheritedFrom string // Optional source binary name when resolved via "inherit"
	HasDirect     bool   `json:"has_direct,omitempty"` // True when the binary has a direct (non-inherited) technique for Function
}

const (
	maxAliasDepth   = 5
	maxInheritDepth = 5
)

var (
	// versionSuffixRegex matches trailing version numbers such as python3, python3.11, php8.2, perl5.34, gcc-12, node18.
	versionSuffixRegex = regexp.MustCompile(`^([a-zA-Z][a-zA-Z0-9_+]+?)[-._]?[0-9]+(?:\.[0-9]+)*$`)

	// distroVariantRegex matches dot-separated binary names whose suffix is validated against distroVariantSuffixes.
	distroVariantRegex = regexp.MustCompile(`^([a-zA-Z0-9_+-]+)\.([a-zA-Z][a-zA-Z0-9_-]*)$`)

	// distroVariantSuffixes lists genuine distribution alternative suffixes
	// (e.g., Debian update-alternatives variants) that are safe to strip.
	// Script extensions (.sh, .bash, .py, .pl, .rb, .js) and filesystem helpers
	// (.nfs, .cifs, .fuse, .ext4) are intentionally excluded to avoid false positives.
	distroVariantSuffixes = map[string]bool{
		"basic":       true,
		"tiny":        true,
		"nox":         true,
		"gtk":         true,
		"gtk2":        true,
		"gtk3":        true,
		"athena":      true,
		"openbsd":     true,
		"traditional": true,
		"gnu":         true,
		"bsd":         true,
		"full":        true,
		"minimal":     true,
		"static":      true,
		"orig":        true,
		"real":        true,
		"default":     true,
		"debian":      true,
		"ubuntu":      true,
	}

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
		"sh":             "dash",
		"rbash":          "bash",
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

	if m := distroVariantRegex.FindStringSubmatch(base); len(m) == 3 && distroVariantSuffixes[m[2]] {
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
	if c == nil {
		return nil
	}
	rootName, rawBypasses := c.checkBinaryRaw(name, make(map[string]bool), 0)
	return consolidateRawBypasses(rootName, rawBypasses)
}

type inheritStep struct {
	binary string
	code   string
}

type rawBypass struct {
	function      string
	code          string
	comment       string
	inheritedFrom string
	chain         []string
	steps         []inheritStep
}

type aliasExecutableEntry struct {
	name string
	exe  Executable
}

var systemdPagerBinaries = map[string]bool{
	"systemctl":   true,
	"journalctl":  true,
	"busctl":      true,
	"loginctl":    true,
	"machinectl":  true,
	"networkctl":  true,
	"timedatectl": true,
	"hostnamectl": true,
	"localectl":   true,
	"portablectl": true,
	"resolvectl":  true,
}

func (c *Client) checkBinaryRaw(name string, inheritVisited map[string]bool, inheritDepth int) (string, []rawBypass) {
	if inheritDepth >= maxInheritDepth {
		return "", nil
	}

	currName, found := c.lookupCandidate(name)
	if !found {
		return "", nil
	}

	aliasVisited := make(map[string]bool)
	var targetExe Executable
	var aliasChainExes []aliasExecutableEntry
	foundTarget := false

	for depth := 0; depth < maxAliasDepth; depth++ {
		if aliasVisited[currName] {
			return "", nil
		}
		aliasVisited[currName] = true

		resolvedName, exists := c.lookupCandidate(currName)
		if !exists {
			return "", nil
		}
		currName = resolvedName
		exe := c.db.Executables[currName]

		if exe.Alias != "" {
			if len(exe.Functions) > 0 {
				aliasChainExes = append(aliasChainExes, aliasExecutableEntry{name: currName, exe: exe})
			}
			currName = exe.Alias
			continue
		}

		targetExe = exe
		foundTarget = true
		break
	}

	if !foundTarget || inheritVisited[currName] {
		return "", nil
	}

	nextVisited := make(map[string]bool, len(inheritVisited)+len(aliasVisited)+1)
	for k, v := range inheritVisited {
		nextVisited[k] = v
	}
	for k := range aliasVisited {
		nextVisited[k] = true
	}
	nextVisited[currName] = true

	rawBypasses := c.collectExecutableBypassesRaw(currName, targetExe, nextVisited, inheritDepth)
	for _, aliasEntry := range aliasChainExes {
		rawBypasses = append(rawBypasses, c.collectExecutableBypassesRaw(aliasEntry.name, aliasEntry.exe, nextVisited, inheritDepth)...)
	}

	return currName, rawBypasses
}

func (c *Client) collectExecutableBypassesRaw(ownerName string, exe Executable, nextVisited map[string]bool, inheritDepth int) []rawBypass {
	// Sort function names for deterministic processing; process direct functions before "inherit".
	funcNames := make([]string, 0, len(exe.Functions))
	hasInherit := false
	for fn := range exe.Functions {
		if fn == "inherit" {
			hasInherit = true
			continue
		}
		funcNames = append(funcNames, fn)
	}
	sort.Strings(funcNames)

	var rawBypasses []rawBypass
	for _, funcName := range funcNames {
		for _, exploit := range exe.Functions[funcName] {
			code, comment, ok := extractSudoCodeAndComment(exploit)
			if !ok {
				continue
			}
			rawBypasses = append(rawBypasses, rawBypass{
				function: funcName,
				code:     code,
				comment:  sanitizeGTFOBinsComment(comment),
				steps:    []inheritStep{{binary: ownerName, code: code}},
			})
		}
	}

	if hasInherit {
		for _, exploit := range exe.Functions["inherit"] {
			if exploit.From == "" {
				continue
			}
			parentCode, parentComment, ok := extractSudoCodeAndComment(exploit)
			if !ok {
				continue
			}

			_, inheritedBypasses := c.checkBinaryRaw(exploit.From, nextVisited, inheritDepth+1)
			for _, child := range inheritedBypasses {
				chain := make([]string, 0, 1+len(child.chain))
				chain = append(chain, exploit.From)
				chain = append(chain, child.chain...)

				steps := make([]inheritStep, 0, 1+len(child.steps))
				if parentCode != "" && (len(child.steps) == 0 || child.steps[0].code != parentCode) {
					steps = append(steps, inheritStep{binary: ownerName, code: parentCode})
				}
				steps = append(steps, child.steps...)

				var commentParts []string
				if sanitized := sanitizeGTFOBinsComment(parentComment); sanitized != "" {
					commentParts = append(commentParts, sanitized)
				}
				if child.comment != "" {
					commentParts = append(commentParts, child.comment)
				}

				rawBypasses = append(rawBypasses, rawBypass{
					function:      child.function,
					code:          child.code,
					comment:       joinUniqueNonEmptyLines(commentParts),
					inheritedFrom: exploit.From,
					chain:         chain,
					steps:         steps,
				})
			}
		}
	}

	return rawBypasses
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

func consolidateRawBypasses(rootBinary string, bypasses []rawBypass) []SudoBypass {
	if len(bypasses) == 0 {
		return nil
	}

	type group struct {
		codes           []string
		codeSeen        map[string]bool
		comments        []string
		chains          [][]string
		chainSeen       map[string]bool
		inheritedFrom   string
		hasDirect       bool
		hasEnvTechnique bool
	}

	groups := make(map[string]*group)
	var funcNames []string

	for _, b := range bypasses {
		g, exists := groups[b.function]
		if !exists {
			g = &group{
				codeSeen:      make(map[string]bool),
				chainSeen:     make(map[string]bool),
				inheritedFrom: b.inheritedFrom,
			}
			groups[b.function] = g
			funcNames = append(funcNames, b.function)
		} else if g.inheritedFrom == "" && b.inheritedFrom != "" {
			g.inheritedFrom = b.inheritedFrom
		}

		codeStr := b.code
		if len(b.chain) == 0 {
			g.hasDirect = true
		} else {
			codeStr = formatInheritedCode(rootBinary, b.chain, b.steps)
			chainKey := strings.Join(b.chain, "->")
			if !g.chainSeen[chainKey] {
				g.chainSeen[chainKey] = true
				g.chains = append(g.chains, b.chain)
			}
			if usesInheritedEnvVar(b.steps, b.code) {
				g.hasEnvTechnique = true
			}
		}

		if codeStr != "" && !g.codeSeen[codeStr] {
			g.codeSeen[codeStr] = true
			g.codes = append(g.codes, codeStr)
		}
		if b.comment != "" {
			g.comments = append(g.comments, b.comment)
		}
	}

	sort.Strings(funcNames)

	result := make([]SudoBypass, 0, len(funcNames))
	for _, fn := range funcNames {
		g := groups[fn]
		var allComments []string
		if len(g.chains) > 0 {
			allComments = append(allComments, formatInheritanceSummary(fn, g.chains))
			if systemdPagerBinaries[rootBinary] && chainsContainBinary(g.chains, "less") {
				allComments = append(allComments, "Note: Pager escape requires a TTY with paged output and is typically restricted on systemd >= 247 (LESSSECURE=1 under sudo) unless PAGER/SYSTEMD_PAGER/LESSSECURE is preserved or overridden.")
				if chainsContainAdjacentPair(g.chains, "less", "vi") {
					allComments = append(allComments, "Launching 'vi' from piped 'less' output requires opening a file first (e.g. ':e /path/to/file' then 'v').")
				}
			}
			if g.hasEnvTechnique {
				allComments = append(allComments, "Note: Environment-variable techniques (e.g. LESSOPEN/VISUAL/EDITOR) require SETENV or matching env_keep permissions.")
			}
		}
		allComments = append(allComments, g.comments...)

		result = append(result, SudoBypass{
			Function:      fn,
			Code:          strings.Join(g.codes, "\n\n"),
			Comment:       joinUniqueNonEmptyLines(allComments),
			InheritedFrom: g.inheritedFrom,
			HasDirect:     g.hasDirect,
		})
	}

	return result
}

func formatInheritedCode(rootBinary string, chain []string, steps []inheritStep) string {
	var nonEmpty []inheritStep
	for _, step := range steps {
		if strings.TrimSpace(step.code) != "" {
			nonEmpty = append(nonEmpty, step)
		}
	}
	if len(nonEmpty) == 0 {
		return ""
	}
	chainLabel := strings.Join(chain, " -> ")
	var lines []string
	for i, step := range nonEmpty {
		if i == 0 {
			if step.binary == rootBinary && rootBinary != "" {
				lines = append(lines, fmt.Sprintf("# Via %s (trigger with %s):", chainLabel, rootBinary))
				lines = append(lines, step.code)
				continue
			}
			lines = append(lines, fmt.Sprintf("# Via %s:", chainLabel))
		}
		lines = append(lines, fmt.Sprintf("# From %s:", step.binary))
		lines = append(lines, step.code)
	}
	return strings.Join(lines, "\n")
}

func formatInheritanceSummary(fn string, chains [][]string) string {
	if len(chains) == 0 {
		return ""
	}
	if len(chains) == 1 {
		return fmt.Sprintf("Inherits %s behavior from %s.", fn, strings.Join(chains[0], " -> "))
	}
	var direct []string
	var transitive []string
	for _, ch := range chains {
		if len(ch) == 1 {
			direct = append(direct, ch[0])
		} else {
			transitive = append(transitive, strings.Join(ch, " -> "))
		}
	}
	if len(direct) > 0 && len(transitive) > 0 {
		return fmt.Sprintf("Inherits %s behavior from %s (and transitively via %s).", fn, strings.Join(direct, ", "), strings.Join(transitive, ", "))
	}
	all := make([]string, 0, len(chains))
	for _, ch := range chains {
		all = append(all, strings.Join(ch, " -> "))
	}
	return fmt.Sprintf("Inherits %s behavior from %s.", fn, strings.Join(all, ", "))
}

func chainsContainBinary(chains [][]string, target string) bool {
	for _, ch := range chains {
		for _, item := range ch {
			if item == target {
				return true
			}
		}
	}
	return false
}

func chainsContainAdjacentPair(chains [][]string, first, second string) bool {
	for _, ch := range chains {
		for i := 0; i+1 < len(ch); i++ {
			if ch[i] == first && ch[i+1] == second {
				return true
			}
		}
	}
	return false
}

func usesInheritedEnvVar(steps []inheritStep, fallbackCode string) bool {
	check := func(s string) bool {
		return strings.Contains(s, "LESSOPEN=") || strings.Contains(s, "VISUAL=") || strings.Contains(s, "EDITOR=")
	}
	for _, step := range steps {
		if check(step.code) {
			return true
		}
	}
	return check(fallbackCode)
}

func sanitizeGTFOBinsComment(s string) string {
	if s == "" || !strings.ContainsRune(s, '`') {
		return s
	}
	lines := strings.Split(s, "\n")
	inFence := false
	for i, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "```") {
			inFence = !inFence
			continue
		}
		if inFence {
			continue
		}
		lines[i] = replaceInlineBackticks(line)
	}
	return strings.Join(lines, "\n")
}

func replaceInlineBackticks(line string) string {
	var b strings.Builder
	b.Grow(len(line))
	for i := 0; i < len(line); i++ {
		if line[i] != '`' {
			b.WriteByte(line[i])
			continue
		}
		end := strings.IndexByte(line[i+1:], '`')
		if end > 0 {
			b.WriteByte('\'')
			b.WriteString(line[i+1 : i+1+end])
			b.WriteByte('\'')
			i += end + 1
			continue
		}
		b.WriteByte(line[i])
	}
	return b.String()
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
