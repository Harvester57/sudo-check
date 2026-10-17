package parser

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sudo-check/pkg/audit"
	"time"
)

const maxIncludeDepth = 64

// listOptionNames defines sudoers Defaults options that operate as lists (list_assign, list_add, list_remove).
var listOptionNames = map[string]bool{
	"env_keep":         true,
	"env_check":        true,
	"env_delete":       true,
	"passprompt_regex": true,
}

// tagMapping defines how sudoers Tag_Spec tokens map to cvtsudoers JSON option keys and boolean values.
type tagDef struct {
	key string
	val bool
}

var tagSpecs = map[string]tagDef{
	"NOPASSWD":     {key: "authenticate", val: false},
	"PASSWD":       {key: "authenticate", val: true},
	"NOEXEC":       {key: "noexec", val: true},
	"EXEC":         {key: "noexec", val: false},
	"INTERCEPT":    {key: "intercept", val: true},
	"NOINTERCEPT":  {key: "intercept", val: false},
	"MAIL":         {key: "send_mail", val: true},
	"NOMAIL":       {key: "send_mail", val: false},
	"SETENV":       {key: "setenv", val: true},
	"NOSETENV":     {key: "setenv", val: false},
	"FOLLOW":       {key: "sudoedit_follow", val: true},
	"NOFOLLOW":     {key: "sudoedit_follow", val: false},
	"LOG_INPUT":    {key: "log_input", val: true},
	"NOLOG_INPUT":  {key: "log_input", val: false},
	"LOG_OUTPUT":   {key: "log_output", val: true},
	"NOLOG_OUTPUT": {key: "log_output", val: false},
}

// tagOrder matches the deterministic order in which cvtsudoers emits tag options in JSON.
var tagOrder = []string{
	"authenticate",
	"noexec",
	"intercept",
	"send_mail",
	"setenv",
	"sudoedit_follow",
	"log_input",
	"log_output",
}

// cmndOptionKeys maps per-command KEY=VALUE specifiers to their cvtsudoers JSON option names.
var cmndOptionKeys = map[string]string{
	"ROLE":             "role",
	"TYPE":             "type",
	"APPARMOR_PROFILE": "apparmor_profile",
	"PRIVS":            "privs",
	"LIMITPRIVS":       "limitprivs",
	"CHROOT":           "runchroot",
	"CWD":              "runcwd",
	"TIMEOUT":          "command_timeout",
	"NOTBEFORE":        "notbefore",
	"NOTAFTER":         "notafter",
}

var cmndPreTagOptionOrder = []string{
	"runchroot",
	"runcwd",
	"command_timeout",
	"notbefore",
	"notafter",
}

var cmndPostTagOptionOrder = []string{
	"role",
	"type",
	"apparmor_profile",
	"privs",
	"limitprivs",
}

// IsJSONPolicy reports whether data represents a JSON-formatted sudoers policy (such as cvtsudoers -f json output)
// rather than a raw sudoers configuration file.
func IsJSONPolicy(data []byte) bool {
	trimmed := bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))
	trimmed = bytes.TrimSpace(trimmed)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return false
	}
	return json.Valid(trimmed)
}

// ParseFile parses a sudoers file from disk (or a cvtsudoers JSON file if detected) into an audit.SudoersPolicy.
func ParseFile(path string) (*audit.SudoersPolicy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read sudoers file %s: %w", path, err)
	}
	if IsJSONPolicy(data) {
		var policy audit.SudoersPolicy
		if err := json.Unmarshal(data, &policy); err != nil {
			return nil, fmt.Errorf("failed to parse JSON policy %s: %w", path, err)
		}
		return &policy, nil
	}
	absPath, err := filepath.Abs(path)
	if err != nil {
		absPath = path
	}
	baseDir := filepath.Dir(path)
	ctx := newParseContext()
	ctx.activeFiles[filepath.Clean(absPath)] = true
	if err := ctx.parseBytes(data, filepath.Clean(path), baseDir, 0); err != nil {
		return nil, err
	}
	return ctx.policy, nil
}

// ParseReader parses raw sudoers content from an io.Reader using baseDir to resolve relative includes.
func ParseReader(r io.Reader, filename string, baseDir string) (*audit.SudoersPolicy, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %w", filename, err)
	}
	if IsJSONPolicy(data) {
		var policy audit.SudoersPolicy
		if err := json.Unmarshal(data, &policy); err != nil {
			return nil, fmt.Errorf("failed to parse JSON policy %s: %w", filename, err)
		}
		return &policy, nil
	}
	if filename == "" {
		filename = "stdin"
	}
	ctx := newParseContext()
	if baseDir != "" && filename != "stdin" {
		if abs, err := filepath.Abs(filepath.Join(baseDir, filepath.Base(filename))); err == nil {
			ctx.activeFiles[filepath.Clean(abs)] = true
		}
	}
	if err := ctx.parseBytes(data, filename, baseDir, 0); err != nil {
		return nil, err
	}
	return ctx.policy, nil
}

// ParseString parses a raw sudoers policy string into an audit.SudoersPolicy.
func ParseString(content string) (*audit.SudoersPolicy, error) {
	return ParseReader(strings.NewReader(content), "stdin", "")
}

type parseContext struct {
	policy      *audit.SudoersPolicy
	activeFiles map[string]bool
	hostname    string
}

func newParseContext() *parseContext {
	h, _ := os.Hostname()
	if idx := strings.IndexByte(h, '.'); idx != -1 {
		h = h[:idx]
	}
	return &parseContext{
		policy:      &audit.SudoersPolicy{},
		activeFiles: make(map[string]bool),
		hostname:    h,
	}
}

type logicalLine struct {
	text string
	line int
}

func normalizeSourceFile(filename string) string {
	if filename == "" || filename == "stdin" {
		return ""
	}
	return filepath.ToSlash(filename)
}

func (ctx *parseContext) parseBytes(data []byte, filename string, baseDir string, depth int) error {
	if depth > maxIncludeDepth {
		return nil
	}
	if srcFile := normalizeSourceFile(filename); srcFile != "" {
		if !slices.Contains(ctx.policy.IncludedFiles, srcFile) {
			ctx.policy.IncludedFiles = append(ctx.policy.IncludedFiles, srcFile)
		}
	}
	content := strings.TrimPrefix(string(data), "\xef\xbb\xbf")
	lines, err := extractLogicalLines(content, filename)
	if err != nil {
		return err
	}

	for _, ll := range lines {
		lineText := strings.TrimSpace(ll.text)
		if lineText == "" {
			continue
		}

		// 1. Check for include / includedir directives (#include, @include, #includedir, @includedir)
		if incKind, incTarget, ok := parseIncludeDirective(lineText); ok {
			if incTarget == "" {
				return fmt.Errorf("%s:%d: empty %s directive", filename, ll.line, incKind)
			}
			if err := ctx.handleInclude(incKind, incTarget, baseDir, depth); err != nil {
				return err
			}
			continue
		}

		// 2. Check for Defaults entries
		if isDefaultsEntry(lineText) {
			if err := ctx.parseDefaultsLine(lineText, filename, ll.line); err != nil {
				return err
			}
			continue
		}

		// 3. Check for Alias definitions (User_Alias, Runas_Alias, Host_Alias, Cmnd_Alias)
		if aliasKind, rest, ok := matchAliasKeyword(lineText); ok {
			if err := ctx.parseAliasLine(aliasKind, rest, filename, ll.line); err != nil {
				return err
			}
			continue
		}

		// 4. Parse as User_Spec
		if err := ctx.parseUserSpecLine(lineText, filename, ll.line); err != nil {
			return err
		}
	}

	return nil
}

// extractLogicalLines strips comments and joins backslash-continued lines, tracking the 1-indexed starting line number.
func extractLogicalLines(content string, filename string) ([]logicalLine, error) {
	trimmedEOF := strings.TrimSuffix(strings.TrimSuffix(content, "\n"), "\r")
	rawLines := strings.Split(trimmedEOF, "\n")
	var result []logicalLine

	var buf strings.Builder
	startLine := 0
	continuing := false

	for i, raw := range rawLines {
		lineNum := i + 1
		line := strings.TrimSuffix(raw, "\r")

		// Check if this physical line is a pure comment line (and not #include / #includedir or #<uid> =)
		trimmed := strings.TrimLeft(line, " \t")
		if strings.HasPrefix(trimmed, "#") && !isIncludePrefix(trimmed) && !isLeadingUIDLine(trimmed, continuing) {
			if continuing {
				// Allow comments inside a multi-line continuation block without breaking the continuation
				continue
			}
			continue
		}

		cleaned, hasContinuation := stripInlineCommentAndContinuation(line, continuing)
		if !continuing {
			if strings.TrimSpace(cleaned) == "" && !hasContinuation {
				continue
			}
			startLine = lineNum
		}

		buf.WriteString(cleaned)
		if hasContinuation {
			continuing = true
		} else {
			continuing = false
			text := strings.TrimSpace(buf.String())
			buf.Reset()
			if text != "" {
				result = append(result, logicalLine{
					text: text,
					line: startLine,
				})
			}
		}
	}

	if continuing {
		return nil, fmt.Errorf("%s:%d: syntax error: continuation character at end of file", filename, startLine)
	}

	return result, nil
}

func isIncludePrefix(trimmed string) bool {
	for _, kw := range []string{"#includedir", "#include", "@includedir", "@include"} {
		if strings.HasPrefix(trimmed, kw) {
			rest := trimmed[len(kw):]
			if len(rest) > 0 && (rest[0] == ' ' || rest[0] == '\t') {
				return true
			}
		}
	}
	return false
}

func isLeadingUIDLine(trimmed string, continuing bool) bool {
	if !isNumericIDTokenAt(trimmed, 0) {
		return false
	}
	if continuing {
		return true
	}
	return strings.Contains(trimmed, "=")
}

// isNumericIDTokenAt checks whether s[pos] is '#' followed by an optional '-' and one or more digits,
// terminated by end-of-string or a sudoers token delimiter.
func isNumericIDTokenAt(s string, pos int) bool {
	if pos >= len(s) || s[pos] != '#' {
		return false
	}
	j := pos + 1
	if j < len(s) && s[j] == '-' {
		j++
	}
	digitStart := j
	for j < len(s) && s[j] >= '0' && s[j] <= '9' {
		j++
	}
	if j == digitStart {
		return false
	}
	if j == len(s) {
		return true
	}
	switch s[j] {
	case ' ', '\t', ',', ':', '=', ')', '!':
		return true
	default:
		return false
	}
}

func stripInlineCommentAndContinuation(line string, continuing bool) (string, bool) {
	inQuotes := false
	trimmedLeft := strings.TrimLeft(line, " \t")
	leadingOffset := len(line) - len(trimmedLeft)
	isInc := isIncludePrefix(trimmedLeft)

	commentIdx := -1
	for i := 0; i < len(line); i++ {
		ch := line[i]
		if ch == '\\' {
			i++ // skip escaped character
			continue
		}
		if ch == '"' {
			inQuotes = !inQuotes
			continue
		}
		if !inQuotes && ch == '#' {
			if isInc && i == leadingOffset {
				continue
			}
			if isNumericIDTokenAt(line, i) {
				if i == leadingOffset && !continuing && !strings.Contains(line, "=") {
					commentIdx = i
					break
				}
				continue
			}
			commentIdx = i
			break
		}
	}

	effective := line
	if commentIdx != -1 {
		effective = line[:commentIdx]
	}

	// Only check for trailing backslash continuation if there was no inline comment after it,
	// or if the backslash was at the end of the non-comment content.
	trimmedRight := strings.TrimRight(effective, " \t")
	if endsWithUnescapedBackslash(trimmedRight) {
		return trimmedRight[:len(trimmedRight)-1], true
	}
	return effective, false
}

func endsWithUnescapedBackslash(s string) bool {
	if len(s) == 0 || s[len(s)-1] != '\\' {
		return false
	}
	count := 0
	for i := len(s) - 1; i >= 0 && s[i] == '\\'; i-- {
		count++
	}
	return count%2 == 1
}

func parseIncludeDirective(line string) (kind string, target string, ok bool) {
	for _, kw := range []string{"#includedir", "@includedir", "#include", "@include"} {
		if strings.HasPrefix(line, kw) {
			rest := line[len(kw):]
			if len(rest) == 0 {
				return kw, "", true
			}
			if rest[0] == ' ' || rest[0] == '\t' {
				target = strings.TrimSpace(rest)
				target = unquoteOrUnescapePath(target)
				return kw, target, true
			}
		}
	}
	return "", "", false
}

func unquoteOrUnescapePath(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return unescapeString(s[1 : len(s)-1])
	}
	return unescapeString(s)
}

func (ctx *parseContext) handleInclude(kind string, rawTarget string, baseDir string, depth int) error {
	if depth >= maxIncludeDepth {
		return nil
	}

	target := strings.ReplaceAll(rawTarget, "%h", ctx.hostname)
	resolved := resolveIncludePath(target, baseDir)

	isDirDirective := strings.HasSuffix(kind, "includedir")
	if isDirDirective {
		entries, err := os.ReadDir(resolved)
		if err != nil {
			// Non-existent includedir is ignored per sudoers specification
			return nil
		}
		var names []string
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			name := entry.Name()
			// sudoers skips files in includedir that contain a '.' or end with '~'
			if strings.Contains(name, ".") || strings.HasSuffix(name, "~") {
				continue
			}
			names = append(names, name)
		}
		slices.Sort(names)
		for _, name := range names {
			filePath := filepath.Join(resolved, name)
			if err := ctx.includeSingleFile(filePath, depth+1); err != nil {
				return err
			}
		}
		return nil
	}

	return ctx.includeSingleFile(resolved, depth+1)
}

func resolveIncludePath(target string, baseDir string) string {
	if filepath.IsAbs(target) || strings.HasPrefix(target, "/") {
		cleanBase := filepath.ToSlash(filepath.Clean(baseDir))
		if baseDir != "" && cleanBase != "/etc" {
			// Prefer offline local candidates when scanning a sudoers policy outside /etc
			trimmed := strings.TrimPrefix(target, "/etc/")
			if trimmed != target {
				candidate := filepath.Join(baseDir, trimmed)
				if _, err := os.Stat(candidate); err == nil {
					return candidate
				}
			}
			baseCandidate := filepath.Join(baseDir, filepath.Base(target))
			if _, err := os.Stat(baseCandidate); err == nil {
				return baseCandidate
			}
		}
		if _, err := os.Stat(target); err == nil {
			return target
		}
		if baseDir != "" {
			trimmed := strings.TrimPrefix(target, "/etc/")
			if trimmed != target {
				candidate := filepath.Join(baseDir, trimmed)
				if _, err := os.Stat(candidate); err == nil {
					return candidate
				}
			}
			baseCandidate := filepath.Join(baseDir, filepath.Base(target))
			if _, err := os.Stat(baseCandidate); err == nil {
				return baseCandidate
			}
		}
		return target
	}
	if baseDir != "" {
		return filepath.Join(baseDir, target)
	}
	return target
}

func (ctx *parseContext) includeSingleFile(filePath string, depth int) error {
	if depth > maxIncludeDepth {
		return nil
	}
	absPath, err := filepath.Abs(filePath)
	if err != nil {
		absPath = filePath
	}
	cleanAbs := filepath.Clean(absPath)
	if ctx.activeFiles[cleanAbs] {
		// Cycle detected: break recursion safely
		return nil
	}
	data, err := os.ReadFile(cleanAbs)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("failed to read included sudoers file %s: %w", filePath, err)
	}

	ctx.activeFiles[cleanAbs] = true
	defer delete(ctx.activeFiles, cleanAbs)

	displayPath := filepath.Clean(filePath)
	return ctx.parseBytes(data, displayPath, filepath.Dir(displayPath), depth)
}

func isDefaultsEntry(line string) bool {
	if !strings.HasPrefix(line, "Defaults") {
		return false
	}
	if len(line) == len("Defaults") {
		return true
	}
	next := line[len("Defaults")]
	switch next {
	case ' ', '\t', '@', ':', '!', '>':
		return true
	default:
		return false
	}
}

func (ctx *parseContext) parseDefaultsLine(line string, filename string, lineNum int) error {
	rest := line[len("Defaults"):]
	if len(rest) == 0 {
		return fmt.Errorf("%s:%d: empty Defaults directive", filename, lineNum)
	}

	var scope byte
	if rest[0] == '@' || rest[0] == ':' || rest[0] == '!' || rest[0] == '>' {
		scope = rest[0]
		rest = rest[1:]
	}

	var binding []audit.Member
	optionsStr := rest

	srcFile := normalizeSourceFile(filename)
	if scope != 0 {
		rawMembers, remaining, err := readLeadingCommaList(rest)
		if err != nil || len(rawMembers) == 0 {
			return fmt.Errorf("%s:%d: invalid binding in Defaults%c", filename, lineNum, scope)
		}
		if strings.TrimSpace(remaining) == "" {
			return fmt.Errorf("%s:%d: missing options in Defaults%c", filename, lineNum, scope)
		}
		optionsStr = remaining
		for _, tok := range rawMembers {
			var m audit.Member
			switch scope {
			case '@':
				m = ctx.parseHostMember(tok, lineNum)
			case ':':
				m = ctx.parseUserMember(tok, lineNum)
			case '!':
				m = ctx.parseCmndBindingMember(tok, lineNum)
			case '>':
				m = ctx.parseRunasUserMember(tok, lineNum)
			}
			m.File = srcFile
			binding = append(binding, m)
		}
	}

	options, err := parseDefaultsOptions(optionsStr, filename, lineNum)
	if err != nil {
		return err
	}

	ctx.policy.Defaults = append(ctx.policy.Defaults, audit.DefaultBinding{
		Binding: binding,
		Options: options,
		File:    srcFile,
		Line:    lineNum,
	})
	return nil
}

// readLeadingCommaList reads a comma-separated list of tokens from the start of s until whitespace
// that is not adjacent to a comma is encountered, returning the tokens and the remaining substring.
func readLeadingCommaList(s string) ([]string, string, error) {
	i := skipSpaces(s, 0)
	if i >= len(s) {
		return nil, "", fmt.Errorf("unexpected end of line")
	}

	var tokens []string
	for i < len(s) {
		var tokBuilder strings.Builder
		// Allow optional whitespace after leading '!'
		for i < len(s) && s[i] == '!' {
			tokBuilder.WriteByte('!')
			i++
			i = skipSpaces(s, i)
		}

		tokStart := i
		inQuotes := false
		for i < len(s) {
			ch := s[i]
			if ch == '\\' {
				i += 2
				continue
			}
			if ch == '"' {
				inQuotes = !inQuotes
				i++
				continue
			}
			if !inQuotes && (ch == ' ' || ch == '\t' || ch == ',' || ch == '=') {
				break
			}
			i++
		}
		if inQuotes {
			return nil, "", fmt.Errorf("unterminated quote")
		}
		if i == tokStart {
			return nil, "", fmt.Errorf("empty member in list")
		}
		tokBuilder.WriteString(s[tokStart:i])
		tokens = append(tokens, tokBuilder.String())

		i = skipSpaces(s, i)
		if i < len(s) && s[i] == ',' {
			i++ // consume ','
			i = skipSpaces(s, i)
			if i >= len(s) {
				return nil, "", fmt.Errorf("trailing comma in list")
			}
			continue
		}
		break
	}

	return tokens, s[i:], nil
}

func skipSpaces(s string, i int) int {
	for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
		i++
	}
	return i
}

func parseDefaultsOptions(optionsStr string, filename string, lineNum int) ([]audit.Option, error) {
	rawOpts, err := splitCommaOutsideQuotes(optionsStr)
	if err != nil {
		return nil, fmt.Errorf("%s:%d: %w", filename, lineNum, err)
	}

	var options []audit.Option
	for _, rawOpt := range rawOpts {
		entry := strings.TrimSpace(rawOpt)
		if entry == "" {
			return nil, fmt.Errorf("%s:%d: empty option in Defaults", filename, lineNum)
		}

		negated := false
		for strings.HasPrefix(entry, "!") {
			negated = !negated
			entry = strings.TrimSpace(entry[1:])
		}
		if entry == "" {
			return nil, fmt.Errorf("%s:%d: invalid negated option in Defaults", filename, lineNum)
		}

		op, key, val, hasOp := splitOptionAssignment(entry)
		if !hasOp {
			options = append(options, audit.Option{
				entry: !negated,
			})
			continue
		}
		if negated {
			return nil, fmt.Errorf("%s:%d: cannot negate assignment option %s", filename, lineNum, key)
		}

		unquoted := unquoteOptionValue(val)
		if key == "command_timeout" {
			if _, ok := parseTimeoutSeconds(unquoted); !ok {
				return nil, fmt.Errorf("%s:%d: invalid command_timeout value %q", filename, lineNum, unquoted)
			}
		}
		if listOptionNames[key] {
			listOp := "list_assign"
			switch op {
			case "+=":
				listOp = "list_add"
			case "-=":
				listOp = "list_remove"
			}
			items := strings.Fields(unquoted)
			if items == nil {
				items = []string{}
			}
			options = append(options, audit.Option{
				"operation": listOp,
				key:         items,
			})
		} else {
			options = append(options, audit.Option{
				key: unquoted,
			})
		}
	}

	if len(options) == 0 {
		return nil, fmt.Errorf("%s:%d: no options specified in Defaults", filename, lineNum)
	}
	return options, nil
}

func splitOptionAssignment(entry string) (op string, key string, val string, ok bool) {
	inQuotes := false
	for i := 0; i < len(entry); i++ {
		ch := entry[i]
		if ch == '\\' {
			i++
			continue
		}
		if ch == '"' {
			inQuotes = !inQuotes
			continue
		}
		if !inQuotes {
			if (ch == '+' || ch == '-') && i+1 < len(entry) && entry[i+1] == '=' {
				key = strings.TrimSpace(entry[:i])
				val = strings.TrimSpace(entry[i+2:])
				if key == "" {
					return "", "", "", false
				}
				return entry[i : i+2], key, val, true
			}
			if ch == '=' {
				key = strings.TrimSpace(entry[:i])
				val = strings.TrimSpace(entry[i+1:])
				if key == "" {
					return "", "", "", false
				}
				return "=", key, val, true
			}
		}
	}
	return "", "", "", false
}

func unquoteOptionValue(s string) string {
	val, _ := unquoteToken(s)
	return val
}

func unquoteToken(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return unescapeQuotedString(s[1 : len(s)-1]), true
	}
	for _, pfx := range []string{"%:", "%", "+"} {
		if strings.HasPrefix(s, pfx+`"`) && strings.HasSuffix(s, `"`) && len(s) >= len(pfx)+2 {
			return pfx + unescapeQuotedString(s[len(pfx)+1:len(s)-1]), true
		}
	}
	return unescapeString(s), false
}

func unescapeQuotedString(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) && (s[i+1] == '"' || s[i+1] == '\\') {
			i++
			b.WriteByte(s[i])
		} else {
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

func unescapeString(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			i++
			b.WriteByte(s[i])
		} else {
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

func validateMemberToken(rawTok string, disallowMyself bool) error {
	tok, _ := stripNegation(rawTok)
	if tok == "" || tok == `""` {
		if disallowMyself {
			return fmt.Errorf("empty member name")
		}
		return nil
	}
	val, wasQuoted := unquoteToken(tok)
	if !wasQuoted {
		for i := 0; i < len(tok); i++ {
			if tok[i] == '\\' {
				i++
				continue
			}
			if tok[i] == ' ' || tok[i] == '\t' || tok[i] == '=' || tok[i] == '"' {
				return fmt.Errorf("invalid character in member %q", rawTok)
			}
		}
	}
	if val == "%" || val == "%:" || val == "+" {
		return fmt.Errorf("empty group or netgroup in member %q", rawTok)
	}
	return nil
}

func splitCommaOutsideQuotes(s string) ([]string, error) {
	var parts []string
	start := 0
	inQuotes := false
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if ch == '\\' {
			i++
			continue
		}
		if ch == '"' {
			inQuotes = !inQuotes
			continue
		}
		if !inQuotes && ch == ',' {
			parts = append(parts, s[start:i])
			start = i + 1
		}
	}
	if inQuotes {
		return nil, fmt.Errorf("unterminated quote in %q", s)
	}
	parts = append(parts, s[start:])
	return parts, nil
}

func matchAliasKeyword(line string) (string, string, bool) {
	for _, kw := range []string{"User_Alias", "Runas_Alias", "Host_Alias", "Cmnd_Alias"} {
		if strings.HasPrefix(line, kw) {
			rest := line[len(kw):]
			if len(rest) == 0 || rest[0] == ' ' || rest[0] == '\t' {
				return kw, strings.TrimSpace(rest), true
			}
		}
	}
	return "", "", false
}

func (ctx *parseContext) parseAliasLine(kind string, rest string, filename string, lineNum int) error {
	if rest == "" {
		return fmt.Errorf("%s:%d: empty %s definition", filename, lineNum, kind)
	}

	clauses := splitAliasClauses(rest)
	for _, clause := range clauses {
		eqIdx := findCharOutsideQuotes(clause, '=')
		if eqIdx == -1 {
			return fmt.Errorf("%s:%d: missing '=' in %s definition", filename, lineNum, kind)
		}
		aliasName := strings.TrimSpace(clause[:eqIdx])
		membersStr := strings.TrimSpace(clause[eqIdx+1:])
		if aliasName == "" || !isValidIdentifier(aliasName) || aliasName == "ALL" {
			return fmt.Errorf("%s:%d: invalid alias name %q in %s", filename, lineNum, aliasName, kind)
		}
		if membersStr == "" {
			return fmt.Errorf("%s:%d: empty member list for alias %s", filename, lineNum, aliasName)
		}

		switch kind {
		case "User_Alias":
			members, err := ctx.parseUserMemberList(membersStr, filename, lineNum)
			if err != nil {
				return err
			}
			if ctx.policy.UserAliases == nil {
				ctx.policy.UserAliases = make(map[string][]audit.Member)
			}
			ctx.policy.UserAliases[aliasName] = append(ctx.policy.UserAliases[aliasName], members...)

		case "Runas_Alias":
			members, err := ctx.parseRunasUserMemberList(membersStr, filename, lineNum)
			if err != nil {
				return err
			}
			if ctx.policy.RunasAliases == nil {
				ctx.policy.RunasAliases = make(map[string][]audit.Member)
			}
			ctx.policy.RunasAliases[aliasName] = append(ctx.policy.RunasAliases[aliasName], members...)

		case "Host_Alias":
			members, err := ctx.parseHostMemberList(membersStr, filename, lineNum)
			if err != nil {
				return err
			}
			if ctx.policy.HostAliases == nil {
				ctx.policy.HostAliases = make(map[string][]audit.Member)
			}
			ctx.policy.HostAliases[aliasName] = append(ctx.policy.HostAliases[aliasName], members...)

		case "Cmnd_Alias":
			members, err := ctx.parseCmndAliasMemberList(membersStr, filename, lineNum)
			if err != nil {
				return err
			}
			if ctx.policy.CommandAliases == nil {
				ctx.policy.CommandAliases = make(map[string][]audit.Member)
			}
			ctx.policy.CommandAliases[aliasName] = append(ctx.policy.CommandAliases[aliasName], members...)
		}
	}
	return nil
}

// splitAliasClauses splits multiple colon-separated alias definitions (`A = ... : B = ...`),
// ignoring colons inside quotes, IPv6 addresses, non-Unix groups (%:), digests (sha256:), or command arguments.
func splitAliasClauses(s string) []string {
	var clauses []string
	start := 0
	inQuotes := false
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if ch == '\\' {
			i++
			continue
		}
		if ch == '"' {
			inQuotes = !inQuotes
			continue
		}
		if !inQuotes && ch == ':' {
			if startsWithIdentEquals(s[i+1:]) {
				clauses = append(clauses, strings.TrimSpace(s[start:i]))
				start = i + 1
			}
		}
	}
	clauses = append(clauses, strings.TrimSpace(s[start:]))
	return clauses
}

func startsWithIdentEquals(s string) bool {
	i := skipSpaces(s, 0)
	identStart := i
	for i < len(s) && isIdentChar(s[i], i == identStart) {
		i++
	}
	if i == identStart {
		return false
	}
	i = skipSpaces(s, i)
	return i < len(s) && s[i] == '='
}

func isValidIdentifier(s string) bool {
	if len(s) == 0 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !isIdentChar(s[i], i == 0) {
			return false
		}
	}
	return true
}

func isIdentChar(ch byte, first bool) bool {
	if (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || ch == '_' {
		return true
	}
	if !first && ch >= '0' && ch <= '9' {
		return true
	}
	return false
}

// isAliasIdentifier reports whether tok matches the standard sudoers alias naming convention (^[A-Z][A-Z0-9_]*$ and != "ALL").
func isAliasIdentifier(tok string) bool {
	if len(tok) == 0 || tok == "ALL" {
		return false
	}
	if tok[0] < 'A' || tok[0] > 'Z' {
		return false
	}
	for i := 1; i < len(tok); i++ {
		ch := tok[i]
		if !((ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '_') {
			return false
		}
	}
	return true
}

func findCharOutsideQuotes(s string, target byte) int {
	inQuotes := false
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if ch == '\\' {
			i++
			continue
		}
		if ch == '"' {
			inQuotes = !inQuotes
			continue
		}
		if !inQuotes && ch == target {
			return i
		}
	}
	return -1
}

func (ctx *parseContext) parseUserMemberList(s string, filename string, lineNum int) ([]audit.Member, error) {
	parts, err := splitCommaOutsideQuotes(s)
	if err != nil {
		return nil, fmt.Errorf("%s:%d: %w", filename, lineNum, err)
	}
	srcFile := normalizeSourceFile(filename)
	var members []audit.Member
	for _, p := range parts {
		tok := strings.TrimSpace(p)
		if tok == "" {
			return nil, fmt.Errorf("%s:%d: empty member in user list", filename, lineNum)
		}
		if err := validateMemberToken(tok, true); err != nil {
			return nil, fmt.Errorf("%s:%d: %w", filename, lineNum, err)
		}
		m := ctx.parseUserMember(tok, lineNum)
		m.File = srcFile
		members = append(members, m)
	}
	return members, nil
}

func (ctx *parseContext) parseRunasUserMemberList(s string, filename string, lineNum int) ([]audit.Member, error) {
	parts, err := splitCommaOutsideQuotes(s)
	if err != nil {
		return nil, fmt.Errorf("%s:%d: %w", filename, lineNum, err)
	}
	srcFile := normalizeSourceFile(filename)
	var members []audit.Member
	for _, p := range parts {
		tok := strings.TrimSpace(p)
		if tok == "" {
			return nil, fmt.Errorf("%s:%d: empty member in runas list", filename, lineNum)
		}
		if err := validateMemberToken(tok, false); err != nil {
			return nil, fmt.Errorf("%s:%d: %w", filename, lineNum, err)
		}
		m := ctx.parseRunasUserMember(tok, lineNum)
		m.File = srcFile
		members = append(members, m)
	}
	return members, nil
}

func (ctx *parseContext) parseRunasGroupMemberList(s string, filename string, lineNum int) ([]audit.Member, error) {
	parts, err := splitCommaOutsideQuotes(s)
	if err != nil {
		return nil, fmt.Errorf("%s:%d: %w", filename, lineNum, err)
	}
	srcFile := normalizeSourceFile(filename)
	var members []audit.Member
	for _, p := range parts {
		tok := strings.TrimSpace(p)
		if tok == "" {
			return nil, fmt.Errorf("%s:%d: empty member in runas group list", filename, lineNum)
		}
		if err := validateMemberToken(tok, false); err != nil {
			return nil, fmt.Errorf("%s:%d: %w", filename, lineNum, err)
		}
		m := ctx.parseRunasGroupMember(tok, lineNum)
		m.File = srcFile
		members = append(members, m)
	}
	return members, nil
}

func (ctx *parseContext) parseHostMemberList(s string, filename string, lineNum int) ([]audit.Member, error) {
	parts, err := splitCommaOutsideQuotes(s)
	if err != nil {
		return nil, fmt.Errorf("%s:%d: %w", filename, lineNum, err)
	}
	srcFile := normalizeSourceFile(filename)
	var members []audit.Member
	for _, p := range parts {
		tok := strings.TrimSpace(p)
		if tok == "" {
			return nil, fmt.Errorf("%s:%d: empty member in host list", filename, lineNum)
		}
		if err := validateMemberToken(tok, false); err != nil {
			return nil, fmt.Errorf("%s:%d: %w", filename, lineNum, err)
		}
		m := ctx.parseHostMember(tok, lineNum)
		m.File = srcFile
		members = append(members, m)
	}
	return members, nil
}

func stripNegation(tok string) (string, bool) {
	negated := false
	tok = strings.TrimSpace(tok)
	for strings.HasPrefix(tok, "!") {
		negated = !negated
		tok = strings.TrimSpace(tok[1:])
	}
	return tok, negated
}

func (ctx *parseContext) parseUserMember(rawTok string, lineNum int) audit.Member {
	tok, negated := stripNegation(rawTok)
	m := audit.Member{Negated: negated, Line: lineNum}

	if tok == "" || tok == `""` {
		m.Myself = true
		return m
	}
	val, wasQuoted := unquoteToken(tok)
	if strings.HasPrefix(val, "%:#") {
		if id, err := strconv.Atoi(val[3:]); err == nil && id >= 0 {
			m.NonUnixGID = &id
			return m
		}
		m.NonUnixGroup = val[2:]
		return m
	}
	if strings.HasPrefix(val, "%:") {
		m.NonUnixGroup = val[2:]
		return m
	}
	if strings.HasPrefix(val, "%#") {
		if id, err := strconv.Atoi(val[2:]); err == nil && id >= 0 {
			m.UserGID = &id
			return m
		}
		m.Usergroup = val[1:]
		return m
	}
	if strings.HasPrefix(val, "%") {
		m.Usergroup = val[1:]
		return m
	}
	if strings.HasPrefix(val, "+") {
		m.Netgroup = val[1:]
		return m
	}
	if strings.HasPrefix(val, "#") {
		if id, err := strconv.Atoi(val[1:]); err == nil && id >= 0 {
			m.UserID = &id
			return m
		}
		m.Username = val
		return m
	}
	if !wasQuoted && val != "ALL" && (isAliasIdentifier(val) || (ctx.policy.UserAliases != nil && ctx.policy.UserAliases[val] != nil)) {
		m.UserAlias = val
		return m
	}
	m.Username = val
	return m
}

func (ctx *parseContext) parseRunasUserMember(rawTok string, lineNum int) audit.Member {
	m := ctx.parseUserMember(rawTok, lineNum)
	if m.UserAlias != "" {
		m.RunasAlias = m.UserAlias
		m.UserAlias = ""
	} else if m.Username != "" && m.Username != "ALL" && ctx.policy.RunasAliases != nil && ctx.policy.RunasAliases[m.Username] != nil {
		m.RunasAlias = m.Username
		m.Username = ""
	}
	return m
}

func (ctx *parseContext) parseRunasGroupMember(rawTok string, lineNum int) audit.Member {
	tok, negated := stripNegation(rawTok)
	m := audit.Member{Negated: negated, Line: lineNum}
	val, wasQuoted := unquoteToken(tok)

	if strings.HasPrefix(val, "%:#") {
		if id, err := strconv.Atoi(val[3:]); err == nil && id >= 0 {
			m.NonUnixGID = &id
			return m
		}
	}
	if strings.HasPrefix(val, "%:") {
		m.NonUnixGroup = val[2:]
		return m
	}
	if strings.HasPrefix(val, "%#") {
		if id, err := strconv.Atoi(val[2:]); err == nil && id >= 0 {
			m.UserGID = &id
			return m
		}
	}
	if strings.HasPrefix(val, "%") {
		m.Usergroup = val[1:]
		return m
	}
	if !wasQuoted && val != "ALL" && (isAliasIdentifier(val) || (ctx.policy.RunasAliases != nil && ctx.policy.RunasAliases[val] != nil)) {
		m.RunasAlias = val
		return m
	}
	m.Usergroup = val
	return m
}

func (ctx *parseContext) parseHostMember(rawTok string, lineNum int) audit.Member {
	tok, negated := stripNegation(rawTok)
	m := audit.Member{Negated: negated, Line: lineNum}
	val, wasQuoted := unquoteToken(tok)

	if strings.HasPrefix(val, "+") {
		m.Netgroup = val[1:]
		return m
	}
	if !wasQuoted && isNetworkAddress(val) {
		m.NetworkAddr = val
		return m
	}
	if !wasQuoted && val != "ALL" && (isAliasIdentifier(val) || (ctx.policy.HostAliases != nil && ctx.policy.HostAliases[val] != nil)) {
		m.HostAlias = val
		return m
	}
	m.Hostname = val
	return m
}

func isNetworkAddress(tok string) bool {
	if net.ParseIP(tok) != nil {
		return true
	}
	if _, _, err := net.ParseCIDR(tok); err == nil {
		return true
	}
	if idx := strings.IndexByte(tok, '/'); idx != -1 {
		ipPart := tok[:idx]
		maskPart := tok[idx+1:]
		if net.ParseIP(ipPart) != nil && net.ParseIP(maskPart) != nil {
			return true
		}
	}
	return false
}

func (ctx *parseContext) parseCmndBindingMember(rawTok string, lineNum int) audit.Member {
	tok, negated := stripNegation(rawTok)
	m := audit.Member{Negated: negated, Line: lineNum}
	if tok != "ALL" && (isAliasIdentifier(tok) || (ctx.policy.CommandAliases != nil && ctx.policy.CommandAliases[tok] != nil)) {
		m.CommandAlias = tok
		return m
	}
	m.Command = normalizeCommandSpacing(tok)
	return m
}

func (ctx *parseContext) parseCmndAliasMemberList(s string, filename string, lineNum int) ([]audit.Member, error) {
	entries, err := splitCmndEntries(s)
	if err != nil {
		return nil, fmt.Errorf("%s:%d: %w", filename, lineNum, err)
	}
	var members []audit.Member
	for _, entry := range entries {
		m, err := ctx.parseDigestedCommand(entry, filename, lineNum)
		if err != nil {
			return nil, err
		}
		members = append(members, m)
	}
	return members, nil
}

func isTokenBoundary(s string, i int) bool {
	if i == 0 {
		return true
	}
	prev := s[i-1]
	return prev == ' ' || prev == '\t' || prev == '!' || prev == ',' || prev == ':' || prev == '=' || prev == ')'
}

func isQuoteStartBoundary(s string, i int) bool {
	if i == 0 {
		return true
	}
	prev := s[i-1]
	return prev == ' ' || prev == '\t' || prev == '!' || prev == ',' || prev == ':' || prev == '=' || prev == '('
}

// findRegexEnd locates the closing unescaped '$' of a sudoers regular expression starting with '^' at start.
func findRegexEnd(s string, start int) (int, bool) {
	for j := start + 1; j < len(s); j++ {
		if s[j] == '\\' {
			j++
			continue
		}
		if s[j] == '$' {
			if j+1 == len(s) || s[j+1] == ' ' || s[j+1] == '\t' || s[j+1] == ',' || s[j+1] == ':' {
				return j, true
			}
		}
	}
	return -1, false
}

// splitCmndEntries splits a Cmnd_List or Cmnd_Spec_List on top-level commas (outside parentheses, quotes, and regexes),
// keeping comma-separated digest specifications (e.g. `sha224:..., sha256:... /bin/sh`) attached to their command.
func splitCmndEntries(s string) ([]string, error) {
	var rawParts []string
	start := 0
	inQuotes := false
	parenDepth := 0
	inCmndPath := false

	for i := 0; i < len(s); i++ {
		ch := s[i]
		if ch == '\\' {
			i++
			continue
		}
		if ch == '"' {
			if inQuotes {
				inQuotes = false
			} else if isQuoteStartBoundary(s, i) {
				inQuotes = true
			}
			continue
		}
		if !inQuotes {
			if ch == '^' && parenDepth == 0 && isTokenBoundary(s, i) {
				if endIdx, ok := findRegexEnd(s, i); ok {
					inCmndPath = true
					i = endIdx
					continue
				}
			}
			if ch == '/' && parenDepth == 0 && isTokenBoundary(s, i) {
				inCmndPath = true
			}
			if ch == '(' && !inCmndPath {
				parenDepth++
			} else if ch == ')' && !inCmndPath {
				if parenDepth == 0 {
					return nil, fmt.Errorf("unmatched ')' in command specification")
				}
				parenDepth--
			} else if ch == ',' && parenDepth == 0 {
				rawParts = append(rawParts, strings.TrimSpace(s[start:i]))
				start = i + 1
				inCmndPath = false
			}
		}
	}
	if inQuotes {
		return nil, fmt.Errorf("unterminated quote in command specification")
	}
	if parenDepth != 0 {
		return nil, fmt.Errorf("unterminated '(' in Runas_Spec")
	}
	rawParts = append(rawParts, strings.TrimSpace(s[start:]))

	// Merge any part that ends with only digest specs (no command yet) with the following part
	var merged []string
	var pending string
	for _, part := range rawParts {
		if part == "" {
			return nil, fmt.Errorf("empty command entry")
		}
		if pending != "" {
			pending = pending + ", " + part
		} else {
			pending = part
		}
		if !isOnlyMetadataAndDigests(pending) {
			merged = append(merged, pending)
			pending = ""
		}
	}
	if pending != "" {
		return nil, fmt.Errorf("digest specification missing target command")
	}
	return merged, nil
}

// isOnlyMetadataAndDigests checks if a comma-separated fragment consists solely of optional Runas, tags, options,
// and digest specifications without the actual command token yet.
func isOnlyMetadataAndDigests(fragment string) bool {
	rest := strings.TrimSpace(fragment)
	// Strip optional leading (runas)
	if strings.HasPrefix(rest, "(") {
		closeIdx := findClosingParen(rest)
		if closeIdx == -1 {
			return false
		}
		rest = strings.TrimSpace(rest[closeIdx+1:])
	}
	// Strip any tags or KEY=VAL options
	for rest != "" {
		if _, after, ok := consumeTagOrCmndOption(rest); ok {
			rest = strings.TrimSpace(after)
			continue
		}
		break
	}
	// Strip optional '!'
	for strings.HasPrefix(rest, "!") {
		rest = strings.TrimSpace(rest[1:])
	}
	if rest == "" {
		return false
	}
	// Check if remaining tokens are exclusively digest specs (possibly comma-separated)
	subParts, err := splitCommaOutsideQuotes(rest)
	if err != nil || len(subParts) == 0 {
		return false
	}
	for _, sp := range subParts {
		sp = strings.TrimSpace(sp)
		for strings.HasPrefix(sp, "!") {
			sp = strings.TrimSpace(sp[1:])
		}
		alg, val, after, ok := matchDigestPrefix(sp)
		if !ok || alg == "" || val == "" || strings.TrimSpace(after) != "" {
			return false
		}
	}
	return true
}

func findClosingParen(s string) int {
	inQuotes := false
	depth := 0
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if ch == '\\' {
			i++
			continue
		}
		if ch == '"' {
			inQuotes = !inQuotes
			continue
		}
		if !inQuotes {
			if ch == '(' {
				depth++
			} else if ch == ')' {
				depth--
				if depth == 0 {
					return i
				}
			}
		}
	}
	return -1
}

func matchDigestPrefix(s string) (alg string, digest string, rest string, ok bool) {
	s = strings.TrimSpace(s)
	for _, prefix := range []string{"sha224", "sha256", "sha384", "sha512"} {
		if len(s) > len(prefix) && strings.EqualFold(s[:len(prefix)], prefix) {
			j := skipSpaces(s, len(prefix))
			if j >= len(s) || s[j] != ':' {
				continue
			}
			afterColon := strings.TrimSpace(s[j+1:])
			if afterColon == "" {
				return "", "", "", false
			}
			// Read digest token up to whitespace or comma
			i := 0
			for i < len(afterColon) && afterColon[i] != ' ' && afterColon[i] != '\t' && afterColon[i] != ',' {
				i++
			}
			if i == 0 {
				return "", "", "", false
			}
			return prefix, afterColon[:i], afterColon[i:], true
		}
	}
	return "", "", "", false
}

func (ctx *parseContext) parseDigestedCommand(s string, filename string, lineNum int) (audit.Member, error) {
	rest := strings.TrimSpace(s)
	negated := false

	for strings.HasPrefix(rest, "!") {
		negated = !negated
		rest = strings.TrimSpace(rest[1:])
	}

	var sha224, sha256, sha384, sha512 audit.DigestList
	for {
		alg, dval, after, ok := matchDigestPrefix(rest)
		if !ok {
			break
		}
		switch alg {
		case "sha224":
			sha224 = append(sha224, dval)
		case "sha256":
			sha256 = append(sha256, dval)
		case "sha384":
			sha384 = append(sha384, dval)
		case "sha512":
			sha512 = append(sha512, dval)
		}
		rest = strings.TrimSpace(after)
		if strings.HasPrefix(rest, ",") {
			rest = strings.TrimSpace(rest[1:])
		}
		for strings.HasPrefix(rest, "!") {
			negated = !negated
			rest = strings.TrimSpace(rest[1:])
		}
	}

	for strings.HasPrefix(rest, "!") {
		negated = !negated
		rest = strings.TrimSpace(rest[1:])
	}

	if rest == "" {
		return audit.Member{}, fmt.Errorf("%s:%d: missing command path", filename, lineNum)
	}

	// Validate that any regular expression token starting with '^' has a closing unescaped '$'
	inQ := false
	for i := 0; i < len(rest); i++ {
		if rest[i] == '\\' {
			i++
			continue
		}
		if rest[i] == '"' {
			if inQ {
				inQ = false
			} else if isQuoteStartBoundary(rest, i) {
				inQ = true
			}
			continue
		}
		if !inQ && rest[i] == '^' && isTokenBoundary(rest, i) {
			endIdx, ok := findRegexEnd(rest, i)
			if !ok {
				return audit.Member{}, fmt.Errorf("%s:%d: unterminated regular expression in command %q", filename, lineNum, rest)
			}
			i = endIdx
		}
	}

	normalized := normalizeCommandSpacing(rest)
	m := audit.Member{
		Negated: negated,
		SHA224:  sha224,
		SHA256:  sha256,
		SHA384:  sha384,
		SHA512:  sha512,
		File:    normalizeSourceFile(filename),
		Line:    lineNum,
	}

	// Single-token uppercase identifier (other than ALL) or defined CommandAlias is a cmndalias
	if !strings.ContainsAny(normalized, " \t") && normalized != "ALL" &&
		(isAliasIdentifier(normalized) || (ctx.policy.CommandAliases != nil && ctx.policy.CommandAliases[normalized] != nil)) {
		m.CommandAlias = normalized
	} else {
		m.Command = normalized
	}

	return m, nil
}

func normalizeCommandSpacing(s string) string {
	s = strings.TrimSpace(s)
	var b strings.Builder
	b.Grow(len(s))
	inQuotes := false
	inSpace := false

	for i := 0; i < len(s); i++ {
		ch := s[i]
		if !inQuotes && ch == '^' && isTokenBoundary(s, i) {
			if endIdx, ok := findRegexEnd(s, i); ok {
				if inSpace {
					b.WriteByte(' ')
					inSpace = false
				}
				b.WriteString(s[i : endIdx+1])
				i = endIdx
				continue
			}
		}
		if ch == '\\' && i+1 < len(s) {
			if inSpace {
				b.WriteByte(' ')
				inSpace = false
			}
			next := s[i+1]
			if inQuotes {
				b.WriteByte('\\')
				b.WriteByte(next)
			} else {
				// Preserve escaped whitespace or special characters in command arguments
				b.WriteByte(next)
			}
			i++
			continue
		}
		if ch == '"' {
			if inSpace {
				b.WriteByte(' ')
				inSpace = false
			}
			if inQuotes {
				inQuotes = false
			} else if isQuoteStartBoundary(s, i) {
				inQuotes = true
			}
			b.WriteByte(ch)
			continue
		}
		if !inQuotes && (ch == ' ' || ch == '\t') {
			inSpace = true
			continue
		}
		if inSpace {
			b.WriteByte(' ')
			inSpace = false
		}
		b.WriteByte(ch)
	}
	return b.String()
}

func (ctx *parseContext) parseUserSpecLine(line string, filename string, lineNum int) error {
	eqIdx := findCharOutsideQuotes(line, '=')
	if eqIdx == -1 {
		return fmt.Errorf("%s:%d: syntax error: missing '=' in user specification", filename, lineNum)
	}

	lhs := strings.TrimSpace(line[:eqIdx])
	rhs := strings.TrimSpace(line[eqIdx+1:])
	if lhs == "" || rhs == "" {
		return fmt.Errorf("%s:%d: syntax error: incomplete user specification", filename, lineNum)
	}

	userTokens, hostLHS, err := readLeadingCommaList(lhs)
	if err != nil || len(userTokens) == 0 || strings.TrimSpace(hostLHS) == "" {
		return fmt.Errorf("%s:%d: syntax error: expected User_List and Host_List before '='", filename, lineNum)
	}

	srcFile := normalizeSourceFile(filename)
	var userList []audit.Member
	for _, ut := range userTokens {
		if err := validateMemberToken(ut, true); err != nil {
			return fmt.Errorf("%s:%d: %w", filename, lineNum, err)
		}
		m := ctx.parseUserMember(ut, lineNum)
		m.File = srcFile
		userList = append(userList, m)
	}

	hostList, err := ctx.parseHostMemberList(hostLHS, filename, lineNum)
	if err != nil || len(hostList) == 0 {
		return fmt.Errorf("%s:%d: invalid Host_List in user specification", filename, lineNum)
	}

	// Split rhs into colon-separated `Host_List = Cmnd_Spec_List` clauses if present
	clauses, err := splitHostPrivilegeClauses(hostList, rhs, ctx, filename, lineNum)
	if err != nil {
		return err
	}

	for _, clause := range clauses {
		cmndSpecs, err := ctx.parseCmndSpecList(clause.cmndSpecStr, filename, lineNum)
		if err != nil {
			return err
		}
		for i := range clause.hostList {
			if clause.hostList[i].File == "" {
				clause.hostList[i].File = srcFile
			}
		}
		userCopy := make([]audit.Member, len(userList))
		copy(userCopy, userList)
		ctx.policy.UserSpecs = append(ctx.policy.UserSpecs, audit.UserSpec{
			UserList:  userCopy,
			HostList:  clause.hostList,
			CmndSpecs: cmndSpecs,
			File:      srcFile,
			Line:      lineNum,
		})
	}

	return nil
}

type hostPrivClause struct {
	hostList    []audit.Member
	cmndSpecStr string
}

func splitHostPrivilegeClauses(firstHosts []audit.Member, rhs string, ctx *parseContext, filename string, lineNum int) ([]hostPrivClause, error) {
	var clauses []hostPrivClause
	curHosts := firstHosts
	start := 0
	inQuotes := false
	parenDepth := 0
	inCmndPath := false

	for i := 0; i < len(rhs); i++ {
		ch := rhs[i]
		if ch == '\\' {
			i++
			continue
		}
		if ch == '"' {
			if inQuotes {
				inQuotes = false
			} else if isQuoteStartBoundary(rhs, i) {
				inQuotes = true
			}
			continue
		}
		if !inQuotes {
			if ch == '^' && parenDepth == 0 && isTokenBoundary(rhs, i) {
				if endIdx, ok := findRegexEnd(rhs, i); ok {
					inCmndPath = true
					i = endIdx
					continue
				}
			}
			if ch == '/' && parenDepth == 0 && isTokenBoundary(rhs, i) {
				inCmndPath = true
			}
			if ch == ',' && parenDepth == 0 {
				inCmndPath = false
			}
			if ch == '(' && !inCmndPath {
				parenDepth++
			} else if ch == ')' && !inCmndPath && parenDepth > 0 {
				parenDepth--
			} else if ch == ':' && parenDepth == 0 {
				if !isPrecededByTagOrDigest(rhs[:i]) {
					if nextHosts, eqOffset, ok := tryParseHostListBeforeEquals(rhs[i+1:], ctx, lineNum); ok {
						cmndPart := strings.TrimSpace(rhs[start:i])
						if cmndPart == "" {
							return nil, fmt.Errorf("%s:%d: empty command specification before ':'", filename, lineNum)
						}
						clauses = append(clauses, hostPrivClause{
							hostList:    curHosts,
							cmndSpecStr: cmndPart,
						})
						curHosts = nextHosts
						start = i + 1 + eqOffset
						i = start - 1
						inCmndPath = false
					}
				}
			}
		}
	}

	lastCmnd := strings.TrimSpace(rhs[start:])
	if lastCmnd == "" {
		return nil, fmt.Errorf("%s:%d: empty command specification", filename, lineNum)
	}
	clauses = append(clauses, hostPrivClause{
		hostList:    curHosts,
		cmndSpecStr: lastCmnd,
	})
	return clauses, nil
}

func isPrecededByTagOrDigest(prefix string) bool {
	trimmed := strings.TrimRight(prefix, " \t")
	// Extract the last token before ':'
	idx := len(trimmed) - 1
	for idx >= 0 && ((trimmed[idx] >= 'A' && trimmed[idx] <= 'Z') || (trimmed[idx] >= 'a' && trimmed[idx] <= 'z') || (trimmed[idx] >= '0' && trimmed[idx] <= '9') || trimmed[idx] == '_') {
		idx--
	}
	word := trimmed[idx+1:]
	if word == "" {
		return false
	}
	if _, ok := tagSpecs[word]; ok {
		return true
	}
	lower := strings.ToLower(word)
	return lower == "sha224" || lower == "sha256" || lower == "sha384" || lower == "sha512"
}

func tryParseHostListBeforeEquals(s string, ctx *parseContext, lineNum int) ([]audit.Member, int, bool) {
	tokens, rest, err := readLeadingCommaList(s)
	if err != nil || len(tokens) == 0 {
		return nil, 0, false
	}
	i := skipSpaces(rest, 0)
	if i >= len(rest) || rest[i] != '=' {
		return nil, 0, false
	}
	// Make sure none of the tokens is a Cmnd_Spec KEY=VALUE option (such as ROLE= or CHROOT=)
	if len(tokens) == 1 {
		upper := strings.ToUpper(tokens[0])
		if _, isOpt := cmndOptionKeys[upper]; isOpt {
			return nil, 0, false
		}
	}
	consumed := len(s) - len(rest) + i + 1
	var hosts []audit.Member
	for _, t := range tokens {
		if err := validateMemberToken(t, false); err != nil {
			return nil, 0, false
		}
		hosts = append(hosts, ctx.parseHostMember(t, lineNum))
	}
	return hosts, consumed, true
}

func (ctx *parseContext) parseCmndSpecList(s string, filename string, lineNum int) ([]audit.CmndSpec, error) {
	entries, err := splitCmndEntries(s)
	if err != nil {
		return nil, fmt.Errorf("%s:%d: %w", filename, lineNum, err)
	}

	var specs []audit.CmndSpec
	var curRunasUsers []audit.Member
	var curRunasGroups []audit.Member

	tagSet := make(map[string]bool)
	tagVal := make(map[string]bool)
	optSet := make(map[string]bool)
	optVal := make(map[string]any)

	for idx, entry := range entries {
		rest := strings.TrimSpace(entry)
		hasExplicitRunas := false
		if strings.HasPrefix(rest, "(") {
			closeIdx := findClosingParen(rest)
			if closeIdx == -1 {
				return nil, fmt.Errorf("%s:%d: unterminated '(' in Runas_Spec", filename, lineNum)
			}
			hasExplicitRunas = true
			inside := rest[1:closeIdx]
			rUsers, rGroups, err := ctx.parseRunasInsideParens(inside, filename, lineNum)
			if err != nil {
				return nil, err
			}
			curRunasUsers = rUsers
			curRunasGroups = rGroups
			rest = strings.TrimSpace(rest[closeIdx+1:])
		}

		changedTagOrOpt := false
		for rest != "" {
			tok, after, ok := consumeTagOrCmndOption(rest)
			if !ok {
				break
			}
			rest = strings.TrimSpace(after)
			if strings.HasSuffix(tok, ":") {
				tagName := strings.TrimSuffix(tok, ":")
				def := tagSpecs[tagName]
				if !tagSet[def.key] || tagVal[def.key] != def.val {
					changedTagOrOpt = true
				}
				tagSet[def.key] = true
				tagVal[def.key] = def.val
			} else {
				_, rawKey, rawVal, _ := splitOptionAssignment(tok)
				optKey := cmndOptionKeys[strings.ToUpper(rawKey)]
				unquoted := unquoteOptionValue(rawVal)
				var parsedVal any = unquoted
				switch optKey {
				case "command_timeout":
					if secs, ok := parseTimeoutSeconds(unquoted); ok {
						if secs <= 0 {
							delete(optSet, optKey)
							delete(optVal, optKey)
							continue
						}
						parsedVal = secs
					}
				case "notbefore", "notafter":
					parsedVal = normalizeGeneralizedTime(unquoted)
				}
				// Match cvtsudoers_json.c cmndspec_continues: only runchroot, runcwd, role, type,
				// apparmor_profile, privs, and limitprivs split adjacent commands into a new Cmnd_Spec.
				if optKey != "command_timeout" && optKey != "notbefore" && optKey != "notafter" {
					if !optSet[optKey] || optVal[optKey] != parsedVal {
						changedTagOrOpt = true
					}
				}
				optSet[optKey] = true
				optVal[optKey] = parsedVal
			}
		}

		cmdMember, err := ctx.parseDigestedCommand(rest, filename, lineNum)
		if err != nil {
			return nil, err
		}

		needNewSpec := idx == 0 || hasExplicitRunas || changedTagOrOpt
		if !needNewSpec && len(specs) > 0 {
			specs[len(specs)-1].Commands = append(specs[len(specs)-1].Commands, cmdMember)
			continue
		}

		// Build options list for this new CmndSpec in exact cvtsudoers_json.c order:
		// 1. Pre-tag options (runchroot, runcwd, command_timeout, notbefore, notafter)
		// 2. Tags (authenticate, noexec, intercept, send_mail, setenv, sudoedit_follow, log_input, log_output)
		// 3. Post-tag options (role, type, apparmor_profile, privs, limitprivs)
		var specOptions []audit.Option
		for _, k := range cmndPreTagOptionOrder {
			if optSet[k] {
				specOptions = append(specOptions, audit.Option{k: optVal[k]})
			}
		}
		for _, k := range tagOrder {
			if tagSet[k] {
				specOptions = append(specOptions, audit.Option{k: tagVal[k]})
			} else if k == "setenv" && cmdMember.Command == "ALL" && !cmdMember.Negated {
				// cvtsudoers implies setenv: true when a CmndSpec starts with unnegated ALL
				specOptions = append(specOptions, audit.Option{"setenv": true})
			}
		}
		for _, k := range cmndPostTagOptionOrder {
			if optSet[k] {
				specOptions = append(specOptions, audit.Option{k: optVal[k]})
			}
		}

		var uCopy, gCopy []audit.Member
		if len(curRunasUsers) > 0 {
			uCopy = make([]audit.Member, len(curRunasUsers))
			copy(uCopy, curRunasUsers)
		}
		if len(curRunasGroups) > 0 {
			gCopy = make([]audit.Member, len(curRunasGroups))
			copy(gCopy, curRunasGroups)
		}

		specs = append(specs, audit.CmndSpec{
			RunasUsers:  uCopy,
			RunasGroups: gCopy,
			Options:     specOptions,
			Commands:    []audit.Member{cmdMember},
		})
	}

	return specs, nil
}

func (ctx *parseContext) parseRunasInsideParens(inside string, filename string, lineNum int) ([]audit.Member, []audit.Member, error) {
	srcFile := normalizeSourceFile(filename)
	colonIdx := findRunasColon(inside)
	if colonIdx == -1 {
		trimmed := strings.TrimSpace(inside)
		if trimmed == "" || trimmed == `""` {
			return []audit.Member{{Myself: true, File: srcFile, Line: lineNum}}, nil, nil
		}
		users, err := ctx.parseRunasUserMemberList(trimmed, filename, lineNum)
		if err != nil {
			return nil, nil, err
		}
		return users, nil, nil
	}

	left := strings.TrimSpace(inside[:colonIdx])
	right := strings.TrimSpace(inside[colonIdx+1:])

	var users []audit.Member
	if left == "" || left == `""` {
		users = []audit.Member{{Myself: true, File: srcFile, Line: lineNum}}
	} else {
		var err error
		users, err = ctx.parseRunasUserMemberList(left, filename, lineNum)
		if err != nil {
			return nil, nil, err
		}
	}

	var groups []audit.Member
	if right != "" && right != `""` {
		var err error
		groups, err = ctx.parseRunasGroupMemberList(right, filename, lineNum)
		if err != nil {
			return nil, nil, err
		}
	}

	return users, groups, nil
}

// findRunasColon locates the ':' separating runas users from runas groups inside parentheses,
// ignoring '%:' non-Unix group prefixes and quoted strings.
func findRunasColon(s string) int {
	inQuotes := false
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if ch == '\\' {
			i++
			continue
		}
		if ch == '"' {
			inQuotes = !inQuotes
			continue
		}
		if !inQuotes && ch == ':' {
			if i > 0 && s[i-1] == '%' {
				continue
			}
			return i
		}
	}
	return -1
}

func consumeTagOrCmndOption(s string) (token string, rest string, ok bool) {
	s = strings.TrimLeft(s, " \t")
	if s == "" {
		return "", "", false
	}

	// Read leading word token
	wEnd := 0
	for wEnd < len(s) && ((s[wEnd] >= 'A' && s[wEnd] <= 'Z') || (s[wEnd] >= 'a' && s[wEnd] <= 'z') || (s[wEnd] >= '0' && s[wEnd] <= '9') || s[wEnd] == '_') {
		wEnd++
	}
	if wEnd == 0 {
		return "", "", false
	}
	word := s[:wEnd]
	j := skipSpaces(s, wEnd)
	if j >= len(s) {
		return "", "", false
	}

	// 1. Check for TAG:
	if s[j] == ':' {
		if _, isTag := tagSpecs[word]; isTag {
			return word + ":", s[j+1:], true
		}
		return "", "", false
	}

	// 2. Check for KEY=VALUE option (ROLE=, TYPE=, APPARMOR_PROFILE=, PRIVS=, LIMITPRIVS=, CHROOT=, CWD=, TIMEOUT=, NOTBEFORE=, NOTAFTER=)
	if s[j] == '=' {
		upper := strings.ToUpper(word)
		if _, isOpt := cmndOptionKeys[upper]; isOpt {
			valStart := skipSpaces(s, j+1)
			i := valStart
			inQuotes := false
			for i < len(s) {
				ch := s[i]
				if ch == '\\' {
					i += 2
					continue
				}
				if ch == '"' {
					inQuotes = !inQuotes
					i++
					continue
				}
				if !inQuotes && (ch == ' ' || ch == '\t') {
					break
				}
				i++
			}
			if i == valStart {
				return "", "", false
			}
			return upper + "=" + s[valStart:i], s[i:], true
		}
	}

	return "", "", false
}

// parseTimeoutSeconds parses sudoers timeout strings like "300", "5m", or "1d2h3m4s" into seconds.
func parseTimeoutSeconds(s string) (int, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, false
	}
	if n, err := strconv.Atoi(s); err == nil {
		return n, n >= 0
	}
	total := 0
	i := 0
	var seenD, seenH, seenM, seenS bool
	for i < len(s) {
		start := i
		for i < len(s) && s[i] >= '0' && s[i] <= '9' {
			i++
		}
		if i == start || i >= len(s) {
			return 0, false
		}
		val, err := strconv.Atoi(s[start:i])
		if err != nil {
			return 0, false
		}
		unit := s[i]
		i++
		switch unit {
		case 'd', 'D':
			if seenD {
				return 0, false
			}
			seenD = true
			total += val * 86400
		case 'h', 'H':
			if seenH {
				return 0, false
			}
			seenH = true
			total += val * 3600
		case 'm', 'M':
			if seenM {
				return 0, false
			}
			seenM = true
			total += val * 60
		case 's', 'S':
			if seenS {
				return 0, false
			}
			seenS = true
			total += val
		default:
			return 0, false
		}
	}
	return total, true
}

// normalizeGeneralizedTime parses ASN.1 GeneralizedTime timestamps used by NOTBEFORE/NOTAFTER
// (YYYYMMDDHH[MM[SS]][(.|,)frac][Z|(+|-)HH[MM]]) and normalizes them to UTC "%Y%m%d%H%M%SZ".
func normalizeGeneralizedTime(s string) string {
	s = strings.TrimSpace(s)
	if len(s) < 10 {
		return s
	}
	for i := 0; i < 10; i++ {
		if s[i] < '0' || s[i] > '9' {
			return s
		}
	}
	year, _ := strconv.Atoi(s[0:4])
	month, _ := strconv.Atoi(s[4:6])
	day, _ := strconv.Atoi(s[6:8])
	hour, _ := strconv.Atoi(s[8:10])
	min := 0
	sec := 0
	i := 10
	lastUnit := 'h'

	if i+2 <= len(s) && s[i] >= '0' && s[i] <= '9' && s[i+1] >= '0' && s[i+1] <= '9' {
		min, _ = strconv.Atoi(s[i : i+2])
		i += 2
		lastUnit = 'm'
		if i+2 <= len(s) && s[i] >= '0' && s[i] <= '9' && s[i+1] >= '0' && s[i+1] <= '9' {
			sec, _ = strconv.Atoi(s[i : i+2])
			i += 2
			lastUnit = 's'
		}
	}

	extraSecs := 0
	if i < len(s) && (s[i] == '.' || s[i] == ',') {
		i++
		fStart := i
		for i < len(s) && s[i] >= '0' && s[i] <= '9' {
			i++
		}
		if i == fStart {
			return s
		}
		if frac, err := strconv.ParseFloat("0."+s[fStart:i], 64); err == nil {
			switch lastUnit {
			case 'h':
				extraSecs = int(frac * 3600)
			case 'm':
				extraSecs = int(frac * 60)
			}
		}
	}

	loc := time.Local
	if i < len(s) {
		if s[i:] == "Z" {
			loc = time.UTC
		} else if (s[i] == '+' || s[i] == '-') && (len(s[i+1:]) == 2 || len(s[i+1:]) == 4) {
			sign := 1
			if s[i] == '-' {
				sign = -1
			}
			tzStr := s[i+1:]
			for k := 0; k < len(tzStr); k++ {
				if tzStr[k] < '0' || tzStr[k] > '9' {
					return s
				}
			}
			tzH, _ := strconv.Atoi(tzStr[0:2])
			tzM := 0
			if len(tzStr) == 4 {
				tzM, _ = strconv.Atoi(tzStr[2:4])
			}
			loc = time.FixedZone("", sign*(tzH*3600+tzM*60))
		} else {
			return s
		}
	}

	t := time.Date(year, time.Month(month), day, hour, min, sec, 0, loc).Add(time.Duration(extraSecs) * time.Second)
	return t.UTC().Format("20060102150405Z")
}
