package audit

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path"
	"regexp"
	"runtime"
	"strings"
)

var scriptAuditShellNames = map[string]bool{
	"sh":   true,
	"bash": true,
	"dash": true,
	"ash":  true,
	"ksh":  true,
	"zsh":  true,
}

var scriptAuditSkipTokens = map[string]bool{
	"if": true, "then": true, "else": true, "elif": true, "fi": true,
	"for": true, "while": true, "until": true, "do": true, "done": true,
	"case": true, "esac": true, "in": true, "select": true,
	"function": true, "time": true, "coproc": true,
	"set": true, "export": true, "local": true, "readonly": true,
	"declare": true, "typeset": true, "umask": true, "unset": true,
	"shift": true, "return": true, "exit": true, "break": true, "continue": true,
	"echo": true, "printf": true, "test": true, "[": true, "[[": true, "]": true, "]]": true,
	"true": true, "false": true, ":": true, "cd": true, "pwd": true,
	"read": true, "trap": true, "exec": true, ".": true, "source": true,
	"eval": true, "command": true, "builtin": true, "hash": true, "type": true,
	"alias": true, "unalias": true, "wait": true, "getopts": true, "let": true,
	"shopt": true, "ulimit": true, "pushd": true, "popd": true, "dirs": true,
	"bg": true, "fg": true, "jobs": true, "disown": true, "enable": true,
	"help": true, "logout": true, "mapfile": true, "readarray": true,
	"!": true, "{": true, "}": true, "(": true, ")": true, ";;": true, ";&": true, ";;&": true,
}

var scriptAuditWritablePrefixes = []string{
	"/tmp/",
	"/var/tmp/",
	"/home/",
	"/dev/shm/",
	"/run/user/",
}

var scriptAuditFuncParenRegex = regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_]*)\s*\(\s*\)\s*(?:\{(.*))?$`)
var scriptAuditFuncKeywordRegex = regexp.MustCompile(`^function\s+([A-Za-z_][A-Za-z0-9_]*)(?:\s*\(\s*\))?\s*(?:\{(.*))?$`)
var scriptAuditAssignPrefixRegex = regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_]*)=`)

type scriptAuditToken struct {
	raw                   string
	text                  string
	hasExpandedPositional bool
	hasUnquotedPositional bool
	isAssignment          bool
	assignName            string
	assignValue           string
	isRedirection         bool
}

// AnalyzeScriptContent inspects text scripts starting with "#!" for PATH-dependent
// execution, unsafe positional parameter evaluation/expansion, and sourcing from
// relative or writable paths. Empty, non-"#!", and binary inputs return nil.
func AnalyzeScriptContent(scriptPath string, content []byte) []Finding {
	if len(content) == 0 || !bytes.HasPrefix(content, []byte("#!")) || bytes.IndexByte(content, 0) >= 0 {
		return nil
	}

	normalized := strings.ReplaceAll(string(content), "\r\n", "\n")
	lines := strings.Split(normalized, "\n")
	if len(lines) == 0 {
		return nil
	}

	interpPath, shellName, usesEnv, ok := scriptAuditParseShebang(lines[0])
	if !ok {
		return nil
	}

	var findings []Finding
	emitted001 := false

	if usesEnv {
		findings = append(findings, Finding{
			ID:              "SUDO-SYS-SCRIPT-001",
			Title:           "Path-Dependent Shebang Interpreter (/usr/bin/env)",
			Description:     fmt.Sprintf("The script '%s' uses '%s' in its shebang, resolving the interpreter via PATH instead of an explicit absolute binary path.", scriptPath, interpPath),
			Severity:        SeverityHigh,
			Command:         scriptPath,
			Context:         scriptPath,
			Line:            1,
			Remediation:     "Replace '/usr/bin/env' in the shebang with an explicit absolute interpreter path and define a secure PATH at the top of the script.",
			RemediationCode: scriptAuditEnvRemediationCode(shellName),
		})
		emitted001 = true
	}

	if shellName == "" {
		return findings
	}

	hasExplicitPATH := false
	funcNames := make(map[string]bool)
	caseDepth := 0
	heredocDelim := ""
	heredocStripTabs := false
	emitted002Lines := make(map[int]bool)
	emitted003Lines := make(map[int]bool)

	for idx := 1; idx < len(lines); idx++ {
		rawLine := strings.TrimSuffix(lines[idx], "\r")
		if heredocDelim != "" {
			candidate := rawLine
			if heredocStripTabs {
				candidate = strings.TrimLeft(candidate, "\t")
			}
			if candidate == heredocDelim {
				heredocDelim = ""
				heredocStripTabs = false
			}
			continue
		}

		startLine := idx + 1
		logical := scriptAuditStripComment(rawLine)
		for scriptAuditHasTrailingContinuation(logical) && idx+1 < len(lines) {
			idx++
			nextRaw := strings.TrimSuffix(lines[idx], "\r")
			nextCleaned := scriptAuditStripComment(nextRaw)
			logical = logical[:len(logical)-1] + " " + nextCleaned
		}

		if d, strip, found := scriptAuditDetectHeredoc(logical); found {
			heredocDelim = d
			heredocStripTabs = strip
		}

		if strings.TrimSpace(logical) == "" {
			continue
		}

		stmts := scriptAuditSplitStatements(logical)
		for _, stmt := range stmts {
			stmtFindings := scriptAuditAnalyzeStatement(
				scriptPath,
				startLine,
				stmt,
				funcNames,
				&caseDepth,
				&hasExplicitPATH,
				&emitted001,
				emitted002Lines,
				emitted003Lines,
			)
			findings = append(findings, stmtFindings...)
		}
	}

	return findings
}

func scriptAuditEnvRemediationCode(shellName string) string {
	const shellSnippet = "#!/bin/bash\nexport PATH=\"/usr/sbin:/usr/bin:/sbin:/bin\""
	if shellName != "" {
		return shellSnippet
	}
	return "#!/bin/bash\nexport PATH=\"/usr/sbin:/usr/bin:/sbin:/bin\"\n# Or pin the exact absolute interpreter path (for example #!/usr/bin/python3)"
}

func scriptAuditParseShebang(firstLine string) (interpPath string, shellName string, usesEnv bool, ok bool) {
	trimmedLine := strings.TrimSuffix(strings.TrimSpace(firstLine), "\r")
	if !strings.HasPrefix(trimmedLine, "#!") {
		return "", "", false, false
	}
	rest := strings.TrimSpace(trimmedLine[2:])
	fields := strings.Fields(rest)
	if len(fields) == 0 {
		return "", "", false, false
	}

	interpPath = fields[0]
	base := path.Base(interpPath)
	if interpPath == "/usr/bin/env" || interpPath == "/bin/env" || base == "env" {
		usesEnv = true
		skipNext := false
		for _, arg := range fields[1:] {
			if skipNext {
				skipNext = false
				continue
			}
			if arg == "-u" || arg == "--unset" || arg == "-C" || arg == "--chdir" {
				skipNext = true
				continue
			}
			if strings.HasPrefix(arg, "-") || strings.Contains(arg, "=") {
				continue
			}
			targetBase := path.Base(arg)
			if scriptAuditShellNames[targetBase] {
				shellName = targetBase
			}
			break
		}
		return interpPath, shellName, usesEnv, true
	}

	if scriptAuditShellNames[base] {
		shellName = base
	}
	return interpPath, shellName, false, true
}

func scriptAuditEvaluateInterpreter(scriptPath, interpPath string, fullMode os.FileMode, ownerUID int, hasOwner bool) []Finding {
	mode := fullMode.Perm()
	if mode&0022 != 0 {
		return []Finding{
			{
				ID:              "SUDO-SYS-SCRIPT-003",
				Title:           "Writable Shebang Interpreter for Sudo Script",
				Description:     fmt.Sprintf("The script '%s' uses shebang interpreter '%s' with writable permissions (%s). Unprivileged modification of the interpreter grants arbitrary code execution when the script runs under sudo.", scriptPath, interpPath, mode),
				Severity:        SeverityCritical,
				Command:         scriptPath,
				Context:         scriptPath,
				Line:            1,
				Remediation:     fmt.Sprintf("Secure '%s' ownership and permissions with root ownership and non-writable mode 0755.", interpPath),
				RemediationCode: fmt.Sprintf("sudo chown root:root %s\nsudo chmod 0755 %s", interpPath, interpPath),
			},
		}
	}
	if hasOwner && ownerUID != 0 {
		return []Finding{
			{
				ID:              "SUDO-SYS-SCRIPT-003",
				Title:           "Shebang Interpreter Not Owned by Root",
				Description:     fmt.Sprintf("The script '%s' uses shebang interpreter '%s' owned by non-root UID %d. Compromise of UID %d allows replacing the interpreter to hijack privileged execution.", scriptPath, interpPath, ownerUID, ownerUID),
				Severity:        SeverityHigh,
				Command:         scriptPath,
				Context:         scriptPath,
				Line:            1,
				Remediation:     fmt.Sprintf("Change ownership of '%s' to root:root and ensure permissions are 0755.", interpPath),
				RemediationCode: fmt.Sprintf("sudo chown root:root %s\nsudo chmod 0755 %s", interpPath, interpPath),
			},
		}
	}
	return nil
}

// AuditPolicyTargetScripts inspects target scripts referenced in sudoers User_Specs
// on live Unix systems for shebang, PATH, injection, sourcing, and interpreter safety.
func AuditPolicyTargetScripts(policy *SudoersPolicy) []Finding {
	if runtime.GOOS == "windows" || policy == nil {
		return nil
	}

	var findings []Finding
	checked := make(map[string]bool)

	for _, spec := range policy.UserSpecs {
		for _, cs := range spec.CmndSpecs {
			var allCmds []Member
			for _, m := range cs.Commands {
				allCmds = append(allCmds, resolveCommands(m, policy)...)
			}
			for _, m := range allCmds {
				if m.Negated || m.Command == "" || m.Command == "ALL" {
					continue
				}
				parts := splitCommandTokens(m.Command)
				if len(parts) == 0 {
					continue
				}
				exePath := parts[0]
				if !strings.HasPrefix(exePath, "/") || wildcardRegex.MatchString(exePath) {
					continue
				}
				if checked[exePath] {
					continue
				}
				checked[exePath] = true

				info, err := os.Stat(exePath)
				if err != nil || !info.Mode().IsRegular() {
					continue
				}

				f, err := os.Open(exePath)
				if err != nil {
					continue
				}
				data, readErr := io.ReadAll(io.LimitReader(f, 256*1024))
				_ = f.Close()
				if readErr != nil || !bytes.HasPrefix(data, []byte("#!")) {
					continue
				}

				findings = append(findings, AnalyzeScriptContent(exePath, data)...)

				firstLine := string(data)
				if nl := strings.IndexByte(firstLine, '\n'); nl >= 0 {
					firstLine = firstLine[:nl]
				}
				interpPath, _, _, ok := scriptAuditParseShebang(firstLine)
				if ok && strings.HasPrefix(interpPath, "/") {
					if iInfo, iErr := os.Stat(interpPath); iErr == nil {
						iUID, _, iOwnerErr := getUnixOwner(iInfo)
						findings = append(findings, scriptAuditEvaluateInterpreter(exePath, interpPath, iInfo.Mode(), iUID, iOwnerErr == nil)...)
					}
				}
			}
		}
	}

	return findings
}

func scriptAuditHasTrailingContinuation(line string) bool {
	if line == "" {
		return false
	}
	bsCount := 0
	for i := len(line) - 1; i >= 0 && line[i] == '\\'; i-- {
		bsCount++
	}
	return bsCount%2 == 1
}

func scriptAuditStripComment(line string) string {
	inSingle := false
	inDouble := false
	escaped := false

	for i := 0; i < len(line); i++ {
		ch := line[i]
		if escaped {
			escaped = false
			continue
		}
		if inSingle {
			if ch == '\'' {
				inSingle = false
			}
			continue
		}
		if ch == '\\' {
			escaped = true
			continue
		}
		if inDouble {
			if ch == '"' {
				inDouble = false
			}
			continue
		}
		if ch == '\'' {
			inSingle = true
			continue
		}
		if ch == '"' {
			inDouble = true
			continue
		}
		if ch == '#' {
			if i == 0 || line[i-1] == ' ' || line[i-1] == '\t' || line[i-1] == ';' || line[i-1] == '&' || line[i-1] == '|' || line[i-1] == '(' {
				return strings.TrimRight(line[:i], " \t")
			}
		}
	}
	return line
}

func scriptAuditDetectHeredoc(line string) (delim string, stripTabs bool, found bool) {
	inSingle := false
	inDouble := false
	escaped := false

	for i := 0; i < len(line); i++ {
		ch := line[i]
		if escaped {
			escaped = false
			continue
		}
		if inSingle {
			if ch == '\'' {
				inSingle = false
			}
			continue
		}
		if ch == '\\' {
			escaped = true
			continue
		}
		if inDouble {
			if ch == '"' {
				inDouble = false
			}
			continue
		}
		if ch == '\'' {
			inSingle = true
			continue
		}
		if ch == '"' {
			inDouble = true
			continue
		}
		if ch == '<' && i+1 < len(line) && line[i+1] == '<' {
			// Skip here-strings (<<<) and bit-shift/unknown operators.
			if i+2 < len(line) && (line[i+2] == '<' || line[i+2] == '=') {
				i += 2
				continue
			}
			j := i + 2
			strip := false
			if j < len(line) && line[j] == '-' {
				strip = true
				j++
			}
			for j < len(line) && (line[j] == ' ' || line[j] == '\t') {
				j++
			}
			if j >= len(line) {
				return "", false, false
			}
			var b strings.Builder
			if line[j] == '\'' || line[j] == '"' {
				q := line[j]
				j++
				for j < len(line) && line[j] != q {
					if q == '"' && line[j] == '\\' && j+1 < len(line) {
						j++
					}
					b.WriteByte(line[j])
					j++
				}
			} else {
				for j < len(line) {
					c := line[j]
					if c == ' ' || c == '\t' || c == ';' || c == '&' || c == '|' || c == '<' || c == '>' || c == ')' {
						break
					}
					if c == '\\' && j+1 < len(line) {
						j++
						b.WriteByte(line[j])
						j++
						continue
					}
					b.WriteByte(c)
					j++
				}
			}
			d := b.String()
			if d != "" {
				return d, strip, true
			}
		}
	}
	return "", false, false
}

func scriptAuditSplitStatements(line string) []string {
	var stmts []string
	var subshells []string

	inSingle := false
	inDouble := false
	inDoubleBracket := false
	escaped := false
	parenDepth := 0
	arithDepth := 0
	start := 0

	isBoundaryBefore := func(idx int) bool {
		if idx == 0 {
			return true
		}
		p := line[idx-1]
		return p == ' ' || p == '\t' || p == ';' || p == '&' || p == '|' || p == '(' || p == '{'
	}
	isBoundaryAfter := func(idx int) bool {
		if idx >= len(line) {
			return true
		}
		n := line[idx]
		return n == ' ' || n == '\t' || n == ';' || n == '&' || n == '|' || n == ')' || n == '}'
	}

	flush := func(end int) {
		part := strings.TrimSpace(line[start:end])
		if part != "" {
			stmts = append(stmts, part)
		}
	}

	for i := 0; i < len(line); i++ {
		ch := line[i]
		if escaped {
			escaped = false
			continue
		}
		if inSingle {
			if ch == '\'' {
				inSingle = false
			}
			continue
		}
		if ch == '\\' {
			escaped = true
			continue
		}

		// Extract $(...) command substitutions (skipping $((...)) arithmetic).
		if ch == '$' && i+1 < len(line) && line[i+1] == '(' {
			if i+2 < len(line) && line[i+2] == '(' {
				arithDepth++
				i += 2
				continue
			}
			body, endIdx := scriptAuditReadCommandSub(line, i+2)
			if endIdx >= i+2 {
				if strings.TrimSpace(body) != "" {
					subshells = append(subshells, scriptAuditSplitStatements(body)...)
				}
				i = endIdx
				continue
			}
		}

		if ch == '`' {
			body, endIdx := scriptAuditReadBacktick(line, i+1)
			if endIdx > i {
				if strings.TrimSpace(body) != "" {
					subshells = append(subshells, scriptAuditSplitStatements(body)...)
				}
				i = endIdx
				continue
			}
		}

		if inDouble {
			if ch == '"' {
				inDouble = false
			}
			continue
		}

		if ch == '\'' {
			inSingle = true
			continue
		}
		if ch == '"' {
			inDouble = true
			continue
		}

		if arithDepth > 0 {
			if ch == ')' && i+1 < len(line) && line[i+1] == ')' {
				arithDepth--
				i++
			}
			continue
		}

		if ch == '(' {
			parenDepth++
			continue
		}
		if ch == ')' {
			if parenDepth > 0 {
				parenDepth--
			}
			continue
		}

		if parenDepth > 0 {
			continue
		}

		if !inDoubleBracket && ch == '[' && i+1 < len(line) && line[i+1] == '[' && isBoundaryBefore(i) && isBoundaryAfter(i+2) {
			inDoubleBracket = true
			i++
			continue
		}
		if inDoubleBracket && ch == ']' && i+1 < len(line) && line[i+1] == ']' && isBoundaryBefore(i) && isBoundaryAfter(i+2) {
			inDoubleBracket = false
			i++
			continue
		}
		if inDoubleBracket {
			continue
		}

		if ch == ';' {
			if i+1 < len(line) && (line[i+1] == ';' || line[i+1] == '&') {
				flush(i)
				if i+2 < len(line) && line[i+2] == '&' {
					i += 2
				} else {
					i++
				}
				start = i + 1
				continue
			}
			flush(i)
			start = i + 1
			continue
		}

		if ch == '|' {
			flush(i)
			if i+1 < len(line) && line[i+1] == '|' {
				i++
			}
			start = i + 1
			continue
		}

		if ch == '&' {
			// Skip redirection forms like >&2, 2>&1, &>.
			isRedir := (i > 0 && (line[i-1] == '>' || line[i-1] == '<')) || (i+1 < len(line) && line[i+1] == '>')
			if !isRedir {
				flush(i)
				if i+1 < len(line) && line[i+1] == '&' {
					i++
				}
				start = i + 1
				continue
			}
		}
	}

	flush(len(line))
	stmts = append(stmts, subshells...)
	return stmts
}

func scriptAuditReadCommandSub(s string, start int) (string, int) {
	depth := 1
	inSingle := false
	inDouble := false
	escaped := false

	for i := start; i < len(s); i++ {
		ch := s[i]
		if escaped {
			escaped = false
			continue
		}
		if inSingle {
			if ch == '\'' {
				inSingle = false
			}
			continue
		}
		if ch == '\\' {
			escaped = true
			continue
		}
		if inDouble {
			if ch == '"' {
				inDouble = false
			}
			continue
		}
		if ch == '\'' {
			inSingle = true
			continue
		}
		if ch == '"' {
			inDouble = true
			continue
		}
		if ch == '(' {
			depth++
		} else if ch == ')' {
			depth--
			if depth == 0 {
				return s[start:i], i
			}
		}
	}
	return "", start
}

func scriptAuditReadBacktick(s string, start int) (string, int) {
	escaped := false
	for i := start; i < len(s); i++ {
		ch := s[i]
		if escaped {
			escaped = false
			continue
		}
		if ch == '\\' {
			escaped = true
			continue
		}
		if ch == '`' {
			return s[start:i], i
		}
	}
	return "", start
}

func scriptAuditConsumeArith(s string, start int) int {
	depth := 1
	for i := start; i < len(s); i++ {
		if s[i] == '(' && i+1 < len(s) && s[i+1] == '(' {
			depth++
			i++
			continue
		}
		if s[i] == ')' && i+1 < len(s) && s[i+1] == ')' {
			depth--
			if depth == 0 {
				return i + 1
			}
			i++
			continue
		}
	}
	return len(s) - 1
}

func scriptAuditTokenize(stmt string) []scriptAuditToken {
	var tokens []scriptAuditToken
	n := len(stmt)
	i := 0

	for i < n {
		for i < n && (stmt[i] == ' ' || stmt[i] == '\t') {
			i++
		}
		if i >= n {
			break
		}

		tokStart := i
		var textBuf strings.Builder
		inSingle := false
		inDouble := false
		escaped := false
		hasExpPos := false
		hasUnqPos := false

		for i < n {
			ch := stmt[i]
			if escaped {
				textBuf.WriteByte(ch)
				escaped = false
				i++
				continue
			}
			if inSingle {
				if ch == '\'' {
					inSingle = false
					i++
					continue
				}
				textBuf.WriteByte(ch)
				i++
				continue
			}
			if ch == '\\' {
				escaped = true
				i++
				continue
			}
			if inDouble {
				if ch == '"' {
					inDouble = false
					i++
					continue
				}
				if ch == '$' && i+1 < n && stmt[i+1] == '(' {
					if i+2 < n && stmt[i+2] == '(' {
						endIdx := scriptAuditConsumeArith(stmt, i+3)
						textBuf.WriteString(stmt[i : endIdx+1])
						i = endIdx + 1
						continue
					}
					_, endIdx := scriptAuditReadCommandSub(stmt, i+2)
					if endIdx >= i+2 {
						textBuf.WriteString(stmt[i : endIdx+1])
						i = endIdx + 1
						continue
					}
				}
				if ch == '`' {
					_, endIdx := scriptAuditReadBacktick(stmt, i+1)
					if endIdx > i {
						textBuf.WriteString(stmt[i : endIdx+1])
						i = endIdx + 1
						continue
					}
				}
				if ch == '$' && scriptAuditCheckPositionalAt(stmt, i, false) {
					hasExpPos = true
				}
				textBuf.WriteByte(ch)
				i++
				continue
			}

			// Outside quotes:
			if ch == ' ' || ch == '\t' {
				break
			}
			if ch == '\'' {
				inSingle = true
				i++
				continue
			}
			if ch == '"' {
				inDouble = true
				i++
				continue
			}
			if ch == '$' && i+1 < n && stmt[i+1] == '(' {
				if i+2 < n && stmt[i+2] == '(' {
					endIdx := scriptAuditConsumeArith(stmt, i+3)
					textBuf.WriteString(stmt[i : endIdx+1])
					i = endIdx + 1
					continue
				}
				_, endIdx := scriptAuditReadCommandSub(stmt, i+2)
				if endIdx >= i+2 {
					textBuf.WriteString(stmt[i : endIdx+1])
					i = endIdx + 1
					continue
				}
			}
			if ch == '`' {
				_, endIdx := scriptAuditReadBacktick(stmt, i+1)
				if endIdx > i {
					textBuf.WriteString(stmt[i : endIdx+1])
					i = endIdx + 1
					continue
				}
			}
			if ch == '$' && scriptAuditCheckPositionalAt(stmt, i, false) {
				hasExpPos = true
				hasUnqPos = true
			}
			textBuf.WriteByte(ch)
			i++
		}

		raw := stmt[tokStart:i]
		text := textBuf.String()
		tok := scriptAuditToken{
			raw:                   raw,
			text:                  text,
			hasExpandedPositional: hasExpPos,
			hasUnquotedPositional: hasUnqPos,
		}
		if m := scriptAuditAssignPrefixRegex.FindStringSubmatch(raw); len(m) == 2 {
			tok.isAssignment = true
			tok.assignName = m[1]
			if eqIdx := strings.IndexByte(text, '='); eqIdx >= 0 {
				tok.assignValue = text[eqIdx+1:]
			}
		}
		if scriptAuditIsRedirToken(raw) {
			tok.isRedirection = true
		}
		tokens = append(tokens, tok)
	}

	return tokens
}

func scriptAuditIsRedirToken(raw string) bool {
	if raw == "" {
		return false
	}
	s := raw
	i := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	if i >= len(s) {
		return false
	}
	return s[i] == '>' || s[i] == '<'
}

// scriptAuditCheckPositionalAt checks whether s[idx] == '$' introduces a positional
// parameter ($1..$9, $@, $*, ${1}, ${@}, ${*}, ${1:-...}).
// Numeric arg count $# and length forms ${#1}, ${#@}, ${#*} are intentionally excluded.
func scriptAuditCheckPositionalAt(s string, idx int, inArith bool) bool {
	_ = inArith
	if idx+1 >= len(s) {
		return false
	}
	next := s[idx+1]
	if (next >= '1' && next <= '9') || next == '@' || next == '*' {
		return true
	}
	if next == '{' && idx+2 < len(s) {
		inner := s[idx+2]
		if (inner >= '1' && inner <= '9') || inner == '@' || inner == '*' {
			return true
		}
	}
	return false
}

func scriptAuditAnalyzeStatement(
	scriptPath string,
	lineNum int,
	stmt string,
	funcNames map[string]bool,
	caseDepth *int,
	hasExplicitPATH *bool,
	emitted001 *bool,
	emitted002Lines map[int]bool,
	emitted003Lines map[int]bool,
) []Finding {
	trimmed := strings.TrimSpace(stmt)
	if trimmed == "" {
		return nil
	}

	// Detect and register shell function headers, analyzing any inline body after '{'.
	if m := scriptAuditFuncParenRegex.FindStringSubmatch(trimmed); len(m) >= 2 {
		funcNames[m[1]] = true
		if len(m) >= 3 && strings.TrimSpace(m[2]) != "" {
			trimmed = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(m[2]), "}"))
		} else {
			return nil
		}
	} else if m := scriptAuditFuncKeywordRegex.FindStringSubmatch(trimmed); len(m) >= 2 {
		funcNames[m[1]] = true
		if len(m) >= 3 && strings.TrimSpace(m[2]) != "" {
			trimmed = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(m[2]), "}"))
		} else {
			return nil
		}
	}

	// Strip case pattern prefix (e.g., "start)" or "*)") when inside a case block.
	if *caseDepth > 0 {
		if stripped, ok := scriptAuditStripCasePattern(trimmed); ok {
			trimmed = stripped
			if trimmed == "" {
				return nil
			}
		}
	}

	toks := scriptAuditTokenize(trimmed)
	if len(toks) == 0 {
		return nil
	}

	// Strip standalone redirection tokens (e.g., "> /dev/null", "2>&1").
	toks = scriptAuditFilterRedirections(toks)
	if len(toks) == 0 {
		return nil
	}

	// Track case / esac boundaries and strip compound-statement prefix keywords.
	for len(toks) > 0 {
		first := toks[0].text
		if first == "case" {
			*caseDepth++
			return nil
		}
		if first == "esac" {
			if *caseDepth > 0 {
				*caseDepth--
			}
			toks = toks[1:]
			continue
		}
		if first == "if" || first == "elif" || first == "while" || first == "until" ||
			first == "then" || first == "else" || first == "do" || first == "!" || first == "{" || first == "time" {
			toks = toks[1:]
			continue
		}
		break
	}
	if len(toks) == 0 {
		return nil
	}

	// Handle "for var in <words>" and "select var in <words>".
	if toks[0].text == "for" || toks[0].text == "select" {
		for idx, tok := range toks {
			if tok.text == "in" {
				for _, w := range toks[idx+1:] {
					if w.hasUnquotedPositional && !emitted002Lines[lineNum] {
						emitted002Lines[lineNum] = true
						return []Finding{scriptAuditMake002Finding(scriptPath, lineNum, "Unquoted positional argument expansion in loop list")}
					}
				}
				break
			}
		}
		return nil
	}

	var findings []Finding

	// Handle leading variable assignments (e.g., PATH=/usr/bin:/bin or FOO=bar cmd).
	for len(toks) > 0 && toks[0].isAssignment {
		if scriptAuditIsSafeExplicitPATHAssignment(toks[0]) {
			*hasExplicitPATH = true
		}
		toks = toks[1:]
	}
	if len(toks) == 0 {
		return findings
	}

	// Handle export / readonly / declare / typeset / local variable declarations.
	cmdText := toks[0].text
	if cmdText == "export" || cmdText == "readonly" || cmdText == "declare" || cmdText == "typeset" || cmdText == "local" {
		for _, arg := range toks[1:] {
			if arg.isAssignment && scriptAuditIsSafeExplicitPATHAssignment(arg) {
				*hasExplicitPATH = true
			}
		}
		return findings
	}

	// Strip trailing brace if inline block ended on this statement.
	if toks[len(toks)-1].text == "}" {
		toks = toks[:len(toks)-1]
		if len(toks) == 0 {
			return findings
		}
	}

	cmdTok := toks[0]
	args := toks[1:]

	// SUDO-SYS-SCRIPT-003: Sourcing relative paths or writable directories.
	if cmdTok.text == "." || cmdTok.text == "source" {
		if len(args) > 0 {
			target := args[0].text
			if scriptAuditIsUnsafeSourceTarget(target) && !emitted003Lines[lineNum] {
				emitted003Lines[lineNum] = true
				findings = append(findings, Finding{
					ID:          "SUDO-SYS-SCRIPT-003",
					Title:       "Unsafe Script Source Path",
					Description: fmt.Sprintf("The script '%s' sources '%s' at line %d using a relative path or a path inside a user-writable directory. Attackers can place a malicious file at that location to execute arbitrary code when the script runs under sudo.", scriptPath, target, lineNum),
					Severity:    SeverityHigh,
					Command:     scriptPath,
					Context:     scriptPath,
					Line:        lineNum,
					Remediation: "Source only root-owned configuration files using absolute paths under '/etc/' or '/usr/local/lib/'.",
					RemediationCode: "if [ -r /etc/myapp/config.env ]; then\n" +
						"    . /etc/myapp/config.env\n" +
						"fi",
				})
			}
		}
	}

	// SUDO-SYS-SCRIPT-002: Positional argument injection via eval, sh -c, command position, or unquoted expansion.
	if reason, triggered := scriptAuditCheckInjection(cmdTok, args); triggered && !emitted002Lines[lineNum] {
		emitted002Lines[lineNum] = true
		findings = append(findings, scriptAuditMake002Finding(scriptPath, lineNum, reason))
	}

	// SUDO-SYS-SCRIPT-001: Unqualified external command invocation prior to an explicit PATH assignment.
	if !*hasExplicitPATH && !*emitted001 {
		if !cmdTok.hasExpandedPositional &&
			!strings.HasPrefix(cmdTok.text, "$") &&
			!strings.Contains(cmdTok.text, "/") &&
			!scriptAuditSkipTokens[cmdTok.text] &&
			!funcNames[cmdTok.text] &&
			scriptAuditLooksLikeCommandName(cmdTok.text) {
			*emitted001 = true
			findings = append(findings, Finding{
				ID:              "SUDO-SYS-SCRIPT-001",
				Title:           "Unqualified Command Invocation Without Explicit PATH",
				Description:     fmt.Sprintf("The script '%s' invokes unqualified command '%s' at line %d before setting an explicit PATH. If PATH is inherited or manipulated, an attacker-controlled binary may be executed instead.", scriptPath, cmdTok.text, lineNum),
				Severity:        SeverityHigh,
				Command:         scriptPath,
				Context:         scriptPath,
				Line:            lineNum,
				Remediation:     "Set an explicit secure PATH (e.g. export PATH=\"/usr/sbin:/usr/bin:/sbin:/bin\") at the top of the script and use absolute paths for commands.",
				RemediationCode: "#!/bin/bash\nexport PATH=\"/usr/sbin:/usr/bin:/sbin:/bin\"",
			})
		}
	}

	return findings
}

func scriptAuditMake002Finding(scriptPath string, lineNum int, reason string) Finding {
	return Finding{
		ID:          "SUDO-SYS-SCRIPT-002",
		Title:       "Command Injection Risk via Positional Parameter Handling",
		Description: fmt.Sprintf("The script '%s' at line %d performs unsafe positional parameter handling (%s), allowing callers to inject arbitrary commands or split arguments when executed via sudo.", scriptPath, lineNum, reason),
		Severity:    SeverityCritical,
		Command:     scriptPath,
		Context:     scriptPath,
		Line:        lineNum,
		Remediation: "Avoid passing positional arguments into 'eval', 'sh -c', 'bash -c', or unquoted expansions. Validate arguments against an explicit allowlist and quote all expansions.",
		RemediationCode: "case \"$1\" in\n" +
			"    start|stop|restart|status)\n" +
			"        /usr/bin/systemctl \"$1\" myapp.service\n" +
			"        ;;\n" +
			"    *)\n" +
			"        echo \"Invalid action\" >&2\n" +
			"        exit 1\n" +
			"        ;;\n" +
			"esac",
	}
}

func scriptAuditCheckInjection(cmdTok scriptAuditToken, args []scriptAuditToken) (string, bool) {
	if cmdTok.hasExpandedPositional {
		return "positional parameter used directly as command", true
	}

	cmdName := cmdTok.text
	cmdBase := path.Base(cmdName)

	if cmdName == "eval" {
		for _, a := range args {
			if a.hasExpandedPositional {
				return "positional parameter passed to eval", true
			}
		}
		return "", false
	}

	if cmdName == "exec" || cmdName == "command" {
		// Find wrapped command token after flags like -a name, -c, -l, -p, -v, -V.
		skipNext := false
		for idx, a := range args {
			if skipNext {
				skipNext = false
				continue
			}
			if a.text == "-a" && cmdName == "exec" {
				skipNext = true
				continue
			}
			if a.text == "--" {
				if idx+1 < len(args) {
					return scriptAuditCheckInjection(args[idx+1], args[idx+2:])
				}
				return "", false
			}
			if strings.HasPrefix(a.text, "-") && len(a.text) > 1 {
				continue
			}
			return scriptAuditCheckInjection(a, args[idx+1:])
		}
		return "", false
	}

	// Check shell -c invocations such as sh -c "$1" or /bin/bash -ec "cmd $1".
	if scriptAuditShellNames[cmdBase] {
		for idx, a := range args {
			if a.text == "--" {
				break
			}
			if scriptAuditIsCFlag(a.text) {
				if idx+1 < len(args) && args[idx+1].hasExpandedPositional {
					return fmt.Sprintf("positional parameter passed to %s %s", cmdBase, a.text), true
				}
			}
		}
	}

	if cmdBase == "env" {
		skipNext := false
		for idx, a := range args {
			if skipNext {
				skipNext = false
				continue
			}
			if a.text == "-u" || a.text == "--unset" || a.text == "-C" || a.text == "--chdir" {
				skipNext = true
				continue
			}
			if a.isAssignment || strings.HasPrefix(a.text, "-") {
				continue
			}
			if scriptAuditShellNames[path.Base(a.text)] {
				return scriptAuditCheckInjection(a, args[idx+1:])
			}
			break
		}
	}

	// Inside bash [[ ... ]], word splitting is not performed on variable expansions.
	if cmdName == "[[" {
		return "", false
	}

	for _, a := range args {
		if a.hasUnquotedPositional {
			return "unquoted positional parameter expansion inside command invocation", true
		}
	}

	return "", false
}

func scriptAuditIsCFlag(flag string) bool {
	if flag == "-c" {
		return true
	}
	if !strings.HasPrefix(flag, "-") || strings.HasPrefix(flag, "--") || len(flag) < 2 {
		return false
	}
	for i := 1; i < len(flag); i++ {
		if flag[i] == 'c' {
			return true
		}
		if flag[i] < 'a' || flag[i] > 'z' {
			return false
		}
	}
	return false
}

func scriptAuditIsSafeExplicitPATHAssignment(tok scriptAuditToken) bool {
	if !tok.isAssignment || tok.assignName != "PATH" || tok.assignValue == "" {
		return false
	}
	if strings.Contains(tok.raw, "$PATH") || strings.Contains(tok.raw, "${PATH}") {
		return false
	}
	return true
}

func scriptAuditIsUnsafeSourceTarget(target string) bool {
	if target == "" || !strings.HasPrefix(target, "/") {
		return true
	}
	for _, prefix := range scriptAuditWritablePrefixes {
		if strings.HasPrefix(target, prefix) {
			return true
		}
	}
	return isWritableOrTempPath(target)
}

func scriptAuditFilterRedirections(toks []scriptAuditToken) []scriptAuditToken {
	var out []scriptAuditToken
	skipNext := false
	for _, t := range toks {
		if skipNext {
			skipNext = false
			continue
		}
		if t.isRedirection {
			// Standalone operator like ">" or "2>" consumes the next filename token.
			if t.raw == ">" || t.raw == ">>" || t.raw == "<" || t.raw == ">|" ||
				(len(t.raw) == 2 && t.raw[0] >= '0' && t.raw[0] <= '9' && (t.raw[1] == '>' || t.raw[1] == '<')) ||
				(len(t.raw) == 3 && t.raw[0] >= '0' && t.raw[0] <= '9' && t.raw[1:] == ">>") {
				skipNext = true
			}
			continue
		}
		out = append(out, t)
	}
	return out
}

func scriptAuditStripCasePattern(stmt string) (string, bool) {
	inSingle := false
	inDouble := false
	escaped := false

	for i := 0; i < len(stmt); i++ {
		ch := stmt[i]
		if escaped {
			escaped = false
			continue
		}
		if inSingle {
			if ch == '\'' {
				inSingle = false
			}
			continue
		}
		if ch == '\\' {
			escaped = true
			continue
		}
		if inDouble {
			if ch == '"' {
				inDouble = false
			}
			continue
		}
		if ch == '\'' {
			inSingle = true
			continue
		}
		if ch == '"' {
			inDouble = true
			continue
		}
		if ch == '(' && i == 0 {
			continue
		}
		// Pattern closes at ')' before any whitespace-separated command unless preceded by command syntax.
		if ch == ')' {
			pat := strings.TrimSpace(stmt[:i])
			if pat != "" && !strings.ContainsAny(pat, " \t") {
				rest := strings.TrimSpace(stmt[i+1:])
				return rest, true
			}
			return "", false
		}
		if ch == ' ' || ch == '\t' {
			return "", false
		}
	}
	return "", false
}

func scriptAuditLooksLikeCommandName(cmd string) bool {
	if cmd == "" {
		return false
	}
	c0 := cmd[0]
	if !((c0 >= 'a' && c0 <= 'z') || (c0 >= 'A' && c0 <= 'Z') || (c0 >= '0' && c0 <= '9') || c0 == '_') {
		return false
	}
	for i := 0; i < len(cmd); i++ {
		c := cmd[i]
		valid := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
			c == '_' || c == '-' || c == '.' || c == '+'
		if !valid {
			return false
		}
	}
	return true
}
