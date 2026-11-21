package parser

import (
	"bytes"
	"fmt"
	"io"
	"path/filepath"
	"strconv"
	"strings"
	"sudo-check/pkg/audit"
)

// IsSudoLLOutput reports whether data appears to be output from `sudo -ll` or `sudo -l`
// rather than a raw sudoers file, JSON policy, or LDIF dump.
func IsSudoLLOutput(data []byte) bool {
	trimmed := bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))
	if len(bytes.TrimSpace(trimmed)) == 0 {
		return false
	}
	for _, rawLine := range strings.Split(string(trimmed), "\n") {
		line := strings.TrimSpace(strings.TrimSuffix(rawLine, "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if _, _, _, ok := sudolParseMatchingDefaultsHeader(line); ok {
			return true
		}
		if _, _, ok := sudolParseUserCommandsHeader(line); ok {
			return true
		}
	}
	return false
}

// ParseSudoLL parses the output of `sudo -ll` (and compatible `sudo -l` listings)
// into an audit.SudoersPolicy. If source is empty, it defaults to "sudo-ll".
func ParseSudoLL(r io.Reader, source string) (*audit.SudoersPolicy, error) {
	if source == "" {
		source = "sudo-ll"
	}
	srcFile := filepath.ToSlash(source)
	if r == nil {
		return nil, fmt.Errorf("failed to read %s: nil reader", srcFile)
	}
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %w", srcFile, err)
	}

	content := strings.TrimPrefix(string(data), "\xef\xbb\xbf")
	if strings.TrimSpace(content) == "" {
		return nil, fmt.Errorf("%s: empty sudo -ll input", srcFile)
	}

	ctx := newParseContext()
	rawLines := strings.Split(content, "\n")

	type parseMode int
	const (
		modeNone parseMode = iota
		modeDefaults
		modeCommands
		modeStanza
	)

	mode := modeNone
	hasHeader := false
	curUser := ""
	curHost := ""
	curUserLine := 0

	var pendingDefaults string
	var pendingDefaultsLine int

	var activeStanza *sudolStanza
	var activeField string

	flushDefaults := func() error {
		if strings.TrimSpace(pendingDefaults) == "" {
			pendingDefaults = ""
			pendingDefaultsLine = 0
			return nil
		}
		opts, err := parseDefaultsOptions(pendingDefaults, srcFile, pendingDefaultsLine)
		if err != nil {
			return err
		}
		ctx.policy.Defaults = append(ctx.policy.Defaults, audit.DefaultBinding{
			Options: opts,
			File:    srcFile,
			Line:    pendingDefaultsLine,
			RawLine: strings.TrimSpace(pendingDefaults),
		})
		pendingDefaults = ""
		pendingDefaultsLine = 0
		return nil
	}

	flushStanza := func() error {
		if activeStanza == nil {
			return nil
		}
		if len(activeStanza.commands) == 0 {
			return fmt.Errorf("%s:%d: Sudoers entry missing Commands", srcFile, activeStanza.startLine)
		}
		if curUser == "" || curHost == "" {
			return fmt.Errorf("%s:%d: Sudoers entry encountered before User/Host header", srcFile, activeStanza.startLine)
		}
		userLine := curUserLine
		if userLine == 0 {
			userLine = activeStanza.startLine
		}
		spec := audit.UserSpec{
			UserList: []audit.Member{{Username: curUser, File: srcFile, Line: userLine}},
			HostList: []audit.Member{{Hostname: curHost, File: srcFile, Line: userLine}},
			CmndSpecs: []audit.CmndSpec{{
				RunasUsers:  activeStanza.runasUsers,
				RunasGroups: activeStanza.runasGroups,
				Options:     activeStanza.opts.buildCanonical(),
				Commands:    activeStanza.commands,
			}},
			File: srcFile,
			Line: activeStanza.startLine,
		}
		ctx.policy.UserSpecs = append(ctx.policy.UserSpecs, spec)
		activeStanza = nil
		activeField = ""
		return nil
	}

	for idx, rawLine := range rawLines {
		lineNum := idx + 1
		lineNoCR := strings.TrimSuffix(rawLine, "\r")
		trimmed := strings.TrimSpace(lineNoCR)
		if trimmed == "" {
			if mode == modeDefaults {
				if err := flushDefaults(); err != nil {
					return nil, err
				}
			}
			continue
		}

		// 1. Check Matching Defaults header
		if dUser, dHost, inlineOpts, ok := sudolParseMatchingDefaultsHeader(trimmed); ok {
			if err := flushDefaults(); err != nil {
				return nil, err
			}
			if err := flushStanza(); err != nil {
				return nil, err
			}
			hasHeader = true
			if curUser == "" && dUser != "" {
				curUser = dUser
				curUserLine = lineNum
			}
			if curHost == "" && dHost != "" {
				curHost = dHost
			}
			mode = modeDefaults
			if inlineOpts != "" {
				opts, err := parseDefaultsOptions(inlineOpts, srcFile, lineNum)
				if err != nil {
					return nil, err
				}
				ctx.policy.Defaults = append(ctx.policy.Defaults, audit.DefaultBinding{
					Options: opts,
					File:    srcFile,
					Line:    lineNum,
					RawLine: strings.TrimSpace(inlineOpts),
				})
			}
			continue
		}

		// 2. Check User <user> may run the following commands on <host>: header
		if u, h, ok := sudolParseUserCommandsHeader(trimmed); ok {
			if err := flushDefaults(); err != nil {
				return nil, err
			}
			if err := flushStanza(); err != nil {
				return nil, err
			}
			hasHeader = true
			curUser = u
			curHost = h
			curUserLine = lineNum
			mode = modeCommands
			continue
		}

		// 3. Check denied message (when user has no commands)
		if sudolIsDeniedLine(trimmed) {
			if err := flushDefaults(); err != nil {
				return nil, err
			}
			if err := flushStanza(); err != nil {
				return nil, err
			}
			mode = modeNone
			continue
		}

		// 4. Check Sudoers entry: or LDAP Role: stanza header
		if trimmed == "Sudoers entry:" || strings.HasPrefix(trimmed, "LDAP Role:") {
			if err := flushDefaults(); err != nil {
				return nil, err
			}
			if err := flushStanza(); err != nil {
				return nil, err
			}
			mode = modeStanza
			activeStanza = &sudolStanza{
				startLine: lineNum,
				opts:      newSudolOptionState(),
			}
			activeField = ""
			continue
		}

		isIndented := len(lineNoCR) > 0 && (lineNoCR[0] == ' ' || lineNoCR[0] == '\t')

		// 5. Handle Defaults block lines
		if mode == modeDefaults {
			if !isIndented {
				return nil, fmt.Errorf("%s:%d: unexpected non-indented line in Defaults block: %q", srcFile, lineNum, trimmed)
			}
			if pendingDefaults == "" {
				pendingDefaults = trimmed
				pendingDefaultsLine = lineNum
			} else {
				pendingDefaults += " " + trimmed
			}
			if !sudolEndsWithTrailingCommaOutsideQuotes(pendingDefaults) {
				if err := flushDefaults(); err != nil {
					return nil, err
				}
			}
			continue
		}

		// 6. Handle lines inside Sudoers entry: stanza
		if mode == modeStanza && activeStanza != nil {
			if field, val, isField := sudolSplitFieldLine(trimmed); isField {
				activeField = field
				switch field {
				case "RunAsUsers", "RunAs":
					users, err := sudolParseRunasUsers(val, srcFile, lineNum)
					if err != nil {
						return nil, err
					}
					activeStanza.runasUsers = append(activeStanza.runasUsers, users...)
				case "RunAsGroups":
					groups, err := sudolParseRunasGroups(val, srcFile, lineNum)
					if err != nil {
						return nil, err
					}
					activeStanza.runasGroups = append(activeStanza.runasGroups, groups...)
				case "Options":
					if err := activeStanza.opts.applyOptionsString(val, srcFile, lineNum); err != nil {
						return nil, err
					}
				case "Commands":
					if val != "" {
						cmdMember, err := sudolParseCommand(ctx, val, srcFile, lineNum)
						if err != nil {
							return nil, err
						}
						activeStanza.commands = append(activeStanza.commands, cmdMember)
					}
				default:
					if err := activeStanza.opts.applyNamedCmndOption(field, val, srcFile, lineNum); err != nil {
						return nil, err
					}
				}
				continue
			}

			if !isIndented {
				return nil, fmt.Errorf("%s:%d: unexpected line in Sudoers entry: %q", srcFile, lineNum, trimmed)
			}

			switch activeField {
			case "Commands":
				cmdMember, err := sudolParseCommand(ctx, trimmed, srcFile, lineNum)
				if err != nil {
					return nil, err
				}
				activeStanza.commands = append(activeStanza.commands, cmdMember)
			case "Options":
				if err := activeStanza.opts.applyOptionsString(trimmed, srcFile, lineNum); err != nil {
					return nil, err
				}
			case "RunAsUsers", "RunAs":
				users, err := sudolParseRunasUsers(trimmed, srcFile, lineNum)
				if err != nil {
					return nil, err
				}
				activeStanza.runasUsers = append(activeStanza.runasUsers, users...)
			case "RunAsGroups":
				groups, err := sudolParseRunasGroups(trimmed, srcFile, lineNum)
				if err != nil {
					return nil, err
				}
				activeStanza.runasGroups = append(activeStanza.runasGroups, groups...)
			default:
				return nil, fmt.Errorf("%s:%d: unexpected line before Commands in Sudoers entry: %q", srcFile, lineNum, trimmed)
			}
			continue
		}

		// 7. Handle sudo -l style indented Cmnd_Spec lines directly under User ... may run...
		if mode == modeCommands && isIndented && sudolLooksLikeCmndSpecLine(trimmed) {
			specs, err := ctx.parseCmndSpecList(trimmed, srcFile, lineNum)
			if err != nil {
				return nil, err
			}
			userLine := curUserLine
			if userLine == 0 {
				userLine = lineNum
			}
			ctx.policy.UserSpecs = append(ctx.policy.UserSpecs, audit.UserSpec{
				UserList:  []audit.Member{{Username: curUser, File: srcFile, Line: userLine}},
				HostList:  []audit.Member{{Hostname: curHost, File: srcFile, Line: userLine}},
				CmndSpecs: specs,
				File:      srcFile,
				Line:      lineNum,
				RawLine:   trimmed,
			})
			continue
		}

		return nil, fmt.Errorf("%s:%d: unexpected line in sudo -ll output: %q", srcFile, lineNum, trimmed)
	}

	if err := flushDefaults(); err != nil {
		return nil, err
	}
	if err := flushStanza(); err != nil {
		return nil, err
	}
	if !hasHeader {
		return nil, fmt.Errorf("%s: no sudo -ll policy headers found", srcFile)
	}

	return ctx.policy, nil
}

type sudolStanza struct {
	startLine   int
	runasUsers  []audit.Member
	runasGroups []audit.Member
	opts        *sudolOptionState
	commands    []audit.Member
}

type sudolOptionState struct {
	tagSet    map[string]bool
	tagVal    map[string]bool
	optSet    map[string]bool
	optVal    map[string]any
	extraOpts []audit.Option
}

func newSudolOptionState() *sudolOptionState {
	return &sudolOptionState{
		tagSet: make(map[string]bool),
		tagVal: make(map[string]bool),
		optSet: make(map[string]bool),
		optVal: make(map[string]any),
	}
}

func sudolParseMatchingDefaultsHeader(line string) (user string, host string, inlineOpts string, ok bool) {
	const prefix = "Matching Defaults entries for "
	if !strings.HasPrefix(line, prefix) {
		return "", "", "", false
	}
	rest := line[len(prefix):]
	colonIdx := -1
	if strings.HasSuffix(rest, ":") {
		colonIdx = len(rest) - 1
	} else if idx := strings.Index(rest, ": "); idx != -1 {
		colonIdx = idx
	} else if idx := strings.Index(rest, ":\t"); idx != -1 {
		colonIdx = idx
	} else {
		colonIdx = strings.LastIndexByte(rest, ':')
	}
	if colonIdx == -1 {
		return "", "", "", false
	}
	headerSubject := strings.TrimSpace(rest[:colonIdx])
	if headerSubject == "" {
		return "", "", "", false
	}
	inlineOpts = strings.TrimSpace(rest[colonIdx+1:])
	if onIdx := strings.LastIndex(headerSubject, " on "); onIdx != -1 {
		user = strings.TrimSpace(headerSubject[:onIdx])
		host = strings.TrimSpace(headerSubject[onIdx+len(" on "):])
	} else {
		user = headerSubject
	}
	return user, host, inlineOpts, true
}

func sudolParseUserCommandsHeader(line string) (user string, host string, ok bool) {
	const prefix = "User "
	const marker = " may run the following commands on "
	if !strings.HasPrefix(line, prefix) || !strings.HasSuffix(line, ":") {
		return "", "", false
	}
	markerIdx := strings.Index(line, marker)
	if markerIdx <= len(prefix) {
		return "", "", false
	}
	user = strings.TrimSpace(line[len(prefix):markerIdx])
	host = strings.TrimSpace(line[markerIdx+len(marker) : len(line)-1])
	if user == "" || host == "" {
		return "", "", false
	}
	return user, host, true
}

func sudolIsDeniedLine(line string) bool {
	return strings.HasPrefix(line, "Sorry, user ") && strings.Contains(line, " may not run sudo on ") ||
		strings.HasPrefix(line, "User ") && strings.Contains(line, " is not allowed to run sudo on ")
}

func sudolEndsWithTrailingCommaOutsideQuotes(s string) bool {
	inQuotes := false
	lastNonSpace := byte(0)
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if ch == '\\' {
			lastNonSpace = ch
			i++
			continue
		}
		if ch == '"' {
			inQuotes = !inQuotes
			lastNonSpace = ch
			continue
		}
		if !inQuotes && (ch == ' ' || ch == '\t') {
			continue
		}
		lastNonSpace = ch
	}
	return !inQuotes && lastNonSpace == ','
}

var sudolKnownFields = map[string]string{
	"runasusers":       "RunAsUsers",
	"runas":            "RunAs",
	"runasgroups":      "RunAsGroups",
	"options":          "Options",
	"commands":         "Commands",
	"runchroot":        "runchroot",
	"chroot":           "runchroot",
	"runcwd":           "runcwd",
	"cwd":              "runcwd",
	"command_timeout":  "command_timeout",
	"timeout":          "command_timeout",
	"notbefore":        "notbefore",
	"notafter":         "notafter",
	"role":             "role",
	"type":             "type",
	"apparmor_profile": "apparmor_profile",
	"apparmor profile": "apparmor_profile",
	"privs":            "privs",
	"limitprivs":       "limitprivs",
}

func sudolSplitFieldLine(line string) (field string, val string, ok bool) {
	colonIdx := strings.IndexByte(line, ':')
	if colonIdx <= 0 {
		return "", "", false
	}
	rawField := strings.TrimSpace(line[:colonIdx])
	canon, found := sudolKnownFields[strings.ToLower(rawField)]
	if !found {
		return "", "", false
	}
	return canon, strings.TrimSpace(line[colonIdx+1:]), true
}

func sudolParseRunasUsers(val string, filename string, lineNum int) ([]audit.Member, error) {
	val = strings.TrimSpace(val)
	if val == "" || strings.EqualFold(val, "(empty)") {
		return []audit.Member{{Username: "root", File: filename, Line: lineNum}}, nil
	}
	tokens, err := sudolSplitCommaOrSpaceTokens(val)
	if err != nil {
		return nil, fmt.Errorf("%s:%d: %w", filename, lineNum, err)
	}
	var members []audit.Member
	for _, tok := range tokens {
		if strings.EqualFold(tok, "(empty)") {
			members = append(members, audit.Member{Username: "root", File: filename, Line: lineNum})
			continue
		}
		if err := validateMemberToken(tok, false); err != nil {
			return nil, fmt.Errorf("%s:%d: %w", filename, lineNum, err)
		}
		members = append(members, sudolParseUserMember(tok, filename, lineNum))
	}
	return members, nil
}

func sudolParseRunasGroups(val string, filename string, lineNum int) ([]audit.Member, error) {
	val = strings.TrimSpace(val)
	if val == "" || strings.EqualFold(val, "(empty)") {
		return nil, nil
	}
	tokens, err := sudolSplitCommaOrSpaceTokens(val)
	if err != nil {
		return nil, fmt.Errorf("%s:%d: %w", filename, lineNum, err)
	}
	var members []audit.Member
	for _, tok := range tokens {
		if strings.EqualFold(tok, "(empty)") {
			continue
		}
		if err := validateMemberToken(tok, false); err != nil {
			return nil, fmt.Errorf("%s:%d: %w", filename, lineNum, err)
		}
		members = append(members, sudolParseGroupMember(tok, filename, lineNum))
	}
	return members, nil
}

func sudolSplitCommaOrSpaceTokens(s string) ([]string, error) {
	commaParts, err := splitCommaOutsideQuotes(s)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, cp := range commaParts {
		cp = strings.TrimSpace(cp)
		if cp == "" {
			continue
		}
		spaceParts, err := sudolSplitWhitespaceOutsideQuotes(cp)
		if err != nil {
			return nil, err
		}
		// Re-attach standalone '!' negation prefix to following token if separated by whitespace
		for i := 0; i < len(spaceParts); i++ {
			tok := spaceParts[i]
			for sudolIsAllBangs(tok) && i+1 < len(spaceParts) {
				i++
				tok += spaceParts[i]
			}
			out = append(out, tok)
		}
	}
	return out, nil
}

func sudolSplitWhitespaceOutsideQuotes(s string) ([]string, error) {
	var parts []string
	var cur strings.Builder
	inQuotes := false
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if ch == '\\' {
			cur.WriteByte(ch)
			if i+1 < len(s) {
				i++
				cur.WriteByte(s[i])
			}
			continue
		}
		if ch == '"' {
			inQuotes = !inQuotes
			cur.WriteByte(ch)
			continue
		}
		if !inQuotes && (ch == ' ' || ch == '\t') {
			if cur.Len() > 0 {
				parts = append(parts, cur.String())
				cur.Reset()
			}
			continue
		}
		cur.WriteByte(ch)
	}
	if inQuotes {
		return nil, fmt.Errorf("unterminated quote in %q", s)
	}
	if cur.Len() > 0 {
		parts = append(parts, cur.String())
	}
	return parts, nil
}

func sudolIsAllBangs(tok string) bool {
	if tok == "" {
		return false
	}
	for i := 0; i < len(tok); i++ {
		if tok[i] != '!' {
			return false
		}
	}
	return true
}

func sudolParseUserMember(rawTok string, filename string, lineNum int) audit.Member {
	tok, negated := stripNegation(rawTok)
	m := audit.Member{Negated: negated, File: filename, Line: lineNum}
	if tok == "" || tok == `""` {
		m.Myself = true
		return m
	}
	val, _ := unquoteToken(tok)
	switch {
	case strings.HasPrefix(val, "%:#"):
		if id, err := strconv.Atoi(val[3:]); err == nil && id >= 0 {
			m.NonUnixGID = &id
			return m
		}
		m.NonUnixGroup = val[2:]
	case strings.HasPrefix(val, "%:"):
		m.NonUnixGroup = val[2:]
	case strings.HasPrefix(val, "%#"):
		if id, err := strconv.Atoi(val[2:]); err == nil && id >= 0 {
			m.UserGID = &id
			return m
		}
		m.Usergroup = val[1:]
	case strings.HasPrefix(val, "%"):
		m.Usergroup = val[1:]
	case strings.HasPrefix(val, "+"):
		m.Netgroup = val[1:]
	case strings.HasPrefix(val, "#"):
		if id, err := strconv.Atoi(val[1:]); err == nil && id >= 0 {
			m.UserID = &id
			return m
		}
		m.Username = val
	default:
		m.Username = val
	}
	return m
}

func sudolParseGroupMember(rawTok string, filename string, lineNum int) audit.Member {
	tok, negated := stripNegation(rawTok)
	m := audit.Member{Negated: negated, File: filename, Line: lineNum}
	val, _ := unquoteToken(tok)
	switch {
	case strings.HasPrefix(val, "%:#"):
		if id, err := strconv.Atoi(val[3:]); err == nil && id >= 0 {
			m.NonUnixGID = &id
			return m
		}
		m.NonUnixGroup = val[2:]
	case strings.HasPrefix(val, "%:"):
		m.NonUnixGroup = val[2:]
	case strings.HasPrefix(val, "%#"):
		if id, err := strconv.Atoi(val[2:]); err == nil && id >= 0 {
			m.UserGID = &id
			return m
		}
		m.Usergroup = val[1:]
	case strings.HasPrefix(val, "%"):
		m.Usergroup = val[1:]
	default:
		m.Usergroup = val
	}
	return m
}

func (st *sudolOptionState) applyOptionsString(raw string, filename string, lineNum int) error {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" || strings.EqualFold(trimmed, "(none)") {
		return nil
	}
	tokens, err := sudolSplitOptionTokens(trimmed)
	if err != nil {
		return fmt.Errorf("%s:%d: %w", filename, lineNum, err)
	}
	for _, tok := range tokens {
		if err := st.applyOptionEntry(tok, filename, lineNum); err != nil {
			return err
		}
	}
	return nil
}

func sudolSplitOptionTokens(s string) ([]string, error) {
	commaParts, err := splitCommaOutsideQuotes(s)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, cp := range commaParts {
		cp = strings.TrimSpace(cp)
		if cp == "" {
			return nil, fmt.Errorf("empty option in Options")
		}
		rawTokens, err := sudolSplitWhitespaceOutsideQuotes(cp)
		if err != nil {
			return nil, err
		}
		for i := 0; i < len(rawTokens); i++ {
			tok := rawTokens[i]
			for sudolIsAllBangs(tok) && i+1 < len(rawTokens) {
				i++
				tok += rawTokens[i]
			}
			// Merge spaces around '=' (e.g. "runchroot = /srv/jail")
			if (strings.HasSuffix(tok, "=") || strings.HasSuffix(tok, "+=") || strings.HasSuffix(tok, "-=")) && i+1 < len(rawTokens) {
				i++
				tok += rawTokens[i]
			} else if i+1 < len(rawTokens) && (rawTokens[i+1] == "=" || rawTokens[i+1] == "+=" || rawTokens[i+1] == "-=") {
				tok += rawTokens[i+1]
				i++
				if i+1 < len(rawTokens) {
					i++
					tok += rawTokens[i]
				}
			}
			out = append(out, tok)
		}
	}
	return out, nil
}

var sudolCanonicalTagNames = map[string]string{
	"authenticate":    "authenticate",
	"noexec":          "noexec",
	"intercept":       "intercept",
	"send_mail":       "send_mail",
	"mail":            "send_mail",
	"setenv":          "setenv",
	"sudoedit_follow": "sudoedit_follow",
	"follow":          "sudoedit_follow",
	"log_input":       "log_input",
	"log_output":      "log_output",
}

var sudolCmndOptionAliases = map[string]string{
	"RUNCHROOT":        "runchroot",
	"CHROOT":           "runchroot",
	"RUNCWD":           "runcwd",
	"CWD":              "runcwd",
	"COMMAND_TIMEOUT":  "command_timeout",
	"TIMEOUT":          "command_timeout",
	"NOTBEFORE":        "notbefore",
	"NOTAFTER":         "notafter",
	"ROLE":             "role",
	"TYPE":             "type",
	"APPARMOR_PROFILE": "apparmor_profile",
	"PRIVS":            "privs",
	"LIMITPRIVS":       "limitprivs",
}

func (st *sudolOptionState) applyOptionEntry(rawEntry string, filename string, lineNum int) error {
	entry, negated := stripNegation(rawEntry)
	if entry == "" {
		return fmt.Errorf("%s:%d: invalid negated option in Options", filename, lineNum)
	}

	_, key, val, hasOp := splitOptionAssignment(entry)
	if !hasOp {
		upper := strings.ToUpper(entry)
		if def, isTag := tagSpecs[upper]; isTag {
			v := def.val
			if negated {
				v = !v
			}
			st.tagSet[def.key] = true
			st.tagVal[def.key] = v
			return nil
		}
		lower := strings.ToLower(entry)
		if canonTag, ok := sudolCanonicalTagNames[lower]; ok {
			st.tagSet[canonTag] = true
			st.tagVal[canonTag] = !negated
			return nil
		}
		st.extraOpts = append(st.extraOpts, audit.Option{lower: !negated})
		return nil
	}

	if negated {
		return fmt.Errorf("%s:%d: cannot negate assignment option %s", filename, lineNum, key)
	}

	unquoted := unquoteOptionValue(val)
	if canonKey, ok := sudolCmndOptionAliases[strings.ToUpper(key)]; ok {
		return st.applyNamedCmndOption(canonKey, unquoted, filename, lineNum)
	}
	if optKey, ok := cmndOptionKeys[strings.ToUpper(key)]; ok {
		return st.applyNamedCmndOption(optKey, unquoted, filename, lineNum)
	}

	opts, err := parseDefaultsOptions(rawEntry, filename, lineNum)
	if err != nil {
		return err
	}
	st.extraOpts = append(st.extraOpts, opts...)
	return nil
}

func (st *sudolOptionState) applyNamedCmndOption(canonKey string, val string, filename string, lineNum int) error {
	unquoted := unquoteOptionValue(val)
	switch canonKey {
	case "command_timeout":
		secs, ok := parseTimeoutSeconds(unquoted)
		if !ok {
			return fmt.Errorf("%s:%d: invalid command_timeout value %q", filename, lineNum, unquoted)
		}
		if secs <= 0 {
			delete(st.optSet, canonKey)
			delete(st.optVal, canonKey)
			return nil
		}
		st.optSet[canonKey] = true
		st.optVal[canonKey] = secs
	case "notbefore", "notafter":
		st.optSet[canonKey] = true
		st.optVal[canonKey] = normalizeGeneralizedTime(unquoted)
	default:
		st.optSet[canonKey] = true
		st.optVal[canonKey] = unquoted
	}
	return nil
}

func (st *sudolOptionState) buildCanonical() []audit.Option {
	var out []audit.Option
	for _, k := range cmndPreTagOptionOrder {
		if st.optSet[k] {
			out = append(out, audit.Option{k: st.optVal[k]})
		}
	}
	for _, k := range tagOrder {
		if st.tagSet[k] {
			out = append(out, audit.Option{k: st.tagVal[k]})
		}
	}
	for _, k := range cmndPostTagOptionOrder {
		if st.optSet[k] {
			out = append(out, audit.Option{k: st.optVal[k]})
		}
	}
	out = append(out, st.extraOpts...)
	return out
}

func sudolParseCommand(ctx *parseContext, rawCmd string, filename string, lineNum int) (audit.Member, error) {
	m, err := ctx.parseDigestedCommand(rawCmd, filename, lineNum)
	if err != nil {
		return audit.Member{}, err
	}
	if m.Command == "" && m.CommandAlias != "" {
		m.Command = m.CommandAlias
		m.CommandAlias = ""
	}
	return m, nil
}

func sudolLooksLikeCmndSpecLine(line string) bool {
	if line == "" {
		return false
	}
	if line[0] == '(' || line[0] == '/' || line[0] == '!' || line[0] == '^' {
		return true
	}
	if line == "ALL" || strings.HasPrefix(line, "ALL ") || strings.HasPrefix(line, "ALL\t") || strings.HasPrefix(line, "ALL,") {
		return true
	}
	if line == "sudoedit" || strings.HasPrefix(line, "sudoedit ") || strings.HasPrefix(line, "sudoedit\t") {
		return true
	}
	if _, _, _, ok := matchDigestPrefix(line); ok {
		return true
	}
	if _, _, ok := consumeTagOrCmndOption(line); ok {
		return true
	}
	return false
}
