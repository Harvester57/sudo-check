package parser

import (
	"bytes"
	"cmp"
	"encoding/base64"
	"fmt"
	"io"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sudo-check/pkg/audit"
)

// IsLDIFPolicy reports whether data appears to be an RFC 2849 LDIF dump containing
// sudoRole entries (objectClass: sudoRole, sudoCommand, or sudoOption), rather than
// a raw sudoers file, JSON policy, or sudo -ll output.
func IsLDIFPolicy(data []byte) bool {
	trimmed := bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))
	if len(bytes.TrimSpace(trimmed)) == 0 {
		return false
	}
	lines, err := ldifUnfoldLines(string(trimmed), "ldif", false)
	if err != nil {
		return false
	}
	for _, l := range lines {
		if l.text == "" {
			continue
		}
		attr, ok, err := ldifParseAttrLine(l.text, "ldif", l.line)
		if err != nil || !ok {
			continue
		}
		switch attr.name {
		case "objectclass":
			if strings.EqualFold(strings.TrimSpace(attr.val), "sudorole") {
				return true
			}
		case "sudocommand", "sudooption":
			return true
		}
	}
	return false
}

// ParseLDIF parses an RFC 2849 LDIF policy export containing sudoRole entries into
// an audit.SudoersPolicy. If source is empty, it defaults to "ldif".
func ParseLDIF(r io.Reader, source string) (*audit.SudoersPolicy, error) {
	if source == "" {
		source = "ldif"
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
		return nil, fmt.Errorf("%s: empty LDIF input", srcFile)
	}

	lines, err := ldifUnfoldLines(content, srcFile, true)
	if err != nil {
		return nil, err
	}

	var entries []ldifEntry
	var cur *ldifEntry
	for _, l := range lines {
		if l.text == "" {
			if cur != nil && len(cur.attrs) > 0 {
				entries = append(entries, *cur)
				cur = nil
			}
			continue
		}
		attr, ok, err := ldifParseAttrLine(l.text, srcFile, l.line)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, fmt.Errorf("%s:%d: invalid LDIF attribute line: %q", srcFile, l.line, l.text)
		}
		if attr.name == "version" && len(entries) == 0 && (cur == nil || len(cur.attrs) == 0) {
			continue
		}
		if cur == nil {
			cur = &ldifEntry{startLine: l.line}
		}
		cur.attrs = append(cur.attrs, attr)
	}
	if cur != nil && len(cur.attrs) > 0 {
		entries = append(entries, *cur)
	}

	ctx := newParseContext()
	var orderedSpecs []ldifOrderedSpec
	foundSudoEntry := false

	for _, entry := range entries {
		if !ldifIsSudoEntry(entry) {
			continue
		}
		foundSudoEntry = true

		if ldifIsDefaultsEntry(entry) {
			var defaultOpts []audit.Option
			for _, attr := range entry.attrs {
				if attr.name != "sudooption" {
					continue
				}
				opts, err := parseDefaultsOptions(attr.val, srcFile, entry.startLine)
				if err != nil {
					return nil, err
				}
				defaultOpts = append(defaultOpts, opts...)
			}
			if len(defaultOpts) > 0 {
				ctx.policy.Defaults = append(ctx.policy.Defaults, audit.DefaultBinding{
					Options: defaultOpts,
					File:    srcFile,
					Line:    entry.startLine,
				})
			}
			continue
		}

		var (
			userList    []audit.Member
			hostList    []audit.Member
			runasUsers  []audit.Member
			runasGroups []audit.Member
			commands    []audit.Member
			sudoOrder   int
			optState    = newSudolOptionState()
		)

		for _, attr := range entry.attrs {
			switch attr.name {
			case "sudouser":
				tok := strings.TrimSpace(attr.val)
				if tok == "" {
					return nil, fmt.Errorf("%s:%d: empty sudoUser value", srcFile, attr.line)
				}
				if err := validateMemberToken(tok, true); err != nil {
					return nil, fmt.Errorf("%s:%d: %w", srcFile, attr.line, err)
				}
				userList = append(userList, ldifParseUserMember(tok, srcFile, entry.startLine))
			case "sudohost":
				tok := strings.TrimSpace(attr.val)
				if tok == "" {
					return nil, fmt.Errorf("%s:%d: empty sudoHost value", srcFile, attr.line)
				}
				if err := validateMemberToken(tok, false); err != nil {
					return nil, fmt.Errorf("%s:%d: %w", srcFile, attr.line, err)
				}
				hostList = append(hostList, ldifParseHostMember(tok, srcFile, entry.startLine))
			case "sudorunasuser", "sudorunas":
				tok := strings.TrimSpace(attr.val)
				if tok == "" {
					runasUsers = append(runasUsers, audit.Member{Myself: true, File: srcFile, Line: entry.startLine})
					continue
				}
				if err := validateMemberToken(tok, false); err != nil {
					return nil, fmt.Errorf("%s:%d: %w", srcFile, attr.line, err)
				}
				runasUsers = append(runasUsers, ldifParseUserMember(tok, srcFile, entry.startLine))
			case "sudorunasgroup":
				tok := strings.TrimSpace(attr.val)
				if tok == "" {
					continue
				}
				if err := validateMemberToken(tok, false); err != nil {
					return nil, fmt.Errorf("%s:%d: %w", srcFile, attr.line, err)
				}
				runasGroups = append(runasGroups, ldifParseRunasGroupMember(tok, srcFile, entry.startLine))
			case "sudooption":
				if err := ldifApplyOptionValue(optState, attr.val, srcFile, entry.startLine); err != nil {
					return nil, err
				}
			case "sudonotbefore":
				if v := strings.TrimSpace(attr.val); v != "" {
					if err := optState.applyNamedCmndOption("notbefore", v, srcFile, attr.line); err != nil {
						return nil, err
					}
				}
			case "sudonotafter":
				if v := strings.TrimSpace(attr.val); v != "" {
					if err := optState.applyNamedCmndOption("notafter", v, srcFile, attr.line); err != nil {
						return nil, err
					}
				}
			case "sudocommand":
				cmdMember, err := sudolParseCommand(ctx, attr.val, srcFile, entry.startLine)
				if err != nil {
					return nil, err
				}
				commands = append(commands, cmdMember)
			case "sudoorder":
				orderStr := strings.TrimSpace(attr.val)
				parsedOrder, err := strconv.Atoi(orderStr)
				if err != nil {
					return nil, fmt.Errorf("%s:%d: invalid sudoOrder %q: %w", srcFile, attr.line, orderStr, err)
				}
				sudoOrder = parsedOrder
			}
		}

		if len(commands) == 0 {
			continue
		}
		if len(hostList) == 0 {
			hostList = []audit.Member{{Hostname: "ALL", File: srcFile, Line: entry.startLine}}
		}

		orderedSpecs = append(orderedSpecs, ldifOrderedSpec{
			order: sudoOrder,
			spec: audit.UserSpec{
				UserList: userList,
				HostList: hostList,
				CmndSpecs: []audit.CmndSpec{{
					RunasUsers:  runasUsers,
					RunasGroups: runasGroups,
					Options:     optState.buildCanonical(),
					Commands:    commands,
				}},
				File: srcFile,
				Line: entry.startLine,
			},
		})
	}

	if !foundSudoEntry {
		return nil, fmt.Errorf("%s: no sudoRole entries found in LDIF", srcFile)
	}

	slices.SortStableFunc(orderedSpecs, func(a, b ldifOrderedSpec) int {
		return cmp.Compare(a.order, b.order)
	})
	for _, item := range orderedSpecs {
		ctx.policy.UserSpecs = append(ctx.policy.UserSpecs, item.spec)
	}

	return ctx.policy, nil
}

type ldifLine struct {
	text string
	line int
}

type ldifAttr struct {
	name string
	val  string
	line int
}

type ldifEntry struct {
	startLine int
	attrs     []ldifAttr
}

type ldifOrderedSpec struct {
	order int
	spec  audit.UserSpec
}

func ldifUnfoldLines(content string, srcFile string, strict bool) ([]ldifLine, error) {
	rawLines := strings.Split(content, "\n")
	var unfolded []ldifLine
	for idx, raw := range rawLines {
		lineNum := idx + 1
		line := strings.TrimSuffix(raw, "\r")
		if strings.HasPrefix(line, "#") {
			continue
		}
		if line == "" {
			unfolded = append(unfolded, ldifLine{text: "", line: lineNum})
			continue
		}
		if line[0] == ' ' {
			if len(unfolded) == 0 || unfolded[len(unfolded)-1].text == "" {
				if strict {
					return nil, fmt.Errorf("%s:%d: unexpected LDIF continuation line", srcFile, lineNum)
				}
				continue
			}
			unfolded[len(unfolded)-1].text += line[1:]
			continue
		}
		unfolded = append(unfolded, ldifLine{text: line, line: lineNum})
	}
	return unfolded, nil
}

func ldifParseAttrLine(line string, srcFile string, lineNum int) (ldifAttr, bool, error) {
	colonIdx := strings.IndexByte(line, ':')
	if colonIdx <= 0 {
		return ldifAttr{}, false, nil
	}
	rawName := line[:colonIdx]
	if !ldifIsValidAttrName(rawName) {
		return ldifAttr{}, false, nil
	}
	baseName := rawName
	if semiIdx := strings.IndexByte(baseName, ';'); semiIdx != -1 {
		baseName = baseName[:semiIdx]
	}
	attrName := strings.ToLower(baseName)
	rest := line[colonIdx+1:]

	if strings.HasPrefix(rest, ":") {
		encoded := strings.TrimSpace(rest[1:])
		decoded, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return ldifAttr{}, true, fmt.Errorf("%s:%d: failed to decode base64 attribute %s: %w", srcFile, lineNum, rawName, err)
		}
		return ldifAttr{name: attrName, val: string(decoded), line: lineNum}, true, nil
	}
	if strings.HasPrefix(rest, "<") {
		return ldifAttr{}, true, fmt.Errorf("%s:%d: LDIF URL attribute (':<') is not supported for %s", srcFile, lineNum, rawName)
	}

	return ldifAttr{name: attrName, val: strings.TrimSpace(rest), line: lineNum}, true, nil
}

func ldifIsValidAttrName(name string) bool {
	if name == "" {
		return false
	}
	first := name[0]
	if !((first >= 'a' && first <= 'z') || (first >= 'A' && first <= 'Z')) {
		return false
	}
	for i := 1; i < len(name); i++ {
		ch := name[i]
		valid := (ch >= 'a' && ch <= 'z') ||
			(ch >= 'A' && ch <= 'Z') ||
			(ch >= '0' && ch <= '9') ||
			ch == '-' || ch == '.' || ch == ';' || ch == '_'
		if !valid {
			return false
		}
	}
	return true
}

func ldifIsSudoEntry(entry ldifEntry) bool {
	for _, attr := range entry.attrs {
		switch attr.name {
		case "objectclass":
			if strings.EqualFold(strings.TrimSpace(attr.val), "sudorole") {
				return true
			}
		case "sudocommand", "sudooption", "sudouser":
			return true
		}
	}
	return false
}

func ldifIsDefaultsEntry(entry ldifEntry) bool {
	hasCNDefaults := false
	hasCommandsOrUsers := false
	for _, attr := range entry.attrs {
		switch attr.name {
		case "cn":
			if strings.EqualFold(strings.TrimSpace(attr.val), "defaults") {
				hasCNDefaults = true
			}
		case "sudocommand", "sudouser":
			hasCommandsOrUsers = true
		}
	}
	return hasCNDefaults && !hasCommandsOrUsers
}

func ldifParseUserMember(rawTok string, filename string, lineNum int) audit.Member {
	return sudolParseUserMember(rawTok, filename, lineNum)
}

func ldifParseRunasGroupMember(rawTok string, filename string, lineNum int) audit.Member {
	return sudolParseGroupMember(rawTok, filename, lineNum)
}

func ldifParseHostMember(rawTok string, filename string, lineNum int) audit.Member {
	tok, negated := stripNegation(rawTok)
	m := audit.Member{Negated: negated, File: filename, Line: lineNum}
	val, wasQuoted := unquoteToken(tok)
	switch {
	case strings.HasPrefix(val, "+"):
		m.Netgroup = val[1:]
	case !wasQuoted && isNetworkAddress(val):
		m.NetworkAddr = val
	default:
		m.Hostname = val
	}
	return m
}

func ldifApplyOptionValue(st *sudolOptionState, raw string, filename string, lineNum int) error {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return fmt.Errorf("%s:%d: empty sudoOption value", filename, lineNum)
	}
	parts, err := splitCommaOutsideQuotes(trimmed)
	if err != nil {
		return fmt.Errorf("%s:%d: %w", filename, lineNum, err)
	}
	for _, part := range parts {
		entry := strings.TrimSpace(part)
		if entry == "" {
			return fmt.Errorf("%s:%d: empty option in sudoOption", filename, lineNum)
		}
		if err := st.applyOptionEntry(entry, filename, lineNum); err != nil {
			return err
		}
	}
	return nil
}
