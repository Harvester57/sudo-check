package audit

import (
	"fmt"
	"path"
	"regexp"
	"strings"
	"sudo-check/pkg/gtfobins"
)

var wildcardRegex = regexp.MustCompile(`[*?\[\]]`)

// editorBinaries lists exact binary names of interactive text editors that allow file modification or shell escape.
// Using an exact set avoids false positives on utilities like visudo, virsh, vipw, or microdnf.
var editorBinaries = map[string]bool{
	"vi":          true,
	"vim":         true,
	"vim.basic":   true,
	"vim.tiny":    true,
	"vim.nox":     true,
	"vim.gtk":     true,
	"vim.gtk3":    true,
	"vim.athena":  true,
	"rvim":        true,
	"rview":       true,
	"view":        true,
	"nvim":        true,
	"neovim":      true,
	"nano":        true,
	"rnano":       true,
	"emacs":       true,
	"emacsclient": true,
	"edit":        true,
	"joe":         true,
	"jmacs":       true,
	"jpico":       true,
	"jstar":       true,
	"rjoe":        true,
	"micro":       true,
	"pico":        true,
	"ed":          true,
	"red":         true,
	"ex":          true,
	"gedit":       true,
	"kate":        true,
	"helix":       true,
	"hx":          true,
	"kak":         true,
}

func isEditorBinary(binaryName string) bool {
	if editorBinaries[binaryName] {
		return true
	}
	if strings.HasPrefix(binaryName, "vim.") || strings.HasPrefix(binaryName, "emacs-") || strings.HasPrefix(binaryName, "emacs2") {
		return true
	}
	return false
}

// noexecImmuneBinaries lists canonical binary basenames where sudo's NOEXEC
// (LD_PRELOAD=sudo_noexec.so) does not neutralize shell/command privilege escalation
// because the binary is itself an interactive shell, a setuid/privilege wrapper
// (where the dynamic linker strips LD_PRELOAD), a static/multi-call shell binary,
// or a client delegating execution to a privileged daemon or runtime.
var noexecImmuneBinaries = map[string]bool{
	"sh":        true,
	"bash":      true,
	"rbash":     true,
	"dash":      true,
	"ash":       true,
	"zsh":       true,
	"ksh":       true,
	"mksh":      true,
	"ksh93":     true,
	"pdksh":     true,
	"csh":       true,
	"tcsh":      true,
	"fish":      true,
	"busybox":   true,
	"su":        true,
	"sudo":      true,
	"doas":      true,
	"pkexec":    true,
	"ksu":       true,
	"sg":        true,
	"docker":    true,
	"podman":    true,
	"kubectl":   true,
	"lxd":       true,
	"ctr":       true,
	"systemctl": true,
}

func isNoexecImmune(binaryName string) bool {
	if noexecImmuneBinaries[binaryName] {
		return true
	}
	for _, candidate := range gtfobins.NormalizeBinaryName(binaryName) {
		if noexecImmuneBinaries[candidate] {
			return true
		}
	}
	return false
}

// splitCommandTokens splits a sudoers command specification into whitespace-delimited tokens
// while preserving whitespace inside POSIX ERE (^...$) tokens, double-quoted strings ("..."),
// and backslash-escaped characters.
func splitCommandTokens(cmdStr string) []string {
	var tokens []string
	var cur strings.Builder
	inQuote := false
	inRegex := false
	escaped := false

	for i := 0; i < len(cmdStr); i++ {
		ch := cmdStr[i]
		if escaped {
			cur.WriteByte(ch)
			escaped = false
			continue
		}
		if ch == '\\' {
			cur.WriteByte(ch)
			escaped = true
			continue
		}
		if inRegex {
			cur.WriteByte(ch)
			if ch == '$' {
				inRegex = false
			}
			continue
		}
		if inQuote {
			cur.WriteByte(ch)
			if ch == '"' {
				inQuote = false
			}
			continue
		}
		if ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n' {
			if cur.Len() > 0 {
				tokens = append(tokens, cur.String())
				cur.Reset()
			}
			continue
		}
		if ch == '^' && cur.Len() == 0 {
			inRegex = true
			cur.WriteByte(ch)
			continue
		}
		if ch == '"' {
			inQuote = true
			cur.WriteByte(ch)
			continue
		}
		cur.WriteByte(ch)
	}
	if cur.Len() > 0 {
		tokens = append(tokens, cur.String())
	}
	return tokens
}

func isRegexCommand(exePath string) bool {
	return len(exePath) >= 2 && strings.HasPrefix(exePath, "^") && strings.HasSuffix(exePath, "$")
}

func stripOuterParens(s string) string {
	for len(s) >= 2 && s[0] == '(' && s[len(s)-1] == ')' {
		depth := 0
		escaped := false
		matchesEnd := true
		for i := 0; i < len(s); i++ {
			ch := s[i]
			if escaped {
				escaped = false
				continue
			}
			if ch == '\\' {
				escaped = true
				continue
			}
			if ch == '(' {
				depth++
			} else if ch == ')' {
				depth--
				if depth == 0 && i < len(s)-1 {
					matchesEnd = false
					break
				}
			}
		}
		if !matchesEnd || depth != 0 {
			break
		}
		s = s[1 : len(s)-1]
		if strings.HasPrefix(s, "?:") {
			s = s[2:]
		}
	}
	return s
}

func splitTopLevelAlternations(s string) []string {
	var parts []string
	depth := 0
	escaped := false
	start := 0
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if escaped {
			escaped = false
			continue
		}
		if ch == '\\' {
			escaped = true
			continue
		}
		switch ch {
		case '(':
			depth++
		case ')':
			if depth > 0 {
				depth--
			}
		case '|':
			if depth == 0 {
				parts = append(parts, s[start:i])
				start = i + 1
			}
		}
	}
	parts = append(parts, s[start:])
	return parts
}

func regexBasename(s string) string {
	lastSlash := -1
	depth := 0
	escaped := false
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if escaped {
			escaped = false
			continue
		}
		if ch == '\\' {
			escaped = true
			continue
		}
		switch ch {
		case '(':
			depth++
		case ')':
			if depth > 0 {
				depth--
			}
		case '/':
			if depth == 0 {
				lastSlash = i
			}
		}
	}
	if lastSlash != -1 {
		return s[lastSlash+1:]
	}
	return s
}

func expandBasenameAlternations(base string) []string {
	base = stripOuterParens(base)
	alts := splitTopLevelAlternations(base)
	if len(alts) > 1 {
		var out []string
		for _, a := range alts {
			out = append(out, expandBasenameAlternations(a)...)
		}
		return out
	}

	// Handle inline grouping such as "python(2|3)" or "python3(\.[0-9]+)?".
	escaped := false
	openIdx := -1
	closeIdx := -1
	depth := 0
	for i := 0; i < len(base); i++ {
		ch := base[i]
		if escaped {
			escaped = false
			continue
		}
		if ch == '\\' {
			escaped = true
			continue
		}
		if ch == '(' {
			if depth == 0 {
				openIdx = i
			}
			depth++
		} else if ch == ')' && depth > 0 {
			depth--
			if depth == 0 && openIdx != -1 {
				closeIdx = i
				break
			}
		}
	}
	if openIdx != -1 && closeIdx != -1 {
		prefix := base[:openIdx]
		group := stripOuterParens(base[openIdx : closeIdx+1])
		suffix := base[closeIdx+1:]
		optional := false
		if strings.HasPrefix(suffix, "?") || strings.HasPrefix(suffix, "*") {
			optional = true
			suffix = suffix[1:]
		}
		groupAlts := splitTopLevelAlternations(group)
		var out []string
		if len(groupAlts) > 1 {
			for _, branch := range groupAlts {
				out = append(out, prefix+branch+suffix)
			}
			if optional {
				out = append(out, prefix+suffix)
			}
			return out
		}
		if optional {
			out = append(out, prefix+suffix)
			out = append(out, prefix+group+suffix)
			return out
		}
	}
	return []string{base}
}

func cleanRegexBinaryCandidate(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	// Strip common trailing wildcard quantifiers (e.g. "journalctl.*").
	for _, suf := range []string{".*", ".+", "?"} {
		if strings.HasSuffix(s, suf) && len(s) > len(suf) {
			s = strings.TrimSuffix(s, suf)
		}
	}
	// Unescape literal filename characters such as \. or \-.
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			i++
			b.WriteByte(s[i])
			continue
		}
		b.WriteByte(s[i])
	}
	candidate := b.String()
	if candidate == "" || candidate == "." || candidate == ".." {
		return ""
	}
	for i := 0; i < len(candidate); i++ {
		c := candidate[i]
		valid := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-' || c == '+'
		if !valid {
			return ""
		}
	}
	return candidate
}

// extractRegexBinaries extracts candidate binary basenames from a POSIX ERE command path
// such as "^/usr/bin/python3$", "^/usr/bin/(vim|nano)$", or "^(/usr/bin/vim|/usr/bin/nano)$".
func extractRegexBinaries(exePath string) []string {
	inner := strings.TrimSuffix(strings.TrimPrefix(exePath, "^"), "$")
	if inner == "" {
		return nil
	}

	alts := splitTopLevelAlternations(stripOuterParens(inner))
	var candidates []string
	seen := make(map[string]bool)
	for _, alt := range alts {
		base := regexBasename(alt)
		if base == "" {
			continue
		}
		for _, item := range expandBasenameAlternations(base) {
			if c := cleanRegexBinaryCandidate(item); c != "" && !seen[c] {
				seen[c] = true
				candidates = append(candidates, c)
			}
		}
	}
	return candidates
}

// isWritableOrTempPath checks if a path equals or resides inside a temporary or user-writable directory tree.
func isWritableOrTempPath(exePath string) bool {
	cleaned := path.Clean(exePath)
	unsafeDirs := []string{
		"/tmp",
		"/var/tmp",
		"/dev/shm",
		"/home",
		"/run/user",
		"/var/mail",
		"/var/spool/samba",
	}
	for _, dir := range unsafeDirs {
		if cleaned == dir || strings.HasPrefix(cleaned, dir+"/") {
			return true
		}
	}
	return false
}

// isSensitiveSudoeditTarget checks if a file path targeted by sudoedit is a critical system configuration or credential file.
func isSensitiveSudoeditTarget(target string) bool {
	cleaned := path.Clean(target)
	if cleaned == "/" || cleaned == "/*" || cleaned == "/etc" || cleaned == "/etc/*" {
		return true
	}
	if strings.HasPrefix(cleaned, "/etc/") {
		rest := strings.TrimPrefix(cleaned, "/etc/")
		if !strings.Contains(rest, "/") && wildcardRegex.MatchString(rest) {
			return true
		}
	}
	sensitivePrefixes := []string{
		"/etc/sudoers",
		"/etc/shadow",
		"/etc/gshadow",
		"/etc/passwd",
		"/etc/group",
		"/etc/pam.d",
		"/etc/systemd",
		"/etc/crontab",
		"/etc/cron",
		"/etc/ssh/sshd_config",
		"/etc/ld.so",
		"/etc/security",
		"/etc/profile",
		"/etc/rc.local",
		"/etc/init.d",
		"/etc/nsswitch.conf",
		"/etc/modprobe.d",
		"/etc/modules",
		"/etc/apt",
		"/etc/yum.repos.d",
		"/etc/polkit-1",
		"/etc/logrotate.d",
		"/etc/udev",
		"/etc/sysctl",
		"/var/spool/cron",
		"/usr/lib/systemd",
		"/lib/systemd",
		"/root",
	}
	for _, prefix := range sensitivePrefixes {
		if cleaned == prefix || strings.HasPrefix(cleaned, prefix+"/") || strings.HasPrefix(cleaned, prefix+".") {
			return true
		}
	}
	return false
}

// AuditCommands runs checks on allowed user commands (User_Specs).
func AuditCommands(policy *SudoersPolicy, gtfoClient *gtfobins.Client) []Finding {
	return auditCommandsWithOptions(policy, gtfoClient, AuditOptions{})
}

func auditCommandsWithOptions(policy *SudoersPolicy, gtfoClient *gtfobins.Client, opts AuditOptions) []Finding {
	if policy == nil {
		return nil
	}
	var findings []Finding

	for _, spec := range policy.UserSpecs {
		resolvedUsers := resolveMemberSlice(spec.UserList, policy, aliasKindUser)
		var users []string
		var negatedUsers []string
		for _, u := range resolvedUsers {
			if name := u.GetName(); name != "" {
				users = append(users, name)
			}
			if u.Negated {
				negatedUsers = append(negatedUsers, u.GetName())
			}
		}
		usersStr := strings.Join(users, ", ")

		resolvedHosts := resolveMemberSlice(spec.HostList, policy, aliasKindHost)
		var hosts []string
		var negatedHosts []string
		for _, h := range resolvedHosts {
			if name := h.GetName(); name != "" {
				hosts = append(hosts, name)
			}
			if h.Negated {
				negatedHosts = append(negatedHosts, h.GetName())
			}
		}
		hostsStr := strings.Join(hosts, ", ")

		if len(negatedUsers) > 0 || len(negatedHosts) > 0 {
			negList := append(append([]string(nil), negatedUsers...), negatedHosts...)
			posUser := "AUTHORIZED_USERS"
			posHost := hostsStr
			if len(negatedHosts) > 0 || posHost == "" {
				posHost = "ALL"
			}
			findings = append(findings, Finding{
				ID:          "SUDO-CMD-008",
				Title:       "Negated User or Host Specification",
				Description: fmt.Sprintf("The policy uses negation (%s) in the User_List or Host_List for rule targeting [%s] on [%s]. Exclusion-based access controls in sudoers are brittle and can be bypassed via secondary groups or host spoofing (e.g. CVE-2025-32462).", strings.Join(negList, ", "), usersStr, hostsStr),
				Severity:    SeverityHigh,
				User:        usersStr,
				Host:        hostsStr,
				SourceLine:  spec.RawLine,
				Context:     spec.File,
				Line:        spec.Line,
				Remediation: "Avoid using negation (!) in User_List or Host_List specifications; define explicit positive allowlists instead.",
				RemediationCode: fmt.Sprintf(
					"User_Alias %s = alice, bob\n%s %s = (root) /usr/bin/id \"\"",
					posUser, posUser, posHost,
				),
				Compliance: []string{"ANSSI-BP-028 R42"},
			})
		}

		for _, cs := range spec.CmndSpecs {
			csStartIdx := len(findings)
			resolvedRunasUsers := resolveMemberSlice(cs.RunasUsers, policy, aliasKindRunas)
			resolvedRunasGroups := resolveMemberSlice(cs.RunasGroups, policy, aliasKindRunas)
			runasStr, negatedRunas := formatRunas(resolvedRunasUsers, resolvedRunasGroups)

			if len(negatedRunas) > 0 {
				findings = append(findings, Finding{
					ID:          "SUDO-CMD-008",
					Title:       "Negated Runas User or Group Specification",
					Description: fmt.Sprintf("The command specification for user(s) [%s] contains negated Runas target(s) [%s]. Negated Runas rules (such as '(ALL, !root)') are discouraged by ANSSI BP-028 and have historically enabled root escalation (e.g. CVE-2019-14287).", usersStr, strings.Join(negatedRunas, ", ")),
					Severity:    SeverityHigh,
					User:        usersStr,
					Host:        hostsStr,
					Runas:       runasStr,
					Context:     spec.File,
					Line:        spec.Line,
					Remediation: "Replace negated Runas lists with an explicit positive list of permitted target accounts.",
					RemediationCode: fmt.Sprintf(
						"Runas_Alias ALLOWED_RUNAS = www-data, postgres\n%s %s = (ALLOWED_RUNAS) /usr/bin/id \"\"",
						usersStr, hostsStr,
					),
					Compliance: []string{"ANSSI-BP-028 R42"},
				})
			}

			// Gather all commands, resolving any aliases if present
			var allCmdMembers []Member
			for _, cmdMember := range cs.Commands {
				allCmdMembers = append(allCmdMembers, resolveCommands(cmdMember, policy)...)
			}

			// Audit dangerous per-command options (SETENV, sudoedit_follow, runchroot, runcwd)
			findings = append(findings, auditCmndSpecOptions(cs.Options, allCmdMembers, usersStr, hostsStr, runasStr, spec.File, spec.Line)...)

			// Check for missing SELinux context elevation on administrator-grade rules (SUDO-CMD-013)
			findings = append(findings, auditSELinuxContextElevation(cs.Options, allCmdMembers, resolvedRunasUsers, usersStr, hostsStr, runasStr, spec.File, spec.Line)...)

			for _, cmdMember := range allCmdMembers {
				cmdStr := cmdMember.Command
				if cmdStr == "" {
					continue
				}
				file, line := spec.File, spec.Line
				if spec.RawLine == "" {
					if cmdMember.File != "" {
						file = cmdMember.File
					}
					if cmdMember.Line != 0 {
						line = cmdMember.Line
					}
				} else {
					if file == "" {
						file = cmdMember.File
					}
					if line == 0 {
						line = cmdMember.Line
					}
				}

				flagRes := resolveEffectiveFlagsDetailed(policy, resolvedUsers, resolvedHosts, resolvedRunasUsers, cmdStr, cs.Options)
				noPasswd, noExec := flagRes.noPasswd, flagRes.noExec

				// Check 1: Command Negation Bypass (e.g. !/usr/bin/passwd)
				if cmdMember.Negated {
					findings = append(findings, Finding{
						ID:              "SUDO-CMD-001",
						Title:           "Negated Command Policy",
						Description:     fmt.Sprintf("The policy contains a negated command '%s' for user(s) [%s]. Sudo command negation is easily bypassed by copying or hardlinking/symlinking the binary, or invoking alternative paths/arguments.", cmdStr, usersStr),
						Severity:        SeverityHigh,
						User:            usersStr,
						Host:            hostsStr,
						Runas:           runasStr,
						Command:         cmdStr,
						Context:         file,
						Line:            line,
						Remediation:     "Avoid using negated commands (!) to enforce restrictions. Instead, use a strict allowlist of permitted commands.",
						RemediationCode: fmt.Sprintf("%s %s = (%s) /usr/bin/systemctl status app", usersStr, hostsStr, runasStr),
						Compliance:      []string{"ANSSI-BP-028 R42"},
					})
					continue
				}

				// Split command to get the executable path and arguments (regex- and quote-aware)
				parts := splitCommandTokens(cmdStr)

				// Check weak cryptographic digest (SHA-224)
				if cmdMember.HasWeakDigestOnly() && len(parts) > 0 {
					exeForDigest := parts[0]
					findings = append(findings, Finding{
						ID:          "SUDO-CMD-012",
						Title:       "Weak Cryptographic Digest on Command (SHA-224)",
						Description: fmt.Sprintf("The command '%s' for user(s) [%s] uses a SHA-224 digest. Stronger hash functions such as SHA-256 or SHA-512 are recommended for integrity pinning.", cmdStr, usersStr),
						Severity:    SeverityLow,
						User:        usersStr,
						Host:        hostsStr,
						Runas:       runasStr,
						Command:     cmdStr,
						Context:     file,
						Line:        line,
						Remediation: "Use 'sha256:' or 'sha512:' digests when pinning command integrity in sudoers.",
						RemediationCode: fmt.Sprintf(
							"# 1. Compute SHA-256 digest:\nsha256sum %s\n\n# 2. Pin in sudoers:\n%s %s = (%s) sha256:<64-hex-digest> %s",
							exeForDigest, usersStr, hostsStr, runasStr, cmdStr,
						),
						Compliance: []string{},
					})
				}

				// Check 2: ALL Commands Allowed
				if cmdStr == "ALL" {
					sev := SeverityHigh
					title := "Full Root Privileges Allowed"
					desc := fmt.Sprintf("The policy allows user(s) [%s] to run any command (ALL) on host(s) [%s] as [%s]. This grants full administrative control.", usersStr, hostsStr, runasStr)
					remediation := "Restrict privileges to only the specific commands required for the user's role."
					remediationCode := fmt.Sprintf(
						"Cmnd_Alias ALLOWED_CMDS = /usr/bin/systemctl restart app, /usr/bin/systemctl status app\n%s %s = (%s) ALLOWED_CMDS",
						usersStr, hostsStr, runasStr,
					)
					id := "SUDO-CMD-002"
					compliance := []string{"ANSSI-BP-028 R43"}
					inheritedDef := ""

					if noPasswd {
						sev = SeverityCritical
						title = "Passwordless Full Root Privileges Allowed (NOPASSWD)"
						desc = fmt.Sprintf("The policy allows user(s) [%s] to run any command (ALL) on host(s) [%s] as [%s] without a password (NOPASSWD). Any compromise of this user account leads to immediate privilege escalation.", usersStr, hostsStr, runasStr)
						remediationCode = fmt.Sprintf(
							"%s %s = (%s) PASSWD: /usr/bin/systemctl restart app",
							usersStr, hostsStr, runasStr,
						)
						id = "SUDO-CMD-003"
						compliance = append(compliance, "CIS-5.2.4")
						inheritedDef = flagRes.noPasswdInherited
					}

					findings = append(findings, Finding{
						ID:                id,
						Title:             title,
						Description:       desc,
						Severity:          sev,
						User:              usersStr,
						Host:              hostsStr,
						Runas:             runasStr,
						Command:           cmdStr,
						InheritedDefaults: inheritedDef,
						Context:           file,
						Line:              line,
						Remediation:       remediation,
						RemediationCode:   remediationCode,
						Compliance:        compliance,
					})
					continue
				}

				if len(parts) == 0 {
					continue
				}
				exePath := parts[0]
				binaryName := path.Base(exePath)

				// Check directory execution (e.g. /usr/bin/, /bin/, /usr/local/bin/, /)
				if strings.HasPrefix(exePath, "/") && strings.HasSuffix(exePath, "/") {
					sev := SeverityHigh
					compliance := []string{"ANSSI-BP-028 R43"}
					desc := fmt.Sprintf("The policy permits user(s) [%s] to execute any binary inside directory '%s' on host(s) [%s] as [%s]. Granting directory-wide execution exposes all current and future binaries in that directory, including potential privilege escalation vectors.", usersStr, exePath, hostsStr, runasStr)
					tagPrefix := ""
					inheritedDef := ""
					if noPasswd {
						sev = SeverityCritical
						compliance = append(compliance, "CIS-5.2.4")
						desc = fmt.Sprintf("The policy permits user(s) [%s] to execute any binary inside directory '%s' on host(s) [%s] as [%s] without a password (NOPASSWD). Granting passwordless directory-wide execution enables immediate privilege escalation via binaries in that directory.", usersStr, exePath, hostsStr, runasStr)
						tagPrefix = "PASSWD: "
						inheritedDef = flagRes.noPasswdInherited
					}
					exampleBin := path.Clean(exePath)
					if exampleBin == "/" {
						exampleBin = "/usr/bin/id"
					} else {
						exampleBin = exampleBin + "/allowed-cmd"
					}
					findings = append(findings, Finding{
						ID:                "SUDO-CMD-014",
						Title:             "Directory Execution Permitted in Sudoers",
						Description:       desc,
						Severity:          sev,
						User:              usersStr,
						Host:              hostsStr,
						Runas:             runasStr,
						Command:           cmdStr,
						InheritedDefaults: inheritedDef,
						Context:           file,
						Line:              line,
						Remediation:       "Replace directory-level execution rules with an explicit allowlist of required absolute binary paths and strict argument specifications.",
						RemediationCode:   fmt.Sprintf("%s %s = (%s) %s%s \"\"", usersStr, hostsStr, runasStr, tagPrefix, exampleBin),
						Compliance:        compliance,
					})
					continue
				}

				// Check 3: Wildcards in command spec (e.g., /usr/bin/cat /var/log/*)
				if wildcardRegex.MatchString(cmdStr) {
					safeCmdExample := fmt.Sprintf("%s \"\"", exePath)
					if len(parts) > 1 {
						cleanArg := wildcardRegex.ReplaceAllString(strings.Join(parts[1:], " "), "explicit_target")
						safeCmdExample = fmt.Sprintf("%s %s", exePath, cleanArg)
					}
					findings = append(findings, Finding{
						ID:              "SUDO-CMD-004",
						Title:           "Wildcard in Command Definition",
						Description:     fmt.Sprintf("The command '%s' allowed for user(s) [%s] contains wildcards. Arguments matching wildcards in sudoers can often be bypassed using directory traversals (e.g. '/var/log/../../etc/shadow') or option injection.", cmdStr, usersStr),
						Severity:        SeverityMedium,
						User:            usersStr,
						Host:            hostsStr,
						Runas:           runasStr,
						Command:         cmdStr,
						Context:         file,
						Line:            line,
						Remediation:     "Avoid wildcards in command paths. Use specific paths or write wrapper scripts that validate inputs before executing commands.",
						RemediationCode: fmt.Sprintf("%s %s = (%s) %s", usersStr, hostsStr, runasStr, safeCmdExample),
						Compliance:      []string{"ANSSI-BP-028 R43"},
					})
				}

				// Special handling for sudoedit
				if exePath == "sudoedit" {
					if len(parts) == 1 {
						findings = append(findings, Finding{
							ID:              "SUDO-CMD-006",
							Title:           "Missing Command Argument Restrictions",
							Description:     fmt.Sprintf("The command '%s' allowed for user(s) [%s] does not specify target file restrictions, allowing arbitrary files to be edited as [%s].", cmdStr, usersStr, runasStr),
							Severity:        SeverityCritical,
							User:            usersStr,
							Host:            hostsStr,
							Runas:           runasStr,
							Command:         cmdStr,
							Context:         file,
							Line:            line,
							Remediation:     "Explicitly specify the exact absolute file paths that may be edited with 'sudoedit'.",
							RemediationCode: fmt.Sprintf("%s %s = (%s) sudoedit /etc/myapp/config.conf", usersStr, hostsStr, runasStr),
							Compliance:      []string{"ANSSI-BP-028 R43"},
						})
					} else {
						for _, arg := range parts[1:] {
							if isSensitiveSudoeditTarget(arg) {
								findings = append(findings, Finding{
									ID:              "SUDO-CMD-010",
									Title:           "sudoedit Permitted on Sensitive System File",
									Description:     fmt.Sprintf("The rule allows user(s) [%s] to edit sensitive system path '%s' via sudoedit as [%s], enabling direct privilege escalation or policy modification.", usersStr, arg, runasStr),
									Severity:        SeverityCritical,
									User:            usersStr,
									Host:            hostsStr,
									Runas:           runasStr,
									Command:         cmdStr,
									Context:         file,
									Line:            line,
									Remediation:     "Remove sensitive system configuration and authentication files from 'sudoedit' rules.",
									RemediationCode: fmt.Sprintf("%s %s = (%s) sudoedit /etc/myapp/config.conf", usersStr, hostsStr, runasStr),
									Compliance:      []string{},
								})
								break
							}
						}
					}
					if noPasswd {
						targetArgs := "/etc/myapp/config.conf"
						if len(parts) > 1 {
							targetArgs = strings.Join(parts[1:], " ")
						}
						findings = append(findings, Finding{
							ID:                "SUDO-CMD-005",
							Title:             "Passwordless sudoedit Execution Allowed (NOPASSWD)",
							Description:       fmt.Sprintf("The user(s) [%s] are permitted to run '%s' as [%s] without entering a password (NOPASSWD). Passwordless privileged file editing expands the local attack surface if the account is compromised.", usersStr, cmdStr, runasStr),
							Severity:          SeverityLow,
							User:              usersStr,
							Host:              hostsStr,
							Runas:             runasStr,
							Command:           cmdStr,
							InheritedDefaults: flagRes.noPasswdInherited,
							Context:           file,
							Line:              line,
							Remediation:       "Require password authentication for sudoedit rules by removing NOPASSWD or explicitly specifying PASSWD:.",
							RemediationCode:   fmt.Sprintf("%s %s = (%s) PASSWD: sudoedit %s", usersStr, hostsStr, runasStr, targetArgs),
							Compliance:        []string{"CIS-5.2.4"},
						})
					}
					continue
				}

				isRegex := isRegexCommand(exePath)
				var candidateBinaries []string
				if isRegex {
					candidateBinaries = extractRegexBinaries(exePath)
				} else {
					candidateBinaries = []string{binaryName}
				}

				// Check for relative command path or writable directory path (SUDO-CMD-011)
				if isRegex {
					if !strings.HasPrefix(exePath, "^/") {
						argSuffix := "\"\""
						if len(parts) > 1 {
							argSuffix = strings.Join(parts[1:], " ")
						}
						suggestedBin := binaryName
						if len(candidateBinaries) > 0 {
							suggestedBin = candidateBinaries[0]
						}
						findings = append(findings, Finding{
							ID:              "SUDO-CMD-011",
							Title:           "Relative Command Path in Sudoers Policy",
							Description:     fmt.Sprintf("The regex command '%s' allowed for user(s) [%s] does not anchor an absolute executable path ('^/'). Sudoers rules must always anchor full absolute paths to prevent PATH hijacking.", cmdStr, usersStr),
							Severity:        SeverityHigh,
							User:            usersStr,
							Host:            hostsStr,
							Runas:           runasStr,
							Command:         cmdStr,
							Context:         file,
							Line:            line,
							Remediation:     "Anchor the regex to a full absolute path (e.g. '^/usr/bin/" + suggestedBin + "$').",
							RemediationCode: fmt.Sprintf("%s %s = (%s) /usr/bin/%s %s", usersStr, hostsStr, runasStr, suggestedBin, argSuffix),
							Compliance:      []string{},
						})
					} else if innerPath := strings.TrimSuffix(strings.TrimPrefix(exePath, "^"), "$"); isWritableOrTempPath(innerPath) {
						suggestedBin := "script"
						if len(candidateBinaries) > 0 {
							suggestedBin = candidateBinaries[0]
						}
						findings = append(findings, Finding{
							ID:          "SUDO-CMD-011",
							Title:       "Command Located in Temporary or User-Writable Directory",
							Description: fmt.Sprintf("The regex command '%s' allowed for user(s) [%s] matches executables in a temporary or user-writable directory tree. Local users may modify or replace the executable to run arbitrary code as [%s].", cmdStr, usersStr, runasStr),
							Severity:    SeverityCritical,
							User:        usersStr,
							Host:        hostsStr,
							Runas:       runasStr,
							Command:     cmdStr,
							Context:     file,
							Line:        line,
							Remediation: "Move scripts and binaries to a root-owned directory with strict permissions (such as '/usr/local/sbin' mode 0755) and pin their SHA-256 digest.",
							RemediationCode: fmt.Sprintf(
								"sudo install -o root -g root -m 0755 <binary> /usr/local/sbin/%s\nsudo sha256sum /usr/local/sbin/%s\n# In visudo:\n%s %s = (%s) sha256:<digest> /usr/local/sbin/%s \"\"",
								suggestedBin, suggestedBin, usersStr, hostsStr, runasStr, suggestedBin,
							),
							Compliance: []string{},
						})
					}
				} else if !strings.HasPrefix(exePath, "/") {
					argSuffix := "\"\""
					if len(parts) > 1 {
						argSuffix = strings.Join(parts[1:], " ")
					}
					findings = append(findings, Finding{
						ID:              "SUDO-CMD-011",
						Title:           "Relative Command Path in Sudoers Policy",
						Description:     fmt.Sprintf("The command '%s' allowed for user(s) [%s] uses a non-absolute executable path '%s'. Sudoers rules must always use full absolute paths to prevent PATH hijacking.", cmdStr, usersStr, exePath),
						Severity:        SeverityHigh,
						User:            usersStr,
						Host:            hostsStr,
						Runas:           runasStr,
						Command:         cmdStr,
						Context:         file,
						Line:            line,
						Remediation:     "Specify the full absolute path to the executable (e.g. '/usr/bin/" + binaryName + "').",
						RemediationCode: fmt.Sprintf("%s %s = (%s) /usr/bin/%s %s", usersStr, hostsStr, runasStr, binaryName, argSuffix),
						Compliance:      []string{},
					})
				} else if isWritableOrTempPath(exePath) {
					findings = append(findings, Finding{
						ID:          "SUDO-CMD-011",
						Title:       "Command Located in Temporary or User-Writable Directory",
						Description: fmt.Sprintf("The command '%s' allowed for user(s) [%s] executes '%s' from a temporary or user-writable directory tree. Local users may modify or replace the executable to run arbitrary code as [%s].", cmdStr, usersStr, exePath, runasStr),
						Severity:    SeverityCritical,
						User:        usersStr,
						Host:        hostsStr,
						Runas:       runasStr,
						Command:     cmdStr,
						Context:     file,
						Line:        line,
						Remediation: "Move scripts and binaries to a root-owned directory with strict permissions (such as '/usr/local/sbin' mode 0755) and pin their SHA-256 digest.",
						RemediationCode: fmt.Sprintf(
							"sudo install -o root -g root -m 0755 %s /usr/local/sbin/%s\nsudo sha256sum /usr/local/sbin/%s\n# In visudo:\n%s %s = (%s) sha256:<digest> /usr/local/sbin/%s \"\"",
							exePath, binaryName, binaryName, usersStr, hostsStr, runasStr, binaryName,
						),
						Compliance: []string{},
					})
				}

				// Check 5: Missing Command Argument Restrictions (SUDO-CMD-006)
				if len(parts) == 1 {
					findings = append(findings, Finding{
						ID:              "SUDO-CMD-006",
						Title:           "Missing Command Argument Restrictions",
						Description:     fmt.Sprintf("The command '%s' allowed for user(s) [%s] does not specify any argument restrictions. This permits the user to run the command with arbitrary arguments, which can be abused to bypass restrictions or inject options.", cmdStr, usersStr),
						Severity:        SeverityMedium,
						User:            usersStr,
						Host:            hostsStr,
						Runas:           runasStr,
						Command:         cmdStr,
						Context:         file,
						Line:            line,
						Remediation:     "Strictly specify the allowed arguments. If the command should be run without any arguments, append empty double quotes '\"\"' to the command (e.g., 'dmesg \"\"').",
						RemediationCode: fmt.Sprintf("%s %s = (%s) %s \"\"", usersStr, hostsStr, runasStr, exePath),
						Compliance:      []string{"ANSSI-BP-028 R43"},
					})
				}

				// Check 6: Direct Text Editor Execution (SUDO-CMD-007)
				for _, candBin := range candidateBinaries {
					if isEditorBinary(candBin) {
						targetFile := "/etc/myapp/config.conf"
						if len(parts) > 1 && parts[1] != "\"\"" && !wildcardRegex.MatchString(parts[1]) && !isSensitiveSudoeditTarget(parts[1]) {
							targetFile = strings.Join(parts[1:], " ")
						}
						findings = append(findings, Finding{
							ID:          "SUDO-CMD-007",
							Title:       "Direct Text Editor Execution via Sudo",
							Description: fmt.Sprintf("The command '%s' allowed for user(s) [%s] invokes a text editor directly under sudo. Text editors typically allow escaping to a shell or editing arbitrary system files. Use 'sudoedit' instead to safely edit files with current user privileges.", cmdStr, usersStr),
							Severity:    SeverityHigh,
							User:        usersStr,
							Host:        hostsStr,
							Runas:       runasStr,
							Command:     cmdStr,
							Context:     file,
							Line:        line,
							Remediation: "Replace direct text editor execution rules with 'sudoedit' permissions for specific files.",
							RemediationCode: fmt.Sprintf(
								"Defaults !sudoedit_follow, sudoedit_checkdir\n%s %s = (%s) sudoedit %s",
								usersStr, hostsStr, runasStr, targetFile,
							),
							Compliance: []string{"ANSSI-BP-028 R44"},
						})
						break
					}
				}

				// Check 4: GTFObins Escalation Match (Consolidated to 1 finding per (rule, binary, function))
				anyGTFOBypass := false
				allGTFOMitigated := true
				for _, candBin := range candidateBinaries {
					bypasses := consolidateBypassesByFunction(gtfoClient.CheckBinary(candBin))
					if len(bypasses) == 0 {
						continue
					}
					anyGTFOBypass = true
					for _, bypass := range bypasses {
						// Evaluate if noexec mitigates child process execution (shell / command).
						// Binaries in noexecImmuneBinaries (shells, setuid wrappers, daemon clients)
						// cannot be neutralized by LD_PRELOAD=sudo_noexec.so.
						mitigated := false
						if noExec && (bypass.Function == "shell" || bypass.Function == "command") && !isNoexecImmune(candBin) {
							mitigated = true
						}
						if !mitigated {
							allGTFOMitigated = false
						}

						isPurelyInherited := bypass.InheritedFrom != "" && !bypass.HasDirect && !isEditorBinary(candBin)
						sev := SeverityHigh
						id := "SUDO-GTFO-001"
						title := fmt.Sprintf("Dangerous Sudo Binary allowed: %s (%s)", candBin, bypass.Function)
						desc := fmt.Sprintf("The user(s) [%s] can run '%s' via sudo as [%s], which is listed in GTFObins with the '%s' capability.", usersStr, cmdStr, runasStr, bypass.Function)
						if isPurelyInherited {
							desc = fmt.Sprintf("The user(s) [%s] can run '%s' via sudo as [%s], which is listed in GTFObins with the '%s' capability (inherited via %s).", usersStr, cmdStr, runasStr, bypass.Function, bypass.InheritedFrom)
						}

						if noPasswd {
							sev = SeverityCritical
							id = "SUDO-GTFO-002"
							title = fmt.Sprintf("Passwordless Dangerous Sudo Binary allowed: %s (%s)", candBin, bypass.Function)
							if isPurelyInherited {
								desc = fmt.Sprintf("The user(s) [%s] can run '%s' via sudo as [%s] without a password (NOPASSWD) with the '%s' capability (inherited via %s). This can enable privilege escalation if the inherited '%s' behavior can be triggered.", usersStr, cmdStr, runasStr, bypass.Function, bypass.InheritedFrom, bypass.InheritedFrom)
							} else {
								desc = fmt.Sprintf("The user(s) [%s] can run '%s' via sudo as [%s] without a password (NOPASSWD) with the '%s' capability. This enables immediate privilege escalation.", usersStr, cmdStr, runasStr, bypass.Function)
							}
						}

						if mitigated {
							sev = SeverityLow
							id = "SUDO-GTFO-003"
							title = fmt.Sprintf("Mitigated Dangerous Sudo Binary: %s (%s)", candBin, bypass.Function)
							desc = fmt.Sprintf("The user(s) [%s] can run '%s' via sudo as [%s], which has a '%s' capability in GTFObins. However, the rule enforces 'NOEXEC', which mitigates child-process execution vectors.", usersStr, cmdStr, runasStr, bypass.Function)
						}

						exploitability := ""
						if opts.SubcommandAwareGTFO && !isRegex && !mitigated {
							constrained, rationale := EvaluateGTFOArgumentConstraint(candBin, parts[1:], bypass.Function)
							if constrained {
								exploitability = "CONSTRAINED"
								if noPasswd {
									sev = SeverityMedium
								} else {
									sev = SeverityLow
								}
								desc += "\nSubcommand Constraint: " + rationale
							}
						}

						commentStr := ""
						if bypass.Comment != "" {
							commentStr = fmt.Sprintf("\nGTFObins Context: %s", bypass.Comment)
						}

						gtfoRemCode := buildGTFORemediationCode(usersStr, hostsStr, runasStr, exePath, candBin, parts, bypass.Function)
						inheritedDef := ""
						if mitigated {
							inheritedDef = flagRes.noExecInherited
						} else if noPasswd {
							inheritedDef = flagRes.noPasswdInherited
						}

						findings = append(findings, Finding{
							ID:                id,
							Title:             title,
							Description:       desc + commentStr,
							Severity:          sev,
							User:              usersStr,
							Host:              hostsStr,
							Runas:             runasStr,
							Command:           cmdStr,
							InheritedDefaults: inheritedDef,
							Context:           file,
							Line:              line,
							Remediation:       "Remove this binary from sudoers or replace it with a tightly scoped wrapper script.",
							RemediationCode:   gtfoRemCode,
							ExploitPoC:        bypass.Code,
							Exploitability:    exploitability,
							Compliance:        []string{"MITRE-T1548.003"},
						})
					}
				}

				if noPasswd && (!anyGTFOBypass || allGTFOMitigated) {
					lockedCmd := cmdStr
					if len(parts) == 1 {
						lockedCmd = cmdStr + " \"\""
					}
					findings = append(findings, Finding{
						ID:                "SUDO-CMD-005",
						Title:             "Passwordless Specific Command Execution Allowed (NOPASSWD)",
						Description:       fmt.Sprintf("The user(s) [%s] are permitted to run the specific command '%s' as [%s] without entering a password (NOPASSWD). While restricted to this binary, any command running passwordless expands the local attack surface if it has argument parsing or script vulnerabilities.", usersStr, cmdStr, runasStr),
						Severity:          SeverityLow,
						User:              usersStr,
						Host:              hostsStr,
						Runas:             runasStr,
						Command:           cmdStr,
						InheritedDefaults: flagRes.noPasswdInherited,
						Context:           file,
						Line:              line,
						Remediation:       "Ensure that passwordless privileges are strictly necessary. If possible, require authentication or implement strict input validation inside target wrapper scripts.",
						RemediationCode:   fmt.Sprintf("%s %s = (%s) PASSWD: NOEXEC: %s", usersStr, hostsStr, runasStr, lockedCmd),
						Compliance:        []string{"CIS-5.2.4"},
					})
				}
			}

			tagsStr := formatCmndSpecOptions(cs.Options)
			for i := csStartIdx; i < len(findings); i++ {
				if findings[i].Tags == "" && tagsStr != "" {
					findings[i].Tags = tagsStr
				}
				if findings[i].SourceLine == "" && spec.RawLine != "" {
					findings[i].SourceLine = spec.RawLine
				}
			}
		}
	}

	return findings
}

// formatCmndSpecOptions renders a CmndSpec's Options slice back into canonical
// sudoers tag/option syntax (e.g., "CWD=/var/www NOPASSWD: SETENV:").
func formatCmndSpecOptions(options []Option) string {
	if len(options) == 0 {
		return ""
	}
	var parts []string
	keyOrder := []string{
		"runchroot",
		"runcwd",
		"command_timeout",
		"notbefore",
		"notafter",
		"authenticate",
		"noexec",
		"intercept",
		"send_mail",
		"setenv",
		"sudoedit_follow",
		"log_input",
		"log_output",
		"role",
		"type",
		"apparmor_profile",
		"privs",
		"limitprivs",
	}
	for _, opt := range options {
		for _, k := range keyOrder {
			v, exists := opt[k]
			if !exists {
				continue
			}
			switch k {
			case "runchroot":
				if s, ok := v.(string); ok && s != "" {
					parts = append(parts, "CHROOT="+s)
				}
			case "runcwd":
				if s, ok := v.(string); ok && s != "" {
					parts = append(parts, "CWD="+s)
				}
			case "command_timeout":
				switch tv := v.(type) {
				case int:
					parts = append(parts, fmt.Sprintf("TIMEOUT=%d", tv))
				case int64:
					parts = append(parts, fmt.Sprintf("TIMEOUT=%d", tv))
				case float64:
					parts = append(parts, fmt.Sprintf("TIMEOUT=%d", int64(tv)))
				case string:
					if tv != "" {
						parts = append(parts, "TIMEOUT="+tv)
					}
				}
			case "notbefore":
				if s, ok := v.(string); ok && s != "" {
					parts = append(parts, "NOTBEFORE="+s)
				}
			case "notafter":
				if s, ok := v.(string); ok && s != "" {
					parts = append(parts, "NOTAFTER="+s)
				}
			case "authenticate":
				if b, ok := v.(bool); ok {
					if b {
						parts = append(parts, "PASSWD:")
					} else {
						parts = append(parts, "NOPASSWD:")
					}
				}
			case "noexec":
				if b, ok := v.(bool); ok {
					if b {
						parts = append(parts, "NOEXEC:")
					} else {
						parts = append(parts, "EXEC:")
					}
				}
			case "intercept":
				if b, ok := v.(bool); ok {
					if b {
						parts = append(parts, "INTERCEPT:")
					} else {
						parts = append(parts, "NOINTERCEPT:")
					}
				}
			case "send_mail":
				if b, ok := v.(bool); ok {
					if b {
						parts = append(parts, "MAIL:")
					} else {
						parts = append(parts, "NOMAIL:")
					}
				}
			case "setenv":
				if b, ok := v.(bool); ok {
					if b {
						parts = append(parts, "SETENV:")
					} else {
						parts = append(parts, "NOSETENV:")
					}
				}
			case "sudoedit_follow":
				if b, ok := v.(bool); ok {
					if b {
						parts = append(parts, "FOLLOW:")
					} else {
						parts = append(parts, "NOFOLLOW:")
					}
				}
			case "log_input":
				if b, ok := v.(bool); ok {
					if b {
						parts = append(parts, "LOG_INPUT:")
					} else {
						parts = append(parts, "NOLOG_INPUT:")
					}
				}
			case "log_output":
				if b, ok := v.(bool); ok {
					if b {
						parts = append(parts, "LOG_OUTPUT:")
					} else {
						parts = append(parts, "NOLOG_OUTPUT:")
					}
				}
			case "role":
				if s, ok := v.(string); ok && s != "" {
					parts = append(parts, "ROLE="+s)
				}
			case "type":
				if s, ok := v.(string); ok && s != "" {
					parts = append(parts, "TYPE="+s)
				}
			case "apparmor_profile":
				if s, ok := v.(string); ok && s != "" {
					parts = append(parts, "APPARMOR_PROFILE="+s)
				}
			case "privs":
				if s, ok := v.(string); ok && s != "" {
					parts = append(parts, "PRIVS="+s)
				}
			case "limitprivs":
				if s, ok := v.(string); ok && s != "" {
					parts = append(parts, "LIMITPRIVS="+s)
				}
			}
		}
	}
	return strings.Join(parts, " ")
}

func buildGTFORemediationCode(usersStr, hostsStr, runasStr, exePath, binaryName string, parts []string, fn string) string {
	if isEditorBinary(binaryName) {
		targetFile := "/etc/myapp/config.conf"
		if len(parts) > 1 && parts[1] != "\"\"" && !wildcardRegex.MatchString(parts[1]) && !isSensitiveSudoeditTarget(parts[1]) {
			targetFile = strings.Join(parts[1:], " ")
		}
		return fmt.Sprintf("Defaults !sudoedit_follow, sudoedit_checkdir\n%s %s = (%s) sudoedit %s", usersStr, hostsStr, runasStr, targetFile)
	}
	if (fn == "shell" || fn == "command") && !isNoexecImmune(binaryName) {
		lockedCmd := exePath + " \"\""
		if len(parts) > 1 && !wildcardRegex.MatchString(strings.Join(parts[1:], " ")) {
			lockedCmd = strings.Join(parts, " ")
		}
		return fmt.Sprintf("# Enforce NOEXEC and explicit arguments, or replace with a dedicated wrapper script:\n%s %s = (%s) PASSWD: NOEXEC: %s", usersStr, hostsStr, runasStr, lockedCmd)
	}
	return fmt.Sprintf("# Replace direct '%s' (%s) access with a root-owned wrapper script (EXEC: required when global Defaults noexec is active):\n%s %s = (%s) PASSWD: EXEC: sha256:<digest> /usr/local/sbin/safe-%s-wrapper.sh \"\"", binaryName, fn, usersStr, hostsStr, runasStr, binaryName)
}

func auditCmndSpecOptions(options []Option, cmdMembers []Member, usersStr, hostsStr, runasStr, file string, line int) []Finding {
	var findings []Finding
	hasUnnegatedALL := false
	for _, m := range cmdMembers {
		if !m.Negated && m.Command == "ALL" {
			hasUnnegatedALL = true
			break
		}
	}
	for _, opt := range options {
		if val, ok := opt["setenv"].(bool); ok && val {
			desc := fmt.Sprintf("The command specification for user(s) [%s] includes the 'SETENV' tag, allowing the user to pass arbitrary environment variables to commands run as [%s].", usersStr, runasStr)
			remediation := "Remove the 'SETENV:' tag or replace it with 'NOSETENV:'."
			if hasUnnegatedALL {
				desc = fmt.Sprintf("The command specification for user(s) [%s] permits 'ALL', which implicitly enables 'SETENV' in sudoers unless 'NOSETENV:' is specified, allowing the user to pass arbitrary environment variables to commands run as [%s].", usersStr, runasStr)
				remediation = "Replace 'ALL' with explicit commands, or add the 'NOSETENV:' tag to suppress the implied SETENV permission."
			}
			findings = append(findings, Finding{
				ID:              "SUDO-CMD-009",
				Title:           "Environment Override Permitted on Command (SETENV)",
				Description:     desc,
				Severity:        SeverityHigh,
				User:            usersStr,
				Host:            hostsStr,
				Runas:           runasStr,
				Context:         file,
				Line:            line,
				Remediation:     remediation,
				RemediationCode: fmt.Sprintf("%s %s = (%s) NOSETENV: /usr/bin/command \"\"", usersStr, hostsStr, runasStr),
				Compliance:      []string{},
			})
		}
		if val, ok := opt["sudoedit_follow"].(bool); ok && val {
			findings = append(findings, Finding{
				ID:              "SUDO-CMD-009",
				Title:           "Symlink Following Permitted on Command (FOLLOW)",
				Description:     fmt.Sprintf("The command specification for user(s) [%s] includes the 'FOLLOW' ('sudoedit_follow') tag, allowing symlink redirection when editing files as [%s].", usersStr, runasStr),
				Severity:        SeverityHigh,
				User:            usersStr,
				Host:            hostsStr,
				Runas:           runasStr,
				Context:         file,
				Line:            line,
				Remediation:     "Remove the 'FOLLOW:' tag or explicitly enforce 'NOFOLLOW:'.",
				RemediationCode: fmt.Sprintf("%s %s = (%s) NOFOLLOW: sudoedit /etc/myapp/config.conf", usersStr, hostsStr, runasStr),
				Compliance:      []string{},
			})
		}
		if val, ok := opt["runchroot"].(string); ok && val != "" {
			findings = append(findings, Finding{
				ID:              "SUDO-CMD-009",
				Title:           "Per-Command Chroot Specification (CHROOT)",
				Description:     fmt.Sprintf("The command specification for user(s) [%s] sets 'CHROOT=%s'. Per-command chroot in sudoers has been associated with critical vulnerabilities (CVE-2023-27320, CVE-2025-32463) and is deprecated upstream.", usersStr, val),
				Severity:        SeverityHigh,
				User:            usersStr,
				Host:            hostsStr,
				Runas:           runasStr,
				Context:         file,
				Line:            line,
				Remediation:     "Remove the 'CHROOT=' specification from the sudoers rule.",
				RemediationCode: fmt.Sprintf("%s %s = (%s) /usr/bin/command \"\"", usersStr, hostsStr, runasStr),
			})
		}
		if val, ok := opt["runcwd"].(string); ok && val == "*" {
			findings = append(findings, Finding{
				ID:              "SUDO-CMD-009",
				Title:           "Unrestricted Per-Command Working Directory (CWD=*)",
				Description:     fmt.Sprintf("The command specification for user(s) [%s] sets 'CWD=*', permitting the invoking user to choose any working directory via 'sudo -D'.", usersStr),
				Severity:        SeverityMedium,
				User:            usersStr,
				Host:            hostsStr,
				Runas:           runasStr,
				Context:         file,
				Line:            line,
				Remediation:     "Restrict 'CWD=' to a fixed, trusted absolute directory or remove it.",
				RemediationCode: fmt.Sprintf("%s %s = (%s) CWD=/opt/app /usr/bin/command \"\"", usersStr, hostsStr, runasStr),
			})
		}
	}
	return findings
}

// optionStringValue returns the string value of the first option with the given key.
func optionStringValue(options []Option, key string) string {
	for _, opt := range options {
		if val, ok := opt[key].(string); ok {
			return val
		}
	}
	return ""
}

// auditSELinuxContextElevation flags administrator-grade command specifications that do not
// elevate the SELinux context via the TYPE= and ROLE= options, as required for designated
// sudoers administrators by DISA STIG V-272484 / RHEL-08-010455. A specification is
// administrator-grade when it allows the ALL command or targets the ALL runas user.
func auditSELinuxContextElevation(options []Option, cmdMembers []Member, runasUsers []Member, usersStr, hostsStr, runasStr, file string, line int) []Finding {
	adminGrade := false
	for _, m := range cmdMembers {
		if !m.Negated && m.Command == "ALL" {
			adminGrade = true
			break
		}
	}
	if !adminGrade {
		for _, m := range runasUsers {
			if !m.Negated && m.GetName() == "ALL" {
				adminGrade = true
				break
			}
		}
	}
	if !adminGrade {
		return nil
	}

	selType := optionStringValue(options, "type")
	selRole := optionStringValue(options, "role")
	if selType != "" && selRole != "" {
		return nil
	}

	title := "Missing SELinux Context Elevation on Administrator Rule (TYPE/ROLE)"
	description := fmt.Sprintf("The administrator-grade rule for user(s) [%s] on host(s) [%s] running as [%s] does not specify the 'TYPE=' and 'ROLE=' options. Without an explicit SELinux type and role transition, commands executed via sudo run in the invoking user's SELinux context instead of the administrator domain.", usersStr, hostsStr, runasStr)
	if selType != "" || selRole != "" {
		title = "Incomplete SELinux Context Elevation on Administrator Rule (TYPE/ROLE)"
		description = fmt.Sprintf("The administrator-grade rule for user(s) [%s] on host(s) [%s] running as [%s] specifies only one of the 'TYPE=' (%s) and 'ROLE=' (%s) options. Both are required together for sudo to transition into the administrator SELinux domain.", usersStr, hostsStr, runasStr, selType, selRole)
	}

	return []Finding{{
		ID:              "SUDO-CMD-013",
		Title:           title,
		Description:     description,
		Severity:        SeverityInfo,
		User:            usersStr,
		Host:            hostsStr,
		Runas:           runasStr,
		Context:         file,
		Line:            line,
		Remediation:     "Add 'TYPE=sysadm_t ROLE=sysadm_r' to the administrator rule so sudo transitions to the SELinux administrator domain (DISA STIG V-272484 / RHEL-08-010455). On hosts not running SELinux this finding is informational and can be disregarded.",
		RemediationCode: fmt.Sprintf("%s %s = (%s) TYPE=sysadm_t ROLE=sysadm_r ALL", usersStr, hostsStr, runasStr),
		Compliance:      []string{"DISA-STIG"},
	}}
}

func formatRunas(runasUsers, runasGroups []Member) (string, []string) {
	var uNames []string
	var gNames []string
	var negated []string

	for _, u := range runasUsers {
		if n := u.GetName(); n != "" {
			uNames = append(uNames, n)
			if u.Negated {
				negated = append(negated, n)
			}
		}
	}
	for _, g := range runasGroups {
		if n := g.GetName(); n != "" {
			gNames = append(gNames, n)
			if g.Negated {
				negated = append(negated, n)
			}
		}
	}

	uPart := strings.Join(uNames, ", ")
	gPart := strings.Join(gNames, ", ")

	if uPart == "" && gPart == "" {
		return "root", negated
	}
	if gPart != "" {
		if uPart == "" {
			return ":" + gPart, negated
		}
		return uPart + " : " + gPart, negated
	}
	return uPart, negated
}

// consolidateBypassesByFunction ensures at most one SudoBypass entry per unique Function,
// merging Code and Comment blocks deterministically.
func consolidateBypassesByFunction(bypasses []gtfobins.SudoBypass) []gtfobins.SudoBypass {
	if len(bypasses) <= 1 {
		return bypasses
	}
	var order []string
	byFunc := make(map[string]*gtfobins.SudoBypass)
	codesSeen := make(map[string]map[string]bool)
	commentsSeen := make(map[string]map[string]bool)

	for _, b := range bypasses {
		existing, ok := byFunc[b.Function]
		if !ok {
			order = append(order, b.Function)
			copyBypass := b
			byFunc[b.Function] = &copyBypass
			codesSeen[b.Function] = map[string]bool{b.Code: true}
			commentsSeen[b.Function] = map[string]bool{b.Comment: true}
			continue
		}
		if b.Code != "" && !codesSeen[b.Function][b.Code] {
			if existing.Code != "" {
				existing.Code += "\n\n" + b.Code
			} else {
				existing.Code = b.Code
			}
			codesSeen[b.Function][b.Code] = true
		}
		if b.Comment != "" && !commentsSeen[b.Function][b.Comment] {
			if existing.Comment != "" {
				existing.Comment += "\n" + b.Comment
			} else {
				existing.Comment = b.Comment
			}
			commentsSeen[b.Function][b.Comment] = true
		}
	}

	var result []gtfobins.SudoBypass
	for _, fn := range order {
		result = append(result, *byFunc[fn])
	}
	return result
}

type aliasKind int

const (
	aliasKindCommand aliasKind = iota
	aliasKindUser
	aliasKindHost
	aliasKindRunas
)

// maxResolveDepth limits recursion depth when resolving aliases to prevent
// stack overflow from circular alias definitions (e.g., ALIAS_A -> ALIAS_B -> ALIAS_A).
const maxResolveDepth = 10

func resolveMemberSlice(members []Member, policy *SudoersPolicy, kind aliasKind) []Member {
	var out []Member
	for _, m := range members {
		out = append(out, resolveMemberDepth(m, policy, kind, 0)...)
	}
	return out
}

// resolveCommands recursively resolves command aliases in the sudoers policy structure.
func resolveCommands(member Member, policy *SudoersPolicy) []Member {
	return resolveMemberDepth(member, policy, aliasKindCommand, 0)
}

func resolveMemberDepth(member Member, policy *SudoersPolicy, kind aliasKind, depth int) []Member {
	if depth >= maxResolveDepth || policy == nil {
		return []Member{member}
	}

	var aliasName string
	var aliasTable map[string][]Member

	switch kind {
	case aliasKindCommand:
		aliasName = member.CommandAlias
		if aliasName == "" {
			aliasName = member.LegacyAlias
		}
		aliasTable = policy.CommandAliases
	case aliasKindUser:
		aliasName = member.UserAlias
		if aliasName == "" && member.Username != "" && policy.UserAliases != nil {
			if _, ok := policy.UserAliases[member.Username]; ok {
				aliasName = member.Username
			}
		}
		aliasTable = policy.UserAliases
	case aliasKindHost:
		aliasName = member.HostAlias
		if aliasName == "" && member.Hostname != "" && policy.HostAliases != nil {
			if _, ok := policy.HostAliases[member.Hostname]; ok {
				aliasName = member.Hostname
			}
		}
		aliasTable = policy.HostAliases
	case aliasKindRunas:
		aliasName = member.RunasAlias
		if aliasName == "" && member.Username != "" && policy.RunasAliases != nil {
			if _, ok := policy.RunasAliases[member.Username]; ok {
				aliasName = member.Username
			}
		}
		aliasTable = policy.RunasAliases
	}

	if aliasName != "" && aliasTable != nil {
		if targets, ok := aliasTable[aliasName]; ok {
			var resolved []Member
			for _, m := range targets {
				if member.Negated {
					m.Negated = !m.Negated
				}
				if m.Line == 0 {
					m.Line = member.Line
				}
				if m.File == "" {
					m.File = member.File
				}
				resolved = append(resolved, resolveMemberDepth(m, policy, kind, depth+1)...)
			}
			return resolved
		}
	}
	return []Member{member}
}
