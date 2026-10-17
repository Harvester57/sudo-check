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

// isWritableOrTempPath checks if an executable path resides inside a temporary or user-writable directory tree.
func isWritableOrTempPath(exePath string) bool {
	cleaned := path.Clean(exePath)
	unsafePrefixes := []string{
		"/tmp/",
		"/var/tmp/",
		"/dev/shm/",
		"/home/",
		"/run/user/",
		"/var/mail/",
		"/var/spool/samba/",
	}
	for _, prefix := range unsafePrefixes {
		if strings.HasPrefix(cleaned, prefix) {
			return true
		}
	}
	return false
}

// isSensitiveSudoeditTarget checks if a file path targeted by sudoedit is a critical system configuration or credential file.
func isSensitiveSudoeditTarget(target string) bool {
	cleaned := path.Clean(target)
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
				Context:     spec.File,
				Line:        spec.Line,
				Remediation: "Avoid using negation (!) in User_List or Host_List specifications; define explicit positive allowlists instead.",
				RemediationCode: fmt.Sprintf(
					"User_Alias %s = alice, bob\n%s %s = (root) /usr/bin/id \"\"",
					posUser, posUser, posHost,
				),
				Compliance: []string{"ANSSI-BP-028 R40"},
			})
		}

		for _, cs := range spec.CmndSpecs {
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
					Compliance: []string{"ANSSI-BP-028 R40"},
				})
			}

			// Audit dangerous per-command options (SETENV, sudoedit_follow, runchroot, runcwd)
			findings = append(findings, auditCmndSpecOptions(cs.Options, usersStr, hostsStr, runasStr, spec.File, spec.Line)...)

			// Gather all commands, resolving any aliases if present
			var allCmdMembers []Member
			for _, cmdMember := range cs.Commands {
				allCmdMembers = append(allCmdMembers, resolveCommands(cmdMember, policy)...)
			}

			for _, cmdMember := range allCmdMembers {
				cmdStr := cmdMember.Command
				if cmdStr == "" {
					continue
				}
				line := cmdMember.Line
				if line == 0 {
					line = spec.Line
				}
				file := cmdMember.File
				if file == "" {
					file = spec.File
				}

				noPasswd, noExec := resolveEffectiveFlags(policy, resolvedUsers, resolvedHosts, resolvedRunasUsers, cmdStr, cs.Options)

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
						Compliance:      []string{"ANSSI-BP-028 R40"},
					})
					continue
				}

				// Check weak cryptographic digest (SHA-224)
				if cmdMember.HasWeakDigestOnly() {
					exeForDigest := strings.Fields(cmdStr)[0]
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
						Compliance: []string{"ANSSI-BP-028"},
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

					if noPasswd {
						sev = SeverityCritical
						title = "Passwordless Full Root Privileges Allowed (NOPASSWD)"
						desc = fmt.Sprintf("The policy allows user(s) [%s] to run any command (ALL) on host(s) [%s] as [%s] without a password (NOPASSWD). Any compromise of this user account leads to immediate privilege escalation.", usersStr, hostsStr, runasStr)
						remediationCode = fmt.Sprintf(
							"%s %s = (%s) PASSWD: /usr/bin/systemctl restart app",
							usersStr, hostsStr, runasStr,
						)
						id = "SUDO-CMD-003"
					}

					findings = append(findings, Finding{
						ID:              id,
						Title:           title,
						Description:     desc,
						Severity:        sev,
						User:            usersStr,
						Host:            hostsStr,
						Runas:           runasStr,
						Command:         cmdStr,
						Context:         file,
						Line:            line,
						Remediation:     remediation,
						RemediationCode: remediationCode,
						Compliance:      []string{"ANSSI-BP-028", "CIS-5.2.4"},
					})
					continue
				}

				// Split command to get the executable path and arguments
				parts := strings.Fields(cmdStr)
				if len(parts) == 0 {
					continue
				}
				exePath := parts[0]
				binaryName := path.Base(exePath)

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
						Compliance:      []string{"ANSSI-BP-028"},
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
							Compliance:      []string{"ANSSI-BP-028"},
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
									Compliance:      []string{"ANSSI-BP-028"},
								})
								break
							}
						}
					}
					continue
				}

				// Check for relative command path or writable directory path (SUDO-CMD-011)
				if !strings.HasPrefix(exePath, "/") {
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
						Compliance:      []string{"ANSSI-BP-028"},
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
						Compliance: []string{"ANSSI-BP-028"},
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
						Compliance:      []string{"ANSSI-BP-028 R41"},
					})
				}

				// Check 6: Direct Text Editor Execution (SUDO-CMD-007)
				if isEditorBinary(binaryName) {
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
						Compliance: []string{"ANSSI-BP-028 R42"},
					})
				}

				// Check 4: GTFObins Escalation Match (Consolidated to 1 finding per (rule, binary, function))
				bypasses := consolidateBypassesByFunction(gtfoClient.CheckBinary(binaryName))
				if len(bypasses) > 0 {
					for _, bypass := range bypasses {
						// Evaluate if noexec mitigates child process execution (shell / command)
						mitigated := false
						if noExec && (bypass.Function == "shell" || bypass.Function == "command") {
							mitigated = true
						}

						sev := SeverityHigh
						id := "SUDO-GTFO-001"
						title := fmt.Sprintf("Dangerous Sudo Binary allowed: %s (%s)", binaryName, bypass.Function)
						desc := fmt.Sprintf("The user(s) [%s] can run '%s' via sudo as [%s], which is listed in GTFObins with the '%s' capability.", usersStr, cmdStr, runasStr, bypass.Function)

						if noPasswd {
							sev = SeverityCritical
							id = "SUDO-GTFO-002"
							title = fmt.Sprintf("Passwordless Dangerous Sudo Binary allowed: %s (%s)", binaryName, bypass.Function)
							desc = fmt.Sprintf("The user(s) [%s] can run '%s' via sudo as [%s] without a password (NOPASSWD) with the '%s' capability. This enables immediate privilege escalation.", usersStr, cmdStr, runasStr, bypass.Function)
						}

						if mitigated {
							sev = SeverityLow
							id = "SUDO-GTFO-003"
							title = fmt.Sprintf("Mitigated Dangerous Sudo Binary: %s (%s)", binaryName, bypass.Function)
							desc = fmt.Sprintf("The user(s) [%s] can run '%s' via sudo as [%s], which has a '%s' capability in GTFObins. However, the rule enforces 'NOEXEC', which mitigates child-process execution vectors.", usersStr, cmdStr, runasStr, bypass.Function)
						}

						commentStr := ""
						if bypass.Comment != "" {
							commentStr = fmt.Sprintf("\nGTFObins Context: %s", bypass.Comment)
						}

						gtfoRemCode := buildGTFORemediationCode(usersStr, hostsStr, runasStr, exePath, binaryName, parts, bypass.Function)

						findings = append(findings, Finding{
							ID:              id,
							Title:           title,
							Description:     desc + commentStr,
							Severity:        sev,
							User:            usersStr,
							Host:            hostsStr,
							Runas:           runasStr,
							Command:         cmdStr,
							Context:         file,
							Line:            line,
							Remediation:     fmt.Sprintf("Remove this binary from sudoers or replace it with a wrapper script. Example exploit command:\n%s", bypass.Code),
							RemediationCode: gtfoRemCode,
							ExploitPoC:      bypass.Code,
							Compliance:      []string{"ANSSI-BP-028", "MITRE-T1548.003"},
						})
					}
				} else {
					if noPasswd {
						lockedCmd := cmdStr
						if len(parts) == 1 {
							lockedCmd = cmdStr + " \"\""
						}
						findings = append(findings, Finding{
							ID:              "SUDO-CMD-005",
							Title:           "Passwordless Specific Command Execution Allowed (NOPASSWD)",
							Description:     fmt.Sprintf("The user(s) [%s] are permitted to run the specific command '%s' as [%s] without entering a password (NOPASSWD). While restricted to this binary, any command running passwordless expands the local attack surface if it has argument parsing or script vulnerabilities.", usersStr, cmdStr, runasStr),
							Severity:        SeverityLow,
							User:            usersStr,
							Host:            hostsStr,
							Runas:           runasStr,
							Command:         cmdStr,
							Context:         file,
							Line:            line,
							Remediation:     "Ensure that passwordless privileges are strictly necessary. If possible, require authentication or implement strict input validation inside target wrapper scripts.",
							RemediationCode: fmt.Sprintf("%s %s = (%s) PASSWD: NOEXEC: %s", usersStr, hostsStr, runasStr, lockedCmd),
							Compliance:      []string{"ANSSI-BP-028", "CIS-5.2.4"},
						})
					}
				}
			}
		}
	}

	return findings
}

func buildGTFORemediationCode(usersStr, hostsStr, runasStr, exePath, binaryName string, parts []string, fn string) string {
	if isEditorBinary(binaryName) {
		targetFile := "/etc/myapp/config.conf"
		if len(parts) > 1 && parts[1] != "\"\"" && !wildcardRegex.MatchString(parts[1]) && !isSensitiveSudoeditTarget(parts[1]) {
			targetFile = strings.Join(parts[1:], " ")
		}
		return fmt.Sprintf("Defaults !sudoedit_follow, sudoedit_checkdir\n%s %s = (%s) sudoedit %s", usersStr, hostsStr, runasStr, targetFile)
	}
	if fn == "shell" || fn == "command" {
		lockedCmd := exePath + " \"\""
		if len(parts) > 1 && !wildcardRegex.MatchString(strings.Join(parts[1:], " ")) {
			lockedCmd = strings.Join(parts, " ")
		}
		return fmt.Sprintf("# Enforce NOEXEC and explicit arguments, or replace with a dedicated wrapper script:\n%s %s = (%s) PASSWD: NOEXEC: %s", usersStr, hostsStr, runasStr, lockedCmd)
	}
	return fmt.Sprintf("# Replace direct '%s' (%s) access with a root-owned wrapper script:\n%s %s = (%s) PASSWD: NOEXEC: sha256:<digest> /usr/local/sbin/safe-%s-wrapper.sh \"\"", binaryName, fn, usersStr, hostsStr, runasStr, binaryName)
}

func auditCmndSpecOptions(options []Option, usersStr, hostsStr, runasStr, file string, line int) []Finding {
	var findings []Finding
	for _, opt := range options {
		if val, ok := opt["setenv"].(bool); ok && val {
			findings = append(findings, Finding{
				ID:              "SUDO-CMD-009",
				Title:           "Environment Override Permitted on Command (SETENV)",
				Description:     fmt.Sprintf("The command specification for user(s) [%s] includes the 'SETENV' tag, allowing the user to pass arbitrary environment variables to commands run as [%s].", usersStr, runasStr),
				Severity:        SeverityHigh,
				User:            usersStr,
				Host:            hostsStr,
				Runas:           runasStr,
				Context:         file,
				Line:            line,
				Remediation:     "Remove the 'SETENV:' tag or replace it with 'NOSETENV:'.",
				RemediationCode: fmt.Sprintf("%s %s = (%s) NOSETENV: /usr/bin/command \"\"", usersStr, hostsStr, runasStr),
				Compliance:      []string{"ANSSI-BP-028"},
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
				Compliance:      []string{"ANSSI-BP-028"},
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
