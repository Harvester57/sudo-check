package audit

import (
	"fmt"
	"path"
	"regexp"
	"strings"
	"sudo-check/pkg/gtfobins"
)

var (
	wildcardRegex        = regexp.MustCompile(`[*?\[\]]`)
	versionedEditorRegex = regexp.MustCompile(`^(?:vim\..+|emacs(?:-.+|[0-9.]+))$`)
)

// knownTextEditors contains exact binary names of interactive text editors.
// Matching against this set (plus versionedEditorRegex) avoids false positives on tools
// that merely share a prefix such as "virsh", "virt-install", "visudo", "microdnf", or "editcap".
var knownTextEditors = map[string]bool{
	"vi": true, "vim": true, "nvim": true, "gvim": true, "rvim": true,
	"view": true, "rview": true, "vimdiff": true, "nvi": true, "nview": true, "elvis": true,
	"nano": true, "rnano": true, "pico": true,
	"emacs": true, "emacsclient": true, "mg": true, "zile": true,
	"joe": true, "rjoe": true, "jpico": true, "jmacs": true, "jstar": true,
	"micro": true, "edit": true, "ed": true, "red": true, "ex": true, "nex": true,
	"kak": true, "helix": true, "hx": true, "gedit": true, "kate": true, "kwrite": true,
	"mcedit": true, "ne": true, "jed": true, "vipw": true, "vigr": true,
}

// isTextEditorBinary returns true if binaryName is a known interactive text editor.
func isTextEditorBinary(binaryName string) bool {
	if knownTextEditors[binaryName] {
		return true
	}
	return versionedEditorRegex.MatchString(binaryName)
}

// formatRunas builds a human-readable representation of the Runas user/group specification.
func formatRunas(cs CmndSpec, policy *SudoersPolicy) string {
	var users []string
	for _, u := range resolveRunasMembers(cs.RunasUsers, policy, 0) {
		name := u.GetName()
		if u.Negated {
			name = "!" + name
		}
		if name != "" {
			users = append(users, name)
		}
	}
	var groups []string
	for _, g := range resolveRunasMembers(cs.RunasGroups, policy, 0) {
		name := g.GetName()
		if g.Negated {
			name = "!" + name
		}
		if name != "" {
			groups = append(groups, name)
		}
	}

	if len(users) == 0 && len(groups) == 0 {
		return "root"
	}
	if len(groups) == 0 {
		return strings.Join(users, ", ")
	}
	if len(users) == 0 {
		return ": " + strings.Join(groups, ", ")
	}
	return strings.Join(users, ", ") + " : " + strings.Join(groups, ", ")
}

// AuditCommands runs security checks on allowed user commands (User_Specs).
func AuditCommands(policy *SudoersPolicy, gtfoClient *gtfobins.Client) []Finding {
	var findings []Finding

	// Inherit baseline noPasswd and noExec states from global Defaults.
	globalNoPasswd, globalNoExec := effectiveGlobalDefaults(policy)

	for _, spec := range policy.UserSpecs {
		// Represent the users list as a string (resolving User_Aliases if present)
		var users []string
		for _, u := range resolveUserMembers(spec.UserList, policy, 0) {
			name := u.GetName()
			if u.Negated {
				name = "!" + name
			}
			if name != "" {
				users = append(users, name)
			}
		}
		usersStr := strings.Join(users, ", ")

		// Represent the hosts list as a string (resolving Host_Aliases if present)
		var hosts []string
		for _, h := range resolveHostMembers(spec.HostList, policy, 0) {
			name := h.GetName()
			if h.Negated {
				name = "!" + name
			}
			if name != "" {
				hosts = append(hosts, name)
			}
		}
		hostsStr := strings.Join(hosts, ", ")

		for _, cs := range spec.CmndSpecs {
			runasStr := formatRunas(cs, policy)

			// Start from global Defaults and apply command-level Options overrides (last-match-wins).
			noPasswd := globalNoPasswd
			noExec := globalNoExec
			setEnv := false
			sudoeditFollow := false
			for _, opt := range cs.Options {
				if val, ok := opt["authenticate"].(bool); ok {
					noPasswd = !val // authenticate: false means NOPASSWD
				}
				if val, ok := opt["noexec"].(bool); ok {
					noExec = val
				}
				if val, ok := opt["setenv"].(bool); ok {
					setEnv = val
				}
				if val, ok := opt["sudoedit_follow"].(bool); ok {
					sudoeditFollow = val
				}
			}

			// Check for negated Runas users or groups (e.g., (ALL, !root))
			for _, ru := range resolveRunasMembers(cs.RunasUsers, policy, 0) {
				if ru.Negated {
					findings = append(findings, Finding{
						ID:          "SUDO-CMD-010",
						Title:       "Negated Runas User Specification",
						Description: fmt.Sprintf("The policy for user(s) [%s] contains a negated Runas user '!%s' (runas: %s). Negated Runas restrictions are error-prone, historically vulnerable to UID -1 bypasses (CVE-2019-14287), and can often be bypassed via other privileged system accounts.", usersStr, ru.GetName(), runasStr),
						Severity:    SeverityHigh,
						User:        usersStr,
						Runas:       runasStr,
						Host:        hostsStr,
						Remediation: "Avoid negating Runas users (such as '(ALL, !root)'). Explicitly list only the specific target accounts the user is authorized to impersonate.",
					})
					break
				}
			}
			for _, rg := range resolveRunasMembers(cs.RunasGroups, policy, 0) {
				if rg.Negated {
					findings = append(findings, Finding{
						ID:          "SUDO-CMD-010",
						Title:       "Negated Runas Group Specification",
						Description: fmt.Sprintf("The policy for user(s) [%s] contains a negated Runas group '!%s' (runas: %s). Negated Runas group restrictions are fragile and difficult to audit safely.", usersStr, rg.GetName(), runasStr),
						Severity:    SeverityHigh,
						User:        usersStr,
						Runas:       runasStr,
						Host:        hostsStr,
						Remediation: "Avoid negating Runas groups. Explicitly allowlist only the required target groups.",
					})
					break
				}
			}

			// Gather all commands, resolving any command aliases if present
			var allCmdMembers []Member
			for _, cmdMember := range cs.Commands {
				allCmdMembers = append(allCmdMembers, resolveCommands(cmdMember, policy)...)
			}

			// Check command-level SETENV and FOLLOW tags
			if setEnv && len(allCmdMembers) > 0 {
				firstCmd := allCmdMembers[0].Command
				findings = append(findings, Finding{
					ID:          "SUDO-CMD-008",
					Title:       "Command Environment Override Allowed (SETENV)",
					Description: fmt.Sprintf("The command rule for user(s) [%s] enables the 'SETENV' tag. This allows the user to preserve or inject arbitrary environment variables (such as LD_PRELOAD, PYTHONPATH, or PATH) via 'sudo -E', facilitating privilege escalation.", usersStr),
					Severity:    SeverityHigh,
					User:        usersStr,
					Runas:       runasStr,
					Host:        hostsStr,
					Command:     firstCmd,
					Remediation: "Remove the 'SETENV:' tag from the command specification and rely on 'NOSETENV:' or strict 'env_reset'.",
				})
			}

			if sudoeditFollow && len(allCmdMembers) > 0 {
				firstCmd := allCmdMembers[0].Command
				findings = append(findings, Finding{
					ID:          "SUDO-CMD-009",
					Title:       "Sudoedit Symlink Following Allowed (FOLLOW)",
					Description: fmt.Sprintf("The command rule for user(s) [%s] enables the 'FOLLOW' ('sudoedit_follow') tag. This allows 'sudoedit' to follow symbolic links, permitting attackers to overwrite arbitrary privileged files.", usersStr),
					Severity:    SeverityHigh,
					User:        usersStr,
					Runas:       runasStr,
					Host:        hostsStr,
					Command:     firstCmd,
					Remediation: "Remove the 'FOLLOW:' tag or explicitly enforce 'NOFOLLOW:' on sudoedit rules.",
				})
			}

			for _, cmdMember := range allCmdMembers {
				cmdStr := cmdMember.Command
				if cmdStr == "" {
					continue
				}

				// Check 1: Command Negation Bypass (e.g. !/usr/bin/passwd)
				if cmdMember.Negated {
					findings = append(findings, Finding{
						ID:          "SUDO-CMD-001",
						Title:       "Negated Command Policy",
						Description: fmt.Sprintf("The policy contains a negated command '%s' for user(s) [%s]. Sudo command negation is easily bypassed by symlinking the binary, copying it to another location, or executing it with slightly different paths/arguments.", cmdStr, usersStr),
						Severity:    SeverityHigh,
						User:        usersStr,
						Runas:       runasStr,
						Host:        hostsStr,
						Command:     cmdStr,
						Remediation: "Avoid using negated commands (!) to enforce restrictions. Instead, use a strict allowlist of permitted commands.",
					})
					continue
				}

				// Check 2: ALL Commands Allowed
				if cmdStr == "ALL" {
					sev := SeverityHigh
					title := "Full Root Privileges Allowed"
					desc := fmt.Sprintf("The policy allows user(s) [%s] to run any command (ALL) on host(s) [%s]. This grants full administrative control.", usersStr, hostsStr)
					remediation := "Restrict privileges to only the specific commands required for the user's role."
					id := "SUDO-CMD-002"

					if noPasswd {
						sev = SeverityCritical
						title = "Passwordless Full Root Privileges Allowed (NOPASSWD)"
						desc = fmt.Sprintf("The policy allows user(s) [%s] to run any command (ALL) on host(s) [%s] without a password (NOPASSWD). Any compromise of this user account leads to immediate root access.", usersStr, hostsStr)
						id = "SUDO-CMD-003"
					}

					findings = append(findings, Finding{
						ID:          id,
						Title:       title,
						Description: desc,
						Severity:    sev,
						User:        usersStr,
						Runas:       runasStr,
						Host:        hostsStr,
						Command:     cmdStr,
						Remediation: remediation,
					})
					continue
				}

				// Check 3: Wildcards in command spec (e.g., /usr/bin/cat /var/log/*)
				if wildcardRegex.MatchString(cmdStr) {
					findings = append(findings, Finding{
						ID:          "SUDO-CMD-004",
						Title:       "Wildcard in Command Definition",
						Description: fmt.Sprintf("The command '%s' allowed for user(s) [%s] contains wildcards. Arguments matching wildcards in sudoers can often be bypassed using directory traversals (e.g. '/var/log/../../etc/shadow') or injection flags.", cmdStr, usersStr),
						Severity:    SeverityMedium,
						User:        usersStr,
						Runas:       runasStr,
						Host:        hostsStr,
						Command:     cmdStr,
						Remediation: "Avoid wildcards in command paths. Use specific paths or write wrapper scripts that sanitize inputs before executing commands.",
					})
				}

				// Check 4: Split command to get the POSIX executable path and binary name
				parts := strings.Fields(cmdStr)
				if len(parts) == 0 {
					continue
				}
				exePath := parts[0]
				binaryName := path.Base(exePath)

				// Check 5: Missing Command Argument Restrictions (SUDO-CMD-006)
				if len(parts) == 1 {
					findings = append(findings, Finding{
						ID:          "SUDO-CMD-006",
						Title:       "Missing Command Argument Restrictions",
						Description: fmt.Sprintf("The command '%s' allowed for user(s) [%s] does not specify any argument restrictions. This permits the user to run the command with arbitrary arguments, which can be abused to bypass restrictions or inject options.", cmdStr, usersStr),
						Severity:    SeverityMedium,
						User:        usersStr,
						Runas:       runasStr,
						Host:        hostsStr,
						Command:     cmdStr,
						Remediation: "Strictly specify the allowed arguments. If the command should be run without any arguments, append empty double quotes '\"\"' to the command (e.g., 'dmesg \"\"').",
					})
				}

				// Check 6: Direct Text Editor Execution (SUDO-CMD-007)
				if isTextEditorBinary(binaryName) {
					findings = append(findings, Finding{
						ID:          "SUDO-CMD-007",
						Title:       "Direct Text Editor Execution via Sudo",
						Description: fmt.Sprintf("The command '%s' allowed for user(s) [%s] invokes a text editor directly under sudo. Text editors typically allow escaping to a shell or editing arbitrary system files. Use 'sudoedit' instead to safely edit files with current user privileges.", cmdStr, usersStr),
						Severity:    SeverityHigh,
						User:        usersStr,
						Runas:       runasStr,
						Host:        hostsStr,
						Command:     cmdStr,
						Remediation: "Replace direct text editor execution rules with 'sudoedit' permissions for specific files.",
					})
				}

				// Check 7: GTFObins Escalation Match
				bypasses := gtfoClient.CheckBinary(binaryName)
				if len(bypasses) > 0 {
					for _, bypass := range bypasses {
						// Evaluate if noexec mitigates this bypass (only subprocess-spawning functions are mitigated;
						// in-process functions like library-load, file-read, and file-write are NOT mitigated by noexec).
						mitigated := noExec && bypass.IsMitigatedByNoExec()

						sev := SeverityHigh
						id := "SUDO-GTFO-001"
						title := fmt.Sprintf("Dangerous Sudo Binary allowed: %s (%s)", binaryName, bypass.Function)
						desc := fmt.Sprintf("The user(s) [%s] can run '%s' via sudo, which is known to be bypassable. The binary has a '%s' function in GTFObins which allows escaping restricted environments.", usersStr, cmdStr, bypass.Function)

						if noPasswd {
							sev = SeverityCritical
							id = "SUDO-GTFO-002"
							title = fmt.Sprintf("Passwordless Dangerous Sudo Binary allowed: %s (%s)", binaryName, bypass.Function)
							desc = fmt.Sprintf("The user(s) [%s] can run '%s' via sudo without a password (NOPASSWD) using the '%s' bypass method. This enables instant root privilege escalation.", usersStr, cmdStr, bypass.Function)
						}

						if mitigated {
							sev = SeverityLow
							id = "SUDO-GTFO-003"
							title = fmt.Sprintf("Mitigated Dangerous Sudo Binary: %s (%s)", binaryName, bypass.Function)
							desc = fmt.Sprintf("The user(s) [%s] can run '%s' via sudo, which contains a '%s' bypass. However, the rule enforces 'NOEXEC', which mitigates execution-based escape vectors.", usersStr, cmdStr, bypass.Function)
						}

						commentStr := ""
						if bypass.Comment != "" {
							commentStr = fmt.Sprintf("\nGTFObins Context: %s", bypass.Comment)
						}

						findings = append(findings, Finding{
							ID:          id,
							Title:       title,
							Description: desc + commentStr,
							Severity:    sev,
							User:        usersStr,
							Runas:       runasStr,
							Host:        hostsStr,
							Command:     cmdStr,
							Remediation: fmt.Sprintf("Remove this binary from sudoers or replace it with a wrapper script. Example exploit command:\n%s", bypass.Code),
						})
					}
				} else if noPasswd {
					findings = append(findings, Finding{
						ID:          "SUDO-CMD-005",
						Title:       "Passwordless Specific Command Execution Allowed (NOPASSWD)",
						Description: fmt.Sprintf("The user(s) [%s] are permitted to run the specific command '%s' without entering a password (NOPASSWD). While restricted to this binary, any command running passwordless as root expands the local attack surface if it has undisclosed command injection or argument parsing vulnerabilities.", usersStr, cmdStr),
						Severity:    SeverityLow,
						User:        usersStr,
						Runas:       runasStr,
						Host:        hostsStr,
						Command:     cmdStr,
						Remediation: "Ensure that passwordless privileges are strictly necessary. If possible, require authentication or implement strict input sanitization inside target binary wrapper scripts.",
					})
				}
			}
		}
	}

	return findings
}

// maxResolveDepth limits recursion depth when resolving aliases to prevent
// stack overflow from circular alias definitions (e.g., ALIAS_A → ALIAS_B → ALIAS_A).
const maxResolveDepth = 10

// resolveCommands recursively resolves command aliases ("cmndalias" or "commandalias") in the sudoers policy.
func resolveCommands(member Member, policy *SudoersPolicy) []Member {
	return resolveCommandsDepth(member, policy, 0)
}

func resolveCommandsDepth(member Member, policy *SudoersPolicy, depth int) []Member {
	if depth >= maxResolveDepth {
		return []Member{member}
	}
	if aliasName := member.GetCommandAlias(); aliasName != "" {
		if cmds, ok := policy.CommandAliases[aliasName]; ok {
			var resolved []Member
			for _, m := range cmds {
				// Inherit negation if the alias reference itself was negated
				if member.Negated {
					m.Negated = !m.Negated
				}
				resolved = append(resolved, resolveCommandsDepth(m, policy, depth+1)...)
			}
			return resolved
		}
	}
	return []Member{member}
}

// resolveUserMembers recursively expands User_Aliases if defined in the policy.
func resolveUserMembers(members []Member, policy *SudoersPolicy, depth int) []Member {
	if depth >= maxResolveDepth || len(policy.UserAliases) == 0 {
		return members
	}
	var out []Member
	for _, m := range members {
		if m.UserAlias != "" {
			if aliased, ok := policy.UserAliases[m.UserAlias]; ok {
				for _, sub := range aliased {
					if m.Negated {
						sub.Negated = !sub.Negated
					}
					out = append(out, resolveUserMembers([]Member{sub}, policy, depth+1)...)
				}
				continue
			}
		}
		out = append(out, m)
	}
	return out
}

// resolveHostMembers recursively expands Host_Aliases if defined in the policy.
func resolveHostMembers(members []Member, policy *SudoersPolicy, depth int) []Member {
	if depth >= maxResolveDepth || len(policy.HostAliases) == 0 {
		return members
	}
	var out []Member
	for _, m := range members {
		if m.HostAlias != "" {
			if aliased, ok := policy.HostAliases[m.HostAlias]; ok {
				for _, sub := range aliased {
					if m.Negated {
						sub.Negated = !sub.Negated
					}
					out = append(out, resolveHostMembers([]Member{sub}, policy, depth+1)...)
				}
				continue
			}
		}
		out = append(out, m)
	}
	return out
}

// resolveRunasMembers recursively expands Runas_Aliases if defined in the policy.
func resolveRunasMembers(members []Member, policy *SudoersPolicy, depth int) []Member {
	if depth >= maxResolveDepth || len(policy.RunasAliases) == 0 {
		return members
	}
	var out []Member
	for _, m := range members {
		if m.RunasAlias != "" {
			if aliased, ok := policy.RunasAliases[m.RunasAlias]; ok {
				for _, sub := range aliased {
					if m.Negated {
						sub.Negated = !sub.Negated
					}
					out = append(out, resolveRunasMembers([]Member{sub}, policy, depth+1)...)
				}
				continue
			}
		}
		out = append(out, m)
	}
	return out
}
