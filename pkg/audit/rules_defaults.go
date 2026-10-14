package audit

import (
	"fmt"
	"path"
	"strconv"
	"strings"
)

// dangerousEnvVars lists environment variables that enable library injection,
// interpreter hijacking, shell startup execution, or editor/pager escalation when preserved.
var dangerousEnvVars = []string{
	"LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT", "LD_DEBUG",
	"PYTHONPATH", "PYTHONHOME", "PYTHONINSPECT", "PYTHONUSERBASE",
	"PERLLIB", "PERL5LIB", "PERL5OPT",
	"RUBYLIB", "RUBYOPT", "GEM_PATH",
	"NODE_OPTIONS", "NODE_PATH", "JAVA_TOOL_OPTIONS",
	"GCONV_PATH", "GETCONF_DIR", "HOSTALIASES", "LOCALDOMAIN", "RES_OPTIONS",
	"PATH", "SHELL", "ENV", "BASH_ENV", "ZDOTDIR",
	"PS4", "SHELLOPTS", "GLOBIGNORE", "BASH_FUNC_*",
	"EDITOR", "VISUAL", "PAGER", "SUDO_EDITOR", "SYSTEMD_PAGER", "LESSOPEN", "LESSCLOSE",
}

// getLastBoolOption returns the last boolean value assigned to key across a slice of Options.
// In sudoers, later Defaults declarations override earlier ones (last-match-wins).
func getLastBoolOption(options []Option, key string) (val bool, found bool) {
	for _, opt := range options {
		if _, hasOp := opt["operation"]; hasOp {
			continue
		}
		if bVal, ok := opt[key].(bool); ok {
			val = bVal
			found = true
		}
	}
	return val, found
}

// getLastRawOption returns the last raw value (and whether it was present) for key across options.
func getLastRawOption(options []Option, key string) (val any, found bool) {
	for _, opt := range options {
		if _, hasOp := opt["operation"]; hasOp {
			continue
		}
		if raw, ok := opt[key]; ok {
			val = raw
			found = true
		}
	}
	return val, found
}

// findDangerousEnvKeep inspects list_add, list_assign, and list_remove operations on env_keep
// in declaration order and returns any dangerous environment variable names or globs preserved.
func findDangerousEnvKeep(options []Option) []string {
	var activeItems []string
	for _, opt := range options {
		op, isListOp := opt["operation"].(string)
		if !isListOp {
			continue
		}
		list, exists := opt["env_keep"]
		if !exists {
			continue
		}

		var items []string
		if anyItems, ok := list.([]any); ok {
			for _, item := range anyItems {
				if str, ok := item.(string); ok {
					items = append(items, str)
				}
			}
		} else if strItems, ok := list.([]string); ok {
			items = strItems
		}

		switch op {
		case "list_assign":
			activeItems = append([]string(nil), items...)
		case "list_add":
			activeItems = append(activeItems, items...)
		case "list_remove":
			var remaining []string
			for _, cur := range activeItems {
				removed := false
				for _, rem := range items {
					if strings.EqualFold(cur, rem) {
						removed = true
						break
					}
				}
				if !removed {
					remaining = append(remaining, cur)
				}
			}
			activeItems = remaining
		}
	}

	var foundDangerous []string
	for _, item := range activeItems {
		// Strip optional =* value suffix supported by sudoers env_keep syntax
		varName := item
		if eqIdx := strings.IndexByte(varName, '='); eqIdx != -1 {
			varName = varName[:eqIdx]
		}
		upperItem := strings.ToUpper(strings.TrimSpace(varName))
		if upperItem == "" {
			continue
		}

		isDangerous := false
		if upperItem == "*" {
			isDangerous = true
		} else {
			for _, dangerous := range dangerousEnvVars {
				if upperItem == dangerous {
					isDangerous = true
					break
				}
				// Check if the env_keep entry uses a glob pattern (e.g., "LD_*", "PYTHON*")
				// that matches a known dangerous environment variable, or vice versa.
				if strings.ContainsAny(upperItem, "*?[") {
					if matched, err := path.Match(upperItem, dangerous); err == nil && matched {
						isDangerous = true
						break
					}
				}
				if strings.ContainsAny(dangerous, "*?[") {
					if matched, err := path.Match(dangerous, upperItem); err == nil && matched {
						isDangerous = true
						break
					}
				}
			}
		}

		if isDangerous {
			foundDangerous = append(foundDangerous, item)
		}
	}
	return foundDangerous
}

// effectiveGlobalDefaults computes the effective global noPasswd (!authenticate) and noExec
// states from global Defaults entries so AuditCommands can inherit them as baseline defaults.
func effectiveGlobalDefaults(policy *SudoersPolicy) (noPasswd bool, noExec bool) {
	var globalOptions []Option
	for _, def := range policy.Defaults {
		if len(def.Binding) == 0 {
			globalOptions = append(globalOptions, def.Options...)
		}
	}
	if authVal, found := getLastBoolOption(globalOptions, "authenticate"); found {
		noPasswd = !authVal
	}
	if noExecVal, found := getLastBoolOption(globalOptions, "noexec"); found {
		noExec = noExecVal
	}
	return noPasswd, noExec
}

// AuditDefaults runs security checks on global Defaults and scoped/bound Defaults entries.
func AuditDefaults(policy *SudoersPolicy) []Finding {
	var findings []Finding

	// Separate global defaults (where Binding is empty) from scoped/bound defaults.
	var globalOptions []Option
	for _, def := range policy.Defaults {
		if len(def.Binding) == 0 {
			globalOptions = append(globalOptions, def.Options...)
		}
	}

	// Helper to check if a boolean option's last effective setting is true.
	isTrue := func(key string) bool {
		val, found := getLastBoolOption(globalOptions, key)
		return found && val
	}

	// Helper to check if a boolean option is missing or its last effective setting is false.
	isMissingOrFalse := func(key string) bool {
		val, found := getLastBoolOption(globalOptions, key)
		return !found || !val
	}

	// Check 1: Missing, disabled, empty, or relative secure_path
	rawSecurePath, hasSecurePath := getLastRawOption(globalOptions, "secure_path")
	if !hasSecurePath {
		findings = append(findings, Finding{
			ID:          "SUDO-DEF-001",
			Title:       "Missing secure_path Configuration",
			Description: "The global 'secure_path' default is not defined. Sudo will run commands using the calling user's PATH variable, which can lead to local command hijacking/privilege escalation if the user's PATH contains writable directories.",
			Severity:    SeverityHigh,
			Remediation: "Add 'Defaults secure_path=\"/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\"' to the sudoers file.",
		})
	} else if bVal, isBool := rawSecurePath.(bool); isBool && !bVal {
		findings = append(findings, Finding{
			ID:          "SUDO-DEF-001",
			Title:       "Disabled secure_path Configuration",
			Description: "The global 'secure_path' is explicitly disabled ('!secure_path'). Sudo will trust the invoking user's PATH environment variable, enabling command hijacking.",
			Severity:    SeverityHigh,
			Remediation: "Enable 'Defaults secure_path=\"/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\"' in the sudoers file.",
		})
	} else if securePath, isStr := rawSecurePath.(string); isStr {
		if securePath == "" {
			findings = append(findings, Finding{
				ID:          "SUDO-DEF-001",
				Title:       "Empty secure_path Configuration",
				Description: "The global 'secure_path' is defined but empty. Sudo will fallback to the user's current PATH environment, raising hijacking risks.",
				Severity:    SeverityHigh,
				Remediation: "Ensure secure_path has a set of safe directories: 'Defaults secure_path=\"/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\"'",
			})
		} else {
			// Check for relative paths or current directory '.' or empty elements in PATH
			parts := strings.Split(securePath, ":")
			for _, part := range parts {
				if part == "." || part == "" || !strings.HasPrefix(part, "/") {
					findings = append(findings, Finding{
						ID:          "SUDO-DEF-002",
						Title:       "Dangerous path in secure_path",
						Description: fmt.Sprintf("The 'secure_path' contains a relative or empty directory entry: '%s'. This can allow attackers to hijack commands if they drop a malicious binary in the relative target path.", part),
						Severity:    SeverityHigh,
						Remediation: "Only specify absolute paths in secure_path.",
					})
					break
				}
			}
		}
	}

	// Check 2: Missing or disabled use_pty
	if isMissingOrFalse("use_pty") {
		findings = append(findings, Finding{
			ID:          "SUDO-DEF-003",
			Title:       "Missing or Disabled use_pty",
			Description: "The 'use_pty' flag is not enabled globally. Without a pseudo-terminal (PTY) allocation, processes run via sudo can write to the terminal's input buffer using TIOCSTI ioctls, enabling terminal hijacking and command injection back into the user's shell.",
			Severity:    SeverityMedium,
			Remediation: "Add 'Defaults use_pty' globally to the sudoers file.",
		})
	}

	// Check 3: Dangerous env_keep list
	if foundDangerous := findDangerousEnvKeep(globalOptions); len(foundDangerous) > 0 {
		findings = append(findings, Finding{
			ID:          "SUDO-DEF-004",
			Title:       "Dangerous Environment Variables Preserved (env_keep)",
			Description: fmt.Sprintf("The policy explicitly preserves dangerous environment variables in env_keep: %s. This can allow local users to inject code into elevated processes (e.g. via dynamic linker hijack LD_PRELOAD, interpreter library paths, or pager/editor overrides).", strings.Join(foundDangerous, ", ")),
			Severity:    SeverityCritical,
			Remediation: "Remove dynamic library path, shell, editor, and interpreter environment variables from 'env_keep' additions in sudoers Defaults.",
		})
	}

	// Check 4: visiblepw enabled
	if isTrue("visiblepw") {
		findings = append(findings, Finding{
			ID:          "SUDO-DEF-005",
			Title:       "visiblepw Flag Enabled",
			Description: "The 'visiblepw' option is enabled globally. This forces sudo to print the password in cleartext if prompting on a terminal, exposing it to shoulder surfing or screen logs.",
			Severity:    SeverityHigh,
			Remediation: "Remove 'Defaults visiblepw' or explicitly set 'Defaults !visiblepw'.",
		})
	}

	// Check 5: pwfeedback enabled
	if isTrue("pwfeedback") {
		findings = append(findings, Finding{
			ID:          "SUDO-DEF-006",
			Title:       "pwfeedback Flag Enabled",
			Description: "The 'pwfeedback' option is enabled. It displays asterisks (*) when typing passwords, which visually leaks the password length and has historically had security vulnerabilities.",
			Severity:    SeverityLow,
			Remediation: "Remove 'Defaults pwfeedback' or explicitly set 'Defaults !pwfeedback' (asterisks feedback is disabled by default).",
		})
	}

	// Check 6: Missing or disabled noexec
	if isMissingOrFalse("noexec") {
		findings = append(findings, Finding{
			ID:          "SUDO-DEF-007",
			Title:       "Missing or Disabled noexec",
			Description: "The global 'noexec' flag is not enabled. This allows run commands to execute subprocesses (e.g. shells) unless individually blocked or restricted, increasing shell escape risk.",
			Severity:    SeverityMedium,
			Remediation: "Add 'Defaults noexec' globally to the sudoers file to prevent execution of subprocesses by default.",
		})
	}

	// Check 7: Missing or disabled requiretty
	if isMissingOrFalse("requiretty") {
		findings = append(findings, Finding{
			ID:          "SUDO-DEF-008",
			Title:       "Missing or Disabled requiretty",
			Description: "The global 'requiretty' flag is not enabled. Without it, commands can be executed from non-interactive environments (like crontab or daemons) which complicates session tracking and audibility.",
			Severity:    SeverityLow,
			Remediation: "Add 'Defaults requiretty' globally to the sudoers file.",
		})
	}

	// Check 8: Missing, disabled, or weak umask (last-match-wins)
	checkUmask := func(opts []Option) (string, bool) {
		rawVal, found := getLastRawOption(opts, "umask")
		if !found {
			return "", false
		}
		switch v := rawVal.(type) {
		case string:
			return v, true
		case float64:
			return fmt.Sprintf("%o", int(v)), true
		case int:
			return fmt.Sprintf("%o", v), true
		case bool:
			// Defaults !umask emits {"umask": false}
			if !v {
				return "!umask", true
			}
		}
		return "", false
	}
	umaskStr, hasUmask := checkUmask(globalOptions)
	if !hasUmask {
		findings = append(findings, Finding{
			ID:          "SUDO-DEF-009",
			Title:       "Missing umask Configuration",
			Description: "The global 'umask' option is not configured. Commands executed under sudo will run with the invoking user's umask, which could result in newly created files having overly permissive access controls.",
			Severity:    SeverityMedium,
			Remediation: "Add 'Defaults umask=0077' to the sudoers file to enforce a restrictive umask for all executed commands.",
		})
	} else {
		umaskVal, err := strconv.ParseInt(umaskStr, 8, 64)
		if err != nil || (umaskVal&0o77) != 0o77 {
			findings = append(findings, Finding{
				ID:          "SUDO-DEF-009",
				Title:       "Weak umask Configuration",
				Description: fmt.Sprintf("The global umask is set to a weak value '%s'. A weak umask can result in files or directories created by commands running as root being readable or writable by unprivileged users.", umaskStr),
				Severity:    SeverityMedium,
				Remediation: "Set 'Defaults umask=0077' in the sudoers file.",
			})
		}
	}

	// Check 9: Missing or disabled ignore_dot
	if isMissingOrFalse("ignore_dot") {
		findings = append(findings, Finding{
			ID:          "SUDO-DEF-010",
			Title:       "Missing or Disabled ignore_dot",
			Description: "The global 'ignore_dot' flag is not enabled. Sudo will not ignore the current directory '.' if it is present in the PATH environment variable, which could allow command hijacking if a user runs sudo in a directory containing malicious scripts.",
			Severity:    SeverityMedium,
			Remediation: "Add 'Defaults ignore_dot' globally to the sudoers file.",
		})
	}

	// Check 10: Missing or disabled env_reset
	if isMissingOrFalse("env_reset") {
		findings = append(findings, Finding{
			ID:          "SUDO-DEF-011",
			Title:       "Missing or Disabled env_reset",
			Description: "The global 'env_reset' flag is not enabled. This allows environment variables to be preserved when running commands under sudo, facilitating environment poisoning and potential privilege escalation.",
			Severity:    SeverityHigh,
			Remediation: "Enable 'Defaults env_reset' globally in the sudoers file.",
		})
	}

	// Check 11: Global authentication disabled (Defaults !authenticate)
	if authVal, found := getLastBoolOption(globalOptions, "authenticate"); found && !authVal {
		findings = append(findings, Finding{
			ID:          "SUDO-DEF-012",
			Title:       "Global Authentication Disabled (!authenticate)",
			Description: "The global 'authenticate' flag is explicitly disabled ('Defaults !authenticate'). All sudo rules will execute without requiring a password by default, turning any permitted command vulnerability into immediate passwordless privilege escalation.",
			Severity:    SeverityCritical,
			Remediation: "Remove 'Defaults !authenticate' and enable 'Defaults authenticate' globally.",
		})
	}

	// Check 12: Global setenv enabled (Defaults setenv)
	if isTrue("setenv") {
		findings = append(findings, Finding{
			ID:          "SUDO-DEF-013",
			Title:       "Global Environment Override Permitted (setenv)",
			Description: "The global 'setenv' option is enabled ('Defaults setenv'). This permits users to preserve their environment via 'sudo -E' or pass arbitrary environment variables on the command line, bypassing 'env_reset'.",
			Severity:    SeverityHigh,
			Remediation: "Remove 'Defaults setenv' or explicitly set 'Defaults !setenv'.",
		})
	}

	// Check 13: Global sudoedit_follow enabled (Defaults sudoedit_follow)
	if isTrue("sudoedit_follow") {
		findings = append(findings, Finding{
			ID:          "SUDO-DEF-014",
			Title:       "Sudoedit Symlink Following Enabled (sudoedit_follow)",
			Description: "The global 'sudoedit_follow' option is enabled. When users edit files with 'sudoedit', sudo will follow symbolic links, allowing attackers with write access to the target path's parent directory or symlink to edit arbitrary root-owned files.",
			Severity:    SeverityHigh,
			Remediation: "Remove 'Defaults sudoedit_follow' or explicitly set 'Defaults !sudoedit_follow'.",
		})
	}

	// Check 14: Weak credential caching (timestamp_timeout < 0 or > 15, or !tty_tickets / global timestamp_type)
	if rawTimeout, found := getLastRawOption(globalOptions, "timestamp_timeout"); found {
		var timeoutVal float64
		var parsed bool
		switch v := rawTimeout.(type) {
		case float64:
			timeoutVal, parsed = v, true
		case int:
			timeoutVal, parsed = float64(v), true
		case string:
			if f, err := strconv.ParseFloat(v, 64); err == nil {
				timeoutVal, parsed = f, true
			}
		}
		if parsed && (timeoutVal < 0 || timeoutVal > 15) {
			findings = append(findings, Finding{
				ID:          "SUDO-DEF-015",
				Title:       "Weak Sudo Credential Cache Timeout (timestamp_timeout)",
				Description: fmt.Sprintf("The 'timestamp_timeout' is set to '%v' minutes. Negative values cause cached sudo credentials to never expire, and values over 15 minutes widen the window for session hijacking.", rawTimeout),
				Severity:    SeverityMedium,
				Remediation: "Set 'Defaults timestamp_timeout=5' (or 0 to always prompt for a password) in the sudoers file.",
			})
		}
	}
	if ttyTickets, found := getLastBoolOption(globalOptions, "tty_tickets"); found && !ttyTickets {
		findings = append(findings, Finding{
			ID:          "SUDO-DEF-015",
			Title:       "Per-TTY Sudo Tickets Disabled (!tty_tickets)",
			Description: "The 'tty_tickets' option is disabled ('Defaults !tty_tickets'). Sudo credential tokens are shared across all terminal sessions for the same user, allowing background processes to piggyback on a user's authenticated sudo session.",
			Severity:    SeverityMedium,
			Remediation: "Enable 'Defaults tty_tickets' or set 'Defaults timestamp_type=tty' in the sudoers file.",
		})
	} else if rawTsType, found := getLastRawOption(globalOptions, "timestamp_type"); found {
		if tsType, ok := rawTsType.(string); ok && strings.EqualFold(tsType, "global") {
			findings = append(findings, Finding{
				ID:          "SUDO-DEF-015",
				Title:       "Global Sudo Credential Timestamp Type (timestamp_type=global)",
				Description: "The 'timestamp_type' is set to 'global'. Sudo credential tokens are shared across all sessions for the user rather than isolated per-TTY or per-PPID.",
				Severity:    SeverityMedium,
				Remediation: "Set 'Defaults timestamp_type=tty' or 'Defaults timestamp_type=ppid' in the sudoers file.",
			})
		}
	}

	// Audit scoped/bound Defaults (e.g., Defaults:user, Defaults@host, Defaults!cmnd, Defaults>runas)
	findings = append(findings, auditBoundDefaults(policy)...)

	return findings
}

// auditBoundDefaults inspects non-global Defaults entries (where Binding is non-empty)
// for dangerous overrides such as disabling env_reset/use_pty/authenticate or adding dangerous env_keep variables.
func auditBoundDefaults(policy *SudoersPolicy) []Finding {
	var findings []Finding

	for _, def := range policy.Defaults {
		if len(def.Binding) == 0 {
			continue
		}

		var targets []string
		for _, m := range def.Binding {
			name := m.GetName()
			if m.Negated {
				name = "!" + name
			}
			if name != "" {
				targets = append(targets, name)
			}
		}
		bindingStr := strings.Join(targets, ", ")

		if val, found := getLastBoolOption(def.Options, "env_reset"); found && !val {
			findings = append(findings, Finding{
				ID:          "SUDO-DEF-011",
				Title:       "Scoped env_reset Disabled",
				Description: fmt.Sprintf("Scoped Defaults for [%s] explicitly disables 'env_reset', allowing environment variables to be preserved.", bindingStr),
				Severity:    SeverityHigh,
				User:        bindingStr,
				Remediation: fmt.Sprintf("Remove '!env_reset' from the scoped Defaults entry for [%s].", bindingStr),
			})
		}

		if val, found := getLastBoolOption(def.Options, "use_pty"); found && !val {
			findings = append(findings, Finding{
				ID:          "SUDO-DEF-003",
				Title:       "Scoped use_pty Disabled",
				Description: fmt.Sprintf("Scoped Defaults for [%s] explicitly disables 'use_pty', exposing those sessions to TIOCSTI terminal hijacking.", bindingStr),
				Severity:    SeverityMedium,
				User:        bindingStr,
				Remediation: fmt.Sprintf("Remove '!use_pty' from the scoped Defaults entry for [%s].", bindingStr),
			})
		}

		if foundDangerous := findDangerousEnvKeep(def.Options); len(foundDangerous) > 0 {
			findings = append(findings, Finding{
				ID:          "SUDO-DEF-004",
				Title:       "Scoped Dangerous Environment Variables Preserved (env_keep)",
				Description: fmt.Sprintf("Scoped Defaults for [%s] preserves dangerous environment variables in env_keep: %s.", bindingStr, strings.Join(foundDangerous, ", ")),
				Severity:    SeverityCritical,
				User:        bindingStr,
				Remediation: fmt.Sprintf("Remove dangerous variables from scoped 'env_keep' for [%s].", bindingStr),
			})
		}

		if val, found := getLastBoolOption(def.Options, "visiblepw"); found && val {
			findings = append(findings, Finding{
				ID:          "SUDO-DEF-005",
				Title:       "Scoped visiblepw Flag Enabled",
				Description: fmt.Sprintf("Scoped Defaults for [%s] enables 'visiblepw', exposing passwords in cleartext.", bindingStr),
				Severity:    SeverityHigh,
				User:        bindingStr,
				Remediation: fmt.Sprintf("Remove 'visiblepw' from the scoped Defaults entry for [%s].", bindingStr),
			})
		}

		if val, found := getLastBoolOption(def.Options, "authenticate"); found && !val {
			findings = append(findings, Finding{
				ID:          "SUDO-DEF-012",
				Title:       "Scoped Authentication Disabled (!authenticate)",
				Description: fmt.Sprintf("Scoped Defaults for [%s] disables authentication ('!authenticate'), granting passwordless execution to matching rules.", bindingStr),
				Severity:    SeverityCritical,
				User:        bindingStr,
				Remediation: fmt.Sprintf("Remove '!authenticate' from the scoped Defaults entry for [%s].", bindingStr),
			})
		}

		if val, found := getLastBoolOption(def.Options, "setenv"); found && val {
			findings = append(findings, Finding{
				ID:          "SUDO-DEF-013",
				Title:       "Scoped Environment Override Permitted (setenv)",
				Description: fmt.Sprintf("Scoped Defaults for [%s] enables 'setenv', allowing users to preserve arbitrary environment variables.", bindingStr),
				Severity:    SeverityHigh,
				User:        bindingStr,
				Remediation: fmt.Sprintf("Remove 'setenv' from the scoped Defaults entry for [%s].", bindingStr),
			})
		}

		if val, found := getLastBoolOption(def.Options, "sudoedit_follow"); found && val {
			findings = append(findings, Finding{
				ID:          "SUDO-DEF-014",
				Title:       "Scoped Sudoedit Symlink Following Enabled (sudoedit_follow)",
				Description: fmt.Sprintf("Scoped Defaults for [%s] enables 'sudoedit_follow', allowing symlink following during sudoedit.", bindingStr),
				Severity:    SeverityHigh,
				User:        bindingStr,
				Remediation: fmt.Sprintf("Remove 'sudoedit_follow' from the scoped Defaults entry for [%s].", bindingStr),
			})
		}
	}

	return findings
}
