package audit

import (
	"fmt"
	"strconv"
	"strings"
)

// dangerousEnvExact lists environment variables that allow code injection, path hijacking,
// pager/editor breakout, or authentication tampering when preserved across sudo.
var dangerousEnvExact = map[string]bool{
	"LD_PRELOAD":               true,
	"LD_LIBRARY_PATH":          true,
	"LD_AUDIT":                 true,
	"LD_DEBUG":                 true,
	"LD_DEBUG_OUTPUT":          true,
	"LD_DYNAMIC_WEAK":          true,
	"LD_ORIGIN_PATH":           true,
	"LD_PROFILE":               true,
	"LD_SHOW_AUXV":             true,
	"LD_USE_LOAD_BIAS":         true,
	"GCONV_PATH":               true,
	"GETCONF_DIR":              true,
	"HOSTALIASES":              true,
	"LOCALDOMAIN":              true,
	"LOCPATH":                  true,
	"MALLOC_TRACE":             true,
	"NIS_PATH":                 true,
	"NLSPATH":                  true,
	"RESOLV_HOST_CONF":         true,
	"RES_OPTIONS":              true,
	"TMPDIR":                   true,
	"TZDIR":                    true,
	"PYTHONPATH":               true,
	"PYTHONHOME":               true,
	"PYTHONINSPECT":            true,
	"PYTHONSTARTUP":            true,
	"PYTHONUSERBASE":           true,
	"PERLLIB":                  true,
	"PERL5LIB":                 true,
	"PERL5OPT":                 true,
	"PERL5DB":                  true,
	"RUBYLIB":                  true,
	"RUBYOPT":                  true,
	"GEM_PATH":                 true,
	"GEM_HOME":                 true,
	"LUA_PATH":                 true,
	"LUA_CPATH":                true,
	"LUA_INIT":                 true,
	"NODE_OPTIONS":             true,
	"NODE_PATH":                true,
	"JAVA_TOOL_OPTIONS":        true,
	"_JAVA_OPTIONS":            true,
	"CLASSPATH":                true,
	"PHP_INI_SCAN_DIR":         true,
	"PHPRC":                    true,
	"GOFLAGS":                  true,
	"RUSTC_WRAPPER":            true,
	"DOTNET_STARTUP_HOOKS":     true,
	"PATH":                     true,
	"SHELL":                    true,
	"ENV":                      true,
	"BASH_ENV":                 true,
	"CDPATH":                   true,
	"IFS":                      true,
	"GLOBIGNORE":               true,
	"SHELLOPTS":                true,
	"BASHOPTS":                 true,
	"PS4":                      true,
	"PROMPT_COMMAND":           true,
	"EDITOR":                   true,
	"VISUAL":                   true,
	"SUDO_EDITOR":              true,
	"PAGER":                    true,
	"MANPAGER":                 true,
	"SYSTEMD_PAGER":            true,
	"GIT_PAGER":                true,
	"LESS":                     true,
	"LESSOPEN":                 true,
	"LESSCLOSE":                true,
	"MORE":                     true,
	"GIT_SSH":                  true,
	"GIT_SSH_COMMAND":          true,
	"GIT_ASKPASS":              true,
	"GIT_EXEC_PATH":            true,
	"SSH_ASKPASS":              true,
	"OPENSSL_CONF":             true,
	"OPENSSL_ENGINES":          true,
	"CURL_HOME":                true,
	"WGETRC":                   true,
	"VIMINIT":                  true,
	"EXINIT":                   true,
	"XAUTHORITY":               true,
	"DBUS_SESSION_BUS_ADDRESS": true,
}

// isDangerousEnvVar checks whether an environment variable name or pattern is unsafe to preserve.
func isDangerousEnvVar(item string) bool {
	cleaned := strings.TrimSpace(item)
	if cleaned == "" {
		return false
	}
	// If it's a key=value pattern in env_keep, extract the key name
	if idx := strings.IndexByte(cleaned, '='); idx != -1 {
		cleaned = cleaned[:idx]
	}
	upper := strings.ToUpper(cleaned)
	if upper == "*" {
		return true
	}
	if dangerousEnvExact[upper] {
		return true
	}
	prefixes := []string{"LD_", "PYTHON", "PERL", "RUBY", "LUA_", "BASH_FUNC_"}
	for _, p := range prefixes {
		if strings.HasPrefix(upper, p) {
			return true
		}
	}
	return false
}

// defaultsState holds the resolved state of a sequence of Defaults options using last-match-wins semantics.
type defaultsState struct {
	boolSet     map[string]bool
	boolVal     map[string]bool
	strSet      map[string]bool
	strVal      map[string]string
	numSet      map[string]bool
	numVal      map[string]float64
	disabledOpt map[string]bool
	lists       map[string][]string
	listRemoved map[string][]string
	optFile     map[string]string
	optLine     map[string]int
}

func newDefaultsState() *defaultsState {
	return &defaultsState{
		boolSet:     make(map[string]bool),
		boolVal:     make(map[string]bool),
		strSet:      make(map[string]bool),
		strVal:      make(map[string]string),
		numSet:      make(map[string]bool),
		numVal:      make(map[string]float64),
		disabledOpt: make(map[string]bool),
		lists:       make(map[string][]string),
		listRemoved: make(map[string][]string),
		optFile:     make(map[string]string),
		optLine:     make(map[string]int),
	}
}

func (s *defaultsState) applyOptions(options []Option) {
	s.applyOptionsFrom(options, "", 0)
}

func (s *defaultsState) applyOptionsFrom(options []Option, file string, line int) {
	for _, opt := range options {
		op, isListOp := opt["operation"].(string)
		if isListOp {
			for k, v := range opt {
				if k == "operation" {
					continue
				}
				if file != "" {
					s.optFile[k] = file
				}
				if line > 0 {
					s.optLine[k] = line
				}
				items := extractStringSlice(v)
				switch op {
				case "list_assign":
					s.lists[k] = append([]string(nil), items...)
				case "list_add":
					for _, item := range items {
						if !containsStr(s.lists[k], item) {
							s.lists[k] = append(s.lists[k], item)
						}
					}
				case "list_remove":
					var remaining []string
					for _, existing := range s.lists[k] {
						if !containsStr(items, existing) {
							remaining = append(remaining, existing)
						}
					}
					s.lists[k] = remaining
					for _, item := range items {
						if !containsStr(s.listRemoved[k], item) {
							s.listRemoved[k] = append(s.listRemoved[k], item)
						}
					}
				}
			}
			continue
		}

		for k, v := range opt {
			if file != "" {
				s.optFile[k] = file
			}
			if line > 0 {
				s.optLine[k] = line
			}
			switch val := v.(type) {
			case bool:
				s.boolSet[k] = true
				s.boolVal[k] = val
				if !val {
					s.disabledOpt[k] = true
					delete(s.strSet, k)
					delete(s.numSet, k)
					delete(s.lists, k)
				} else {
					delete(s.disabledOpt, k)
				}
			case string:
				s.strSet[k] = true
				s.strVal[k] = val
				delete(s.disabledOpt, k)
			case float64:
				s.numSet[k] = true
				s.numVal[k] = val
				delete(s.disabledOpt, k)
			case int:
				s.numSet[k] = true
				s.numVal[k] = float64(val)
				delete(s.disabledOpt, k)
			}
		}
	}
}

func (s *defaultsState) resolveLoc(key string, globalFile string, globalLine int) (string, int) {
	f := globalFile
	if s.optFile[key] != "" {
		f = s.optFile[key]
	}
	if l := s.optLine[key]; l > 0 {
		return f, l
	}
	return f, globalLine
}

func (s *defaultsState) isTrue(key string) bool {
	return s.boolSet[key] && s.boolVal[key]
}

func (s *defaultsState) isFalse(key string) bool {
	return s.boolSet[key] && !s.boolVal[key]
}

func (s *defaultsState) hasOption(key string) bool {
	if s.disabledOpt[key] {
		return false
	}
	return s.boolSet[key] || s.strSet[key] || s.numSet[key]
}

func (s *defaultsState) getUmask() (string, bool) {
	if s.disabledOpt["umask"] {
		return "", false
	}
	if s.strSet["umask"] {
		return s.strVal["umask"], true
	}
	if s.numSet["umask"] {
		return fmt.Sprintf("%04o", int(s.numVal["umask"])), true
	}
	return "", false
}

func (s *defaultsState) getFloat(key string) (float64, bool) {
	if s.disabledOpt[key] {
		return 0, false
	}
	if s.numSet[key] {
		return s.numVal[key], true
	}
	if s.strSet[key] {
		if f, err := strconv.ParseFloat(strings.TrimSpace(s.strVal[key]), 64); err == nil {
			return f, true
		}
	}
	return 0, false
}

func extractStringSlice(v any) []string {
	var items []string
	switch list := v.(type) {
	case []any:
		for _, item := range list {
			if str, ok := item.(string); ok {
				items = append(items, str)
			}
		}
	case []string:
		items = append(items, list...)
	}
	return items
}

func containsStr(slice []string, target string) bool {
	for _, s := range slice {
		if s == target {
			return true
		}
	}
	return false
}

const defaultSafeSecurePath = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

func sanitizeSecurePath(raw string) string {
	var safe []string
	for _, p := range strings.Split(raw, ":") {
		trimmed := strings.TrimSpace(p)
		if trimmed == "" || trimmed == "." || !strings.HasPrefix(trimmed, "/") {
			continue
		}
		if strings.HasPrefix(trimmed, "/tmp") || strings.HasPrefix(trimmed, "/var/tmp") || strings.HasPrefix(trimmed, "/dev/shm") {
			continue
		}
		safe = append(safe, trimmed)
	}
	if len(safe) == 0 {
		return defaultSafeSecurePath
	}
	return strings.Join(safe, ":")
}

func formatScopedDefaultsDirective(binding []Member, scopeLabel string) string {
	if len(binding) == 0 || scopeLabel == "" {
		return "Defaults"
	}
	sep := ":"
	for _, m := range binding {
		if m.Command != "" || m.CommandAlias != "" || m.LegacyAlias != "" {
			sep = "!"
			break
		}
		if m.Hostname != "" || m.NetworkAddr != "" || m.HostAlias != "" {
			sep = "@"
			break
		}
		if m.RunasAlias != "" {
			sep = ">"
			break
		}
	}
	return "Defaults" + sep + scopeLabel
}

// AuditDefaults runs security checks on global and scoped Defaults in the policy.
func AuditDefaults(policy *SudoersPolicy) []Finding {
	var findings []Finding

	globalState := newDefaultsState()
	var globalLine int
	var globalFile string
	for _, def := range policy.Defaults {
		if len(def.Binding) == 0 {
			if globalLine == 0 && def.Line > 0 {
				globalLine = def.Line
			}
			if globalFile == "" && def.File != "" {
				globalFile = def.File
			}
			globalState.applyOptionsFrom(def.Options, def.File, def.Line)
		}
	}

	// Check 1: Missing or empty secure_path (SUDO-DEF-001) & dangerous path in secure_path (SUDO-DEF-002)
	if !globalState.hasOption("secure_path") {
		fCtx, fLine := globalState.resolveLoc("secure_path", globalFile, globalLine)
		findings = append(findings, Finding{
			ID:              "SUDO-DEF-001",
			Title:           "Missing secure_path Configuration",
			Description:     "The global 'secure_path' default is not defined. Sudo will run commands using the calling user's PATH variable, which can lead to local command hijacking/privilege escalation if the user's PATH contains writable directories.",
			Severity:        SeverityHigh,
			Context:         fCtx,
			Line:            fLine,
			Remediation:     "Add 'Defaults secure_path=\"/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\"' to the sudoers file.",
			RemediationCode: fmt.Sprintf("Defaults secure_path=%q", defaultSafeSecurePath),
			Compliance:      []string{},
		})
	} else {
		fCtx, fLine := globalState.resolveLoc("secure_path", globalFile, globalLine)
		securePath := globalState.strVal["secure_path"]
		if securePath == "" {
			findings = append(findings, Finding{
				ID:              "SUDO-DEF-001",
				Title:           "Empty secure_path Configuration",
				Description:     "The global 'secure_path' is defined but empty. Sudo will fallback to the user's current PATH environment, raising hijacking risks.",
				Severity:        SeverityHigh,
				Context:         fCtx,
				Line:            fLine,
				Remediation:     "Ensure secure_path has a set of safe directories: 'Defaults secure_path=\"/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\"'",
				RemediationCode: fmt.Sprintf("Defaults secure_path=%q", defaultSafeSecurePath),
				Compliance:      []string{},
			})
		} else {
			parts := strings.Split(securePath, ":")
			for _, part := range parts {
				if part == "." || part == "" || !strings.HasPrefix(part, "/") {
					findings = append(findings, Finding{
						ID:              "SUDO-DEF-002",
						Title:           "Dangerous path in secure_path",
						Description:     fmt.Sprintf("The 'secure_path' contains a relative or empty directory entry: '%s'. This can allow local users to hijack commands if a binary is placed in the relative target path.", part),
						Severity:        SeverityHigh,
						Context:         fCtx,
						Line:            fLine,
						Remediation:     "Only specify absolute paths in secure_path.",
						RemediationCode: fmt.Sprintf("Defaults secure_path=%q", sanitizeSecurePath(securePath)),
						Compliance:      []string{},
					})
					break
				}
			}
		}
	}

	// Check 2: Missing or disabled use_pty (SUDO-DEF-003)
	if !globalState.hasOption("use_pty") || globalState.isFalse("use_pty") {
		fCtx, fLine := globalState.resolveLoc("use_pty", globalFile, globalLine)
		findings = append(findings, Finding{
			ID:              "SUDO-DEF-003",
			Title:           "Missing or Disabled use_pty",
			Description:     "The 'use_pty' flag is not enabled globally. Without a pseudo-terminal (PTY) allocation, processes run via sudo can access the invoking terminal's input buffer, enabling terminal hijacking.",
			Severity:        SeverityMedium,
			Context:         fCtx,
			Line:            fLine,
			Remediation:     "Add 'Defaults use_pty' globally to the sudoers file.",
			RemediationCode: "Defaults use_pty",
			Compliance:      []string{"ANSSI-BP-028 R39", "CIS-5.2.2"},
		})
	}

	// Check 3: Dangerous environment variables preserved in env_keep or env_check, or removed from env_delete (SUDO-DEF-004)
	envCtx, envLine := globalFile, globalLine
	for _, k := range []string{"env_keep", "env_check", "env_delete"} {
		if c, l := globalState.resolveLoc(k, globalFile, globalLine); c != "" && c != globalFile {
			envCtx, envLine = c, l
			break
		}
	}
	findings = append(findings, checkEnvLists(globalState, "", "Defaults", envCtx, envLine)...)

	// Check 4: visiblepw enabled (SUDO-DEF-005)
	if globalState.isTrue("visiblepw") {
		fCtx, fLine := globalState.resolveLoc("visiblepw", globalFile, globalLine)
		findings = append(findings, Finding{
			ID:              "SUDO-DEF-005",
			Title:           "visiblepw Flag Enabled",
			Description:     "The 'visiblepw' option is enabled globally. This forces sudo to print the password in cleartext if prompting on a terminal without echo suppression, exposing it to shoulder surfing or screen logs.",
			Severity:        SeverityHigh,
			Context:         fCtx,
			Line:            fLine,
			Remediation:     "Remove 'Defaults visiblepw' or explicitly set 'Defaults !visiblepw'.",
			RemediationCode: "Defaults !visiblepw",
			Compliance:      []string{},
		})
	}

	// Check 5: pwfeedback enabled (SUDO-DEF-006)
	if globalState.isTrue("pwfeedback") {
		fCtx, fLine := globalState.resolveLoc("pwfeedback", globalFile, globalLine)
		findings = append(findings, Finding{
			ID:              "SUDO-DEF-006",
			Title:           "pwfeedback Flag Enabled",
			Description:     "The 'pwfeedback' option is enabled. It displays visual feedback when typing passwords, which leaks password length and has historically been associated with buffer overflow vulnerabilities (CVE-2019-18634).",
			Severity:        SeverityLow,
			Context:         fCtx,
			Line:            fLine,
			Remediation:     "Remove 'Defaults pwfeedback' or explicitly set 'Defaults !pwfeedback' (visual feedback is disabled by default).",
			RemediationCode: "Defaults !pwfeedback",
			Compliance:      []string{},
		})
	}

	// Check 6: Missing or disabled noexec (SUDO-DEF-007)
	if !globalState.hasOption("noexec") || globalState.isFalse("noexec") {
		fCtx, fLine := globalState.resolveLoc("noexec", globalFile, globalLine)
		findings = append(findings, Finding{
			ID:              "SUDO-DEF-007",
			Title:           "Missing or Disabled noexec",
			Description:     "The global 'noexec' flag is not enabled. This allows permitted commands to execute child processes (such as interactive shells or pagers) unless individually restricted.",
			Severity:        SeverityMedium,
			Context:         fCtx,
			Line:            fLine,
			Remediation:     "Add 'Defaults noexec' globally to the sudoers file to prevent execution of subprocesses by default.",
			RemediationCode: "Defaults noexec",
			Compliance:      []string{"ANSSI-BP-028 R39"},
		})
	}

	// Check 7: Missing or disabled requiretty (SUDO-DEF-008)
	if !globalState.hasOption("requiretty") || globalState.isFalse("requiretty") {
		fCtx, fLine := globalState.resolveLoc("requiretty", globalFile, globalLine)
		findings = append(findings, Finding{
			ID:              "SUDO-DEF-008",
			Title:           "Missing or Disabled requiretty",
			Description:     "The global 'requiretty' flag is not enabled. Without it, commands can be executed from non-interactive sessions (such as background daemons or cron jobs), complicating session attribution.",
			Severity:        SeverityLow,
			Context:         fCtx,
			Line:            fLine,
			Remediation:     "Add 'Defaults requiretty' globally to the sudoers file.",
			RemediationCode: "Defaults requiretty",
			Compliance:      []string{"ANSSI-BP-028 R39"},
		})
	}

	// Check 8: Missing or weak umask (SUDO-DEF-009)
	umaskStr, hasUmask := globalState.getUmask()
	if !hasUmask {
		fCtx, fLine := globalState.resolveLoc("umask", globalFile, globalLine)
		findings = append(findings, Finding{
			ID:              "SUDO-DEF-009",
			Title:           "Missing umask Configuration",
			Description:     "The global 'umask' option is not configured. Commands executed under sudo will run with the invoking user's umask, which could result in newly created files having overly permissive access controls.",
			Severity:        SeverityMedium,
			Context:         fCtx,
			Line:            fLine,
			Remediation:     "Add 'Defaults umask=0077' to the sudoers file to enforce a restrictive umask for all executed commands.",
			RemediationCode: "Defaults umask=0077",
			Compliance:      []string{"ANSSI-BP-028 R39"},
		})
	} else {
		fCtx, fLine := globalState.resolveLoc("umask", globalFile, globalLine)
		umaskVal, err := strconv.ParseInt(umaskStr, 8, 64)
		if err != nil || (umaskVal&0o77) != 0o77 {
			findings = append(findings, Finding{
				ID:              "SUDO-DEF-009",
				Title:           "Weak umask Configuration",
				Description:     fmt.Sprintf("The global umask is set to a weak value '%s'. A weak umask can result in files or directories created by commands running as root being readable or writable by unprivileged users.", umaskStr),
				Severity:        SeverityMedium,
				Context:         fCtx,
				Line:            fLine,
				Remediation:     "Set 'Defaults umask=0077' in the sudoers file.",
				RemediationCode: "Defaults umask=0077",
				Compliance:      []string{"ANSSI-BP-028 R39"},
			})
		}
	}

	// Check 9: Missing or disabled ignore_dot (SUDO-DEF-010)
	if !globalState.hasOption("ignore_dot") || globalState.isFalse("ignore_dot") {
		fCtx, fLine := globalState.resolveLoc("ignore_dot", globalFile, globalLine)
		findings = append(findings, Finding{
			ID:              "SUDO-DEF-010",
			Title:           "Missing or Disabled ignore_dot",
			Description:     "The global 'ignore_dot' flag is not enabled. Sudo will not ignore the current directory '.' if it is present in PATH, which could allow binary hijacking from the working directory.",
			Severity:        SeverityMedium,
			Context:         fCtx,
			Line:            fLine,
			Remediation:     "Add 'Defaults ignore_dot' globally to the sudoers file.",
			RemediationCode: "Defaults ignore_dot",
			Compliance:      []string{"ANSSI-BP-028 R39"},
		})
	}

	// Check 10: Missing or disabled env_reset (SUDO-DEF-011)
	if !globalState.hasOption("env_reset") || globalState.isFalse("env_reset") {
		fCtx, fLine := globalState.resolveLoc("env_reset", globalFile, globalLine)
		findings = append(findings, Finding{
			ID:              "SUDO-DEF-011",
			Title:           "Missing or Disabled env_reset",
			Description:     "The global 'env_reset' flag is not enabled. This allows the calling user's environment variables to be inherited when running commands under sudo.",
			Severity:        SeverityHigh,
			Context:         fCtx,
			Line:            fLine,
			Remediation:     "Enable 'Defaults env_reset' globally in the sudoers file.",
			RemediationCode: "Defaults env_reset",
			Compliance:      []string{"ANSSI-BP-028 R39"},
		})
	}

	// Check 11: Global authentication disabled via Defaults !authenticate (SUDO-DEF-012)
	if globalState.isFalse("authenticate") {
		fCtx, fLine := globalState.resolveLoc("authenticate", globalFile, globalLine)
		findings = append(findings, Finding{
			ID:              "SUDO-DEF-012",
			Title:           "Password Authentication Disabled Globally (!authenticate)",
			Description:     "The global 'Defaults !authenticate' option is set, disabling password verification for all sudo rules across the policy.",
			Severity:        SeverityCritical,
			Context:         fCtx,
			Line:            fLine,
			Remediation:     "Remove 'Defaults !authenticate' and require authentication for privileged operations.",
			RemediationCode: "Defaults authenticate",
			Compliance:      []string{"CIS-5.2.5", "DISA-STIG"},
		})
	}

	// Check 12: Global setenv enabled (SUDO-DEF-013)
	if globalState.isTrue("setenv") {
		fCtx, fLine := globalState.resolveLoc("setenv", globalFile, globalLine)
		findings = append(findings, Finding{
			ID:              "SUDO-DEF-013",
			Title:           "Environment Override Permitted Globally (setenv)",
			Description:     "The global 'Defaults setenv' option is enabled, allowing users to pass arbitrary environment variables via 'sudo -E' or command-line variable assignments, bypassing 'env_reset'.",
			Severity:        SeverityHigh,
			Context:         fCtx,
			Line:            fLine,
			Remediation:     "Remove 'Defaults setenv' or explicitly set 'Defaults !setenv'.",
			RemediationCode: "Defaults !setenv",
			Compliance:      []string{},
		})
	}

	// Check 13: Insecure sudoedit symlink/directory settings (SUDO-DEF-014)
	if globalState.isTrue("sudoedit_follow") || globalState.isFalse("sudoedit_checkdir") {
		key := "sudoedit_follow"
		if !globalState.isTrue("sudoedit_follow") {
			key = "sudoedit_checkdir"
		}
		fCtx, fLine := globalState.resolveLoc(key, globalFile, globalLine)
		findings = append(findings, Finding{
			ID:              "SUDO-DEF-014",
			Title:           "Insecure sudoedit Symlink or Directory Configuration",
			Description:     "The policy enables 'sudoedit_follow' or disables 'sudoedit_checkdir' globally. This allows 'sudoedit' to follow symbolic links or edit files inside user-writable parent directories, enabling arbitrary file modification.",
			Severity:        SeverityHigh,
			Context:         fCtx,
			Line:            fLine,
			Remediation:     "Ensure 'Defaults !sudoedit_follow' and 'Defaults sudoedit_checkdir' are enforced.",
			RemediationCode: "Defaults !sudoedit_follow, sudoedit_checkdir",
			Compliance:      []string{},
		})
	}

	// Check 14: Weak authentication or credential caching timeouts (SUDO-DEF-015)
	if tsTimeout, ok := globalState.getFloat("timestamp_timeout"); ok {
		if tsTimeout < 0 || tsTimeout > 15 {
			fCtx, fLine := globalState.resolveLoc("timestamp_timeout", globalFile, globalLine)
			findings = append(findings, Finding{
				ID:              "SUDO-DEF-015",
				Title:           "Weak Sudo Credential Cache Timeout (timestamp_timeout)",
				Description:     fmt.Sprintf("The 'timestamp_timeout' option is set to %v minutes. Negative values disable credential expiration entirely, and values above 15 minutes extend the window for session reuse.", tsTimeout),
				Severity:        SeverityMedium,
				Context:         fCtx,
				Line:            fLine,
				Remediation:     "Set 'Defaults timestamp_timeout=5' (or 0 to always prompt) in the sudoers file.",
				RemediationCode: "Defaults timestamp_timeout=5",
				Compliance:      []string{"CIS-5.2.6", "DISA-STIG"},
			})
		}
	}
	if pwTimeout, ok := globalState.getFloat("passwd_timeout"); ok {
		if pwTimeout <= 0 || pwTimeout > 5 {
			fCtx, fLine := globalState.resolveLoc("passwd_timeout", globalFile, globalLine)
			findings = append(findings, Finding{
				ID:              "SUDO-DEF-015",
				Title:           "Weak Sudo Password Prompt Timeout (passwd_timeout)",
				Description:     fmt.Sprintf("The 'passwd_timeout' option is set to %v minutes. Values of 0 disable the password prompt timeout, and high values leave unattended password prompts open.", pwTimeout),
				Severity:        SeverityLow,
				Context:         fCtx,
				Line:            fLine,
				Remediation:     "Set 'Defaults passwd_timeout=1' in the sudoers file.",
				RemediationCode: "Defaults passwd_timeout=1",
				Compliance:      []string{},
			})
		}
	}
	if globalState.strSet["timestamp_type"] && strings.EqualFold(globalState.strVal["timestamp_type"], "global") {
		fCtx, fLine := globalState.resolveLoc("timestamp_type", globalFile, globalLine)
		findings = append(findings, Finding{
			ID:              "SUDO-DEF-015",
			Title:           "Global Credential Cache Scope (timestamp_type=global)",
			Description:     "The 'timestamp_type' is set to 'global', sharing cached sudo authentication tickets across all terminal sessions of the same user.",
			Severity:        SeverityMedium,
			Context:         fCtx,
			Line:            fLine,
			Remediation:     "Set 'Defaults timestamp_type=tty' or 'Defaults timestamp_type=ppid' to isolate authentication tickets per session.",
			RemediationCode: "Defaults timestamp_type=tty",
			Compliance:      []string{},
		})
	}

	// Check 15: Global runchroot or insecure runcwd (SUDO-DEF-016)
	if globalState.strSet["runchroot"] && globalState.strVal["runchroot"] != "" {
		fCtx, fLine := globalState.resolveLoc("runchroot", globalFile, globalLine)
		findings = append(findings, Finding{
			ID:              "SUDO-DEF-016",
			Title:           "Deprecated or Risky Chroot Directive in Defaults (runchroot)",
			Description:     fmt.Sprintf("The global 'runchroot' option is set to '%s'. Sudo chroot functionality has been associated with critical vulnerabilities (CVE-2023-27320, CVE-2025-32463) and is deprecated upstream.", globalState.strVal["runchroot"]),
			Severity:        SeverityHigh,
			Context:         fCtx,
			Line:            fLine,
			Remediation:     "Remove 'Defaults runchroot' from the sudoers policy and use OS-level containerization or namespaces instead.",
			RemediationCode: "Defaults !runchroot",
		})
	}
	if globalState.strSet["runcwd"] && globalState.strVal["runcwd"] == "*" {
		fCtx, fLine := globalState.resolveLoc("runcwd", globalFile, globalLine)
		findings = append(findings, Finding{
			ID:              "SUDO-DEF-016",
			Title:           "Unrestricted Working Directory Override in Defaults (runcwd=*)",
			Description:     "The global 'runcwd' option is set to '*', allowing users to set the command's working directory to arbitrary paths via 'sudo -D'.",
			Severity:        SeverityMedium,
			Context:         fCtx,
			Line:            fLine,
			Remediation:     "Remove 'Defaults runcwd=*' or restrict 'runcwd' to a trusted absolute directory.",
			RemediationCode: "Defaults !runcwd",
		})
	}

	// Audit Scoped Defaults (where len(def.Binding) > 0)
	findings = append(findings, auditScopedDefaults(policy)...)

	return findings
}

func checkEnvLists(state *defaultsState, scopeLabel string, defaultsDirective string, file string, line int) []Finding {
	var findings []Finding
	var foundDangerous []string

	for _, listName := range []string{"env_keep", "env_check"} {
		for _, item := range state.lists[listName] {
			if isDangerousEnvVar(item) && !containsStr(foundDangerous, item) {
				foundDangerous = append(foundDangerous, item)
			}
		}
	}
	for _, item := range state.listRemoved["env_delete"] {
		if isDangerousEnvVar(item) && !containsStr(foundDangerous, item) {
			foundDangerous = append(foundDangerous, item)
		}
	}

	if len(foundDangerous) > 0 {
		scopeDesc := "The policy"
		if scopeLabel != "" {
			scopeDesc = fmt.Sprintf("Scoped Defaults for [%s]", scopeLabel)
		}
		if defaultsDirective == "" {
			defaultsDirective = "Defaults"
		}
		var remCode string
		if containsStr(foundDangerous, "*") {
			remCode = fmt.Sprintf("%s env_reset\n%s env_keep=\"LANG LC_ALL TERM\"", defaultsDirective, defaultsDirective)
		} else {
			remCode = fmt.Sprintf("%s env_keep -= %q", defaultsDirective, strings.Join(foundDangerous, " "))
		}
		findings = append(findings, Finding{
			ID:              "SUDO-DEF-004",
			Title:           "Dangerous Environment Variables Preserved (env_keep)",
			Description:     fmt.Sprintf("%s explicitly preserves dangerous environment variables: %s. This can allow local users to alter runtime linker behavior, interpreter module paths, or pager/editor execution in elevated processes.", scopeDesc, strings.Join(foundDangerous, ", ")),
			Severity:        SeverityCritical,
			User:            scopeLabel,
			Context:         file,
			Line:            line,
			Remediation:     "Remove dynamic library path, interpreter path, and shell/editor environment variables from 'env_keep' and 'env_check' in sudoers Defaults.",
			RemediationCode: remCode,
			Compliance:      []string{},
		})
	}
	return findings
}

func auditScopedDefaults(policy *SudoersPolicy) []Finding {
	var findings []Finding

	for _, def := range policy.Defaults {
		if len(def.Binding) == 0 {
			continue
		}
		var names []string
		for _, m := range def.Binding {
			if n := m.GetName(); n != "" {
				names = append(names, n)
			}
		}
		scopeLabel := strings.Join(names, ", ")
		directive := formatScopedDefaultsDirective(def.Binding, scopeLabel)
		state := newDefaultsState()
		state.applyOptionsFrom(def.Options, def.File, def.Line)

		if state.isFalse("authenticate") {
			findings = append(findings, Finding{
				ID:              "SUDO-DEF-012",
				Title:           "Password Authentication Disabled in Scoped Defaults (!authenticate)",
				Description:     fmt.Sprintf("Scoped Defaults for [%s] sets '!authenticate', disabling password prompts for all matching rules.", scopeLabel),
				Severity:        SeverityCritical,
				User:            scopeLabel,
				Context:         def.File,
				Line:            def.Line,
				Remediation:     fmt.Sprintf("Remove '!authenticate' from Defaults for [%s].", scopeLabel),
				RemediationCode: fmt.Sprintf("%s authenticate", directive),
				Compliance:      []string{"CIS-5.2.5"},
			})
		}
		if state.isFalse("env_reset") {
			findings = append(findings, Finding{
				ID:              "SUDO-DEF-011",
				Title:           "Disabled env_reset in Scoped Defaults",
				Description:     fmt.Sprintf("Scoped Defaults for [%s] explicitly disables 'env_reset', preserving user environment variables.", scopeLabel),
				Severity:        SeverityHigh,
				User:            scopeLabel,
				Context:         def.File,
				Line:            def.Line,
				Remediation:     fmt.Sprintf("Remove '!env_reset' from Defaults for [%s].", scopeLabel),
				RemediationCode: fmt.Sprintf("%s env_reset", directive),
				Compliance:      []string{"ANSSI-BP-028 R39"},
			})
		}
		if state.isFalse("use_pty") {
			findings = append(findings, Finding{
				ID:              "SUDO-DEF-003",
				Title:           "Disabled use_pty in Scoped Defaults",
				Description:     fmt.Sprintf("Scoped Defaults for [%s] explicitly disables 'use_pty'.", scopeLabel),
				Severity:        SeverityMedium,
				User:            scopeLabel,
				Context:         def.File,
				Line:            def.Line,
				Remediation:     fmt.Sprintf("Remove '!use_pty' from Defaults for [%s].", scopeLabel),
				RemediationCode: fmt.Sprintf("%s use_pty", directive),
				Compliance:      []string{"ANSSI-BP-028 R39", "CIS-5.2.2"},
			})
		}
		if state.isFalse("noexec") {
			findings = append(findings, Finding{
				ID:              "SUDO-DEF-007",
				Title:           "Disabled noexec in Scoped Defaults",
				Description:     fmt.Sprintf("Scoped Defaults for [%s] explicitly disables 'noexec'.", scopeLabel),
				Severity:        SeverityMedium,
				User:            scopeLabel,
				Context:         def.File,
				Line:            def.Line,
				Remediation:     fmt.Sprintf("Remove '!noexec' from Defaults for [%s].", scopeLabel),
				RemediationCode: fmt.Sprintf("%s noexec", directive),
				Compliance:      []string{"ANSSI-BP-028 R39"},
			})
		}
		if state.isTrue("visiblepw") {
			findings = append(findings, Finding{
				ID:              "SUDO-DEF-005",
				Title:           "visiblepw Enabled in Scoped Defaults",
				Description:     fmt.Sprintf("Scoped Defaults for [%s] enables 'visiblepw'.", scopeLabel),
				Severity:        SeverityHigh,
				User:            scopeLabel,
				Context:         def.File,
				Line:            def.Line,
				Remediation:     fmt.Sprintf("Remove 'visiblepw' from Defaults for [%s].", scopeLabel),
				RemediationCode: fmt.Sprintf("%s !visiblepw", directive),
			})
		}
		if state.isTrue("setenv") {
			findings = append(findings, Finding{
				ID:              "SUDO-DEF-013",
				Title:           "Environment Override Permitted in Scoped Defaults (setenv)",
				Description:     fmt.Sprintf("Scoped Defaults for [%s] enables 'setenv', allowing arbitrary environment variable overrides.", scopeLabel),
				Severity:        SeverityHigh,
				User:            scopeLabel,
				Context:         def.File,
				Line:            def.Line,
				Remediation:     fmt.Sprintf("Remove 'setenv' from Defaults for [%s].", scopeLabel),
				RemediationCode: fmt.Sprintf("%s !setenv", directive),
			})
		}
		if state.isTrue("sudoedit_follow") || state.isFalse("sudoedit_checkdir") {
			findings = append(findings, Finding{
				ID:              "SUDO-DEF-014",
				Title:           "Insecure sudoedit Configuration in Scoped Defaults",
				Description:     fmt.Sprintf("Scoped Defaults for [%s] enables 'sudoedit_follow' or disables 'sudoedit_checkdir'.", scopeLabel),
				Severity:        SeverityHigh,
				User:            scopeLabel,
				Context:         def.File,
				Line:            def.Line,
				Remediation:     fmt.Sprintf("Enforce '!sudoedit_follow' and 'sudoedit_checkdir' for [%s].", scopeLabel),
				RemediationCode: fmt.Sprintf("%s !sudoedit_follow, sudoedit_checkdir", directive),
			})
		}
		findings = append(findings, checkEnvLists(state, scopeLabel, directive, def.File, def.Line)...)
	}

	return findings
}

// resolveEffectiveFlags computes the effective (noPasswd, noExec) flags for a command specification,
// taking into account global Defaults, matching scoped Defaults, and per-command CmndSpec.Options.
func resolveEffectiveFlags(policy *SudoersPolicy, users []Member, hosts []Member, runasUsers []Member, cmdStr string, csOptions []Option) (noPasswd bool, noExec bool) {
	// Notice: historically AuditCommands only treated noExec as true when set on csOptions or matching command/user Defaults,
	// unless we check whether authenticate/noexec were set.
	// Wait: if global Defaults sets !authenticate, then every command is passwordless!
	for _, def := range policy.Defaults {
		if len(def.Binding) == 0 {
			for _, opt := range def.Options {
				if val, ok := opt["authenticate"].(bool); ok {
					noPasswd = !val
				}
			}
		} else if bindingMatches(def.Binding, policy, users, hosts, runasUsers, cmdStr) {
			for _, opt := range def.Options {
				if val, ok := opt["authenticate"].(bool); ok {
					noPasswd = !val
				}
				if val, ok := opt["noexec"].(bool); ok {
					noExec = val
				}
			}
		}
	}

	for _, opt := range csOptions {
		if val, ok := opt["authenticate"].(bool); ok {
			noPasswd = !val
		}
		if val, ok := opt["noexec"].(bool); ok {
			noExec = val
		}
	}

	return noPasswd, noExec
}

func bindingMatches(binding []Member, policy *SudoersPolicy, users []Member, hosts []Member, runasUsers []Member, cmdStr string) bool {
	exePath := ""
	if parts := strings.Fields(cmdStr); len(parts) > 0 {
		exePath = parts[0]
	}
	for _, b := range binding {
		if b.Negated {
			continue
		}
		name := b.rawName()
		if name == "ALL" {
			return true
		}
		if b.Command != "" && (b.Command == cmdStr || b.Command == exePath) {
			return true
		}
		if b.CommandAlias != "" {
			for _, resolved := range resolveCommands(b, policy) {
				if !resolved.Negated && (resolved.Command == cmdStr || resolved.Command == exePath) {
					return true
				}
			}
		}
		for _, u := range users {
			if !u.Negated && u.rawName() == name && name != "" {
				return true
			}
		}
		for _, h := range hosts {
			if !h.Negated && h.rawName() == name && name != "" {
				return true
			}
		}
		for _, r := range runasUsers {
			if !r.Negated && r.rawName() == name && name != "" {
				return true
			}
		}
	}
	return false
}
