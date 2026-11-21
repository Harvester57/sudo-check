package audit

import (
	"fmt"
	"path"
	"slices"
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
	"GIT_EXTERNAL_DIFF":        true,
	"GIT_CONFIG_PARAMETERS":    true,
	"GIT_CONFIG_GLOBAL":        true,
	"GIT_TEMPLATE_DIR":         true,
	"SSH_ASKPASS":              true,
	"OPENSSL_CONF":             true,
	"OPENSSL_ENGINES":          true,
	"OPENSSL_MODULES":          true,
	"CURL_HOME":                true,
	"WGETRC":                   true,
	"VIMINIT":                  true,
	"EXINIT":                   true,
	"XAUTHORITY":               true,
	"DBUS_SESSION_BUS_ADDRESS": true,
	"HOME":                     true,
	"ZDOTDIR":                  true,
	"FPATH":                    true,
}

var dangerousEnvPrefixes = []string{
	"LD_",
	"DYLD_",
	"PYTHON",
	"PERL",
	"RUBY",
	"LUA_",
	"BASH_FUNC_",
}

var dangerousEnvWildcardSamples = []string{
	"LD_PRELOAD",
	"DYLD_INSERT_LIBRARIES",
	"PYTHONPATH",
	"PERL5OPT",
	"RUBYOPT",
	"LUA_INIT",
	"BASH_FUNC_X",
}

// isDangerousEnvVar checks whether an environment variable name or fnmatch pattern is unsafe to preserve.
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
	for _, p := range dangerousEnvPrefixes {
		if strings.HasPrefix(upper, p) {
			return true
		}
	}
	if strings.ContainsAny(upper, "*?[") {
		for candidate := range dangerousEnvExact {
			if matched, err := path.Match(upper, candidate); err == nil && matched {
				return true
			}
		}
		for _, sample := range dangerousEnvWildcardSamples {
			if matched, err := path.Match(upper, sample); err == nil && matched {
				return true
			}
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
	optRawLine  map[string]string
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
		optRawLine:  make(map[string]string),
	}
}

func (s *defaultsState) applyOptions(options []Option) {
	s.applyOptionsFrom(options, "", 0, "")
}

func sortedOptionKeys(opt Option) []string {
	keys := make([]string, 0, len(opt))
	for k := range opt {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

func (s *defaultsState) applyOptionsFrom(options []Option, file string, line int, rawLine string) {
	for _, opt := range options {
		op, isListOp := opt["operation"].(string)
		keys := sortedOptionKeys(opt)
		if isListOp {
			for _, k := range keys {
				if k == "operation" {
					continue
				}
				v := opt[k]
				if file != "" {
					s.optFile[k] = file
				}
				if line > 0 {
					s.optLine[k] = line
				}
				if rawLine != "" {
					s.optRawLine[k] = rawLine
				}
				items := extractStringSlice(v)
				delete(s.disabledOpt, k)
				delete(s.boolSet, k)
				delete(s.boolVal, k)
				switch op {
				case "list_assign":
					s.lists[k] = append([]string(nil), items...)
					delete(s.listRemoved, k)
				case "list_add":
					for _, item := range items {
						if !containsStr(s.lists[k], item) {
							s.lists[k] = append(s.lists[k], item)
						}
					}
					s.listRemoved[k] = removeStrings(s.listRemoved[k], items)
				case "list_remove":
					s.lists[k] = removeStrings(s.lists[k], items)
					for _, item := range items {
						if !containsStr(s.listRemoved[k], item) {
							s.listRemoved[k] = append(s.listRemoved[k], item)
						}
					}
				}
			}
			continue
		}

		for _, k := range keys {
			v := opt[k]
			if file != "" {
				s.optFile[k] = file
			}
			if line > 0 {
				s.optLine[k] = line
			}
			if rawLine != "" {
				s.optRawLine[k] = rawLine
			}
			switch val := v.(type) {
			case bool:
				s.boolSet[k] = true
				s.boolVal[k] = val
				if !val {
					s.disabledOpt[k] = true
					delete(s.strSet, k)
					delete(s.strVal, k)
					delete(s.numSet, k)
					delete(s.numVal, k)
					delete(s.lists, k)
					delete(s.listRemoved, k)
				} else {
					delete(s.disabledOpt, k)
				}
			case string:
				s.strSet[k] = true
				s.strVal[k] = val
				delete(s.disabledOpt, k)
				delete(s.boolSet, k)
				delete(s.boolVal, k)
				delete(s.numSet, k)
				delete(s.numVal, k)
			case float64:
				s.numSet[k] = true
				s.numVal[k] = val
				delete(s.disabledOpt, k)
				delete(s.boolSet, k)
				delete(s.boolVal, k)
				delete(s.strSet, k)
				delete(s.strVal, k)
			case int:
				s.numSet[k] = true
				s.numVal[k] = float64(val)
				delete(s.disabledOpt, k)
				delete(s.boolSet, k)
				delete(s.boolVal, k)
				delete(s.strSet, k)
				delete(s.strVal, k)
			}
		}
	}
}

func (s *defaultsState) resolveLoc(key string, globalFile string, globalLine int) (string, int, string) {
	f := globalFile
	if s.optFile[key] != "" {
		f = s.optFile[key]
	}
	raw := s.optRawLine[key]
	if l := s.optLine[key]; l > 0 {
		return f, l, raw
	}
	return f, globalLine, raw
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

func removeStrings(slice []string, toRemove []string) []string {
	if len(slice) == 0 || len(toRemove) == 0 {
		return slice
	}
	var remaining []string
	for _, existing := range slice {
		if !containsStr(toRemove, existing) {
			remaining = append(remaining, existing)
		}
	}
	return remaining
}

const defaultSafeSecurePath = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

func hasPathTraversal(p string) bool {
	for _, seg := range strings.Split(p, "/") {
		if seg == ".." {
			return true
		}
	}
	return false
}

// isUnsafeSecurePathEntry checks whether a single colon-delimited entry of secure_path
// is empty, relative, contains parent-directory traversal, or points into a temporary or
// user-writable directory tree.
func isUnsafeSecurePathEntry(part string) (bool, string) {
	if part == "" || part == "." || !strings.HasPrefix(part, "/") {
		return true, "relative or empty"
	}
	cleaned := path.Clean(part)
	if hasPathTraversal(part) || hasPathTraversal(cleaned) {
		return true, "parent directory traversal"
	}
	if isWritableOrTempPath(part) {
		return true, "temporary or user-writable"
	}
	return false, ""
}

func sanitizeSecurePath(raw string) string {
	var safe []string
	for _, p := range strings.Split(raw, ":") {
		trimmed := strings.TrimSpace(p)
		if unsafe, _ := isUnsafeSecurePathEntry(trimmed); unsafe {
			continue
		}
		safe = append(safe, trimmed)
	}
	if len(safe) == 0 {
		return defaultSafeSecurePath
	}
	return strings.Join(safe, ":")
}

type defaultsScope int

const (
	scopeGlobal defaultsScope = iota
	scopeHost
	scopeUser
	scopeRunas
	scopeCommand
)

// inferBindingScope derives the Defaults binding scope purely from JSON-serializable
// Member fields so native parser and cvtsudoers JSON ASTs always produce identical results.
func inferBindingScope(binding []Member) defaultsScope {
	if len(binding) == 0 {
		return scopeGlobal
	}
	for _, m := range binding {
		if m.Command != "" || m.CommandAlias != "" || m.LegacyAlias != "" {
			return scopeCommand
		}
		if m.Hostname != "" || m.NetworkAddr != "" || m.HostAlias != "" {
			return scopeHost
		}
		if m.RunasAlias != "" {
			return scopeRunas
		}
	}
	return scopeUser
}

func canonicalBindingKey(binding []Member) string {
	scope := inferBindingScope(binding)
	var names []string
	hasNegated := false
	for _, m := range binding {
		if n := m.GetName(); n != "" {
			names = append(names, n)
			if m.Negated {
				hasNegated = true
			}
		}
	}
	// When no negations are present, member order does not alter matching semantics.
	// When any negation is present, order matters (last-match-wins) and must be preserved.
	if !hasNegated {
		slices.Sort(names)
	}
	return fmt.Sprintf("%d|%s", scope, strings.Join(names, ","))
}

func formatScopedDefaultsDirective(binding []Member, scopeLabel string) string {
	if len(binding) == 0 || scopeLabel == "" {
		return "Defaults"
	}
	var sep string
	switch inferBindingScope(binding) {
	case scopeCommand:
		sep = "!"
	case scopeHost:
		sep = "@"
	case scopeRunas:
		sep = ">"
	default:
		sep = ":"
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
			globalState.applyOptionsFrom(def.Options, def.File, def.Line, def.RawLine)
		}
	}

	// Check 1: Missing or empty secure_path (SUDO-DEF-001) & dangerous path in secure_path (SUDO-DEF-002)
	if !globalState.hasOption("secure_path") {
		fCtx, fLine, fRaw := globalState.resolveLoc("secure_path", globalFile, globalLine)
		findings = append(findings, Finding{
			ID:              "SUDO-DEF-001",
			Title:           "Missing secure_path Configuration",
			Description:     "The global 'secure_path' default is not defined. Sudo will run commands using the calling user's PATH variable, which can lead to local command hijacking/privilege escalation if the user's PATH contains writable directories.",
			Severity:        SeverityHigh,
			SourceLine:      fRaw,
			Context:         fCtx,
			Line:            fLine,
			Remediation:     "Add 'Defaults secure_path=\"/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\"' to the sudoers file.",
			RemediationCode: fmt.Sprintf("Defaults secure_path=%q", defaultSafeSecurePath),
			Compliance:      []string{},
		})
	} else {
		fCtx, fLine, fRaw := globalState.resolveLoc("secure_path", globalFile, globalLine)
		securePath := globalState.strVal["secure_path"]
		if securePath == "" {
			findings = append(findings, Finding{
				ID:              "SUDO-DEF-001",
				Title:           "Empty secure_path Configuration",
				Description:     "The global 'secure_path' is defined but empty. Sudo will fallback to the user's current PATH environment, raising hijacking risks.",
				Severity:        SeverityHigh,
				SourceLine:      fRaw,
				Context:         fCtx,
				Line:            fLine,
				Remediation:     "Ensure secure_path has a set of safe directories: 'Defaults secure_path=\"/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\"'",
				RemediationCode: fmt.Sprintf("Defaults secure_path=%q", defaultSafeSecurePath),
				Compliance:      []string{},
			})
		} else {
			parts := strings.Split(securePath, ":")
			for _, part := range parts {
				if unsafe, reason := isUnsafeSecurePathEntry(part); unsafe {
					findings = append(findings, Finding{
						ID:              "SUDO-DEF-002",
						Title:           "Dangerous path in secure_path",
						Description:     fmt.Sprintf("The 'secure_path' contains a %s directory entry: '%s'. This can allow local users to hijack commands if a malicious binary is placed in the unsafe target path.", reason, part),
						Severity:        SeverityHigh,
						SourceLine:      fRaw,
						Context:         fCtx,
						Line:            fLine,
						Remediation:     "Only specify absolute, root-owned system directories without traversal or writable paths in secure_path.",
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
		fCtx, fLine, fRaw := globalState.resolveLoc("use_pty", globalFile, globalLine)
		findings = append(findings, Finding{
			ID:              "SUDO-DEF-003",
			Title:           "Missing or Disabled use_pty",
			Description:     "The 'use_pty' flag is not enabled globally. Without a pseudo-terminal (PTY) allocation, processes run via sudo can access the invoking terminal's input buffer, enabling terminal hijacking.",
			Severity:        SeverityMedium,
			SourceLine:      fRaw,
			Context:         fCtx,
			Line:            fLine,
			Remediation:     "Add 'Defaults use_pty' globally to the sudoers file.",
			RemediationCode: "Defaults use_pty",
			Compliance:      []string{"ANSSI-BP-028 R39", "CIS-5.2.2"},
		})
	}

	// Check 3: Dangerous environment variables preserved in env_keep or env_check, or removed from env_delete (SUDO-DEF-004)
	findings = append(findings, checkEnvLists(globalState, "", "Defaults", globalFile, globalLine)...)

	// Check 4: visiblepw enabled (SUDO-DEF-005)
	if globalState.isTrue("visiblepw") {
		fCtx, fLine, fRaw := globalState.resolveLoc("visiblepw", globalFile, globalLine)
		findings = append(findings, Finding{
			ID:              "SUDO-DEF-005",
			Title:           "visiblepw Flag Enabled",
			Description:     "The 'visiblepw' option is enabled globally. This forces sudo to print the password in cleartext if prompting on a terminal without echo suppression, exposing it to shoulder surfing or screen logs.",
			Severity:        SeverityHigh,
			SourceLine:      fRaw,
			Context:         fCtx,
			Line:            fLine,
			Remediation:     "Remove 'Defaults visiblepw' or explicitly set 'Defaults !visiblepw'.",
			RemediationCode: "Defaults !visiblepw",
			Compliance:      []string{},
		})
	}

	// Check 5: pwfeedback enabled (SUDO-DEF-006)
	if globalState.isTrue("pwfeedback") {
		fCtx, fLine, fRaw := globalState.resolveLoc("pwfeedback", globalFile, globalLine)
		findings = append(findings, Finding{
			ID:              "SUDO-DEF-006",
			Title:           "pwfeedback Flag Enabled",
			Description:     "The 'pwfeedback' option is enabled. It displays visual feedback when typing passwords, which leaks password length and has historically been associated with buffer overflow vulnerabilities (CVE-2019-18634).",
			Severity:        SeverityLow,
			SourceLine:      fRaw,
			Context:         fCtx,
			Line:            fLine,
			Remediation:     "Remove 'Defaults pwfeedback' or explicitly set 'Defaults !pwfeedback' (visual feedback is disabled by default).",
			RemediationCode: "Defaults !pwfeedback",
			Compliance:      []string{},
		})
	}

	// Check 6: Missing or disabled noexec (SUDO-DEF-007)
	if !globalState.hasOption("noexec") || globalState.isFalse("noexec") {
		fCtx, fLine, fRaw := globalState.resolveLoc("noexec", globalFile, globalLine)
		findings = append(findings, Finding{
			ID:              "SUDO-DEF-007",
			Title:           "Missing or Disabled noexec",
			Description:     "The global 'noexec' flag is not enabled. This allows permitted commands to execute child processes (such as interactive shells or pagers) unless individually restricted.",
			Severity:        SeverityMedium,
			SourceLine:      fRaw,
			Context:         fCtx,
			Line:            fLine,
			Remediation:     "Add 'Defaults noexec' globally to the sudoers file to prevent execution of subprocesses by default.",
			RemediationCode: "Defaults noexec",
			Compliance:      []string{"ANSSI-BP-028 R39"},
		})
	}

	// Check 7: Missing or disabled requiretty (SUDO-DEF-008)
	if !globalState.hasOption("requiretty") || globalState.isFalse("requiretty") {
		fCtx, fLine, fRaw := globalState.resolveLoc("requiretty", globalFile, globalLine)
		findings = append(findings, Finding{
			ID:              "SUDO-DEF-008",
			Title:           "Missing or Disabled requiretty",
			Description:     "The global 'requiretty' flag is not enabled. Without it, commands can be executed from non-interactive sessions (such as background daemons or cron jobs), complicating session attribution.",
			Severity:        SeverityLow,
			SourceLine:      fRaw,
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
		fCtx, fLine, fRaw := globalState.resolveLoc("umask", globalFile, globalLine)
		findings = append(findings, Finding{
			ID:              "SUDO-DEF-009",
			Title:           "Missing umask Configuration",
			Description:     "The global 'umask' option is not configured. Commands executed under sudo will run with the invoking user's umask, which could result in newly created files having overly permissive access controls.",
			Severity:        SeverityMedium,
			SourceLine:      fRaw,
			Context:         fCtx,
			Line:            fLine,
			Remediation:     "Add 'Defaults umask=0077' to the sudoers file to enforce a restrictive umask for all executed commands.",
			RemediationCode: "Defaults umask=0077",
			Compliance:      []string{"ANSSI-BP-028 R39"},
		})
	} else {
		fCtx, fLine, fRaw := globalState.resolveLoc("umask", globalFile, globalLine)
		umaskVal, err := strconv.ParseInt(umaskStr, 8, 64)
		if err != nil || (umaskVal&0o77) != 0o77 {
			findings = append(findings, Finding{
				ID:              "SUDO-DEF-009",
				Title:           "Weak umask Configuration",
				Description:     fmt.Sprintf("The global umask is set to a weak value '%s'. A weak umask can result in files or directories created by commands running as root being readable or writable by unprivileged users.", umaskStr),
				Severity:        SeverityMedium,
				SourceLine:      fRaw,
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
		fCtx, fLine, fRaw := globalState.resolveLoc("ignore_dot", globalFile, globalLine)
		findings = append(findings, Finding{
			ID:              "SUDO-DEF-010",
			Title:           "Missing or Disabled ignore_dot",
			Description:     "The global 'ignore_dot' flag is not enabled. Sudo will not ignore the current directory '.' if it is present in PATH, which could allow binary hijacking from the working directory.",
			Severity:        SeverityMedium,
			SourceLine:      fRaw,
			Context:         fCtx,
			Line:            fLine,
			Remediation:     "Add 'Defaults ignore_dot' globally to the sudoers file.",
			RemediationCode: "Defaults ignore_dot",
			Compliance:      []string{"ANSSI-BP-028 R39"},
		})
	}

	// Check 10: Missing or disabled env_reset (SUDO-DEF-011)
	if !globalState.hasOption("env_reset") || globalState.isFalse("env_reset") {
		fCtx, fLine, fRaw := globalState.resolveLoc("env_reset", globalFile, globalLine)
		findings = append(findings, Finding{
			ID:              "SUDO-DEF-011",
			Title:           "Missing or Disabled env_reset",
			Description:     "The global 'env_reset' flag is not enabled. This allows the calling user's environment variables to be inherited when running commands under sudo.",
			Severity:        SeverityHigh,
			SourceLine:      fRaw,
			Context:         fCtx,
			Line:            fLine,
			Remediation:     "Enable 'Defaults env_reset' globally in the sudoers file.",
			RemediationCode: "Defaults env_reset",
			Compliance:      []string{"ANSSI-BP-028 R39"},
		})
	}

	// Check 11: Global authentication disabled via Defaults !authenticate (SUDO-DEF-012)
	if globalState.isFalse("authenticate") {
		fCtx, fLine, fRaw := globalState.resolveLoc("authenticate", globalFile, globalLine)
		findings = append(findings, Finding{
			ID:              "SUDO-DEF-012",
			Title:           "Password Authentication Disabled Globally (!authenticate)",
			Description:     "The global 'Defaults !authenticate' option is set, disabling password verification for all sudo rules across the policy.",
			Severity:        SeverityCritical,
			SourceLine:      fRaw,
			Context:         fCtx,
			Line:            fLine,
			Remediation:     "Remove 'Defaults !authenticate' and require authentication for privileged operations.",
			RemediationCode: "Defaults authenticate",
			Compliance:      []string{"CIS-5.2.5", "DISA-STIG"},
		})
	}

	// Check 12: Global setenv enabled (SUDO-DEF-013)
	if globalState.isTrue("setenv") {
		fCtx, fLine, fRaw := globalState.resolveLoc("setenv", globalFile, globalLine)
		findings = append(findings, Finding{
			ID:              "SUDO-DEF-013",
			Title:           "Environment Override Permitted Globally (setenv)",
			Description:     "The global 'Defaults setenv' option is enabled, allowing users to pass arbitrary environment variables via 'sudo -E' or command-line variable assignments, bypassing 'env_reset'.",
			Severity:        SeverityHigh,
			SourceLine:      fRaw,
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
		fCtx, fLine, fRaw := globalState.resolveLoc(key, globalFile, globalLine)
		findings = append(findings, Finding{
			ID:              "SUDO-DEF-014",
			Title:           "Insecure sudoedit Symlink or Directory Configuration",
			Description:     "The policy enables 'sudoedit_follow' or disables 'sudoedit_checkdir' globally. This allows 'sudoedit' to follow symbolic links or edit files inside user-writable parent directories, enabling arbitrary file modification.",
			Severity:        SeverityHigh,
			SourceLine:      fRaw,
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
			fCtx, fLine, fRaw := globalState.resolveLoc("timestamp_timeout", globalFile, globalLine)
			findings = append(findings, Finding{
				ID:              "SUDO-DEF-015",
				Title:           "Weak Sudo Credential Cache Timeout (timestamp_timeout)",
				Description:     fmt.Sprintf("The 'timestamp_timeout' option is set to %v minutes. Negative values disable credential expiration entirely, and values above 15 minutes extend the window for session reuse.", tsTimeout),
				Severity:        SeverityMedium,
				SourceLine:      fRaw,
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
			fCtx, fLine, fRaw := globalState.resolveLoc("passwd_timeout", globalFile, globalLine)
			findings = append(findings, Finding{
				ID:              "SUDO-DEF-015",
				Title:           "Weak Sudo Password Prompt Timeout (passwd_timeout)",
				Description:     fmt.Sprintf("The 'passwd_timeout' option is set to %v minutes. Values of 0 disable the password prompt timeout, and high values leave unattended password prompts open.", pwTimeout),
				Severity:        SeverityLow,
				SourceLine:      fRaw,
				Context:         fCtx,
				Line:            fLine,
				Remediation:     "Set 'Defaults passwd_timeout=1' in the sudoers file.",
				RemediationCode: "Defaults passwd_timeout=1",
				Compliance:      []string{},
			})
		}
	}
	if globalState.strSet["timestamp_type"] && strings.EqualFold(globalState.strVal["timestamp_type"], "global") {
		fCtx, fLine, fRaw := globalState.resolveLoc("timestamp_type", globalFile, globalLine)
		findings = append(findings, Finding{
			ID:              "SUDO-DEF-015",
			Title:           "Global Credential Cache Scope (timestamp_type=global)",
			Description:     "The 'timestamp_type' is set to 'global', sharing cached sudo authentication tickets across all terminal sessions of the same user.",
			Severity:        SeverityMedium,
			SourceLine:      fRaw,
			Context:         fCtx,
			Line:            fLine,
			Remediation:     "Set 'Defaults timestamp_type=tty' or 'Defaults timestamp_type=ppid' to isolate authentication tickets per session.",
			RemediationCode: "Defaults timestamp_type=tty",
			Compliance:      []string{},
		})
	}

	// Check 15: Global runchroot or insecure runcwd (SUDO-DEF-016)
	if globalState.strSet["runchroot"] && globalState.strVal["runchroot"] != "" {
		fCtx, fLine, fRaw := globalState.resolveLoc("runchroot", globalFile, globalLine)
		findings = append(findings, Finding{
			ID:              "SUDO-DEF-016",
			Title:           "Deprecated or Risky Chroot Directive in Defaults (runchroot)",
			Description:     fmt.Sprintf("The global 'runchroot' option is set to '%s'. Sudo chroot functionality has been associated with critical vulnerabilities (CVE-2023-27320, CVE-2025-32463) and is deprecated upstream.", globalState.strVal["runchroot"]),
			Severity:        SeverityHigh,
			SourceLine:      fRaw,
			Context:         fCtx,
			Line:            fLine,
			Remediation:     "Remove 'Defaults runchroot' from the sudoers policy and use OS-level containerization or namespaces instead.",
			RemediationCode: "Defaults !runchroot",
		})
	}
	if globalState.strSet["runcwd"] && globalState.strVal["runcwd"] == "*" {
		fCtx, fLine, fRaw := globalState.resolveLoc("runcwd", globalFile, globalLine)
		findings = append(findings, Finding{
			ID:              "SUDO-DEF-016",
			Title:           "Unrestricted Working Directory Override in Defaults (runcwd=*)",
			Description:     "The global 'runcwd' option is set to '*', allowing users to set the command's working directory to arbitrary paths via 'sudo -D'.",
			Severity:        SeverityMedium,
			SourceLine:      fRaw,
			Context:         fCtx,
			Line:            fLine,
			Remediation:     "Remove 'Defaults runcwd=*' or restrict 'runcwd' to a trusted absolute directory.",
			RemediationCode: "Defaults !runcwd",
		})
	}

	// Check 16: Missing or disabled logfile (SUDO-DEF-017)
	if !globalState.hasOption("logfile") || strings.TrimSpace(globalState.strVal["logfile"]) == "" {
		fCtx, fLine, fRaw := globalState.resolveLoc("logfile", globalFile, globalLine)
		findings = append(findings, Finding{
			ID:              "SUDO-DEF-017",
			Title:           "Missing or Disabled Sudo Log File (logfile)",
			Description:     "The global 'logfile' option is not configured or is empty. Without a dedicated sudo log file, auditing and incident response for privileged command execution depend solely on syslog configuration.",
			Severity:        SeverityLow,
			SourceLine:      fRaw,
			Context:         fCtx,
			Line:            fLine,
			Remediation:     "Configure a dedicated sudo log file by adding 'Defaults logfile=\"/var/log/sudo.log\"' to the sudoers file.",
			RemediationCode: `Defaults logfile="/var/log/sudo.log"`,
			Compliance:      []string{"CIS-5.2.3"},
		})
	}

	// Check 17: Shared target password authentication enabled (SUDO-DEF-018)
	var sharedPwOpts []string
	for _, optName := range []string{"rootpw", "targetpw", "runaspw"} {
		if globalState.isTrue(optName) {
			sharedPwOpts = append(sharedPwOpts, optName)
		}
	}
	if len(sharedPwOpts) > 0 {
		fCtx, fLine, fRaw := globalState.resolveLoc(sharedPwOpts[0], globalFile, globalLine)
		findings = append(findings, Finding{
			ID:              "SUDO-DEF-018",
			Title:           "Shared Target Password Authentication Enabled (rootpw/targetpw/runaspw)",
			Description:     fmt.Sprintf("The global option(s) [%s] are enabled, requiring the root or target account's password instead of the invoking user's password. This encourages sharing privileged account credentials and undermines individual accountability.", strings.Join(sharedPwOpts, ", ")),
			Severity:        SeverityMedium,
			SourceLine:      fRaw,
			Context:         fCtx,
			Line:            fLine,
			Remediation:     "Disable 'rootpw', 'targetpw', and 'runaspw' so users authenticate with their own account credentials.",
			RemediationCode: "Defaults !rootpw, !targetpw, !runaspw",
			Compliance:      []string{"DISA-STIG"},
		})
	}

	// Audit Scoped Defaults (where len(def.Binding) > 0)
	findings = append(findings, auditScopedDefaults(policy)...)

	return findings
}

func checkEnvLists(state *defaultsState, scopeLabel string, defaultsDirective string, baseFile string, baseLine int) []Finding {
	var findings []Finding
	var foundDangerous []string
	var keepBad []string
	var checkBad []string
	var deleteBad []string
	triggeredKey := ""

	for _, item := range state.lists["env_keep"] {
		if isDangerousEnvVar(item) {
			if !containsStr(keepBad, item) {
				keepBad = append(keepBad, item)
			}
			if !containsStr(foundDangerous, item) {
				foundDangerous = append(foundDangerous, item)
			}
		}
	}
	if len(keepBad) > 0 && triggeredKey == "" {
		triggeredKey = "env_keep"
	}

	for _, item := range state.lists["env_check"] {
		if isDangerousEnvVar(item) {
			if !containsStr(checkBad, item) {
				checkBad = append(checkBad, item)
			}
			if !containsStr(foundDangerous, item) {
				foundDangerous = append(foundDangerous, item)
			}
		}
	}
	if len(checkBad) > 0 && triggeredKey == "" {
		triggeredKey = "env_check"
	}

	for _, item := range state.listRemoved["env_delete"] {
		if isDangerousEnvVar(item) {
			if !containsStr(deleteBad, item) {
				deleteBad = append(deleteBad, item)
			}
			if !containsStr(foundDangerous, item) {
				foundDangerous = append(foundDangerous, item)
			}
		}
	}
	if len(deleteBad) > 0 && triggeredKey == "" {
		triggeredKey = "env_delete"
	}

	if len(foundDangerous) > 0 {
		scopeDesc := "The policy"
		if scopeLabel != "" {
			scopeDesc = fmt.Sprintf("Scoped Defaults for [%s]", scopeLabel)
		}
		if defaultsDirective == "" {
			defaultsDirective = "Defaults"
		}
		var remLines []string
		if len(keepBad) > 0 {
			if containsStr(keepBad, "*") {
				remLines = append(remLines,
					fmt.Sprintf("%s env_reset", defaultsDirective),
					fmt.Sprintf("%s env_keep=\"LANG LC_ALL TERM\"", defaultsDirective),
				)
			} else {
				remLines = append(remLines, fmt.Sprintf("%s env_keep -= %q", defaultsDirective, strings.Join(keepBad, " ")))
			}
		}
		if len(checkBad) > 0 {
			if containsStr(checkBad, "*") {
				remLines = append(remLines, fmt.Sprintf("%s !env_check", defaultsDirective))
			} else {
				remLines = append(remLines, fmt.Sprintf("%s env_check -= %q", defaultsDirective, strings.Join(checkBad, " ")))
			}
		}
		if len(deleteBad) > 0 {
			if containsStr(deleteBad, "*") {
				remLines = append(remLines, fmt.Sprintf("%s env_delete += \"LD_PRELOAD LD_LIBRARY_PATH PYTHONPATH\"", defaultsDirective))
			} else {
				remLines = append(remLines, fmt.Sprintf("%s env_delete += %q", defaultsDirective, strings.Join(deleteBad, " ")))
			}
		}
		fCtx, fLine, fRaw := state.resolveLoc(triggeredKey, baseFile, baseLine)
		findings = append(findings, Finding{
			ID:              "SUDO-DEF-004",
			Title:           "Dangerous Environment Variables Preserved (env_keep)",
			Description:     fmt.Sprintf("%s explicitly preserves dangerous environment variables: %s. This can allow local users to alter runtime linker behavior, interpreter module paths, or pager/editor execution in elevated processes.", scopeDesc, strings.Join(foundDangerous, ", ")),
			Severity:        SeverityCritical,
			User:            scopeLabel,
			SourceLine:      fRaw,
			Context:         fCtx,
			Line:            fLine,
			Remediation:     "Remove dynamic library path, interpreter path, and shell/editor environment variables from 'env_keep' and 'env_check', and keep them in 'env_delete' in sudoers Defaults.",
			RemediationCode: strings.Join(remLines, "\n"),
			Compliance:      []string{},
		})
	}
	return findings
}

func auditScopedDefaults(policy *SudoersPolicy) []Finding {
	type scopedGroup struct {
		binding    []Member
		scopeLabel string
		directive  string
		firstFile  string
		firstLine  int
		state      *defaultsState
	}

	var groupOrder []string
	groups := make(map[string]*scopedGroup)

	for _, def := range policy.Defaults {
		if len(def.Binding) == 0 {
			continue
		}
		key := canonicalBindingKey(def.Binding)
		grp, exists := groups[key]
		if !exists {
			var names []string
			for _, m := range def.Binding {
				if n := m.GetName(); n != "" {
					names = append(names, n)
				}
			}
			scopeLabel := strings.Join(names, ", ")
			grp = &scopedGroup{
				binding:    def.Binding,
				scopeLabel: scopeLabel,
				directive:  formatScopedDefaultsDirective(def.Binding, scopeLabel),
				firstFile:  def.File,
				firstLine:  def.Line,
				state:      newDefaultsState(),
			}
			groups[key] = grp
			groupOrder = append(groupOrder, key)
		} else {
			if grp.firstFile == "" && def.File != "" {
				grp.firstFile = def.File
			}
			if grp.firstLine == 0 && def.Line > 0 {
				grp.firstLine = def.Line
			}
		}
		grp.state.applyOptionsFrom(def.Options, def.File, def.Line, def.RawLine)
	}

	var findings []Finding
	for _, key := range groupOrder {
		grpStartIdx := len(findings)
		grp := groups[key]
		state := grp.state
		scopeLabel := grp.scopeLabel
		directive := grp.directive
		baseFile := grp.firstFile
		baseLine := grp.firstLine

		// Scoped secure_path (!secure_path, empty, or dangerous path)
		if state.isFalse("secure_path") {
			fCtx, fLine, fRaw := state.resolveLoc("secure_path", baseFile, baseLine)
			findings = append(findings, Finding{
				ID:              "SUDO-DEF-001",
				Title:           "Disabled secure_path in Scoped Defaults",
				Description:     fmt.Sprintf("Scoped Defaults for [%s] explicitly disables 'secure_path', falling back to the invoking user's PATH variable and raising command hijacking risks.", scopeLabel),
				Severity:        SeverityHigh,
				User:            scopeLabel,
				SourceLine:      fRaw,
				Context:         fCtx,
				Line:            fLine,
				Remediation:     fmt.Sprintf("Remove '!secure_path' or configure a safe 'secure_path' for [%s].", scopeLabel),
				RemediationCode: fmt.Sprintf("%s secure_path=%q", directive, defaultSafeSecurePath),
				Compliance:      []string{},
			})
		} else if state.strSet["secure_path"] {
			fCtx, fLine, fRaw := state.resolveLoc("secure_path", baseFile, baseLine)
			securePath := state.strVal["secure_path"]
			if securePath == "" {
				findings = append(findings, Finding{
					ID:              "SUDO-DEF-001",
					Title:           "Empty secure_path in Scoped Defaults",
					Description:     fmt.Sprintf("Scoped Defaults for [%s] sets 'secure_path' to an empty value, falling back to the invoking user's PATH.", scopeLabel),
					Severity:        SeverityHigh,
					User:            scopeLabel,
					SourceLine:      fRaw,
					Context:         fCtx,
					Line:            fLine,
					Remediation:     fmt.Sprintf("Configure a safe 'secure_path' for [%s].", scopeLabel),
					RemediationCode: fmt.Sprintf("%s secure_path=%q", directive, defaultSafeSecurePath),
					Compliance:      []string{},
				})
			} else {
				for _, part := range strings.Split(securePath, ":") {
					if unsafe, reason := isUnsafeSecurePathEntry(part); unsafe {
						findings = append(findings, Finding{
							ID:              "SUDO-DEF-002",
							Title:           "Dangerous path in Scoped secure_path",
							Description:     fmt.Sprintf("Scoped Defaults for [%s] sets 'secure_path' containing a %s directory entry: '%s'. This can allow local users to hijack commands.", scopeLabel, reason, part),
							Severity:        SeverityHigh,
							User:            scopeLabel,
							SourceLine:      fRaw,
							Context:         fCtx,
							Line:            fLine,
							Remediation:     fmt.Sprintf("Only specify absolute, root-owned system directories in 'secure_path' for [%s].", scopeLabel),
							RemediationCode: fmt.Sprintf("%s secure_path=%q", directive, sanitizeSecurePath(securePath)),
							Compliance:      []string{},
						})
						break
					}
				}
			}
		}

		if state.isFalse("authenticate") {
			fCtx, fLine, fRaw := state.resolveLoc("authenticate", baseFile, baseLine)
			findings = append(findings, Finding{
				ID:              "SUDO-DEF-012",
				Title:           "Password Authentication Disabled in Scoped Defaults (!authenticate)",
				Description:     fmt.Sprintf("Scoped Defaults for [%s] sets '!authenticate', disabling password prompts for all matching rules.", scopeLabel),
				Severity:        SeverityCritical,
				User:            scopeLabel,
				SourceLine:      fRaw,
				Context:         fCtx,
				Line:            fLine,
				Remediation:     fmt.Sprintf("Remove '!authenticate' from Defaults for [%s].", scopeLabel),
				RemediationCode: fmt.Sprintf("%s authenticate", directive),
				Compliance:      []string{"CIS-5.2.5"},
			})
		}
		if state.isFalse("env_reset") {
			fCtx, fLine, fRaw := state.resolveLoc("env_reset", baseFile, baseLine)
			findings = append(findings, Finding{
				ID:              "SUDO-DEF-011",
				Title:           "Disabled env_reset in Scoped Defaults",
				Description:     fmt.Sprintf("Scoped Defaults for [%s] explicitly disables 'env_reset', preserving user environment variables.", scopeLabel),
				Severity:        SeverityHigh,
				User:            scopeLabel,
				SourceLine:      fRaw,
				Context:         fCtx,
				Line:            fLine,
				Remediation:     fmt.Sprintf("Remove '!env_reset' from Defaults for [%s].", scopeLabel),
				RemediationCode: fmt.Sprintf("%s env_reset", directive),
				Compliance:      []string{"ANSSI-BP-028 R39"},
			})
		}
		if state.isFalse("use_pty") {
			fCtx, fLine, fRaw := state.resolveLoc("use_pty", baseFile, baseLine)
			findings = append(findings, Finding{
				ID:              "SUDO-DEF-003",
				Title:           "Disabled use_pty in Scoped Defaults",
				Description:     fmt.Sprintf("Scoped Defaults for [%s] explicitly disables 'use_pty'.", scopeLabel),
				Severity:        SeverityMedium,
				User:            scopeLabel,
				SourceLine:      fRaw,
				Context:         fCtx,
				Line:            fLine,
				Remediation:     fmt.Sprintf("Remove '!use_pty' from Defaults for [%s].", scopeLabel),
				RemediationCode: fmt.Sprintf("%s use_pty", directive),
				Compliance:      []string{"ANSSI-BP-028 R39", "CIS-5.2.2"},
			})
		}
		if state.isFalse("noexec") {
			fCtx, fLine, fRaw := state.resolveLoc("noexec", baseFile, baseLine)
			findings = append(findings, Finding{
				ID:              "SUDO-DEF-007",
				Title:           "Disabled noexec in Scoped Defaults",
				Description:     fmt.Sprintf("Scoped Defaults for [%s] explicitly disables 'noexec'.", scopeLabel),
				Severity:        SeverityMedium,
				User:            scopeLabel,
				SourceLine:      fRaw,
				Context:         fCtx,
				Line:            fLine,
				Remediation:     fmt.Sprintf("Remove '!noexec' from Defaults for [%s].", scopeLabel),
				RemediationCode: fmt.Sprintf("%s noexec", directive),
				Compliance:      []string{"ANSSI-BP-028 R39"},
			})
		}
		if state.isTrue("visiblepw") {
			fCtx, fLine, fRaw := state.resolveLoc("visiblepw", baseFile, baseLine)
			findings = append(findings, Finding{
				ID:              "SUDO-DEF-005",
				Title:           "visiblepw Enabled in Scoped Defaults",
				Description:     fmt.Sprintf("Scoped Defaults for [%s] enables 'visiblepw'.", scopeLabel),
				Severity:        SeverityHigh,
				User:            scopeLabel,
				SourceLine:      fRaw,
				Context:         fCtx,
				Line:            fLine,
				Remediation:     fmt.Sprintf("Remove 'visiblepw' from Defaults for [%s].", scopeLabel),
				RemediationCode: fmt.Sprintf("%s !visiblepw", directive),
			})
		}
		if state.isTrue("pwfeedback") {
			fCtx, fLine, fRaw := state.resolveLoc("pwfeedback", baseFile, baseLine)
			findings = append(findings, Finding{
				ID:              "SUDO-DEF-006",
				Title:           "pwfeedback Enabled in Scoped Defaults",
				Description:     fmt.Sprintf("Scoped Defaults for [%s] enables 'pwfeedback', exposing password length visually.", scopeLabel),
				Severity:        SeverityLow,
				User:            scopeLabel,
				SourceLine:      fRaw,
				Context:         fCtx,
				Line:            fLine,
				Remediation:     fmt.Sprintf("Remove 'pwfeedback' from Defaults for [%s].", scopeLabel),
				RemediationCode: fmt.Sprintf("%s !pwfeedback", directive),
				Compliance:      []string{},
			})
		}
		if state.isFalse("requiretty") {
			fCtx, fLine, fRaw := state.resolveLoc("requiretty", baseFile, baseLine)
			findings = append(findings, Finding{
				ID:              "SUDO-DEF-008",
				Title:           "Disabled requiretty in Scoped Defaults",
				Description:     fmt.Sprintf("Scoped Defaults for [%s] explicitly disables 'requiretty', permitting non-interactive sudo execution.", scopeLabel),
				Severity:        SeverityLow,
				User:            scopeLabel,
				SourceLine:      fRaw,
				Context:         fCtx,
				Line:            fLine,
				Remediation:     fmt.Sprintf("Remove '!requiretty' from Defaults for [%s].", scopeLabel),
				RemediationCode: fmt.Sprintf("%s requiretty", directive),
				Compliance:      []string{"ANSSI-BP-028 R39"},
			})
		}
		if state.isFalse("umask") {
			fCtx, fLine, fRaw := state.resolveLoc("umask", baseFile, baseLine)
			findings = append(findings, Finding{
				ID:              "SUDO-DEF-009",
				Title:           "Disabled umask in Scoped Defaults",
				Description:     fmt.Sprintf("Scoped Defaults for [%s] explicitly disables 'umask', causing commands to inherit the invoking user's umask.", scopeLabel),
				Severity:        SeverityMedium,
				User:            scopeLabel,
				SourceLine:      fRaw,
				Context:         fCtx,
				Line:            fLine,
				Remediation:     fmt.Sprintf("Set '%s umask=0077' in the sudoers file.", directive),
				RemediationCode: fmt.Sprintf("%s umask=0077", directive),
				Compliance:      []string{"ANSSI-BP-028 R39"},
			})
		} else if umaskStr, hasUmask := state.getUmask(); hasUmask {
			umaskVal, err := strconv.ParseInt(umaskStr, 8, 64)
			if err != nil || (umaskVal&0o77) != 0o77 {
				fCtx, fLine, fRaw := state.resolveLoc("umask", baseFile, baseLine)
				findings = append(findings, Finding{
					ID:              "SUDO-DEF-009",
					Title:           "Weak umask in Scoped Defaults",
					Description:     fmt.Sprintf("Scoped Defaults for [%s] sets 'umask' to a weak value '%s'.", scopeLabel, umaskStr),
					Severity:        SeverityMedium,
					User:            scopeLabel,
					SourceLine:      fRaw,
					Context:         fCtx,
					Line:            fLine,
					Remediation:     fmt.Sprintf("Set '%s umask=0077' in the sudoers file.", directive),
					RemediationCode: fmt.Sprintf("%s umask=0077", directive),
					Compliance:      []string{"ANSSI-BP-028 R39"},
				})
			}
		}
		if state.isFalse("ignore_dot") {
			fCtx, fLine, fRaw := state.resolveLoc("ignore_dot", baseFile, baseLine)
			findings = append(findings, Finding{
				ID:              "SUDO-DEF-010",
				Title:           "Disabled ignore_dot in Scoped Defaults",
				Description:     fmt.Sprintf("Scoped Defaults for [%s] explicitly disables 'ignore_dot', permitting '.' entries in PATH.", scopeLabel),
				Severity:        SeverityMedium,
				User:            scopeLabel,
				SourceLine:      fRaw,
				Context:         fCtx,
				Line:            fLine,
				Remediation:     fmt.Sprintf("Remove '!ignore_dot' from Defaults for [%s].", scopeLabel),
				RemediationCode: fmt.Sprintf("%s ignore_dot", directive),
				Compliance:      []string{"ANSSI-BP-028 R39"},
			})
		}
		if state.isTrue("setenv") {
			fCtx, fLine, fRaw := state.resolveLoc("setenv", baseFile, baseLine)
			findings = append(findings, Finding{
				ID:              "SUDO-DEF-013",
				Title:           "Environment Override Permitted in Scoped Defaults (setenv)",
				Description:     fmt.Sprintf("Scoped Defaults for [%s] enables 'setenv', allowing arbitrary environment variable overrides.", scopeLabel),
				Severity:        SeverityHigh,
				User:            scopeLabel,
				SourceLine:      fRaw,
				Context:         fCtx,
				Line:            fLine,
				Remediation:     fmt.Sprintf("Remove 'setenv' from Defaults for [%s].", scopeLabel),
				RemediationCode: fmt.Sprintf("%s !setenv", directive),
			})
		}
		if state.isTrue("sudoedit_follow") || state.isFalse("sudoedit_checkdir") {
			key := "sudoedit_follow"
			if !state.isTrue("sudoedit_follow") {
				key = "sudoedit_checkdir"
			}
			fCtx, fLine, fRaw := state.resolveLoc(key, baseFile, baseLine)
			findings = append(findings, Finding{
				ID:              "SUDO-DEF-014",
				Title:           "Insecure sudoedit Configuration in Scoped Defaults",
				Description:     fmt.Sprintf("Scoped Defaults for [%s] enables 'sudoedit_follow' or disables 'sudoedit_checkdir'.", scopeLabel),
				Severity:        SeverityHigh,
				User:            scopeLabel,
				SourceLine:      fRaw,
				Context:         fCtx,
				Line:            fLine,
				Remediation:     fmt.Sprintf("Enforce '!sudoedit_follow' and 'sudoedit_checkdir' for [%s].", scopeLabel),
				RemediationCode: fmt.Sprintf("%s !sudoedit_follow, sudoedit_checkdir", directive),
			})
		}
		if tsTimeout, ok := state.getFloat("timestamp_timeout"); ok && (tsTimeout < 0 || tsTimeout > 15) {
			fCtx, fLine, fRaw := state.resolveLoc("timestamp_timeout", baseFile, baseLine)
			findings = append(findings, Finding{
				ID:              "SUDO-DEF-015",
				Title:           "Weak Sudo Credential Cache Timeout in Scoped Defaults (timestamp_timeout)",
				Description:     fmt.Sprintf("Scoped Defaults for [%s] sets 'timestamp_timeout' to %v minutes.", scopeLabel, tsTimeout),
				Severity:        SeverityMedium,
				User:            scopeLabel,
				SourceLine:      fRaw,
				Context:         fCtx,
				Line:            fLine,
				Remediation:     fmt.Sprintf("Set '%s timestamp_timeout=5' (or 0 to always prompt) in the sudoers file.", directive),
				RemediationCode: fmt.Sprintf("%s timestamp_timeout=5", directive),
				Compliance:      []string{"CIS-5.2.6", "DISA-STIG"},
			})
		}
		if pwTimeout, ok := state.getFloat("passwd_timeout"); ok && (pwTimeout <= 0 || pwTimeout > 5) {
			fCtx, fLine, fRaw := state.resolveLoc("passwd_timeout", baseFile, baseLine)
			findings = append(findings, Finding{
				ID:              "SUDO-DEF-015",
				Title:           "Weak Sudo Password Prompt Timeout in Scoped Defaults (passwd_timeout)",
				Description:     fmt.Sprintf("Scoped Defaults for [%s] sets 'passwd_timeout' to %v minutes.", scopeLabel, pwTimeout),
				Severity:        SeverityLow,
				User:            scopeLabel,
				SourceLine:      fRaw,
				Context:         fCtx,
				Line:            fLine,
				Remediation:     fmt.Sprintf("Set '%s passwd_timeout=1' in the sudoers file.", directive),
				RemediationCode: fmt.Sprintf("%s passwd_timeout=1", directive),
				Compliance:      []string{},
			})
		}
		if state.strSet["timestamp_type"] && strings.EqualFold(state.strVal["timestamp_type"], "global") {
			fCtx, fLine, fRaw := state.resolveLoc("timestamp_type", baseFile, baseLine)
			findings = append(findings, Finding{
				ID:              "SUDO-DEF-015",
				Title:           "Global Credential Cache Scope in Scoped Defaults (timestamp_type=global)",
				Description:     fmt.Sprintf("Scoped Defaults for [%s] sets 'timestamp_type' to 'global', sharing cached sudo authentication tickets across all sessions.", scopeLabel),
				Severity:        SeverityMedium,
				User:            scopeLabel,
				SourceLine:      fRaw,
				Context:         fCtx,
				Line:            fLine,
				Remediation:     fmt.Sprintf("Set '%s timestamp_type=tty' or '%s timestamp_type=ppid'.", directive, directive),
				RemediationCode: fmt.Sprintf("%s timestamp_type=tty", directive),
				Compliance:      []string{},
			})
		}
		if state.strSet["runchroot"] && state.strVal["runchroot"] != "" {
			fCtx, fLine, fRaw := state.resolveLoc("runchroot", baseFile, baseLine)
			findings = append(findings, Finding{
				ID:              "SUDO-DEF-016",
				Title:           "Deprecated or Risky Chroot Directive in Scoped Defaults (runchroot)",
				Description:     fmt.Sprintf("Scoped Defaults for [%s] sets 'runchroot' to '%s'. Sudo chroot functionality has been associated with critical vulnerabilities (CVE-2023-27320, CVE-2025-32463) and is deprecated upstream.", scopeLabel, state.strVal["runchroot"]),
				Severity:        SeverityHigh,
				User:            scopeLabel,
				SourceLine:      fRaw,
				Context:         fCtx,
				Line:            fLine,
				Remediation:     fmt.Sprintf("Remove 'runchroot' from Defaults for [%s].", scopeLabel),
				RemediationCode: fmt.Sprintf("%s !runchroot", directive),
			})
		}
		if state.strSet["runcwd"] && state.strVal["runcwd"] == "*" {
			fCtx, fLine, fRaw := state.resolveLoc("runcwd", baseFile, baseLine)
			findings = append(findings, Finding{
				ID:              "SUDO-DEF-016",
				Title:           "Unrestricted Working Directory Override in Scoped Defaults (runcwd=*)",
				Description:     fmt.Sprintf("Scoped Defaults for [%s] sets 'runcwd=*', allowing arbitrary working directory overrides via 'sudo -D'.", scopeLabel),
				Severity:        SeverityMedium,
				User:            scopeLabel,
				SourceLine:      fRaw,
				Context:         fCtx,
				Line:            fLine,
				Remediation:     fmt.Sprintf("Remove 'runcwd=*' from Defaults for [%s] or restrict it to a trusted absolute directory.", scopeLabel),
				RemediationCode: fmt.Sprintf("%s !runcwd", directive),
			})
		}
		if state.isFalse("logfile") || (state.strSet["logfile"] && strings.TrimSpace(state.strVal["logfile"]) == "") {
			fCtx, fLine, fRaw := state.resolveLoc("logfile", baseFile, baseLine)
			findings = append(findings, Finding{
				ID:              "SUDO-DEF-017",
				Title:           "Disabled Sudo Log File in Scoped Defaults (!logfile)",
				Description:     fmt.Sprintf("Scoped Defaults for [%s] disables or clears 'logfile', suppressing dedicated sudo log file recording.", scopeLabel),
				Severity:        SeverityLow,
				User:            scopeLabel,
				SourceLine:      fRaw,
				Context:         fCtx,
				Line:            fLine,
				Remediation:     fmt.Sprintf("Remove '!logfile' from Defaults for [%s] or set an explicit log file path.", scopeLabel),
				RemediationCode: fmt.Sprintf(`%s logfile="/var/log/sudo.log"`, directive),
				Compliance:      []string{"CIS-5.2.3"},
			})
		}
		var sharedPwOpts []string
		for _, optName := range []string{"rootpw", "targetpw", "runaspw"} {
			if state.isTrue(optName) {
				sharedPwOpts = append(sharedPwOpts, optName)
			}
		}
		if len(sharedPwOpts) > 0 {
			fCtx, fLine, fRaw := state.resolveLoc(sharedPwOpts[0], baseFile, baseLine)
			findings = append(findings, Finding{
				ID:              "SUDO-DEF-018",
				Title:           "Shared Target Password Authentication Enabled in Scoped Defaults (rootpw/targetpw/runaspw)",
				Description:     fmt.Sprintf("Scoped Defaults for [%s] enables [%s], prompting for the root or target account password instead of the invoking user's password.", scopeLabel, strings.Join(sharedPwOpts, ", ")),
				Severity:        SeverityMedium,
				User:            scopeLabel,
				SourceLine:      fRaw,
				Context:         fCtx,
				Line:            fLine,
				Remediation:     fmt.Sprintf("Remove 'rootpw', 'targetpw', and 'runaspw' from Defaults for [%s].", scopeLabel),
				RemediationCode: fmt.Sprintf("%s !rootpw, !targetpw, !runaspw", directive),
				Compliance:      []string{"DISA-STIG"},
			})
		}

		findings = append(findings, checkEnvLists(state, scopeLabel, directive, baseFile, baseLine)...)
		if directive != "" {
			for i := grpStartIdx; i < len(findings); i++ {
				if findings[i].DefaultsScope == "" {
					findings[i].DefaultsScope = directive
				}
			}
		}
	}

	return findings
}

type effectiveFlagResolution struct {
	noPasswd          bool
	noExec            bool
	noPasswdInherited string
	noExecInherited   string
}

func formatDefaultsBindingPrefix(binding []Member) string {
	if len(binding) == 0 {
		return "Defaults"
	}
	var names []string
	for _, m := range binding {
		if n := m.GetName(); n != "" {
			names = append(names, n)
		}
	}
	return formatScopedDefaultsDirective(binding, strings.Join(names, ", "))
}

// resolveEffectiveFlags computes the effective (noPasswd, noExec) flags for a command specification,
// evaluating Defaults in sudo's actual scope precedence order:
// Global -> Host (@) -> User (:) -> Runas (>) -> Command (!) -> per-command CmndSpec.Options.
func resolveEffectiveFlags(policy *SudoersPolicy, users []Member, hosts []Member, runasUsers []Member, cmdStr string, csOptions []Option) (noPasswd bool, noExec bool) {
	res := resolveEffectiveFlagsDetailed(policy, users, hosts, runasUsers, cmdStr, csOptions)
	return res.noPasswd, res.noExec
}

// resolveEffectiveFlagsDetailed computes effective (noPasswd, noExec) flags and records
// the canonical winning Defaults directive whenever a flag is inherited from Defaults
// rather than set explicitly in CmndSpec.Options.
func resolveEffectiveFlagsDetailed(policy *SudoersPolicy, users []Member, hosts []Member, runasUsers []Member, cmdStr string, csOptions []Option) effectiveFlagResolution {
	var res effectiveFlagResolution
	scopeOrder := []defaultsScope{scopeGlobal, scopeHost, scopeUser, scopeRunas, scopeCommand}
	for _, scope := range scopeOrder {
		for _, def := range policy.Defaults {
			if inferBindingScope(def.Binding) != scope {
				continue
			}
			if scope == scopeGlobal || bindingMatches(def.Binding, scope, policy, users, hosts, runasUsers, cmdStr) {
				prefix := formatDefaultsBindingPrefix(def.Binding)
				for _, opt := range def.Options {
					if val, ok := opt["authenticate"].(bool); ok {
						res.noPasswd = !val
						if !val {
							res.noPasswdInherited = prefix + " !authenticate"
						} else {
							res.noPasswdInherited = ""
						}
					}
					if val, ok := opt["noexec"].(bool); ok {
						res.noExec = val
						if val {
							res.noExecInherited = prefix + " noexec"
						} else {
							res.noExecInherited = ""
						}
					}
				}
			}
		}
	}

	for _, opt := range csOptions {
		if val, ok := opt["authenticate"].(bool); ok {
			res.noPasswd = !val
			res.noPasswdInherited = ""
		}
		if val, ok := opt["noexec"].(bool); ok {
			res.noExec = val
			res.noExecInherited = ""
		}
	}

	return res
}

func memberMatchesTargetName(bindingMember Member, targetName string) bool {
	bName := bindingMember.rawName()
	if bName == "" || targetName == "" {
		return false
	}
	return bName == "ALL" || bName == targetName
}

func bindingMatches(binding []Member, scope defaultsScope, policy *SudoersPolicy, users []Member, hosts []Member, runasUsers []Member, cmdStr string) bool {
	switch scope {
	case scopeCommand:
		exePath := ""
		if parts := splitCommandTokens(cmdStr); len(parts) > 0 {
			exePath = parts[0]
		}
		expanded := resolveMemberSlice(binding, policy, aliasKindCommand)
		matched := false
		for _, b := range expanded {
			bCmd := b.Command
			if bCmd == "" {
				bCmd = b.rawName()
			}
			if bCmd == "ALL" || (bCmd != "" && (bCmd == cmdStr || bCmd == exePath)) {
				matched = !b.Negated
			}
		}
		return matched

	case scopeHost:
		expanded := resolveMemberSlice(binding, policy, aliasKindHost)
		for _, h := range hosts {
			if h.Negated {
				continue
			}
			tName := h.rawName()
			if tName == "" {
				continue
			}
			matched := false
			for _, b := range expanded {
				if memberMatchesTargetName(b, tName) {
					matched = !b.Negated
				}
			}
			if matched {
				return true
			}
		}
		return false

	case scopeRunas:
		expanded := resolveMemberSlice(binding, policy, aliasKindRunas)
		targets := runasUsers
		if len(targets) == 0 {
			targets = []Member{{Username: "root"}}
		}
		for _, r := range targets {
			if r.Negated {
				continue
			}
			tName := r.rawName()
			if tName == "" {
				continue
			}
			matched := false
			for _, b := range expanded {
				if memberMatchesTargetName(b, tName) {
					matched = !b.Negated
				}
			}
			if matched {
				return true
			}
		}
		return false

	case scopeUser:
		expanded := resolveMemberSlice(binding, policy, aliasKindUser)
		for _, u := range users {
			if u.Negated {
				continue
			}
			tName := u.rawName()
			if tName == "" {
				continue
			}
			matched := false
			for _, b := range expanded {
				if memberMatchesTargetName(b, tName) {
					matched = !b.Negated
				}
			}
			if matched {
				return true
			}
		}
		return false
	}
	return false
}
