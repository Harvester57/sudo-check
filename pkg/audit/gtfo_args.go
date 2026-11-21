package audit

import (
	"fmt"
	"path"
	"strings"
	"sudo-check/pkg/gtfobins"
)

var (
	gtfoArgNeverConstrainedBinaries = map[string]bool{
		// Pagers
		"less": true,
		"more": true,
		"man":  true,
		"most": true,
		"pg":   true,
		// Shells
		"sh":    true,
		"bash":  true,
		"rbash": true,
		"dash":  true,
		"ash":   true,
		"zsh":   true,
		"ksh":   true,
		"mksh":  true,
		"ksh93": true,
		"pdksh": true,
		"csh":   true,
		"tcsh":  true,
		"fish":  true,
		// Interpreters
		"python":       true,
		"perl":         true,
		"ruby":         true,
		"php":          true,
		"lua":          true,
		"node":         true,
		"nodejs":       true,
		"awk":          true,
		"gawk":         true,
		"mawk":         true,
		"nawk":         true,
		"original-awk": true,
		// Archivers
		"tar":   true,
		"zip":   true,
		"unzip": true,
		"gzip":  true,
		"bzip2": true,
		// Search
		"find": true,
		// Container and daemon CLIs
		"docker":  true,
		"podman":  true,
		"kubectl": true,
		"lxd":     true,
		"ctr":     true,
		"crictl":  true,
		"nerdctl": true,
	}

	gtfoArgSystemctlSafeSubcommands = map[string]bool{
		"restart":           true,
		"reload":            true,
		"start":             true,
		"stop":              true,
		"try-restart":       true,
		"reload-or-restart": true,
		"is-active":         true,
		"is-enabled":        true,
	}

	gtfoArgServiceSafeActions = map[string]bool{
		"start":   true,
		"stop":    true,
		"restart": true,
		"reload":  true,
		"status":  true,
	}

	gtfoArgGitDangerousExact = map[string]bool{
		"-c":                  true,
		"--config-env":        true,
		"--exec-path":         true,
		"--git-dir":           true,
		"--work-tree":         true,
		"-p":                  true,
		"--paginate":          true,
		"--output":            true,
		"--ext-diff":          true,
		"-C":                  true,
		"-P":                  true,
		"--pager":             true,
		"-h":                  true,
		"--help":              true,
		"--man-path":          true,
		"--html-path":         true,
		"--info-path":         true,
		"--bare":              true,
		"--literal-pathspecs": true,
		"--glob-pathspecs":    true,
	}

	gtfoArgGitDangerousPrefixes = []string{
		"-c",
		"-C",
		"--config-env=",
		"--exec-path=",
		"--git-dir=",
		"--work-tree=",
		"--output=",
		"--pager=",
	}

	gtfoArgGitStatusSafeFlags = map[string]bool{
		"-s":          true,
		"--short":     true,
		"--porcelain": true,
		"-b":          true,
		"--branch":    true,
	}

	gtfoArgGitRevParseSafeFlags = map[string]bool{
		"--short":               true,
		"--abbrev-ref":          true,
		"--show-toplevel":       true,
		"--is-inside-work-tree": true,
		"--is-bare-repository":  true,
		"--verify":              true,
		"--symbolic-full-name":  true,
	}

	gtfoArgGitDescribeSafeFlags = map[string]bool{
		"--tags":        true,
		"--always":      true,
		"--long":        true,
		"--dirty":       true,
		"--exact-match": true,
		"--all":         true,
	}
)

// EvaluateGTFOArgumentConstraint evaluates whether fixed command arguments neutralize
// a GTFObins bypass capability for an allowlisted enterprise command.
func EvaluateGTFOArgumentConstraint(binaryName string, args []string, function string) (constrained bool, rationale string) {
	bin := gtfoArgNormalizeBinary(binaryName)
	if bin == "" {
		return false, ""
	}
	fn := strings.ToLower(strings.TrimSpace(function))
	if fn == "" {
		return false, ""
	}

	if gtfoArgIsNeverConstrained(bin) {
		return false, ""
	}

	if len(args) == 0 {
		return false, ""
	}
	for _, arg := range args {
		if !gtfoArgIsSafeToken(arg) {
			return false, ""
		}
	}

	switch bin {
	case "systemctl":
		return gtfoArgEvalSystemctl(args, fn)
	case "service":
		return gtfoArgEvalService(args, fn)
	case "cat", "head", "tail":
		return gtfoArgEvalFileReader(bin, args, fn)
	case "git":
		return gtfoArgEvalGit(args, fn)
	case "apt-get", "apt":
		return gtfoArgEvalApt(bin, args, fn)
	default:
		return false, ""
	}
}

func gtfoArgNormalizeBinary(binaryName string) string {
	trimmed := strings.TrimSpace(binaryName)
	if trimmed == "" {
		return ""
	}
	base := strings.ToLower(path.Base(trimmed))
	if base == "" || base == "." || base == "/" {
		return ""
	}
	return base
}

func gtfoArgIsNeverConstrained(bin string) bool {
	if isEditorBinary(bin) || gtfoArgNeverConstrainedBinaries[bin] {
		return true
	}
	for _, cand := range gtfobins.NormalizeBinaryName(bin) {
		lowerCand := strings.ToLower(cand)
		if isEditorBinary(lowerCand) || gtfoArgNeverConstrainedBinaries[lowerCand] {
			return true
		}
	}
	return false
}

func gtfoArgIsSafeToken(arg string) bool {
	trimmed := strings.TrimSpace(arg)
	if arg == "" || trimmed == "" || trimmed == "\"\"" || arg != trimmed {
		return false
	}
	if wildcardRegex.MatchString(arg) || gtfoArgHasTraversal(arg) || gtfoArgHasMetachar(arg) {
		return false
	}
	return true
}

func gtfoArgHasTraversal(arg string) bool {
	return strings.Contains(arg, "..")
}

func gtfoArgHasMetachar(arg string) bool {
	for i := 0; i < len(arg); i++ {
		ch := arg[i]
		if ch <= 0x20 || ch == 0x7f {
			return true
		}
		switch ch {
		case ';', '&', '|', '`', '$', '(', ')', '{', '}', '<', '>', '\\', '!', '\'', '"', '~':
			return true
		}
	}
	return false
}

func gtfoArgIsValidUnitName(unit string) bool {
	if unit == "" || strings.HasPrefix(unit, "-") || strings.HasPrefix(unit, ".") {
		return false
	}
	if strings.Contains(unit, "/") {
		return false
	}
	for i := 0; i < len(unit); i++ {
		ch := unit[i]
		valid := (ch >= 'a' && ch <= 'z') ||
			(ch >= 'A' && ch <= 'Z') ||
			(ch >= '0' && ch <= '9') ||
			ch == ':' || ch == '_' || ch == '.' || ch == '@' || ch == '-'
		if !valid {
			return false
		}
	}
	return true
}

func gtfoArgEvalSystemctl(args []string, fn string) (bool, string) {
	switch fn {
	case "shell", "command", "file-read", "file-write":
	default:
		return false, ""
	}
	if len(args) != 2 {
		return false, ""
	}
	subcmd := args[0]
	unit := args[1]
	if !gtfoArgSystemctlSafeSubcommands[subcmd] || !gtfoArgIsValidUnitName(unit) {
		return false, ""
	}
	return true, fmt.Sprintf("systemctl is pinned to non-interactive lifecycle subcommand %q on fixed unit %q without flags, preventing pager escape, unit linking, and unit editing", subcmd, unit)
}

func gtfoArgEvalService(args []string, fn string) (bool, string) {
	if fn != "shell" && fn != "command" {
		return false, ""
	}
	if len(args) != 2 {
		return false, ""
	}
	unit := args[0]
	action := args[1]
	if !gtfoArgServiceSafeActions[action] || !gtfoArgIsValidUnitName(unit) {
		return false, ""
	}
	return true, fmt.Sprintf("service is pinned to action %q on fixed service %q without path separators or flags, preventing relative path traversal execution", action, unit)
}

func gtfoArgEvalFileReader(bin string, args []string, fn string) (bool, string) {
	if fn != "file-read" {
		return false, ""
	}
	for _, arg := range args {
		if strings.HasPrefix(arg, "-") {
			return false, ""
		}
		if !strings.HasPrefix(arg, "/") || strings.HasSuffix(arg, "/") {
			return false, ""
		}
		if isSensitiveSudoeditTarget(arg) {
			return false, ""
		}
	}
	return true, fmt.Sprintf("%s is pinned to explicit non-sensitive absolute file path(s) (%s) without flags, wildcards, or traversal, preventing arbitrary file disclosure", bin, strings.Join(args, " "))
}

func gtfoArgIsDangerousGitArg(arg string) bool {
	if gtfoArgGitDangerousExact[arg] {
		return true
	}
	for _, prefix := range gtfoArgGitDangerousPrefixes {
		if strings.HasPrefix(arg, prefix) {
			return true
		}
	}
	return false
}

func gtfoArgIsSafeGitRef(arg string) bool {
	if arg == "" || strings.HasPrefix(arg, "-") || strings.HasPrefix(arg, "/") || strings.HasPrefix(arg, ".") {
		return false
	}
	for i := 0; i < len(arg); i++ {
		ch := arg[i]
		valid := (ch >= 'a' && ch <= 'z') ||
			(ch >= 'A' && ch <= 'Z') ||
			(ch >= '0' && ch <= '9') ||
			ch == '.' || ch == '_' || ch == '/' || ch == '@' || ch == '-'
		if !valid {
			return false
		}
	}
	return true
}

func gtfoArgIsGitAbbrevFlag(arg string) bool {
	if !strings.HasPrefix(arg, "--abbrev=") {
		return false
	}
	digits := strings.TrimPrefix(arg, "--abbrev=")
	if digits == "" {
		return false
	}
	for i := 0; i < len(digits); i++ {
		if digits[i] < '0' || digits[i] > '9' {
			return false
		}
	}
	return true
}

func gtfoArgEvalGit(args []string, fn string) (bool, string) {
	switch fn {
	case "shell", "command", "file-read", "file-write":
	default:
		return false, ""
	}
	for _, arg := range args {
		if gtfoArgIsDangerousGitArg(arg) {
			return false, ""
		}
	}

	idx := 0
	if args[0] == "--no-pager" {
		idx = 1
	}
	if idx >= len(args) {
		return false, ""
	}

	subcmd := args[idx]
	rest := args[idx+1:]

	switch subcmd {
	case "status":
		for _, arg := range rest {
			if !gtfoArgGitStatusSafeFlags[arg] {
				return false, ""
			}
		}
	case "rev-parse":
		for _, arg := range rest {
			if !gtfoArgGitRevParseSafeFlags[arg] && !gtfoArgIsSafeGitRef(arg) {
				return false, ""
			}
		}
	case "describe":
		for _, arg := range rest {
			if !gtfoArgGitDescribeSafeFlags[arg] && !gtfoArgIsGitAbbrevFlag(arg) && !gtfoArgIsSafeGitRef(arg) {
				return false, ""
			}
		}
	case "branch":
		if len(rest) != 1 || rest[0] != "--show-current" {
			return false, ""
		}
	default:
		return false, ""
	}

	return true, fmt.Sprintf("git is pinned to read-only non-paged subcommand %q without config, exec-path, or pager injection flags", strings.Join(args, " "))
}

func gtfoArgEvalApt(bin string, args []string, fn string) (bool, string) {
	if fn != "shell" && fn != "command" {
		return false, ""
	}
	if len(args) != 1 || args[0] != "update" {
		return false, ""
	}
	return true, fmt.Sprintf("%s is strictly pinned to 'update' with zero extra flags or packages, blocking -o Pre-Invoke hooks, -c config overrides, and changelog paging", bin)
}
