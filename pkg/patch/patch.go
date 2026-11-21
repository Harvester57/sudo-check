package patch

import (
	"bytes"
	"fmt"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sudo-check/pkg/audit"
	"sudo-check/pkg/parser"
)

// PatchOptions configures hardening patch generation behavior.
type PatchOptions struct {
	IncludeDisruptive bool // When true, also inserts Defaults noexec and Defaults requiretty
}

const defaultSafeSecurePath = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

type globalDefaultsState struct {
	boolSet     map[string]bool
	boolVal     map[string]bool
	strSet      map[string]bool
	strVal      map[string]string
	numSet      map[string]bool
	numVal      map[string]float64
	disabledOpt map[string]bool
}

func newGlobalDefaultsState(policy *audit.SudoersPolicy) *globalDefaultsState {
	s := &globalDefaultsState{
		boolSet:     make(map[string]bool),
		boolVal:     make(map[string]bool),
		strSet:      make(map[string]bool),
		strVal:      make(map[string]string),
		numSet:      make(map[string]bool),
		numVal:      make(map[string]float64),
		disabledOpt: make(map[string]bool),
	}
	if policy == nil {
		return s
	}
	for _, def := range policy.Defaults {
		if len(def.Binding) != 0 {
			continue
		}
		s.applyOptions(def.Options)
	}
	return s
}

func (s *globalDefaultsState) applyOptions(options []audit.Option) {
	for _, opt := range options {
		if _, isListOp := opt["operation"].(string); isListOp {
			for k := range opt {
				if k == "operation" {
					continue
				}
				delete(s.disabledOpt, k)
				delete(s.boolSet, k)
				delete(s.boolVal, k)
			}
			continue
		}
		for k, v := range opt {
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

func (s *globalDefaultsState) isTrue(key string) bool {
	return s.boolSet[key] && s.boolVal[key]
}

func (s *globalDefaultsState) isFalse(key string) bool {
	return s.boolSet[key] && !s.boolVal[key]
}

func (s *globalDefaultsState) hasSafeSecurePath() bool {
	if s.disabledOpt["secure_path"] || !s.strSet["secure_path"] {
		return false
	}
	sp := s.strVal["secure_path"]
	if sp == "" {
		return false
	}
	for _, part := range strings.Split(sp, ":") {
		if isUnsafePathEntry(part) {
			return false
		}
	}
	return true
}

func (s *globalDefaultsState) hasStrictUmask() bool {
	if s.disabledOpt["umask"] {
		return false
	}
	var raw string
	switch {
	case s.strSet["umask"]:
		raw = s.strVal["umask"]
	case s.numSet["umask"]:
		raw = fmt.Sprintf("%04o", int(s.numVal["umask"]))
	default:
		return false
	}
	val, err := strconv.ParseInt(strings.TrimSpace(raw), 8, 64)
	if err != nil {
		return false
	}
	return (val & 0o77) == 0o77
}

func (s *globalDefaultsState) hasNonEmptyString(key string) bool {
	if s.disabledOpt[key] || !s.strSet[key] {
		return false
	}
	return strings.TrimSpace(s.strVal[key]) != ""
}

func isUnsafePathEntry(part string) bool {
	if part == "" || part == "." || !strings.HasPrefix(part, "/") {
		return true
	}
	for _, seg := range strings.Split(part, "/") {
		if seg == ".." {
			return true
		}
	}
	cleaned := path.Clean(part)
	for _, seg := range strings.Split(cleaned, "/") {
		if seg == ".." {
			return true
		}
	}
	for _, dir := range []string{"/tmp", "/var/tmp", "/dev/shm", "/home", "/run/user", "/var/mail", "/var/spool/samba"} {
		if cleaned == dir || strings.HasPrefix(cleaned, dir+"/") {
			return true
		}
	}
	return false
}

type hardeningRule struct {
	ruleIDs     []string
	directive   string
	disruptive  bool
	isSatisfied func(*globalDefaultsState) bool
}

var orderedHardeningRules = []hardeningRule{
	{
		ruleIDs:     []string{"SUDO-DEF-001", "SUDO-DEF-002"},
		directive:   fmt.Sprintf("Defaults secure_path=%q", defaultSafeSecurePath),
		isSatisfied: func(s *globalDefaultsState) bool { return s.hasSafeSecurePath() },
	},
	{
		ruleIDs:     []string{"SUDO-DEF-003"},
		directive:   "Defaults use_pty",
		isSatisfied: func(s *globalDefaultsState) bool { return s.isTrue("use_pty") },
	},
	{
		ruleIDs:     []string{"SUDO-DEF-005"},
		directive:   "Defaults !visiblepw",
		isSatisfied: func(s *globalDefaultsState) bool { return s.isFalse("visiblepw") },
	},
	{
		ruleIDs:     []string{"SUDO-DEF-006"},
		directive:   "Defaults !pwfeedback",
		isSatisfied: func(s *globalDefaultsState) bool { return s.isFalse("pwfeedback") },
	},
	{
		ruleIDs:     []string{"SUDO-DEF-009"},
		directive:   "Defaults umask=0077",
		isSatisfied: func(s *globalDefaultsState) bool { return s.hasStrictUmask() },
	},
	{
		ruleIDs:     []string{"SUDO-DEF-010"},
		directive:   "Defaults ignore_dot",
		isSatisfied: func(s *globalDefaultsState) bool { return s.isTrue("ignore_dot") },
	},
	{
		ruleIDs:     []string{"SUDO-DEF-011"},
		directive:   "Defaults env_reset",
		isSatisfied: func(s *globalDefaultsState) bool { return s.isTrue("env_reset") },
	},
	{
		ruleIDs:     []string{"SUDO-DEF-017"},
		directive:   `Defaults logfile="/var/log/sudo.log"`,
		isSatisfied: func(s *globalDefaultsState) bool { return s.hasNonEmptyString("logfile") },
	},
	{
		ruleIDs:   []string{"SUDO-DEF-018"},
		directive: "Defaults !rootpw, !targetpw, !runaspw",
		isSatisfied: func(s *globalDefaultsState) bool {
			return s.isFalse("rootpw") && s.isFalse("targetpw") && s.isFalse("runaspw")
		},
	},
	{
		ruleIDs:     []string{"SUDO-DEF-007"},
		directive:   "Defaults noexec",
		disruptive:  true,
		isSatisfied: func(s *globalDefaultsState) bool { return s.isTrue("noexec") },
	},
	{
		ruleIDs:     []string{"SUDO-DEF-008"},
		directive:   "Defaults requiretty",
		disruptive:  true,
		isSatisfied: func(s *globalDefaultsState) bool { return s.isTrue("requiretty") },
	},
}

// GenerateHardeningPatch generates a unified diff and patched sudoers content that adds
// safe, non-disruptive global Defaults directives to remediate Defaults findings.
func GenerateHardeningPatch(filePath string, original []byte, findings []audit.Finding) (patchText string, patchedContent []byte, err error) {
	return GenerateHardeningPatchWithOptions(filePath, original, findings, PatchOptions{})
}

// GenerateHardeningPatchWithOptions generates a unified diff and patched sudoers content
// for raw sudoers input, optionally including disruptive hardening directives.
func GenerateHardeningPatchWithOptions(filePath string, original []byte, findings []audit.Finding, opts PatchOptions) (patchText string, patchedContent []byte, err error) {
	displayPath := cleanPatchPath(filePath)

	if parser.IsJSONPolicy(original) {
		return "", nil, fmt.Errorf("cannot generate hardening patch for JSON policy %s: raw sudoers syntax is required", displayPath)
	}

	policy, err := parser.ParseString(string(original))
	if err != nil {
		return "", nil, fmt.Errorf("invalid sudoers input for %s: %w", displayPath, err)
	}

	directives := selectHardeningDirectives(policy, findings, opts)
	if len(directives) == 0 {
		return "", original, nil
	}

	patchedContent = applyDirectiveInsertion(original, directives)

	if _, err := parser.ParseString(string(patchedContent)); err != nil {
		return "", nil, fmt.Errorf("patched sudoers validation failed for %s: %w", displayPath, err)
	}

	oldLines, oldTrailingNL := splitNormalizedLines(original)
	newLines, newTrailingNL := splitNormalizedLines(patchedContent)
	patchText = buildUnifiedDiff(displayPath, oldLines, oldTrailingNL, newLines, newTrailingNL)

	return patchText, patchedContent, nil
}

func selectHardeningDirectives(policy *audit.SudoersPolicy, findings []audit.Finding, opts PatchOptions) []string {
	triggered := make(map[string]bool)
	for _, f := range findings {
		if f.Suppressed {
			continue
		}
		if strings.TrimSpace(f.User) != "" {
			// Scoped Defaults or user-specific command findings cannot be safely remediated
			// by inserting global Defaults directives.
			continue
		}
		id := strings.TrimSpace(f.ID)
		if id != "" {
			triggered[id] = true
		}
	}

	state := newGlobalDefaultsState(policy)
	var directives []string
	for _, rule := range orderedHardeningRules {
		if rule.disruptive && !opts.IncludeDisruptive {
			continue
		}
		matched := false
		for _, id := range rule.ruleIDs {
			if triggered[id] {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}
		if rule.isSatisfied != nil && rule.isSatisfied(state) {
			continue
		}
		directives = append(directives, rule.directive)
	}
	return directives
}

func cleanPatchPath(filePath string) string {
	trimmed := strings.TrimSpace(filePath)
	if trimmed == "" {
		return "sudoers"
	}
	if vol := filepath.VolumeName(trimmed); vol != "" {
		trimmed = strings.TrimPrefix(trimmed, vol)
	}
	slashed := strings.ReplaceAll(trimmed, "\\", "/")
	cleaned := path.Clean(slashed)
	cleaned = strings.TrimLeft(cleaned, "/")
	if cleaned == "" || cleaned == "." {
		return "sudoers"
	}
	return cleaned
}

func splitNormalizedLines(data []byte) ([]string, bool) {
	if len(data) == 0 {
		return nil, false
	}
	hasTrailingNL := bytes.HasSuffix(data, []byte("\n"))
	s := string(data)
	if hasTrailingNL {
		s = strings.TrimSuffix(s, "\n")
		s = strings.TrimSuffix(s, "\r")
	}
	raw := strings.Split(s, "\n")
	lines := make([]string, len(raw))
	for i, line := range raw {
		lines[i] = strings.TrimSuffix(line, "\r")
	}
	return lines, hasTrailingNL
}

func applyDirectiveInsertion(original []byte, directives []string) []byte {
	lineSep := "\n"
	if bytes.Contains(original, []byte("\r\n")) {
		lineSep = "\r\n"
	}

	if len(original) == 0 {
		return []byte(strings.Join(directives, lineSep) + lineSep)
	}

	lines, hasTrailingNL := splitNormalizedLines(original)
	insertIdx := findInsertionIndex(lines)

	resultLines := make([]string, 0, len(lines)+len(directives))
	resultLines = append(resultLines, lines[:insertIdx]...)
	resultLines = append(resultLines, directives...)
	resultLines = append(resultLines, lines[insertIdx:]...)

	outTrailingNL := hasTrailingNL
	if insertIdx == len(lines) && len(directives) > 0 {
		outTrailingNL = true
	}

	var buf bytes.Buffer
	for i, line := range resultLines {
		if i > 0 {
			buf.WriteString(lineSep)
		}
		buf.WriteString(line)
	}
	if outTrailingNL {
		buf.WriteString(lineSep)
	}
	return buf.Bytes()
}

type logicalSpan struct {
	startIdx int
	endIdx   int
	text     string
}

func findInsertionIndex(lines []string) int {
	spans := collectLogicalSpans(lines)
	lastGlobalDefaultsEnd := -1
	firstNonDefaultsStart := -1

	for _, sp := range spans {
		trimmed := strings.TrimSpace(sp.text)
		if trimmed == "" {
			continue
		}
		if isGlobalDefaultsLine(trimmed) {
			lastGlobalDefaultsEnd = sp.endIdx
			continue
		}
		if isScopedDefaultsLine(trimmed) {
			continue
		}
		if firstNonDefaultsStart == -1 && isSectionBoundaryLine(trimmed) {
			firstNonDefaultsStart = sp.startIdx
		}
	}

	if lastGlobalDefaultsEnd != -1 {
		return lastGlobalDefaultsEnd + 1
	}
	if firstNonDefaultsStart != -1 {
		return firstNonDefaultsStart
	}
	return len(lines)
}

func collectLogicalSpans(lines []string) []logicalSpan {
	var spans []logicalSpan
	var buf strings.Builder
	startIdx := 0
	continuing := false

	for i, raw := range lines {
		line := raw
		if i == 0 {
			line = strings.TrimPrefix(line, "\xef\xbb\xbf")
		}
		trimmed := strings.TrimLeft(line, " \t")
		if strings.HasPrefix(trimmed, "#") && !isIncludeDirectivePrefix(trimmed) && !isNumericUIDAssignment(trimmed, continuing) {
			continue
		}
		cleaned, hasCont := stripInlineCommentAndCont(line, continuing)
		if !continuing {
			if strings.TrimSpace(cleaned) == "" && !hasCont {
				continue
			}
			startIdx = i
		}
		buf.WriteString(cleaned)
		if hasCont {
			continuing = true
		} else {
			continuing = false
			text := strings.TrimSpace(buf.String())
			buf.Reset()
			if text != "" {
				spans = append(spans, logicalSpan{
					startIdx: startIdx,
					endIdx:   i,
					text:     text,
				})
			}
		}
	}
	return spans
}

func isIncludeDirectivePrefix(trimmed string) bool {
	for _, kw := range []string{"#includedir", "#include", "@includedir", "@include"} {
		if strings.HasPrefix(trimmed, kw) {
			rest := trimmed[len(kw):]
			if len(rest) > 0 && (rest[0] == ' ' || rest[0] == '\t') {
				return true
			}
		}
	}
	return false
}

func isNumericUIDAssignment(trimmed string, continuing bool) bool {
	if !isNumericIDAt(trimmed, 0) {
		return false
	}
	if continuing {
		return true
	}
	return strings.Contains(trimmed, "=")
}

func isNumericIDAt(s string, pos int) bool {
	if pos >= len(s) || s[pos] != '#' {
		return false
	}
	j := pos + 1
	if j < len(s) && s[j] == '-' {
		j++
	}
	digitStart := j
	for j < len(s) && s[j] >= '0' && s[j] <= '9' {
		j++
	}
	if j == digitStart {
		return false
	}
	if j == len(s) {
		return true
	}
	switch s[j] {
	case ' ', '\t', ',', ':', '=', ')', '!':
		return true
	default:
		return false
	}
}

func stripInlineCommentAndCont(line string, continuing bool) (string, bool) {
	inQuotes := false
	trimmedLeft := strings.TrimLeft(line, " \t")
	leadingOffset := len(line) - len(trimmedLeft)
	isInc := isIncludeDirectivePrefix(trimmedLeft)

	commentIdx := -1
	for i := 0; i < len(line); i++ {
		ch := line[i]
		if ch == '\\' {
			i++
			continue
		}
		if ch == '"' {
			inQuotes = !inQuotes
			continue
		}
		if !inQuotes && ch == '#' {
			if isInc && i == leadingOffset {
				continue
			}
			if isNumericIDAt(line, i) {
				if i == leadingOffset && !continuing && !strings.Contains(line, "=") {
					commentIdx = i
					break
				}
				continue
			}
			commentIdx = i
			break
		}
	}

	effective := line
	if commentIdx != -1 {
		effective = line[:commentIdx]
	}
	trimmedRight := strings.TrimRight(effective, " \t")
	if hasUnescapedTrailingBackslash(trimmedRight) {
		return trimmedRight[:len(trimmedRight)-1], true
	}
	return effective, false
}

func hasUnescapedTrailingBackslash(s string) bool {
	if len(s) == 0 || s[len(s)-1] != '\\' {
		return false
	}
	count := 0
	for i := len(s) - 1; i >= 0 && s[i] == '\\'; i-- {
		count++
	}
	return count%2 == 1
}

func isGlobalDefaultsLine(trimmed string) bool {
	if !strings.HasPrefix(trimmed, "Defaults") {
		return false
	}
	if len(trimmed) == len("Defaults") {
		return false
	}
	next := trimmed[len("Defaults")]
	return next == ' ' || next == '\t'
}

func isScopedDefaultsLine(trimmed string) bool {
	if !strings.HasPrefix(trimmed, "Defaults") || len(trimmed) <= len("Defaults") {
		return false
	}
	next := trimmed[len("Defaults")]
	return next == '@' || next == ':' || next == '!' || next == '>'
}

func isSectionBoundaryLine(trimmed string) bool {
	if isIncludeDirectivePrefix(trimmed) {
		return true
	}
	for _, kw := range []string{"User_Alias", "Host_Alias", "Runas_Alias", "Cmnd_Alias"} {
		if strings.HasPrefix(trimmed, kw) {
			rest := trimmed[len(kw):]
			if len(rest) == 0 || rest[0] == ' ' || rest[0] == '\t' {
				return true
			}
		}
	}
	// Any remaining non-empty logical statement after includes/Defaults/aliases is a User_Spec.
	return true
}

type diffLine struct {
	text  string
	hasNL bool
}

type diffOp struct {
	kind   byte
	oldIdx int
	newIdx int
	line   diffLine
}

func makeDiffLines(lines []string, trailingNL bool) []diffLine {
	if len(lines) == 0 {
		return nil
	}
	out := make([]diffLine, len(lines))
	for i, l := range lines {
		nl := true
		if i == len(lines)-1 {
			nl = trailingNL
		}
		out[i] = diffLine{text: l, hasNL: nl}
	}
	return out
}

func buildUnifiedDiff(cleanPath string, oldLines []string, oldTrailingNL bool, newLines []string, newTrailingNL bool) string {
	a := makeDiffLines(oldLines, oldTrailingNL)
	b := makeDiffLines(newLines, newTrailingNL)

	ops := diffLineSlices(a, b)
	hasChanges := false
	for _, op := range ops {
		if op.kind != ' ' {
			hasChanges = true
			break
		}
	}
	if !hasChanges {
		return ""
	}

	const ctxLines = 3
	type hunkRange struct {
		start int
		end   int
	}
	var hunks []hunkRange
	for i, op := range ops {
		if op.kind == ' ' {
			continue
		}
		hStart := max(0, i-ctxLines)
		hEnd := min(len(ops)-1, i+ctxLines)
		if len(hunks) > 0 && hStart <= hunks[len(hunks)-1].end+1 {
			hunks[len(hunks)-1].end = hEnd
		} else {
			hunks = append(hunks, hunkRange{start: hStart, end: hEnd})
		}
	}

	var out strings.Builder
	fmt.Fprintf(&out, "--- a/%s\n+++ b/%s\n", cleanPath, cleanPath)

	for _, h := range hunks {
		oldCount := 0
		newCount := 0
		oldStart := -1
		newStart := -1

		for idx := h.start; idx <= h.end; idx++ {
			op := ops[idx]
			if op.kind == ' ' || op.kind == '-' {
				if oldStart == -1 {
					oldStart = op.oldIdx + 1
				}
				oldCount++
			}
			if op.kind == ' ' || op.kind == '+' {
				if newStart == -1 {
					newStart = op.newIdx + 1
				}
				newCount++
			}
		}

		if oldCount == 0 {
			oldStart = computeZeroRangeStart(ops, h.start, true)
		}
		if newCount == 0 {
			newStart = computeZeroRangeStart(ops, h.start, false)
		}

		fmt.Fprintf(&out, "@@ -%s +%s @@\n", formatHunkRange(oldStart, oldCount), formatHunkRange(newStart, newCount))
		for idx := h.start; idx <= h.end; idx++ {
			op := ops[idx]
			out.WriteByte(op.kind)
			out.WriteString(op.line.text)
			out.WriteByte('\n')
			if !op.line.hasNL {
				out.WriteString("\\ No newline at end of file\n")
			}
		}
	}

	return out.String()
}

func computeZeroRangeStart(ops []diffOp, hunkStart int, isOld bool) int {
	for i := hunkStart - 1; i >= 0; i-- {
		op := ops[i]
		if isOld && (op.kind == ' ' || op.kind == '-') {
			return op.oldIdx + 1
		}
		if !isOld && (op.kind == ' ' || op.kind == '+') {
			return op.newIdx + 1
		}
	}
	return 0
}

func formatHunkRange(start, count int) string {
	if count == 1 {
		return strconv.Itoa(start)
	}
	return fmt.Sprintf("%d,%d", start, count)
}

func diffLineSlices(a, b []diffLine) []diffOp {
	prefix := 0
	for prefix < len(a) && prefix < len(b) && a[prefix] == b[prefix] {
		prefix++
	}
	suffix := 0
	for suffix < len(a)-prefix && suffix < len(b)-prefix && a[len(a)-1-suffix] == b[len(b)-1-suffix] {
		suffix++
	}

	var ops []diffOp
	for i := range prefix {
		ops = append(ops, diffOp{kind: ' ', oldIdx: i, newIdx: i, line: a[i]})
	}

	midA := a[prefix : len(a)-suffix]
	midB := b[prefix : len(b)-suffix]
	midOps := myersDiff(midA, midB, prefix, prefix)
	ops = append(ops, midOps...)

	aSufStart := len(a) - suffix
	bSufStart := len(b) - suffix
	for i := range suffix {
		ops = append(ops, diffOp{
			kind:   ' ',
			oldIdx: aSufStart + i,
			newIdx: bSufStart + i,
			line:   a[aSufStart+i],
		})
	}
	return ops
}

func myersDiff(a, b []diffLine, aBase, bBase int) []diffOp {
	n := len(a)
	m := len(b)
	if n == 0 && m == 0 {
		return nil
	}
	if n == 0 {
		ops := make([]diffOp, m)
		for j := range m {
			ops[j] = diffOp{kind: '+', newIdx: bBase + j, line: b[j]}
		}
		return ops
	}
	if m == 0 {
		ops := make([]diffOp, n)
		for i := range n {
			ops[i] = diffOp{kind: '-', oldIdx: aBase + i, line: a[i]}
		}
		return ops
	}

	maxD := n + m
	offset := maxD
	v := make([]int, 2*maxD+1)
	trace := make([][]int, 0, maxD+1)

	for d := 0; d <= maxD; d++ {
		done := false
		for k := -d; k <= d; k += 2 {
			var x int
			if k == -d || (k != d && v[offset+k-1] < v[offset+k+1]) {
				x = v[offset+k+1]
			} else {
				x = v[offset+k-1] + 1
			}
			y := x - k
			for x < n && y < m && a[x] == b[y] {
				x++
				y++
			}
			v[offset+k] = x
			if x == n && y == m {
				done = true
			}
		}
		snap := make([]int, len(v))
		copy(snap, v)
		trace = append(trace, snap)
		if done {
			break
		}
	}

	var revOps []diffOp
	x, y := n, m
	for d := len(trace) - 1; d > 0; d-- {
		prevV := trace[d-1]
		k := x - y
		var prevK int
		if k == -d || (k != d && prevV[offset+k-1] < prevV[offset+k+1]) {
			prevK = k + 1
		} else {
			prevK = k - 1
		}
		prevX := prevV[offset+prevK]
		prevY := prevX - prevK

		for x > prevX && y > prevY {
			x--
			y--
			revOps = append(revOps, diffOp{kind: ' ', oldIdx: aBase + x, newIdx: bBase + y, line: a[x]})
		}
		if x > prevX {
			x--
			revOps = append(revOps, diffOp{kind: '-', oldIdx: aBase + x, line: a[x]})
		} else if y > prevY {
			y--
			revOps = append(revOps, diffOp{kind: '+', newIdx: bBase + y, line: b[y]})
		}
	}

	for x > 0 && y > 0 {
		x--
		y--
		revOps = append(revOps, diffOp{kind: ' ', oldIdx: aBase + x, newIdx: bBase + y, line: a[x]})
	}

	for l, r := 0, len(revOps)-1; l < r; l, r = l+1, r-1 {
		revOps[l], revOps[r] = revOps[r], revOps[l]
	}
	return revOps
}
