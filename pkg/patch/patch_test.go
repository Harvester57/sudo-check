package patch

import (
	"bytes"
	"fmt"
	"strings"
	"sudo-check/pkg/audit"
	"sudo-check/pkg/parser"
	"testing"
)

func TestGenerateHardeningPatch_ValidationAndNoOp(t *testing.T) {
	t.Run("InvalidSudoersReturnsError", func(t *testing.T) {
		bad := []byte("Defaults\nroot ALL=(ALL) ALL\n")
		_, _, err := GenerateHardeningPatch("/etc/sudoers", bad, []audit.Finding{{ID: "SUDO-DEF-003"}})
		if err == nil {
			t.Fatal("expected syntax error for invalid sudoers input")
		}
	})

	t.Run("RejectsJSONPolicy", func(t *testing.T) {
		jsonPolicy := []byte(`{"Defaults": [{"Options": [{"env_reset": true}]}]}`)
		_, _, err := GenerateHardeningPatch("/etc/sudoers.json", jsonPolicy, []audit.Finding{{ID: "SUDO-DEF-003"}})
		if err == nil {
			t.Fatal("expected error rejecting JSON policy input")
		}
		if !strings.Contains(err.Error(), "JSON") {
			t.Fatalf("expected JSON rejection error message, got: %v", err)
		}
	})

	t.Run("RejectsEmptyJSONObjectPolicy", func(t *testing.T) {
		_, _, err := GenerateHardeningPatch("policy.json", []byte(`{}`), []audit.Finding{{ID: "SUDO-DEF-003"}})
		if err == nil {
			t.Fatal("expected error rejecting empty JSON policy object")
		}
	})

	t.Run("NoFindingsReturnsUnchanged", func(t *testing.T) {
		orig := []byte("Defaults env_reset\nroot ALL=(ALL:ALL) ALL\n")
		patchText, patched, err := GenerateHardeningPatch("/etc/sudoers", orig, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if patchText != "" {
			t.Fatalf("expected empty patchText, got:\n%s", patchText)
		}
		if !bytes.Equal(patched, orig) {
			t.Fatalf("expected unchanged content, got:\n%s", string(patched))
		}
	})

	t.Run("NonDefaultsFindingsReturnsUnchanged", func(t *testing.T) {
		orig := []byte("root ALL=(ALL:ALL) ALL\n")
		findings := []audit.Finding{
			{ID: "SUDO-CMD-001", Severity: audit.SeverityCritical},
			{ID: "SUDO-GTFO-001", Severity: audit.SeverityHigh},
			{ID: "SUDO-DEF-003", User: "alice", Severity: audit.SeverityMedium}, // scoped finding
			{ID: "SUDO-DEF-011", Suppressed: true},
		}
		patchText, patched, err := GenerateHardeningPatch("/etc/sudoers", orig, findings)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if patchText != "" || !bytes.Equal(patched, orig) {
			t.Fatalf("expected no-op patch for non-global/suppressed findings, got:\n%s", patchText)
		}
	})
}

func TestGenerateHardeningPatch_AllRuleMappingsAndOptions(t *testing.T) {
	orig := []byte("# minimal sudoers\nroot ALL=(ALL:ALL) ALL\n")
	findings := []audit.Finding{
		{ID: "SUDO-DEF-018"},
		{ID: "SUDO-DEF-001"},
		{ID: "SUDO-DEF-002"},
		{ID: "SUDO-DEF-003"},
		{ID: "SUDO-DEF-005"},
		{ID: "SUDO-DEF-006"},
		{ID: "SUDO-DEF-007"},
		{ID: "SUDO-DEF-008"},
		{ID: "SUDO-DEF-009"},
		{ID: "SUDO-DEF-010"},
		{ID: "SUDO-DEF-011"},
		{ID: "SUDO-DEF-017"},
	}

	// Default options (IncludeDisruptive=false) must omit noexec and requiretty.
	patchText, patched, err := GenerateHardeningPatch("/etc/sudoers", orig, findings)
	if err != nil {
		t.Fatalf("GenerateHardeningPatch failed: %v", err)
	}

	patchedStr := string(patched)
	expectedSafe := []string{
		`Defaults secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"`,
		"Defaults use_pty",
		"Defaults !visiblepw",
		"Defaults !pwfeedback",
		"Defaults umask=0077",
		"Defaults ignore_dot",
		"Defaults env_reset",
		`Defaults logfile="/var/log/sudo.log"`,
		"Defaults !rootpw, !targetpw, !runaspw",
	}
	for _, want := range expectedSafe {
		if strings.Count(patchedStr, want) != 1 {
			t.Errorf("expected directive %q once in patched content, got:\n%s", want, patchedStr)
		}
	}
	for _, excluded := range []string{"Defaults noexec", "Defaults requiretty"} {
		if strings.Contains(patchedStr, excluded) {
			t.Errorf("did not expect disruptive directive %q when IncludeDisruptive=false", excluded)
		}
	}
	if !strings.Contains(patchedStr, "root ALL=(ALL:ALL) ALL") {
		t.Error("expected User_Spec line to remain intact")
	}

	// Verify patch applies cleanly to reconstruct patched content.
	reconstructed, err := applyUnifiedDiff(orig, patchText)
	if err != nil {
		t.Fatalf("failed to apply generated unified diff: %v\npatch:\n%s", err, patchText)
	}
	if !bytes.Equal(reconstructed, patched) {
		t.Fatalf("applied diff mismatch:\ngot:\n%s\nwant:\n%s", string(reconstructed), patchedStr)
	}

	// Verify IncludeDisruptive=true includes noexec and requiretty.
	patchDisruptive, patchedDisruptive, err := GenerateHardeningPatchWithOptions(
		"/etc/sudoers",
		orig,
		findings,
		PatchOptions{IncludeDisruptive: true},
	)
	if err != nil {
		t.Fatalf("GenerateHardeningPatchWithOptions failed: %v", err)
	}
	disruptiveStr := string(patchedDisruptive)
	for _, want := range append(expectedSafe, "Defaults noexec", "Defaults requiretty") {
		if strings.Count(disruptiveStr, want) != 1 {
			t.Errorf("expected directive %q once when IncludeDisruptive=true, got:\n%s", want, disruptiveStr)
		}
	}
	reconstructedDisruptive, err := applyUnifiedDiff(orig, patchDisruptive)
	if err != nil {
		t.Fatalf("failed to apply disruptive unified diff: %v", err)
	}
	if !bytes.Equal(reconstructedDisruptive, patchedDisruptive) {
		t.Fatalf("applied disruptive diff mismatch")
	}
}

func TestGenerateHardeningPatch_RealAuditRoundTripAndIdempotency(t *testing.T) {
	orig := []byte(`# /etc/sudoers
Defaults	mail_badpass
Defaults	secure_path="/tmp:/usr/sbin:/usr/bin"
Defaults	visiblepw
Defaults	pwfeedback
Defaults	umask=0022
Defaults	rootpw

# User privilege specification
root	ALL=(ALL:ALL) ALL
alice	ALL=(ALL) /usr/bin/id

#includedir /etc/sudoers.d
`)

	policy, err := parser.ParseString(string(orig))
	if err != nil {
		t.Fatalf("ParseString failed: %v", err)
	}
	findings := audit.RunAudit(policy, nil)

	patchText, patched, err := GenerateHardeningPatchWithOptions(
		"/etc/sudoers",
		orig,
		findings,
		PatchOptions{IncludeDisruptive: true},
	)
	if err != nil {
		t.Fatalf("GenerateHardeningPatchWithOptions failed: %v", err)
	}
	if !strings.HasPrefix(patchText, "--- a/etc/sudoers\n+++ b/etc/sudoers\n@@ ") {
		t.Fatalf("unexpected diff header:\n%s", patchText)
	}

	// Ensure existing User_Spec lines were never modified.
	patchedStr := string(patched)
	if !strings.Contains(patchedStr, "root\tALL=(ALL:ALL) ALL\n") || !strings.Contains(patchedStr, "alice\tALL=(ALL) /usr/bin/id\n") {
		t.Fatalf("existing User_Spec lines were modified:\n%s", patchedStr)
	}

	// Patched content must insert after the last global Defaults line (Defaults rootpw) and before User_Spec.
	rootpwIdx := strings.Index(patchedStr, "Defaults\trootpw")
	userSpecIdx := strings.Index(patchedStr, "root\tALL=(ALL:ALL) ALL")
	usePtyIdx := strings.Index(patchedStr, "Defaults use_pty")
	if !(rootpwIdx < usePtyIdx && usePtyIdx < userSpecIdx) {
		t.Fatalf("expected directives between last global Defaults and User_Spec, got:\n%s", patchedStr)
	}

	// Re-audit patched policy and ensure all target SUDO-DEF findings are eliminated.
	patchedPolicy, err := parser.ParseString(patchedStr)
	if err != nil {
		t.Fatalf("patched ParseString failed: %v", err)
	}
	remaining := audit.RunAudit(patchedPolicy, nil)
	for _, f := range remaining {
		if strings.HasPrefix(f.ID, "SUDO-DEF-") {
			t.Errorf("unexpected remaining SUDO-DEF finding after disruptive hardening patch: %s (%s)", f.ID, f.Title)
		}
	}

	// Idempotency: re-running with remaining findings OR original findings must produce no changes.
	p2, b2, err := GenerateHardeningPatchWithOptions("/etc/sudoers", patched, remaining, PatchOptions{IncludeDisruptive: true})
	if err != nil || p2 != "" || !bytes.Equal(b2, patched) {
		t.Fatalf("expected idempotent no-op with remaining findings, got err=%v patch=%q", err, p2)
	}
	p3, b3, err := GenerateHardeningPatchWithOptions("/etc/sudoers", patched, findings, PatchOptions{IncludeDisruptive: true})
	if err != nil || p3 != "" || !bytes.Equal(b3, patched) {
		t.Fatalf("expected idempotent no-op with original findings, got err=%v patch=%q", err, p3)
	}

	reconstructed, err := applyUnifiedDiff(orig, patchText)
	if err != nil {
		t.Fatalf("applyUnifiedDiff failed: %v", err)
	}
	if !bytes.Equal(reconstructed, patched) {
		t.Fatalf("reconstructed bytes mismatch")
	}
}

func TestGenerateHardeningPatch_InsertionPlacementEdgeCases(t *testing.T) {
	t.Run("MultilineGlobalDefaultsContinuation", func(t *testing.T) {
		orig := []byte("Defaults env_reset, \\\n    mail_badpass, \\\n    !use_pty\n# end defaults\nroot ALL=(ALL) ALL\n")
		patchText, patched, err := GenerateHardeningPatch("sudoers", orig, []audit.Finding{{ID: "SUDO-DEF-003"}})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := "Defaults env_reset, \\\n    mail_badpass, \\\n    !use_pty\nDefaults use_pty\n# end defaults\nroot ALL=(ALL) ALL\n"
		if string(patched) != want {
			t.Fatalf("got:\n%q\nwant:\n%q", string(patched), want)
		}
		reconstructed, err := applyUnifiedDiff(orig, patchText)
		if err != nil || !bytes.Equal(reconstructed, patched) {
			t.Fatalf("diff round-trip failed: %v", err)
		}
	})

	t.Run("NoDefaultsInsertsBeforeFirstAliasOrInclude", func(t *testing.T) {
		orig := []byte("# header comment\n\nUser_Alias ADMINS = alice\nADMINS ALL=(ALL) ALL\n")
		_, patched, err := GenerateHardeningPatch("sudoers", orig, []audit.Finding{{ID: "SUDO-DEF-011"}})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := "# header comment\n\nDefaults env_reset\nUser_Alias ADMINS = alice\nADMINS ALL=(ALL) ALL\n"
		if string(patched) != want {
			t.Fatalf("got:\n%q\nwant:\n%q", string(patched), want)
		}
	})

	t.Run("OnlyIncludeDirective", func(t *testing.T) {
		orig := []byte("# policy\n@includedir /etc/sudoers.d\n")
		_, patched, err := GenerateHardeningPatch("sudoers", orig, []audit.Finding{{ID: "SUDO-DEF-003"}})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := "# policy\nDefaults use_pty\n@includedir /etc/sudoers.d\n"
		if string(patched) != want {
			t.Fatalf("got:\n%q\nwant:\n%q", string(patched), want)
		}
	})

	t.Run("ScopedDefaultsOnlyWithoutGlobal", func(t *testing.T) {
		orig := []byte("Defaults:alice !requiretty\n#1000 ALL=(ALL) ALL\n")
		_, patched, err := GenerateHardeningPatch("sudoers", orig, []audit.Finding{{ID: "SUDO-DEF-003"}})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := "Defaults:alice !requiretty\nDefaults use_pty\n#1000 ALL=(ALL) ALL\n"
		if string(patched) != want {
			t.Fatalf("got:\n%q\nwant:\n%q", string(patched), want)
		}
	})

	t.Run("OnlyCommentsAppendsAtEnd", func(t *testing.T) {
		orig := []byte("# comment only\n")
		_, patched, err := GenerateHardeningPatch("sudoers", orig, []audit.Finding{{ID: "SUDO-DEF-003"}})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := "# comment only\nDefaults use_pty\n"
		if string(patched) != want {
			t.Fatalf("got:\n%q\nwant:\n%q", string(patched), want)
		}
	})

	t.Run("EmptyFile", func(t *testing.T) {
		patchText, patched, err := GenerateHardeningPatch("", []byte{}, []audit.Finding{{ID: "SUDO-DEF-003"}})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if string(patched) != "Defaults use_pty\n" {
			t.Fatalf("unexpected patched content: %q", string(patched))
		}
		if !strings.Contains(patchText, "--- a/sudoers\n+++ b/sudoers\n@@ -0,0 +1 @@\n+Defaults use_pty\n") {
			t.Fatalf("unexpected diff for empty file:\n%s", patchText)
		}
		reconstructed, err := applyUnifiedDiff([]byte{}, patchText)
		if err != nil || !bytes.Equal(reconstructed, patched) {
			t.Fatalf("diff round-trip failed for empty file: %v", err)
		}
	})
}

func TestGenerateHardeningPatch_LineEndingsAndNoTrailingNewline(t *testing.T) {
	t.Run("PreservesCRLFAndNormalizesDiffToLF", func(t *testing.T) {
		orig := []byte("Defaults env_reset\r\nroot ALL=(ALL) ALL\r\n")
		patchText, patched, err := GenerateHardeningPatch("C:\\etc\\sudoers", orig, []audit.Finding{{ID: "SUDO-DEF-003"}})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := "Defaults env_reset\r\nDefaults use_pty\r\nroot ALL=(ALL) ALL\r\n"
		if string(patched) != want {
			t.Fatalf("CRLF not preserved: got %q, want %q", string(patched), want)
		}
		if strings.Contains(patchText, "\r") {
			t.Fatalf("diff must normalize line endings to LF without CR: %q", patchText)
		}
		if !strings.HasPrefix(patchText, "--- a/etc/sudoers\n+++ b/etc/sudoers\n") {
			t.Fatalf("unexpected cleaned Windows path in diff header:\n%s", patchText)
		}
	})

	t.Run("AppendAfterDefaultsWithoutTrailingNewline", func(t *testing.T) {
		orig := []byte("Defaults env_reset")
		patchText, patched, err := GenerateHardeningPatch("./sudoers", orig, []audit.Finding{{ID: "SUDO-DEF-003"}})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := "Defaults env_reset\nDefaults use_pty\n"
		if string(patched) != want {
			t.Fatalf("got %q, want %q", string(patched), want)
		}
		reconstructed, err := applyUnifiedDiff(orig, patchText)
		if err != nil {
			t.Fatalf("applyUnifiedDiff failed: %v\npatch:\n%s", err, patchText)
		}
		if !bytes.Equal(reconstructed, patched) {
			t.Fatalf("round-trip mismatch: got %q, want %q", string(reconstructed), string(patched))
		}
	})

	t.Run("InsertBeforeUserSpecWithoutTrailingNewline", func(t *testing.T) {
		orig := []byte("root ALL=(ALL) ALL")
		patchText, patched, err := GenerateHardeningPatch("sudoers", orig, []audit.Finding{{ID: "SUDO-DEF-003"}})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := "Defaults use_pty\nroot ALL=(ALL) ALL"
		if string(patched) != want {
			t.Fatalf("got %q, want %q", string(patched), want)
		}
		reconstructed, err := applyUnifiedDiff(orig, patchText)
		if err != nil {
			t.Fatalf("applyUnifiedDiff failed: %v\npatch:\n%s", err, patchText)
		}
		if !bytes.Equal(reconstructed, patched) {
			t.Fatalf("round-trip mismatch: got %q, want %q", string(reconstructed), string(patched))
		}
	})
}

func TestBuildUnifiedDiff_MultiHunkRoundTrip(t *testing.T) {
	oldText := strings.Join([]string{
		"line01", "line02", "line03", "line04", "line05",
		"line06", "line07", "line08", "line09", "line10",
		"line11", "line12", "line13", "line14", "line15",
	}, "\n") + "\n"
	newText := strings.Join([]string{
		"line01", "line02_mod", "line03", "line04", "line05",
		"line06", "line07", "line08", "line09", "line10",
		"line11", "line12", "line13_a", "line13_b", "line14", "line15",
	}, "\n") + "\n"

	oldLines, oldNL := splitNormalizedLines([]byte(oldText))
	newLines, newNL := splitNormalizedLines([]byte(newText))
	diff := buildUnifiedDiff("etc/sudoers", oldLines, oldNL, newLines, newNL)

	if strings.Count(diff, "@@ ") != 2 {
		t.Fatalf("expected 2 separate hunks, got diff:\n%s", diff)
	}
	reconstructed, err := applyUnifiedDiff([]byte(oldText), diff)
	if err != nil {
		t.Fatalf("applyUnifiedDiff failed: %v", err)
	}
	if string(reconstructed) != newText {
		t.Fatalf("round-trip failed:\ngot:\n%s\nwant:\n%s", string(reconstructed), newText)
	}
}

func TestCleanPatchPathAndHelpers(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"", "sudoers"},
		{"/", "sudoers"},
		{".", "sudoers"},
		{"/etc/sudoers", "etc/sudoers"},
		{"./sudoers.d/app", "sudoers.d/app"},
		{"C:\\etc\\sudoers.d\\10_ops", "etc/sudoers.d/10_ops"},
	}
	for _, tc := range cases {
		if got := cleanPatchPath(tc.in); got != tc.want {
			t.Errorf("cleanPatchPath(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestGlobalDefaultsStateHelpers(t *testing.T) {
	pol := &audit.SudoersPolicy{
		Defaults: []audit.DefaultBinding{
			{
				Options: []audit.Option{
					{"operation": "list_assign", "env_keep": []string{"LANG"}},
					{"umask": 0o022},
					{"umask": "0077"},
					{"use_pty": true},
					{"visiblepw": false},
					{"logfile": "/var/log/sudo.log"},
					{"secure_path": "/usr/local/bin:/usr/bin"},
					{"temp_flag": 42.0},
					{"temp_flag": false},
				},
			},
			{
				Binding: []audit.Member{{Username: "alice"}},
				Options: []audit.Option{{"use_pty": false}},
			},
		},
	}
	st := newGlobalDefaultsState(pol)
	if !st.isTrue("use_pty") {
		t.Error("expected global use_pty to remain true despite scoped override")
	}
	if !st.isFalse("visiblepw") {
		t.Error("expected visiblepw to be false")
	}
	if !st.hasStrictUmask() {
		t.Error("expected umask 0077 to be strict")
	}
	if !st.hasSafeSecurePath() {
		t.Error("expected secure_path to be safe")
	}
	if !st.hasNonEmptyString("logfile") {
		t.Error("expected logfile to be non-empty")
	}
	if !isUnsafePathEntry("relative/path") || !isUnsafePathEntry("/usr/../tmp") || !isUnsafePathEntry("/var/tmp/sub") || !isUnsafePathEntry("") {
		t.Error("expected unsafe path checks to catch relative, traversal, empty, and temp paths")
	}
}

// applyUnifiedDiff applies a standard unified diff onto original bytes for test verification.
func applyUnifiedDiff(original []byte, patchText string) ([]byte, error) {
	if patchText == "" {
		return original, nil
	}
	origLines, origNL := splitNormalizedLines(original)
	oldTokens := makeDiffLines(origLines, origNL)

	rawDiffLines := strings.Split(strings.TrimSuffix(patchText, "\n"), "\n")
	if len(rawDiffLines) < 3 || !strings.HasPrefix(rawDiffLines[0], "--- ") || !strings.HasPrefix(rawDiffLines[1], "+++ ") {
		return nil, fmt.Errorf("missing unified diff file headers")
	}

	var out []diffLine
	oldPos := 0
	i := 2
	for i < len(rawDiffLines) {
		hdr := rawDiffLines[i]
		if !strings.HasPrefix(hdr, "@@ ") {
			return nil, fmt.Errorf("expected hunk header at line %d, got %q", i, hdr)
		}
		oldStart, _, err := parseHunkHeader(hdr)
		if err != nil {
			return nil, err
		}
		targetIdx := oldStart - 1
		if oldStart == 0 {
			targetIdx = 0
		}
		for oldPos < targetIdx {
			if oldPos >= len(oldTokens) {
				return nil, fmt.Errorf("oldPos out of range")
			}
			out = append(out, oldTokens[oldPos])
			oldPos++
		}
		i++

		for i < len(rawDiffLines) && !strings.HasPrefix(rawDiffLines[i], "@@ ") {
			line := rawDiffLines[i]
			if len(line) == 0 {
				return nil, fmt.Errorf("unexpected empty line inside hunk")
			}
			prefix := line[0]
			body := line[1:]
			hasNL := true
			if i+1 < len(rawDiffLines) && rawDiffLines[i+1] == "\\ No newline at end of file" {
				hasNL = false
				i++
			}
			tok := diffLine{text: body, hasNL: hasNL}
			switch prefix {
			case ' ':
				if oldPos >= len(oldTokens) || oldTokens[oldPos] != tok {
					return nil, fmt.Errorf("context mismatch at old line %d: got %+v", oldPos+1, tok)
				}
				out = append(out, tok)
				oldPos++
			case '-':
				if oldPos >= len(oldTokens) || oldTokens[oldPos] != tok {
					return nil, fmt.Errorf("delete mismatch at old line %d: got %+v", oldPos+1, tok)
				}
				oldPos++
			case '+':
				out = append(out, tok)
			default:
				return nil, fmt.Errorf("invalid diff op %q", string(prefix))
			}
			i++
		}
	}

	for oldPos < len(oldTokens) {
		out = append(out, oldTokens[oldPos])
		oldPos++
	}

	var buf bytes.Buffer
	for idx, tok := range out {
		buf.WriteString(tok.text)
		if tok.hasNL || idx < len(out)-1 {
			buf.WriteByte('\n')
		}
	}
	return buf.Bytes(), nil
}

func parseHunkHeader(hdr string) (oldStart int, oldCount int, err error) {
	trimmed := strings.TrimPrefix(hdr, "@@ ")
	endIdx := strings.Index(trimmed, " @@")
	if endIdx == -1 {
		return 0, 0, fmt.Errorf("malformed hunk header %q", hdr)
	}
	parts := strings.Fields(trimmed[:endIdx])
	if len(parts) != 2 || !strings.HasPrefix(parts[0], "-") || !strings.HasPrefix(parts[1], "+") {
		return 0, 0, fmt.Errorf("malformed hunk range %q", hdr)
	}
	oldRange := strings.TrimPrefix(parts[0], "-")
	if comma := strings.IndexByte(oldRange, ','); comma != -1 {
		_, err = fmt.Sscanf(oldRange, "%d,%d", &oldStart, &oldCount)
	} else {
		oldCount = 1
		_, err = fmt.Sscanf(oldRange, "%d", &oldStart)
	}
	if err != nil {
		return 0, 0, fmt.Errorf("invalid hunk old range %q: %w", oldRange, err)
	}
	return oldStart, oldCount, nil
}
