package fleet

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sudo-check/pkg/audit"
	"testing"
	"unicode"
)

func writeTempReport(t *testing.T, dir, name string, content []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, content, 0o600); err != nil {
		t.Fatalf("failed to write temp report %s: %v", p, err)
	}
	return p
}

func TestMergeReportFiles_Errors(t *testing.T) {
	dir := t.TempDir()

	t.Run("EmptyPaths", func(t *testing.T) {
		if _, err := MergeReportFiles(nil); err == nil {
			t.Fatal("expected error for empty paths slice")
		}
	})

	t.Run("UnreadableFile", func(t *testing.T) {
		if _, err := MergeReportFiles([]string{filepath.Join(dir, "missing.json")}); err == nil {
			t.Fatal("expected error for missing file")
		}
	})

	t.Run("InvalidJSON", func(t *testing.T) {
		p := writeTempReport(t, dir, "bad.json", []byte("{not valid json"))
		if _, err := MergeReportFiles([]string{p}); err == nil {
			t.Fatal("expected error for invalid JSON")
		}
	})

	t.Run("JSONArrayRejected", func(t *testing.T) {
		p := writeTempReport(t, dir, "array.json", []byte(`[{"id": "SUDO-001"}]`))
		if _, err := MergeReportFiles([]string{p}); err == nil {
			t.Fatal("expected error when JSON root is an array instead of object")
		}
	})

	t.Run("JSONNullRejected", func(t *testing.T) {
		p := writeTempReport(t, dir, "null.json", []byte(`null`))
		if _, err := MergeReportFiles([]string{p}); err == nil {
			t.Fatal("expected error when JSON root is null")
		}
	})

	t.Run("UnrelatedJSONObjectRejected", func(t *testing.T) {
		p := writeTempReport(t, dir, "other.json", []byte(`{"Defaults": [], "User_Specs": []}`))
		if _, err := MergeReportFiles([]string{p}); err == nil {
			t.Fatal("expected error for non-AuditResult JSON object")
		}
	})

	t.Run("MalformedFieldTypesRejected", func(t *testing.T) {
		p := writeTempReport(t, dir, "bad_fields.json", []byte(`{"hostname": "h1", "policy_findings": "not-an-array"}`))
		if _, err := MergeReportFiles([]string{p}); err == nil {
			t.Fatal("expected error when policy_findings is not an array")
		}
	})
}

func TestMergeReportFiles_AggregationSortingAndDisambiguation(t *testing.T) {
	dir := t.TempDir()

	rWeb1, _ := json.Marshal(audit.AuditResult{
		Hostname:    "web-01",
		SudoVersion: "1.9.15p5",
		SystemFindings: []audit.Finding{
			{ID: "CVE-2021-3156", Title: "Baron Samedit Heap Overflow", Severity: audit.SeverityCritical},
		},
		PolicyFindings: []audit.Finding{
			{ID: "SUDO-GTFO-001", Title: "GTFObins Shell Escape", Severity: audit.SeverityHigh},
			{ID: "SUDO-GTFO-001", Title: "GTFObins Shell Escape", Severity: audit.SeverityCritical},
			{ID: "SUDO-DEF-003", Title: "Missing use_pty", Severity: audit.SeverityMedium},
		},
	})
	// BOM prefix + empty hostname -> derived from filename "db-alpha.JSON" -> "db-alpha"
	rDBAlpha, _ := json.Marshal(audit.AuditResult{
		Hostname:    "",
		SudoVersion: "1.9.13",
		PolicyFindings: []audit.Finding{
			{ID: "SUDO-DEF-003", Title: "Missing use_pty", Severity: audit.SeverityMedium},
			{ID: "SUDO-DEF-008", Title: "Missing requiretty", Severity: audit.SeverityLow},
		},
	})
	// Duplicate hostname "web-01" -> disambiguated to "web-01 (2)"
	rWeb1Dup, _ := json.Marshal(audit.AuditResult{
		Hostname:    "web-01",
		SudoVersion: "1.9.15p5",
		PolicyFindings: []audit.Finding{
			{ID: "SUDO-DEF-001", Title: "Missing secure_path", Severity: audit.SeverityHigh},
			{ID: "SUDO-DEF-003", Title: "Missing use_pty", Severity: audit.SeverityMedium},
		},
	})
	// Same severity tie-breakers: High=0, Medium=1, Low=0, Total=1 vs db-alpha (Med=1, Low=1, Total=2)
	rAppA, _ := json.Marshal(audit.AuditResult{
		Hostname:    "app-a",
		SudoVersion: "1.9.16",
		PolicyFindings: []audit.Finding{
			{ID: "SUDO-DEF-003", Title: "Missing use_pty", Severity: audit.SeverityMedium},
		},
	})
	// Clean host with 0 findings
	rClean, _ := json.Marshal(audit.AuditResult{
		Hostname:       "clean-host",
		SudoVersion:    "1.9.17",
		PolicyFindings: []audit.Finding{},
		SystemFindings: []audit.Finding{},
	})

	p1 := writeTempReport(t, dir, "web1.json", rWeb1)
	p2 := writeTempReport(t, dir, "db-alpha.JSON", append([]byte("\xef\xbb\xbf"), rDBAlpha...))
	p3 := writeTempReport(t, dir, "web1-dup.json", rWeb1Dup)
	p4 := writeTempReport(t, dir, "app-a.json", rAppA)
	p5 := writeTempReport(t, dir, "clean.json", rClean)

	summary, err := MergeReportFiles([]string{p1, p2, p3, p4, p5})
	if err != nil {
		t.Fatalf("MergeReportFiles failed: %v", err)
	}

	if summary.HostCount != 5 {
		t.Fatalf("HostCount = %d, want 5", summary.HostCount)
	}
	if summary.TotalFindings != 9 {
		t.Fatalf("TotalFindings = %d, want 9", summary.TotalFindings)
	}

	// Verify HostSummaries ordering:
	// 1. web-01 (Crit=2, High=1, Med=1, Total=4)
	// 2. web-01 (2) (Crit=0, High=1, Med=1, Total=2)
	// 3. db-alpha (Crit=0, High=0, Med=1, Low=1, Total=2)
	// 4. app-a (Crit=0, High=0, Med=1, Low=0, Total=1)
	// 5. clean-host (Total=0, Highest=NONE)
	wantHostOrder := []string{"web-01", "web-01 (2)", "db-alpha", "app-a", "clean-host"}
	if len(summary.HostSummaries) != len(wantHostOrder) {
		t.Fatalf("got %d host summaries, want %d", len(summary.HostSummaries), len(wantHostOrder))
	}
	for i, wantHost := range wantHostOrder {
		if summary.HostSummaries[i].Hostname != wantHost {
			t.Errorf("HostSummaries[%d].Hostname = %q, want %q", i, summary.HostSummaries[i].Hostname, wantHost)
		}
	}
	if summary.HostSummaries[4].Highest != audit.Severity("NONE") {
		t.Errorf("clean host Highest = %q, want NONE", summary.HostSummaries[4].Highest)
	}

	// Verify SeverityCounts totals.
	if summary.SeverityCounts[audit.SeverityCritical] != 2 ||
		summary.SeverityCounts[audit.SeverityHigh] != 2 ||
		summary.SeverityCounts[audit.SeverityMedium] != 4 ||
		summary.SeverityCounts[audit.SeverityLow] != 1 ||
		summary.SeverityCounts[audit.SeverityInfo] != 0 {
		t.Fatalf("unexpected SeverityCounts: %+v", summary.SeverityCounts)
	}

	// Verify RulePrevalence ordering:
	// Critical: CVE-2021-3156 (HostCount=1), SUDO-GTFO-001 (HostCount=1, TotalCount=2) -> SUDO-GTFO-001 before CVE-2021-3156 because TotalCount desc!
	// High: SUDO-DEF-001 (HostCount=1)
	// Medium: SUDO-DEF-003 (HostCount=4)
	// Low: SUDO-DEF-008 (HostCount=1)
	wantRules := []struct {
		id         string
		sev        audit.Severity
		hostCount  int
		totalCount int
	}{
		{"SUDO-GTFO-001", audit.SeverityCritical, 1, 2},
		{"CVE-2021-3156", audit.SeverityCritical, 1, 1},
		{"SUDO-DEF-001", audit.SeverityHigh, 1, 1},
		{"SUDO-DEF-003", audit.SeverityMedium, 4, 4},
		{"SUDO-DEF-008", audit.SeverityLow, 1, 1},
	}
	if len(summary.RulePrevalence) != len(wantRules) {
		t.Fatalf("got %d rules, want %d", len(summary.RulePrevalence), len(wantRules))
	}
	for i, wr := range wantRules {
		got := summary.RulePrevalence[i]
		if got.RuleID != wr.id || got.Severity != wr.sev || got.HostCount != wr.hostCount || got.TotalCount != wr.totalCount {
			t.Errorf("RulePrevalence[%d] = %+v, want %+v", i, got, wr)
		}
	}

	// Verify AffectedHosts sorted alphabetically for SUDO-DEF-003.
	wantAffected := []string{"app-a", "db-alpha", "web-01", "web-01 (2)"}
	gotAffected := summary.RulePrevalence[3].AffectedHosts
	if strings.Join(gotAffected, ",") != strings.Join(wantAffected, ",") {
		t.Errorf("SUDO-DEF-003 AffectedHosts = %v, want %v", gotAffected, wantAffected)
	}
}

func TestMergeReportFiles_TieBreakers(t *testing.T) {
	dir := t.TempDir()

	// Test HostSummaries tie-breakers:
	// host-z: 1 Low, 1 Info (Total 2)
	// host-a: 1 Low, 0 Info (Total 1)
	// host-b: 1 Low, 0 Info (Total 1) -> alphabetical tie-breaker after Total
	makeHost := func(name string, findings ...audit.Finding) string {
		b, _ := json.Marshal(audit.AuditResult{Hostname: name, PolicyFindings: findings})
		return writeTempReport(t, dir, name+".json", b)
	}
	pZ := makeHost("host-z",
		audit.Finding{ID: "R2", Severity: audit.SeverityLow},
		audit.Finding{ID: "R1", Severity: audit.SeverityInfo},
	)
	pB := makeHost("host-b", audit.Finding{ID: "R1", Severity: audit.SeverityLow})
	pA := makeHost("host-a", audit.Finding{ID: "R2", Severity: audit.SeverityLow})

	summary, err := MergeReportFiles([]string{pZ, pB, pA})
	if err != nil {
		t.Fatalf("MergeReportFiles failed: %v", err)
	}
	gotOrder := []string{
		summary.HostSummaries[0].Hostname,
		summary.HostSummaries[1].Hostname,
		summary.HostSummaries[2].Hostname,
	}
	if strings.Join(gotOrder, ",") != "host-z,host-a,host-b" {
		t.Fatalf("unexpected host tie-breaker order: %v", gotOrder)
	}

	// Test RuleID alphabetical tie-breaker: R1 (Low, HostCount=2) vs R2 (Low, HostCount=2)
	if summary.RulePrevalence[0].RuleID != "R1" || summary.RulePrevalence[1].RuleID != "R2" {
		t.Fatalf("unexpected rule tie-breaker order: %+v", summary.RulePrevalence)
	}
}

func TestWriteFleetExporters(t *testing.T) {
	summary := &FleetSummary{
		HostCount:     2,
		TotalFindings: 3,
		SeverityCounts: map[audit.Severity]int{
			audit.SeverityCritical: 1,
			audit.SeverityHigh:     1,
			audit.SeverityMedium:   0,
			audit.SeverityLow:      1,
			audit.SeverityInfo:     0,
		},
		HostSummaries: []HostRiskSummary{
			{
				Hostname:    "prod-api-01",
				SourceFile:  "/reports/prod-api-01.json",
				SudoVersion: "1.9.15p5",
				Critical:    1,
				High:        1,
				Total:       2,
				Highest:     audit.SeverityCritical,
			},
			{
				Hostname:    "staging,<script>alert(1)</script>",
				SourceFile:  "/reports/staging.json",
				SudoVersion: "",
				Low:         1,
				Total:       1,
				Highest:     audit.SeverityLow,
			},
		},
		RulePrevalence: []RulePrevalenceSummary{
			{
				RuleID:        "SUDO-CMD-001",
				Title:         "Unrestricted ALL=(ALL) NOPASSWD Rule",
				Severity:      audit.SeverityCritical,
				HostCount:     1,
				TotalCount:    1,
				AffectedHosts: []string{"prod-api-01"},
			},
			{
				RuleID:        "SUDO-DEF-017",
				Title:         "Missing <logfile> Configuration",
				Severity:      audit.SeverityLow,
				HostCount:     1,
				TotalCount:    1,
				AffectedHosts: []string{"staging,<script>alert(1)</script>"},
			},
		},
	}

	t.Run("WriteFleetJSON", func(t *testing.T) {
		var buf bytes.Buffer
		if err := WriteFleetJSON(summary, &buf); err != nil {
			t.Fatalf("WriteFleetJSON failed: %v", err)
		}
		out := buf.String()
		if !strings.Contains(out, "  \"host_count\": 2") {
			t.Fatalf("expected indented JSON output, got:\n%s", out)
		}
		var decoded FleetSummary
		if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
			t.Fatalf("failed to unmarshal JSON output: %v", err)
		}
		if decoded.HostCount != 2 || len(decoded.HostSummaries) != 2 || len(decoded.RulePrevalence) != 2 {
			t.Fatalf("unexpected decoded summary: %+v", decoded)
		}
	})

	t.Run("WriteFleetCSV", func(t *testing.T) {
		var buf bytes.Buffer
		if err := WriteFleetCSV(summary, &buf); err != nil {
			t.Fatalf("WriteFleetCSV failed: %v", err)
		}
		records, err := csv.NewReader(&buf).ReadAll()
		if err != nil {
			t.Fatalf("failed to parse generated CSV: %v", err)
		}
		if len(records) != 3 {
			t.Fatalf("expected 3 CSV rows (header + 2 hosts), got %d", len(records))
		}
		wantHeader := "hostname,sudo_version,critical,high,medium,low,info,total,highest_severity,source_file"
		if strings.Join(records[0], ",") != wantHeader {
			t.Fatalf("CSV header = %q, want %q", strings.Join(records[0], ","), wantHeader)
		}
		if records[1][0] != "prod-api-01" || records[1][2] != "1" || records[1][8] != "CRITICAL" {
			t.Fatalf("unexpected CSV row 1: %v", records[1])
		}
		if records[2][0] != "staging,<script>alert(1)</script>" || records[2][7] != "1" {
			t.Fatalf("unexpected CSV row 2: %v", records[2])
		}
	})

	t.Run("WriteFleetHTML", func(t *testing.T) {
		var buf bytes.Buffer
		if err := WriteFleetHTML(summary, &buf); err != nil {
			t.Fatalf("WriteFleetHTML failed: %v", err)
		}
		htmlOut := buf.String()

		// Offline safety: zero external URLs or CDN references.
		lower := strings.ToLower(htmlOut)
		if strings.Contains(lower, "http://") || strings.Contains(lower, "https://") {
			t.Fatal("HTML report must be 100% offline-safe with zero external http/https URLs")
		}
		if strings.Contains(htmlOut, "ZgotmplZ") {
			t.Fatal("html/template produced ZgotmplZ sanitization marker")
		}
		// Zero emojis: ensure no Unicode Symbol, Other (So) characters exist.
		for _, r := range htmlOut {
			if unicode.Is(unicode.So, r) {
				t.Fatalf("unexpected symbol/emoji rune %U in HTML output", r)
			}
		}
		// Theme toggle + localStorage.
		if !strings.Contains(htmlOut, "localStorage") || !strings.Contains(htmlOut, "toggleTheme()") || !strings.Contains(htmlOut, "sudo-check-theme") {
			t.Fatal("expected localStorage theme toggle support in HTML output")
		}
		// XSS escaping via html/template.
		if strings.Contains(htmlOut, "<script>alert(1)</script>") {
			t.Fatal("expected html/template to escape script tags in hostname")
		}
		if !strings.Contains(htmlOut, "&lt;script&gt;alert(1)&lt;/script&gt;") {
			t.Fatal("expected escaped script payload in HTML output")
		}
		// Content presence.
		for _, expected := range []string{"prod-api-01", "SUDO-CMD-001", "SUDO-DEF-017", "Host Risk Ranking", "Rule Prevalence Across Fleet"} {
			if !strings.Contains(htmlOut, expected) {
				t.Errorf("expected %q in HTML output", expected)
			}
		}
	})

	t.Run("WriteFleetHTMLEmpty", func(t *testing.T) {
		var buf bytes.Buffer
		empty := &FleetSummary{}
		if err := WriteFleetHTML(empty, &buf); err != nil {
			t.Fatalf("WriteFleetHTML on empty summary failed: %v", err)
		}
		if !strings.Contains(buf.String(), "No host reports were included") {
			t.Error("expected empty state message in HTML output")
		}
	})

	t.Run("NilArgumentErrors", func(t *testing.T) {
		var buf bytes.Buffer
		if err := WriteFleetJSON(nil, &buf); err == nil {
			t.Error("expected error for nil summary in WriteFleetJSON")
		}
		if err := WriteFleetJSON(summary, nil); err == nil {
			t.Error("expected error for nil writer in WriteFleetJSON")
		}
		if err := WriteFleetCSV(nil, &buf); err == nil {
			t.Error("expected error for nil summary in WriteFleetCSV")
		}
		if err := WriteFleetCSV(summary, nil); err == nil {
			t.Error("expected error for nil writer in WriteFleetCSV")
		}
		if err := WriteFleetHTML(nil, &buf); err == nil {
			t.Error("expected error for nil summary in WriteFleetHTML")
		}
		if err := WriteFleetHTML(summary, nil); err == nil {
			t.Error("expected error for nil writer in WriteFleetHTML")
		}
	})
}

func TestMergeReportFiles_OrderIndependentAndCanonicalTitles(t *testing.T) {
	dir := t.TempDir()

	rHighRisk, _ := json.Marshal(audit.AuditResult{
		Hostname:    "web-01",
		SudoVersion: "1.9.15p5",
		PolicyFindings: []audit.Finding{
			{ID: "SUDO-GTFO-002", Title: "Passwordless Dangerous Sudo Binary allowed: vim (shell)", Severity: audit.SeverityCritical},
			{ID: "SUDO-DEF-003", Title: "Disabled use_pty in Scoped Defaults", Severity: audit.SeverityMedium},
		},
	})
	rLowRiskDup, _ := json.Marshal(audit.AuditResult{
		Hostname:    "web-01",
		SudoVersion: "1.9.15p5",
		PolicyFindings: []audit.Finding{
			{ID: "SUDO-GTFO-002", Title: "Passwordless Dangerous Sudo Binary allowed: awk (shell)", Severity: audit.SeverityCritical},
		},
	})

	p1 := writeTempReport(t, dir, "a-high.json", rHighRisk)
	p2 := writeTempReport(t, dir, "z-dup.json", rLowRiskDup)

	sumForward, err := MergeReportFiles([]string{p1, p2})
	if err != nil {
		t.Fatalf("MergeReportFiles forward failed: %v", err)
	}
	sumReverse, err := MergeReportFiles([]string{p2, p1})
	if err != nil {
		t.Fatalf("MergeReportFiles reverse failed: %v", err)
	}

	var jsonFwd, jsonRev bytes.Buffer
	if err := WriteFleetJSON(sumForward, &jsonFwd); err != nil {
		t.Fatalf("WriteFleetJSON forward failed: %v", err)
	}
	if err := WriteFleetJSON(sumReverse, &jsonRev); err != nil {
		t.Fatalf("WriteFleetJSON reverse failed: %v", err)
	}
	if !bytes.Equal(jsonFwd.Bytes(), jsonRev.Bytes()) {
		t.Fatalf("expected identical fleet JSON regardless of input order:\n--- forward ---\n%s\n--- reverse ---\n%s", jsonFwd.String(), jsonRev.String())
	}

	var htmlFwd, htmlRev bytes.Buffer
	if err := WriteFleetHTML(sumForward, &htmlFwd); err != nil {
		t.Fatalf("WriteFleetHTML forward failed: %v", err)
	}
	if err := WriteFleetHTML(sumReverse, &htmlRev); err != nil {
		t.Fatalf("WriteFleetHTML reverse failed: %v", err)
	}
	if !bytes.Equal(htmlFwd.Bytes(), htmlRev.Bytes()) {
		t.Fatal("expected identical fleet HTML regardless of input order")
	}

	if len(sumForward.RulePrevalence) < 1 || sumForward.RulePrevalence[0].RuleID != "SUDO-GTFO-002" {
		t.Fatalf("expected SUDO-GTFO-002 first in RulePrevalence, got %+v", sumForward.RulePrevalence)
	}
	wantTitle := "Passwordless Permitted Binary in GTFObins Catalog"
	if sumForward.RulePrevalence[0].Title != wantTitle {
		t.Errorf("RulePrevalence[0].Title = %q, want canonical %q", sumForward.RulePrevalence[0].Title, wantTitle)
	}
}
