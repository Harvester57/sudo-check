package cmd

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sudo-check/pkg/audit"
	"sudo-check/pkg/fleet"
	"testing"
	"unicode"
)

func mergeTestResetFlags() {
	outputDir = ""
	formats = "text,sarif,pdf,html"
	gtfoBinsPath = ""
	cvtSudoersPath = ""
	failOn = ""
	noColor = false
	configPath = ""
	profileName = ""
	customGTFObinsPath = ""
	baselinePath = ""
	subcommandAware = false

	for _, name := range []string{
		"output-dir",
		"formats",
		"gtfobins-path",
		"cvtsudoers-path",
		"fail-on",
		"no-color",
		"config",
		"profile",
		"custom-gtfobins",
		"baseline",
		"subcommand-aware",
		"help",
	} {
		if f := rootCmd.PersistentFlags().Lookup(name); f != nil {
			f.Changed = false
		}
		if f := mergeCmd.Flags().Lookup(name); f != nil {
			f.Changed = false
		}
	}

	rootCmd.SetOut(nil)
	rootCmd.SetErr(nil)
	rootCmd.SetIn(nil)
}

func mergeTestWriteReport(t *testing.T, path string, res audit.AuditResult) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	b, err := json.Marshal(res)
	if err != nil {
		t.Fatalf("marshal report %s: %v", path, err)
	}
	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatalf("write report %s: %v", path, err)
	}
}

func TestMergeCmd_DirectoryAndFileOutputFormats(t *testing.T) {
	mergeTestResetFlags()
	t.Cleanup(mergeTestResetFlags)

	dir := t.TempDir()
	reportsDir := filepath.Join(dir, "reports")
	web1Path := filepath.Join(reportsDir, "web01.json")
	db1Path := filepath.Join(reportsDir, "nested", "db01.JSON")
	app1Path := filepath.Join(dir, "standalone-app01.json")
	hiddenPath := filepath.Join(reportsDir, ".hidden", "ignored.json")
	outDir := filepath.Join(reportsDir, "merged-out")

	mergeTestWriteReport(t, web1Path, audit.AuditResult{
		Hostname:    "web01",
		SudoVersion: "1.9.15p5",
		PolicyFindings: []audit.Finding{
			{ID: "SUDO-CMD-003", Title: "NOPASSWD ALL", Severity: audit.SeverityCritical},
			{ID: "SUDO-DEF-001", Title: "Missing secure_path", Severity: audit.SeverityHigh},
		},
	})
	mergeTestWriteReport(t, db1Path, audit.AuditResult{
		Hostname:    "db01",
		SudoVersion: "1.9.16",
		PolicyFindings: []audit.Finding{
			{ID: "SUDO-DEF-001", Title: "Missing secure_path", Severity: audit.SeverityHigh},
		},
	})
	mergeTestWriteReport(t, app1Path, audit.AuditResult{
		Hostname:    "app01",
		SudoVersion: "1.9.17",
		PolicyFindings: []audit.Finding{
			{ID: "SUDO-DEF-003", Title: "Missing use_pty", Severity: audit.SeverityMedium},
		},
	})
	// Should be skipped because it lives under hidden directory .hidden
	if err := os.MkdirAll(filepath.Dir(hiddenPath), 0750); err != nil {
		t.Fatalf("mkdir hidden: %v", err)
	}
	if err := os.WriteFile(hiddenPath, []byte(`{invalid-ignored}`), 0600); err != nil {
		t.Fatalf("write hidden file: %v", err)
	}

	// Pass overlapping web1Path and reportsDir to verify deduplication.
	rootCmd.SetArgs([]string{"merge", reportsDir, web1Path, app1Path, "-o", outDir})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("merge command failed: %v", err)
	}

	for _, name := range []string{"fleet-report.html", "fleet-report.csv", "fleet-report.json"} {
		p := filepath.Join(outDir, name)
		info, err := os.Stat(p)
		if err != nil {
			t.Fatalf("expected %s to exist: %v", p, err)
		}
		if info.Size() == 0 {
			t.Fatalf("expected non-empty %s", p)
		}
	}

	jsonBytes, err := os.ReadFile(filepath.Join(outDir, "fleet-report.json"))
	if err != nil {
		t.Fatalf("read fleet-report.json: %v", err)
	}
	var summary fleet.FleetSummary
	if err := json.Unmarshal(jsonBytes, &summary); err != nil {
		t.Fatalf("unmarshal fleet-report.json: %v", err)
	}
	if summary.HostCount != 3 || summary.TotalFindings != 4 {
		t.Fatalf("expected HostCount=3 TotalFindings=4, got HostCount=%d TotalFindings=%d", summary.HostCount, summary.TotalFindings)
	}

	csvBytes, err := os.ReadFile(filepath.Join(outDir, "fleet-report.csv"))
	if err != nil {
		t.Fatalf("read fleet-report.csv: %v", err)
	}
	records, err := csv.NewReader(bytes.NewReader(csvBytes)).ReadAll()
	if err != nil {
		t.Fatalf("parse fleet-report.csv: %v", err)
	}
	if len(records) != 4 {
		t.Fatalf("expected 4 CSV rows (header + 3 hosts), got %d", len(records))
	}

	htmlBytes, err := os.ReadFile(filepath.Join(outDir, "fleet-report.html"))
	if err != nil {
		t.Fatalf("read fleet-report.html: %v", err)
	}
	htmlStr := string(htmlBytes)
	lowerHTML := strings.ToLower(htmlStr)
	if strings.Contains(lowerHTML, "http://") || strings.Contains(lowerHTML, "https://") {
		t.Fatal("fleet-report.html must be 100% offline-safe without http/https URLs")
	}
	for _, r := range htmlStr {
		if unicode.Is(unicode.So, r) {
			t.Fatalf("unexpected symbol/emoji rune %U in fleet-report.html", r)
		}
	}
	for _, want := range []string{"web01", "db01", "app01", "SUDO-CMD-003", "SUDO-DEF-001"} {
		if !strings.Contains(htmlStr, want) {
			t.Errorf("expected %q in fleet-report.html", want)
		}
	}
}

func TestMergeCmd_StdoutCSVAndJSON(t *testing.T) {
	dir := t.TempDir()
	p1 := filepath.Join(dir, "h1.json")
	p2 := filepath.Join(dir, "h2.json")
	mergeTestWriteReport(t, p1, audit.AuditResult{
		Hostname: "h1",
		PolicyFindings: []audit.Finding{
			{ID: "SUDO-DEF-001", Title: "Missing secure_path", Severity: audit.SeverityHigh},
		},
	})
	mergeTestWriteReport(t, p2, audit.AuditResult{
		Hostname: "h2",
		PolicyFindings: []audit.Finding{
			{ID: "SUDO-DEF-003", Title: "Missing use_pty", Severity: audit.SeverityMedium},
		},
	})

	t.Run("StdoutJSON", func(t *testing.T) {
		mergeTestResetFlags()
		t.Cleanup(mergeTestResetFlags)
		var out bytes.Buffer
		rootCmd.SetOut(&out)
		rootCmd.SetArgs([]string{"merge", p1, p2, "-f", "json"})
		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("merge -f json to stdout failed: %v", err)
		}
		var summary fleet.FleetSummary
		if err := json.Unmarshal(out.Bytes(), &summary); err != nil {
			t.Fatalf("unmarshal stdout JSON failed: %v", err)
		}
		if summary.HostCount != 2 || summary.TotalFindings != 2 {
			t.Fatalf("unexpected summary: %+v", summary)
		}
	})

	t.Run("StdoutCSV", func(t *testing.T) {
		mergeTestResetFlags()
		t.Cleanup(mergeTestResetFlags)
		var out bytes.Buffer
		rootCmd.SetOut(&out)
		rootCmd.SetArgs([]string{"merge", p1, p2, "-f", "csv"})
		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("merge -f csv to stdout failed: %v", err)
		}
		records, err := csv.NewReader(&out).ReadAll()
		if err != nil {
			t.Fatalf("parse stdout CSV failed: %v", err)
		}
		if len(records) != 3 {
			t.Fatalf("expected 3 CSV rows, got %d", len(records))
		}
	})
}

func TestMergeCmd_Errors(t *testing.T) {
	dir := t.TempDir()
	validReport := filepath.Join(dir, "valid.json")
	mergeTestWriteReport(t, validReport, audit.AuditResult{Hostname: "h1"})

	t.Run("HTMLRequiresOutputDir", func(t *testing.T) {
		mergeTestResetFlags()
		t.Cleanup(mergeTestResetFlags)
		rootCmd.SetArgs([]string{"merge", validReport, "-f", "html"})
		if err := rootCmd.Execute(); err == nil || !strings.Contains(err.Error(), "--output-dir") {
			t.Fatalf("expected --output-dir error for html without -o, got: %v", err)
		}
	})

	t.Run("DefaultFormatsWithoutOutputDirRejected", func(t *testing.T) {
		mergeTestResetFlags()
		t.Cleanup(mergeTestResetFlags)
		rootCmd.SetArgs([]string{"merge", validReport})
		if err := rootCmd.Execute(); err == nil || !strings.Contains(err.Error(), "--output-dir") {
			t.Fatalf("expected --output-dir error for default formats without -o, got: %v", err)
		}
	})

	t.Run("MultipleFormatsWithoutOutputDirRejected", func(t *testing.T) {
		mergeTestResetFlags()
		t.Cleanup(mergeTestResetFlags)
		rootCmd.SetArgs([]string{"merge", validReport, "-f", "csv,json"})
		if err := rootCmd.Execute(); err == nil || !strings.Contains(err.Error(), "multiple formats") {
			t.Fatalf("expected multiple formats stdout error, got: %v", err)
		}
	})

	t.Run("UnsupportedFormat", func(t *testing.T) {
		mergeTestResetFlags()
		t.Cleanup(mergeTestResetFlags)
		rootCmd.SetArgs([]string{"merge", validReport, "-f", "pdf", "-o", filepath.Join(dir, "out")})
		if err := rootCmd.Execute(); err == nil || !strings.Contains(err.Error(), "unsupported merge format") {
			t.Fatalf("expected unsupported format error, got: %v", err)
		}
	})

	t.Run("EmptyFormatRejected", func(t *testing.T) {
		mergeTestResetFlags()
		t.Cleanup(mergeTestResetFlags)
		rootCmd.SetArgs([]string{"merge", validReport, "-f", ""})
		if err := rootCmd.Execute(); err == nil || !strings.Contains(err.Error(), "no output formats") {
			t.Fatalf("expected empty format error, got: %v", err)
		}
	})

	t.Run("EmptyDirNoJSON", func(t *testing.T) {
		mergeTestResetFlags()
		t.Cleanup(mergeTestResetFlags)
		emptyDir := t.TempDir()
		rootCmd.SetArgs([]string{"merge", emptyDir, "-f", "json"})
		if err := rootCmd.Execute(); err == nil || !strings.Contains(err.Error(), "no JSON report files") {
			t.Fatalf("expected no JSON report files error, got: %v", err)
		}
	})

	t.Run("MissingPath", func(t *testing.T) {
		mergeTestResetFlags()
		t.Cleanup(mergeTestResetFlags)
		rootCmd.SetArgs([]string{"merge", filepath.Join(dir, "missing.json"), "-f", "json"})
		if err := rootCmd.Execute(); err == nil {
			t.Fatal("expected error for missing input path")
		}
	})

	t.Run("NonReportJSON", func(t *testing.T) {
		mergeTestResetFlags()
		t.Cleanup(mergeTestResetFlags)
		badJSON := filepath.Join(dir, "not_report.json")
		if err := os.WriteFile(badJSON, []byte(`{"Defaults":[]}`), 0600); err != nil {
			t.Fatalf("write bad json: %v", err)
		}
		rootCmd.SetArgs([]string{"merge", badJSON, "-f", "json"})
		if err := rootCmd.Execute(); err == nil {
			t.Fatal("expected error for non-AuditResult JSON")
		}
	})
}
