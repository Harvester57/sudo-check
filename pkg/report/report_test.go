package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"sudo-check/internal/buildinfo"
	"sudo-check/pkg/audit"
	"testing"
)

// createDummyResult creates a sample audit result with a mix of findings.
func createDummyResult() *audit.AuditResult {
	return &audit.AuditResult{
		Hostname:    "test-host",
		SudoVersion: "1.9.12",
		SystemFindings: []audit.Finding{
			{
				ID:          "SUDO-SYS-PERM-002",
				Title:       "Sudoers Writable by Group",
				Description: "The sudoers file '/etc/sudoers' has group write permissions: -rw-rw-r--.",
				Severity:    audit.SeverityCritical,
				Remediation: "Run 'chmod 0440 /etc/sudoers' to restrict write access.",
			},
		},
		PolicyFindings: []audit.Finding{
			{
				ID:          "SUDO-DEF-001",
				Title:       "Missing or Empty secure_path",
				Description: "The sudoers policy does not define a 'secure_path'.",
				Severity:    audit.SeverityHigh,
				Remediation: "Add Defaults secure_path=\"/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\" to sudoers.",
			},
			{
				ID:          "SUDO-GTFO-001",
				Title:       "GTFObins Sudo Bypass",
				Description: "The command 'find' is allowed and can be used to bypass sudo restrictions.",
				Severity:    audit.SeverityCritical,
				User:        "alice",
				Command:     "/usr/bin/find",
				Context:     "/etc/sudoers.d/alice",
				Remediation: "Review if 'find' requires elevated privileges.",
			},
			{
				ID:          "SUDO-XSS-TEST",
				Title:       "XSS Test <script>alert(1)</script>",
				Description: "Quotes \" and unicode ☺.",
				Severity:    audit.SeverityInfo,
			},
		},
	}
}

func TestWriteTextReport(t *testing.T) {
	result := createDummyResult()
	var buf bytes.Buffer

	err := WriteTextReport(result, &buf)
	if err != nil {
		t.Fatalf("WriteTextReport failed: %v", err)
	}

	out := buf.String()
	// Assert key sections present
	if !strings.Contains(out, "=== SUDOERS SECURITY AUDIT REPORT ===") {
		t.Errorf("Missing report header")
	}
	if !strings.Contains(out, "Target Hostname: test-host") {
		t.Errorf("Missing hostname")
	}
	if !strings.Contains(out, "Sudo Version:    1.9.12") {
		t.Errorf("Missing sudo version")
	}
	if !strings.Contains(out, "Sudoers Writable by Group") {
		t.Errorf("Missing system finding")
	}
	if !strings.Contains(out, "Missing or Empty secure_path") {
		t.Errorf("Missing policy finding")
	}
	if !strings.Contains(out, "--- Summary of Findings ---") {
		t.Errorf("Missing summary section")
	}
	if !strings.Contains(out, "CRITICAL:") {
		t.Errorf("Missing critical summary")
	}
}

func TestWriteSarifReport(t *testing.T) {
	buildinfo.Set("1.0.0-test", "commit123", "2026-01-01")
	result := createDummyResult()
	var buf bytes.Buffer

	err := WriteSarifReport(result, &buf)
	if err != nil {
		t.Fatalf("WriteSarifReport failed: %v", err)
	}

	var sarif map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &sarif); err != nil {
		t.Fatalf("Generated SARIF is not valid JSON: %v", err)
	}

	if sarif["version"] != "2.1.0" {
		t.Errorf("Expected SARIF version 2.1.0, got %v", sarif["version"])
	}

	runs, ok := sarif["runs"].([]interface{})
	if !ok || len(runs) == 0 {
		t.Fatalf("Missing or empty 'runs' array in SARIF")
	}

	run := runs[0].(map[string]interface{})
	tool := run["tool"].(map[string]interface{})
	driver := tool["driver"].(map[string]interface{})

	if driver["name"] != "sudo-check" {
		t.Errorf("Expected driver name 'sudo-check', got %v", driver["name"])
	}
	if driver["version"] != "1.0.0-test" {
		t.Errorf("Expected driver version '1.0.0-test', got %v", driver["version"])
	}

	results, ok := run["results"].([]interface{})
	if !ok || len(results) != 4 {
		t.Errorf("Expected 4 results, got %v", len(results))
	}
}

func TestWriteHTMLReport(t *testing.T) {
	result := createDummyResult()
	var buf bytes.Buffer

	err := WriteHTMLReport(result, &buf)
	if err != nil {
		t.Fatalf("WriteHTMLReport failed: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "<!DOCTYPE html>") {
		t.Errorf("Missing HTML doctype")
	}
	if !strings.Contains(out, "Sudoers Writable by Group") {
		t.Errorf("Missing finding title")
	}
	if !strings.Contains(out, "SUDO-DEF-001") {
		t.Errorf("Missing finding ID")
	}
	if !strings.Contains(out, "badge-crit") {
		t.Errorf("Missing severity badge class")
	}
}

func TestWritePDFReport(t *testing.T) {
	result := createDummyResult()
	var buf bytes.Buffer

	err := WritePDFReport(result, &buf)
	if err != nil {
		t.Fatalf("WritePDFReport failed: %v", err)
	}

	if buf.Len() == 0 {
		t.Errorf("Generated PDF is empty")
	}

	out := buf.String()
	if !strings.HasPrefix(out, "%PDF-") {
		t.Errorf("Generated file is not a valid PDF")
	}
}

func TestReportsWithEmptyFindings(t *testing.T) {
	emptyResult := &audit.AuditResult{}

	t.Run("TextEmpty", func(t *testing.T) {
		var buf bytes.Buffer
		if err := WriteTextReport(emptyResult, &buf); err != nil {
			t.Fatalf("WriteTextReport failed on empty findings: %v", err)
		}
		if !strings.Contains(buf.String(), "No sudoers policy misconfigurations found.") {
			t.Errorf("Missing empty policy message in text report")
		}
	})

	t.Run("SarifEmpty", func(t *testing.T) {
		var buf bytes.Buffer
		if err := WriteSarifReport(emptyResult, &buf); err != nil {
			t.Fatalf("WriteSarifReport failed on empty findings: %v", err)
		}
	})

	t.Run("HtmlEmpty", func(t *testing.T) {
		var buf bytes.Buffer
		if err := WriteHTMLReport(emptyResult, &buf); err != nil {
			t.Fatalf("WriteHTMLReport failed on empty findings: %v", err)
		}
	})

	t.Run("PdfEmpty", func(t *testing.T) {
		var buf bytes.Buffer
		if err := WritePDFReport(emptyResult, &buf); err != nil {
			t.Fatalf("WritePDFReport failed on empty findings: %v", err)
		}
		if buf.Len() == 0 {
			t.Errorf("Generated PDF is empty")
		}
	})
}

func TestWriteTextReportWithColor_NoANSIInFileMode(t *testing.T) {
	result := createDummyResult()
	var buf bytes.Buffer
	if err := WriteTextReportWithColor(result, &buf, false); err != nil {
		t.Fatalf("WriteTextReportWithColor failed: %v", err)
	}
	if strings.Contains(buf.String(), "\033[") {
		t.Errorf("Expected uncolored text report to contain no ANSI escape sequences")
	}
}

func TestGenerateReports_ValidationAndDiskOutput(t *testing.T) {
	result := createDummyResult()
	tempDir := t.TempDir()

	generated, err := GenerateReports(result, []string{"text", "sarif", "html", "pdf"}, tempDir)
	if err != nil {
		t.Fatalf("GenerateReports failed: %v", err)
	}
	if len(generated) != 4 {
		t.Errorf("Expected 4 generated reports, got %d", len(generated))
	}

	if _, err := GenerateReports(result, []string{"invalid-format"}, tempDir); err == nil {
		t.Errorf("Expected error for unsupported report format")
	}
}
