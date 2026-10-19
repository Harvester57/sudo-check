package report

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sudo-check/internal/buildinfo"
	"sudo-check/pkg/audit"
	"sudo-check/pkg/gtfobins"
	"sudo-check/pkg/parser"
	"testing"
)

// createDummyResult creates a sample audit result with a mix of findings.
func createDummyResult() *audit.AuditResult {
	return &audit.AuditResult{
		Hostname:    "test-host",
		SudoVersion: "1.9.12",
		SystemFindings: []audit.Finding{
			{
				ID:          "SUDO-SYS-PERM-004",
				Title:       "Sudoers World Readable",
				Description: "The sudoers file '/etc/sudoers' is world-readable.",
				Severity:    audit.SeverityHigh,
				Context:     "/etc/sudoers",
				Remediation: "Upgrade permissions on /etc/sudoers.",
				Compliance:  []string{"CIS-5.2.3", "ANSSI-BP-028-R39"},
			},
			{
				ID:          "SUDO-SYS-PERM-002",
				Title:       "Sudoers Writable by Group",
				Description: "The sudoers file '/etc/sudoers' has group write permissions: -rw-rw-r--.",
				Severity:    audit.SeverityCritical,
				Context:     "/etc/sudoers",
				Line:        1,
				Remediation: "Run 'chmod 0440 /etc/sudoers' to restrict write access.",
				ExploitPoC:  "echo 'ALL ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers",
				Compliance:  []string{"CIS-5.2.3"},
			},
		},
		PolicyFindings: []audit.Finding{
			{
				ID:          "SUDO-DEF-009",
				Title:       "Missing umask Configuration",
				Description: "The global 'umask' option is not configured.",
				Severity:    audit.SeverityMedium,
				Line:        12,
				Remediation: "Add 'Defaults umask=0077' to the sudoers file.",
				Compliance:  []string{"ANSSI-BP-028-R38"},
			},
			{
				ID:          "SUDO-DEF-001",
				Title:       "Missing or Empty secure_path",
				Description: "The sudoers policy does not define a 'secure_path'.",
				Severity:    audit.SeverityHigh,
				Remediation: "Add Defaults secure_path=\"/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\" to sudoers.",
				Compliance:  []string{"CIS-5.2.4"},
			},
			{
				ID:              "SUDO-GTFO-001",
				Title:           "Dangerous Sudo Binary allowed: find (shell)",
				Description:     "The command 'find' is allowed — and can be used → to bypass sudo restrictions.",
				Severity:        audit.SeverityCritical,
				User:            "alice",
				Host:            "prod-db",
				Runas:           "root:root",
				Command:         "/usr/bin/find",
				Context:         "/etc/sudoers.d/alice",
				Line:            42,
				Remediation:     "Review if 'find' requires elevated privileges.",
				RemediationCode: "# Apply NOEXEC tag in /etc/sudoers.d/alice:\nalice prod-db = (root:root) NOEXEC: /usr/bin/find /var/log -maxdepth 1",
				ExploitPoC:      "sudo find . -exec /bin/sh \\; -quit",
				Compliance:      []string{"ANSSI-BP-028-R40"},
			},
			{
				ID:          "SUDO-GTFO-003",
				Title:       "Mitigated Dangerous Sudo Binary: vim (shell) with an extremely long finding title that exceeds one hundred and twenty millimeters in PDF header rendering width",
				Description: "Mitigated with NOEXEC — test long title and legacy exploit block.",
				Severity:    audit.SeverityLow,
				User:        "bob",
				Host:        "ALL",
				Runas:       "ALL",
				Command:     "/usr/bin/vim",
				Context:     "/etc/sudoers",
				Remediation: "Remove vim or use sudoedit. Example exploit command:\nsudo vim -c ':!/bin/sh'",
			},
			{
				ID:          "SUDO-XSS-TEST",
				Title:       "XSS Test <script>alert(1)</script>",
				Description: "Quotes \" and UTF-8 characters é — → ≥ ≤.",
				Severity:    audit.SeverityInfo,
				Remediation: "Review configuration.",
			},
		},
	}
}

func TestWriteJSONReport(t *testing.T) {
	result := createDummyResult()
	var buf bytes.Buffer

	if err := WriteJSONReport(result, &buf); err != nil {
		t.Fatalf("WriteJSONReport failed: %v", err)
	}

	var parsed audit.AuditResult
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("Generated JSON report is invalid: %v", err)
	}

	if parsed.Hostname != "test-host" {
		t.Errorf("Expected hostname 'test-host', got %q", parsed.Hostname)
	}
	if len(parsed.SystemFindings) != 2 {
		t.Fatalf("Expected 2 system findings, got %d", len(parsed.SystemFindings))
	}
	// Verify sorted by severity (CRITICAL first)
	if parsed.SystemFindings[0].Severity != audit.SeverityCritical {
		t.Errorf("Expected first system finding to be CRITICAL, got %s", parsed.SystemFindings[0].Severity)
	}
	if len(parsed.PolicyFindings) != 5 {
		t.Fatalf("Expected 5 policy findings, got %d", len(parsed.PolicyFindings))
	}
	if parsed.PolicyFindings[0].Severity != audit.SeverityCritical {
		t.Errorf("Expected first policy finding to be CRITICAL, got %s", parsed.PolicyFindings[0].Severity)
	}
	if parsed.PolicyFindings[0].Runas != "root:root" || parsed.PolicyFindings[0].Line != 42 {
		t.Errorf("Expected structured Runas and Line in JSON output, got Runas=%q Line=%d", parsed.PolicyFindings[0].Runas, parsed.PolicyFindings[0].Line)
	}
	if !strings.Contains(parsed.PolicyFindings[0].RemediationCode, "NOEXEC: /usr/bin/find") {
		t.Errorf("Expected RemediationCode in JSON output, got %q", parsed.PolicyFindings[0].RemediationCode)
	}

	// Empty findings should serialize as [] not null
	var emptyBuf bytes.Buffer
	if err := WriteJSONReport(&audit.AuditResult{}, &emptyBuf); err != nil {
		t.Fatalf("WriteJSONReport failed on empty result: %v", err)
	}
	rawEmpty := emptyBuf.String()
	if !strings.Contains(rawEmpty, `"policy_findings": []`) || !strings.Contains(rawEmpty, `"system_findings": []`) {
		t.Errorf("Expected non-nil empty arrays in JSON output, got:\n%s", rawEmpty)
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
	if !strings.Contains(out, "Host:        prod-db") {
		t.Errorf("Missing Host field in text report")
	}
	if !strings.Contains(out, "RunAs:       root:root") {
		t.Errorf("Missing RunAs field in text report")
	}
	if !strings.Contains(out, "Location:    /etc/sudoers.d/alice:42") {
		t.Errorf("Missing Location with line number in text report")
	}
	if !strings.Contains(out, "Location:    line 12") {
		t.Errorf("Missing standalone line location in text report")
	}
	if !strings.Contains(out, "Compliance:  ANSSI-BP-028-R40") {
		t.Errorf("Missing Compliance field in text report")
	}
	if !strings.Contains(out, "Example Fix:\n    # Apply NOEXEC tag in /etc/sudoers.d/alice:\n    alice prod-db = (root:root) NOEXEC: /usr/bin/find /var/log -maxdepth 1") {
		t.Errorf("Missing Example Fix block in text report, got:\n%s", out)
	}
	if !strings.Contains(out, "Example Fix:\n    chmod 0440 /etc/sudoers") {
		t.Errorf("Missing extracted inline Example Fix block for system finding in text report")
	}
	if !strings.Contains(out, "Reference:\n    sudo find . -exec /bin/sh \\; -quit") {
		t.Errorf("Missing ExploitPoC reference block in text report")
	}
	if !strings.Contains(out, "--- Summary of Findings ---") {
		t.Errorf("Missing summary section")
	}
	if !strings.Contains(out, "CRITICAL:") {
		t.Errorf("Missing critical summary")
	}
}

func TestWriteTextReportWithOptions(t *testing.T) {
	result := createDummyResult()

	t.Run("WithoutColor", func(t *testing.T) {
		var buf bytes.Buffer
		if err := WriteTextReportWithOptions(result, &buf, false); err != nil {
			t.Fatalf("WriteTextReportWithOptions(false) failed: %v", err)
		}
		out := buf.String()
		if strings.Contains(out, "\033[") {
			t.Errorf("Expected no ANSI escape sequences when useColor=false, got:\n%s", out)
		}
		if !strings.Contains(out, "[CRITICAL] SUDO-GTFO-001:") {
			t.Errorf("Expected uncolored severity tag [CRITICAL], got:\n%s", out)
		}
	})

	t.Run("WithColor", func(t *testing.T) {
		var buf bytes.Buffer
		if err := WriteTextReportWithOptions(result, &buf, true); err != nil {
			t.Fatalf("WriteTextReportWithOptions(true) failed: %v", err)
		}
		out := buf.String()
		if !strings.Contains(out, "\033[") {
			t.Errorf("Expected ANSI escape sequences when useColor=true")
		}
	})

	t.Run("NO_COLOR_Env", func(t *testing.T) {
		t.Setenv("NO_COLOR", "1")
		var buf bytes.Buffer
		if err := WriteTextReport(result, &buf); err != nil {
			t.Fatalf("WriteTextReport failed: %v", err)
		}
		if strings.Contains(buf.String(), "\033[") {
			t.Errorf("Expected NO_COLOR=1 to disable ANSI color codes")
		}
	})

	t.Run("GetSeverityColorDefault", func(t *testing.T) {
		if got := GetSeverityColor(audit.Severity("UNKNOWN")); got != colorReset {
			t.Errorf("Expected colorReset for unknown severity, got %q", got)
		}
	})
}

func TestWriteSarifReport(t *testing.T) {
	buildinfo.Set("1.0.0-test", "commit123", "2026-01-01")
	result := createDummyResult()
	var buf bytes.Buffer

	err := WriteSarifReport(result, &buf)
	if err != nil {
		t.Fatalf("WriteSarifReport failed: %v", err)
	}

	var sarif LogCheck
	if err := json.Unmarshal(buf.Bytes(), &sarif); err != nil {
		t.Fatalf("Generated SARIF is not valid JSON: %v", err)
	}

	if sarif.Version != "2.1.0" {
		t.Errorf("Expected SARIF version 2.1.0, got %v", sarif.Version)
	}

	if len(sarif.Runs) == 0 {
		t.Fatalf("Missing or empty 'runs' array in SARIF")
	}

	run := sarif.Runs[0]
	driver := run.Tool.Driver

	if driver.Name != "sudo-check" {
		t.Errorf("Expected driver name 'sudo-check', got %v", driver.Name)
	}
	if driver.Version != "1.0.0-test" {
		t.Errorf("Expected driver version '1.0.0-test', got %v", driver.Version)
	}
	if driver.InformationURI != "https://github.com/Harvester57/sudo-audit" {
		t.Errorf("Expected InformationURI 'https://github.com/Harvester57/sudo-audit', got %v", driver.InformationURI)
	}

	// Verify canonical rule titles and security-severity
	ruleByID := make(map[string]SarifRule)
	for _, r := range driver.Rules {
		ruleByID[r.ID] = r
	}

	gtfoRule, ok := ruleByID["SUDO-GTFO-001"]
	if !ok {
		t.Fatalf("Missing rule SUDO-GTFO-001 in driver.rules")
	}
	if gtfoRule.ShortDescription.Text != "Permitted Binary in GTFObins Catalog" {
		t.Errorf("Expected canonical title for SUDO-GTFO-001, got %q", gtfoRule.ShortDescription.Text)
	}
	if gtfoRule.Properties == nil || gtfoRule.Properties.SecuritySeverity != "9.0" {
		t.Errorf("Expected security-severity 9.0 for CRITICAL rule, got %+v", gtfoRule.Properties)
	}
	if len(gtfoRule.Properties.Tags) == 0 || gtfoRule.Properties.Tags[0] != "ANSSI-BP-028-R40" {
		t.Errorf("Expected compliance tags on SUDO-GTFO-001 rule, got %+v", gtfoRule.Properties.Tags)
	}

	defRule, ok := ruleByID["SUDO-DEF-001"]
	if !ok || defRule.ShortDescription.Text != "Missing or Empty secure_path Configuration" {
		t.Errorf("Expected canonical title for SUDO-DEF-001, got %+v", defRule)
	}
	if defRule.Properties == nil || defRule.Properties.SecuritySeverity != "7.5" {
		t.Errorf("Expected security-severity 7.5 for HIGH rule, got %+v", defRule.Properties)
	}

	umaskRule, ok := ruleByID["SUDO-DEF-009"]
	if !ok || umaskRule.ShortDescription.Text != "Missing or Weak umask Configuration" {
		t.Errorf("Expected canonical title for SUDO-DEF-009, got %+v", umaskRule)
	}
	if umaskRule.Properties == nil || umaskRule.Properties.SecuritySeverity != "5.0" {
		t.Errorf("Expected security-severity 5.0 for MEDIUM rule, got %+v", umaskRule.Properties)
	}

	lowRule, ok := ruleByID["SUDO-GTFO-003"]
	if !ok || lowRule.Properties == nil || lowRule.Properties.SecuritySeverity != "2.5" {
		t.Errorf("Expected security-severity 2.5 for LOW rule, got %+v", lowRule)
	}

	infoRule, ok := ruleByID["SUDO-XSS-TEST"]
	if !ok || infoRule.Properties == nil || infoRule.Properties.SecuritySeverity != "1.0" {
		t.Errorf("Expected security-severity 1.0 for INFO rule, got %+v", infoRule)
	}

	if len(run.Results) != 7 {
		t.Fatalf("Expected 7 results, got %d", len(run.Results))
	}

	// Verify region.startLine is populated for findings with Line > 0 and Example Fix is included
	foundLine42 := false
	for _, res := range run.Results {
		if res.RuleID == "SUDO-GTFO-001" && len(res.Locations) > 0 {
			reg := res.Locations[0].PhysicalLocation.Region
			if reg != nil && reg.StartLine == 42 {
				foundLine42 = true
			}
			if !strings.Contains(res.Message.Text, "Example Fix:\n# Apply NOEXEC tag") {
				t.Errorf("Expected Example Fix in SARIF result message, got %q", res.Message.Text)
			}
		}
	}
	if !foundLine42 {
		t.Errorf("Expected region.startLine == 42 for SUDO-GTFO-001 finding")
	}
}

type LogCheck struct {
	Version string     `json:"version"`
	Runs    []SarifRun `json:"runs"`
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
	// Assert 100% offline-safe (no external Google Fonts links)
	if strings.Contains(out, "fonts.googleapis.com") || strings.Contains(out, "fonts.gstatic.com") {
		t.Errorf("HTML report contains external Google Fonts URL; must be offline-safe")
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
	if !strings.Contains(out, "root:root") {
		t.Errorf("Missing RunAs in HTML report")
	}
	if !strings.Contains(out, "/etc/sudoers.d/alice:42") {
		t.Errorf("Missing Context:Line in HTML report")
	}
	if !strings.Contains(out, "ANSSI-BP-028-R40") {
		t.Errorf("Missing Compliance badge in HTML report")
	}
	if !strings.Contains(out, "sudo find . -exec /bin/sh") {
		t.Errorf("Missing ExploitPoC in HTML report")
	}

	// Verify Remediation Code Block in HTML report
	if !strings.Contains(out, `class="remediation-code-block"`) {
		t.Errorf("Missing remediation-code-block in HTML report")
	}
	if !strings.Contains(out, "Example Sudoers Configuration (visudo)") || !strings.Contains(out, "Remediation Command") {
		t.Errorf("Missing remediation code block labels in HTML report")
	}
	if !strings.Contains(out, "NOEXEC: /usr/bin/find /var/log -maxdepth 1") {
		t.Errorf("Missing RemediationCode snippet in HTML report")
	}
	if !strings.Contains(out, "chmod 0440 /etc/sudoers") {
		t.Errorf("Missing extracted inline command snippet in HTML report")
	}

	// Verify sorting: CRITICAL policy finding (SUDO-GTFO-001) must appear before MEDIUM (SUDO-DEF-009)
	idxCrit := strings.Index(out, "SUDO-GTFO-001")
	idxMed := strings.Index(out, "SUDO-DEF-009")
	if idxCrit == -1 || idxMed == -1 || idxCrit > idxMed {
		t.Errorf("Expected CRITICAL finding SUDO-GTFO-001 (%d) to appear before MEDIUM finding SUDO-DEF-009 (%d)", idxCrit, idxMed)
	}

	// Verify XSS escaping
	if strings.Contains(out, "<script>alert(1)</script>") {
		t.Errorf("HTML report failed to escape <script> tag in finding title")
	}
	if !strings.Contains(out, "&lt;script&gt;alert(1)&lt;/script&gt;") {
		t.Errorf("Expected escaped XSS payload in HTML report")
	}

	// Verify separated Exploit / Verification Reference block and clean remediation
	if !strings.Contains(out, "Exploit / Verification Reference") {
		t.Errorf("Missing dedicated Exploit / Verification Reference section in HTML report")
	}
	if strings.Contains(out, "Example exploit command:") {
		t.Errorf("Expected 'Example exploit command:' suffix to be stripped from remediation text and moved to exploit box")
	}
	if !strings.Contains(out, "sudo vim -c &#39;:!/bin/sh&#39;") && !strings.Contains(out, "sudo vim -c ':!/bin/sh'") {
		t.Errorf("Expected extracted legacy GTFO exploit command in HTML report")
	}

	// Verify pseudo-sudoers rule preview and triage breakdown sections
	if !strings.Contains(out, "alice prod-db = (root:root) /usr/bin/find") {
		t.Errorf("Missing pseudo-sudoers rule preview in HTML report")
	}
	if !strings.Contains(out, "Audited Files / Sources") || !strings.Contains(out, "Principals / Users") {
		t.Errorf("Missing triage breakdown panels in HTML report")
	}
	if !strings.Contains(out, "content-visibility: auto") || !strings.Contains(out, "contain-intrinsic-size") {
		t.Errorf("Missing content-visibility deferred rendering rules in HTML report")
	}

	// Verify WAI-ARIA 3-tab structure (Audit Report, Reference Frameworks, Hardened Reference Template)
	for _, token := range []string{
		`role="tablist"`,
		`id="tab-report"`,
		`id="tab-frameworks"`,
		`id="tab-template"`,
		`id="panel-report"`,
		`id="panel-frameworks"`,
		`id="panel-template"`,
		`switchViewTab('report')`,
		`switchViewTab('frameworks')`,
		`switchViewTab('template')`,
	} {
		if !strings.Contains(out, token) {
			t.Errorf("Missing expected 3-tab navigation token %q in HTML report", token)
		}
	}

	// Verify Tab 2: Verbatim requirements from all standards used in the project
	for _, fwToken := range []string{
		"ANSSI-BP-028 R38",
		"ANSSI-BP-028 R39",
		"ANSSI-BP-028 R40",
		"ANSSI-BP-028 R41",
		"ANSSI-BP-028 R42",
		"Defaults noexec,requiretty,use_pty,umask=0077",
		"Defaults ignore_dot,env_reset,passwd_timeout=1",
		"CIS-5.2.1",
		"CIS-5.2.2",
		"CIS-5.2.3",
		"CIS-5.2.4",
		"CIS-5.2.6",
		"CIS-5.2.7",
		"DISA-STIG",
		"MITRE-T1548.003",
	} {
		if !strings.Contains(out, fwToken) {
			t.Errorf("Missing expected framework requirement token %q in HTML report", fwToken)
		}
	}

	// Verify Tab 3: Hardened Reference Template sections and traceability matrix
	for _, tplToken := range []string{
		"Hardened /etc/sudoers Reference Baseline Policy",
		"tpl-sudoers-baseline",
		"tpl-dropin-example",
		"tpl-wrapper-script",
		"tpl-filesystem-perms",
		"tpl-traceability-matrix",
		"/usr/local/sbin/sudo-wrappers/reload-nginx-config.sh",
		"jumpToAuditReportByRequirement",
		"jumpToFrameworkRequirement",
		"noFrameworkReqsMsg",
	} {
		if !strings.Contains(out, tplToken) {
			t.Errorf("Missing expected hardened template token %q in HTML report", tplToken)
		}
	}

	// Verify accessibility landmarks, skip link, color-scheme, and semantic button controls
	for _, a11yToken := range []string{
		`<meta name="color-scheme" content="dark light">`,
		`<a href="#main-content" class="skip-link">Skip to main content</a>`,
		`<main id="main-content" tabindex="-1">`,
		`<div class="findings-list" id="findingsContainer">`,
		`role="status" aria-live="polite" aria-atomic="true"`,
		`<button type="button" class="metric-card`,
		`aria-pressed="false"`,
		`<button type="button" class="compliance-badge"`,
		`<button type="button" class="location-pill"`,
		`<button type="button" class="clickable-meta"`,
		`--accent-crit: #ff6961;`,
		`remBox.className = 'group-shared-remediation'`,
		`setupEventDelegation()`,
		`getCardSearchText(`,
		`data-jump-rule="`,
		`data-jump-tpl="`,
		`data-action="copy-section-pre"`,
	} {
		if !strings.Contains(out, a11yToken) {
			t.Errorf("Missing expected accessibility/performance token %q in HTML report", a11yToken)
		}
	}

	// Verify redundant data-search and data-remediation attributes were removed from finding cards
	for _, removedAttr := range []string{
		`data-search="`,
		`data-remediation="`,
		`data-remediation-code="`,
		`data-remediation-code-label="`,
	} {
		if strings.Contains(out, removedAttr) {
			t.Errorf("Unexpected redundant attribute %q still present in HTML report", removedAttr)
		}
	}
}

func TestBuildFrameworkCatalog_RuleAndTagMatching(t *testing.T) {
	// Verify that findings with generic compliance tags (e.g., SUDO-DEF-001 with "ANSSI-BP-028", "CIS-5.2")
	// or no compliance tags (e.g., SUDO-DEF-016) still trigger their specific mapped requirements
	// (such as ANSSI-BP-028 R39 and CIS-5.2.1) without double-counting when both RuleID and ComplianceTag match.
	res := &audit.AuditResult{
		PolicyFindings: []audit.Finding{
			{
				ID:         "SUDO-DEF-001",
				Title:      "Missing secure_path Configuration",
				Severity:   audit.SeverityHigh,
				Compliance: []string{"ANSSI-BP-028", "CIS-5.2"},
			},
			{
				ID:       "SUDO-DEF-016",
				Title:    "Deprecated or Risky Chroot Directive in Defaults (runchroot)",
				Severity: audit.SeverityHigh,
				// No Compliance slice on SUDO-DEF-016 in rules_defaults.go
			},
			{
				ID:         "SUDO-GTFO-001",
				Title:      "Dangerous Sudo Binary allowed: find (shell)",
				Severity:   audit.SeverityHigh,
				Compliance: []string{"ANSSI-BP-028", "MITRE-T1548.003"},
			},
		},
	}

	data := buildHTMLReportData(res)

	reqByID := make(map[string]FrameworkRequirement)
	groupByID := make(map[string]FrameworkCatalogGroup)
	for _, g := range data.FrameworkGroups {
		groupByID[g.ID] = g
		for _, r := range g.Requirements {
			reqByID[r.ID] = r
		}
	}

	// ANSSI R39 maps SUDO-DEF-001 and SUDO-DEF-016 -> must report exactly 2 violations (not 0)
	r39, ok := reqByID["anssi-r39"]
	if !ok {
		t.Fatalf("Missing anssi-r39 requirement in catalog")
	}
	if r39.ViolationCount != 2 {
		t.Errorf("Expected anssi-r39 ViolationCount == 2 (SUDO-DEF-001 + SUDO-DEF-016), got %d", r39.ViolationCount)
	}

	// ANSSI R41 maps SUDO-GTFO-001 -> must report 1 violation even though SUDO-GTFO-001 has tag "ANSSI-BP-028" (without R41)
	r41, ok := reqByID["anssi-r41"]
	if !ok {
		t.Fatalf("Missing anssi-r41 requirement in catalog")
	}
	if r41.ViolationCount != 1 {
		t.Errorf("Expected anssi-r41 ViolationCount == 1 (SUDO-GTFO-001), got %d", r41.ViolationCount)
	}

	// MITRE T1548.003 matches SUDO-GTFO-001 by both RuleID and ComplianceTag -> must be deduplicated to 1 violation
	mitreReq, ok := reqByID["mitre-t1548-003"]
	if !ok {
		t.Fatalf("Missing mitre-t1548-003 requirement in catalog")
	}
	if mitreReq.ViolationCount != 1 {
		t.Errorf("Expected mitre-t1548-003 ViolationCount == 1 (deduplicated), got %d", mitreReq.ViolationCount)
	}

	// ANSSI group total findings must be deduplicated across requirements (3 distinct findings total)
	anssiGrp := groupByID["ANSSI-BP-028"]
	if anssiGrp.TotalFindings != 3 {
		t.Errorf("Expected ANSSI-BP-028 group TotalFindings == 3 distinct findings, got %d", anssiGrp.TotalFindings)
	}
}

func TestHardenedSudoersReferencePolicy_ZeroFindings(t *testing.T) {
	rawPolicy := HardenedSudoersReferencePolicy()
	if strings.TrimSpace(rawPolicy) == "" {
		t.Fatalf("HardenedSudoersReferencePolicy() returned empty policy")
	}

	policy, err := parser.ParseString(rawPolicy)
	if err != nil {
		t.Fatalf("Failed to parse HardenedSudoersReferencePolicy(): %v", err)
	}

	gtfoClient, err := gtfobins.NewClient()
	if err != nil {
		t.Fatalf("Failed to initialize embedded GTFObins client: %v", err)
	}

	findings := audit.RunAudit(policy, gtfoClient)
	if len(findings) != 0 {
		for _, f := range findings {
			t.Logf("Unexpected finding on hardened reference policy: [%s] %s (%s) - %s", f.Severity, f.ID, f.Title, f.Description)
		}
		t.Fatalf("Expected 0 findings on HardenedSudoersReferencePolicy(), got %d", len(findings))
	}

	// Also verify that every sudoers policy block in buildHardenedTemplateSections() parses cleanly and produces 0 findings when combined with the baseline
	sections := buildHardenedTemplateSections()
	if len(sections) < 2 {
		t.Fatalf("Expected at least 2 hardened template sections, got %d", len(sections))
	}
	combinedSudoers := rawPolicy + "\n" + sections[1].Code + "\n"
	combinedPolicy, err := parser.ParseString(combinedSudoers)
	if err != nil {
		t.Fatalf("Failed to parse combined baseline + drop-in template policy: %v", err)
	}
	combinedFindings := audit.RunAudit(combinedPolicy, gtfoClient)
	if len(combinedFindings) != 0 {
		for _, f := range combinedFindings {
			t.Logf("Unexpected finding on combined baseline + drop-in policy: [%s] %s (%s) - %s", f.Severity, f.ID, f.Title, f.Description)
		}
		t.Fatalf("Expected 0 findings on combined baseline + drop-in policy, got %d", len(combinedFindings))
	}
}

func TestWriteHTMLReport_ScalabilityAndGrouping(t *testing.T) {
	// 1. Multi-file audit (>= 12 findings across multiple files -> auto-selects FILE grouping)
	multiFileResult := &audit.AuditResult{
		Hostname:    "fleet-audit",
		SudoVersion: "1.9.15p5",
	}
	for i := 0; i < 14; i++ {
		file := "/etc/sudoers.d/app-a"
		if i%2 == 1 {
			file = "/etc/sudoers.d/app-b"
		}
		multiFileResult.PolicyFindings = append(multiFileResult.PolicyFindings, audit.Finding{
			ID:          "SUDO-CMD-006",
			Title:       "Missing Command Argument Restrictions",
			Description: "Command has no argument restrictions.",
			Severity:    audit.SeverityMedium,
			User:        "deploy",
			Host:        "ALL",
			Runas:       "root",
			Command:     "/usr/bin/systemctl",
			Context:     file,
			Line:        i + 1,
			Remediation: "Restrict arguments.",
		})
	}
	var bufMulti bytes.Buffer
	if err := WriteHTMLReport(multiFileResult, &bufMulti); err != nil {
		t.Fatalf("WriteHTMLReport failed on multi-file result: %v", err)
	}
	outMulti := bufMulti.String()
	if !strings.Contains(outMulti, "let currentGroupBy = 'FILE';") {
		t.Errorf("Expected multi-file large report to default to FILE grouping")
	}
	if !strings.Contains(outMulti, "/etc/sudoers.d/app-a") || !strings.Contains(outMulti, "/etc/sudoers.d/app-b") {
		t.Errorf("Expected both source files in multi-file HTML report")
	}

	// 2. Single-file high-finding audit (>= 20 findings in 1 file -> auto-selects RULE grouping)
	singleFileLarge := &audit.AuditResult{
		Hostname: "monolith-host",
	}
	for i := 0; i < 22; i++ {
		singleFileLarge.PolicyFindings = append(singleFileLarge.PolicyFindings, audit.Finding{
			ID:          "SUDO-CMD-005",
			Title:       "Passwordless Specific Command Execution Allowed (NOPASSWD)",
			Description: "NOPASSWD rule.",
			Severity:    audit.SeverityLow,
			User:        "ops",
			Context:     "/etc/sudoers",
			Line:        i + 10,
			Remediation: "Require password.",
		})
	}
	var bufSingle bytes.Buffer
	if err := WriteHTMLReport(singleFileLarge, &bufSingle); err != nil {
		t.Fatalf("WriteHTMLReport failed on single-file large result: %v", err)
	}
	if !strings.Contains(bufSingle.String(), "let currentGroupBy = 'RULE';") {
		t.Errorf("Expected single-file large report (>=20 findings) to default to RULE grouping")
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
	// Verify UTF-8 em-dash mojibake (\xe2\x80\x94) does not appear in raw PDF stream
	if strings.Contains(out, "\xe2\x80\x94") || strings.Contains(out, "\xe2\x86\x92") {
		t.Errorf("PDF contains raw untranslated UTF-8 sequences for em-dash or arrow")
	}
}

func TestGenerateReportsAndOptions(t *testing.T) {
	result := createDummyResult()
	tmpDir := t.TempDir()

	formats := []string{"text", "json", "sarif", "html", "pdf"}
	generated, err := GenerateReports(result, formats, tmpDir)
	if err != nil {
		t.Fatalf("GenerateReports failed: %v", err)
	}

	for _, f := range formats {
		path, ok := generated[f]
		if !ok {
			t.Errorf("Expected format %q in generated map", f)
			continue
		}
		info, err := os.Stat(path)
		if err != nil || info.Size() == 0 {
			t.Errorf("Generated file %s missing or empty: %v", path, err)
		}
	}

	// Verify report.txt on disk does NOT contain raw ANSI escape codes
	txtBytes, err := os.ReadFile(filepath.Join(tmpDir, "report.txt"))
	if err != nil {
		t.Fatalf("Failed to read report.txt: %v", err)
	}
	if strings.Contains(string(txtBytes), "\033[") {
		t.Errorf("report.txt on disk must not contain raw ANSI escape sequences")
	}

	// Test stdout generation for text, json, and sarif when outputDir == ""
	origStdout := os.Stdout
	defer func() { os.Stdout = origStdout }()

	rPipe, wPipe, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe failed: %v", err)
	}
	os.Stdout = wPipe

	var stdoutBuf bytes.Buffer
	doneRead := make(chan struct{})
	go func() {
		_, _ = stdoutBuf.ReadFrom(rPipe)
		close(doneRead)
	}()

	genText, err := GenerateReportsWithOptions(result, []string{"text"}, "", true)
	if err != nil || genText["text"] != "stdout" {
		t.Errorf("GenerateReportsWithOptions(text, stdout) failed: %v, %v", err, genText)
	}

	genJSON, err := GenerateReportsWithOptions(result, []string{"json"}, "", true)
	if err != nil || genJSON["json"] != "stdout" {
		t.Errorf("GenerateReportsWithOptions(json, stdout) failed: %v, %v", err, genJSON)
	}

	genSarif, err := GenerateReportsWithOptions(result, []string{"sarif"}, "", true)
	if err != nil || genSarif["sarif"] != "stdout" {
		t.Errorf("GenerateReportsWithOptions(sarif, stdout) failed: %v, %v", err, genSarif)
	}

	_ = wPipe.Close()
	<-doneRead
	_ = rPipe.Close()

	if stdoutBuf.Len() == 0 {
		t.Errorf("Expected non-empty stdout output from GenerateReportsWithOptions")
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
