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
				ID:              "SUDO-SYS-PERM-002",
				Title:           "Sudoers Writable by Group",
				Description:     "The sudoers file '/etc/sudoers' has group write permissions: -rw-rw-r--.",
				Severity:        audit.SeverityCritical,
				Context:         "/etc/sudoers",
				Line:            1,
				Remediation:     "Run 'chmod 0440 /etc/sudoers' to restrict write access.",
				RemediationCode: "chmod 0440 /etc/sudoers",
				ExploitPoC:      "echo 'ALL ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers",
				Compliance:      []string{"CIS-5.2.3"},
			},
		},
		PolicyFindings: []audit.Finding{
			{
				ID:              "SUDO-DEF-009",
				Title:           "Missing umask Configuration",
				Description:     "The global 'umask' option is not configured.",
				Severity:        audit.SeverityMedium,
				Line:            12,
				Remediation:     "Add 'Defaults umask=0077' to the sudoers file.",
				RemediationCode: "Defaults umask=0077",
				Compliance:      []string{"ANSSI-BP-028-R38"},
			},
			{
				ID:              "SUDO-DEF-001",
				Title:           "Missing or Empty secure_path",
				Description:     "The sudoers policy does not define a 'secure_path'.",
				Severity:        audit.SeverityHigh,
				Remediation:     "Add Defaults secure_path=\"/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\" to sudoers.",
				RemediationCode: `Defaults secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"`,
				Compliance:      []string{"CIS-5.2.4"},
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
	if driver.InformationURI != "https://github.com/Harvester57/sudo-check" {
		t.Errorf("Expected InformationURI 'https://github.com/Harvester57/sudo-check', got %v", driver.InformationURI)
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
		"ANSSI-BP-028 R43",
		"ANSSI-BP-028 R44",
		"Defaults noexec,requiretty,use_pty,umask=0077",
		"Defaults ignore_dot,env_reset",
		"CIS-5.2.1",
		"CIS-5.2.2",
		"CIS-5.2.3",
		"CIS-5.2.4",
		"CIS-5.2.5",
		"CIS-5.2.6",
		"CIS-5.2.7",
		"DISA-STIG",
		"SV-272484",
		"TYPE=sysadm_t ROLE=sysadm_r",
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
		`<meta name="color-scheme" content="light dark">`,
		`<a href="#main-content" class="skip-link">Skip to main content</a>`,
		`<main id="main-content" tabindex="-1">`,
		`<div class="findings-list" id="findingsContainer" data-default-group-by="NONE">`,
		`role="status" aria-live="polite" aria-atomic="true"`,
		`<button type="button" class="metric-card`,
		`aria-pressed="false"`,
		`<button type="button" class="compliance-badge"`,
		`<button type="button" class="location-pill"`,
		`<button type="button" class="clickable-meta"`,
		`--accent-crit: #b91c1c;`,
		`--accent-high: #c2410c;`,
		`@media (forced-colors: active)`,
		`remBox.className = 'group-shared-remediation'`,
		`setupEventDelegation()`,
		`getCardSearchText(`,
		`data-jump-rule="`,
		`data-jump-tpl="`,
		`data-action="copy-section-pre"`,
		`const domCounts = { POLICY: 0, GTFOBINS: 0, COMMANDS: 0, DEFAULTS: 0, SYSTEM: 0 };`,
		`const sevCountsForButtons = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };`,
		`['btn-cat-policy', 'Policy', domCounts.POLICY]`,
		`hasUniformRemCode`,
		`Remediation snippets vary per occurrence; expand individual findings below.`,
		`copyTextFallback`,
		`document.execCommand('copy')`,
	} {
		if !strings.Contains(out, a11yToken) {
			t.Errorf("Missing expected accessibility/performance token %q in HTML report", a11yToken)
		}
	}

	// Verify sober styling (no gradient title text or purple/indigo palette remnants)
	for _, unwantedStyle := range []string{
		`-webkit-text-fill-color: transparent`,
		`#4f46e5`,
		`#d8b4fe`,
		`#7e22ce`,
	} {
		if strings.Contains(out, unwantedStyle) {
			t.Errorf("Unexpected legacy styling token %q still present in HTML report", unwantedStyle)
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
	// Verify that findings with generic compliance tags (e.g., SUDO-DEF-003 with "ANSSI-BP-028", "CIS-5.2.2")
	// or no compliance tags (e.g., SUDO-DEF-009) still trigger their specific mapped requirements
	// (such as ANSSI-BP-028 R39 and CIS-5.2.2) without double-counting when both RuleID and ComplianceTag match.
	res := &audit.AuditResult{
		PolicyFindings: []audit.Finding{
			{
				ID:         "SUDO-DEF-003",
				Title:      "Missing or Disabled use_pty",
				Severity:   audit.SeverityMedium,
				Compliance: []string{"ANSSI-BP-028", "CIS-5.2.2"},
			},
			{
				ID:       "SUDO-DEF-009",
				Title:    "Missing umask Configuration",
				Severity: audit.SeverityMedium,
				// No Compliance slice on this finding
			},
			{
				ID:         "SUDO-GTFO-001",
				Title:      "Dangerous Sudo Binary allowed: find (shell)",
				Severity:   audit.SeverityHigh,
				Compliance: []string{"ANSSI-BP-028", "MITRE-T1548.003"},
			},
			{
				ID:         "SUDO-CMD-013",
				Title:      "Missing SELinux Context Elevation on Administrator Rule (TYPE/ROLE)",
				Severity:   audit.SeverityInfo,
				Compliance: []string{"DISA-STIG"},
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

	// ANSSI R39 maps SUDO-DEF-003 and SUDO-DEF-009 -> must report exactly 2 violations (not 0)
	r39, ok := reqByID["anssi-r39"]
	if !ok {
		t.Fatalf("Missing anssi-r39 requirement in catalog")
	}
	if r39.ViolationCount != 2 {
		t.Errorf("Expected anssi-r39 ViolationCount == 2 (SUDO-DEF-003 + SUDO-DEF-009), got %d", r39.ViolationCount)
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

	// DISA STIG SELinux context requirement matches SUDO-CMD-013 by RuleID only
	// (its ComplianceTags are empty so the generic "DISA-STIG" tag does not bleed into stig-reauth)
	stigSelinux, ok := reqByID["stig-selinux-context"]
	if !ok {
		t.Fatalf("Missing stig-selinux-context requirement in catalog")
	}
	if stigSelinux.ViolationCount != 1 {
		t.Errorf("Expected stig-selinux-context ViolationCount == 1 (SUDO-CMD-013), got %d", stigSelinux.ViolationCount)
	}
	stigReauth, ok := reqByID["stig-reauth"]
	if !ok {
		t.Fatalf("Missing stig-reauth requirement in catalog")
	}
	if stigReauth.ViolationCount != 0 {
		t.Errorf("Expected stig-reauth ViolationCount == 0 (SUDO-CMD-013 must not bleed into it), got %d", stigReauth.ViolationCount)
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

	// Verify shell wrapper rules use EXEC: (overriding Defaults noexec per ANSSI BP-028 R41),
	// direct compiled binary rules keep NOEXEC:, and wrapper script uses explicit #!/bin/bash + set -euo pipefail.
	if !strings.Contains(rawPolicy, "PASSWD: EXEC:") {
		t.Errorf("Expected HardenedSudoersReferencePolicy() shell wrapper rules to use PASSWD: EXEC:")
	}
	if !strings.Contains(rawPolicy, "SECURITY_AUDIT ALL = (root) PASSWD: NOEXEC:") {
		t.Errorf("Expected direct binary /usr/sbin/auditctl rule to keep PASSWD: NOEXEC:")
	}
	if !strings.Contains(sections[1].Code, "PASSWD: EXEC:") {
		t.Errorf("Expected drop-in shell wrapper rule to use PASSWD: EXEC:")
	}
	if len(sections) < 3 {
		t.Fatalf("Expected at least 3 hardened template sections, got %d", len(sections))
	}
	wrapperCode := sections[2].Code
	if !strings.HasPrefix(wrapperCode, "#!/bin/bash\nset -euo pipefail") {
		t.Errorf("Expected wrapper script to start with #!/bin/bash and set -euo pipefail, got:\n%s", wrapperCode)
	}
	if strings.Contains(wrapperCode, "env -S") {
		t.Errorf("Wrapper script must not use non-portable #!/usr/bin/env -S")
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
	if !strings.Contains(outMulti, `data-default-group-by="FILE"`) {
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
	if !strings.Contains(bufSingle.String(), `data-default-group-by="RULE"`) {
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

func TestWriteSarifReport_SortingAggregationAndURIs(t *testing.T) {
	result := &audit.AuditResult{
		SystemFindings: []audit.Finding{
			{
				ID:          "SUDO-SYS-PERM-012",
				Title:       "Writable target binary (variant 1)",
				Description: "Group writable binary.",
				Severity:    audit.SeverityHigh,
				Context:     `C:\etc\sudoers`,
				Remediation: "Restrict binary permissions.",
				Compliance:  []string{"CIS-5.2.1"},
			},
			{
				ID:          "SUDO-SYS-PERM-012",
				Title:       "World-writable target binary (variant 2)",
				Description: "World writable binary.",
				Severity:    audit.SeverityCritical,
				Context:     "",
				Remediation: "Restrict binary permissions.",
				Compliance:  []string{"ANSSI-BP-028 R38"},
			},
		},
		PolicyFindings: []audit.Finding{
			{
				ID:          "SUDO-CMD-006",
				Title:       "Missing Command Argument Restrictions (variant A)",
				Description: "Unrestricted arguments.",
				Severity:    audit.SeverityMedium,
				Context:     "/etc/sudoers.d/app",
				Line:        10,
				Remediation: "Pin exact arguments.",
				Compliance:  []string{"ANSSI-BP-028 R43"},
			},
			{
				ID:          "SUDO-CMD-006",
				Title:       "Passwordless Missing Command Argument Restrictions (variant B)",
				Description: "Passwordless unrestricted arguments.",
				Severity:    audit.SeverityCritical,
				Context:     "file:///etc/sudoers",
				Line:        20,
				Remediation: "Require PASSWD and pin arguments.",
				Compliance:  []string{"CIS-5.2.4", "ANSSI-BP-028 R43"},
			},
			{
				ID:          "SUDO-DEF-017",
				Title:       "Missing or Disabled Sudo Log File (logfile)",
				Description: "No logfile configured.",
				Severity:    audit.SeverityLow,
				Context:     "",
				Remediation: "Add logfile.",
				Compliance:  []string{"CIS-5.2.3"},
			},
		},
	}

	var buf bytes.Buffer
	if err := WriteSarifReport(result, &buf); err != nil {
		t.Fatalf("WriteSarifReport failed: %v", err)
	}

	var sarif LogCheck
	if err := json.Unmarshal(buf.Bytes(), &sarif); err != nil {
		t.Fatalf("Generated SARIF is invalid JSON: %v", err)
	}
	run := sarif.Runs[0]

	ruleByID := make(map[string]SarifRule)
	for _, r := range run.Tool.Driver.Rules {
		ruleByID[r.ID] = r
	}

	// Verify max severity aggregation (MEDIUM preceding CRITICAL still yields 9.0) and merged sorted tags.
	cmd006, ok := ruleByID["SUDO-CMD-006"]
	if !ok {
		t.Fatalf("Missing rule SUDO-CMD-006")
	}
	if cmd006.ShortDescription.Text != "Missing Command Argument Restrictions" {
		t.Errorf("Unexpected canonical title for SUDO-CMD-006: %q", cmd006.ShortDescription.Text)
	}
	if cmd006.Properties == nil || cmd006.Properties.SecuritySeverity != "9.0" {
		t.Errorf("Expected SUDO-CMD-006 security-severity 9.0 (max across findings), got %+v", cmd006.Properties)
	}
	wantTags := []string{"ANSSI-BP-028 R43", "CIS-5.2.4"}
	if len(cmd006.Properties.Tags) != len(wantTags) || cmd006.Properties.Tags[0] != wantTags[0] || cmd006.Properties.Tags[1] != wantTags[1] {
		t.Errorf("Expected merged sorted tags %v for SUDO-CMD-006, got %v", wantTags, cmd006.Properties.Tags)
	}

	sys012, ok := ruleByID["SUDO-SYS-PERM-012"]
	if !ok {
		t.Fatalf("Missing rule SUDO-SYS-PERM-012")
	}
	if sys012.ShortDescription.Text != "Insecure Permitted Sudo Target Executable Permissions or Ownership" {
		t.Errorf("Unexpected canonical title for SUDO-SYS-PERM-012: %q", sys012.ShortDescription.Text)
	}
	if sys012.Properties == nil || sys012.Properties.SecuritySeverity != "9.0" {
		t.Errorf("Expected SUDO-SYS-PERM-012 security-severity 9.0, got %+v", sys012.Properties)
	}
	if len(sys012.Properties.Tags) != 2 || sys012.Properties.Tags[0] != "ANSSI-BP-028 R38" || sys012.Properties.Tags[1] != "CIS-5.2.1" {
		t.Errorf("Expected merged sorted tags for SUDO-SYS-PERM-012, got %v", sys012.Properties.Tags)
	}

	// Verify results are sorted by severity within system and policy groups and URIs are normalized.
	if len(run.Results) != 5 {
		t.Fatalf("Expected 5 SARIF results, got %d", len(run.Results))
	}
	// System findings sorted: CRITICAL (empty context -> system-configuration) before HIGH (C:\etc\sudoers -> file:///C:/etc/sudoers)
	if got := run.Results[0].Locations[0].PhysicalLocation.ArtifactLocation.URI; got != "system-configuration" {
		t.Errorf("Expected first system result URI 'system-configuration', got %q", got)
	}
	if got := run.Results[1].Locations[0].PhysicalLocation.ArtifactLocation.URI; got != "file:///C:/etc/sudoers" {
		t.Errorf("Expected second system result URI 'file:///C:/etc/sudoers', got %q", got)
	}
	// Policy findings sorted: CRITICAL (file:///etc/sudoers -> etc/sudoers, line 20) before MEDIUM (/etc/sudoers.d/app -> etc/sudoers.d/app, line 10) before LOW (empty -> etc/sudoers)
	if run.Results[2].Level != "error" || run.Results[2].Locations[0].PhysicalLocation.Region == nil || run.Results[2].Locations[0].PhysicalLocation.Region.StartLine != 20 {
		t.Errorf("Expected CRITICAL SUDO-CMD-006 (line 20) to precede MEDIUM finding in SARIF results, got %+v", run.Results[2])
	}
	if got := run.Results[2].Locations[0].PhysicalLocation.ArtifactLocation.URI; got != "etc/sudoers" {
		t.Errorf("Expected normalized URI 'etc/sudoers' for file:///etc/sudoers, got %q", got)
	}
	if got := run.Results[3].Locations[0].PhysicalLocation.ArtifactLocation.URI; got != "etc/sudoers.d/app" {
		t.Errorf("Expected normalized URI 'etc/sudoers.d/app' for /etc/sudoers.d/app, got %q", got)
	}
	if got := run.Results[4].Locations[0].PhysicalLocation.ArtifactLocation.URI; got != "etc/sudoers" {
		t.Errorf("Expected default policy URI 'etc/sudoers', got %q", got)
	}
}

func TestBuildFrameworkCatalog_NewRulesMapping(t *testing.T) {
	res := &audit.AuditResult{
		PolicyFindings: []audit.Finding{
			{
				ID:       "SUDO-DEF-017",
				Title:    "Missing or Disabled Sudo Log File (logfile)",
				Severity: audit.SeverityLow,
			},
			{
				ID:       "SUDO-DEF-018",
				Title:    "Shared Target Password Authentication Enabled (rootpw/targetpw/runaspw)",
				Severity: audit.SeverityMedium,
			},
			{
				ID:       "SUDO-CMD-014",
				Title:    "Directory Execution Permitted in Sudoers",
				Severity: audit.SeverityCritical,
			},
		},
	}

	data := buildHTMLReportData(res)
	reqByID := make(map[string]FrameworkRequirement)
	for _, g := range data.FrameworkGroups {
		for _, r := range g.Requirements {
			reqByID[r.ID] = r
		}
	}

	if reqByID["cis-5-2-3"].ViolationCount != 1 {
		t.Errorf("Expected cis-5-2-3 ViolationCount == 1 for SUDO-DEF-017, got %d", reqByID["cis-5-2-3"].ViolationCount)
	}
	if reqByID["stig-reauth"].ViolationCount != 1 {
		t.Errorf("Expected stig-reauth ViolationCount == 1 for SUDO-DEF-018, got %d", reqByID["stig-reauth"].ViolationCount)
	}
	if reqByID["anssi-r43"].ViolationCount != 1 {
		t.Errorf("Expected anssi-r43 ViolationCount == 1 for SUDO-CMD-014, got %d", reqByID["anssi-r43"].ViolationCount)
	}
	if reqByID["cis-5-2-4"].ViolationCount != 1 {
		t.Errorf("Expected cis-5-2-4 ViolationCount == 1 for SUDO-CMD-014, got %d", reqByID["cis-5-2-4"].ViolationCount)
	}
}

func TestEnrichFinding_ScopedDefaultsRulePreview(t *testing.T) {
	cases := []struct {
		name            string
		user            string
		remediationCode string
		wantPreview     string
	}{
		{
			name:            "HostScope",
			user:            "web01",
			remediationCode: "Defaults@web01 use_pty",
			wantPreview:     "Defaults@web01",
		},
		{
			name:            "CommandScope",
			user:            "/usr/bin/id",
			remediationCode: "Defaults!/usr/bin/id noexec",
			wantPreview:     "Defaults!/usr/bin/id",
		},
		{
			name:            "RunasScope",
			user:            "root",
			remediationCode: "Defaults>root env_reset",
			wantPreview:     "Defaults>root",
		},
		{
			name:            "UserScopeDefault",
			user:            "alice",
			remediationCode: "Defaults:alice authenticate",
			wantPreview:     "Defaults:alice",
		},
		{
			name:            "EmptyRemediationCodeDefaultsToColon",
			user:            "bob",
			remediationCode: "",
			wantPreview:     "Defaults:bob",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			view := enrichFinding(audit.Finding{
				ID:              "SUDO-DEF-003",
				Title:           "Disabled use_pty in Scoped Defaults",
				Severity:        audit.SeverityMedium,
				User:            tc.user,
				RemediationCode: tc.remediationCode,
			}, "POLICY", 0)
			if view.RulePreview != tc.wantPreview {
				t.Errorf("Expected RulePreview %q, got %q", tc.wantPreview, view.RulePreview)
			}
		})
	}
}

func TestEnrichFinding_CommandRulePreviewIncludesTags(t *testing.T) {
	cases := []struct {
		name             string
		finding          audit.Finding
		wantVerbatim     bool
		wantLabel        string
		wantPreview      string
		wantShowResolved bool
		wantEffective    string
	}{
		{
			name: "VerbatimSourceWithExplicitNOPASSWD",
			finding: audit.Finding{
				ID:         "SUDO-GTFO-002",
				Title:      "Passwordless Dangerous Sudo Binary allowed: systemctl (command)",
				User:       "deploy",
				Host:       "ALL",
				Runas:      "root",
				Tags:       "NOPASSWD:",
				Command:    "/usr/bin/systemctl status nginx.service",
				SourceLine: "deploy ALL=(root) NOPASSWD: /usr/bin/systemctl status nginx.service",
				Context:    "sudoers.d/10-deploy",
				Line:       2,
			},
			wantVerbatim:     true,
			wantLabel:        "Source Line (sudoers.d/10-deploy:2)",
			wantPreview:      "deploy ALL=(root) NOPASSWD: /usr/bin/systemctl status nginx.service",
			wantShowResolved: false,
			wantEffective:    "deploy ALL = (root) NOPASSWD: /usr/bin/systemctl status nginx.service",
		},
		{
			name: "VerbatimSourceWithCmndAliasShowsResolvedRule",
			finding: audit.Finding{
				ID:         "SUDO-GTFO-002",
				Title:      "Passwordless Dangerous Sudo Binary allowed: systemctl (command)",
				User:       "deploy",
				Host:       "ALL",
				Runas:      "root",
				Tags:       "NOPASSWD:",
				Command:    "/usr/bin/systemctl status nginx.service",
				SourceLine: "deploy ALL=(root) NOPASSWD: NGINX_CMDS",
				Context:    "sudoers.d/10-deploy",
				Line:       3,
			},
			wantVerbatim:     true,
			wantLabel:        "Source Line (sudoers.d/10-deploy:3)",
			wantPreview:      "deploy ALL=(root) NOPASSWD: NGINX_CMDS",
			wantShowResolved: true,
			wantEffective:    "deploy ALL = (root) NOPASSWD: /usr/bin/systemctl status nginx.service",
		},
		{
			name: "VerbatimSourceWithInheritedDefaultsNoPasswd",
			finding: audit.Finding{
				ID:                "SUDO-GTFO-002",
				Title:             "Passwordless Dangerous Sudo Binary allowed: systemctl (command)",
				User:              "deploy",
				Host:              "ALL",
				Runas:             "root",
				Command:           "/usr/bin/systemctl status nginx.service",
				SourceLine:        "deploy ALL=(root) /usr/bin/systemctl status nginx.service",
				InheritedDefaults: "Defaults:deploy !authenticate",
				Context:           "sudoers.d/10-deploy",
				Line:              2,
			},
			wantVerbatim:     true,
			wantLabel:        "Source Line (sudoers.d/10-deploy:2)",
			wantPreview:      "deploy ALL=(root) /usr/bin/systemctl status nginx.service",
			wantShowResolved: false,
			wantEffective:    "deploy ALL = (root) /usr/bin/systemctl status nginx.service",
		},
		{
			name: "SynthesizedFallbackIncludesMultipleOptionsAndTags",
			finding: audit.Finding{
				ID:      "SUDO-GTFO-002",
				Title:   "Passwordless Dangerous Sudo Binary allowed: systemctl (command)",
				User:    "deploy",
				Host:    "web01",
				Runas:   "root",
				Tags:    "CWD=/srv/app NOPASSWD: SETENV:",
				Command: "/usr/bin/systemctl status nginx.service",
			},
			wantVerbatim:     false,
			wantLabel:        "Effective Rule (Synthesized)",
			wantPreview:      "deploy web01 = (root) CWD=/srv/app NOPASSWD: SETENV: /usr/bin/systemctl status nginx.service",
			wantShowResolved: false,
			wantEffective:    "deploy web01 = (root) CWD=/srv/app NOPASSWD: SETENV: /usr/bin/systemctl status nginx.service",
		},
		{
			name: "OptionOnlyFindingWithoutCommand",
			finding: audit.Finding{
				ID:    "SUDO-CMD-009",
				Title: "Environment Override Permitted on Command (SETENV)",
				User:  "deploy",
				Host:  "ALL",
				Runas: "root",
				Tags:  "NOPASSWD: SETENV:",
			},
			wantVerbatim:     false,
			wantLabel:        "Effective Rule (Synthesized)",
			wantPreview:      "deploy ALL = (root) NOPASSWD: SETENV: ...",
			wantShowResolved: false,
			wantEffective:    "deploy ALL = (root) NOPASSWD: SETENV: ...",
		},
		{
			name: "RegularCommandWithoutTags",
			finding: audit.Finding{
				ID:      "SUDO-GTFO-001",
				Title:   "Dangerous Sudo Binary allowed: systemctl (command)",
				User:    "deploy",
				Host:    "ALL",
				Runas:   "root",
				Command: "/usr/bin/systemctl status nginx.service",
			},
			wantVerbatim:     false,
			wantLabel:        "Effective Rule (Synthesized)",
			wantPreview:      "deploy ALL = (root) /usr/bin/systemctl status nginx.service",
			wantShowResolved: false,
			wantEffective:    "deploy ALL = (root) /usr/bin/systemctl status nginx.service",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			view := enrichFinding(tc.finding, "POLICY", 0)
			if view.HasVerbatimSource != tc.wantVerbatim {
				t.Errorf("Expected HasVerbatimSource=%v, got %v", tc.wantVerbatim, view.HasVerbatimSource)
			}
			if view.RulePreviewLabel != tc.wantLabel {
				t.Errorf("Expected RulePreviewLabel %q, got %q", tc.wantLabel, view.RulePreviewLabel)
			}
			if view.RulePreview != tc.wantPreview {
				t.Errorf("Expected RulePreview %q, got %q", tc.wantPreview, view.RulePreview)
			}
			if view.ShowResolvedRule != tc.wantShowResolved {
				t.Errorf("Expected ShowResolvedRule=%v, got %v", tc.wantShowResolved, view.ShowResolvedRule)
			}
			if view.EffectiveRule != tc.wantEffective {
				t.Errorf("Expected EffectiveRule %q, got %q", tc.wantEffective, view.EffectiveRule)
			}
		})
	}
}

func TestAllReports_DeterministicAcrossShuffledInputAndRepeatedRuns(t *testing.T) {
	origV, origC, origD := buildinfo.Version, buildinfo.Commit, buildinfo.Date
	buildinfo.Set("v1.0.0-det", "abcdef0", "2026-01-01")
	t.Cleanup(func() { buildinfo.Set(origV, origC, origD) })

	base := &audit.AuditResult{
		Hostname:    "prod-web-01",
		SudoVersion: "1.9.16p2",
		SystemFindings: []audit.Finding{
			{
				ID:              "SUDO-SYS-PERM-002",
				Title:           "Sudoers Writable by Group",
				Description:     "Group writable sudoers.",
				Severity:        audit.SeverityCritical,
				Context:         "/etc/sudoers",
				Line:            1,
				Remediation:     "Restrict permissions.",
				RemediationCode: "chmod 0440 /etc/sudoers",
				Compliance:      []string{"ANSSI-BP-028 R38"},
			},
			{
				ID:              "SUDO-SYS-PERM-012",
				Title:           "Writable Target Binary",
				Description:     "Target binary is writable.",
				Severity:        audit.SeverityCritical,
				Context:         "/usr/local/bin/deploy.sh",
				Remediation:     "Fix target binary mode.",
				RemediationCode: "chmod 0755 /usr/local/bin/deploy.sh",
				Compliance:      []string{"ANSSI-BP-028 R38"},
			},
		},
		PolicyFindings: []audit.Finding{
			{
				ID:                "SUDO-GTFO-002",
				Title:             "Passwordless Dangerous Sudo Binary allowed: systemctl (command)",
				Description:       "Passwordless systemctl via Defaults !authenticate.",
				Severity:          audit.SeverityCritical,
				User:              "ops",
				Host:              "ALL",
				Runas:             "root",
				Command:           "/usr/bin/systemctl status nginx.service",
				SourceLine:        "ops ALL=(root) /usr/bin/systemctl status nginx.service",
				InheritedDefaults: "Defaults:ops !authenticate",
				Context:           "/etc/sudoers.d/20-ops",
				Line:              4,
				Remediation:       "Remove binary or wrap it.",
				RemediationCode:   `ops ALL = (root) PASSWD: NOEXEC: /usr/bin/systemctl status nginx.service`,
				ExploitPoC:        "sudo systemctl status nginx.service",
				Compliance:        []string{"MITRE-T1548.003"},
			},
			{
				ID:              "SUDO-GTFO-002",
				Title:           "Passwordless Dangerous Sudo Binary allowed: vim (shell)",
				Description:     "Passwordless vim.",
				Severity:        audit.SeverityCritical,
				User:            "deploy",
				Host:            "ALL",
				Runas:           "root",
				Tags:            "NOPASSWD:",
				Command:         "/usr/bin/vim /etc/nginx/nginx.conf",
				SourceLine:      "deploy ALL=(root) NOPASSWD: /usr/bin/vim /etc/nginx/nginx.conf",
				Context:         "/etc/sudoers.d/10-deploy",
				Line:            2,
				Remediation:     "Use sudoedit.",
				RemediationCode: "deploy ALL = (root) sudoedit /etc/nginx/nginx.conf",
				ExploitPoC:      "sudo vim -c ':!/bin/sh'",
				Compliance:      []string{"MITRE-T1548.003"},
			},
			{
				ID:              "SUDO-DEF-005",
				Title:           "visiblepw Flag Enabled",
				Description:     "visiblepw enabled.",
				Severity:        audit.SeverityHigh,
				SourceLine:      "Defaults visiblepw",
				Context:         "/etc/sudoers",
				Line:            3,
				Remediation:     "Disable visiblepw.",
				RemediationCode: "Defaults !visiblepw",
			},
		},
	}

	// Build a permuted copy with reversed PolicyFindings and SystemFindings
	permuted := &audit.AuditResult{
		Hostname:       base.Hostname,
		SudoVersion:    base.SudoVersion,
		SystemFindings: []audit.Finding{base.SystemFindings[1], base.SystemFindings[0]},
		PolicyFindings: []audit.Finding{base.PolicyFindings[2], base.PolicyFindings[0], base.PolicyFindings[1]},
	}

	writers := []struct {
		name  string
		write func(*audit.AuditResult, *bytes.Buffer) error
	}{
		{"text", func(r *audit.AuditResult, b *bytes.Buffer) error { return WriteTextReportWithOptions(r, b, false) }},
		{"json", func(r *audit.AuditResult, b *bytes.Buffer) error { return WriteJSONReport(r, b) }},
		{"sarif", func(r *audit.AuditResult, b *bytes.Buffer) error { return WriteSarifReport(r, b) }},
		{"html", func(r *audit.AuditResult, b *bytes.Buffer) error { return WriteHTMLReport(r, b) }},
		{"pdf", func(r *audit.AuditResult, b *bytes.Buffer) error { return WritePDFReport(r, b) }},
	}

	for _, w := range writers {
		t.Run(w.name, func(t *testing.T) {
			var run1, run2, runPerm bytes.Buffer
			if err := w.write(base, &run1); err != nil {
				t.Fatalf("run1 failed: %v", err)
			}
			if err := w.write(base, &run2); err != nil {
				t.Fatalf("run2 failed: %v", err)
			}
			if err := w.write(permuted, &runPerm); err != nil {
				t.Fatalf("permuted run failed: %v", err)
			}
			if !bytes.Equal(run1.Bytes(), run2.Bytes()) {
				t.Errorf("%s report is non-deterministic across repeated runs", w.name)
			}
			if !bytes.Equal(run1.Bytes(), runPerm.Bytes()) {
				t.Errorf("%s report differs when tied-severity findings are permuted", w.name)
			}
		})
	}
}

func TestEndToEndReport_VerbatimSourceLineAndInheritedDefaults(t *testing.T) {
	gtfoClient, err := gtfobins.NewClient()
	if err != nil {
		t.Fatalf("failed to load GTFObins DB: %v", err)
	}

	sudoers := strings.Join([]string{
		"Defaults env_reset, use_pty, requiretty, ignore_dot, umask=0077, logfile=\"/var/log/sudo.log\", secure_path=\"/usr/sbin:/usr/bin:/sbin:/bin\"",
		"Defaults visiblepw",
		"Defaults:ops !authenticate",
		"Cmnd_Alias NGINX_CMDS = /usr/bin/systemctl status nginx.service",
		"deploy ALL=(root) NOPASSWD: /usr/bin/systemctl status nginx.service",
		"ops ALL=(root) /usr/bin/systemctl status nginx.service",
		"aliased ALL=(root) NOPASSWD: NGINX_CMDS",
	}, "\n") + "\n"

	policy, err := parser.ParseReader(strings.NewReader(sudoers), "sudoers.d/10-deploy", "")
	if err != nil {
		t.Fatalf("ParseReader failed: %v", err)
	}
	findings := audit.RunAudit(policy, gtfoClient)
	result := &audit.AuditResult{PolicyFindings: findings}

	var htmlBuf, textBuf, jsonBuf, sarifBuf, pdfBuf bytes.Buffer
	if err := WriteHTMLReport(result, &htmlBuf); err != nil {
		t.Fatalf("WriteHTMLReport failed: %v", err)
	}
	if err := WriteTextReportWithOptions(result, &textBuf, false); err != nil {
		t.Fatalf("WriteTextReportWithOptions failed: %v", err)
	}
	if err := WriteJSONReport(result, &jsonBuf); err != nil {
		t.Fatalf("WriteJSONReport failed: %v", err)
	}
	if err := WriteSarifReport(result, &sarifBuf); err != nil {
		t.Fatalf("WriteSarifReport failed: %v", err)
	}
	if err := WritePDFReport(result, &pdfBuf); err != nil {
		t.Fatalf("WritePDFReport failed: %v", err)
	}

	htmlOut := htmlBuf.String()
	for _, want := range []string{
		"Source Line (sudoers.d/10-deploy:5)",
		"deploy ALL=(root) NOPASSWD: /usr/bin/systemctl status nginx.service",
		"Source Line (sudoers.d/10-deploy:6)",
		"ops ALL=(root) /usr/bin/systemctl status nginx.service",
		"Defaults:ops !authenticate",
		"Source Line (sudoers.d/10-deploy:7)",
		"aliased ALL=(root) NOPASSWD: NGINX_CMDS",
		"Resolved Rule:",
		"aliased ALL = (root) NOPASSWD: /usr/bin/systemctl status nginx.service",
		"Source Line (sudoers.d/10-deploy:2)",
		"Defaults visiblepw",
		"Offline Policy Scan",
		"Passwordless Permitted Binary in GTFObins Catalog",
	} {
		if !strings.Contains(htmlOut, want) {
			t.Errorf("Expected HTML report to contain %q", want)
		}
	}

	textOut := textBuf.String()
	for _, want := range []string{
		"Tags:        NOPASSWD:",
		"Defaults:    Defaults:ops !authenticate",
		"Source Line: deploy ALL=(root) NOPASSWD: /usr/bin/systemctl status nginx.service",
		"Source Line: aliased ALL=(root) NOPASSWD: NGINX_CMDS",
	} {
		if !strings.Contains(textOut, want) {
			t.Errorf("Expected text report to contain %q", want)
		}
	}

	// Ensure JSON Remediation never contains legacy embedded exploit prose
	var parsedJSON audit.AuditResult
	if err := json.Unmarshal(jsonBuf.Bytes(), &parsedJSON); err != nil {
		t.Fatalf("JSON unmarshal failed: %v", err)
	}
	for _, f := range parsedJSON.PolicyFindings {
		if strings.Contains(f.Remediation, "Example exploit command:") {
			t.Errorf("Finding %s still embeds legacy exploit prose in Remediation: %q", f.ID, f.Remediation)
		}
	}

	// Ensure SARIF rules are sorted deterministically by ID
	var parsedSarif SarifLog
	if err := json.Unmarshal(sarifBuf.Bytes(), &parsedSarif); err != nil {
		t.Fatalf("SARIF unmarshal failed: %v", err)
	}
	rules := parsedSarif.Runs[0].Tool.Driver.Rules
	for i := 1; i < len(rules); i++ {
		if rules[i-1].ID >= rules[i].ID {
			t.Errorf("SARIF driver.rules not strictly sorted by ID: %q before %q", rules[i-1].ID, rules[i].ID)
		}
	}

	if !bytes.HasPrefix(pdfBuf.Bytes(), []byte("%PDF-")) {
		t.Errorf("Expected valid PDF header")
	}
}

func TestGenerateReports_ValidationAndStdoutSafety(t *testing.T) {
	result := createDummyResult()

	t.Run("UnknownFormatRejectedWithoutOutputDir", func(t *testing.T) {
		_, err := GenerateReportsWithOptions(result, []string{"yaml"}, "", true)
		if err == nil || !strings.Contains(err.Error(), `unsupported report format "yaml"`) {
			t.Errorf("Expected unsupported format error for yaml, got: %v", err)
		}
	})

	t.Run("UnknownFormatRejectedBeforeCreatingOutputDir", func(t *testing.T) {
		missingDir := filepath.Join(t.TempDir(), "should-not-exist")
		_, err := GenerateReportsWithOptions(result, []string{"text", "xml"}, missingDir, true)
		if err == nil || !strings.Contains(err.Error(), `unsupported report format "xml"`) {
			t.Errorf("Expected unsupported format error for xml, got: %v", err)
		}
		if _, statErr := os.Stat(missingDir); !os.IsNotExist(statErr) {
			t.Errorf("Expected outputDir not to be created when format validation fails")
		}
	})

	t.Run("FileOnlyFormatsRequireOutputDir", func(t *testing.T) {
		for _, fmts := range [][]string{{"html"}, {"pdf"}, {"html", "pdf"}} {
			_, err := GenerateReportsWithOptions(result, fmts, "", true)
			if err == nil || !strings.Contains(err.Error(), "require --output-dir (-o)") {
				t.Errorf("Expected --output-dir error for %v without outputDir, got: %v", fmts, err)
			}
		}
	})

	t.Run("MultipleStructuredFormatsToStdoutRejected", func(t *testing.T) {
		_, err := GenerateReportsWithOptions(result, []string{"json", "sarif"}, "", true)
		if err == nil || !strings.Contains(err.Error(), "cannot write multiple structured formats (json, sarif) to stdout") {
			t.Errorf("Expected multi-structured stdout error for json,sarif, got: %v", err)
		}
	})

	t.Run("DefaultFormatsWithoutOutputDirWritesTextOnlyToStdout", func(t *testing.T) {
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

		generated, genErr := GenerateReportsWithOptions(result, []string{"text", "sarif", "pdf", "html"}, "", true)

		_ = wPipe.Close()
		<-doneRead
		_ = rPipe.Close()

		if genErr != nil {
			t.Fatalf("Expected default formats without outputDir to succeed, got: %v", genErr)
		}
		if len(generated) != 1 || generated["text"] != "stdout" {
			t.Errorf("Expected only text->stdout in generated map, got: %v", generated)
		}
		if !strings.Contains(stdoutBuf.String(), "=== SUDOERS SECURITY AUDIT REPORT ===") {
			t.Errorf("Expected text report on stdout")
		}
	})
}

func TestWriteSarifReport_PartialFingerprintsAndWave2Rules(t *testing.T) {
	result := &audit.AuditResult{
		SystemFindings: []audit.Finding{
			{
				ID:          "SUDO-SYS-PERM-014",
				Title:       "Sudo Binary Executable by All Local Users (No Dedicated Group Restriction)",
				Description: "World-executable sudo binary.",
				Severity:    audit.SeverityInfo,
				Context:     "/usr/bin/sudo",
				Remediation: "Restrict sudo binary to dedicated group.",
				Fingerprint: "fp-sys-perm-014",
			},
			{
				ID:          "SUDO-SYS-ID-001",
				Title:       "Orphaned User Referenced",
				Description: "Orphaned account in sudoers.",
				Severity:    audit.SeverityLow,
				Context:     "/etc/sudoers",
				Line:        8,
				Remediation: "Remove stale principal.",
			},
			{
				ID:          "SUDO-SYS-SCRIPT-001",
				Title:       "Path-Dependent Shebang Interpreter (/usr/bin/env)",
				Description: "Uses env shebang.",
				Severity:    audit.SeverityHigh,
				Context:     "/usr/local/sbin/wrap1.sh",
				Line:        1,
				Remediation: "Use explicit path and PATH.",
				Fingerprint: "fp-sys-script-001",
			},
			{
				ID:          "SUDO-SYS-SCRIPT-002",
				Title:       "Command Injection Risk via Positional Parameter Handling",
				Description: "Unsafe eval of $1.",
				Severity:    audit.SeverityCritical,
				Context:     "/usr/local/sbin/wrap2.sh",
				Line:        12,
				Remediation: "Validate arguments.",
			},
			{
				ID:          "SUDO-SYS-SCRIPT-003",
				Title:       "Unsafe Script Source Path",
				Description: "Sources relative file.",
				Severity:    audit.SeverityHigh,
				Context:     "/usr/local/sbin/wrap3.sh",
				Line:        4,
				Remediation: "Source root-owned config.",
			},
		},
		PolicyFindings: []audit.Finding{
			{
				ID:          "SUDO-CMD-015",
				Title:       "Shadowed Rule Variant",
				Description: "Earlier rule overridden.",
				Severity:    audit.SeverityMedium,
				Context:     "/etc/sudoers",
				Line:        20,
				Remediation: "Consolidate rules.",
				Fingerprint: "fp-cmd-015",
			},
			{
				ID:          "SUDO-CMD-016",
				Title:       "Expired Temporary Sudoers Rule (NOTAFTER)",
				Description: "Rule expired.",
				Severity:    audit.SeverityLow,
				Context:     "/etc/sudoers.d/temp",
				Line:        5,
				Remediation: "Remove expired rule.",
			},
		},
	}

	var buf bytes.Buffer
	if err := WriteSarifReport(result, &buf); err != nil {
		t.Fatalf("WriteSarifReport failed: %v", err)
	}

	var sarif SarifLog
	if err := json.Unmarshal(buf.Bytes(), &sarif); err != nil {
		t.Fatalf("Generated SARIF is not valid JSON: %v", err)
	}
	if len(sarif.Runs) != 1 {
		t.Fatalf("Expected 1 SARIF run, got %d", len(sarif.Runs))
	}

	run := sarif.Runs[0]
	ruleByID := make(map[string]SarifRule)
	for _, r := range run.Tool.Driver.Rules {
		ruleByID[r.ID] = r
	}

	wantTitles := map[string]string{
		"SUDO-CMD-015":        "Shadowed or Overridden Sudoers Rule",
		"SUDO-CMD-016":        "Expired or Inverted Sudoers Validity Window (NOTBEFORE/NOTAFTER)",
		"SUDO-SYS-PERM-014":   "Sudo Binary Not Restricted to Dedicated Group",
		"SUDO-SYS-ID-001":     "Nonexistent or Orphaned User/Group Referenced in Sudoers",
		"SUDO-SYS-SCRIPT-001": "Privileged Wrapper Script Uses Unsafe PATH or env Shebang",
		"SUDO-SYS-SCRIPT-002": "Privileged Wrapper Script Argument Injection Sink",
		"SUDO-SYS-SCRIPT-003": "Privileged Wrapper Script Sources Untrusted Path or Interpreter",
	}
	for id, wantTitle := range wantTitles {
		rule, ok := ruleByID[id]
		if !ok {
			t.Errorf("Missing rule %s in SARIF driver.rules", id)
			continue
		}
		if rule.ShortDescription.Text != wantTitle {
			t.Errorf("Rule %s ShortDescription = %q, want %q", id, rule.ShortDescription.Text, wantTitle)
		}
	}

	resByID := make(map[string]SarifResult)
	for _, res := range run.Results {
		resByID[res.RuleID] = res
	}

	for id, wantFP := range map[string]string{
		"SUDO-SYS-PERM-014":   "fp-sys-perm-014",
		"SUDO-SYS-SCRIPT-001": "fp-sys-script-001",
		"SUDO-CMD-015":        "fp-cmd-015",
	} {
		res, ok := resByID[id]
		if !ok {
			t.Errorf("Missing result for %s", id)
			continue
		}
		if res.PartialFingerprints["sudoCheckFingerprint/v1"] != wantFP {
			t.Errorf("Result %s partialFingerprints = %+v, want %q", id, res.PartialFingerprints, wantFP)
		}
	}

	for _, id := range []string{"SUDO-SYS-ID-001", "SUDO-SYS-SCRIPT-002", "SUDO-SYS-SCRIPT-003", "SUDO-CMD-016"} {
		res, ok := resByID[id]
		if !ok {
			t.Errorf("Missing result for %s", id)
			continue
		}
		if res.PartialFingerprints != nil {
			t.Errorf("Result %s expected nil PartialFingerprints when Fingerprint is empty, got %+v", id, res.PartialFingerprints)
		}
	}

	// Also ensure raw JSON omits partialFingerprints when no finding carries a fingerprint.
	noFPResult := &audit.AuditResult{
		PolicyFindings: []audit.Finding{
			{
				ID:          "SUDO-CMD-015",
				Title:       "Shadowed Rule",
				Description: "Overridden.",
				Severity:    audit.SeverityMedium,
				Remediation: "Consolidate.",
			},
		},
	}
	var noFPBuf bytes.Buffer
	if err := WriteSarifReport(noFPResult, &noFPBuf); err != nil {
		t.Fatalf("WriteSarifReport without fingerprints failed: %v", err)
	}
	if strings.Contains(noFPBuf.String(), "partialFingerprints") {
		t.Errorf("Expected partialFingerprints to be omitted when Fingerprint is empty, got:\n%s", noFPBuf.String())
	}
}

func TestReports_ExploitabilityRendering(t *testing.T) {
	withExploitability := &audit.AuditResult{
		Hostname: "host-exp",
		SystemFindings: []audit.Finding{
			{
				ID:             "CVE-2021-3156",
				Title:          "Baron Samedit",
				Description:    "Heap overflow.",
				Severity:       audit.SeverityCritical,
				Context:        "/usr/bin/sudo",
				Remediation:    "Upgrade sudo.",
				Exploitability: "ACTIVE",
			},
			{
				ID:             "CVE-2019-18634",
				Title:          "pwfeedback Buffer Overflow",
				Description:    "Requires pwfeedback.",
				Severity:       audit.SeverityHigh,
				Context:        "/usr/bin/sudo",
				Remediation:    "Upgrade sudo.",
				Exploitability: "LATENT",
			},
			{
				ID:             "CVE-2021-3156-BP",
				Title:          "Distro Backport Patched",
				Description:    "Patched via distro backport.",
				Severity:       audit.SeverityInfo,
				Context:        "/usr/bin/sudo",
				Remediation:    "No action required.",
				Exploitability: "PATCHED_BACKPORT",
			},
		},
		PolicyFindings: []audit.Finding{
			{
				ID:             "SUDO-GTFO-001",
				Title:          "Dangerous Sudo Binary allowed: systemctl (shell)",
				Description:    "Constrained to read-only status.",
				Severity:       audit.SeverityLow,
				User:           "ops",
				Host:           "ALL",
				Runas:          "root",
				Command:        "/usr/bin/systemctl status nginx",
				Context:        "/etc/sudoers.d/ops",
				Line:           3,
				Remediation:    "Apply NOEXEC.",
				Exploitability: "CONSTRAINED",
			},
		},
	}

	var textBuf bytes.Buffer
	if err := WriteTextReportWithOptions(withExploitability, &textBuf, false); err != nil {
		t.Fatalf("WriteTextReportWithOptions failed: %v", err)
	}
	textOut := textBuf.String()
	for _, want := range []string{
		"  Exploitability: ACTIVE\n",
		"  Exploitability: LATENT\n",
		"  Exploitability: PATCHED_BACKPORT\n",
		"  Exploitability: CONSTRAINED\n",
	} {
		if !strings.Contains(textOut, want) {
			t.Errorf("Expected text report to contain %q, got:\n%s", want, textOut)
		}
	}

	var htmlBuf bytes.Buffer
	if err := WriteHTMLReport(withExploitability, &htmlBuf); err != nil {
		t.Fatalf("WriteHTMLReport failed: %v", err)
	}
	htmlOut := htmlBuf.String()
	for _, wantBadge := range []string{
		`<span class="exploit-badge exploit-active">ACTIVE</span>`,
		`<span class="exploit-badge exploit-latent">LATENT</span>`,
		`<span class="exploit-badge exploit-patched-backport">PATCHED_BACKPORT</span>`,
		`<span class="exploit-badge exploit-constrained">CONSTRAINED</span>`,
	} {
		if !strings.Contains(htmlOut, wantBadge) {
			t.Errorf("Expected HTML report to contain %q", wantBadge)
		}
	}

	// Verify that when Exploitability is empty, neither text nor HTML card badges are emitted.
	withoutExploitability := createDummyResult()
	var emptyTextBuf bytes.Buffer
	if err := WriteTextReportWithOptions(withoutExploitability, &emptyTextBuf, false); err != nil {
		t.Fatalf("WriteTextReportWithOptions(dummy) failed: %v", err)
	}
	if strings.Contains(emptyTextBuf.String(), "Exploitability:") {
		t.Errorf("Expected no Exploitability line when Exploitability is empty")
	}

	var emptyHTMLBuf bytes.Buffer
	if err := WriteHTMLReport(withoutExploitability, &emptyHTMLBuf); err != nil {
		t.Fatalf("WriteHTMLReport(dummy) failed: %v", err)
	}
	if strings.Contains(emptyHTMLBuf.String(), `<span class="exploit-badge`) {
		t.Errorf("Expected no exploit-badge span rendered when Exploitability is empty")
	}
}

func TestReferenceData_Wave2CatalogAndTraceability(t *testing.T) {
	res := &audit.AuditResult{
		SystemFindings: []audit.Finding{
			{
				ID:       "SUDO-SYS-PERM-014",
				Title:    "Sudo Binary Executable by All Local Users (No Dedicated Group Restriction)",
				Severity: audit.SeverityInfo,
				// Intentionally omit Compliance tags to verify RuleID-based mapping to anssi-r38.
			},
		},
	}

	data := buildHTMLReportData(res)
	var anssiR38 *FrameworkRequirement
	for gi := range data.FrameworkGroups {
		for ri := range data.FrameworkGroups[gi].Requirements {
			req := &data.FrameworkGroups[gi].Requirements[ri]
			if req.ID == "anssi-r38" {
				anssiR38 = req
				break
			}
		}
	}
	if anssiR38 == nil {
		t.Fatalf("Missing anssi-r38 requirement in framework catalog")
	}
	hasPerm014 := false
	for _, rid := range anssiR38.RuleIDs {
		if rid == "SUDO-SYS-PERM-014" {
			hasPerm014 = true
			break
		}
	}
	if !hasPerm014 {
		t.Errorf("Expected SUDO-SYS-PERM-014 in anssi-r38 RuleIDs, got %v", anssiR38.RuleIDs)
	}
	if anssiR38.ViolationCount != 1 {
		t.Errorf("Expected anssi-r38 ViolationCount == 1 for SUDO-SYS-PERM-014, got %d", anssiR38.ViolationCount)
	}

	rows := buildTraceabilityMatrix()
	byRule := make(map[string]TraceabilityRow, len(rows))
	for _, row := range rows {
		byRule[row.RuleID] = row
	}

	expectedRows := []struct {
		ruleID     string
		domain     string
		severity   audit.Severity
		title      string
		frameworks []string
	}{
		{
			ruleID:   "SUDO-CMD-015",
			domain:   "Command Rule",
			severity: audit.SeverityMedium,
			title:    "Shadowed or Overridden Sudoers Rule",
		},
		{
			ruleID:   "SUDO-CMD-016",
			domain:   "Command Rule",
			severity: audit.SeverityLow,
			title:    "Expired or Inverted Sudoers Validity Window (NOTBEFORE/NOTAFTER)",
		},
		{
			ruleID:     "SUDO-SYS-PERM-014",
			domain:     "System Host",
			severity:   audit.SeverityInfo,
			frameworks: []string{"ANSSI-BP-028 R38"},
		},
		{
			ruleID:   "SUDO-SYS-ID-001",
			domain:   "System Host",
			severity: audit.SeverityLow,
		},
		{
			ruleID:   "SUDO-SYS-SCRIPT-001",
			domain:   "System Host",
			severity: audit.SeverityHigh,
		},
		{
			ruleID:   "SUDO-SYS-SCRIPT-002",
			domain:   "System Host",
			severity: audit.SeverityCritical,
		},
		{
			ruleID:   "SUDO-SYS-SCRIPT-003",
			domain:   "System Host",
			severity: audit.SeverityHigh,
		},
	}

	for _, want := range expectedRows {
		got, ok := byRule[want.ruleID]
		if !ok {
			t.Errorf("Missing TraceabilityRow for %s", want.ruleID)
			continue
		}
		if got.Domain != want.domain {
			t.Errorf("%s Domain = %q, want %q", want.ruleID, got.Domain, want.domain)
		}
		if got.Severity != want.severity {
			t.Errorf("%s Severity = %s, want %s", want.ruleID, got.Severity, want.severity)
		}
		if want.title != "" && got.Title != want.title {
			t.Errorf("%s Title = %q, want %q", want.ruleID, got.Title, want.title)
		}
		if len(want.frameworks) > 0 {
			if len(got.Frameworks) != len(want.frameworks) || got.Frameworks[0] != want.frameworks[0] {
				t.Errorf("%s Frameworks = %v, want %v", want.ruleID, got.Frameworks, want.frameworks)
			}
		}
		if strings.TrimSpace(got.Title) == "" || strings.TrimSpace(got.Directive) == "" || strings.TrimSpace(got.SectionID) == "" {
			t.Errorf("%s TraceabilityRow has empty metadata: %+v", want.ruleID, got)
		}
	}
}

func TestWriteSarifReport_SnippetAndProperties(t *testing.T) {
	res := &audit.AuditResult{
		PolicyFindings: []audit.Finding{
			{
				ID:                "SUDO-GTFO-002",
				Title:             "Passwordless Dangerous Sudo Binary allowed: systemctl (command)",
				Description:       "Passwordless systemctl permitted.",
				Severity:          audit.SeverityCritical,
				User:              "deploy",
				Host:              "ALL",
				Runas:             "root",
				Tags:              "NOPASSWD: SETENV:",
				Command:           "/usr/bin/systemctl status nginx.service",
				SourceLine:        "deploy ALL=(root) NOPASSWD: SETENV: /usr/bin/systemctl status nginx.service",
				InheritedDefaults: "Defaults !authenticate",
				Exploitability:    "ACTIVE",
				Context:           "sudoers.d/10-deploy",
				Line:              2,
				Remediation:       "Require PASSWD and restrict arguments.",
				RemediationCode:   "deploy ALL = (root) PASSWD: /usr/local/sbin/nginx-status.sh \"\"",
			},
			{
				ID:          "SUDO-DEF-005",
				Title:       "visiblepw Flag Enabled",
				Description: "visiblepw enabled.",
				Severity:    audit.SeverityMedium,
				SourceLine:  "Defaults visiblepw",
				Context:     "etc/sudoers",
				Line:        0,
				Remediation: "Remove visiblepw.",
			},
		},
	}

	var buf bytes.Buffer
	if err := WriteSarifReport(res, &buf); err != nil {
		t.Fatalf("WriteSarifReport failed: %v", err)
	}

	var parsed SarifLog
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("failed to unmarshal SARIF: %v", err)
	}
	if len(parsed.Runs) != 1 || len(parsed.Runs[0].Results) != 2 {
		t.Fatalf("unexpected SARIF results count: %+v", parsed)
	}

	r0 := parsed.Runs[0].Results[0]
	if r0.RuleID != "SUDO-GTFO-002" {
		t.Fatalf("expected SUDO-GTFO-002 first, got %q", r0.RuleID)
	}
	reg0 := r0.Locations[0].PhysicalLocation.Region
	if reg0 == nil || reg0.StartLine != 2 || reg0.Snippet == nil || reg0.Snippet.Text != "deploy ALL=(root) NOPASSWD: SETENV: /usr/bin/systemctl status nginx.service" {
		t.Errorf("unexpected SARIF region/snippet for SUDO-GTFO-002: %+v", reg0)
	}
	if r0.Properties == nil || r0.Properties.Tags != "NOPASSWD: SETENV:" || r0.Properties.InheritedDefaults != "Defaults !authenticate" || r0.Properties.Exploitability != "ACTIVE" {
		t.Errorf("unexpected SARIF result properties for SUDO-GTFO-002: %+v", r0.Properties)
	}

	// Verify snippet is emitted even when Line == 0 and properties is omitted when empty.
	r1 := parsed.Runs[0].Results[1]
	reg1 := r1.Locations[0].PhysicalLocation.Region
	if reg1 == nil || reg1.StartLine != 0 || reg1.Snippet == nil || reg1.Snippet.Text != "Defaults visiblepw" {
		t.Errorf("expected snippet without startLine for Line==0 finding, got %+v", reg1)
	}
	if r1.Properties != nil {
		t.Errorf("expected nil Properties when Tags/InheritedDefaults/Exploitability are empty, got %+v", r1.Properties)
	}
}

func TestEnrichFinding_StructuredDefaultsScopeOverridesRemediationCode(t *testing.T) {
	view := enrichFinding(audit.Finding{
		ID:              "SUDO-DEF-003",
		Title:           "Disabled use_pty in Scoped Defaults",
		Severity:        audit.SeverityMedium,
		User:            "web01",
		DefaultsScope:   "Defaults@web01",
		RemediationCode: "",
	}, "POLICY", 0)
	if view.RulePreview != "Defaults@web01" {
		t.Errorf("expected RulePreview %q from structured DefaultsScope, got %q", "Defaults@web01", view.RulePreview)
	}
	if view.RulePreviewLabel != "Effective Scope (Synthesized)" {
		t.Errorf("expected RulePreviewLabel %q, got %q", "Effective Scope (Synthesized)", view.RulePreviewLabel)
	}
}

func TestWritePDFReport_LongTitleNotTruncatedAndDeterministic(t *testing.T) {
	longTitle := "Extremely Long Sudoers Security Audit Finding Title That Previously Exceeded One Hundred Twenty Millimeters And Got Truncated With Ellipsis"
	res := &audit.AuditResult{
		Hostname:    "prod-web-01",
		SudoVersion: "1.9.16p2",
		PolicyFindings: []audit.Finding{
			{
				ID:          "SUDO-CMD-009",
				Title:       longTitle,
				Description: "Verify full title renders without ellipsis truncation.",
				Severity:    audit.SeverityHigh,
				User:        "deploy",
				Host:        "ALL",
				Runas:       "root",
				Tags:        "NOPASSWD: SETENV:",
				Command:     "/usr/bin/systemctl restart nginx",
				SourceLine:  "deploy ALL=(root) NOPASSWD: SETENV: /usr/bin/systemctl restart nginx",
				Context:     "/etc/sudoers.d/deploy",
				Line:        4,
				Remediation: "Remove SETENV.",
			},
		},
	}

	var buf1, buf2 bytes.Buffer
	if err := WritePDFReport(res, &buf1); err != nil {
		t.Fatalf("first WritePDFReport failed: %v", err)
	}
	if err := WritePDFReport(res, &buf2); err != nil {
		t.Fatalf("second WritePDFReport failed: %v", err)
	}
	if !bytes.Equal(buf1.Bytes(), buf2.Bytes()) {
		t.Fatal("expected byte-for-byte identical PDF output across repeated runs")
	}
	if buf1.Len() < 500 || !bytes.HasPrefix(buf1.Bytes(), []byte("%PDF-")) {
		t.Fatalf("expected valid PDF output, got %d bytes", buf1.Len())
	}
}
