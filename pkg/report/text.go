package report

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sudo-check/pkg/audit"
)

// ANSI color codes
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorPurple = "\033[35m"
	colorCyan   = "\033[36m"
	colorBold   = "\033[1m"
)

// GetSeverityColor returns the ANSI color code for a given severity.
func GetSeverityColor(sev audit.Severity) string {
	switch sev {
	case audit.SeverityCritical:
		return colorRed + colorBold
	case audit.SeverityHigh:
		return colorPurple + colorBold
	case audit.SeverityMedium:
		return colorYellow + colorBold
	case audit.SeverityLow:
		return colorCyan
	case audit.SeverityInfo:
		return colorBlue
	default:
		return colorReset
	}
}

// WriteTextReport formats the audit results as human-readable plaintext.
// ANSI colors are enabled unless the NO_COLOR environment variable is non-empty.
func WriteTextReport(result *audit.AuditResult, w io.Writer) error {
	return WriteTextReportWithOptions(result, w, os.Getenv("NO_COLOR") == "")
}

// WriteTextReportWithOptions formats the audit results as human-readable plaintext
// with explicit control over whether ANSI escape codes are emitted.
func WriteTextReportWithOptions(result *audit.AuditResult, w io.Writer, useColor bool) error {
	var sb strings.Builder

	bold, reset, red, purple, yellow, cyan, blue := "", "", "", "", "", "", ""
	if useColor {
		bold = colorBold
		reset = colorReset
		red = colorRed
		purple = colorPurple
		yellow = colorYellow
		cyan = colorCyan
		blue = colorBlue
	}

	writeFinding := func(f audit.Finding, category string) {
		sevColor := ""
		if useColor {
			sevColor = GetSeverityColor(f.Severity)
		}
		sb.WriteString(fmt.Sprintf("[%s%s%s] %s: %s\n", sevColor, f.Severity, reset, f.ID, f.Title))
		if f.User != "" {
			sb.WriteString(fmt.Sprintf("  User/Group:  %s\n", f.User))
		}
		if f.Host != "" {
			sb.WriteString(fmt.Sprintf("  Host:        %s\n", f.Host))
		}
		if f.Runas != "" {
			sb.WriteString(fmt.Sprintf("  RunAs:       %s\n", f.Runas))
		}
		if f.Command != "" {
			sb.WriteString(fmt.Sprintf("  Command:     %s\n", f.Command))
		}
		if f.Context != "" {
			loc := f.Context
			if f.Line > 0 {
				loc = fmt.Sprintf("%s:%d", f.Context, f.Line)
			}
			sb.WriteString(fmt.Sprintf("  Location:    %s\n", loc))
		} else if f.Line > 0 {
			sb.WriteString(fmt.Sprintf("  Location:    line %d\n", f.Line))
		}
		if len(f.Compliance) > 0 {
			sb.WriteString(fmt.Sprintf("  Compliance:  %s\n", strings.Join(f.Compliance, ", ")))
		}
		sb.WriteString(fmt.Sprintf("  Description: %s\n", f.Description))

		cleanRem, effectiveRemCode, _, effectivePoC := resolveFindingRemediationAndExploit(f, category)
		sb.WriteString(fmt.Sprintf("  Remediation: %s\n", cleanRem))
		if effectiveRemCode != "" {
			indentedFix := strings.ReplaceAll(strings.TrimSpace(effectiveRemCode), "\n", "\n    ")
			sb.WriteString(fmt.Sprintf("  Example Fix:\n    %s\n", indentedFix))
		}
		if effectivePoC != "" {
			indented := strings.ReplaceAll(strings.TrimSpace(effectivePoC), "\n", "\n    ")
			sb.WriteString(fmt.Sprintf("  Reference:\n    %s\n", indented))
		}
		sb.WriteString("\n")
	}

	sb.WriteString(fmt.Sprintf("%s=== SUDOERS SECURITY AUDIT REPORT ===%s\n\n", bold, reset))
	if result.Hostname != "" {
		sb.WriteString(fmt.Sprintf("Target Hostname: %s\n", result.Hostname))
	}
	if result.SudoVersion != "" {
		sb.WriteString(fmt.Sprintf("Sudo Version:    %s\n", result.SudoVersion))
	}
	sb.WriteString("\n")

	// Print System Findings (sorted by severity)
	if len(result.SystemFindings) > 0 {
		sorted := make([]audit.Finding, len(result.SystemFindings))
		copy(sorted, result.SystemFindings)
		audit.SortFindingsBySeverity(sorted)

		sb.WriteString(fmt.Sprintf("%s--- System Vulnerability Findings (%d) ---%s\n", bold, len(sorted), reset))
		for _, f := range sorted {
			writeFinding(f, "SYSTEM")
		}
	}

	// Print Policy Findings (sorted by severity)
	if len(result.PolicyFindings) > 0 {
		sorted := make([]audit.Finding, len(result.PolicyFindings))
		copy(sorted, result.PolicyFindings)
		audit.SortFindingsBySeverity(sorted)

		sb.WriteString(fmt.Sprintf("%s--- Sudoers Policy Findings (%d) ---%s\n", bold, len(sorted), reset))
		for _, f := range sorted {
			writeFinding(f, "POLICY")
		}
	} else {
		sb.WriteString("No sudoers policy misconfigurations found.\n")
	}

	// Print Summary stats using helper
	counts := audit.CountBySeverity(result.SystemFindings, result.PolicyFindings)

	sb.WriteString(fmt.Sprintf("%s--- Summary of Findings ---%s\n", bold, reset))
	sb.WriteString(fmt.Sprintf("  %sCRITICAL:%s %d\n", red, reset, counts[audit.SeverityCritical]))
	sb.WriteString(fmt.Sprintf("  %sHIGH:%s     %d\n", purple, reset, counts[audit.SeverityHigh]))
	sb.WriteString(fmt.Sprintf("  %sMEDIUM:%s   %d\n", yellow, reset, counts[audit.SeverityMedium]))
	sb.WriteString(fmt.Sprintf("  %sLOW:%s      %d\n", cyan, reset, counts[audit.SeverityLow]))
	sb.WriteString(fmt.Sprintf("  %sINFO:%s     %d\n", blue, reset, counts[audit.SeverityInfo]))
	sb.WriteString("\n")

	_, err := io.WriteString(w, sb.String())
	return err
}
