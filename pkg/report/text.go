package report

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sudo-check/pkg/audit"
)

// ANSI color codes for terminal output.
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

// WriteTextReport formats the audit results as human-readable plaintext with ANSI colors
// (unless the NO_COLOR environment variable is set).
func WriteTextReport(result *audit.AuditResult, w io.Writer) error {
	useColor := os.Getenv("NO_COLOR") == ""
	return WriteTextReportWithColor(result, w, useColor)
}

// WriteTextReportWithColor formats the audit results as human-readable plaintext,
// optionally emitting ANSI escape codes when useColor is true (for terminal stdout)
// or plain uncolored text when useColor is false (for report.txt files on disk).
func WriteTextReportWithColor(result *audit.AuditResult, w io.Writer, useColor bool) error {
	var sb strings.Builder

	cBold, cReset, cRed, cPurple, cYellow, cCyan, cBlue := "", "", "", "", "", "", ""
	if useColor {
		cBold = colorBold
		cReset = colorReset
		cRed = colorRed
		cPurple = colorPurple
		cYellow = colorYellow
		cCyan = colorCyan
		cBlue = colorBlue
	}

	sevColor := func(sev audit.Severity) string {
		if !useColor {
			return ""
		}
		return GetSeverityColor(sev)
	}

	sb.WriteString(fmt.Sprintf("%s=== SUDOERS SECURITY AUDIT REPORT ===%s\n\n", cBold, cReset))
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

		sb.WriteString(fmt.Sprintf("%s--- System Vulnerability Findings (%d) ---%s\n", cBold, len(sorted), cReset))
		for _, f := range sorted {
			color := sevColor(f.Severity)
			sb.WriteString(fmt.Sprintf("[%s%s%s] %s: %s\n", color, f.Severity, cReset, f.ID, f.Title))
			if f.Context != "" {
				sb.WriteString(fmt.Sprintf("  Location:    %s\n", f.Context))
			}
			sb.WriteString(fmt.Sprintf("  Description: %s\n", f.Description))
			sb.WriteString(fmt.Sprintf("  Remediation: %s\n\n", f.Remediation))
		}
	}

	// Print Policy Findings (sorted by severity)
	if len(result.PolicyFindings) > 0 {
		sorted := make([]audit.Finding, len(result.PolicyFindings))
		copy(sorted, result.PolicyFindings)
		audit.SortFindingsBySeverity(sorted)

		sb.WriteString(fmt.Sprintf("%s--- Sudoers Policy Findings (%d) ---%s\n", cBold, len(sorted), cReset))
		for _, f := range sorted {
			color := sevColor(f.Severity)
			sb.WriteString(fmt.Sprintf("[%s%s%s] %s: %s\n", color, f.Severity, cReset, f.ID, f.Title))
			if f.User != "" {
				sb.WriteString(fmt.Sprintf("  User/Group:  %s\n", f.User))
			}
			if f.Runas != "" {
				sb.WriteString(fmt.Sprintf("  Runas:       %s\n", f.Runas))
			}
			if f.Command != "" {
				sb.WriteString(fmt.Sprintf("  Command:     %s\n", f.Command))
			}
			if f.Context != "" {
				sb.WriteString(fmt.Sprintf("  Location:    %s\n", f.Context))
			}
			sb.WriteString(fmt.Sprintf("  Description: %s\n", f.Description))
			sb.WriteString(fmt.Sprintf("  Remediation: %s\n\n", f.Remediation))
		}
	} else {
		sb.WriteString("No sudoers policy misconfigurations found.\n")
	}

	// Print Summary stats using helper
	counts := audit.CountBySeverity(result.SystemFindings, result.PolicyFindings)

	sb.WriteString(fmt.Sprintf("%s--- Summary of Findings ---%s\n", cBold, cReset))
	sb.WriteString(fmt.Sprintf("  %sCRITICAL:%s %d\n", cRed, cReset, counts[audit.SeverityCritical]))
	sb.WriteString(fmt.Sprintf("  %sHIGH:%s     %d\n", cPurple, cReset, counts[audit.SeverityHigh]))
	sb.WriteString(fmt.Sprintf("  %sMEDIUM:%s   %d\n", cYellow, cReset, counts[audit.SeverityMedium]))
	sb.WriteString(fmt.Sprintf("  %sLOW:%s      %d\n", cCyan, cReset, counts[audit.SeverityLow]))
	sb.WriteString(fmt.Sprintf("  %sINFO:%s     %d\n", cBlue, cReset, counts[audit.SeverityInfo]))
	sb.WriteString("\n")

	_, err := io.WriteString(w, sb.String())
	return err
}
