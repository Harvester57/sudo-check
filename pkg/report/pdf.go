package report

import (
	"fmt"
	"io"
	"strings"
	"sudo-check/pkg/audit"
	"time"

	"github.com/go-pdf/fpdf"
)

// WritePDFReport generates a styled PDF document representing the audit results.
func WritePDFReport(result *audit.AuditResult, w io.Writer) error {
	pdf := fpdf.New("P", "mm", "A4", "")
	pdf.SetMargins(20, 20, 20)
	pdf.SetAutoPageBreak(true, 20)

	// fpdf's built-in core fonts (Helvetica, Courier) use CP1252 encoding rather than UTF-8.
	// Using UnicodeTranslatorFromDescriptor prevents UTF-8 punctuation/symbols from rendering as mojibake.
	tr := pdf.UnicodeTranslatorFromDescriptor("")

	// Set Footer
	pdf.SetFooterFunc(func() {
		pdf.SetY(-15)
		pdf.SetFont("Helvetica", "I", 8)
		pdf.SetTextColor(148, 163, 184)
		pdf.CellFormat(0, 10, fmt.Sprintf("Page %d of {nb}  |  sudo-check Report", pdf.PageNo()), "", 0, "C", false, 0, "")
	})

	pdf.AliasNbPages("{nb}")
	pdf.AddPage()

	// --- Cover Page / Header ---
	pdf.SetFont("Helvetica", "B", 24)
	pdf.SetTextColor(15, 23, 42) // Dark Slate
	pdf.Cell(0, 15, "Sudoers Security Audit")
	pdf.Ln(10)

	pdf.SetFont("Helvetica", "B", 14)
	pdf.SetTextColor(99, 102, 241) // Indigo accent
	pdf.Cell(0, 10, "CONFIDENTIAL SECURITY REPORT")
	pdf.Ln(15)

	// Host metadata table
	pdf.SetFont("Helvetica", "B", 10)
	pdf.SetTextColor(100, 116, 139)
	pdf.Cell(30, 8, "Target Host:")
	pdf.SetFont("Helvetica", "", 10)
	pdf.SetTextColor(30, 41, 59)
	host := result.Hostname
	if host == "" {
		host = "localhost"
	}
	pdf.Cell(0, 8, tr(host))
	pdf.Ln(6)

	pdf.SetFont("Helvetica", "B", 10)
	pdf.SetTextColor(100, 116, 139)
	pdf.Cell(30, 8, "Sudo Version:")
	pdf.SetFont("Helvetica", "", 10)
	pdf.SetTextColor(30, 41, 59)
	sudoVer := result.SudoVersion
	if sudoVer == "" {
		sudoVer = "Unknown"
	}
	pdf.Cell(0, 8, tr(sudoVer))
	pdf.Ln(6)

	pdf.SetFont("Helvetica", "B", 10)
	pdf.SetTextColor(100, 116, 139)
	pdf.Cell(30, 8, "Generated On:")
	pdf.SetFont("Helvetica", "", 10)
	pdf.SetTextColor(30, 41, 59)
	pdf.Cell(0, 8, time.Now().Format("2006-01-02 15:04:05 MST"))
	pdf.Ln(15)

	// Divider
	pdf.SetDrawColor(226, 232, 240)
	pdf.SetLineWidth(0.5)
	pdf.Line(20, pdf.GetY(), 190, pdf.GetY())
	pdf.Ln(10)

	// --- Statistics Summary Grid ---
	counts := audit.CountBySeverity(result.SystemFindings, result.PolicyFindings)

	pdf.SetFont("Helvetica", "B", 12)
	pdf.SetTextColor(15, 23, 42)
	pdf.Cell(0, 8, "Findings Summary")
	pdf.Ln(10)

	// Draw boxes for counts
	drawStatBox := func(x, y, w, h float64, count int, label string, r, g, b int) {
		pdf.SetFillColor(248, 250, 252)
		pdf.SetDrawColor(226, 232, 240)
		pdf.Rect(x, y, w, h, "DF")

		// colored border top
		pdf.SetFillColor(r, g, b)
		pdf.Rect(x, y, w, 3, "F")

		// Number
		pdf.SetY(y + 6)
		pdf.SetX(x)
		pdf.SetFont("Helvetica", "B", 18)
		pdf.SetTextColor(30, 41, 59)
		pdf.CellFormat(w, 8, fmt.Sprintf("%d", count), "", 0, "C", false, 0, "")

		// Label
		pdf.SetY(y + 14)
		pdf.SetX(x)
		pdf.SetFont("Helvetica", "B", 8)
		pdf.SetTextColor(r, g, b)
		pdf.CellFormat(w, 5, strings.ToUpper(label), "", 0, "C", false, 0, "")
	}

	xStart := 20.0
	yStart := pdf.GetY()
	boxWidth := 28.0
	boxHeight := 22.0
	gap := 5.0

	drawStatBox(xStart, yStart, boxWidth, boxHeight, counts[audit.SeverityCritical], "Critical", 239, 68, 68)
	drawStatBox(xStart+(boxWidth+gap)*1, yStart, boxWidth, boxHeight, counts[audit.SeverityHigh], "High", 168, 85, 247)
	drawStatBox(xStart+(boxWidth+gap)*2, yStart, boxWidth, boxHeight, counts[audit.SeverityMedium], "Medium", 245, 158, 11)
	drawStatBox(xStart+(boxWidth+gap)*3, yStart, boxWidth, boxHeight, counts[audit.SeverityLow], "Low", 6, 182, 212)
	drawStatBox(xStart+(boxWidth+gap)*4, yStart, boxWidth, boxHeight, counts[audit.SeverityInfo], "Info", 59, 130, 246)

	pdf.SetY(yStart + boxHeight + 15)

	// --- Detailed Findings ---
	pdf.SetFont("Helvetica", "B", 14)
	pdf.SetTextColor(15, 23, 42)
	pdf.Cell(0, 10, "Detailed Audit Findings")
	pdf.Ln(8)

	// Merge and sort all findings by severity
	var allFindings []audit.Finding
	allFindings = append(allFindings, result.SystemFindings...)
	allFindings = append(allFindings, result.PolicyFindings...)
	audit.SortFindingsBySeverity(allFindings)

	if len(allFindings) == 0 {
		pdf.SetFont("Helvetica", "", 10)
		pdf.SetTextColor(100, 116, 139)
		pdf.Cell(0, 10, "No vulnerabilities or misconfigurations identified in the policy or target host.")
		return pdf.Output(w)
	}

	for _, f := range allFindings {
		// Ensure enough spacing or page break
		if pdf.GetY() > 240 {
			pdf.AddPage()
		}

		// Header Background Fill based on Severity
		var r, g, b int
		switch f.Severity {
		case audit.SeverityCritical:
			r, g, b = 239, 68, 68
		case audit.SeverityHigh:
			r, g, b = 168, 85, 247
		case audit.SeverityMedium:
			r, g, b = 245, 158, 11
		case audit.SeverityLow:
			r, g, b = 6, 182, 212
		default:
			r, g, b = 59, 130, 246
		}

		// Drawing a neat card header
		pdf.SetFillColor(248, 250, 252)
		pdf.SetDrawColor(226, 232, 240)
		pdf.Rect(20, pdf.GetY(), 170, 10, "DF")

		// Draw severity colored tag on the left
		pdf.SetFillColor(r, g, b)
		pdf.Rect(20, pdf.GetY(), 4, 10, "F")

		pdf.SetY(pdf.GetY() + 1)
		pdf.SetX(26)
		pdf.SetFont("Helvetica", "B", 10)
		pdf.SetTextColor(30, 41, 59)
		headerTitle := fmt.Sprintf("%s: %s", f.ID, f.Title)
		if len(headerTitle) > 68 {
			headerTitle = headerTitle[:65] + "..."
		}
		pdf.Cell(120, 8, tr(headerTitle))

		// Severity label right aligned
		pdf.SetX(150)
		pdf.SetFont("Helvetica", "B", 9)
		pdf.SetTextColor(r, g, b)
		pdf.CellFormat(35, 8, string(f.Severity), "", 0, "R", false, 0, "")
		pdf.Ln(11)

		// Metadata Info if available (User, Runas, Command, Host, Context)
		var metaParts []string
		if f.User != "" {
			metaParts = append(metaParts, fmt.Sprintf("User/Group: %s", f.User))
		}
		if f.Runas != "" {
			metaParts = append(metaParts, fmt.Sprintf("Runas: %s", f.Runas))
		}
		if f.Command != "" {
			metaParts = append(metaParts, fmt.Sprintf("Command: %s", f.Command))
		}
		if f.Context != "" {
			metaParts = append(metaParts, fmt.Sprintf("Location: %s", f.Context))
		}

		if len(metaParts) > 0 {
			pdf.SetFont("Helvetica", "B", 8)
			pdf.SetTextColor(100, 116, 139)
			pdf.SetX(20)
			pdf.MultiCell(170, 5, tr(strings.Join(metaParts, "  |  ")), "", "L", false)
			pdf.Ln(2)
		}

		// Description
		pdf.SetFont("Helvetica", "", 9.5)
		pdf.SetTextColor(51, 65, 85)
		pdf.SetX(20)
		pdf.MultiCell(170, 5, tr(f.Description), "", "L", false)
		pdf.Ln(2)

		// Remediation Block
		pdf.SetFont("Helvetica", "B", 9)
		pdf.SetTextColor(16, 185, 129) // Emerald green
		pdf.SetX(20)
		pdf.Cell(0, 5, "REMEDIATION:")
		pdf.Ln(5)

		pdf.SetFont("Helvetica", "", 9)
		pdf.SetTextColor(30, 41, 59)

		// If remediation has code block format, print it in a shaded Courier box
		isCodeBlock := strings.Contains(f.Remediation, "Defaults ") || strings.HasPrefix(f.Remediation, "Run ") || strings.Contains(f.Remediation, "Example exploit command:")

		if isCodeBlock {
			exploitText := f.Remediation
			exploitCmd := ""
			if strings.Contains(f.Remediation, "Example exploit command:\n") {
				parts := strings.Split(f.Remediation, "Example exploit command:\n")
				exploitText = parts[0]
				if len(parts) > 1 {
					exploitCmd = parts[1]
				}
			}

			pdf.SetX(20)
			pdf.MultiCell(170, 5, tr(exploitText), "", "L", false)
			pdf.Ln(2)

			if exploitCmd != "" {
				pdf.SetFillColor(241, 245, 249) // Light grey
				pdf.SetFont("Courier", "", 8.5)
				pdf.SetTextColor(16, 185, 129)
				pdf.SetX(20)
				pdf.MultiCell(170, 5, tr(exploitCmd), "1", "L", true)
				pdf.Ln(2)
			} else if strings.Contains(f.Remediation, "Defaults ") {
				pdf.SetFillColor(241, 245, 249)
				pdf.SetFont("Courier", "", 8.5)
				pdf.SetTextColor(16, 185, 129)
				pdf.SetX(20)
				pdf.MultiCell(170, 5, tr(f.Remediation), "1", "L", true)
				pdf.Ln(2)
			}
		} else {
			pdf.SetX(20)
			pdf.MultiCell(170, 5, tr(f.Remediation), "", "L", false)
			pdf.Ln(2)
		}

		pdf.Ln(6)
	}

	return pdf.Output(w)
}
