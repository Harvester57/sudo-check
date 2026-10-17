package report

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sudo-check/pkg/audit"
)

// ReportOptions configures report generation behavior.
type ReportOptions struct {
	Formats   []string
	OutputDir string
	NoColor   bool
}

// GenerateReports generates all requested reports inside the target outputDir.
// Returns a map of format names to generated file paths.
func GenerateReports(result *audit.AuditResult, formats []string, outputDir string) (map[string]string, error) {
	return GenerateReportsWithOptions(result, formats, outputDir, false)
}

// GenerateReportsWithOptions generates all requested reports inside the target outputDir
// with explicit control over terminal color output.
func GenerateReportsWithOptions(result *audit.AuditResult, formats []string, outputDir string, noColor bool) (map[string]string, error) {
	if outputDir != "" {
		if err := os.MkdirAll(outputDir, 0755); err != nil {
			return nil, fmt.Errorf("failed to create output directory: %w", err)
		}
	}

	hasText := false
	for _, f := range formats {
		norm := strings.ToLower(strings.TrimSpace(f))
		if norm == "text" || norm == "txt" {
			hasText = true
			break
		}
	}

	generated := make(map[string]string)

	for _, format := range formats {
		format = strings.ToLower(strings.TrimSpace(format))
		switch format {
		case "text", "txt":
			if outputDir != "" {
				outPath := filepath.Join(outputDir, "report.txt")
				if err := writeToFile(outPath, func(w *os.File) error {
					return WriteTextReportWithOptions(result, w, false)
				}); err != nil {
					return nil, fmt.Errorf("failed to write text report: %w", err)
				}
				generated["text"] = outPath
			} else {
				useColor := !noColor && os.Getenv("NO_COLOR") == ""
				if err := WriteTextReportWithOptions(result, os.Stdout, useColor); err != nil {
					return nil, fmt.Errorf("failed to write text report to stdout: %w", err)
				}
				generated["text"] = "stdout"
			}
		case "json":
			if outputDir != "" {
				outPath := filepath.Join(outputDir, "report.json")
				if err := writeToFile(outPath, func(w *os.File) error {
					return WriteJSONReport(result, w)
				}); err != nil {
					return nil, fmt.Errorf("failed to write JSON report: %w", err)
				}
				generated["json"] = outPath
			} else if !hasText {
				if err := WriteJSONReport(result, os.Stdout); err != nil {
					return nil, fmt.Errorf("failed to write JSON report to stdout: %w", err)
				}
				generated["json"] = "stdout"
			}
		case "sarif":
			if outputDir != "" {
				outPath := filepath.Join(outputDir, "report.sarif")
				if err := writeToFile(outPath, func(w *os.File) error {
					return WriteSarifReport(result, w)
				}); err != nil {
					return nil, fmt.Errorf("failed to write SARIF report: %w", err)
				}
				generated["sarif"] = outPath
			} else if !hasText {
				if err := WriteSarifReport(result, os.Stdout); err != nil {
					return nil, fmt.Errorf("failed to write SARIF report to stdout: %w", err)
				}
				generated["sarif"] = "stdout"
			}
		case "html":
			if outputDir == "" {
				continue
			}
			outPath := filepath.Join(outputDir, "report.html")
			if err := writeToFile(outPath, func(w *os.File) error {
				return WriteHTMLReport(result, w)
			}); err != nil {
				return nil, fmt.Errorf("failed to write HTML report: %w", err)
			}
			generated["html"] = outPath
		case "pdf":
			if outputDir == "" {
				continue
			}
			outPath := filepath.Join(outputDir, "report.pdf")
			if err := writeToFile(outPath, func(w *os.File) error {
				return WritePDFReport(result, w)
			}); err != nil {
				return nil, fmt.Errorf("failed to write PDF report: %w", err)
			}
			generated["pdf"] = outPath
		}
	}

	return generated, nil
}

// writeToFile creates a file at path, calls fn to write content, and ensures the file is properly closed.
// Close errors are propagated since they can indicate data loss (e.g., buffered writes failing on close).
func writeToFile(path string, fn func(w *os.File) error) (err error) {
	f, createErr := os.Create(path)
	if createErr != nil {
		return fmt.Errorf("failed to create file %s: %w", path, createErr)
	}
	defer func() {
		if closeErr := f.Close(); closeErr != nil && err == nil {
			err = fmt.Errorf("failed to close file %s: %w", path, closeErr)
		}
	}()
	return fn(f)
}
