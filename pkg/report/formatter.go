package report

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sudo-check/pkg/audit"
)

// GenerateReports generates all requested reports inside the target outputDir (or stdout when outputDir is empty).
// Returns a map of format names to generated file paths.
func GenerateReports(result *audit.AuditResult, formats []string, outputDir string) (map[string]string, error) {
	if outputDir != "" {
		if err := os.MkdirAll(outputDir, 0755); err != nil {
			return nil, fmt.Errorf("failed to create output directory: %w", err)
		}
	}

	generated := make(map[string]string)
	singleStdoutFormat := outputDir == "" && len(formats) == 1

	for _, format := range formats {
		format = strings.ToLower(strings.TrimSpace(format))
		switch format {
		case "text", "txt":
			if outputDir != "" {
				outPath := filepath.Join(outputDir, "report.txt")
				// Write plain text without raw ANSI escape sequences when saving to a file.
				if err := writeToFile(outPath, func(w *os.File) error {
					return WriteTextReportWithColor(result, w, false)
				}); err != nil {
					return nil, fmt.Errorf("failed to write text report: %w", err)
				}
				generated["text"] = outPath
			} else {
				// If no output dir, write colorized text to stdout (unless NO_COLOR is set).
				if err := WriteTextReport(result, os.Stdout); err != nil {
					return nil, fmt.Errorf("failed to write text report to stdout: %w", err)
				}
				generated["text"] = "stdout"
			}
		case "sarif":
			if outputDir == "" {
				if singleStdoutFormat {
					if err := WriteSarifReport(result, os.Stdout); err != nil {
						return nil, fmt.Errorf("failed to write SARIF report to stdout: %w", err)
					}
					generated["sarif"] = "stdout"
				}
				continue
			}
			outPath := filepath.Join(outputDir, "report.sarif")
			if err := writeToFile(outPath, func(w *os.File) error {
				return WriteSarifReport(result, w)
			}); err != nil {
				return nil, fmt.Errorf("failed to write SARIF report: %w", err)
			}
			generated["sarif"] = outPath
		case "html":
			if outputDir == "" {
				if singleStdoutFormat {
					if err := WriteHTMLReport(result, os.Stdout); err != nil {
						return nil, fmt.Errorf("failed to write HTML report to stdout: %w", err)
					}
					generated["html"] = "stdout"
				}
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
				if singleStdoutFormat {
					return nil, fmt.Errorf("PDF format requires --output-dir (-o) to save the binary PDF file")
				}
				continue
			}
			outPath := filepath.Join(outputDir, "report.pdf")
			if err := writeToFile(outPath, func(w *os.File) error {
				return WritePDFReport(result, w)
			}); err != nil {
				return nil, fmt.Errorf("failed to write PDF report: %w", err)
			}
			generated["pdf"] = outPath
		default:
			return nil, fmt.Errorf("unsupported report format %q (supported: text, sarif, pdf, html)", format)
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
