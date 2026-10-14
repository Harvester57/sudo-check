package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sudo-check/pkg/audit"
	"sudo-check/pkg/report"

	"github.com/spf13/cobra"
)

var scanCmd = &cobra.Command{
	Use:   "scan <file-or-dir>",
	Short: "Scan pre-converted JSON sudoers policies",
	Long:  `Scan a single cvtsudoers JSON policy file or a directory of multiple JSON policy files.`,
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		targetPath := args[0]

		// Validate --fail-on flag upfront if provided
		if strings.TrimSpace(failOnSeverity) != "" {
			if _, err := audit.ParseSeverity(failOnSeverity); err != nil {
				return err
			}
		}

		// 1. Initialize GTFObins client
		gtfoClient, err := newGTFOClient()
		if err != nil {
			return fmt.Errorf("failed to load GTFObins: %w", err)
		}

		// 2. Locate policy files
		var files []string
		info, err := os.Stat(targetPath)
		if err != nil {
			return fmt.Errorf("target path not found: %w", err)
		}

		if info.IsDir() {
			err = filepath.Walk(targetPath, func(path string, fInfo os.FileInfo, walkErr error) error {
				if walkErr != nil {
					return walkErr
				}
				if !fInfo.IsDir() && strings.HasSuffix(strings.ToLower(fInfo.Name()), ".json") {
					files = append(files, path)
				}
				return nil
			})
			if err != nil {
				return fmt.Errorf("failed to walk directory: %w", err)
			}
		} else {
			files = append(files, targetPath)
		}

		if len(files) == 0 {
			return fmt.Errorf("no JSON policy files found at target path: %s", targetPath)
		}

		// 3. Parse and audit policies
		var combinedFindings []audit.Finding
		for _, file := range files {
			data, err := os.ReadFile(file)
			if err != nil {
				return fmt.Errorf("failed to read file %s: %w", file, err)
			}

			var policy audit.SudoersPolicy
			if err := json.Unmarshal(data, &policy); err != nil {
				if info.IsDir() {
					fmt.Fprintf(os.Stderr, "Warning: failed to parse JSON in %s (skipping): %v\n", file, err)
					continue
				} else {
					return fmt.Errorf("failed to parse JSON in %s: %w", file, err)
				}
			}

			// Run audit and set context as the file name
			findings := audit.RunAudit(&policy, gtfoClient)
			for i := range findings {
				if findings[i].Context == "" {
					findings[i].Context = filepath.ToSlash(file)
				}
			}
			combinedFindings = append(combinedFindings, findings...)
		}

		// 4. Generate Reports
		result := &audit.AuditResult{
			PolicyFindings: combinedFindings,
		}

		// Try to fetch hostname for context if possible
		if hostname, err := os.Hostname(); err == nil {
			result.Hostname = hostname
		}

		generated, err := report.GenerateReports(result, getFormatsList(), outputDir)
		if err != nil {
			return fmt.Errorf("failed to generate reports: %w", err)
		}

		// Print summary in deterministic order
		if outputDir != "" {
			fmt.Printf("\nScan completed successfully! Generated reports:\n")
			fmtNames := make([]string, 0, len(generated))
			for fmtName := range generated {
				fmtNames = append(fmtNames, fmtName)
			}
			slices.Sort(fmtNames)
			for _, fmtName := range fmtNames {
				fmt.Printf("  - %s: %s\n", strings.ToUpper(fmtName), generated[fmtName])
			}
		}

		return checkFailOnThreshold(result)
	},
}

func init() {
	rootCmd.AddCommand(scanCmd)
}
