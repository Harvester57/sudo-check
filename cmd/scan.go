package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sudo-check/pkg/audit"
	"sudo-check/pkg/parser"
	"sudo-check/pkg/report"

	"github.com/spf13/cobra"
)

var scanCmd = &cobra.Command{
	Use:   "scan <file-or-dir>",
	Short: "Scan raw sudoers files or pre-converted JSON sudoers policies",
	Long:  `Scan a single raw sudoers configuration file, a pre-converted cvtsudoers JSON policy file, or a directory of policy files.`,
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if strings.TrimSpace(failOn) != "" {
			if _, ok := audit.ParseSeverity(failOn); !ok {
				return fmt.Errorf("invalid --fail-on severity %q (valid values: CRITICAL, HIGH, MEDIUM, LOW, INFO)", failOn)
			}
		}

		targetPath := args[0]

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
			var jsonFiles []string
			var sudoersFiles []string
			rootSudoers := filepath.Join(targetPath, "sudoers")
			hasRootSudoers := false
			if st, err := os.Stat(rootSudoers); err == nil && !st.IsDir() {
				hasRootSudoers = true
			}

			err = filepath.Walk(targetPath, func(path string, fInfo os.FileInfo, walkErr error) error {
				if walkErr != nil {
					return walkErr
				}
				if fInfo.IsDir() {
					return nil
				}
				name := fInfo.Name()
				lower := strings.ToLower(name)
				if strings.HasSuffix(lower, ".json") {
					jsonFiles = append(jsonFiles, path)
					return nil
				}
				if strings.HasPrefix(name, ".") || strings.HasSuffix(name, "~") || strings.HasSuffix(lower, ".bak") || strings.HasSuffix(lower, ".swp") {
					return nil
				}
				if strings.HasSuffix(lower, ".sudoers") || name == "sudoers" || !strings.Contains(name, ".") {
					sudoersFiles = append(sudoersFiles, path)
				}
				return nil
			})
			if err != nil {
				return fmt.Errorf("failed to walk directory: %w", err)
			}

			if hasRootSudoers {
				orderedSudoers := []string{rootSudoers}
				for _, sf := range sudoersFiles {
					if filepath.Clean(sf) != filepath.Clean(rootSudoers) {
						orderedSudoers = append(orderedSudoers, sf)
					}
				}
				sudoersFiles = orderedSudoers
			}

			if len(jsonFiles) > 0 && hasRootSudoers {
				files = append(files, jsonFiles...)
				files = append(files, sudoersFiles...)
			} else if len(jsonFiles) > 0 {
				files = jsonFiles
			} else {
				files = sudoersFiles
			}
		} else {
			files = append(files, targetPath)
		}

		if len(files) == 0 {
			return fmt.Errorf("no sudoers or JSON policy files found at target path: %s", targetPath)
		}

		normalizeKey := func(p string) string {
			if abs, err := filepath.Abs(filepath.FromSlash(p)); err == nil {
				return filepath.ToSlash(filepath.Clean(abs))
			}
			return filepath.ToSlash(filepath.Clean(p))
		}

		// 3. Parse and audit policies
		visitedFiles := make(map[string]bool)
		var combinedFindings []audit.Finding
		for _, file := range files {
			if visitedFiles[normalizeKey(file)] {
				continue
			}

			data, err := os.ReadFile(file)
			if err != nil {
				return fmt.Errorf("failed to read file %s: %w", file, err)
			}

			var policy *audit.SudoersPolicy
			if parser.IsJSONPolicy(data) {
				var p audit.SudoersPolicy
				if err := json.Unmarshal(data, &p); err != nil {
					if info.IsDir() {
						fmt.Fprintf(os.Stderr, "Warning: failed to parse JSON in %s (skipping): %v\n", file, err)
						continue
					}
					return fmt.Errorf("failed to parse JSON in %s: %w", file, err)
				}
				policy = &p
			} else if strings.HasSuffix(strings.ToLower(file), ".json") {
				if info.IsDir() {
					fmt.Fprintf(os.Stderr, "Warning: failed to parse JSON in %s (skipping): invalid JSON policy\n", file)
					continue
				}
				return fmt.Errorf("failed to parse JSON in %s: invalid JSON policy", file)
			} else {
				p, err := parser.ParseFile(file)
				if err != nil {
					if info.IsDir() {
						fmt.Fprintf(os.Stderr, "Warning: failed to parse sudoers file %s (skipping): %v\n", file, err)
						continue
					}
					return fmt.Errorf("failed to parse sudoers file %s: %w", file, err)
				}
				policy = p
			}

			visitedFiles[normalizeKey(file)] = true
			for _, inc := range policy.IncludedFiles {
				visitedFiles[normalizeKey(inc)] = true
			}

			// Run audit and set context as the file name
			findings := audit.RunAudit(policy, gtfoClient)
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

		generated, err := report.GenerateReportsWithOptions(result, getFormatsList(), outputDir, noColor)
		if err != nil {
			return fmt.Errorf("failed to generate reports: %w", err)
		}

		// Print summary in deterministic order
		if outputDir != "" {
			fmt.Fprintf(os.Stderr, "\nScan completed successfully! Generated reports:\n")
			fmtNames := make([]string, 0, len(generated))
			for fmtName := range generated {
				fmtNames = append(fmtNames, fmtName)
			}
			slices.Sort(fmtNames)
			for _, fmtName := range fmtNames {
				fmt.Fprintf(os.Stderr, "  - %s: %s\n", strings.ToUpper(fmtName), generated[fmtName])
			}
		}

		return checkFailOn(result)
	},
}

func init() {
	rootCmd.AddCommand(scanCmd)
}
