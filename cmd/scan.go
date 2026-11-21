package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sudo-check/pkg/audit"
	"sudo-check/pkg/parser"
	"sudo-check/pkg/patch"
	"sudo-check/pkg/report"
	"time"

	"github.com/spf13/cobra"
)

var (
	dropInMode     bool
	checkShadowing bool
	checkExpiry    bool
	fixPatchPath   string
	scanHost       string
)

// ignoredDocFiles lists common extensionless documentation and build files
// skipped during standalone directory walks so they are not audited as sudoers drop-ins.
var ignoredDocFiles = map[string]bool{
	"readme":     true,
	"license":    true,
	"licence":    true,
	"notice":     true,
	"changelog":  true,
	"copying":    true,
	"authors":    true,
	"makefile":   true,
	"dockerfile": true,
}

func isIgnoredDocFile(name string) bool {
	return ignoredDocFiles[strings.ToLower(name)]
}

func normalizePathKey(p string) string {
	native := filepath.FromSlash(p)
	if abs, err := filepath.Abs(native); err == nil {
		return filepath.ToSlash(filepath.Clean(abs))
	}
	return filepath.ToSlash(filepath.Clean(native))
}

var scanCmd = &cobra.Command{
	Use:   "scan <file-or-dir|->",
	Short: "Scan raw sudoers files, JSON, LDIF, sudo -ll, or stdin policies",
	Long:  `Scan a single raw sudoers configuration file, a pre-converted cvtsudoers JSON policy file, an LDIF export, sudo -ll output, stdin ('-'), or a directory of policy files.`,
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if strings.TrimSpace(failOn) != "" {
			if _, ok := audit.ParseSeverity(failOn); !ok {
				return fmt.Errorf("invalid --fail-on severity %q (valid values: CRITICAL, HIGH, MEDIUM, LOW, INFO)", failOn)
			}
		}

		cfg, err := loadEffectiveConfig(cmd)
		if err != nil {
			return err
		}

		targetPath := args[0]

		// 1. Initialize GTFObins client
		gtfoClient, err := newGTFOClientWithConfig(cfg)
		if err != nil {
			return fmt.Errorf("failed to load GTFObins: %w", err)
		}

		effectiveDropIn := dropInMode || cfg.DropInMode
		effectiveSubcmdAware := subcommandAware || cfg.SubcommandAware
		effectiveShadowing := checkShadowing
		if effectiveDropIn && !cmd.Flags().Changed("check-shadowing") {
			effectiveShadowing = false
		}
		var nowFn func() time.Time
		if checkExpiry {
			nowFn = time.Now
		}
		auditOpts := audit.AuditOptions{
			DropInMode:          effectiveDropIn,
			SubcommandAwareGTFO: effectiveSubcmdAware,
			CheckShadowing:      effectiveShadowing,
			Now:                 nowFn,
		}

		// 2. Parse and audit policies (supporting stdin '-' or disk file/directory)
		var (
			combinedFindings []audit.Finding
			singleRawBytes   []byte
			targetLabel      string
			isSingleTarget   bool
		)

		if targetPath == "-" {
			stdinBytes, readErr := io.ReadAll(cmd.InOrStdin())
			if readErr != nil {
				return fmt.Errorf("failed to read stdin: %w", readErr)
			}
			policy, parseErr := parser.ParseReaderWithOptions(bytes.NewReader(stdinBytes), "stdin", "", parser.ParseOptions{
				Hostname: scanHost,
				Offline:  true,
			})
			if parseErr != nil {
				return fmt.Errorf("failed to parse policy from stdin: %w", parseErr)
			}

			findings := audit.RunAuditWithOptions(policy, gtfoClient, auditOpts)
			for i := range findings {
				if findings[i].Context == "" {
					findings[i].Context = "stdin"
				}
			}
			combinedFindings = append(combinedFindings, findings...)
			singleRawBytes = stdinBytes
			targetLabel = "stdin"
			isSingleTarget = true
		} else {
			var files []string
			info, statErr := os.Stat(targetPath)
			if statErr != nil {
				return fmt.Errorf("target path not found: %w", statErr)
			}

			if strings.TrimSpace(fixPatchPath) != "" && info.IsDir() {
				return fmt.Errorf("--fix-patch requires a single raw sudoers file target, not directory %q", targetPath)
			}

			if info.IsDir() {
				var jsonFiles []string
				var sudoersFiles []string
				var extraPolicyFiles []string
				rootSudoers := filepath.Join(targetPath, "sudoers")
				hasRootSudoers := false
				if st, stErr := os.Stat(rootSudoers); stErr == nil && !st.IsDir() {
					hasRootSudoers = true
				}

				walkErr := filepath.Walk(targetPath, func(path string, fInfo os.FileInfo, walkErr error) error {
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
					if isIgnoredDocFile(name) {
						return nil
					}
					if strings.HasSuffix(lower, ".ldif") || strings.HasSuffix(lower, ".sudoll") {
						extraPolicyFiles = append(extraPolicyFiles, path)
						return nil
					}
					if strings.HasSuffix(lower, ".sudoers") || name == "sudoers" || !strings.Contains(name, ".") {
						sudoersFiles = append(sudoersFiles, path)
					}
					return nil
				})
				if walkErr != nil {
					return fmt.Errorf("failed to walk directory: %w", walkErr)
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

				// Always scan raw sudoers files (root sudoers first), JSON policy files, and LDIF/sudoll files;
				// non-policy JSON files are skipped with a warning during the audit loop below.
				files = append(files, sudoersFiles...)
				files = append(files, jsonFiles...)
				files = append(files, extraPolicyFiles...)
			} else {
				files = append(files, targetPath)
				isSingleTarget = true
				targetLabel = filepath.ToSlash(targetPath)
			}

			if len(files) == 0 {
				return fmt.Errorf("no sudoers, JSON, or LDIF policy files found at target path: %s", targetPath)
			}

			visitedFiles := make(map[string]bool)
			for _, file := range files {
				if visitedFiles[normalizePathKey(file)] {
					continue
				}

				data, readErr := os.ReadFile(file)
				if readErr != nil {
					return fmt.Errorf("failed to read file %s: %w", file, readErr)
				}
				if !info.IsDir() {
					singleRawBytes = data
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
						fmt.Fprintf(os.Stderr, "Warning: skipping non-policy JSON file %s: invalid JSON policy\n", file)
						continue
					}
					return fmt.Errorf("failed to parse JSON in %s: invalid JSON policy", file)
				} else {
					p, err := parser.ParseFileWithOptions(file, parser.ParseOptions{
						Hostname: scanHost,
						Offline:  true,
					})
					if err != nil {
						if info.IsDir() {
							fmt.Fprintf(os.Stderr, "Warning: failed to parse sudoers file %s (skipping): %v\n", file, err)
							continue
						}
						return fmt.Errorf("failed to parse sudoers file %s: %w", file, err)
					}
					policy = p
				}

				visitedFiles[normalizePathKey(file)] = true
				for _, inc := range policy.IncludedFiles {
					visitedFiles[normalizePathKey(inc)] = true
				}

				// Run audit and set context as the file name
				findings := audit.RunAuditWithOptions(policy, gtfoClient, auditOpts)
				for i := range findings {
					if findings[i].Context == "" {
						findings[i].Context = filepath.ToSlash(file)
					}
				}
				combinedFindings = append(combinedFindings, findings...)
			}
		}

		// 3. Optional hardening patch generation for single raw sudoers target
		if trimmedPatch := strings.TrimSpace(fixPatchPath); trimmedPatch != "" {
			if !isSingleTarget {
				return fmt.Errorf("--fix-patch is only supported for a single raw sudoers file target")
			}
			if parser.IsJSONPolicy(singleRawBytes) || parser.IsSudoLLOutput(singleRawBytes) || parser.IsLDIFPolicy(singleRawBytes) {
				return fmt.Errorf("--fix-patch requires raw sudoers syntax; non-raw policy format detected for %s", targetLabel)
			}
			patchText, _, patchErr := patch.GenerateHardeningPatch(targetLabel, singleRawBytes, combinedFindings)
			if patchErr != nil {
				return fmt.Errorf("failed to generate hardening patch: %w", patchErr)
			}
			if writeErr := os.WriteFile(trimmedPatch, []byte(patchText), 0644); writeErr != nil {
				return fmt.Errorf("failed to write hardening patch %s: %w", trimmedPatch, writeErr)
			}
			if patchText == "" {
				fmt.Fprintf(os.Stderr, "No safe hardening changes required for %s (wrote empty patch to %s)\n", targetLabel, trimmedPatch)
			} else {
				fmt.Fprintf(os.Stderr, "Hardening patch written to %s\n", trimmedPatch)
			}
		}

		// 4. Apply config/baseline and generate reports
		// Do not populate Hostname for offline scans because the audited files
		// typically originate from remote hosts rather than the auditor workstation.
		result := &audit.AuditResult{
			PolicyFindings: combinedFindings,
		}

		filteredResult, gateResult, err := applyConfigAndBaseline(result, cfg, baselinePath)
		if err != nil {
			return err
		}

		generated, err := report.GenerateReportsWithOptions(filteredResult, getFormatsList(), outputDir, noColor)
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

		return checkFailOn(gateResult)
	},
}

func init() {
	scanCmd.Flags().BoolVar(&dropInMode, "dropin", false, "Audit standalone drop-in file(s), suppressing missing global Defaults rules (SUDO-DEF-001, 003, 007, 008, 009, 010, 011, 017)")
	scanCmd.Flags().BoolVar(&checkShadowing, "check-shadowing", true, "Enable SUDO-CMD-015 shadowing analysis (automatically defaults to false when --dropin is enabled unless explicitly set)")
	scanCmd.Flags().BoolVar(&checkExpiry, "check-expiry", false, "Enable SUDO-CMD-016 NOTBEFORE/NOTAFTER validity window checks against current time")
	scanCmd.Flags().StringVar(&fixPatchPath, "fix-patch", "", "Write a safe hardening unified diff patch for a single raw sudoers file")
	scanCmd.Flags().StringVar(&scanHost, "host", "", "Target hostname used to expand %h in #include/@include directives during offline scans (disabled by default for determinism)")
	rootCmd.AddCommand(scanCmd)
}
