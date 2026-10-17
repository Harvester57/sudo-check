package cmd

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sudo-check/pkg/audit"
	"sudo-check/pkg/cvtsudoers"
	"sudo-check/pkg/parser"
	"sudo-check/pkg/report"

	"github.com/spf13/cobra"
)

var (
	sudoersFile string
)

var systemCmd = &cobra.Command{
	Use:   "system",
	Short: "Audit the local system configuration autonomously",
	Long: `Run an autonomous security scan on the local host. Converts or natively parses
the active /etc/sudoers policy, audits it, and checks local sudo version CVEs
and file permissions.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if strings.TrimSpace(failOn) != "" {
			if _, ok := audit.ParseSeverity(failOn); !ok {
				return fmt.Errorf("invalid --fail-on severity %q (valid values: CRITICAL, HIGH, MEDIUM, LOW, INFO)", failOn)
			}
		}

		// 1. Initialize GTFObins client
		gtfoClient, err := newGTFOClient()
		if err != nil {
			return fmt.Errorf("failed to load GTFObins: %w", err)
		}

		// 2. Parse policy via cvtsudoers (preferred when available) or fallback to native parser
		fmt.Fprintf(os.Stderr, "Locating and parsing sudoers policy from '%s'...\n", sudoersFile)
		var policy *audit.SudoersPolicy
		wrapper, wrapperErr := cvtsudoers.NewWrapper(cvtSudoersPath)
		if wrapperErr != nil {
			if cvtSudoersPath != "" {
				return wrapperErr
			}
			fmt.Fprintf(os.Stderr, "Notice: cvtsudoers not found in PATH, using built-in native sudoers parser...\n")
			policy, err = parser.ParseFile(sudoersFile)
		} else {
			policy, err = wrapper.ConvertPolicy(sudoersFile)
		}
		if err != nil {
			if os.IsPermission(err) || strings.Contains(strings.ToLower(err.Error()), "permission denied") || strings.Contains(strings.ToLower(err.Error()), "unable to open") {
				return fmt.Errorf("%w\n[!] TIP: Sudoers files are typically root-only readable. Please run this command using 'sudo' or as the 'root' user.", err)
			}
			return err
		}

		// 3. Run policy audits
		fmt.Fprintf(os.Stderr, "Auditing policy configuration...\n")
		policyFindings := audit.RunAudit(policy, gtfoClient)
		for i := range policyFindings {
			if policyFindings[i].Context == "" {
				policyFindings[i].Context = filepath.ToSlash(sudoersFile)
			}
		}

		// 4. System checks
		fmt.Fprintf(os.Stderr, "Performing target system checks...\n")
		var systemFindings []audit.Finding

		// Audit sudoers file permissions
		permFindings := audit.AuditSudoersPermissions(sudoersFile)
		systemFindings = append(systemFindings, permFindings...)

		// Audit sudoers.d directory permissions
		sudoersDir := filepath.Join(filepath.Dir(sudoersFile), "sudoers.d")
		dirFindings := audit.AuditSudoersDirPermissions(sudoersDir)
		systemFindings = append(systemFindings, dirFindings...)

		// Locate sudo binary via PATH fallback to /usr/bin/sudo
		sudoBinPath, lookErr := exec.LookPath("sudo")
		if lookErr != nil || sudoBinPath == "" {
			sudoBinPath = "/usr/bin/sudo"
		}
		sudoBinaryFindings := audit.AuditSudoBinaryPermissions(sudoBinPath)
		systemFindings = append(systemFindings, sudoBinaryFindings...)

		// Audit target binaries referenced in the sudoers policy
		targetBinFindings := audit.AuditPolicyTargetBinaries(policy)
		systemFindings = append(systemFindings, targetBinFindings...)

		// Audit sudo version
		var sudoVersionStr string
		sudoCmd := exec.Command(sudoBinPath, "--version")
		var sudoOut bytes.Buffer
		sudoCmd.Stdout = &sudoOut
		sudoCmd.Stderr = &sudoOut
		if err := sudoCmd.Run(); err == nil {
			verRegex := regexp.MustCompile(`Sudo version\s+([0-9]+\.[0-9]+\.[0-9]+(?:p[0-9]+)?)`)
			matches := verRegex.FindStringSubmatch(sudoOut.String())
			if len(matches) > 1 {
				sudoVersionStr = matches[1]
				fmt.Fprintf(os.Stderr, "Detected Sudo Version: %s\n", sudoVersionStr)
				vFindings, err := audit.AuditSudoVersion(sudoVersionStr)
				if err == nil {
					systemFindings = append(systemFindings, vFindings...)
				}
			}
		} else {
			fmt.Fprintf(os.Stderr, "Warning: 'sudo' binary execution failed, skipping version vulnerability checks: %v\n", err)
		}

		// 5. Generate Reports
		hostname, _ := os.Hostname()
		result := &audit.AuditResult{
			PolicyFindings: policyFindings,
			SystemFindings: systemFindings,
			SudoVersion:    sudoVersionStr,
			Hostname:       hostname,
		}

		generated, err := report.GenerateReportsWithOptions(result, getFormatsList(), outputDir, noColor)
		if err != nil {
			return fmt.Errorf("failed to generate reports: %w", err)
		}

		// Print summary in deterministic order
		if outputDir != "" {
			fmt.Fprintf(os.Stderr, "\nSystem audit completed successfully! Generated reports:\n")
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
	systemCmd.Flags().StringVar(&sudoersFile, "sudoers-file", "/etc/sudoers", "Path to target sudoers file (defaults to /etc/sudoers)")
	rootCmd.AddCommand(systemCmd)
}
