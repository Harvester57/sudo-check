package cmd

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"slices"
	"strings"
	"sudo-check/pkg/audit"
	"sudo-check/pkg/cvtsudoers"
	"sudo-check/pkg/report"

	"github.com/spf13/cobra"
)

var (
	sudoersFile string
)

var systemCmd = &cobra.Command{
	Use:   "system",
	Short: "Audit the local system configuration autonomously",
	Long: `Run an autonomous security scan on the local host. Locates the cvtsudoers binary, 
converts the active /etc/sudoers policy to JSON, audits it, and audits local sudo version CVEs 
and file permissions.`,
	RunE: func(cmd *cobra.Command, args []string) error {
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

		// 2. Initialize cvtsudoers wrapper
		wrapper, err := cvtsudoers.NewWrapper(cvtSudoersPath)
		if err != nil {
			return err
		}

		// 3. Convert policy
		fmt.Printf("Locating and parsing sudoers policy from '%s'...\n", sudoersFile)
		policy, err := wrapper.ConvertPolicy(sudoersFile)
		if err != nil {
			if os.IsPermission(err) || strings.Contains(err.Error(), "permission denied") || strings.Contains(err.Error(), "unable to open") {
				return fmt.Errorf("%w\n[!] TIP: Sudoers files are typically root-only readable. Please run this command using 'sudo' or as the 'root' user.", err)
			}
			return err
		}

		// 4. Run policy audits
		fmt.Println("Auditing policy configuration...")
		policyFindings := audit.RunAudit(policy, gtfoClient)

		// 5. System checks
		fmt.Println("Performing target system checks...")
		var systemFindings []audit.Finding

		// Audit sudoers file and /etc/sudoers.d permissions
		permFindings := audit.AuditSudoersPermissions(sudoersFile)
		systemFindings = append(systemFindings, permFindings...)

		// Resolve sudo binary path dynamically via PATH, falling back to /usr/bin/sudo
		sudoBinPath := "/usr/bin/sudo"
		if resolvedSudo, lookErr := exec.LookPath("sudo"); lookErr == nil && resolvedSudo != "" {
			sudoBinPath = resolvedSudo
		}

		// Audit sudo binary permissions
		sudoBinaryFindings := audit.AuditSudoBinaryPermissions(sudoBinPath)
		systemFindings = append(systemFindings, sudoBinaryFindings...)

		// Audit permissions of concrete command binaries permitted by the policy
		cmdPermFindings := audit.AuditAllowedCommandPermissions(policy)
		systemFindings = append(systemFindings, cmdPermFindings...)

		// Audit sudo version
		var sudoVersionStr string
		sudoCmd := exec.Command(sudoBinPath, "--version")
		var sudoOut bytes.Buffer
		sudoCmd.Stdout = &sudoOut
		sudoCmd.Stderr = &sudoOut
		if err := sudoCmd.Run(); err == nil {
			// Extract version string using regex
			verRegex := regexp.MustCompile(`Sudo version\s+([0-9]+\.[0-9]+\.[0-9]+(?:p[0-9]+)?)`)
			matches := verRegex.FindStringSubmatch(sudoOut.String())
			if len(matches) > 1 {
				sudoVersionStr = matches[1]
				fmt.Printf("Detected Sudo Version: %s\n", sudoVersionStr)
				vFindings, err := audit.AuditSudoVersion(sudoVersionStr)
				if err == nil {
					systemFindings = append(systemFindings, vFindings...)
				}
			}
		} else {
			fmt.Fprintf(os.Stderr, "Warning: 'sudo' binary execution failed, skipping version vulnerability checks: %v\n", err)
		}

		// 6. Generate Reports
		hostname, _ := os.Hostname()
		result := &audit.AuditResult{
			PolicyFindings: policyFindings,
			SystemFindings: systemFindings,
			SudoVersion:    sudoVersionStr,
			Hostname:       hostname,
		}

		generated, err := report.GenerateReports(result, getFormatsList(), outputDir)
		if err != nil {
			return fmt.Errorf("failed to generate reports: %w", err)
		}

		// Print summary in deterministic order
		if outputDir != "" {
			fmt.Printf("\nSystem audit completed successfully! Generated reports:\n")
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
	systemCmd.Flags().StringVar(&sudoersFile, "sudoers-file", "/etc/sudoers", "Path to target sudoers file (defaults to /etc/sudoers)")
	rootCmd.AddCommand(systemCmd)
}
