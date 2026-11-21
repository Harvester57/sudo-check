package cmd

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sudo-check/pkg/audit"
	"sudo-check/pkg/cvtsudoers"
	"sudo-check/pkg/parser"
	"sudo-check/pkg/report"
	"time"

	"github.com/spf13/cobra"
)

var (
	sudoersFile string

	classicSudoVersionRegex = regexp.MustCompile(`Sudo version\s+([0-9]+\.[0-9]+\.[0-9]+(?:p[0-9]+)?)`)
	sudoRSVersionRegex      = regexp.MustCompile(`sudo-rs\s+([0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.]+)?)`)
)

func isPermissionError(err error) bool {
	if err == nil {
		return false
	}
	lower := strings.ToLower(err.Error())
	return os.IsPermission(err) || strings.Contains(lower, "permission denied") || strings.Contains(lower, "unable to open")
}

// isUntrustedSudoBinary reports whether sudo binary permission or ownership checks
// identified tampering risks (group-writable, world-writable, or non-root owned).
func isUntrustedSudoBinary(findings []audit.Finding) bool {
	for _, f := range findings {
		switch f.ID {
		case "SUDO-SYS-PERM-008", "SUDO-SYS-PERM-009", "SUDO-SYS-PERM-010":
			return true
		}
	}
	return false
}

// parseSudoVersionOutput extracts the sudo version string from `sudo --version`
// output and reports whether the binary is the Rust sudo-rs implementation.
func parseSudoVersionOutput(output string) (version string, isSudoRS bool) {
	if matches := sudoRSVersionRegex.FindStringSubmatch(output); len(matches) > 1 {
		return "sudo-rs " + matches[1], true
	}
	if matches := classicSudoVersionRegex.FindStringSubmatch(output); len(matches) > 1 {
		return matches[1], false
	}
	return "", false
}

// collectAdditionalIncludedFiles filters policy.IncludedFiles to those not already
// audited by AuditSudoersPermissions(sudoersFile) or AuditSudoersDirPermissions(sudoersDir).
func collectAdditionalIncludedFiles(sudoersFile, sudoersDir string, includedFiles []string) []string {
	sudoersKey := normalizePathKey(sudoersFile)
	sudoersDirKey := normalizePathKey(sudoersDir)

	seen := map[string]bool{
		sudoersKey: true,
	}

	var additional []string
	for _, inc := range includedFiles {
		if strings.TrimSpace(inc) == "" {
			continue
		}
		incKey := normalizePathKey(inc)
		if seen[incKey] {
			continue
		}
		seen[incKey] = true

		// Files directly inside sudoersDir without '.' or trailing '~' are already
		// audited by audit.AuditSudoersDirPermissions(sudoersDir).
		base := path.Base(incKey)
		if path.Dir(incKey) == sudoersDirKey && !strings.Contains(base, ".") && !strings.HasSuffix(base, "~") {
			continue
		}

		additional = append(additional, filepath.Clean(filepath.FromSlash(inc)))
	}
	return additional
}

var systemCmd = &cobra.Command{
	Use:   "system",
	Short: "Audit the local system configuration autonomously",
	Long: `Run an autonomous security scan on the local host. Natively parses or converts
the active /etc/sudoers policy, audits it, and checks local sudo version CVEs
and file permissions.`,
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

		// 1. Initialize GTFObins client
		gtfoClient, err := newGTFOClientWithConfig(cfg)
		if err != nil {
			return fmt.Errorf("failed to load GTFObins: %w", err)
		}

		// 2. Parse policy: strictly use custom --cvtsudoers-path if set; otherwise prefer
		// built-in native parser (preserving exact per-file Context, Line, and IncludedFiles)
		// with automatic fallback to cvtsudoers on non-permission parse errors.
		fmt.Fprintf(os.Stderr, "Locating and parsing sudoers policy from '%s'...\n", sudoersFile)
		var policy *audit.SudoersPolicy
		if cvtSudoersPath != "" {
			wrapper, wrapperErr := cvtsudoers.NewWrapper(cvtSudoersPath)
			if wrapperErr != nil {
				return wrapperErr
			}
			policy, err = wrapper.ConvertPolicy(sudoersFile)
		} else {
			policy, err = parser.ParseFile(sudoersFile)
			if err != nil && !isPermissionError(err) && !os.IsNotExist(err) {
				if wrapper, wrapperErr := cvtsudoers.NewWrapper(""); wrapperErr == nil {
					fmt.Fprintf(os.Stderr, "Notice: built-in native parser failed (%v), falling back to cvtsudoers...\n", err)
					policy, err = wrapper.ConvertPolicy(sudoersFile)
				}
			}
		}
		if err != nil {
			if isPermissionError(err) {
				return fmt.Errorf("%w\n[!] TIP: Sudoers files are typically root-only readable. Please run this command using 'sudo' or as the 'root' user.", err)
			}
			return err
		}

		// 3. Run policy audits
		fmt.Fprintf(os.Stderr, "Auditing policy configuration...\n")
		auditOpts := audit.AuditOptions{
			SubcommandAwareGTFO: subcommandAware || cfg.SubcommandAware,
			CheckShadowing:      true,
			Now:                 time.Now,
		}
		policyFindings := audit.RunAuditWithOptions(policy, gtfoClient, auditOpts)
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

		// Audit permissions on all additional included policy files (#include / custom #includedir)
		for _, incFile := range collectAdditionalIncludedFiles(sudoersFile, sudoersDir, policy.IncludedFiles) {
			systemFindings = append(systemFindings, audit.AuditSudoersPermissions(incFile)...)
		}

		// Locate sudo binary via PATH fallback to /usr/bin/sudo
		sudoBinPath, lookErr := exec.LookPath("sudo")
		if lookErr != nil || sudoBinPath == "" {
			sudoBinPath = "/usr/bin/sudo"
		}
		sudoBinaryFindings := audit.AuditSudoBinaryPermissions(sudoBinPath)
		systemFindings = append(systemFindings, sudoBinaryFindings...)
		systemFindings = append(systemFindings, audit.AuditSudoBinaryGroupRestriction(sudoBinPath)...)

		// Audit target binaries, referenced scripts, and referenced principals in the sudoers policy
		targetBinFindings := audit.AuditPolicyTargetBinaries(policy)
		systemFindings = append(systemFindings, targetBinFindings...)
		systemFindings = append(systemFindings, audit.AuditPolicyTargetScripts(policy)...)
		systemFindings = append(systemFindings, audit.AuditLocalPolicyIdentities(policy)...)

		// Audit sudo version (refuse to execute untrusted sudo binaries as root)
		var sudoVersionStr string
		if isUntrustedSudoBinary(sudoBinaryFindings) {
			fmt.Fprintf(os.Stderr, "Warning: refusing to execute untrusted sudo binary '%s' (failed ownership/write-permission checks); skipping version checks.\n", sudoBinPath)
			systemFindings = append(systemFindings, audit.Finding{
				ID:              "SUDO-SYS-001",
				Title:           "Sudo Version Check Skipped for Untrusted Binary",
				Description:     fmt.Sprintf("Execution of '%s --version' was skipped because the sudo binary failed ownership or write-permission checks (SUDO-SYS-PERM-008/009/010). Running an untrusted binary as root could execute attacker-controlled code.", sudoBinPath),
				Severity:        audit.SeverityInfo,
				Context:         sudoBinPath,
				Remediation:     fmt.Sprintf("Restore root ownership and secure permissions on '%s' before running version checks.", sudoBinPath),
				RemediationCode: "sudo chown root:root " + sudoBinPath + "\nsudo chmod 4755 " + sudoBinPath,
			})
		} else {
			sudoCmd := exec.Command(sudoBinPath, "--version")
			var sudoOut bytes.Buffer
			sudoCmd.Stdout = &sudoOut
			sudoCmd.Stderr = &sudoOut
			if err := sudoCmd.Run(); err == nil {
				ver, isSudoRS := parseSudoVersionOutput(sudoOut.String())
				if ver != "" {
					sudoVersionStr = ver
					if isSudoRS {
						fmt.Fprintf(os.Stderr, "Detected Sudo Implementation: %s (skipping classic C sudo CVE checks)\n", sudoVersionStr)
					} else {
						fmt.Fprintf(os.Stderr, "Detected Sudo Version: %s\n", sudoVersionStr)
						vFindings, err := audit.AuditSudoVersion(sudoVersionStr)
						if err == nil {
							patchedCVEs := audit.CollectLocalPatchedSudoCVEs()
							vFindings = audit.FilterBackportedCVEs(vFindings, patchedCVEs)
							vFindings = audit.CorrelateCVEsWithPolicy(vFindings, policy)
							systemFindings = append(systemFindings, vFindings...)
						}
					}
				}
			} else {
				fmt.Fprintf(os.Stderr, "Warning: 'sudo' binary execution failed, skipping version vulnerability checks: %v\n", err)
			}
		}

		// 5. Apply config/baseline and generate reports
		hostname, _ := os.Hostname()
		result := &audit.AuditResult{
			PolicyFindings: policyFindings,
			SystemFindings: systemFindings,
			SudoVersion:    sudoVersionStr,
			Hostname:       hostname,
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

		return checkFailOn(gateResult)
	},
}

func init() {
	systemCmd.Flags().StringVar(&sudoersFile, "sudoers-file", "/etc/sudoers", "Path to target sudoers file (defaults to /etc/sudoers)")
	rootCmd.AddCommand(systemCmd)
}
