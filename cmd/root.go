package cmd

import (
	"fmt"
	"os"
	"strings"
	"sudo-check/pkg/audit"
	"sudo-check/pkg/gtfobins"

	"github.com/spf13/cobra"
)

var (
	outputDir      string
	formats        string
	gtfoBinsPath   string
	cvtSudoersPath string
	failOnSeverity string
)

var rootCmd = &cobra.Command{
	Use:   "sudo-check",
	Short: "sudo-check audits sudoers policies and target host configurations for security risks",
	Long: `A statically compiled command-line utility to audit sudoers configuration policies 
for security misconfigurations, dangerous defaults, and privilege escalation vectors 
via the GTFObins database.

It supports scanning pre-converted JSON policies (from cvtsudoers) or running autonomously 
on target systems using the local cvtsudoers command.`,
	SilenceUsage:  true,
	SilenceErrors: true,
}

// Execute adds all child commands to the root command and sets flags appropriately.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&outputDir, "output-dir", "o", "", "Directory to save the generated reports (if not set, plaintext reports are written to stdout)")
	rootCmd.PersistentFlags().StringVarP(&formats, "formats", "f", "text,sarif,pdf,html", "Comma-separated list of output formats (text, sarif, pdf, html)")
	rootCmd.PersistentFlags().StringVar(&gtfoBinsPath, "gtfobins-path", "", "Path to custom gtfobins.json database snapshot")
	rootCmd.PersistentFlags().StringVar(&cvtSudoersPath, "cvtsudoers-path", "", "Path to custom cvtsudoers binary")
	rootCmd.PersistentFlags().StringVar(&failOnSeverity, "fail-on", "", "Exit with code 1 if any finding meets or exceeds this severity (critical, high, medium, low, info)")
}

// getFormatsList returns the slice of formatted outputs selected by the user.
func getFormatsList() []string {
	parts := strings.Split(formats, ",")
	var cleaned []string
	for _, p := range parts {
		c := strings.TrimSpace(p)
		if c != "" {
			cleaned = append(cleaned, c)
		}
	}
	return cleaned
}

// newGTFOClient creates a GTFObins client using the custom path flag or the embedded database.
func newGTFOClient() (*gtfobins.Client, error) {
	if gtfoBinsPath != "" {
		return gtfobins.NewClientFromFile(gtfoBinsPath)
	}
	return gtfobins.NewClient()
}

// checkFailOnThreshold validates and evaluates the optional --fail-on severity threshold.
// When failOnSeverity is empty (default), it always returns nil to preserve exit code 0.
func checkFailOnThreshold(result *audit.AuditResult) error {
	if strings.TrimSpace(failOnSeverity) == "" {
		return nil
	}
	threshold, err := audit.ParseSeverity(failOnSeverity)
	if err != nil {
		return err
	}
	if result != nil && audit.HasFindingsAtOrAbove(threshold, result.SystemFindings, result.PolicyFindings) {
		return fmt.Errorf("audit failed: one or more findings met or exceeded the %s severity threshold", threshold)
	}
	return nil
}
