package cmd

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"sudo-check/pkg/audit"
	"sudo-check/pkg/gtfobins"

	"github.com/spf13/cobra"
)

// ErrFailOnThreshold is returned when findings meet or exceed the --fail-on severity threshold.
var ErrFailOnThreshold = errors.New("findings exceeded fail-on severity threshold")

var (
	outputDir      string
	formats        string
	gtfoBinsPath   string
	cvtSudoersPath string
	failOn         string
	noColor        bool
)

var rootCmd = &cobra.Command{
	Use:   "sudo-check",
	Short: "sudo-check audits sudoers policies and target host configurations for security risks",
	Long: `A statically compiled command-line utility to audit sudoers configuration policies
for security misconfigurations, dangerous defaults, and privilege escalation vectors
via the GTFObins database.

It supports scanning raw sudoers configuration files (using its built-in native parser),
pre-converted JSON policies (from cvtsudoers), or running autonomously on target systems.`,
	SilenceUsage:  true,
	SilenceErrors: true,
}

// Execute adds all child commands to the root command and sets flags appropriately.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		if errors.Is(err, ErrFailOnThreshold) {
			os.Exit(2)
		}
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&outputDir, "output-dir", "o", "", "Directory to save the generated reports (if not set, text/json/sarif reports are written to stdout)")
	rootCmd.PersistentFlags().StringVarP(&formats, "formats", "f", "text,sarif,pdf,html", "Comma-separated list of output formats (text, json, sarif, pdf, html)")
	rootCmd.PersistentFlags().StringVar(&gtfoBinsPath, "gtfobins-path", "", "Path to custom gtfobins.json database snapshot")
	rootCmd.PersistentFlags().StringVar(&cvtSudoersPath, "cvtsudoers-path", "", "Path to custom cvtsudoers binary")
	rootCmd.PersistentFlags().StringVar(&failOn, "fail-on", "", "Exit with non-zero status if any finding meets or exceeds this severity (CRITICAL, HIGH, MEDIUM, LOW, INFO)")
	rootCmd.PersistentFlags().BoolVar(&noColor, "no-color", false, "Disable ANSI color output in terminal reports")
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

// checkFailOn validates the --fail-on flag and returns ErrFailOnThreshold if any finding meets or exceeds it.
func checkFailOn(result *audit.AuditResult) error {
	if strings.TrimSpace(failOn) == "" {
		return nil
	}
	threshold, ok := audit.ParseSeverity(failOn)
	if !ok {
		return fmt.Errorf("invalid --fail-on severity %q (valid values: CRITICAL, HIGH, MEDIUM, LOW, INFO)", failOn)
	}
	if result != nil && audit.HasSeverityAtLeast(threshold, result.PolicyFindings, result.SystemFindings) {
		return fmt.Errorf("%w: at least one finding has severity >= %s", ErrFailOnThreshold, threshold)
	}
	return nil
}
