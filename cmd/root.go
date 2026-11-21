package cmd

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"sudo-check/pkg/audit"
	"sudo-check/pkg/config"
	"sudo-check/pkg/gtfobins"
	"time"

	"github.com/spf13/cobra"
)

// ErrFailOnThreshold is returned when findings meet or exceed the --fail-on severity threshold.
var ErrFailOnThreshold = errors.New("findings exceeded fail-on severity threshold")

var (
	outputDir          string
	formats            string
	gtfoBinsPath       string
	cvtSudoersPath     string
	failOn             string
	noColor            bool
	configPath         string
	profileName        string
	customGTFObinsPath string
	baselinePath       string
	subcommandAware    bool
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
	rootCmd.PersistentFlags().StringVar(&configPath, "config", "", "Path to .sudo-check.yaml or .sudo-check.json configuration file")
	rootCmd.PersistentFlags().StringVar(&profileName, "profile", "", "Compliance profile filter (all, anssi-bp028, cis-5.2, disa-stig, minimal)")
	rootCmd.PersistentFlags().StringVar(&customGTFObinsPath, "custom-gtfobins", "", "Path to custom GTFObins overlay JSON file merged onto the catalog")
	rootCmd.PersistentFlags().StringVar(&baselinePath, "baseline", "", "Path to baseline report.json (fail --fail-on only on newly added findings)")
	rootCmd.PersistentFlags().BoolVar(&subcommandAware, "subcommand-aware", false, "Enable subcommand/argument-aware GTFObins risk evaluation")
}

// loadEffectiveConfig loads the configuration file (if --config is set), applies
// explicit CLI flag overrides, validates the result, and returns it.
func loadEffectiveConfig(cmd *cobra.Command) (*config.Config, error) {
	var cfg *config.Config
	if trimmed := strings.TrimSpace(configPath); trimmed != "" {
		loaded, err := config.LoadFile(trimmed)
		if err != nil {
			return nil, err
		}
		cfg = loaded
	} else {
		cfg = &config.Config{}
	}

	if p := strings.TrimSpace(profileName); p != "" {
		cfg.Profile = p
	}
	if custom := strings.TrimSpace(customGTFObinsPath); custom != "" {
		cfg.CustomGTFObins = custom
	}
	if (cmd != nil && cmd.Flags().Changed("subcommand-aware")) || subcommandAware {
		cfg.SubcommandAware = subcommandAware
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
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

// newGTFOClient creates a GTFObins client using the custom path flag or the embedded database,
// merging any --custom-gtfobins overlay.
func newGTFOClient() (*gtfobins.Client, error) {
	return newGTFOClientWithConfig(nil)
}

// newGTFOClientWithConfig creates a GTFObins client using --gtfobins-path or the embedded database
// and merges any custom GTFObins overlay from --custom-gtfobins or cfg.CustomGTFObins.
func newGTFOClientWithConfig(cfg *config.Config) (*gtfobins.Client, error) {
	var (
		client *gtfobins.Client
		err    error
	)
	if trimmedPath := strings.TrimSpace(gtfoBinsPath); trimmedPath != "" {
		client, err = gtfobins.NewClientFromFile(trimmedPath)
	} else {
		client, err = gtfobins.NewClient()
	}
	if err != nil {
		return nil, err
	}

	overlayPath := strings.TrimSpace(customGTFObinsPath)
	if overlayPath == "" && cfg != nil {
		overlayPath = strings.TrimSpace(cfg.CustomGTFObins)
	}
	if overlayPath != "" {
		if err := client.MergeOverlayFile(overlayPath); err != nil {
			return nil, fmt.Errorf("failed to merge custom GTFObins overlay: %w", err)
		}
	}
	return client, nil
}

// applyConfigAndBaseline populates finding fingerprints, applies configuration filters/overrides/suppressions,
// warns on expired suppressions, and optionally computes a baseline diff gate result.
func applyConfigAndBaseline(result *audit.AuditResult, cfg *config.Config, baselineFile string) (filtered *audit.AuditResult, gateResult *audit.AuditResult, err error) {
	if result != nil {
		audit.PopulateFingerprints(result.PolicyFindings)
		audit.PopulateFingerprints(result.SystemFindings)
	}

	filtered, _, expired := config.Apply(result, cfg, time.Now().UTC())
	for _, exp := range expired {
		fmt.Fprintf(os.Stderr, "Warning: suppression for rule %q expired on %s (%s) and was not applied\n", exp.Rule, exp.Expires, exp.Reason)
	}

	gateResult = filtered
	if trimmedBaseline := strings.TrimSpace(baselineFile); trimmedBaseline != "" {
		baselineRes, err := config.LoadBaselineResult(trimmedBaseline)
		if err != nil {
			return nil, nil, err
		}
		diff := config.DiffResults(baselineRes, filtered)
		fmt.Fprintf(os.Stderr, "Baseline diff: %d added, %d resolved, %d unchanged\n", len(diff.Added), len(diff.Resolved), len(diff.Unchanged))
		gateResult = &audit.AuditResult{PolicyFindings: diff.Added}
	}

	return filtered, gateResult, nil
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
