package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sudo-check/pkg/audit"
	"sudo-check/pkg/config"
	"sudo-check/pkg/gtfobins"
	"sudo-check/pkg/parser"

	"github.com/spf13/cobra"
)

var diffAuditResultKeys = map[string]bool{
	"policy_findings": true,
	"system_findings": true,
	"sudo_version":    true,
	"hostname":        true,
}

var diffCmd = &cobra.Command{
	Use:   "diff <old-file-or-report> <new-file-or-report>",
	Short: "Compare two sudoers policies or audit reports",
	Long: `Compare a baseline sudoers policy or JSON AuditResult report against a current
sudoers policy or JSON AuditResult report and list Added, Resolved, and Unchanged
findings using deterministic finding fingerprints.`,
	Args: cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		fmtName, err := diffResolveFormat(cmd)
		if err != nil {
			return err
		}

		var threshold audit.Severity
		hasFailOn := false
		if strings.TrimSpace(failOn) != "" {
			var ok bool
			threshold, ok = audit.ParseSeverity(failOn)
			if !ok {
				return fmt.Errorf("invalid --fail-on severity %q (valid values: CRITICAL, HIGH, MEDIUM, LOW, INFO)", failOn)
			}
			hasFailOn = true
		}

		gtfoClient, err := newGTFOClient()
		if err != nil {
			return fmt.Errorf("failed to load GTFObins: %w", err)
		}

		oldRes, oldIsPolicy, err := diffLoadInputAsResult(args[0], gtfoClient)
		if err != nil {
			return err
		}
		newRes, newIsPolicy, err := diffLoadInputAsResult(args[1], gtfoClient)
		if err != nil {
			return err
		}

		if oldIsPolicy && newIsPolicy {
			diffNormalizePolicyContext(oldRes, args[0])
			diffNormalizePolicyContext(newRes, args[1])
		}

		diff := config.DiffResults(oldRes, newRes)

		out := cmd.OutOrStdout()
		switch fmtName {
		case "json":
			enc := json.NewEncoder(out)
			enc.SetIndent("", "  ")
			if err := enc.Encode(diff); err != nil {
				return err
			}
		default:
			if err := diffWriteText(out, args[0], args[1], diff); err != nil {
				return err
			}
		}

		if hasFailOn && audit.HasSeverityAtLeast(threshold, diff.Added) {
			return fmt.Errorf("%w: at least one newly added finding has severity >= %s", ErrFailOnThreshold, threshold)
		}
		return nil
	},
}

func diffResolveFormat(cmd *cobra.Command) (string, error) {
	if !cmd.Flags().Changed("formats") {
		return "text", nil
	}
	fmts := getFormatsList()
	if len(fmts) != 1 {
		return "", fmt.Errorf("diff requires a single output format (supported: text, json)")
	}
	norm := strings.ToLower(strings.TrimSpace(fmts[0]))
	switch norm {
	case "text", "txt":
		return "text", nil
	case "json":
		return "json", nil
	default:
		return "", fmt.Errorf("unsupported format %q for diff (supported: text, json)", fmts[0])
	}
}

func diffHasAuditResultKey(obj map[string]json.RawMessage) bool {
	for k := range obj {
		if diffAuditResultKeys[k] {
			return true
		}
	}
	return false
}

func diffLoadInputAsResult(path string, gtfoClient *gtfobins.Client) (*audit.AuditResult, bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false, fmt.Errorf("failed to read input file %s: %w", path, err)
	}

	trimmed := bytes.TrimSpace(bytes.TrimPrefix(data, []byte("\xef\xbb\xbf")))
	if len(trimmed) > 0 && trimmed[0] == '{' && json.Valid(trimmed) {
		if !parser.IsJSONPolicy(trimmed) {
			var obj map[string]json.RawMessage
			if err := json.Unmarshal(trimmed, &obj); err == nil && diffHasAuditResultKey(obj) {
				res, err := config.LoadBaselineResult(path)
				if err != nil {
					return nil, false, err
				}
				return res, false, nil
			}
			return nil, false, fmt.Errorf("file %s is JSON but is neither an audit report nor a cvtsudoers policy", path)
		}
	} else if strings.HasSuffix(strings.ToLower(path), ".json") {
		return nil, false, fmt.Errorf("failed to parse JSON in %s: invalid JSON report or policy", path)
	}

	policy, err := parser.ParseFileWithOptions(path, parser.ParseOptions{
		Offline: true,
	})
	if err != nil {
		return nil, false, err
	}

	findings := audit.RunAuditWithOptions(policy, gtfoClient, audit.AuditOptions{
		CheckShadowing: true,
	})
	defaultCtx := filepath.ToSlash(filepath.Clean(path))
	for i := range findings {
		if findings[i].Context == "" {
			findings[i].Context = defaultCtx
		}
	}

	return &audit.AuditResult{
		PolicyFindings: findings,
	}, true, nil
}

func diffNormalizePolicyContext(res *audit.AuditResult, topPath string) {
	if res == nil {
		return
	}
	target := filepath.ToSlash(filepath.Clean(topPath))
	for i := range res.PolicyFindings {
		ctx := filepath.ToSlash(filepath.Clean(res.PolicyFindings[i].Context))
		if res.PolicyFindings[i].Context == "" || ctx == target {
			res.PolicyFindings[i].Context = "policy"
			res.PolicyFindings[i].Fingerprint = ""
		}
	}
}

func diffWriteText(w io.Writer, oldPath, newPath string, diff *config.DiffResult) error {
	if diff == nil {
		return fmt.Errorf("diff result is nil")
	}

	var sb strings.Builder
	sb.WriteString("=== SUDOERS AUDIT DIFF REPORT ===\n\n")
	sb.WriteString(fmt.Sprintf("Baseline: %s\n", oldPath))
	sb.WriteString(fmt.Sprintf("Current:  %s\n\n", newPath))
	sb.WriteString("Summary:\n")
	sb.WriteString(fmt.Sprintf("  Added:     %d\n", len(diff.Added)))
	sb.WriteString(fmt.Sprintf("  Resolved:  %d\n", len(diff.Resolved)))
	sb.WriteString(fmt.Sprintf("  Unchanged: %d\n\n", len(diff.Unchanged)))

	diffAppendSection(&sb, "Added Findings", diff.Added)
	diffAppendSection(&sb, "Resolved Findings", diff.Resolved)
	diffAppendSection(&sb, "Unchanged Findings", diff.Unchanged)

	_, err := io.WriteString(w, sb.String())
	return err
}

func diffAppendSection(sb *strings.Builder, heading string, findings []audit.Finding) {
	sb.WriteString(fmt.Sprintf("%s (%d):\n", heading, len(findings)))
	if len(findings) == 0 {
		sb.WriteString("  (none)\n\n")
		return
	}
	for _, f := range findings {
		sb.WriteString(fmt.Sprintf("  [%s] %s: %s\n", f.Severity, f.ID, f.Title))
		if f.User != "" {
			sb.WriteString(fmt.Sprintf("    User/Group: %s\n", f.User))
		}
		if f.Host != "" {
			sb.WriteString(fmt.Sprintf("    Host:       %s\n", f.Host))
		}
		if f.Runas != "" {
			sb.WriteString(fmt.Sprintf("    RunAs:      %s\n", f.Runas))
		}
		if f.Command != "" {
			sb.WriteString(fmt.Sprintf("    Command:    %s\n", f.Command))
		}
		if f.Context != "" || f.Line > 0 {
			loc := f.Context
			switch {
			case loc != "" && f.Line > 0:
				loc = fmt.Sprintf("%s:%d", loc, f.Line)
			case loc == "" && f.Line > 0:
				loc = fmt.Sprintf("line %d", f.Line)
			}
			sb.WriteString(fmt.Sprintf("    Location:   %s\n", loc))
		}
	}
	sb.WriteString("\n")
}

func init() {
	rootCmd.AddCommand(diffCmd)
}
