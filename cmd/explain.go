package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"slices"
	"strings"
	"sudo-check/pkg/audit"
	"sudo-check/pkg/parser"

	"github.com/spf13/cobra"
)

var (
	explainUser   string
	explainUID    int
	explainGroups string
	explainHost   string
	explainIPs    string
)

var explainCmd = &cobra.Command{
	Use:   "explain <sudoers-or-json>",
	Short: "Simulate effective sudoers privileges for a user, group, and host",
	Long: `Evaluate a sudoers policy (raw sudoers, cvtsudoers JSON, sudo -ll, or LDIF)
for a specific principal query and display effective Defaults, allowed and denied
commands, resolved rule flags, and GTFObins privilege escalation paths.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		fmtName, err := explainResolveFormat(cmd)
		if err != nil {
			return err
		}

		userTrimmed := strings.TrimSpace(explainUser)
		uidChanged := cmd.Flags().Changed("uid")
		if uidChanged && explainUID < 0 {
			return fmt.Errorf("invalid --uid %d: UID must be non-negative", explainUID)
		}
		if userTrimmed == "" && !uidChanged && explainUID < 0 {
			return fmt.Errorf("missing target principal: specify --user or --uid")
		}

		groups := explainParseCommaList(explainGroups, true)
		ips, err := explainParseIPList(explainIPs)
		if err != nil {
			return err
		}

		targetPath := args[0]
		if strings.HasSuffix(strings.ToLower(targetPath), ".json") {
			data, readErr := os.ReadFile(targetPath)
			if readErr != nil {
				return fmt.Errorf("failed to read policy file %s: %w", targetPath, readErr)
			}
			if !parser.IsJSONPolicy(data) {
				return fmt.Errorf("failed to parse JSON in %s: invalid JSON policy", targetPath)
			}
		}

		policy, err := parser.ParseFileWithOptions(targetPath, parser.ParseOptions{
			Hostname: strings.TrimSpace(explainHost),
			Offline:  true,
		})
		if err != nil {
			return err
		}

		gtfoClient, err := newGTFOClient()
		if err != nil {
			return fmt.Errorf("failed to load GTFObins: %w", err)
		}

		query := audit.PrincipalQuery{
			Username: userTrimmed,
			Groups:   groups,
			Host:     strings.TrimSpace(explainHost),
			HostIPs:  ips,
		}
		if uidChanged || explainUID >= 0 {
			uidVal := explainUID
			query.UID = &uidVal
		}

		res := audit.ExplainPolicy(policy, gtfoClient, query)

		out := cmd.OutOrStdout()
		switch fmtName {
		case "json":
			enc := json.NewEncoder(out)
			enc.SetIndent("", "  ")
			return enc.Encode(res)
		default:
			return explainWriteText(out, res)
		}
	},
}

func explainResolveFormat(cmd *cobra.Command) (string, error) {
	if !cmd.Flags().Changed("formats") {
		return "text", nil
	}
	fmts := getFormatsList()
	if len(fmts) != 1 {
		return "", fmt.Errorf("explain requires a single output format (supported: text, json)")
	}
	norm := strings.ToLower(strings.TrimSpace(fmts[0]))
	switch norm {
	case "text", "txt":
		return "text", nil
	case "json":
		return "json", nil
	default:
		return "", fmt.Errorf("unsupported format %q for explain (supported: text, json)", fmts[0])
	}
}

func explainParseCommaList(raw string, stripPercent bool) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	var out []string
	for _, p := range parts {
		item := strings.TrimSpace(p)
		if stripPercent {
			item = strings.TrimSpace(strings.TrimPrefix(item, "%"))
		}
		if item != "" {
			out = append(out, item)
		}
	}
	return out
}

func explainParseIPList(raw string) ([]string, error) {
	items := explainParseCommaList(raw, false)
	for _, ipStr := range items {
		if net.ParseIP(ipStr) == nil {
			return nil, fmt.Errorf("invalid IP address %q in --ip", ipStr)
		}
	}
	return items, nil
}

func explainWriteText(w io.Writer, res *audit.ExplainResult) error {
	if res == nil {
		return fmt.Errorf("explain result is nil")
	}

	var sb strings.Builder
	sb.WriteString("=== SUDOERS PRINCIPAL EXPLANATION ===\n\n")

	sb.WriteString("Query:\n")
	userLabel := res.Query.Username
	if userLabel == "" {
		userLabel = "(none)"
	}
	sb.WriteString(fmt.Sprintf("  User:   %s\n", userLabel))
	if res.Query.UID != nil {
		sb.WriteString(fmt.Sprintf("  UID:    %d\n", *res.Query.UID))
	}
	if len(res.Query.Groups) > 0 {
		sb.WriteString(fmt.Sprintf("  Groups: %s\n", strings.Join(res.Query.Groups, ", ")))
	} else {
		sb.WriteString("  Groups: (none)\n")
	}
	hostLabel := res.Query.Host
	if hostLabel == "" {
		hostLabel = "(unspecified; matching ALL only)"
	}
	sb.WriteString(fmt.Sprintf("  Host:   %s\n", hostLabel))
	if len(res.Query.HostIPs) > 0 {
		sb.WriteString(fmt.Sprintf("  IPs:    %s\n", strings.Join(res.Query.HostIPs, ", ")))
	}

	sb.WriteString(fmt.Sprintf("\nHighest Risk: %s\n", res.HighestRisk))

	sb.WriteString("\nEffective Defaults:\n")
	if len(res.EffectiveDefaults) == 0 {
		sb.WriteString("  (none)\n")
	} else {
		keys := make([]string, 0, len(res.EffectiveDefaults))
		for k := range res.EffectiveDefaults {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		for _, k := range keys {
			sb.WriteString(fmt.Sprintf("  %s = %s\n", k, explainFormatDefaultValue(res.EffectiveDefaults[k])))
		}
	}

	sb.WriteString(fmt.Sprintf("\nAllowed Commands (%d):\n", len(res.AllowedCommands)))
	if len(res.AllowedCommands) == 0 {
		sb.WriteString("  (none)\n")
	} else {
		for i, ec := range res.AllowedCommands {
			runas := ec.Runas
			if runas == "" {
				runas = "default"
			}
			sb.WriteString(fmt.Sprintf("  %d. (%s) %s\n", i+1, runas, ec.Command))

			var flags []string
			if ec.NoPasswd {
				flags = append(flags, "NOPASSWD")
			}
			if ec.NoExec {
				flags = append(flags, "NOEXEC")
			}
			if ec.SetEnv {
				flags = append(flags, "SETENV")
			}
			flagsStr := "none"
			if len(flags) > 0 {
				flagsStr = strings.Join(flags, ", ")
			}
			sb.WriteString(fmt.Sprintf("     Flags:    %s\n", flagsStr))

			if ec.SourceFile != "" || ec.Line > 0 {
				loc := ec.SourceFile
				switch {
				case loc != "" && ec.Line > 0:
					loc = fmt.Sprintf("%s:%d", loc, ec.Line)
				case loc == "" && ec.Line > 0:
					loc = fmt.Sprintf("line %d", ec.Line)
				}
				sb.WriteString(fmt.Sprintf("     Source:   %s\n", loc))
			}

			if ec.EscalationPath {
				sb.WriteString("     Risk:     ESCALATION PATH\n")
			} else if len(ec.GTFOBinsRisk) > 0 {
				sb.WriteString("     Risk:     MITIGATED (NOEXEC)\n")
			} else {
				sb.WriteString("     Risk:     LOW\n")
			}

			if len(ec.GTFOBinsRisk) > 0 {
				funcs := make([]string, 0, len(ec.GTFOBinsRisk))
				for _, b := range ec.GTFOBinsRisk {
					if b.Function != "" {
						funcs = append(funcs, b.Function)
					}
				}
				if len(funcs) > 0 {
					sb.WriteString(fmt.Sprintf("     GTFObins: %s\n", strings.Join(funcs, ", ")))
				}
			}
		}
	}

	sb.WriteString(fmt.Sprintf("\nDenied Commands (%d):\n", len(res.DeniedCommands)))
	if len(res.DeniedCommands) == 0 {
		sb.WriteString("  (none)\n")
	} else {
		for _, denied := range res.DeniedCommands {
			sb.WriteString(fmt.Sprintf("  - %s\n", denied))
		}
	}

	_, err := io.WriteString(w, sb.String())
	return err
}

func explainFormatDefaultValue(val any) string {
	switch v := val.(type) {
	case []string:
		if len(v) == 0 {
			return "(empty)"
		}
		return strings.Join(v, ", ")
	default:
		return fmt.Sprintf("%v", v)
	}
}

func init() {
	explainCmd.Flags().StringVar(&explainUser, "user", "", "Target username to evaluate")
	explainCmd.Flags().IntVar(&explainUID, "uid", -1, "Target numeric UID to evaluate")
	explainCmd.Flags().StringVar(&explainGroups, "groups", "", "Comma-separated Unix group names")
	explainCmd.Flags().StringVar(&explainHost, "host", "", "Target hostname (short or FQDN)")
	explainCmd.Flags().StringVar(&explainIPs, "ip", "", "Comma-separated IPv4/IPv6 addresses for CIDR matching")
	rootCmd.AddCommand(explainCmd)
}
