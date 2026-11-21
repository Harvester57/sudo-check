package audit

import (
	"sudo-check/pkg/gtfobins"
)

// globalDefaultRuleOptionKey maps each rule in GlobalMissingDefaultRuleIDs to the
// global Defaults option key it validates so DropInMode only suppresses genuinely
// omitted global defaults and still catches explicit global weakenings in drop-ins.
var globalDefaultRuleOptionKey = map[string]string{
	"SUDO-DEF-001": "secure_path",
	"SUDO-DEF-003": "use_pty",
	"SUDO-DEF-007": "noexec",
	"SUDO-DEF-008": "requiretty",
	"SUDO-DEF-009": "umask",
	"SUDO-DEF-010": "ignore_dot",
	"SUDO-DEF-011": "env_reset",
	"SUDO-DEF-017": "logfile",
}

// RunAudit runs all default oracle-compatible policy-level audit rules against
// the parsed sudoers policy.
func RunAudit(policy *SudoersPolicy, gtfoClient *gtfobins.Client) []Finding {
	return RunAuditWithOptions(policy, gtfoClient, AuditOptions{})
}

// RunAuditWithOptions runs policy-level audit rules with optional behavioral
// extensions controlled by opts (drop-in suppression, subcommand-aware GTFObins
// scoring, rule shadowing analysis, and validity timestamp evaluation).
func RunAuditWithOptions(policy *SudoersPolicy, gtfoClient *gtfobins.Client, opts AuditOptions) []Finding {
	if policy == nil {
		return nil
	}

	var findings []Finding

	// Run global and scoped Defaults audits.
	defFindings := AuditDefaults(policy)
	if opts.DropInMode {
		explicitGlobal := collectExplicitGlobalDefaultKeys(policy)
		for _, f := range defFindings {
			if GlobalMissingDefaultRuleIDs[f.ID] && f.User == "" {
				if optKey, mapped := globalDefaultRuleOptionKey[f.ID]; !mapped || !explicitGlobal[optKey] {
					continue
				}
			}
			findings = append(findings, f)
		}
	} else {
		findings = append(findings, defFindings...)
	}

	// Run allowed commands / GTFObins audits.
	findings = append(findings, auditCommandsWithOptions(policy, gtfoClient, opts)...)

	// Optionally run last-match-wins shadowing analysis (SUDO-CMD-015).
	if opts.CheckShadowing {
		findings = append(findings, AuditShadowing(policy)...)
	}

	// Optionally run NOTBEFORE/NOTAFTER validity window checks (SUDO-CMD-016).
	if opts.Now != nil {
		findings = append(findings, AuditTimeWindows(policy, opts.Now())...)
	}

	return findings
}

func collectExplicitGlobalDefaultKeys(policy *SudoersPolicy) map[string]bool {
	explicit := make(map[string]bool)
	if policy == nil {
		return explicit
	}
	for _, def := range policy.Defaults {
		if len(def.Binding) != 0 {
			continue
		}
		for _, opt := range def.Options {
			for k := range opt {
				if k != "operation" {
					explicit[k] = true
				}
			}
		}
	}
	return explicit
}
