package report

import (
	"fmt"
	"html/template"
	"io"
	"path"
	"slices"
	"strings"
	"sudo-check/pkg/audit"
)

type htmlFindingView struct {
	audit.Finding
	Index                    int
	CardID                   string
	Category                 string
	Domain                   string
	DomainLabel              string
	BadgeClass               string
	SourceFile               string
	Location                 string
	Principal                string
	RulePreview              string
	CleanRemediation         string
	EffectiveRemediationCode string
	RemediationCodeLabel     string
	EffectiveExploitPoC      string
	ComplianceCSV            string
	SearchText               string
}

type htmlFileSummary struct {
	File            string
	ShortName       string
	Total           int
	Crit            int
	High            int
	Med             int
	Low             int
	Info            int
	HighestSeverity audit.Severity
	BadgeClass      string
}

type htmlPrincipalSummary struct {
	Name            string
	Total           int
	Crit            int
	High            int
	Med             int
	Low             int
	Info            int
	HighestSeverity audit.Severity
	BadgeClass      string
}

type htmlRuleSummary struct {
	ID          string
	Title       string
	Domain      string
	DomainLabel string
	Severity    audit.Severity
	BadgeClass  string
	Count       int
	FilesCount  int
	Remediation string
}

type htmlComplianceSummary struct {
	Tag   string
	Count int
}

type htmlReportData struct {
	Hostname            string
	SudoVersion         string
	TotalCount          int
	CritCount           int
	HighCount           int
	MedCount            int
	LowCount            int
	InfoCount           int
	CritPct             float64
	HighPct             float64
	MedPct              float64
	LowPct              float64
	InfoPct             float64
	SystemCount         int
	PolicyCount         int
	GTFOCount           int
	CmdCount            int
	DefCount            int
	AuditedFilesCount   int
	PrincipalsCount     int
	DistinctRulesCount  int
	DefaultGroupBy      string
	SystemFindings      []htmlFindingView
	PolicyFindings      []htmlFindingView
	FileSummaries       []htmlFileSummary
	PrincipalSummaries  []htmlPrincipalSummary
	RuleSummaries       []htmlRuleSummary
	ComplianceSummaries []htmlComplianceSummary
	FrameworkGroups     []FrameworkCatalogGroup
	TotalRequirements   int
	TriggeredReqsCount  int
	TemplateSections    []HardenedTemplateSection
	TraceabilityRows    []TraceabilityRow
}

func severityBadgeClass(sev audit.Severity) string {
	switch sev {
	case audit.SeverityCritical:
		return "badge-crit"
	case audit.SeverityHigh:
		return "badge-high"
	case audit.SeverityMedium:
		return "badge-med"
	case audit.SeverityLow:
		return "badge-low"
	default:
		return "badge-info"
	}
}

func classifyFindingDomain(f audit.Finding, category string) (string, string) {
	if category == "SYSTEM" || strings.HasPrefix(f.ID, "SUDO-SYS-") || strings.HasPrefix(f.ID, "CVE-") {
		return "SYSTEM", "System Host"
	}
	if strings.HasPrefix(f.ID, "SUDO-GTFO-") {
		return "GTFOBINS", "GTFObins"
	}
	if strings.HasPrefix(f.ID, "SUDO-CMD-") {
		return "COMMANDS", "Command Rule"
	}
	if strings.HasPrefix(f.ID, "SUDO-DEF-") {
		return "DEFAULTS", "Policy Default"
	}
	return "POLICY", "Policy Rule"
}

func extractInlineRemediationSnippet(cleanRem string) string {
	if strings.HasPrefix(cleanRem, "Defaults ") {
		return cleanRem
	}
	if idx := strings.Index(cleanRem, "Defaults "); idx != -1 {
		sub := cleanRem[idx:]
		if endQuote := strings.IndexByte(sub, '\''); endQuote != -1 {
			return strings.TrimSpace(sub[:endQuote])
		}
		sub = strings.TrimSuffix(sub, ".")
		sub = strings.TrimSuffix(sub, " to sudoers")
		sub = strings.TrimSuffix(sub, " in sudoers")
		sub = strings.TrimSuffix(sub, " to the sudoers file")
		sub = strings.TrimSuffix(sub, " in the sudoers file")
		return strings.TrimSpace(sub)
	}

	// Extract single-quoted shell commands like 'chmod 0440 /etc/sudoers' or 'chown root:root /etc/sudoers'
	var cmds []string
	rem := cleanRem
	for {
		start := strings.IndexByte(rem, '\'')
		if start == -1 {
			break
		}
		rest := rem[start+1:]
		end := strings.IndexByte(rest, '\'')
		if end == -1 {
			break
		}
		candidate := strings.TrimSpace(rest[:end])
		for _, prefix := range []string{"chmod ", "chown ", "sudo ", "visudo", "apt", "dnf", "yum", "zypper", "pacman"} {
			if strings.HasPrefix(candidate, prefix) {
				cmds = append(cmds, candidate)
				break
			}
		}
		rem = rest[end+1:]
	}
	return strings.Join(cmds, "\n")
}

func resolveFindingRemediationAndExploit(f audit.Finding, category string) (cleanRem string, effectiveRemCode string, remCodeLabel string, effectivePoC string) {
	const sep = "Example exploit command:\n"
	cleanRem = strings.TrimSpace(f.Remediation)
	effectiveRemCode = strings.TrimSpace(f.RemediationCode)
	effectivePoC = strings.TrimSpace(f.ExploitPoC)

	if idx := strings.Index(cleanRem, sep); idx != -1 {
		extracted := strings.TrimSpace(cleanRem[idx+len(sep):])
		cleanRem = strings.TrimSpace(cleanRem[:idx])
		if effectivePoC == "" {
			effectivePoC = extracted
		}
	}

	if effectiveRemCode == "" {
		effectiveRemCode = extractInlineRemediationSnippet(cleanRem)
	}

	if effectiveRemCode != "" {
		isSystem := category == "SYSTEM" || strings.HasPrefix(f.ID, "SUDO-SYS-") || strings.HasPrefix(f.ID, "CVE-")
		hasShellCmd := strings.HasPrefix(effectiveRemCode, "sudo ") ||
			strings.HasPrefix(effectiveRemCode, "chmod ") ||
			strings.HasPrefix(effectiveRemCode, "chown ") ||
			strings.HasPrefix(effectiveRemCode, "ls ") ||
			strings.HasPrefix(effectiveRemCode, "sha256sum ") ||
			strings.HasPrefix(effectiveRemCode, "# 1. Compute") ||
			strings.HasPrefix(effectiveRemCode, "# Debian")
		hasVisudo := strings.Contains(effectiveRemCode, "Defaults") || strings.Contains(effectiveRemCode, "visudo") || strings.Contains(effectiveRemCode, "sha256:")
		if isSystem && hasVisudo {
			remCodeLabel = "Remediation Commands & Sudoers Example"
		} else if isSystem || (hasShellCmd && !hasVisudo) {
			remCodeLabel = "Remediation Command"
		} else if hasShellCmd && hasVisudo {
			remCodeLabel = "Remediation Commands & Sudoers Example"
		} else {
			remCodeLabel = "Example Sudoers Configuration (visudo)"
		}
	}

	return cleanRem, effectiveRemCode, remCodeLabel, effectivePoC
}

func enrichFinding(f audit.Finding, category string, idx int) htmlFindingView {
	domain, domainLabel := classifyFindingDomain(f, category)
	badge := severityBadgeClass(f.Severity)

	sourceFile := strings.TrimSpace(f.Context)
	if sourceFile == "" {
		if category == "SYSTEM" {
			sourceFile = "System Check"
		} else {
			sourceFile = "Global Policy"
		}
	}

	var location string
	if f.Context != "" && f.Line > 0 {
		location = fmt.Sprintf("%s:%d", f.Context, f.Line)
	} else if f.Context != "" {
		location = f.Context
	} else if f.Line > 0 {
		location = fmt.Sprintf("line %d", f.Line)
	}

	principal := strings.TrimSpace(f.User)
	if principal == "" {
		if category == "SYSTEM" {
			principal = "(System Host)"
		} else {
			principal = "(Global / Unscoped)"
		}
	}

	var rulePreview string
	if f.Command != "" {
		u := f.User
		if u == "" {
			u = "ALL"
		}
		h := f.Host
		if h == "" {
			h = "ALL"
		}
		r := f.Runas
		if r == "" {
			r = "root"
		}
		rulePreview = fmt.Sprintf("%s %s = (%s) %s", u, h, r, f.Command)
	} else if f.User != "" && strings.HasPrefix(f.ID, "SUDO-DEF-") {
		rulePreview = fmt.Sprintf("Defaults:%s", f.User)
	} else if f.User != "" && f.Host != "" {
		r := f.Runas
		if r != "" {
			rulePreview = fmt.Sprintf("%s %s = (%s) ...", f.User, f.Host, r)
		} else {
			rulePreview = fmt.Sprintf("%s %s = ...", f.User, f.Host)
		}
	}

	cleanRem, effectiveRemCode, remCodeLabel, effectivePoC := resolveFindingRemediationAndExploit(f, category)
	compCSV := strings.Join(f.Compliance, ",")

	searchParts := []string{
		f.ID,
		f.Title,
		f.Description,
		string(f.Severity),
		category,
		domain,
		domainLabel,
		f.User,
		f.Host,
		f.Runas,
		f.Command,
		sourceFile,
		location,
		rulePreview,
		cleanRem,
		effectiveRemCode,
		effectivePoC,
		strings.Join(f.Compliance, " "),
	}
	searchText := strings.ToLower(strings.Join(searchParts, " "))

	return htmlFindingView{
		Finding:                  f,
		Index:                    idx,
		CardID:                   fmt.Sprintf("finding-%d", idx),
		Category:                 category,
		Domain:                   domain,
		DomainLabel:              domainLabel,
		BadgeClass:               badge,
		SourceFile:               sourceFile,
		Location:                 location,
		Principal:                principal,
		RulePreview:              rulePreview,
		CleanRemediation:         cleanRem,
		EffectiveRemediationCode: effectiveRemCode,
		RemediationCodeLabel:     remCodeLabel,
		EffectiveExploitPoC:      effectivePoC,
		ComplianceCSV:            compCSV,
		SearchText:               searchText,
	}
}

func buildHTMLReportData(result *audit.AuditResult) htmlReportData {
	sysCopy := make([]audit.Finding, len(result.SystemFindings))
	polCopy := make([]audit.Finding, len(result.PolicyFindings))
	copy(sysCopy, result.SystemFindings)
	copy(polCopy, result.PolicyFindings)
	audit.SortFindingsBySeverity(sysCopy)
	audit.SortFindingsBySeverity(polCopy)

	data := htmlReportData{
		Hostname:    result.Hostname,
		SudoVersion: result.SudoVersion,
	}

	idx := 0
	var allViews []htmlFindingView

	for _, f := range sysCopy {
		idx++
		v := enrichFinding(f, "SYSTEM", idx)
		data.SystemFindings = append(data.SystemFindings, v)
		allViews = append(allViews, v)
	}
	for _, f := range polCopy {
		idx++
		v := enrichFinding(f, "POLICY", idx)
		data.PolicyFindings = append(data.PolicyFindings, v)
		allViews = append(allViews, v)
	}

	data.TotalCount = len(allViews)
	data.SystemCount = len(data.SystemFindings)
	data.PolicyCount = len(data.PolicyFindings)

	fileMap := make(map[string]*htmlFileSummary)
	principalMap := make(map[string]*htmlPrincipalSummary)
	ruleMap := make(map[string]*htmlRuleSummary)
	ruleFiles := make(map[string]map[string]bool)
	compMap := make(map[string]int)

	for _, v := range allViews {
		switch v.Severity {
		case audit.SeverityCritical:
			data.CritCount++
		case audit.SeverityHigh:
			data.HighCount++
		case audit.SeverityMedium:
			data.MedCount++
		case audit.SeverityLow:
			data.LowCount++
		default:
			data.InfoCount++
		}

		switch v.Domain {
		case "GTFOBINS":
			data.GTFOCount++
		case "COMMANDS":
			data.CmdCount++
		case "DEFAULTS":
			data.DefCount++
		}

		// File summary
		fs, ok := fileMap[v.SourceFile]
		if !ok {
			short := path.Base(strings.ReplaceAll(v.SourceFile, "\\", "/"))
			if short == "." || short == "/" || short == "" {
				short = v.SourceFile
			}
			fs = &htmlFileSummary{
				File:            v.SourceFile,
				ShortName:       short,
				HighestSeverity: v.Severity,
				BadgeClass:      v.BadgeClass,
			}
			fileMap[v.SourceFile] = fs
		}
		fs.Total++
		if v.Severity.Order() < fs.HighestSeverity.Order() {
			fs.HighestSeverity = v.Severity
			fs.BadgeClass = v.BadgeClass
		}
		switch v.Severity {
		case audit.SeverityCritical:
			fs.Crit++
		case audit.SeverityHigh:
			fs.High++
		case audit.SeverityMedium:
			fs.Med++
		case audit.SeverityLow:
			fs.Low++
		default:
			fs.Info++
		}

		// Principal summary
		ps, ok := principalMap[v.Principal]
		if !ok {
			ps = &htmlPrincipalSummary{
				Name:            v.Principal,
				HighestSeverity: v.Severity,
				BadgeClass:      v.BadgeClass,
			}
			principalMap[v.Principal] = ps
		}
		ps.Total++
		if v.Severity.Order() < ps.HighestSeverity.Order() {
			ps.HighestSeverity = v.Severity
			ps.BadgeClass = v.BadgeClass
		}
		switch v.Severity {
		case audit.SeverityCritical:
			ps.Crit++
		case audit.SeverityHigh:
			ps.High++
		case audit.SeverityMedium:
			ps.Med++
		case audit.SeverityLow:
			ps.Low++
		default:
			ps.Info++
		}

		// Rule summary
		rs, ok := ruleMap[v.ID]
		if !ok {
			rs = &htmlRuleSummary{
				ID:          v.ID,
				Title:       v.Title,
				Domain:      v.Domain,
				DomainLabel: v.DomainLabel,
				Severity:    v.Severity,
				BadgeClass:  v.BadgeClass,
				Remediation: v.CleanRemediation,
			}
			ruleMap[v.ID] = rs
			ruleFiles[v.ID] = make(map[string]bool)
		}
		rs.Count++
		if v.Severity.Order() < rs.Severity.Order() {
			rs.Severity = v.Severity
			rs.BadgeClass = v.BadgeClass
		}
		ruleFiles[v.ID][v.SourceFile] = true

		// Compliance summary
		for _, c := range v.Compliance {
			normComp := normalizeComplianceKey(c)
			compMap[normComp]++
		}
	}

	if data.TotalCount > 0 {
		totalF := float64(data.TotalCount)
		data.CritPct = (float64(data.CritCount) / totalF) * 100
		data.HighPct = (float64(data.HighCount) / totalF) * 100
		data.MedPct = (float64(data.MedCount) / totalF) * 100
		data.LowPct = (float64(data.LowCount) / totalF) * 100
		data.InfoPct = (float64(data.InfoCount) / totalF) * 100
	}

	for _, fs := range fileMap {
		data.FileSummaries = append(data.FileSummaries, *fs)
	}
	slices.SortFunc(data.FileSummaries, func(a, b htmlFileSummary) int {
		if a.Crit != b.Crit {
			return b.Crit - a.Crit
		}
		if a.High != b.High {
			return b.High - a.High
		}
		if a.Med != b.Med {
			return b.Med - a.Med
		}
		if a.Total != b.Total {
			return b.Total - a.Total
		}
		return strings.Compare(a.File, b.File)
	})
	data.AuditedFilesCount = len(data.FileSummaries)

	for _, ps := range principalMap {
		data.PrincipalSummaries = append(data.PrincipalSummaries, *ps)
	}
	slices.SortFunc(data.PrincipalSummaries, func(a, b htmlPrincipalSummary) int {
		// Sort explicit user/group principals ahead of unscoped fallback labels when severity is equal
		aUnscoped := strings.HasPrefix(a.Name, "(")
		bUnscoped := strings.HasPrefix(b.Name, "(")
		if a.Crit != b.Crit {
			return b.Crit - a.Crit
		}
		if a.High != b.High {
			return b.High - a.High
		}
		if a.Med != b.Med {
			return b.Med - a.Med
		}
		if aUnscoped != bUnscoped {
			if aUnscoped {
				return 1
			}
			return -1
		}
		if a.Total != b.Total {
			return b.Total - a.Total
		}
		return strings.Compare(a.Name, b.Name)
	})
	data.PrincipalsCount = len(data.PrincipalSummaries)

	for id, rs := range ruleMap {
		rs.FilesCount = len(ruleFiles[id])
		data.RuleSummaries = append(data.RuleSummaries, *rs)
	}
	slices.SortFunc(data.RuleSummaries, func(a, b htmlRuleSummary) int {
		if a.Severity.Order() != b.Severity.Order() {
			return a.Severity.Order() - b.Severity.Order()
		}
		if a.Count != b.Count {
			return b.Count - a.Count
		}
		return strings.Compare(a.ID, b.ID)
	})
	data.DistinctRulesCount = len(data.RuleSummaries)

	for tag, count := range compMap {
		data.ComplianceSummaries = append(data.ComplianceSummaries, htmlComplianceSummary{
			Tag:   tag,
			Count: count,
		})
	}
	slices.SortFunc(data.ComplianceSummaries, func(a, b htmlComplianceSummary) int {
		if a.Count != b.Count {
			return b.Count - a.Count
		}
		return strings.Compare(a.Tag, b.Tag)
	})

	data.DefaultGroupBy = "NONE"
	if data.AuditedFilesCount > 1 && data.TotalCount >= 12 {
		data.DefaultGroupBy = "FILE"
	} else if data.TotalCount >= 20 {
		data.DefaultGroupBy = "RULE"
	}

	data.FrameworkGroups, data.TotalRequirements, data.TriggeredReqsCount = buildFrameworkCatalog(allViews)
	data.TemplateSections = buildHardenedTemplateSections()
	data.TraceabilityRows = buildTraceabilityMatrix()

	return data
}

const htmlTemplateStr = `<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="description" content="Sudoers Security Audit Report. Identifies security misconfigurations, dangerous defaults, and GTFObins bypass vulnerabilities.">
    <title>Sudoers Audit Report - {{if .Hostname}}{{.Hostname}}{{else}}localhost{{end}}</title>
    <style>
        :root {
            --bg-gradient-start: #0b0f19;
            --bg-gradient-end: #020617;
            --panel-bg: rgba(17, 24, 39, 0.78);
            --panel-bg-elevated: rgba(15, 23, 42, 0.92);
            --panel-border: rgba(255, 255, 255, 0.08);
            --panel-border-strong: rgba(255, 255, 255, 0.14);
            --surface-subtle: rgba(0, 0, 0, 0.22);
            --surface-hover: rgba(255, 255, 255, 0.05);
            --text-main: #f3f4f6;
            --text-muted: #9ca3af;
            --font-primary: 'Outfit', 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            --font-code: 'Space Mono', 'JetBrains Mono', 'Fira Code', Consolas, monospace;
            --accent-primary: #6366f1;
            --accent-primary-bg: rgba(99, 102, 241, 0.16);
            --accent-crit: #ff453a;
            --accent-high: #bf5af2;
            --accent-med: #ff9f0a;
            --accent-low: #64d2ff;
            --accent-info: #0a84ff;
            --accent-crit-bg: rgba(255, 69, 58, 0.15);
            --accent-high-bg: rgba(191, 90, 242, 0.15);
            --accent-med-bg: rgba(255, 159, 10, 0.15);
            --accent-low-bg: rgba(100, 210, 255, 0.15);
            --accent-info-bg: rgba(10, 132, 255, 0.15);
            --remediation-accent: #10b981;
            --remediation-bg: rgba(16, 185, 129, 0.07);
            --exploit-accent: #f59e0b;
            --exploit-bg: rgba(245, 158, 11, 0.08);
            --code-text: #34d399;
            --exploit-code-text: #fbbf24;
            --shadow-glow: rgba(0, 0, 0, 0.45);
        }

        [data-theme="light"] {
            --bg-gradient-start: #f8fafc;
            --bg-gradient-end: #e2e8f0;
            --panel-bg: rgba(255, 255, 255, 0.88);
            --panel-bg-elevated: rgba(255, 255, 255, 0.96);
            --panel-border: rgba(15, 23, 42, 0.09);
            --panel-border-strong: rgba(15, 23, 42, 0.16);
            --surface-subtle: rgba(15, 23, 42, 0.04);
            --surface-hover: rgba(15, 23, 42, 0.05);
            --text-main: #0f172a;
            --text-muted: #475569;
            --accent-crit: #dc2626;
            --accent-high: #9333ea;
            --accent-med: #d97706;
            --accent-low: #0284c7;
            --accent-info: #2563eb;
            --accent-crit-bg: rgba(220, 38, 38, 0.1);
            --accent-high-bg: rgba(147, 51, 234, 0.1);
            --accent-med-bg: rgba(217, 119, 6, 0.1);
            --accent-low-bg: rgba(2, 132, 199, 0.1);
            --accent-info-bg: rgba(37, 99, 235, 0.1);
            --remediation-accent: #059669;
            --remediation-bg: rgba(5, 150, 105, 0.06);
            --exploit-accent: #d97706;
            --exploit-bg: rgba(217, 119, 6, 0.07);
            --code-text: #047857;
            --exploit-code-text: #b45309;
            --shadow-glow: rgba(148, 163, 184, 0.22);
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }

        body {
            font-family: var(--font-primary);
            background: linear-gradient(135deg, var(--bg-gradient-start) 0%, var(--bg-gradient-end) 100%);
            background-attachment: fixed;
            color: var(--text-main);
            min-height: 100vh;
            padding: 1.5rem 1rem 3rem;
            line-height: 1.5;
        }

        .container {
            max-width: 1320px;
            margin: 0 auto;
        }

        /* Header */
        header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            gap: 1rem;
            margin-bottom: 1.25rem;
            padding: 1.25rem 1.5rem;
            background: var(--panel-bg);
            border: 1px solid var(--panel-border);
            backdrop-filter: blur(12px);
            border-radius: 14px;
            box-shadow: 0 8px 32px var(--shadow-glow);
        }

        .header-title h1 {
            font-size: 1.65rem;
            font-weight: 700;
            letter-spacing: -0.025em;
            background: linear-gradient(90deg, #38bdf8, #818cf8);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }

        .header-title p {
            font-size: 0.85rem;
            color: var(--text-muted);
            margin-top: 0.15rem;
        }

        .header-actions {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            flex-wrap: wrap;
        }

        .action-btn,
        .theme-toggle-btn {
            background: var(--surface-subtle);
            border: 1px solid var(--panel-border);
            color: var(--text-main);
            cursor: pointer;
            padding: 0.45rem 0.85rem;
            border-radius: 8px;
            font-size: 0.82rem;
            font-weight: 500;
            font-family: var(--font-primary);
            display: inline-flex;
            align-items: center;
            gap: 0.45rem;
            transition: background-color 0.15s, border-color 0.15s;
        }

        .action-btn:hover,
        .theme-toggle-btn:hover {
            background: var(--surface-hover);
            border-color: var(--panel-border-strong);
        }

        /* System Metadata Strip */
        .system-meta {
            background: var(--panel-bg);
            border: 1px solid var(--panel-border);
            border-radius: 14px;
            padding: 0.9rem 1.25rem;
            margin-bottom: 1.25rem;
            font-size: 0.86rem;
            display: flex;
            flex-wrap: wrap;
            align-items: center;
            gap: 1.25rem 2rem;
            box-shadow: 0 4px 20px var(--shadow-glow);
        }

        .meta-item {
            display: inline-flex;
            align-items: center;
            gap: 0.4rem;
        }

        .meta-item strong {
            color: var(--text-muted);
            font-weight: 600;
        }

        .meta-pill {
            font-family: var(--font-code);
            font-size: 0.8rem;
            padding: 0.15rem 0.5rem;
            border-radius: 6px;
            background: var(--surface-subtle);
            border: 1px solid var(--panel-border);
        }

        /* Metrics Dashboard */
        .metrics-grid {
            display: grid;
            grid-template-columns: repeat(5, minmax(140px, 1fr));
            gap: 1rem;
            margin-bottom: 0.75rem;
        }

        .metric-card {
            background: var(--panel-bg);
            border: 1px solid var(--panel-border);
            backdrop-filter: blur(12px);
            border-radius: 14px;
            padding: 1.1rem 1rem;
            text-align: center;
            box-shadow: 0 4px 20px var(--shadow-glow);
            position: relative;
            overflow: hidden;
            cursor: pointer;
            user-select: none;
            transition: transform 0.15s, border-color 0.15s, box-shadow 0.15s;
        }

        .metric-card:hover {
            transform: translateY(-2px);
            border-color: var(--panel-border-strong);
        }

        .metric-card.active-metric {
            border-color: var(--accent-primary);
            box-shadow: 0 0 0 2px var(--accent-primary), 0 4px 20px var(--shadow-glow);
        }

        .metric-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 4px;
        }

        .card-crit::before { background: var(--accent-crit); }
        .card-high::before { background: var(--accent-high); }
        .card-med::before { background: var(--accent-med); }
        .card-low::before { background: var(--accent-low); }
        .card-info::before { background: var(--accent-info); }

        .metric-num {
            font-size: 2.1rem;
            font-weight: 700;
            margin: 0.25rem 0 0.1rem;
            line-height: 1.1;
        }

        .metric-label {
            font-size: 0.78rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.06em;
            color: var(--text-muted);
        }

        .metric-hint {
            font-size: 0.7rem;
            color: var(--text-muted);
            opacity: 0.75;
        }

        /* Proportional Severity Bar */
        .severity-distribution {
            height: 8px;
            border-radius: 999px;
            background: var(--surface-subtle);
            border: 1px solid var(--panel-border);
            overflow: hidden;
            display: flex;
            margin-bottom: 1.5rem;
        }

        .sev-seg-crit { background: var(--accent-crit); }
        .sev-seg-high { background: var(--accent-high); }
        .sev-seg-med { background: var(--accent-med); }
        .sev-seg-low { background: var(--accent-low); }
        .sev-seg-info { background: var(--accent-info); }

        /* Triage Intelligence Dashboard */
        .triage-overview {
            background: var(--panel-bg);
            border: 1px solid var(--panel-border);
            border-radius: 14px;
            margin-bottom: 1.5rem;
            box-shadow: 0 4px 24px var(--shadow-glow);
            overflow: hidden;
        }

        .triage-overview > summary {
            list-style: none;
            cursor: pointer;
            padding: 0.9rem 1.25rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
            font-weight: 600;
            font-size: 0.92rem;
            border-bottom: 1px solid transparent;
            user-select: none;
        }

        .triage-overview > summary::-webkit-details-marker {
            display: none;
        }

        .triage-overview[open] > summary {
            border-bottom-color: var(--panel-border);
        }

        .triage-summary-title {
            display: flex;
            align-items: center;
            gap: 0.6rem;
        }

        .triage-summary-hint {
            font-size: 0.78rem;
            font-weight: 400;
            color: var(--text-muted);
        }

        .triage-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
            gap: 1rem;
            padding: 1rem 1.25rem 1.25rem;
        }

        .triage-panel {
            background: var(--surface-subtle);
            border: 1px solid var(--panel-border);
            border-radius: 10px;
            padding: 0.9rem 1rem;
            display: flex;
            flex-direction: column;
            gap: 0.65rem;
        }

        .triage-panel-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            font-size: 0.8rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: var(--text-muted);
        }

        .triage-list {
            display: flex;
            flex-direction: column;
            gap: 0.4rem;
            max-height: 210px;
            overflow-y: auto;
            padding-right: 0.2rem;
        }

        .triage-row {
            display: flex;
            justify-content: space-between;
            align-items: center;
            gap: 0.5rem;
            padding: 0.42rem 0.6rem;
            border-radius: 7px;
            background: rgba(255, 255, 255, 0.02);
            border: 1px solid var(--panel-border);
            cursor: pointer;
            text-align: left;
            color: var(--text-main);
            font-family: var(--font-primary);
            font-size: 0.82rem;
            transition: background-color 0.15s, border-color 0.15s;
        }

        .triage-row:hover {
            background: var(--surface-hover);
            border-color: var(--panel-border-strong);
        }

        .triage-row.active-facet {
            background: var(--accent-primary-bg);
            border-color: var(--accent-primary);
        }

        .triage-row-name {
            font-family: var(--font-code);
            font-size: 0.78rem;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
            flex: 1;
            min-width: 0;
        }

        .triage-row-badges {
            display: inline-flex;
            align-items: center;
            gap: 0.25rem;
            flex-shrink: 0;
        }

        .mini-sev {
            font-family: var(--font-code);
            font-size: 0.68rem;
            font-weight: 700;
            padding: 0.1rem 0.38rem;
            border-radius: 4px;
        }

        .mini-total {
            font-family: var(--font-code);
            font-size: 0.72rem;
            color: var(--text-muted);
            margin-left: 0.2rem;
        }

        /* Sticky Filter & Pivot Toolbar */
        .controls-panel {
            position: sticky;
            top: 0.75rem;
            z-index: 40;
            background: var(--panel-bg-elevated);
            border: 1px solid var(--panel-border-strong);
            backdrop-filter: blur(16px);
            border-radius: 14px;
            padding: 1rem 1.25rem;
            margin-bottom: 1.5rem;
            box-shadow: 0 8px 30px var(--shadow-glow);
            display: flex;
            flex-direction: column;
            gap: 0.75rem;
        }

        .toolbar-top-row {
            display: flex;
            flex-wrap: wrap;
            gap: 0.65rem;
            align-items: center;
        }

        .search-bar {
            position: relative;
            flex: 1 1 280px;
            display: flex;
            align-items: center;
        }

        .search-input {
            width: 100%;
            background: var(--surface-subtle);
            border: 1px solid var(--panel-border);
            border-radius: 8px;
            padding: 0.6rem 4.2rem 0.6rem 0.9rem;
            color: var(--text-main);
            font-family: var(--font-primary);
            font-size: 0.9rem;
        }

        .search-input:focus {
            outline: 2px solid var(--accent-primary);
            outline-offset: -1px;
        }

        .search-shortcut {
            position: absolute;
            right: 0.55rem;
            display: inline-flex;
            align-items: center;
            gap: 0.3rem;
        }

        .kbd-hint {
            font-family: var(--font-code);
            font-size: 0.7rem;
            color: var(--text-muted);
            border: 1px solid var(--panel-border);
            border-radius: 4px;
            padding: 0.08rem 0.38rem;
            background: var(--panel-bg);
            pointer-events: none;
        }

        .clear-search-btn {
            display: none;
            background: transparent;
            border: none;
            color: var(--text-muted);
            cursor: pointer;
            font-size: 0.8rem;
            padding: 0.15rem 0.35rem;
            border-radius: 4px;
        }

        .clear-search-btn:hover {
            color: var(--text-main);
            background: var(--surface-hover);
        }

        .facet-selects {
            display: flex;
            flex-wrap: wrap;
            gap: 0.5rem;
            align-items: center;
        }

        .toolbar-select-group {
            display: inline-flex;
            align-items: center;
            gap: 0.35rem;
            font-size: 0.78rem;
            color: var(--text-muted);
        }

        .toolbar-select {
            background: var(--surface-subtle);
            border: 1px solid var(--panel-border);
            color: var(--text-main);
            padding: 0.5rem 0.65rem;
            border-radius: 8px;
            font-family: var(--font-primary);
            font-size: 0.82rem;
            max-width: 220px;
            cursor: pointer;
        }

        .toolbar-select:focus {
            outline: 2px solid var(--accent-primary);
            outline-offset: -1px;
        }

        .toolbar-filters-row {
            display: flex;
            flex-wrap: wrap;
            justify-content: space-between;
            align-items: center;
            gap: 0.6rem;
        }

        .filter-buttons {
            display: flex;
            flex-wrap: wrap;
            gap: 0.38rem;
            align-items: center;
        }

        .filter-divider {
            width: 1px;
            height: 20px;
            background: var(--panel-border-strong);
            margin: 0 0.25rem;
        }

        .filter-btn {
            background: var(--surface-subtle);
            border: 1px solid var(--panel-border);
            color: var(--text-main);
            padding: 0.38rem 0.75rem;
            border-radius: 7px;
            font-size: 0.79rem;
            font-weight: 500;
            font-family: var(--font-primary);
            cursor: pointer;
            transition: background-color 0.15s, border-color 0.15s;
        }

        .filter-btn.active {
            background: var(--accent-primary);
            color: #ffffff;
            border-color: var(--accent-primary);
        }

        .filter-btn:hover:not(.active) {
            background: var(--surface-hover);
            border-color: var(--panel-border-strong);
        }

        .policy-filter-group {
            display: inline-flex;
            align-items: center;
            flex-wrap: wrap;
            gap: 0.25rem;
            padding: 0.2rem 0.3rem;
            background: var(--surface-subtle);
            border: 1px solid var(--panel-border);
            border-radius: 9px;
            transition: border-color 0.15s, background-color 0.15s;
        }

        .policy-filter-group.has-active-policy {
            border-color: rgba(99, 102, 241, 0.45);
            background: rgba(99, 102, 241, 0.04);
        }

        .policy-filter-group .filter-btn-parent {
            border-color: transparent;
            background: transparent;
            font-weight: 600;
            padding: 0.28rem 0.65rem;
            border-radius: 6px;
        }

        .policy-filter-group .filter-btn-parent.active {
            background: var(--accent-primary);
            color: #ffffff;
        }

        .policy-filter-group .filter-btn-parent.parent-context:not(.active) {
            color: var(--accent-primary);
            background: rgba(99, 102, 241, 0.1);
        }

        .policy-subfilters {
            display: inline-flex;
            align-items: center;
            flex-wrap: wrap;
            gap: 0.22rem;
            padding-left: 0.35rem;
            border-left: 1px solid var(--panel-border-strong);
        }

        .policy-subfilters .filter-btn-sub {
            border-color: transparent;
            background: transparent;
            font-size: 0.75rem;
            padding: 0.24rem 0.55rem;
            border-radius: 5px;
            color: var(--text-muted);
        }

        .policy-subfilters .filter-btn-sub:hover:not(.active) {
            color: var(--text-main);
            background: var(--surface-hover);
        }

        .policy-subfilters .filter-btn-sub.active {
            background: var(--accent-primary);
            color: #ffffff;
        }

        .view-mode-group {
            display: inline-flex;
            border: 1px solid var(--panel-border);
            border-radius: 8px;
            overflow: hidden;
            background: var(--surface-subtle);
        }

        .view-mode-btn {
            background: transparent;
            border: none;
            color: var(--text-muted);
            padding: 0.38rem 0.75rem;
            font-size: 0.78rem;
            font-weight: 600;
            font-family: var(--font-primary);
            cursor: pointer;
        }

        .view-mode-btn.active {
            background: var(--accent-primary);
            color: #ffffff;
        }

        .toolbar-status-row {
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 0.5rem;
            padding-top: 0.45rem;
            border-top: 1px solid var(--panel-border);
            font-size: 0.8rem;
            color: var(--text-muted);
        }

        .active-filters-list {
            display: flex;
            flex-wrap: wrap;
            align-items: center;
            gap: 0.4rem;
        }

        .active-filter-chip {
            display: inline-flex;
            align-items: center;
            gap: 0.35rem;
            padding: 0.15rem 0.55rem;
            border-radius: 999px;
            background: var(--accent-primary-bg);
            color: var(--text-main);
            border: 1px solid rgba(99, 102, 241, 0.35);
            font-size: 0.75rem;
            cursor: pointer;
        }

        .reset-filters-btn {
            background: transparent;
            border: 1px solid var(--panel-border);
            color: var(--text-muted);
            padding: 0.2rem 0.6rem;
            border-radius: 6px;
            font-size: 0.76rem;
            cursor: pointer;
            display: none;
        }

        .reset-filters-btn:hover {
            color: var(--text-main);
            border-color: var(--panel-border-strong);
        }

        /* Findings Container & Groups */
        .findings-list {
            display: flex;
            flex-direction: column;
            gap: 1rem;
        }

        .finding-group {
            background: var(--panel-bg);
            border: 1px solid var(--panel-border-strong);
            border-radius: 14px;
            box-shadow: 0 4px 24px var(--shadow-glow);
            overflow: hidden;
        }

        /* Defer rendering only for below-the-fold groups and cards per defer-rendering-heavy-content */
        .finding-card:nth-child(n+6),
        .finding-group:nth-child(n+4) {
            content-visibility: auto;
            contain-intrinsic-size: auto none auto 220px;
        }

        .finding-group-header {
            list-style: none;
            cursor: pointer;
            padding: 0.95rem 1.25rem;
            background: var(--surface-subtle);
            display: flex;
            justify-content: space-between;
            align-items: center;
            gap: 1rem;
            user-select: none;
            border-bottom: 1px solid transparent;
        }

        .finding-group-header::-webkit-details-marker {
            display: none;
        }

        .finding-group[open] > .finding-group-header {
            border-bottom-color: var(--panel-border);
        }

        .group-header-left {
            display: flex;
            align-items: center;
            gap: 0.65rem;
            min-width: 0;
            flex-wrap: wrap;
        }

        .group-chevron {
            font-size: 0.75rem;
            color: var(--text-muted);
            transition: transform 0.2s;
        }

        .finding-group[open] > .finding-group-header .group-chevron {
            transform: rotate(90deg);
        }

        .group-title {
            font-weight: 700;
            font-size: 0.98rem;
            font-family: var(--font-code);
            word-break: break-all;
        }

        .group-subtitle {
            font-size: 0.85rem;
            color: var(--text-muted);
            font-family: var(--font-primary);
        }

        .group-shared-remediation {
            margin: 0.85rem 1rem 0;
            padding: 0.75rem 1rem;
            border-left: 3px solid var(--remediation-accent);
            background: var(--remediation-bg);
            border-radius: 0 8px 8px 0;
            font-size: 0.86rem;
        }

        .group-shared-remediation strong {
            color: var(--remediation-accent);
            text-transform: uppercase;
            font-size: 0.75rem;
            letter-spacing: 0.05em;
            display: block;
            margin-bottom: 0.2rem;
        }

        .finding-group-body {
            padding: 1rem;
            display: flex;
            flex-direction: column;
            gap: 0.85rem;
        }

        /* Finding Card (Detailed Mode) */
        .finding-card {
            background: var(--panel-bg);
            border: 1px solid var(--panel-border);
            border-radius: 14px;
            padding: 1.25rem 1.4rem;
            box-shadow: 0 4px 20px var(--shadow-glow);
            position: relative;
            display: flex;
            flex-direction: column;
            gap: 0.9rem;
        }

        .finding-header {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            gap: 1rem;
        }

        .finding-title-sec {
            display: flex;
            flex-direction: column;
            gap: 0.3rem;
            min-width: 0;
            flex: 1;
        }

        .finding-meta-top {
            display: flex;
            flex-wrap: wrap;
            align-items: center;
            gap: 0.45rem;
        }

        .finding-id {
            font-family: var(--font-code);
            font-size: 0.76rem;
            color: var(--text-main);
            font-weight: 700;
            letter-spacing: 0.04em;
            padding: 0.12rem 0.45rem;
            border-radius: 4px;
            background: var(--surface-subtle);
            border: 1px solid var(--panel-border);
        }

        .domain-badge {
            font-size: 0.7rem;
            font-weight: 600;
            padding: 0.12rem 0.48rem;
            border-radius: 4px;
            background: rgba(56, 189, 248, 0.12);
            color: #38bdf8;
            border: 1px solid rgba(56, 189, 248, 0.25);
        }

        .location-pill {
            font-family: var(--font-code);
            font-size: 0.73rem;
            color: var(--text-muted);
            padding: 0.12rem 0.5rem;
            border-radius: 4px;
            background: var(--surface-subtle);
            border: 1px solid var(--panel-border);
            cursor: pointer;
        }

        .location-pill:hover {
            color: var(--text-main);
            border-color: var(--panel-border-strong);
        }

        .finding-title {
            font-size: 1.12rem;
            font-weight: 600;
            line-height: 1.35;
        }

        .compact-summary-pills {
            display: none;
            align-items: center;
            gap: 0.4rem;
            flex-wrap: wrap;
            font-family: var(--font-code);
            font-size: 0.74rem;
            color: var(--text-muted);
        }

        .compact-pill {
            padding: 0.12rem 0.45rem;
            border-radius: 4px;
            background: var(--surface-subtle);
            border: 1px solid var(--panel-border);
            max-width: 240px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }

        .finding-header-right {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            flex-shrink: 0;
        }

        .sev-badge {
            font-size: 0.73rem;
            font-weight: 700;
            padding: 0.28rem 0.72rem;
            border-radius: 6px;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            white-space: nowrap;
        }

        .badge-crit { background: var(--accent-crit-bg); color: var(--accent-crit); border: 1px solid rgba(255, 69, 58, 0.35); }
        .badge-high { background: var(--accent-high-bg); color: var(--accent-high); border: 1px solid rgba(191, 90, 242, 0.35); }
        .badge-med { background: var(--accent-med-bg); color: var(--accent-med); border: 1px solid rgba(255, 159, 10, 0.35); }
        .badge-low { background: var(--accent-low-bg); color: var(--accent-low); border: 1px solid rgba(100, 210, 255, 0.35); }
        .badge-info { background: var(--accent-info-bg); color: var(--accent-info); border: 1px solid rgba(10, 132, 255, 0.35); }

        .compact-toggle-btn {
            display: none;
            background: var(--surface-subtle);
            border: 1px solid var(--panel-border);
            color: var(--text-muted);
            border-radius: 6px;
            padding: 0.25rem 0.5rem;
            font-size: 0.75rem;
            cursor: pointer;
        }

        .finding-expandable-body {
            display: flex;
            flex-direction: column;
            gap: 0.85rem;
        }

        /* Rule Preview Bar */
        .rule-preview-bar {
            display: flex;
            justify-content: space-between;
            align-items: center;
            gap: 0.75rem;
            background: var(--surface-subtle);
            border: 1px solid var(--panel-border);
            border-left: 3px solid var(--accent-primary);
            padding: 0.5rem 0.85rem;
            border-radius: 6px;
            font-family: var(--font-code);
            font-size: 0.82rem;
            overflow-x: auto;
        }

        .rule-preview-code {
            color: var(--text-main);
            white-space: pre-wrap;
            word-break: break-all;
        }

        .copy-btn {
            background: var(--panel-bg);
            border: 1px solid var(--panel-border);
            color: var(--text-muted);
            padding: 0.2rem 0.55rem;
            border-radius: 5px;
            font-family: var(--font-primary);
            font-size: 0.72rem;
            font-weight: 500;
            cursor: pointer;
            flex-shrink: 0;
        }

        .copy-btn:hover {
            color: var(--text-main);
            border-color: var(--panel-border-strong);
        }

        .finding-details-grid {
            display: flex;
            flex-wrap: wrap;
            align-items: safe center;
            gap: 0.5rem 1.5rem;
            background: var(--surface-subtle);
            padding: 0.65rem 0.95rem;
            border-radius: 8px;
            font-size: 0.84rem;
            border: 1px solid var(--panel-border);
        }

        .finding-detail-item {
            display: inline-flex;
            align-items: baseline;
            gap: 0.35rem;
            min-inline-size: 0;
            max-inline-size: 100%;
        }

        .finding-detail-item strong {
            color: var(--text-muted);
            white-space: nowrap;
            flex-shrink: 0;
        }

        .finding-detail-item span,
        .finding-detail-item code {
            overflow-wrap: anywhere;
        }

        .clickable-meta {
            cursor: pointer;
            text-decoration: underline;
            text-decoration-style: dotted;
            text-underline-offset: 3px;
        }

        .clickable-meta:hover {
            color: #818cf8;
        }

        .compliance-tags {
            display: flex;
            flex-wrap: wrap;
            gap: 0.4rem;
        }

        .compliance-badge {
            font-family: var(--font-code);
            font-size: 0.72rem;
            padding: 0.18rem 0.55rem;
            border-radius: 4px;
            background: rgba(99, 102, 241, 0.14);
            color: #818cf8;
            border: 1px solid rgba(99, 102, 241, 0.3);
            cursor: pointer;
        }

        .compliance-badge:hover {
            background: rgba(99, 102, 241, 0.25);
        }

        .finding-desc {
            font-size: 0.92rem;
            color: var(--text-main);
            line-height: 1.55;
        }

        .finding-remediation {
            border-left: 3px solid var(--remediation-accent);
            background: var(--remediation-bg);
            padding: 0.7rem 1rem;
            border-radius: 0 8px 8px 0;
        }

        .remediation-title {
            font-size: 0.76rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: var(--remediation-accent);
            margin-bottom: 0.25rem;
        }

        .remediation-content {
            font-size: 0.88rem;
            color: var(--text-main);
        }

        .remediation-code-block {
            margin-top: 0.5rem;
        }

        .remediation-code-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            gap: 0.5rem;
            margin-bottom: 0.2rem;
        }

        .remediation-code-label {
            font-size: 0.73rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.04em;
            color: var(--remediation-accent);
            opacity: 0.92;
        }

        .remediation-code-block pre {
            margin-top: 0.15rem;
        }

        /* Dedicated Exploit / Verification Reference Box */
        .finding-exploit {
            border-left: 3px solid var(--exploit-accent);
            background: var(--exploit-bg);
            padding: 0.7rem 1rem;
            border-radius: 0 8px 8px 0;
        }

        .exploit-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 0.3rem;
        }

        .exploit-title {
            font-size: 0.76rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: var(--exploit-accent);
        }

        pre {
            background: rgba(0, 0, 0, 0.32);
            border: 1px solid var(--panel-border);
            padding: 0.65rem 0.9rem;
            border-radius: 7px;
            font-family: var(--font-code);
            font-size: 0.82rem;
            overflow-x: auto;
            margin-top: 0.35rem;
            color: var(--code-text);
            white-space: pre-wrap;
            word-break: break-word;
        }

        .finding-exploit pre {
            color: var(--exploit-code-text);
            margin-top: 0.15rem;
        }

        /* Compact Table / High-Density Mode */
        .findings-list.view-compact {
            gap: 0.45rem;
        }

        .findings-list.view-compact .finding-group-body {
            gap: 0.45rem;
            padding: 0.65rem;
        }

        .findings-list.view-compact .finding-card {
            padding: 0.5rem 0.95rem;
            border-radius: 8px;
            gap: 0.5rem;
        }

        .findings-list.view-compact .finding-header {
            align-items: center;
            cursor: pointer;
        }

        .findings-list.view-compact .finding-title-sec {
            flex-direction: row;
            align-items: center;
            flex-wrap: nowrap;
            gap: 0.6rem;
            overflow: hidden;
        }

        .findings-list.view-compact .finding-meta-top {
            flex-wrap: nowrap;
            flex-shrink: 0;
        }

        .findings-list.view-compact .location-pill {
            max-width: 220px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }

        .findings-list.view-compact .finding-title {
            font-size: 0.9rem;
            margin-right: auto;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
            min-width: 0;
        }

        .findings-list.view-compact .compact-summary-pills {
            display: inline-flex;
            flex-shrink: 0;
            flex-wrap: nowrap;
        }

        .findings-list.view-compact .compact-toggle-btn {
            display: inline-flex;
        }

        .findings-list.view-compact .finding-expandable-body {
            padding-top: 0.65rem;
            border-top: 1px solid var(--panel-border);
        }

        .no-findings {
            text-align: center;
            padding: 3rem;
            background: var(--panel-bg);
            border: 1px solid var(--panel-border);
            border-radius: 14px;
            color: var(--text-muted);
        }

        /* Focus Indicators (Modern Web Guidance accessibility) */
        :where(button, a, select, input, summary, pre):focus-visible {
            outline: 2px solid var(--accent-primary);
            outline-offset: 2px;
        }

        /* Top-Level WAI-ARIA View Tabs */
        .view-tabs {
            display: flex;
            flex-wrap: wrap;
            gap: 0.5rem;
            padding: 0.45rem;
            margin-bottom: 1.35rem;
            background: var(--panel-bg);
            border: 1px solid var(--panel-border);
            border-radius: 14px;
            box-shadow: 0 4px 20px var(--shadow-glow);
            backdrop-filter: blur(12px);
        }

        .view-tab-btn {
            flex: 1 1 220px;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            gap: 0.55rem;
            padding: 0.68rem 1rem;
            border-radius: 10px;
            border: 1px solid transparent;
            background: transparent;
            color: var(--text-muted);
            font-family: var(--font-primary);
            font-size: 0.9rem;
            font-weight: 600;
            cursor: pointer;
            transition: background-color 0.15s, color 0.15s, border-color 0.15s;
        }

        .view-tab-btn:hover:not([aria-selected="true"]) {
            background: var(--surface-hover);
            color: var(--text-main);
        }

        .view-tab-btn[aria-selected="true"] {
            background: var(--accent-primary);
            color: #ffffff;
            border-color: rgba(255, 255, 255, 0.18);
            box-shadow: 0 4px 14px rgba(99, 102, 241, 0.35);
        }

        .tab-badge {
            font-family: var(--font-code);
            font-size: 0.72rem;
            font-weight: 700;
            padding: 0.12rem 0.48rem;
            border-radius: 999px;
            background: rgba(0, 0, 0, 0.25);
            color: inherit;
            border: 1px solid rgba(255, 255, 255, 0.16);
        }

        .view-tab-btn:not([aria-selected="true"]) .tab-badge {
            background: var(--surface-subtle);
            border-color: var(--panel-border);
            color: var(--text-muted);
        }

        .tab-badge-ok {
            background: rgba(16, 185, 129, 0.18) !important;
            color: var(--remediation-accent) !important;
            border-color: rgba(16, 185, 129, 0.35) !important;
        }

        .view-tab-btn[aria-selected="true"] .tab-badge-ok {
            background: rgba(255, 255, 255, 0.2) !important;
            color: #ffffff !important;
            border-color: rgba(255, 255, 255, 0.35) !important;
        }

        .view-tabpanel[hidden] {
            display: none !important;
        }

        /* Tab 2: Reference Frameworks & Verbatim Standards */
        .frameworks-intro-banner,
        .template-intro-banner {
            background: var(--panel-bg);
            border: 1px solid var(--panel-border);
            border-radius: 14px;
            padding: 1.2rem 1.4rem;
            margin-bottom: 1.25rem;
            box-shadow: 0 4px 20px var(--shadow-glow);
            display: flex;
            flex-direction: column;
            gap: 0.45rem;
        }

        .frameworks-intro-banner h2,
        .template-intro-banner h2 {
            font-size: 1.22rem;
            font-weight: 700;
        }

        .frameworks-intro-banner p,
        .template-intro-banner p {
            font-size: 0.88rem;
            color: var(--text-muted);
        }

        .framework-group-card {
            background: var(--panel-bg);
            border: 1px solid var(--panel-border-strong);
            border-radius: 14px;
            margin-bottom: 1.35rem;
            box-shadow: 0 4px 24px var(--shadow-glow);
            overflow: hidden;
        }

        .framework-group-header {
            list-style: none;
            cursor: pointer;
            padding: 1.05rem 1.35rem;
            background: var(--surface-subtle);
            display: flex;
            justify-content: space-between;
            align-items: center;
            gap: 1rem;
            user-select: none;
            border-bottom: 1px solid transparent;
        }

        .framework-group-header::-webkit-details-marker {
            display: none;
        }

        .framework-group-card[open] > .framework-group-header {
            border-bottom-color: var(--panel-border);
        }

        .framework-group-card[open] > .framework-group-header .group-chevron {
            transform: rotate(90deg);
        }

        .framework-group-meta {
            padding: 0.9rem 1.35rem;
            border-bottom: 1px solid var(--panel-border);
            font-size: 0.86rem;
            color: var(--text-muted);
            display: flex;
            flex-direction: column;
            gap: 0.45rem;
        }

        .framework-meta-links {
            display: flex;
            flex-wrap: wrap;
            gap: 0.6rem 1.5rem;
            font-size: 0.8rem;
        }

        .framework-meta-links a {
            color: #38bdf8;
            text-decoration: none;
        }

        .framework-meta-links a:hover {
            text-decoration: underline;
        }

        .framework-reqs-body {
            padding: 1.1rem 1.25rem;
            display: flex;
            flex-direction: column;
            gap: 1rem;
        }

        .framework-req-card {
            background: var(--panel-bg-elevated);
            border: 1px solid var(--panel-border);
            border-radius: 12px;
            padding: 1.15rem 1.3rem;
            display: flex;
            flex-direction: column;
            gap: 0.8rem;
        }

        .framework-req-header {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            gap: 1rem;
            flex-wrap: wrap;
        }

        .framework-req-title-wrap {
            display: flex;
            flex-direction: column;
            gap: 0.28rem;
            min-width: 0;
            flex: 1;
        }

        .framework-req-code {
            font-family: var(--font-code);
            font-size: 0.78rem;
            font-weight: 700;
            padding: 0.14rem 0.5rem;
            border-radius: 4px;
            background: var(--accent-primary-bg);
            color: #818cf8;
            border: 1px solid rgba(99, 102, 241, 0.32);
        }

        .framework-level-pill {
            font-size: 0.72rem;
            font-weight: 600;
            padding: 0.12rem 0.48rem;
            border-radius: 4px;
            background: var(--surface-subtle);
            color: var(--text-muted);
            border: 1px solid var(--panel-border);
        }

        .badge-compliant {
            background: rgba(16, 185, 129, 0.14);
            color: var(--remediation-accent);
            border: 1px solid rgba(16, 185, 129, 0.35);
        }

        .verbatim-box {
            border-left: 3px solid var(--accent-primary);
            background: var(--surface-subtle);
            padding: 0.75rem 1rem;
            border-radius: 0 8px 8px 0;
            font-size: 0.88rem;
            display: flex;
            flex-direction: column;
            gap: 0.45rem;
        }

        .verbatim-label {
            font-size: 0.73rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: #818cf8;
        }

        .verbatim-quote {
            font-style: italic;
            color: var(--text-main);
            white-space: pre-line;
            line-height: 1.55;
        }

        .verbatim-quote-fr {
            font-size: 0.83rem;
            color: var(--text-muted);
            border-top: 1px dashed var(--panel-border);
            padding-top: 0.45rem;
            white-space: pre-line;
        }

        .req-CrossLinks {
            display: flex;
            flex-wrap: wrap;
            justify-content: space-between;
            align-items: center;
            gap: 0.65rem;
            padding-top: 0.4rem;
            border-top: 1px solid var(--panel-border);
        }

        .req-rule-pills {
            display: flex;
            flex-wrap: wrap;
            align-items: center;
            gap: 0.35rem;
        }

        .req-action-links {
            display: flex;
            flex-wrap: wrap;
            gap: 0.45rem;
        }

        .jump-btn {
            background: var(--surface-subtle);
            border: 1px solid var(--panel-border-strong);
            color: var(--text-main);
            padding: 0.3rem 0.68rem;
            border-radius: 6px;
            font-family: var(--font-primary);
            font-size: 0.76rem;
            font-weight: 600;
            cursor: pointer;
            transition: background-color 0.15s, border-color 0.15s;
        }

        .jump-btn:hover {
            background: var(--accent-primary-bg);
            border-color: var(--accent-primary);
        }

        /* Tab 3: Hardened Reference Template */
        .template-quick-nav {
            display: flex;
            flex-wrap: wrap;
            gap: 0.5rem;
            margin-bottom: 1.25rem;
        }

        .template-section-card {
            background: var(--panel-bg);
            border: 1px solid var(--panel-border-strong);
            border-radius: 14px;
            padding: 1.3rem 1.45rem;
            margin-bottom: 1.25rem;
            box-shadow: 0 4px 24px var(--shadow-glow);
            display: flex;
            flex-direction: column;
            gap: 0.85rem;
        }

        .template-section-header {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            gap: 1rem;
            flex-wrap: wrap;
        }

        .template-highlights {
            list-style: disc;
            padding-left: 1.25rem;
            font-size: 0.86rem;
            color: var(--text-muted);
            display: flex;
            flex-direction: column;
            gap: 0.25rem;
        }

        .traceability-card {
            background: var(--panel-bg);
            border: 1px solid var(--panel-border-strong);
            border-radius: 14px;
            padding: 1.3rem 1.45rem;
            box-shadow: 0 4px 24px var(--shadow-glow);
            overflow-x: auto;
        }

        .traceability-table {
            width: 100%;
            border-collapse: collapse;
            font-size: 0.82rem;
            margin-top: 0.75rem;
        }

        .traceability-table caption {
            text-align: left;
            font-weight: 700;
            font-size: 1.02rem;
            margin-bottom: 0.4rem;
            color: var(--text-main);
        }

        .traceability-table th,
        .traceability-table td {
            padding: 0.6rem 0.75rem;
            border-bottom: 1px solid var(--panel-border);
            text-align: left;
            vertical-align: top;
        }

        .traceability-table th {
            font-size: 0.75rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: var(--text-muted);
            background: var(--surface-subtle);
        }

        .traceability-table code {
            font-family: var(--font-code);
            font-size: 0.76rem;
            color: var(--code-text);
            white-space: pre-wrap;
            word-break: break-word;
        }

        @media (max-width: 900px) {
            .metrics-grid {
                grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
            }
        }

        @media (max-width: 768px) {
            header {
                flex-direction: column;
                align-items: flex-start;
            }
            .controls-panel {
                position: static;
            }
        }

        @media print {
            body {
                background: #ffffff !important;
                color: #000000 !important;
                padding: 0;
            }
            .controls-panel,
            .header-actions,
            .view-tabs,
            .copy-btn,
            .compact-toggle-btn {
                display: none !important;
            }
            .finding-card,
            .finding-group,
            .framework-group-card,
            .framework-req-card,
            .template-section-card,
            header,
            .system-meta,
            .triage-overview {
                box-shadow: none !important;
                border: 1px solid #cbd5e1 !important;
                break-inside: avoid;
                content-visibility: visible !important;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="header-title">
                <h1>Sudoers Security Audit Report</h1>
                <p>Generated by sudo-check utility</p>
            </div>
            <div class="header-actions">
                <button class="action-btn" type="button" onclick="expandAllDisclosures(true)" title="Expand all groups and compact rows">Expand All</button>
                <button class="action-btn" type="button" onclick="expandAllDisclosures(false)" title="Collapse all groups or compact rows">Collapse All</button>
                <button class="action-btn" type="button" onclick="window.print()" title="Print or save as PDF">Print</button>
                <button class="theme-toggle-btn" id="themeToggleBtn" type="button" onclick="toggleTheme()">
                    <svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364-6.364l-.707.707M6.343 17.657l-.707.707m0-12.728l.707.707m11.314 11.314l.707.707M12 5a7 7 0 100 14 7 7 0 000-14z"/></svg>
                    Toggle Theme
                </button>
            </div>
        </header>

        <section class="system-meta">
            <div class="meta-item"><strong>Target Host:</strong> <span class="meta-pill">{{if .Hostname}}{{.Hostname}}{{else}}localhost{{end}}</span></div>
            <div class="meta-item"><strong>Sudo Version:</strong> <span class="meta-pill">{{if .SudoVersion}}{{.SudoVersion}}{{else}}Unknown{{end}}</span></div>
            <div class="meta-item"><strong>Audited Sources:</strong> <span class="meta-pill" id="auditedFilesCount">{{.AuditedFilesCount}}</span></div>
            <div class="meta-item"><strong>Principals:</strong> <span class="meta-pill">{{.PrincipalsCount}}</span></div>
            <div class="meta-item"><strong>Unique Rules:</strong> <span class="meta-pill">{{.DistinctRulesCount}}</span></div>
            <div class="meta-item"><strong>Total Findings:</strong> <span class="meta-pill" id="totalFindingsCount">{{.TotalCount}}</span></div>
        </section>

        <!-- Top-Level WAI-ARIA View Tabs -->
        <div class="view-tabs" role="tablist" aria-label="Report Views" onkeydown="handleTablistKeydown(event)">
            <button type="button" class="view-tab-btn" role="tab" id="tab-report" aria-selected="true" aria-controls="panel-report" tabindex="0" onclick="switchViewTab('report')">
                <span>Audit Report</span>
                <span class="tab-badge">{{.TotalCount}} Findings</span>
            </button>
            <button type="button" class="view-tab-btn" role="tab" id="tab-frameworks" aria-selected="false" aria-controls="panel-frameworks" tabindex="-1" onclick="switchViewTab('frameworks')">
                <span>Reference Frameworks</span>
                <span class="tab-badge">{{.TotalRequirements}} Requirements</span>
            </button>
            <button type="button" class="view-tab-btn" role="tab" id="tab-template" aria-selected="false" aria-controls="panel-template" tabindex="-1" onclick="switchViewTab('template')">
                <span>Hardened Reference Template</span>
                <span class="tab-badge tab-badge-ok">Zero-Finding Baseline</span>
            </button>
        </div>

        <!-- TAB PANEL 1: AUDIT REPORT -->
        <div id="panel-report" class="view-tabpanel" role="tabpanel" aria-labelledby="tab-report">
        <!-- Dashboard Metrics (Click any card to filter by severity) -->
        <section class="metrics-grid">
            <div class="metric-card card-crit" id="metric-crit" onclick="toggleSeverityCard('CRITICAL')" title="Click to filter Critical findings">
                <div class="metric-label">Critical</div>
                <div class="metric-num" id="crit-count">{{.CritCount}}</div>
                <div class="metric-hint">Click to filter</div>
            </div>
            <div class="metric-card card-high" id="metric-high" onclick="toggleSeverityCard('HIGH')" title="Click to filter High findings">
                <div class="metric-label">High</div>
                <div class="metric-num" id="high-count">{{.HighCount}}</div>
                <div class="metric-hint">Click to filter</div>
            </div>
            <div class="metric-card card-med" id="metric-med" onclick="toggleSeverityCard('MEDIUM')" title="Click to filter Medium findings">
                <div class="metric-label">Medium</div>
                <div class="metric-num" id="med-count">{{.MedCount}}</div>
                <div class="metric-hint">Click to filter</div>
            </div>
            <div class="metric-card card-low" id="metric-low" onclick="toggleSeverityCard('LOW')" title="Click to filter Low findings">
                <div class="metric-label">Low</div>
                <div class="metric-num" id="low-count">{{.LowCount}}</div>
                <div class="metric-hint">Click to filter</div>
            </div>
            <div class="metric-card card-info" id="metric-info" onclick="toggleSeverityCard('INFO')" title="Click to filter Info findings">
                <div class="metric-label">Info</div>
                <div class="metric-num" id="info-count">{{.InfoCount}}</div>
                <div class="metric-hint">Click to filter</div>
            </div>
        </section>

        <div class="severity-distribution" title="Severity distribution across all findings">
            {{if gt .CritCount 0}}<div class="sev-seg-crit" style="width: {{printf "%.2f" .CritPct}}%"></div>{{end}}
            {{if gt .HighCount 0}}<div class="sev-seg-high" style="width: {{printf "%.2f" .HighPct}}%"></div>{{end}}
            {{if gt .MedCount 0}}<div class="sev-seg-med" style="width: {{printf "%.2f" .MedPct}}%"></div>{{end}}
            {{if gt .LowCount 0}}<div class="sev-seg-low" style="width: {{printf "%.2f" .LowPct}}%"></div>{{end}}
            {{if gt .InfoCount 0}}<div class="sev-seg-info" style="width: {{printf "%.2f" .InfoPct}}%"></div>{{end}}
        </div>

        {{if gt .TotalCount 0}}
        <!-- Collapsible Triage Breakdown Panels -->
        <details class="triage-overview" open>
            <summary>
                <span class="triage-summary-title">
                    <span>Scope &amp; Triage Breakdown</span>
                    <span class="triage-summary-hint">Click any source file, user/group, rule, or compliance badge to filter</span>
                </span>
                <span class="triage-summary-hint">Toggle Overview</span>
            </summary>
            <div class="triage-grid">
                <!-- Panel 1: Audited Files / Sources -->
                <div class="triage-panel">
                    <div class="triage-panel-header">
                        <span>Audited Files / Sources ({{.AuditedFilesCount}})</span>
                        <span>By Risk</span>
                    </div>
                    <div class="triage-list">
                        {{range .FileSummaries}}
                        <button type="button" class="triage-row" data-facet-file="{{.File}}" onclick="toggleFileFilter(this.getAttribute('data-facet-file'))" title="{{.File}}">
                            <span class="triage-row-name">{{.File}}</span>
                            <span class="triage-row-badges">
                                {{if gt .Crit 0}}<span class="mini-sev badge-crit">{{.Crit}} CRIT</span>{{end}}
                                {{if gt .High 0}}<span class="mini-sev badge-high">{{.High}} HIGH</span>{{end}}
                                {{if gt .Med 0}}<span class="mini-sev badge-med">{{.Med}} MED</span>{{end}}
                                {{if gt .Low 0}}<span class="mini-sev badge-low">{{.Low}} LOW</span>{{end}}
                                <span class="mini-total">({{.Total}})</span>
                            </span>
                        </button>
                        {{end}}
                    </div>
                </div>

                <!-- Panel 2: Top Affected Principals -->
                <div class="triage-panel">
                    <div class="triage-panel-header">
                        <span>Principals / Users ({{.PrincipalsCount}})</span>
                        <span>By Risk</span>
                    </div>
                    <div class="triage-list">
                        {{range .PrincipalSummaries}}
                        <button type="button" class="triage-row" data-facet-principal="{{.Name}}" onclick="togglePrincipalFilter(this.getAttribute('data-facet-principal'))" title="{{.Name}}">
                            <span class="triage-row-name">{{.Name}}</span>
                            <span class="triage-row-badges">
                                {{if gt .Crit 0}}<span class="mini-sev badge-crit">{{.Crit}} CRIT</span>{{end}}
                                {{if gt .High 0}}<span class="mini-sev badge-high">{{.High}} HIGH</span>{{end}}
                                {{if gt .Med 0}}<span class="mini-sev badge-med">{{.Med}} MED</span>{{end}}
                                {{if gt .Low 0}}<span class="mini-sev badge-low">{{.Low}} LOW</span>{{end}}
                                <span class="mini-total">({{.Total}})</span>
                            </span>
                        </button>
                        {{end}}
                    </div>
                </div>

                <!-- Panel 3: Top Triggered Rules & Compliance -->
                <div class="triage-panel">
                    <div class="triage-panel-header">
                        <span>Triggered Rules ({{.DistinctRulesCount}})</span>
                        <span>Occurrences</span>
                    </div>
                    <div class="triage-list">
                        {{range .RuleSummaries}}
                        <button type="button" class="triage-row" data-facet-rule="{{.ID}}" onclick="toggleRuleFilter(this.getAttribute('data-facet-rule'))" title="{{.ID}} - {{.Title}}">
                            <span class="triage-row-name">{{.ID}}: {{.Title}}</span>
                            <span class="triage-row-badges">
                                <span class="mini-sev {{.BadgeClass}}">{{.Severity}}</span>
                                <span class="mini-total">&times;{{.Count}}</span>
                            </span>
                        </button>
                        {{end}}
                    </div>
                    {{if .ComplianceSummaries}}
                    <div class="triage-panel-header" style="margin-top: 0.25rem;">
                        <span>Compliance Frameworks</span>
                    </div>
                    <div class="compliance-tags">
                        {{range .ComplianceSummaries}}
                        <span class="compliance-badge" data-facet-comp="{{.Tag}}" onclick="toggleComplianceFilter(this.getAttribute('data-facet-comp'))">{{.Tag}} ({{.Count}})</span>
                        {{end}}
                    </div>
                    {{end}}
                </div>
            </div>
        </details>
        {{end}}

        <!-- Sticky Interactive Filter, Pivot & Density Controls -->
        <section class="controls-panel">
            <div class="toolbar-top-row">
                <div class="search-bar">
                    <input type="text" class="search-input" id="searchInput" aria-label="Search audit findings" placeholder="Search by ID, title, command, user, host, file path, compliance..." oninput="filterFindings()">
                    <div class="search-shortcut">
                        <button type="button" class="clear-search-btn" id="clearSearchBtn" onclick="clearSearch()" title="Clear search">&times;</button>
                        <span class="kbd-hint" id="searchKbdHint">/</span>
                    </div>
                </div>
                <div class="facet-selects">
                    <label class="toolbar-select-group">
                        <span>Source:</span>
                        <select class="toolbar-select" id="fileFilterSelect" onchange="setFileFilter(this.value)">
                            <option value="ALL">All Sources ({{.AuditedFilesCount}})</option>
                            {{range .FileSummaries}}
                            <option value="{{.File}}">{{.File}} ({{.Total}})</option>
                            {{end}}
                        </select>
                    </label>
                    <label class="toolbar-select-group">
                        <span>Principal:</span>
                        <select class="toolbar-select" id="principalFilterSelect" onchange="setPrincipalFilter(this.value)">
                            <option value="ALL">All Principals ({{.PrincipalsCount}})</option>
                            {{range .PrincipalSummaries}}
                            <option value="{{.Name}}">{{.Name}} ({{.Total}})</option>
                            {{end}}
                        </select>
                    </label>
                    <label class="toolbar-select-group">
                        <span>Group By:</span>
                        <select class="toolbar-select" id="groupBySelect" onchange="setGroupBy(this.value)">
                            <option value="NONE" {{if eq .DefaultGroupBy "NONE"}}selected{{end}}>No Grouping (Severity Order)</option>
                            <option value="FILE" {{if eq .DefaultGroupBy "FILE"}}selected{{end}}>Source File ({{.AuditedFilesCount}})</option>
                            <option value="RULE" {{if eq .DefaultGroupBy "RULE"}}selected{{end}}>Rule ID / Deduplicate ({{.DistinctRulesCount}})</option>
                            <option value="USER">User / Principal ({{.PrincipalsCount}})</option>
                            <option value="SEVERITY">Severity Level</option>
                        </select>
                    </label>
                    <div class="view-mode-group" role="group" aria-label="View density">
                        <button type="button" class="view-mode-btn active" id="btn-view-detailed" onclick="setViewDensity('detailed')">Detailed</button>
                        <button type="button" class="view-mode-btn" id="btn-view-compact" onclick="setViewDensity('compact')">Compact</button>
                    </div>
                </div>
            </div>

            <div class="toolbar-filters-row">
                <div class="filter-buttons">
                    <button type="button" class="filter-btn active" id="btn-all" onclick="filterSeverity('ALL')">All Severities</button>
                    <button type="button" class="filter-btn" id="btn-crit" onclick="filterSeverity('CRITICAL')">Critical ({{.CritCount}})</button>
                    <button type="button" class="filter-btn" id="btn-high" onclick="filterSeverity('HIGH')">High ({{.HighCount}})</button>
                    <button type="button" class="filter-btn" id="btn-med" onclick="filterSeverity('MEDIUM')">Medium ({{.MedCount}})</button>
                    <button type="button" class="filter-btn" id="btn-low" onclick="filterSeverity('LOW')">Low ({{.LowCount}})</button>
                    <button type="button" class="filter-btn" id="btn-info" onclick="filterSeverity('INFO')">Info ({{.InfoCount}})</button>
                </div>
                <div class="filter-buttons">
                    <button type="button" class="filter-btn active" id="btn-cat-all" onclick="filterCategory('ALL')">All Domains</button>
                    <div class="policy-filter-group" id="policyFilterGroup" role="group" aria-label="Policy domain filters">
                        <button type="button" class="filter-btn filter-btn-parent" id="btn-cat-policy" onclick="filterCategory('POLICY')" title="All sudoers policy findings (GTFObins + Commands + Defaults)">Policy ({{.PolicyCount}})</button>
                        <div class="policy-subfilters">
                            <button type="button" class="filter-btn filter-btn-sub" id="btn-dom-gtfo" onclick="filterCategory('GTFOBINS')">GTFObins ({{.GTFOCount}})</button>
                            <button type="button" class="filter-btn filter-btn-sub" id="btn-dom-cmd" onclick="filterCategory('COMMANDS')">Commands ({{.CmdCount}})</button>
                            <button type="button" class="filter-btn filter-btn-sub" id="btn-dom-def" onclick="filterCategory('DEFAULTS')">Defaults ({{.DefCount}})</button>
                        </div>
                    </div>
                    <button type="button" class="filter-btn" id="btn-cat-system" onclick="filterCategory('SYSTEM')">System ({{.SystemCount}})</button>
                </div>
            </div>

            <div class="toolbar-status-row">
                <div>
                    Showing <strong id="visibleFindingsCount">{{.TotalCount}}</strong> of <strong id="totalFindingsInline">{{.TotalCount}}</strong> findings
                </div>
                <div class="active-filters-list" id="activeFiltersList"></div>
                <button type="button" class="reset-filters-btn" id="resetFiltersBtn" onclick="resetAllFilters()">Reset All Filters</button>
            </div>
        </section>

        <!-- Findings Lists -->
        <main class="findings-list" id="findingsContainer">
            <!-- Render System Findings -->
            {{range .SystemFindings}}
            <article class="finding-card" id="{{.CardID}}" data-order="{{.Index}}" data-id="{{.ID}}" data-title="{{.Title}}" data-severity="{{.Severity}}" data-category="SYSTEM" data-domain="{{.Domain}}" data-file="{{.SourceFile}}" data-principal="{{.Principal}}" data-compliance="{{.ComplianceCSV}}" data-remediation="{{.CleanRemediation}}" data-remediation-code="{{.EffectiveRemediationCode}}" data-remediation-label="{{.RemediationCodeLabel}}" data-search="{{.SearchText}}">
                <div class="finding-header" onclick="handleCardHeaderClick(event, this)">
                    <div class="finding-title-sec">
                        <div class="finding-meta-top">
                            <span class="finding-id">{{.ID}}</span>
                            <span class="domain-badge">{{.DomainLabel}}</span>
                            {{if .Location}}<span class="location-pill" data-loc-file="{{.SourceFile}}" onclick="event.stopPropagation(); toggleFileFilter(this.getAttribute('data-loc-file'))" title="Filter by source file">{{.Location}}</span>{{end}}
                        </div>
                        <h2 class="finding-title">{{.Title}}</h2>
                        <div class="compact-summary-pills">
                            {{if .Context}}<span class="compact-pill">{{.Location}}</span>{{end}}
                        </div>
                    </div>
                    <div class="finding-header-right">
                        <span class="sev-badge {{.BadgeClass}}">{{.Severity}}</span>
                        <button type="button" class="compact-toggle-btn" aria-expanded="true" onclick="event.stopPropagation(); toggleCompactCard(this.closest('.finding-card'))">Details</button>
                    </div>
                </div>
                <div class="finding-expandable-body">
                    <div class="finding-details-grid">
                        <div class="finding-detail-item"><strong>Source:</strong> System Health Check</div>
                        {{if .Context}}<div class="finding-detail-item"><strong>Target Path:</strong> <span class="clickable-meta" data-loc-file="{{.SourceFile}}" onclick="toggleFileFilter(this.getAttribute('data-loc-file'))">{{.Context}}{{if gt .Line 0}}:{{.Line}}{{end}}</span></div>{{end}}
                    </div>
                    {{if .Compliance}}
                    <div class="compliance-tags">
                        {{range .Compliance}}<span class="compliance-badge" data-comp="{{.}}" onclick="toggleComplianceFilter(this.getAttribute('data-comp'))">{{.}}</span>{{end}}
                    </div>
                    {{end}}
                    <p class="finding-desc">{{.Description}}</p>
                    <div class="finding-remediation">
                        <div class="remediation-title">Remediation</div>
                        <div class="remediation-content">
                            {{if .CleanRemediation}}<p>{{.CleanRemediation}}</p>{{end}}
                            {{if .EffectiveRemediationCode}}
                            <div class="remediation-code-block">
                                <div class="remediation-code-header">
                                    <span class="remediation-code-label">{{.RemediationCodeLabel}}</span>
                                    <button type="button" class="copy-btn" onclick="copyCodeBlock(this)">Copy</button>
                                </div>
                                <pre tabindex="0"><code>{{.EffectiveRemediationCode}}</code></pre>
                            </div>
                            {{end}}
                        </div>
                    </div>
                    {{if .EffectiveExploitPoC}}
                    <div class="finding-exploit">
                        <div class="exploit-header">
                            <span class="exploit-title">Exploit / Verification Reference</span>
                            <button type="button" class="copy-btn" onclick="copyCodeBlock(this)">Copy</button>
                        </div>
                        <pre tabindex="0"><code>{{.EffectiveExploitPoC}}</code></pre>
                    </div>
                    {{end}}
                </div>
            </article>
            {{end}}

            <!-- Render Policy Findings -->
            {{range .PolicyFindings}}
            <article class="finding-card" id="{{.CardID}}" data-order="{{.Index}}" data-id="{{.ID}}" data-title="{{.Title}}" data-severity="{{.Severity}}" data-category="POLICY" data-domain="{{.Domain}}" data-file="{{.SourceFile}}" data-principal="{{.Principal}}" data-compliance="{{.ComplianceCSV}}" data-remediation="{{.CleanRemediation}}" data-remediation-code="{{.EffectiveRemediationCode}}" data-remediation-label="{{.RemediationCodeLabel}}" data-search="{{.SearchText}}">
                <div class="finding-header" onclick="handleCardHeaderClick(event, this)">
                    <div class="finding-title-sec">
                        <div class="finding-meta-top">
                            <span class="finding-id">{{.ID}}</span>
                            <span class="domain-badge">{{.DomainLabel}}</span>
                            {{if .Location}}<span class="location-pill" data-loc-file="{{.SourceFile}}" onclick="event.stopPropagation(); toggleFileFilter(this.getAttribute('data-loc-file'))" title="Filter by source file">{{.Location}}</span>{{end}}
                        </div>
                        <h2 class="finding-title">{{.Title}}</h2>
                        <div class="compact-summary-pills">
                            {{if .User}}<span class="compact-pill" title="User/Group">{{.User}}</span>{{end}}
                            {{if .Command}}<span class="compact-pill" title="Command">{{.Command}}</span>{{end}}
                        </div>
                    </div>
                    <div class="finding-header-right">
                        <span class="sev-badge {{.BadgeClass}}">{{.Severity}}</span>
                        <button type="button" class="compact-toggle-btn" aria-expanded="true" onclick="event.stopPropagation(); toggleCompactCard(this.closest('.finding-card'))">Details</button>
                    </div>
                </div>
                <div class="finding-expandable-body">
                    {{if .RulePreview}}
                    <div class="rule-preview-bar">
                        <code class="rule-preview-code">{{.RulePreview}}</code>
                        <button type="button" class="copy-btn" onclick="copySiblingCode(this)">Copy Rule</button>
                    </div>
                    {{end}}
                    <div class="finding-details-grid">
                        <div class="finding-detail-item"><strong>Source:</strong> Sudoers Policy</div>
                        {{if .User}}<div class="finding-detail-item"><strong>User/Group:</strong> <span class="clickable-meta" data-user="{{.Principal}}" onclick="togglePrincipalFilter(this.getAttribute('data-user'))">{{.User}}</span></div>{{end}}
                        {{if .Host}}<div class="finding-detail-item"><strong>Host:</strong> {{.Host}}</div>{{end}}
                        {{if .Runas}}<div class="finding-detail-item"><strong>RunAs:</strong> {{.Runas}}</div>{{end}}
                        {{if .Command}}<div class="finding-detail-item"><strong>Command:</strong> <code>{{.Command}}</code></div>{{end}}
                        {{if .Context}}<div class="finding-detail-item"><strong>Location:</strong> <span class="clickable-meta" data-loc-file="{{.SourceFile}}" onclick="toggleFileFilter(this.getAttribute('data-loc-file'))">{{.Context}}{{if gt .Line 0}}:{{.Line}}{{end}}</span></div>{{end}}
                    </div>
                    {{if .Compliance}}
                    <div class="compliance-tags">
                        {{range .Compliance}}<span class="compliance-badge" data-comp="{{.}}" onclick="toggleComplianceFilter(this.getAttribute('data-comp'))">{{.}}</span>{{end}}
                    </div>
                    {{end}}
                    <p class="finding-desc">{{.Description}}</p>
                    <div class="finding-remediation">
                        <div class="remediation-title">Remediation</div>
                        <div class="remediation-content">
                            {{if .CleanRemediation}}<p>{{.CleanRemediation}}</p>{{end}}
                            {{if .EffectiveRemediationCode}}
                            <div class="remediation-code-block">
                                <div class="remediation-code-header">
                                    <span class="remediation-code-label">{{.RemediationCodeLabel}}</span>
                                    <button type="button" class="copy-btn" onclick="copyCodeBlock(this)">Copy</button>
                                </div>
                                <pre tabindex="0"><code>{{.EffectiveRemediationCode}}</code></pre>
                            </div>
                            {{end}}
                        </div>
                    </div>
                    {{if .EffectiveExploitPoC}}
                    <div class="finding-exploit">
                        <div class="exploit-header">
                            <span class="exploit-title">Exploit / Verification Reference</span>
                            <button type="button" class="copy-btn" onclick="copyCodeBlock(this)">Copy</button>
                        </div>
                        <pre tabindex="0"><code>{{.EffectiveExploitPoC}}</code></pre>
                    </div>
                    {{end}}
                </div>
            </article>
            {{end}}

            <div class="no-findings" id="noFindingsMsg" style="{{if eq .TotalCount 0}}display: block;{{else}}display: none;{{end}}">
                <h2>{{if eq .TotalCount 0}}No security findings detected.{{else}}No findings match the selected filters.{{end}}</h2>
            </div>
        </main>
        </div>

        <!-- TAB PANEL 2: REFERENCE FRAMEWORKS & VERBATIM REQUIREMENTS -->
        <div id="panel-frameworks" class="view-tabpanel" role="tabpanel" aria-labelledby="tab-frameworks" hidden>
            <div class="frameworks-intro-banner">
                <h2>Reference Security Frameworks &amp; Verbatim Requirements</h2>
                <p>Complete reference catalog of all security standards enforced by <code>sudo-check</code>: <strong>ANSSI BP-028</strong> (v1.2 &amp; v2.0 French &amp; English verbatim recommendations), <strong>CIS Distribution Independent Linux Benchmark (Section 5.2)</strong>, <strong>DISA STIG</strong>, and <strong>MITRE ATT&amp;CK (T1548.003)</strong>. Click any rule ID or compliance status badge to filter findings in the Audit Report, or jump directly to the corresponding section in the Hardened Reference Template.</p>
            </div>

            <div class="controls-panel">
                <div class="toolbar-top-row">
                    <div class="search-bar">
                        <input type="text" class="search-input" id="frameworkSearchInput" aria-label="Search framework requirements" placeholder="Search requirements by code (R38, CIS-5.2.2, T1548.003), keyword (use_pty, sudoedit, NOPASSWD), or rule ID..." oninput="filterFrameworkCatalog()">
                        <div class="search-shortcut">
                            <button type="button" class="clear-search-btn" id="clearFrameworkSearchBtn" onclick="clearFrameworkSearch()" title="Clear search">&times;</button>
                        </div>
                    </div>
                </div>
                <div class="toolbar-filters-row">
                    <div class="filter-buttons">
                        <button type="button" class="filter-btn active" id="btn-fw-all" onclick="setFrameworkFilter('ALL')">All Frameworks ({{.TotalRequirements}})</button>
                        {{range .FrameworkGroups}}
                        <button type="button" class="filter-btn" id="btn-fw-{{.ID}}" onclick="setFrameworkFilter('{{.ID}}')">{{.ShortName}} ({{.TotalReqs}})</button>
                        {{end}}
                    </div>
                    <div class="filter-buttons">
                        <button type="button" class="filter-btn" id="btn-fw-triggered" onclick="toggleTriggeredReqsOnly()">Triggered in This Scan Only ({{.TriggeredReqsCount}})</button>
                    </div>
                </div>
            </div>

            <div id="frameworksCatalogContainer">
                {{range .FrameworkGroups}}
                <details class="framework-group-card" data-fw-group="{{.ID}}" open>
                    <summary class="framework-group-header">
                        <div class="group-header-left">
                            <span class="group-chevron">&#9654;</span>
                            <span class="group-title">{{.FullName}}</span>
                            <span class="framework-level-pill">{{.VersionInfo}}</span>
                        </div>
                        <div class="triage-row-badges">
                            {{if gt .TotalFindings 0}}
                            <span class="mini-sev badge-high">{{.TriggeredReqs}}/{{.TotalReqs}} Triggered ({{.TotalFindings}} findings)</span>
                            {{else}}
                            <span class="mini-sev badge-compliant">{{.TotalReqs}} Requirements — 0 Violations</span>
                            {{end}}
                        </div>
                    </summary>
                    <div class="framework-group-meta">
                        <p>{{.Summary}}</p>
                        <div class="framework-meta-links">
                            <span><strong>Authority:</strong> {{.Publisher}}</span>
                            <span><strong>Official Publication:</strong> <a href="{{.ReferenceURL}}" target="_blank" rel="noopener noreferrer">{{.ReferenceURL}}</a></span>
                        </div>
                    </div>
                    <div class="framework-reqs-body">
                        {{range .Requirements}}
                        <article class="framework-req-card" id="req-{{.ID}}" data-fw-id="{{.FrameworkID}}" data-req-triggered="{{if gt .ViolationCount 0}}true{{else}}false{{end}}" data-req-search="{{.SearchText}}">
                            <div class="framework-req-header">
                                <div class="framework-req-title-wrap">
                                    <div class="finding-meta-top">
                                        <span class="framework-req-code">{{.Code}}</span>
                                        <span class="framework-level-pill">{{.Level}}</span>
                                    </div>
                                    <h3 class="finding-title">{{.Title}}</h3>
                                </div>
                                <div class="finding-header-right">
                                    {{if gt .ViolationCount 0}}
                                    <span class="sev-badge {{.BadgeClass}}">{{.ViolationCount}} Violation{{if gt .ViolationCount 1}}s{{end}} ({{.HighestSeverity}})</span>
                                    {{else}}
                                    <span class="sev-badge badge-compliant">0 Violations — Compliant</span>
                                    {{end}}
                                </div>
                            </div>

                            <div class="verbatim-box">
                                <span class="verbatim-label">Verbatim Standard Requirement</span>
                                <blockquote class="verbatim-quote" cite="{{.CitationURL}}">{{.VerbatimQuote}}</blockquote>
                                {{if .VerbatimQuoteFR}}
                                <blockquote class="verbatim-quote-fr" lang="fr" cite="{{.CitationURL}}"><strong>Texte original (ANSSI BP-028) :</strong> {{.VerbatimQuoteFR}}</blockquote>
                                {{end}}
                            </div>

                            <p class="finding-desc"><strong>Security Rationale:</strong> {{.Rationale}}</p>

                            <div class="finding-remediation">
                                <div class="remediation-code-header">
                                    <span class="remediation-code-label">Required Sudoers Directives &amp; Controls</span>
                                    <button type="button" class="copy-btn" onclick="copyCodeBlock(this)">Copy</button>
                                </div>
                                <pre tabindex="0"><code>{{.DirectivesCode}}</code></pre>
                            </div>

                            <div class="req-CrossLinks">
                                <div class="req-rule-pills">
                                    <strong style="font-size: 0.76rem; color: var(--text-muted); margin-right: 0.25rem;">Mapped Audit Rules:</strong>
                                    {{range .RuleIDs}}
                                    <button type="button" class="compliance-badge" onclick="jumpToAuditReportByRule('{{.}}')" title="Filter Audit Report by rule {{.}}">{{.}}</button>
                                    {{end}}
                                </div>
                                <div class="req-action-links">
                                    {{if gt .ViolationCount 0}}
                                    <button type="button" class="jump-btn" data-req-code="{{.Code}}" data-req-rules="{{range $i, $r := .RuleIDs}}{{if $i}},{{end}}{{$r}}{{end}}" data-req-comps="{{range $i, $c := .ComplianceTags}}{{if $i}},{{end}}{{$c}}{{end}}" onclick="jumpToAuditReportByRequirement(this)">View Triggered Findings ({{.ViolationCount}})</button>
                                    {{end}}
                                    <button type="button" class="jump-btn" onclick="jumpToTemplateSection('{{.TemplateAnchor}}')">View in Hardened Template</button>
                                </div>
                            </div>
                        </article>
                        {{end}}
                    </div>
                </details>
                {{end}}
                <div class="no-findings" id="noFrameworkReqsMsg" style="display: none;">
                    <h2>No framework requirements match the selected filter.</h2>
                </div>
            </div>
        </div>

        <!-- TAB PANEL 3: HARDENED REFERENCE TEMPLATE -->
        <div id="panel-template" class="view-tabpanel" role="tabpanel" aria-labelledby="tab-template" hidden>
            <div class="template-intro-banner">
                <h2>Hardened Reference Sudoers Baseline &amp; Implementation Patterns</h2>
                <p>Production-ready reference templates implementing every recommendation from <strong>ANSSI BP-028 (R38–R42/R44)</strong>, <strong>CIS Benchmark (5.2.1–5.2.7)</strong>, <strong>DISA STIG</strong>, and <strong>MITRE ATT&amp;CK (T1548.003)</strong>. The primary <code>/etc/sudoers</code> baseline below is continuously verified in unit tests to pass <code>sudo-check</code> with <strong>zero security findings</strong>.</p>
            </div>

            <div class="template-quick-nav">
                {{range .TemplateSections}}
                <button type="button" class="jump-btn" onclick="scrollToElementId('{{.ID}}')">{{.Title}}</button>
                {{end}}
                <button type="button" class="jump-btn" onclick="scrollToElementId('tpl-traceability-matrix')">5. Rule-to-Directive Traceability Matrix</button>
            </div>

            {{range .TemplateSections}}
            <article class="template-section-card" id="{{.ID}}">
                <div class="template-section-header">
                    <div class="framework-req-title-wrap">
                        <div class="finding-meta-top">
                            <span class="framework-req-code">{{.Badge}}</span>
                            <span class="location-pill">{{.FilePath}}</span>
                        </div>
                        <h3 class="finding-title">{{.Title}}</h3>
                    </div>
                    <button type="button" class="action-btn" onclick="copySectionPre(this)">Copy Template</button>
                </div>
                <p class="finding-desc">{{.Description}}</p>
                {{if .Highlights}}
                <ul class="template-highlights">
                    {{range .Highlights}}
                    <li>{{.}}</li>
                    {{end}}
                </ul>
                {{end}}
                <div class="finding-remediation">
                    <div class="remediation-code-header">
                        <span class="remediation-code-label">{{.FilePath}}</span>
                        <button type="button" class="copy-btn" onclick="copyCodeBlock(this)">Copy</button>
                    </div>
                    <pre tabindex="0"><code>{{.Code}}</code></pre>
                </div>
                <div class="req-rule-pills">
                    <strong style="font-size: 0.76rem; color: var(--text-muted); margin-right: 0.25rem;">Satisfies Rules:</strong>
                    {{range .RuleIDs}}
                    <span class="finding-id">{{.}}</span>
                    {{end}}
                </div>
            </article>
            {{end}}

            <div class="traceability-card" id="tpl-traceability-matrix">
                <table class="traceability-table">
                    <caption>5. Complete Rule-to-Directive Traceability Matrix</caption>
                    <thead>
                        <tr>
                            <th scope="col">Rule ID</th>
                            <th scope="col">Domain</th>
                            <th scope="col">Max Severity</th>
                            <th scope="col">Security Check</th>
                            <th scope="col">Standards</th>
                            <th scope="col">Hardened Baseline Control</th>
                        </tr>
                    </thead>
                    <tbody>
                        {{range .TraceabilityRows}}
                        <tr>
                            <td><span class="finding-id" style="cursor: pointer;" onclick="scrollToElementId('{{.SectionID}}')" title="Jump to template section">{{.RuleID}}</span></td>
                            <td>{{.Domain}}</td>
                            <td><span class="mini-sev {{.BadgeClass}}">{{.Severity}}</span></td>
                            <td>{{.Title}}</td>
                            <td>
                                <div class="compliance-tags">
                                    {{range .Frameworks}}<span class="compliance-badge" onclick="jumpToFrameworkRequirement('{{.}}')">{{.}}</span>{{end}}
                                </div>
                            </td>
                            <td><code>{{.Directive}}</code></td>
                        </tr>
                        {{end}}
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <script>
        let currentSeverity = 'ALL';
        let currentCategory = 'ALL';
        let currentFile = 'ALL';
        let currentPrincipal = 'ALL';
        let currentRule = 'ALL';
        let currentCompliance = 'ALL';
        let currentReqFilter = null;
        let currentGroupBy = '{{.DefaultGroupBy}}';
        let currentDensity = 'detailed';
        let currentViewTab = 'report';
        let currentFrameworkFilter = 'ALL';
        let triggeredReqsOnly = false;
        let allCards = [];

        const severityOrder = {
            'CRITICAL': 0,
            'HIGH': 1,
            'MEDIUM': 2,
            'LOW': 3,
            'INFO': 4
        };

        const badgeClassMap = {
            'CRITICAL': 'badge-crit',
            'HIGH': 'badge-high',
            'MEDIUM': 'badge-med',
            'LOW': 'badge-low',
            'INFO': 'badge-info'
        };

        function normalizeComplianceJS(tag) {
            return (tag || '').trim().toUpperCase().replace(/^ANSSI-BP-028-R/, 'ANSSI-BP-028 R');
        }

        function switchViewTab(tabName, focusTabBtn) {
            const validTabs = ['report', 'frameworks', 'template'];
            if (!validTabs.includes(tabName)) tabName = 'report';
            currentViewTab = tabName;

            validTabs.forEach(t => {
                const btn = document.getElementById('tab-' + t);
                const panel = document.getElementById('panel-' + t);
                const isSelected = (t === tabName);
                if (btn) {
                    btn.setAttribute('aria-selected', isSelected ? 'true' : 'false');
                    btn.setAttribute('tabindex', isSelected ? '0' : '-1');
                    if (isSelected && focusTabBtn) {
                        btn.focus();
                    }
                }
                if (panel) {
                    if (isSelected) {
                        panel.removeAttribute('hidden');
                    } else {
                        panel.setAttribute('hidden', '');
                    }
                }
            });
        }

        function handleTablistKeydown(event) {
            const tabs = ['report', 'frameworks', 'template'];
            const idx = tabs.indexOf(currentViewTab);
            if (idx === -1) return;

            let nextIdx = -1;
            if (event.key === 'ArrowRight') {
                nextIdx = (idx + 1) % tabs.length;
            } else if (event.key === 'ArrowLeft') {
                nextIdx = (idx - 1 + tabs.length) % tabs.length;
            } else if (event.key === 'Home') {
                nextIdx = 0;
            } else if (event.key === 'End') {
                nextIdx = tabs.length - 1;
            }

            if (nextIdx !== -1) {
                event.preventDefault();
                switchViewTab(tabs[nextIdx], true);
            }
        }

        function setFrameworkFilter(fwId) {
            currentFrameworkFilter = fwId || 'ALL';
            const allBtn = document.getElementById('btn-fw-all');
            if (allBtn) allBtn.classList.toggle('active', currentFrameworkFilter === 'ALL');
            document.querySelectorAll('[id^="btn-fw-"]').forEach(btn => {
                if (btn.id === 'btn-fw-all' || btn.id === 'btn-fw-triggered') return;
                btn.classList.toggle('active', btn.id === 'btn-fw-' + currentFrameworkFilter);
            });
            filterFrameworkCatalog();
        }

        function toggleTriggeredReqsOnly() {
            triggeredReqsOnly = !triggeredReqsOnly;
            const btn = document.getElementById('btn-fw-triggered');
            if (btn) btn.classList.toggle('active', triggeredReqsOnly);
            filterFrameworkCatalog();
        }

        function clearFrameworkSearch() {
            const input = document.getElementById('frameworkSearchInput');
            if (input) {
                input.value = '';
                filterFrameworkCatalog();
            }
        }

        function filterFrameworkCatalog() {
            const input = document.getElementById('frameworkSearchInput');
            const query = input ? input.value.trim().toLowerCase() : '';
            const clearBtn = document.getElementById('clearFrameworkSearchBtn');
            if (clearBtn) clearBtn.style.display = query.length > 0 ? 'inline-block' : 'none';

            let totalVisibleReqs = 0;
            document.querySelectorAll('.framework-group-card').forEach(groupEl => {
                const groupFwId = groupEl.getAttribute('data-fw-group');
                const groupMatchesFw = (currentFrameworkFilter === 'ALL' || groupFwId === currentFrameworkFilter);
                let visibleReqs = 0;

                groupEl.querySelectorAll('.framework-req-card').forEach(reqEl => {
                    const isTriggered = reqEl.getAttribute('data-req-triggered') === 'true';
                    const searchBlob = reqEl.getAttribute('data-req-search') || reqEl.innerText.toLowerCase();
                    const matchesQuery = (query === '' || searchBlob.includes(query));
                    const matchesTriggered = (!triggeredReqsOnly || isTriggered);

                    if (groupMatchesFw && matchesQuery && matchesTriggered) {
                        reqEl.style.display = 'flex';
                        visibleReqs++;
                        totalVisibleReqs++;
                    } else {
                        reqEl.style.display = 'none';
                    }
                });

                groupEl.style.display = (groupMatchesFw && visibleReqs > 0) ? 'block' : 'none';
            });

            const noFwMsg = document.getElementById('noFrameworkReqsMsg');
            if (noFwMsg) {
                noFwMsg.style.display = totalVisibleReqs === 0 ? 'block' : 'none';
            }
        }

        function jumpToAuditReportByRule(ruleId) {
            switchViewTab('report', false);
            resetAllFilters();
            currentRule = ruleId;
            document.querySelectorAll('[data-facet-rule]').forEach(el => {
                el.classList.toggle('active-facet', el.getAttribute('data-facet-rule') === currentRule);
            });
            filterFindings();
            const container = document.getElementById('findingsContainer');
            if (container) container.scrollIntoView({ behavior: 'smooth', block: 'start' });
        }

        function jumpToAuditReportByCompliance(compTag) {
            switchViewTab('report', false);
            resetAllFilters();
            currentCompliance = normalizeComplianceJS(compTag);
            document.querySelectorAll('[data-facet-comp]').forEach(el => {
                el.classList.toggle('active-facet', normalizeComplianceJS(el.getAttribute('data-facet-comp')) === currentCompliance);
            });
            filterFindings();
            const container = document.getElementById('findingsContainer');
            if (container) container.scrollIntoView({ behavior: 'smooth', block: 'start' });
        }

        function jumpToAuditReportByRequirement(btn) {
            if (!btn) return;
            const code = btn.getAttribute('data-req-code') || '';
            const rulesCSV = btn.getAttribute('data-req-rules') || '';
            const compsCSV = btn.getAttribute('data-req-comps') || '';
            switchViewTab('report', false);
            resetAllFilters();
            currentReqFilter = {
                code: code,
                rules: rulesCSV ? rulesCSV.split(',').map(s => s.trim()).filter(Boolean) : [],
                comps: compsCSV ? compsCSV.split(',').map(s => normalizeComplianceJS(s)).filter(Boolean) : []
            };
            filterFindings();
            const container = document.getElementById('findingsContainer');
            if (container) container.scrollIntoView({ behavior: 'smooth', block: 'start' });
        }

        function jumpToFrameworkRequirement(fwCode) {
            switchViewTab('frameworks', false);
            setFrameworkFilter('ALL');
            if (triggeredReqsOnly) toggleTriggeredReqsOnly();
            const input = document.getElementById('frameworkSearchInput');
            if (input) {
                input.value = fwCode || '';
                filterFrameworkCatalog();
            }
        }

        function jumpToTemplateSection(sectionId) {
            switchViewTab('template', false);
            scrollToElementId(sectionId);
        }

        function scrollToElementId(id) {
            const el = document.getElementById(id);
            if (el) {
                el.scrollIntoView({ behavior: 'smooth', block: 'start' });
            }
        }

        function copySectionPre(btn) {
            const section = btn.closest('.template-section-card');
            const code = section ? section.querySelector('pre code') : null;
            if (code) copyTextWithFeedback(btn, code.textContent);
        }

        function toggleTheme() {
            const html = document.documentElement;
            const currentTheme = html.getAttribute('data-theme');
            const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
            html.setAttribute('data-theme', newTheme);
            try {
                localStorage.setItem('sudo-check-theme', newTheme);
            } catch (e) {}
        }

        (function restoreSavedTheme() {
            try {
                const saved = localStorage.getItem('sudo-check-theme');
                if (saved === 'light' || saved === 'dark') {
                    document.documentElement.setAttribute('data-theme', saved);
                }
            } catch (e) {}
        })();

        window.onload = function() {
            allCards = Array.from(document.querySelectorAll('.finding-card'));
            calculateStats();
            setupKeyboardShortcuts();
            setupBeforeMatchDelegation();
            if (currentGroupBy !== 'NONE') {
                rebuildGrouping();
            }
            filterFindings();
        };

        function setupKeyboardShortcuts() {
            document.addEventListener('keydown', function(e) {
                const activeSearchId = currentViewTab === 'frameworks' ? 'frameworkSearchInput' : 'searchInput';
                const searchInput = document.getElementById(activeSearchId);
                if (!searchInput) return;
                if (e.key === '/' && document.activeElement !== searchInput && !['INPUT', 'SELECT', 'TEXTAREA'].includes(document.activeElement.tagName)) {
                    e.preventDefault();
                    searchInput.focus();
                    searchInput.select();
                } else if (e.key === 'Escape' && document.activeElement === searchInput) {
                    if (searchInput.value !== '') {
                        if (currentViewTab === 'frameworks') clearFrameworkSearch();
                        else clearSearch();
                    } else {
                        searchInput.blur();
                    }
                }
            });
        }

        // Synchronize UI state when browser Find-in-Page matches hidden="until-found" content in compact mode
        function setupBeforeMatchDelegation() {
            const container = document.getElementById('findingsContainer');
            if (!container) return;

            container.addEventListener('beforematch', function(e) {
                const card = e.target.closest('.finding-card');
                if (card) {
                    card.classList.add('is-expanded');
                    const btn = card.querySelector('.compact-toggle-btn');
                    if (btn) btn.setAttribute('aria-expanded', 'true');
                }
            });
        }

        function calculateStats() {
            const cards = allCards.length > 0 ? allCards : Array.from(document.querySelectorAll('.finding-card'));
            let total = 0, crit = 0, high = 0, med = 0, low = 0, info = 0;

            cards.forEach(card => {
                total++;
                const sev = card.getAttribute('data-severity');
                if (sev === 'CRITICAL') crit++;
                else if (sev === 'HIGH') high++;
                else if (sev === 'MEDIUM') med++;
                else if (sev === 'LOW') low++;
                else if (sev === 'INFO') info++;
            });

            document.getElementById('totalFindingsCount').innerText = total;
            const inlineTotal = document.getElementById('totalFindingsInline');
            if (inlineTotal) inlineTotal.innerText = total;
            document.getElementById('crit-count').innerText = crit;
            document.getElementById('high-count').innerText = high;
            document.getElementById('med-count').innerText = med;
            document.getElementById('low-count').innerText = low;
            document.getElementById('info-count').innerText = info;
        }

        function toggleSeverityCard(sev) {
            filterSeverity(currentSeverity === sev ? 'ALL' : sev);
        }

        function filterSeverity(sev) {
            currentSeverity = sev;
            updateSeverityButtons();
            filterFindings();
        }

        function filterCategory(cat) {
            currentCategory = cat;
            updateCategoryButtons();
            filterFindings();
        }

        function setFileFilter(file) {
            currentFile = file || 'ALL';
            const sel = document.getElementById('fileFilterSelect');
            if (sel && sel.value !== currentFile) sel.value = currentFile;
            document.querySelectorAll('[data-facet-file]').forEach(el => {
                el.classList.toggle('active-facet', el.getAttribute('data-facet-file') === currentFile);
            });
            filterFindings();
        }

        function toggleFileFilter(file) {
            setFileFilter(currentFile === file ? 'ALL' : file);
        }

        function setPrincipalFilter(principal) {
            currentPrincipal = principal || 'ALL';
            const sel = document.getElementById('principalFilterSelect');
            if (sel && sel.value !== currentPrincipal) sel.value = currentPrincipal;
            document.querySelectorAll('[data-facet-principal]').forEach(el => {
                el.classList.toggle('active-facet', el.getAttribute('data-facet-principal') === currentPrincipal);
            });
            filterFindings();
        }

        function togglePrincipalFilter(principal) {
            setPrincipalFilter(currentPrincipal === principal ? 'ALL' : principal);
        }

        function toggleRuleFilter(ruleId) {
            currentRule = currentRule === ruleId ? 'ALL' : ruleId;
            document.querySelectorAll('[data-facet-rule]').forEach(el => {
                el.classList.toggle('active-facet', el.getAttribute('data-facet-rule') === currentRule);
            });
            filterFindings();
        }

        function toggleComplianceFilter(comp) {
            const norm = normalizeComplianceJS(comp);
            currentCompliance = currentCompliance === norm ? 'ALL' : norm;
            document.querySelectorAll('[data-facet-comp]').forEach(el => {
                el.classList.toggle('active-facet', normalizeComplianceJS(el.getAttribute('data-facet-comp')) === currentCompliance);
            });
            filterFindings();
        }

        function clearSearch() {
            const input = document.getElementById('searchInput');
            if (input) {
                input.value = '';
                filterFindings();
            }
        }

        function resetAllFilters() {
            currentSeverity = 'ALL';
            currentCategory = 'ALL';
            currentFile = 'ALL';
            currentPrincipal = 'ALL';
            currentRule = 'ALL';
            currentCompliance = 'ALL';
            currentReqFilter = null;
            const input = document.getElementById('searchInput');
            if (input) input.value = '';
            const fileSel = document.getElementById('fileFilterSelect');
            if (fileSel) fileSel.value = 'ALL';
            const prinSel = document.getElementById('principalFilterSelect');
            if (prinSel) prinSel.value = 'ALL';
            document.querySelectorAll('.active-facet').forEach(el => el.classList.remove('active-facet'));
            updateSeverityButtons();
            updateCategoryButtons();
            filterFindings();
        }

        function updateSeverityButtons() {
            const buttons = {
                'ALL': 'btn-all',
                'CRITICAL': 'btn-crit',
                'HIGH': 'btn-high',
                'MEDIUM': 'btn-med',
                'LOW': 'btn-low',
                'INFO': 'btn-info'
            };
            const metricCards = {
                'CRITICAL': 'metric-crit',
                'HIGH': 'metric-high',
                'MEDIUM': 'metric-med',
                'LOW': 'metric-low',
                'INFO': 'metric-info'
            };
            for (let s in buttons) {
                const btn = document.getElementById(buttons[s]);
                if (btn) btn.classList.toggle('active', s === currentSeverity);
            }
            for (let s in metricCards) {
                const mc = document.getElementById(metricCards[s]);
                if (mc) mc.classList.toggle('active-metric', s === currentSeverity);
            }
        }

        function updateCategoryButtons() {
            const buttons = {
                'ALL': 'btn-cat-all',
                'POLICY': 'btn-cat-policy',
                'GTFOBINS': 'btn-dom-gtfo',
                'COMMANDS': 'btn-dom-cmd',
                'DEFAULTS': 'btn-dom-def',
                'SYSTEM': 'btn-cat-system'
            };
            for (let c in buttons) {
                const btn = document.getElementById(buttons[c]);
                if (btn) btn.classList.toggle('active', c === currentCategory);
            }
            const isPolicySub = (currentCategory === 'GTFOBINS' || currentCategory === 'COMMANDS' || currentCategory === 'DEFAULTS');
            const isAnyPolicy = (currentCategory === 'POLICY' || isPolicySub);
            const policyGroup = document.getElementById('policyFilterGroup');
            const policyParentBtn = document.getElementById('btn-cat-policy');
            if (policyGroup) policyGroup.classList.toggle('has-active-policy', isAnyPolicy);
            if (policyParentBtn) policyParentBtn.classList.toggle('parent-context', isPolicySub);
        }

        function setViewDensity(mode) {
            currentDensity = mode === 'compact' ? 'compact' : 'detailed';
            const container = document.getElementById('findingsContainer');
            const btnDet = document.getElementById('btn-view-detailed');
            const btnComp = document.getElementById('btn-view-compact');
            if (btnDet) btnDet.classList.toggle('active', currentDensity === 'detailed');
            if (btnComp) btnComp.classList.toggle('active', currentDensity === 'compact');

            if (container) {
                container.classList.toggle('view-compact', currentDensity === 'compact');
            }

            const supportsBeforeMatch = ('onbeforematch' in HTMLElement.prototype);
            const cards = allCards.length > 0 ? allCards : Array.from(document.querySelectorAll('.finding-card'));
            cards.forEach(card => {
                const body = card.querySelector('.finding-expandable-body');
                const btn = card.querySelector('.compact-toggle-btn');
                if (!body) return;
                if (currentDensity === 'compact') {
                    card.classList.remove('is-expanded');
                    if (supportsBeforeMatch) {
                        body.setAttribute('hidden', 'until-found');
                    } else {
                        body.removeAttribute('hidden');
                        card.classList.add('is-expanded');
                    }
                    if (btn) btn.setAttribute('aria-expanded', supportsBeforeMatch ? 'false' : 'true');
                } else {
                    card.classList.remove('is-expanded');
                    body.removeAttribute('hidden');
                    if (btn) btn.setAttribute('aria-expanded', 'true');
                }
            });
        }

        function handleCardHeaderClick(event, headerEl) {
            if (currentDensity !== 'compact') return;
            const card = headerEl.closest('.finding-card');
            if (card) toggleCompactCard(card);
        }

        function toggleCompactCard(card) {
            if (!card) return;
            const body = card.querySelector('.finding-expandable-body');
            const btn = card.querySelector('.compact-toggle-btn');
            const expanding = !card.classList.contains('is-expanded');
            card.classList.toggle('is-expanded', expanding);
            if (body) {
                if (expanding) {
                    body.removeAttribute('hidden');
                } else if ('onbeforematch' in HTMLElement.prototype) {
                    body.setAttribute('hidden', 'until-found');
                }
            }
            if (btn) btn.setAttribute('aria-expanded', expanding ? 'true' : 'false');
        }

        function expandAllDisclosures(expand) {
            if (currentViewTab === 'frameworks') {
                document.querySelectorAll('.framework-group-card').forEach(grp => {
                    grp.open = expand;
                });
                return;
            }
            document.querySelectorAll('.finding-group').forEach(grp => {
                grp.open = expand;
            });
            if (currentDensity === 'compact') {
                const cards = allCards.length > 0 ? allCards : Array.from(document.querySelectorAll('.finding-card'));
                cards.forEach(card => {
                    const body = card.querySelector('.finding-expandable-body');
                    const btn = card.querySelector('.compact-toggle-btn');
                    card.classList.toggle('is-expanded', expand);
                    if (body) {
                        if (expand) {
                            body.removeAttribute('hidden');
                        } else if ('onbeforematch' in HTMLElement.prototype) {
                            body.setAttribute('hidden', 'until-found');
                        }
                    }
                    if (btn) btn.setAttribute('aria-expanded', expand ? 'true' : 'false');
                });
            }
        }

        function setGroupBy(mode) {
            currentGroupBy = mode || 'NONE';
            const sel = document.getElementById('groupBySelect');
            if (sel && sel.value !== currentGroupBy) sel.value = currentGroupBy;
            rebuildGrouping();
            filterFindings();
        }

        function rebuildGrouping() {
            const container = document.getElementById('findingsContainer');
            const noMsg = document.getElementById('noFindingsMsg');
            if (!container) return;
            if (allCards.length === 0) {
                allCards = Array.from(container.querySelectorAll('.finding-card'));
            }

            // Sort cards back to canonical order first
            const sortedCards = allCards.slice().sort((a, b) => {
                return parseInt(a.getAttribute('data-order') || '0', 10) - parseInt(b.getAttribute('data-order') || '0', 10);
            });

            // Remove existing dynamic group containers
            container.querySelectorAll('.finding-group').forEach(grp => grp.remove());

            if (currentGroupBy === 'NONE') {
                sortedCards.forEach(card => container.insertBefore(card, noMsg));
                return;
            }

            const groupsMap = new Map();
            sortedCards.forEach(card => {
                let key = '';
                let title = '';
                let subtitle = '';
                let sharedRem = '';
                let sharedRemCode = '';
                let sharedRemLabel = '';

                if (currentGroupBy === 'FILE') {
                    key = card.getAttribute('data-file') || 'Global Policy';
                    title = key;
                    subtitle = 'Source File';
                } else if (currentGroupBy === 'RULE') {
                    key = card.getAttribute('data-id') || 'RULE';
                    title = key;
                    subtitle = card.getAttribute('data-title') || '';
                    sharedRem = card.getAttribute('data-remediation') || '';
                    sharedRemCode = card.getAttribute('data-remediation-code') || '';
                    sharedRemLabel = card.getAttribute('data-remediation-label') || 'Example Fix';
                } else if (currentGroupBy === 'USER') {
                    key = card.getAttribute('data-principal') || '(Global / Unscoped)';
                    title = key;
                    subtitle = 'Principal Scope';
                } else if (currentGroupBy === 'SEVERITY') {
                    key = card.getAttribute('data-severity') || 'INFO';
                    title = key;
                    subtitle = 'Severity Level';
                }

                if (!groupsMap.has(key)) {
                    groupsMap.set(key, {
                        key: key,
                        title: title,
                        subtitle: subtitle,
                        sharedRem: sharedRem,
                        sharedRemCode: sharedRemCode,
                        sharedRemLabel: sharedRemLabel,
                        cards: [],
                        crit: 0,
                        high: 0,
                        med: 0,
                        low: 0,
                        info: 0,
                        minOrder: 99
                    });
                }
                const g = groupsMap.get(key);
                g.cards.push(card);
                const sev = card.getAttribute('data-severity') || 'INFO';
                const ord = severityOrder[sev] !== undefined ? severityOrder[sev] : 5;
                if (ord < g.minOrder) g.minOrder = ord;
                if (sev === 'CRITICAL') g.crit++;
                else if (sev === 'HIGH') g.high++;
                else if (sev === 'MEDIUM') g.med++;
                else if (sev === 'LOW') g.low++;
                else g.info++;
            });

            const groupsList = Array.from(groupsMap.values());
            groupsList.sort((a, b) => {
                if (a.minOrder !== b.minOrder) return a.minOrder - b.minOrder;
                if (a.crit !== b.crit) return b.crit - a.crit;
                if (a.high !== b.high) return b.high - a.high;
                if (a.med !== b.med) return b.med - a.med;
                if (a.cards.length !== b.cards.length) return b.cards.length - a.cards.length;
                return a.key.localeCompare(b.key);
            });

            groupsList.forEach(g => {
                const details = document.createElement('details');
                details.className = 'finding-group';
                details.setAttribute('data-group-kind', currentGroupBy);
                details.setAttribute('data-group-key', g.key);
                details.open = true;

                const summary = document.createElement('summary');
                summary.className = 'finding-group-header';

                const left = document.createElement('div');
                left.className = 'group-header-left';

                const chevron = document.createElement('span');
                chevron.className = 'group-chevron';
                chevron.textContent = '\u25B6';
                left.appendChild(chevron);

                const titleSpan = document.createElement('span');
                titleSpan.className = 'group-title';
                titleSpan.textContent = g.title;
                left.appendChild(titleSpan);

                if (g.subtitle) {
                    const subSpan = document.createElement('span');
                    subSpan.className = 'group-subtitle';
                    subSpan.textContent = '\u2014 ' + g.subtitle;
                    left.appendChild(subSpan);
                }

                const right = document.createElement('div');
                right.className = 'triage-row-badges';

                if ( g.crit > 0 ) right.appendChild(makeMiniBadge(g.crit + ' CRIT', 'badge-crit', 'CRIT'));
                if ( g.high > 0 ) right.appendChild(makeMiniBadge(g.high + ' HIGH', 'badge-high', 'HIGH'));
                if ( g.med > 0 ) right.appendChild(makeMiniBadge(g.med + ' MED', 'badge-med', 'MED'));
                if ( g.low > 0 ) right.appendChild(makeMiniBadge(g.low + ' LOW', 'badge-low', 'LOW'));
                if ( g.info > 0 ) right.appendChild(makeMiniBadge(g.info + ' INFO', 'badge-info', 'INFO'));

                const totalSpan = document.createElement('span');
                totalSpan.className = 'mini-total group-visible-count';
                totalSpan.textContent = '(' + g.cards.length + ')';
                right.appendChild(totalSpan);

                summary.appendChild(left);
                summary.appendChild(right);
                details.appendChild(summary);

                const body = document.createElement('div');
                body.className = 'finding-group-body';
                g.cards.forEach(card => body.appendChild(card));
                details.appendChild(body);

                container.insertBefore(details, noMsg);
            });
        }

        function makeMiniBadge(text, cls, sevKey) {
            const span = document.createElement('span');
            span.className = 'mini-sev ' + cls;
            if (sevKey) span.setAttribute('data-group-sev', sevKey);
            span.textContent = text;
            return span;
        }

        function filterFindings() {
            const searchEl = document.getElementById('searchInput');
            const query = searchEl ? searchEl.value.trim().toLowerCase() : '';
            const clearBtn = document.getElementById('clearSearchBtn');
            const kbdHint = document.getElementById('searchKbdHint');
            if (clearBtn) clearBtn.style.display = query.length > 0 ? 'inline-block' : 'none';
            if (kbdHint) kbdHint.style.display = query.length > 0 ? 'none' : 'inline-block';

            const cards = allCards.length > 0 ? allCards : Array.from(document.querySelectorAll('.finding-card'));
            let visibleCount = 0;

            cards.forEach(card => {
                const sev = card.getAttribute('data-severity');
                const cat = card.getAttribute('data-category');
                const dom = card.getAttribute('data-domain');
                const file = card.getAttribute('data-file');
                const principal = card.getAttribute('data-principal');
                const ruleId = card.getAttribute('data-id');
                const compCSV = card.getAttribute('data-compliance') || '';
                const searchBlob = card.getAttribute('data-search') || card.innerText.toLowerCase();

                const normCardComps = compCSV ? compCSV.split(',').map(s => normalizeComplianceJS(s)) : [];
                const matchesQuery = query === '' || searchBlob.includes(query);
                const matchesSeverity = (currentSeverity === 'ALL' || sev === currentSeverity);
                const matchesCategory = (currentCategory === 'ALL' || cat === currentCategory || dom === currentCategory);
                const matchesFile = (currentFile === 'ALL' || file === currentFile);
                const matchesPrincipal = (currentPrincipal === 'ALL' || principal === currentPrincipal);
                const matchesRule = (currentRule === 'ALL' || ruleId === currentRule);
                const matchesComp = (currentCompliance === 'ALL' || normCardComps.includes(normalizeComplianceJS(currentCompliance)));
                const matchesReq = (!currentReqFilter || currentReqFilter.rules.includes(ruleId) || currentReqFilter.comps.some(c => normCardComps.includes(c)));

                if (matchesQuery && matchesSeverity && matchesCategory && matchesFile && matchesPrincipal && matchesRule && matchesComp && matchesReq) {
                    card.style.display = 'flex';
                    visibleCount++;
                } else {
                    card.style.display = 'none';
                }
            });

            // Update group visibility and counts when grouped
            document.querySelectorAll('.finding-group').forEach(grp => {
                const grpCards = grp.querySelectorAll('.finding-card');
                let grpVisible = 0, gCrit = 0, gHigh = 0, gMed = 0, gLow = 0, gInfo = 0;
                grpCards.forEach(c => {
                    if (c.style.display !== 'none') {
                        grpVisible++;
                        const s = c.getAttribute('data-severity');
                        if (s === 'CRITICAL') gCrit++;
                        else if (s === 'HIGH') gHigh++;
                        else if (s === 'MEDIUM') gMed++;
                        else if (s === 'LOW') gLow++;
                        else gInfo++;
                    }
                });
                grp.style.display = grpVisible > 0 ? 'block' : 'none';
                const countEl = grp.querySelector('.group-visible-count');
                if (countEl) countEl.textContent = '(' + grpVisible + ')';
                const sevCounts = { 'CRIT': gCrit, 'HIGH': gHigh, 'MED': gMed, 'LOW': gLow, 'INFO': gInfo };
                grp.querySelectorAll('[data-group-sev]').forEach(badge => {
                    const k = badge.getAttribute('data-group-sev');
                    const cnt = sevCounts[k] || 0;
                    badge.style.display = cnt > 0 ? 'inline-block' : 'none';
                    badge.textContent = cnt + ' ' + k;
                });
                const remTitle = grp.querySelector('.group-shared-remediation-title');
                if (remTitle) {
                    remTitle.textContent = 'Shared Rule Remediation (' + grpVisible + (grpVisible === 1 ? ' occurrence)' : ' occurrences)');
                }
            });

            const visEl = document.getElementById('visibleFindingsCount');
            if (visEl) visEl.innerText = visibleCount;

            updateActiveFilterChips(query);

            const noMsg = document.getElementById('noFindingsMsg');
            if (noMsg) {
                noMsg.style.display = visibleCount === 0 ? 'block' : 'none';
            }
        }

        function updateActiveFilterChips(query) {
            const list = document.getElementById('activeFiltersList');
            const resetBtn = document.getElementById('resetFiltersBtn');
            if (!list) return;
            list.innerHTML = '';
            let anyActive = false;

            function addChip(label, onRemove) {
                anyActive = true;
                const chip = document.createElement('button');
                chip.type = 'button';
                chip.className = 'active-filter-chip';
                chip.textContent = label + ' \u00D7';
                chip.onclick = onRemove;
                list.appendChild(chip);
            }

            if (currentSeverity !== 'ALL') addChip('Severity: ' + currentSeverity, () => filterSeverity('ALL'));
            if (currentCategory !== 'ALL') {
                const catLabels = {
                    'POLICY': 'Policy (All)',
                    'GTFOBINS': 'Policy \u203A GTFObins',
                    'COMMANDS': 'Policy \u203A Commands',
                    'DEFAULTS': 'Policy \u203A Defaults',
                    'SYSTEM': 'System'
                };
                addChip('Domain: ' + (catLabels[currentCategory] || currentCategory), () => filterCategory('ALL'));
            }
            if (currentFile !== 'ALL') addChip('Source: ' + currentFile, () => setFileFilter('ALL'));
            if (currentPrincipal !== 'ALL') addChip('Principal: ' + currentPrincipal, () => setPrincipalFilter('ALL'));
            if (currentRule !== 'ALL') addChip('Rule: ' + currentRule, () => toggleRuleFilter(currentRule));
            if (currentCompliance !== 'ALL') addChip('Compliance: ' + currentCompliance, () => toggleComplianceFilter(currentCompliance));
            if (currentReqFilter) addChip('Requirement: ' + currentReqFilter.code, () => { currentReqFilter = null; filterFindings(); });
            if (query !== '') addChip('Search: "' + query + '"', () => clearSearch());

            if (resetBtn) {
                resetBtn.style.display = anyActive ? 'inline-block' : 'none';
            }
        }

        function copyTextWithFeedback(btn, text) {
            if (!text || !navigator.clipboard) return;
            const orig = btn.textContent;
            navigator.clipboard.writeText(text).then(() => {
                btn.textContent = 'Copied!';
                setTimeout(() => { btn.textContent = orig; }, 1400);
            }).catch(() => {});
        }

        function copySiblingCode(btn) {
            const code = btn.parentElement ? btn.parentElement.querySelector('code') : null;
            if (code) copyTextWithFeedback(btn, code.textContent);
        }

        function copyCodeBlock(btn) {
            const box = btn.closest('.finding-exploit, .finding-remediation, .group-shared-remediation');
            const code = box ? box.querySelector('code') : null;
            if (code) copyTextWithFeedback(btn, code.textContent);
        }
    </script>
</body>
</html>
`

// WriteHTMLReport formats the audit results as a responsive, interactive HTML report.
func WriteHTMLReport(result *audit.AuditResult, w io.Writer) error {
	t, err := template.New("htmlReport").Parse(htmlTemplateStr)
	if err != nil {
		return err
	}

	reportData := buildHTMLReportData(result)
	return t.Execute(w, &reportData)
}
