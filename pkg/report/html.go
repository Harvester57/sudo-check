package report

import (
	_ "embed"
	"fmt"
	"html/template"
	"io"
	"path"
	"slices"
	"strings"
	"sudo-check/internal/buildinfo"
	"sudo-check/pkg/audit"
)

//go:embed templates/report.html
var htmlReportTemplateStr string

//go:embed templates/report.css
var htmlReportCSS string

//go:embed templates/report.js
var htmlReportJS string

var htmlReportTmpl = template.Must(template.New("htmlReport").Parse(htmlReportTemplateStr))

type htmlFindingView struct {
	audit.Finding
	Index                    int
	CardID                   string
	Category                 string
	Domain                   string
	DomainLabel              string
	CanonicalRuleTitle       string
	BadgeClass               string
	ExploitabilityClass      string
	SourceFile               string
	Location                 string
	Principal                string
	HasVerbatimSource        bool
	RulePreviewLabel         string
	RulePreview              string
	EffectiveRule            string
	ShowResolvedRule         bool
	CleanRemediation         string
	EffectiveRemediationCode string
	RemediationCodeLabel     string
	EffectiveExploitPoC      string
	ComplianceCSV            string
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
	ToolVersion         string
	StyleCSS            template.CSS
	ScriptJS            template.JS
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

func exploitabilityBadgeClass(exploitability string) string {
	switch strings.ToUpper(strings.TrimSpace(exploitability)) {
	case "ACTIVE":
		return "exploit-active"
	case "LATENT":
		return "exploit-latent"
	case "CONSTRAINED":
		return "exploit-constrained"
	case "PATCHED_BACKPORT":
		return "exploit-patched-backport"
	default:
		return "exploit-default"
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

// resolveFindingRemediationAndExploit normalizes structured remediation and exploit
// fields without scraping prose for synthetic commands.
func resolveFindingRemediationAndExploit(f audit.Finding, category string) (cleanRem string, effectiveRemCode string, remCodeLabel string, effectivePoC string) {
	const legacyExploitSep = "Example exploit command:\n"
	cleanRem = strings.TrimSpace(f.Remediation)
	effectiveRemCode = strings.TrimSpace(f.RemediationCode)
	effectivePoC = strings.TrimSpace(f.ExploitPoC)

	if idx := strings.Index(cleanRem, legacyExploitSep); idx != -1 {
		extracted := strings.TrimSpace(cleanRem[idx+len(legacyExploitSep):])
		cleanRem = strings.TrimSpace(cleanRem[:idx])
		if effectivePoC == "" {
			effectivePoC = extracted
		}
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
		switch {
		case isSystem && hasVisudo:
			remCodeLabel = "Remediation Commands & Sudoers Example"
		case isSystem || (hasShellCmd && !hasVisudo):
			remCodeLabel = "Remediation Command"
		case hasShellCmd && hasVisudo:
			remCodeLabel = "Remediation Commands & Sudoers Example"
		default:
			remCodeLabel = "Example Sudoers Configuration (visudo)"
		}
	}

	return cleanRem, effectiveRemCode, remCodeLabel, effectivePoC
}

func buildSynthesizedRule(f audit.Finding) (rule string, isDefaultsScope bool) {
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
		if f.Tags != "" {
			return fmt.Sprintf("%s %s = (%s) %s %s", u, h, r, f.Tags, f.Command), false
		}
		return fmt.Sprintf("%s %s = (%s) %s", u, h, r, f.Command), false
	}
	if strings.TrimSpace(f.DefaultsScope) != "" {
		return strings.TrimSpace(f.DefaultsScope), true
	}
	if f.User != "" && strings.HasPrefix(f.ID, "SUDO-DEF-") {
		// Legacy fallback for pre-DefaultsScope JSON findings without structured scope metadata.
		sep := ":"
		trimmedCode := strings.TrimSpace(f.RemediationCode)
		switch {
		case strings.HasPrefix(trimmedCode, "Defaults@"):
			sep = "@"
		case strings.HasPrefix(trimmedCode, "Defaults!"):
			sep = "!"
		case strings.HasPrefix(trimmedCode, "Defaults>"):
			sep = ">"
		}
		return fmt.Sprintf("Defaults%s%s", sep, f.User), true
	}
	if f.User != "" && f.Host != "" {
		r := f.Runas
		switch {
		case r != "" && f.Tags != "":
			return fmt.Sprintf("%s %s = (%s) %s ...", f.User, f.Host, r, f.Tags), false
		case r != "":
			return fmt.Sprintf("%s %s = (%s) ...", f.User, f.Host, r), false
		case f.Tags != "":
			return fmt.Sprintf("%s %s = %s ...", f.User, f.Host, f.Tags), false
		default:
			return fmt.Sprintf("%s %s = ...", f.User, f.Host), false
		}
	}
	return "", false
}

func normalizeRuleCompare(s string) string {
	joined := strings.Join(strings.Fields(s), " ")
	replacer := strings.NewReplacer(
		" = ", "=",
		" =", "=",
		"= ", "=",
		"( ", "(",
		" )", ")",
		" ,", ",",
		", ", ",",
	)
	return replacer.Replace(joined)
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

	rawSource := strings.TrimSpace(f.SourceLine)
	effectiveRule, isDefScope := buildSynthesizedRule(f)

	var (
		hasVerbatim      bool
		rulePreviewLabel string
		rulePreview      string
		showResolvedRule bool
	)

	if rawSource != "" {
		hasVerbatim = true
		rulePreview = rawSource
		if location != "" {
			rulePreviewLabel = fmt.Sprintf("Source Line (%s)", location)
		} else {
			rulePreviewLabel = "Source Line"
		}
		if effectiveRule != "" && !isDefScope && !strings.HasSuffix(effectiveRule, "...") && normalizeRuleCompare(rawSource) != normalizeRuleCompare(effectiveRule) {
			showResolvedRule = true
		}
	} else if effectiveRule != "" {
		rulePreview = effectiveRule
		if isDefScope {
			rulePreviewLabel = "Effective Scope (Synthesized)"
		} else {
			rulePreviewLabel = "Effective Rule (Synthesized)"
		}
	}

	cleanRem, effectiveRemCode, remCodeLabel, effectivePoC := resolveFindingRemediationAndExploit(f, category)
	compCSV := strings.Join(f.Compliance, ",")
	f.Exploitability = strings.TrimSpace(f.Exploitability)
	var exploitClass string
	if f.Exploitability != "" {
		exploitClass = exploitabilityBadgeClass(f.Exploitability)
	}

	return htmlFindingView{
		Finding:                  f,
		Index:                    idx,
		CardID:                   fmt.Sprintf("finding-%d", idx),
		Category:                 category,
		Domain:                   domain,
		DomainLabel:              domainLabel,
		CanonicalRuleTitle:       canonicalRuleTitle(f),
		BadgeClass:               badge,
		ExploitabilityClass:      exploitClass,
		SourceFile:               sourceFile,
		Location:                 location,
		Principal:                principal,
		HasVerbatimSource:        hasVerbatim,
		RulePreviewLabel:         rulePreviewLabel,
		RulePreview:              rulePreview,
		EffectiveRule:            effectiveRule,
		ShowResolvedRule:         showResolvedRule,
		CleanRemediation:         cleanRem,
		EffectiveRemediationCode: effectiveRemCode,
		RemediationCodeLabel:     remCodeLabel,
		EffectiveExploitPoC:      effectivePoC,
		ComplianceCSV:            compCSV,
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
		ToolVersion: buildinfo.Version,
		StyleCSS:    template.CSS(htmlReportCSS),
		ScriptJS:    template.JS(htmlReportJS),
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

		// Rule summary (always keyed by canonical rule title so counts/labels never depend on first-seen finding)
		rs, ok := ruleMap[v.ID]
		if !ok {
			rs = &htmlRuleSummary{
				ID:          v.ID,
				Title:       v.CanonicalRuleTitle,
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
		if a.Low != b.Low {
			return b.Low - a.Low
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
		if a.Low != b.Low {
			return b.Low - a.Low
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

// WriteHTMLReport formats the audit results as a responsive, interactive HTML report.
func WriteHTMLReport(result *audit.AuditResult, w io.Writer) error {
	reportData := buildHTMLReportData(result)
	return htmlReportTmpl.Execute(w, &reportData)
}
