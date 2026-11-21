package fleet

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sudo-check/pkg/audit"
)

// HostRiskSummary aggregates finding counts and highest severity for a single host report.
type HostRiskSummary struct {
	Hostname    string         `json:"hostname"`
	SourceFile  string         `json:"source_file"`
	SudoVersion string         `json:"sudo_version,omitempty"`
	Critical    int            `json:"critical"`
	High        int            `json:"high"`
	Medium      int            `json:"medium"`
	Low         int            `json:"low"`
	Info        int            `json:"info"`
	Total       int            `json:"total"`
	Highest     audit.Severity `json:"highest_severity"`
}

// RulePrevalenceSummary tracks how widely a rule ID appears across the audited fleet.
type RulePrevalenceSummary struct {
	RuleID        string         `json:"rule_id"`
	Title         string         `json:"title"`
	Severity      audit.Severity `json:"severity"`
	HostCount     int            `json:"host_count"`
	TotalCount    int            `json:"total_count"`
	AffectedHosts []string       `json:"affected_hosts"`
}

// FleetSummary holds aggregated risk metrics across multiple audited hosts.
type FleetSummary struct {
	HostCount      int                     `json:"host_count"`
	TotalFindings  int                     `json:"total_findings"`
	SeverityCounts map[audit.Severity]int  `json:"severity_counts"`
	HostSummaries  []HostRiskSummary       `json:"host_summaries"`
	RulePrevalence []RulePrevalenceSummary `json:"rule_prevalence"`
}

var validAuditResultKeys = map[string]bool{
	"policy_findings": true,
	"system_findings": true,
	"sudo_version":    true,
	"hostname":        true,
}

// MergeReportFiles reads multiple JSON audit report files and aggregates host risk
// and rule prevalence metrics across the fleet.
func MergeReportFiles(paths []string) (*FleetSummary, error) {
	if len(paths) == 0 {
		return nil, fmt.Errorf("no report files provided")
	}

	summary := &FleetSummary{
		SeverityCounts: map[audit.Severity]int{
			audit.SeverityCritical: 0,
			audit.SeverityHigh:     0,
			audit.SeverityMedium:   0,
			audit.SeverityLow:      0,
			audit.SeverityInfo:     0,
		},
		HostSummaries:  make([]HostRiskSummary, 0, len(paths)),
		RulePrevalence: make([]RulePrevalenceSummary, 0),
	}

	type parsedHostReport struct {
		hostSum     HostRiskSummary
		rawHostname string
		baseHost    string
		path        string
		findings    []audit.Finding
	}

	parsedHosts := make([]parsedHostReport, 0, len(paths))
	for _, p := range paths {
		res, err := parseAuditReportFile(p)
		if err != nil {
			return nil, err
		}

		hostSum := HostRiskSummary{
			SourceFile:  filepath.ToSlash(p),
			SudoVersion: strings.TrimSpace(res.SudoVersion),
		}

		allFindings := make([]audit.Finding, 0, len(res.SystemFindings)+len(res.PolicyFindings))
		allFindings = append(allFindings, res.SystemFindings...)
		allFindings = append(allFindings, res.PolicyFindings...)
		audit.SortFindingsBySeverity(allFindings)

		var highest audit.Severity
		for _, f := range allFindings {
			sev := normalizeSeverity(f.Severity)
			switch sev {
			case audit.SeverityCritical:
				hostSum.Critical++
			case audit.SeverityHigh:
				hostSum.High++
			case audit.SeverityMedium:
				hostSum.Medium++
			case audit.SeverityLow:
				hostSum.Low++
			case audit.SeverityInfo:
				hostSum.Info++
			}
			if sev != "" {
				summary.SeverityCounts[sev]++
			}
			hostSum.Total++
			summary.TotalFindings++

			if highest == "" || sev.Order() < highest.Order() {
				highest = sev
			}
		}

		if hostSum.Total == 0 {
			hostSum.Highest = audit.Severity("NONE")
		} else {
			hostSum.Highest = highest
		}

		parsedHosts = append(parsedHosts, parsedHostReport{
			hostSum:     hostSum,
			rawHostname: res.Hostname,
			baseHost:    deriveBaseHostname(res.Hostname, p),
			path:        p,
			findings:    allFindings,
		})
	}

	// Sort parsed hosts deterministically before disambiguating duplicate hostnames
	// so "(2)" suffixes and rule prevalence never depend on CLI argument order.
	slices.SortFunc(parsedHosts, func(a, b parsedHostReport) int {
		if a.hostSum.Critical != b.hostSum.Critical {
			return b.hostSum.Critical - a.hostSum.Critical
		}
		if a.hostSum.High != b.hostSum.High {
			return b.hostSum.High - a.hostSum.High
		}
		if a.hostSum.Medium != b.hostSum.Medium {
			return b.hostSum.Medium - a.hostSum.Medium
		}
		if a.hostSum.Low != b.hostSum.Low {
			return b.hostSum.Low - a.hostSum.Low
		}
		if a.hostSum.Total != b.hostSum.Total {
			return b.hostSum.Total - a.hostSum.Total
		}
		if a.baseHost != b.baseHost {
			return strings.Compare(a.baseHost, b.baseHost)
		}
		return strings.Compare(a.hostSum.SourceFile, b.hostSum.SourceFile)
	})

	usedHostnames := make(map[string]bool, len(parsedHosts))
	ruleAgg := make(map[string]*RulePrevalenceSummary)
	ruleHosts := make(map[string]map[string]bool)

	for _, ph := range parsedHosts {
		hostname := resolveUniqueHostname(ph.rawHostname, ph.path, usedHostnames)
		ph.hostSum.Hostname = hostname

		for _, f := range ph.findings {
			sev := normalizeSeverity(f.Severity)
			ruleID := strings.TrimSpace(f.ID)
			if ruleID == "" {
				ruleID = "UNKNOWN"
			}
			fTitle := audit.CanonicalRuleTitle(ruleID, f.Title)
			rp, exists := ruleAgg[ruleID]
			if !exists {
				rp = &RulePrevalenceSummary{
					RuleID:        ruleID,
					Title:         fTitle,
					Severity:      sev,
					AffectedHosts: make([]string, 0, 1),
				}
				ruleAgg[ruleID] = rp
				ruleHosts[ruleID] = make(map[string]bool)
			} else {
				if sev.Order() < rp.Severity.Order() {
					rp.Severity = sev
					if fTitle != "" {
						rp.Title = fTitle
					}
				} else if sev.Order() == rp.Severity.Order() && fTitle != "" && (rp.Title == "" || fTitle < rp.Title) {
					rp.Title = fTitle
				} else if rp.Title == "" && fTitle != "" {
					rp.Title = fTitle
				}
			}
			rp.TotalCount++
			if !ruleHosts[ruleID][hostname] {
				ruleHosts[ruleID][hostname] = true
				rp.AffectedHosts = append(rp.AffectedHosts, hostname)
			}
		}

		summary.HostSummaries = append(summary.HostSummaries, ph.hostSum)
	}

	summary.HostCount = len(summary.HostSummaries)

	slices.SortFunc(summary.HostSummaries, func(a, b HostRiskSummary) int {
		if a.Critical != b.Critical {
			return b.Critical - a.Critical
		}
		if a.High != b.High {
			return b.High - a.High
		}
		if a.Medium != b.Medium {
			return b.Medium - a.Medium
		}
		if a.Low != b.Low {
			return b.Low - a.Low
		}
		if a.Total != b.Total {
			return b.Total - a.Total
		}
		return strings.Compare(a.Hostname, b.Hostname)
	})

	for _, rp := range ruleAgg {
		slices.Sort(rp.AffectedHosts)
		rp.HostCount = len(rp.AffectedHosts)
		summary.RulePrevalence = append(summary.RulePrevalence, *rp)
	}

	slices.SortFunc(summary.RulePrevalence, func(a, b RulePrevalenceSummary) int {
		if a.Severity.Order() != b.Severity.Order() {
			return a.Severity.Order() - b.Severity.Order()
		}
		if a.HostCount != b.HostCount {
			return b.HostCount - a.HostCount
		}
		if a.TotalCount != b.TotalCount {
			return b.TotalCount - a.TotalCount
		}
		return strings.Compare(a.RuleID, b.RuleID)
	})

	return summary, nil
}

func parseAuditReportFile(path string) (*audit.AuditResult, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read report file %s: %w", path, err)
	}

	trimmed := bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))
	trimmed = bytes.TrimSpace(trimmed)
	if len(trimmed) == 0 || trimmed[0] != '{' || !json.Valid(trimmed) {
		return nil, fmt.Errorf("invalid report file %s: expected a JSON object", path)
	}

	var obj map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &obj); err != nil || obj == nil {
		return nil, fmt.Errorf("invalid report file %s: failed to decode JSON object: %w", path, err)
	}
	if len(obj) > 0 {
		hasKnownKey := false
		for k := range obj {
			if validAuditResultKeys[k] {
				hasKnownKey = true
				break
			}
		}
		if !hasKnownKey {
			return nil, fmt.Errorf("invalid report file %s: JSON object does not contain audit result fields", path)
		}
	}

	var res audit.AuditResult
	if err := json.Unmarshal(trimmed, &res); err != nil {
		return nil, fmt.Errorf("failed to unmarshal audit report %s: %w", path, err)
	}
	return &res, nil
}

func deriveBaseHostname(rawHostname string, filePath string) string {
	baseHost := strings.TrimSpace(rawHostname)
	if baseHost == "" {
		base := filepath.Base(filePath)
		if strings.HasSuffix(strings.ToLower(base), ".json") {
			base = base[:len(base)-len(".json")]
		}
		baseHost = strings.TrimSpace(base)
		if baseHost == "" || baseHost == "." || baseHost == string(filepath.Separator) {
			baseHost = filePath
		}
	}
	return baseHost
}

func resolveUniqueHostname(rawHostname string, filePath string, used map[string]bool) string {
	baseHost := deriveBaseHostname(rawHostname, filePath)

	candidate := baseHost
	if used[candidate] {
		for n := 2; ; n++ {
			next := fmt.Sprintf("%s (%d)", baseHost, n)
			if !used[next] {
				candidate = next
				break
			}
		}
	}
	used[candidate] = true
	return candidate
}

func normalizeSeverity(sev audit.Severity) audit.Severity {
	if parsed, ok := audit.ParseSeverity(string(sev)); ok {
		return parsed
	}
	trimmed := strings.ToUpper(strings.TrimSpace(string(sev)))
	if trimmed == "" {
		return audit.SeverityInfo
	}
	return audit.Severity(trimmed)
}

// WriteFleetJSON writes the aggregated fleet summary as indented JSON.
func WriteFleetJSON(summary *FleetSummary, w io.Writer) error {
	if summary == nil {
		return fmt.Errorf("fleet summary is nil")
	}
	if w == nil {
		return fmt.Errorf("output writer is nil")
	}

	out := FleetSummary{
		HostCount:      summary.HostCount,
		TotalFindings:  summary.TotalFindings,
		SeverityCounts: make(map[audit.Severity]int, 5),
		HostSummaries:  make([]HostRiskSummary, len(summary.HostSummaries)),
		RulePrevalence: make([]RulePrevalenceSummary, len(summary.RulePrevalence)),
	}
	for _, sev := range []audit.Severity{
		audit.SeverityCritical,
		audit.SeverityHigh,
		audit.SeverityMedium,
		audit.SeverityLow,
		audit.SeverityInfo,
	} {
		out.SeverityCounts[sev] = summary.SeverityCounts[sev]
	}
	copy(out.HostSummaries, summary.HostSummaries)
	for i, rp := range summary.RulePrevalence {
		hosts := make([]string, len(rp.AffectedHosts))
		copy(hosts, rp.AffectedHosts)
		rp.AffectedHosts = hosts
		out.RulePrevalence[i] = rp
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

// WriteFleetCSV writes the per-host fleet risk summary rows as RFC 4180 CSV.
func WriteFleetCSV(summary *FleetSummary, w io.Writer) error {
	if summary == nil {
		return fmt.Errorf("fleet summary is nil")
	}
	if w == nil {
		return fmt.Errorf("output writer is nil")
	}

	cw := csv.NewWriter(w)
	header := []string{
		"hostname",
		"sudo_version",
		"critical",
		"high",
		"medium",
		"low",
		"info",
		"total",
		"highest_severity",
		"source_file",
	}
	if err := cw.Write(header); err != nil {
		return fmt.Errorf("failed to write CSV header: %w", err)
	}

	for _, hs := range summary.HostSummaries {
		highest := string(hs.Highest)
		if highest == "" {
			highest = "NONE"
		}
		row := []string{
			hs.Hostname,
			hs.SudoVersion,
			strconv.Itoa(hs.Critical),
			strconv.Itoa(hs.High),
			strconv.Itoa(hs.Medium),
			strconv.Itoa(hs.Low),
			strconv.Itoa(hs.Info),
			strconv.Itoa(hs.Total),
			highest,
			hs.SourceFile,
		}
		if err := cw.Write(row); err != nil {
			return fmt.Errorf("failed to write CSV row for %s: %w", hs.Hostname, err)
		}
	}

	cw.Flush()
	if err := cw.Error(); err != nil {
		return fmt.Errorf("failed to flush CSV writer: %w", err)
	}
	return nil
}

type fleetHTMLHostView struct {
	Rank        int
	Hostname    string
	SudoVersion string
	Critical    int
	High        int
	Medium      int
	Low         int
	Info        int
	Total       int
	Highest     string
	BadgeClass  string
	SourceFile  string
}

type fleetHTMLRuleView struct {
	RuleID        string
	Title         string
	Severity      string
	BadgeClass    string
	HostCount     int
	TotalCount    int
	AffectedHosts []string
	HostsCSV      string
}

type fleetHTMLData struct {
	HostCount          int
	TotalFindings      int
	DistinctRulesCount int
	HostsWithCrit      int
	CritCount          int
	HighCount          int
	MedCount           int
	LowCount           int
	InfoCount          int
	CritPct            float64
	HighPct            float64
	MedPct             float64
	LowPct             float64
	InfoPct            float64
	Hosts              []fleetHTMLHostView
	Rules              []fleetHTMLRuleView
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
	case audit.SeverityInfo:
		return "badge-info"
	default:
		return "badge-none"
	}
}

func buildFleetHTMLData(summary *FleetSummary) fleetHTMLData {
	crit := summary.SeverityCounts[audit.SeverityCritical]
	high := summary.SeverityCounts[audit.SeverityHigh]
	med := summary.SeverityCounts[audit.SeverityMedium]
	low := summary.SeverityCounts[audit.SeverityLow]
	info := summary.SeverityCounts[audit.SeverityInfo]

	total := summary.TotalFindings
	pct := func(n int) float64 {
		if total <= 0 {
			return 0
		}
		return float64(n) * 100.0 / float64(total)
	}

	hosts := make([]fleetHTMLHostView, 0, len(summary.HostSummaries))
	hostsWithCrit := 0
	for i, hs := range summary.HostSummaries {
		if hs.Critical > 0 {
			hostsWithCrit++
		}
		highest := string(hs.Highest)
		if highest == "" {
			highest = "NONE"
		}
		ver := hs.SudoVersion
		if ver == "" {
			ver = "Unknown"
		}
		hosts = append(hosts, fleetHTMLHostView{
			Rank:        i + 1,
			Hostname:    hs.Hostname,
			SudoVersion: ver,
			Critical:    hs.Critical,
			High:        hs.High,
			Medium:      hs.Medium,
			Low:         hs.Low,
			Info:        hs.Info,
			Total:       hs.Total,
			Highest:     highest,
			BadgeClass:  severityBadgeClass(hs.Highest),
			SourceFile:  hs.SourceFile,
		})
	}

	rules := make([]fleetHTMLRuleView, 0, len(summary.RulePrevalence))
	for _, rp := range summary.RulePrevalence {
		title := rp.Title
		if title == "" {
			title = rp.RuleID
		}
		rules = append(rules, fleetHTMLRuleView{
			RuleID:        rp.RuleID,
			Title:         title,
			Severity:      string(rp.Severity),
			BadgeClass:    severityBadgeClass(rp.Severity),
			HostCount:     rp.HostCount,
			TotalCount:    rp.TotalCount,
			AffectedHosts: rp.AffectedHosts,
			HostsCSV:      strings.Join(rp.AffectedHosts, ", "),
		})
	}

	return fleetHTMLData{
		HostCount:          summary.HostCount,
		TotalFindings:      summary.TotalFindings,
		DistinctRulesCount: len(summary.RulePrevalence),
		HostsWithCrit:      hostsWithCrit,
		CritCount:          crit,
		HighCount:          high,
		MedCount:           med,
		LowCount:           low,
		InfoCount:          info,
		CritPct:            pct(crit),
		HighPct:            pct(high),
		MedPct:             pct(med),
		LowPct:             pct(low),
		InfoPct:            pct(info),
		Hosts:              hosts,
		Rules:              rules,
	}
}

const fleetHTMLTemplateStr = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="color-scheme" content="light dark">
    <meta name="description" content="Sudoers Fleet Security Summary Report. Aggregates sudoers audit findings and host risk posture across hosts.">
    <title>Sudoers Fleet Security Summary ({{.HostCount}} Hosts)</title>
    <script>
        (function() {
            try {
                var saved = localStorage.getItem('sudo-check-theme');
                if (saved === 'light' || saved === 'dark') {
                    document.documentElement.setAttribute('data-theme', saved);
                } else if (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) {
                    document.documentElement.setAttribute('data-theme', 'dark');
                } else {
                    document.documentElement.setAttribute('data-theme', 'light');
                }
            } catch (e) {}
        })();
    </script>
    <style>
        :root {
            color-scheme: light dark;
            --bg-page: #f6f8fa;
            --panel-bg: #ffffff;
            --panel-bg-elevated: #ffffff;
            --panel-border: #d0d7de;
            --panel-border-strong: #afb8c1;
            --surface-subtle: #f6f8fa;
            --surface-hover: #eaeef2;
            --text-main: #1f2328;
            --text-muted: #59636e;
            --font-primary: system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            --font-code: ui-monospace, SFMono-Regular, 'SF Mono', Menlo, Consolas, 'Liberation Mono', monospace;
            --accent-primary: #0f4c81;
            --accent-primary-bg: rgba(15, 76, 129, 0.08);
            --accent-crit: #b91c1c;
            --accent-high: #c2410c;
            --accent-med: #92400e;
            --accent-low: #0369a1;
            --accent-info: #475569;
            --accent-none: #15803d;
            --accent-crit-bg: #fef2f2;
            --accent-high-bg: #fff7ed;
            --accent-med-bg: #fffbeb;
            --accent-low-bg: #f0f9ff;
            --accent-info-bg: #f1f5f9;
            --accent-none-bg: #f0fdf4;
            --accent-crit-border: #fecaca;
            --accent-high-border: #fed7aa;
            --accent-med-border: #fde68a;
            --accent-low-border: #bae6fd;
            --accent-info-border: #cbd5e1;
            --accent-none-border: #bbf7d0;
            --shadow-sm: 0 1px 2px rgba(15, 23, 42, 0.05);
            --shadow-md: 0 2px 8px rgba(15, 23, 42, 0.08);
            accent-color: var(--accent-primary);
        }

        [data-theme="light"] {
            color-scheme: light;
        }

        [data-theme="dark"] {
            color-scheme: dark;
            --bg-page: #0d1117;
            --panel-bg: #161b22;
            --panel-bg-elevated: #1c2128;
            --panel-border: #30363d;
            --panel-border-strong: #484f58;
            --surface-subtle: #0d1117;
            --surface-hover: #21262d;
            --text-main: #e6edf3;
            --text-muted: #8b949e;
            --accent-primary: #2563eb;
            --accent-primary-bg: rgba(59, 130, 246, 0.14);
            --accent-crit: #f87171;
            --accent-high: #fb923c;
            --accent-med: #eab308;
            --accent-low: #60a5fa;
            --accent-info: #94a3b8;
            --accent-none: #4ade80;
            --accent-crit-bg: rgba(239, 68, 68, 0.13);
            --accent-high-bg: rgba(249, 115, 22, 0.13);
            --accent-med-bg: rgba(234, 179, 8, 0.12);
            --accent-low-bg: rgba(59, 130, 246, 0.12);
            --accent-info-bg: rgba(148, 163, 184, 0.12);
            --accent-none-bg: rgba(34, 197, 94, 0.12);
            --accent-crit-border: rgba(248, 113, 113, 0.32);
            --accent-high-border: rgba(251, 146, 60, 0.32);
            --accent-med-border: rgba(234, 179, 8, 0.30);
            --accent-low-border: rgba(96, 165, 250, 0.30);
            --accent-info-border: rgba(148, 163, 184, 0.28);
            --accent-none-border: rgba(74, 222, 128, 0.30);
            --shadow-sm: 0 1px 2px rgba(0, 0, 0, 0.28);
            --shadow-md: 0 2px 8px rgba(0, 0, 0, 0.36);
        }

        @media (prefers-color-scheme: dark) {
            :root:not([data-theme="light"]) {
                color-scheme: dark;
                --bg-page: #0d1117;
                --panel-bg: #161b22;
                --panel-bg-elevated: #1c2128;
                --panel-border: #30363d;
                --panel-border-strong: #484f58;
                --surface-subtle: #0d1117;
                --surface-hover: #21262d;
                --text-main: #e6edf3;
                --text-muted: #8b949e;
                --accent-primary: #2563eb;
                --accent-primary-bg: rgba(59, 130, 246, 0.14);
                --accent-crit: #f87171;
                --accent-high: #fb923c;
                --accent-med: #eab308;
                --accent-low: #60a5fa;
                --accent-info: #94a3b8;
                --accent-none: #4ade80;
                --accent-crit-bg: rgba(239, 68, 68, 0.13);
                --accent-high-bg: rgba(249, 115, 22, 0.13);
                --accent-med-bg: rgba(234, 179, 8, 0.12);
                --accent-low-bg: rgba(59, 130, 246, 0.12);
                --accent-info-bg: rgba(148, 163, 184, 0.12);
                --accent-none-bg: rgba(34, 197, 94, 0.12);
                --accent-crit-border: rgba(248, 113, 113, 0.32);
                --accent-high-border: rgba(251, 146, 60, 0.32);
                --accent-med-border: rgba(234, 179, 8, 0.30);
                --accent-low-border: rgba(96, 165, 250, 0.30);
                --accent-info-border: rgba(148, 163, 184, 0.28);
                --accent-none-border: rgba(74, 222, 128, 0.30);
                --shadow-sm: 0 1px 2px rgba(0, 0, 0, 0.28);
                --shadow-md: 0 2px 8px rgba(0, 0, 0, 0.36);
            }
        }

        .skip-link {
            position: absolute;
            top: 0.5rem;
            left: 0.5rem;
            z-index: 100;
            padding: 0.5rem 1rem;
            background: var(--accent-primary);
            color: #ffffff;
            font-weight: 600;
            border-radius: 6px;
            text-decoration: none;
        }

        .skip-link:not(:focus):not(:active) {
            position: absolute;
            width: 1px;
            height: 1px;
            padding: 0;
            margin: -1px;
            overflow: hidden;
            clip-path: inset(50%);
            white-space: nowrap;
            border: 0;
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }

        body {
            font-family: var(--font-primary);
            background: var(--bg-page);
            color: var(--text-main);
            min-height: 100vh;
            padding: 1.5rem 1rem 3rem;
            line-height: 1.5;
        }

        .container {
            max-width: 1320px;
            margin: 0 auto;
        }

        header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            gap: 1rem;
            margin-bottom: 1.25rem;
            padding: 1.25rem 1.5rem;
            background: var(--panel-bg);
            border: 1px solid var(--panel-border);
            border-radius: 8px;
            box-shadow: var(--shadow-sm);
        }

        .header-title h1 {
            font-size: 1.5rem;
            font-weight: 700;
            letter-spacing: -0.02em;
            color: var(--text-main);
        }

        .header-title p {
            font-size: 0.85rem;
            color: var(--text-muted);
            margin-top: 0.2rem;
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
            padding: 0.42rem 0.8rem;
            border-radius: 6px;
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

        .fleet-meta {
            background: var(--panel-bg);
            border: 1px solid var(--panel-border);
            border-radius: 8px;
            padding: 0.85rem 1.25rem;
            margin-bottom: 1.25rem;
            font-size: 0.85rem;
            display: flex;
            flex-wrap: wrap;
            align-items: center;
            gap: 0.9rem 1.75rem;
            box-shadow: var(--shadow-sm);
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
            padding: 0.12rem 0.48rem;
            border-radius: 4px;
            background: var(--surface-subtle);
            border: 1px solid var(--panel-border);
        }

        .metrics-grid {
            display: grid;
            grid-template-columns: repeat(5, minmax(140px, 1fr));
            gap: 0.85rem;
            margin-bottom: 0.75rem;
        }

        .metric-card {
            background: var(--panel-bg);
            border: 1px solid var(--panel-border);
            border-radius: 8px;
            padding: 1rem 0.9rem;
            text-align: center;
            box-shadow: var(--shadow-sm);
            position: relative;
            overflow: hidden;
            cursor: pointer;
            color: var(--text-main);
            font-family: var(--font-primary);
            width: 100%;
            transition: background-color 0.15s, border-color 0.15s, box-shadow 0.15s;
        }

        .metric-card:hover {
            background: var(--surface-hover);
            border-color: var(--panel-border-strong);
        }

        .metric-card.active-metric {
            border-color: var(--accent-primary);
            box-shadow: 0 0 0 2px var(--accent-primary);
        }

        .metric-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 3px;
        }

        .card-crit::before { background: var(--accent-crit); }
        .card-high::before { background: var(--accent-high); }
        .card-med::before { background: var(--accent-med); }
        .card-low::before { background: var(--accent-low); }
        .card-info::before { background: var(--accent-info); }

        .metric-num {
            display: block;
            font-size: 1.95rem;
            font-weight: 700;
            font-variant-numeric: tabular-nums;
            margin: 0.25rem 0 0.1rem;
            line-height: 1.1;
        }

        .metric-label {
            display: block;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.06em;
            color: var(--text-muted);
        }

        .metric-hint {
            display: block;
            font-size: 0.7rem;
            color: var(--text-muted);
        }

        .severity-distribution {
            height: 6px;
            border-radius: 999px;
            background: var(--surface-subtle);
            border: 1px solid var(--panel-border);
            overflow: hidden;
            display: flex;
            margin-bottom: 1.25rem;
        }

        .sev-seg-crit { background: var(--accent-crit); width: {{printf "%.2f" .CritPct}}%; }
        .sev-seg-high { background: var(--accent-high); width: {{printf "%.2f" .HighPct}}%; }
        .sev-seg-med { background: var(--accent-med); width: {{printf "%.2f" .MedPct}}%; }
        .sev-seg-low { background: var(--accent-low); width: {{printf "%.2f" .LowPct}}%; }
        .sev-seg-info { background: var(--accent-info); width: {{printf "%.2f" .InfoPct}}%; }

        .controls-panel {
            background: var(--panel-bg-elevated);
            border: 1px solid var(--panel-border-strong);
            border-radius: 8px;
            padding: 0.85rem 1.15rem;
            margin-bottom: 1.25rem;
            display: flex;
            flex-wrap: wrap;
            gap: 0.75rem;
            align-items: center;
            justify-content: space-between;
            box-shadow: var(--shadow-sm);
        }

        .search-input {
            flex: 1 1 260px;
            background: var(--surface-subtle);
            border: 1px solid var(--panel-border);
            border-radius: 6px;
            padding: 0.5rem 0.8rem;
            color: var(--text-main);
            font-family: var(--font-primary);
            font-size: 0.88rem;
        }

        .search-input:focus {
            outline: 2px solid var(--accent-primary);
            outline-offset: -1px;
        }

        .filter-buttons {
            display: flex;
            flex-wrap: wrap;
            gap: 0.38rem;
            align-items: center;
        }

        .filter-btn {
            background: var(--surface-subtle);
            border: 1px solid var(--panel-border);
            color: var(--text-main);
            padding: 0.36rem 0.72rem;
            border-radius: 6px;
            font-size: 0.78rem;
            font-weight: 500;
            font-family: var(--font-primary);
            cursor: pointer;
        }

        .filter-btn.active {
            background: var(--accent-primary);
            color: #ffffff;
            border-color: var(--accent-primary);
        }

        .panel-section {
            background: var(--panel-bg);
            border: 1px solid var(--panel-border);
            border-radius: 8px;
            margin-bottom: 1.25rem;
            box-shadow: var(--shadow-sm);
            overflow: hidden;
        }

        .panel-header {
            padding: 1rem 1.25rem;
            border-bottom: 1px solid var(--panel-border);
            display: flex;
            justify-content: space-between;
            align-items: center;
            gap: 1rem;
            flex-wrap: wrap;
        }

        .panel-header h2 {
            font-size: 1.05rem;
            font-weight: 700;
        }

        .panel-subtitle {
            font-size: 0.8rem;
            color: var(--text-muted);
        }

        .table-wrap {
            width: 100%;
            overflow-x: auto;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            font-size: 0.85rem;
        }

        thead th {
            text-align: left;
            padding: 0.72rem 0.9rem;
            font-size: 0.73rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: var(--text-muted);
            background: var(--surface-subtle);
            border-bottom: 1px solid var(--panel-border);
            white-space: nowrap;
        }

        tbody td {
            padding: 0.72rem 0.9rem;
            border-bottom: 1px solid var(--panel-border);
            vertical-align: middle;
        }

        tbody tr:last-child td {
            border-bottom: none;
        }

        tbody tr:hover {
            background: var(--surface-hover);
        }

        .num-col {
            text-align: right;
            font-family: var(--font-code);
            font-variant-numeric: tabular-nums;
        }

        .code-cell {
            font-family: var(--font-code);
            font-size: 0.8rem;
        }

        .sev-badge {
            display: inline-block;
            font-size: 0.71rem;
            font-weight: 700;
            padding: 0.2rem 0.55rem;
            border-radius: 6px;
            text-transform: uppercase;
            letter-spacing: 0.04em;
            white-space: nowrap;
        }

        .badge-crit { background: var(--accent-crit-bg); color: var(--accent-crit); border: 1px solid var(--accent-crit-border); }
        .badge-high { background: var(--accent-high-bg); color: var(--accent-high); border: 1px solid var(--accent-high-border); }
        .badge-med { background: var(--accent-med-bg); color: var(--accent-med); border: 1px solid var(--accent-med-border); }
        .badge-low { background: var(--accent-low-bg); color: var(--accent-low); border: 1px solid var(--accent-low-border); }
        .badge-info { background: var(--accent-info-bg); color: var(--accent-info); border: 1px solid var(--accent-info-border); }
        .badge-none { background: var(--accent-none-bg); color: var(--accent-none); border: 1px solid var(--accent-none-border); }

        .host-pills {
            display: flex;
            flex-wrap: wrap;
            gap: 0.3rem;
        }

        .host-pill {
            font-family: var(--font-code);
            font-size: 0.72rem;
            padding: 0.1rem 0.42rem;
            border-radius: 4px;
            background: var(--surface-subtle);
            border: 1px solid var(--panel-border);
        }

        .empty-state {
            padding: 1.5rem 1.25rem;
            color: var(--text-muted);
            font-size: 0.9rem;
        }

        @media (max-width: 820px) {
            .metrics-grid {
                grid-template-columns: repeat(2, minmax(120px, 1fr));
            }
        }

        @media (forced-colors: active) {
            .metric-card.active-metric,
            .filter-btn.active {
                border: 2px solid Highlight;
            }
        }

        @media print {
            :root,
            [data-theme="dark"],
            [data-theme="light"] {
                color-scheme: light !important;
                --bg-page: #ffffff !important;
                --panel-bg: #ffffff !important;
                --panel-bg-elevated: #ffffff !important;
                --panel-border: #cbd5e1 !important;
                --panel-border-strong: #94a3b8 !important;
                --surface-subtle: #f8fafc !important;
                --text-main: #0f172a !important;
                --text-muted: #475569 !important;
                --accent-primary: #0f4c81 !important;
                --accent-crit: #b91c1c !important;
                --accent-high: #c2410c !important;
                --accent-med: #92400e !important;
                --accent-low: #0369a1 !important;
                --accent-info: #475569 !important;
                --accent-none: #15803d !important;
            }
            body {
                background: #ffffff !important;
                color: #0f172a !important;
                padding: 0;
            }
            .controls-panel,
            .header-actions {
                display: none !important;
            }
            header,
            .fleet-meta,
            .panel-section,
            .metric-card {
                box-shadow: none !important;
                border: 1px solid #cbd5e1 !important;
            }
        }
    </style>
</head>
<body>
    <a href="#main-content" class="skip-link">Skip to main content</a>
    <div class="container">
        <header>
            <div class="header-title">
                <h1>Sudoers Fleet Security Summary</h1>
                <p>Multi-host posture aggregation generated by sudo-check</p>
            </div>
            <div class="header-actions">
                <button class="action-btn" type="button" onclick="window.print()" title="Print or save as PDF">Print</button>
                <button class="theme-toggle-btn" id="themeToggleBtn" type="button" onclick="toggleTheme()">
                    <svg aria-hidden="true" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364-6.364l-.707.707M6.343 17.657l-.707.707m0-12.728l.707.707m11.314 11.314l.707.707M12 5a7 7 0 100 14 7 7 0 000-14z"/></svg>
                    Toggle Theme
                </button>
            </div>
        </header>

        <main id="main-content" tabindex="-1">
            <section class="fleet-meta" aria-label="Fleet summary metadata">
                <div class="meta-item"><strong>Hosts Audited:</strong> <span class="meta-pill">{{.HostCount}}</span></div>
                <div class="meta-item"><strong>Total Findings:</strong> <span class="meta-pill">{{.TotalFindings}}</span></div>
                <div class="meta-item"><strong>Distinct Rules Triggered:</strong> <span class="meta-pill">{{.DistinctRulesCount}}</span></div>
                <div class="meta-item"><strong>Hosts with Critical Risk:</strong> <span class="meta-pill">{{.HostsWithCrit}}</span></div>
            </section>

            <section class="metrics-grid" aria-label="Fleet severity breakdown">
                <button type="button" class="metric-card card-crit" id="metric-crit" onclick="toggleSeverityFilter('CRITICAL')">
                    <span class="metric-label">Critical</span>
                    <span class="metric-num">{{.CritCount}}</span>
                    <span class="metric-hint">Click to filter</span>
                </button>
                <button type="button" class="metric-card card-high" id="metric-high" onclick="toggleSeverityFilter('HIGH')">
                    <span class="metric-label">High</span>
                    <span class="metric-num">{{.HighCount}}</span>
                    <span class="metric-hint">Click to filter</span>
                </button>
                <button type="button" class="metric-card card-med" id="metric-med" onclick="toggleSeverityFilter('MEDIUM')">
                    <span class="metric-label">Medium</span>
                    <span class="metric-num">{{.MedCount}}</span>
                    <span class="metric-hint">Click to filter</span>
                </button>
                <button type="button" class="metric-card card-low" id="metric-low" onclick="toggleSeverityFilter('LOW')">
                    <span class="metric-label">Low</span>
                    <span class="metric-num">{{.LowCount}}</span>
                    <span class="metric-hint">Click to filter</span>
                </button>
                <button type="button" class="metric-card card-info" id="metric-info" onclick="toggleSeverityFilter('INFO')">
                    <span class="metric-label">Info</span>
                    <span class="metric-num">{{.InfoCount}}</span>
                    <span class="metric-hint">Click to filter</span>
                </button>
            </section>

            <div class="severity-distribution" aria-hidden="true">
                <div class="sev-seg-crit"></div>
                <div class="sev-seg-high"></div>
                <div class="sev-seg-med"></div>
                <div class="sev-seg-low"></div>
                <div class="sev-seg-info"></div>
            </div>

            <section class="controls-panel" aria-label="Fleet table filters">
                <input type="text" class="search-input" id="fleetSearchInput" aria-label="Search hosts or rules" placeholder="Filter by hostname, rule ID, title, sudo version, or source file..." oninput="applyFleetFilters()">
                <div class="filter-buttons">
                    <button type="button" class="filter-btn active" id="btn-sev-ALL" onclick="setSeverityFilter('ALL')">All Severities</button>
                    <button type="button" class="filter-btn" id="btn-sev-CRITICAL" onclick="setSeverityFilter('CRITICAL')">Critical</button>
                    <button type="button" class="filter-btn" id="btn-sev-HIGH" onclick="setSeverityFilter('HIGH')">High</button>
                    <button type="button" class="filter-btn" id="btn-sev-MEDIUM" onclick="setSeverityFilter('MEDIUM')">Medium</button>
                    <button type="button" class="filter-btn" id="btn-sev-LOW" onclick="setSeverityFilter('LOW')">Low</button>
                    <button type="button" class="filter-btn" id="btn-sev-INFO" onclick="setSeverityFilter('INFO')">Info</button>
                </div>
            </section>

            <section class="panel-section" aria-labelledby="hosts-heading">
                <div class="panel-header">
                    <div>
                        <h2 id="hosts-heading">Host Risk Ranking</h2>
                        <p class="panel-subtitle">Ordered by Critical, High, Medium, Low, and Total findings</p>
                    </div>
                    <span class="meta-pill" id="visibleHostsCount">{{len .Hosts}} hosts</span>
                </div>
                {{if .Hosts}}
                <div class="table-wrap">
                    <table id="hostsTable">
                        <thead>
                            <tr>
                                <th>#</th>
                                <th>Hostname</th>
                                <th>Sudo Version</th>
                                <th class="num-col">Critical</th>
                                <th class="num-col">High</th>
                                <th class="num-col">Medium</th>
                                <th class="num-col">Low</th>
                                <th class="num-col">Info</th>
                                <th class="num-col">Total</th>
                                <th>Highest Severity</th>
                                <th>Source File</th>
                            </tr>
                        </thead>
                        <tbody>
                            {{range .Hosts}}
                            <tr class="host-row" data-highest="{{.Highest}}" data-crit="{{.Critical}}" data-high="{{.High}}" data-med="{{.Medium}}" data-low="{{.Low}}" data-info="{{.Info}}">
                                <td class="num-col">{{.Rank}}</td>
                                <td class="code-cell"><strong>{{.Hostname}}</strong></td>
                                <td class="code-cell">{{.SudoVersion}}</td>
                                <td class="num-col">{{.Critical}}</td>
                                <td class="num-col">{{.High}}</td>
                                <td class="num-col">{{.Medium}}</td>
                                <td class="num-col">{{.Low}}</td>
                                <td class="num-col">{{.Info}}</td>
                                <td class="num-col"><strong>{{.Total}}</strong></td>
                                <td><span class="sev-badge {{.BadgeClass}}">{{.Highest}}</span></td>
                                <td class="code-cell">{{.SourceFile}}</td>
                            </tr>
                            {{end}}
                        </tbody>
                    </table>
                </div>
                {{else}}
                <p class="empty-state">No host reports were included in this fleet summary.</p>
                {{end}}
            </section>

            <section class="panel-section" aria-labelledby="rules-heading">
                <div class="panel-header">
                    <div>
                        <h2 id="rules-heading">Rule Prevalence Across Fleet</h2>
                        <p class="panel-subtitle">Ordered by highest severity, affected host count, total occurrences, and rule ID</p>
                    </div>
                    <span class="meta-pill" id="visibleRulesCount">{{len .Rules}} rules</span>
                </div>
                {{if .Rules}}
                <div class="table-wrap">
                    <table id="rulesTable">
                        <thead>
                            <tr>
                                <th>Rule ID</th>
                                <th>Title</th>
                                <th>Severity</th>
                                <th class="num-col">Hosts Affected</th>
                                <th class="num-col">Total Occurrences</th>
                                <th>Affected Hosts</th>
                            </tr>
                        </thead>
                        <tbody>
                            {{range .Rules}}
                            <tr class="rule-row" data-severity="{{.Severity}}">
                                <td class="code-cell"><strong>{{.RuleID}}</strong></td>
                                <td>{{.Title}}</td>
                                <td><span class="sev-badge {{.BadgeClass}}">{{.Severity}}</span></td>
                                <td class="num-col">{{.HostCount}}</td>
                                <td class="num-col">{{.TotalCount}}</td>
                                <td>
                                    <div class="host-pills">
                                        {{range .AffectedHosts}}
                                        <span class="host-pill">{{.}}</span>
                                        {{end}}
                                    </div>
                                </td>
                            </tr>
                            {{end}}
                        </tbody>
                    </table>
                </div>
                {{else}}
                <p class="empty-state">No audit findings were reported across the audited hosts.</p>
                {{end}}
            </section>
        </main>
    </div>

    <script>
        var currentSevFilter = 'ALL';

        function toggleTheme() {
            var html = document.documentElement;
            var current = html.getAttribute('data-theme');
            var isDark = current === 'dark' || (!current && window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches);
            var next = isDark ? 'light' : 'dark';
            html.setAttribute('data-theme', next);
            try {
                localStorage.setItem('sudo-check-theme', next);
            } catch (e) {}
        }

        if (window.matchMedia) {
            var colorSchemeMQ = window.matchMedia('(prefers-color-scheme: dark)');
            var onSchemeChange = function(e) {
                try {
                    var saved = localStorage.getItem('sudo-check-theme');
                    if (saved === 'light' || saved === 'dark') return;
                } catch (err) {}
                document.documentElement.setAttribute('data-theme', e.matches ? 'dark' : 'light');
            };
            if (typeof colorSchemeMQ.addEventListener === 'function') {
                colorSchemeMQ.addEventListener('change', onSchemeChange);
            }
        }

        function toggleSeverityFilter(sev) {
            setSeverityFilter(currentSevFilter === sev ? 'ALL' : sev);
        }

        function setSeverityFilter(sev) {
            currentSevFilter = sev;
            var btnIds = ['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
            for (var i = 0; i < btnIds.length; i++) {
                var id = btnIds[i];
                var btn = document.getElementById('btn-sev-' + id);
                if (btn) {
                    btn.classList.toggle('active', id === sev);
                }
            }
            var metricMap = {
                'CRITICAL': 'metric-crit',
                'HIGH': 'metric-high',
                'MEDIUM': 'metric-med',
                'LOW': 'metric-low',
                'INFO': 'metric-info'
            };
            Object.keys(metricMap).forEach(function(k) {
                var el = document.getElementById(metricMap[k]);
                if (el) {
                    el.classList.toggle('active-metric', k === sev);
                }
            });
            applyFleetFilters();
        }

        function hostMatchesSeverity(row, sev) {
            if (sev === 'ALL') return true;
            var attrMap = {
                'CRITICAL': 'data-crit',
                'HIGH': 'data-high',
                'MEDIUM': 'data-med',
                'LOW': 'data-low',
                'INFO': 'data-info'
            };
            var attr = attrMap[sev];
            if (!attr) return true;
            return parseInt(row.getAttribute(attr) || '0', 10) > 0;
        }

        function applyFleetFilters() {
            var input = document.getElementById('fleetSearchInput');
            var query = input ? input.value.trim().toLowerCase() : '';

            var hostRows = document.querySelectorAll('.host-row');
            var visHosts = 0;
            hostRows.forEach(function(row) {
                var text = (row.textContent || '').toLowerCase();
                var ok = (query === '' || text.indexOf(query) !== -1) && hostMatchesSeverity(row, currentSevFilter);
                row.style.display = ok ? '' : 'none';
                if (ok) visHosts++;
            });
            var vhEl = document.getElementById('visibleHostsCount');
            if (vhEl) vhEl.textContent = visHosts + (visHosts === 1 ? ' host' : ' hosts');

            var ruleRows = document.querySelectorAll('.rule-row');
            var visRules = 0;
            ruleRows.forEach(function(row) {
                var text = (row.textContent || '').toLowerCase();
                var sev = row.getAttribute('data-severity') || '';
                var ok = (query === '' || text.indexOf(query) !== -1) && (currentSevFilter === 'ALL' || sev === currentSevFilter);
                row.style.display = ok ? '' : 'none';
                if (ok) visRules++;
            });
            var vrEl = document.getElementById('visibleRulesCount');
            if (vrEl) vrEl.textContent = visRules + (visRules === 1 ? ' rule' : ' rules');
        }
    </script>
</body>
</html>
`

var fleetHTMLTmpl = template.Must(template.New("fleetReport").Parse(fleetHTMLTemplateStr))

// WriteFleetHTML renders a self-contained, offline-safe HTML fleet summary report.
func WriteFleetHTML(summary *FleetSummary, w io.Writer) error {
	if summary == nil {
		return fmt.Errorf("fleet summary is nil")
	}
	if w == nil {
		return fmt.Errorf("output writer is nil")
	}

	data := buildFleetHTMLData(summary)
	return fleetHTMLTmpl.Execute(w, &data)
}
