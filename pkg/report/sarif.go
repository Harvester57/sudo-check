package report

import (
	"encoding/json"
	"io"
	"slices"
	"strings"
	"sudo-check/internal/buildinfo"
	"sudo-check/pkg/audit"
)

// SarifLog represents the root of a SARIF log file
type SarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []SarifRun `json:"runs"`
}

type SarifRun struct {
	Tool    SarifTool     `json:"tool"`
	Results []SarifResult `json:"results"`
}

type SarifTool struct {
	Driver SarifDriver `json:"driver"`
}

type SarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version,omitempty"`
	InformationURI string      `json:"informationUri,omitempty"`
	Rules          []SarifRule `json:"rules"`
}

type SarifRule struct {
	ID               string               `json:"id"`
	ShortDescription SarifMultiformatText `json:"shortDescription"`
	Properties       *SarifRuleProperties `json:"properties,omitempty"`
}

type SarifRuleProperties struct {
	SecuritySeverity string   `json:"security-severity,omitempty"`
	Tags             []string `json:"tags,omitempty"`
}

type SarifMultiformatText struct {
	Text string `json:"text"`
}

type SarifResult struct {
	RuleID              string                 `json:"ruleId"`
	Message             SarifMultiformatText   `json:"message"`
	Level               string                 `json:"level"` // "error", "warning", "note", "none"
	Locations           []SarifLocation        `json:"locations,omitempty"`
	PartialFingerprints map[string]string      `json:"partialFingerprints,omitempty"`
	Properties          *SarifResultProperties `json:"properties,omitempty"`
}

type SarifResultProperties struct {
	Tags              string `json:"tags,omitempty"`
	InheritedDefaults string `json:"inheritedDefaults,omitempty"`
	Exploitability    string `json:"exploitability,omitempty"`
}

type SarifLocation struct {
	PhysicalLocation SarifPhysicalLocation `json:"physicalLocation"`
}

type SarifPhysicalLocation struct {
	ArtifactLocation SarifArtifactLocation `json:"artifactLocation"`
	Region           *SarifRegion          `json:"region,omitempty"`
}

type SarifArtifactContent struct {
	Text string `json:"text,omitempty"`
}

type SarifRegion struct {
	StartLine int                   `json:"startLine,omitempty"`
	Snippet   *SarifArtifactContent `json:"snippet,omitempty"`
}

type SarifArtifactLocation struct {
	URI string `json:"uri"`
}

func canonicalRuleTitle(f audit.Finding) string {
	return audit.CanonicalRuleTitle(f.ID, f.Title)
}

func isWindowsDrivePath(p string) bool {
	if len(p) < 3 {
		return false
	}
	c := p[0]
	isAlpha := (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
	return isAlpha && p[1] == ':' && p[2] == '/'
}

func normalizeSarifURI(raw string, defaultURI string) string {
	uri := strings.TrimSpace(raw)
	if uri == "" {
		uri = defaultURI
	}
	uri = strings.ReplaceAll(uri, "\\", "/")
	if strings.HasPrefix(uri, "file:///") {
		rest := strings.TrimPrefix(uri, "file:///")
		if isWindowsDrivePath(rest) {
			return "file:///" + rest
		}
		rest = strings.TrimLeft(rest, "/")
		if rest == "" {
			return defaultURI
		}
		return rest
	}
	if isWindowsDrivePath(uri) {
		return "file:///" + uri
	}
	uri = strings.TrimLeft(uri, "/")
	for strings.HasPrefix(uri, "./") {
		uri = strings.TrimPrefix(uri, "./")
	}
	if uri == "" {
		return defaultURI
	}
	return uri
}

func mapSecuritySeverity(sev audit.Severity) string {
	switch sev {
	case audit.SeverityCritical:
		return "9.0"
	case audit.SeverityHigh:
		return "7.5"
	case audit.SeverityMedium:
		return "5.0"
	case audit.SeverityLow:
		return "2.5"
	case audit.SeverityInfo:
		return "1.0"
	default:
		return "1.0"
	}
}

// WriteSarifReport formats the audit results as a SARIF JSON report.
func WriteSarifReport(result *audit.AuditResult, w io.Writer) error {
	log := SarifLog{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
	}

	driver := SarifDriver{
		Name:           "sudo-check",
		Version:        buildinfo.Version,
		InformationURI: "https://github.com/Harvester57/sudo-check",
		Rules:          []SarifRule{},
	}

	// Helper to map audit severity to SARIF levels
	mapLevel := func(sev audit.Severity) string {
		switch sev {
		case audit.SeverityCritical, audit.SeverityHigh:
			return "error"
		case audit.SeverityMedium, audit.SeverityLow:
			return "warning"
		case audit.SeverityInfo:
			return "note"
		default:
			return "none"
		}
	}

	sysCopy := make([]audit.Finding, len(result.SystemFindings))
	copy(sysCopy, result.SystemFindings)
	audit.SortFindingsBySeverity(sysCopy)

	polCopy := make([]audit.Finding, len(result.PolicyFindings))
	copy(polCopy, result.PolicyFindings)
	audit.SortFindingsBySeverity(polCopy)

	results := []SarifResult{}
	ruleIdxByID := make(map[string]int)
	ruleBestSev := make(map[string]audit.Severity)
	ruleTagSet := make(map[string]map[string]struct{})

	addFindings := func(findings []audit.Finding, defaultURI string, category string) {
		for _, f := range findings {
			// Add or update rule metadata, preserving the highest severity and merging unique tags
			if idx, exists := ruleIdxByID[f.ID]; !exists {
				props := &SarifRuleProperties{
					SecuritySeverity: mapSecuritySeverity(f.Severity),
				}
				driver.Rules = append(driver.Rules, SarifRule{
					ID: f.ID,
					ShortDescription: SarifMultiformatText{
						Text: canonicalRuleTitle(f),
					},
					Properties: props,
				})
				ruleIdxByID[f.ID] = len(driver.Rules) - 1
				ruleBestSev[f.ID] = f.Severity
				ruleTagSet[f.ID] = make(map[string]struct{})
			} else if f.Severity.Order() < ruleBestSev[f.ID].Order() {
				ruleBestSev[f.ID] = f.Severity
				driver.Rules[idx].Properties.SecuritySeverity = mapSecuritySeverity(f.Severity)
			}

			for _, tag := range f.Compliance {
				if trimmed := strings.TrimSpace(tag); trimmed != "" {
					ruleTagSet[f.ID][trimmed] = struct{}{}
				}
			}

			uri := normalizeSarifURI(f.Context, defaultURI)

			physLoc := SarifPhysicalLocation{
				ArtifactLocation: SarifArtifactLocation{
					URI: uri,
				},
			}
			srcLine := strings.TrimSpace(f.SourceLine)
			if f.Line > 0 || srcLine != "" {
				reg := &SarifRegion{
					StartLine: f.Line,
				}
				if srcLine != "" {
					reg.Snippet = &SarifArtifactContent{Text: srcLine}
				}
				physLoc.Region = reg
			}

			cleanRem, effectiveRemCode, _, _ := resolveFindingRemediationAndExploit(f, category)
			msgText := f.Description + "\nRemediation: " + cleanRem
			if effectiveRemCode != "" {
				msgText += "\nExample Fix:\n" + effectiveRemCode
			}

			res := SarifResult{
				RuleID: f.ID,
				Message: SarifMultiformatText{
					Text: msgText,
				},
				Level: mapLevel(f.Severity),
				Locations: []SarifLocation{
					{
						PhysicalLocation: physLoc,
					},
				},
			}
			if f.Fingerprint != "" {
				res.PartialFingerprints = map[string]string{
					"sudoCheckFingerprint/v1": f.Fingerprint,
				}
			}
			tags := strings.TrimSpace(f.Tags)
			inherited := strings.TrimSpace(f.InheritedDefaults)
			exploitability := strings.TrimSpace(f.Exploitability)
			if tags != "" || inherited != "" || exploitability != "" {
				res.Properties = &SarifResultProperties{
					Tags:              tags,
					InheritedDefaults: inherited,
					Exploitability:    exploitability,
				}
			}
			results = append(results, res)
		}
	}

	addFindings(sysCopy, "system-configuration", "SYSTEM")
	addFindings(polCopy, "etc/sudoers", "POLICY")

	for i := range driver.Rules {
		tagMap := ruleTagSet[driver.Rules[i].ID]
		if len(tagMap) > 0 {
			tags := make([]string, 0, len(tagMap))
			for tag := range tagMap {
				tags = append(tags, tag)
			}
			slices.Sort(tags)
			driver.Rules[i].Properties.Tags = tags
		}
	}
	slices.SortFunc(driver.Rules, func(a, b SarifRule) int {
		return strings.Compare(a.ID, b.ID)
	})

	run := SarifRun{
		Tool: SarifTool{
			Driver: driver,
		},
		Results: results,
	}

	log.Runs = []SarifRun{run}

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(log)
}
