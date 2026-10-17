package report

import (
	"encoding/json"
	"io"
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
	RuleID    string               `json:"ruleId"`
	Message   SarifMultiformatText `json:"message"`
	Level     string               `json:"level"` // "error", "warning", "note", "none"
	Locations []SarifLocation      `json:"locations,omitempty"`
}

type SarifLocation struct {
	PhysicalLocation SarifPhysicalLocation `json:"physicalLocation"`
}

type SarifPhysicalLocation struct {
	ArtifactLocation SarifArtifactLocation `json:"artifactLocation"`
	Region           *SarifRegion          `json:"region,omitempty"`
}

type SarifRegion struct {
	StartLine int `json:"startLine,omitempty"`
}

type SarifArtifactLocation struct {
	URI string `json:"uri"`
}

// canonicalRuleTitles maps rule IDs that can have dynamic or variant per-finding titles
// to a stable, canonical rule description for the SARIF driver.rules table.
var canonicalRuleTitles = map[string]string{
	"SUDO-GTFO-001": "Permitted Binary in GTFObins Catalog",
	"SUDO-GTFO-002": "Passwordless Permitted Binary in GTFObins Catalog",
	"SUDO-GTFO-003": "Mitigated Permitted Binary in GTFObins Catalog",
	"SUDO-DEF-001":  "Missing or Empty secure_path Configuration",
	"SUDO-DEF-009":  "Missing or Weak umask Configuration",
}

func canonicalRuleTitle(f audit.Finding) string {
	if title, ok := canonicalRuleTitles[f.ID]; ok {
		return title
	}
	return f.Title
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
		InformationURI: "https://github.com/Harvester57/sudo-audit",
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

	results := []SarifResult{}
	ruleMap := make(map[string]bool)

	addFindings := func(findings []audit.Finding, defaultURI string, category string) {
		for _, f := range findings {
			// Add rule metadata if not already present
			if !ruleMap[f.ID] {
				props := &SarifRuleProperties{
					SecuritySeverity: mapSecuritySeverity(f.Severity),
				}
				if len(f.Compliance) > 0 {
					tags := make([]string, len(f.Compliance))
					copy(tags, f.Compliance)
					props.Tags = tags
				}

				driver.Rules = append(driver.Rules, SarifRule{
					ID: f.ID,
					ShortDescription: SarifMultiformatText{
						Text: canonicalRuleTitle(f),
					},
					Properties: props,
				})
				ruleMap[f.ID] = true
			}

			uri := defaultURI
			if f.Context != "" {
				uri = f.Context
			}

			physLoc := SarifPhysicalLocation{
				ArtifactLocation: SarifArtifactLocation{
					URI: uri,
				},
			}
			if f.Line > 0 {
				physLoc.Region = &SarifRegion{
					StartLine: f.Line,
				}
			}

			cleanRem, effectiveRemCode, _, _ := resolveFindingRemediationAndExploit(f, category)
			msgText := f.Description + "\nRemediation: " + cleanRem
			if effectiveRemCode != "" {
				msgText += "\nExample Fix:\n" + effectiveRemCode
			}

			results = append(results, SarifResult{
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
			})
		}
	}

	addFindings(result.SystemFindings, "system-configuration", "SYSTEM")
	addFindings(result.PolicyFindings, "file:///etc/sudoers", "POLICY")

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
