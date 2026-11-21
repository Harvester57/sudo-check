package config

import (
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strings"

	"sudo-check/pkg/audit"
)

// DiffResult summarizes added, resolved, and unchanged findings between
// a baseline audit result and a current audit result.
type DiffResult struct {
	Added     []audit.Finding `json:"added"`
	Resolved  []audit.Finding `json:"resolved"`
	Unchanged []audit.Finding `json:"unchanged"`
}

// LoadBaselineResult reads a JSON-encoded audit.AuditResult file from path,
// populates any missing finding fingerprints, and returns the parsed result.
func LoadBaselineResult(path string) (*audit.AuditResult, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read baseline result %q: %w", path, err)
	}

	var result *audit.AuditResult
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("parse baseline result %q: %w", path, err)
	}
	if result == nil {
		return nil, fmt.Errorf("parse baseline result %q: baseline JSON is null", path)
	}

	audit.PopulateFingerprints(result.PolicyFindings)
	audit.PopulateFingerprints(result.SystemFindings)

	return result, nil
}

// DiffResults compares baseline and current audit results using fingerprint
// multiset counting so duplicate findings are tracked accurately.
func DiffResults(baseline, current *audit.AuditResult) *DiffResult {
	baseFindings := collectFindingsWithFingerprints(baseline)
	currFindings := collectFindingsWithFingerprints(current)

	remainingBase := make(map[string]int, len(baseFindings))
	for _, f := range baseFindings {
		remainingBase[f.Fingerprint]++
	}

	remainingCurr := make(map[string]int, len(currFindings))
	for _, f := range currFindings {
		remainingCurr[f.Fingerprint]++
	}

	diff := &DiffResult{
		Added:     make([]audit.Finding, 0),
		Resolved:  make([]audit.Finding, 0),
		Unchanged: make([]audit.Finding, 0),
	}

	for _, f := range currFindings {
		if remainingBase[f.Fingerprint] > 0 {
			remainingBase[f.Fingerprint]--
			diff.Unchanged = append(diff.Unchanged, f)
		} else {
			diff.Added = append(diff.Added, f)
		}
	}

	for _, f := range baseFindings {
		if remainingCurr[f.Fingerprint] > 0 {
			remainingCurr[f.Fingerprint]--
		} else {
			diff.Resolved = append(diff.Resolved, f)
		}
	}

	audit.SortFindingsBySeverity(diff.Added)
	audit.SortFindingsBySeverity(diff.Resolved)
	audit.SortFindingsBySeverity(diff.Unchanged)

	return diff
}

func collectFindingsWithFingerprints(res *audit.AuditResult) []audit.Finding {
	if res == nil {
		return nil
	}
	out := make([]audit.Finding, 0, len(res.SystemFindings)+len(res.PolicyFindings))
	for _, f := range res.SystemFindings {
		out = append(out, cloneWithFingerprint(f))
	}
	for _, f := range res.PolicyFindings {
		out = append(out, cloneWithFingerprint(f))
	}
	return out
}

func cloneWithFingerprint(f audit.Finding) audit.Finding {
	f.Compliance = slices.Clone(f.Compliance)
	if strings.TrimSpace(f.Fingerprint) == "" {
		f.Fingerprint = audit.ComputeFingerprint(f)
	}
	return f
}
