package report

import (
	"encoding/json"
	"io"
	"sudo-check/pkg/audit"
)

// WriteJSONReport serializes the audit results as pretty-printed JSON.
// It ensures PolicyFindings and SystemFindings are non-nil slices sorted by severity.
func WriteJSONReport(result *audit.AuditResult, w io.Writer) error {
	out := audit.AuditResult{
		PolicyFindings: make([]audit.Finding, len(result.PolicyFindings)),
		SystemFindings: make([]audit.Finding, len(result.SystemFindings)),
		SudoVersion:    result.SudoVersion,
		Hostname:       result.Hostname,
	}
	copy(out.PolicyFindings, result.PolicyFindings)
	copy(out.SystemFindings, result.SystemFindings)
	audit.SortFindingsBySeverity(out.PolicyFindings)
	audit.SortFindingsBySeverity(out.SystemFindings)

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(out)
}
