package report

import (
	"bytes"
	"flag"
	"io"
	"os"
	"path/filepath"
	"testing"

	"sudo-check/internal/buildinfo"
	"sudo-check/pkg/audit"
)

var update = flag.Bool("update", false, "update golden report files")

// TestGoldenReports renders the shared dummy audit result through every
// deterministic report writer and compares the output byte-for-byte against
// the golden files in testdata/golden. Regenerate after intentional format
// changes with:
//
//	go test ./pkg/report -update
//
// The PDF writer is excluded because it embeds the current timestamp.
func TestGoldenReports(t *testing.T) {
	// Pin buildinfo so the SARIF driver version is deterministic.
	origV, origC, origD := buildinfo.Version, buildinfo.Commit, buildinfo.Date
	buildinfo.Set("v0.0.0-golden", "golden", "2026-01-01")
	t.Cleanup(func() { buildinfo.Set(origV, origC, origD) })

	result := createDummyResult()

	writers := []struct {
		name  string
		write func(*audit.AuditResult, io.Writer) error
	}{
		{"text", func(r *audit.AuditResult, w io.Writer) error {
			return WriteTextReportWithOptions(r, w, false)
		}},
		{"json", WriteJSONReport},
		{"sarif", WriteSarifReport},
		{"html", WriteHTMLReport},
	}

	for _, w := range writers {
		t.Run(w.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := w.write(result, &buf); err != nil {
				t.Fatalf("render %s report failed: %v", w.name, err)
			}

			goldenPath := filepath.Join("testdata", "golden", w.name+".golden")
			if *update {
				if err := os.MkdirAll(filepath.Dir(goldenPath), 0755); err != nil {
					t.Fatalf("failed to create golden directory: %v", err)
				}
				if err := os.WriteFile(goldenPath, buf.Bytes(), 0644); err != nil {
					t.Fatalf("failed to write golden file: %v", err)
				}
				return
			}

			want, err := os.ReadFile(goldenPath)
			if err != nil {
				t.Fatalf("failed to read golden file (run 'go test ./pkg/report -update' to generate it): %v", err)
			}
			if !bytes.Equal(buf.Bytes(), want) {
				at := firstDiffIndex(want, buf.Bytes())
				t.Errorf("%s report output differs from golden at byte %d (got %d bytes, want %d bytes).\n"+
					"Run 'go test ./pkg/report -update' if this format change is intentional.\n"+
					"--- got around difference ---\n%s\n--- want around difference ---\n%s",
					w.name, at, buf.Len(), len(want),
					snippetAround(buf.Bytes(), at), snippetAround(want, at))
			}
		})
	}
}

// firstDiffIndex returns the offset of the first differing byte, or the length
// of the shorter input if one is a prefix of the other.
func firstDiffIndex(a, b []byte) int {
	n := min(len(a), len(b))
	for i := 0; i < n; i++ {
		if a[i] != b[i] {
			return i
		}
	}
	return n
}

// snippetAround returns up to 160 bytes around the given offset, decoded lossily.
func snippetAround(b []byte, at int) string {
	start := max(at-80, 0)
	end := min(at+80, len(b))
	return string(b[start:end])
}
