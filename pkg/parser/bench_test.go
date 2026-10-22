package parser

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// BenchmarkParseString measures native parser throughput on representative
// real-world corpus files. Run with:
//
//	go test -bench=BenchmarkParseString -benchmem -run=^$ ./pkg/parser
func BenchmarkParseString(b *testing.B) {
	corpusRoot := filepath.Join("..", "..", "testdata", "corpus")
	benchmarks := []struct {
		name string
		path string
	}{
		{"Small_OracleRac", filepath.Join(corpusRoot, "enterprise_cloud", "20_oracle_rac_11g_12c_grid_infrastructure_produc.sudoers")},
		{"Medium_FreeBSD", filepath.Join(corpusRoot, "distros", "freebsd_sudoers.sudoers")},
		{"Large_Ubuntu", filepath.Join(corpusRoot, "distros", "ubuntu_sudoers.sudoers")},
	}

	for _, bm := range benchmarks {
		b.Run(bm.name, func(b *testing.B) {
			data, err := os.ReadFile(bm.path)
			if err != nil {
				b.Fatalf("failed to read %s: %v", bm.path, err)
			}
			content := stripIncludeDirectivesForStdinOracle(string(data))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := ParseString(content); err != nil {
					b.Fatalf("ParseString failed: %v", err)
				}
			}
		})
	}
}

// BenchmarkParseStringSynthetic stresses the parser with generated input of
// increasing size to expose super-linear behavior.
func BenchmarkParseStringSynthetic(b *testing.B) {
	sizes := []int{100, 1000, 10000}
	for _, size := range sizes {
		b.Run("Lines="+strconv.Itoa(size), func(b *testing.B) {
			var sb strings.Builder
			for i := 0; i < size; i++ {
				sb.WriteString("Defaults env_reset, use_pty, secure_path=\"/usr/sbin:/usr/bin\"\n")
				sb.WriteString("user" + strconv.Itoa(i) + " ALL = (root) NOPASSWD: /usr/bin/cmd" + strconv.Itoa(i) + " \"\"\n")
			}
			content := sb.String()
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := ParseString(content); err != nil {
					b.Fatalf("ParseString failed: %v", err)
				}
			}
		})
	}
}
