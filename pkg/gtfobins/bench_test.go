package gtfobins

import "testing"

// BenchmarkCheckBinary measures GTFObins lookup throughput across the
// lookup paths exercised by the auditor: exact hits, versioned variants,
// alias/inherit chains, and misses. Run with:
//
//	go test -bench=BenchmarkCheckBinary -benchmem -run=^$ ./pkg/gtfobins
func BenchmarkCheckBinary(b *testing.B) {
	client, err := NewClient()
	if err != nil {
		b.Fatalf("failed to initialize client: %v", err)
	}

	benchmarks := []struct {
		name   string
		binary string
	}{
		{"ExactHit_Vim", "vim"},
		{"ExactHit_Find", "find"},
		{"VersionedVariant_Python311", "python3.11"},
		{"Variant_VimTiny", "vim.tiny"},
		{"AliasChain_Mawk", "mawk"},
		{"InheritChain_Rview", "rview"},
		{"Miss", "non-existent-binary-xyz"},
	}

	for _, bm := range benchmarks {
		b.Run(bm.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				client.CheckBinary(bm.binary)
			}
		})
	}
}
