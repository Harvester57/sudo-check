package parser

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sudo-check/pkg/audit"
	"sudo-check/pkg/gtfobins"
	"testing"
)

func TestRealWorldCorpusDifferentialAndStress(t *testing.T) {
	gtfoClient, err := gtfobins.NewClient()
	if err != nil {
		t.Fatalf("Failed to initialize GTFObins client: %v", err)
	}

	corpusRoot := filepath.Join("..", "..", "testdata", "corpus")
	categories := []string{"distros", "upstream_regress", "enterprise_cloud"}

	for _, cat := range categories {
		catDir := filepath.Join(corpusRoot, cat)
		entries, err := os.ReadDir(catDir)
		if err != nil {
			t.Fatalf("Failed to read corpus category %s: %v", cat, err)
		}
		if len(entries) == 0 {
			t.Fatalf("Expected non-empty corpus category %s", cat)
		}

		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sudoers") {
				continue
			}
			filePath := filepath.Join(catDir, entry.Name())
			testName := cat + "/" + entry.Name()

			t.Run(testName, func(t *testing.T) {
				rawBytes, err := os.ReadFile(filePath)
				if err != nil {
					t.Fatalf("Failed to read %s: %v", filePath, err)
				}
				content := string(rawBytes)

				// Strip @include / #include / @includedir / #includedir directives when comparing stdin
				// against cvtsudoers so missing host paths like /etc/sudoers.d inside WSL don't skew comparison.
				stdinContent := stripIncludeDirectivesForStdinOracle(content)

				nativePolicy, err := ParseString(stdinContent)
				if err != nil {
					t.Fatalf("Native ParseString failed on %s: %v", testName, err)
				}

				// Run full audit on nativePolicy to verify no panics and valid findings
				nativeFindings := stripFindingLines(audit.RunAudit(nativePolicy, gtfoClient))

				// Also parse via ParseFile (which handles @includedir gracefully)
				filePolicy, err := ParseFile(filePath)
				if err != nil {
					t.Fatalf("Native ParseFile failed on %s: %v", testName, err)
				}
				_ = audit.RunAudit(filePolicy, gtfoClient)

				// Upstream sudo 1.9.16+ tests (test24 quoted CHROOT/CWD and test31 SELinux/AppArmor/Solaris privs)
				// trigger an upstream cvtsudoers <= 1.9.15p5 JSON formatting bug (`"Options": [ "runchroot": ... ]`
				// without object braces, fixed in sudo 1.9.16 cvtsudoers_json.c). Verify their ASTs directly.
				if entry.Name() == "sudoers_test24.sudoers" {
					verifyTest24AST(t, nativePolicy)
					return
				}
				if entry.Name() == "sudoers_test31.sudoers" {
					verifyTest31AST(t, nativePolicy)
					return
				}

				// In sudo 1.9.16+, test26 includes `Defaults cmddenial_message="That's not allowed!"` which
				// cvtsudoers <= 1.9.15p5 does not recognize. Strip that single line for the oracle if needed.
				oracleInput := stdinContent
				oracleNativePolicy := nativePolicy
				if entry.Name() == "sudoers_test26.sudoers" {
					oracleInput = strings.ReplaceAll(stdinContent, "Defaults cmddenial_message=\"That's not allowed!\"", "# Defaults cmddenial_message")
					var err error
					oracleNativePolicy, err = ParseString(oracleInput)
					if err != nil {
						t.Fatalf("ParseString failed on filtered test26: %v", err)
					}
				}

				// Compare against cvtsudoers oracle if available
				cvtPolicy := runCvtsudoersOracle(t, oracleInput)
				normCvt := normalizePolicyViaJSON(t, cvtPolicy)
				normNative := normalizePolicyViaJSON(t, oracleNativePolicy)

				if !reflect.DeepEqual(normNative, normCvt) {
					cvtJSON, _ := json.MarshalIndent(normCvt, "", "  ")
					natJSON, _ := json.MarshalIndent(normNative, "", "  ")
					t.Errorf("AST mismatch on %s:\n--- Native ---\n%s\n--- cvtsudoers ---\n%s", testName, string(natJSON), string(cvtJSON))
				}

				cvtFindings := stripFindingLines(audit.RunAudit(cvtPolicy, gtfoClient))
				oracleNativeFindings := stripFindingLines(audit.RunAudit(oracleNativePolicy, gtfoClient))
				if !reflect.DeepEqual(oracleNativeFindings, cvtFindings) {
					t.Errorf("Audit findings mismatch on %s:\n--- Native (%d) ---\n%+v\n--- cvtsudoers (%d) ---\n%+v",
						testName, len(nativeFindings), oracleNativeFindings, len(cvtFindings), cvtFindings)
				}
			})
		}
	}
}

func TestInvalidUpstreamCorpus(t *testing.T) {
	invalidDir := filepath.Join("..", "..", "testdata", "corpus", "upstream_regress_invalid")
	entries, err := os.ReadDir(invalidDir)
	if err != nil {
		t.Fatalf("Failed to read upstream_regress_invalid: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("Expected non-empty upstream_regress_invalid corpus directory")
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sudoers") {
			continue
		}
		filePath := filepath.Join(invalidDir, entry.Name())
		t.Run(entry.Name(), func(t *testing.T) {
			rawBytes, err := os.ReadFile(filePath)
			if err != nil {
				t.Fatalf("Failed to read %s: %v", filePath, err)
			}
			if _, err := ParseString(string(rawBytes)); err == nil {
				t.Errorf("Expected ParseString syntax error on invalid corpus file %s, but got nil", entry.Name())
			}
			if _, err := ParseFile(filePath); err == nil {
				t.Errorf("Expected ParseFile syntax error on invalid corpus file %s, but got nil", entry.Name())
			}
		})
	}
}

func verifyTest24AST(t *testing.T, p *audit.SudoersPolicy) {
	t.Helper()
	if len(p.Defaults) != 4 || len(p.UserSpecs) != 4 {
		t.Fatalf("Unexpected counts in test24: defaults=%d userspecs=%d", len(p.Defaults), len(p.UserSpecs))
	}
	// user0 and user1 both set runchroot=/var/www and runcwd=/htdocs on /bin/ksh
	for _, idx := range []int{0, 1} {
		opts := p.UserSpecs[idx].CmndSpecs[0].Options
		want := []audit.Option{{"runchroot": "/var/www"}, {"runcwd": "/htdocs"}}
		if !reflect.DeepEqual(opts, want) {
			t.Errorf("test24 UserSpecs[%d] options = %+v, want %+v", idx, opts, want)
		}
	}
	// user2 and user3 have two CmndSpecs because CWD changes from ~root to /tmp
	for _, idx := range []int{2, 3} {
		if len(p.UserSpecs[idx].CmndSpecs) != 2 {
			t.Fatalf("test24 UserSpecs[%d] CmndSpecs len = %d, want 2", idx, len(p.UserSpecs[idx].CmndSpecs))
		}
	}
}

func verifyTest31AST(t *testing.T, p *audit.SudoersPolicy) {
	t.Helper()
	if len(p.UserSpecs) != 3 {
		t.Fatalf("Expected 3 UserSpecs in test31, got %d", len(p.UserSpecs))
	}
	// user1: ROLE=foo_r TYPE=bar_t ALL -> setenv: true, role: foo_r, type: bar_t
	want0 := []audit.Option{{"setenv": true}, {"role": "foo_r"}, {"type": "bar_t"}}
	if !reflect.DeepEqual(p.UserSpecs[0].CmndSpecs[0].Options, want0) {
		t.Errorf("test31 user1 options = %+v, want %+v", p.UserSpecs[0].CmndSpecs[0].Options, want0)
	}
	// user2: APPARMOR_PROFILE=usr.bin.tcpdump /usr/bin/tcpdump
	want1 := []audit.Option{{"apparmor_profile": "usr.bin.tcpdump"}}
	if !reflect.DeepEqual(p.UserSpecs[1].CmndSpecs[0].Options, want1) {
		t.Errorf("test31 user2 options = %+v, want %+v", p.UserSpecs[1].CmndSpecs[0].Options, want1)
	}
	// user3: PRIVS="..." LIMITPRIVS=default ALL -> setenv: true, privs: "...", limitprivs: "default"
	want2 := []audit.Option{
		{"setenv": true},
		{"privs": "file_link_any,net_access,proc_exec,proc_fork,proc_info,proc_session"},
		{"limitprivs": "default"},
	}
	if !reflect.DeepEqual(p.UserSpecs[2].CmndSpecs[0].Options, want2) {
		t.Errorf("test31 user3 options = %+v, want %+v", p.UserSpecs[2].CmndSpecs[0].Options, want2)
	}
}

func stripIncludeDirectivesForStdinOracle(s string) string {
	lines := strings.Split(s, "\n")
	var out []string
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isIncludePrefix(trimmed) {
			out = append(out, "# "+line)
			continue
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n")
}
