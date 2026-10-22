package audit_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sudo-check/pkg/audit"
	"sudo-check/pkg/gtfobins"
	"sudo-check/pkg/parser"
	"testing"
)

// FuzzParseSudoVersion checks that ParseSudoVersion and AuditSudoVersion handle
// arbitrary version strings without panicking, and that Compare behaves as a
// total order (reflexive and antisymmetric against the fixed CVE boundary
// versions) for every successfully parsed version.
//
// The seed corpus includes real-world `sudo --version` output shapes plus
// overflow and garbage inputs. Extended fuzzing runs with:
//
//	go test -fuzz=FuzzParseSudoVersion -fuzztime=5m ./pkg/audit
func FuzzParseSudoVersion(f *testing.F) {
	seeds := []string{
		"",
		"1.8.31p2",
		"1.9.15p5",
		"1.9.12",
		"1.8.7",
		"2.0.1",
		"Sudo version 1.8.31 (Debian 10)",
		"sudo 1.9.16p2-1ubuntu1",
		"1.8.30",
		"1.9.16.2",
		"1.7.1",
		"p5",
		"1.2",
		"abc",
		"99999999999999999999.99999999999999999999.99999999999999999999p99999999999999999999",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	// Fixed boundary versions used by the CVE range checks in AuditSudoVersion.
	boundaries := []audit.SudoVersion{
		{Major: 1, Minor: 8, Patch: 28},
		{Major: 1, Minor: 7, Patch: 1},
		{Major: 1, Minor: 8, Patch: 30, Pl: 99},
		{Major: 1, Minor: 9, Patch: 12},
		{Major: 1, Minor: 8, Patch: 7},
		{Major: 1, Minor: 9, Patch: 15, Pl: 5},
		{Major: 1, Minor: 9, Patch: 16, Pl: 2},
	}

	knownFindingIDs := map[string]bool{
		"SUDO-SYS-001":   true,
		"CVE-2019-14287": true,
		"CVE-2019-18634": true,
		"CVE-2021-3156":  true,
		"CVE-2022-43995": true,
		"CVE-2023-22809": true,
		"CVE-2023-27320": true,
		"CVE-2025-32462": true,
		"CVE-2025-32463": true,
	}

	f.Fuzz(func(t *testing.T, verStr string) {
		v, err := audit.ParseSudoVersion(verStr)
		if err != nil {
			return
		}

		if v.Compare(v) != 0 {
			t.Errorf("Compare is not reflexive for %q: %+v compared against itself", verStr, v)
		}
		for _, b := range boundaries {
			ab := v.Compare(b)
			ba := b.Compare(v)
			if (ab < 0 && ba <= 0) || (ab > 0 && ba >= 0) {
				t.Errorf("Compare is not antisymmetric for %q: v.Compare(b)=%d but b.Compare(v)=%d", verStr, ab, ba)
			}
		}

		findings, ferr := audit.AuditSudoVersion(verStr)
		if ferr != nil {
			t.Fatalf("AuditSudoVersion failed on parseable version %q: %v", verStr, ferr)
		}
		for _, fd := range findings {
			if !knownFindingIDs[fd.ID] {
				t.Errorf("AuditSudoVersion emitted unexpected finding ID %q for version %q", fd.ID, verStr)
			}
		}
	})
}

// FuzzAuditJSONPolicy checks that the cvtsudoers JSON policy ingestion path
// used by `scan` (json.Unmarshal into SudoersPolicy, then RunAudit) handles
// arbitrary JSON without panicking, and that any successfully unmarshaled
// policy survives a JSON marshal/unmarshal round trip idempotently
// (unmarshal(marshal(unmarshal(marshal(p)))) == unmarshal(marshal(p))).
//
// Unlike FuzzParseString in pkg/parser, which only sees policies produced by
// the native sudoers parser, this target exercises JSON-origin policies with
// hostile shapes the parser never emits: duplicate digest keys, single-string
// vs array DigestList values, nil pointer members, and malformed Options.
//
// The seed corpus includes hand-written schema edge cases plus every valid
// file of the real-world corpus in testdata/corpus marshaled through the
// native parser. Extended fuzzing runs with:
//
//	go test -fuzz=FuzzAuditJSONPolicy -fuzztime=5m ./pkg/audit
func FuzzAuditJSONPolicy(f *testing.F) {
	seeds := []string{
		"{}",
		"null",
		"[]",
		`{"User_Specs":[]}`,
		`{"Defaults":[{"Options":[{"env_reset":true}]}]}`,
		// Digest as single string and as array (DigestList unmarshal quirk).
		`{"User_Specs":[{"User_List":[{"username":"alice"}],"Host_List":[{"hostname":"ALL"}],"Cmnd_Specs":[{"Commands":[{"command":"/bin/ls","sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]}]}]}`,
		`{"User_Specs":[{"User_List":[{"username":"alice"}],"Host_List":[{"hostname":"ALL"}],"Cmnd_Specs":[{"Commands":[{"command":"/bin/ls","sha256":["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"]}]}]}]}`,
		// Duplicate sha256 keys in one object (cvtsudoers emits these when a
		// command carries multiple digests of the same algorithm).
		`{"User_Specs":[{"User_List":[{"username":"alice"}],"Host_List":[{"hostname":"ALL"}],"Cmnd_Specs":[{"Commands":[{"command":"/bin/ls","sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}]}]}]}`,
		// Legacy "commandalias" member key alongside "cmndalias".
		`{"Command_Aliases":{"CMDS":[{"commandalias":"/bin/ls"}]},"User_Specs":[{"User_List":[{"username":"alice"}],"Host_List":[{"hostname":"ALL"}],"Cmnd_Specs":[{"Commands":[{"cmndalias":"CMDS"}]}]}]}`,
		// MYSELF: empty username, plus userid and negation variants.
		`{"User_Specs":[{"User_List":[{"username":""}],"Host_List":[{"hostname":"ALL"}],"Cmnd_Specs":[{"Commands":[{"command":"/bin/ls"}]}]}]}`,
		`{"User_Specs":[{"User_List":[{"userid":0},{"userid":-1},{"usergroup":"wheel","negated":true}],"Host_List":[{"hostname":"ALL"}],"Cmnd_Specs":[{"Commands":[{"command":"/bin/ls"}]}]}]}`,
		// Options array with tag and pre/post-tag option shapes.
		`{"User_Specs":[{"User_List":[{"username":"alice"}],"Host_List":[{"hostname":"ALL"}],"Cmnd_Specs":[{"Options":[{"authenticate":false},{"noexec":true},{"notbefore":"20250101120000Z"},{"notafter":"20260101120000Z"},{"role":"sysadm_r"},{"type":"sysadm_t"}],"Commands":[{"command":"/usr/bin/env"}]}]}]}`,
		// Runas users and groups, including empty runas user list.
		`{"User_Specs":[{"User_List":[{"username":"alice"}],"Host_List":[{"hostname":"ALL"}],"Cmnd_Specs":[{"RunasUsers":[{"username":"root"}],"RunasGroups":[{"usergroup":"root"}],"Commands":[{"command":"/bin/id"}]},{"RunasUsers":[],"Commands":[{"command":"/bin/true"}]}]}]}`,
		// POSIX regular expression command paths.
		`{"User_Specs":[{"User_List":[{"username":"alice"}],"Host_List":[{"hostname":"ALL"}],"Cmnd_Specs":[{"Commands":[{"command":"^/usr/bin/journalctl.*$"}]}]}]}`,
		// Alias maps with empty and single-entry lists.
		`{"User_Aliases":{"ADMINS":[{"username":"alice"}]},"Runas_Aliases":{},"Host_Aliases":{"SRV":[{"hostname":"srv1"}]},"Command_Aliases":{"EMPTY":[]}}`,
	}

	// Seed with the real-world corpus marshaled through the native parser
	// (valid categories only; invalid files are skipped).
	corpusRoot := filepath.Join("..", "..", "testdata", "corpus")
	categories := []string{"distros", "upstream_regress", "enterprise_cloud"}
	for _, cat := range categories {
		entries, err := os.ReadDir(filepath.Join(corpusRoot, cat))
		if err != nil {
			continue // corpus is optional for fuzz seeding
		}
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sudoers") {
				continue
			}
			data, err := os.ReadFile(filepath.Join(corpusRoot, cat, entry.Name()))
			if err != nil {
				continue
			}
			policy, err := parser.ParseString(string(data))
			if err != nil {
				continue
			}
			if marshaled, err := json.Marshal(policy); err == nil {
				seeds = append(seeds, string(marshaled))
			}
		}
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}

	gtfoClient, err := gtfobins.NewClient()
	if err != nil {
		f.Fatalf("Failed to load GTFObins database: %v", err)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		var policy audit.SudoersPolicy
		if err := json.Unmarshal(data, &policy); err != nil {
			return
		}

		// A successfully unmarshaled policy must round trip through JSON
		// idempotently: applying the round trip a second time changes nothing.
		first, err := json.Marshal(&policy)
		if err != nil {
			t.Fatalf("json.Marshal of unmarshaled policy failed: %v", err)
		}
		var once audit.SudoersPolicy
		if err := json.Unmarshal(first, &once); err != nil {
			t.Fatalf("json.Unmarshal of marshaled policy failed: %v", err)
		}
		second, err := json.Marshal(&once)
		if err != nil {
			t.Fatalf("json.Marshal of round-tripped policy failed: %v", err)
		}
		var twice audit.SudoersPolicy
		if err := json.Unmarshal(second, &twice); err != nil {
			t.Fatalf("json.Unmarshal of re-marshaled policy failed: %v", err)
		}
		if !reflect.DeepEqual(once, twice) {
			t.Errorf("JSON round trip is not idempotent:\nonce:  %.500q\ntwice: %.500q", first, second)
		}

		// The auditor must handle any unmarshaled policy without panicking.
		_ = audit.RunAudit(&policy, gtfoClient)
	})
}
