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

// FuzzParseString checks that the native sudoers parser and the auditor built
// on top of it handle arbitrary input without panicking or hanging, and that
// any successfully parsed policy survives a JSON marshal/unmarshal round trip
// idempotently (unmarshal(marshal(unmarshal(marshal(p)))) == unmarshal(marshal(p))).
//
// The seed corpus includes hand-picked syntax edge cases plus every file of the
// real-world corpus in testdata/corpus, so plain `go test` already replays all
// seeds as unit tests. Extended fuzzing runs with:
//
//	go test -fuzz=FuzzParseString -fuzztime=5m ./pkg/parser
func FuzzParseString(f *testing.F) {
	seeds := []string{
		"",
		"\n",
		"# only a comment\n",
		"Defaults env_reset\n",
		"Defaults secure_path=\"/usr/sbin:/usr/bin\"\n",
		"Defaults:alice, %wheel, #1000 !authenticate\n",
		"Defaults env_keep = \"LANG\", env_keep += \"LD_PRELOAD\", env_keep -= \"LANG\", !env_keep\n",
		"Defaults umask=0077, timestamp_timeout=5, passwd_timeout=1\n",
		"User_Alias ADMINS = alice, %wheel : DEVS = bob, !charlie, #-1\n",
		"Cmnd_Alias CMDS = /bin/ls, /bin/cat /var/log/*\n",
		"root ALL=(ALL:ALL) ALL\n",
		"alice ALL = NOPASSWD: NOEXEC: SETENV: /usr/bin/find, PASSWD: /usr/bin/id \"\"\n",
		"bob ALL = (ALL, !root, #-1) /usr/bin/id \"\"\n",
		"eve ALL = ROLE=sysadm_r TYPE=sysadm_t CHROOT=/ CWD=* TIMEOUT=1d2h3m /usr/bin/env\n",
		"dave ALL = sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789 /bin/sh\n",
		"editor ALL = sudoedit /etc/sudoers, sudoedit\n",
		"auditor ALL = NOTBEFORE=20250101120000Z NOTAFTER=20260101120000Z /usr/bin/journalctl -u ssh\n",
		// Syntax error seeds: the parser must reject these without panicking.
		"Defaults secure_path=\"/unterminated\n",
		"alice ALL = (root /bin/ls\n",
		"User_Alias\n",
		"@include\n",
		"Defaults !umask=0022\n",
		"alice ALL = sha256:short /bin/ls\n",
		// Structural stress seeds.
		strings.Repeat("Defaults env_reset\n", 200),
		strings.Repeat("(", 64) + "\n",
		strings.Repeat("!", 64) + "ALL ALL = ALL\n",
	}

	// Seed with the entire real-world corpus (valid and invalid categories).
	corpusRoot := filepath.Join("..", "..", "testdata", "corpus")
	categories := []string{"distros", "upstream_regress", "upstream_regress_invalid", "enterprise_cloud"}
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
			if err == nil {
				seeds = append(seeds, string(data))
			}
		}
	}
	for _, s := range seeds {
		f.Add(s)
	}

	gtfoClient, err := gtfobins.NewClient()
	if err != nil {
		f.Fatalf("Failed to load GTFObins database: %v", err)
	}

	f.Fuzz(func(t *testing.T, input string) {
		policy, err := ParseString(input)
		if err != nil {
			return
		}
		if policy == nil {
			t.Fatal("ParseString returned nil policy and nil error")
		}

		// A parsed policy must serialize to a valid JSON policy that
		// unmarshals back into a policy, and that round trip must be
		// idempotent: applying it a second time changes nothing.
		first, err := json.Marshal(policy)
		if err != nil {
			t.Fatalf("json.Marshal of parsed policy failed: %v", err)
		}
		if !IsJSONPolicy(first) {
			t.Fatalf("marshaled policy not detected as JSON policy: %.200q", first)
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

		// The auditor must handle any parsed policy without panicking.
		_ = audit.RunAudit(policy, gtfoClient)
	})
}
