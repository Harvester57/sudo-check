package audit

import (
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func hostAuditTestFindID(findings []Finding, id string) (Finding, bool) {
	for _, f := range findings {
		if f.ID == id {
			return f, true
		}
	}
	return Finding{}, false
}

func hostAuditTestIntPtr(v int) *int {
	return &v
}

func TestEvaluateSudoBinaryGroupRestriction(t *testing.T) {
	t.Run("WorldExecutableTriggersR38", func(t *testing.T) {
		findings := EvaluateSudoBinaryGroupRestriction("/usr/bin/sudo", os.ModeSetuid|0755, 0)
		f, ok := hostAuditTestFindID(findings, "SUDO-SYS-PERM-014")
		if !ok {
			t.Fatalf("Expected SUDO-SYS-PERM-014 for mode 4755, got %+v", findings)
		}
		if f.Title != "Sudo Binary Executable by All Local Users (No Dedicated Group Restriction)" {
			t.Errorf("Unexpected title: %q", f.Title)
		}
		if f.Severity != SeverityInfo || f.Context != "/usr/bin/sudo" {
			t.Errorf("Unexpected severity/context: %+v", f)
		}
		if len(f.Compliance) != 1 || f.Compliance[0] != "ANSSI-BP-028 R38" {
			t.Errorf("Unexpected compliance: %v", f.Compliance)
		}
		expectedCode := "sudo chgrp sudo /usr/bin/sudo\nsudo chmod 4750 /usr/bin/sudo"
		if f.RemediationCode != expectedCode {
			t.Errorf("Expected RemediationCode %q, got %q", expectedCode, f.RemediationCode)
		}
	})

	t.Run("GroupRestrictedPasses", func(t *testing.T) {
		for _, mode := range []os.FileMode{os.ModeSetuid | 0750, os.ModeSetuid | 0110, 04750} {
			if got := EvaluateSudoBinaryGroupRestriction("/usr/bin/sudo", mode, 27); len(got) != 0 {
				t.Errorf("Mode %o: expected 0 findings, got %+v", mode, got)
			}
		}
	})

	t.Run("LiveWrapper", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			if got := AuditSudoBinaryGroupRestriction("C:\\nonexistent\\sudo"); got != nil {
				t.Errorf("Expected nil on Windows, got %+v", got)
			}
			return
		}
		tmpFile := filepath.Join(t.TempDir(), "sudo")
		if err := os.WriteFile(tmpFile, []byte("stub"), 0755); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		findings := AuditSudoBinaryGroupRestriction(tmpFile)
		if _, ok := hostAuditTestFindID(findings, "SUDO-SYS-PERM-014"); !ok {
			t.Errorf("Expected SUDO-SYS-PERM-014 for 0755 temp binary on Unix, got %+v", findings)
		}
		if got := AuditSudoBinaryGroupRestriction(filepath.Join(t.TempDir(), "missing")); got != nil {
			t.Errorf("Expected nil for missing file, got %+v", got)
		}
	})
}

func TestAuditPolicyIdentities(t *testing.T) {
	passwdData := []byte(strings.Join([]string{
		"# comment",
		"root:x:0:0:root:/root:/bin/bash",
		"alice:x:1000:1000:Alice:/home/alice:/bin/bash",
		"www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin",
	}, "\n"))
	groupData := []byte(strings.Join([]string{
		"# comment",
		"root:x:0:",
		"wheel:x:10:alice",
		"staff:x:50:",
	}, "\n"))

	t.Run("NilAndEmptyInputs", func(t *testing.T) {
		if got := AuditPolicyIdentities(nil, passwdData, groupData); got != nil {
			t.Errorf("Expected nil for nil policy, got %+v", got)
		}
		if got := AuditLocalPolicyIdentities(nil); got != nil {
			t.Errorf("Expected nil for AuditLocalPolicyIdentities(nil), got %+v", got)
		}
		policy := &SudoersPolicy{
			UserSpecs: []UserSpec{{
				UserList: []Member{{Username: "ghost"}, {Usergroup: "ghostgrp"}},
				HostList: []Member{{Hostname: "ALL"}},
			}},
		}
		if got := AuditPolicyIdentities(policy, nil, nil); len(got) != 0 {
			t.Errorf("Expected 0 findings when both passwd and group are empty, got %+v", got)
		}
		onlyPasswd := AuditPolicyIdentities(policy, passwdData, nil)
		if len(onlyPasswd) != 1 || onlyPasswd[0].User != "ghost" {
			t.Errorf("Expected only user 'ghost' when groupData is empty, got %+v", onlyPasswd)
		}
		onlyGroup := AuditPolicyIdentities(policy, nil, groupData)
		if len(onlyGroup) != 1 || onlyGroup[0].User != "%ghostgrp" {
			t.Errorf("Expected only group '%%ghostgrp' when passwdData is empty, got %+v", onlyGroup)
		}
	})

	t.Run("ValidAndSkippedPrincipals", func(t *testing.T) {
		policy := &SudoersPolicy{
			UserAliases: map[string][]Member{
				"OPS": {{Username: "alice"}, {UserID: hostAuditTestIntPtr(1000)}, {Usergroup: "wheel"}, {UserGID: hostAuditTestIntPtr(10)}},
			},
			UserSpecs: []UserSpec{
				{
					UserList: []Member{
						{UserAlias: "OPS"},
						{Username: "ALL"},
						{Netgroup: "net_ops"},
						{NonUnixGroup: "ldapadmins"},
						{NonUnixGID: hostAuditTestIntPtr(5000)},
						{UserAlias: "UNRESOLVED_ALIAS"},
					},
					HostList: []Member{{Hostname: "ALL"}},
					CmndSpecs: []CmndSpec{
						{
							RunasUsers:  []Member{{Myself: true}, {Username: "www-data"}, {Username: "ALL"}, {RunasAlias: "UNRESOLVED_RUNAS"}},
							RunasGroups: []Member{{Usergroup: "staff"}, {Usergroup: "ALL"}},
							Commands:    []Member{{Command: "/usr/bin/id"}},
						},
					},
				},
			},
		}
		findings := AuditPolicyIdentities(policy, passwdData, groupData)
		if len(findings) != 0 {
			t.Errorf("Expected 0 findings for valid/skipped principals, got %+v", findings)
		}
	})

	t.Run("MissingAndDeduplicatedPrincipals", func(t *testing.T) {
		policy := &SudoersPolicy{
			UserAliases: map[string][]Member{
				"STALE_USERS": {{Username: "ghost1"}, {UserID: hostAuditTestIntPtr(9999)}, {Usergroup: "ghostgrp"}},
			},
			RunasAliases: map[string][]Member{
				"STALE_RUNAS": {{Username: "ghostrunas"}, {UserGID: hostAuditTestIntPtr(8888)}},
			},
			UserSpecs: []UserSpec{
				{
					File: "/etc/sudoers.d/app",
					Line: 10,
					UserList: []Member{
						{UserAlias: "STALE_USERS"},
						{Username: "ghost1", Line: 11}, // Duplicate of ghost1 in alias
					},
					HostList: []Member{{Hostname: "ALL"}},
					CmndSpecs: []CmndSpec{
						{
							RunasUsers:  []Member{{RunasAlias: "STALE_RUNAS"}, {Username: "ghost1"}},
							RunasGroups: []Member{{Usergroup: "missingrg"}, {Usergroup: "#7777"}},
							Commands:    []Member{{Command: "/usr/bin/id"}},
						},
					},
				},
			},
		}

		findings := AuditPolicyIdentities(policy, passwdData, groupData)
		// Expected unique missing principals: ghost1, #9999, %ghostgrp, ghostrunas, %#8888, %missingrg, %#7777 (7 total)
		if len(findings) != 7 {
			t.Fatalf("Expected 7 deduplicated SUDO-SYS-ID-001 findings, got %d: %+v", len(findings), findings)
		}
		for _, f := range findings {
			if f.ID != "SUDO-SYS-ID-001" || f.Severity != SeverityLow {
				t.Errorf("Unexpected ID/severity: %+v", f)
			}
			if f.Title != "Nonexistent or Orphaned User/Group Referenced in Sudoers" {
				t.Errorf("Unexpected title: %q", f.Title)
			}
			if f.Context != "/etc/sudoers.d/app" || f.Line == 0 || f.RemediationCode == "" {
				t.Errorf("Missing context/line/RemediationCode: %+v", f)
			}
		}
	})

	t.Run("StringPrefixedPrincipalsAndRunasGroups", func(t *testing.T) {
		policy := &SudoersPolicy{
			UserSpecs: []UserSpec{
				{
					File: "/etc/sudoers",
					Line: 42,
					UserList: []Member{
						{Username: "%wheel"},
						{Username: "%#10"},
						{Username: "#1000"},
						{Username: "+netgrp"},
						{Username: "%:nonunix"},
						{Username: "%missingstrgrp"},
						{Username: "%#4321"},
						{Username: "#4321"},
					},
					HostList: []Member{{Hostname: "ALL"}},
					CmndSpecs: []CmndSpec{
						{
							RunasGroups: []Member{{Username: "missingrunasgrp"}, {Username: "#9876"}},
							Commands:    []Member{{Command: "/usr/bin/id"}},
						},
					},
				},
			},
		}
		findings := AuditPolicyIdentities(policy, passwdData, groupData)
		if len(findings) != 5 {
			t.Fatalf("Expected 5 missing string-prefixed principals, got %d: %+v", len(findings), findings)
		}
	})
}

func TestParsePatchedCVEsFromChangelog(t *testing.T) {
	changelog := `
* Tue Feb 01 2021 Maintainer <sec@example.org> - 1.8.29-7
- Resolves: cve-2021-3156 heap buffer overflow (Baron Samedit)
- Backport fixes for CVE-2019-18634 and CVE-2019-14287
  * Duplicate mention cve-2021-3156
  * Long number CVE-2025-12345
`
	got := ParsePatchedCVEsFromChangelog(changelog)
	expected := []string{"CVE-2021-3156", "CVE-2019-18634", "CVE-2019-14287", "CVE-2025-12345"}
	if len(got) != len(expected) {
		t.Fatalf("Expected %d CVEs, got %d: %v", len(expected), len(got), got)
	}
	for _, cve := range expected {
		if !got[cve] {
			t.Errorf("Expected %s in parsed CVEs, got %v", cve, got)
		}
	}

	if empty := ParsePatchedCVEsFromChangelog("no cves mentioned"); len(empty) != 0 {
		t.Errorf("Expected empty map, got %v", empty)
	}

	// Ensure local collector runs without panic on all platforms.
	localPatched := CollectLocalPatchedSudoCVEs()
	if localPatched == nil {
		t.Errorf("Expected non-nil map from CollectLocalPatchedSudoCVEs")
	}

	// Test gzipped changelog reader directly across valid, corrupt, and missing files.
	tmpDir := t.TempDir()
	gzPath := filepath.Join(tmpDir, "changelog.Debian.gz")
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, _ = zw.Write([]byte("sudo (1.9.5p2-3+deb11u1) bullseye-security; urgency=high\n  * Fix CVE-2023-22809 and CVE-2021-3156\n"))
	_ = zw.Close()
	if err := os.WriteFile(gzPath, buf.Bytes(), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	text, ok := hostAuditReadGzipFile(gzPath, 1024*1024)
	if !ok {
		t.Fatalf("Expected hostAuditReadGzipFile to succeed")
	}
	parsedGz := ParsePatchedCVEsFromChangelog(text)
	if !parsedGz["CVE-2023-22809"] || !parsedGz["CVE-2021-3156"] {
		t.Errorf("Expected CVEs from gzipped changelog, got %v", parsedGz)
	}

	corruptPath := filepath.Join(tmpDir, "bad.gz")
	_ = os.WriteFile(corruptPath, []byte("not-gzip"), 0644)
	if _, ok := hostAuditReadGzipFile(corruptPath, 1024); ok {
		t.Errorf("Expected false for corrupt gzip file")
	}
	if _, ok := hostAuditReadGzipFile(filepath.Join(tmpDir, "missing.gz"), 1024); ok {
		t.Errorf("Expected false for missing gzip file")
	}
}

func TestFilterBackportedCVEs(t *testing.T) {
	if got := FilterBackportedCVEs(nil, map[string]bool{"CVE-2021-3156": true}); got != nil {
		t.Errorf("Expected nil for nil findings, got %+v", got)
	}

	orig := []Finding{
		{
			ID:              "CVE-2021-3156",
			Title:           "Baron Samedit Sudo Heap Buffer Overflow",
			Description:     "Heap overflow.",
			Severity:        SeverityCritical,
			RemediationCode: "apt install sudo",
		},
		{
			ID:              "CVE-2025-32463",
			Title:           "Sudo Chroot (-R) Local Privilege Escalation",
			Description:     "Chroot LPE.",
			Severity:        SeverityCritical,
			RemediationCode: "apt install sudo",
		},
		{
			ID:              "SUDO-SYS-001",
			Title:           "Unrecognized Sudo Version Format",
			Description:     "Unknown.",
			Severity:        SeverityInfo,
			RemediationCode: "sudo -V",
		},
	}

	patched := map[string]bool{"CVE-2021-3156": true}
	filtered := FilterBackportedCVEs(orig, patched)

	// Input slice must not be mutated.
	if orig[0].Severity != SeverityCritical || orig[0].Exploitability != "" {
		t.Errorf("Input finding slice was mutated: %+v", orig[0])
	}

	if filtered[0].Severity != SeverityInfo || filtered[0].Exploitability != "PATCHED_BACKPORT" {
		t.Errorf("Expected CVE-2021-3156 downgraded to INFO/PATCHED_BACKPORT, got %+v", filtered[0])
	}
	if !strings.Contains(filtered[0].Title, "Backport") || !strings.Contains(filtered[0].Description, "backport") {
		t.Errorf("Expected backport note in title/description, got %+v", filtered[0])
	}
	if !strings.Contains(filtered[0].RemediationCode, "grep CVE-2021-3156") {
		t.Errorf("Unexpected RemediationCode: %q", filtered[0].RemediationCode)
	}

	if filtered[1].Severity != SeverityCritical || filtered[1].Exploitability != "" {
		t.Errorf("Expected unpatched CVE-2025-32463 unchanged, got %+v", filtered[1])
	}
	if filtered[2].ID != "SUDO-SYS-001" || filtered[2].Exploitability != "" {
		t.Errorf("Expected non-CVE SUDO-SYS-001 unchanged, got %+v", filtered[2])
	}
}

func TestCorrelateCVEsWithPolicy(t *testing.T) {
	if got := CorrelateCVEsWithPolicy(nil, nil); got != nil {
		t.Errorf("Expected nil for nil findings, got %+v", got)
	}

	baseCVEs := func() []Finding {
		return []Finding{
			{ID: "CVE-2019-18634", Description: "pwfeedback."},
			{ID: "CVE-2019-14287", Description: "negated runas."},
			{ID: "CVE-2023-22809", Description: "sudoedit."},
			{ID: "CVE-2023-27320", Description: "runchroot."},
			{ID: "CVE-2025-32462", Description: "host option."},
			{ID: "CVE-2021-3156", Description: "baron samedit."},
			{ID: "CVE-2025-32463", Description: "chroot -R."},
			{ID: "CVE-2022-43995", Description: "crypt()."},
			{ID: "SUDO-SYS-001", Description: "non-cve."},
		}
	}

	findByID := func(fs []Finding, id string) Finding {
		f, ok := hostAuditTestFindID(fs, id)
		if !ok {
			t.Fatalf("Finding %s missing", id)
		}
		return f
	}

	t.Run("AllActiveViaPolicy", func(t *testing.T) {
		policy := &SudoersPolicy{
			Defaults: []DefaultBinding{
				{Options: []Option{{"pwfeedback": true}, {"runchroot": "/var/chroot"}}},
			},
			RunasAliases: map[string][]Member{
				"NONROOT": {{Username: "ALL"}, {Username: "root", Negated: true}},
			},
			CommandAliases: map[string][]Member{
				"EDITORS": {{Command: "sudoedit /etc/hosts"}},
			},
			HostAliases: map[string][]Member{
				"WEBHOSTS": {{Hostname: "web01"}},
			},
			UserSpecs: []UserSpec{
				{
					UserList: []Member{{Username: "alice"}},
					HostList: []Member{{HostAlias: "WEBHOSTS"}},
					CmndSpecs: []CmndSpec{
						{
							RunasUsers: []Member{{RunasAlias: "NONROOT"}},
							Commands:   []Member{{CommandAlias: "EDITORS"}},
						},
					},
				},
			},
		}

		res := CorrelateCVEsWithPolicy(baseCVEs(), policy)
		for _, id := range []string{
			"CVE-2019-18634",
			"CVE-2019-14287",
			"CVE-2023-22809",
			"CVE-2023-27320",
			"CVE-2025-32462",
			"CVE-2021-3156",
			"CVE-2025-32463",
		} {
			f := findByID(res, id)
			if f.Exploitability != "ACTIVE" {
				t.Errorf("%s: expected ACTIVE, got %q (desc: %s)", id, f.Exploitability, f.Description)
			}
			if !strings.Contains(f.Description, "Policy correlation: ACTIVE") {
				t.Errorf("%s: expected policy evidence in Description, got %q", id, f.Description)
			}
		}
		if f := findByID(res, "CVE-2022-43995"); f.Exploitability != "LATENT" {
			t.Errorf("CVE-2022-43995: expected LATENT, got %q", f.Exploitability)
		}
		if f := findByID(res, "SUDO-SYS-001"); f.Exploitability != "" {
			t.Errorf("SUDO-SYS-001: expected empty Exploitability, got %q", f.Exploitability)
		}
	})

	t.Run("AllPolicyDependentLatentAndLastMatchWins", func(t *testing.T) {
		policy := &SudoersPolicy{
			Defaults: []DefaultBinding{
				{Options: []Option{{"pwfeedback": true}, {"runchroot": "/var/chroot"}}},
				{Options: []Option{{"pwfeedback": false}, {"runchroot": false}}},
				{
					Binding: []Member{{Username: "alice"}},
					Options: []Option{{"pwfeedback": true}},
				},
				{
					Binding: []Member{{Username: "alice"}},
					Options: []Option{{"pwfeedback": false}},
				},
			},
			UserSpecs: []UserSpec{
				{
					UserList: []Member{{Username: "alice"}},
					HostList: []Member{{Hostname: "ALL"}},
					CmndSpecs: []CmndSpec{
						{
							RunasUsers: []Member{{Username: "root"}},
							Commands: []Member{
								{Command: "/usr/bin/systemctl status app"},
								{Command: "sudoedit /etc/hosts", Negated: true},
							},
						},
					},
				},
			},
		}

		res := CorrelateCVEsWithPolicy(baseCVEs(), policy)
		for _, id := range []string{
			"CVE-2019-18634",
			"CVE-2019-14287",
			"CVE-2023-22809",
			"CVE-2023-27320",
			"CVE-2025-32462",
			"CVE-2022-43995",
		} {
			f := findByID(res, id)
			if f.Exploitability != "LATENT" {
				t.Errorf("%s: expected LATENT, got %q (desc: %s)", id, f.Exploitability, f.Description)
			}
		}
		for _, id := range []string{"CVE-2021-3156", "CVE-2025-32463"} {
			if f := findByID(res, id); f.Exploitability != "ACTIVE" {
				t.Errorf("%s: expected unconditional ACTIVE, got %q", id, f.Exploitability)
			}
		}
	})

	t.Run("AlternatePreconditionsAndPreservesPatchedBackport", func(t *testing.T) {
		policy := &SudoersPolicy{
			Defaults: []DefaultBinding{
				{
					Binding: []Member{{Username: "bob"}},
					Options: []Option{{"pwfeedback": true}},
				},
				{
					Binding: []Member{{Hostname: "db01"}},
					Options: []Option{{"env_reset": true}},
				},
			},
			UserSpecs: []UserSpec{
				{
					UserList: []Member{{Username: "bob"}},
					HostList: []Member{{Hostname: "ALL"}},
					CmndSpecs: []CmndSpec{
						{
							RunasGroups: []Member{{Usergroup: "wheel", Negated: true}},
							Options:     []Option{{"runchroot": "/srv/chroot"}},
							Commands:    []Member{{Command: "ALL"}},
						},
					},
				},
			},
		}

		input := append(baseCVEs(), Finding{
			ID:             "CVE-2021-3156",
			Exploitability: "PATCHED_BACKPORT",
			Description:    "Already backported.",
		})
		// Replace the first CVE-2021-3156 with patched backport to test preservation clearly.
		res := CorrelateCVEsWithPolicy(input[0:9], policy)
		for _, id := range []string{"CVE-2019-18634", "CVE-2019-14287", "CVE-2023-22809", "CVE-2023-27320", "CVE-2025-32462"} {
			if f := findByID(res, id); f.Exploitability != "ACTIVE" {
				t.Errorf("%s: expected ACTIVE via alternate preconditions, got %q", id, f.Exploitability)
			}
		}

		patchedInput := []Finding{{ID: "CVE-2021-3156", Exploitability: "PATCHED_BACKPORT", Description: "Backported."}}
		patchedOut := CorrelateCVEsWithPolicy(patchedInput, policy)
		if patchedOut[0].Exploitability != "PATCHED_BACKPORT" {
			t.Errorf("Expected PATCHED_BACKPORT preserved, got %q", patchedOut[0].Exploitability)
		}

		// Nil policy keeps unconditional CVEs ACTIVE and policy-dependent CVEs LATENT.
		nilPolicyOut := CorrelateCVEsWithPolicy(baseCVEs(), nil)
		if f := findByID(nilPolicyOut, "CVE-2021-3156"); f.Exploitability != "ACTIVE" {
			t.Errorf("Expected CVE-2021-3156 ACTIVE with nil policy, got %q", f.Exploitability)
		}
		if f := findByID(nilPolicyOut, "CVE-2019-18634"); f.Exploitability != "LATENT" {
			t.Errorf("Expected CVE-2019-18634 LATENT with nil policy, got %q", f.Exploitability)
		}

		// Regex sudoedit command triggers ACTIVE for CVE-2023-22809.
		regexSudoeditPolicy := &SudoersPolicy{
			UserSpecs: []UserSpec{{
				UserList: []Member{{Username: "alice"}},
				HostList: []Member{{Hostname: "ALL"}},
				CmndSpecs: []CmndSpec{{
					Commands: []Member{{Command: "^/usr/bin/sudoedit$ /etc/hosts"}},
				}},
			}},
		}
		regexOut := CorrelateCVEsWithPolicy([]Finding{{ID: "CVE-2023-22809", Description: "sudoedit."}}, regexSudoeditPolicy)
		if regexOut[0].Exploitability != "ACTIVE" {
			t.Errorf("Expected ACTIVE for regex sudoedit command, got %+v", regexOut[0])
		}
	})
}
