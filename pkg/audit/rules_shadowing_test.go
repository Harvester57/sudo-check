package audit

import (
	"strings"
	"testing"
	"time"
)

func shadowTestAssertSingle(t *testing.T, findings []Finding, wantSev Severity, wantPrevLoc, wantCurrLoc string) {
	t.Helper()
	if len(findings) != 1 {
		t.Fatalf("expected 1 SUDO-CMD-015 finding, got %d: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.ID != "SUDO-CMD-015" {
		t.Errorf("expected ID SUDO-CMD-015, got %s", f.ID)
	}
	if f.Title != "Shadowed or Overridden Sudoers Rule" {
		t.Errorf("unexpected title %q", f.Title)
	}
	if f.Severity != wantSev {
		t.Errorf("expected Severity=%s, got %s (desc: %s)", wantSev, f.Severity, f.Description)
	}
	if !strings.Contains(f.Description, wantPrevLoc) || !strings.Contains(f.Description, wantCurrLoc) {
		t.Errorf("expected Description to contain %q and %q, got %q", wantPrevLoc, wantCurrLoc, f.Description)
	}
	if f.Remediation == "" {
		t.Error("expected non-empty Remediation")
	}
	if f.RemediationCode == "" {
		t.Error("expected non-empty RemediationCode")
	}
}

func TestAuditShadowing_NilPolicy(t *testing.T) {
	if got := AuditShadowing(nil); len(got) != 0 {
		t.Errorf("expected no findings for nil policy, got %+v", got)
	}
}

func TestAuditShadowing_WeakeningOverrides(t *testing.T) {
	t.Run("PASSWD_To_NOPASSWD", func(t *testing.T) {
		policy := &SudoersPolicy{
			UserSpecs: []UserSpec{
				{
					UserList: []Member{{Username: "alice"}},
					HostList: []Member{{Hostname: "ALL"}},
					CmndSpecs: []CmndSpec{{
						RunasUsers: []Member{{Username: "root"}},
						Commands:   []Member{{Command: "/bin/cat"}},
					}},
					File: "/etc/sudoers",
					Line: 10,
				},
				{
					UserList: []Member{{Username: "alice"}},
					HostList: []Member{{Hostname: "ALL"}},
					CmndSpecs: []CmndSpec{{
						RunasUsers: []Member{{Username: "root"}},
						Options:    []Option{{"authenticate": false}},
						Commands:   []Member{{Command: "/bin/cat"}},
					}},
					File: "/etc/sudoers.d/override",
					Line: 3,
				},
			},
		}
		findings := AuditShadowing(policy)
		shadowTestAssertSingle(t, findings, SeverityMedium, "/etc/sudoers:10", "/etc/sudoers.d/override:3")
		if findings[0].Context != "/etc/sudoers.d/override" || findings[0].Line != 3 {
			t.Errorf("expected Context/Line at overriding rule, got %s:%d", findings[0].Context, findings[0].Line)
		}
	})

	t.Run("NOEXEC_To_EXEC", func(t *testing.T) {
		policy := &SudoersPolicy{
			UserSpecs: []UserSpec{
				{
					UserList: []Member{{Username: "alice"}},
					HostList: []Member{{Hostname: "ALL"}},
					CmndSpecs: []CmndSpec{{
						RunasUsers: []Member{{Username: "root"}},
						Options:    []Option{{"noexec": true}},
						Commands:   []Member{{Command: "/usr/bin/less /var/log/app.log"}},
					}},
					File: "sudoers",
					Line: 5,
				},
				{
					UserList: []Member{{Username: "alice"}},
					HostList: []Member{{Hostname: "ALL"}},
					CmndSpecs: []CmndSpec{{
						RunasUsers: []Member{{Username: "root"}},
						Options:    []Option{{"noexec": false}},
						Commands:   []Member{{Command: "/usr/bin/less /var/log/app.log"}},
					}},
					File: "sudoers",
					Line: 12,
				},
			},
		}
		findings := AuditShadowing(policy)
		shadowTestAssertSingle(t, findings, SeverityMedium, "sudoers:5", "sudoers:12")
	})

	t.Run("NoSetEnv_To_SetEnv", func(t *testing.T) {
		policy := &SudoersPolicy{
			UserSpecs: []UserSpec{
				{
					UserList: []Member{{Username: "alice"}},
					HostList: []Member{{Hostname: "ALL"}},
					CmndSpecs: []CmndSpec{{
						Options:  []Option{{"setenv": false}},
						Commands: []Member{{Command: `/usr/bin/env ""`}},
					}},
					File: "sudoers",
					Line: 10,
				},
				{
					UserList: []Member{{Username: "alice"}},
					HostList: []Member{{Hostname: "ALL"}},
					CmndSpecs: []CmndSpec{{
						Options:  []Option{{"setenv": true}},
						Commands: []Member{{Command: `/usr/bin/env ""`}},
					}},
					File: "sudoers",
					Line: 20,
				},
			},
		}
		findings := AuditShadowing(policy)
		shadowTestAssertSingle(t, findings, SeverityMedium, "sudoers:10", "sudoers:20")
	})

	t.Run("RestrictedCommand_To_ALL", func(t *testing.T) {
		policy := &SudoersPolicy{
			UserSpecs: []UserSpec{
				{
					UserList: []Member{{Username: "alice"}},
					HostList: []Member{{Hostname: "ALL"}},
					CmndSpecs: []CmndSpec{{
						Commands: []Member{{Command: `/bin/cat ""`}},
					}},
					File: "sudoers",
					Line: 15,
				},
				{
					UserList: []Member{{Username: "alice"}},
					HostList: []Member{{Hostname: "ALL"}},
					CmndSpecs: []CmndSpec{{
						Commands: []Member{{Command: "ALL"}},
					}},
					File: "sudoers",
					Line: 25,
				},
			},
		}
		findings := AuditShadowing(policy)
		shadowTestAssertSingle(t, findings, SeverityMedium, "sudoers:15", "sudoers:25")
	})

	t.Run("ALL_FollowedBy_NOPASSWD_SpecificCommand", func(t *testing.T) {
		policy := &SudoersPolicy{
			UserSpecs: []UserSpec{
				{
					UserList: []Member{{Username: "alice"}},
					HostList: []Member{{Hostname: "ALL"}},
					CmndSpecs: []CmndSpec{{
						Commands: []Member{{Command: "ALL"}},
					}},
					File: "sudoers",
					Line: 8,
				},
				{
					UserList: []Member{{Username: "alice"}},
					HostList: []Member{{Hostname: "ALL"}},
					CmndSpecs: []CmndSpec{{
						Options:  []Option{{"authenticate": false}},
						Commands: []Member{{Command: "/bin/cat"}},
					}},
					File: "sudoers",
					Line: 16,
				},
			},
		}
		findings := AuditShadowing(policy)
		shadowTestAssertSingle(t, findings, SeverityMedium, "sudoers:8", "sudoers:16")
	})

	t.Run("RestrictedArgs_To_UnrestrictedArgs", func(t *testing.T) {
		policy := &SudoersPolicy{
			UserSpecs: []UserSpec{
				{
					UserList: []Member{{Username: "alice"}},
					HostList: []Member{{Hostname: "ALL"}},
					CmndSpecs: []CmndSpec{{
						Commands: []Member{{Command: "/bin/cat /var/log/syslog"}},
					}},
					File: "sudoers",
					Line: 4,
				},
				{
					UserList: []Member{{Username: "alice"}},
					HostList: []Member{{Hostname: "ALL"}},
					CmndSpecs: []CmndSpec{{
						Commands: []Member{{Command: "/bin/cat"}},
					}},
					File: "sudoers",
					Line: 9,
				},
			},
		}
		findings := AuditShadowing(policy)
		shadowTestAssertSingle(t, findings, SeverityMedium, "sudoers:4", "sudoers:9")
	})
}

func TestAuditShadowing_RedundantTighteningAndAliases(t *testing.T) {
	t.Run("NOPASSWD_To_PASSWD_TighteningInfo", func(t *testing.T) {
		policy := &SudoersPolicy{
			UserSpecs: []UserSpec{
				{
					UserList: []Member{{Username: "alice"}},
					HostList: []Member{{Hostname: "ALL"}},
					CmndSpecs: []CmndSpec{{
						Options:  []Option{{"authenticate": false}},
						Commands: []Member{{Command: "/bin/cat"}},
					}},
					File: "sudoers",
					Line: 10,
				},
				{
					UserList: []Member{{Username: "alice"}},
					HostList: []Member{{Hostname: "ALL"}},
					CmndSpecs: []CmndSpec{{
						Options:  []Option{{"authenticate": true}},
						Commands: []Member{{Command: "/bin/cat"}},
					}},
					File: "sudoers",
					Line: 14,
				},
			},
		}
		findings := AuditShadowing(policy)
		shadowTestAssertSingle(t, findings, SeverityInfo, "sudoers:10", "sudoers:14")
	})

	t.Run("DuplicateExactRuleInfo", func(t *testing.T) {
		policy := &SudoersPolicy{
			UserSpecs: []UserSpec{
				{
					UserList: []Member{{Username: "alice"}},
					HostList: []Member{{Hostname: "ALL"}},
					CmndSpecs: []CmndSpec{{
						Commands: []Member{{Command: `/usr/bin/id ""`}},
					}},
					File: "sudoers",
					Line: 5,
				},
				{
					UserList: []Member{{Username: "alice"}},
					HostList: []Member{{Hostname: "ALL"}},
					CmndSpecs: []CmndSpec{{
						Commands: []Member{{Command: `/usr/bin/id ""`}},
					}},
					File: "sudoers.d/dup",
					Line: 2,
				},
			},
		}
		findings := AuditShadowing(policy)
		shadowTestAssertSingle(t, findings, SeverityInfo, "sudoers:5", "sudoers.d/dup:2")
	})

	t.Run("AliasAndCIDROverlap", func(t *testing.T) {
		policy := &SudoersPolicy{
			UserAliases: map[string][]Member{
				"OPS": {{Username: "alice"}, {Username: "bob"}},
			},
			HostAliases: map[string][]Member{
				"SUBNET": {{NetworkAddr: "10.0.0.0/24"}},
			},
			CommandAliases: map[string][]Member{
				"READ_CMD": {{Command: "/bin/cat /var/log/app.log"}},
			},
			UserSpecs: []UserSpec{
				{
					UserList: []Member{{UserAlias: "OPS"}},
					HostList: []Member{{HostAlias: "SUBNET"}},
					CmndSpecs: []CmndSpec{{
						Commands: []Member{{CommandAlias: "READ_CMD"}},
					}},
					File: "sudoers",
					Line: 20,
				},
				{
					UserList: []Member{{Username: "alice"}},
					HostList: []Member{{NetworkAddr: "10.0.0.5"}},
					CmndSpecs: []CmndSpec{{
						Options:  []Option{{"authenticate": false}},
						Commands: []Member{{Command: "/bin/cat /var/log/app.log"}},
					}},
					File: "sudoers",
					Line: 30,
				},
			},
		}
		findings := AuditShadowing(policy)
		shadowTestAssertSingle(t, findings, SeverityMedium, "sudoers:20", "sudoers:30")
	})
}

func TestAuditShadowing_DistinctRulesNoFalsePositives(t *testing.T) {
	t.Run("DistinctCommandsSameUserHostRunas", func(t *testing.T) {
		policy := &SudoersPolicy{
			UserSpecs: []UserSpec{
				{
					UserList: []Member{{Usergroup: "sudo_webops"}},
					HostList: []Member{{Hostname: "web01.internal.example"}},
					CmndSpecs: []CmndSpec{{
						RunasUsers: []Member{{Username: "www-data"}},
						Options:    []Option{{"authenticate": true}, {"noexec": false}},
						Commands: []Member{
							{Command: `/usr/local/sbin/reload-nginx-config.sh ""`},
							{Command: `/usr/local/sbin/nginx-service-status.sh ""`},
						},
					}},
					File: "/etc/sudoers",
					Line: 10,
				},
				{
					UserList: []Member{{Usergroup: "sudo_webops"}},
					HostList: []Member{{Hostname: "web01.internal.example"}},
					CmndSpecs: []CmndSpec{{
						RunasUsers: []Member{{Username: "www-data"}},
						Options:    []Option{{"authenticate": true}},
						Commands:   []Member{{Command: `sudoedit /etc/nginx/conf.d/app-vhost.conf`}},
					}},
					File: "/etc/sudoers",
					Line: 20,
				},
			},
		}
		if findings := AuditShadowing(policy); len(findings) != 0 {
			t.Errorf("expected 0 findings for distinct commands on same user/host/runas, got %+v", findings)
		}
	})

	t.Run("HardenedReferenceBaselineZeroFindings", func(t *testing.T) {
		policy := &SudoersPolicy{
			HostAliases: map[string][]Member{
				"PROD_WEB_SERVERS": {{Hostname: "web01.internal.example"}, {Hostname: "web02.internal.example"}},
				"PROD_DB_SERVERS":  {{Hostname: "db01.internal.example"}},
			},
			UserAliases: map[string][]Member{
				"WEB_OPERATORS":  {{Usergroup: "sudo_webops"}},
				"DB_OPERATORS":   {{Usergroup: "sudo_dbops"}},
				"SECURITY_AUDIT": {{Usergroup: "sudo_auditors"}},
			},
			RunasAliases: map[string][]Member{
				"WEB_SVC_USER": {{Username: "www-data"}},
				"DB_SVC_USER":  {{Username: "postgres"}},
			},
			UserSpecs: []UserSpec{
				{
					UserList: []Member{{UserAlias: "WEB_OPERATORS"}},
					HostList: []Member{{HostAlias: "PROD_WEB_SERVERS"}},
					CmndSpecs: []CmndSpec{{
						RunasUsers: []Member{{RunasAlias: "WEB_SVC_USER"}},
						Options:    []Option{{"authenticate": true}, {"noexec": false}},
						Commands:   []Member{{Command: `/usr/local/sbin/sudo-wrappers/reload-nginx-config.sh ""`}},
					}},
					File: "/etc/sudoers",
					Line: 60,
				},
				{
					UserList: []Member{{UserAlias: "DB_OPERATORS"}},
					HostList: []Member{{HostAlias: "PROD_DB_SERVERS"}},
					CmndSpecs: []CmndSpec{{
						RunasUsers: []Member{{RunasAlias: "DB_SVC_USER"}},
						Options:    []Option{{"authenticate": true}, {"noexec": false}},
						Commands:   []Member{{Command: `/usr/local/sbin/sudo-wrappers/pg-ControlledCheck.sh --status`}},
					}},
					File: "/etc/sudoers",
					Line: 64,
				},
				{
					UserList: []Member{{UserAlias: "WEB_OPERATORS"}},
					HostList: []Member{{HostAlias: "PROD_WEB_SERVERS"}},
					CmndSpecs: []CmndSpec{{
						RunasUsers: []Member{{Username: "root"}},
						Options:    []Option{{"authenticate": true}, {"noexec": false}},
						Commands:   []Member{{Command: `/usr/local/sbin/sudo-wrappers/nginx-service-status.sh ""`}},
					}},
					File: "/etc/sudoers",
					Line: 69,
				},
				{
					UserList: []Member{{UserAlias: "SECURITY_AUDIT"}},
					HostList: []Member{{Hostname: "ALL"}},
					CmndSpecs: []CmndSpec{{
						RunasUsers: []Member{{Username: "root"}},
						Options:    []Option{{"authenticate": true}, {"noexec": true}},
						Commands:   []Member{{Command: `/usr/sbin/auditctl -s`}},
					}},
					File: "/etc/sudoers",
					Line: 74,
				},
				{
					UserList: []Member{{UserAlias: "WEB_OPERATORS"}},
					HostList: []Member{{HostAlias: "PROD_WEB_SERVERS"}},
					CmndSpecs: []CmndSpec{{
						RunasUsers: []Member{{RunasAlias: "WEB_SVC_USER"}},
						Options:    []Option{{"authenticate": true}},
						Commands:   []Member{{Command: `sudoedit /etc/nginx/conf.d/app-vhost.conf`}},
					}},
					File: "/etc/sudoers",
					Line: 79,
				},
			},
		}

		if findings := AuditShadowing(policy); len(findings) != 0 {
			t.Errorf("expected 0 SUDO-CMD-015 findings on hardened reference policy, got %+v", findings)
		}
	})

	t.Run("InlineExclusionAndNegatedPrincipalAndDisjointRunas", func(t *testing.T) {
		policy := &SudoersPolicy{
			UserSpecs: []UserSpec{
				{
					// Inline exclusion in same CmndSpec should not trigger SUDO-CMD-015 against itself.
					UserList: []Member{{Username: "bob"}},
					HostList: []Member{{Hostname: "ALL"}},
					CmndSpecs: []CmndSpec{{
						Commands: []Member{
							{Command: "ALL"},
							{Command: "/bin/sh", Negated: true},
						},
					}},
					File: "sudoers",
					Line: 1,
				},
				{
					// ALL, !alice, !bob does not overlap alice or bob.
					UserList: []Member{{Username: "ALL"}, {Username: "alice", Negated: true}, {Username: "bob", Negated: true}},
					HostList: []Member{{Hostname: "ALL"}},
					CmndSpecs: []CmndSpec{{
						Commands: []Member{{Command: "/bin/cat"}},
					}},
					File: "sudoers",
					Line: 2,
				},
				{
					UserList: []Member{{Username: "alice"}},
					HostList: []Member{{Hostname: "ALL"}},
					CmndSpecs: []CmndSpec{
						{
							RunasUsers: []Member{{Username: "www-data"}},
							Commands:   []Member{{Command: "/bin/cat"}},
						},
						{
							RunasUsers: []Member{{Username: "root"}},
							Commands:   []Member{{Command: "/bin/cat"}},
						},
					},
					File: "sudoers",
					Line: 3,
				},
			},
		}
		if findings := AuditShadowing(policy); len(findings) != 0 {
			t.Errorf("expected 0 findings for inline exclusions, negated principals, and disjoint runas, got %+v", findings)
		}
	})

	t.Run("CleanPolicyZeroShadowingFindings", func(t *testing.T) {
		clean := loadTestPolicy(t, "clean_policy.json")
		if findings := AuditShadowing(clean); len(findings) != 0 {
			t.Errorf("expected 0 SUDO-CMD-015 findings on clean_policy.json, got %+v", findings)
		}
	})
}

func TestAuditShadowing_DirectoryAndWildcardAndDefaultsFlags(t *testing.T) {
	t.Run("SpecificBinary_To_DirectoryExecution", func(t *testing.T) {
		policy := &SudoersPolicy{
			UserSpecs: []UserSpec{
				{
					UserList: []Member{{Username: "alice"}},
					HostList: []Member{{Hostname: "ALL"}},
					CmndSpecs: []CmndSpec{{
						Commands: []Member{{Command: `/usr/local/bin/deploy.sh ""`}},
					}},
					File: "sudoers",
					Line: 10,
				},
				{
					UserList: []Member{{Username: "alice"}},
					HostList: []Member{{Hostname: "ALL"}},
					CmndSpecs: []CmndSpec{{
						Commands: []Member{{Command: `/usr/local/bin/`}},
					}},
					File: "sudoers",
					Line: 20,
				},
			},
		}
		findings := AuditShadowing(policy)
		shadowTestAssertSingle(t, findings, SeverityMedium, "sudoers:10", "sudoers:20")
	})

	t.Run("LiteralArgs_To_WildcardArgs", func(t *testing.T) {
		policy := &SudoersPolicy{
			UserSpecs: []UserSpec{
				{
					UserList: []Member{{Username: "alice"}},
					HostList: []Member{{Hostname: "ALL"}},
					CmndSpecs: []CmndSpec{{
						Commands: []Member{{Command: "/bin/cat /var/log/syslog"}},
					}},
					File: "sudoers",
					Line: 10,
				},
				{
					UserList: []Member{{Username: "alice"}},
					HostList: []Member{{Hostname: "ALL"}},
					CmndSpecs: []CmndSpec{{
						Commands: []Member{{Command: "/bin/cat /var/log/*"}},
					}},
					File: "sudoers",
					Line: 20,
				},
			},
		}
		findings := AuditShadowing(policy)
		shadowTestAssertSingle(t, findings, SeverityMedium, "sudoers:10", "sudoers:20")
	})

	t.Run("NegatedCommandOverriddenByLaterAllow", func(t *testing.T) {
		policy := &SudoersPolicy{
			UserSpecs: []UserSpec{
				{
					UserList: []Member{{Username: "alice"}},
					HostList: []Member{{Hostname: "ALL"}},
					CmndSpecs: []CmndSpec{{
						Commands: []Member{
							{Command: "ALL"},
							{Command: "/bin/sh", Negated: true},
						},
					}},
					File: "sudoers",
					Line: 5,
				},
				{
					UserList: []Member{{Username: "alice"}},
					HostList: []Member{{Hostname: "ALL"}},
					CmndSpecs: []CmndSpec{{
						Commands: []Member{{Command: "/bin/sh"}},
					}},
					File: "sudoers",
					Line: 12,
				},
			},
		}
		findings := AuditShadowing(policy)
		shadowTestAssertSingle(t, findings, SeverityMedium, "sudoers:5", "sudoers:12")
	})

	t.Run("InheritedDefaultsAuthenticateWeakening", func(t *testing.T) {
		policy := &SudoersPolicy{
			Defaults: []DefaultBinding{
				{Options: []Option{{"authenticate": false}}},
			},
			UserSpecs: []UserSpec{
				{
					UserList: []Member{{Username: "alice"}},
					HostList: []Member{{Hostname: "ALL"}},
					CmndSpecs: []CmndSpec{{
						Options:  []Option{{"authenticate": true}},
						Commands: []Member{{Command: `/bin/cat ""`}},
					}},
					File: "sudoers",
					Line: 10,
				},
				{
					UserList: []Member{{Username: "alice"}},
					HostList: []Member{{Hostname: "ALL"}},
					CmndSpecs: []CmndSpec{{
						Commands: []Member{{Command: `/bin/cat ""`}},
					}},
					File: "sudoers",
					Line: 15,
				},
			},
		}
		findings := AuditShadowing(policy)
		shadowTestAssertSingle(t, findings, SeverityMedium, "sudoers:10", "sudoers:15")
	})
}

func TestAuditTimeWindows(t *testing.T) {
	now := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)

	t.Run("NilPolicy", func(t *testing.T) {
		if got := AuditTimeWindows(nil, now); len(got) != 0 {
			t.Errorf("expected 0 findings for nil policy, got %+v", got)
		}
	})

	t.Run("InvertedValidityWindow", func(t *testing.T) {
		policy := &SudoersPolicy{
			UserSpecs: []UserSpec{{
				UserList: []Member{{Username: "contractor"}},
				HostList: []Member{{Hostname: "app01"}},
				CmndSpecs: []CmndSpec{{
					RunasUsers: []Member{{Username: "deploy"}},
					Options: []Option{
						{"notbefore": "20270501000000Z"},
						{"notafter": "20270101000000Z"},
					},
					Commands: []Member{{Command: "/usr/bin/systemctl restart app"}},
				}},
				File: "/etc/sudoers.d/contractor",
				Line: 7,
			}},
		}
		findings := AuditTimeWindows(policy, now)
		if len(findings) != 1 {
			t.Fatalf("expected 1 finding for inverted window, got %d: %+v", len(findings), findings)
		}
		f := findings[0]
		if f.ID != "SUDO-CMD-016" || f.Severity != SeverityLow {
			t.Errorf("expected SUDO-CMD-016 LOW, got %s %s", f.ID, f.Severity)
		}
		if f.Title != "Inverted Sudoers Validity Window (NOTBEFORE > NOTAFTER)" {
			t.Errorf("unexpected title %q", f.Title)
		}
		if f.User != "contractor" || f.Host != "app01" || f.Runas != "deploy" || f.Command != "/usr/bin/systemctl restart app" {
			t.Errorf("unexpected context metadata: %+v", f)
		}
		if f.Context != "/etc/sudoers.d/contractor" || f.Line != 7 {
			t.Errorf("unexpected file/line: %s:%d", f.Context, f.Line)
		}
		if f.Remediation == "" || f.RemediationCode == "" {
			t.Errorf("expected non-empty Remediation and RemediationCode, got %+v", f)
		}
	})

	t.Run("ExpiredRule", func(t *testing.T) {
		policy := &SudoersPolicy{
			UserSpecs: []UserSpec{{
				UserList: []Member{{Username: "auditor"}},
				HostList: []Member{{Hostname: "ALL"}},
				CmndSpecs: []CmndSpec{{
					Options: []Option{
						{"notbefore": "20250101000000Z"},
						{"notafter": "20260101000000Z"},
					},
					Commands: []Member{{Command: "/usr/bin/journalctl -u ssh"}},
				}},
				File: "/etc/sudoers.d/temp",
				Line: 4,
			}},
		}
		findings := AuditTimeWindows(policy, now)
		if len(findings) != 1 {
			t.Fatalf("expected 1 finding for expired rule, got %d: %+v", len(findings), findings)
		}
		f := findings[0]
		if f.ID != "SUDO-CMD-016" || f.Severity != SeverityInfo {
			t.Errorf("expected SUDO-CMD-016 INFO, got %s %s", f.ID, f.Severity)
		}
		if f.Title != "Expired Temporary Sudoers Rule (NOTAFTER)" {
			t.Errorf("unexpected title %q", f.Title)
		}
		if f.Runas != "root" || f.Remediation == "" || f.RemediationCode == "" {
			t.Errorf("expected Runas=root and populated Remediation/RemediationCode, got %+v", f)
		}
	})

	t.Run("InvertedAndExpiredAndValidAndMalformed", func(t *testing.T) {
		policy := &SudoersPolicy{
			UserSpecs: []UserSpec{
				{
					// Both inverted and expired -> both findings emitted.
					UserList: []Member{{Username: "u1"}},
					HostList: []Member{{Hostname: "ALL"}},
					CmndSpecs: []CmndSpec{{
						Options: []Option{
							{"notbefore": "20250601000000Z"},
							{"notafter": "20250101000000Z"},
						},
						Commands: []Member{{Command: "/bin/date"}},
					}},
					File: "sudoers",
					Line: 1,
				},
				{
					// Valid active window -> 0 findings.
					UserList: []Member{{Username: "u2"}},
					HostList: []Member{{Hostname: "ALL"}},
					CmndSpecs: []CmndSpec{{
						Options: []Option{
							{"notbefore": "20260101000000Z"},
							{"notafter": "20270101000000Z"},
						},
						Commands: []Member{{Command: "/bin/date"}},
					}},
					File: "sudoers",
					Line: 2,
				},
				{
					// Malformed timestamps -> skipped safely.
					UserList: []Member{{Username: "u3"}},
					HostList: []Member{{Hostname: "ALL"}},
					CmndSpecs: []CmndSpec{{
						Options: []Option{
							{"notbefore": "not-a-timestamp"},
							{"notafter": "bad"},
						},
						Commands: []Member{{Command: "/bin/date"}},
					}},
					File: "sudoers",
					Line: 3,
				},
			},
		}
		findings := AuditTimeWindows(policy, now)
		if len(findings) != 2 {
			t.Fatalf("expected 2 findings (1 inverted + 1 expired), got %d: %+v", len(findings), findings)
		}
	})
}
