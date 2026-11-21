package audit

import (
	"reflect"
	"slices"
	"sudo-check/pkg/gtfobins"
	"testing"
)

func explainTestIntPtr(v int) *int {
	return &v
}

func explainTestNewGTFO(t *testing.T) *gtfobins.Client {
	t.Helper()
	client, err := gtfobins.NewClient()
	if err != nil {
		t.Fatalf("failed to create gtfobins client: %v", err)
	}
	return client
}

func TestExplainPolicy_NilPolicyAndNilClient(t *testing.T) {
	q := PrincipalQuery{
		Username: "alice",
		Host:     "web01.example.com",
	}

	res := ExplainPolicy(nil, nil, q)
	if res == nil {
		t.Fatal("expected non-nil ExplainResult for nil policy")
	}
	if res.Query.Username != "alice" || res.Query.Host != "web01.example.com" {
		t.Errorf("expected Query preserved, got %+v", res.Query)
	}
	if res.EffectiveDefaults == nil || len(res.EffectiveDefaults) != 0 {
		t.Errorf("expected initialized empty EffectiveDefaults, got %#v", res.EffectiveDefaults)
	}
	if len(res.AllowedCommands) != 0 {
		t.Errorf("expected no AllowedCommands, got %#v", res.AllowedCommands)
	}
	if res.HighestRisk != SeverityInfo {
		t.Errorf("expected HighestRisk=%s, got %s", SeverityInfo, res.HighestRisk)
	}

	// Non-nil policy with nil gtfoClient should still classify ALL and dir execution.
	policy := &SudoersPolicy{
		UserSpecs: []UserSpec{
			{
				UserList: []Member{{Username: "alice"}},
				HostList: []Member{{Hostname: "ALL"}},
				CmndSpecs: []CmndSpec{
					{
						Options:  []Option{{"authenticate": false}},
						Commands: []Member{{Command: "ALL"}},
					},
					{
						Commands: []Member{{Command: "/usr/bin/"}},
					},
				},
			},
		},
	}

	resNilClient := ExplainPolicy(policy, nil, q)
	if len(resNilClient.AllowedCommands) != 2 {
		t.Fatalf("expected 2 allowed commands, got %d", len(resNilClient.AllowedCommands))
	}
	if !resNilClient.AllowedCommands[0].EscalationPath || !resNilClient.AllowedCommands[0].SetEnv {
		t.Errorf("expected ALL command to have EscalationPath=true and SetEnv=true, got %+v", resNilClient.AllowedCommands[0])
	}
	if !resNilClient.AllowedCommands[1].EscalationPath {
		t.Errorf("expected directory command to have EscalationPath=true, got %+v", resNilClient.AllowedCommands[1])
	}
	if resNilClient.HighestRisk != SeverityCritical {
		t.Errorf("expected HighestRisk=%s, got %s", SeverityCritical, resNilClient.HighestRisk)
	}
}

func TestExplainPolicy_UserMatchingAndAliases(t *testing.T) {
	gtfo := explainTestNewGTFO(t)

	policy := &SudoersPolicy{
		UserAliases: map[string][]Member{
			"OPS": {
				{Username: "alice"},
				{Username: "bob", Negated: true},
				{Usergroup: "sre"},
			},
			"UID_USERS": {
				{UserID: explainTestIntPtr(1050)},
				{UserGID: explainTestIntPtr(2050)},
			},
		},
		UserSpecs: []UserSpec{
			{
				UserList: []Member{{UserAlias: "OPS"}},
				HostList: []Member{{Hostname: "ALL"}},
				CmndSpecs: []CmndSpec{{
					Commands: []Member{{Command: `/usr/sbin/auditctl -s`}},
				}},
			},
			{
				UserList: []Member{{UserAlias: "UID_USERS"}},
				HostList: []Member{{Hostname: "ALL"}},
				CmndSpecs: []CmndSpec{{
					Commands: []Member{{Command: `/usr/bin/id ""`}},
				}},
			},
			{
				// Last-match-wins user negation: ALL except %wheel, unless explicit charlie.
				UserList: []Member{
					{Username: "ALL"},
					{Usergroup: "wheel", Negated: true},
					{Username: "charlie"},
				},
				HostList: []Member{{Hostname: "ALL"}},
				CmndSpecs: []CmndSpec{{
					Commands: []Member{{Command: `/usr/bin/uptime ""`}},
				}},
			},
			{
				// Negated alias flips inner negations: !OPS negates alice and %sre, un-negates bob.
				UserList: []Member{
					{UserAlias: "OPS", Negated: true},
				},
				HostList: []Member{{Hostname: "ALL"}},
				CmndSpecs: []CmndSpec{{
					Commands: []Member{{Command: `/usr/bin/whoami ""`}},
				}},
			},
		},
	}

	tests := []struct {
		name         string
		query        PrincipalQuery
		wantCommands []string
		wantRisk     Severity
	}{
		{
			name:         "AliceMatchesOPSAndLastMatchALL",
			query:        PrincipalQuery{Username: "alice", Host: "web01"},
			wantCommands: []string{`/usr/sbin/auditctl -s`, `/usr/bin/uptime ""`},
			wantRisk:     SeverityLow,
		},
		{
			name:         "BobNegatedInOPSButPositiveViaNegatedAlias",
			query:        PrincipalQuery{Username: "bob", Host: "web01"},
			wantCommands: []string{`/usr/bin/uptime ""`, `/usr/bin/whoami ""`},
			wantRisk:     SeverityLow,
		},
		{
			name:         "GroupWithLeadingPercentStripped",
			query:        PrincipalQuery{Username: "diana", Groups: []string{"%sre"}, Host: "web01"},
			wantCommands: []string{`/usr/sbin/auditctl -s`, `/usr/bin/uptime ""`},
			wantRisk:     SeverityLow,
		},
		{
			name:         "UIDMatch",
			query:        PrincipalQuery{Username: "svc", UID: explainTestIntPtr(1050), Host: "web01"},
			wantCommands: []string{`/usr/bin/id ""`, `/usr/bin/uptime ""`},
			wantRisk:     SeverityLow,
		},
		{
			name:         "GIDMatch",
			query:        PrincipalQuery{Username: "svc2", GIDs: []int{2050}, Host: "web01"},
			wantCommands: []string{`/usr/bin/id ""`, `/usr/bin/uptime ""`},
			wantRisk:     SeverityLow,
		},
		{
			name:         "WheelExcludedByNegation",
			query:        PrincipalQuery{Username: "dave", Groups: []string{"wheel"}, Host: "web01"},
			wantCommands: []string{},
			wantRisk:     SeverityInfo,
		},
		{
			name:         "CharlieReIncludedAfterWheelNegation",
			query:        PrincipalQuery{Username: "charlie", Groups: []string{"wheel"}, Host: "web01"},
			wantCommands: []string{`/usr/bin/uptime ""`},
			wantRisk:     SeverityLow,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res := ExplainPolicy(policy, gtfo, tc.query)
			var got []string
			for _, cmd := range res.AllowedCommands {
				got = append(got, cmd.Command)
			}
			if len(got) == 0 && len(tc.wantCommands) == 0 {
				if res.HighestRisk != tc.wantRisk {
					t.Fatalf("expected HighestRisk=%s, got %s", tc.wantRisk, res.HighestRisk)
				}
				return
			}
			if !reflect.DeepEqual(got, tc.wantCommands) {
				t.Errorf("got commands %v, want %v", got, tc.wantCommands)
			}
			if res.HighestRisk != tc.wantRisk {
				t.Errorf("expected HighestRisk=%s, got %s", tc.wantRisk, res.HighestRisk)
			}
		})
	}
}

func TestExplainPolicy_HostMatchingCIDRAndNetmask(t *testing.T) {
	policy := &SudoersPolicy{
		HostAliases: map[string][]Member{
			"PROD_NET": {
				{NetworkAddr: "10.20.0.0/16"},
				{NetworkAddr: "10.20.99.0/24", Negated: true},
			},
		},
		UserSpecs: []UserSpec{
			{
				UserList: []Member{{Username: "alice"}},
				HostList: []Member{{Hostname: "ALL"}},
				CmndSpecs: []CmndSpec{{
					Commands: []Member{{Command: `/bin/cmd_all`}},
				}},
			},
			{
				UserList: []Member{{Username: "alice"}},
				HostList: []Member{{Hostname: "web01"}},
				CmndSpecs: []CmndSpec{{
					Commands: []Member{{Command: `/bin/cmd_short`}},
				}},
			},
			{
				UserList: []Member{{Username: "alice"}},
				HostList: []Member{{Hostname: "*.prod.example.com"}},
				CmndSpecs: []CmndSpec{{
					Commands: []Member{{Command: `/bin/cmd_glob_fqdn`}},
				}},
			},
			{
				UserList: []Member{{Username: "alice"}},
				HostList: []Member{{Hostname: "web0?"}},
				CmndSpecs: []CmndSpec{{
					Commands: []Member{{Command: `/bin/cmd_glob_short`}},
				}},
			},
			{
				UserList: []Member{{Username: "alice"}},
				HostList: []Member{{HostAlias: "PROD_NET"}},
				CmndSpecs: []CmndSpec{{
					Commands: []Member{{Command: `/bin/cmd_cidr`}},
				}},
			},
			{
				UserList: []Member{{Username: "alice"}},
				HostList: []Member{{NetworkAddr: "192.168.10.0/255.255.255.0"}},
				CmndSpecs: []CmndSpec{{
					Commands: []Member{{Command: `/bin/cmd_netmask`}},
				}},
			},
			{
				UserList: []Member{{Username: "alice"}},
				HostList: []Member{{NetworkAddr: "fd00:abcd::/32"}},
				CmndSpecs: []CmndSpec{{
					Commands: []Member{{Command: `/bin/cmd_ipv6`}},
				}},
			},
			{
				UserList: []Member{{Username: "alice"}},
				HostList: []Member{{NetworkAddr: "172.16.1.5"}},
				CmndSpecs: []CmndSpec{{
					Commands: []Member{{Command: `/bin/cmd_exact_ip`}},
				}},
			},
		},
	}

	t.Run("EmptyHostMatchesOnlyALL", func(t *testing.T) {
		res := ExplainPolicy(policy, nil, PrincipalQuery{Username: "alice"})
		if len(res.AllowedCommands) != 1 || res.AllowedCommands[0].Command != "/bin/cmd_all" {
			t.Errorf("expected only /bin/cmd_all for empty host, got %+v", res.AllowedCommands)
		}
	})

	t.Run("FQDNShortnameGlobsAndCIDR", func(t *testing.T) {
		res := ExplainPolicy(policy, nil, PrincipalQuery{
			Username: "alice",
			Host:     "WEB01.prod.example.com",
			HostIPs:  []string{"10.20.1.5", "fd00:abcd::42"},
		})
		var got []string
		for _, c := range res.AllowedCommands {
			got = append(got, c.Command)
		}
		want := []string{
			"/bin/cmd_all",
			"/bin/cmd_short",
			"/bin/cmd_glob_fqdn",
			"/bin/cmd_glob_short",
			"/bin/cmd_cidr",
			"/bin/cmd_ipv6",
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("NegatedSubnetAndNetmaskAndIPInHostField", func(t *testing.T) {
		res := ExplainPolicy(policy, nil, PrincipalQuery{
			Username: "alice",
			Host:     "172.16.1.5",
			HostIPs:  []string{"10.20.99.10", "192.168.10.25"},
		})
		var got []string
		for _, c := range res.AllowedCommands {
			got = append(got, c.Command)
		}
		want := []string{
			"/bin/cmd_all",
			"/bin/cmd_netmask",
			"/bin/cmd_exact_ip",
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})
}

func TestExplainPolicy_DefaultsPrecedenceAndSetEnv(t *testing.T) {
	policy := &SudoersPolicy{
		Defaults: []DefaultBinding{
			{
				Options: []Option{
					{"env_reset": true},
					{"use_pty": true},
					{"noexec": true},
					{"authenticate": true},
					{"setenv": false},
					{"timestamp_timeout": 5},
					{"secure_path": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"},
					{"operation": "list_assign", "env_keep": []any{"LANG", "TERM"}},
				},
			},
			{
				Binding: []Member{{Hostname: "web01"}},
				Options: []Option{
					{"authenticate": false},
					{"operation": "list_add", "env_keep": []any{"LC_ALL"}},
				},
			},
			{
				Binding: []Member{{Hostname: "otherhost"}},
				Options: []Option{
					{"visiblepw": true},
				},
			},
			{
				Binding: []Member{{Username: "alice"}},
				Options: []Option{
					{"authenticate": true}, // User overrides Host
					{"operation": "list_remove", "env_keep": []any{"TERM"}},
				},
			},
			{
				Binding: []Member{{Username: "bob"}},
				Options: []Option{
					{"env_reset": false},
				},
			},
			{
				Binding: []Member{{Username: "postgres"}},
				Options: []Option{
					{"setenv": true},
				},
			},
			{
				Binding: []Member{{Command: "/usr/bin/cat"}},
				Options: []Option{
					{"noexec": false},
				},
			},
		},
		UserSpecs: []UserSpec{
			{
				UserList: []Member{{Username: "alice"}},
				HostList: []Member{{Hostname: "web01.example.com"}},
				CmndSpecs: []CmndSpec{
					{
						RunasUsers: []Member{{Username: "postgres"}},
						Commands:   []Member{{Command: `/usr/bin/cat /etc/motd`}},
					},
					{
						RunasUsers: []Member{{Username: "root"}},
						Options:    []Option{{"authenticate": false}, {"noexec": true}},
						Commands:   []Member{{Command: "ALL"}},
					},
					{
						RunasUsers: []Member{{Username: "www-data"}},
						Options:    []Option{{"setenv": false}},
						Commands:   []Member{{Command: "ALL"}},
					},
				},
				File: "/etc/sudoers",
				Line: 42,
			},
		},
	}

	// Ensure Runas binding for postgres uses scopeRunas (RunasAlias or > syntax).
	policy.Defaults[5].Binding = []Member{{RunasAlias: "PG_RUNAS"}}
	policy.RunasAliases = map[string][]Member{
		"PG_RUNAS": {{Username: "postgres"}},
	}

	res := ExplainPolicy(policy, nil, PrincipalQuery{
		Username: "alice",
		Host:     "web01.example.com",
	})

	if res.EffectiveDefaults["use_pty"] != true {
		t.Errorf("expected use_pty=true, got %#v", res.EffectiveDefaults["use_pty"])
	}
	if res.EffectiveDefaults["authenticate"] != true {
		t.Errorf("expected user Defaults to override host Defaults for authenticate=true, got %#v", res.EffectiveDefaults["authenticate"])
	}
	if _, leaked := res.EffectiveDefaults["visiblepw"]; leaked {
		t.Errorf("did not expect Defaults@otherhost visiblepw in EffectiveDefaults")
	}
	if res.EffectiveDefaults["timestamp_timeout"] != float64(5) {
		t.Errorf("expected numeric timestamp_timeout=5, got %#v", res.EffectiveDefaults["timestamp_timeout"])
	}
	if res.EffectiveDefaults["secure_path"] != "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" {
		t.Errorf("unexpected secure_path: %#v", res.EffectiveDefaults["secure_path"])
	}
	gotKeep, ok := res.EffectiveDefaults["env_keep"].([]string)
	if !ok || !reflect.DeepEqual(gotKeep, []string{"LANG", "LC_ALL"}) {
		t.Errorf("expected env_keep=[LANG LC_ALL], got %#v", res.EffectiveDefaults["env_keep"])
	}

	if len(res.AllowedCommands) != 3 {
		t.Fatalf("expected 3 allowed commands, got %d", len(res.AllowedCommands))
	}

	// 1. /usr/bin/cat /etc/motd as postgres: Runas sets SetEnv=true, Command sets NoExec=false, User keeps NoPasswd=false
	c0 := res.AllowedCommands[0]
	if c0.Runas != "postgres" || c0.NoPasswd || c0.NoExec || !c0.SetEnv {
		t.Errorf("unexpected flags for cat command: %+v", c0)
	}
	if c0.SourceFile != "/etc/sudoers" || c0.Line != 42 {
		t.Errorf("expected SourceFile=/etc/sudoers Line=42, got %s:%d", c0.SourceFile, c0.Line)
	}

	// 2. ALL as root: CmndSpec NOPASSWD + NOEXEC, implicit SetEnv=true
	c1 := res.AllowedCommands[1]
	if c1.Runas != "root" || !c1.NoPasswd || !c1.NoExec || !c1.SetEnv || !c1.EscalationPath {
		t.Errorf("unexpected flags for root ALL: %+v", c1)
	}

	// 3. NOSETENV: ALL as www-data: explicit SetEnv=false
	c2 := res.AllowedCommands[2]
	if c2.Runas != "www-data" || c2.SetEnv || !c2.EscalationPath {
		t.Errorf("expected NOSETENV: ALL to have SetEnv=false and EscalationPath=true, got %+v", c2)
	}
}

func TestExplainPolicy_GTFObinsMitigationAndCommandLastMatchWins(t *testing.T) {
	gtfo := explainTestNewGTFO(t)

	t.Run("MitigatedShellOnlyBinary", func(t *testing.T) {
		policy := &SudoersPolicy{
			Defaults: []DefaultBinding{{Options: []Option{{"noexec": true}}}},
			UserSpecs: []UserSpec{{
				UserList: []Member{{Username: "alice"}},
				HostList: []Member{{Hostname: "ALL"}},
				CmndSpecs: []CmndSpec{{
					Options:  []Option{{"authenticate": false}},
					Commands: []Member{{Command: `/usr/bin/chrt ""`}},
				}},
			}},
		}
		res := ExplainPolicy(policy, gtfo, PrincipalQuery{Username: "alice", Host: "web01"})
		if len(res.AllowedCommands) != 1 {
			t.Fatalf("expected 1 allowed command, got %d", len(res.AllowedCommands))
		}
		ec := res.AllowedCommands[0]
		if len(ec.GTFOBinsRisk) == 0 {
			t.Fatalf("expected GTFOBinsRisk populated for chrt")
		}
		if ec.EscalationPath {
			t.Errorf("expected EscalationPath=false when shell-only non-immune binary has NOEXEC")
		}
		if res.HighestRisk != SeverityLow {
			t.Errorf("expected HighestRisk=%s for mitigated GTFObins, got %s", SeverityLow, res.HighestRisk)
		}
	})

	t.Run("NoexecImmuneAndVersionedAndRegexBinaries", func(t *testing.T) {
		policy := &SudoersPolicy{
			Defaults: []DefaultBinding{{Options: []Option{{"noexec": true}}}},
			UserSpecs: []UserSpec{
				{
					UserList: []Member{{Username: "alice"}},
					HostList: []Member{{Hostname: "ALL"}},
					CmndSpecs: []CmndSpec{{
						Commands: []Member{{Command: `/bin/bash ""`}},
					}},
				},
				{
					UserList: []Member{{Username: "bob"}},
					HostList: []Member{{Hostname: "ALL"}},
					CmndSpecs: []CmndSpec{{
						Options:  []Option{{"authenticate": false}},
						Commands: []Member{{Command: `/usr/bin/python3.11 /opt/task.py`}},
					}},
				},
				{
					UserList: []Member{{Username: "carol"}},
					HostList: []Member{{Hostname: "ALL"}},
					CmndSpecs: []CmndSpec{{
						Commands: []Member{{Command: `^/usr/bin/(vim|nano)$`}},
					}},
				},
			},
		}

		resAlice := ExplainPolicy(policy, gtfo, PrincipalQuery{Username: "alice", Host: "app01"})
		if len(resAlice.AllowedCommands) != 1 || !resAlice.AllowedCommands[0].EscalationPath {
			t.Errorf("expected bash to be unmitigated EscalationPath under NOEXEC, got %+v", resAlice.AllowedCommands)
		}
		if resAlice.HighestRisk != SeverityHigh {
			t.Errorf("expected HighestRisk=%s, got %s", SeverityHigh, resAlice.HighestRisk)
		}

		resBob := ExplainPolicy(policy, gtfo, PrincipalQuery{Username: "bob", Host: "app01"})
		if len(resBob.AllowedCommands) != 1 || !resBob.AllowedCommands[0].EscalationPath || len(resBob.AllowedCommands[0].GTFOBinsRisk) == 0 {
			t.Errorf("expected python3.11 to normalize and set EscalationPath=true, got %+v", resBob.AllowedCommands)
		}
		if resBob.HighestRisk != SeverityCritical {
			t.Errorf("expected HighestRisk=%s for NOPASSWD unmitigated GTFObins, got %s", SeverityCritical, resBob.HighestRisk)
		}

		resCarol := ExplainPolicy(policy, gtfo, PrincipalQuery{Username: "carol", Host: "app01"})
		if len(resCarol.AllowedCommands) != 1 || !resCarol.AllowedCommands[0].EscalationPath || len(resCarol.AllowedCommands[0].GTFOBinsRisk) == 0 {
			t.Errorf("expected regex vim|nano to match GTFObins and set EscalationPath=true, got %+v", resCarol.AllowedCommands)
		}
	})

	t.Run("DeniedCommandsAndLastMatchWins", func(t *testing.T) {
		policy := &SudoersPolicy{
			UserSpecs: []UserSpec{
				{
					UserList: []Member{{Username: "alice"}},
					HostList: []Member{{Hostname: "ALL"}},
					CmndSpecs: []CmndSpec{{
						Options: []Option{{"authenticate": false}},
						Commands: []Member{
							{Command: "ALL"},
							{Command: "/usr/bin/passwd", Negated: true},
							{Command: "/usr/bin/vim"},
						},
					}},
				},
				{
					UserList: []Member{{Username: "alice"}},
					HostList: []Member{{Hostname: "ALL"}},
					CmndSpecs: []CmndSpec{
						{
							Commands: []Member{{Command: "/usr/bin/vim", Negated: true}},
						},
						{
							RunasUsers: []Member{{Username: "www-data"}},
							Commands:   []Member{{Command: "/usr/bin/id"}},
						},
					},
				},
			},
		}

		res := ExplainPolicy(policy, gtfo, PrincipalQuery{Username: "alice", Host: "web01"})
		var allowedCmds []string
		for _, c := range res.AllowedCommands {
			allowedCmds = append(allowedCmds, c.Command+"@"+c.Runas)
		}
		if slices.Contains(allowedCmds, "/usr/bin/vim@root") {
			t.Errorf("expected /usr/bin/vim@root to be removed by later negation, got %v", allowedCmds)
		}
		if !slices.Contains(allowedCmds, "ALL@root") || !slices.Contains(allowedCmds, "/usr/bin/id@www-data") {
			t.Errorf("expected ALL@root and /usr/bin/id@www-data in allowed, got %v", allowedCmds)
		}
		if !slices.Contains(res.DeniedCommands, "/usr/bin/passwd") || !slices.Contains(res.DeniedCommands, "/usr/bin/vim") {
			t.Errorf("expected denied commands to contain passwd and vim, got %v", res.DeniedCommands)
		}
		if res.HighestRisk != SeverityCritical {
			t.Errorf("expected HighestRisk=%s due to NOPASSWD ALL, got %s", SeverityCritical, res.HighestRisk)
		}
	})

	t.Run("LaterNegationRemovesAllAllowed", func(t *testing.T) {
		policy := &SudoersPolicy{
			UserSpecs: []UserSpec{
				{
					UserList: []Member{{Username: "alice"}},
					HostList: []Member{{Hostname: "ALL"}},
					CmndSpecs: []CmndSpec{{
						Commands: []Member{{Command: "/usr/bin/vim"}},
					}},
				},
				{
					UserList: []Member{{Username: "alice"}},
					HostList: []Member{{Hostname: "ALL"}},
					CmndSpecs: []CmndSpec{{
						Commands: []Member{{Command: "/usr/bin/vim", Negated: true}},
					}},
				},
			},
		}
		res := ExplainPolicy(policy, gtfo, PrincipalQuery{Username: "alice", Host: "web01"})
		if len(res.AllowedCommands) != 0 {
			t.Errorf("expected 0 allowed commands, got %+v", res.AllowedCommands)
		}
		if !reflect.DeepEqual(res.DeniedCommands, []string{"/usr/bin/vim"}) {
			t.Errorf("expected denied [/usr/bin/vim], got %v", res.DeniedCommands)
		}
		if res.HighestRisk != SeverityInfo {
			t.Errorf("expected HighestRisk=%s when no commands allowed, got %s", SeverityInfo, res.HighestRisk)
		}
	})
}
