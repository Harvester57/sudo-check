package parser

import (
	"errors"
	"strings"
	"sudo-check/pkg/audit"
	"sudo-check/pkg/gtfobins"
	"testing"
	"testing/iotest"
)

func TestIsSudoLLOutput(t *testing.T) {
	tests := []struct {
		name string
		data string
		want bool
	}{
		{
			name: "FullSudoLL",
			data: `Matching Defaults entries for alice on prod-web-01:
    env_reset, mail_badpass

User alice may run the following commands on prod-web-01:

Sudoers entry:
    RunAsUsers: root
    Commands:
        /usr/bin/id
`,
			want: true,
		},
		{
			name: "DefaultsHeaderOnlyWithBOMAndCRLF",
			data: "\xef\xbb\xbfMatching Defaults entries for bob on app01:\r\n    env_reset\r\n",
			want: true,
		},
		{
			name: "UserCommandsHeaderOnly",
			data: "User deploy may run the following commands on web02:\n    (root) NOPASSWD: /usr/bin/systemctl restart nginx\n",
			want: true,
		},
		{
			name: "RawSudoers",
			data: "Defaults env_reset\nalice ALL=(ALL:ALL) NOPASSWD: ALL\n",
			want: false,
		},
		{
			name: "RawSudoersWithCommentMimickingHeader",
			data: "# Matching Defaults entries for alice on web01:\n# User alice may run the following commands on web01:\nDefaults env_reset\nalice ALL=(root) /usr/bin/id\n",
			want: false,
		},
		{
			name: "JSONPolicy",
			data: `{"Defaults": [{"Options": [{"env_reset": true}]}]}`,
			want: false,
		},
		{
			name: "LDIFPolicy",
			data: "dn: cn=web,ou=SUDOers,dc=example,dc=com\nobjectClass: sudoRole\nsudoUser: alice\nsudoCommand: /usr/bin/id\n",
			want: false,
		},
		{
			name: "DeniedOutputOnly",
			data: "Sorry, user alice may not run sudo on web01.\n",
			want: false,
		},
		{
			name: "Empty",
			data: "   \r\n\t  ",
			want: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsSudoLLOutput([]byte(tc.data)); got != tc.want {
				t.Errorf("IsSudoLLOutput() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestParseSudoLLDefaultsAndSource(t *testing.T) {
	t.Run("DefaultSourceAndMultiLineDefaults", func(t *testing.T) {
		input := "\xef\xbb\xbf" + strings.Join([]string{
			"Matching Defaults entries for alice on fe80::1:",
			"    env_reset, mail_badpass,",
			`    secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",`,
			`    env_keep+="LANG LC_ALL"`,
			"    !visiblepw, umask=0027",
		}, "\r\n")

		policy, err := ParseSudoLL(strings.NewReader(input), "")
		if err != nil {
			t.Fatalf("ParseSudoLL failed: %v", err)
		}
		if len(policy.Defaults) != 2 {
			t.Fatalf("expected 2 DefaultBindings, got %d: %+v", len(policy.Defaults), policy.Defaults)
		}

		d0 := policy.Defaults[0]
		if d0.File != "sudo-ll" || d0.Line != 2 {
			t.Errorf("first DefaultBinding File/Line = (%q, %d), want (%q, 2)", d0.File, d0.Line, "sudo-ll")
		}
		if len(d0.Options) != 4 {
			t.Fatalf("expected 4 options in first binding, got %d: %+v", len(d0.Options), d0.Options)
		}
		if d0.Options[0]["env_reset"] != true ||
			d0.Options[1]["mail_badpass"] != true ||
			d0.Options[2]["secure_path"] != "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" ||
			d0.Options[3]["operation"] != "list_add" {
			t.Errorf("unexpected first binding options: %+v", d0.Options)
		}

		d1 := policy.Defaults[1]
		if d1.File != "sudo-ll" || d1.Line != 5 {
			t.Errorf("second DefaultBinding File/Line = (%q, %d), want (%q, 5)", d1.File, d1.Line, "sudo-ll")
		}
		if d1.Options[0]["visiblepw"] != false || d1.Options[1]["umask"] != "0027" {
			t.Errorf("unexpected second binding options: %+v", d1.Options)
		}
	})

	t.Run("InlineDefaultsAndCustomSource", func(t *testing.T) {
		input := "Matching Defaults entries for bob on app01: env_reset, timestamp_timeout=5\n"
		policy, err := ParseSudoLL(strings.NewReader(input), "/var/tmp/bob.sudoll")
		if err != nil {
			t.Fatalf("ParseSudoLL failed: %v", err)
		}
		if len(policy.Defaults) != 1 {
			t.Fatalf("expected 1 DefaultBinding, got %d", len(policy.Defaults))
		}
		if policy.Defaults[0].File != "/var/tmp/bob.sudoll" || policy.Defaults[0].Line != 1 {
			t.Errorf("got File=%q Line=%d, want (/var/tmp/bob.sudoll, 1)", policy.Defaults[0].File, policy.Defaults[0].Line)
		}
		if policy.Defaults[0].Options[0]["env_reset"] != true || policy.Defaults[0].Options[1]["timestamp_timeout"] != "5" {
			t.Errorf("unexpected inline options: %+v", policy.Defaults[0].Options)
		}
	})
}

func TestParseSudoLLStanzasOptionsAndCommands(t *testing.T) {
	input := `Matching Defaults entries for alice on prod-web-01:
    env_reset, use_pty

User alice may run the following commands on prod-web-01:

Sudoers entry:
    RunAsUsers: root, %admin, #1000, ALL, !nobody
    RunAsGroups: wheel, %#200
    Options: role=sysadm_r, !authenticate, noexec, !setenv, sudoedit_follow, log_input, log_output, intercept, send_mail, runchroot=/var/chroot, runcwd=/opt/app, command_timeout=5m, notbefore=202501011200+0200, notafter=20260101000000Z, type=sysadm_t, apparmor_profile=unconfined, privs=all, limitprivs=all
    Commands:
        /usr/bin/systemctl restart nginx
        /bin/mount -o ro,noexec /dev/sda1 /mnt
        !/bin/sh
        sudoedit /etc/hosts
        sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 /usr/bin/id ""

Sudoers entry:
    RunAsUsers: (empty)
    Options: authenticate, !noexec, setenv, !sudoedit_follow
    Commands:
        ALL

LDAP Role: cn=deploy,ou=SUDOers,dc=example,dc=com
    RunAsUsers: ADMIN %dba
    NotBefore: 20250201000000Z
    NotAfter: 20260201000000Z
    Commands:
        ^/usr/bin/(vim|nano)$
`

	policy, err := ParseSudoLL(strings.NewReader(input), "host1.sudoll")
	if err != nil {
		t.Fatalf("ParseSudoLL failed: %v", err)
	}

	if len(policy.UserSpecs) != 3 {
		t.Fatalf("expected 3 UserSpecs, got %d", len(policy.UserSpecs))
	}

	// Verify first stanza
	s0 := policy.UserSpecs[0]
	if s0.File != "host1.sudoll" || s0.Line != 6 {
		t.Errorf("spec[0] File/Line = (%q, %d), want (host1.sudoll, 6)", s0.File, s0.Line)
	}
	if len(s0.UserList) != 1 || s0.UserList[0].Username != "alice" || s0.UserList[0].Line != 4 {
		t.Errorf("unexpected spec[0] UserList: %+v", s0.UserList)
	}
	if len(s0.HostList) != 1 || s0.HostList[0].Hostname != "prod-web-01" || s0.HostList[0].Line != 4 {
		t.Errorf("unexpected spec[0] HostList: %+v", s0.HostList)
	}
	cs0 := s0.CmndSpecs[0]
	if len(cs0.RunasUsers) != 5 {
		t.Fatalf("expected 5 RunasUsers, got %d: %+v", len(cs0.RunasUsers), cs0.RunasUsers)
	}
	if cs0.RunasUsers[0].Username != "root" ||
		cs0.RunasUsers[1].Usergroup != "admin" ||
		cs0.RunasUsers[2].UserID == nil || *cs0.RunasUsers[2].UserID != 1000 ||
		cs0.RunasUsers[3].Username != "ALL" ||
		cs0.RunasUsers[4].Username != "nobody" || !cs0.RunasUsers[4].Negated {
		t.Errorf("unexpected RunasUsers: %+v", cs0.RunasUsers)
	}
	if len(cs0.RunasGroups) != 2 ||
		cs0.RunasGroups[0].Usergroup != "wheel" ||
		cs0.RunasGroups[1].UserGID == nil || *cs0.RunasGroups[1].UserGID != 200 {
		t.Errorf("unexpected RunasGroups: %+v", cs0.RunasGroups)
	}

	// Verify canonical option ordering:
	// pre-tag (runchroot, runcwd, command_timeout, notbefore, notafter)
	// tags (authenticate, noexec, intercept, send_mail, setenv, sudoedit_follow, log_input, log_output)
	// post-tag (role, type, apparmor_profile, privs, limitprivs)
	wantOrder := []struct {
		key string
		val any
	}{
		{"runchroot", "/var/chroot"},
		{"runcwd", "/opt/app"},
		{"command_timeout", 300},
		{"notbefore", "20250101100000Z"},
		{"notafter", "20260101000000Z"},
		{"authenticate", false},
		{"noexec", true},
		{"intercept", true},
		{"send_mail", true},
		{"setenv", false},
		{"sudoedit_follow", true},
		{"log_input", true},
		{"log_output", true},
		{"role", "sysadm_r"},
		{"type", "sysadm_t"},
		{"apparmor_profile", "unconfined"},
		{"privs", "all"},
		{"limitprivs", "all"},
	}
	if len(cs0.Options) != len(wantOrder) {
		t.Fatalf("expected %d canonical options, got %d: %+v", len(wantOrder), len(cs0.Options), cs0.Options)
	}
	for i, w := range wantOrder {
		gotVal, ok := cs0.Options[i][w.key]
		if !ok || gotVal != w.val {
			t.Errorf("Options[%d] = %+v, want {%q: %v}", i, cs0.Options[i], w.key, w.val)
		}
	}

	if len(cs0.Commands) != 5 {
		t.Fatalf("expected 5 commands, got %d: %+v", len(cs0.Commands), cs0.Commands)
	}
	if cs0.Commands[0].Command != "/usr/bin/systemctl restart nginx" || cs0.Commands[0].Line != 11 {
		t.Errorf("cmd[0] = %+v", cs0.Commands[0])
	}
	if cs0.Commands[1].Command != "/bin/mount -o ro,noexec /dev/sda1 /mnt" {
		t.Errorf("cmd[1] = %+v", cs0.Commands[1])
	}
	if cs0.Commands[2].Command != "/bin/sh" || !cs0.Commands[2].Negated {
		t.Errorf("cmd[2] = %+v", cs0.Commands[2])
	}
	if cs0.Commands[3].Command != "sudoedit /etc/hosts" {
		t.Errorf("cmd[3] = %+v", cs0.Commands[3])
	}
	if cs0.Commands[4].Command != `/usr/bin/id ""` || len(cs0.Commands[4].SHA256) != 1 ||
		cs0.Commands[4].SHA256[0] != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		t.Errorf("cmd[4] = %+v", cs0.Commands[4])
	}

	// Verify second stanza: (empty) -> root, ALL
	cs1 := policy.UserSpecs[1].CmndSpecs[0]
	if len(cs1.RunasUsers) != 1 || cs1.RunasUsers[0].Username != "root" {
		t.Errorf("spec[1] (empty) RunasUsers = %+v, want root", cs1.RunasUsers)
	}
	if len(cs1.Commands) != 1 || cs1.Commands[0].Command != "ALL" {
		t.Errorf("spec[1] Commands = %+v, want ALL", cs1.Commands)
	}

	// Verify third stanza (LDAP Role): space-separated RunAsUsers, uppercase username not treated as alias
	cs2 := policy.UserSpecs[2].CmndSpecs[0]
	if len(cs2.RunasUsers) != 2 || cs2.RunasUsers[0].Username != "ADMIN" || cs2.RunasUsers[1].Usergroup != "dba" {
		t.Errorf("spec[2] RunasUsers = %+v", cs2.RunasUsers)
	}
	if len(cs2.Options) != 2 || cs2.Options[0]["notbefore"] != "20250201000000Z" || cs2.Options[1]["notafter"] != "20260201000000Z" {
		t.Errorf("spec[2] Options = %+v", cs2.Options)
	}
	if len(cs2.Commands) != 1 || cs2.Commands[0].Command != "^/usr/bin/(vim|nano)$" {
		t.Errorf("spec[2] Commands = %+v", cs2.Commands)
	}
}

func TestParseSudoLLVariationsAndSudoL(t *testing.T) {
	input := `Matching Defaults entries for ops on web01:
    env_reset

User ops may run the following commands on web01:
    (root) NOPASSWD: /usr/bin/systemctl restart nginx, /usr/bin/systemctl status nginx
    (ALL : ALL) ALL

Matching Defaults entries for readonly on db01:
    env_reset

Sorry, user readonly may not run sudo on db01.
`

	policy, err := ParseSudoLL(strings.NewReader(input), "sudo-l-mix")
	if err != nil {
		t.Fatalf("ParseSudoLL failed: %v", err)
	}
	if len(policy.Defaults) != 2 {
		t.Fatalf("expected 2 Defaults bindings, got %d", len(policy.Defaults))
	}
	if len(policy.UserSpecs) != 2 {
		t.Fatalf("expected 2 UserSpecs from sudo -l lines, got %d", len(policy.UserSpecs))
	}
	if policy.UserSpecs[0].CmndSpecs[0].Commands[0].Command != "/usr/bin/systemctl restart nginx" ||
		policy.UserSpecs[0].CmndSpecs[0].Commands[1].Command != "/usr/bin/systemctl status nginx" {
		t.Errorf("unexpected sudo -l parsed commands: %+v", policy.UserSpecs[0].CmndSpecs[0].Commands)
	}
	if policy.UserSpecs[1].CmndSpecs[0].Commands[0].Command != "ALL" {
		t.Errorf("unexpected sudo -l ALL command: %+v", policy.UserSpecs[1].CmndSpecs[0].Commands)
	}
}

func TestParseSudoLLWithAudit(t *testing.T) {
	input := `Matching Defaults entries for contractor on prod-app-01:
    !env_reset, env_keep+="LD_PRELOAD"

User contractor may run the following commands on prod-app-01:

Sudoers entry:
    RunAsUsers: root
    Options: !authenticate
    Commands:
        /usr/bin/vim /var/log/app.log
        sudoedit /etc/shadow

Sudoers entry:
    RunAsUsers: root
    Options: !authenticate, noexec
    Commands:
        /usr/bin/find /var/log -name "*.log"

Sudoers entry:
    RunAsUsers: ALL
    Options: !authenticate
    Commands:
        ALL
`

	policy, err := ParseSudoLL(strings.NewReader(input), "contractor.sudoll")
	if err != nil {
		t.Fatalf("ParseSudoLL failed: %v", err)
	}

	gtfoClient, err := gtfobins.NewClient()
	if err != nil {
		t.Fatalf("gtfobins.NewClient failed: %v", err)
	}

	findings := audit.RunAudit(policy, gtfoClient)
	ids := make(map[string]bool)
	for _, f := range findings {
		ids[f.ID] = true
		if f.RemediationCode == "" {
			t.Errorf("finding %s missing RemediationCode", f.ID)
		}
		if f.Context != "contractor.sudoll" {
			t.Errorf("finding %s Context = %q, want contractor.sudoll", f.ID, f.Context)
		}
	}

	expectedIDs := []string{
		"SUDO-DEF-011",  // !env_reset
		"SUDO-DEF-004",  // dangerous env_keep LD_PRELOAD
		"SUDO-CMD-003",  // ALL + NOPASSWD
		"SUDO-CMD-007",  // direct editor vim
		"SUDO-CMD-010",  // sudoedit /etc/shadow
		"SUDO-GTFO-002", // passwordless vim in GTFObins
		"SUDO-GTFO-003", // find mitigated by noexec
	}
	for _, id := range expectedIDs {
		if !ids[id] {
			t.Errorf("expected finding %s from audit of sudo -ll policy, got ids: %v", id, ids)
		}
	}
}

func TestParseSudoLLErrors(t *testing.T) {
	t.Run("NilReader", func(t *testing.T) {
		if _, err := ParseSudoLL(nil, ""); err == nil {
			t.Fatal("expected error for nil reader")
		}
	})

	t.Run("ReaderErrorWrapped", func(t *testing.T) {
		boom := errors.New("boom io")
		_, err := ParseSudoLL(iotest.ErrReader(boom), "broken")
		if !errors.Is(err, boom) {
			t.Fatalf("expected wrapped boom error, got %v", err)
		}
	})

	cases := []struct {
		name  string
		input string
	}{
		{
			name:  "Empty",
			input: "   \n\t ",
		},
		{
			name:  "RawSudoersRejected",
			input: "Defaults env_reset\nroot ALL=(ALL:ALL) ALL\n",
		},
		{
			name:  "StanzaMissingCommands",
			input: "User alice may run the following commands on host1:\n\nSudoers entry:\n    RunAsUsers: root\n    Options: !authenticate\n",
		},
		{
			name:  "StanzaBeforeHeader",
			input: "Sudoers entry:\n    RunAsUsers: root\n    Commands:\n        /bin/ls\n",
		},
		{
			name:  "InvalidTimeoutOption",
			input: "User alice may run the following commands on host1:\n\nSudoers entry:\n    Options: command_timeout=notanumber\n    Commands:\n        /bin/ls\n",
		},
		{
			name:  "NegatedAssignmentOption",
			input: "User alice may run the following commands on host1:\n\nSudoers entry:\n    Options: !runchroot=/tmp\n    Commands:\n        /bin/ls\n",
		},
		{
			name:  "BareBangOption",
			input: "User alice may run the following commands on host1:\n\nSudoers entry:\n    Options: !\n    Commands:\n        /bin/ls\n",
		},
		{
			name:  "TrailingCommaInDefaults",
			input: "Matching Defaults entries for alice on host1:\n    env_reset,\n\nUser alice may run the following commands on host1:\n",
		},
		{
			name:  "UnterminatedRegexInCommand",
			input: "User alice may run the following commands on host1:\n\nSudoers entry:\n    Commands:\n        ^/usr/bin/foo\n",
		},
		{
			name:  "UnexpectedGarbageLine",
			input: "User alice may run the following commands on host1:\n    not a valid command entry\n",
		},
		{
			name:  "NonIndentedDefaultsLine",
			input: "Matching Defaults entries for alice on host1:\nenv_reset\n",
		},
		{
			name:  "LineBeforeCommandsInStanza",
			input: "User alice may run the following commands on host1:\n\nSudoers entry:\n    /usr/bin/id\n",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseSudoLL(strings.NewReader(tc.input), "test.sudoll"); err == nil {
				t.Errorf("expected error for %s, got nil", tc.name)
			}
		})
	}
}

func TestParseSudoLLEdgeCases(t *testing.T) {
	input := `User svcuser may run the following commands on host2:

Sudoers entry:
    RunAsUsers: %:ad_admins, %:#1001, +net_runas, ""
    RunAsGroups: %:ad_grp, %:#2001, (empty)
    Options: NOPASSWD ! NOEXEC command_timeout=60 command_timeout=0 runchroot = "/var/my chroot" env_keep+=TERM
        !requiretty
    Commands: /usr/bin/id

User svcuser may run the following commands on host2:
    NOPASSWD: /bin/ls
    !/bin/sh
    sudoedit /etc/hosts
    ^/usr/bin/env$
    sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 /usr/bin/cat
`
	policy, err := ParseSudoLL(strings.NewReader(input), "edge.sudoll")
	if err != nil {
		t.Fatalf("ParseSudoLL edge cases failed: %v", err)
	}
	if len(policy.UserSpecs) != 6 {
		t.Fatalf("expected 6 UserSpecs, got %d", len(policy.UserSpecs))
	}

	cs0 := policy.UserSpecs[0].CmndSpecs[0]
	if len(cs0.RunasUsers) != 4 ||
		cs0.RunasUsers[0].NonUnixGroup != "ad_admins" ||
		cs0.RunasUsers[1].NonUnixGID == nil || *cs0.RunasUsers[1].NonUnixGID != 1001 ||
		cs0.RunasUsers[2].Netgroup != "net_runas" ||
		!cs0.RunasUsers[3].Myself {
		t.Errorf("unexpected RunasUsers: %+v", cs0.RunasUsers)
	}
	if len(cs0.RunasGroups) != 2 ||
		cs0.RunasGroups[0].NonUnixGroup != "ad_grp" ||
		cs0.RunasGroups[1].NonUnixGID == nil || *cs0.RunasGroups[1].NonUnixGID != 2001 {
		t.Errorf("unexpected RunasGroups: %+v", cs0.RunasGroups)
	}
	if len(cs0.Commands) != 1 || cs0.Commands[0].Command != "/usr/bin/id" {
		t.Errorf("unexpected inline Commands: %+v", cs0.Commands)
	}
	// Verify command_timeout=0 removed command_timeout and spaced runchroot = "/var/my chroot" parsed cleanly
	hasChroot := false
	for _, opt := range cs0.Options {
		if _, hasTimeout := opt["command_timeout"]; hasTimeout {
			t.Errorf("expected command_timeout=0 to clear command_timeout, got: %+v", cs0.Options)
		}
		if v, ok := opt["runchroot"].(string); ok && v == "/var/my chroot" {
			hasChroot = true
		}
	}
	if !hasChroot {
		t.Errorf("expected runchroot=/var/my chroot in options: %+v", cs0.Options)
	}
}
