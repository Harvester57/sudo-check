package parser

import (
	"encoding/base64"
	"errors"
	"strings"
	"sudo-check/pkg/audit"
	"sudo-check/pkg/gtfobins"
	"testing"
	"testing/iotest"
)

func TestIsLDIFPolicy(t *testing.T) {
	b64Role := base64.StdEncoding.EncodeToString([]byte("sudoRole"))
	b64Cmd := base64.StdEncoding.EncodeToString([]byte("/usr/bin/id"))

	tests := []struct {
		name string
		data string
		want bool
	}{
		{
			name: "StandardSudoRole",
			data: "version: 1\ndn: cn=ops,ou=SUDOers,dc=example,dc=com\nobjectClass: top\nOBJECTCLASS: SUDOROLE\ncn: ops\nsudoUser: alice\nsudoCommand: /usr/bin/id\n",
			want: true,
		},
		{
			name: "FoldedObjectClass",
			data: "dn: cn=ops,ou=SUDOers,dc=example,dc=com\nobjectClass: sudo\n Role\n",
			want: true,
		},
		{
			name: "Base64ObjectClass",
			data: "dn: cn=ops,ou=SUDOers,dc=example,dc=com\nobjectClass:: " + b64Role + "\n",
			want: true,
		},
		{
			name: "Base64CommandWithoutObjectClass",
			data: "dn: cn=ops,ou=SUDOers,dc=example,dc=com\nsudoUser: alice\nsudoCommand:: " + b64Cmd + "\n",
			want: true,
		},
		{
			name: "DefaultsOptionOnly",
			data: "dn: cn=defaults,ou=SUDOers,dc=example,dc=com\ncn: defaults\nsudoOption: env_reset\n",
			want: true,
		},
		{
			name: "RawSudoersWithComment",
			data: "# objectClass: sudoRole\n# sudoCommand: /bin/ls\nDefaults env_reset\nalice ALL=(root) NOPASSWD: /bin/ls\n",
			want: false,
		},
		{
			name: "SudoLLOutput",
			data: "Matching Defaults entries for alice on host1:\n    env_reset\n\nUser alice may run the following commands on host1:\n\nSudoers entry:\n    RunAsUsers: root\n    Commands:\n        /bin/ls\n",
			want: false,
		},
		{
			name: "JSONPolicy",
			data: `{"User_Specs": []}`,
			want: false,
		},
		{
			name: "NonSudoLDIF",
			data: "dn: ou=People,dc=example,dc=com\nobjectClass: organizationalUnit\nou: People\n",
			want: false,
		},
		{
			name: "Empty",
			data: "  \r\n ",
			want: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsLDIFPolicy([]byte(tc.data)); got != tc.want {
				t.Errorf("IsLDIFPolicy() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestParseLDIFDefaultsAndRoles(t *testing.T) {
	b64User := base64.StdEncoding.EncodeToString([]byte("alice"))
	b64Cmd := base64.StdEncoding.EncodeToString([]byte("/usr/bin/systemctl restart nginx"))
	b64Opt := base64.StdEncoding.EncodeToString([]byte("env_keep+=TERM"))

	// Folded lines, comments, base64, container OU entry, cn: defaults, and sudoRole variations.
	ldifInput := "\xef\xbb\xbf" + strings.Join([]string{
		"version: 1",
		"# Container OU should be ignored",
		"dn: ou=SUDOers,dc=example,dc=com",
		"objectClass: top",
		"objectClass: organizationalUnit",
		"ou: SUDOers",
		"",
		"# Global defaults",
		"dn: cn=defaults,ou=SUDOers,dc=example,dc=com",
		"objectClass: top",
		"objectClass: sudoRole",
		"CN: DEFAULTS",
		"sudoOption: env_reset",
		"sudoOption: !visiblepw",
		`sudoOption: secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"`,
		"sudoOption:: " + b64Opt,
		"",
		"# Role with rich users, hosts, runas, options, timestamps, and folded command",
		"dn: cn=webops,ou=SUDOers,dc=example,dc=com",
		"objectClass: sudoRole",
		"cn;lang-en: webops",
		"sudoUser:: " + b64User[:3],
		" " + b64User[3:],
		"sudoUser: %wheel",
		"sudoUser: %#1000",
		"sudoUser: #500",
		"sudoUser: +net_ops",
		"sudoUser: !bob",
		"sudoHost: 10.0.0.0/8",
		"sudoHost: 192.168.1.10",
		"sudoHost: !db01.example.com",
		"sudoHost: +web_hosts",
		"sudoHost: web01.example.com",
		"sudoRunAsUser: root",
		"sudoRunAs: ADMIN",
		"sudoRunAsGroup: adm",
		"sudoOption: !authenticate",
		"sudoOption: noexec",
		"sudoOption: !setenv",
		"sudoOption: runchroot=/srv/jail",
		"sudoOption: command_timeout=10m",
		"sudoOption: role=sysadm_r",
		"sudoNotBefore: 202501011200+0200",
		"sudoNotAfter: 20260101000000Z",
		"sudoCommand:: " + b64Cmd,
		"sudoCommand: /bin/echo",
		"  hello world",
		"sudoCommand: !/bin/sh",
		"sudoCommand: sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 /usr/bin/id",
		"",
		"# Role omitting sudoHost should default HostList to ALL",
		"dn: cn=minimal,ou=SUDOers,dc=example,dc=com",
		"objectClass: sudoRole",
		"cn: minimal",
		"sudoUser: ALL",
		"sudoCommand: sudoedit /etc/hosts",
	}, "\r\n")

	policy, err := ParseLDIF(strings.NewReader(ldifInput), "")
	if err != nil {
		t.Fatalf("ParseLDIF failed: %v", err)
	}

	if len(policy.Defaults) != 1 {
		t.Fatalf("expected 1 DefaultBinding, got %d", len(policy.Defaults))
	}
	def := policy.Defaults[0]
	if def.File != "ldif" || def.Line != 9 {
		t.Errorf("DefaultBinding File/Line = (%q, %d), want (ldif, 9)", def.File, def.Line)
	}
	if len(def.Options) != 4 ||
		def.Options[0]["env_reset"] != true ||
		def.Options[1]["visiblepw"] != false ||
		def.Options[2]["secure_path"] != "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" ||
		def.Options[3]["operation"] != "list_add" {
		t.Errorf("unexpected DefaultBinding options: %+v", def.Options)
	}

	if len(policy.UserSpecs) != 2 {
		t.Fatalf("expected 2 UserSpecs, got %d", len(policy.UserSpecs))
	}

	spec0 := policy.UserSpecs[0]
	if spec0.File != "ldif" || spec0.Line != 19 {
		t.Errorf("spec0 File/Line = (%q, %d), want (ldif, 19)", spec0.File, spec0.Line)
	}
	if len(spec0.UserList) != 6 {
		t.Fatalf("expected 6 users in spec0, got %d: %+v", len(spec0.UserList), spec0.UserList)
	}
	if spec0.UserList[0].Username != "alice" ||
		spec0.UserList[1].Usergroup != "wheel" ||
		spec0.UserList[2].UserGID == nil || *spec0.UserList[2].UserGID != 1000 ||
		spec0.UserList[3].UserID == nil || *spec0.UserList[3].UserID != 500 ||
		spec0.UserList[4].Netgroup != "net_ops" ||
		spec0.UserList[5].Username != "bob" || !spec0.UserList[5].Negated {
		t.Errorf("unexpected spec0 UserList: %+v", spec0.UserList)
	}

	if len(spec0.HostList) != 5 {
		t.Fatalf("expected 5 hosts in spec0, got %d: %+v", len(spec0.HostList), spec0.HostList)
	}
	if spec0.HostList[0].NetworkAddr != "10.0.0.0/8" ||
		spec0.HostList[1].NetworkAddr != "192.168.1.10" ||
		spec0.HostList[2].Hostname != "db01.example.com" || !spec0.HostList[2].Negated ||
		spec0.HostList[3].Netgroup != "web_hosts" ||
		spec0.HostList[4].Hostname != "web01.example.com" {
		t.Errorf("unexpected spec0 HostList: %+v", spec0.HostList)
	}

	cs0 := spec0.CmndSpecs[0]
	if len(cs0.RunasUsers) != 2 || cs0.RunasUsers[0].Username != "root" || cs0.RunasUsers[1].Username != "ADMIN" {
		t.Errorf("unexpected RunasUsers: %+v", cs0.RunasUsers)
	}
	if len(cs0.RunasGroups) != 1 || cs0.RunasGroups[0].Usergroup != "adm" {
		t.Errorf("unexpected RunasGroups: %+v", cs0.RunasGroups)
	}

	wantOpts := []struct {
		key string
		val any
	}{
		{"runchroot", "/srv/jail"},
		{"command_timeout", 600},
		{"notbefore", "20250101100000Z"},
		{"notafter", "20260101000000Z"},
		{"authenticate", false},
		{"noexec", true},
		{"setenv", false},
		{"role", "sysadm_r"},
	}
	if len(cs0.Options) != len(wantOpts) {
		t.Fatalf("expected %d options, got %d: %+v", len(wantOpts), len(cs0.Options), cs0.Options)
	}
	for i, w := range wantOpts {
		if cs0.Options[i][w.key] != w.val {
			t.Errorf("Options[%d] = %+v, want {%q: %v}", i, cs0.Options[i], w.key, w.val)
		}
	}

	if len(cs0.Commands) != 4 {
		t.Fatalf("expected 4 commands, got %d: %+v", len(cs0.Commands), cs0.Commands)
	}
	if cs0.Commands[0].Command != "/usr/bin/systemctl restart nginx" || cs0.Commands[0].Line != 19 {
		t.Errorf("cmd[0] = %+v", cs0.Commands[0])
	}
	if cs0.Commands[1].Command != "/bin/echo hello world" {
		t.Errorf("cmd[1] (two-space RFC2849 fold) = %+v", cs0.Commands[1])
	}
	if cs0.Commands[2].Command != "/bin/sh" || !cs0.Commands[2].Negated {
		t.Errorf("cmd[2] = %+v", cs0.Commands[2])
	}
	if cs0.Commands[3].Command != "/usr/bin/id" || len(cs0.Commands[3].SHA256) != 1 {
		t.Errorf("cmd[3] = %+v", cs0.Commands[3])
	}

	// Verify omitted sudoHost defaults to ALL
	spec1 := policy.UserSpecs[1]
	if len(spec1.HostList) != 1 || spec1.HostList[0].Hostname != "ALL" {
		t.Errorf("expected omitted sudoHost to default to ALL, got %+v", spec1.HostList)
	}
	if spec1.CmndSpecs[0].Commands[0].Command != "sudoedit /etc/hosts" {
		t.Errorf("spec1 command = %+v", spec1.CmndSpecs[0].Commands)
	}
}

func TestParseLDIFOrderSorting(t *testing.T) {
	ldifInput := `dn: cn=order30,ou=SUDOers,dc=example,dc=com
objectClass: sudoRole
sudoUser: user30
sudoCommand: /usr/bin/id
sudoOrder: 30

dn: cn=defaultZeroA,ou=SUDOers,dc=example,dc=com
objectClass: sudoRole
sudoUser: user0a
sudoCommand: /usr/bin/id

dn: cn=negative,ou=SUDOers,dc=example,dc=com
objectClass: sudoRole
sudoUser: userNeg
sudoCommand: /usr/bin/id
sudoOrder: -5

dn: cn=defaultZeroB,ou=SUDOers,dc=example,dc=com
objectClass: sudoRole
sudoUser: user0b
sudoCommand: /usr/bin/id
sudoOrder: 0

dn: cn=order10,ou=SUDOers,dc=example,dc=com
objectClass: sudoRole
sudoUser: user10
sudoCommand: /usr/bin/id
sudoOrder: 10
`

	policy, err := ParseLDIF(strings.NewReader(ldifInput), "roles.ldif")
	if err != nil {
		t.Fatalf("ParseLDIF failed: %v", err)
	}
	if len(policy.UserSpecs) != 5 {
		t.Fatalf("expected 5 UserSpecs, got %d", len(policy.UserSpecs))
	}

	gotOrder := make([]string, len(policy.UserSpecs))
	for i, spec := range policy.UserSpecs {
		gotOrder[i] = spec.UserList[0].Username
	}
	wantOrder := []string{"userNeg", "user0a", "user0b", "user10", "user30"}
	for i := range wantOrder {
		if gotOrder[i] != wantOrder[i] {
			t.Errorf("sorted UserSpecs[%d].User = %q, want %q (full order: %v)", i, gotOrder[i], wantOrder[i], gotOrder)
		}
	}
}

func TestParseLDIFWithAudit(t *testing.T) {
	ldifInput := `version: 1
dn: cn=defaults,ou=SUDOers,dc=example,dc=com
objectClass: sudoRole
cn: defaults
sudoOption: !env_reset
sudoOption: env_keep+=PYTHONPATH

dn: cn=dev_python,ou=SUDOers,dc=example,dc=com
objectClass: sudoRole
cn: dev_python
sudoUser: %devs
sudoHost: ALL
sudoRunAsUser: root
sudoOption: !authenticate
sudoCommand: /usr/bin/python3 /opt/scripts/*
sudoOrder: 10

dn: cn=legacy_admin,ou=SUDOers,dc=example,dc=com
objectClass: sudoRole
cn: legacy_admin
sudoUser: secops
sudoHost: ALL
sudoOption: !authenticate
sudoNotAfter: 20200101000000Z
sudoCommand: ALL
sudoOrder: 20
`

	policy, err := ParseLDIF(strings.NewReader(ldifInput), "directory.ldif")
	if err != nil {
		t.Fatalf("ParseLDIF failed: %v", err)
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
		if f.Context != "directory.ldif" {
			t.Errorf("finding %s Context = %q, want directory.ldif", f.ID, f.Context)
		}
	}

	for _, id := range []string{"SUDO-DEF-011", "SUDO-DEF-004", "SUDO-CMD-003", "SUDO-CMD-004", "SUDO-GTFO-002"} {
		if !ids[id] {
			t.Errorf("expected finding %s from LDIF audit, got: %v", id, ids)
		}
	}

	// Verify sudoNotAfter normalized cleanly on legacy_admin
	legacyOpts := policy.UserSpecs[1].CmndSpecs[0].Options
	foundNotAfter := false
	for _, opt := range legacyOpts {
		if v, ok := opt["notafter"].(string); ok && v == "20200101000000Z" {
			foundNotAfter = true
		}
	}
	if !foundNotAfter {
		t.Errorf("expected normalized notafter=20200101000000Z on legacy_admin, got: %+v", legacyOpts)
	}
}

func TestParseLDIFErrors(t *testing.T) {
	t.Run("NilReader", func(t *testing.T) {
		if _, err := ParseLDIF(nil, ""); err == nil {
			t.Fatal("expected error for nil reader")
		}
	})

	t.Run("ReaderErrorWrapped", func(t *testing.T) {
		boom := errors.New("ldif read failure")
		_, err := ParseLDIF(iotest.ErrReader(boom), "bad.ldif")
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
			input: "  \r\n ",
		},
		{
			name:  "NonSudoLDIFOnly",
			input: "dn: ou=People,dc=example,dc=com\nobjectClass: organizationalUnit\nou: People\n",
		},
		{
			name:  "InvalidBase64",
			input: "dn: cn=bad,ou=SUDOers,dc=example,dc=com\nobjectClass: sudoRole\nsudoUser:: @@@not-base64@@@\nsudoCommand: /bin/ls\n",
		},
		{
			name:  "UnsupportedURLAttribute",
			input: "dn: cn=bad,ou=SUDOers,dc=example,dc=com\nobjectClass: sudoRole\nsudoCommand:< file:///etc/passwd\n",
		},
		{
			name:  "UnexpectedLeadingContinuation",
			input: " folded-before-attr\n",
		},
		{
			name:  "InvalidAttrLineMissingColon",
			input: "dn: cn=bad,ou=SUDOers,dc=example,dc=com\nobjectClass: sudoRole\nnot an attribute\n",
		},
		{
			name:  "InvalidSudoOrder",
			input: "dn: cn=bad,ou=SUDOers,dc=example,dc=com\nobjectClass: sudoRole\nsudoUser: alice\nsudoCommand: /bin/ls\nsudoOrder: high\n",
		},
		{
			name:  "InvalidDefaultsSudoOption",
			input: "dn: cn=defaults,ou=SUDOers,dc=example,dc=com\nobjectClass: sudoRole\ncn: defaults\nsudoOption: !secure_path=/bin\n",
		},
		{
			name:  "InvalidRoleSudoOption",
			input: "dn: cn=bad,ou=SUDOers,dc=example,dc=com\nobjectClass: sudoRole\nsudoUser: alice\nsudoOption: !\nsudoCommand: /bin/ls\n",
		},
		{
			name:  "UnterminatedRegexCommand",
			input: "dn: cn=bad,ou=SUDOers,dc=example,dc=com\nobjectClass: sudoRole\nsudoUser: alice\nsudoCommand: ^/usr/bin/id\n",
		},
		{
			name:  "EmptySudoUser",
			input: "dn: cn=bad,ou=SUDOers,dc=example,dc=com\nobjectClass: sudoRole\nsudoUser:   \nsudoCommand: /bin/ls\n",
		},
		{
			name:  "EmptySudoHost",
			input: "dn: cn=bad,ou=SUDOers,dc=example,dc=com\nobjectClass: sudoRole\nsudoUser: alice\nsudoHost:  \nsudoCommand: /bin/ls\n",
		},
		{
			name:  "EmptySudoOptionOnRole",
			input: "dn: cn=bad,ou=SUDOers,dc=example,dc=com\nobjectClass: sudoRole\nsudoUser: alice\nsudoOption:   \nsudoCommand: /bin/ls\n",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseLDIF(strings.NewReader(tc.input), "test.ldif"); err == nil {
				t.Errorf("expected error for %s, got nil", tc.name)
			}
		})
	}
}

func TestParseLDIFEdgeCases(t *testing.T) {
	ldifInput := `dn: cn=defaults,ou=SUDOers,dc=example,dc=com
objectClass: sudoRole
cn: defaults

dn: cn=emptyrole,ou=SUDOers,dc=example,dc=com
objectClass: sudoRole
cn: emptyrole
sudoUser: bob

dn: cn=nonunix,ou=SUDOers,dc=example,dc=com
objectClass: sudoRole
cn: nonunix
sudoUser: %:ad_users
sudoUser: %:#3001
sudoRunAsUser:
sudoRunAsGroup: %:ad_grp
sudoRunAsGroup: %:#4001
sudoOption: command_timeout=30
sudoOption: command_timeout=0
sudoOption: !requiretty
sudoCommand: /usr/bin/id
`
	policy, err := ParseLDIF(strings.NewReader(ldifInput), "edge.ldif")
	if err != nil {
		t.Fatalf("ParseLDIF edge cases failed: %v", err)
	}
	if len(policy.Defaults) != 0 {
		t.Errorf("expected 0 Defaults for empty cn=defaults, got %d", len(policy.Defaults))
	}
	if len(policy.UserSpecs) != 1 {
		t.Fatalf("expected 1 UserSpec (emptyrole skipped), got %d", len(policy.UserSpecs))
	}
	spec := policy.UserSpecs[0]
	if spec.UserList[0].NonUnixGroup != "ad_users" ||
		spec.UserList[1].NonUnixGID == nil || *spec.UserList[1].NonUnixGID != 3001 {
		t.Errorf("unexpected nonunix users: %+v", spec.UserList)
	}
	if !spec.CmndSpecs[0].RunasUsers[0].Myself {
		t.Errorf("expected empty sudoRunAsUser to map to Myself, got %+v", spec.CmndSpecs[0].RunasUsers)
	}
	if spec.CmndSpecs[0].RunasGroups[0].NonUnixGroup != "ad_grp" ||
		spec.CmndSpecs[0].RunasGroups[1].NonUnixGID == nil || *spec.CmndSpecs[0].RunasGroups[1].NonUnixGID != 4001 {
		t.Errorf("unexpected nonunix runas groups: %+v", spec.CmndSpecs[0].RunasGroups)
	}
}
