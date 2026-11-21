package audit

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func scriptAuditTestFindID(findings []Finding, id string) (Finding, bool) {
	for _, f := range findings {
		if f.ID == id {
			return f, true
		}
	}
	return Finding{}, false
}

func scriptAuditTestCountID(findings []Finding, id string) int {
	count := 0
	for _, f := range findings {
		if f.ID == id {
			count++
		}
	}
	return count
}

func TestAnalyzeScriptContent_EmptyBinaryAndNonShebang(t *testing.T) {
	cases := []struct {
		name    string
		content []byte
	}{
		{"Nil", nil},
		{"Empty", []byte{}},
		{"NoShebang", []byte("echo hello\nrm -rf /tmp/foo\n")},
		{"ELFBinary", []byte("\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00")},
		{"ShebangWithNulByte", []byte("#!/bin/sh\x00rm -f $1\n")},
		{"EmptyShebang", []byte("#!\nrm -f $1\n")},
		{"PinnedPythonScript", []byte("#!/usr/bin/python3\nimport os\nos.system('id')\n")},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			findings := AnalyzeScriptContent("/usr/local/sbin/test-script", tc.content)
			if len(findings) != 0 {
				t.Errorf("Expected 0 findings for %s, got %+v", tc.name, findings)
			}
		})
	}
}

func TestAnalyzeScriptContent_Script001_EnvAndPath(t *testing.T) {
	t.Run("EnvShebangShell", func(t *testing.T) {
		script := "#!/usr/bin/env bash\nexport PATH=\"/usr/sbin:/usr/bin:/sbin:/bin\"\n/usr/bin/id\n"
		findings := AnalyzeScriptContent("/usr/local/bin/backup.sh", []byte(script))
		f, ok := scriptAuditTestFindID(findings, "SUDO-SYS-SCRIPT-001")
		if !ok {
			t.Fatalf("Expected SUDO-SYS-SCRIPT-001 for /usr/bin/env shebang, got %+v", findings)
		}
		if f.Severity != SeverityHigh || f.Line != 1 || f.Context != "/usr/local/bin/backup.sh" || f.Command != "/usr/local/bin/backup.sh" {
			t.Errorf("Unexpected finding metadata: %+v", f)
		}
		if !strings.Contains(f.RemediationCode, "#!/bin/bash") || !strings.Contains(f.RemediationCode, `export PATH="/usr/sbin:/usr/bin:/sbin:/bin"`) {
			t.Errorf("Unexpected RemediationCode: %q", f.RemediationCode)
		}
		if scriptAuditTestCountID(findings, "SUDO-SYS-SCRIPT-001") != 1 {
			t.Errorf("Expected exactly 1 SUDO-SYS-SCRIPT-001 finding, got %+v", findings)
		}
	})

	t.Run("EnvShebangPython", func(t *testing.T) {
		script := "#!/usr/bin/env python3\nprint('ok')\n"
		findings := AnalyzeScriptContent("/opt/tools/check.py", []byte(script))
		f, ok := scriptAuditTestFindID(findings, "SUDO-SYS-SCRIPT-001")
		if !ok {
			t.Fatalf("Expected SUDO-SYS-SCRIPT-001 for /usr/bin/env python3, got %+v", findings)
		}
		if f.Severity != SeverityHigh || f.Line != 1 || f.RemediationCode == "" {
			t.Errorf("Unexpected finding fields: %+v", f)
		}
	})

	t.Run("EnvDashSAndShellChecks", func(t *testing.T) {
		script := "#!/usr/bin/env -S bash -e\neval \"$1\"\n"
		findings := AnalyzeScriptContent("/opt/tools/run.sh", []byte(script))
		if _, ok := scriptAuditTestFindID(findings, "SUDO-SYS-SCRIPT-001"); !ok {
			t.Errorf("Expected SUDO-SYS-SCRIPT-001, got %+v", findings)
		}
		if _, ok := scriptAuditTestFindID(findings, "SUDO-SYS-SCRIPT-002"); !ok {
			t.Errorf("Expected SUDO-SYS-SCRIPT-002 to still run for env -S bash, got %+v", findings)
		}
	})

	t.Run("UnqualifiedCommandWithoutPath", func(t *testing.T) {
		for _, shell := range []string{"/bin/sh", "/bin/bash", "/bin/dash", "/bin/ash", "/bin/ksh", "/bin/zsh"} {
			script := "#!" + shell + "\n# comment\nFOO=bar\necho \"starting\"\nsystemctl restart nginx\n"
			findings := AnalyzeScriptContent("/usr/local/sbin/svc.sh", []byte(script))
			f, ok := scriptAuditTestFindID(findings, "SUDO-SYS-SCRIPT-001")
			if !ok {
				t.Fatalf("Shell %s: expected SUDO-SYS-SCRIPT-001, got %+v", shell, findings)
			}
			if f.Line != 5 || f.Severity != SeverityHigh {
				t.Errorf("Shell %s: expected Line 5 and HIGH severity, got %+v", shell, f)
			}
			if !strings.Contains(f.RemediationCode, "#!/bin/bash") || !strings.Contains(f.RemediationCode, `export PATH="/usr/sbin:/usr/bin:/sbin:/bin"`) {
				t.Errorf("Shell %s: unexpected RemediationCode %q", shell, f.RemediationCode)
			}
		}
	})

	t.Run("UnqualifiedCommandBeforePathAssignment", func(t *testing.T) {
		script := "#!/bin/bash\nid\nexport PATH=\"/usr/sbin:/usr/bin:/sbin:/bin\"\nsystemctl status app\n"
		findings := AnalyzeScriptContent("/usr/local/sbin/order.sh", []byte(script))
		f, ok := scriptAuditTestFindID(findings, "SUDO-SYS-SCRIPT-001")
		if !ok {
			t.Fatalf("Expected SUDO-SYS-SCRIPT-001 when command precedes PATH=, got %+v", findings)
		}
		if f.Line != 2 {
			t.Errorf("Expected Line 2, got %d", f.Line)
		}
	})

	t.Run("InheritedDollarPathStillUnsafe", func(t *testing.T) {
		script := "#!/bin/bash\nexport PATH=\"$PATH:/opt/bin\"\nsystemctl status app\n"
		findings := AnalyzeScriptContent("/usr/local/sbin/append_path.sh", []byte(script))
		if _, ok := scriptAuditTestFindID(findings, "SUDO-SYS-SCRIPT-001"); !ok {
			t.Fatalf("Expected SUDO-SYS-SCRIPT-001 when PATH inherits $PATH, got %+v", findings)
		}
	})

	t.Run("CommandInsideSubshellWithoutPath", func(t *testing.T) {
		script := "#!/bin/bash\nUID_VAL=$(id -u)\necho \"$UID_VAL\"\n"
		findings := AnalyzeScriptContent("/usr/local/sbin/subshell.sh", []byte(script))
		f, ok := scriptAuditTestFindID(findings, "SUDO-SYS-SCRIPT-001")
		if !ok {
			t.Fatalf("Expected SUDO-SYS-SCRIPT-001 for unqualified command inside $(), got %+v", findings)
		}
		if f.Line != 2 {
			t.Errorf("Expected Line 2, got %d", f.Line)
		}
	})

	t.Run("BacktickSubshellAndTabHeredocAndHereString", func(t *testing.T) {
		script := strings.Join([]string{
			"#!/bin/bash",
			"export PATH=\"/usr/sbin:/usr/bin:/sbin:/bin\"",
			"/bin/cat <<-EOF > /dev/null",
			"\tignored_unqualified_cmd",
			"\teval \"$1\"",
			"\tEOF",
			"OUT=`/usr/bin/id -u`",
			"/bin/cat <<< \"$1\"",
			"CALC=$(( (1 + $1) * 2 ))",
			"echo \"$OUT\" \"$CALC\"",
		}, "\n")
		findings := AnalyzeScriptContent("/usr/local/sbin/backtick.sh", []byte(script))
		if len(findings) != 0 {
			t.Errorf("Expected 0 findings, got %+v", findings)
		}

		vulnBacktick := "#!/bin/bash\nexport PATH=\"/usr/sbin:/usr/bin:/sbin:/bin\"\nRES=`eval \"$1\"`\n"
		vulnFindings := AnalyzeScriptContent("/usr/local/sbin/backtick_vuln.sh", []byte(vulnBacktick))
		if _, ok := scriptAuditTestFindID(vulnFindings, "SUDO-SYS-SCRIPT-002"); !ok {
			t.Errorf("Expected SUDO-SYS-SCRIPT-002 for eval inside backticks, got %+v", vulnFindings)
		}
	})

	t.Run("SafeExplicitPathAndBuiltinsAndQualified", func(t *testing.T) {
		script := strings.Join([]string{
			"#!/bin/bash",
			"set -euo pipefail",
			"umask 077",
			"FOO=bar",
			"readonly BAR=baz",
			"local_helper() {",
			"    echo \"$1\"",
			"}",
			"function another_fn {",
			"    printf '%s\\n' \"$1\"",
			"}",
			"if [ -f /etc/myapp/conf ]; then",
			"    /usr/bin/cat <<'EOF' > /dev/null",
			"systemctl restart bogus_inside_heredoc",
			"eval \"$1\"",
			"EOF",
			"    /usr/bin/systemctl \\",
			"        restart myapp",
			"elif [[ \"$#\" -ne 0 ]]; then",
			"    local_helper \"$1\"",
			"    another_fn \"$1\"",
			"else",
			"    true",
			"fi",
			"OUT=$(/usr/bin/grep -F root /etc/passwd)",
			"case \"$1\" in",
			"    start) /usr/bin/systemctl start app ;;",
			"    *) exit 0 ;;",
			"esac",
			"export PATH=\"/usr/sbin:/usr/bin:/sbin:/bin\"",
			"systemctl status myapp",
			"unset FOO",
			"return 0 || true",
		}, "\n")
		findings := AnalyzeScriptContent("/usr/local/sbin/safe.sh", []byte(script))
		if len(findings) != 0 {
			t.Errorf("Expected 0 findings for clean script, got %+v", findings)
		}
	})
}

func TestAnalyzeScriptContent_Script002_Injection(t *testing.T) {
	unsafeCases := []struct {
		name   string
		script string
		line   int
	}{
		{
			name:   "EvalQuotedPositional",
			script: "#!/bin/bash\nexport PATH=\"/usr/sbin:/usr/bin:/sbin:/bin\"\neval \"$1\"\n",
			line:   3,
		},
		{
			name:   "EvalUnquotedAt",
			script: "#!/bin/sh\nPATH=/usr/bin:/bin\neval $@\n",
			line:   3,
		},
		{
			name:   "ShDashC",
			script: "#!/bin/sh\nPATH=/usr/bin:/bin\nsh -c \"$1\"\n",
			line:   3,
		},
		{
			name:   "BinBashDashEC",
			script: "#!/bin/bash\nPATH=/usr/bin:/bin\n/bin/bash -ec \"systemctl restart ${1}\"\n",
			line:   3,
		},
		{
			name:   "EnvBashDashC",
			script: "#!/bin/bash\nPATH=/usr/bin:/bin\n/usr/bin/env -u HOME bash -c \"$*\"\n",
			line:   3,
		},
		{
			name:   "ExecBashDashC",
			script: "#!/bin/bash\nPATH=/usr/bin:/bin\nexec /bin/sh -c \"$1\"\n",
			line:   3,
		},
		{
			name:   "PositionalAsCommand",
			script: "#!/bin/sh\nPATH=/usr/bin:/bin\n$1 restart\n",
			line:   3,
		},
		{
			name:   "QuotedAtAsCommand",
			script: "#!/bin/bash\nPATH=/usr/bin:/bin\n\"$@\"\n",
			line:   3,
		},
		{
			name:   "ExecQuotedAt",
			script: "#!/bin/bash\nPATH=/usr/bin:/bin\nexec \"$@\"\n",
			line:   3,
		},
		{
			name:   "UnquotedPositionalInCmd",
			script: "#!/bin/bash\nPATH=/usr/bin:/bin\n/bin/rm -f $1\n",
			line:   3,
		},
		{
			name:   "UnquotedBracedInCmd",
			script: "#!/bin/bash\nPATH=/usr/bin:/bin\n/bin/cat ${2}\n",
			line:   3,
		},
		{
			name:   "UnquotedStarInLoop",
			script: "#!/bin/bash\nPATH=/usr/bin:/bin\nfor x in $*; do\n    /bin/echo \"$x\"\ndone\n",
			line:   3,
		},
		{
			name:   "EchoUnquotedPositional",
			script: "#!/bin/bash\nPATH=/usr/bin:/bin\necho $1\n",
			line:   3,
		},
	}

	for _, tc := range unsafeCases {
		t.Run(tc.name, func(t *testing.T) {
			findings := AnalyzeScriptContent("/usr/local/sbin/vuln.sh", []byte(tc.script))
			f, ok := scriptAuditTestFindID(findings, "SUDO-SYS-SCRIPT-002")
			if !ok {
				t.Fatalf("Case %s: expected SUDO-SYS-SCRIPT-002, got %+v", tc.name, findings)
			}
			if f.Severity != SeverityCritical || f.Line != tc.line || f.RemediationCode == "" {
				t.Errorf("Case %s: unexpected finding fields %+v", tc.name, f)
			}
		})
	}

	t.Run("SafeQuotedPositionalPatterns", func(t *testing.T) {
		script := strings.Join([]string{
			"#!/bin/bash",
			"export PATH=\"/usr/sbin:/usr/bin:/sbin:/bin\"",
			"if [[ \"$#\" -ne 0 ]]; then",
			"    echo \"$1\"",
			"fi",
			"if [[ \"$1\" == \"start\" && \"$2\" == \"now\" ]]; then",
			"    /usr/bin/systemctl \"$1\" app",
			"fi",
			"if [ \"$1\" = \"status\" ]; then",
			"    /usr/bin/systemctl status \"$1\"",
			"fi",
			"ACTION=\"$1\"",
			"RAW_ACTION=$1",
			"case \"$1\" in",
			"    start) /usr/bin/echo \"$1\" ;;",
			"esac",
			"for item in \"$@\"; do",
			"    /usr/bin/printf '%s\\n' \"$item\"",
			"done",
			"/bin/echo '$1'",
			"/bin/sh -c 'echo \"$1\"' _ \"$1\"",
			"MATCH=$(/usr/bin/grep -F \"$1\" /etc/hosts)",
			"NUM=$(( $1 + 1 ))",
		}, "\n")
		findings := AnalyzeScriptContent("/usr/local/sbin/safe_args.sh", []byte(script))
		if _, ok := scriptAuditTestFindID(findings, "SUDO-SYS-SCRIPT-002"); ok {
			t.Errorf("Unexpected SUDO-SYS-SCRIPT-002 on safe quoted patterns: %+v", findings)
		}
	})
}

func TestAnalyzeScriptContent_Script003_Sourcing(t *testing.T) {
	unsafeCases := []struct {
		name   string
		script string
	}{
		{"DotRelative", "#!/bin/sh\nPATH=/usr/bin:/bin\n. ./env.sh\n"},
		{"SourceBareRelative", "#!/bin/bash\nPATH=/usr/bin:/bin\nsource helper.sh\n"},
		{"SourceTmp", "#!/bin/bash\nPATH=/usr/bin:/bin\nsource /tmp/override.sh\n"},
		{"DotVarTmp", "#!/bin/sh\nPATH=/usr/bin:/bin\n. /var/tmp/env.conf\n"},
		{"SourceHome", "#!/bin/bash\nPATH=/usr/bin:/bin\nsource /home/alice/env.sh\n"},
		{"DotDevShm", "#!/bin/sh\nPATH=/usr/bin:/bin\n. /dev/shm/payload.sh\n"},
		{"SourceRunUser", "#!/bin/bash\nPATH=/usr/bin:/bin\nsource /run/user/1000/vars.sh\n"},
	}

	for _, tc := range unsafeCases {
		t.Run(tc.name, func(t *testing.T) {
			findings := AnalyzeScriptContent("/usr/local/sbin/src.sh", []byte(tc.script))
			f, ok := scriptAuditTestFindID(findings, "SUDO-SYS-SCRIPT-003")
			if !ok {
				t.Fatalf("Case %s: expected SUDO-SYS-SCRIPT-003, got %+v", tc.name, findings)
			}
			if f.Severity != SeverityHigh || f.Line != 3 {
				t.Errorf("Case %s: expected HIGH at line 3, got %+v", tc.name, f)
			}
			if !strings.Contains(f.RemediationCode, "/etc/") {
				t.Errorf("Case %s: expected /etc/ path in RemediationCode, got %q", tc.name, f.RemediationCode)
			}
		})
	}

	t.Run("SafeAbsoluteSourcing", func(t *testing.T) {
		script := "#!/bin/bash\nPATH=/usr/bin:/bin\n. /etc/myapp/config.env\nsource /usr/local/lib/myapp/helpers.sh\n. /tmpfs/readonly.env\n"
		findings := AnalyzeScriptContent("/usr/local/sbin/safe_src.sh", []byte(script))
		if len(findings) != 0 {
			t.Errorf("Expected 0 findings for safe sourcing, got %+v", findings)
		}
	})
}

func TestScriptAudit_EvaluateInterpreter(t *testing.T) {
	t.Run("GroupOrWorldWritable", func(t *testing.T) {
		for _, mode := range []os.FileMode{0775, 0757, 0777} {
			findings := scriptAuditEvaluateInterpreter("/usr/local/sbin/run.sh", "/usr/local/bin/mysh", mode, 0, true)
			f, ok := scriptAuditTestFindID(findings, "SUDO-SYS-SCRIPT-003")
			if !ok {
				t.Fatalf("Mode %o: expected SUDO-SYS-SCRIPT-003, got %+v", mode, findings)
			}
			if f.Severity != SeverityCritical {
				t.Errorf("Mode %o: expected CRITICAL, got %s", mode, f.Severity)
			}
			if !strings.Contains(f.RemediationCode, "chown root:root /usr/local/bin/mysh") {
				t.Errorf("Unexpected RemediationCode: %q", f.RemediationCode)
			}
		}
	})

	t.Run("NonRootOwner", func(t *testing.T) {
		findings := scriptAuditEvaluateInterpreter("/usr/local/sbin/run.sh", "/usr/local/bin/mysh", 0755, 1000, true)
		f, ok := scriptAuditTestFindID(findings, "SUDO-SYS-SCRIPT-003")
		if !ok {
			t.Fatalf("Expected SUDO-SYS-SCRIPT-003 for non-root interpreter, got %+v", findings)
		}
		if f.Severity != SeverityHigh || f.Line != 1 {
			t.Errorf("Expected HIGH at line 1, got %+v", f)
		}
	})

	t.Run("CleanRootOwnedInterpreter", func(t *testing.T) {
		findings := scriptAuditEvaluateInterpreter("/usr/local/sbin/run.sh", "/bin/bash", 0755, 0, true)
		if len(findings) != 0 {
			t.Errorf("Expected 0 findings for 0755 root-owned interpreter, got %+v", findings)
		}
		unknownOwner := scriptAuditEvaluateInterpreter("/usr/local/sbin/run.sh", "/bin/bash", 0755, 1000, false)
		if len(unknownOwner) != 0 {
			t.Errorf("Expected 0 findings when hasOwner=false and mode is 0755, got %+v", unknownOwner)
		}
	})
}

func TestAuditPolicyTargetScripts(t *testing.T) {
	if got := AuditPolicyTargetScripts(nil); got != nil {
		t.Errorf("Expected nil for nil policy, got %+v", got)
	}

	tmpDir := t.TempDir()
	scriptPath := filepath.Join(tmpDir, "deploy.sh")
	scriptBody := "#!/usr/bin/env bash\neval \"$1\"\nsource ./local.env\n"
	if err := os.WriteFile(scriptPath, []byte(scriptBody), 0755); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	policy := &SudoersPolicy{
		CommandAliases: map[string][]Member{
			"DEPLOY": {{Command: scriptPath}, {Command: "ALL"}},
		},
		UserSpecs: []UserSpec{
			{
				UserList: []Member{{Username: "deploy"}},
				HostList: []Member{{Hostname: "ALL"}},
				CmndSpecs: []CmndSpec{
					{
						Commands: []Member{
							{CommandAlias: "DEPLOY"},
							{Command: scriptPath, Negated: true},
							{Command: "relative_cmd"},
							{Command: "/usr/bin/cat /var/log/*"},
						},
					},
				},
			},
		},
	}

	findings := AuditPolicyTargetScripts(policy)
	if runtime.GOOS == "windows" {
		if findings != nil {
			t.Errorf("Expected nil on Windows, got %+v", findings)
		}
		return
	}

	if _, ok := scriptAuditTestFindID(findings, "SUDO-SYS-SCRIPT-001"); !ok {
		t.Errorf("Expected SUDO-SYS-SCRIPT-001 on Unix, got %+v", findings)
	}
	if _, ok := scriptAuditTestFindID(findings, "SUDO-SYS-SCRIPT-002"); !ok {
		t.Errorf("Expected SUDO-SYS-SCRIPT-002 on Unix, got %+v", findings)
	}
	if _, ok := scriptAuditTestFindID(findings, "SUDO-SYS-SCRIPT-003"); !ok {
		t.Errorf("Expected SUDO-SYS-SCRIPT-003 on Unix, got %+v", findings)
	}
}
