package audit

import (
	"testing"
)

func TestEvaluateGTFOArgumentConstraint(t *testing.T) {
	tests := []struct {
		name            string
		binaryName      string
		args            []string
		function        string
		wantConstrained bool
	}{
		// Empty / invalid inputs
		{"EmptyBinary", "", []string{"restart", "nginx"}, "shell", false},
		{"DotBinary", ".", []string{"restart", "nginx"}, "shell", false},
		{"SlashBinary", "/", []string{"restart", "nginx"}, "shell", false},
		{"EmptyFunction", "systemctl", []string{"restart", "nginx"}, "", false},
		{"EmptyArgs", "systemctl", nil, "shell", false},
		{"EmptyArgsSlice", "systemctl", []string{}, "shell", false},
		{"SudoersZeroArgQuotes_Systemctl", "systemctl", []string{`""`}, "shell", false},
		{"SudoersZeroArgQuotes_Cat", "/bin/cat", []string{`""`}, "file-read", false},
		{"SudoersZeroArgEmptyString", "systemctl", []string{""}, "shell", false},
		{"WhitespaceToken", "systemctl", []string{"restart ", "nginx"}, "shell", false},
		{"ControlCharToken", "systemctl", []string{"restart", "nginx\x00"}, "shell", false},
		{"DelCharToken", "systemctl", []string{"restart", "nginx\x7f"}, "shell", false},

		// Never-constrained categories: editors, pagers, shells, interpreters, archivers, find, containers
		{"NeverEditor_Vim", "/usr/bin/vim", []string{"/var/log/app.log"}, "shell", false},
		{"NeverEditor_VimBasic", "/usr/bin/vim.basic", []string{"/var/log/app.log"}, "file-write", false},
		{"NeverEditor_Nano", "nano", []string{"/var/log/app.log"}, "file-write", false},
		{"NeverPager_Less", "/usr/bin/less", []string{"/var/log/app.log"}, "file-read", false},
		{"NeverPager_More", "more", []string{"/var/log/app.log"}, "shell", false},
		{"NeverPager_Man", "man", []string{"ls"}, "shell", false},
		{"NeverPager_Most", "most", []string{"/var/log/app.log"}, "shell", false},
		{"NeverPager_Pg", "pg", []string{"/var/log/app.log"}, "shell", false},
		{"NeverShell_Sh", "/bin/sh", []string{"-c", "id"}, "shell", false},
		{"NeverShell_Bash", "/bin/bash", []string{"--norc"}, "shell", false},
		{"NeverShell_Rbash", "rbash", []string{"script.sh"}, "shell", false},
		{"NeverShell_Zsh", "zsh", []string{"status"}, "shell", false},
		{"NeverShell_Dash", "dash", []string{"status"}, "shell", false},
		{"NeverShell_Fish", "fish", []string{"status"}, "shell", false},
		{"NeverInterpreter_Python3", "/usr/bin/python3.11", []string{"/opt/app/check.py"}, "shell", false},
		{"NeverInterpreter_Perl", "perl5.34", []string{"/opt/app/check.pl"}, "shell", false},
		{"NeverInterpreter_Ruby", "ruby3.1", []string{"/opt/app/check.rb"}, "shell", false},
		{"NeverInterpreter_PHP", "php8.2", []string{"/opt/app/check.php"}, "shell", false},
		{"NeverInterpreter_Lua", "lua5.4", []string{"/opt/app/check.lua"}, "shell", false},
		{"NeverInterpreter_Node", "node18", []string{"/opt/app/check.js"}, "shell", false},
		{"NeverInterpreter_Gawk", "gawk", []string{"/var/log/app.log"}, "file-read", false},
		{"NeverInterpreter_Mawk", "mawk", []string{"/var/log/app.log"}, "shell", false},
		{"NeverArchiver_Tar", "/bin/tar", []string{"-cf", "/tmp/backup.tar", "/var/log/app.log"}, "shell", false},
		{"NeverArchiver_Zip", "zip", []string{"/tmp/out.zip", "/var/log/app.log"}, "shell", false},
		{"NeverArchiver_Unzip", "unzip", []string{"/tmp/in.zip"}, "shell", false},
		{"NeverArchiver_Gzip", "gzip", []string{"/var/log/app.log"}, "shell", false},
		{"NeverArchiver_Bzip2", "bzip2", []string{"/var/log/app.log"}, "shell", false},
		{"NeverSearch_Find", "/usr/bin/find", []string{"/var/log", "-name", "*.log"}, "shell", false},
		{"NeverContainer_Docker", "/usr/bin/docker", []string{"ps"}, "shell", false},
		{"NeverContainer_Podman", "podman", []string{"ps"}, "shell", false},
		{"NeverContainer_Kubectl", "kubectl", []string{"get", "pods"}, "shell", false},
		{"NeverContainer_LXD", "lxd", []string{"status"}, "shell", false},
		{"NeverContainer_Ctr", "ctr", []string{"version"}, "shell", false},
		{"NeverContainer_Crictl", "crictl", []string{"ps"}, "shell", false},
		{"NeverContainer_Nerdctl", "nerdctl", []string{"ps"}, "shell", false},
		{"UnknownWrapperScript", "/usr/local/bin/systemctl.sh", []string{"restart", "nginx"}, "shell", false},

		// Rule 1: systemctl
		{"Systemctl_RestartShell", "/usr/bin/systemctl", []string{"restart", "nginx"}, "shell", true},
		{"Systemctl_RestartServiceUnit", "/bin/systemctl", []string{"restart", "nginx.service"}, "command", true},
		{"Systemctl_ReloadFileRead", "systemctl", []string{"reload", "php8.2-fpm.service"}, "file-read", true},
		{"Systemctl_StartFileWrite", "systemctl", []string{"start", "app@1.service"}, "file-write", true},
		{"Systemctl_Stop", "systemctl", []string{"stop", "worker_1"}, "shell", true},
		{"Systemctl_TryRestart", "systemctl", []string{"try-restart", "nginx"}, "shell", true},
		{"Systemctl_ReloadOrRestart", "systemctl", []string{"reload-or-restart", "nginx"}, "shell", true},
		{"Systemctl_IsActive", "systemctl", []string{"is-active", "nginx"}, "shell", true},
		{"Systemctl_IsEnabled", "SYSTEMCTL", []string{"is-enabled", "nginx"}, "shell", true},
		{"Systemctl_RejectLibraryLoad", "systemctl", []string{"restart", "nginx"}, "library-load", false},
		{"Systemctl_RejectStatus", "systemctl", []string{"status", "nginx"}, "shell", false},
		{"Systemctl_RejectEdit", "systemctl", []string{"edit", "nginx"}, "shell", false},
		{"Systemctl_RejectLink", "systemctl", []string{"link", "evil.service"}, "shell", false},
		{"Systemctl_RejectEnable", "systemctl", []string{"enable", "nginx"}, "shell", false},
		{"Systemctl_RejectDisable", "systemctl", []string{"disable", "nginx"}, "shell", false},
		{"Systemctl_RejectCat", "systemctl", []string{"cat", "nginx"}, "shell", false},
		{"Systemctl_RejectShow", "systemctl", []string{"show", "nginx"}, "shell", false},
		{"Systemctl_RejectListUnits", "systemctl", []string{"list-units", "nginx"}, "shell", false},
		{"Systemctl_RejectSingleArg", "systemctl", []string{"restart"}, "shell", false},
		{"Systemctl_RejectExtraFlag", "systemctl", []string{"restart", "nginx", "--now"}, "shell", false},
		{"Systemctl_RejectPagerFlag", "systemctl", []string{"--pager", "restart"}, "shell", false},
		{"Systemctl_RejectHostFlag", "systemctl", []string{"-H", "host"}, "shell", false},
		{"Systemctl_RejectUnitFlag", "systemctl", []string{"restart", "--user"}, "shell", false},
		{"Systemctl_RejectUnitSlash", "systemctl", []string{"start", "/tmp/evil.service"}, "shell", false},
		{"Systemctl_RejectUnitLeadingDot", "systemctl", []string{"restart", ".hidden"}, "shell", false},
		{"Systemctl_RejectUnitInvalidChar", "systemctl", []string{"restart", "nginx+evil"}, "shell", false},
		{"Systemctl_RejectUnitTraversal", "systemctl", []string{"restart", "../evil.service"}, "shell", false},
		{"Systemctl_RejectUnitWildcard", "systemctl", []string{"restart", "nginx*"}, "shell", false},
		{"Systemctl_RejectUnitMetachar", "systemctl", []string{"restart", "nginx;id"}, "shell", false},

		// Rule 2: service
		{"Service_RestartShell", "/usr/sbin/service", []string{"nginx", "restart"}, "shell", true},
		{"Service_StatusCommand", "service", []string{"postgresql", "status"}, "command", true},
		{"Service_Start", "service", []string{"app-worker", "start"}, "shell", true},
		{"Service_Stop", "service", []string{"app_worker", "stop"}, "shell", true},
		{"Service_Reload", "service", []string{"rsyslog", "reload"}, "shell", true},
		{"Service_RejectFileRead", "service", []string{"nginx", "restart"}, "file-read", false},
		{"Service_RejectTraversalUnit", "service", []string{"../../bin/sh", "start"}, "shell", false},
		{"Service_RejectSlashUnit", "service", []string{"/bin/sh", "start"}, "shell", false},
		{"Service_RejectFlagUnit", "service", []string{"--status-all", "start"}, "shell", false},
		{"Service_RejectSingleArg", "service", []string{"nginx"}, "shell", false},
		{"Service_RejectThreeArgs", "service", []string{"nginx", "restart", "--full"}, "shell", false},
		{"Service_RejectUnknownAction", "service", []string{"nginx", "edit"}, "shell", false},
		{"Service_RejectWildcard", "service", []string{"nginx*", "restart"}, "shell", false},
		{"Service_RejectMetachar", "service", []string{"nginx|id", "restart"}, "shell", false},

		// Rule 3: cat, head, tail
		{"Cat_SafeAbsoluteLog", "/bin/cat", []string{"/var/log/nginx/access.log"}, "file-read", true},
		{"Cat_MultipleSafeLogs", "/usr/bin/cat", []string{"/var/log/app/a.log", "/var/log/app/b.log"}, "file-read", true},
		{"Head_SafeAbsoluteLog", "/usr/bin/head", []string{"/var/log/syslog"}, "file-read", true},
		{"Tail_SafeAbsoluteLog", "/usr/bin/tail", []string{"/opt/myapp/logs/service.log"}, "file-read", true},
		{"Cat_RejectWrongFunction", "/bin/cat", []string{"/var/log/syslog"}, "shell", false},
		{"Cat_RejectShadow", "/bin/cat", []string{"/etc/shadow"}, "file-read", false},
		{"Cat_RejectSudoers", "/bin/cat", []string{"/etc/sudoers"}, "file-read", false},
		{"Cat_RejectSudoersDropin", "/bin/cat", []string{"/etc/sudoers.d/ops"}, "file-read", false},
		{"Cat_RejectPasswd", "/bin/cat", []string{"/etc/passwd"}, "file-read", false},
		{"Cat_RejectRootSSH", "/bin/cat", []string{"/root/.ssh/id_rsa"}, "file-read", false},
		{"Cat_RejectDoubleSlashShadow", "/bin/cat", []string{"/etc//shadow"}, "file-read", false},
		{"Cat_RejectRelativePath", "/bin/cat", []string{"app.log"}, "file-read", false},
		{"Cat_RejectTraversal", "/bin/cat", []string{"/var/log/../../etc/shadow"}, "file-read", false},
		{"Cat_RejectWildcard", "/bin/cat", []string{"/var/log/*.log"}, "file-read", false},
		{"Cat_RejectDirectory", "/bin/cat", []string{"/var/log/"}, "file-read", false},
		{"Cat_RejectFlag", "/bin/cat", []string{"-n", "/var/log/syslog"}, "file-read", false},
		{"Tail_RejectFollowFlag", "/usr/bin/tail", []string{"-f", "/var/log/syslog"}, "file-read", false},
		{"Cat_RejectDashStdin", "/bin/cat", []string{"-"}, "file-read", false},
		{"Cat_RejectMetachar", "/bin/cat", []string{"/var/log/syslog;id"}, "file-read", false},
		{"Cat_RejectMixedSensitive", "/bin/cat", []string{"/var/log/syslog", "/etc/shadow"}, "file-read", false},

		// Rule 4: git
		{"Git_StatusShell", "/usr/bin/git", []string{"status"}, "shell", true},
		{"Git_StatusCommand", "git", []string{"status"}, "command", true},
		{"Git_StatusFileRead", "git", []string{"status"}, "file-read", true},
		{"Git_StatusFileWrite", "git", []string{"status"}, "file-write", true},
		{"Git_StatusShort", "git", []string{"status", "--short"}, "shell", true},
		{"Git_StatusPorcelain", "git", []string{"status", "--porcelain"}, "shell", true},
		{"Git_NoPagerStatus", "git", []string{"--no-pager", "status"}, "shell", true},
		{"Git_RevParse", "git", []string{"rev-parse"}, "shell", true},
		{"Git_RevParseHead", "git", []string{"rev-parse", "HEAD"}, "shell", true},
		{"Git_RevParseShortHead", "git", []string{"rev-parse", "--short", "HEAD"}, "shell", true},
		{"Git_RevParseAbbrevRef", "git", []string{"rev-parse", "--abbrev-ref", "HEAD"}, "shell", true},
		{"Git_Describe", "git", []string{"describe"}, "shell", true},
		{"Git_DescribeTagsAlways", "git", []string{"describe", "--tags", "--always"}, "shell", true},
		{"Git_DescribeAbbrev", "git", []string{"describe", "--abbrev=7"}, "shell", true},
		{"Git_BranchShowCurrent", "git", []string{"branch", "--show-current"}, "shell", true},
		{"Git_NoPagerBranchShowCurrent", "git", []string{"--no-pager", "branch", "--show-current"}, "shell", true},
		{"Git_RejectLibraryLoad", "git", []string{"status"}, "library-load", false},
		{"Git_RejectBranchBare", "git", []string{"branch"}, "shell", false},
		{"Git_RejectBranchAll", "git", []string{"branch", "-a"}, "shell", false},
		{"Git_RejectBranchCreate", "git", []string{"branch", "feature"}, "shell", false},
		{"Git_RejectBranchHelp", "git", []string{"branch", "--help"}, "shell", false},
		{"Git_RejectStatusHelp", "git", []string{"status", "--help"}, "shell", false},
		{"Git_RejectStatusH", "git", []string{"status", "-h"}, "shell", false},
		{"Git_RejectDashC", "git", []string{"-c", "core.pager=/bin/sh", "status"}, "shell", false},
		{"Git_RejectDashCAttached", "git", []string{"-ccore.pager=/bin/sh", "status"}, "shell", false},
		{"Git_RejectConfigEnv", "git", []string{"--config-env", "GIT_PAGER=sh", "status"}, "shell", false},
		{"Git_RejectConfigEnvEq", "git", []string{"--config-env=GIT_PAGER=sh", "status"}, "shell", false},
		{"Git_RejectExecPath", "git", []string{"--exec-path", "/tmp", "status"}, "shell", false},
		{"Git_RejectExecPathEq", "git", []string{"--exec-path=/tmp", "status"}, "shell", false},
		{"Git_RejectGitDir", "git", []string{"--git-dir", "/tmp/.git", "status"}, "shell", false},
		{"Git_RejectGitDirEq", "git", []string{"--git-dir=/tmp/.git", "status"}, "shell", false},
		{"Git_RejectWorkTree", "git", []string{"--work-tree", "/tmp", "status"}, "shell", false},
		{"Git_RejectWorkTreeEq", "git", []string{"--work-tree=/tmp", "status"}, "shell", false},
		{"Git_RejectDashP", "git", []string{"-p", "status"}, "shell", false},
		{"Git_RejectPaginate", "git", []string{"--paginate", "status"}, "shell", false},
		{"Git_RejectOutput", "git", []string{"status", "--output", "/tmp/x"}, "shell", false},
		{"Git_RejectOutputEq", "git", []string{"status", "--output=/tmp/x"}, "shell", false},
		{"Git_RejectExtDiff", "git", []string{"status", "--ext-diff"}, "shell", false},
		{"Git_RejectDashCapC", "git", []string{"-C", "/tmp/evil", "status"}, "shell", false},
		{"Git_RejectDiff", "git", []string{"diff", "/dev/null", "/etc/shadow"}, "file-read", false},
		{"Git_RejectApply", "git", []string{"apply", "/tmp/x.patch"}, "file-write", false},
		{"Git_RejectHelp", "git", []string{"help", "config"}, "shell", false},
		{"Git_RejectCommit", "git", []string{"commit", "-m", "x"}, "shell", false},
		{"Git_RejectNoPagerOnly", "git", []string{"--no-pager"}, "shell", false},
		{"Git_RejectStatusUnknownFlag", "git", []string{"status", "--unknown"}, "shell", false},
		{"Git_RejectRevParseUnknownFlag", "git", []string{"rev-parse", "--unknown"}, "shell", false},
		{"Git_RejectRevParseAbsPath", "git", []string{"rev-parse", "/etc/shadow"}, "shell", false},
		{"Git_RejectRevParseInvalidRefChar", "git", []string{"rev-parse", "HEAD^"}, "shell", false},
		{"Git_RejectDescribeUnknownFlag", "git", []string{"describe", "--unknown"}, "shell", false},
		{"Git_RejectDescribeAbbrevEmpty", "git", []string{"describe", "--abbrev="}, "shell", false},
		{"Git_RejectDescribeAbbrevAlpha", "git", []string{"describe", "--abbrev=abc"}, "shell", false},
		{"Git_RejectMetachar", "git", []string{"rev-parse", "$(id)"}, "shell", false},

		// Rule 5: apt-get, apt
		{"AptGet_UpdateShell", "/usr/bin/apt-get", []string{"update"}, "shell", true},
		{"AptGet_UpdateCommand", "apt-get", []string{"update"}, "command", true},
		{"Apt_UpdateShell", "/usr/bin/apt", []string{"update"}, "shell", true},
		{"Apt_UpdateCommand", "apt", []string{"update"}, "command", true},
		{"AptGet_RejectFileRead", "apt-get", []string{"update"}, "file-read", false},
		{"AptGet_RejectUpdatePreInvoke", "apt-get", []string{"update", "-o", "APT::Update::Pre-Invoke::=/bin/sh"}, "shell", false},
		{"AptGet_RejectUpdateFlag", "apt-get", []string{"update", "-y"}, "shell", false},
		{"AptGet_RejectUpgrade", "apt-get", []string{"upgrade"}, "shell", false},
		{"AptGet_RejectInstall", "apt-get", []string{"install", "nginx"}, "shell", false},
		{"AptGet_RejectChangelog", "apt-get", []string{"changelog", "apt"}, "shell", false},
		{"Apt_RejectShow", "apt", []string{"show", "nginx"}, "shell", false},
		{"Apt_RejectEmpty", "apt", []string{}, "shell", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotConstrained, gotRationale := EvaluateGTFOArgumentConstraint(tc.binaryName, tc.args, tc.function)
			if gotConstrained != tc.wantConstrained {
				t.Errorf("EvaluateGTFOArgumentConstraint(%q, %v, %q) constrained = %v, want %v (rationale=%q)",
					tc.binaryName, tc.args, tc.function, gotConstrained, tc.wantConstrained, gotRationale)
			}
			if gotConstrained && gotRationale == "" {
				t.Errorf("EvaluateGTFOArgumentConstraint(%q, %v, %q) returned constrained=true with empty rationale",
					tc.binaryName, tc.args, tc.function)
			}
			if !gotConstrained && gotRationale != "" {
				t.Errorf("EvaluateGTFOArgumentConstraint(%q, %v, %q) returned constrained=false with non-empty rationale %q",
					tc.binaryName, tc.args, tc.function, gotRationale)
			}
		})
	}
}
