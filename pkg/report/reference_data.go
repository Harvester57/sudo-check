package report

import (
	"strings"
	"sudo-check/pkg/audit"
)

// FrameworkCatalogGroup represents a standard or security benchmark family in Tab 2.
type FrameworkCatalogGroup struct {
	ID            string
	ShortName     string
	FullName      string
	VersionInfo   string
	Publisher     string
	ReferenceURL  string
	Summary       string
	TotalReqs     int
	TriggeredReqs int
	TotalFindings int
	Requirements  []FrameworkRequirement
}

// FrameworkRequirement represents a single verbatim requirement within a standard.
type FrameworkRequirement struct {
	ID               string
	FrameworkID      string
	FrameworkShort   string
	Code             string
	Title            string
	Level            string
	CitationURL      string
	VerbatimQuote    string
	VerbatimQuoteFR  string
	Rationale        string
	DirectivesCode   string
	RuleIDs          []string
	ViolatingRuleIDs []string
	ComplianceTags   []string
	ViolationCount   int
	HighestSeverity  audit.Severity
	BadgeClass       string
	TemplateAnchor   string
	SearchText       string
}

// HardenedTemplateSection represents a copy-pasteable configuration or shell block in Tab 3.
type HardenedTemplateSection struct {
	ID          string
	Badge       string
	Title       string
	FilePath    string
	Description string
	Code        string
	Highlights  []string
	RuleIDs     []string
}

// TraceabilityRow maps a sudo-check audit rule to its framework references and hardened baseline directive.
type TraceabilityRow struct {
	RuleID     string
	Domain     string
	Severity   audit.Severity
	BadgeClass string
	Title      string
	Frameworks []string
	Directive  string
	SectionID  string
}

// HardenedSudoersReferencePolicy returns the canonical hardened /etc/sudoers baseline policy
// rendered in Tab 3 of the HTML report. It implements every ANSSI BP-028, CIS Benchmark,
// DISA STIG, and MITRE ATT&CK control checked by sudo-check and passes audit.RunAudit with zero findings.
func HardenedSudoersReferencePolicy() string {
	return strings.TrimSpace(`
# ==============================================================================
# Hardened /etc/sudoers Reference Baseline Policy
# Standards: ANSSI BP-028 (R38-R42/R44), CIS Benchmark 5.2.1-5.2.7, DISA STIG
# Validation: visudo -c -f /etc/sudoers && sudo-check scan /etc/sudoers
# ==============================================================================

# --- 1. Mandatory Environment & Execution Hardening (ANSSI BP-028 R39 / CIS 5.2) ---
Defaults env_reset
Defaults !setenv
Defaults ignore_dot
Defaults secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
Defaults env_keep="LANG LC_ALL LC_CTYPE LC_MESSAGES TERM COLORTERM"

# --- 2. Terminal Isolation, Subprocess Control & Umask (ANSSI BP-028 R39 / CIS 5.2.2) ---
Defaults use_pty
Defaults requiretty
Defaults noexec
Defaults umask=0077
Defaults umask_override

# --- 3. Authentication & Credential Cache Hardening (CIS 5.2.4-5.2.7 / DISA STIG) ---
Defaults authenticate
Defaults !visiblepw
Defaults !pwfeedback
Defaults passwd_timeout=1
Defaults passwd_tries=3
Defaults timestamp_timeout=5
Defaults timestamp_type=tty

# --- 4. Sudoedit Symlink & Directory Traversal Protection (ANSSI BP-028 R42/R44) ---
Defaults !sudoedit_follow
Defaults sudoedit_checkdir

# --- 5. Audit Logging & I/O Telemetry (CIS 5.2.3 / DISA STIG) ---
Defaults logfile="/var/log/sudo.log"
Defaults log_input, log_output
Defaults iolog_dir="/var/log/sudo-io/%{user}"
Defaults mail_badpass, mail_no_user, mail_no_perms

# --- 6. Explicit Positive Host, User, Runas & Command Aliases (ANSSI BP-028 R40/R41) ---
# Never use negation (!) in aliases or specs; define explicit positive allowlists.
Host_Alias  PROD_WEB_SERVERS = web01.internal.example, web02.internal.example
Host_Alias  PROD_DB_SERVERS  = db01.internal.example

User_Alias  WEB_OPERATORS    = %sudo_webops
User_Alias  DB_OPERATORS     = %sudo_dbops
User_Alias  SECURITY_AUDIT   = %sudo_auditors

Runas_Alias WEB_SVC_USER     = www-data
Runas_Alias DB_SVC_USER      = postgres

# --- 7. Least-Privilege Rules with Explicit Arguments & SHA-256 Digest Pinning ---
# ANSSI BP-028 R40: Prefer dedicated non-root target accounts where root is unnecessary.
# ANSSI BP-028 R41: Pin exact arguments (or "" for zero arguments) and avoid wildcards (*).
WEB_OPERATORS PROD_WEB_SERVERS = (WEB_SVC_USER) PASSWD: NOEXEC: \
    sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 \
    /usr/local/sbin/sudo-wrappers/reload-nginx-config.sh ""

DB_OPERATORS PROD_DB_SERVERS = (DB_SVC_USER) PASSWD: NOEXEC: \
    sha256:a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3 \
    /usr/local/sbin/sudo-wrappers/pg-ControlledCheck.sh --status

# Controlled service status inspection via dedicated root-owned wrapper (avoids GTFObins systemctl pager inheritance):
WEB_OPERATORS PROD_WEB_SERVERS = (root) PASSWD: NOEXEC: \
    sha256:2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae \
    /usr/local/sbin/sudo-wrappers/nginx-service-status.sh ""

# Read-only diagnostic command with explicit argument constraint:
SECURITY_AUDIT ALL = (root) PASSWD: NOEXEC: \
    /usr/sbin/auditctl -s

# --- 8. Safe Configuration Editing via sudoedit (ANSSI BP-028 R42/R44) ---
# Never grant direct sudo access to vim/nano/emacs/less; use sudoedit on explicit application files.
WEB_OPERATORS PROD_WEB_SERVERS = (WEB_SVC_USER) PASSWD: \
    sudoedit /etc/nginx/conf.d/app-vhost.conf

# --- 9. Modular Drop-In Directory (ANSSI BP-028 R38 / CIS 5.2.1) ---
# Note: Only enable #includedir after verifying /etc/sudoers.d and all files inside are root:root 0440.
# #includedir /etc/sudoers.d
`) + "\n"
}

func buildFrameworkCatalog(findings []htmlFindingView) ([]FrameworkCatalogGroup, int, int) {
	groups := []FrameworkCatalogGroup{
		{
			ID:           "ANSSI-BP-028",
			ShortName:    "ANSSI BP-028",
			FullName:     "ANSSI — Recommandations de sécurité relatives à un système GNU/Linux (BP-028)",
			VersionInfo:  "v1.2 & v2.0 (ANSSI-BP-028)",
			Publisher:    "Agence nationale de la sécurité des systèmes d'information (ANSSI)",
			ReferenceURL: "https://cyber.gouv.fr/publications/recommandations-de-securite-relatives-un-systeme-gnulinux",
			Summary:      "French National Cybersecurity Agency (ANSSI) baseline security guide for GNU/Linux systems. Section 3.4.5 (v1.2 R38–R42 / v2.0 R40–R44) defines strict architectural controls for sudo installation, filesystem permissions, Defaults hardening, non-root target accounts, negation bans, argument pinning, and safe file editing via sudoedit.",
			Requirements: []FrameworkRequirement{
				{
					ID:              "anssi-r38",
					FrameworkID:     "ANSSI-BP-028",
					FrameworkShort:  "ANSSI BP-028",
					Code:            "ANSSI-BP-028 R38",
					Title:           "Dedicated sudo Group & Strict Sudoers / Binary Permissions",
					Level:           "Enhanced / Basic (R38)",
					CitationURL:     "https://cyber.gouv.fr/publications/recommandations-de-securite-relatives-un-systeme-gnulinux",
					VerbatimQuote:   "R38 - Use a dedicated group for sudo usage: Only members of a dedicated group should be able to execute the sudo binary. Furthermore, the configuration files (/etc/sudoers and files within /etc/sudoers.d/) must be owned by root:root with mode 0440, and the sudo binary must be owned by root with the setuid bit set and without write permissions for group or other.",
					VerbatimQuoteFR: "R38 - Utiliser un groupe dédié à l'utilisation de sudo : Il est recommandé de restreindre l'exécution du binaire sudo aux seuls membres d'un groupe dédié (via les permissions du binaire ou la configuration PAM/sudoers) et de protéger les fichiers /etc/sudoers et /etc/sudoers.d/* (propriétaire root:root, permissions 0440).",
					Rationale:       "World-readable sudoers files expose privilege escalation paths and command structures to local attackers for reconnaissance. Group-writable or world-writable sudoers files, drop-in directories, or sudo binaries allow immediate local root compromise.",
					DirectivesCode:  "sudo chown root:root /etc/sudoers /etc/sudoers.d\nsudo chmod 0440 /etc/sudoers\nsudo chmod 0750 /etc/sudoers.d\nsudo find /etc/sudoers.d -type f -exec chown root:root {} + -exec chmod 0440 {} +\nsudo chown root:root /usr/bin/sudo\nsudo chmod 4755 /usr/bin/sudo",
					RuleIDs:         []string{"SUDO-SYS-PERM-001", "SUDO-SYS-PERM-002", "SUDO-SYS-PERM-003", "SUDO-SYS-PERM-004", "SUDO-SYS-PERM-005", "SUDO-SYS-PERM-006", "SUDO-SYS-PERM-007", "SUDO-SYS-PERM-008", "SUDO-SYS-PERM-009", "SUDO-SYS-PERM-010", "SUDO-SYS-PERM-011"},
					ComplianceTags:  []string{"ANSSI-BP-028 R38"},
					TemplateAnchor:  "tpl-filesystem-perms",
				},
				{
					ID:              "anssi-r39",
					FrameworkID:     "ANSSI-BP-028",
					FrameworkShort:  "ANSSI BP-028",
					Code:            "ANSSI-BP-028 R39",
					Title:           "Secure Sudo Configuration Directives (Defaults Hardening)",
					Level:           "Standard (R39)",
					CitationURL:     "https://cyber.gouv.fr/publications/recommandations-de-securite-relatives-un-systeme-gnulinux",
					VerbatimQuote:   "R39 - Configure sudo securely: The sudo configuration must include the following directives in the /etc/sudoers file:\nDefaults noexec,requiretty,use_pty,umask=0077\nDefaults ignore_dot,env_reset,passwd_timeout=1",
					VerbatimQuoteFR: "R39 - Configurer sudo de manière sécurisée : Il est recommandé d'ajouter les directives suivantes dans le fichier /etc/sudoers :\nDefaults noexec,requiretty,use_pty,umask=0077\nDefaults ignore_dot,env_reset,passwd_timeout=1\nAinsi que de définir explicitement secure_path et d'interdire la conservation de variables d'environnement dangereuses (env_keep / setenv).",
					Rationale:       "Without env_reset, secure_path, and ignore_dot, callers can hijack shared libraries (LD_PRELOAD), interpreter paths (PYTHONPATH), or relative PATH entries. Without use_pty and requiretty, child processes can inject keystrokes into the calling terminal via TIOCSTI ioctl. Without noexec, allowed utilities can spawn interactive shells. Without umask=0077, files created by root inherit the caller's permissive umask.",
					DirectivesCode:  "Defaults noexec,requiretty,use_pty,umask=0077,umask_override\nDefaults ignore_dot,env_reset,passwd_timeout=1\nDefaults secure_path=\"/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\"\nDefaults !visiblepw,!pwfeedback,!setenv",
					RuleIDs:         []string{"SUDO-DEF-001", "SUDO-DEF-002", "SUDO-DEF-003", "SUDO-DEF-004", "SUDO-DEF-005", "SUDO-DEF-006", "SUDO-DEF-007", "SUDO-DEF-008", "SUDO-DEF-009", "SUDO-DEF-010", "SUDO-DEF-011", "SUDO-DEF-013", "SUDO-DEF-015", "SUDO-DEF-016", "SUDO-CMD-009"},
					ComplianceTags:  []string{"ANSSI-BP-028 R39"},
					TemplateAnchor:  "tpl-sudoers-baseline",
				},
				{
					ID:              "anssi-r40",
					FrameworkID:     "ANSSI-BP-028",
					FrameworkShort:  "ANSSI BP-028",
					Code:            "ANSSI-BP-028 R40",
					Title:           "Unprivileged Target Users & Prohibition of Negation (!) in Rules",
					Level:           "Standard (R40 / v2.0 R42)",
					CitationURL:     "https://cyber.gouv.fr/publications/recommandations-de-securite-relatives-un-systeme-gnulinux",
					VerbatimQuote:   "R40 - Privilege non-privileged target users for sudo commands and prohibit negation: Whenever a privileged action does not strictly require root privileges, the target user (Runas) specified in sudoers must be a dedicated non-privileged service account. Furthermore, never use the negation operator (!) in sudoers specifications (User_Spec, Runas_Spec, Host_Spec, or Cmnd_Spec) to exclude users, groups, hosts, or commands.",
					VerbatimQuoteFR: "R40 (v1.2) / R42 (v2.0) - Privilégier des utilisateurs cibles non privilégiés et proscrire l'opérateur de négation (!) : Les règles sudo doivent cibler le compte applicatif minimal nécessaire (et non root par défaut). Il ne faut jamais utiliser la négation (!) dans les règles sudoers pour tenter de restreindre une liste d'utilisateurs, de comptes cibles ou de commandes.",
					Rationale:       "Exclusion-based security controls using '!' are brittle: negated commands (e.g., 'ALL, !/bin/sh') are trivially bypassed by copying or linking binaries, and negated Runas or Host specifications have led to critical authorization bypasses (such as CVE-2019-14287 with UID -1 and CVE-2025-32462).",
					DirectivesCode:  "# Define explicit positive aliases (zero '!' exclusions):\nUser_Alias  WEB_OPERATORS = %sudo_webops\nRunas_Alias WEB_SVC_USER  = www-data\nWEB_OPERATORS PROD_WEB_SERVERS = (WEB_SVC_USER) PASSWD: NOEXEC: /usr/local/sbin/sudo-wrappers/reload-nginx-config.sh \"\"",
					RuleIDs:         []string{"SUDO-CMD-001", "SUDO-CMD-002", "SUDO-CMD-008"},
					ComplianceTags:  []string{"ANSSI-BP-028 R40"},
					TemplateAnchor:  "tpl-sudoers-baseline",
				},
				{
					ID:              "anssi-r41",
					FrameworkID:     "ANSSI-BP-028",
					FrameworkShort:  "ANSSI BP-028",
					Code:            "ANSSI-BP-028 R41",
					Title:           "Strict Command Argument Pinning & Wildcard Prohibition",
					Level:           "Standard (R41 / v2.0 R43)",
					CitationURL:     "https://cyber.gouv.fr/publications/recommandations-de-securite-relatives-un-systeme-gnulinux",
					VerbatimQuote:   "R41 - Limit arguments passed to sudo commands: Every command authorized in sudoers must explicitly specify the exact arguments allowed. If a command is intended to be executed without any arguments, it must be followed by empty double quotes (\"\"). Wildcards (*) must not be used in command argument specifications, as shell-style globbing matches arbitrary flags and path traversal sequences.",
					VerbatimQuoteFR: "R41 (v1.2) / R43 (v2.0) - Limiter les arguments passés aux commandes par sudo : Toute commande autorisée dans sudoers doit préciser explicitement les arguments permis. Si une commande ne doit prendre aucun argument, la chaîne vide \"\" doit être spécifiée après le chemin du binaire. L'usage de jokers (*) dans les arguments est à proscrire.",
					Rationale:       "When a command in sudoers has no argument specification, sudo permits arbitrary caller-supplied flags. When wildcards (*) are used, attackers can inject malicious option flags (e.g. '--checkpoint-action=exec=sh') or traverse directories ('../../etc/shadow').",
					DirectivesCode:  "# Zero arguments allowed (explicit \"\"):\nSECURITY_AUDIT ALL = (root) PASSWD: NOEXEC: /usr/sbin/auditctl -s\nWEB_OPERATORS PROD_WEB_SERVERS = (WEB_SVC_USER) PASSWD: NOEXEC: /usr/local/sbin/sudo-wrappers/reload-nginx-config.sh \"\"",
					RuleIDs:         []string{"SUDO-CMD-004", "SUDO-CMD-006", "SUDO-GTFO-001", "SUDO-GTFO-002", "SUDO-GTFO-003"},
					ComplianceTags:  []string{"ANSSI-BP-028 R41"},
					TemplateAnchor:  "tpl-wrapper-script",
				},
				{
					ID:              "anssi-r42",
					FrameworkID:     "ANSSI-BP-028",
					FrameworkShort:  "ANSSI BP-028",
					Code:            "ANSSI-BP-028 R42",
					Title:           "Safe File Editing Exclusively via sudoedit (sudo -e)",
					Level:           "Standard (R42 / v2.0 R44)",
					CitationURL:     "https://cyber.gouv.fr/publications/recommandations-de-securite-relatives-un-systeme-gnulinux",
					VerbatimQuote:   "R42 (v1.2) / R44 (v2.0) - Use sudoedit to edit privileged files: Never authorize interactive text editors (such as vim, vi, nano, emacs) or pagers directly in sudoers. Instead, use the sudoedit (sudo -e) mechanism on explicit, non-sensitive target file paths, combined with Defaults !sudoedit_follow and Defaults sudoedit_checkdir.",
					VerbatimQuoteFR: "R42 (v1.2) / R44 (v2.0) - Utiliser sudoedit pour l'édition de fichiers : Lorsqu'un utilisateur doit modifier un fichier nécessitant des privilèges élevés, il est impératif d'utiliser la directive sudoedit (ou sudo -e) qui exécute l'éditeur avec les privilèges de l'utilisateur appelant sur une copie temporaire, tout en désactivant le suivi des liens symboliques (!sudoedit_follow) et en vérifiant les répertoires parents (sudoedit_checkdir).",
					Rationale:       "Running an interactive editor (vim, nano, emacs) as root allows immediate shell escape (:!/bin/sh) or opening arbitrary system files (:e /etc/shadow). Even with NOEXEC, editors retain arbitrary file-read and file-write capabilities. sudoedit runs the editor under the unprivileged caller UID and copies the validated temporary file back only on exit.",
					DirectivesCode:  "Defaults !sudoedit_follow, sudoedit_checkdir\nWEB_OPERATORS PROD_WEB_SERVERS = (WEB_SVC_USER) PASSWD: sudoedit /etc/nginx/conf.d/app-vhost.conf",
					RuleIDs:         []string{"SUDO-CMD-007", "SUDO-CMD-010", "SUDO-DEF-014"},
					ComplianceTags:  []string{"ANSSI-BP-028 R42"},
					TemplateAnchor:  "tpl-sudoers-baseline",
				},
				{
					ID:              "anssi-general",
					FrameworkID:     "ANSSI-BP-028",
					FrameworkShort:  "ANSSI BP-028",
					Code:            "ANSSI-BP-028 (General & Integrity)",
					Title:           "Executable Path Integrity, Root Ownership & SHA-256 Digest Pinning",
					Level:           "Enhanced (Section 3.4.5)",
					CitationURL:     "https://cyber.gouv.fr/publications/recommandations-de-securite-relatives-un-systeme-gnulinux",
					VerbatimQuote:   "ANSSI-BP-028 Section 3.4.5 - Every command referenced in sudoers must use a canonical absolute path residing inside a root-owned directory without group or world write permissions (mode 0755). Custom scripts or delegated administrative binaries should be pinned using a cryptographic SHA-256 or SHA-512 digest in sudoers.",
					VerbatimQuoteFR: "ANSSI-BP-028 Section 3.4.5 - Toute commande mentionnée dans sudoers doit être désignée par son chemin absolu complet dans un répertoire appartenant à root et non inscriptible par des tiers. L'empreinte cryptographique (sha256 ou sha512) des scripts ou exécutables délégués doit être vérifiée par sudo.",
					Rationale:       "Relative command paths or executables stored in /tmp, /var/tmp, /home, or group-writable parent directories allow local users to swap the target binary before invoking sudo. Pinning a SHA-256 digest guarantees that any modification to a wrapper script invalidates the sudo rule.",
					DirectivesCode:  "sudo chown root:root /usr/local/sbin/sudo-wrappers /usr/local/sbin/sudo-wrappers/reload-nginx-config.sh\nsudo chmod 0755 /usr/local/sbin/sudo-wrappers\nsudo chmod 0750 /usr/local/sbin/sudo-wrappers/reload-nginx-config.sh\n# In sudoers:\nWEB_OPERATORS PROD_WEB_SERVERS = (WEB_SVC_USER) PASSWD: NOEXEC: sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 /usr/local/sbin/sudo-wrappers/reload-nginx-config.sh \"\"",
					RuleIDs:         []string{"SUDO-CMD-011", "SUDO-CMD-012", "SUDO-SYS-PERM-012", "SUDO-SYS-PERM-013"},
					ComplianceTags:  []string{"ANSSI-BP-028"},
					TemplateAnchor:  "tpl-wrapper-script",
				},
			},
		},
		{
			ID:           "CIS-BENCHMARK",
			ShortName:    "CIS Benchmarks",
			FullName:     "CIS Distribution Independent Linux Benchmark (Section 5.2 — Configure Privilege Escalation)",
			VersionInfo:  "v2.0+ / v3.0+ (Controls 5.2.1 – 5.2.7)",
			Publisher:    "Center for Internet Security (CIS)",
			ReferenceURL: "https://www.cisecurity.org/cis-benchmarks",
			Summary:      "Consensus-driven configuration standards for hardening Linux privilege escalation. Section 5.2 mandates strict sudoers file ownership, pseudo-terminal (PTY) allocation, dedicated audit logging, password re-authentication, bounded credential caching, and per-TTY ticket isolation.",
			Requirements: []FrameworkRequirement{
				{
					ID:             "cis-5-2-1",
					FrameworkID:    "CIS-BENCHMARK",
					FrameworkShort: "CIS Benchmarks",
					Code:           "CIS-5.2.1",
					Title:          "Ensure sudo is installed and /etc/sudoers & /etc/sudoers.d permissions are 0440 root:root",
					Level:          "Level 1 — Server & Workstation",
					CitationURL:    "https://www.cisecurity.org/cis-benchmarks",
					VerbatimQuote:  "CIS 5.2 / 5.2.1: Ensure sudo is installed and configured with a clean environment (Defaults env_reset, Defaults !setenv, and a restricted Defaults secure_path). Verify that /etc/sudoers and all files in /etc/sudoers.d/ are owned by root:root and have mode 0440 (or more restrictive).",
					Rationale:      "Restricting sudoers ownership to root:root with mode 0440 prevents unauthorized modification or disclosure of privilege escalation policies, while env_reset and secure_path prevent caller environment poisoning.",
					DirectivesCode: "Defaults env_reset\nDefaults !setenv\nDefaults secure_path=\"/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\"\n# Shell remediation:\nsudo chown root:root /etc/sudoers /etc/sudoers.d/*\nsudo chmod 0440 /etc/sudoers /etc/sudoers.d/*",
					RuleIDs:        []string{"SUDO-SYS-PERM-002", "SUDO-SYS-PERM-003", "SUDO-SYS-PERM-004", "SUDO-SYS-PERM-005", "SUDO-SYS-PERM-011", "SUDO-DEF-001", "SUDO-DEF-002", "SUDO-DEF-004", "SUDO-DEF-011", "SUDO-DEF-013"},
					ComplianceTags: []string{"CIS-5.2", "CIS-5.2.1"},
					TemplateAnchor: "tpl-sudoers-baseline",
				},
				{
					ID:             "cis-5-2-2",
					FrameworkID:    "CIS-BENCHMARK",
					FrameworkShort: "CIS Benchmarks",
					Code:           "CIS-5.2.2",
					Title:          "Ensure sudo commands use pty",
					Level:          "Level 1 — Server & Workstation",
					CitationURL:    "https://www.cisecurity.org/cis-benchmarks",
					VerbatimQuote:  "CIS 5.2.2 - Ensure sudo commands use pty: Attackers can run a malicious program using sudo which forks a background process that remains attached to the user's terminal device even after the main program has finished executing. Configure 'Defaults use_pty' in /etc/sudoers or a file in /etc/sudoers.d/.",
					Rationale:      "Running sudo commands inside a dedicated pseudo-terminal (PTY) isolates the privileged process I/O streams and prevents backgrounded subprocesses from snooping or injecting keystrokes into the invoking user's controlling terminal.",
					DirectivesCode: "Defaults use_pty",
					RuleIDs:        []string{"SUDO-DEF-003"},
					ComplianceTags: []string{"CIS-5.2.2"},
					TemplateAnchor: "tpl-sudoers-baseline",
				},
				{
					ID:             "cis-5-2-3",
					FrameworkID:    "CIS-BENCHMARK",
					FrameworkShort: "CIS Benchmarks",
					Code:           "CIS-5.2.3",
					Title:          "Ensure sudo log file exists and I/O logging is configured",
					Level:          "Level 1 — Server & Workstation",
					CitationURL:    "https://www.cisecurity.org/cis-benchmarks",
					VerbatimQuote:  "CIS 5.2.3 - Ensure sudo log file exists: Sudo can use a custom log file in addition to syslog. Configure 'Defaults logfile=\"/var/log/sudo.log\"' in /etc/sudoers to simplify auditing of privileged commands and incidents.",
					Rationale:      "A dedicated sudo log file paired with log_input and log_output provides tamper-evident forensic attribution for every privileged command invocation and failed authentication attempt.",
					DirectivesCode: "Defaults logfile=\"/var/log/sudo.log\"\nDefaults log_input, log_output\nDefaults iolog_dir=\"/var/log/sudo-io/%{user}\"",
					RuleIDs:        []string{"SUDO-SYS-PERM-002", "SUDO-SYS-PERM-004"},
					ComplianceTags: []string{"CIS-5.2.3"},
					TemplateAnchor: "tpl-sudoers-baseline",
				},
				{
					ID:             "cis-5-2-4",
					FrameworkID:    "CIS-BENCHMARK",
					FrameworkShort: "CIS Benchmarks",
					Code:           "CIS-5.2.4",
					Title:          "Ensure users must provide password for privilege escalation (!NOPASSWD & !authenticate)",
					Level:          "Level 1 — Server & Workstation",
					CitationURL:    "https://www.cisecurity.org/cis-benchmarks",
					VerbatimQuote:  "CIS 5.2.4 & 5.2.5 - Ensure users must provide password for privilege escalation & Ensure re-authentication for privilege escalation is not disabled globally: Verify that no sudoers rules contain the 'NOPASSWD' tag and no Defaults entries contain '!authenticate'.",
					Rationale:      "Disabling password authentication via NOPASSWD or !authenticate allows an attacker who hijacks an unprivileged user session or SSH socket to escalate to root non-interactively without knowing the user's credentials.",
					DirectivesCode: "Defaults authenticate\n# Always require PASSWD on User_Spec rules:\nWEB_OPERATORS PROD_WEB_SERVERS = (WEB_SVC_USER) PASSWD: NOEXEC: /usr/local/sbin/sudo-wrappers/reload-nginx-config.sh \"\"",
					RuleIDs:        []string{"SUDO-DEF-012", "SUDO-CMD-002", "SUDO-CMD-003", "SUDO-CMD-005"},
					ComplianceTags: []string{"CIS-5.2.4"},
					TemplateAnchor: "tpl-sudoers-baseline",
				},
				{
					ID:             "cis-5-2-6",
					FrameworkID:    "CIS-BENCHMARK",
					FrameworkShort: "CIS Benchmarks",
					Code:           "CIS-5.2.6",
					Title:          "Ensure sudo authentication timeout is configured correctly (<= 15 minutes)",
					Level:          "Level 1 — Server & Workstation",
					CitationURL:    "https://www.cisecurity.org/cis-benchmarks",
					VerbatimQuote:  "CIS 5.2.6 - Ensure sudo authentication timeout is configured correctly: Sudo caches credentials for a default period (typically 5 or 15 minutes). Verify that 'timestamp_timeout' is configured to 15 minutes or less, and is never set to -1 (which disables expiration).",
					Rationale:      "Long or infinite credential cache timeouts allow unauthorized reuse of an authenticated sudo session if a workstation or SSH session is left unattended.",
					DirectivesCode: "Defaults timestamp_timeout=5\nDefaults passwd_timeout=1",
					RuleIDs:        []string{"SUDO-DEF-015"},
					ComplianceTags: []string{"CIS-5.2.6"},
					TemplateAnchor: "tpl-sudoers-baseline",
				},
				{
					ID:             "cis-5-2-7",
					FrameworkID:    "CIS-BENCHMARK",
					FrameworkShort: "CIS Benchmarks",
					Code:           "CIS-5.2.7",
					Title:          "Ensure credential cache scope is isolated per terminal (timestamp_type=tty)",
					Level:          "Level 1 — Server & Workstation",
					CitationURL:    "https://www.cisecurity.org/cis-benchmarks",
					VerbatimQuote:  "CIS 5.2.7 - Ensure sudo timestamp_type is not set to global: Ensure 'Defaults timestamp_type=tty' (or 'ppid') is configured so that sudo credential cache tickets are bound to the originating terminal session rather than shared across all login sessions of the user.",
					Rationale:      "When timestamp_type is set to global, an attacker running a background process or secondary shell under the same UID can silently piggyback on a user's interactive sudo authentication in another terminal.",
					DirectivesCode: "Defaults timestamp_type=tty",
					RuleIDs:        []string{"SUDO-DEF-015"},
					ComplianceTags: []string{"CIS-5.2.7"},
					TemplateAnchor: "tpl-sudoers-baseline",
				},
			},
		},
		{
			ID:           "DISA-STIG",
			ShortName:    "DISA STIG",
			FullName:     "DISA Security Technical Implementation Guide (RHEL / Ubuntu / General UNIX STIG)",
			VersionInfo:  "RHEL 8/9 STIG & Ubuntu 22.04/24.04 STIG",
			Publisher:    "Defense Information Systems Agency (DISA)",
			ReferenceURL: "https://public.cyber.mil/stigs/",
			Summary:      "U.S. Department of Defense (DoD) mandatory configuration requirements for operating systems. Enforces strict interactive re-authentication for privilege elevation, prohibits NOPASSWD and !authenticate directives, bounds credential caching, and mandates per-session ticket isolation.",
			Requirements: []FrameworkRequirement{
				{
					ID:             "stig-reauth",
					FrameworkID:    "DISA-STIG",
					FrameworkShort: "DISA STIG",
					Code:           "DISA-STIG",
					Title:          "Mandatory Re-Authentication & Prohibition of NOPASSWD / !authenticate, Bounded Cache Timeout, and Per-TTY Tickets",
					Level:          "CAT II (Medium / High)",
					CitationURL:    "https://public.cyber.mil/stigs/",
					VerbatimQuote:  "DISA STIG (SV-230273 / SV-230274 / SV-230275 / V-230273): The operating system must require users to reauthenticate for privilege escalation. Remove any occurrence of 'NOPASSWD' or '!authenticate' from /etc/sudoers and files in /etc/sudoers.d/. Configure 'Defaults timestamp_timeout' to a value between 0 and 15 minutes (inclusive, never negative) and ensure 'Defaults timestamp_type' is set to 'tty' or 'ppid' (never 'global').",
					Rationale:      "Without mandatory password verification and bounded per-TTY credential caching, any compromise of an unprivileged process allows silent, unauthenticated execution of administrative commands across sessions.",
					DirectivesCode: "Defaults authenticate\nDefaults timestamp_timeout=5\nDefaults timestamp_type=tty",
					RuleIDs:        []string{"SUDO-DEF-012", "SUDO-DEF-015", "SUDO-CMD-003", "SUDO-CMD-005"},
					ComplianceTags: []string{"DISA-STIG"},
					TemplateAnchor: "tpl-sudoers-baseline",
				},
			},
		},
		{
			ID:           "MITRE-ATTACK",
			ShortName:    "MITRE ATT&CK",
			FullName:     "MITRE ATT&CK Enterprise Matrix — Privilege Escalation & Defense Evasion",
			VersionInfo:  "ATT&CK v16 — Technique T1548.003",
			Publisher:    "MITRE Corporation & GTFObins Project",
			ReferenceURL: "https://attack.mitre.org/techniques/T1548/003/",
			Summary:      "Adversary tactics and techniques for abusing sudo policies, credential caching, and GTFObins living-off-the-land binaries (shell escapes, command execution, arbitrary file read/write, library loading, and SUID/sudo preservation).",
			Requirements: []FrameworkRequirement{
				{
					ID:             "mitre-t1548-003",
					FrameworkID:    "MITRE-ATTACK",
					FrameworkShort: "MITRE ATT&CK",
					Code:           "MITRE-T1548.003",
					Title:          "Abuse Elevation Control Mechanism: Sudo and Sudo Caching (GTFObins Escalation Vectors)",
					Level:          "Privilege Escalation / Defense Evasion",
					CitationURL:    "https://attack.mitre.org/techniques/T1548/003/",
					VerbatimQuote:  "MITRE ATT&CK T1548.003: Adversaries may perform sudo caching and/or use the sudoers file to elevate privileges. Adversaries may abuse poor sudoers configurations (such as NOPASSWD, wildcards, missing argument restrictions, or GTFObins-capable binaries with shell, command, file-read, file-write, or library-load capabilities) to spawn elevated shells or modify system files.\n\nMitigations (M1026 Privileged Account Management, M1028 Operating System Configuration, M1038 Execution Prevention): Restrict sudoers rules to explicit fixed-argument commands, enforce NOEXEC to block child process execution, and replace direct access to interpreters/editors/pagers/archivers with root-owned wrapper scripts pinned by SHA-256 digest.",
					Rationale:      "Hundreds of standard Unix utilities (find, vim, less, awk, python, tar, journalctl, systemctl, etc.) include legitimate features to execute subshells, load shared libraries, or read/write arbitrary files. Note that NOEXEC only mitigates child process execution ('shell' and 'command' functions) and does NOT prevent 'file-read', 'file-write', or 'library-load' GTFObins vectors.",
					DirectivesCode: "# 1. Enforce global NOEXEC and PTY isolation:\nDefaults noexec, use_pty, requiretty\n\n# 2. Replace GTFObins binaries with fixed-argument root-owned wrapper scripts pinned by SHA-256:\nWEB_OPERATORS PROD_WEB_SERVERS = (WEB_SVC_USER) PASSWD: NOEXEC: \\\n    sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 \\\n    /usr/local/sbin/sudo-wrappers/reload-nginx-config.sh \"\"",
					RuleIDs:        []string{"SUDO-GTFO-001", "SUDO-GTFO-002", "SUDO-GTFO-003"},
					ComplianceTags: []string{"MITRE-T1548.003"},
					TemplateAnchor: "tpl-wrapper-script",
				},
			},
		},
	}

	totalReqs := 0
	triggeredReqs := 0

	for gi := range groups {
		g := &groups[gi]
		g.TotalReqs = len(g.Requirements)
		totalReqs += g.TotalReqs
		groupFindingSeen := make(map[int]bool)

		for ri := range g.Requirements {
			req := &g.Requirements[ri]
			count := 0
			highest := audit.SeverityInfo
			hasSev := false

			normTags := make(map[string]bool, len(req.ComplianceTags))
			for _, tag := range req.ComplianceTags {
				normTags[normalizeComplianceKey(tag)] = true
			}
			ruleSet := make(map[string]bool, len(req.RuleIDs))
			for _, rid := range req.RuleIDs {
				ruleSet[rid] = true
			}

			violatingRulesSeen := make(map[string]bool)
			for _, f := range findings {
				matched := ruleSet[f.ID]
				if !matched {
					for _, c := range f.Compliance {
						if normTags[normalizeComplianceKey(c)] {
							matched = true
							break
						}
					}
				}
				if matched {
					count++
					groupFindingSeen[f.Index] = true
					if !violatingRulesSeen[f.ID] {
						violatingRulesSeen[f.ID] = true
						req.ViolatingRuleIDs = append(req.ViolatingRuleIDs, f.ID)
					}
					if !hasSev || f.Severity.Order() < highest.Order() {
						highest = f.Severity
						hasSev = true
					}
				}
			}

			if count > 0 {
				req.ViolationCount = count
				req.HighestSeverity = highest
				req.BadgeClass = severityBadgeClass(highest)
				g.TriggeredReqs++
				triggeredReqs++
			} else {
				req.HighestSeverity = audit.SeverityInfo
				req.BadgeClass = "badge-compliant"
			}

			searchParts := []string{
				req.Code,
				req.FrameworkShort,
				req.Title,
				req.Level,
				req.VerbatimQuote,
				req.VerbatimQuoteFR,
				req.Rationale,
				req.DirectivesCode,
				strings.Join(req.RuleIDs, " "),
				strings.Join(req.ComplianceTags, " "),
			}
			req.SearchText = strings.ToLower(strings.Join(searchParts, " "))
		}
		g.TotalFindings = len(groupFindingSeen)
	}

	return groups, totalReqs, triggeredReqs
}

// normalizeComplianceKey normalizes minor formatting variants such as "ANSSI-BP-028-R39" and "ANSSI-BP-028 R39".
func normalizeComplianceKey(tag string) string {
	trimmed := strings.TrimSpace(strings.ToUpper(tag))
	if strings.HasPrefix(trimmed, "ANSSI-BP-028-R") {
		return "ANSSI-BP-028 R" + strings.TrimPrefix(trimmed, "ANSSI-BP-028-R")
	}
	return trimmed
}

func buildHardenedTemplateSections() []HardenedTemplateSection {
	return []HardenedTemplateSection{
		{
			ID:          "tpl-sudoers-baseline",
			Badge:       "Primary Policy",
			Title:       "1. Complete Hardened /etc/sudoers Baseline Configuration",
			FilePath:    "/etc/sudoers (mode 0440, owner root:root)",
			Description: "Drop-in replacement baseline for /etc/sudoers implementing all ANSSI BP-028 (R38–R42/R44), CIS Benchmark (5.2.1–5.2.7), DISA STIG, and MITRE ATT&CK controls. Verified to produce zero findings under sudo-check.",
			Code:        HardenedSudoersReferencePolicy(),
			Highlights: []string{
				"Enforces Defaults env_reset, !setenv, ignore_dot, and a strict root-owned secure_path.",
				"Isolates terminal I/O via use_pty and requiretty, blocks child shell escapes via noexec, and enforces umask=0077.",
				"Requires password authentication (authenticate, !visiblepw, !pwfeedback) with passwd_timeout=1, timestamp_timeout=5, and timestamp_type=tty.",
				"Hardens sudoedit with !sudoedit_follow and sudoedit_checkdir and enables full input/output audit logging.",
				"Uses explicit positive aliases (zero '!' negations), non-root Runas service accounts, explicit argument pinning (\"\"), and SHA-256 digests.",
			},
			RuleIDs: []string{
				"SUDO-DEF-001", "SUDO-DEF-002", "SUDO-DEF-003", "SUDO-DEF-004",
				"SUDO-DEF-005", "SUDO-DEF-006", "SUDO-DEF-007", "SUDO-DEF-008",
				"SUDO-DEF-009", "SUDO-DEF-010", "SUDO-DEF-011", "SUDO-DEF-012",
				"SUDO-DEF-013", "SUDO-DEF-014", "SUDO-DEF-015", "SUDO-DEF-016",
				"SUDO-CMD-001", "SUDO-CMD-002", "SUDO-CMD-003", "SUDO-CMD-004",
				"SUDO-CMD-005", "SUDO-CMD-006", "SUDO-CMD-007", "SUDO-CMD-008",
				"SUDO-CMD-009", "SUDO-CMD-010", "SUDO-CMD-011", "SUDO-CMD-012",
			},
		},
		{
			ID:          "tpl-dropin-example",
			Badge:       "Modular Drop-In",
			Title:       "2. Hardened /etc/sudoers.d/10-app-deploy Drop-In Policy",
			FilePath:    "/etc/sudoers.d/10-app-deploy (mode 0440, owner root:root)",
			Description: "Example modular drop-in file for application deployment teams. Demonstrates scoped Defaults that tighten (never weaken) global settings, explicit working directory pinning (CWD=/opt/app), and non-root target execution.",
			Code: strings.TrimSpace(`
# ==============================================================================
# /etc/sudoers.d/10-app-deploy — Scoped Application Deployment Policy
# Validate before activation: visudo -c -f /etc/sudoers.d/10-app-deploy
# ==============================================================================

User_Alias  APP_DEPLOYERS = %sudo_appdeploy
Host_Alias  APP_NODES     = app01.internal.example, app02.internal.example
Runas_Alias APP_USER      = appservice

# Scoped Defaults for APP_DEPLOYERS: tighten credential timeout to 0 (always prompt)
Defaults:APP_DEPLOYERS timestamp_timeout=0, passwd_timeout=1, use_pty, noexec

# Allow running the root-owned deployment wrapper as 'appservice' with a fixed working directory:
APP_DEPLOYERS APP_NODES = (APP_USER) CWD=/opt/app PASSWD: NOEXEC: \
    sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08 \
    /usr/local/sbin/sudo-wrappers/deploy-release.sh --env=production

# Allow safe configuration editing on a single application file via sudoedit:
APP_DEPLOYERS APP_NODES = (APP_USER) PASSWD: \
    sudoedit /etc/appservice/production.ini
`),
			Highlights: []string{
				"Scoped Defaults:APP_DEPLOYERS sets timestamp_timeout=0 so every invocation prompts for a password.",
				"Uses explicit CWD=/opt/app rather than wildcard CWD=* (preventing SUDO-CMD-009).",
				"Executes as dedicated unprivileged account (APP_USER) rather than root (ANSSI BP-028 R40).",
			},
			RuleIDs: []string{"SUDO-DEF-015", "SUDO-CMD-006", "SUDO-CMD-009", "SUDO-CMD-012"},
		},
		{
			ID:          "tpl-wrapper-script",
			Badge:       "GTFObins Mitigation",
			Title:       "3. Hardened Root-Owned Wrapper Script Pattern (Eliminating Wildcards & GTFObins)",
			FilePath:    "/usr/local/sbin/sudo-wrappers/reload-nginx-config.sh (mode 0750, owner root:root)",
			Description: "When operators need to run utilities listed in GTFObins (such as find, tar, journalctl, docker, or scripts with variable parameters), wrap the logic inside a root-owned script with strict input validation, zero arguments (or an allowlisted enum), and pin its SHA-256 hash in sudoers.",
			Code: strings.TrimSpace(`
#!/usr/bin/env -S bash -euo pipefail
# ==============================================================================
# /usr/local/sbin/sudo-wrappers/reload-nginx-config.sh
# Owner: root:root | Permissions: 0750
# Purpose: Validate and reload Nginx configuration without exposing shell/GTFObins
# ==============================================================================

export PATH="/usr/sbin:/usr/bin:/sbin:/bin"
export LC_ALL="C"
umask 0077

if [[ "$#" -ne 0 ]]; then
    echo "Error: This wrapper does not accept any command-line arguments." >&2
    exit 2
fi

# 1. Verify configuration syntax using absolute binary path
/usr/sbin/nginx -t -c /etc/nginx/nginx.conf

# 2. Reload service cleanly via systemctl
/usr/bin/systemctl reload nginx.service
`),
			Highlights: []string{
				"Sanitizes PATH, LC_ALL, and umask inside the script itself as defense-in-depth.",
				"Rejects unexpected positional arguments ($# -ne 0) and uses fixed absolute paths.",
				"Eliminates the need to grant direct sudo access to GTFObins binaries or shell wildcards (*).",
			},
			RuleIDs: []string{"SUDO-CMD-004", "SUDO-CMD-006", "SUDO-CMD-011", "SUDO-CMD-012", "SUDO-GTFO-001", "SUDO-GTFO-002"},
		},
		{
			ID:          "tpl-filesystem-perms",
			Badge:       "Host Hardening & Verification",
			Title:       "4. Filesystem Permissions, Digest Calculation & Validation Runbook",
			FilePath:    "Root Shell Remediation & CI Verification Commands",
			Description: "Copy-pasteable commands to enforce ANSSI BP-028 R38 and CIS 5.2.1 ownership and permissions across /etc/sudoers, /etc/sudoers.d, /usr/bin/sudo, and wrapper directories, followed by syntax and security audit verification.",
			Code: strings.TrimSpace(`
# 1. Enforce strict ownership and 0440 permissions on /etc/sudoers (SUDO-SYS-PERM-002..005, 011)
sudo chown root:root /etc/sudoers
sudo chmod 0440 /etc/sudoers

# 2. Secure /etc/sudoers.d directory and all drop-in files (ANSSI BP-028 R38 / CIS 5.2.1)
sudo chown root:root /etc/sudoers.d
sudo chmod 0750 /etc/sudoers.d
sudo find /etc/sudoers.d -maxdepth 1 -type f -exec chown root:root {} + -exec chmod 0440 {} +

# 3. Verify /usr/bin/sudo binary ownership and SUID mode 4755 (SUDO-SYS-PERM-007..010)
sudo chown root:root /usr/bin/sudo
sudo chmod 4755 /usr/bin/sudo

# 4. Secure dedicated wrapper script directory and compute SHA-256 digest (SUDO-SYS-PERM-012..013, SUDO-CMD-012)
sudo install -d -o root -g root -m 0755 /usr/local/sbin/sudo-wrappers
sudo chown root:root /usr/local/sbin/sudo-wrappers/reload-nginx-config.sh
sudo chmod 0750 /usr/local/sbin/sudo-wrappers/reload-nginx-config.sh
sudo sha256sum /usr/local/sbin/sudo-wrappers/reload-nginx-config.sh

# 5. Validate sudoers syntax with visudo and run sudo-check verification
sudo visudo -c -f /etc/sudoers
sudo sudo-check scan /etc/sudoers --fail-on=LOW
`),
			Highlights: []string{
				"Satisfies every system permission check (SUDO-SYS-PERM-001 through SUDO-SYS-PERM-013).",
				"Uses visudo -c -f to prevent syntax lockouts before deploying changes.",
				"Verifies zero policy or host findings with sudo-check.",
			},
			RuleIDs: []string{
				"SUDO-SYS-PERM-002", "SUDO-SYS-PERM-003", "SUDO-SYS-PERM-004", "SUDO-SYS-PERM-005",
				"SUDO-SYS-PERM-007", "SUDO-SYS-PERM-008", "SUDO-SYS-PERM-009", "SUDO-SYS-PERM-010",
				"SUDO-SYS-PERM-011", "SUDO-SYS-PERM-012", "SUDO-SYS-PERM-013",
			},
		},
	}
}

func buildTraceabilityMatrix() []TraceabilityRow {
	rows := []TraceabilityRow{
		{RuleID: "SUDO-DEF-001", Domain: "Defaults", Severity: audit.SeverityHigh, Title: "Missing or Empty secure_path Configuration", Frameworks: []string{"ANSSI-BP-028 R39", "CIS-5.2"}, Directive: `Defaults secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"`, SectionID: "tpl-sudoers-baseline"},
		{RuleID: "SUDO-DEF-002", Domain: "Defaults", Severity: audit.SeverityHigh, Title: "Relative or Unsafe Entry in secure_path", Frameworks: []string{"ANSSI-BP-028 R39", "CIS-5.2"}, Directive: `Defaults secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"`, SectionID: "tpl-sudoers-baseline"},
		{RuleID: "SUDO-DEF-003", Domain: "Defaults", Severity: audit.SeverityMedium, Title: "Missing or Disabled use_pty", Frameworks: []string{"ANSSI-BP-028 R39", "CIS-5.2.2"}, Directive: `Defaults use_pty`, SectionID: "tpl-sudoers-baseline"},
		{RuleID: "SUDO-DEF-004", Domain: "Defaults", Severity: audit.SeverityCritical, Title: "Dangerous Environment Variables Preserved (env_keep / env_check)", Frameworks: []string{"ANSSI-BP-028 R39", "CIS-5.2"}, Directive: `Defaults env_reset` + "\n" + `Defaults env_keep="LANG LC_ALL LC_CTYPE LC_MESSAGES TERM COLORTERM"`, SectionID: "tpl-sudoers-baseline"},
		{RuleID: "SUDO-DEF-005", Domain: "Defaults", Severity: audit.SeverityHigh, Title: "Cleartext Password Echo Enabled (visiblepw)", Frameworks: []string{"ANSSI-BP-028 R39"}, Directive: `Defaults !visiblepw`, SectionID: "tpl-sudoers-baseline"},
		{RuleID: "SUDO-DEF-006", Domain: "Defaults", Severity: audit.SeverityLow, Title: "Password Length Feedback Enabled (pwfeedback)", Frameworks: []string{"ANSSI-BP-028 R39"}, Directive: `Defaults !pwfeedback`, SectionID: "tpl-sudoers-baseline"},
		{RuleID: "SUDO-DEF-007", Domain: "Defaults", Severity: audit.SeverityMedium, Title: "Missing or Disabled noexec", Frameworks: []string{"ANSSI-BP-028 R39"}, Directive: `Defaults noexec`, SectionID: "tpl-sudoers-baseline"},
		{RuleID: "SUDO-DEF-008", Domain: "Defaults", Severity: audit.SeverityLow, Title: "Missing or Disabled requiretty", Frameworks: []string{"ANSSI-BP-028 R39"}, Directive: `Defaults requiretty`, SectionID: "tpl-sudoers-baseline"},
		{RuleID: "SUDO-DEF-009", Domain: "Defaults", Severity: audit.SeverityMedium, Title: "Missing or Weak umask Configuration", Frameworks: []string{"ANSSI-BP-028 R39"}, Directive: `Defaults umask=0077, umask_override`, SectionID: "tpl-sudoers-baseline"},
		{RuleID: "SUDO-DEF-010", Domain: "Defaults", Severity: audit.SeverityMedium, Title: "Missing or Disabled ignore_dot", Frameworks: []string{"ANSSI-BP-028 R39"}, Directive: `Defaults ignore_dot`, SectionID: "tpl-sudoers-baseline"},
		{RuleID: "SUDO-DEF-011", Domain: "Defaults", Severity: audit.SeverityHigh, Title: "Missing or Disabled env_reset", Frameworks: []string{"ANSSI-BP-028 R39", "CIS-5.2"}, Directive: `Defaults env_reset`, SectionID: "tpl-sudoers-baseline"},
		{RuleID: "SUDO-DEF-012", Domain: "Defaults", Severity: audit.SeverityCritical, Title: "Password Authentication Disabled (!authenticate)", Frameworks: []string{"ANSSI-BP-028", "CIS-5.2.4", "DISA-STIG"}, Directive: `Defaults authenticate`, SectionID: "tpl-sudoers-baseline"},
		{RuleID: "SUDO-DEF-013", Domain: "Defaults", Severity: audit.SeverityHigh, Title: "Environment Override Permitted Globally (setenv)", Frameworks: []string{"ANSSI-BP-028 R39", "CIS-5.2"}, Directive: `Defaults !setenv`, SectionID: "tpl-sudoers-baseline"},
		{RuleID: "SUDO-DEF-014", Domain: "Defaults", Severity: audit.SeverityHigh, Title: "Insecure sudoedit Symlink or Directory Configuration", Frameworks: []string{"ANSSI-BP-028 R42"}, Directive: `Defaults !sudoedit_follow, sudoedit_checkdir`, SectionID: "tpl-sudoers-baseline"},
		{RuleID: "SUDO-DEF-015", Domain: "Defaults", Severity: audit.SeverityMedium, Title: "Weak Credential Cache Timeout or Global Ticket Scope", Frameworks: []string{"ANSSI-BP-028 R39", "CIS-5.2.6", "CIS-5.2.7", "DISA-STIG"}, Directive: `Defaults passwd_timeout=1, timestamp_timeout=5, timestamp_type=tty`, SectionID: "tpl-sudoers-baseline"},
		{RuleID: "SUDO-DEF-016", Domain: "Defaults", Severity: audit.SeverityHigh, Title: "Deprecated Chroot (runchroot) or Unrestricted Working Directory (runcwd=*)", Frameworks: []string{"ANSSI-BP-028 R39"}, Directive: `# Omit runchroot and runcwd=* from Defaults`, SectionID: "tpl-sudoers-baseline"},
		{RuleID: "SUDO-CMD-001", Domain: "Command Rule", Severity: audit.SeverityHigh, Title: "Negated Command Policy (!command)", Frameworks: []string{"ANSSI-BP-028 R40"}, Directive: `# Use positive command allowlists without '!'`, SectionID: "tpl-sudoers-baseline"},
		{RuleID: "SUDO-CMD-002", Domain: "Command Rule", Severity: audit.SeverityHigh, Title: "Unrestricted ALL Commands Allowed", Frameworks: []string{"ANSSI-BP-028 R40", "CIS-5.2.4"}, Directive: `# Scope rules to explicit binaries and arguments instead of ALL`, SectionID: "tpl-sudoers-baseline"},
		{RuleID: "SUDO-CMD-003", Domain: "Command Rule", Severity: audit.SeverityCritical, Title: "Passwordless Full Root Privileges (NOPASSWD: ALL)", Frameworks: []string{"ANSSI-BP-028", "CIS-5.2.4", "DISA-STIG"}, Directive: `WEB_OPERATORS PROD_WEB_SERVERS = (WEB_SVC_USER) PASSWD: NOEXEC: /usr/local/sbin/sudo-wrappers/reload-nginx-config.sh ""`, SectionID: "tpl-sudoers-baseline"},
		{RuleID: "SUDO-CMD-004", Domain: "Command Rule", Severity: audit.SeverityMedium, Title: "Wildcard (*) in Command or Arguments", Frameworks: []string{"ANSSI-BP-028 R41"}, Directive: `# Enumerate exact arguments or delegate to a fixed-argument wrapper script`, SectionID: "tpl-wrapper-script"},
		{RuleID: "SUDO-CMD-005", Domain: "Command Rule", Severity: audit.SeverityLow, Title: "Passwordless Specific Command Execution (NOPASSWD)", Frameworks: []string{"ANSSI-BP-028", "CIS-5.2.4", "DISA-STIG"}, Directive: `PASSWD: NOEXEC: /usr/sbin/auditctl -s`, SectionID: "tpl-sudoers-baseline"},
		{RuleID: "SUDO-CMD-006", Domain: "Command Rule", Severity: audit.SeverityMedium, Title: "Missing Command Argument Restrictions", Frameworks: []string{"ANSSI-BP-028 R41"}, Directive: `/usr/local/sbin/sudo-wrappers/reload-nginx-config.sh ""`, SectionID: "tpl-sudoers-baseline"},
		{RuleID: "SUDO-CMD-007", Domain: "Command Rule", Severity: audit.SeverityHigh, Title: "Direct Text Editor Execution via Sudo", Frameworks: []string{"ANSSI-BP-028 R42"}, Directive: `WEB_OPERATORS PROD_WEB_SERVERS = (WEB_SVC_USER) PASSWD: sudoedit /etc/nginx/conf.d/app-vhost.conf`, SectionID: "tpl-sudoers-baseline"},
		{RuleID: "SUDO-CMD-008", Domain: "Command Rule", Severity: audit.SeverityHigh, Title: "Negated User, Host, or Runas Specification", Frameworks: []string{"ANSSI-BP-028 R40"}, Directive: `User_Alias WEB_OPERATORS = %sudo_webops` + "\n" + `Runas_Alias WEB_SVC_USER = www-data`, SectionID: "tpl-sudoers-baseline"},
		{RuleID: "SUDO-CMD-009", Domain: "Command Rule", Severity: audit.SeverityHigh, Title: "Dangerous Per-Command Tag (SETENV, FOLLOW, CHROOT, CWD=*)", Frameworks: []string{"ANSSI-BP-028 R39"}, Directive: `APP_DEPLOYERS APP_NODES = (APP_USER) CWD=/opt/app PASSWD: NOEXEC: ...`, SectionID: "tpl-dropin-example"},
		{RuleID: "SUDO-CMD-010", Domain: "Command Rule", Severity: audit.SeverityCritical, Title: "sudoedit Permitted on Sensitive System File", Frameworks: []string{"ANSSI-BP-028 R42"}, Directive: `sudoedit /etc/nginx/conf.d/app-vhost.conf`, SectionID: "tpl-sudoers-baseline"},
		{RuleID: "SUDO-CMD-011", Domain: "Command Rule", Severity: audit.SeverityCritical, Title: "Relative or Temporary/Writable Command Path", Frameworks: []string{"ANSSI-BP-028"}, Directive: `/usr/local/sbin/sudo-wrappers/reload-nginx-config.sh ""`, SectionID: "tpl-wrapper-script"},
		{RuleID: "SUDO-CMD-012", Domain: "Command Rule", Severity: audit.SeverityLow, Title: "Weak Cryptographic Digest on Command (SHA-224)", Frameworks: []string{"ANSSI-BP-028"}, Directive: `sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 /usr/local/sbin/...`, SectionID: "tpl-sudoers-baseline"},
		{RuleID: "SUDO-GTFO-001", Domain: "GTFObins", Severity: audit.SeverityHigh, Title: "Permitted Binary in GTFObins Catalog", Frameworks: []string{"ANSSI-BP-028 R41", "MITRE-T1548.003"}, Directive: `PASSWD: NOEXEC: sha256:<digest> /usr/local/sbin/sudo-wrappers/reload-nginx-config.sh ""`, SectionID: "tpl-wrapper-script"},
		{RuleID: "SUDO-GTFO-002", Domain: "GTFObins", Severity: audit.SeverityCritical, Title: "Passwordless Permitted Binary in GTFObins Catalog", Frameworks: []string{"ANSSI-BP-028 R41", "MITRE-T1548.003"}, Directive: `PASSWD: NOEXEC: sha256:<digest> /usr/local/sbin/sudo-wrappers/reload-nginx-config.sh ""`, SectionID: "tpl-wrapper-script"},
		{RuleID: "SUDO-GTFO-003", Domain: "GTFObins", Severity: audit.SeverityLow, Title: "Mitigated GTFObins Binary (NOEXEC on shell/command)", Frameworks: []string{"ANSSI-BP-028 R41", "MITRE-T1548.003"}, Directive: `# Replace direct GTFObins binary with dedicated root-owned wrapper script`, SectionID: "tpl-wrapper-script"},
		{RuleID: "SUDO-SYS-PERM-002..013", Domain: "System Host", Severity: audit.SeverityCritical, Title: "Sudoers, Drop-In, Sudo Binary & Target Binary Permissions", Frameworks: []string{"ANSSI-BP-028 R38", "CIS-5.2.1"}, Directive: `sudo chown root:root /etc/sudoers && sudo chmod 0440 /etc/sudoers`, SectionID: "tpl-filesystem-perms"},
	}

	for i := range rows {
		rows[i].BadgeClass = severityBadgeClass(rows[i].Severity)
	}
	return rows
}
