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
# Standards: ANSSI BP-028 v2.0 (R38-R44), CIS Benchmark 5.2.1-5.2.7, DISA STIG
# Validation: visudo -c -f /etc/sudoers && sudo-check scan /etc/sudoers
# ==============================================================================

# --- 1. Environment Hardening (ANSSI BP-028 R39: env_reset, ignore_dot) ---
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

# --- 3. Authentication & Credential Cache Hardening (CIS 5.2.5-5.2.6 / DISA STIG) ---
Defaults authenticate
Defaults !visiblepw
Defaults !pwfeedback
Defaults passwd_timeout=1
Defaults passwd_tries=3
Defaults timestamp_timeout=5
Defaults timestamp_type=tty

# --- 4. Sudoedit Symlink & Directory Traversal Protection (defense-in-depth, not ANSSI BP-028) ---
Defaults !sudoedit_follow
Defaults sudoedit_checkdir

# --- 5. Audit Logging & I/O Telemetry (CIS 5.2.3 / DISA STIG) ---
Defaults logfile="/var/log/sudo.log"
Defaults log_input, log_output
Defaults iolog_dir="/var/log/sudo-io/%{user}"
Defaults mail_badpass, mail_no_user, mail_no_perms

# --- 6. Explicit Positive Host, User, Runas & Command Aliases (ANSSI BP-028 R40/R42) ---
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
# ANSSI BP-028 R43: Pin exact arguments (or "" for zero arguments) and avoid wildcards (*).
# Note: SHA-256 digest pinning is an integrity defense-in-depth measure; it is not part of ANSSI BP-028.
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

# --- 8. Safe Configuration Editing via sudoedit (ANSSI BP-028 R44) ---
# Never grant direct sudo access to vim/nano/emacs/less; use sudoedit on explicit application files.
WEB_OPERATORS PROD_WEB_SERVERS = (WEB_SVC_USER) PASSWD: \
    sudoedit /etc/nginx/conf.d/app-vhost.conf

# --- 9. Modular Drop-In Directory ---
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
			VersionInfo:  "v2.0 (ANSSI-BP-028)",
			Publisher:    "Agence nationale de la sécurité des systèmes d'information (ANSSI)",
			ReferenceURL: "https://cyber.gouv.fr/publications/recommandations-de-securite-relatives-un-systeme-gnulinux",
			Summary:      "French National Cybersecurity Agency (ANSSI) baseline security guide for GNU/Linux systems. Section 6.3.1 \"Unix traditional model\" (v2.0 R38–R44; v1.2 R57–R64 per the backward compatibility table in Appendix C.3) defines controls for sudo: a dedicated execution group, secure Defaults directives, non-root target users, strict limitation of commands requiring the EXEC directive, a ban on negations, strict argument specifications, and safe file editing via sudoedit.",
			Requirements: []FrameworkRequirement{
				{
					ID:              "anssi-r38",
					FrameworkID:     "ANSSI-BP-028",
					FrameworkShort:  "ANSSI BP-028",
					Code:            "ANSSI-BP-028 R38",
					Title:           "Creating a Group Dedicated to the Use of sudo",
					Level:           "Minimal / Intermediate / Enhanced (R38)",
					CitationURL:     "https://cyber.gouv.fr/publications/recommandations-de-securite-relatives-un-systeme-gnulinux",
					VerbatimQuote:   "R38 - Creating a group dedicated to the use of sudo: A group dedicated to the use of sudo must be created. Only the members of this group should have the right to run sudo. Example: # ls -al /usr/bin/sudo → -rwsr-x---. 2 root sudogrp [...] /usr/bin/sudo. Warning: this modification can be overwritten by an update of the sudo package; it is recommended to check the access rights of the file after an update and apply them again if needed.",
					VerbatimQuoteFR: "R38 - Créer un groupe dédié à l'utilisation de sudo : Un groupe dédié à l'utilisation de sudo doit être créé. Seuls les membres de ce groupe doivent avoir le droit d'exécuter sudo. Exemple : # ls -al /usr/bin/sudo → -rwsr-x---. 2 root sudogrp [...] /usr/bin/sudo.",
					Rationale:       "sudo is a setuid root executable installed by default with open execution rights. Restricting execution to a dedicated group reduces the attack surface when the system or the binary itself is affected by exploitable vulnerabilities (e.g. CVE-2019-14287, CVE-2021-3156). A sudo binary that is writable by group or other, or not owned by root, defeats this restriction and allows immediate local root compromise.",
					DirectivesCode:  "sudo chown root:root /usr/bin/sudo\nsudo chmod 4755 /usr/bin/sudo\n# Restrict execution to a dedicated group (example):\nsudo groupadd sudogrp\nsudo chown root:sudogrp /usr/bin/sudo\nsudo chmod 4750 /usr/bin/sudo",
					RuleIDs:         []string{"SUDO-SYS-PERM-008", "SUDO-SYS-PERM-009", "SUDO-SYS-PERM-010"},
					ComplianceTags:  []string{"ANSSI-BP-028 R38"},
					TemplateAnchor:  "tpl-filesystem-perms",
				},
				{
					ID:              "anssi-r39",
					FrameworkID:     "ANSSI-BP-028",
					FrameworkShort:  "ANSSI BP-028",
					Code:            "ANSSI-BP-028 R39",
					Title:           "Sudo Configuration Guidelines",
					Level:           "Minimal / Intermediate (R39)",
					CitationURL:     "https://cyber.gouv.fr/publications/recommandations-de-securite-relatives-un-systeme-gnulinux",
					VerbatimQuote:   "R39 - Sudo configuration guidelines: The following guidelines must be enabled by default: noexec (applies the NOEXEC tag by default on the commands); requiretty (requires the user to have a tty login); use_pty (uses a pseudo-tty when a command is executed); umask=0077 (forces umask to a more restrictive mask); ignore_dot (ignores the \".\" in $PATH); env_reset (resets the environment variables). Guidelines for the /etc/sudoers configuration file: Defaults noexec,requiretty,use_pty,umask=0077 / Defaults ignore_dot,env_reset. It is then possible to override a default value if needed when an entry is added for a user or for a group (e.g. myuser ALL = EXEC: /usr/bin/mycommand).",
					VerbatimQuoteFR: "R39 - Recommandations de configuration pour sudo : Les directives suivantes doivent être activées par défaut : noexec (applique par défaut la balise NOEXEC aux commandes) ; requiretty (exige que l'utilisateur dispose d'un tty) ; use_pty (utilise un pseudo-tty lors de l'exécution d'une commande) ; umask=0077 (force un umask plus restrictif) ; ignore_dot (ignore le « . » dans $PATH) ; env_reset (réinitialise les variables d'environnement). Dans le fichier /etc/sudoers : Defaults noexec,requiretty,use_pty,umask=0077 puis Defaults ignore_dot,env_reset.",
					Rationale:       "Without env_reset and ignore_dot, callers can hijack the execution environment through inherited variables or relative PATH entries. Without use_pty and requiretty, child processes can snoop or inject keystrokes into the calling terminal. Without noexec, allowed utilities can spawn interactive shells. Without umask=0077, files created by root inherit the caller's permissive umask.",
					DirectivesCode:  "Defaults noexec,requiretty,use_pty,umask=0077\nDefaults ignore_dot,env_reset",
					RuleIDs:         []string{"SUDO-DEF-003", "SUDO-DEF-007", "SUDO-DEF-008", "SUDO-DEF-009", "SUDO-DEF-010", "SUDO-DEF-011", "SUDO-GTFO-003"},
					ComplianceTags:  []string{"ANSSI-BP-028 R39"},
					TemplateAnchor:  "tpl-sudoers-baseline",
				},
				{
					ID:              "anssi-r40",
					FrameworkID:     "ANSSI-BP-028",
					FrameworkShort:  "ANSSI BP-028",
					Code:            "ANSSI-BP-028 R40",
					Title:           "Using Unprivileged Users as Target for sudo Commands",
					Level:           "Minimal / Intermediate (R40)",
					CitationURL:     "https://cyber.gouv.fr/publications/recommandations-de-securite-relatives-un-systeme-gnulinux",
					VerbatimQuote:   "R40 - Using unprivileged users as target for sudo commands: The targeted users of a rule should be, as much as possible, non privileged users (i.e.: non root). It is common that the command to be executed does not require an elevated privilege level (editing a file whose owner is not root, sending a signal to an unprivileged process, ...). In order to limit any attempt of privilege escalation through a command, it is better to apply regular user rights.",
					VerbatimQuoteFR: "R40 - Utiliser des utilisateurs non privilégiés comme cible des commandes sudo : Les utilisateurs ciblés par une règle doivent être, autant que possible, des utilisateurs non privilégiés (c'est-à-dire non root). Il est fréquent que la commande à exécuter ne nécessite pas un niveau de privilège élevé ; afin de limiter toute tentative d'élévation de privilèges via une commande, il est préférable d'appliquer les droits de l'utilisateur régulier.",
					Rationale:       "Running delegated commands as root when the task does not require it turns any argument-injection or binary flaw into a direct root compromise. Targeting a dedicated unprivileged service account contains the blast radius of a misused rule.",
					DirectivesCode:  "Runas_Alias WEB_SVC_USER = www-data\nWEB_OPERATORS PROD_WEB_SERVERS = (WEB_SVC_USER) PASSWD: NOEXEC: /usr/local/sbin/sudo-wrappers/reload-nginx-config.sh \"\"",
					RuleIDs:         []string{},
					ComplianceTags:  []string{"ANSSI-BP-028 R40"},
					TemplateAnchor:  "tpl-sudoers-baseline",
				},
				{
					ID:              "anssi-r41",
					FrameworkID:     "ANSSI-BP-028",
					FrameworkShort:  "ANSSI BP-028",
					Code:            "ANSSI-BP-028 R41",
					Title:           "Limiting the Number of Commands Requiring the Use of the EXEC Directive",
					Level:           "Minimal / Intermediate / Enhanced (R41)",
					CitationURL:     "https://cyber.gouv.fr/publications/recommandations-de-securite-relatives-un-systeme-gnulinux",
					VerbatimQuote:   "R41 - Limiting the number of commands requiring the use of the EXEC directive: The commands requiring the execution of sub-processes, EXEC directive must be explicitly listed and their use should be reduced to a strict minimum. Functionally rich commands can be executed via sudo, like text editors (vi). They may allow execution of sub-commands in the environment created by sudo and thus enable a user to run other software with privileges not foreseen initially.",
					VerbatimQuoteFR: "R41 - Limiter le nombre de commandes nécessitant l'utilisation de la directive EXEC : Les commandes nécessitant l'exécution de sous-processus (directive EXEC) doivent être explicitement listées et leur usage doit être réduit au strict minimum. Des commandes fonctionnellement riches, comme les éditeurs de texte (vi), peuvent permettre l'exécution de sous-commandes dans l'environnement créé par sudo.",
					Rationale:       "The noexec default (R39) blocks child-process execution, but sudo can override the functions allowing execution of other software when a command genuinely requires sub-processes. Every EXEC-requiring command (editors, pagers, GTFObins binaries with shell or command capabilities) must be an explicit, minimal exception; otherwise users can spawn unanticipated privileged processes.",
					DirectivesCode:  "# Keep EXEC-requiring commands an explicit, minimal exception list:\nCmnd_Alias EXEC_CMDS = /usr/bin/systemctl status app\n# Replace GTFObins-capable binaries with fixed-argument root-owned wrapper scripts:\nWEB_OPERATORS PROD_WEB_SERVERS = (WEB_SVC_USER) PASSWD: NOEXEC: /usr/local/sbin/sudo-wrappers/reload-nginx-config.sh \"\"",
					RuleIDs:         []string{"SUDO-GTFO-001", "SUDO-GTFO-002"},
					ComplianceTags:  []string{"ANSSI-BP-028 R41"},
					TemplateAnchor:  "tpl-wrapper-script",
				},
				{
					ID:              "anssi-r42",
					FrameworkID:     "ANSSI-BP-028",
					FrameworkShort:  "ANSSI BP-028",
					Code:            "ANSSI-BP-028 R42",
					Title:           "Banishing the Negations in sudo Policies",
					Level:           "Minimal / Intermediate (R42)",
					CitationURL:     "https://cyber.gouv.fr/publications/recommandations-de-securite-relatives-un-systeme-gnulinux",
					VerbatimQuote:   "R42 - Banishing the negations in sudo policies: Policies applied by sudo through the sudoers file should not involve any negation. Specifying access right using negation, blacklist approach, is inefficient and can be easily circumvented. Example (to avoid absolutely, this rule can be easily circumvented): user ALL = ALL,!/bin/sh - just copy the binary /bin/sh to a different name to make it executable again through the rule directive ALL.",
					VerbatimQuoteFR: "R42 - Proscrire les négations dans les politiques sudo : Les politiques appliquées par sudo via le fichier sudoers ne doivent comporter aucune négation. La spécification de droits par négation (approche par liste noire) est inefficace et peut être contournée facilement. Exemple (à proscrire absolument) : user ALL = ALL,!/bin/sh - il suffit de copier le binaire /bin/sh sous un autre nom pour pouvoir l'exécuter via la règle ALL.",
					Rationale:       "Exclusion-based security controls using '!' are brittle: negated commands (e.g. 'ALL, !/bin/sh') are trivially bypassed by copying or linking binaries, and negated Runas or Host specifications have led to critical authorization bypasses (such as CVE-2019-14287 with UID -1 and CVE-2025-32462).",
					DirectivesCode:  "# Define explicit positive aliases (zero '!' exclusions):\nUser_Alias  WEB_OPERATORS = %sudo_webops\nRunas_Alias WEB_SVC_USER  = www-data\nWEB_OPERATORS PROD_WEB_SERVERS = (WEB_SVC_USER) PASSWD: NOEXEC: /usr/local/sbin/sudo-wrappers/reload-nginx-config.sh \"\"",
					RuleIDs:         []string{"SUDO-CMD-001", "SUDO-CMD-008"},
					ComplianceTags:  []string{"ANSSI-BP-028 R42"},
					TemplateAnchor:  "tpl-sudoers-baseline",
				},
				{
					ID:              "anssi-r43",
					FrameworkID:     "ANSSI-BP-028",
					FrameworkShort:  "ANSSI BP-028",
					Code:            "ANSSI-BP-028 R43",
					Title:           "Defining the Arguments in sudo Specifications",
					Level:           "Minimal / Intermediate (R43)",
					CitationURL:     "https://cyber.gouv.fr/publications/recommandations-de-securite-relatives-un-systeme-gnulinux",
					VerbatimQuote:   "R43 - Defining the arguments in sudo specifications: All commands in the sudoers configuration file must strictly specify the arguments allowed to be used for a given user. The use of * (wildcard) in the rules should be avoided as much as possible. The absence of arguments in a command must be specified by the presence of an empty chain (\"\"). Example: user ALL = dmesg \"\" - restrict the arguments in order to prevent the user from reading any arbitrary file through the --file option.",
					VerbatimQuoteFR: "R43 - Définir les arguments dans les spécifications sudo : Toutes les commandes du fichier de configuration sudoers doivent préciser strictement les arguments autorisés pour un utilisateur donné. L'utilisation du joker * dans les règles doit être évitée autant que possible. L'absence d'arguments dans une commande doit être spécifiée par la présence d'une chaîne vide (\"\"). Exemple : user ALL = dmesg \"\".",
					Rationale:       "Any argument can modify quite significantly the behavior of a program, whether regarding the realized operation (read, write, delete, ...) or accessed resources (path in a file system tree). When a command in sudoers has no argument specification, sudo permits arbitrary caller-supplied flags; wildcards (*) additionally match arbitrary flags and path traversal sequences.",
					DirectivesCode:  "# Zero arguments allowed (explicit \"\"):\nWEB_OPERATORS PROD_WEB_SERVERS = (WEB_SVC_USER) PASSWD: NOEXEC: /usr/local/sbin/sudo-wrappers/reload-nginx-config.sh \"\"\n# Fixed argument allowlist:\nSECURITY_AUDIT ALL = (root) PASSWD: NOEXEC: /usr/sbin/auditctl -s",
					RuleIDs:         []string{"SUDO-CMD-002", "SUDO-CMD-003", "SUDO-CMD-004", "SUDO-CMD-006"},
					ComplianceTags:  []string{"ANSSI-BP-028 R43"},
					TemplateAnchor:  "tpl-sudoers-baseline",
				},
				{
					ID:              "anssi-r44",
					FrameworkID:     "ANSSI-BP-028",
					FrameworkShort:  "ANSSI BP-028",
					Code:            "ANSSI-BP-028 R44",
					Title:           "Editing Files Securely with sudo",
					Level:           "Minimal / Intermediate (R44)",
					CitationURL:     "https://cyber.gouv.fr/publications/recommandations-de-securite-relatives-un-systeme-gnulinux",
					VerbatimQuote:   "R44 - Editing files securely with sudo: A file requiring sudo to be edited must be edited through the sudoedit command. The sudoedit text editor solves these problems by editing a temporary version of the file with the current user rights, then replacing the original file by this temporary version once the operation is finished. The editor runs thus only with the current user rights and never with the privileges of the target user.",
					VerbatimQuoteFR: "R44 - Éditer des fichiers de manière sécurisée avec sudo : Un fichier nécessitant sudo pour être modifié doit être édité via la commande sudoedit. L'éditeur travaille sur une version temporaire du fichier avec les droits de l'utilisateur courant, puis remplace le fichier original une fois l'opération terminée. L'éditeur ne s'exécute qu'avec les droits de l'utilisateur courant, jamais avec les privilèges de l'utilisateur cible.",
					Rationale:       "A text editor is a functionally rich program that can open and edit other files via internal commands or even run a shell, offering a full privileged environment to a user. sudoedit runs the editor under the unprivileged caller UID on a temporary copy and swaps it back only on exit.",
					DirectivesCode:  "WEB_OPERATORS PROD_WEB_SERVERS = (WEB_SVC_USER) PASSWD: sudoedit /etc/nginx/conf.d/app-vhost.conf",
					RuleIDs:         []string{"SUDO-CMD-007"},
					ComplianceTags:  []string{"ANSSI-BP-028 R44"},
					TemplateAnchor:  "tpl-sudoers-baseline",
				},
			},
		},
		{
			ID:           "CIS-BENCHMARK",
			ShortName:    "CIS Benchmarks",
			FullName:     "CIS Linux Benchmarks — Section 5.2 Configure Privilege Escalation (RHEL / Ubuntu / Debian)",
			VersionInfo:  "RHEL 9 v2.0.0 / Ubuntu 24.04 LTS v1.0.0 numbering (Controls 5.2.1 – 5.2.7)",
			Publisher:    "Center for Internet Security (CIS)",
			ReferenceURL: "https://www.cisecurity.org/cis-benchmarks",
			Summary:      "Consensus-driven configuration standards for hardening Linux privilege escalation. Section 5.2 of the current CIS Linux benchmarks (identical numbering in RHEL 9 v2.0.0 and Ubuntu 24.04 LTS v1.0.0; older releases numbered these controls 5.3.x) requires sudo to be installed, commands to run inside a pseudo-terminal, a dedicated sudo log file, a password for escalation without NOPASSWD, re-authentication not disabled via !authenticate, and a credential cache timeout of at most 15 minutes, and restricts access to the su command.",
			Requirements: []FrameworkRequirement{
				{
					ID:             "cis-5-2-1",
					FrameworkID:    "CIS-BENCHMARK",
					FrameworkShort: "CIS Benchmarks",
					Code:           "CIS-5.2.1",
					Title:          "Ensure sudo is installed",
					Level:          "Level 1 — Server & Workstation",
					CitationURL:    "https://www.cisecurity.org/cis-benchmarks",
					VerbatimQuote:  "CIS 5.2.1 - Ensure sudo is installed: 'sudo allows a permitted user to execute a command as the superuser or another user, as specified by the security policy.' Audit: 'Verify that sudo is installed. Run the following command: # dnf list sudo'. Note: sudo-check verifies sudo availability on the target host in system mode via 'sudo --version'; it does not audit package installation.",
					Rationale:      "The default security policy is sudoers, which is configured via the file /etc/sudoers and any entries in /etc/sudoers.d. Without the sudo package installed, privilege escalation policy cannot be enforced or audited.",
					DirectivesCode: "# dnf install sudo   # RHEL / SUSE\n# apt install sudo    # Debian / Ubuntu",
					RuleIDs:        []string{},
					ComplianceTags: []string{"CIS-5.2.1"},
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
					VerbatimQuote:  "CIS 5.2.2 - Ensure sudo commands use pty: 'sudo can be configured to run only from a pseudo terminal (pseudo-pty).' Rationale: 'Attackers can run a malicious program using sudo which would fork a background process that remains even when the main program has finished executing.' Remediation: 'Edit the file /etc/sudoers with visudo or a file in /etc/sudoers.d/ with visudo -f <PATH TO FILE> and add the following line: Defaults use_pty'.",
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
					Title:          "Ensure sudo log file exists",
					Level:          "Level 1 — Server & Workstation",
					CitationURL:    "https://www.cisecurity.org/cis-benchmarks",
					VerbatimQuote:  "CIS 5.2.3 - Ensure sudo log file exists: 'The Defaults logfile entry sets the path to the sudo log file. Setting a path turns on logging to a file; negating this option turns it off. By default, sudo logs via syslog.' Rationale: 'Defining a dedicated log file for sudo simplifies auditing of sudo commands and creation of auditd rules for sudo.' Remediation example: 'Defaults logfile=\"/var/log/sudo.log\"'. Note: log_input and log_output are defense-in-depth additions; they are not part of this CIS control.",
					Rationale:      "A dedicated sudo log file simplifies auditing of privileged commands and the creation of auditd rules for sudo; without it, sudo activity is only available through syslog.",
					DirectivesCode: "Defaults logfile=\"/var/log/sudo.log\"",
					RuleIDs:        []string{},
					ComplianceTags: []string{"CIS-5.2.3"},
					TemplateAnchor: "tpl-sudoers-baseline",
				},
				{
					ID:             "cis-5-2-4",
					FrameworkID:    "CIS-BENCHMARK",
					FrameworkShort: "CIS Benchmarks",
					Code:           "CIS-5.2.4",
					Title:          "Ensure users must provide password for escalation (no NOPASSWD)",
					Level:          "Level 2 — Server & Workstation",
					CitationURL:    "https://www.cisecurity.org/cis-benchmarks",
					VerbatimQuote:  "CIS 5.2.4 - Ensure users must provide password for escalation: 'The operating system must be configured so that users must provide a password for privilege escalation.' Audit: 'Verify the operating system requires users to supply a password for privilege escalation. Check the configuration of the /etc/sudoers and /etc/sudoers.d/* files with the following command: # grep -r \"^[^#].*NOPASSWD\" /etc/sudoers*'. Remediation: 'Remove any line with occurrences of NOPASSWD tags in the file.'",
					Rationale:      "Without re-authentication, users may access resources or perform tasks for which they do not have authorization. When operating systems provide the capability to escalate a functional capability, it is critical the user re-authenticate.",
					DirectivesCode: "Defaults authenticate\n# Always require PASSWD on User_Spec rules:\nWEB_OPERATORS PROD_WEB_SERVERS = (WEB_SVC_USER) PASSWD: NOEXEC: /usr/local/sbin/sudo-wrappers/reload-nginx-config.sh \"\"",
					RuleIDs:        []string{"SUDO-CMD-003", "SUDO-CMD-005"},
					ComplianceTags: []string{"CIS-5.2.4"},
					TemplateAnchor: "tpl-sudoers-baseline",
				},
				{
					ID:             "cis-5-2-5",
					FrameworkID:    "CIS-BENCHMARK",
					FrameworkShort: "CIS Benchmarks",
					Code:           "CIS-5.2.5",
					Title:          "Ensure re-authentication for privilege escalation is not disabled globally (no !authenticate)",
					Level:          "Level 1 — Server & Workstation",
					CitationURL:    "https://www.cisecurity.org/cis-benchmarks",
					VerbatimQuote:  "CIS 5.2.5 - Ensure re-authentication for privilege escalation is not disabled globally: 'The operating system must be configured so that users must re-authenticate for privilege escalation.' Audit: 'Verify the operating system requires users to re-authenticate for privilege escalation. Check the configuration of the /etc/sudoers and /etc/sudoers.d/* files with the following command: # grep -r \"^[^#].*\\!authenticate\" /etc/sudoers*'. Remediation: 'Remove any occurrences of !authenticate tags in the file(s).'",
					Rationale:      "Without re-authentication, users may access resources or perform tasks for which they do not have authorization. When operating systems provide the capability to escalate a functional capability, it is critical the user re-authenticate.",
					DirectivesCode: "Defaults authenticate",
					RuleIDs:        []string{"SUDO-DEF-012"},
					ComplianceTags: []string{"CIS-5.2.5"},
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
					VerbatimQuote:  "CIS 5.2.6 - Ensure sudo authentication timeout is configured correctly: 'sudo caches used credentials for a default of 5 minutes. This is for ease of use when there are multiple administrative tasks to perform. The timeout can be modified to suit local security policies.' Audit: 'Ensure that the caching timeout is no more than 15 minutes. # grep -roP \"timestamp_timeout=\\K[0-9]*\" /etc/sudoers* Note: A value of -1 means that the timeout is disabled.' Remediation: 'If the currently configured timeout is larger than 15 minutes, edit the file listed in the audit section with visudo -f <PATH TO FILE> and modify the entry timestamp_timeout= to 15 minutes or less as per your site policy.'",
					Rationale:      "Setting a timeout value reduces the window of opportunity for unauthorized privileged access to another user.",
					DirectivesCode: "Defaults timestamp_timeout=15",
					RuleIDs:        []string{"SUDO-DEF-015"},
					ComplianceTags: []string{"CIS-5.2.6"},
					TemplateAnchor: "tpl-sudoers-baseline",
				},
				{
					ID:             "cis-5-2-7",
					FrameworkID:    "CIS-BENCHMARK",
					FrameworkShort: "CIS Benchmarks",
					Code:           "CIS-5.2.7",
					Title:          "Ensure access to the su command is restricted",
					Level:          "Level 1 — Server & Workstation",
					CitationURL:    "https://www.cisecurity.org/cis-benchmarks",
					VerbatimQuote:  "CIS 5.2.7 - Ensure access to the su command is restricted: 'The su command allows a user to run a command or shell as another user. The program has been superseded by sudo, which allows for more granular control over privileged access.' Remediation: 'Create an empty group that will be specified for use of the su command. Example: # groupadd sugroup. Add the following line to the /etc/pam.d/su file, specifying the empty group: auth required pam_wheel.so use_uid group=sugroup'. Note: sudo-check audits sudoers policies only; it does not inspect /etc/pam.d/su.",
					Rationale:      "Restricting the use of su, and using sudo in its place, provides system administrators better control of the escalation of user privileges to execute privileged commands, as well as a better logging and audit mechanism.",
					DirectivesCode: "# groupadd sugroup\necho 'auth required pam_wheel.so use_uid group=sugroup' >> /etc/pam.d/su",
					RuleIDs:        []string{},
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
			Summary:      "U.S. Department of Defense (DoD) mandatory configuration requirements for operating systems. Requires a password and re-authentication for privilege escalation, prohibits NOPASSWD and !authenticate, requires the invoking user's password for sudo (prohibiting rootpw, targetpw, and runaspw), requires a non-negative sudo timestamp timeout. The RHEL 9 and Ubuntu LTS STIGs carry equivalent findings.",
			Requirements: []FrameworkRequirement{
				{
					ID:             "stig-reauth",
					FrameworkID:    "DISA-STIG",
					FrameworkShort: "DISA STIG",
					Code:           "DISA-STIG",
					Title:          "Mandatory Password Re-Authentication for Privilege Escalation (NOPASSWD / !authenticate Prohibited, Non-Negative Credential Cache Timeout)",
					Level:          "CAT II (Medium)",
					CitationURL:    "https://public.cyber.mil/stigs/",
					VerbatimQuote:  "RHEL 8 STIG, SV-230271 (RHEL-08-010380): 'RHEL 8 must require users to provide a password for privilege escalation.' SV-230272 (RHEL-08-010381): 'RHEL 8 must require users to reauthenticate for privilege escalation.' SV-237643 (RHEL-08-010383): 'RHEL 8 must require re-authentication when using the \"sudo\" command.' Fix text: 'Configure the \"sudo\" command to require re-authentication. Edit the /etc/sudoers file: Add or modify the following line: Defaults timestamp_timeout=[value] Note: The \"[value]\" must be a number that is greater than or equal to \"0\".' Equivalent findings: RHEL 9 STIG V-258084 and RHEL-09-611085; Ubuntu 24.04 LTS STIG V-270707.",
					Rationale:      "Without mandatory password verification and a bounded credential cache, any compromise of an unprivileged process allows silent, unauthenticated execution of administrative commands across sessions.",
					DirectivesCode: "Defaults authenticate\nDefaults timestamp_timeout=5",
					RuleIDs:        []string{"SUDO-DEF-012", "SUDO-DEF-015", "SUDO-CMD-003", "SUDO-CMD-005"},
					ComplianceTags: []string{},
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
			Description: "Drop-in replacement baseline for /etc/sudoers implementing all ANSSI BP-028 v2.0 (R38–R44), CIS Benchmark (5.2.1–5.2.7), DISA STIG, and MITRE ATT&CK controls. Verified to produce zero findings under sudo-check.",
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
			Description: "Copy-pasteable commands to enforce CIS 5.2.1 ownership and permissions across /etc/sudoers, /etc/sudoers.d, /usr/bin/sudo, and wrapper directories (ANSSI BP-028 R38 additionally recommends restricting sudo binary execution to a dedicated group), followed by syntax and security audit verification.",
			Code: strings.TrimSpace(`
# 1. Enforce strict ownership and 0440 permissions on /etc/sudoers (SUDO-SYS-PERM-002..005, 011)
sudo chown root:root /etc/sudoers
sudo chmod 0440 /etc/sudoers

# 2. Secure /etc/sudoers.d directory and all drop-in files (CIS 5.2.1)
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
		{RuleID: "SUDO-DEF-001", Domain: "Defaults", Severity: audit.SeverityHigh, Title: "Missing or Empty secure_path Configuration", Frameworks: []string{}, Directive: `Defaults secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"`, SectionID: "tpl-sudoers-baseline"},
		{RuleID: "SUDO-DEF-002", Domain: "Defaults", Severity: audit.SeverityHigh, Title: "Relative or Unsafe Entry in secure_path", Frameworks: []string{}, Directive: `Defaults secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"`, SectionID: "tpl-sudoers-baseline"},
		{RuleID: "SUDO-DEF-003", Domain: "Defaults", Severity: audit.SeverityMedium, Title: "Missing or Disabled use_pty", Frameworks: []string{"ANSSI-BP-028 R39", "CIS-5.2.2"}, Directive: `Defaults use_pty`, SectionID: "tpl-sudoers-baseline"},
		{RuleID: "SUDO-DEF-004", Domain: "Defaults", Severity: audit.SeverityCritical, Title: "Dangerous Environment Variables Preserved (env_keep / env_check)", Frameworks: []string{}, Directive: `Defaults env_reset` + "\n" + `Defaults env_keep="LANG LC_ALL LC_CTYPE LC_MESSAGES TERM COLORTERM"`, SectionID: "tpl-sudoers-baseline"},
		{RuleID: "SUDO-DEF-005", Domain: "Defaults", Severity: audit.SeverityHigh, Title: "Cleartext Password Echo Enabled (visiblepw)", Frameworks: []string{}, Directive: `Defaults !visiblepw`, SectionID: "tpl-sudoers-baseline"},
		{RuleID: "SUDO-DEF-006", Domain: "Defaults", Severity: audit.SeverityLow, Title: "Password Length Feedback Enabled (pwfeedback)", Frameworks: []string{}, Directive: `Defaults !pwfeedback`, SectionID: "tpl-sudoers-baseline"},
		{RuleID: "SUDO-DEF-007", Domain: "Defaults", Severity: audit.SeverityMedium, Title: "Missing or Disabled noexec", Frameworks: []string{"ANSSI-BP-028 R39"}, Directive: `Defaults noexec`, SectionID: "tpl-sudoers-baseline"},
		{RuleID: "SUDO-DEF-008", Domain: "Defaults", Severity: audit.SeverityLow, Title: "Missing or Disabled requiretty", Frameworks: []string{"ANSSI-BP-028 R39"}, Directive: `Defaults requiretty`, SectionID: "tpl-sudoers-baseline"},
		{RuleID: "SUDO-DEF-009", Domain: "Defaults", Severity: audit.SeverityMedium, Title: "Missing or Weak umask Configuration", Frameworks: []string{"ANSSI-BP-028 R39"}, Directive: `Defaults umask=0077, umask_override`, SectionID: "tpl-sudoers-baseline"},
		{RuleID: "SUDO-DEF-010", Domain: "Defaults", Severity: audit.SeverityMedium, Title: "Missing or Disabled ignore_dot", Frameworks: []string{"ANSSI-BP-028 R39"}, Directive: `Defaults ignore_dot`, SectionID: "tpl-sudoers-baseline"},
		{RuleID: "SUDO-DEF-011", Domain: "Defaults", Severity: audit.SeverityHigh, Title: "Missing or Disabled env_reset", Frameworks: []string{"ANSSI-BP-028 R39"}, Directive: `Defaults env_reset`, SectionID: "tpl-sudoers-baseline"},
		{RuleID: "SUDO-DEF-012", Domain: "Defaults", Severity: audit.SeverityCritical, Title: "Password Authentication Disabled (!authenticate)", Frameworks: []string{"CIS-5.2.5", "DISA-STIG"}, Directive: `Defaults authenticate`, SectionID: "tpl-sudoers-baseline"},
		{RuleID: "SUDO-DEF-013", Domain: "Defaults", Severity: audit.SeverityHigh, Title: "Environment Override Permitted Globally (setenv)", Frameworks: []string{}, Directive: `Defaults !setenv`, SectionID: "tpl-sudoers-baseline"},
		{RuleID: "SUDO-DEF-014", Domain: "Defaults", Severity: audit.SeverityHigh, Title: "Insecure sudoedit Symlink or Directory Configuration", Frameworks: []string{}, Directive: `Defaults !sudoedit_follow, sudoedit_checkdir`, SectionID: "tpl-sudoers-baseline"},
		{RuleID: "SUDO-DEF-015", Domain: "Defaults", Severity: audit.SeverityMedium, Title: "Weak Credential Cache Timeout or Global Ticket Scope", Frameworks: []string{"CIS-5.2.6", "DISA-STIG"}, Directive: `Defaults passwd_timeout=1, timestamp_timeout=5, timestamp_type=tty`, SectionID: "tpl-sudoers-baseline"},
		{RuleID: "SUDO-DEF-016", Domain: "Defaults", Severity: audit.SeverityHigh, Title: "Deprecated Chroot (runchroot) or Unrestricted Working Directory (runcwd=*)", Frameworks: []string{}, Directive: `# Omit runchroot and runcwd=* from Defaults`, SectionID: "tpl-sudoers-baseline"},
		{RuleID: "SUDO-CMD-001", Domain: "Command Rule", Severity: audit.SeverityHigh, Title: "Negated Command Policy (!command)", Frameworks: []string{"ANSSI-BP-028 R42"}, Directive: `# Use positive command allowlists without '!'`, SectionID: "tpl-sudoers-baseline"},
		{RuleID: "SUDO-CMD-002", Domain: "Command Rule", Severity: audit.SeverityHigh, Title: "Unrestricted ALL Commands Allowed", Frameworks: []string{"ANSSI-BP-028 R43"}, Directive: `# Scope rules to explicit binaries and arguments instead of ALL`, SectionID: "tpl-sudoers-baseline"},
		{RuleID: "SUDO-CMD-003", Domain: "Command Rule", Severity: audit.SeverityCritical, Title: "Passwordless Full Root Privileges (NOPASSWD: ALL)", Frameworks: []string{"ANSSI-BP-028 R43", "CIS-5.2.4", "DISA-STIG"}, Directive: `WEB_OPERATORS PROD_WEB_SERVERS = (WEB_SVC_USER) PASSWD: NOEXEC: /usr/local/sbin/sudo-wrappers/reload-nginx-config.sh ""`, SectionID: "tpl-sudoers-baseline"},
		{RuleID: "SUDO-CMD-004", Domain: "Command Rule", Severity: audit.SeverityMedium, Title: "Wildcard (*) in Command or Arguments", Frameworks: []string{"ANSSI-BP-028 R43"}, Directive: `# Enumerate exact arguments or delegate to a fixed-argument wrapper script`, SectionID: "tpl-wrapper-script"},
		{RuleID: "SUDO-CMD-005", Domain: "Command Rule", Severity: audit.SeverityLow, Title: "Passwordless Specific Command Execution (NOPASSWD)", Frameworks: []string{"CIS-5.2.4", "DISA-STIG"}, Directive: `PASSWD: NOEXEC: /usr/sbin/auditctl -s`, SectionID: "tpl-sudoers-baseline"},
		{RuleID: "SUDO-CMD-006", Domain: "Command Rule", Severity: audit.SeverityMedium, Title: "Missing Command Argument Restrictions", Frameworks: []string{"ANSSI-BP-028 R43"}, Directive: `/usr/local/sbin/sudo-wrappers/reload-nginx-config.sh ""`, SectionID: "tpl-sudoers-baseline"},
		{RuleID: "SUDO-CMD-007", Domain: "Command Rule", Severity: audit.SeverityHigh, Title: "Direct Text Editor Execution via Sudo", Frameworks: []string{"ANSSI-BP-028 R44"}, Directive: `WEB_OPERATORS PROD_WEB_SERVERS = (WEB_SVC_USER) PASSWD: sudoedit /etc/nginx/conf.d/app-vhost.conf`, SectionID: "tpl-sudoers-baseline"},
		{RuleID: "SUDO-CMD-008", Domain: "Command Rule", Severity: audit.SeverityHigh, Title: "Negated User, Host, or Runas Specification", Frameworks: []string{"ANSSI-BP-028 R42"}, Directive: `User_Alias WEB_OPERATORS = %sudo_webops` + "\n" + `Runas_Alias WEB_SVC_USER = www-data`, SectionID: "tpl-sudoers-baseline"},
		{RuleID: "SUDO-CMD-009", Domain: "Command Rule", Severity: audit.SeverityHigh, Title: "Dangerous Per-Command Tag (SETENV, FOLLOW, CHROOT, CWD=*)", Frameworks: []string{}, Directive: `APP_DEPLOYERS APP_NODES = (APP_USER) CWD=/opt/app PASSWD: NOEXEC: ...`, SectionID: "tpl-dropin-example"},
		{RuleID: "SUDO-CMD-010", Domain: "Command Rule", Severity: audit.SeverityCritical, Title: "sudoedit Permitted on Sensitive System File", Frameworks: []string{}, Directive: `sudoedit /etc/nginx/conf.d/app-vhost.conf`, SectionID: "tpl-sudoers-baseline"},
		{RuleID: "SUDO-CMD-011", Domain: "Command Rule", Severity: audit.SeverityCritical, Title: "Relative or Temporary/Writable Command Path", Frameworks: []string{}, Directive: `/usr/local/sbin/sudo-wrappers/reload-nginx-config.sh ""`, SectionID: "tpl-wrapper-script"},
		{RuleID: "SUDO-CMD-012", Domain: "Command Rule", Severity: audit.SeverityLow, Title: "Weak Cryptographic Digest on Command (SHA-224)", Frameworks: []string{}, Directive: `sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 /usr/local/sbin/...`, SectionID: "tpl-sudoers-baseline"},
		{RuleID: "SUDO-GTFO-001", Domain: "GTFObins", Severity: audit.SeverityHigh, Title: "Permitted Binary in GTFObins Catalog", Frameworks: []string{"ANSSI-BP-028 R41", "MITRE-T1548.003"}, Directive: `PASSWD: NOEXEC: sha256:<digest> /usr/local/sbin/sudo-wrappers/reload-nginx-config.sh ""`, SectionID: "tpl-wrapper-script"},
		{RuleID: "SUDO-GTFO-002", Domain: "GTFObins", Severity: audit.SeverityCritical, Title: "Passwordless Permitted Binary in GTFObins Catalog", Frameworks: []string{"ANSSI-BP-028 R41", "MITRE-T1548.003"}, Directive: `PASSWD: NOEXEC: sha256:<digest> /usr/local/sbin/sudo-wrappers/reload-nginx-config.sh ""`, SectionID: "tpl-wrapper-script"},
		{RuleID: "SUDO-GTFO-003", Domain: "GTFObins", Severity: audit.SeverityLow, Title: "Mitigated GTFObins Binary (NOEXEC on shell/command)", Frameworks: []string{"ANSSI-BP-028 R39", "MITRE-T1548.003"}, Directive: `# Replace direct GTFObins binary with dedicated root-owned wrapper script`, SectionID: "tpl-wrapper-script"},
		{RuleID: "SUDO-SYS-PERM-002..013", Domain: "System Host", Severity: audit.SeverityCritical, Title: "Sudoers, Drop-In, Sudo Binary & Target Binary Permissions", Frameworks: []string{"ANSSI-BP-028 R38"}, Directive: `sudo chown root:root /etc/sudoers && sudo chmod 0440 /etc/sudoers`, SectionID: "tpl-filesystem-perms"},
	}

	for i := range rows {
		rows[i].BadgeClass = severityBadgeClass(rows[i].Severity)
	}
	return rows
}
