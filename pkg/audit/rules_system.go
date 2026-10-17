package audit

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
)

// SudoVersion represents parsed semantic components of the sudo version string.
type SudoVersion struct {
	Raw   string
	Major int
	Minor int
	Patch int
	Pl    int // Patch release, e.g. p2 -> 2
}

var versionRegex = regexp.MustCompile(`([0-9]+)\.([0-9]+)\.([0-9]+)(?:p([0-9]+))?`)

// ParseSudoVersion parses a sudo version string (like "1.8.31p2", "1.9.12", or "Sudo version 1.8.31 (Debian 10)").
func ParseSudoVersion(verStr string) (SudoVersion, error) {
	trimmed := strings.TrimSpace(verStr)
	if trimmed == "" {
		return SudoVersion{Raw: verStr}, fmt.Errorf("unable to parse empty sudo version")
	}

	matches := versionRegex.FindStringSubmatch(trimmed)
	if len(matches) < 4 {
		return SudoVersion{Raw: verStr}, fmt.Errorf("unable to parse sudo version: %s", verStr)
	}

	major, _ := strconv.Atoi(matches[1])
	minor, _ := strconv.Atoi(matches[2])
	patch, _ := strconv.Atoi(matches[3])
	pl := 0
	if len(matches) > 4 && matches[4] != "" {
		pl, _ = strconv.Atoi(matches[4])
	}

	return SudoVersion{
		Raw:   verStr,
		Major: major,
		Minor: minor,
		Patch: patch,
		Pl:    pl,
	}, nil
}

// Compare returns:
//
//	-1 if v < other
//	 0 if v == other
//	 1 if v > other
func (v SudoVersion) Compare(other SudoVersion) int {
	if v.Major != other.Major {
		if v.Major < other.Major {
			return -1
		}
		return 1
	}
	if v.Minor != other.Minor {
		if v.Minor < other.Minor {
			return -1
		}
		return 1
	}
	if v.Patch != other.Patch {
		if v.Patch < other.Patch {
			return -1
		}
		return 1
	}
	if v.Pl != other.Pl {
		if v.Pl < other.Pl {
			return -1
		}
		return 1
	}
	return 0
}

// AuditSudoVersion checks if the current sudo version falls within known CVE version ranges.
func AuditSudoVersion(verStr string) ([]Finding, error) {
	if verStr == "" {
		return nil, nil
	}

	v, err := ParseSudoVersion(verStr)
	if err != nil {
		return []Finding{
			{
				ID:          "SUDO-SYS-001",
				Title:       "Unrecognized Sudo Version Format",
				Description: fmt.Sprintf("The detected sudo version string '%s' could not be parsed into a semantic version. Sudo version vulnerability analysis was skipped.", verStr),
				Severity:    SeverityInfo,
				Remediation: "Manually verify the sudo version against known vulnerability advisories.",
			},
		}, nil
	}

	var findings []Finding

	// CVE-2019-14287: Sudo < 1.8.28 (Runas UID -1 bypass)
	v1828 := SudoVersion{Major: 1, Minor: 8, Patch: 28, Pl: 0}
	if v.Compare(v1828) < 0 {
		findings = append(findings, Finding{
			ID:          "CVE-2019-14287",
			Title:       "Sudo UID -1 Authorization Bypass",
			Description: fmt.Sprintf("The system runs sudo version %s, which is vulnerable to CVE-2019-14287. Users with permissions to execute commands as any user except root (e.g. 'ALL, !root') can bypass this restriction and execute commands as root by specifying UID -1 or 4294967295.", v.Raw),
			Severity:    SeverityHigh,
			Remediation: "Upgrade sudo to version 1.8.28 or later, or apply vendor security updates.",
		})
	}

	// CVE-2019-18634: Sudo 1.7.1 through 1.8.30 (pwfeedback stack buffer overflow)
	v171 := SudoVersion{Major: 1, Minor: 7, Patch: 1, Pl: 0}
	v1830 := SudoVersion{Major: 1, Minor: 8, Patch: 30, Pl: 99}
	if v.Compare(v171) >= 0 && v.Compare(v1830) <= 0 {
		findings = append(findings, Finding{
			ID:          "CVE-2019-18634",
			Title:       "Sudo pwfeedback Stack Buffer Overflow",
			Description: fmt.Sprintf("The system runs sudo version %s, which is vulnerable to CVE-2019-18634 when 'pwfeedback' is enabled in sudoers.", v.Raw),
			Severity:    SeverityHigh,
			Remediation: "Upgrade sudo to version 1.8.31 or later and ensure 'Defaults !pwfeedback' is set.",
		})
	}

	// CVE-2021-3156 (Baron Samedit): heap buffer overflow
	// Affected: 1.8.2 through 1.8.31p2, and 1.9.0 through 1.9.5p1
	v182 := SudoVersion{Major: 1, Minor: 8, Patch: 2, Pl: 0}
	v1831p2 := SudoVersion{Major: 1, Minor: 8, Patch: 31, Pl: 2}
	v190 := SudoVersion{Major: 1, Minor: 9, Patch: 0, Pl: 0}
	v195p1 := SudoVersion{Major: 1, Minor: 9, Patch: 5, Pl: 1}

	isVulnerable18 := v.Compare(v182) >= 0 && v.Compare(v1831p2) <= 0
	isVulnerable19 := v.Compare(v190) >= 0 && v.Compare(v195p1) <= 0

	if isVulnerable18 || isVulnerable19 {
		findings = append(findings, Finding{
			ID:          "CVE-2021-3156",
			Title:       "Baron Samedit Sudo Heap Buffer Overflow",
			Description: fmt.Sprintf("The system runs sudo version %s, which falls in the affected range for CVE-2021-3156 (Baron Samedit). A heap-based buffer overflow in command-line argument unescaping allows local users to escalate privileges to root.", v.Raw),
			Severity:    SeverityCritical,
			Remediation: "Upgrade sudo to version 1.8.32, 1.9.5p2, or install the distribution's backported security patch.",
		})
	}

	// CVE-2022-43995: Sudo 1.8.0 through 1.9.12 (heap overflow in password prompt with crypt)
	v180 := SudoVersion{Major: 1, Minor: 8, Patch: 0, Pl: 0}
	v1912 := SudoVersion{Major: 1, Minor: 9, Patch: 12, Pl: 0}
	if v.Compare(v180) >= 0 && v.Compare(v1912) <= 0 {
		findings = append(findings, Finding{
			ID:          "CVE-2022-43995",
			Title:       "Sudo crypt() Password Prompt Heap Buffer Overflow",
			Description: fmt.Sprintf("The system runs sudo version %s, which is affected by CVE-2022-43995 (versions 1.8.0 through 1.9.12).", v.Raw),
			Severity:    SeverityHigh,
			Remediation: "Upgrade sudo to version 1.9.12p1 or later.",
		})
	}

	// CVE-2023-22809: Sudoedit unauthorized file modification via EDITOR/VISUAL flag injection
	// Affected: 1.8.0 through 1.9.12p1 (Fixed in 1.9.12p2)
	v1912p1 := SudoVersion{Major: 1, Minor: 9, Patch: 12, Pl: 1}
	if v.Compare(v180) >= 0 && v.Compare(v1912p1) <= 0 {
		findings = append(findings, Finding{
			ID:          "CVE-2023-22809",
			Title:       "Sudoedit Argument Injection Privilege Escalation",
			Description: fmt.Sprintf("The system runs sudo version %s, which is vulnerable to CVE-2023-22809. Users permitted to run 'sudoedit' can inject '--' arguments via SUDO_EDITOR, VISUAL, or EDITOR environment variables to edit arbitrary files as root.", v.Raw),
			Severity:    SeverityHigh,
			Remediation: "Upgrade sudo to version 1.9.12p2 or later, or add SUDO_EDITOR, VISUAL, and EDITOR to env_delete.",
		})
	}

	// CVE-2023-27320: Double free in per-command chroot handling
	// Affected: 1.9.8 through 1.9.13p1 (Fixed in 1.9.13p2)
	v198 := SudoVersion{Major: 1, Minor: 9, Patch: 8, Pl: 0}
	v1913p1 := SudoVersion{Major: 1, Minor: 9, Patch: 13, Pl: 1}
	if v.Compare(v198) >= 0 && v.Compare(v1913p1) <= 0 {
		findings = append(findings, Finding{
			ID:          "CVE-2023-27320",
			Title:       "Sudo Per-Command Chroot Double Free Vulnerability",
			Description: fmt.Sprintf("The system runs sudo version %s, which is vulnerable to CVE-2023-27320 (versions 1.9.8 through 1.9.13p1). A double-free memory management flaw in per-command 'CHROOT=' rules can lead to memory corruption or privilege escalation.", v.Raw),
			Severity:    SeverityHigh,
			Remediation: "Upgrade sudo to version 1.9.13p2 or later.",
		})
	}

	// CVE-2025-32462: Host option (-h / --host) policy check bypass
	// Affected: 1.8.8 through 1.9.17 (Fixed in 1.9.17p1)
	v188 := SudoVersion{Major: 1, Minor: 8, Patch: 8, Pl: 0}
	v1917 := SudoVersion{Major: 1, Minor: 9, Patch: 17, Pl: 0}
	if v.Compare(v188) >= 0 && v.Compare(v1917) <= 0 {
		findings = append(findings, Finding{
			ID:          "CVE-2025-32462",
			Title:       "Sudo Host Option (-h) Policy Check Bypass",
			Description: fmt.Sprintf("The system runs sudo version %s, which is vulnerable to CVE-2025-32462 (versions 1.8.8 through 1.9.17). Passing the '-h' ('--host') option allows local users to evaluate rules intended for remote hosts and execute commands locally.", v.Raw),
			Severity:    SeverityHigh,
			Remediation: "Upgrade sudo to version 1.9.17p1 or later, or apply vendor security updates.",
		})
	}

	// CVE-2025-32463: Chroot (-R / --chroot) local privilege escalation via untrusted nsswitch.conf
	// Affected: 1.9.14 through 1.9.17 (Fixed in 1.9.17p1)
	v1914 := SudoVersion{Major: 1, Minor: 9, Patch: 14, Pl: 0}
	if v.Compare(v1914) >= 0 && v.Compare(v1917) <= 0 {
		findings = append(findings, Finding{
			ID:          "CVE-2025-32463",
			Title:       "Sudo Chroot (-R) Local Privilege Escalation",
			Description: fmt.Sprintf("The system runs sudo version %s, which is vulnerable to CVE-2025-32463 (versions 1.9.14 through 1.9.17). Path resolution inside a user-specified '--chroot' directory prior to policy evaluation allows loading arbitrary shared libraries as root.", v.Raw),
			Severity:    SeverityCritical,
			Remediation: "Upgrade sudo to version 1.9.17p1 or later immediately.",
		})
	}

	return findings, nil
}

// AuditSudoersPermissions checks ownership and permissions of /etc/sudoers (Unix/Linux).
func AuditSudoersPermissions(filePath string) []Finding {
	if runtime.GOOS == "windows" {
		return nil
	}

	info, err := os.Stat(filePath)
	if err != nil {
		return []Finding{
			{
				ID:          "SUDO-SYS-PERM-001",
				Title:       "Unable to access sudoers file",
				Description: fmt.Sprintf("Could not stat sudoers file at '%s': %v. Ensure the auditor is running with sufficient privileges.", filePath, err),
				Severity:    SeverityMedium,
				Context:     filePath,
				Remediation: "Run the sudo-check utility with root/sudo privileges.",
			},
		}
	}

	uid, gid, ownerErr := getUnixOwner(info)
	return evaluateSudoersFilePermissions(filePath, info.Mode(), uid, gid, ownerErr == nil)
}

// evaluateSudoersFilePermissions performs platform-independent permission and ownership checks
// on a sudoers configuration file given its FileMode and UID/GID.
func evaluateSudoersFilePermissions(filePath string, fullMode os.FileMode, ownerUID, ownerGID int, hasOwner bool) []Finding {
	var findings []Finding
	mode := fullMode.Perm()

	// Check if group has write permission
	if mode&0020 != 0 {
		findings = append(findings, Finding{
			ID:          "SUDO-SYS-PERM-002",
			Title:       "Sudoers Writable by Group",
			Description: fmt.Sprintf("The sudoers file '%s' has group write permissions: %s. This allows members of the group to modify the file and elevate privileges.", filePath, mode),
			Severity:    SeverityCritical,
			Context:     filePath,
			Remediation: fmt.Sprintf("Run 'chmod 0440 %s' to restrict write access.", filePath),
			Compliance:  []string{"ANSSI-BP-028 R38", "CIS-5.2.1"},
		})
	}
	// Check if world has write permission
	if mode&0002 != 0 {
		findings = append(findings, Finding{
			ID:          "SUDO-SYS-PERM-003",
			Title:       "Sudoers World Writable",
			Description: fmt.Sprintf("The sudoers file '%s' is world-writable: %s. Any local user can modify the configuration to grant passwordless root privileges.", filePath, mode),
			Severity:    SeverityCritical,
			Context:     filePath,
			Remediation: fmt.Sprintf("Run 'chmod 0440 %s' immediately to secure the policy file.", filePath),
			Compliance:  []string{"ANSSI-BP-028 R38", "CIS-5.2.1"},
		})
	}
	// Check if world has read permission
	if mode&0004 != 0 {
		findings = append(findings, Finding{
			ID:          "SUDO-SYS-PERM-004",
			Title:       "Sudoers World Readable",
			Description: fmt.Sprintf("The sudoers file '%s' is world-readable: %s. This exposes the privilege policy structure to unprivileged local users.", filePath, mode),
			Severity:    SeverityHigh,
			Context:     filePath,
			Remediation: fmt.Sprintf("Run 'chmod 0440 %s' to restrict read access to authorized users.", filePath),
			Compliance:  []string{"ANSSI-BP-028 R38", "CIS-5.2.1"},
		})
	}

	if hasOwner {
		if ownerUID != 0 {
			findings = append(findings, Finding{
				ID:          "SUDO-SYS-PERM-005",
				Title:       "Sudoers Not Owned by Root",
				Description: fmt.Sprintf("The sudoers file '%s' is owned by UID %d, not UID 0 (root). The file owner can modify the policy to grant arbitrary privileges.", filePath, ownerUID),
				Severity:    SeverityCritical,
				Context:     filePath,
				Remediation: fmt.Sprintf("Run 'chown root:root %s' to reset ownership.", filePath),
				Compliance:  []string{"ANSSI-BP-028 R38", "CIS-5.2.1"},
			})
		}
		if ownerGID != 0 && (mode&0070 != 0) {
			findings = append(findings, Finding{
				ID:          "SUDO-SYS-PERM-011",
				Title:       "Sudoers Group Owner Is Not Root",
				Description: fmt.Sprintf("The sudoers file '%s' has group permissions (%s) and is assigned to non-root GID %d. Members of GID %d can access the policy file.", filePath, mode, ownerGID, ownerGID),
				Severity:    SeverityMedium,
				Context:     filePath,
				Remediation: fmt.Sprintf("Run 'chown root:root %s' and 'chmod 0440 %s'.", filePath, filePath),
				Compliance:  []string{"ANSSI-BP-028 R38", "CIS-5.2.1"},
			})
		}
	}

	return findings
}

// AuditSudoersDirPermissions audits a sudoers drop-in directory (such as /etc/sudoers.d) and all active files within it.
func AuditSudoersDirPermissions(dirPath string) []Finding {
	if runtime.GOOS == "windows" {
		return nil
	}

	info, err := os.Stat(dirPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return nil
	}
	if !info.IsDir() {
		return nil
	}

	var findings []Finding
	uid, gid, ownerErr := getUnixOwner(info)
	findings = append(findings, evaluateSudoersFilePermissions(dirPath, info.Mode(), uid, gid, ownerErr == nil)...)

	entries, err := os.ReadDir(dirPath)
	if err != nil {
		return findings
	}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || strings.Contains(name, ".") || strings.HasSuffix(name, "~") {
			continue
		}
		fullPath := filepath.Join(dirPath, name)
		fInfo, statErr := os.Stat(fullPath)
		if statErr != nil {
			continue
		}
		fUID, fGID, fOwnerErr := getUnixOwner(fInfo)
		findings = append(findings, evaluateSudoersFilePermissions(fullPath, fInfo.Mode(), fUID, fGID, fOwnerErr == nil)...)
	}

	return findings
}

// AuditSudoBinaryPermissions checks ownership and permissions of the sudo binary (Unix/Linux).
func AuditSudoBinaryPermissions(filePath string) []Finding {
	if runtime.GOOS == "windows" {
		return nil
	}

	info, err := os.Stat(filePath)
	if err != nil {
		return []Finding{
			{
				ID:          "SUDO-SYS-PERM-006",
				Title:       "Unable to access sudo binary",
				Description: fmt.Sprintf("Could not stat sudo binary at '%s': %v.", filePath, err),
				Severity:    SeverityMedium,
				Context:     filePath,
				Remediation: "Ensure that the sudo binary exists at the expected path or verify permissions.",
			},
		}
	}

	uid, gid, ownerErr := getUnixOwner(info)
	return evaluateSudoBinaryPermissions(filePath, info.Mode(), uid, gid, ownerErr == nil)
}

// evaluateSudoBinaryPermissions performs platform-independent permission and ownership checks
// on the sudo binary given its FileMode and UID/GID.
func evaluateSudoBinaryPermissions(filePath string, fullMode os.FileMode, ownerUID, ownerGID int, hasOwner bool) []Finding {
	var findings []Finding
	mode := fullMode.Perm()
	_ = ownerGID

	// The sudo binary must have the SUID bit set
	if fullMode&os.ModeSetuid == 0 {
		findings = append(findings, Finding{
			ID:          "SUDO-SYS-PERM-007",
			Title:       "Sudo Binary Missing SUID Bit",
			Description: fmt.Sprintf("The sudo binary '%s' does not have the setuid (SUID) bit set. Sudo relies on the SUID bit to run commands as root.", filePath),
			Severity:    SeverityCritical,
			Context:     filePath,
			Remediation: fmt.Sprintf("Run 'chmod 4755 %s' (or 'chmod 4110 %s' for restricted group access) to restore the SUID bit.", filePath, filePath),
		})
	}

	// Sudo binary should not be writable by group or other
	if mode&0020 != 0 {
		findings = append(findings, Finding{
			ID:          "SUDO-SYS-PERM-008",
			Title:       "Sudo Binary Writable by Group",
			Description: fmt.Sprintf("The sudo binary '%s' is writable by group: %s. This allows group members to modify the binary and compromise the system.", filePath, mode),
			Severity:    SeverityCritical,
			Context:     filePath,
			Remediation: fmt.Sprintf("Run 'chmod g-w %s' to remove group write permissions.", filePath),
			Compliance:  []string{"ANSSI-BP-028 R38"},
		})
	}
	if mode&0002 != 0 {
		findings = append(findings, Finding{
			ID:          "SUDO-SYS-PERM-009",
			Title:       "Sudo Binary World Writable",
			Description: fmt.Sprintf("The sudo binary '%s' is world-writable: %s. Any local user can overwrite the sudo binary to escalate privileges.", filePath, mode),
			Severity:    SeverityCritical,
			Context:     filePath,
			Remediation: fmt.Sprintf("Run 'chmod o-w %s' immediately to secure the sudo binary.", filePath),
			Compliance:  []string{"ANSSI-BP-028 R38"},
		})
	}

	if hasOwner && ownerUID != 0 {
		findings = append(findings, Finding{
			ID:          "SUDO-SYS-PERM-010",
			Title:       "Sudo Binary Not Owned by Root",
			Description: fmt.Sprintf("The sudo binary '%s' is owned by UID %d instead of UID 0 (root). This is highly insecure.", filePath, ownerUID),
			Severity:    SeverityCritical,
			Context:     filePath,
			Remediation: fmt.Sprintf("Run 'chown root:root %s' to reset ownership.", filePath),
			Compliance:  []string{"ANSSI-BP-028 R38"},
		})
	}

	return findings
}

// AuditPolicyTargetBinaries inspects the on-disk permissions and ownership of command binaries
// referenced in the sudoers policy when running on a live Unix system.
func AuditPolicyTargetBinaries(policy *SudoersPolicy) []Finding {
	if runtime.GOOS == "windows" || policy == nil {
		return nil
	}

	var findings []Finding
	checked := make(map[string]bool)
	checkedDirs := make(map[string]bool)

	for _, spec := range policy.UserSpecs {
		for _, cs := range spec.CmndSpecs {
			var allCmds []Member
			for _, m := range cs.Commands {
				allCmds = append(allCmds, resolveCommands(m, policy)...)
			}
			for _, m := range allCmds {
				if m.Negated || m.Command == "" || m.Command == "ALL" {
					continue
				}
				parts := strings.Fields(m.Command)
				if len(parts) == 0 {
					continue
				}
				exePath := parts[0]
				if !strings.HasPrefix(exePath, "/") || wildcardRegex.MatchString(exePath) {
					continue
				}

				if !checked[exePath] {
					checked[exePath] = true
					if info, err := os.Stat(exePath); err == nil && !info.IsDir() {
						uid, _, ownerErr := getUnixOwner(info)
						findings = append(findings, evaluateTargetBinaryPermissions(exePath, info.Mode(), uid, ownerErr == nil)...)
					}
				}

				parentDir := filepath.Dir(exePath)
				if !checkedDirs[parentDir] {
					checkedDirs[parentDir] = true
					if dirInfo, err := os.Stat(parentDir); err == nil && dirInfo.IsDir() {
						dirMode := dirInfo.Mode().Perm()
						if (dirMode&0002 != 0 && dirInfo.Mode()&os.ModeSticky == 0) || dirMode&0020 != 0 {
							findings = append(findings, Finding{
								ID:          "SUDO-SYS-PERM-013",
								Title:       "Permitted Sudo Command Parent Directory Writable",
								Description: fmt.Sprintf("The parent directory '%s' of permitted sudo command '%s' has write permissions (%s). Attackers can rename or replace the binary inside this directory.", parentDir, exePath, dirMode),
								Severity:    SeverityCritical,
								Command:     exePath,
								Context:     parentDir,
								Remediation: fmt.Sprintf("Run 'chmod 0755 %s' and 'chown root:root %s' to secure the directory.", parentDir, parentDir),
								Compliance:  []string{"ANSSI-BP-028"},
							})
						}
					}
				}
			}
		}
	}

	return findings
}

func evaluateTargetBinaryPermissions(exePath string, fullMode os.FileMode, ownerUID int, hasOwner bool) []Finding {
	var findings []Finding
	mode := fullMode.Perm()

	if mode&0002 != 0 || mode&0020 != 0 {
		findings = append(findings, Finding{
			ID:          "SUDO-SYS-PERM-012",
			Title:       "Permitted Sudo Target Executable Is Group or World Writable",
			Description: fmt.Sprintf("The executable '%s' referenced in the sudoers policy has writable permissions (%s). Unprivileged users who can modify this file can execute arbitrary code when it is invoked via sudo.", exePath, mode),
			Severity:    SeverityCritical,
			Command:     exePath,
			Context:     exePath,
			Remediation: fmt.Sprintf("Run 'chmod 0755 %s' and 'chown root:root %s' to prevent unauthorized modification.", exePath, exePath),
			Compliance:  []string{"ANSSI-BP-028"},
		})
	} else if hasOwner && ownerUID != 0 {
		findings = append(findings, Finding{
			ID:          "SUDO-SYS-PERM-012",
			Title:       "Permitted Sudo Target Executable Not Owned by Root",
			Description: fmt.Sprintf("The executable '%s' referenced in the sudoers policy is owned by non-root UID %d. Account compromise of UID %d allows replacing the binary to escalate privileges.", exePath, ownerUID, ownerUID),
			Severity:    SeverityHigh,
			Command:     exePath,
			Context:     exePath,
			Remediation: fmt.Sprintf("Run 'chown root:root %s' to ensure the executable is owned by root.", exePath),
			Compliance:  []string{"ANSSI-BP-028"},
		})
	}

	return findings
}
