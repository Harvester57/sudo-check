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

var (
	versionRegex     = regexp.MustCompile(`^([0-9]+)\.([0-9]+)\.([0-9]+)(?:p([0-9]+))?`)
	nonDigitVerRegex = regexp.MustCompile(`[^\d.p]+`)
	leadNonDigitRx   = regexp.MustCompile(`^[^\d]+`)
)

// ParseSudoVersion parses a sudo version string (like "1.8.31p2" or "1.9.12").
func ParseSudoVersion(verStr string) (SudoVersion, error) {
	// Clean up trailing text or carriage returns
	cleanVer := nonDigitVerRegex.ReplaceAllString(verStr, "")
	cleanVer = leadNonDigitRx.ReplaceAllString(cleanVer, "")

	matches := versionRegex.FindStringSubmatch(cleanVer)
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

// AuditSudoVersion checks if the current sudo version is vulnerable to known high-profile CVEs.
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

	// CVE-2019-14287: Sudo < 1.8.28 (UID -1 / 4294967295 root bypass)
	v1828 := SudoVersion{Major: 1, Minor: 8, Patch: 28, Pl: 0}
	if v.Compare(v1828) < 0 {
		findings = append(findings, Finding{
			ID:          "CVE-2019-14287",
			Title:       "Sudo uid -1 Bypass Vulnerability",
			Description: fmt.Sprintf("The system runs sudo version %s, which is vulnerable to CVE-2019-14287. Users with permissions to execute commands as any user except root can bypass this restriction and execute commands as root by passing UID -1 or 4294967295.", v.Raw),
			Severity:    SeverityHigh,
			Remediation: "Upgrade sudo to version 1.8.28 or later.",
		})
	}

	// CVE-2021-3156 (Baron Samedit): heap-based buffer overflow
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
			Description: fmt.Sprintf("The system runs sudo version %s, which is vulnerable to CVE-2021-3156 (Baron Samedit). A local unprivileged user can exploit this buffer overflow vulnerability in command-line argument parsing to escalate privileges and execute arbitrary commands as root.", v.Raw),
			Severity:    SeverityCritical,
			Remediation: "Upgrade sudo to version 1.8.32, 1.9.5p2, or install the vendor security patch.",
		})
	}

	// CVE-2023-22809 / CVE-2023-27320: Sudoedit arbitrary file write / privilege escalation
	// Affected: 1.8.0 through 1.9.12p1
	v180 := SudoVersion{Major: 1, Minor: 8, Patch: 0, Pl: 0}
	v1912p1 := SudoVersion{Major: 1, Minor: 9, Patch: 12, Pl: 1}

	if v.Compare(v180) >= 0 && v.Compare(v1912p1) <= 0 {
		findings = append(findings, Finding{
			ID:          "CVE-2023-22809",
			Title:       "Sudoedit Arbitrary File Write Vulnerability",
			Description: fmt.Sprintf("The system runs sudo version %s, which is vulnerable to CVE-2023-22809. Sudoedit fails to properly sanitize user-provided environment variables (SUDO_EDITOR, VISUAL, EDITOR), allowing local users with sudoedit access to edit arbitrary files as root.", v.Raw),
			Severity:    SeverityHigh,
			Remediation: "Upgrade sudo to version 1.9.12p2 or later.",
		})
		findings = append(findings, Finding{
			ID:          "CVE-2023-27320",
			Title:       "Sudoedit Privilege Escalation Vulnerability",
			Description: fmt.Sprintf("The system runs sudo version %s, which is vulnerable to CVE-2023-27320. Sudoedit allows local users with permission to edit files to execute arbitrary commands with root privileges via symbolic links.", v.Raw),
			Severity:    SeverityHigh,
			Remediation: "Upgrade sudo to version 1.9.12p2 or later.",
		})
	}

	// CVE-2025-32462: Sudo --host (-h) option privilege escalation
	// Affected: 1.8.8 through 1.9.17 (fixed in 1.9.17p1)
	v188 := SudoVersion{Major: 1, Minor: 8, Patch: 8, Pl: 0}
	v1917 := SudoVersion{Major: 1, Minor: 9, Patch: 17, Pl: 0}
	if v.Compare(v188) >= 0 && v.Compare(v1917) <= 0 {
		findings = append(findings, Finding{
			ID:          "CVE-2025-32462",
			Title:       "Sudo Host Option (-h) Privilege Escalation",
			Description: fmt.Sprintf("The system runs sudo version %s, which is vulnerable to CVE-2025-32462. Local users can pass the '--host' ('-h') flag with a remote hostname found in the sudoers policy to execute commands intended only for other hosts on the local machine.", v.Raw),
			Severity:    SeverityHigh,
			Remediation: "Upgrade sudo to version 1.9.17p1 or later, or install the vendor security backport.",
		})
	}

	// CVE-2025-32463: Sudo --chroot (-R) NSS arbitrary shared library load as root
	// Affected: 1.9.14 through 1.9.17 (fixed in 1.9.17p1)
	v1914 := SudoVersion{Major: 1, Minor: 9, Patch: 14, Pl: 0}
	if v.Compare(v1914) >= 0 && v.Compare(v1917) <= 0 {
		findings = append(findings, Finding{
			ID:          "CVE-2025-32463",
			Title:       "Sudo Chroot (-R) Root Privilege Escalation",
			Description: fmt.Sprintf("The system runs sudo version %s, which is vulnerable to CVE-2025-32463. Any local unprivileged user can specify a user-controlled directory via 'sudo -R' (--chroot) containing a crafted '/etc/nsswitch.conf' and shared library to execute arbitrary code as root.", v.Raw),
			Severity:    SeverityCritical,
			Remediation: "Upgrade sudo immediately to version 1.9.17p1 or later.",
		})
	}

	return findings, nil
}

// AuditSudoersPermissions checks ownership and permissions of /etc/sudoers and /etc/sudoers.d (Unix only).
func AuditSudoersPermissions(filePath string) []Finding {
	if runtime.GOOS == "windows" {
		// Permissions checks are bypassed on Windows host
		return nil
	}

	var findings []Finding
	findings = append(findings, auditSingleSudoersFile(filePath)...)

	// Also check /etc/sudoers.d drop-in directory if it exists alongside the main sudoers file.
	sudoersDir := filePath + ".d"
	if dirInfo, err := os.Stat(sudoersDir); err == nil && dirInfo.IsDir() {
		dirMode := dirInfo.Mode().Perm()
		if dirMode&0020 != 0 || dirMode&0002 != 0 {
			findings = append(findings, Finding{
				ID:          "SUDO-SYS-PERM-002",
				Title:       "Sudoers Drop-in Directory Writable by Group or World",
				Description: fmt.Sprintf("The sudoers drop-in directory '%s' has overly permissive write permissions: %s. Non-root users may be able to plant or replace drop-in policy files.", sudoersDir, dirMode),
				Severity:    SeverityCritical,
				Context:     sudoersDir,
				Remediation: fmt.Sprintf("Run 'chmod 0750 %s' to restrict directory access.", sudoersDir),
			})
		}
		if ownerUID, _, err := getUnixOwner(dirInfo); err == nil && ownerUID != 0 {
			findings = append(findings, Finding{
				ID:          "SUDO-SYS-PERM-005",
				Title:       "Sudoers Drop-in Directory Not Owned by Root",
				Description: fmt.Sprintf("The sudoers drop-in directory '%s' is owned by UID %d instead of UID 0 (root).", sudoersDir, ownerUID),
				Severity:    SeverityCritical,
				Context:     sudoersDir,
				Remediation: fmt.Sprintf("Run 'chown root:root %s' to reset ownership.", sudoersDir),
			})
		}

		if entries, err := os.ReadDir(sudoersDir); err == nil {
			for _, entry := range entries {
				name := entry.Name()
				// Sudo ignores files in sudoers.d that contain a '.' or end with '~'
				if entry.IsDir() || strings.Contains(name, ".") || strings.HasSuffix(name, "~") {
					continue
				}
				findings = append(findings, auditSingleSudoersFile(filepath.Join(sudoersDir, name))...)
			}
		}
	}

	return findings
}

// auditSingleSudoersFile checks permissions and ownership of a single sudoers policy file.
func auditSingleSudoersFile(filePath string) []Finding {
	var findings []Finding

	info, err := os.Stat(filePath)
	if err != nil {
		findings = append(findings, Finding{
			ID:          "SUDO-SYS-PERM-001",
			Title:       "Unable to access sudoers file",
			Description: fmt.Sprintf("Could not stat sudoers file at '%s': %v. Ensure the auditor is running with sufficient privileges.", filePath, err),
			Severity:    SeverityMedium,
			Context:     filePath,
			Remediation: "Run the sudo-check utility with root/sudo privileges.",
		})
		return findings
	}

	// Get file mode and check permissions
	mode := info.Mode().Perm()

	// Check if group/other has write permission
	if mode&0020 != 0 {
		findings = append(findings, Finding{
			ID:          "SUDO-SYS-PERM-002",
			Title:       "Sudoers Writable by Group",
			Description: fmt.Sprintf("The sudoers file '%s' has group write permissions: %s. This allows members of the group to overwrite the file and elevate privileges.", filePath, mode),
			Severity:    SeverityCritical,
			Context:     filePath,
			Remediation: fmt.Sprintf("Run 'chmod 0440 %s' to restrict write access.", filePath),
		})
	}
	if mode&0002 != 0 {
		findings = append(findings, Finding{
			ID:          "SUDO-SYS-PERM-003",
			Title:       "Sudoers World Writable",
			Description: fmt.Sprintf("The sudoers file '%s' is world-writable: %s. Any local user can modify the configuration to grant themselves passwordless root privileges.", filePath, mode),
			Severity:    SeverityCritical,
			Context:     filePath,
			Remediation: fmt.Sprintf("Run 'chmod 0440 %s' immediately to secure the policy file.", filePath),
		})
	}

	// Check if other has read permission (leaks sensitive configuration)
	if mode&0004 != 0 {
		findings = append(findings, Finding{
			ID:          "SUDO-SYS-PERM-004",
			Title:       "Sudoers World Readable",
			Description: fmt.Sprintf("The sudoers file '%s' is world-readable: %s. This leaks the full privilege policy structure, allowing local users to identify vulnerabilities and bypass paths.", filePath, mode),
			Severity:    SeverityHigh,
			Context:     filePath,
			Remediation: fmt.Sprintf("Run 'chmod 0440 %s' to restrict read access to authorized users.", filePath),
		})
	}

	// Owner and Group check (requires syscall on Unix/Linux)
	if ownerUID, ownerGID, err := getUnixOwner(info); err == nil {
		if ownerUID != 0 {
			findings = append(findings, Finding{
				ID:          "SUDO-SYS-PERM-005",
				Title:       "Sudoers Not Owned by Root",
				Description: fmt.Sprintf("The sudoers file '%s' is owned by UID %d, not UID 0 (root). The owner can modify the file to grant arbitrary privileges.", filePath, ownerUID),
				Severity:    SeverityCritical,
				Context:     filePath,
				Remediation: fmt.Sprintf("Run 'chown root:root %s' to reset ownership.", filePath),
			})
		}
		// On Unix/Linux, GIDs >= 1000 belong to regular unprivileged user groups.
		// If group read is enabled (mode 0440), members of that group can read the sudoers policy.
		if ownerGID >= 1000 {
			findings = append(findings, Finding{
				ID:          "SUDO-SYS-PERM-011",
				Title:       "Sudoers Assigned to Non-System Group",
				Description: fmt.Sprintf("The sudoers file '%s' has group ownership set to non-system GID %d. Members of this group may be able to read or inspect the policy.", filePath, ownerGID),
				Severity:    SeverityMedium,
				Context:     filePath,
				Remediation: fmt.Sprintf("Run 'chown root:root %s' to restrict group ownership to root.", filePath),
			})
		}
	}

	return findings
}

// AuditSudoBinaryPermissions checks ownership and permissions of the sudo binary (Linux/Unix only).
func AuditSudoBinaryPermissions(filePath string) []Finding {
	if runtime.GOOS == "windows" {
		return nil
	}

	var findings []Finding

	info, err := os.Stat(filePath)
	if err != nil {
		findings = append(findings, Finding{
			ID:          "SUDO-SYS-PERM-006",
			Title:       "Unable to access sudo binary",
			Description: fmt.Sprintf("Could not stat sudo binary at '%s': %v.", filePath, err),
			Severity:    SeverityMedium,
			Context:     filePath,
			Remediation: "Ensure that the sudo binary exists at the default path or check permissions.",
		})
		return findings
	}

	mode := info.Mode().Perm()

	// The sudo binary must have the SUID bit set
	if info.Mode()&os.ModeSetuid == 0 {
		findings = append(findings, Finding{
			ID:          "SUDO-SYS-PERM-007",
			Title:       "Sudo Binary Missing SUID Bit",
			Description: fmt.Sprintf("The sudo binary '%s' does not have the setuid (SUID) bit set. Sudo relies on the SUID bit to run commands as root.", filePath),
			Severity:    SeverityCritical,
			Context:     filePath,
			Remediation: fmt.Sprintf("Run 'chmod u+s %s' to restore the SUID bit.", filePath),
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
		})
	}

	// Owner check
	if ownerUID, _, err := getUnixOwner(info); err == nil {
		if ownerUID != 0 {
			findings = append(findings, Finding{
				ID:          "SUDO-SYS-PERM-010",
				Title:       "Sudo Binary Not Owned by Root",
				Description: fmt.Sprintf("The sudo binary '%s' is owned by UID %d instead of UID 0 (root). This is highly insecure.", filePath, ownerUID),
				Severity:    SeverityCritical,
				Context:     filePath,
				Remediation: fmt.Sprintf("Run 'chown root:root %s' to reset ownership.", filePath),
			})
		}
	}

	return findings
}

// AuditAllowedCommandPermissions inspects the local filesystem permissions of concrete binaries
// and scripts permitted by the sudoers policy. If an allowed script/binary (or its parent directory)
// is writable by non-root users, local attackers can modify or replace it for root privilege escalation.
func AuditAllowedCommandPermissions(policy *SudoersPolicy) []Finding {
	if runtime.GOOS == "windows" || policy == nil {
		return nil
	}

	var findings []Finding
	checkedPaths := make(map[string]bool)
	checkedDirs := make(map[string]bool)

	for _, spec := range policy.UserSpecs {
		for _, cs := range spec.CmndSpecs {
			for _, cmdMember := range cs.Commands {
				for _, resolved := range resolveCommands(cmdMember, policy) {
					if resolved.Negated || resolved.Command == "" || resolved.Command == "ALL" {
						continue
					}
					parts := strings.Fields(resolved.Command)
					if len(parts) == 0 {
						continue
					}
					exePath := parts[0]
					if !strings.HasPrefix(exePath, "/") || wildcardRegex.MatchString(exePath) {
						continue
					}

					if !checkedPaths[exePath] {
						checkedPaths[exePath] = true
						if info, err := os.Stat(exePath); err == nil && !info.IsDir() {
							mode := info.Mode().Perm()
							if mode&0002 != 0 || mode&0020 != 0 {
								findings = append(findings, Finding{
									ID:          "SUDO-SYS-PERM-012",
									Title:       "Permitted Sudo Command Binary Writable by Non-Root",
									Description: fmt.Sprintf("The command binary '%s' permitted in sudoers has insecure write permissions (%s). Unprivileged users can modify its contents to execute arbitrary code with elevated privileges.", exePath, mode),
									Severity:    SeverityCritical,
									Command:     exePath,
									Context:     exePath,
									Remediation: fmt.Sprintf("Run 'chmod 0755 %s' and 'chown root:root %s' to secure the executable.", exePath, exePath),
								})
							}
							if ownerUID, _, err := getUnixOwner(info); err == nil && ownerUID != 0 {
								findings = append(findings, Finding{
									ID:          "SUDO-SYS-PERM-012",
									Title:       "Permitted Sudo Command Binary Not Owned by Root",
									Description: fmt.Sprintf("The command binary '%s' permitted in sudoers is owned by UID %d instead of UID 0 (root). The file owner can modify the binary to escalate privileges.", exePath, ownerUID),
									Severity:    SeverityCritical,
									Command:     exePath,
									Context:     exePath,
									Remediation: fmt.Sprintf("Run 'chown root:root %s' to transfer ownership to root.", exePath),
								})
							}
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
								})
							}
						}
					}
				}
			}
		}
	}

	return findings
}
