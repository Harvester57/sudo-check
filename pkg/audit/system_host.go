package audit

import (
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

var hostAuditCVERegex = regexp.MustCompile(`(?i)CVE-\d{4}-\d{4,}`)

// EvaluateSudoBinaryGroupRestriction checks ANSSI BP-028 R38 compliance on the
// sudo binary permissions, flagging world-executable binaries (e.g. 4755) that are
// not restricted to a dedicated administrative group.
func EvaluateSudoBinaryGroupRestriction(filePath string, fullMode os.FileMode, ownerGID int) []Finding {
	if fullMode.Perm()&0001 != 0 {
		return []Finding{
			{
				ID:              "SUDO-SYS-PERM-014",
				Title:           "Sudo Binary Executable by All Local Users (No Dedicated Group Restriction)",
				Description:     fmt.Sprintf("The sudo binary '%s' has world-execute permissions (%s, group GID %d). Any local user can invoke sudo. ANSSI BP-028 R38 recommends restricting sudo execution to a dedicated administrative group.", filePath, fullMode.Perm(), ownerGID),
				Severity:        SeverityInfo,
				Context:         filePath,
				Remediation:     fmt.Sprintf("Restrict execution of '%s' to a dedicated sudo group (such as 'sudo' or 'wheel') and remove world-execute permissions.", filePath),
				RemediationCode: "sudo chgrp sudo " + filePath + "\nsudo chmod 4750 " + filePath,
				Compliance:      []string{"ANSSI-BP-028 R38"},
			},
		}
	}
	return nil
}

// AuditSudoBinaryGroupRestriction inspects the live host sudo binary for ANSSI BP-028 R38
// dedicated group restriction compliance. Returns nil on Windows or if the file cannot be accessed.
func AuditSudoBinaryGroupRestriction(filePath string) []Finding {
	if runtime.GOOS == "windows" {
		return nil
	}
	info, err := os.Stat(filePath)
	if err != nil {
		return nil
	}
	_, gid, _ := getUnixOwner(info)
	return EvaluateSudoBinaryGroupRestriction(filePath, info.Mode(), gid)
}

type hostAuditIdentityDB struct {
	hasPasswd bool
	users     map[string]bool
	uids      map[int]bool
	hasGroup  bool
	groups    map[string]bool
	gids      map[int]bool
}

func hostAuditParseIdentities(passwdData, groupData []byte) hostAuditIdentityDB {
	db := hostAuditIdentityDB{
		users:  make(map[string]bool),
		uids:   make(map[int]bool),
		groups: make(map[string]bool),
		gids:   make(map[int]bool),
	}

	if len(passwdData) > 0 {
		for _, rawLine := range strings.Split(string(passwdData), "\n") {
			line := strings.TrimSpace(strings.TrimSuffix(rawLine, "\r"))
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			fields := strings.Split(line, ":")
			if len(fields) < 3 {
				continue
			}
			name := strings.TrimSpace(fields[0])
			if name != "" {
				db.users[name] = true
			}
			if uid, err := strconv.Atoi(strings.TrimSpace(fields[2])); err == nil {
				db.uids[uid] = true
			}
		}
		db.hasPasswd = len(db.users) > 0 || len(db.uids) > 0
	}

	if len(groupData) > 0 {
		for _, rawLine := range strings.Split(string(groupData), "\n") {
			line := strings.TrimSpace(strings.TrimSuffix(rawLine, "\r"))
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			fields := strings.Split(line, ":")
			if len(fields) < 3 {
				continue
			}
			name := strings.TrimSpace(fields[0])
			if name != "" {
				db.groups[name] = true
			}
			if gid, err := strconv.Atoi(strings.TrimSpace(fields[2])); err == nil {
				db.gids[gid] = true
			}
		}
		db.hasGroup = len(db.groups) > 0 || len(db.gids) > 0
	}

	return db
}

// AuditPolicyIdentities validates explicit usernames, UIDs, groups, and GIDs referenced
// in sudoers User_List, Runas_Users, and Runas_Groups against passwd and group database bytes.
func AuditPolicyIdentities(policy *SudoersPolicy, passwdData, groupData []byte) []Finding {
	if policy == nil {
		return nil
	}

	db := hostAuditParseIdentities(passwdData, groupData)
	if !db.hasPasswd && !db.hasGroup {
		return nil
	}

	var findings []Finding
	seenMissing := make(map[string]bool)

	checkMember := func(m Member, isRunasGroup bool, specUserStr string, isRunas bool, fallbackFile string, fallbackLine int) {
		key, display, missing := hostAuditCheckMemberMissing(m, isRunasGroup, db)
		if !missing || seenMissing[key] {
			return
		}
		seenMissing[key] = true

		ctx := m.File
		if ctx == "" {
			ctx = fallbackFile
		}
		line := m.Line
		if line == 0 {
			line = fallbackLine
		}

		f := Finding{
			ID:          "SUDO-SYS-ID-001",
			Title:       "Nonexistent or Orphaned User/Group Referenced in Sudoers",
			Description: fmt.Sprintf("The sudoers policy references principal '%s', which does not exist in the local passwd/group database. Orphaned sudoers entries can lead to unintended privilege assignment if the name or numeric ID is later reused.", display),
			Severity:    SeverityLow,
			Context:     ctx,
			Line:        line,
			Remediation: fmt.Sprintf("Remove the stale sudoers entry referencing '%s' via visudo, or provision the missing user/group account.", display),
			RemediationCode: fmt.Sprintf(
				"# Remove stale entry for '%s' from visudo or provision the account\nsudo visudo",
				display,
			),
		}
		if isRunas {
			f.User = specUserStr
			f.Runas = display
		} else {
			f.User = display
		}
		findings = append(findings, f)
	}

	for _, spec := range policy.UserSpecs {
		resolvedUsers := resolveMemberSlice(spec.UserList, policy, aliasKindUser)
		specUserStr := hostAuditJoinMemberNames(resolvedUsers)
		for _, m := range resolvedUsers {
			checkMember(m, false, specUserStr, false, spec.File, spec.Line)
		}

		for _, cs := range spec.CmndSpecs {
			resolvedRunasUsers := resolveMemberSlice(cs.RunasUsers, policy, aliasKindRunas)
			for _, m := range resolvedRunasUsers {
				checkMember(m, false, specUserStr, true, spec.File, spec.Line)
			}
			resolvedRunasGroups := resolveMemberSlice(cs.RunasGroups, policy, aliasKindRunas)
			for _, m := range resolvedRunasGroups {
				checkMember(m, true, specUserStr, true, spec.File, spec.Line)
			}
		}
	}

	return findings
}

func hostAuditCheckMemberMissing(m Member, isRunasGroup bool, db hostAuditIdentityDB) (dedupKey string, display string, missing bool) {
	if m.Myself || m.Netgroup != "" || m.NonUnixGroup != "" || m.NonUnixGID != nil {
		return "", "", false
	}
	// Skip aliases that did not resolve in the policy.
	if m.UserAlias != "" || m.RunasAlias != "" {
		return "", "", false
	}

	if m.UserID != nil {
		if !db.hasPasswd {
			return "", "", false
		}
		if !db.uids[*m.UserID] {
			disp := fmt.Sprintf("#%d", *m.UserID)
			return "uid:" + strconv.Itoa(*m.UserID), disp, true
		}
		return "", "", false
	}

	if m.UserGID != nil {
		if !db.hasGroup {
			return "", "", false
		}
		if !db.gids[*m.UserGID] {
			disp := fmt.Sprintf("%%#%d", *m.UserGID)
			return "gid:" + strconv.Itoa(*m.UserGID), disp, true
		}
		return "", "", false
	}

	if m.Usergroup != "" {
		if m.Usergroup == "ALL" || m.Usergroup == "MYSELF" {
			return "", "", false
		}
		if strings.HasPrefix(m.Usergroup, ":") {
			// Non-unix group notation parsed inside Usergroup.
			return "", "", false
		}
		if strings.HasPrefix(m.Usergroup, "#") {
			if gid, err := strconv.Atoi(m.Usergroup[1:]); err == nil {
				if db.hasGroup && !db.gids[gid] {
					disp := fmt.Sprintf("%%#%d", gid)
					return "gid:" + strconv.Itoa(gid), disp, true
				}
				return "", "", false
			}
		}
		if db.hasGroup && !db.groups[m.Usergroup] {
			return "group:" + m.Usergroup, "%" + m.Usergroup, true
		}
		return "", "", false
	}

	if m.Username != "" {
		u := m.Username
		if u == "ALL" || u == "MYSELF" || strings.HasPrefix(u, "+") || strings.HasPrefix(u, "%:") {
			return "", "", false
		}
		if strings.HasPrefix(u, "%#") {
			if gid, err := strconv.Atoi(u[2:]); err == nil {
				if db.hasGroup && !db.gids[gid] {
					return "gid:" + strconv.Itoa(gid), u, true
				}
				return "", "", false
			}
		}
		if strings.HasPrefix(u, "%") {
			gName := u[1:]
			if gName != "" && db.hasGroup && !db.groups[gName] {
				return "group:" + gName, u, true
			}
			return "", "", false
		}
		if strings.HasPrefix(u, "#") {
			if uid, err := strconv.Atoi(u[1:]); err == nil {
				if isRunasGroup {
					if db.hasGroup && !db.gids[uid] {
						return "gid:" + strconv.Itoa(uid), fmt.Sprintf("%%#%d", uid), true
					}
					return "", "", false
				}
				if db.hasPasswd && !db.uids[uid] {
					return "uid:" + strconv.Itoa(uid), u, true
				}
				return "", "", false
			}
		}
		if isRunasGroup {
			if db.hasGroup && !db.groups[u] {
				return "group:" + u, "%" + u, true
			}
			return "", "", false
		}
		if db.hasPasswd && !db.users[u] {
			return "user:" + u, u, true
		}
	}

	return "", "", false
}

func hostAuditJoinMemberNames(members []Member) string {
	var names []string
	for _, m := range members {
		if n := m.GetName(); n != "" {
			names = append(names, n)
		}
	}
	return strings.Join(names, ", ")
}

// AuditLocalPolicyIdentities reads /etc/passwd and /etc/group on live Unix hosts
// and validates sudoers principal references via AuditPolicyIdentities.
func AuditLocalPolicyIdentities(policy *SudoersPolicy) []Finding {
	if runtime.GOOS == "windows" || policy == nil {
		return nil
	}
	passwdData, _ := os.ReadFile("/etc/passwd")
	groupData, _ := os.ReadFile("/etc/group")
	return AuditPolicyIdentities(policy, passwdData, groupData)
}

// ParsePatchedCVEsFromChangelog extracts unique CVE identifiers from package changelog text,
// normalized to uppercase (for example "CVE-2021-3156").
func ParsePatchedCVEsFromChangelog(changelog string) map[string]bool {
	patched := make(map[string]bool)
	for _, match := range hostAuditCVERegex.FindAllString(changelog, -1) {
		patched[strings.ToUpper(match)] = true
	}
	return patched
}

// FilterBackportedCVEs returns a new slice where any CVE finding present in patchedCVEs
// is downgraded to SeverityInfo with Exploitability set to "PATCHED_BACKPORT".
func FilterBackportedCVEs(findings []Finding, patchedCVEs map[string]bool) []Finding {
	if findings == nil {
		return nil
	}
	filtered := make([]Finding, len(findings))
	for i, f := range findings {
		out := f
		normID := strings.ToUpper(strings.TrimSpace(f.ID))
		if patchedCVEs != nil && patchedCVEs[normID] {
			out.Severity = SeverityInfo
			out.Exploitability = "PATCHED_BACKPORT"
			out.Title = fmt.Sprintf("%s [Patched via Vendor Backport]", f.Title)
			out.Description = fmt.Sprintf("%s Vendor package changelog confirms %s is patched via distribution backport.", f.Description, normID)
			out.Remediation = fmt.Sprintf("No upgrade needed if running the vendor package; %s is listed as patched in the local package changelog.", normID)
			out.RemediationCode = fmt.Sprintf("dpkg -l sudo || rpm -q --changelog sudo | grep %s", normID)
		}
		filtered[i] = out
	}
	return filtered
}

// CollectLocalPatchedSudoCVEs inspects local RPM and Debian/gzipped sudo changelogs
// on Unix hosts to collect CVEs marked as patched by distribution backports.
func CollectLocalPatchedSudoCVEs() map[string]bool {
	patched := make(map[string]bool)
	if runtime.GOOS == "windows" {
		return patched
	}

	if rpmPath, err := exec.LookPath("rpm"); err == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		out, cmdErr := exec.CommandContext(ctx, rpmPath, "-q", "--changelog", "sudo").Output()
		cancel()
		if cmdErr == nil {
			for k := range ParsePatchedCVEsFromChangelog(string(out)) {
				patched[k] = true
			}
		}
	}

	for _, gzPath := range []string{
		"/usr/share/doc/sudo/changelog.Debian.gz",
		"/usr/share/doc/sudo/changelog.gz",
	} {
		if text, ok := hostAuditReadGzipFile(gzPath, 8*1024*1024); ok {
			for k := range ParsePatchedCVEsFromChangelog(text) {
				patched[k] = true
			}
		}
	}

	return patched
}

func hostAuditReadGzipFile(gzPath string, maxBytes int64) (string, bool) {
	f, err := os.Open(gzPath)
	if err != nil {
		return "", false
	}
	defer func() { _ = f.Close() }()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return "", false
	}
	defer func() { _ = gz.Close() }()

	data, err := io.ReadAll(io.LimitReader(gz, maxBytes))
	if err != nil {
		return "", false
	}
	return string(data), true
}

type hostAuditPolicyContext struct {
	hasPwfeedback        bool
	pwfeedbackEvidence   string
	hasNegatedRunas      bool
	negatedRunasEvidence string
	hasSudoeditOrALL     bool
	sudoeditEvidence     string
	hasChroot            bool
	chrootEvidence       string
	hasNonALLHost        bool
	nonALLHostEvidence   string
}

func hostAuditAnalyzePolicyForCVEs(policy *SudoersPolicy) hostAuditPolicyContext {
	var ctx hostAuditPolicyContext
	if policy == nil {
		return ctx
	}

	// Evaluate global Defaults sequentially with last-match-wins semantics.
	globalState := newDefaultsState()
	type scopedGroup struct {
		scopeLabel string
		binding    []Member
		state      *defaultsState
	}
	var groupOrder []string
	scopedGroups := make(map[string]*scopedGroup)

	for _, def := range policy.Defaults {
		if len(def.Binding) == 0 {
			globalState.applyOptionsFrom(def.Options, def.File, def.Line, def.RawLine)
			continue
		}
		key := canonicalBindingKey(def.Binding)
		grp, exists := scopedGroups[key]
		if !exists {
			scopeLabel := hostAuditJoinMemberNames(def.Binding)
			grp = &scopedGroup{
				scopeLabel: scopeLabel,
				binding:    def.Binding,
				state:      newDefaultsState(),
			}
			scopedGroups[key] = grp
			groupOrder = append(groupOrder, key)
		}
		grp.state.applyOptionsFrom(def.Options, def.File, def.Line, def.RawLine)

		// Check Defaults@ host-scoped non-ALL restrictions for CVE-2025-32462.
		if !ctx.hasNonALLHost && inferBindingScope(def.Binding) == scopeHost {
			resolvedHosts := resolveMemberSlice(def.Binding, policy, aliasKindHost)
			for _, h := range resolvedHosts {
				if n := h.rawName(); n != "" && (n != "ALL" || h.Negated) {
					ctx.hasNonALLHost = true
					ctx.nonALLHostEvidence = fmt.Sprintf("Defaults@%s restricts scope to non-ALL host target", grp.scopeLabel)
					break
				}
			}
		}
	}

	if globalState.isTrue("pwfeedback") {
		ctx.hasPwfeedback = true
		ctx.pwfeedbackEvidence = "global Defaults enables pwfeedback"
	} else {
		for _, key := range groupOrder {
			grp := scopedGroups[key]
			if grp.state.isTrue("pwfeedback") {
				ctx.hasPwfeedback = true
				ctx.pwfeedbackEvidence = fmt.Sprintf("scoped Defaults for [%s] enables pwfeedback", grp.scopeLabel)
				break
			}
		}
	}

	if globalState.strSet["runchroot"] && globalState.strVal["runchroot"] != "" {
		ctx.hasChroot = true
		ctx.chrootEvidence = fmt.Sprintf("global Defaults sets runchroot=%s", globalState.strVal["runchroot"])
	} else {
		for _, key := range groupOrder {
			grp := scopedGroups[key]
			if grp.state.strSet["runchroot"] && grp.state.strVal["runchroot"] != "" {
				ctx.hasChroot = true
				ctx.chrootEvidence = fmt.Sprintf("scoped Defaults for [%s] sets runchroot=%s", grp.scopeLabel, grp.state.strVal["runchroot"])
				break
			}
		}
	}

	// Inspect User_Specs for negated runas, sudoedit/ALL, per-command CHROOT=, and non-ALL host lists.
	for _, spec := range policy.UserSpecs {
		resolvedUsers := resolveMemberSlice(spec.UserList, policy, aliasKindUser)
		usersStr := hostAuditJoinMemberNames(resolvedUsers)

		if !ctx.hasNonALLHost {
			resolvedHosts := resolveMemberSlice(spec.HostList, policy, aliasKindHost)
			for _, h := range resolvedHosts {
				if n := h.rawName(); n != "" && (n != "ALL" || h.Negated) {
					ctx.hasNonALLHost = true
					ctx.nonALLHostEvidence = fmt.Sprintf("User_Spec for [%s] uses host restriction [%s]", usersStr, h.GetName())
					break
				}
			}
		}

		for _, cs := range spec.CmndSpecs {
			if !ctx.hasNegatedRunas {
				resolvedRunasUsers := resolveMemberSlice(cs.RunasUsers, policy, aliasKindRunas)
				for _, r := range resolvedRunasUsers {
					if r.Negated {
						ctx.hasNegatedRunas = true
						ctx.negatedRunasEvidence = fmt.Sprintf("rule for [%s] uses negated Runas user [%s]", usersStr, r.GetName())
						break
					}
				}
			}
			if !ctx.hasNegatedRunas {
				resolvedRunasGroups := resolveMemberSlice(cs.RunasGroups, policy, aliasKindRunas)
				for _, r := range resolvedRunasGroups {
					if r.Negated {
						ctx.hasNegatedRunas = true
						ctx.negatedRunasEvidence = fmt.Sprintf("rule for [%s] uses negated Runas group [%s]", usersStr, r.GetName())
						break
					}
				}
			}

			if !ctx.hasChroot {
				for _, opt := range cs.Options {
					if val, ok := opt["runchroot"].(string); ok && val != "" {
						ctx.hasChroot = true
						ctx.chrootEvidence = fmt.Sprintf("rule for [%s] specifies CHROOT=%s", usersStr, val)
						break
					}
				}
			}

			if !ctx.hasSudoeditOrALL {
				for _, m := range cs.Commands {
					for _, cmd := range resolveCommands(m, policy) {
						if cmd.Negated || cmd.Command == "" {
							continue
						}
						if hostAuditCommandAllowsSudoeditOrALL(cmd.Command) {
							ctx.hasSudoeditOrALL = true
							ctx.sudoeditEvidence = fmt.Sprintf("rule for [%s] permits '%s'", usersStr, cmd.Command)
							break
						}
					}
					if ctx.hasSudoeditOrALL {
						break
					}
				}
			}
		}
	}

	return ctx
}

func hostAuditCommandAllowsSudoeditOrALL(cmdStr string) bool {
	parts := splitCommandTokens(cmdStr)
	if len(parts) == 0 {
		return false
	}
	exe := parts[0]
	if exe == "ALL" || exe == "sudoedit" || path.Base(exe) == "sudoedit" {
		return true
	}
	if isRegexCommand(exe) {
		for _, cand := range extractRegexBinaries(exe) {
			if cand == "sudoedit" {
				return true
			}
		}
	}
	return false
}

// CorrelateCVEsWithPolicy annotates sudo version CVE findings with Exploitability
// ("ACTIVE" or "LATENT") and policy evidence based on concrete sudoers preconditions.
// Findings already marked "PATCHED_BACKPORT" and non-CVE findings are preserved untouched.
func CorrelateCVEsWithPolicy(cveFindings []Finding, policy *SudoersPolicy) []Finding {
	if cveFindings == nil {
		return nil
	}

	ctx := hostAuditAnalyzePolicyForCVEs(policy)
	correlated := make([]Finding, len(cveFindings))

	for i, f := range cveFindings {
		out := f
		if out.Exploitability == "PATCHED_BACKPORT" {
			correlated[i] = out
			continue
		}

		switch strings.ToUpper(strings.TrimSpace(out.ID)) {
		case "CVE-2019-18634":
			if ctx.hasPwfeedback {
				out.Exploitability = "ACTIVE"
				out.Description += fmt.Sprintf(" Policy correlation: ACTIVE (%s).", ctx.pwfeedbackEvidence)
			} else {
				out.Exploitability = "LATENT"
				out.Description += " Policy correlation: LATENT (Defaults pwfeedback is not enabled)."
			}
		case "CVE-2019-14287":
			if ctx.hasNegatedRunas {
				out.Exploitability = "ACTIVE"
				out.Description += fmt.Sprintf(" Policy correlation: ACTIVE (%s).", ctx.negatedRunasEvidence)
			} else {
				out.Exploitability = "LATENT"
				out.Description += " Policy correlation: LATENT (no negated Runas specifications detected)."
			}
		case "CVE-2023-22809":
			if ctx.hasSudoeditOrALL {
				out.Exploitability = "ACTIVE"
				out.Description += fmt.Sprintf(" Policy correlation: ACTIVE (%s).", ctx.sudoeditEvidence)
			} else {
				out.Exploitability = "LATENT"
				out.Description += " Policy correlation: LATENT (no sudoedit or ALL command permissions detected)."
			}
		case "CVE-2023-27320":
			if ctx.hasChroot {
				out.Exploitability = "ACTIVE"
				out.Description += fmt.Sprintf(" Policy correlation: ACTIVE (%s).", ctx.chrootEvidence)
			} else {
				out.Exploitability = "LATENT"
				out.Description += " Policy correlation: LATENT (no CHROOT= or Defaults runchroot directive detected)."
			}
		case "CVE-2025-32462":
			if ctx.hasNonALLHost {
				out.Exploitability = "ACTIVE"
				out.Description += fmt.Sprintf(" Policy correlation: ACTIVE (%s).", ctx.nonALLHostEvidence)
			} else {
				out.Exploitability = "LATENT"
				out.Description += " Policy correlation: LATENT (no non-ALL host restrictions detected in User_Specs or Defaults@)."
			}
		case "CVE-2021-3156", "CVE-2025-32463":
			out.Exploitability = "ACTIVE"
			out.Description += " Policy correlation: ACTIVE (no special sudoers rule required; exploitable whenever vulnerable sudo binary is present)."
		case "CVE-2022-43995":
			out.Exploitability = "LATENT"
			out.Description += " Policy correlation: LATENT (depends on non-PAM sudo build using crypt() password authentication)."
		}

		correlated[i] = out
	}

	return correlated
}
