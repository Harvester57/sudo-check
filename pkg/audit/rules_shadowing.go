package audit

import (
	"fmt"
	"net"
	"strings"
	"time"
)

const timeWindowNormalizedLayout = "20060102150405Z"

type shadowRuleEntry struct {
	specIdx     int
	cmndSpecIdx int
	usersStr    string
	hostsStr    string
	runasStr    string
	tagsStr     string
	rawLine     string
	users       []Member
	hosts       []Member
	runasUsers  []Member
	runasGroups []Member
	cmdStr      string
	negated     bool
	noPasswd    bool
	noExec      bool
	setEnv      bool
	file        string
	line        int
}

type shadowOverlapCandidate struct {
	prev      shadowRuleEntry
	weakening bool
	reason    string
}

// AuditShadowing detects overlapping, shadowed, or overridden sudoers rules across
// User_Specs in last-match-wins evaluation order (SUDO-CMD-015).
func AuditShadowing(policy *SudoersPolicy) []Finding {
	if policy == nil {
		return nil
	}

	var seen []shadowRuleEntry
	var findings []Finding

	for specIdx, spec := range policy.UserSpecs {
		resolvedUsers := resolveMemberSlice(spec.UserList, policy, aliasKindUser)
		if len(resolvedUsers) == 0 {
			continue
		}
		usersStr := shadowFormatMembers(resolvedUsers)

		resolvedHosts := resolveMemberSlice(spec.HostList, policy, aliasKindHost)
		if len(resolvedHosts) == 0 {
			continue
		}
		hostsStr := shadowFormatMembers(resolvedHosts)

		for csIdx, cs := range spec.CmndSpecs {
			resolvedRunasUsers := resolveMemberSlice(cs.RunasUsers, policy, aliasKindRunas)
			resolvedRunasGroups := resolveMemberSlice(cs.RunasGroups, policy, aliasKindRunas)
			runasStr, _ := formatRunas(resolvedRunasUsers, resolvedRunasGroups)

			effRunasUsers := resolvedRunasUsers
			if len(effRunasUsers) == 0 && len(resolvedRunasGroups) == 0 {
				effRunasUsers = []Member{{Username: "root"}}
			}

			var allCmdMembers []Member
			for _, cmdMember := range cs.Commands {
				allCmdMembers = append(allCmdMembers, resolveCommands(cmdMember, policy)...)
			}

			for _, cmdMember := range allCmdMembers {
				cmdStr := cmdMember.Command
				if cmdStr == "" {
					continue
				}

				file := spec.File
				if file == "" {
					file = cmdMember.File
				}
				line := spec.Line
				if line == 0 {
					line = cmdMember.Line
				}

				noPasswd, noExec := resolveEffectiveFlags(policy, resolvedUsers, resolvedHosts, resolvedRunasUsers, cmdStr, cs.Options)
				setEnv := shadowResolveSetEnv(policy, resolvedUsers, resolvedHosts, resolvedRunasUsers, cmdStr, cs.Options)

				curr := shadowRuleEntry{
					specIdx:     specIdx,
					cmndSpecIdx: csIdx,
					usersStr:    usersStr,
					hostsStr:    hostsStr,
					runasStr:    runasStr,
					tagsStr:     formatCmndSpecOptions(cs.Options),
					rawLine:     spec.RawLine,
					users:       resolvedUsers,
					hosts:       resolvedHosts,
					runasUsers:  effRunasUsers,
					runasGroups: resolvedRunasGroups,
					cmdStr:      cmdStr,
					negated:     cmdMember.Negated,
					noPasswd:    noPasswd,
					noExec:      noExec,
					setEnv:      setEnv,
					file:        file,
					line:        line,
				}

				var best *shadowOverlapCandidate
				for i := len(seen) - 1; i >= 0; i-- {
					prev := seen[i]
					if prev.specIdx == curr.specIdx && prev.cmndSpecIdx == curr.cmndSpecIdx {
						if curr.negated || prev.negated {
							continue
						}
					}
					if !shadowEntriesOverlap(prev, curr) {
						continue
					}
					weakening, reason := shadowEvaluateChange(prev, curr)
					if best == nil || (weakening && !best.weakening) {
						best = &shadowOverlapCandidate{
							prev:      prev,
							weakening: weakening,
							reason:    reason,
						}
						if weakening {
							break
						}
					}
				}

				if best != nil {
					findings = append(findings, shadowBuildFinding(best.prev, curr, best.weakening, best.reason))
				}

				seen = append(seen, curr)
			}
		}
	}

	return findings
}

func shadowBuildFinding(prev, curr shadowRuleEntry, weakening bool, reason string) Finding {
	sev := SeverityInfo
	if weakening {
		sev = SeverityMedium
	}

	prevLoc := shadowFormatLoc(prev.file, prev.line)
	currLoc := shadowFormatLoc(curr.file, curr.line)

	currDisplayCmd := curr.cmdStr
	if curr.negated {
		currDisplayCmd = "!" + curr.cmdStr
	}
	prevDisplayCmd := prev.cmdStr
	if prev.negated {
		prevDisplayCmd = "!" + prev.cmdStr
	}

	desc := fmt.Sprintf(
		"The rule at %s for user(s) [%s] on host(s) [%s] as [%s] granting '%s' shadows or overrides the earlier rule at %s ('%s'). Because sudoers evaluates matching rules using last-match-wins semantics, %s.",
		currLoc, curr.usersStr, curr.hostsStr, curr.runasStr, currDisplayCmd, prevLoc, prevDisplayCmd, reason,
	)

	remCmd := curr.cmdStr
	if remCmd == "ALL" || curr.negated {
		if !prev.negated && prev.cmdStr != "" && prev.cmdStr != "ALL" {
			remCmd = prev.cmdStr
		} else {
			remCmd = "/usr/local/sbin/allowed-cmd \"\""
		}
	}

	remCode := fmt.Sprintf(
		"# Consolidate overlapping rules (%s and %s) into a single explicit rule:\n%s %s = (%s) PASSWD: NOEXEC: NOSETENV: %s",
		prevLoc, currLoc, curr.usersStr, curr.hostsStr, curr.runasStr, remCmd,
	)

	return Finding{
		ID:              "SUDO-CMD-015",
		Title:           "Shadowed or Overridden Sudoers Rule",
		Description:     desc,
		Severity:        sev,
		User:            curr.usersStr,
		Host:            curr.hostsStr,
		Runas:           curr.runasStr,
		Tags:            curr.tagsStr,
		Command:         curr.cmdStr,
		SourceLine:      curr.rawLine,
		Context:         curr.file,
		Line:            curr.line,
		Remediation:     "Consolidate overlapping sudoers entries so each principal, host, runas target, and command has a single unambiguous rule without unintended last-match-wins overrides.",
		RemediationCode: remCode,
		Compliance:      []string{},
	}
}

func shadowFormatLoc(file string, line int) string {
	f := strings.TrimSpace(file)
	if f == "" {
		f = "sudoers"
	}
	return fmt.Sprintf("%s:%d", f, line)
}

func shadowFormatMembers(members []Member) string {
	var names []string
	for _, m := range members {
		if n := m.GetName(); n != "" {
			names = append(names, n)
		}
	}
	return strings.Join(names, ", ")
}

func shadowResolveSetEnv(policy *SudoersPolicy, users []Member, hosts []Member, runasUsers []Member, cmdStr string, csOptions []Option) bool {
	setEnv := false
	scopeOrder := []defaultsScope{scopeGlobal, scopeHost, scopeUser, scopeRunas, scopeCommand}
	for _, scope := range scopeOrder {
		for _, def := range policy.Defaults {
			if inferBindingScope(def.Binding) != scope {
				continue
			}
			if scope == scopeGlobal || bindingMatches(def.Binding, scope, policy, users, hosts, runasUsers, cmdStr) {
				for _, opt := range def.Options {
					if val, ok := opt["setenv"].(bool); ok {
						setEnv = val
					}
				}
			}
		}
	}

	explicit := false
	for _, opt := range csOptions {
		if val, ok := opt["setenv"].(bool); ok {
			setEnv = val
			explicit = true
		}
	}
	if cmdStr == "ALL" && !explicit {
		setEnv = true
	}
	return setEnv
}

func shadowEntriesOverlap(prev, curr shadowRuleEntry) bool {
	if !shadowMemberListsOverlap(prev.users, curr.users, shadowUserListMatchesMember) {
		return false
	}
	if !shadowMemberListsOverlap(prev.hosts, curr.hosts, shadowHostListMatchesMember) {
		return false
	}
	if !shadowRunasOverlap(prev, curr) {
		return false
	}
	return shadowCommandsOverlap(prev, curr)
}

func shadowRunasOverlap(prev, curr shadowRuleEntry) bool {
	prevHasUsers := len(prev.runasUsers) > 0
	currHasUsers := len(curr.runasUsers) > 0
	if prevHasUsers != currHasUsers {
		return false
	}
	if prevHasUsers && !shadowMemberListsOverlap(prev.runasUsers, curr.runasUsers, shadowUserListMatchesMember) {
		return false
	}

	prevHasGroups := len(prev.runasGroups) > 0
	currHasGroups := len(curr.runasGroups) > 0
	if !prevHasUsers && (prevHasGroups || currHasGroups) {
		return prevHasGroups && currHasGroups && shadowMemberListsOverlap(prev.runasGroups, curr.runasGroups, shadowUserListMatchesMember)
	}
	if prevHasGroups && currHasGroups {
		return shadowMemberListsOverlap(prev.runasGroups, curr.runasGroups, shadowUserListMatchesMember)
	}
	return true
}

func shadowMemberListsOverlap(listA, listB []Member, matchFn func(list []Member, candidate Member) bool) bool {
	if shadowHasActiveALL(listA) && shadowHasActiveALL(listB) {
		return true
	}

	for _, m := range listB {
		if m.Negated || m.rawName() == "ALL" {
			continue
		}
		if matchFn(listB, m) && matchFn(listA, m) {
			return true
		}
	}
	for _, m := range listA {
		if m.Negated || m.rawName() == "ALL" {
			continue
		}
		if matchFn(listA, m) && matchFn(listB, m) {
			return true
		}
	}
	return false
}

func shadowHasActiveALL(list []Member) bool {
	active := false
	for _, m := range list {
		if m.rawName() == "ALL" {
			active = !m.Negated
		}
	}
	return active
}

func shadowUserListMatchesMember(list []Member, candidate Member) bool {
	matched := false
	for _, m := range list {
		if shadowUserMemberMatches(m, candidate) {
			matched = !m.Negated
		}
	}
	return matched
}

func shadowUserMemberMatches(m, candidate Member) bool {
	if m.rawName() == "ALL" {
		return true
	}
	if m.Username != "" && candidate.Username != "" && m.Username == candidate.Username {
		return true
	}
	if m.UserID != nil && candidate.UserID != nil && *m.UserID == *candidate.UserID {
		return true
	}
	if m.Usergroup != "" && candidate.Usergroup != "" && strings.TrimPrefix(m.Usergroup, "%") == strings.TrimPrefix(candidate.Usergroup, "%") {
		return true
	}
	if m.UserGID != nil && candidate.UserGID != nil && *m.UserGID == *candidate.UserGID {
		return true
	}
	if m.NonUnixGroup != "" && candidate.NonUnixGroup != "" && m.NonUnixGroup == candidate.NonUnixGroup {
		return true
	}
	if m.NonUnixGID != nil && candidate.NonUnixGID != nil && *m.NonUnixGID == *candidate.NonUnixGID {
		return true
	}
	if m.Netgroup != "" && candidate.Netgroup != "" && m.Netgroup == candidate.Netgroup {
		return true
	}
	if m.Myself && candidate.Myself {
		return true
	}
	return false
}

func shadowHostListMatchesMember(list []Member, candidate Member) bool {
	matched := false
	for _, m := range list {
		if shadowHostMemberMatches(m, candidate) {
			matched = !m.Negated
		}
	}
	return matched
}

func shadowHostMemberMatches(m, candidate Member) bool {
	if m.rawName() == "ALL" {
		return true
	}
	if m.Hostname != "" && candidate.Hostname != "" {
		shortCand := shadowShortHost(candidate.Hostname)
		if explainHostnameMatches(m.Hostname, candidate.Hostname, shortCand) {
			return true
		}
	}
	if m.NetworkAddr != "" && candidate.NetworkAddr != "" {
		if shadowNetworkSpecMatches(m.NetworkAddr, candidate.NetworkAddr) {
			return true
		}
	}
	if m.Netgroup != "" && candidate.Netgroup != "" && m.Netgroup == candidate.Netgroup {
		return true
	}
	return false
}

func shadowShortHost(host string) string {
	h := strings.TrimSpace(host)
	if h == "" || net.ParseIP(h) != nil {
		return ""
	}
	if idx := strings.IndexByte(h, '.'); idx > 0 {
		return h[:idx]
	}
	return h
}

func shadowNetworkSpecMatches(patternSpec, targetSpec string) bool {
	exactTarget, targetNet, ok := explainParseNetwork(targetSpec)
	if !ok {
		return false
	}
	if exactTarget != nil {
		return explainMatchNetwork(patternSpec, []net.IP{exactTarget})
	}
	if targetNet != nil {
		return explainMatchNetwork(patternSpec, []net.IP{targetNet.IP})
	}
	return false
}

func shadowCommandsOverlap(prev, curr shadowRuleEntry) bool {
	if prev.negated || curr.negated {
		if prev.cmdStr == curr.cmdStr || prev.cmdStr == "ALL" || curr.cmdStr == "ALL" {
			return true
		}
		return false
	}

	if prev.cmdStr == curr.cmdStr {
		return true
	}
	if prev.cmdStr == "ALL" || curr.cmdStr == "ALL" {
		return true
	}

	prevParts := splitCommandTokens(prev.cmdStr)
	currParts := splitCommandTokens(curr.cmdStr)
	if len(prevParts) == 0 || len(currParts) == 0 {
		return false
	}

	prevExe := prevParts[0]
	currExe := currParts[0]

	if strings.HasPrefix(prevExe, "/") && strings.HasSuffix(prevExe, "/") && strings.HasPrefix(currExe, prevExe) {
		return true
	}
	if strings.HasPrefix(currExe, "/") && strings.HasSuffix(currExe, "/") && strings.HasPrefix(prevExe, currExe) {
		return true
	}

	if prevExe != currExe {
		return false
	}

	if len(prevParts) == 1 || len(currParts) == 1 {
		return true
	}

	prevArgs := strings.Join(prevParts[1:], " ")
	currArgs := strings.Join(currParts[1:], " ")
	if wildcardRegex.MatchString(prevArgs) && shadowWildcardMatch(prevArgs, currArgs) {
		return true
	}
	if wildcardRegex.MatchString(currArgs) && shadowWildcardMatch(currArgs, prevArgs) {
		return true
	}

	return false
}

func shadowWildcardMatch(pattern, target string) bool {
	pi, ti := 0, 0
	starIdx, matchIdx := -1, 0

	for ti < len(target) {
		if pi < len(pattern) && (pattern[pi] == '?' || pattern[pi] == target[ti]) {
			pi++
			ti++
		} else if pi < len(pattern) && pattern[pi] == '*' {
			starIdx = pi
			matchIdx = ti
			pi++
		} else if starIdx != -1 {
			pi = starIdx + 1
			matchIdx++
			ti = matchIdx
		} else {
			return false
		}
	}

	for pi < len(pattern) && pattern[pi] == '*' {
		pi++
	}
	return pi == len(pattern)
}

func shadowEvaluateChange(prev, curr shadowRuleEntry) (bool, string) {
	if !prev.negated && curr.negated {
		return false, "the later negated entry overrides or narrows the earlier rule"
	}

	var weakens []string
	if prev.negated && !curr.negated {
		weakens = append(weakens, "negated rule overridden by later allow (!cmd -> allow)")
	}
	if !prev.noPasswd && curr.noPasswd {
		weakens = append(weakens, "PASSWD -> NOPASSWD")
	}
	if prev.noExec && !curr.noExec {
		weakens = append(weakens, "NOEXEC -> EXEC")
	}
	if !prev.setEnv && curr.setEnv {
		weakens = append(weakens, "!SETENV -> SETENV")
	}
	if prev.cmdStr != "ALL" && !curr.negated && curr.cmdStr == "ALL" {
		weakens = append(weakens, "restricted command -> ALL")
	}
	if !shadowHasActiveALL(prev.runasUsers) && shadowHasActiveALL(curr.runasUsers) {
		weakens = append(weakens, "restricted runas -> ALL")
	}

	prevParts := splitCommandTokens(prev.cmdStr)
	currParts := splitCommandTokens(curr.cmdStr)
	if len(prevParts) > 0 && len(currParts) > 0 && prev.cmdStr != "ALL" && curr.cmdStr != "ALL" {
		if strings.HasSuffix(currParts[0], "/") && !strings.HasSuffix(prevParts[0], "/") {
			weakens = append(weakens, "specific binary -> directory execution")
		} else if prevParts[0] == currParts[0] {
			if len(prevParts) > 1 && len(currParts) == 1 {
				weakens = append(weakens, "restricted arguments -> unrestricted arguments")
			} else if len(prevParts) > 1 && len(currParts) > 1 {
				prevArgs := strings.Join(prevParts[1:], " ")
				currArgs := strings.Join(currParts[1:], " ")
				if !wildcardRegex.MatchString(prevArgs) && wildcardRegex.MatchString(currArgs) {
					weakens = append(weakens, "literal arguments -> wildcard arguments")
				}
			}
		}
	}

	if len(weakens) > 0 {
		return true, fmt.Sprintf("the later rule weakens security controls (%s)", strings.Join(weakens, "; "))
	}

	if prev.noPasswd == curr.noPasswd && prev.noExec == curr.noExec && prev.setEnv == curr.setEnv && prev.cmdStr == curr.cmdStr {
		return false, "the later rule duplicates the earlier authorization without changing effective controls"
	}
	return false, "the later rule overrides or tightens the earlier authorization without weakening security controls"
}

// AuditTimeWindows checks CmndSpec.Options across User_Specs for inverted
// (NOTBEFORE > NOTAFTER) or expired (NOTAFTER < now) validity timestamps (SUDO-CMD-016).
func AuditTimeWindows(policy *SudoersPolicy, now time.Time) []Finding {
	if policy == nil {
		return nil
	}

	var findings []Finding
	nowUTC := now.UTC()

	for _, spec := range policy.UserSpecs {
		resolvedUsers := resolveMemberSlice(spec.UserList, policy, aliasKindUser)
		usersStr := shadowFormatMembers(resolvedUsers)

		resolvedHosts := resolveMemberSlice(spec.HostList, policy, aliasKindHost)
		hostsStr := shadowFormatMembers(resolvedHosts)

		for _, cs := range spec.CmndSpecs {
			nbStr := timeWindowOptionValue(cs.Options, "notbefore")
			naStr := timeWindowOptionValue(cs.Options, "notafter")
			if nbStr == "" && naStr == "" {
				continue
			}

			var nbTime, naTime time.Time
			hasNB := false
			hasNA := false

			if nbStr != "" {
				if t, err := time.Parse(timeWindowNormalizedLayout, strings.TrimSpace(nbStr)); err == nil {
					nbTime = t.UTC()
					hasNB = true
				}
			}
			if naStr != "" {
				if t, err := time.Parse(timeWindowNormalizedLayout, strings.TrimSpace(naStr)); err == nil {
					naTime = t.UTC()
					hasNA = true
				}
			}

			if !hasNB && !hasNA {
				continue
			}

			resolvedRunasUsers := resolveMemberSlice(cs.RunasUsers, policy, aliasKindRunas)
			resolvedRunasGroups := resolveMemberSlice(cs.RunasGroups, policy, aliasKindRunas)
			runasStr, _ := formatRunas(resolvedRunasUsers, resolvedRunasGroups)

			var allCmdMembers []Member
			for _, cmdMember := range cs.Commands {
				allCmdMembers = append(allCmdMembers, resolveCommands(cmdMember, policy)...)
			}
			cmdStr := shadowFormatMembers(allCmdMembers)

			file := spec.File
			line := spec.Line
			if len(allCmdMembers) > 0 {
				if file == "" {
					file = allCmdMembers[0].File
				}
				if line == 0 {
					line = allCmdMembers[0].Line
				}
			}
			loc := shadowFormatLoc(file, line)

			cmdExample := cmdStr
			if cmdExample == "" {
				cmdExample = `/usr/local/sbin/allowed-cmd ""`
			}

			if hasNB && hasNA && nbTime.After(naTime) {
				fixedNA := nbTime.Add(30 * 24 * time.Hour).Format(timeWindowNormalizedLayout)
				findings = append(findings, Finding{
					ID:          "SUDO-CMD-016",
					Title:       "Inverted Sudoers Validity Window (NOTBEFORE > NOTAFTER)",
					Description: fmt.Sprintf("The command specification at %s for user(s) [%s] on host(s) [%s] as [%s] defines NOTBEFORE=%s after NOTAFTER=%s, creating an inverted validity window that can never be satisfied.", loc, usersStr, hostsStr, runasStr, nbStr, naStr),
					Severity:    SeverityLow,
					User:        usersStr,
					Host:        hostsStr,
					Runas:       runasStr,
					Tags:        formatCmndSpecOptions(cs.Options),
					Command:     cmdStr,
					SourceLine:  spec.RawLine,
					Context:     file,
					Line:        line,
					Remediation: "Ensure NOTBEFORE precedes NOTAFTER in UTC GeneralizedTime format (YYYYMMDDHHMMSSZ), or remove the obsolete rule.",
					RemediationCode: fmt.Sprintf(
						"# Ensure NOTBEFORE <= NOTAFTER (UTC GeneralizedTime) or remove the rule:\n%s %s = (%s) NOTBEFORE=%s NOTAFTER=%s %s",
						usersStr, hostsStr, runasStr, nbStr, fixedNA, cmdExample,
					),
					Compliance: []string{},
				})
			}

			if hasNA && naTime.Before(nowUTC) {
				renewNA := nowUTC.Add(30 * 24 * time.Hour).Format(timeWindowNormalizedLayout)
				findings = append(findings, Finding{
					ID:          "SUDO-CMD-016",
					Title:       "Expired Temporary Sudoers Rule (NOTAFTER)",
					Description: fmt.Sprintf("The temporary command specification at %s for user(s) [%s] on host(s) [%s] as [%s] expired at NOTAFTER=%s (prior to evaluation time %s) and remains stale in the policy.", loc, usersStr, hostsStr, runasStr, naStr, nowUTC.Format(timeWindowNormalizedLayout)),
					Severity:    SeverityInfo,
					User:        usersStr,
					Host:        hostsStr,
					Runas:       runasStr,
					Tags:        formatCmndSpecOptions(cs.Options),
					Command:     cmdStr,
					SourceLine:  spec.RawLine,
					Context:     file,
					Line:        line,
					Remediation: "Remove the expired temporary sudoers rule, or extend NOTAFTER to an approved future timestamp if access is still required.",
					RemediationCode: fmt.Sprintf(
						"# Remove the expired rule at %s, or renew NOTAFTER if access is still approved:\n%s %s = (%s) NOTAFTER=%s %s",
						loc, usersStr, hostsStr, runasStr, renewNA, cmdExample,
					),
					Compliance: []string{},
				})
			}
		}
	}

	return findings
}

func timeWindowOptionValue(options []Option, key string) string {
	val := ""
	for _, opt := range options {
		if s, ok := opt[key].(string); ok {
			val = s
		}
	}
	return val
}
