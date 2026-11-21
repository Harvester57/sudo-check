package audit

import (
	"net"
	"path"
	"strings"
	"sudo-check/pkg/gtfobins"
)

// PrincipalQuery describes a user, their Unix group/ID memberships, and target host
// context for simulating effective sudoers privileges.
type PrincipalQuery struct {
	Username string
	UID      *int
	Groups   []string // Unix group names (without leading '%')
	GIDs     []int
	Host     string   // Short or FQDN hostname
	HostIPs  []string // Optional IPv4/IPv6 addresses for CIDR matching
}

// EffectiveCommand describes a command permission granted to a queried principal
// along with its resolved execution flags and GTFObins escalation analysis.
type EffectiveCommand struct {
	Command        string                `json:"command"`
	Runas          string                `json:"runas"`
	NoPasswd       bool                  `json:"no_passwd"`
	NoExec         bool                  `json:"no_exec"`
	SetEnv         bool                  `json:"set_env"`
	SourceFile     string                `json:"source_file,omitempty"`
	Line           int                   `json:"line,omitempty"`
	GTFOBinsRisk   []gtfobins.SudoBypass `json:"gtfobins_risk,omitempty"`
	EscalationPath bool                  `json:"escalation_path"`
}

// ExplainResult summarizes the effective Defaults, allowed/denied commands, and
// highest privilege risk calculated for a PrincipalQuery against a SudoersPolicy.
type ExplainResult struct {
	Query             PrincipalQuery     `json:"query"`
	EffectiveDefaults map[string]any     `json:"effective_defaults"`
	AllowedCommands   []EffectiveCommand `json:"allowed_commands"`
	DeniedCommands    []string           `json:"denied_commands,omitempty"`
	HighestRisk       Severity           `json:"highest_risk"`
}

type explainPrincipalContext struct {
	query        PrincipalQuery
	groupSet     map[string]bool
	gidSet       map[int]bool
	shortHost    string
	candidateIPs []net.IP
}

type explainDeniedEntry struct {
	command string
	runas   string
}

// ExplainPolicy simulates sudoers(5) policy evaluation for the given principal query,
// resolving aliases, last-match-wins User/Host/Command semantics, effective Defaults
// precedence, GTFObins risks, and NOEXEC mitigations.
func ExplainPolicy(policy *SudoersPolicy, gtfoClient *gtfobins.Client, q PrincipalQuery) *ExplainResult {
	if policy == nil {
		return &ExplainResult{
			Query:             q,
			EffectiveDefaults: map[string]any{},
			AllowedCommands:   []EffectiveCommand{},
			HighestRisk:       SeverityInfo,
		}
	}

	ctx := explainNewPrincipalContext(q)
	baseDefaults := explainEffectiveDefaultsState(policy, ctx)

	allowed := make([]EffectiveCommand, 0)
	var denied []explainDeniedEntry

	for _, spec := range policy.UserSpecs {
		expandedUsers := resolveMemberSlice(spec.UserList, policy, aliasKindUser)
		if !explainMatchUserList(expandedUsers, ctx) {
			continue
		}

		expandedHosts := resolveMemberSlice(spec.HostList, policy, aliasKindHost)
		if !explainMatchHostList(expandedHosts, ctx) {
			continue
		}

		for _, cs := range spec.CmndSpecs {
			resolvedRunasUsers := resolveMemberSlice(cs.RunasUsers, policy, aliasKindRunas)
			resolvedRunasGroups := resolveMemberSlice(cs.RunasGroups, policy, aliasKindRunas)
			runasStr, _ := formatRunas(resolvedRunasUsers, resolvedRunasGroups)

			var allCmdMembers []Member
			for _, cmdMember := range cs.Commands {
				allCmdMembers = append(allCmdMembers, resolveCommands(cmdMember, policy)...)
			}

			for _, cmdMember := range allCmdMembers {
				cmdStr := cmdMember.Command
				if cmdStr == "" {
					continue
				}

				if cmdMember.Negated {
					allowed = explainRemoveAllowed(allowed, cmdStr, runasStr)
					denied = explainAddDenied(denied, cmdStr, runasStr)
					continue
				}

				denied = explainRemoveDenied(denied, cmdStr, runasStr)
				allowed = explainRemoveExactAllowed(allowed, cmdStr, runasStr)

				line := cmdMember.Line
				if line == 0 {
					line = spec.Line
				}
				file := cmdMember.File
				if file == "" {
					file = spec.File
				}

				noPasswd, noExec, setEnv := explainResolveCommandFlags(policy, baseDefaults, resolvedRunasUsers, cmdStr, cs.Options)
				risks, escalationPath := explainAnalyzeCommandGTFO(cmdStr, noExec, gtfoClient)

				allowed = append(allowed, EffectiveCommand{
					Command:        cmdStr,
					Runas:          runasStr,
					NoPasswd:       noPasswd,
					NoExec:         noExec,
					SetEnv:         setEnv,
					SourceFile:     file,
					Line:           line,
					GTFOBinsRisk:   risks,
					EscalationPath: escalationPath,
				})
			}
		}
	}

	var deniedCmds []string
	seenDenied := make(map[string]bool)
	for _, d := range denied {
		if !seenDenied[d.command] {
			seenDenied[d.command] = true
			deniedCmds = append(deniedCmds, d.command)
		}
	}

	highestRisk := SeverityInfo
	for _, ec := range allowed {
		cmdRisk := SeverityLow
		if ec.EscalationPath || ec.Command == "ALL" {
			if ec.NoPasswd {
				cmdRisk = SeverityCritical
			} else {
				cmdRisk = SeverityHigh
			}
		}
		if cmdRisk.Order() < highestRisk.Order() {
			highestRisk = cmdRisk
		}
	}

	return &ExplainResult{
		Query:             q,
		EffectiveDefaults: explainDefaultsStateToMap(baseDefaults),
		AllowedCommands:   allowed,
		DeniedCommands:    deniedCmds,
		HighestRisk:       highestRisk,
	}
}

func explainNewPrincipalContext(q PrincipalQuery) explainPrincipalContext {
	groupSet := make(map[string]bool, len(q.Groups))
	for _, g := range q.Groups {
		cleaned := strings.TrimPrefix(strings.TrimSpace(g), "%")
		if cleaned != "" {
			groupSet[cleaned] = true
		}
	}

	gidSet := make(map[int]bool, len(q.GIDs))
	for _, gid := range q.GIDs {
		gidSet[gid] = true
	}

	host := strings.TrimSpace(q.Host)
	shortHost := ""
	var candidateIPs []net.IP

	if host != "" {
		if ip := net.ParseIP(host); ip != nil {
			candidateIPs = append(candidateIPs, ip)
		} else if dotIdx := strings.IndexByte(host, '.'); dotIdx > 0 {
			shortHost = host[:dotIdx]
		} else {
			shortHost = host
		}
	}

	for _, rawIP := range q.HostIPs {
		if ip := net.ParseIP(strings.TrimSpace(rawIP)); ip != nil {
			candidateIPs = append(candidateIPs, ip)
		}
	}

	return explainPrincipalContext{
		query:        q,
		groupSet:     groupSet,
		gidSet:       gidSet,
		shortHost:    shortHost,
		candidateIPs: candidateIPs,
	}
}

func explainMatchUserList(expanded []Member, ctx explainPrincipalContext) bool {
	matched := false
	for _, m := range expanded {
		if explainUserMemberMatches(m, ctx) {
			matched = !m.Negated
		}
	}
	return matched
}

func explainUserMemberMatches(m Member, ctx explainPrincipalContext) bool {
	if m.Username == "ALL" || m.rawName() == "ALL" {
		return true
	}
	if m.Username != "" {
		return ctx.query.Username != "" && m.Username == ctx.query.Username
	}
	if m.UserID != nil {
		return ctx.query.UID != nil && *m.UserID == *ctx.query.UID
	}
	if m.Usergroup != "" {
		grp := strings.TrimPrefix(m.Usergroup, "%")
		return grp != "" && ctx.groupSet[grp]
	}
	if m.UserGID != nil {
		return ctx.gidSet[*m.UserGID]
	}
	return false
}

func explainMatchHostList(expanded []Member, ctx explainPrincipalContext) bool {
	matched := false
	for _, m := range expanded {
		if explainHostMemberMatches(m, ctx) {
			matched = !m.Negated
		}
	}
	return matched
}

func explainHostMemberMatches(m Member, ctx explainPrincipalContext) bool {
	if m.Hostname == "ALL" || m.rawName() == "ALL" {
		return true
	}
	if m.Hostname != "" {
		return explainHostnameMatches(m.Hostname, ctx.query.Host, ctx.shortHost)
	}
	if m.NetworkAddr != "" {
		return explainMatchNetwork(m.NetworkAddr, ctx.candidateIPs)
	}
	return false
}

func explainHostnameMatches(pattern, host, shortHost string) bool {
	h := strings.ToLower(strings.TrimSpace(host))
	if h == "" {
		return false
	}
	p := strings.ToLower(strings.TrimSpace(pattern))
	if p == "" {
		return false
	}
	s := strings.ToLower(strings.TrimSpace(shortHost))

	if p == h {
		return true
	}
	if s != "" && p == s {
		return true
	}
	if strings.ContainsAny(p, "*?[") {
		if ok, err := path.Match(p, h); err == nil && ok {
			return true
		}
		if s != "" {
			if ok, err := path.Match(p, s); err == nil && ok {
				return true
			}
		}
	}
	return false
}

func explainParseNetwork(spec string) (net.IP, *net.IPNet, bool) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, nil, false
	}
	if exact := net.ParseIP(spec); exact != nil {
		return exact, nil, true
	}
	if _, ipNet, err := net.ParseCIDR(spec); err == nil {
		return nil, ipNet, true
	}
	if slashIdx := strings.IndexByte(spec, '/'); slashIdx != -1 {
		baseIP := net.ParseIP(strings.TrimSpace(spec[:slashIdx]))
		maskIP := net.ParseIP(strings.TrimSpace(spec[slashIdx+1:]))
		if baseIP != nil && maskIP != nil {
			if b4, m4 := baseIP.To4(), maskIP.To4(); b4 != nil && m4 != nil {
				mask := net.IPMask(m4)
				return nil, &net.IPNet{IP: b4.Mask(mask), Mask: mask}, true
			}
			if baseIP.To4() == nil && maskIP.To4() == nil {
				b16, m16 := baseIP.To16(), maskIP.To16()
				mask := net.IPMask(m16)
				return nil, &net.IPNet{IP: b16.Mask(mask), Mask: mask}, true
			}
		}
	}
	return nil, nil, false
}

func explainMatchNetwork(spec string, ips []net.IP) bool {
	if len(ips) == 0 {
		return false
	}
	exact, ipNet, ok := explainParseNetwork(spec)
	if !ok {
		return false
	}
	for _, ip := range ips {
		if exact != nil && exact.Equal(ip) {
			return true
		}
		if ipNet != nil && ipNet.Contains(ip) {
			return true
		}
	}
	return false
}

func explainEffectiveDefaultsState(policy *SudoersPolicy, ctx explainPrincipalContext) *defaultsState {
	state := newDefaultsState()
	scopeOrder := []defaultsScope{scopeGlobal, scopeHost, scopeUser}
	for _, scope := range scopeOrder {
		for _, def := range policy.Defaults {
			if inferBindingScope(def.Binding) != scope {
				continue
			}
			switch scope {
			case scopeGlobal:
				state.applyOptionsFrom(def.Options, def.File, def.Line, def.RawLine)
			case scopeHost:
				expanded := resolveMemberSlice(def.Binding, policy, aliasKindHost)
				if explainMatchHostList(expanded, ctx) {
					state.applyOptionsFrom(def.Options, def.File, def.Line, def.RawLine)
				}
			case scopeUser:
				expanded := resolveMemberSlice(def.Binding, policy, aliasKindUser)
				if explainMatchUserList(expanded, ctx) {
					state.applyOptionsFrom(def.Options, def.File, def.Line, def.RawLine)
				}
			}
		}
	}
	return state
}

func explainDefaultsStateToMap(state *defaultsState) map[string]any {
	out := make(map[string]any)
	for k, set := range state.boolSet {
		if set {
			out[k] = state.boolVal[k]
		}
	}
	for k, set := range state.strSet {
		if set && !state.disabledOpt[k] {
			out[k] = state.strVal[k]
		}
	}
	for k, set := range state.numSet {
		if set && !state.disabledOpt[k] {
			out[k] = state.numVal[k]
		}
	}
	for k, list := range state.lists {
		if !state.disabledOpt[k] {
			cp := make([]string, len(list))
			copy(cp, list)
			out[k] = cp
		}
	}
	return out
}

func explainResolveCommandFlags(policy *SudoersPolicy, baseState *defaultsState, resolvedRunasUsers []Member, cmdStr string, csOptions []Option) (noPasswd bool, noExec bool, setEnv bool) {
	noPasswd = baseState.isFalse("authenticate")
	noExec = baseState.isTrue("noexec")
	setEnv = baseState.isTrue("setenv")

	for _, scope := range []defaultsScope{scopeRunas, scopeCommand} {
		for _, def := range policy.Defaults {
			if inferBindingScope(def.Binding) != scope {
				continue
			}
			if bindingMatches(def.Binding, scope, policy, nil, nil, resolvedRunasUsers, cmdStr) {
				for _, opt := range def.Options {
					if val, ok := opt["authenticate"].(bool); ok {
						noPasswd = !val
					}
					if val, ok := opt["noexec"].(bool); ok {
						noExec = val
					}
					if val, ok := opt["setenv"].(bool); ok {
						setEnv = val
					}
				}
			}
		}
	}

	explicitSetEnv := false
	for _, opt := range csOptions {
		if val, ok := opt["authenticate"].(bool); ok {
			noPasswd = !val
		}
		if val, ok := opt["noexec"].(bool); ok {
			noExec = val
		}
		if val, ok := opt["setenv"].(bool); ok {
			setEnv = val
			explicitSetEnv = true
		}
	}

	if cmdStr == "ALL" && !explicitSetEnv {
		setEnv = true
	}

	return noPasswd, noExec, setEnv
}

func explainAnalyzeCommandGTFO(cmdStr string, noExec bool, gtfoClient *gtfobins.Client) ([]gtfobins.SudoBypass, bool) {
	if cmdStr == "ALL" {
		return nil, true
	}
	parts := splitCommandTokens(cmdStr)
	if len(parts) == 0 {
		return nil, false
	}
	exePath := parts[0]
	if strings.HasSuffix(exePath, "/") {
		return nil, true
	}
	if exePath == "sudoedit" || gtfoClient == nil {
		return nil, false
	}

	var candidateBinaries []string
	if isRegexCommand(exePath) {
		candidateBinaries = extractRegexBinaries(exePath)
	} else {
		candidateBinaries = []string{path.Base(exePath)}
	}

	var allBypasses []gtfobins.SudoBypass
	unmitigated := false
	for _, candBin := range candidateBinaries {
		normalized := gtfobins.NormalizeBinaryName(candBin)
		if len(normalized) == 0 {
			continue
		}
		bypasses := consolidateBypassesByFunction(gtfoClient.CheckBinary(candBin))
		for _, b := range bypasses {
			mitigated := noExec && (b.Function == "shell" || b.Function == "command") && !isNoexecImmune(candBin)
			if !mitigated {
				unmitigated = true
			}
		}
		allBypasses = append(allBypasses, bypasses...)
	}

	return consolidateBypassesByFunction(allBypasses), unmitigated
}

func explainRemoveAllowed(allowed []EffectiveCommand, cmdStr, runasStr string) []EffectiveCommand {
	out := allowed[:0]
	for _, ec := range allowed {
		runasMatch := runasStr == "ALL" || ec.Runas == runasStr
		cmdMatch := cmdStr == "ALL" || ec.Command == cmdStr
		if runasMatch && cmdMatch {
			continue
		}
		out = append(out, ec)
	}
	return out
}

func explainRemoveExactAllowed(allowed []EffectiveCommand, cmdStr, runasStr string) []EffectiveCommand {
	out := allowed[:0]
	for _, ec := range allowed {
		if ec.Command == cmdStr && ec.Runas == runasStr {
			continue
		}
		out = append(out, ec)
	}
	return out
}

func explainAddDenied(denied []explainDeniedEntry, cmdStr, runasStr string) []explainDeniedEntry {
	for _, d := range denied {
		if d.command == cmdStr && d.runas == runasStr {
			return denied
		}
	}
	return append(denied, explainDeniedEntry{command: cmdStr, runas: runasStr})
}

func explainRemoveDenied(denied []explainDeniedEntry, cmdStr, runasStr string) []explainDeniedEntry {
	out := denied[:0]
	for _, d := range denied {
		runasMatch := runasStr == "ALL" || d.runas == runasStr
		cmdMatch := cmdStr == "ALL" || d.command == cmdStr
		if runasMatch && cmdMatch {
			continue
		}
		out = append(out, d)
	}
	return out
}
