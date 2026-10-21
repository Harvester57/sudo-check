---
name: add-sudo-audit-rule
description: >-
  Step-by-step runbook for adding a new sudoers policy audit rule (SUDO-DEF-*,
  SUDO-CMD-*, SUDO-GTFO-*) or system/permission check (SUDO-SYS-*) to sudo-check.
  Use whenever adding, modifying, or extending audit detections in pkg/audit.
---

# Adding a Sudo Audit Rule

Follow these steps to add a new audit check to `sudo-check` without breaking
evaluation semantics, SARIF rule descriptors, or cross-platform tests.

## 1. Assign Rule ID & Metadata
- **Defaults rules**: `SUDO-DEF-XXX` in `pkg/audit/rules_defaults.go`
- **Command rules**: `SUDO-CMD-XXX` in `pkg/audit/rules_commands.go`
- **GTFObins rules**: `SUDO-GTFO-XXX` in `pkg/audit/rules_commands.go`
- **System permission rules**: `SUDO-SYS-PERM-XXX` in `pkg/audit/rules_system.go`
- **System CVE rules**: `CVE-YYYY-NNNNN` in `pkg/audit/rules_system.go`
- Populate `Compliance` with applicable `ANSSI-BP-028` and `CIS` benchmark IDs.
  When citing ANSSI BP-028, verify the exact recommendation number against the
  official v2.0 English guide checked in at `docs/reference/linux_configuration-en-v2.pdf`
  (sudo recommendations R38–R44 live in section 6.3.1 "Unix traditional model";
  v1.2 R57–R64 map to v2.0 R38–R44 per Appendix C.3). Only cite a recommendation
  the guide actually states: R38 dedicated sudo group, R39 Defaults guidelines
  (`noexec`, `requiretty`, `use_pty`, `umask=0077`, `ignore_dot`, `env_reset`),
  R40 non-root Runas targets, R41 limiting EXEC-requiring commands, R42 no negations,
  R43 strict argument specifications (no `*` wildcards, `""` for zero arguments),
  R44 editing via sudoedit. Do not attribute checks the guide does not mention
  (e.g. secure_path, digest pinning, sudoedit_follow, timeouts) to ANSSI.
- Always populate `RemediationCode` (`json:"remediation_code,omitempty"`) with a concrete, copy-pasteable `sudoers` configuration snippet or shell command(s) tailored to the finding's context (`User`, `Host`, `Runas`, `Command`, `Context`, or scoped `Defaults` binding). Keep prose explanations in `Remediation`, remediation commands/config in `RemediationCode`, and verification/exploit commands in `ExploitPoC`.

## 2. Follow Evaluation Invariants
- **For `Defaults` checks (`pkg/audit/rules_defaults.go`)**:
  - Never scan `policy.Defaults` with an early-return first-match loop.
  - Add any newly tracked option to `defaultsState` and update `applyOptionsFrom`
    so `=`, `+=`, `-=`, and `!flag` follow `sudo`'s last-match-wins semantics.
  - Check both global defaults and scoped `Defaults` (`Defaults@host`, `Defaults:user`,
    `Defaults!cmnd`, `Defaults>runas`) when the option can be overridden per scope, and
    use `formatScopedDefaultsDirective(def.Binding, scopeLabel)` when constructing
    `RemediationCode` for scoped findings.
- **For Command checks (`pkg/audit/rules_commands.go`)**:
  - Operate on the alias-expanded users, hosts, runas targets, and commands.
  - Populate `User`, `Host`, `Runas`, `Command`, `Context`, `Line`, and `RemediationCode`
    on the emitted `Finding`.
  - Ensure `RemediationCode` is computed deterministically from normalized policy fields
    so `TestOracleComparisonWithCvtsudoers` and `TestRealWorldCorpusDifferentialAndStress`
    (`reflect.DeepEqual` between `cvtsudoers` JSON and native parser output) continue to match.
- **For System permission checks (`pkg/audit/rules_system.go`)**:
  - Put permission/ownership evaluation logic inside a pure helper function taking
    `(path string, mode os.FileMode, uid, gid int, checkOwnership bool)` so unit tests
    on Windows can test all branches (`checkOwnership = true`) without Unix syscalls.
  - Populate `RemediationCode` with exact `chown`/`chmod` and `visudo -c -f` verification
    commands referencing the target path.

## 3. Register Parameterized Titles in SARIF
If the new rule's `Finding.Title` embeds a dynamic binary or option name (like
`SUDO-GTFO-001` or `SUDO-DEF-001`), add a generic canonical title entry to
`canonicalRuleTitles` in `pkg/report/sarif.go` so the SARIF `driver.rules` metadata
is not polluted by the first finding's instance title.

## 4. Verify
1. Add unit tests in `pkg/audit/auditor_test.go` (note that `TestRunAudit_VulnerablePolicy` asserts every finding has a non-empty `RemediationCode`).
2. If `pkg/parser` or `pkg/audit/types.go` was touched, run `go test -v ./pkg/parser/...`
   to verify `TestOracleComparisonWithCvtsudoers` and `TestRealWorldCorpusDifferentialAndStress` still pass.
3. Run `go test "-coverprofile=coverage.out" ./...` and `go vet ./...`.
