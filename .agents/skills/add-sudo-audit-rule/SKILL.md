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
- **System CVE rules**: `SUDO-SYS-CVE-YYYY-NNNNN` in `pkg/audit/rules_system.go`
- Populate `Compliance` with applicable `ANSSI-BP-028` and `CIS` benchmark IDs.

## 2. Follow Evaluation Invariants
- **For `Defaults` checks (`pkg/audit/rules_defaults.go`)**:
  - Never scan `policy.Defaults` with an early-return first-match loop.
  - Add any newly tracked option to `defaultsState` and update `reduceGlobalDefaults`
    so `=`, `+=`, `-=`, and `!flag` follow `sudo`'s last-match-wins semantics.
  - Check both global defaults and scoped `Defaults` (`Defaults@host`, `Defaults:user`,
    `Defaults!cmnd`, `Defaults>runas`) in `auditScopedDefaults` when the option can be
    overridden per scope.
- **For Command checks (`pkg/audit/rules_commands.go`)**:
  - Operate on the alias-expanded users, hosts, runas targets, and commands.
  - Populate `User`, `Host`, `Runas`, `Command`, and `Line` on the emitted `Finding`.
- **For System permission checks (`pkg/audit/rules_system.go`)**:
  - Put permission/ownership evaluation logic inside a pure helper function taking
    `(path string, mode os.FileMode, uid, gid int, checkOwnership bool)` so unit tests
    on Windows can test all branches (`checkOwnership = true`) without Unix syscalls.

## 3. Register Parameterized Titles in SARIF
If the new rule's `Finding.Title` embeds a dynamic binary or option name (like
`SUDO-GTFO-001` or `SUDO-DEF-001`), add a generic canonical title entry to
`canonicalRuleTitles` in `pkg/report/sarif.go` so the SARIF `driver.rules` metadata
is not polluted by the first finding's instance title.

## 4. Verify
1. Add unit tests in `pkg/audit/auditor_test.go`.
2. If `pkg/parser` or `pkg/audit/types.go` was touched, run `go test -v ./pkg/parser/...`
   to verify `TestOracleComparisonWithCvtsudoers` still passes.
3. Run `go test "-coverprofile=coverage.out" ./...` and `go vet ./...`.
