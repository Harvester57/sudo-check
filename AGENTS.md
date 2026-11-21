# Developer & Agent Instructions: sudo-check

Welcome! This repository contains `sudo-check`, a security audit utility for sudoers configuration policies and target hosts written in Go. Below are the key architecture details, rules, and guidelines to help you navigate and modify this codebase safely.

---

## 1. Project Overview & Architecture

`sudo-check` is designed to be a standalone, self-contained binary. It checks raw `sudoers` configuration files (via [pkg/parser/](./pkg/parser/parser.go)), `cvtsudoers` JSON policies, `sudo -ll` output, or RFC 2849 LDIF exports for security weaknesses, dangerous defaults, shadowing, wrapper script issues, and GTFObins bypasses.

### Package Structure
- **`cmd/`**: Cobra command specifications.
  - [root.go](./cmd/root.go): Common persistent flags (`--output-dir`, `--formats`, `--fail-on`, `--no-color`, `--gtfobins-path`, `--custom-gtfobins`, `--cvtsudoers-path`, `--config`, `--profile`, `--baseline`, `--subcommand-aware`) and config/baseline application helpers.
  - [scan.go](./cmd/scan.go): Command to parse and scan raw `sudoers` files, `sudoers.d` directories, `cvtsudoers` JSON policies, `sudo -ll` output, LDIF exports, or stdin (`-`), supporting `--dropin`, `--check-shadowing`, `--check-expiry`, and `--fix-patch`.
  - [system.go](./cmd/system.go): Command to run autonomously on a live host (using `pkg/parser` by default with `cvtsudoers` fallback, or an explicit `--cvtsudoers-path`) and checking local `sudo` versions, backport changelogs, policy CVE correlation, file/binary/group permissions, passwd/group identities, and wrapper scripts.
  - [explain.go](./cmd/explain.go): Command to simulate `sudoers(5)` policy evaluation for a target principal (`--user`, `--uid`, `--groups`, `--host`, `--ip`).
  - [diff.go](./cmd/diff.go): Command to compare two sudoers policies or JSON `AuditResult` reports by finding fingerprint.
  - [merge.go](./cmd/merge.go): Command to aggregate multiple host JSON `AuditResult` reports into fleet HTML, CSV, and JSON summaries.
  - [update_db.go](./cmd/update_db.go): Helper command to download fresh GTFObins catalog dumps.
  - [version.go](./cmd/version.go): Command to print the build version, commit, and date injected via ldflags.
- **`pkg/parser/`**:
  - [parser.go](./pkg/parser/parser.go): Native Go `sudoers` parser supporting `#include`/`#includedir` (`@include`/`@includedir`), global and scoped `Defaults`, `User_Alias`/`Runas_Alias`/`Host_Alias`/`Cmnd_Alias`, `User_Spec` rules, tags, digests, source line tracking, and unified `ParseFile`/`ParseReader` format auto-detection.
  - [sudol.go](./pkg/parser/sudol.go): Parser for `sudo -ll` and `sudo -l` listings.
  - [ldif.go](./pkg/parser/ldif.go): Parser for RFC 2849 LDIF `sudoRole` exports with `sudoOrder` sorting.
  - [corpus_test.go](./pkg/parser/corpus_test.go): Differential oracle and stress tests across the 105-file real-world corpus in [testdata/corpus/](./testdata/corpus/README.md) (`distros/`, `upstream_regress/`, `upstream_regress_invalid/`, `enterprise_cloud/`).
- **`pkg/gtfobins/`**:
  - [client.go](./pkg/gtfobins/client.go): Loads the embedded GTFObins snapshot ([database.json](./pkg/gtfobins/database.json) via `go:embed`) or external file, merges custom overlay catalogs (`MergeOverlayFile`), normalizes versioned/variant binary names, resolves alias and `inherit` (`from`) chains, and consolidates findings per `(binary, function)`.
- **`pkg/audit/`**:
  - [auditor.go](./pkg/audit/auditor.go): Combines defaults, command, shadowing, and validity window audits (`RunAudit` and `RunAuditWithOptions`).
  - [types.go](./pkg/audit/types.go): Data structures for `SudoersPolicy`, `Finding`, `AuditOptions`, `Severity`, `Member`, `DigestList`, and deterministic `ComputeFingerprint`.
  - [rules_defaults.go](./pkg/audit/rules_defaults.go): Audits global and scoped defaults using last-match-wins reduction (`SUDO-DEF-001` through `SUDO-DEF-018`).
  - [rules_commands.go](./pkg/audit/rules_commands.go): Expands aliases and audits user command rules against GTFObins, wildcards, negations, argument restrictions, `sudoedit` targets, writable paths, per-rule tags, digests, SELinux context elevation, and directory execution (`SUDO-CMD-001` through `SUDO-CMD-014`, `SUDO-GTFO-001` through `SUDO-GTFO-003`).
  - [rules_shadowing.go](./pkg/audit/rules_shadowing.go): Detects last-match-wins shadowed/overridden rules (`SUDO-CMD-015`) and expired/inverted `NOTBEFORE`/`NOTAFTER` validity windows (`SUDO-CMD-016`).
  - [gtfo_args.go](./pkg/audit/gtfo_args.go): Evaluates pinned non-interactive command arguments for `--subcommand-aware` GTFObins risk downgrades.
  - [explain.go](./pkg/audit/explain.go): Simulates `sudoers(5)` policy evaluation (`ExplainPolicy`) for `PrincipalQuery` targets.
  - [rules_system.go](./pkg/audit/rules_system.go): Audits target system file/directory/binary permissions (`SUDO-SYS-PERM-001` through `SUDO-SYS-PERM-013`) and compares `sudo --version` against CVE ranges.
  - [script_audit.go](./pkg/audit/script_audit.go): Performs static security analysis on `#!` privileged wrapper scripts (`SUDO-SYS-SCRIPT-001` through `SUDO-SYS-SCRIPT-003`).
  - [system_host.go](./pkg/audit/system_host.go): Audits `sudo` dedicated group restriction (`SUDO-SYS-PERM-014`), validates `/etc/passwd` & `/etc/group` identities (`SUDO-SYS-ID-001`), detects vendor changelog backports (`PATCHED_BACKPORT`), and correlates CVEs against policy preconditions (`ACTIVE`/`LATENT`).
- **`pkg/config/`**:
  - [config.go](./pkg/config/config.go): Loads `.sudo-check.yaml`/`.sudo-check.json`, enforces compliance profiles (`anssi-bp028`, `cis-5.2`, `disa-stig`, `minimal`), applies rule disables, severity overrides, and expiring suppressions.
  - [diff.go](./pkg/config/diff.go): Loads baseline `AuditResult` JSON reports and computes fingerprint-multiset diffs (`DiffResults`).
- **`pkg/patch/`**:
  - [patch.go](./pkg/patch/patch.go): Generates `visudo`-verified unified diff hardening patches (`GenerateHardeningPatch`) for raw `sudoers` files.
- **`pkg/fleet/`**:
  - [fleet.go](./pkg/fleet/fleet.go): Aggregates multiple host JSON `AuditResult` reports into consolidated host risk and rule prevalence summaries in HTML, CSV, and JSON.
- **`pkg/cvtsudoers/`**:
  - [wrapper.go](./pkg/cvtsudoers/wrapper.go): Finds and runs `cvtsudoers` with flags `-e -f json`.
- **`pkg/report/`**:
  - [formatter.go](./pkg/report/formatter.go), [text.go](./pkg/report/text.go), [json.go](./pkg/report/json.go), [sarif.go](./pkg/report/sarif.go), [pdf.go](./pkg/report/pdf.go), [html.go](./pkg/report/html.go), [reference_data.go](./pkg/report/reference_data.go): Multi-format exporters (`text`, `json`, `sarif`, `pdf`, `html`) plus compliance catalog, hardened baseline templates, and 43-rule traceability matrix.
- **`internal/buildinfo/`**:
  - [buildinfo.go](./internal/buildinfo/buildinfo.go): Holds build-time `Version`, `Commit`, and `Date` metadata injected via `-ldflags`.
- **Packaging, CI & Legal**:
  - [Dockerfile](./Dockerfile): Multi-stage static Go build on `golang:1.27-alpine` producing a rootless `scratch` container (`65532:65532`).
  - [action.yml](./action.yml): Composite GitHub Action with SARIF upload support.
  - [LICENSE](./LICENSE): MIT License.
  - [THIRD_PARTY_NOTICES.md](./THIRD_PARTY_NOTICES.md): Attribution for [docs/reference/cvtsudoers-src/](./docs/reference/cvtsudoers-src/) (retained under ISC), GTFObins snapshot, corpus, and Go dependencies.

---

## 2. Development Guidelines

### Language & Compiler version
- Target Go version: **Go 1.27** (specified in [go.mod](./go.mod)). Use standard Go formatting (`go fmt`).

### Cross-Compilation & Build Tags
- Target system audits check the owner of `/etc/sudoers` which relies on Unix syscalls.
- To prevent compilation breaks on non-Unix environments (like Windows), system audit helper functions are separated using build tags:
  - [rules_system_unix.go](./pkg/audit/rules_system_unix.go): Active logic for Unix-like OSes (`//go:build !windows`).
  - [rules_system_windows.go](./pkg/audit/rules_system_windows.go): Non-operational stub for Windows (`//go:build windows`).
- If you modify file ownership checks or low-level file interactions, make sure to update both files or check OS-specific compile targets.

### Compilation
Build the binary locally using:
```powershell
$env:CGO_ENABLED=0; go build -ldflags="-s -w" -trimpath -o sudo-check.exe
```
(Remove `sudo-check.exe` after verification if it was built only for testing so the working tree stays clean.)

### Running Tests & CI Checks
To ensure the CI build will pass, agents must run the following checks locally:

1. **Unit Tests**:
   Run all tests and coverage using:
   ```powershell
   go test -v -race -cover ./...
   ```
   *(Note: If running on a Windows system without Cgo/gcc configured, run without `-race`: `go test -v -cover ./...`)*
   To generate and inspect a coverage profile in PowerShell, quote the flag to prevent PowerShell from splitting on `.`:
   ```powershell
   go test "-coverprofile=coverage.out" ./...
   go tool cover "-func=coverage.out"
   Remove-Item -Force coverage.out
   ```

2. **Static Analysis**:
   Run `go vet` to catch common mistakes:
   ```powershell
   go vet ./...
   ```

3. **Code Formatting**:
   Ensure all files are formatted according to `gofmt`. Run the check to list unformatted files:
   ```powershell
   gofmt -l .
   ```
   To automatically format all files, run:
   ```powershell
   gofmt -w .
   ```

4. **Module Tidiness**:
   Verify that dependencies are tidy:
   ```powershell
   go mod tidy
   git diff --exit-code go.mod go.sum
   ```

**CRITICAL RULE**: Agents MUST run all unit tests and verify they pass after making any changes to the codebase. Ensure all tests pass, `go vet ./...` succeeds, code is properly formatted via `gofmt`, and modules are tidy before proposing any updates or completing the task.

---

## 3. Domain & Schema Invariants

- **Parser Oracle Parity (`pkg/parser`)**: `TestOracleComparisonWithCvtsudoers` in [parser_test.go](./pkg/parser/parser_test.go) and `TestRealWorldCorpusDifferentialAndStress` in [corpus_test.go](./pkg/parser/corpus_test.go) compare `parser.ParseString` against `cvtsudoers -f json` (invoked directly on Unix or via `wsl /usr/bin/cvtsudoers` on Windows). Any changes to `pkg/parser/` or `pkg/audit/types.go` must maintain parity with `cvtsudoers` JSON output and `audit.RunAudit` findings across the entire corpus.
- **Third-Party Reference Retention**: Do not remove [docs/reference/cvtsudoers-src/](./docs/reference/cvtsudoers-src/); keep attributions synchronized in [THIRD_PARTY_NOTICES.md](./THIRD_PARTY_NOTICES.md).
- **`cvtsudoers` JSON Schema Quirks**:
  - `Cmnd_Spec.Options` is a JSON array of single-key option objects (`[]audit.Option`) emitted in exact `cvtsudoers_json.c` order: pre-tag options (`runchroot`, `runcwd`, `command_timeout`, `notbefore`, `notafter`), then tags (`authenticate`, `noexec`, `intercept`, `send_mail`, `setenv`, `sudoedit_follow`, `log_input`, `log_output`), then post-tag options (`role`, `type`, `apparmor_profile`, `privs`, `limitprivs`).
  - Adjacent commands in a `Cmnd_Spec_List` are merged into the same `Cmnd_Spec` unless `runas`, tags, or non-timeout/non-timestamp options (`runchroot`, `runcwd`, `role`, `type`, `apparmor_profile`, `privs`, `limitprivs`) change, matching `cmndspec_continues` in `cvtsudoers_json.c`.
  - `Digest_Spec` hash fields (`sha224`, `sha256`, `sha384`, `sha512`) use `audit.DigestList` to unmarshal both single strings and string arrays, and must append on single-string unmarshals because `cvtsudoers` emits duplicate JSON keys in the same object when multiple digests share the same algorithm.
  - `Member` command alias references must support both `"cmndalias"` (emitted by `cvtsudoers` 1.9+) and `"commandalias"`.
  - `NOTBEFORE` and `NOTAFTER` ASN.1 GeneralizedTime values (`YYYYMMDDHH[MM[SS]][(.|,)frac][Z|(+|-)HH[MM]]`) are normalized to UTC `%Y%m%d%H%M%SZ`.
  - POSIX ERE regular expression command paths and arguments (`^...$`) may contain unescaped `,`, `:`, `(`, `)`, `=`, and preserved `\x` escapes up to the closing unescaped `$`.
- **Audit Semantics**:
  - `Defaults` options must be evaluated sequentially using last-match-wins semantics (`list_assign`, `list_add`, `list_remove`, and `!flag` resets).
  - Oracle-compatible `audit.RunAudit` defaults must remain untouched; new behavioral flags (drop-in mode, subcommand-aware GTFObins scoring, `SUDO-CMD-015` shadowing, `SUDO-CMD-016` expiry) are gated through `audit.AuditOptions` in `audit.RunAuditWithOptions`.
  - GTFObins findings are consolidated to **one finding per `(rule, binary, function)`**, and `noexec` only mitigates `shell` and `command` functions (never `library-load`, `file-read`, `file-write`, `suid`, `sudo`, or `capabilities`).
  - Finding fingerprints (`audit.ComputeFingerprint`) normalize paths with `path.Base` and exclude volatile line numbers so `diff` and `--baseline` stay stable across line shifts.
  - Every emitted `Finding` must populate `RemediationCode` deterministically with copy-pasteable `sudoers` configuration directives or shell commands (kept separate from prose `Remediation` and `ExploitPoC`).
