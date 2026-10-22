# Developer & Agent Instructions: sudo-check

Welcome! This repository contains `sudo-check`, a security audit utility for sudoers configuration policies and target hosts written in Go. Below are the key architecture details, rules, and guidelines to help you navigate and modify this codebase safely.

---

## 1. Project Overview & Architecture

`sudo-check` is designed to be a standalone, self-contained binary. It checks raw `sudoers` configuration files (via `pkg/parser`) or pre-converted `cvtsudoers` JSON policies for security weaknesses, dangerous defaults, and GTFObins bypasses.

### Package Structure
- **`cmd/`**: Cobra command specifications.
  - [root.go](cmd/root.go): Common persistent flags (`--output-dir`, `--formats`, `--fail-on`, `--no-color`, `--gtfobins-path`, `--cvtsudoers-path`).
  - [scan.go](cmd/scan.go): Command to parse and scan raw `sudoers` files, `sudoers.d` directories, or `cvtsudoers` JSON policy files/directories.
  - [system.go](cmd/system.go): Command to run autonomously on a live host (calling `cvtsudoers` or falling back to `pkg/parser`) and checking local versions and file/binary permissions.
  - [update_db.go](cmd/update_db.go): Helper command to download fresh GTFObins catalog dumps.
  - [version.go](cmd/version.go): Command to print the build version, commit, and date injected via ldflags.
- **`pkg/parser/`**:
  - [parser.go](pkg/parser/parser.go): Native Go `sudoers` parser supporting `#include`/`#includedir` (`@include`/`@includedir`), global and scoped `Defaults`, `User_Alias`/`Runas_Alias`/`Host_Alias`/`Cmnd_Alias`, `User_Spec` rules, tags, digests, and source line tracking.
  - [corpus_test.go](pkg/parser/corpus_test.go): Differential oracle and stress tests across the 105-file real-world corpus in [testdata/corpus/](testdata/corpus/README.md) (`distros/`, `upstream_regress/`, `upstream_regress_invalid/`, `enterprise_cloud/`).
- **`pkg/gtfobins/`**:
  - [client.go](pkg/gtfobins/client.go): Loads the embedded GTFObins snapshot (`database.json` via `go:embed`) or external file. Normalizes versioned/variant binary names, resolves alias and `inherit` (`from`) chains, and consolidates findings per `(binary, function)`.
- **`pkg/audit/`**:
  - [auditor.go](pkg/audit/auditor.go): Combines defaults and command audits.
  - [types.go](pkg/audit/types.go): Data structures for `SudoersPolicy`, `Finding`, `Severity`, `Member`, and `DigestList`.
  - [rules_defaults.go](pkg/audit/rules_defaults.go): Audits global and scoped defaults using last-match-wins reduction (`SUDO-DEF-001` through `SUDO-DEF-016`).
  - [rules_commands.go](pkg/audit/rules_commands.go): Expands aliases and audits user command rules against GTFObins, wildcards, negations, argument restrictions, `sudoedit` targets, writable paths, per-rule tags, digests, and SELinux context elevation (`SUDO-CMD-001` through `SUDO-CMD-013`, `SUDO-GTFO-001` through `SUDO-GTFO-003`).
  - [rules_system.go](pkg/audit/rules_system.go): Audits target system file/directory/binary permissions and compares `sudo --version` against CVE ranges.
- **`pkg/cvtsudoers/`**:
  - [wrapper.go](pkg/cvtsudoers/wrapper.go): Finds and runs `cvtsudoers` with flags `-e -f json`.
- **`pkg/report/`**:
  - [formatter.go](pkg/report/formatter.go): Report coordinator.
  - [text.go](pkg/report/text.go): Plaintext terminal and file reporter with optional ANSI color support.
  - [json.go](pkg/report/json.go): Structured JSON exporter.
  - [sarif.go](pkg/report/sarif.go): Exporter for Static Analysis Results Interchange Format v2.1.0.
  - [pdf.go](pkg/report/pdf.go): Programmatic PDF builder using `github.com/go-pdf/fpdf`.
  - [html.go](pkg/report/html.go): Offline-safe self-contained HTML report with dark/light modes and client-side filtering.

---

## 2. Development Guidelines

### Language & Compiler version
- Target Go version: **Go 1.27** (specified in [go.mod](go.mod)). Use standard Go formatting (`go fmt`).

### Cross-Compilation & Build Tags
- Target system audits check the owner of `/etc/sudoers` which relies on Unix syscalls.
- To prevent compilation breaks on non-Unix environments (like Windows), system audit helper functions are separated using build tags:
  - [rules_system_unix.go](pkg/audit/rules_system_unix.go): Active logic for Unix-like OSes (`//go:build !windows`).
  - [rules_system_windows.go](pkg/audit/rules_system_windows.go): Non-operational stub for Windows (`//go:build windows`).
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

- **Parser Oracle Parity (`pkg/parser`)**: `TestOracleComparisonWithCvtsudoers` in [parser_test.go](pkg/parser/parser_test.go) and `TestRealWorldCorpusDifferentialAndStress` in [corpus_test.go](pkg/parser/corpus_test.go) compare `parser.ParseString` against `cvtsudoers -f json` (invoked directly on Unix or via `wsl /usr/bin/cvtsudoers` on Windows). Any changes to `pkg/parser/` or `pkg/audit/types.go` must maintain parity with `cvtsudoers` JSON output and `audit.RunAudit` findings across the entire corpus.
- **`cvtsudoers` JSON Schema Quirks**:
  - `Cmnd_Spec.Options` is a JSON array of single-key option objects (`[]audit.Option`) emitted in exact `cvtsudoers_json.c` order: pre-tag options (`runchroot`, `runcwd`, `command_timeout`, `notbefore`, `notafter`), then tags (`authenticate`, `noexec`, `intercept`, `send_mail`, `setenv`, `sudoedit_follow`, `log_input`, `log_output`), then post-tag options (`role`, `type`, `apparmor_profile`, `privs`, `limitprivs`).
  - Adjacent commands in a `Cmnd_Spec_List` are merged into the same `Cmnd_Spec` unless `runas`, tags, or non-timeout/non-timestamp options (`runchroot`, `runcwd`, `role`, `type`, `apparmor_profile`, `privs`, `limitprivs`) change, matching `cmndspec_continues` in `cvtsudoers_json.c`.
  - `Digest_Spec` hash fields (`sha224`, `sha256`, `sha384`, `sha512`) use `audit.DigestList` to unmarshal both single strings and string arrays, and must append on single-string unmarshals because `cvtsudoers` emits duplicate JSON keys in the same object when multiple digests share the same algorithm.
  - `Member` command alias references must support both `"cmndalias"` (emitted by `cvtsudoers` 1.9+) and `"commandalias"`.
  - `NOTBEFORE` and `NOTAFTER` ASN.1 GeneralizedTime values (`YYYYMMDDHH[MM[SS]][(.|,)frac][Z|(+|-)HH[MM]]`) are normalized to UTC `%Y%m%d%H%M%SZ`.
  - POSIX ERE regular expression command paths and arguments (`^...$`) may contain unescaped `,`, `:`, `(`, `)`, `=`, and preserved `\x` escapes up to the closing unescaped `$`.
- **Audit Semantics**:
  - `Defaults` options must be evaluated sequentially using last-match-wins semantics (`list_assign`, `list_add`, `list_remove`, and `!flag` resets).
  - GTFObins findings are consolidated to **one finding per `(rule, binary, function)`**, and `noexec` only mitigates `shell` and `command` functions (never `library-load`, `file-read`, `file-write`, `suid`, `sudo`, or `capabilities`).
  - Every emitted `Finding` must populate `RemediationCode` deterministically with copy-pasteable `sudoers` configuration directives or shell commands (kept separate from prose `Remediation` and `ExploitPoC`).
