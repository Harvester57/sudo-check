# sudo-check

`sudo-check` is a standalone, statically compiled security auditing utility for **sudoers** configuration policies and target systems written in Go.

It scans raw `sudoers` configuration files (including `#include`/`@include` and `#includedir`/`@includedir` drop-ins) or pre-converted `cvtsudoers` JSON policies for dangerous defaults, privilege escalation vectors, compliance violations (ANSSI BP-028, CIS Benchmarks, DISA STIG), and executable binaries in the **GTFObins** catalog.

---

## Features

- **Native Sudoers Parser & `cvtsudoers` Parity**:
  - Parses raw `/etc/sudoers` and `/etc/sudoers.d/*` configurations directly using a built-in native Go parser (`pkg/parser`) or accepts `cvtsudoers -f json` policy dumps.
  - Supports `#include`/`#includedir` (`@include`/`@includedir`), global and scoped `Defaults`, `User_Alias`/`Runas_Alias`/`Host_Alias`/`Cmnd_Alias`, `User_Spec` rules, tags, SHA-2 digests, ASN.1 `GeneralizedTime` timestamps (`NOTBEFORE`/`NOTAFTER`), and POSIX ERE regular expressions.
  - Tracks included files during directory scans to avoid duplicate auditing of drop-ins when a root `sudoers` file is present, while preserving exact per-file `Context` and line number attribution.
  - Validated for differential parity against `cvtsudoers -f json` across a 105-file real-world test corpus (`testdata/corpus/`).
- **GTFObins Matching**:
  - Resolves recursive `inherit` chains (e.g., `vim`, `systemctl`, `journalctl`, `git`, `crontab`) and binary aliases.
  - Normalizes versioned and distribution-specific binary names (e.g., `python3.11`, `vim.basic`, `gawk`, `nc.openbsd`).
  - Consolidates findings to one finding per `(rule, binary, function)` with function-accurate `noexec` mitigation awareness (`shell`/`command` vs. `library-load`, `file-read`, `file-write`, `suid`, `sudo`, `capabilities`).
- **Defaults Auditing (Global & Scoped)**:
  - Evaluates `Defaults` sequentially using `sudo`'s last-match-wins semantics (`=`, `+=`, `-=`, `!flag`) across global and scoped (`Defaults@host`, `Defaults:user`, `Defaults!cmnd`, `Defaults>runas`) bindings.
  - Audits `secure_path`, `env_reset`, `use_pty`, `noexec`, `requiretty`, `umask`, `ignore_dot`, `visiblepw`, `pwfeedback`, `!authenticate`, `setenv`, `sudoedit_follow`, `!sudoedit_checkdir`, `timestamp_timeout`, `passwd_timeout`, `timestamp_type=global`, `runchroot`, `runcwd=*`, and 90+ dangerous environment variables/prefixes in `env_keep`, `env_check`, and `env_delete`.
- **Allowed Commands & Alias Expansion**:
  - Expands `User_Aliases`, `Host_Aliases`, `Runas_Aliases`, and `Command_Aliases` recursively.
  - Detects `ALL` command rules, wildcard/glob rules, negated commands (`!cmd`) and negated identities (`!user`, `!host`, `!runas`), missing argument restrictions, direct text editor execution, sensitive `sudoedit` targets, relative or user-writable/temporary command paths, per-command `SETENV`/`FOLLOW`/`CHROOT`/`CWD=*` overrides, and weak `sha224` digests.
- **System Verification**:
  - Checks the target host's active `sudo` version against known vulnerabilities: `CVE-2019-14287`, `CVE-2019-18634` (`pwfeedback` overflow), `CVE-2021-3156` ("Baron Samedit"), `CVE-2022-43995`, `CVE-2023-22809` (`sudoedit` arbitrary file write), `CVE-2023-27320` (`chroot` double-free), `CVE-2025-32462` (`-h` host option), and `CVE-2025-32463` (`chroot` `nsswitch.conf`).
  - Validates permissions and `root:root` ownership on `/etc/sudoers`, `/etc/sudoers.d` and its drop-in files, `/usr/bin/sudo` (including SUID bit verification), and target binaries and parent directories referenced in the policy.
- **Actionable Remediation & Multi-Format Exporters**:
  - Every finding emits a deterministic, copy-pasteable `RemediationCode` snippet (`sudoers` policy directive or shell command) separated from prose `Remediation` and `ExploitPoC` reference commands.
  - **HTML** ([Example Report](docs/example-report.html)): Self-contained, 100% offline-safe responsive dark/light report organized into three toggleable WAI-ARIA tabs:
    1. **Audit Report**: Interactive triage dashboard featuring multi-file, rule, and principal breakdown panels, adaptive grouping (`SEVERITY`, `FILE`, `RULE`, `USER`), pseudo-`sudoers` rule previews, one-click copyable remediation blocks, print/PDF-ready layout, and `content-visibility: auto` deferred rendering.
    2. **Reference Frameworks**: Verbatim requirements, security rationale, required directives, and live violation counts across **ANSSI BP-028** (`R38`–`R42`/`R44`, in English and original French), **CIS Linux Benchmark Section 5.2** (`5.2.1`–`5.2.7`), **DISA STIG**, and **MITRE ATT&CK** (`T1548.003`), with one-click cross-filtering to triggered findings.
    3. **Hardened Reference Template**: Annotated, copy-pasteable `/etc/sudoers` baseline policy (verified in unit tests to produce zero `sudo-check` findings), `/etc/sudoers.d/` drop-in example, root-owned wrapper script pattern, host permission remediation runbook, and a complete 32-rule Traceability Matrix.
  - **Text**: Terminal output with optional `--no-color` / `NO_COLOR` support, clean ANSI-free file export, and indented `Example Fix` / `Reference` blocks.
  - **JSON**: Structured JSON report including `remediation_code`, `exploit_poc`, and compliance mappings for automation.
  - **SARIF**: Static Analysis Results Interchange Format v2.1.0 with GitHub Code Scanning `security-severity`, remediation snippets, compliance tags, and source file/line regions.
  - **PDF**: Programmatically formatted vector report with dedicated remediation code and exploit/verification reference boxes.

---

## Audit Rule Catalog

| Category | Rule IDs | Scope |
| :--- | :--- | :--- |
| **Defaults Rules** | `SUDO-DEF-001` – `SUDO-DEF-016` | Global and scoped `Defaults` (`secure_path`, `use_pty`, `env_keep`/`env_check`/`env_delete`, `visiblepw`, `pwfeedback`, `noexec`, `requiretty`, `umask`, `ignore_dot`, `env_reset`, `!authenticate`, `setenv`, `sudoedit_follow`/`!sudoedit_checkdir`, `timestamp_timeout`/`passwd_timeout`/`timestamp_type`, `runchroot`/`runcwd`) |
| **Command Rules** | `SUDO-CMD-001` – `SUDO-CMD-012` | Negated commands (`!cmd`), `ALL` privileges (`PASSWD` & `NOPASSWD`), wildcards, passwordless specific commands, missing argument restrictions, direct editor execution, negated `User`/`Host`/`Runas` specs, per-command `SETENV`/`FOLLOW`/`CHROOT`/`CWD=*`, sensitive `sudoedit` targets, relative or writable paths, and weak `sha224` digests |
| **GTFObins Rules** | `SUDO-GTFO-001` – `SUDO-GTFO-003` | Authenticated GTFObins binaries (`HIGH`), passwordless `NOPASSWD` GTFObins binaries (`CRITICAL`), and `NOEXEC`-mitigated `shell`/`command` binaries (`LOW`) |
| **System & File Permissions** | `SUDO-SYS-001`, `SUDO-SYS-PERM-001` – `SUDO-SYS-PERM-013` | `sudo` version parsing, `/etc/sudoers` and `/etc/sudoers.d/*` permissions and `root:root` ownership, `sudo` binary SUID bit and ownership, and permitted target binary/directory write permissions |
| **Sudo CVEs** | `CVE-2019-14287`, `CVE-2019-18634`, `CVE-2021-3156`, `CVE-2022-43995`, `CVE-2023-22809`, `CVE-2023-27320`, `CVE-2025-32462`, `CVE-2025-32463` | Active `sudo --version` vulnerability range matching |

---

## Installation & Build

### Download Prebuilt Binaries
Prebuilt static binaries (`linux/amd64`, `linux/arm64`, `windows/amd64`) and CycloneDX SBOMs are available on the [GitHub Releases](https://github.com/Harvester57/sudo-check/releases) page.

### Build from Source
Requires [Go 1.26](https://go.dev/) or later:
```bash
git clone https://github.com/Harvester57/sudo-check.git
cd sudo-check
CGO_ENABLED=0 go build -ldflags="-s -w" -trimpath -o sudo-check
```

---

## CLI Usage

```
sudo-check [command] [flags]
```

### 1. Scan Sudoers Files or Pre-Converted JSON Policies
Analyze a raw `sudoers` file, a `sudoers.d` directory, a directory containing a root `sudoers` file and drop-ins, or `cvtsudoers` JSON policy files:
```bash
./sudo-check scan /path/to/sudoers -o reports/
```

Enforce a CI/CD severity gate (exits with status code `2` if any finding meets or exceeds the threshold):
```bash
./sudo-check scan /path/to/sudoers -f sarif --fail-on HIGH
```

### 2. Autonomous Local System Scan
Audit the local host autonomously (uses `cvtsudoers` if installed, or automatically falls back to the built-in native parser):
```bash
sudo ./sudo-check system -o reports/
```

### 3. Update the GTFObins Database
Fetch the latest database snapshot from `https://gtfobins.org/api.json` and save it locally:
```bash
./sudo-check update-db -p gtfobins.json
```

### 4. Display Version
Print the build version, commit hash, and build date:
```bash
./sudo-check version
```

---

## Command Flags

### Global Flags
- `-o, --output-dir <string>`: Directory to save generated reports (if omitted, `text`, `json`, or `sarif` reports are written to `stdout`).
- `-f, --formats <string>`: Comma-separated list of report formats (`text,json,sarif,pdf,html`) (default: `"text,sarif,pdf,html"`).
- `--fail-on <severity>`: Exit with non-zero status code (`2`) if any finding meets or exceeds the specified severity (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`).
- `--no-color`: Disable ANSI color codes in terminal text output (also respects `NO_COLOR`).
- `--gtfobins-path <string>`: Path to a custom `gtfobins.json` database file.
- `--cvtsudoers-path <string>`: Path to a custom `cvtsudoers` binary.

### System Scan Flags
- `--sudoers-file <string>`: Path to target sudoers file (default `"/etc/sudoers"`).

---

## Developer Guide
For codebase architecture details, cross-compilation configurations, and test setup, please refer to [AGENTS.md](AGENTS.md) and [CHANGELOG.md](CHANGELOG.md).
