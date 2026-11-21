# sudo-check

`sudo-check` is a standalone, statically compiled security auditing utility for **sudoers** configuration policies and target systems written in Go.

It scans raw `sudoers` configuration files (including `#include`/`@include` and `#includedir`/`@includedir` drop-ins), `cvtsudoers` JSON policies, `sudo -ll` listings, RFC 2849 LDIF `sudoRole` exports, and standard input (`-`) for dangerous defaults, privilege escalation vectors, rule shadowing, expired validity windows, compliance violations (ANSSI BP-028, CIS Benchmarks, DISA STIG), and executable binaries in the **GTFObins** catalog.

---

## Features

- **Native Multi-Format Parser & `cvtsudoers` Parity**:
  - Parses raw `/etc/sudoers` and `/etc/sudoers.d/*` configurations directly using a built-in native Go parser ([pkg/parser/](./pkg/parser/parser.go)) or accepts `cvtsudoers -f json` policy dumps, `sudo -ll` / `sudo -l` listings ([pkg/parser/sudol.go](./pkg/parser/sudol.go)), RFC 2849 LDIF `sudoRole` exports ([pkg/parser/ldif.go](./pkg/parser/ldif.go)), and stdin (`scan -`).
  - Supports `#include`/`#includedir` (`@include`/`@includedir`), global and scoped `Defaults`, `User_Alias`/`Runas_Alias`/`Host_Alias`/`Cmnd_Alias`, `User_Spec` rules, tags, SHA-2 digests, ASN.1 `GeneralizedTime` timestamps (`NOTBEFORE`/`NOTAFTER`), and POSIX ERE regular expressions.
  - Tracks included files during directory scans to avoid duplicate auditing of drop-ins when a root `sudoers` file is present, while preserving exact per-file `Context` and line number attribution.
  - Validated for differential parity against `cvtsudoers -f json` across a 105-file real-world test corpus ([testdata/corpus/](./testdata/corpus/README.md)).
- **GTFObins Matching & Subcommand Awareness**:
  - Resolves recursive `inherit` chains (e.g., `vim`, `systemctl`, `journalctl`, `git`, `crontab`) and binary aliases, and supports merging custom site catalogs via `--custom-gtfobins`.
  - Normalizes versioned and distribution-specific binary names (e.g., `python3.11`, `vim.basic`, `gawk`, `nc.openbsd`).
  - Consolidates findings to one finding per `(rule, binary, function)` with function-accurate `noexec` mitigation awareness (`shell`/`command` vs. `library-load`, `file-read`, `file-write`, `suid`, `sudo`, `capabilities`).
  - Optional `--subcommand-aware` evaluation downgrades genuinely constrained enterprise command invocations (e.g., `systemctl restart nginx.service`, `git status --short`, non-sensitive `cat`/`head`/`tail` file paths, or `apt-get update`) with `Exploitability: CONSTRAINED`.
- **Defaults Auditing (Global & Scoped)**:
  - Evaluates `Defaults` sequentially using `sudo`'s last-match-wins semantics (`=`, `+=`, `-=`, `!flag`) across global and scoped (`Defaults@host`, `Defaults:user`, `Defaults!cmnd`, `Defaults>runas`) bindings.
  - Audits `secure_path`, `env_reset`, `use_pty`, `noexec`, `requiretty`, `umask`, `ignore_dot`, `visiblepw`, `pwfeedback`, `!authenticate`, `setenv`, `sudoedit_follow`, `!sudoedit_checkdir`, `timestamp_timeout`, `passwd_timeout`, `timestamp_type=global`, `runchroot`, `runcwd=*`, `logfile`, `rootpw`/`targetpw`/`runaspw`, and 90+ dangerous environment variables/prefixes in `env_keep`, `env_check`, and `env_delete`.
- **Allowed Commands, Shadowing & Validity Windows**:
  - Expands `User_Aliases`, `Host_Aliases`, `Runas_Aliases`, and `Command_Aliases` recursively.
  - Detects `ALL` command rules, wildcard/glob rules, negated commands (`!cmd`) and negated identities (`!user`, `!host`, `!runas`), missing argument restrictions, direct text editor execution, sensitive `sudoedit` targets, relative or user-writable/temporary command paths, per-command `SETENV`/`FOLLOW`/`CHROOT`/`CWD=*` overrides, weak `sha224` digests, missing SELinux `TYPE=`/`ROLE=` context elevation (`SUDO-CMD-013`), and directory-wide command execution (`SUDO-CMD-014`).
  - Detects shadowed or overridden rules in `sudoers` last-match-wins evaluation order (`SUDO-CMD-015`, enabled by default on full policy scans and disabled automatically in `--dropin` mode unless explicitly set) and inverted or expired `NOTBEFORE`/`NOTAFTER` validity windows (`SUDO-CMD-016` via `--check-expiry` and `system` scans).
- **Principal Simulation, Policy Diffing, Fleet Aggregation & Safe Patching**:
  - `explain`: Evaluates effective `Defaults`, allowed/denied commands, resolved flags (`NOPASSWD`, `NOEXEC`, `SETENV`), and GTFObins escalation paths for a specific user, UID, group list, host, or IP address.
  - `diff` & `--baseline`: Compares two policies or JSON `AuditResult` reports using deterministic SHA-256 finding fingerprints (`Added`, `Resolved`, `Unchanged`) and lets CI gates fail only on newly introduced findings.
  - `merge`: Aggregates multiple host JSON `AuditResult` reports into consolidated fleet-wide host risk rankings and rule prevalence summaries ([fleet-report.html](./docs/examples/fleet-report.html), [fleet-report.csv](./docs/examples/fleet-report.csv), [fleet-report.json](./docs/examples/fleet-report.json)).
  - `--fix-patch` & `--config` / `--profile`: Generates `visudo`-validated unified diff hardening patches for raw `sudoers` files and supports `.sudo-check.yaml`/`.sudo-check.json` policy files with compliance profiles, rule disables, severity overrides, and expiring suppressions.
- **Autonomous System Verification**:
  - Checks the target host's active `sudo` version against known vulnerabilities (`CVE-2019-14287`, `CVE-2019-18634`, `CVE-2021-3156`, `CVE-2022-43995`, `CVE-2023-22809`, `CVE-2023-27320`, `CVE-2025-32462`, `CVE-2025-32463`), inspects local RPM/Debian changelogs to flag vendor-patched packages as `PATCHED_BACKPORT` (`INFO`), and correlates active policy preconditions to classify CVEs as `ACTIVE` or `LATENT`.
  - Validates permissions and `root:root` ownership on `/etc/sudoers`, `/etc/sudoers.d` and its drop-in files, custom `#include` targets, `/usr/bin/sudo` (including SUID bit and ANSSI BP-028 R38 dedicated group restriction `SUDO-SYS-PERM-014`), and target binaries, symlinks, ancestor directories, and `secure_path` directories.
  - Validates principals referenced in `sudoers` against `/etc/passwd` and `/etc/group` (`SUDO-SYS-ID-001`) and performs static security analysis on `#!` wrapper scripts referenced by `sudoers` (`SUDO-SYS-SCRIPT-001`–`003`).
- **Actionable Remediation & Multi-Format Exporters** ([All Example Reports](./docs/examples/README.md)):
  - Every finding emits a deterministic, copy-pasteable `RemediationCode` snippet (`sudoers` policy directive or shell command) separated from prose `Remediation` and `ExploitPoC` reference commands, along with verbatim `SourceLine`, `Tags`, and `InheritedDefaults` evidence.
  - **HTML** ([report.html](./docs/examples/report.html) | [Large Corpus Example](./docs/example-report.html)): Self-contained, 100% offline-safe responsive dark/light report organized into three toggleable WAI-ARIA tabs:
    1. **Audit Report**: Interactive triage dashboard featuring multi-file, rule, and principal breakdown panels, adaptive grouping (`SEVERITY`, `FILE`, `RULE`, `USER`), verbatim source lines with alias-resolved rules and inherited `Defaults`, one-click copyable remediation blocks, print/PDF-ready layout, and `content-visibility: auto` deferred rendering.
    2. **Reference Frameworks**: Verbatim requirements, security rationale, required directives, and live violation counts across **ANSSI BP-028 v2.0** (`R38`–`R44`, English with French translation), **CIS Linux Benchmarks Section 5.2** (`5.2.1`–`5.2.7`), **DISA STIG**, and **MITRE ATT&CK** (`T1548.003`), with one-click cross-filtering to triggered findings.
    3. **Hardened Reference Template**: Annotated, copy-pasteable `/etc/sudoers` baseline policy (verified in unit tests to produce zero `sudo-check` findings), `/etc/sudoers.d/` drop-in example, root-owned wrapper script pattern, host permission remediation runbook, and a complete 43-rule Traceability Matrix.
  - **Text** ([report.txt](./docs/examples/report.txt)): Terminal output with optional `--no-color` / `NO_COLOR` support, clean ANSI-free file export, verbatim source lines, and indented `Example Fix` / `Reference` blocks.
  - **JSON** ([report.json](./docs/examples/report.json)): Structured JSON report including `source_line`, `tags`, `inherited_defaults`, `remediation_code`, `exploit_poc`, `fingerprint`, `exploitability`, and compliance mappings for automation.
  - **SARIF** ([report.sarif](./docs/examples/report.sarif)): Static Analysis Results Interchange Format v2.1.0 with GitHub Code Scanning `security-severity`, sorted rules, remediation snippets, compliance tags, fingerprints, and source file/line regions.
  - **PDF** ([report.pdf](./docs/examples/report.pdf)): Deterministic programmatic vector report with source line blocks, dedicated remediation code, and exploit/verification reference boxes.

---

## Audit Rule Catalog

| Category | Rule IDs | Scope |
| :--- | :--- | :--- |
| **Defaults Rules** | `SUDO-DEF-001` – `SUDO-DEF-018` | Global and scoped `Defaults` (`secure_path`, `use_pty`, `env_keep`/`env_check`/`env_delete` including wildcards and `DYLD_*`, `visiblepw`, `pwfeedback`, `noexec`, `requiretty`, `umask`, `ignore_dot`, `env_reset`, `!authenticate`, `setenv`, `sudoedit_follow`/`!sudoedit_checkdir`, `timestamp_timeout`/`passwd_timeout`/`timestamp_type`, `runchroot`/`runcwd`, `logfile`, and `rootpw`/`targetpw`/`runaspw`) |
| **Command Rules** | `SUDO-CMD-001` – `SUDO-CMD-016` | Negated commands (`!cmd`), `ALL` privileges (`PASSWD` & `NOPASSWD`), wildcards, passwordless specific commands (including `sudoedit`), missing argument restrictions, direct editor execution, negated `User`/`Host`/`Runas` specs, per-command `SETENV`/`FOLLOW`/`CHROOT`/`CWD=*`, sensitive `sudoedit` targets, relative or writable paths, weak `sha224` digests, missing `TYPE=`/`ROLE=` SELinux context elevation (`SUDO-CMD-013`, `INFO`), directory-wide command execution (`/usr/bin/`, `SUDO-CMD-014`), last-match-wins shadowed/overridden rules (`SUDO-CMD-015`, `MEDIUM`/`INFO`), and inverted or expired `NOTBEFORE`/`NOTAFTER` validity windows (`SUDO-CMD-016`, `LOW`/`INFO`) |
| **GTFObins Rules** | `SUDO-GTFO-001` – `SUDO-GTFO-003` | Authenticated GTFObins binaries (`HIGH`), passwordless `NOPASSWD` GTFObins binaries (`CRITICAL`), and `NOEXEC`-mitigated `shell`/`command` binaries (`LOW`, excluding `NOEXEC`-immune shells, SUID wrappers, and container/daemon clients), with `--subcommand-aware` `CONSTRAINED` downgrades (`MEDIUM`/`LOW`) |
| **System & Host Checks** | `SUDO-SYS-001`, `SUDO-SYS-PERM-001` – `SUDO-SYS-PERM-014`, `SUDO-SYS-ID-001`, `SUDO-SYS-SCRIPT-001` – `SUDO-SYS-SCRIPT-003` | `sudo` version parsing (including `sudo-rs`), `/etc/sudoers`, `/etc/sudoers.d/*`, and custom included file permissions and `root:root` ownership, `sudo` binary SUID bit and ownership, ANSSI BP-028 R38 dedicated group restriction (`SUDO-SYS-PERM-014`, `INFO`), permitted target binary/symlink/ancestor/`secure_path` directory permissions, `/etc/passwd` & `/etc/group` orphaned principal validation (`SUDO-SYS-ID-001`, `LOW`), and `#!` wrapper script static security audit (`SUDO-SYS-SCRIPT-001`–`003`: unsafe `PATH`/`env` shebang, positional parameter injection sinks, untrusted source paths or writable/non-root interpreters) |
| **Sudo CVEs** | `CVE-2019-14287`, `CVE-2019-18634`, `CVE-2021-3156`, `CVE-2022-43995`, `CVE-2023-22809`, `CVE-2023-27320`, `CVE-2025-32462`, `CVE-2025-32463` | Active `sudo --version` vulnerability range matching with local RPM/Debian changelog backport detection (`PATCHED_BACKPORT`) and policy precondition correlation (`ACTIVE` / `LATENT`) |

---

## Installation & Build

### Download Prebuilt Binaries
Prebuilt static binaries (`linux/amd64`, `linux/arm64`, `darwin/amd64`, `darwin/arm64`, `windows/amd64`), `SHA256SUMS`, and CycloneDX SBOMs are available on the [GitHub Releases](https://github.com/Harvester57/sudo-check/releases) page.

### Build from Source
Requires [Go 1.27](https://go.dev/) or later:
```bash
git clone https://github.com/Harvester57/sudo-check.git
cd sudo-check
CGO_ENABLED=0 go build -ldflags="-s -w" -trimpath -o sudo-check
```

### Docker
Build the rootless static container image using [Dockerfile](./Dockerfile):
```bash
docker build -t sudo-check:local .
```

Scan a local `sudoers` file or policy directory mounted read-only:
```bash
docker run --rm -v "$(pwd):/workspace:ro" sudo-check:local scan /workspace/sudoers --no-color -f text
```

---

## CLI Usage

```text
sudo-check [command] [flags]
```

### 1. Scan Policies (Files, Directories, Stdin, `sudo -ll`, LDIF)
Analyze a raw `sudoers` file, a `sudoers.d` directory, a directory containing a root `sudoers` file and drop-ins, `cvtsudoers` JSON, `sudo -ll` output, or an `.ldif` `sudoRole` export:
```bash
./sudo-check scan /path/to/sudoers -o reports/
```

Scan from standard input (`-`), e.g. piping `sudo -ll` output directly:
```bash
sudo -ll | ./sudo-check scan - -f text
```

Audit a standalone `/etc/sudoers.d/` drop-in file without noise from global defaults defined in `/etc/sudoers`, check `NOTBEFORE`/`NOTAFTER` expirations, and generate a safe hardening patch:
```bash
./sudo-check scan /etc/sudoers.d/10-app --dropin --check-expiry --fix-patch 10-app.patch
```

Enforce a CI/CD severity gate (exits with status code `2` if any newly added finding meets or exceeds `--fail-on`):
```bash
./sudo-check scan /path/to/sudoers -f sarif --baseline baseline-report.json --fail-on HIGH
```

### 2. Autonomous Local System Scan
Audit the local host autonomously (uses the built-in native parser for exact file/line attribution with automatic `cvtsudoers` fallback, or a custom `--cvtsudoers-path` binary):
```bash
sudo ./sudo-check system -o reports/
```

### 3. Simulate Principal Privileges (`explain`)
Evaluate effective `Defaults`, allowed/denied commands, rule flags, and GTFObins escalation paths for a user, UID, group set, hostname, and/or IP list:
```bash
./sudo-check explain /etc/sudoers --user deploy --groups webops,sudo --host web01.internal -f text
```

### 4. Compare Policies or Audit Reports (`diff`)
Compare two `sudoers` policies or two JSON `AuditResult` reports by finding fingerprint and optionally fail only on newly added findings:
```bash
./sudo-check diff baseline-report.json current-report.json --fail-on HIGH
```

### 5. Aggregate Fleet Audit Reports (`merge`)
Consolidate multiple host JSON `AuditResult` files or directories into a fleet-wide risk ranking and rule prevalence dashboard (`fleet-report.html`, `fleet-report.csv`, `fleet-report.json`):
```bash
./sudo-check merge ./host-reports/ -o ./fleet-summary/ -f html,csv,json
```

### 6. Update the GTFObins Database
Fetch the latest database snapshot from `https://gtfobins.org/api.json` and save it locally:
```bash
./sudo-check update-db -p gtfobins.json
```

### 7. Display Version
Print the build version, commit hash, and build date:
```bash
./sudo-check version
```

---

## Configuration File & Compliance Profiles

Pass `--config .sudo-check.yaml` (YAML or JSON) to configure compliance profiles, disable rules, override severities, enable scan modes, merge custom GTFObins overlays, and define expiring suppressions:

```yaml
profile: anssi-bp028 # all | anssi-bp028 | cis-5.2 | disa-stig | minimal
dropin_mode: false
subcommand_aware: true
custom_gtfobins: ./custom-gtfobins.json
disable_rules:
  - SUDO-DEF-006
severity_overrides:
  SUDO-DEF-008: info
suppressions:
  - rule: SUDO-CMD-005
    user: deploy
    host: ALL
    command: /usr/bin/systemctl restart app.service
    reason: Approved non-interactive service restart ticket SEC-1042
    expires: 2027-06-30
```

---

## GitHub Action

Use the composite action defined in [action.yml](./action.yml) to audit `sudoers` configurations in CI/CD and optionally upload SARIF results to GitHub Code Scanning:

```yaml
name: Sudoers Security Audit
on: [push, pull_request]

permissions:
  contents: read
  security-events: write

jobs:
  sudo-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: Harvester57/sudo-check@main
        with:
          target: ./sudoers/
          profile: anssi-bp028
          fail-on: HIGH
          formats: sarif,text
          upload-sarif: 'true'
```

---

## Command Flags

### Global Persistent Flags
- `-o, --output-dir <string>`: Directory to save generated reports (if omitted, `text`, `json`, or `sarif` reports are written to `stdout`).
- `-f, --formats <string>`: Comma-separated list of report formats (default: `"text,sarif,pdf,html"` for `scan`/`system`; `"text"` or `"json"` for `explain`/`diff`; `"html,csv,json"` for `merge`).
- `--fail-on <severity>`: Exit with non-zero status code (`2`) if any finding meets or exceeds the specified severity (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`).
- `--no-color`: Disable ANSI color codes in terminal text output (also respects `NO_COLOR`).
- `--gtfobins-path <string>`: Path to a custom `gtfobins.json` database file.
- `--custom-gtfobins <string>`: Path to a custom GTFObins overlay JSON file merged onto the loaded catalog.
- `--cvtsudoers-path <string>`: Path to a custom `cvtsudoers` binary.
- `--config <string>`: Path to `.sudo-check.yaml` or `.sudo-check.json` configuration file.
- `--profile <string>`: Compliance profile filter (`all`, `anssi-bp028`, `cis-5.2`, `disa-stig`, `minimal`).
- `--baseline <string>`: Path to a baseline `report.json` so `--fail-on` triggers only on newly added findings.
- `--subcommand-aware`: Enable subcommand/argument-aware GTFObins risk evaluation.

### Scan Flags (`scan`)
- `--dropin`: Audit standalone drop-in file(s), suppressing missing global `Defaults` rules (`SUDO-DEF-001`, `003`, `007`, `008`, `009`, `010`, `011`, `017`).
- `--check-shadowing`: Enable `SUDO-CMD-015` shadowing analysis (default `true`; defaults to `false` when `--dropin` is enabled unless explicitly set).
- `--check-expiry`: Enable `SUDO-CMD-016` `NOTBEFORE`/`NOTAFTER` validity window checks against current UTC time.
- `--fix-patch <string>`: Write a `visudo`-validated hardening unified diff patch for a single raw `sudoers` file target.

### System Scan Flags (`system`)
- `--sudoers-file <string>`: Path to target sudoers file (default `"/etc/sudoers"`).

### Explain Flags (`explain`)
- `--user <string>`: Target username to evaluate.
- `--uid <int>`: Target numeric UID to evaluate.
- `--groups <string>`: Comma-separated Unix group names.
- `--host <string>`: Target hostname (short or FQDN).
- `--ip <string>`: Comma-separated IPv4/IPv6 addresses for CIDR matching.

### Database Update Flags (`update-db`)
- `-p, --output <string>`: Output path for the updated `gtfobins.json` (default `"gtfobins.json"`).

---

## License, Notices & Developer Guide
- Licensed under the MIT License; see [LICENSE](./LICENSE) and [THIRD_PARTY_NOTICES.md](./THIRD_PARTY_NOTICES.md).
- For codebase architecture details, cross-compilation configurations, and test setup, please refer to [AGENTS.md](./AGENTS.md) and [CHANGELOG.md](./CHANGELOG.md).
