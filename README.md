# sudo-check

`sudo-check` is a standalone, statically compiled security auditing utility for **sudoers** configuration policies and target systems written in Go.

It scans raw `sudoers` configuration files (including `#include` and `#includedir` drop-ins) or pre-converted `cvtsudoers` JSON policies for dangerous defaults, security misconfigurations, compliance violations (ANSSI BP-028, CIS Benchmarks), and executable binaries in the **GTFObins** catalog.

---

## Features

- **Native Sudoers Parser & `cvtsudoers` Compatibility**: Parses raw `/etc/sudoers` and `/etc/sudoers.d/*` configurations directly using a built-in native Go parser (`pkg/parser`) or accepts `cvtsudoers -f json` policy dumps.
- **GTFObins Matching**:
  - Resolves recursive `inherit` chains (e.g., `vim`, `systemctl`, `journalctl`, `git`, `crontab`) and binary aliases.
  - Normalizes versioned and alternative binary names (e.g., `python3.11`, `vim.basic`, `gawk`, `nc.openbsd`).
  - Consolidates findings to one finding per `(rule, binary, function)` with function-accurate `noexec` mitigation awareness (`shell`/`command` vs. `library-load`, `file-read`, `file-write`).
- **Defaults Auditing (Global & Scoped)**:
  - Evaluates `Defaults` sequentially using `sudo`'s last-match-wins semantics (`=`, `+=`, `-=`, `!flag`) across global and scoped (`Defaults@host`, `Defaults:user`, `Defaults!cmnd`, `Defaults>runas`) bindings.
  - Audits `secure_path`, `env_reset`, `use_pty`, `noexec`, `requiretty`, `umask`, `ignore_dot`, `visiblepw`, `pwfeedback`, `!authenticate`, `setenv`, `sudoedit_follow`, `!sudoedit_checkdir`, `timestamp_timeout`, `passwd_timeout`, `timestamp_type=global`, `runchroot`, `runcwd=*`, and 90+ dangerous environment variables/prefixes in `env_keep` and `env_check`.
- **Allowed Commands & Alias Expansion**:
  - Expands `User_Aliases`, `Host_Aliases`, `Runas_Aliases`, and `Command_Aliases` recursively.
  - Detects `ALL` command rules, wildcard/glob rules, negated commands (`!cmd`) and negated identities (`!user`, `!host`, `!runas`), missing argument restrictions, sensitive `sudoedit` targets, relative or world-writable command paths, per-command `SETENV`/`FOLLOW`/`CHROOT`/`CWD=*` overrides, and weak `sha224` digests.
- **System Verification**:
  - Checks the target host's active `sudo` version against known vulnerabilities: `CVE-2019-14287`, `CVE-2019-18634` (`pwfeedback` overflow), `CVE-2021-3156` ("Baron Samedit"), `CVE-2022-43995`, `CVE-2023-22809` (`sudoedit` arbitrary file write), `CVE-2023-27320` (`chroot` double-free), `CVE-2025-32462` (`-h` host option), and `CVE-2025-32463` (`chroot` `nsswitch.conf`).
  - Validates permissions and `root:root` ownership on `/etc/sudoers`, `/etc/sudoers.d/*`, `/usr/bin/sudo`, and target binaries referenced in the policy.
- **Exporters**:
  - **Text**: Terminal output with optional `--no-color` / `NO_COLOR` support and clean ANSI-free file export.
  - **JSON**: Structured JSON report for automation and programmatic consumption.
  - **SARIF**: Static Analysis Results Interchange Format v2.1.0 with GitHub Code Scanning `security-severity`, compliance tags, and line number regions.
  - **PDF**: Programmatically formatted vector report with CP1252 Unicode translation.
  - **HTML**: Self-contained, 100% offline-safe responsive dark/light dashboard with client-side search and severity filters.

---

## Installation & Build

### Prerequisites
- [Go 1.26](https://go.dev/) or later.

### Build from Source
Compile the binary statically using standard Go tools:
```bash
git clone https://github.com/Harvester57/sudo-audit.git
cd sudo-audit
CGO_ENABLED=0 go build -ldflags="-s -w" -trimpath -o sudo-check
```

---

## CLI Usage

```
sudo-check [command] [flags]
```

### 1. Scan Sudoers Files or Pre-Converted JSON Policies
Analyze a raw `sudoers` file, a `sudoers.d` directory, a `cvtsudoers` JSON policy file, or a directory of policies:
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
For codebase architecture details, cross-compilation configurations, and test setup, please refer to [AGENTS.md](AGENTS.md).
