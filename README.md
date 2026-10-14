# sudo-check

`sudo-check` is a standalone, statically compiled security auditing utility for **sudoers** configuration policies and target systems written in Go.

It scans sudoers policies for dangerous defaults, security misconfigurations, and executable binaries that are susceptible to privilege escalation using the **GTFObins** catalog.

---

## Features

- **GTFObins Matching**: Identifies binary rules in sudoers matching GTFObins privilege escalation techniques (e.g. spawning a shell, executing commands, reading/writing files, library loading, and inherited capabilities from pagers/editors).
- **Defaults Auditing**: Audits global and scoped/bound `Defaults` configurations (using sudoers last-match-wins precedence) such as missing/disabled `secure_path`, missing `use_pty` (TIOCSTI terminal hijacking protection), dangerous variables or globs added to `env_keep` (like `LD_*`, `PYTHONPATH`), `visiblepw`, `pwfeedback`, `!authenticate`, `setenv`, `sudoedit_follow`, and weak `timestamp_timeout` / `!tty_tickets`.
- **Allowed Commands Analysis**: Flags use of wildcards/globs in paths, negated commands and negated `Runas` specifications (`!root`), `ALL` wildcards, `SETENV` / `FOLLOW` tags, direct text editor execution, and missing argument restrictions.
- **System Verification**: Checks the target host's active `sudo` version against CVE ranges (`CVE-2019-14287`, `CVE-2021-3156` "Baron Samedit", `CVE-2023-22809`, `CVE-2023-27320`, `CVE-2025-32462`, and `CVE-2025-32463`) and validates permissions and ownership of `/etc/sudoers`, `/etc/sudoers.d/*`, the `sudo` SUID binary, and permitted command executables.
- **Diverse Exporters**:
  - **Text**: Colorized terminal output (and clean ANSI-free plaintext when written to `report.txt`).
  - **SARIF**: Static Analysis Results Interchange Format 2.1.0 JSON with GitHub Code Scanning `security-severity` metadata.
  - **PDF**: Programmatically formatted grid layout reports with CP1252/UTF-8 character translation.
  - **HTML**: Self-contained, offline-ready responsive dark/light mode dashboard with client-side interactive search and severity/category filters.

---

## Installation & Build

### Prerequisites
- [Go 1.26](https://go.dev/) or later.
- The `cvtsudoers` utility installed on the system (usually packaged with `sudo` itself) if running in autonomous system mode.

### Build from Source
Compile the binary statically using standard Go tools:
```bash
git clone https://github.com/Harvester57/sudo-audit.git
cd sudo-audit
CGO_ENABLED=0 go build -ldflags="-s -w" -trimpath -o sudo-check
```

---

## CLI Usage

`sudo-check` uses a subcommand structure powered by Cobra:

```
sudo-check [command] [flags]
```

### 1. Scan Pre-Converted JSON policies
Analyze a single JSON policy file or a directory containing multiple JSON policies converted with `cvtsudoers` beforehand:
```bash
./sudo-check scan /path/to/policies/ -o reports/
```

### 2. Autonomous Local System Scan
Audit the local host autonomously by converting `/etc/sudoers` automatically (requires read privileges; run with `sudo` if necessary):
```bash
sudo ./sudo-check system -o reports/
```

### 3. Update the GTFObins Database
Fetch the latest database snapshot dynamically from the online URL `https://gtfobins.org/api.json` and save it locally:
```bash
./sudo-check update-db -p gtfobins.json
```

### 4. Display Version
Print the injected build version, commit hash, and build date:
```bash
./sudo-check version
```

---

## Command Flags

### Global Flags
- `-o, --output-dir <string>`: Directory to save generated reports (default is stdout for plaintext).
- `-f, --formats <string>`: Comma-separated list of report formats (`text,sarif,pdf,html`) (default: `"text,sarif,pdf,html"`).
- `--fail-on <string>`: Exit with non-zero code `1` if any finding meets or exceeds this severity (`critical`, `high`, `medium`, `low`, `info`). Defaults to `""` (exit `0`).
- `--gtfobins-path <string>`: Path to a custom `gtfobins.json` database file.
- `--cvtsudoers-path <string>`: Path to a custom `cvtsudoers` binary.

### System-Specific Flags
- `--sudoers-file <string>`: Path to target sudoers file (default `"/etc/sudoers"`).

---

## Developer Guide
For codebase architecture details, cross-compilation configurations, and test setup, please refer to [AGENTS.md](AGENTS.md).
