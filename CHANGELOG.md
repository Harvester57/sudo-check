# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed
- **Go Toolchain**: Bumped minimum Go version in `go.mod` to `1.27.3` to resolve GO-2026-6809 (distrust of compromised intermediate certificates in `crypto/x509`, fixed in Go 1.26.10) and updated all dependencies (`github.com/spf13/pflag` to `v1.0.10`).

### Added
- **New Fuzzing Targets (`FuzzAuditJSONPolicy`, `FuzzParseSudoVersion`)**: Added two fuzz targets in `pkg/audit` alongside the existing `FuzzParseString`. `FuzzAuditJSONPolicy` exercises the `cvtsudoers` JSON policy ingestion path used by `scan` (arbitrary JSON unmarshaled into `SudoersPolicy`, then `RunAudit`) with hostile shapes the native parser never emits — duplicate digest keys, single-string vs array `DigestList` values, nil pointer members, and malformed `Options` — enforcing JSON round-trip idempotency. `FuzzParseSudoVersion` verifies `ParseSudoVersion`/`AuditSudoVersion` on arbitrary version strings and checks that `SudoVersion.Compare` is reflexive and antisymmetric against the fixed CVE boundary versions. The scheduled fuzzing workflow now runs all three targets as a parallel job matrix with per-target corpus caches and per-target crash artifacts, and the 189 inputs generated during local smoke runs are committed as permanent regression seeds under `pkg/audit/testdata/fuzz/`.
- **SELinux Context Elevation Check (`SUDO-CMD-013`)**: New `INFO`-severity command rule implementing DISA STIG V-272484 / RHEL-08-010455 ("RHEL 8 must elevate the SELinux context when an administrator calls the sudo command"). Flags administrator-grade rules (any `ALL` command or `ALL` runas target) that do not specify both the `TYPE=sysadm_t` and `ROLE=sysadm_r` options, including partially specified elevations, with a copy-pasteable remediation directive. The DISA STIG reference catalog gained a second requirement (`stig-selinux-context`) with the verbatim STIG check and fix text, and the hardened reference template documents the required directive. On hosts not running SELinux the finding is informational and does not affect default `--fail-on` exit codes.

### Fixed
- **Parser Panic on Trailing Backslash (`GO fuzz crasher`)**: Fixed a slice-bounds panic in `readLeadingCommaList` and the command-option value scanner when a token or option value ends with a lone backslash (found by the nightly `FuzzParseString` job, crasher input `00\ =0`). A trailing backslash now consumes only itself, and such lines are rejected as syntax errors. The crasher and the 384-input generated fuzz corpus from the failing run are committed under `pkg/parser/testdata/fuzz/FuzzParseString/` as permanent regression seeds replayed by plain `go test`.
- **ANSSI BP-028 References**: Corrected every ANSSI BP-028 recommendation mapping against the official v2.0 English guide (checked in as `docs/reference/linux_configuration-en-v2.pdf`, sudo recommendations in section 6.3.1): negation bans are now correctly R42 (was R40), strict argument specifications are R43 (was R41), secure file editing via sudoedit is R44 (was R42), and R41 is the limitation of commands requiring the EXEC directive. Removed references not present in the guide (sudoers file `0440` ownership in R38, `passwd_timeout` in R39, SHA-256 digest pinning, `sudoedit_follow`/`sudoedit_checkdir`, and the nonexistent "Section 3.4.5"), replaced invented verbatim quotes with the actual guide text, and documented the v1.2 to v2.0 renumbering (v1.2 R57–R64 maps to v2.0 R38–R44 per Appendix C.3).
- **DISA STIG References**: Corrected the DISA STIG catalog entry against the published RHEL 8/9 and Ubuntu STIG findings: the sudo re-authentication requirements are SV-230271/SV-230272 (RHEL-08-010380/010381) and SV-237643 (RHEL-08-010383), not SV-230273/274/275 (which cover multifactor authentication packages, certificate status checking, and PIV credentials). Removed two claims with no STIG basis: the 0–15 minute `timestamp_timeout` window (the STIG only requires a value greater than or equal to 0; the 0–15 range comes from CIS 5.2.6) and the `timestamp_type=tty|ppid` mandate (no STIG requirement exists; the corresponding `DISA-STIG` compliance tag was removed from the `timestamp_type=global` finding).
- **CIS References**: Corrected every CIS compliance mapping against the actual CIS benchmarks (RHEL 9 v2.0.0 / Ubuntu 24.04 LTS v1.0.0, section 5.2 "Configure Privilege Escalation"): the global `!authenticate` finding is now tagged CIS 5.2.5 (re-authentication must not be disabled globally, was incorrectly 5.2.4), and CIS 5.2.4 (users must provide a password for escalation, a Level 2 control) is now only tagged on `NOPASSWD` findings. Removed fabricated CIS tags from findings with no CIS counterpart: sudoers file permission checks (5.2.1 only requires sudo to be installed), `timestamp_type` (no CIS control exists), and generic "CIS-5.2" tags on `env_reset`, `secure_path`, `setenv`, `env_keep`, `visiblepw`, and `pwfeedback` findings. Renamed the framework from the nonexistent "CIS Distribution Independent Linux Benchmark" to the correct CIS Linux Benchmarks, added the missing CIS 5.2.5 requirement to the reference catalog, corrected the CIS 5.2.4 level to 2, and replaced invented requirement text with the verbatim benchmark wording.

## [0.2.1] - 2026-10-19

### Added
- **Release Builds & CI**: Added macOS release binaries (`darwin/amd64`, `darwin/arm64`), `SHA256SUMS` release checksums, Windows CI test execution, and automated `govulncheck` vulnerability scanning.
- **HTML Report (`Rule ID` Grouping)**: Completed the shared remediation summary box when grouping findings by Rule ID, displaying a single copy-pasteable fix above all occurrences of the same rule.

### Changed
- **HTML Report Performance & Size**: Reduced generated HTML file size by ~37% and improved rendering and grouping speed on large reports via event delegation and deferred off-screen rendering.
- **Go Toolchain**: Bumped minimum Go version in `go.mod` to `1.26.9`.

### Fixed
- **HTML Report Accessibility & Contrast**: Fixed WCAG AA color contrast issues across dark and light themes, converted clickable filter pills and metric cards to native keyboard-accessible buttons, fixed HTML5 landmark structure across all tabs, and enabled browser Find-in-Page (`Ctrl+F`) to automatically expand matching rows in compact view.

## [0.2.0] - 2026-10-18

### Added
- **Three-Tab HTML Report**: Expanded the interactive HTML report into three tabs:
  - **Audit Report**: Triage dashboard with grouping by file, rule, user, or severity.
  - **Reference Frameworks**: Searchable catalog of **ANSSI BP-028** (English and French), **CIS Linux Benchmark**, **DISA STIG**, and **MITRE ATT&CK (`T1548.003`)** requirements with live violation counts.
  - **Hardened Reference Template**: Copy-pasteable zero-finding `/etc/sudoers` baseline, `/etc/sudoers.d/` drop-in example, wrapper script pattern, permission fix commands, and rule-to-standard traceability table.
- **Example Report**: Added a pre-generated sample report at `docs/example-report.html`.

## [0.1.0] - 2026-10-17

### Added
- **Built-in `sudoers` Parser**: Native Go parser for raw `/etc/sudoers` and `#includedir` drop-in files with full `cvtsudoers` JSON compatibility—no external `sudo` binary required for offline scans.
- **Expanded Policy & GTFObins Rules**: Added 16 `Defaults` rules (`SUDO-DEF-001`–`016`), 12 command rules (`SUDO-CMD-001`–`012`), and 3 GTFObins rules (`SUDO-GTFO-001`–`003`) covering wildcards, negations, missing argument restrictions, `sudoedit` targets, environment variables, and `NOEXEC` bypasses.
- **System & CVE Checks**: Added checks for 8 `sudo` CVEs (`CVE-2019-14287` through `CVE-2025-32463`) and host file/directory ownership and permission audits (`SUDO-SYS-PERM-001`–`013`).
- **Actionable Remediations & Reports**: Added copy-pasteable fix commands and exploit verification references across HTML, PDF, SARIF, JSON, and Text reports.

### Fixed
- **Directory Scans & Includes**: Avoided duplicate findings when scanning directories that contain both `/etc/sudoers` and `#includedir` drop-in files, and preserved exact file and line attribution for every finding.

## [0.0.2] - 2026-09-28

### Added
- **ANSSI BP-028 Checks**: Added compliance checks and tags based on ANSSI Linux configuration guidelines.

### Changed
- **CI Dependencies**: Updated GitHub Actions workflows and Dependabot configuration.

## [0.0.1] - 2026-06-13

### Added
- **Initial Release**: Core `sudo-check` CLI (`scan`, `system`, `update-db`, `version`) with `cvtsudoers` JSON policy auditing, embedded GTFObins detection, and Text, JSON, SARIF, HTML, and PDF report exporters.

[0.2.1]: https://github.com/Harvester57/sudo-check/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/Harvester57/sudo-check/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/Harvester57/sudo-check/compare/v0.0.2...v0.1.0
[0.0.2]: https://github.com/Harvester57/sudo-check/compare/v0.0.1...v0.0.2
[0.0.1]: https://github.com/Harvester57/sudo-check/releases/tag/v0.0.1
