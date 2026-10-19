# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
