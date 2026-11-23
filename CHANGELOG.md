# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **New CLI Commands (`explain`, `diff`, `merge`)**: Simulate `sudoers(5)` policy evaluation for a target principal, diff policies or JSON reports by finding fingerprint, and aggregate multi-host reports into fleet HTML, CSV, and JSON summaries.
- **Additional Input Formats**: Added `sudo -ll`/`sudo -l` and RFC 2849 LDIF (`sudoRole`) parsers with automatic format detection and stdin (`-`) support.
- **Expanded Policy & Host Rules**: Added SELinux context elevation (`SUDO-CMD-013`, DISA STIG `V-272484`), directory execution (`SUDO-CMD-014`), rule shadowing (`SUDO-CMD-015`), validity window expiry (`SUDO-CMD-016`), new `Defaults` rules (`SUDO-DEF-017`–`018`), wrapper script static analysis (`SUDO-SYS-SCRIPT-001`–`003`), dedicated sudo group and passwd/group checks (`SUDO-SYS-PERM-014`, `SUDO-SYS-ID-001`), backport detection, and CVE policy correlation.
- **Config, Profiles & Suppressions**: Added `.sudo-check.yaml`/`.sudo-check.json` configuration, compliance profiles (`anssi-bp028`, `cis-5.2`, `disa-stig`, `minimal`), expiring suppressions, `--baseline` diffing, and `--dropin` mode.
- **Hardening Patch Generator (`--fix-patch`)**: Added `visudo`-verified unified diff generation for raw `sudoers` files.
- **GTFObins Enhancements**: Added custom overlay catalogs (`--custom-gtfobins`), `--subcommand-aware` scoring, alias/inheritance resolution, and consolidated per-`(binary, function)` findings.
- **Packaging & CI**: Added rootless `Dockerfile`, hardened GHCR release workflow (SBOM, attestations, Trivy scans), composite GitHub Action (`action.yml`), `LICENSE`, `THIRD_PARTY_NOTICES.md`, and new fuzz targets (`FuzzAuditJSONPolicy`, `FuzzParseSudoVersion`) with parallel CI jobs.

### Changed
- **Report Redesign**: Redesigned HTML, PDF, SARIF, and text reports with golden-file test coverage.
- **Go Toolchain & Dependencies**: Bumped minimum Go version in `go.mod` to `1.27.4` (including the `GO-2026-6809` fix) and updated Go and GitHub Actions dependencies.

### Fixed
- **Parser & Patch Edge Cases**: Fixed a trailing-backslash slice-bounds panic (found by `FuzzParseString`), Linux `includedir` isolation, wrapped `ErrPermission` checks, and Windows drive-letter stripping.
- **`cvtsudoers` Compatibility**: Treated empty `cvtsudoers` stdout as an empty policy and added Ubuntu 26.04 `cvtsudoers.ws` and unresolved alias normalization support.
- **CVE-2021-3156 Affected Range**: Added the missing `1.7.7`–`1.7.10p9` branch to the Baron Samedit version check.
- **Compliance Reference Mappings**: Audited and corrected **ANSSI BP-028** (v2.0 R38–R44), **DISA STIG** (`SV-230271`/`SV-230272`/`SV-237643`), and **CIS Linux Benchmark** (section 5.2) IDs, verbatim text, and rule tags, removing unsupported references.

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
