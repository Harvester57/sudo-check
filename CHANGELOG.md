# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-10-17

### Added
- Native Go `sudoers` configuration parser (`pkg/parser`) supporting `#include`/`#includedir` and `@include`/`@includedir`, global and scoped `Defaults`, `User_Alias`/`Runas_Alias`/`Host_Alias`/`Cmnd_Alias`, `User_Spec` rules, tags, digests, and source file/line tracking without requiring `cvtsudoers`.
- Full parity with `cvtsudoers -f json` schema, including pre-tag/tag/post-tag option ordering, `cmndspec_continues` command merging rules, ASN.1 `GeneralizedTime` UTC normalization (`NOTBEFORE`/`NOTAFTER`), POSIX ERE regular expression command/argument handling, and duplicate digest key unmarshaling (`DigestList`).
- Real-world 105-file `sudoers` test corpus (`testdata/corpus/`) covering Linux/BSD/macOS distributions, upstream `sudo` regression suites, and enterprise/cloud policies, validated via differential oracle and stress tests against `cvtsudoers`.
- Expanded defaults audit rules (`SUDO-DEF-001` through `SUDO-DEF-016`) using last-match-wins sequential reduction across global and scoped `Defaults` (`env_reset`, `env_keep`, `env_check`, `use_pty`, `requiretty`, `noexec`, `umask`, `ignore_dot`, `timestamp_timeout`, `passwd_tries`, `log_input`/`log_output`, `mail_badpass`, `authenticate`, `visiblepw`, `rootpw`/`targetpw`/`runaspw`, and `insults`).
- Expanded command and privilege escalation audit rules (`SUDO-CMD-001` through `SUDO-CMD-012`, `SUDO-GTFO-001` through `SUDO-GTFO-003`) covering `ALL` commands, wildcards, negation bypasses, `NOPASSWD`, missing argument restrictions, `SETENV`, `sudoedit` path traversal/wildcard risks, UID `-1` (`CVE-2019-14287`), privileged group execution, writable binary paths, and missing SHA-2 command digests.
- Enhanced GTFObins database loader (`pkg/gtfobins`) with alias/inheritance (`from`) resolution, versioned binary name normalization, function-level consolidation per `(rule, binary, function)`, and accurate `noexec` mitigation scoping.
- Expanded live system and CVE checks (`pkg/audit/rules_system.go`) covering `sudo` version vulnerability ranges (`CVE-2021-3156`, `CVE-2023-22809`, `CVE-2023-42465`, `CVE-2025-32462`, `CVE-2025-32463`), `/etc/sudoers` and `/etc/sudoers.d` ownership/permissions, world/group-writable permitted binaries, and `PATH` directory permissions.
- Deterministic, copy-pasteable `RemediationCode` snippets and separated `ExploitPoC` references across all policy and system findings.
- Redesigned self-contained HTML report (`pkg/report/html.go`) featuring interactive multi-file, rule, and principal triage panels, pseudo-sudoers rule previews, dark/light theme support, client-side filtering, and deferred rendering (`content-visibility: auto`).
- Enriched Text, JSON, SARIF v2.1.0, and PDF report formatters with dedicated remediation code and exploit reference sections.

### Fixed
- Deduplicated included drop-in files during directory scans (`sudo-check scan <dir>`) when both a root `sudoers` file and `#includedir` drop-ins are present, while still auditing standalone `.sudoers` files.
- Preserved exact per-file `Finding.Context` attribution across `#include` and `#includedir` directives.
- Preferred local `baseDir` candidates over host `/etc` paths when resolving `/etc/...` includes during offline directory scans.

## [0.0.2] - 2026-09-28

### Added
- Added ANSSI-BP-028 compliance control checks for `sudoers` policies.

### Changed
- Updated GitHub Actions workflow dependencies (`actions/checkout`, `actions/setup-go`, `sbomify/sbomify-action`) and Dependabot schedule configuration.

## [0.0.1] - 2026-06-13

### Added
- Initial release of `sudo-check` CLI (`scan`, `system`, `update-db`, `version` commands).
- Policy auditing via `cvtsudoers` JSON wrapper and embedded GTFObins database.
- Multi-format reporting (Text, JSON, SARIF, HTML, and PDF).
- GitHub Actions CI/CD pipeline with cross-platform binary matrix builds (`linux/amd64`, `linux/arm64`, `windows/amd64`) and CycloneDX SBOM generation.

[0.1.0]: https://github.com/Harvester57/sudo-check/compare/v0.0.2...v0.1.0
[0.0.2]: https://github.com/Harvester57/sudo-check/compare/v0.0.1...v0.0.2
[0.0.1]: https://github.com/Harvester57/sudo-check/releases/tag/v0.0.1
