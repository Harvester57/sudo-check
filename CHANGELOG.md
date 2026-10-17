# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-10-17

### Added
- Native Go `sudoers` configuration parser (`pkg/parser`) supporting `#include`/`#includedir` and `@include`/`@includedir`, global and scoped `Defaults`, `User_Alias`/`Runas_Alias`/`Host_Alias`/`Cmnd_Alias`, `User_Spec` rules, tags, digests, and source file/line tracking without requiring `cvtsudoers`.
- Full parity with `cvtsudoers -f json` schema, including pre-tag/tag/post-tag option ordering, `cmndspec_continues` command merging rules, ASN.1 `GeneralizedTime` UTC normalization (`NOTBEFORE`/`NOTAFTER`), POSIX ERE regular expression command/argument handling, and duplicate digest key unmarshaling (`DigestList`).
- Real-world 105-file `sudoers` test corpus (`testdata/corpus/`) covering Linux/BSD/macOS distributions, upstream `sudo` regression suites, and enterprise/cloud policies, validated via differential oracle and stress tests against `cvtsudoers`.
- Expanded defaults audit rules (`SUDO-DEF-001` through `SUDO-DEF-016`) using last-match-wins sequential reduction across global and scoped `Defaults` (`secure_path`, `use_pty`, `env_keep`/`env_check`/`env_delete`, `visiblepw`, `pwfeedback`, `noexec`, `requiretty`, `umask`, `ignore_dot`, `env_reset`, `!authenticate`, `setenv`, `sudoedit_follow`/`!sudoedit_checkdir`, `timestamp_timeout`/`passwd_timeout`/`timestamp_type=global`, and `runchroot`/`runcwd=*`).
- Expanded command and privilege escalation audit rules (`SUDO-CMD-001` through `SUDO-CMD-012`, `SUDO-GTFO-001` through `SUDO-GTFO-003`) covering negated commands (`!cmd`), `ALL` privileges (`PASSWD` and `NOPASSWD`), wildcards, passwordless specific commands, missing argument restrictions, direct text editor execution, negated `User`/`Host`/`Runas` specifications, per-command `SETENV`/`FOLLOW`/`CHROOT`/`CWD=*` overrides, sensitive `sudoedit` targets, relative or user-writable/temporary command paths, and weak `sha224` digests.
- Enhanced GTFObins database loader (`pkg/gtfobins`) with alias/inheritance (`from`) resolution, versioned binary name normalization, function-level consolidation per `(rule, binary, function)`, and accurate `noexec` mitigation scoping.
- Expanded live system and CVE checks (`pkg/audit/rules_system.go`) covering `sudo` version vulnerability ranges (`CVE-2019-14287`, `CVE-2019-18634`, `CVE-2021-3156`, `CVE-2022-43995`, `CVE-2023-22809`, `CVE-2023-27320`, `CVE-2025-32462`, `CVE-2025-32463`), `/etc/sudoers` and `/etc/sudoers.d` ownership/permissions (`SUDO-SYS-PERM-001` through `SUDO-SYS-PERM-011`), `sudo` binary SUID bit and ownership, and permitted target binary and parent directory write permissions (`SUDO-SYS-PERM-012`, `SUDO-SYS-PERM-013`).
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
