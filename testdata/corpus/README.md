# Real-World Sudoers Stress-Test Corpus

This directory contains **105 real-world `sudoers` configuration files** collected from official operating system distribution repositories, the upstream `sudo-project/sudo` regression suite, and production enterprise, cloud, DevOps, and security hardening repositories.

It is used by [`pkg/parser/corpus_test.go`](../../pkg/parser/corpus_test.go) and [`cmd/cmd_test.go`](../../cmd/cmd_test.go) for differential oracle testing (`parser.ParseString` / `parser.ParseFile` vs `cvtsudoers -f json`), downstream `audit.RunAudit` parity verification, negative syntax-error testing, and multi-format report stress testing (`text`, `json`, `sarif`, `html`, `pdf`).

---

## Corpus Structure (105 Files)

### 1. `distros/` (14 Official OS Distribution Default `sudoers` Files)
Verbatim `/etc/sudoers` configurations shipped by major Linux, BSD, and macOS distributions:
- `upstream_default_sudoers.sudoers` — Upstream `sudo-project/sudo` (`examples/sudoers.in`)
- `upstream_examples_sudoers.sudoers` — Upstream `sudo-project/sudo` (`examples/sudoers`)
- `debian_sudoers.sudoers` — Debian GNU/Linux (`salsa.debian.org/sudo-team/sudo`)
- `ubuntu_sudoers.sudoers` — Ubuntu Linux (`git.launchpad.net/ubuntu/+source/sudo`)
- `fedora_sudoers.sudoers` — Fedora Linux (`src.fedoraproject.org/rpms/sudo`)
- `centos9_sudoers.sudoers` — CentOS Stream 9 / RHEL 9 (`gitlab.com/redhat/centos-stream/rpms/sudo`)
- `centos10_sudoers.sudoers` — CentOS Stream 10 / RHEL 10 (`gitlab.com/redhat/centos-stream/rpms/sudo`)
- `archlinux_sudoers.sudoers` — Arch Linux (`gitlab.archlinux.org/archlinux/packaging/packages/sudo`)
- `opensuse_sudoers.sudoers` — openSUSE Factory (`build.opensuse.org/package/show/Base:System/sudo`)
- `gentoo_sudoers.sudoers` — Gentoo Linux (`gitweb.gentoo.org/repo/gentoo.git/tree/app-admin/sudo`)
- `freebsd_sudoers.sudoers` — FreeBSD Ports (`cgit.freebsd.org/ports/tree/security/sudo`)
- `openbsd_sudoers.sudoers` — OpenBSD Ports (`cvsweb.openbsd.org/ports/security/sudo`)
- `macos_sudoers.sudoers` — Apple macOS Darwin (`apple-oss-distributions/sudo`)
- `nixos_sudoers.sudoers` — NixOS generated `/etc/sudoers` (`NixOS/nixpkgs`)

### 2. `upstream_regress/` (33 Valid Upstream `sudo-project/sudo` Regression Test Files)
Verbatim parser, lexer, `cvtsudoers`, and `visudo` regression inputs from `plugins/sudoers/regress/` in `sudo-project/sudo`:
- `sudoers_test01.sudoers` — Multi-clause `User_Alias`, `Runas_Alias`, `Host_Alias`, `Cmnd_Alias`, and complex multi-host rules
- `sudoers_test02.sudoers` — Quoted usernames, quoted `%group` / `%:non-Unix group` / `+netgroup`, escaped quotes, and unescaped quotes in command paths
- `sudoers_test03.sudoers` — Comprehensive `Defaults` and `User_Spec` grammar stress test
- `sudoers_test06.sudoers` — Quoted and unquoted `#uid` and `%#gid` in `Defaults` and `Cmnd_Spec` (`(#0 : #0)`)
- `sudoers_test09.sudoers` & `sudoers_test10.sudoers` — Empty and whitespace-only `sudoers` files
- `sudoers_test14.sudoers` — Single and multi-digest (`sha224`, `sha256`, `sha384`, `sha512`) command aliases and `ALL` rules
- `sudoers_test15.sudoers` & `sudoers_test16.sudoers` — Backslash line continuations inside aliases and comments
- `sudoers_test17.sudoers` — `Defaults command_timeout` and per-command `TIMEOUT=` specifications (`7d4h10m30s`, `TIMEOUT=0`)
- `sudoers_test19.sudoers` — ASN.1 GeneralizedTime `NOTBEFORE=` and `NOTAFTER=` timestamps with fractional hours/minutes/seconds and timezone offsets
- `sudoers_test20.sudoers` through `sudoers_test23.sudoers` — Domain-qualified hostnames, netgroups, and command argument edge cases
- `sudoers_test24.sudoers` — Quoted and unquoted `CHROOT=` and `CWD=` per-command options and `Defaults runcwd` / `runchroot`
- `sudoers_test26.sudoers` — Exhaustive ~130-entry `Defaults` table test covering every `sudo_defs_table` flag, integer, string, mode, and list option
- `sudoers_test27.sudoers` — `sudoedit` and ` Cmnd_Alias` combinations
- `sudoers_test28.sudoers` — POSIX ERE regular expression commands and arguments (`^...$`) and `Defaults passprompt_regex`
- `sudoers_test30.sudoers` — Digest list variations
- `sudoers_test31.sudoers` — SELinux (`ROLE=`, `TYPE=`), AppArmor (`APPARMOR_PROFILE=`), and Solaris privilege (`PRIVS=`, `LIMITPRIVS=`) per-command options
- `cvtsudoers_sudoers*.sudoers`, `cvtsudoers_test*.sudoers`, `visudo_test*.sudoers` — Upstream `cvtsudoers` and `visudo` regression inputs (including local-timezone `NOTBEFORE` timestamps, empty `()` runas specs, and unused alias resolution)

### 3. `upstream_regress_invalid/` (10 Negative Syntax-Error Regression Test Files)
Upstream `sudo-project/sudo` negative test cases verified to produce syntax errors in `ParseString` and `ParseFile`:
- `sudoers_test04_invalid.sudoers` — Invalid line continuation merging two `User_Alias` definitions without separator
- `sudoers_test05_invalid.sudoers` — Empty string `""` in `User_Alias` and `User_Spec` user list
- `sudoers_test07_invalid.sudoers` — Empty group (`"%"`, `"%:"`) and netgroup (`"+"`) specifiers
- `sudoers_test08_invalid.sudoers` — Unescaped quotes in unquoted tokens (`x\"y`) and unterminated string literals
- `sudoers_test11_invalid.sudoers` — Bare word missing `=`
- `sudoers_test12_invalid.sudoers` & `sudoers_test13_invalid.sudoers` — Missing command after `(ALL)` Runas_Spec
- `sudoers_test18_invalid.sudoers` — Malformed `command_timeout` and `TIMEOUT=` unit strings (`59ss`, `15f`, `7dd`)
- `sudoers_test25_invalid.sudoers` — Trailing `\` continuation character at EOF with nothing to continue
- `sudoers_test29_invalid.sudoers` — Unterminated regular expressions (`^` without closing unescaped `$`)

### 4. `enterprise_cloud/` (48 Real-World Production, Cloud, DevOps & Hardening Files)
Real production `sudoers` and `sudoers.d` policies across 5 operational domains:
- **OpenStack & Cloud Infrastructure** (`01`–`09`): OpenStack Kolla base, Nova compute, Neutron networking, Cinder storage, Etcd, Fluentd, Grafana, MariaDB, and Cyborg accelerator service policies.
- **Monitoring & Backup Systems** (`10`–`17`): Nagios/NRPE (GlusterFS/OpenvSwitch, OVHcloud The Bastion, 389 Directory Server Icinga), Zabbix (smartctl, 1C Enterprise cluster, PM2, agent extensions), Checkmk agent, BackupPC, OpenStreetMap France BackupPC, Veeam Backup & Replication for Proxmox VE (KB4701 with regex arguments), phpBorg, and Borgmatic.
- **Enterprise Databases & Middleware** (`18`–`23`): PostgreSQL HA (Patroni, Pgpool-II, repmgr), SAP HANA System Replication (`SAPHanaSR`), Oracle Grid Infrastructure / RAC 11g/12c, Oracle Enterprise Manager 13c host provisioning, Oracle Puppet `ora_cis` verification, and Foreman Smart Proxy.
- **Virtualization, CI/CD & Cloud Provisioning** (`24`–`31`): HashiCorp Vagrant (macOS NFS/SMB, Linux Fedora/Ubuntu NFS, Ion Torrent TSVM), Canonical `cloud-init`, Terraform Proxmox Provider, GitLab CI Runner, and Jenkins CI/CD deployment policies.
- **Corporate Multi-Team & Security Benchmarks** (`32`–`48`): Symantec multi-team corporate `sudoers`, `drduh` hardened sysadmin policy, EAS Station & StorijOS appliance policies, RHEL 8/9 DISA STIG ISSO policy, Microsoft Azure Linux CIS benchmark, and ANSSI BP-028 (`Pavois`) hardened `sudoers`.
