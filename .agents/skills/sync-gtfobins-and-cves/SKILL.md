---
name: sync-gtfobins-and-cves
description: >-
  Update the embedded GTFObins database snapshot (pkg/gtfobins/database.json) and
  sudo CVE vulnerability ranges (pkg/audit/rules_system.go). Use when asked to
  refresh GTFObins data, check for new sudo CVEs, or update binary normalization mappings.
---

# Syncing GTFObins & Sudo CVEs

## 1. Refresh the Embedded GTFObins Database
1. Fetch the latest catalog directly into the embedded database path:
   ```powershell
   go run . update-db -p pkg/gtfobins/database.json
   ```
2. Verify that `pkg/gtfobins/database.json` is valid JSON and non-empty.
3. Run the GTFObins test suite to confirm all `alias` and `inherit` (`from`) chains
   resolve cleanly and findings remain consolidated to one per `(binary, function)`:
   ```powershell
   go test -v -cover ./pkg/gtfobins/...
   ```
4. If new multi-version binaries or distribution alternative names were added, update
   `binaryAliases` or `versionedPrefixes` in `pkg/gtfobins/client.go`.

## 2. Update Sudo CVE Ranges (`pkg/audit/rules_system.go`)
1. Review advisories at `https://www.sudo.ws/security/advisories/`.
2. In `AuditSudoVersion(versionStr string)` in `pkg/audit/rules_system.go`:
   - Use `Version.Compare(minVer) >= 0 && Version.Compare(maxVer) <= 0` for inclusive
     affected ranges, or `< fixedVer` for open-ended lower ranges.
   - Keep distinct CVEs in separate checks with accurate affected version bounds and
     remediation versions.
3. Add boundary unit tests in `pkg/audit/auditor_test.go` testing:
   - The first vulnerable version
   - The last vulnerable version
   - The first patched version (asserting the CVE is NOT reported)
