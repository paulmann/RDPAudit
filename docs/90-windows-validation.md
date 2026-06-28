# Windows validation checklist (Stage 10)

This checklist captures the **manual smoke validation** that must succeed on a real Windows
host before RdpAudit v2 ships. Each step lists what to do, what to look for, and which file
or component is exercised. Linux CI cannot cover any of the items below; all of them require
a Windows 10/11 or Windows Server 2019+ machine with administrator rights.

Run from an elevated PowerShell prompt unless otherwise noted.

## 1. Build & publish

- [ ] `dotnet build RdpAudit.sln -c Release` succeeds.
- [ ] `dotnet test RdpAudit.sln -c Release` succeeds.
- [ ] `pwsh -NoProfile -File ./publish.ps1 -SelfTest` reports **Self-test PASSED**.
- [ ] `pwsh -NoProfile -File ./publish.ps1` produces `publish/Service/RdpAudit.Service.exe`
      and `publish/Configurator/RdpAudit.Configurator.exe` as sibling folders.
- [ ] No `[DllImport]` attributes appear in the build output (only `[LibraryImport]`).

## 2. Service install / start

- [ ] `Copy-Item -Recurse publish/Service "$env:ProgramFiles/RdpAudit/Service"`.
- [ ] Launch `publish/Configurator/RdpAudit.Configurator.exe`. UAC prompts for elevation.
- [ ] Overview tab shows the sibling `Service` distribution path correctly. Author /
      Contact links resolve.
- [ ] Service tab → Install: service registers without `sc.exe` exit code 1639.
- [ ] Service starts; the Configurator's status flips to `Running`.
- [ ] Event Log (`Application` channel) contains a Serilog "Service starting" entry.

## 3. Audit policy + SACL

- [ ] Audit Policy tab → Apply Recommended. Each subcategory's "Current" column updates
      after refresh (locale-independent — verified on en-US, ru-RU and de-DE).
- [ ] Prerequisites tab shows green for "Audit subcategories enforced".
- [ ] Manually run `auditpol /get /subcategory:"Logon"` and confirm Success+Failure.

## 4. Database & migrations

- [ ] `%ProgramData%\RdpAudit\rdpaudit.db` is created with mode 0600 ACL
      (`icacls` should show only NT AUTHORITY\SYSTEM and BUILTIN\Administrators).
- [ ] `dotnet ef migrations list` (from `src/RdpAudit.Service`) lists `InitialCreate`
      and `Stage2FirewallStats`; both `Applied` after first start.
- [ ] SQLite journal mode reports `wal` (verify with `sqlite3 rdpaudit.db "PRAGMA journal_mode;"`).

## 5. Live Events + context actions

- [ ] Generate a failed RDP login (e.g. `mstsc /v:localhost`, bad credentials). The Live
      Events tab shows the event within ~5 s.
- [ ] Right-click → Block IP. Confirmation dialog defaults to **No**.
- [ ] Right-click → Whitelist IP. The IP is added to `WhitelistEntries`. The follow-up
      "Also unblock?" prompt only appears if a matching block exists.
- [ ] Filtering by IP / user / event-id narrows the grid in real time.

## 6. Firewall tab

- [ ] Status panel reports the active provider (Windows / MikroTik / Both / None) and
      whether each provider is reachable.
- [ ] Blocklist add / remove from the UI applies through IPC; the service writes the
      `netsh advfirewall` rule on Windows or the REST call on MikroTik.
- [ ] Manual block of `203.0.113.99` for 1 minute disappears after the expiration worker
      fires (`Status` goes to `Removed`, no orphaned firewall rule remains).

## 7. Attack Statistics tab

- [ ] Refresh button repopulates rows; threat band colour matches `ThreatScore` thresholds.
- [ ] Min-threat / only-blocked / recent-period filters apply locally.
- [ ] Auto-refresh toggle re-renders every 5 s without re-entry.

## 8. Remote RDP Clients + shadow policy

- [ ] Remote RDP Clients tab lists active sessions parsed from `qwinsta`.
- [ ] Disconnect / Logoff dialogs default to **No** and route through IPC.
- [ ] Shadow policy tab toggles `Shadow=2` (RDS-Shadowing) and surfaces the before /
      after state. Backup snapshot is created automatically before the change.

## 9. AbuseIPDB tab

- [ ] With an empty key the tab clearly says "not configured" and never echoes the API key.
- [ ] After Save, the tab reports `***configured***` instead of the key.
- [ ] Validate key returns HTTP 200; an HTTP 429 surfaces as a friendly "rate limited"
      message in the status strip, not as a stack trace.
- [ ] Toggle Report Attacks; a synthetic high-threat row triggers a single report (verified
      via `AbuseReports` table) and respects the 15-minute dedup window.

## 10. MikroTik tab

- [ ] Enter host / port / user / password. The plaintext password is never displayed
      after Save — only `***configured***`.
- [ ] Test connection returns HTTP 200 and `RemoteVerified = true`.
- [ ] With Enable + AddAttackerRules ticked, a synthetic block produces a
      `/ip/firewall/filter` rule whose comment begins with the configured prefix
      (default `RdpAudit:`).
- [ ] Manually-added non-RdpAudit rules are never deleted by the expiration worker.
- [ ] TLS verification: disabling `ValidateServerCertificate` is logged with a WARN entry
      so operators can audit it.

## 11. Backup / Restore

- [ ] Overview → Backup creates a timestamped snapshot under
      `%ProgramData%\RdpAudit\Backups\yyyyMMdd-HHmmss\` containing `appsettings.json`,
      `audit-policy.csv`, `registry/*.reg`, `service.config.txt`, `metadata.json`.
- [ ] The `appsettings.json` copy contains DPAPI-protected envelopes (no plaintext
      secret) — confirm with `findstr /R "\\\"\\\$protected\\\"" appsettings.json`.
- [ ] Restore dialog defaults to **No**. After confirming Yes, a pre-restore snapshot
      is captured first; the event database (`rdpaudit.db`) is **not** modified.

## 12. Retention / Maintenance worker

- [ ] After 24 h (or by adjusting `StorageOptions.EventRetentionDays` down and waiting
      for the next tick), `RawEvents` older than the cutoff are removed in bounded batches.
- [ ] `AbuseReports`, removed `ActiveBlocks`, and stale `AttackStats` are pruned per
      `AbuseReportRetentionDays` / `ActiveBlockRetentionDays` / `AttackStatRetentionDays`.
- [ ] Service log shows `Maintenance complete: events=... alerts=... abuseReports=...
      activeBlocks=... attackStats=...` per pass. No `SQLITE_BUSY` exceptions surface to
      the log at WARN+ level (retries logged at WARN are expected under load).

## 13. Diagnostics

- [ ] Settings tab → Debug Mode toggles enrich the service log; secrets remain redacted
      even at Debug.
- [ ] Diagnostics export bundle never includes plaintext secrets — only the protected
      envelopes from `appsettings.json` and sanitised provider snippets.

When every box above is ticked, the build is ready for an external Windows smoke test.
