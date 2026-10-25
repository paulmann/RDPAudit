# Troubleshooting

This guide covers the common failures we've seen during Stage 10 release-readiness testing and
how to resolve each one. Symptoms are written first so you can grep for the exact message you
see in the Configurator or the service log.

## 1. ProgramData ACL is wrong

**Symptom.** Service refuses to start. Event Log: `Access to the path
'C:\\ProgramData\\RdpAudit\\rdpaudit.db' is denied.`

**Cause.** The Configurator's first-run flow normally hardens
`%ProgramData%\RdpAudit\` to SYSTEM + BUILTIN\Administrators only. If the folder was
created out-of-band (e.g. an admin manually copied the binaries), inherited ACLs may
leave the directory readable by Users / Authenticated Users.

**Fix.**

```powershell
icacls "$env:ProgramData\RdpAudit" /inheritance:r `
    /grant:r "*S-1-5-18:(OI)(CI)F" `        # NT AUTHORITY\SYSTEM
    "*S-1-5-32-544:(OI)(CI)F"               # BUILTIN\Administrators
```

Then restart the service from the Configurator's Service tab.

## 2. `sc.exe` exit 1639 during install

**Symptom.** Service tab → Install fails with `sc.exe exit 1639` and the message
"Invalid command-line."

**Cause.** Historical regression where the install command embedded the binary path with
unescaped spaces. Fixed in commit `1b6c63c` (see `git log -- src/RdpAudit.Configurator/Services/InstallationService.cs`).

**Fix.** Ensure the Configurator is the published `RdpAudit.Configurator.exe` (>= Stage 1
fix) and not an older binary. The fixed code uses `ProcessStartInfo.ArgumentList` so spaces
are escaped automatically; nothing is concatenated into a shell string.

## 3. `publish.ps1` reports locked files

**Symptom.** `publish.ps1` aborts with `Cannot remove publish\Service — files are in use`.

**Cause.** A previous Configurator or Service process is still running and holding a
handle to a file inside `publish\`. The script's locked-file detector lists the responsible
PID(s) and executable paths in the diagnostics block.

**Fix.** Stop the named processes, then re-run. Typical commands:

```powershell
Get-Process RdpAudit.Configurator,RdpAudit.Service -ErrorAction SilentlyContinue | Stop-Process
./publish.ps1
```

For locked files outside this product (e.g. an open File Explorer preview), the
diagnostics block will list them under "Inspection failures" rather than "Blockers" —
those are advisory and the script will proceed once you close the inspecting process.

## 4. Audit policy "Current" column shows `?`

**Symptom.** Audit Policy tab refreshes but every subcategory's Current state is `?`.

**Cause.** Either `auditpol.exe` is unavailable in PATH (rare — only on stripped Server
Core installs) or the parser failed to map the localised "Inclusion Setting" column.

**Fix.** Confirm `auditpol /get /subcategory:*` works from an elevated prompt. If it does,
the parser falls back to `AuditQuerySystemPolicy` via `[LibraryImport]`; verify that
`advapi32.dll` exports both `AuditQuerySystemPolicy` and `AuditFree`. The fallback handles
en/ru/de/fr/es Windows builds — file a bug if your locale's "Success and Failure" wording
doesn't match.

## 5. Firewall provider unavailable

**Symptom.** Firewall tab status reads `Windows: Unavailable` or `MikroTik: NotConfigured`.

**Causes & fixes.**

* **Windows provider unavailable** — the Windows Firewall service (`MpsSvc`) is not
  running. Start it: `Start-Service MpsSvc`.
* **MikroTik NotConfigured** — no host or no protected password is set. Open the MikroTik
  tab and Save the settings.
* **MikroTik Unavailable** — TLS / cert / DNS failure. See section 7 below.

## 6. AbuseIPDB returns HTTP 429

**Symptom.** Status strip shows `AbuseIPDB rate limited (HTTP 429) — backing off`.

**Cause.** AbuseIPDB enforces per-IP rate limits and the local dedup window must respect
their 15-minutes-per-IP report rule. The client surfaces 429 without retrying so it never
amplifies the rate-limit violation.

**Fix.** Either wait for the API window to clear or tighten the local `MinThreatScore`
and `MinFailedAttempts` so fewer rows qualify. The local dedup window is enforced via the
`AbuseReports` table — bumping `DeduplicationWindowMinutes` further reduces churn.

## 7. MikroTik TLS / certificate / auth failures

**Symptom.** Test connection shows one of:

* `MikroTik: TLS handshake failed (RemoteCertificateNameMismatch)`
* `MikroTik: authentication failed (HTTP 401)`
* `MikroTik: connection refused` / `host unreachable`

**Causes & fixes.**

* **`RemoteCertificateNameMismatch` / `UntrustedRoot`.** The router's certificate isn't
  trusted by the Windows store. Either install the router's certificate into
  `LocalMachine\Root`, or — only if you've assessed the risk — uncheck
  `ValidateServerCertificate`. The service logs a WARN entry when validation is disabled
  so the operator action is auditable.
* **HTTP 401.** Username or password is wrong. The Configurator never echoes the
  plaintext; Save the credentials again. Confirm that the dedicated `rdpaudit` RouterOS
  user has at least `read,write,api,policy` permissions on `/ip/firewall/filter`.
* **Connection refused.** REST is disabled on the router (`/ip service print` should show
  `www-ssl` enabled and listening on the configured port). If you're behind a NAT,
  confirm the firewall on the router itself permits the Configurator host on the chosen
  port.

## 8. Service hangs at shutdown

**Symptom.** `Stop-Service RdpAudit` blocks for 30 s then reports a timeout.

**Cause.** A long-running worker (typically `MaintenanceWorker` doing a vacuum or an
`AbuseIpDbReportWorker` doing an HTTP call) hasn't observed the cancellation token yet.

**Fix.** No action required — the hosting infrastructure forces a stop after the host
shutdown timeout. If you see this repeatedly, file a bug with the matching service log
window so the offending worker can be identified.

## 9. `publish.ps1` fails the parser self-check

**Symptom.** `Self-test FAILED (1 failure(s))` with a parser error pointing at a recent
edit.

**Fix.** Run `pwsh -NoProfile -Command "$tokens=$null;$errors=$null;[System.Management.Automation.Language.Parser]::ParseFile('publish.ps1',[ref]$tokens,[ref]$errors); $errors"`
to see the exact diagnostics. The self-check is intentionally pedantic so syntax bugs in
unreachable branches still surface.

## 10. Configurator cannot find the Service distribution

**Symptom.** Overview tab shows `Service distribution: not found alongside the Configurator`.

**Cause.** The Configurator looks for a sibling `..\Service\RdpAudit.Service.exe` next to
its own executable. If you copied only one of the two folders, sibling discovery fails.

**Fix.** Either keep both `Service` and `Configurator` folders side by side under the same
parent (`...\RdpAudit\Service\` and `...\RdpAudit\Configurator\`) or use the Configurator's
"Browse..." control to point at an explicit Service location. The published layout from
`publish.ps1` is the canonical reference.

## 11. Service exits immediately with code 0x1000 (already running)

**Symptom.** `RdpAudit.Service.exe` starts and exits immediately. In `--console` mode
stderr shows the refusal line ending with `ExitCode=0x1000`; in service mode the SCM
shows an abrupt stop and the service log contains the structured single-instance refusal
event (`ExpectedState=Running`, `ActualState=AlreadyRunning`, `MutexName=Global\RdpAuditService`).

**Cause.** Another RdpAuditService process already owns the kernel mutex
`Global\RdpAuditService`. `Program.Main` acquires this mutex through
`SingleInstanceGuard` before building the host, so a second instance (for example a
manual `publish\Service\RdpAudit.Service.exe --console` while the Windows service is
running) is refused with the project exit code `0x1000`.

**Fix.** Stop the running instance first:

```powershell
Get-Process RdpAudit.Service -ErrorAction SilentlyContinue | Stop-Process
# or, for the installed service:
Stop-Service RdpAudit
```

Then start the desired instance (service or console). `0x1000` is intentional, not a
crash: it is outside the `0..255` process-error range and distinct from Win32 code `2`
and the host-fault exit code `1`. If the code still appears with no other process
visible, a stale abandoned mutex from a crashed process is normally recovered as
`RecoveredAbandoned`; when recovery is not possible, restart the session or reboot to
release the kernel object.

## 12. Shard batches dropped with EventID 7013

**Symptom.** The Windows Event Log records `EventID 7013` (the generic .NET
host-lifecycle fault) shortly after events are ingested, and the per-IP
forensic shard files under the actions root stop receiving records while
`RawEvents` keeps growing. In older builds the exception text read
"BeginTransaction requires an open connection" or named a closed SQLite
connection.

**Cause.** The shard flush ran on the same `SqliteConnection` that EF Core
owned for the main `RawEvents` transaction. EF Core closes that connection
together with the disposed transaction, so any shard `BeginTransaction` after
the main commit threw and silently dropped the shard batch. In v2.3.4 the
shard phase was further hardened: it now runs OUTSIDE the main commit's
try/catch, so a shard failure could no longer roll back already-committed
`RawEvents` or discard the pending queue.

**Fix.** Confirm the installed service binary is v2.3.4 or newer
(Service tab -> Runtime version). In v2.3.4+:

* Shard rows are written on a dedicated live `SqliteConnection` with the same
  WAL/NORMAL pragmas and bounded `SQLITE_BUSY` / `SQLITE_LOCKED` retries.
* `ShardIngestionSink.CommitAsync()` is a true durability boundary: the
  pending queue is cleared and the writer pool trimmed only after the whole
  batch succeeds. A failure inside the batch retains the queue, and the next
  successful flush recovers it.
* Cancellation during the shard phase keeps both the committed `RawEvents`
  and the pending shard queue.

If shard files still do not grow on >= v2.3.4, check
`ServiceMetrics.ShardWriteFailures` in the Diagnostics tab: a saturated shard
file budget shows the `Shard file budget reached` warning, while repeated
`SQLITE_BUSY` retries followed by a Warning in the service log point at
long-running writers on the audit database.

---

## 13. Repeated `IpcServerWorker` ExecuteAsync entries in one PID

**Symptom.** `%ProgramData%\RdpAudit\logs\ipc-startup.log` shows more than one
`ExecuteAsync entered` line for the same PID (`entry=2` / `entry=3`), or several
`instance constructed` lines with different `instanceId` values.

**Cause.** Either one worker instance was started more than once, or more than one
worker / host instance was created in the same process.

**Diagnosis.** In v2.3.5+ each `IpcServerWorker` carries a stable `Guid instanceId`
and writes `instance constructed` / `ExecuteAsync entered` / `ExecuteAsync exiting`
to `ipc-startup.log`. Read the log alongside the process list:

```powershell
Get-CimInstance Win32_Process -Filter "Name='RdpAudit.Service.exe'" | Select ProcessId, CommandLine
Get-Content "$env:ProgramData\RdpAudit\logs\ipc-startup.log" -Tail 30
```

- Repeated `entered` lines with the same `instanceId` (entry=2/3) mean one worker
  instance was started more than once.
- Multiple distinct `instanceId` values mean more than one worker or host instance
  was created.

**Fix.** If the symptom persists, the installed binary may not match the current
source: compare the SHA-256 of the deployed `RdpAudit.Service.exe` against the
published build and confirm the running `CommandLine` points inside
`%ProgramFiles%\RdpAudit\Service`. Restart the service
(`Restart-Service RdpAudit`) and verify the log shows one `instance constructed`,
one `entered ... entry=1`, and one `exiting ... exitReason=HostStop,
hostApplicationStoppingCancelled=True`.

---

## 14. `SQLite Error 6: 'database table is locked'` while the service is ingesting

**Symptom.** `C:\ProgramData\RdpAudit\logs\service-*.log` contains repeated

```
SQLite Error 6: 'database table is locked: RawEvents'
```

next to `Persist batch of {Count} failed`, `Retention pass failed` or
`Shard DB busy`. The service keeps running, but a failed batch is dropped from the ring buffer and
its bookmark is rolled back, so those events reappear only after a restart or a backfill.

**Cause (measured 2026-10-23 on 192.168.1.50, 2.6 GB store).** Every connection was opened with
`Cache=Shared`. In shared-cache mode SQLite hands the second writer `SQLITE_LOCKED` (code 6)
*immediately* and never consults the busy handler, so writer-versus-writer contention - the event
processor against a retention or maintenance pass - became a hard failure instead of a short wait.
Two further defects made it worse: the bounded retry filtered on `SqliteException` while EF Core
wraps save failures in `DbUpdateException` (zero retries in four days of logs), and the write PRAGMA
interceptor also ran on EF's read-only existence probe.

Sandbox measurement with the shipped `e_sqlite3`, two connections, one write transaction open:

| Connection string | Second writer | Waited |
|---|---|---|
| `Cache=Shared`, `busy_timeout=0` | code 6 `database table is locked` | 2 ms |
| `Cache=Shared`, `busy_timeout=2000` | code 6 `database table is locked` | 0 ms |
| private cache, WAL, `busy_timeout=2000` | code 5 `database is locked` | 2206 ms |

**Fix (2.0.2).** `AuditDbContextOptionsFactory` no longer emits `Cache=Shared`: the write connection
is `Data Source=...;Default Timeout=30`, the read-only one `Mode=ReadOnly;Default Timeout=5`.
`SqliteTransientErrors.IsTransient` walks the exception chain so the bounded retry also fires on the
EF wrapper, and `SqlitePragmaInterceptor` applies only connection-local PRAGMAs on the read-only
probe. WAL already isolates readers from the writer, so the private cache costs nothing but memory
per connection.

**Verification.** After the upgrade:

```powershell
Select-String -Path 'C:\ProgramData\RdpAudit\logs\service-*.log' -Pattern 'table is locked'
```

must return nothing for the new day's file, `RawEvents` must keep growing, and the Database tab must
report `journal_mode = wal`. If the error survives, the binary is still the old one - check
Service -> Runtime version for `2.0.2+`.

If a problem doesn't appear here, open a GitHub issue with:

1. The Configurator's full status-strip line.
2. The matching block from `%ProgramData%\RdpAudit\logs\service-*.log` (redact secrets if
   any survived — they shouldn't).
3. The output of `./publish.ps1 -SelfTest` so we can rule out a publish-script regression.
