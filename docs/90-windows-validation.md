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
- [ ] `pwsh -NoProfile -File ./bench-storage.ps1 -Quick` writes `report.md`, `report.json` and
      `recommended-settings.json` outside the repository, and `%ProgramData%\RdpAudit` is unchanged
      afterwards (compare a before/after listing). See `docs/92-storage-benchmarks-and-tuning.md`.

## 1a. Automated test suite: how to run it, and how the tests stay isolated

**The commands.** Build and test at solution level, and make sure the platform is stated. This
repository produces TWO Debug trees on the same machine (`bin\Debug\...` without a platform and
`bin\x64\Debug\...` for a solution build), so a per-project command without `-p:Platform=x64`, or a
`--no-build` command pointed at the wrong tree, can answer from a stale binary - or, worse, answer
"No test matches the given testcase filter" with exit code 0 while executing nothing.

```powershell
$env:DOTNET_ROOT = 'C:\Program Files\dotnet'
dotnet build RdpAudit.sln -p:Platform=x64
dotnet test  RdpAudit.sln -p:Platform=x64                       # parallel projects (default)
dotnet test  RdpAudit.sln -p:Platform=x64 -m:1                  # one test project at a time
dotnet test  tests/RdpAudit.Service.Tests/RdpAudit.Service.Tests.csproj -p:Platform=x64
```

If `dotnet restore` fails in a given shell with `NuGet.targets(...): error : Value cannot be null.
(Parameter 'path1')`, that shell is missing environment variables NuGet reads while resolving its
machine-wide settings folder (observed in this environment; `PROGRAMDATA`/`ALLUSERSPROFILE` are not
exported there). The restore itself is not needed once `obj/project.assets.json` exists - add
`--no-restore` (never combine it with `--no-build` when a tool inspects the EF model).

**The precise cause, traced 2026-09-15.** NuGet's own
`NuGet.Common.NuGetEnvironment.GetFolderPath` does not call `Environment.GetFolderPath` for the
machine-wide folders: it reads the **environment variables** `PROGRAMDATA`, `ALLUSERSPROFILE`,
`PROGRAMFILES` and `PROGRAMFILES(X86)` directly, and a missing one makes it return null, so
`Path.Combine(null, "NuGet")` throws inside `ConfigurationDefaults`' static constructor. Exporting
those four variables fixes restore in any shell, and `bench-storage.ps1` does exactly that before it
restores. Note that the identical `Environment.GetFolderPath(SpecialFolder.CommonApplicationData)`
call works fine in the same shell - the failure is NuGet's variable lookup, not Windows' folder
resolution.

**When is `-m:1` still worth passing?** `dotnet test RdpAudit.sln` runs the test projects in
parallel, which is the command that must be trustworthy. It is, because the named-pipe tests no
longer share a name (below). `-m:1` remains useful when diagnosing resource contention rather than
isolation: the real-pipe tests measure per-connection deadlines and the Configurator page tests
measure bounded IPC timeouts, so on a saturated machine a timing assertion can fail for capacity
reasons. A failure there is a capacity signal, not a reason to make the command single-threaded
permanently. The pairing to remember is: run both modes, capture both with the loggers below, and
compare - a failure that only appears while the projects share the machine is a contention or
shared-resource finding, not a broken test.

**Capture the failing name - a summary-only log is not evidence (B26).** A run kept only as a summary
line (`Failed: 1, Passed: 181, Total: 182`), or one that ended in a hang dump, leaves the failure
unidentifiable. B26 stayed open for exactly that reason: the two runs that observed it printed summaries
without the per-test failure block, so the name was lost and the defect could not be named. Always write
a machine-readable record, and keep it until the case is closed:

```powershell
dotnet test RdpAudit.sln -p:Platform=x64 `
  --logger "trx;LogFileName=iter01.trx" `
  --logger "console;verbosity=normal" `
  --results-directory C:\rdpaudit-logs\iter01
```

- `--logger "trx;..."` writes one `<UnitTestResult>` per test case carrying the outcome, the duration
  and the failure message with its stack; `console;verbosity=normal` prints the `Failed <name> [n s]`
  line and the failure block. Keep both - the console log is what a human reads, the TRX is what a
  script can query.
- **A solution-level TRX is not per-project.** Every test project writes
  `<results-directory>/<LogFileName>`, so the projects overwrite each other and the surviving file
  belongs to whichever project finished last. For a machine-readable record of ONE project, run that
  project with its own results directory:
  `dotnet test tests/RdpAudit.Configurator.Tests/RdpAudit.Configurator.Tests.csproj -p:Platform=x64 --logger "trx;LogFileName=cfg.trx" --results-directory C:\rdpaudit-logs\cfg`.
- Where to look: in the TRX, search for `outcome="Failed"` (or sum `Total tests` / `Passed` and compare
  with the expected count); in the console log, the first `Failed <test name>` line, followed by
  `Error Message:` and the stack. A project that ran nothing reports
  `No test matches the given testcase filter` with exit code 0, so always compare the total against the
  known count.
- **A hanging test names nobody.** If a run wedges, add `--blame-hang --blame-hang-timeout 2m`: VSTest
  dumps the host under `TestResults/<guid>/` and writes a `Sequence_*.xml` next to the dump listing every
  dispatched test with `Completed="True|False"`. The single `False` entry is the test that was still in
  flight - which is how the dump left in `tests/RdpAudit.Configurator.Tests/TestResults/` is attributed to
  `DatabasePageTests.Overview_WithoutAService_ReportsAnErrorStatus`, the class whose blocking wait on its
  own STA thread was the hang `StaTestHarness` was written to remove (it pumps the message queue and joins
  the thread with a deadline). Never delete a dump or its sequence file while the case is open: it is the
  only record of what was running.

**How pipe-name isolation works (why a parallel run is safe).** `IpcServerWorker` serves
`IpcConstants.PipeName` (`RdpAuditService`) in production. That name is fixed, and the ACL on the
pipe grants only `BUILTIN\Administrators` (ReadWrite | CreateNewInstance) and `LocalSystem`
(FullControl) - neither is configurable.

Integration tests that need a REAL pipe (`IpcServerWorkerInstanceCapTests`,
`IpcServerWorkerLifecycleTests`) must not serve that name: while such a test host is up, any other
process on the machine - including the Configurator test host, whose `IpcClient` resolves the
production name - can connect to it. That was B4: the two `DatabasePageTests` overview cases that
assert the service is **unreachable** occasionally read a live answer (`Database overview loaded.`)
when the solution was tested in parallel, because another project's test server was on the shared
name.

The fix is by construction, not by scheduling:

- `IpcServerWorker.PipeName` is an `internal` init-only property that defaults to
  `IpcConstants.PipeName`. Production therefore resolves exactly the shipped name; no environment
  variable, appsettings key or public constructor argument can change it, and
  `IpcPipeNameIsolationTests` fails if that ever stops being true.
- Only the test assembly (via `InternalsVisibleTo`) can set it. The real-pipe tests build their
  worker as `new IpcServerWorker(services, logger) { PipeName = TestPipeNames.Unique() }`, where
  `TestPipeNames.Unique()` returns `RdpAuditService-<pid>-<guid>` - unique per test instance, so two
  tests cannot collide, and unguessable, so no other project can attach. The test clients in the same
  test connect to that same per-test name.
- The DACL, the instance cap and the message framing are NOT parameterised: a test chooses the name
  of its own pipe, never who may open a service pipe. The admin-only ACL still means the real-pipe
  tests need an **elevated** test host: from a non-elevated one the server comes up but the
  same-process client is refused with `UnauthorizedAccessException` by that ACL.

**The elevation precondition is stated, not assumed (B21).** Because that ACL is a security control and
is deliberately not relaxed for tests, every test that binds or connects to a real pipe is marked
`[ElevationFact]` / `[ElevationTheory]` (`ElevationTestGuard.cs`):

- the guard probes the process token **fail-closed** - any failure to establish elevation reads as "not
  elevated" - and **caches** the answer, because elevation cannot change while a process runs;
- on a non-elevated host those tests are **skipped with a recorded reason** that names the ACL, the
  observed fact and the remedy, instead of failing with a misleading `UnauthorizedAccessException`;
- on an elevated host they still run and pass. Both branches are exercised deterministically through the
  guard's internal probe seam, because a non-elevated run is not always available: the CI/automation host
  for this repository **is** elevated.
- `ElevationPreconditionMetaTests` fails the suite when a test method that drives a real `IpcServerWorker`
  loses the precondition, and separately fails when the detector itself stops matching (a recorded
  per-file count), so neither the guard nor the check over it can disappear silently.

The service-side `StorageAclPolicy` and the pipe DACL are unaffected by any of this: the fix is entirely
test-side.

**End-to-end smoke test (B9).** `ServiceHostSmokeTests` boots a REAL host from `Program.RegisterServices`
against a temporary `%TEMP%` root, lets `DatabaseInitializationWorker` apply the migrations to a clean store
and `StoreIntegrityWorker` capture the shutdown fingerprint through the real DPAPI-protected chain, and then
drives the Database tab's whole command set through the REAL dispatcher: `GetDatabaseOverview`,
`GetRetentionPolicy`, `PreviewRetention`, `CreateDatabaseBackup`, `ListDatabaseBackups`,
`VerifyDatabaseBackup`, `GetDeletionLedger` and `PurgeBySubject` **as a dry run only**. What it verifies
that no other test does: the composition root resolves end to end, migrations land on a clean store with no
failure marker, the retention report carries real resolved values, and the machine's own
`%ProgramData%\RdpAudit` files are byte-for-byte and timestamp-for-timestamp unchanged afterwards. It runs
in about 3 seconds and removes its temporary root (clearing the SQLite pools first, or a pooled handle keeps
the file open).

It deliberately does **not** start the other hosted services, and says so in its header: `IpcServerWorker`
would bind the production pipe name (the isolation defect B4 fixed), `RestApiHostedService` binds a TCP
listener, the collector workers subscribe to the operator's real Security channel, and the firewall workers
invoke `netsh`/`route`. The count of skipped hosted services is asserted against the composition root, so a
newly registered worker forces that decision to be made explicitly.

**Deterministic timing-sensitive tests.** A test that cancels a retention pass mid-way must not poll
for "has a batch landed yet" from another thread - under load the pass can finish first and the test
then fails on its own timing. `InformationDensityRetentionEngine.AfterBatchCommitted` (internal, null
in production) is invoked right after a batch commits, so the test cancels from inside the pass and
asserts the resulting state (anchor and tail intact, ledger accounting exactly the removed rows, no
duplicated window). WinForms page tests run on `StaTestHarness`, whose join on the STA thread carries
a deadline and a per-class time budget, so a future awaited body fails the test instead of hanging the
run.

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

## 14. Store integrity verdict on screen (B25)

The service computes the store-integrity verdict on every start-up (B19/B24) and records it in the
operation log and the anomaly marker. Since B25 it is also on screen, on two tabs, so this check is about
what an operator can SEE - not about the mechanism, which the automated suite covers.

- [ ] After a normal stop and start, Database tab -> Overview shows the docked banner under the button bar
      reading `Store integrity: ... ok ...` in the neutral face, and the `Integrity / tamper evidence`
      section lists the chain state, the entry count and both fingerprint timestamps. The same section
      appears in the Diagnostic tab's report.
- [ ] Force a verdict and confirm it is visible WITHOUT opening a log file. With the service stopped,
      delete ONE file from `%ProgramData%\RdpAudit\integrity\fingerprints\` (keep
      `store-fingerprint-sealed.json`), start the service and open both tabs. Expected: the banner turns
      red and names `missing`; the section shows the state, the chain message and the entry count the
      readable chain still holds; the Diagnostic tab shows the same verdict in its own section.
- [ ] Restore the deleted file (or delete the whole `fingerprints` folder and the sealed tip to reset the
      baseline) and confirm the verdict returns to `ok` in the neutral face.
- [ ] Confirm the "no verdict" case is not a pass: stop the service and press Refresh on the Database tab.
      Expected: the banner reads `UNKNOWN` in the red face and says the tamper evidence was NOT verified -
      never a neutral or stale `ok`.
- [ ] Confirm the interrupted/warning distinction survives a real crash: kill the service process
      mid-capture (Task Manager, not a clean stop) and restart it. Expected: `interrupted` is rendered in
      the AMBER warning face - a cut-short capture must not look like tampering (B24), and must not look
      like a pass either.

When every box above is ticked, the build is ready for an external Windows smoke test.
