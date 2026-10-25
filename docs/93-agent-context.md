# 93 — Agent context passport (RDPAudit 2.0)

Purpose: give an agent the project-specific knowledge that `AGENTS.md`,
`ARCHITECTURE.md`, `SPEC.md` and `PROJECT_MAP.md` spread across hundreds of
lines, in one bounded document. Read this before touching unfamiliar
subsystems; read code before asserting any behavior.

Scope note: this file records what was **verified by reading repository files**.
Anything not confirmed in code is marked as unconfirmed. Nothing here was
produced by running the build, tests or the service.

---

## 1. Product identity in one paragraph

RDPAudit 2.0 (root `C:\1st_RdpMON\Service`) is a Windows RDP security
monitoring and auto-block platform. A Windows service (`RdpAuditService`,
LocalSystem) subscribes to the Security event log and a hybrid ETW pipeline,
normalizes events into canonical facts, evaluates 20+ alert rules, persists
everything to SQLite (WAL), exposes a named-pipe IPC surface, and can block
attacker IPs locally (Windows Firewall) and at the network edge (MikroTik
RouterOS v7 REST). A WinForms Configurator drives the service over IPC and
provides operator surfaces (live events, statistics, firewall, retention,
diagnostics, session map, web access). Optional read-only surfaces: an HTTPS
REST API and an IIS dashboard behind a loopback YARP proxy.

## 2. Components and responsibility

| Project | Responsibility | Runtime |
|---|---|---|
| `src/RdpAudit.Service` | Worker service: ingest, persist, alert, enforce, IPC server; all platform-bound code | Windows, LocalSystem |
| `src/RdpAudit.Configurator` | WinForms UI (22 tabs); mutations only through IPC, read-only local fallbacks | Windows, admin |
| `src/RdpAudit.Mikrotik` | RouterOS v7 setup wizard (SSH/REST, CA/PKI) | Windows |
| `src/RdpAudit.Notifier` | Privileged tray notifier; polls over IPC, holds no secrets, writes no files | user session |
| `src/RdpAudit.Web` | Read-only IIS dashboard plus loopback YARP reverse proxy with server-side token injection | IIS + Hosting Bundle |
| `src/RdpAudit.Core` | Pure domain: models, EF entities, IPC contracts, options, parsers, decision engines; no I/O, no Win32 | `net8.0-windows` |

Namespaces by project (file counts from a source scan, excluding `bin`/`obj`):

- **Core** — `Ipc.Contracts` (80), `Util` (55), `Models` (49), `Data.Migrations` (45), `Data.Configurations` (34), `Events` (31), `Config` (29), `Firewall` (21), `Diagnostics` (11), `WebUi` (10), `Data` (10), `Siem` (9), `Storage.Sharding` (9), `Backup` (8), `Security` (7), `MikroTik` (7), `CrossHost` (6), `ThreatIntel` (4), `RestApi` (4), `Retention` (4), `Sessions` (3).
- **Service** — `Services` (29+), `Alerts` (26), `Workers` (19+), `RestApi` (17+), `Firewall` (14), `Infrastructure` (13), `EventSources` (11), `Processors` (8), `Ipc` (4), `ThreatIntel` (4), `Collectors` (3), `CrossHost` (2), `ProcessMonitoring` (2), `Storage` (2).
- **Configurator** — `Services` (51), `Forms` (25), `Theming` (5), `Ipc` (3), `Controls` (2).
- **Mikrotik** — `Ui` (12), `Core` (8), `Helpers` (3), `Pki` (3), `Ipc` (1).
- **Notifier** — `Notifications` (14), `Ipc` (2), `Forms` (1).
- **Web** — `Proxy` (9), `wwwroot` (3), `Config` (1), `Hosting` (1).

## 3. Data flow (service side)

```text
Security / TerminalServices-RemoteConnectionManager / LocalSessionManager logs
                        + hybrid ETW pipeline
                                │
                    EventCollectorHostedWorker
                                │
                       EventProcessorWorker  ──►  canonical facts
                                │
                           AlertWorker  ──►  20+ rules
                                │
                    FirewallAutoBlockWorker
                    (Windows Firewall + MikroTik REST)
                                │
                   SQLite (WAL, %ProgramData%\RdpAudit)
                                │
                        Named pipe IPC server
                                │  MessagePack over NamedPipe
                                ▼
                     RdpAudit.Configurator (WinForms)
```

Worker names are a documentation contract: only
`EventCollectorHostedWorker`, `EventProcessorWorker` and `AlertWorker` are
current. `EventCollectorWorker`, `EventNormalizerWorker` and
`AlertEvaluatorWorker` are retired names that must not reappear in
`README.md` / `README.ru.md`.

## 4. Subsystem map

### 4.1 Terminal Services / RDP policy (Configurator-owned)

- `src/RdpAudit.Configurator/Services/LocalRdpConfigurationProvider.cs` — reads current RDP configuration.
- `src/RdpAudit.Configurator/Services/LocalRdpConfigurationWriter.cs` — writes configuration; takes a snapshot of **all** tracked Terminal Services values before mutating.
- `src/RdpAudit.Configurator/Forms/RdpConfigurationPage.cs` — operator surface (`fDenyTSConnections` and peers).
- `src/RdpAudit.Configurator/Services/LocalShadowPolicyReader.cs` — shadow-session policy from `HKLM\SOFTWARE\Policies\...\Terminal Services\Shadow` and `HKLM\SYSTEM\...\Control\Terminal Server\Shadow`.
- `src/RdpAudit.Core/Backup/BackupCommandBuilder.cs` — includes Terminal Server and `WinStations\RDP-Tcp` registry keys in backups.
- **Hard rule:** the RDP listener port is resolved only through `RdpListenerPortResolver`; a literal `3389` is a defect (SPEC C-4).

### 4.2 Event XML normalization (Core-owned)

- `src/RdpAudit.Core/Events/EventXmlParser.cs` — hardened XML parsing: `DtdProcessing.Prohibit`, `XmlResolver = null`, 1 MiB document limit, 4 KiB entity limit.
- `PerEventIpResolver`, `IpNormalizer` — IP extraction and normalization; host names never become `SourceIp`.
- `EtwPayloadXmlFormatter` — ETW payload to XML shape.
- `SecurityAuthQuery.cs` — canonical XPath for Event IDs 4624, 4625, 4648, 4768, 4769, 4771, 4776, 4825.
- RdpCoreTS / RdpCoreTCP / WTS channels are never treated as an atomic source (SPEC FR-ING-3).

### 4.3 Alerting and statistics

- `src/RdpAudit.Service/Alerts/*` — 20+ rules (brute force, Kerberos spraying, pass-the-hash, Golden/Silver ticket, LSASS/PPL, privileged logon 4672, RDP hijack, off-hours, and others).
- `AttackStatsAggregator`, `AttackThreatScoring` — per-IP statistics and a 0..100 score with green/yellow/red banding.
- Per-IP forensics are stored as **file shards** (128-byte records, CRC-32C, ring overwrite), not as tables.
- **Current detection strategy is `Detect_Attack_Strategy_v3.md`**; references to it exist in 10+ code sites. `Detect_Attack_Strategy.md` (v1) and `_v2.md` are archive and are not referenced by code.

### 4.4 IPC

- Pipe name `RdpAuditService` (`src/RdpAudit.Core/Ipc/IpcConstants.cs`).
- ACL: `BUILTIN\Administrators` (`ReadWrite|CreateNewInstance`) plus LocalSystem (`FullControl`), applied in `src/RdpAudit.Service/Workers/IpcServerWorker.cs`.
- Frame: uint32 little-endian length, then MessagePack `IpcRequest` / `IpcResponse`; payloads are JSON.
- Command ordinals are append-only and currently run 0..94 (last: `PurgeBySubject = 94`).
- Per-command timeouts live in `IpcConstants.TimeoutMsFor`; a command without an explicit timeout silently inherits the 5-second default.

### 4.5 Storage

- SQLite via `Microsoft.EntityFrameworkCore.Sqlite` 8.0.10, EF Core 8.0.10.
- Table groups: Ingestion / Facts / Aggregates / ThreatIntel / Actions / CrossHost / Ops.
- PRAGMA set on every connection (`SqlitePragmaInterceptor`): `auto_vacuum=INCREMENTAL` **first**, then `journal_mode=WAL`, `synchronous=NORMAL`, `cache_size=-32000`, `foreign_keys=ON`, `temp_store=MEMORY`. Order is critical.
- Migrations: 22 migrations plus snapshot in `src/RdpAudit.Core/Data/Migrations` (InitialCreate, Stage2..Stage19, V126/V129/V133). Applied by `AuditDbInitializer.ApplyMigrationsAsync` via `MigrateAsync`, always with a pre-migration snapshot (`IPreMigrationBackupProvider`) and a failure marker (`DatabaseMigrationFailureMarker`).
- Retention defaults (`StorageOptions.cs`): events 365 days, logs 90, alerts 730, abuse reports 365 (min 30), active blocks 90 (min 7), attack stats 180, session-IP correlation 30, RDP connection facts 90; maintenance batch size 50 000. Decimation is off by default.
- Durability: events and bookmarks commit in one transaction (`BookmarkCheckpointLedger`); shard flush happens post-commit on a separate connection with the queue preserved on failure; config writes are atomic (temp then rename); torn writes are detected by a double CRC header; store integrity is hash-chained with a sealed tip under DPAPI.

### 4.6 External integrations

- **AbuseIPDB v2** — reporting (`AbuseIpDbReportWorker`, `AbuseIpDbCommentBuilder`, `IpReportability`) and enrichment via `GET /api/v2/check` (`Service/ThreatIntel/AbuseIpDbThreatIntelClient`, `ThreatIntelLookupStore`, `ThreatIntelRateLimiter`, `ThreatIntelEnrichmentWorker`).
- **MikroTik RouterOS v7** — REST/SSH, DPAPI-protected credentials, CA/PKI bootstrap.
- **Hard rule:** threat-intel results never feed auto-block; API keys are DPAPI envelopes and only a presence marker (for example `CredentialPresent`) may cross IPC boundaries.

## 5. Trust boundaries and privileges

- Service account: `LocalSystem` (`Core/Util/ScCommandBuilder.cs`, `InstallationService.cs`). `%ProgramData%\RdpAudit` DACL: Administrators + SYSTEM.
- Untrusted inputs: Windows Event XML (hardened parser), event fields (IPs normalized, host names excluded from `SourceIp`), operator input (never concatenated into a shell — `ProcessStartInfo.ArgumentList` or whitelisted factories only), external HTTP responses (AbuseIPDB, MikroTik — fail-closed classification), browser requests (Host must be a loopback literal or the request is rejected; CSP without inline script).
- Secrets: DPAPI LocalMachine (`ISecretProtector` / `DpapiSecretProtector`, `ProtectedEnvelope`, `WebTokenVault`). `GetSettings` masks envelopes, so secrets never reach logs, DTOs or IPC payloads.
- Fail-closed: REST disabled by default (`RestApiPlanBuilder`: Disabled / FailClosed / Listening); an unreachable cross-host agent reports no facts instead of guessing; a failing firewall provider leaves no ghost rows; missing SqlCipher support aborts startup.
- **Encryption at rest is not implemented** (B13): store, WAL and shards are plaintext by design decision (`docs/89-encryption-at-rest-decision.md`).
- Logging: Serilog (file + EventLog + compact), durable `OperationLog` in SQLite for ban/settings/maintenance/startup/crash, Configurator unhandled-exception log, DEBUG-gated fields such as `LogEventXmlAtDebug`, and `CrashGuard` as the last line of defense in a dying process.

## 6. Directory index

`src/` — see the namespace table in section 2.

`tests/` — `RdpAudit.Core.Tests`, `RdpAudit.Service.Tests`, `RdpAudit.Configurator.Tests`, `RdpAudit.Mikrotik.Tests`, `RdpAudit.Notifier.Tests`, `RdpAudit.Web.Tests`, `RdpAudit.ScenarioTests`, `RdpAudit.StorageBenchmarks.Tests`, plus `RdpAudit.Benchmarks` (not in the solution; driven by `benchmarks.ps1`).

`docs/` — one line per file, from that file's own title:

| File | Subject |
|---|---|
| `00-overview.md` | Architecture overview |
| `10-core.md` | RdpAudit.Core |
| `20-service.md` | RdpAudit.Service internals (workers, durability, hardening) |
| `30-configurator.md` | RdpAudit.Configurator |
| `40-alert-rules.md` | Alert rule catalogue |
| `40-options.md` | Configuration options |
| `41-data-model.md` | Data model |
| `45-firewall.md` | Firewall integration |
| `46-attack-statistics.md` | Attack statistics |
| `47-remote-rdp-clients.md` | Remote RDP clients |
| `48-abuseipdb.md` | AbuseIPDB integration |
| `49-mikrotik.md` | MikroTik RouterOS v7 integration |
| `50-ipc.md` | Named-pipe IPC — full ABI (largest doc) |
| `51-rest-api.md` | Read-only HTTPS REST API |
| `52-siem-export.md` | SIEM export |
| `54-session-map.md` | Session timeline map |
| `60-debug-mode.md` | Debug mode |
| `70-publish.md` | Publishing procedure |
| `80-lockfree-ringbuffer-architecture.md` | Lock-free SPSC ring buffer architecture |
| `80-roadmap.md` | Roadmap (large planning document) |
| `81-memory-layout-specification.md` | Memory layout specification |
| `82-event-collection-architecture-diagnosis.md` | Event collection diagnosis |
| `83-event-collection-implementation.md` | Event collection implementation map |
| `84-event-collection-operator-behavior.md` | Event collection operator behavior |
| `85-event-collection-residual-risks.md` | Event collection residual risks |
| `86-shard-ingestion.md` | Shard ingestion |
| `87-information-density-retention.md` | Information-density retention |
| `88-database-backup-and-restore.md` | Database backup and restore |
| `89-encryption-at-rest-decision.md` | Encryption-at-rest decision record |
| `90-windows-validation.md` | Windows validation checklist |
| `91-troubleshooting.md` | Troubleshooting |
| `92-storage-benchmarks-and-tuning.md` | Storage benchmarking and tuning |
| `93-agent-context.md` | This file |
| `Plan_WebUI_1st-RDPMon_IIS_RdpAudit.md` | Plan: web UI on IIS |
| `Road_Map_ETW_2026_08_14.md` | Task: `IEventSource` + `EtwRealtimeSource` |

Note: `publish.ps1` copies every `docs/*.md` into the published package, so new
documents ship to customers automatically.

## 7. Documentation drift tests (what will fail if you edit docs carelessly)

These tests read repository files directly. They are the reason several
documents are effectively append-only.

The same contracts can be verified without a .NET SDK via
`tools/Invoke-DocContractCheck.ps1` (`#Requires -Version 7.6`), which
re-implements all seven checks below and exits 1 on failure. Keep the script and
these tables in sync: if a contract changes, update both.

| Test | Guarded artifact | Contract |
|---|---|---|
| `Changelog_EntriesFollowMachineJournalFormat` (`tests/RdpAudit.ScenarioTests/RepositoryHygieneScenarioTests.cs`) | `CHANGELOG.md` | line 1 = `# Service Changelog`, line 3 = `Automatically maintained by DevAgent.`, every non-empty line from line 4 = `- [YYYY-MM-DDTHH:MM:SS] ...` |
| `VersionHeaders_AreCanonicalTripletsOrAbsent` (same file) | `src/**`, `tests/**` `*.cs` | a `// Version:` line, **if present**, must be `M.N.P`; files without it are fine |
| `CiWorkflows_DeclareWindowsRunnersOnly` (same file) | `.github/workflows/*.yml|yaml` | CI stays on Windows runners |
| `OperatorIpReference_CoversEveryCommandConstant` (`DocumentationDriftScenarioTests.cs`) | `docs/50-ipc.md` | every `IpcCommand` enum name appears as a substring |
| `ContributorProjectMap_CoversEverySourceFileOnDisk` (same file) | `PROJECT_MAP.md` | every `src/**/*.cs` and `tests/**/*.cs` path appears |
| `ReviewerReadmeDiagrams_UseCurrentWorkerPipeline` (same file) | `README.md`, `README.ru.md` | current worker names present, retired names absent |
| `RestApiDoc_MentionsEveryCommittedDescriptorPath`, `RestApiDoc_ReferencesTheCommittedDescriptorPath` (`tests/RdpAudit.Service.Tests/Scenarios/DocumentationDriftScenarioTests.cs`) | `docs/51-rest-api.md` | every path in `openapi-v1.json` plus the descriptor path |

Verified facts about these guards: no test reads or requires `AGENTS.md`; no
test enumerates the repository root or `docs/` (so **new** markdown files never
break anything); no test inspects `.editorconfig`, `.gitattributes` or git
state. Editing the five guarded artifacts above is the only documentation
change with test risk.

## 8. Open defects and accepted limitations (from `BUGS.md`)

Severity is as recorded in the repository.

| ID | Sev | Status | Content |
|---|---|---|---|
| B2 | P3 | open | 64 unprotected `+= async` event-handler sites in 18 WinForms files; a counter test tracks the number |
| B26 | P2 | open | single non-reproducible Configurator test failure; root cause not proven |
| B13 | P2 | open (security gap) | encryption at rest designed but not implemented; store/WAL/shards are plaintext |
| B19 | P2 | open (honesty limit) | offline tamper detection is hash-chained, but a local admin can re-sign or delete it |
| B10 | P2 | partial | the "no >16 ms UI stall" budget is not instrumented |
| B16 | P3 | partial | auto-vacuum visibility exists; no one-click compaction from the overview |
| B11–B15, B18, B20 | P3 | open | shard caps, best-effort shard backup, ACL applied only at install/start, CIDR cap 4096, trusted ledger prefix, no address in shard aggregates |
| B27 | — | fixed | fresh stores missed `auto_vacuum=INCREMENTAL` because of PRAGMA order |
| P1-1 | P1 | fixed | real-pipe IPC tests failed under a non-elevated host; product ACL was correct, the test contract was wrong (fixed by `ElevationTestGuard`) |
| P2-1 | P2 | fixed | Configurator blocked the UI on a 15-second `netsh` probe |
| P2-2 | P2 | fixed | `CrashGuard` blocked a thread for up to 3 seconds |
| P2-3 | P2 | fixed | documentation-drift bundle (docs described a different tree: `Pages` vs `Forms`, dead paths) |
| P3-2 | P3 | fixed | double versioning; 182 `// Version:` headers removed, `Directory.Build.props` is the only source |
| P3-3 | P3 | fixed | false claims about Linux CI replaced with honest windows-only statements |

Developer traps implied by the above: per-run pipe names in test hosts,
elevation for real-pipe tests, no `--no-build` against divergent output trees,
PRAGMA order, and never adding a `// Version:` header to a new file.

## 9. Documentation contradictions found during review

Recorded here so nobody acts on stale text. These were observed while building
this passport; the code is the authority.

1. `ARCHITECTURE.md` §5 states "Command ordinals: 0..79 defined", while
   `IpcCommand.cs` defines 0..94 (`PurgeBySubject = 94`) and `docs/50-ipc.md`
   already describes 85–94.
2. Test-project inventories disagree: `SPEC.md` says seven test projects plus
   Benchmarks, `ARCHITECTURE.md` §11 lists six (omitting `RdpAudit.Web.Tests`),
   and `tests/` actually holds nine directories, including
   `RdpAudit.StorageBenchmarks.Tests`, which neither document mentions.
3. BUGS.md claims curated release notes sit at the top of `CHANGELOG.md`
   guarded by `Changelog_CuratedNotesPrecedeRawJournal`; on the current snapshot
   the file has no `##` headings at all, only `# Service Changelog` plus raw
   journal entries.
4. `docs/50-ipc.md` header text still labels the state "Stage 16" while the
   code has moved past it.
5. Exit codes `0x1000` (single-instance mutex conflict) and `20260814` (fatal
   migration failure) and the worker startup order appear in `ARCHITECTURE.md`;
   they were not traced to source lines during this review.
6. Historical test counts quoted in `BUGS.md` (Core 1526 passed; Service 828
   passed / 6 failed, dated 2026-09-09) were not re-run here and may be stale.

## 10. Task routing

| If the task is about | Start here |
|---|---|
| RDP policy, listener port, shadow sessions | §4.1 of this file, then `docs/30-configurator.md` |
| A UI tab or operator surface | `src/RdpAudit.Configurator/Forms/*`, `Services/*`, `docs/30-configurator.md` |
| Event parsing, Event IDs, IP fields | `EventXmlParser`, `SecurityAuthQuery`, `docs/40-alert-rules.md` |
| Detection rules, scoring, statistics | `Service/Alerts/*`, `AttackStatsAggregator`, `Detect_Attack_Strategy_v3.md`, `docs/46-attack-statistics.md` |
| Schema, migrations, retention, storage performance | `Core/Data/**`, `SqlitePragmaInterceptor`, `StorageOptions`, `docs/41/86/87/88/92-*`, `bench-storage.ps1` |
| IPC command or contract | `IpcCommand`, `IpcConstants`, `IpcServerWorker`, `docs/50-ipc.md` |
| Blocking, firewall, router integration | `Core/Firewall/*`, `Service/Firewall/*`, `Mikrotik/*`, `docs/45-firewall.md`, `docs/49-mikrotik.md` |
| REST API or web dashboard | `Service/RestApi/*`, `Web/*`, `docs/51-rest-api.md` |
| Reputation enrichment | `Core/AbuseIpDb/*`, `Service/ThreatIntel/*`, `docs/48-abuseipdb.md` |
| Build, publish, install | `publish.ps1`, `install.ps1`, `Directory.Build.props`, `global.json`, `docs/70-publish.md` |

## 11. Verification checklist for any change

1. Does it touch an enumerate-and-persist ABI (ordinals, MessagePack `[Key]`, `IpcResultStatus`)? It must be append-only.
2. Does it touch schema or persisted formats? It needs a migration plus pre-migration snapshot compatibility and a documented rollback.
3. Does it add an IPC command? It needs an explicit timeout, both sides implemented, idempotency reasoning, and a `docs/50-ipc.md` update.
4. Does it add or change a `src/**/*.cs` file? `PROJECT_MAP.md` needs the row.
5. Does it introduce a hardcoded port, LINQ in a per-event path, or shell string concatenation? Those are defects regardless of intent.
6. Does it add a `+= async` handler in WinForms? Do not increase the B2 count.
7. Is a `try/catch` used to hide an obsolete or unexpected API failure? Replace the API instead.
8. Can the change be verified locally? Without a .NET SDK in the sandbox, only static review is possible — state that plainly, and hand over exact commands for a machine with SDK 8.0.424. Documentation contracts, however, are checkable here: run `pwsh -NoLogo -NoProfile -NonInteractive -File .\tools\Invoke-DocContractCheck.ps1`.
