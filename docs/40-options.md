# RdpAudit configuration (options)

This document covers the `RdpAudit` section of `%ProgramData%\RdpAudit\appsettings.json`. The file is hot-reloaded by `IOptionsMonitor<RdpAuditOptions>` whenever it changes on disk.

## Top-level sections

| Section | Type | Purpose |
|---------|------|---------|
| `Monitoring` | `MonitoringOptions` | Event collection toggles and batching. |
| `Alerts` | `AlertOptions` | Detection rule thresholds, business hours, whitelists. |
| `Firewall` | `FirewallOptions` | Auto-block, provider selection, static block / allow lists. |
| `Storage` | `StorageOptions` | Database path and retention windows. |
| `Sharding` | `ShardingOptions` | Optional per-source-IP shard files, their capacity ceilings and the cardinality guard. |
| `Diagnostics` | `DiagnosticsOptions` | Debug-only switches. |
| `AbuseIpDb` | `AbuseIpDbOptions` | AbuseIPDB external reputation / reporting integration. |
| `MikroTik` | `MikroTikOptions` | MikroTik RouterOS external firewall integration. |
| `SessionControl` | `SessionControlOptions` | Disconnect / log-off / shadow policy switches. |
| `Api` | `ApiOptions` | Optional read-only HTTPS REST API built on Kestrel (bearer token, read-only). |

## FirewallOptions

Backward-compatible with pre-Stage-1 deployments — new fields default to safe values.

| Field | Default | Meaning |
|-------|---------|---------|
| `AutoBlockBruteForce` | `false` | Enables the brute-force auto-block worker. |
| `AutoBlockThreshold` | `50` | Failures from one IP that trigger an auto-block. |
| `BlockRuleName` | `"RdpAudit-Block"` | Base name used to construct per-IP firewall rules. |
| `Provider` | `"Windows"` | One of `None`, `Windows`, `MikroTik`, `Both`. |
| `Whitelist` | `[]` | CIDR / IP entries that must NEVER be auto-blocked. |
| `Blacklist` | `[]` | CIDR / IP entries always treated as hostile. |
| `BlockOnBlacklistedLogin` | `false` | Block immediately on any successful logon from a blacklisted IP. |
| `InstantBlockLogins` | `[]` | User names (e.g. `guest`, `admin`) whose successful logon triggers an immediate block of the source IP. |
| `DefaultBlockDurationMinutes` | `0` | `0` or negative means permanent until manually removed. |
| `MaxActiveBlocks` | `10000` | Guardrail against rule-table flooding. |
| `WhitelistIps` | `[]` | Flat list of literal IPs in addition to `Whitelist` (CIDR entries). Consumed by the auto-block worker. |
| `RefusePrivateAddressBlock` | `true` | Windows provider refuses to block loopback / RFC1918 / multicast / link-local addresses. |
| `AutoBlockDebounceSeconds` | `60` | Per-IP debounce window applied by the auto-block worker to avoid block storms. |
| `PowerShellScanTimeoutSeconds` | `30` | Hard timeout for the locale-independent PowerShell live firewall scan. Values below 1 are treated as the default. |
| `PowerShellRetryProbeIntervalMinutes` | `15` | Minimum interval between PowerShell re-probe attempts while the live scanner is latched onto the netsh fallback. Values below 1 are treated as the default. |

## AbuseIpDbOptions

The `ApiKey` field is stored as a protected envelope (see "Secret protection"). The Service unwraps it through `ISecretProtector` only when a request is actually made — the plaintext never appears in IPC responses, logs, or status DTOs.

| Field | Default | Meaning |
|-------|---------|---------|
| `Enabled` | `false` | Master switch for the integration. |
| `ReportAttacks` | `false` | When true (and `Enabled` is true) the Stage 8 worker submits abuse reports. |
| `ApiKey` | `""` | Protected envelope holding the AbuseIPDB API key. Plaintext keys are wrapped by `SettingsManager` before persistence. |
| `BaseUrl` | `"https://api.abuseipdb.com"` | Override for on-premises proxies. |
| `EndpointUrl` | `"https://api.abuseipdb.com/api/v2/report"` | Submission URL used by the Stage 8 report worker. |
| `TimeoutSeconds` | `15` | HTTP timeout. |
| `MaxReportsPerMinute` | `60` | Client-side rate limit (informational). |
| `MaxReportsPerHour` | `100` | Soft cap honoured by the Stage 8 worker. |
| `MaxReportsPerDay` | `500` | Hard cap honoured by the Stage 8 worker. |
| `DeduplicationWindowMinutes` | `15` | Minimum gap between successive reports of the same IP. Clamped to 15 minutes minimum. |
| `CacheLookups` | `true` | Cache reputation lookups on disk. |
| `CacheTtlMinutes` | `60` | Cache TTL. |
| `ReportThreshold` | `80` | Abuse confidence (0..100) at which an IP is treated as hostile. |
| `MinThreatScore` | `60.0` | Minimum `AttackStat.ThreatScore` required before an IP qualifies for reporting. |
| `MinFailedAttempts` | `10` | Minimum failed logons required before an IP qualifies for reporting. |
| `ReportCategories` | `[18, 22]` | Categories submitted with each report (SSH, Brute-Force). |

## MikroTikOptions

The `Password` field is stored as a protected envelope. Plaintext is unwrapped only at HTTP-send time and discarded immediately. See `docs/49-mikrotik.md` for the full Stage 9 surface map.

| Field | Default | Meaning |
|-------|---------|---------|
| `Enabled` | `false` | Master switch for the integration. |
| `AddAttackerRules` | `true` | When false the client is wired but no firewall rules are written. |
| `BaseUrl` | `""` | Optional fully-formed RouterOS REST endpoint (`https://10.0.0.1:8443`). Wins over `Scheme/Host/Port` when set. |
| `UseHttps` | `true` | Selects HTTPS when `BaseUrl` is empty. |
| `Host` | `""` | Router host name or IP literal. |
| `Port` | `0` | Explicit TCP port. `0` means "scheme default" (443 / 80). |
| `UserName` | `""` | REST API user. |
| `Password` | `""` | Protected envelope holding the REST password. |
| `TimeoutSeconds` | `15` | HTTP timeout (clamped to `[1..60]`). |
| `AddressList` | `"rdpaudit-block"` | Address list name (reserved for operators who want to wire it into a router-side rule). |
| `FilterChain` | `"input"` | Firewall filter chain (`input` / `forward`). |
| `FilterAction` | `"drop"` | Firewall filter action (`drop` / `reject`). |
| `CommentTemplate` | `"RdpAudit auto-block"` | Body of the rule comment. |
| `CommentPrefix` | `"RdpAudit"` | Prefix recognised on existing rules so the provider only removes its own entries. |
| `ValidateServerCertificate` | `true` | Disable only for lab / staging. |
| `MaxOperationsPerMinute` | `120` | Rate limit guardrail. |
| `BlockDurationDays` | `0` | Days component of the block duration. |
| `BlockDurationHours` | `1` | Hours component of the block duration. |
| `BlockDurationMinutes` | `0` | Minutes component of the block duration. |

## SessionControlOptions

Session-control actions (disconnect, log off, shadow) are auditable, reversible (where applicable), and rate-limited.

| Field | Default | Meaning |
|-------|---------|---------|
| `Enabled` | `true` | Master switch. Disabling makes the related IPC commands return `Unavailable`. |
| `AllowDisconnect` | `true` | Permit `DisconnectSession`. |
| `AllowLogoff` | `true` | Permit `LogoffSession`. |
| `AllowShadow` | `false` | Permit `ShadowSession`. Disabled by default — opt-in. |
| `RequireShadowPolicy` | `true` | Refuse shadow requests if the Terminal Services policy is missing. |
| `BackupShadowPolicyOnApply` | `true` | Always back up before mutating the shadow policy. |
| `ShadowPolicyMode` | `1` | Microsoft `Shadow` registry value: `0`=off, `1`=full+prompt, `2`=full silent, `3`=view+prompt, `4`=view silent. |
| `MaxOperationsPerMinute` | `30` | Rate limit per operator. |
| `AuditAllOperations` | `true` | Mirror every operation into the alert log. |

## StorageOptions

| Field | Default | Meaning |
|-------|---------|---------|
| `DatabasePath` | `""` | Explicit SQLite database path. Empty resolves to the default under ProgramData. |
| `EventRetentionDays` | `365` | Retention window for `RawEvents`. |
| `LogRetentionDays` | `90` | Retention window for service log files. |
| `AlertRetentionDays` | `730` | Retention window for alert log rows. |
| `LogDirectory` | `""` | Explicit log directory. Empty resolves to the default under ProgramData. |
| `AbuseReportRetentionDays` | `365` | Retention window for `AbuseReports` rows (effective minimum 30). |
| `ActiveBlockRetentionDays` | `90` | Retention window for removed / expired `ActiveBlocks` rows (effective minimum 7). |
| `AttackStatRetentionDays` | `180` | Retention window for stale `AttackStats` rows (effective minimum 14). |
| `SessionIpCorrelationRetentionDays` | `30` | Retention window for stale `SessionIpCorrelations` rows (effective minimum 7). |
| `RdpConnectionFactRetentionDays` | `90` | Retention window for stale `RdpConnectionFacts` rows (effective minimum 30). |
| `MaintenanceBatchSize` | `50000` | Max rows deleted from one retention pass per table. Keeps writer locks short. |
| `Decimation` | *(see below)* | Optional frequency-oriented decimation of raw event telemetry. Disabled by default. |
| `RetentionPolicy` | *(see below)* | Optional information-density retention: pressure-driven deletion of the interior of the densest event codes. Disabled by default. |
| `Backup` | *(see below)* | Optional database snapshots: consistent online copies of the SQLite store with a SHA-256 manifest, bounded retention, and the snapshot taken before EF migrations. The operator surface is disabled by default; the pre-migration snapshot is on by default. |

### DecimationOptions

Frequency-oriented decimation runs after ordinary retention pruning. It shrinks monotonically high-frequency bursts of a single event id from a single source IP by deleting only the **middle** of each burst: head and tail rows always survive for forensics, rare events are never candidates, and rows without a source IP are ignored. Disabled by default so existing installations keep today's behaviour until an operator opts in.

| Field | Default | Meaning |
|-------|---------|---------|
| `Enabled` | `false` | Master switch for the decimation pass. |
| `MinAgeDays` | `30` | Rows newer than this many days are never candidates (clamped to ≥7). |
| `BurstGapSeconds` | `300` | Gap in seconds between consecutive rows of the same (SourceIp, EventId) pair that starts a new burst (clamped to ≥10). |
| `CandidateMinRows` | `100000` | Minimum row count of one event id inside the decimation window required to become a candidate (clamped to ≥10,000). |
| `HeadKeepPerBurst` | `100` | Rows preserved at the start of every burst (clamped to 1..100,000). |
| `TailKeepPerBurst` | `100` | Rows preserved at the end of every burst (clamped to 1..100,000). |
| `MaxCandidateEventIds` | `5` | Maximum distinct event ids examined by one decimation tick (clamped to 1..32). |
| `BatchSize` | `5000` | Maximum rows one decimation statement may delete (clamped to 100..100,000). |

### RetentionPolicyOptions

Information-density retention. A **pressure** rule: it runs only when a configured ceiling is
breached, and it reduces the store by deleting the interior of the densest event codes — never the
oldest record of a code (the anchor), never the newest `TailKeepPerCode` records (the tail), never
a row newer than `MinAgeDays`, never a protected class, and never a row that alert evidence still
references. Every deleted window is recorded in `EventDeletionLedger`. The rule, its triggers, its
invariants and the honest-skip states are documented in `docs/87-information-density-retention.md`.

Disabled by default: with `Enabled: false` no trigger is evaluated and no row is written.

| Field | Default | Meaning |
|-------|---------|---------|
| `Enabled` | `false` | Master switch for the pressure pass. |
| `LegalHold` | `false` | When true every pressure rule is inert: no trigger is evaluated and nothing is deleted. |
| `AnchorScope` | `PerCode` | Code granularity: `PerCode` = `(EventId, Channel)`; `PerCodeAndIp` adds the source address, so every attacker keeps a first-contact anchor. An out-of-range value falls back to `PerCode`. |
| `TailKeepPerCode` | `512` | Newest records of each code that are never deleted (clamped to 1..100,000). |
| `CandidateMinRows` | `1000` | Minimum eligible interior rows before a code becomes a candidate (clamped to 10..100,000,000). |
| `MinAgeDays` | `7` | Rows newer than this many days are never candidates (clamped to 1..3,650). |
| `MaxRowsPerPass` | `50000` | Maximum rows one pass may delete across all codes (clamped to 1..10,000,000). |
| `MaxWriterLockMs` | `250` | Maximum time one batch may hold the writer lock before the pass yields to ingestion (clamped to 10..60,000). |
| `DeleteBatchRows` | `2000` | Rows removed by one `DELETE` statement; bounds a single writer-lock section (clamped to 100..100,000). |
| `MaxDatabaseBytes` | `0` | Database + WAL + SHM ceiling in bytes; `0` disables the trigger. |
| `MaxRawEventRows` | `0` | `RawEvents` row ceiling; `0` disables the trigger. |
| `MinFreeDiskBytes` | `0` | Free-space floor in bytes for the database and shard-tree volumes; `0` disables the trigger. |
| `ProtectedEventIds` | `[4672, 4673, 4674, 4697, 4720, 4722, 4723, 4724, 4728, 4732, 4756, 4769, 4771, 7045]` | Event codes that are never pressure candidates. A null or empty array resolves back to this default, so clearing it cannot silently disarm the protection. |

Clamped resolution helpers: `ResolveTailKeepPerCode`, `ResolveCandidateMinRows`, `ResolveMinAgeDays`,
`ResolveMaxRowsPerPass`, `ResolveMaxWriterLockMs`, `ResolveDeleteBatchRows`, `ResolveMaxDatabaseBytes`,
`ResolveMaxRawEventRows`, `ResolveMinFreeDiskBytes`, `ResolveAnchorScope`, `ResolveProtectedEventIds`.
`IsPressureDeletionAllowed()` is `Enabled && !LegalHold`; `HasAnyPressureTrigger()` reports whether
any ceiling is positive, so "enabled but nothing to trigger on" is visible instead of silent.

These values, the global `StorageOptions` windows above and the per-event `EventRetention` overrides
are readable and writable over IPC since stage 2a: `GetRetentionPolicy` (81) reports every field as
configured and as clamped-effective, `SaveRetentionPolicy` (82) validates and clamps the whole
request before writing and records the change in `OperationLog`, and `PreviewRetention` (83) dry-runs
the pass. `docs/50-ipc.md` carries the contracts; `docs/87-information-density-retention.md` carries
the rule. A save never widens a bound: the service writes the clamped value, so an out-of-range
number cannot be persisted through IPC.

### BackupOptions

Database snapshots: consistent online copies of the live SQLite store, taken without stopping the
service, each with a SHA-256 manifest and bounded retention. The mechanism, the artifact layout, the
verification verdicts, the restore procedures and the rollback guidance are documented in
`docs/88-database-backup-and-restore.md`.

`Enabled` is the operator surface only. It does **not** gate the pre-migration snapshot
(`PreMigrationBackupEnabled`, on by default) nor the downgrade guard, which is always on: protecting a
schema upgrade and refusing to open a newer store are not optional conveniences.

| Field | Default | Meaning |
|-------|---------|---------|
| `Enabled` | `false` | Master switch for the operator-facing snapshot surface: `CreateDatabaseBackup` refuses when it is false, and no snapshot folder grows on its own. A pre-migration snapshot is governed by `PreMigrationBackupEnabled`, not by this switch. |
| `RetentionCopies` | `5` | Database snapshots kept; older ones are removed after a successful new snapshot (clamped to 1..1,000). Snapshots of other scopes (settings, shadow policy) and `rdpaudit.db.*.bak` files are never counted and never deleted. |
| `MinFreeDiskBytesBeforeBackup` | `0` | Free-space floor in bytes that must remain on the destination volume after the snapshot. `0` means only the snapshot's own size must fit. Checked before the first byte is written. |
| `IncludeShards` | `false` | Also copy the shard tree (`actions\`) into the snapshot. Off by default: the tree can be far larger than the database and the copy is a best-effort file copy, not a transactional one. |
| `PreMigrationBackupEnabled` | `true` | Take one snapshot before pending EF migrations are applied, and refuse to migrate when it cannot be taken (marker + exit code 20260815). Set to `false` only to migrate without a rollback point. |
| `BackupDirectory` | `""` | Backup root. Empty resolves to `%ProgramData%\RdpAudit\Backups`, the folder the settings snapshots already use. |

Clamped resolution helpers: `ResolveRetentionCopies`, `ResolveMinFreeDiskBytesBeforeBackup` and
`ResolveBackupDirectory(programDataDirectory)`. A hand-edited `RetentionCopies` of `0` becomes `1`
(snapshot, then keep exactly one), and a negative floor becomes `0`; the free-space comparison
saturates, so an absurd floor refuses the snapshot instead of wrapping into a negative requirement.

These values are **not** part of `GetRetentionPolicy` / `SaveRetentionPolicy`, which govern retention
windows only. `GetDatabaseOverview` (80) reports the snapshot state in its `Backups` section
(enabled, pre-migration switch, backup directory, snapshot count, retention, newest snapshot), and
editing `BackupOptions` over IPC is a later stage.

## ShardingOptions

Optional per-source-IP forensic shard files beside the SQLite event store. Disabled by default, and
every capacity ceiling is disabled by default too, so a configuration written before this stage keeps
exactly the behaviour it had. `docs/86-shard-ingestion.md` is the normative document for the format,
the failure semantics, the cardinality guard and orphan collection; this section is the option
reference.

| Field | Default | Meaning |
|-------|---------|---------|
| `Enabled` | `false` | Master switch for shard writing. |
| `ActionsRoot` | `""` | Absolute shard-tree root; empty uses `%ProgramData%\RdpAudit\actions`. |
| `ShardCapacityRecords` | `1024` | Ring capacity per shard, in 128-byte records (clamped to ≥1). |
| `MaxOpenWriters` | `128` | Maximum cached open shard writers (clamped to ≥1). |
| `MaxShardFiles` | `4096` | File-creation budget; existing open shards keep being written (clamped to ≥0). |
| `MaxShardBytes` | `0` | Per-shard byte ceiling; `0` disables it. Selects the ring capacity of NEW shards only: `min(ShardCapacityRecords, MaxShardBytes / 128)`. |
| `MaxTotalShardBytes` | `0` | Whole-tree byte budget for `actions\`; `0` disables it. |
| `MinFreeDiskBytes` | `0` | Free-space floor of the shard volume; `0` disables it. |
| `OrphanGraceDays` | `14` | Untouched days before orphan collection may remove a shard (clamped to 1..3650). |
| `SubnetAggregation` | *(see below)* | Cardinality-guard thresholds. |

Clamped resolution helpers: `ResolveShardCapacityRecords`, `ResolveRingCapacityRecords`,
`ResolveMaxOpenWriters`, `ResolveMaxShardFiles`, `ResolveMaxShardBytes`, `ResolveMaxTotalShardBytes`,
`ResolveMinFreeDiskBytes`, `ResolveOrphanGraceDays`. `ResolveRingCapacityRecords` is the one the sink
uses for a new file; a shard already on disk keeps the capacity its own header declares, because
re-shaping a pre-allocated file would move evidence.

Honest limitation of a byte ceiling against the fixed shard format: the record region is
`capacity * 128` bytes, so `MaxShardBytes` is converted by integer division and the file's real length
is `128 + capacity * 128` - up to 128 bytes above the ceiling, never rounded up.

### SubnetAggregationOptions

The shard-cardinality guard. Disabled by default; with it off the sink writes one file per source and a
reached `MaxShardFiles` still refuses new files (with an operator-visible banner) instead of silently
changing where evidence is written.

| Field | Default | Meaning |
|-------|---------|---------|
| `Enabled` | `false` | Master switch for the guard. |
| `TotalFileThreshold` | `4096` | The guard engages once the tree holds MORE files than this (clamped to ≥1). |
| `NewFilesPerIntervalLimit` | `64` | The guard engages once this process created this many files in the window (clamped to ≥1). |
| `IntervalSeconds` | `60` | Rate-window length (clamped to 1..86 400). |
| `MinSourceRowsPerInterval` | `8` | A source below this many rows in the window counts as low volume (clamped to ≥0). |

Clamped resolution helpers: `ResolveTotalFileThreshold`, `ResolveNewFilesPerIntervalLimit`,
`ResolveIntervalSeconds`, `ResolveMinSourceRowsPerInterval`.

These values are readable and writable over IPC since stage 4: `GetShardInventory` (88) reports the
effective policy and the live capacity state as part of the shard inventory (no separate read command),
and `SaveShardingPolicy` (91) validates and clamps the whole request before writing, records the change
in `OperationLog` with the invoking identity and the old and new policy, and is live without a service
restart. `CollectShardGarbage` (92) reclaims orphan shards under `OrphanGraceDays`.
`docs/50-ipc.md` carries the contracts. A save never widens a bound: a value above a supported maximum
is clamped and the clamped value is written and reported, while a negative value or an unusable
`ActionsRoot` is refused with **no** write at all.

## ApiOptions

The read-only HTTPS REST API delivered by roadmap backlog #3. Disabled by default: the
service starts no listener until `Enabled` is set and every prerequisite resolves
(fail-closed). The Service and Configurator config templates both expose this block with
the same defaults. Endpoint, authentication and error-model documentation lives in
`docs/51-rest-api.md`.

| Field | Default | Meaning |
|-------|---------|---------|
| `Enabled` | `false` | Master switch for the REST API listener. |
| `Token` | `""` | Static bearer token required by every endpoint except `/healthz`. Stored as a protected envelope and masked in every IPC / REST response. |
| `ListenAddress` | `"127.0.0.1"` | HTTPS listen address. Blank resolves to the IPv4 loopback default. |
| `Port` | `8443` | Listen port (clamped to 1..65535). |
| `CertificateThumbprint` | `""` | Thumbprint of the server TLS certificate in `LocalMachine\My`; wins over `CertificateSubject`. |
| `CertificateSubject` | `""` | Subject of the server TLS certificate, used only when `CertificateThumbprint` is blank. |
| `AllowInsecureLoopback` | `false` | Accept an untrusted (self-signed) certificate - loopback listeners only; the host logs a risk warning. |
| `MaxConnections` | `100` | Maximum concurrent Kestrel connections (clamped to 1..10000). |
| `RateLimitPerMinute` | `60` | Per-IP fixed-window request budget per minute (clamped to 1..60000). |

## Secret protection

Configuration values that name a real secret (today: `AbuseIpDb.ApiKey`, `MikroTik.Password`, `Api.Token`) are stored as a JSON envelope:

```json
{ "$protected": "<base64-cipher>", "scope": "LocalMachine" }
```

* On Windows the envelope is produced by `DpapiSecretProtector` using `ProtectedData.Protect` with `LocalMachine` scope and a fixed entropy of `"RdpAudit/v1"`.
* On non-Windows CI the service substitutes `InMemorySecretProtector`, which is **not confidential** — it only exists to make the envelope contract round-trip in tests.
* Plaintext is never logged, returned over IPC, or written into status DTOs.
* A plain (non-envelope) string in the config is still accepted on first run — the secret protector returns it unchanged so operators can supply the value once and then re-save through the Configurator to install the envelope.

## LLM-safe extension rules

When extending this surface:

* **Options are append-only at runtime.** Existing field names must keep their meaning. Add new fields with safe defaults; never repurpose an old field.
* **Never log a protected value.** Log only `Length` / boolean "present" facts about secrets.
* **Never echo a secret over IPC.** Status / test DTOs carry `CredentialPresent` flags, not plaintext.
* **Provider abstractions must stay behind `IFirewallProvider` / `ISecretProtector`.** New providers add a new ordinal to `FirewallProviderKind` (append-only); they must not reuse a retired ordinal.
* **Defaults must be safe.** A new feature defaults to `Enabled = false`. Operators opt in explicitly.

## Stage 5 storage-hardening options

All defaults preserve today's behaviour; nothing below is required for the service to run.

### `RdpAudit:Storage:Integrity`

Governs the store fingerprint and the scheduled integrity checks (docs/88, docs/41).

| Key | Default | Meaning and trade-off |
|-----|---------|------------------------|
| `Enabled` | `true` | Captures the store fingerprint at every clean shutdown, compares it at the next start, and runs the scheduled checks. On by default because it is read-only and cheap (table counts plus one small ledger scan) and because an alarm that has to be switched on by hand is an alarm nobody has. Turning it off removes offline-modification detection entirely and disables every check below. |
| `QuickCheckEnabled` | `true` | Daily bounded `PRAGMA quick_check`: a structural walk of the B-trees without verifying every page against its checksum. Cheap enough to run unattended. |
| `FullCheckEnabled` | `false` | `PRAGMA integrity_check` reads every page: minutes on a multi-gigabyte store, so it is opt-in. When enabled it only ever starts inside the maintenance window. |
| `FullCheckIntervalDays` | `7` | Days between full checks; clamped to 1..365. The cadence is read from the journal, so a restart does not reset it. |
| `MaintenanceWindowStartHourLocal` | `3` | Local hour the window opens; clamped to 0..23. |
| `MaintenanceWindowDurationHours` | `4` | Window length; clamped to 1..24. A window that crosses midnight (22 + 6) wraps, because that is what the operator means. |
| `ForeignKeyCheckEnabled` | `true` | Runs `PRAGMA foreign_key_check` in the scheduled pass: cheap relative to a full check and it catches referential damage `quick_check` accepts. |

Every check is an observation: no code path repairs, truncates or rebuilds the store from a result. A
check that could not run is journaled as `Warning`, never as `Ok`.

### `RdpAudit:Storage:Encryption`

The encryption-at-rest seam. **No data is encrypted in this release**; the decision record is
`docs/89-encryption-at-rest-decision.md`.

| Key | Default | Meaning and trade-off |
|-----|---------|------------------------|
| `Mode` | `None` | `None` — plain files protected by ACLs (today's behaviour). `VolumeManaged` — the volume (BitLocker / hardware) does the work; accepted with a start-up warning, because the product cannot verify the volume's state and the setting is therefore an operator assertion. `SqlCipher` — **not implemented, and selecting it refuses to start** rather than run with plain-text files under a setting that says they are encrypted. |
| `KeySecretName` | `""` | The **name** of the secret that would hold the database key, resolved through the existing `ISecretProtector` (DPAPI machine scope, TPM-backed later). Never the key itself: no key material belongs in `appsettings.json`, logs, IPC responses or diagnostics. |
| `KeyRotationDays` | `0` | Intended key-rotation interval; unused until a mode is implemented. |

The assertion runs twice: once in `Program` before the host is built, and again in `AuditDbInitializer`
immediately before the store would be opened, so an alternative host wiring cannot bypass the refusal.
The Database tab's overview reports the mode in force (`EncryptionMode`) next to the store's size.
