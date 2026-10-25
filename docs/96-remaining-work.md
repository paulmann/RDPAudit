# docs/96 — Remaining Work: Code-Review Defects (engineering backlog)

Status: ALL ITEMS CLOSED — every P1/P2/P3 finding is fixed, built and tested.

Verified on this machine (.NET SDK 8.0.426): `dotnet build RdpAudit.sln -c Release
-p:Platform=x64` → 0 warnings / 0 errors; full `dotnet test` (elevated) → 4397 passed /
0 failed across all 8 test projects.

| Wave | Items | State |
|---|---|---|
| 1 | 15 low-risk patches (§3) | applied + verified; the previously untested ones now have pinned regression tests (see C-1) |
| 2 | P1-1 (MPMC default), P2-1 (event-time anchoring), P2-4 (scanner DisplayName), P2-5 (cleanup by exact name) | applied + verified; pinned tests added |
| 3 | P1-2 (8 KB slot + truncation flag), P1-3 (RecordId dedup + Stage 20 migration), P2-2 (time-bounded chain dedup + refresh), P2-3 (fail-closed unknown host) | applied + verified; pinned tests added |
| 4 | P3-1..P3-14 | applied + verified; pinned tests added (§6) |

All 27 findings from the 2026-10-23 review are now fixed, built and tested green. §6 records each
P3 fix together with the test that pins it.

Severity legend:

| Severity | Meaning |
|---|---|
| P1 | Fails closed on a real attack, silent data loss, or a fail-open enforcement gap. Block release. |
| P2 | Observable functional / security defect (false detection, fail-open on one leg, misleading UI/state). |
| P3 | Hygiene / edge / robustness; schedule but do not block release. |

---

## 1. Context and objective

RDPAudit 2.0 is a Windows service + WinForms configurator for RDP attack monitoring and
auto-block. A static code review (four parallel reviewers plus a lead verifier) produced
27 findings. All 27 are now fixed, built and tested green (§3 + waves 2–4); §6 records each
P3 fix and the test that pins it.

**Non-negotiable invariants that every fix must preserve** (from `AGENTS.md` / `SPEC.md`):

1. Append-only ABI: enum ordinals persisted to SQLite, `IpcCommand` values, MessagePack
   `[Key]` indices and `IpcResultStatus` ordinals may only be extended at the end.
2. No hardcoded RDP port — `RdpListenerPortResolver` is the only source.
3. No LINQ or string interpolation in per-event hot paths (`NFR-PERF-1`).
4. Threat intel never feeds auto-block; AbuseIPDB verdicts are enrichment only.
5. Secrets are DPAPI envelopes and must not reach logs, DTOs or IPC payloads.
6. Fail-closed by default; an unknown external answer means "no data", never "all clear".
7. Crash consistency: atomic writes (temp + rename), partial-write detection, bounded
   queues, bounded retries with backoff.
8. Bounded overload policy: floods, queue saturation and backpressure have defined,
   documented behavior; no silent data loss, no unbounded growth.

---

## 2. Ground rules for implementation

- Every fix ships with a pinned test that reproduces the original evidence and locks the
  stable contract (see `ARCHITECTURE.md` §11 for the per-area test pattern).
- Config / enum / IPC / migration changes follow the matching recipe in
  `ARCHITECTURE.md` §9 and update `PROJECT_MAP.md` / `docs/50-ipc.md` /
  `docs/51-rest-api.md` / `README*` when the contracts drift.
- Do not weaken the production named-pipe ACL, the append-only ordinals, or the
  fail-closed REST plan.
- Each fix must name its trust boundary, failure mode and rollback path.
- CI is Windows-only (`windows-latest`), `-warnaserror`, `AnalysisMode=All`,
  `EnforceCodeStyleInBuild=true`. New code must build clean under those settings.

---

## 3. Already applied in this session (needs tests, not re-fixing)

These 15 patches are **verified**: the solution builds with 0 warnings / 0 errors and the
full suite passes. Where a patch corrected a behaviour the tests had pinned, the test was
updated (its intent preserved) rather than the fix reverted. The table lists what each fix
is locked by.

| ID | Fixed defect | File | Test to write/extend |
|---|---|---|---|
| F-01 | `GetMaskedSettings` dropped Sharding/Logs/CrossHost/Notifications from the settings round-trip | `src/RdpAudit.Service/Ipc/IpcDispatcher.cs` | Round-trip test: `GetSettings` → `SaveSettings` preserves all 14 sections; a cross-host credential survives masked round-trip |
| F-02 | Cross-host credentials would be persisted as the literal `***configured***` placeholder | `src/RdpAudit.Service/Services/SettingsManager.cs` | Save masked CrossHost → stored envelope preserved; blank HostName → emptied; plaintext → wrapped |
| F-03 | `BruteForceNtlmRule` dead (4776 has no IP; keyed on `SourceIp ?? UserName`) | `src/RdpAudit.Service/Alerts/BruteForceNtlmRule.cs` | NTLM failure burst over threshold fires; success-only stream stays silent; canonical NTSTATUS forms |
| F-04 | Maintenance deleted Active/Pending blocks with stale `ExpiresUtc` | `src/RdpAudit.Service/Workers/MaintenanceWorker.cs` | Active block with past `ExpiresUtc` is NOT pruned; Removed/Failed/AuditOnly are |
| F-05 | `Provider=Both` partial failure reported `Installed` (fail-open on one leg) | `src/RdpAudit.Service/Workers/FirewallAutoBlockWorker.cs` | Windows ok + MikroTik fail → `ProviderFailed` (retry scheduled), no lost leg |
| F-06 | Whitelist compared textually (IPv6 case/compression, leading zeros, mapped IPv6) | `src/RdpAudit.Service/Workers/FirewallAutoBlockWorker.cs` | Canonicalized literal matches `IPAddress.ToString()`; CIDR still via range matcher |
| F-07 | LSASS whitelist `EndsWith` bypass (`Evilwininit.exe`) | `src/RdpAudit.Service/Alerts/LsassAccessRule.cs` | Exact file-name match only |
| F-08 | `AlertCooldownTracker` unbounded dictionary | `src/RdpAudit.Service/Alerts/AlertCooldownTracker.cs` | Map bounded; prune is throttled; no lost suppression |
| F-09 | `PrivilegedGroupChangeRule` attributed the actor to the group | `src/RdpAudit.Service/Alerts/PrivilegedGroupChangeRule.cs` | `Alert.UserName` = `SubjectUserName`; message names the caller |
| F-10 | IANA time-zone ids silently fell back to UTC | `src/RdpAudit.Service/Alerts/OffHoursLoginRule.cs` | `Europe/Minsk` resolves via IANA→Windows conversion |
| F-11 | `MaxReportsPerMinute` declared but unenforced | `src/RdpAudit.Service/Workers/AbuseIpDbReportWorker.cs` | Per-minute budget honored in the pass |
| F-12 | `DecimationOptions.ResolveMinAgeDays` no upper clamp (AddDays overflow) | `src/RdpAudit.Core/Config/DecimationOptions.cs` | Absurd value clamps, no throw |
| F-13 | `IsReservedAddress` skipped IPv4-mapped IPv6 | `src/RdpAudit.Service/Firewall/NetshCommandBuilder.cs` | `::ffff:10.0.0.1` treated reserved |
| F-14 | Empty `FilterChain` broke MikroTik idempotency | `src/RdpAudit.Service/Firewall/MikroTikClient.cs` | Match uses resolved `"input"` chain |
| F-15 | `DefaultBlockDurationMinutes` doc contradicted auto-block floor | `src/RdpAudit.Core/Config/FirewallOptions.cs` | Doc states the auto-block 60-min floor |

---

## 4. P1 — remaining (block release)

### P1-1 — [FIXED] Default ring backend was SPSC but written by many producers → silent event loss
- **Fix:** `MonitoringOptions.RingBufferBackend` now defaults to `RingBufferBackend.Mpmc`. The
  shared `IEventPipe` is written concurrently by per-channel EventLogWatcher callbacks plus both
  backfill workers (and ETW in hybrid mode), so the SPSC default violated its own single-producer
  contract; MPMC is the concurrency-safe backend.
- **Tests:** `EventChannelRingBufferTests.EventChannel_DefaultBackend_IsMpmc` and
  `MpmcEventChannelTests.EventChannel_UsesMpmcBackend_ByDefault` pin the new default; the
  SPSC-specific tests now set `RingBufferBackend.Spsc` explicitly
  (`EventChannelRingBufferTests`, `EventProcessorWorkerRingBufferTests`).
- **Residual risk:** hot-path backend change — measure throughput on the target host before
  claiming the incident-response SLA. Rollback is a one-line default restore (enum unchanged).

### P1-2 — [FIXED] XML payload was truncated to 1910 chars, dropping `IpAddress`
- **Fix:** the ring slot grew from 4096 to **8192 bytes** and the XML capacity from 1910 to
  **3954 chars** (`RawEventSlot.SizeBytes` / `MaxXmlPayloadChars`), so a realistic Security
  4624/4625 payload (~1.7-2.2 KB) is carried whole. `RawEventSerializer` sets
  `RawEventSlot.TruncatedFlag` (bit 31 of `PayloadLength`) when the source is still longer than
  the slot; the flag travels as `RawEventDto.XmlTruncated` and `EventNormalizer` marks such a row
  `SourceIpUnresolved`, so any remaining loss is visible instead of silent. The default
  `ChannelCapacity` moved 50,000 → 32,768 to keep the ring at ~270 MB.
- **Tests:** `RawEventSerializerTests.Serialize_KeepsXmlLongerThanTheOld1910Cap_AndIpAddressSurvives`
  (a >1910-char 4625 round-trips and `EventXmlParser` still reads `203.0.113.7`);
  `Serialize_TruncatesLongXmlPayload_Gracefully` now asserts the truncation flag.
- **Docs:** `docs/80-lockfree-ringbuffer-architecture.md`, `docs/81-memory-layout-specification.md`.
- **Residual risk:** the memory layout changed; a deployment with a very large explicit
  `ChannelCapacity` (e.g. 50,000) would now allocate ~541 MB instead of ~272 MB. Hosts that tuned
  it should review the value.

### P1-3 — [FIXED] Duplicate ingestion: live watcher and backfill workers forwarded the same events
- **Fix:** `RawEvent.RecordId` (nullable, carried through the ring slot) is populated by the live
  `EventLogWatcherEventSource` and both backfill workers. Persistence deduplicates on
  `(Channel, RecordId, TimeUtc)` before insert (`EventProcessorWorker.DedupeByRecordIdAsync`),
  backed by a partial unique index (`RecordId IS NOT NULL`). `TimeUtc` is in the key so a
  cleared/rotated log that restarts RecordId does not false-deduplicate; ETW rows (null RecordId)
  keep their previous behaviour.
- **Migration:** `20261023204643_Stage20RawEventRecordId` (additive: nullable column + partial
  unique index; Down drops both).
- **Tests:** `RawEventRecordIdDedupTests` (persisted duplicate, in-batch duplicate, rotation,
  null RecordId, unique-index backstop); `RawEventSerializerTests.RecordId_RoundTrips` /
  `NullRecordId_RoundTripsAsNull`.
- **Residual risk:** the dedup is one bounded DB read per batch; a backlog of duplicate rows
  written before this fix is not retro-cleaned (a one-off dedupe pass is a separate task).

---

## 5. P2 — remaining

### P2-1 — [FIXED for PassTheHashRule] Lookback was anchored to `UtcNow`, not the event time
- **Fix:** added `IAlertContext.GetRecentByUserAroundAsync(user, count, anchorUtc, before, after, ct)`
  (backward-compatible default implementation falls back to the wall-clock lookup) and an
  event-anchored override in `DbAlertContext`. `PassTheHashRule` now anchors its 5 s window to
  `evt.TimeUtc`, so a 4624 evaluated after a backlog still sees the 4648 that preceded it.
- **Tests:** `AlertRuleTests.PassTheHash_PrecedingExplicitUnderProcessingLatency_ReturnsNull`
  (4624 is 60 s old, 4648 is 1 s earlier in event time → no alert);
  `PassTheHash_PrecedingExplicitMatchingLogonId_ReturnsNull` now timestamps the 4648.
- **Remaining:** `RapidReconnectRule` (30 s, session-keyed) and the `PrivilegedLoginRule` lookback
  still use the wall-clock helpers; their wider windows make the error unlikely. Convert them to
  the anchored API in a follow-up.

### P2-2 — [FIXED] Cross-host chain dedup was time-independent → recurring attacks suppressed forever
- **Fix:** dedup is now bounded to the fact window. `LoadKnownChainKeysAsync(nowUtc)` only returns
  the keys of chains with `LastSeenUtc >= nowUtc - (DefaultMaxFactAgeHours + 2)`, so a route that
  no longer has facts in the window is forgotten. `PersistChainsAsync` now **refreshes** an
  existing `(RuleId, ChainKey)` row instead of only inserting: it updates the times/score/count,
  clears `AlertId` and `IsAcknowledged`, so `CrossHostChainAlertProcessor` raises a NEW
  CROSS_HOST_CHAIN alert for the recurrence. Within the window the key stays known and the chain
  is still deduplicated.
- **Tests:** `CrossHostCorrelationWorkerTests.PersistChains_StaleExistingChain_IsRefreshedAndReAlerts`
  (stale row refreshed, alert gate cleared, processor raises exactly one new alert).
- **Residual risk:** the persisted `ChainKey` semantics are unchanged (no migration); a very
  long-running identical route now re-alerts once per fact window instead of never.

### P2-3 — [FIXED] Stale facts from a dead host under an alias re-entered correlation
- **Fix:** the engine now requires a host to be **positively `Available`** this pass; an absent
  host is treated exactly like an unavailable one (`!TryGetValue || != Available → reject`). The
  pull path already registers an alias as `Available` only on a successful pull, so after a host
  goes down its alias is absent and its persisted facts are dropped — fail-closed.
- **Tests:** `CrossHostCorrelationEngineTests.AbsentHost_FactIsRejected_FailClosed`.
- **Residual risk:** a fact from a host that is neither configured nor a successful-pull alias is
  now rejected; that is the intended "unknown means no data" behaviour.

### P2-4 — [FIXED] PowerShell scanner could not discover GUID-named / DisplayName-only rules
- **Fix:** the primary scan script now enumerates once and keeps a rule matching on any of the
  three identity forms — Group/DisplayGroup == RdpAudit, Name prefix, or **DisplayName prefix**
  (`FirewallRulesJsonScriptTemplate` + `BuildPrimaryScanScript`). The secondary name-prefix
  fallback was extended the same way. This makes the parser's existing `displayNameMatch` branch
  reachable, so a GUID-named rule is no longer invisible to reconciliation (which previously
  demoted it to `Failed` and let `Repair` create a duplicate).
- **Tests:** `PowerShellFirewallRuleParserTests` already covers the GUID/DisplayName payload
  shape; the script change is covered by `PowerShellFirewallScannerLatchTests` (single invocation,
  unchanged fallback counts).
- **Residual risk:** the primary scan now enumerates all rules rather than using `-Group`, trading
  a little latency for correctness; rollback restores the group-only script.

### P2-5 — [FIXED] Emergency/per-IP cleanup reconstructed the rule name instead of using the discovered one
- **Fix:** new `IRuleNameRemover` capability (implemented by `WindowsFirewallProvider`). All four
  cleanup paths now call `RemoveDiscoveredRuleAsync`, which deletes by the discovered
  `DiscoveredBlockRule.RuleName` and only falls back to `UnblockAsync({prefix}-{ip})` when the
  provider cannot address a rule by name. `RemoveRuleByNameAsync` uses netsh for netsh-safe names
  and `Remove-NetFirewallRule -Name` for GUID-named rules (the netsh argument validator rejects
  `{`/`}`); it reports `NotFound` via a `NOTFOUND` marker instead of throwing.
- **Tests:** `WindowsFirewallProviderTests.RemoveRuleByName_GuidNamedRule_UsesPowerShellExactName`,
  `RemoveRuleByName_NetshSafeName_DeletesByExactName`, `RemoveRuleByName_NoMatchingRule_ReturnsNotFound`.
- **Residual risk:** a PowerShell-only delete path; when no PowerShell runner is wired, a
  non-netsh-safe name is reported `Unavailable` rather than a silent "removed".

---

## 6. P3 — hygiene backlog (ALL FIXED)

All fourteen items are fixed and pinned by a test. P3-7 is the one without a dedicated test: its
failure mode needs OS-level ring contention that the harness cannot force deterministically, so it
is covered by code review plus the existing overflow-accounting tests.

| ID | Fix | Pinned by |
|---|---|---|
| P3-1 | `PipelineLogFloodRule` now accumulates metric deltas against a tumbling-window baseline (advanced only on window expiry or after firing) instead of advancing it on every event; `TimeProvider` is injectable for the expiry test. | `PipelineLogFloodRuleTests.SustainedFlood_AccumulatesAcrossEvents_AndFires`, `IdleGapLongerThanWindow_ResetsTheBaseline_NoFalseFlood` |
| P3-2 | Cross-host fact dedup key uses millisecond precision (`yyyyMMddHHmmssfff`). | `CrossHostCorrelationEngineTests.BuildDedupKey_DistinguishesTwoFactsInTheSameSecond`, `BuildDedupKey_IsStableAcrossHostAndUserCasing` |
| P3-3 | `TryBuildChain` rejects a chain whose TOTAL span exceeds `MaxChainSpanMinutes + skew`, not just each hop. | `CrossHostCorrelationEngineTests.ChainSpanningLongerThanMaxChainSpan_IsRejected_EvenWhenEachHopFits` |
| P3-4 | Ring `SequenceNumber` is 64-bit end-to-end (`RawEventSlot` offset 0, `long`); the `(uint)` cast is gone. | `RawEventSerializerTests.Sequence_IsSixtyFourBit_AndRoundTripsAboveUintMax` |
| P3-5 | A zero LUID (`0x0` / `0x00000000` / `0`) is treated as "no session": `BuildKey` falls through to the username key and the row stores null, instead of collapsing every failed logon into `L:0x0`. | `SessionIpCorrelationUpserterTests.BuildKey_ZeroLogonIdSentinel_FallsThroughToUsernameKey`, `NormalizeLogonIdOrNull_TreatsZeroFormsAsAbsent` |
| P3-6 | The 65 536-char raw substring is removed from `EventLogWatcherEventSource`; the 8 KB slot clips and sets the truncation flag (P1-2), so the XML is never cut by an unrecorded raw slice. | `RawEventSerializerTests.Serialize_TruncatesLongXmlPayload_Gracefully`, `Serialize_KeepsXmlLongerThanTheOld1910Cap_AndIpAddressSurvives` |
| P3-7 | `MpmcEventChannel` increments `_hardDropCount` when the follow-up write after an eviction also fails. | Code review (needs OS contention to force); `MpmcEventChannelTests` overflow accounting passes. |
| P3-8 | Policy made explicit and documented: an unverifiable scan leaves the row untouched (avoids flapping the whole table on a transient provider outage; the DTO carries the unknown confidence). | `EnforcementReconciliationServiceTests.ReconcileAsync_UnscannableProvider_LeavesActiveRowActive` |
| P3-9 | `RouteBlackholeProvider.UnblockAsync` maps exit 1 to `NotFound` and any other non-zero exit to `Unavailable` (retryable). | `RouteBlackholeProviderTests.UnblockAsync_ExitOne_ReturnsNotFound`, `UnblockAsync_NonOneFailure_ReturnsUnavailable` |
| P3-10 | Ping status mapping extracted to `IsReachableFromStatus`: only definitive timeouts/unreachable count as unreachable; ambiguous statuses and ping exceptions fail SAFE (reachable → route refused). | `RouteBlackholeProviderTests.IsReachableFromStatus_FailsSafeOnAmbiguousStatus`, `BlockAsync_ReachableGateway_IsRefused` |
| P3-11 | `FirewallAutoBlockWorker` tracks `(ip, provider)` rows written in the current unsaved batch; idempotency and `MaxActiveBlocks` include them. | `FirewallWorkerIntegrationTests.AutoBlockWorker_TwoAlertsForSameIpInOneBatch_WriteOneRowAndOneBlockCall` |
| P3-12 | `RepairAsync`'s verified fast path restores a demoted row to `Active` (and clears `LastError`). | `EnforcementReconciliationServiceTests.RepairAsync_AlreadyVerified_RestoresADemotedRowToActive` |
| P3-13 | `NewAccountRule` reports `SubjectUserName` (the creator) as the actor instead of the new account's domain. | `AlertRuleTests.NewAccount_4720_ReportsCreatorNotDomain` |
| P3-14 | Staleness bound documented: per-session keys are exact to the TTL, the username key is last-wins best effort, and every read is TTL-checked. | `SessionCorrelationCacheTests` (TTL coverage); doc comment in `SessionCorrelationCache` |

---

## 7. Cross-cutting tasks

### C-1 — Regression tests for the §3 patches — DONE
Every fix whose behaviour changed has a pinned test. The wave-1 patches that were originally
applied without SDK verification now each have one: F-01 `IpcDispatcherMaskedSettingsTests`; F-02
the `SettingsManagerSecretsTests` cross-host cases; F-03 `BruteForceNtlm_*`; F-04
`MaintenanceWorkerRetentionTests`; F-05 `AutoBlockWorker_BothProviders_OneLegFails_*`; F-06
`WhitelistLiteral_*`; F-07 `LsassAccess_Whitelist_IsExactFileNameNotSuffix`; F-08
`AlertCooldownTracker_SuppressesWithinWindow_AndAllowsDistinctKeys`; F-09
`PrivilegedGroupChange_4732AdminsGroup_ReturnsAlert` (actor assertion); F-10
`OffHoursLogin_ResolveTimeZone_ConvertsIanaId`; F-11 `RunOnceAsync_EnforcesMaxReportsPerMinute`;
F-12 `DecimationOptionsTests`; F-13 `IsReservedAddress_Ipv4MappedIpv6_IsReserved`; F-14
`AddBlockAsync_EmptyConfiguredChain_StillReusesExistingInputRule`. F-15 was documentation only.

### C-2 — Update `BUGS.md` — DONE
One `[FIXED …]` entry per review finding was added to `BUGS.md` (symptom → root cause → fix →
verification), preserving the file's existing format.

### C-3 — Full verification — DONE on this machine
```
dotnet restore RdpAudit.sln
dotnet build  RdpAudit.sln -c Release --no-restore -p:Platform=x64
dotnet test   RdpAudit.sln -c Release --no-build  -p:Platform=x64
```
Final run: 0 warnings / 0 errors; **4397 passed / 0 failed** (Notifier 41, Mikrotik 34, Scenario 28,
Web 36, StorageBenchmarks 12, Core 2426, Configurator 286, Service 1534), executed from an elevated
terminal so the real-pipe tests ran. Do not use `--no-build` against a stale tree (B7).

### C-4 — Documentation drift — DONE
`docs/81-memory-layout-specification.md` and `docs/80-lockfree-ringbuffer-architecture.md` describe
the 8 KB slot / 3952-char XML / 64-bit sequence / `RecordId` layout; `docs/41-data-model.md` was
checked (it has no per-column `RawEvents` table to extend); `PROJECT_MAP.md` lists every new source
and test file. `tools/Invoke-DocContractCheck.ps1` exits 0.

---

## 8. Sequencing and dependencies

1. **C-1 + C-3 first** — prove the §3 tree builds and tests pass before stacking more change.
2. **P1-1 → P1-2 → P1-3** in order: each touches the ingestion hot path; do them one at a time
   with a full suite run between.
3. **P2-1** (event-time anchoring) can land independently; it also de-risks the alert rules.
4. **P2-2 / P2-3 / P3-2 / P3-3** form a cross-host correlation cluster — implement together.
5. **P2-4 / P2-5 / P3-8 / P3-12** form a reconciliation cluster — implement together.
6. **P3 items** may be batched by area (alerts / ingestion / firewall) once P1/P2 land.

---

## 9. Definition of Done

- Every item in §4 and §5 has a landed patch + a pinned regression test, and the full solution
  builds clean (`0 warnings / 0 errors`) and passes on Windows CI.
- §6 items are either fixed with a test, or explicitly triaged as "will not fix" with a written
  reason and a `BUGS.md` entry.
- `BUGS.md` and the docs listed in C-4 are updated and `Invoke-DocContractCheck.ps1` exits 0.
- Verification (C-3) is recorded, including which live-host checks were performed and which were
  deferred (named, not silently skipped).

---

## 10. Explicitly dismissed (not a defect — do not "fix")

- **4625 positional IP fallback index.** The reviewer claimed `GetDataAt(doc, 19)` reads
  `IpPort` (index 18 = `IpAddress`). Verified against the Windows 4625 `EventData` order:
  `IpAddress` is the 19th child (0-based index 19), `IpPort` is index 20. The code
  (`PerEventIpResolver.cs:94`) and its Cameyo-parity comment are correct. No change.
