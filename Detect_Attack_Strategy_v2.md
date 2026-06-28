# RdpAudit Attack Detection Strategy — v2.0

> **Version:** 2.0
> **Scope:** Windows 10/11, Windows Server 2012 R2 – 2025, RDS Session Host, RD Gateway, standalone hosts
> **Audience:** Senior Windows security engineers, detection engineers, RdpAudit developers

---

## 1. Mental Model: The RDP Authentication Stack

A correct detection strategy must understand which layer emits which event and which fields each layer knows.

| # | Layer | Component | Channel | Key Events | What It Knows |
|---:|---|---|---|---|---|
| 1 | TCP/TLS Transport | TermService / RdpCoreTS | RdpCoreTS/Operational | **131**, **140**, 65, 141 | Source IP, source port — **NOT** username |
| 2 | RD Gateway (optional) | TSGateway | TS-Gateway/Operational | **302**, **303**, 304, 305 | External client IP, target server, username |
| 3 | NLA / CredSSP | LSASS (SSP chain) | Security, NTLM/Operational | **4776**, 8001/8004; DC: **4768**/**4771** | Username, auth package, result — often **no IP** on target |
| 4 | Local Security Authority | LSA | Security | **4624**, **4625**, **4648**, 4634, 4647 | LogonType, credentials, IP (when NLA doesn't strip it) |
| 5 | Session / Shell | Termsrv / Userinit | LSM/Operational, RCM/Operational | LSM **21/22/23/24/25/39/40**; RCM **1149**, 261 | Session ID, user, client IP (LSM 21 Address) |

**The root cause of "4625 without IP"**: NLA + NTLMv2 authenticates the user *before* a logon ticket reaches the LSA. By the time Event 4625 is written, the source IP has been consumed by the transport layer. The IP must be recovered from RdpCoreTS 131/140 via time-correlated enrichment.

---

## 2. Objectives

- **Detect brute-force, password spray, targeted account, credential stuffing, and post-compromise lateral movement** — each as a distinct classification with MITRE ATT&CK mapping.
- **Capture the full RDP lifecycle**: TCP arrival → NLA challenge → credential validation → LSA logon → session creation → shell ready → reconnect/disconnect → logoff.
- **Survive audit-policy gaps**: degrade gracefully with explicit diagnostics when Security audit is disabled, NLA hides IPs, or logs have rolled over.
- **Never invent facts**: every field carries `EnrichmentSource` and `EnrichmentConfidence`. Counters increment only from authoritative evidence.
- **Detect advanced RDP attacks**: Session Hijacking (tscon.exe), Restricted Admin Mode / Pass-the-Hash over RDP, and post-compromise persistence.
- **Stay lightweight**: bounded backfill, indexed queries, batched writes, bounded correlation buffers.

---

## 3. Data Sources

### 3.1 Windows Security Log

**Required Audit Policy (Advanced Audit Policy Configuration):**

| Subcategory | Required | Why |
|---|---|---|
| Logon | Success + Failure | 4624/4625/4648 |
| Logoff | Success | 4634/4647 |
| Special Logon | Success | 4672 (privileged logon) |
| Other Logon/Logoff Events | Success | 4778/4779 (reconnect/disconnect) |
| Credential Validation | Success + Failure | 4776 (NTLM validation) |
| Kerberos Authentication Service | Success + Failure | 4768/4771 (DC only) |
| Account Lockout | Success | 4740 |
| Security Group Management | Success | 4732/4733 (post-compromise) |

**Complete Event Table:**

| EID | Meaning | RDP Logon Types | Key Fields |
|---:|---|---|---|
| 4625 | Failed logon | **10** (RDP), **3** (NLA), 7 | TargetUserName, IpAddress (may be blank under NLA), Status, SubStatus, LogonType |
| 4624 | Successful logon | **10**, **3** (NLA), **7** (reconnect) | TargetUserName, IpAddress, TargetLogonId, AuthenticationPackageName |
| 4634 | Logoff | by TargetLogonId | Session duration closure |
| 4647 | User-initiated logoff | — | Stronger than 4634 for explicit sign-out |
| 4648 | Explicit credentials | — | RunAs/saved credentials, lateral movement indicator |
| 4672 | Special privileges assigned | — | Admin RDP sessions, sensitive privilege detection |
| 4776 | NTLM credential validation | — | TargetUserName, Workstation (no IP), Status |
| 4771 | Kerberos pre-auth failed | — | TargetUserName, **IpAddress** (carries client IP!), Status |
| 4778 | Session reconnected | — | AccountName, ClientName, ClientAddress |
| 4779 | Session disconnected | — | AccountName, ClientName, ClientAddress |
| 4740 | Account locked out | — | TargetUserName, CallerComputerName |
| 4825 | RDP access denied | — | Authenticated but lacks Remote Desktop Users rights |

**SubStatus Code Reference (Critical for Attack Classification):**

| SubStatus | Meaning | Attack Indicator |
|---|---|---|
| 0xC000006A | Wrong password | Brute-force / credential stuffing |
| 0xC0000064 | User does not exist | User enumeration / spray |
| 0xC0000234 | Account locked | DoS / aggressive brute-force |
| 0xC0000072 | Account disabled | Stale account targeting |
| 0xC000006F | Outside logon hours | Not attack (legitimate restriction) |
| 0xC0000071 | Password expired | Not attack (user friction) |
| 0xC0000133 | Clock skew | Diagnostic, not attack |
| 0xC000015B | Logon type not granted | Authorization failure, not credential failure |

**Logon Type Handling:**

| LogonType | Meaning | RDP Relevance |
|---:|---|---|
| 10 | RemoteInteractive | Strong RDP indicator (non-NLA or post-NLA session) |
| 3 | Network | **Can be NLA-RDP** when correlated with CredSSP/RdpCoreTS/RCM |
| 7 | Unlock | Reconnect/unlock, relevant with 4778/LSM 25 |

**Rule:** Do not rely on LogonType 10 alone. With NLA enabled (default), RDP failures manifest as Type 3. Classification requires correlation with RdpCoreTS/RCM events.

**Parsing Rules:**

1. Parse via named `EventData/Data[@Name=…]` first; positional `Properties[i]` is fallback only (emit `ParserFallbackUsed` diagnostic).
2. Use XXE-safe XML settings: `DtdProcessing = Prohibit`, `XmlResolver = null`, max 256 KiB.
3. Capture `ToXml()` before `EventRecord` disposal; cap at 64 KiB.
4. Treat `IpAddress` values of `-`, `::1`, `127.0.0.1`, `0.0.0.0` as **absent** (flag for enrichment).

**Compatibility Fallback Indexes:**

| EID | Field | Index | Notes |
|---:|---|---:|---|
| 4625 | TargetUserName | 5 | Legacy template only |
| 4625 | IpAddress | 19 | Use only if named `IpAddress` empty/absent |
| 4625 | IpPort | 20 | |
| 4625 | LogonType | 10 | |
| 4625 | Status | 7 | |
| 4625 | SubStatus | 9 | |
| 4624 | TargetUserName | 5 | |
| 4624 | IpAddress | 18 | |
| 4624 | LogonType | 8 | |
| 4648 | TargetUserName | 5 | |
| 4648 | IpAddress | 12 | |
| 4771 | TargetUserName | 0 | |
| 4771 | IpAddress | 6 | Kerberos pre-auth client IP |
| 4776 | TargetUserName | 1 | |
| 4776 | Workstation | 2 | |

---

### 3.2 Terminal Services LocalSessionManager/Operational

| EID | Meaning | Primary Use |
|---:|---|---|
| 21 | Session logon succeeded | Session ID, user, **Address** (gold standard for client IP) |
| 22 | Shell start | Interactive session readiness confirmation |
| 23 | Session logoff | Session end |
| 24 | Session disconnected | Disconnect state |
| 25 | Session reconnected | Reconnect timeline |
| 39 | Session disconnected by another session | Console takeover indicator |
| 40 | Session disconnect/reconnect reason | Reason code enrichment |

**LSM 40 Key Reason Codes:**

| Code | Meaning |
|---:|---|
| 0 | No additional information |
| 5 | Replaced by another connection |
| 11 | User-initiated disconnect |
| 12 | User-initiated logoff |

**Important:** LSM 21 `Address` field contains:
- Client IP for remote sessions
- `LOCAL` for console sessions
- Possibly IPv6 `::ffff:x.x.x.x` format — normalize to IPv4

---

### 3.3 RemoteConnectionManager/Operational

| EID | Meaning | Primary Use |
|---:|---|---|
| 1149 | User authentication succeeded (NLA phase) | Username, Domain, Source IP — **strongest pre-LSA IP source** |
| 1148 | TS auth pre-stage failure | Pre-4625 failure signal |
| 261 | Listener/transport event | Weak connection signal |

**Critical:** Event 1149 fires when NLA authentication succeeds, but the overall RDP login may still fail at a later stage (e.g., account disabled, no Remote Desktop Users membership). Event 1149 must NOT be counted as a successful logon by itself — it requires correlation with 4624 or LSM 21.

---

### 3.4 RdpCoreTS/Operational

| EID | Meaning | Primary Use |
|---:|---|---|
| 65 | Connection arrival | Earliest IP fingerprint |
| 131 | Server accepted new TCP connection | **Always carries ClientIP:port** — primary IP enrichment for NLA-stripped 4625 |
| 140 | Connection failed / user not allowed | Carries source IP, proves unknown user when correlated with 4625 SubStatus 0xC0000064 |
| 141 | Disconnect after auth | |
| 82 | Corrupt/malformed payload | Protocol fuzzing / non-standard client detection |

---

### 3.5 TerminalServices-Gateway/Operational (RD Gateway role only)

| EID | Meaning | Key Fields |
|---:|---|---|
| 302 | User connected to resource | **External client IP**, target server, username |
| 303 | User disconnected | Duration, bytes |
| 304 | Resource not authorized | |
| 305 | User failed CAP/RAP | |

**When RD Gateway is present, Event 302 is the ONLY place the real external client IP appears.** Session Hosts behind the gateway see only the gateway's internal IP. RdpAudit must support remote ingestion of gateway logs and maintain both `ExternalIp` (from 302) and `RelayIp` (gateway internal).

---

### 3.6 NTLM Operational (Microsoft-Windows-NTLM/Operational)

Events 8001/8002/8004 plus Security 4776 expose every NTLM auth attempt. Required when AD policy "Restrict NTLM: Audit Incoming NTLM Traffic" is enabled. Source is `Workstation` field (NetBIOS name, not IP) — must pair with RdpCoreTS 131 for IP.

---

### 3.7 WTS Active Session State (Snapshot)

| WTS Field | Purpose |
|---|---|
| Session ID | Runtime session key |
| Username | Current session user |
| Domain | Account domain |
| State | Active, disconnected, listen, idle, reset, down |
| LogonTime | Session start |
| ConnectTime | Connection time |
| DisconnectTime | Disconnected duration |
| LastInputTime | Activity signal |
| ClientAddress | Best-effort active client IP |
| ClientName | Fallback correlation key |
| ProtocolType | RDP vs console |

**Rules:** WTS is a snapshot, not history. It can refresh current state but cannot create session-fact rows. Session-fact creation must be triggered by LSM 21 or 4624 LogonType 10.

---

### 3.8 TCP Connection Snapshot

Port from: `HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\PortNumber` (fallback 3389).

| Field | Purpose |
|---|---|
| LocalAddress / LocalPort | Bound listener |
| RemoteAddress / RemotePort | Candidate client IP |
| State | Established, TimeWait, etc. |
| OwningProcess | Must be TermService/svchost |
| SnapshotTimeUtc | Correlation timestamp |

**Rules:** Lowest confidence. Never infer username or outcome. Only enrich IP when `OwningProcess = TermService` and `LocalPort = resolvedRdpPort` and no other source available.

---

## 4. Unified Event Model

| Property | Description |
|---|---|
| EventUid | Stable internal unique ID |
| TimeUtc | UTC timestamp (preserve 100ns ticks) |
| IngestedUtc | Ingestion time |
| Channel | Windows event channel |
| Provider | Provider name |
| EventId | Windows Event ID |
| RecordId | Event record ID |
| ActivityId | ETW correlation GUID (critical for cross-channel joins) |
| RelatedActivityId | Related ETW GUID |
| SourceIp | Normalized source IP |
| SourcePort | Source port |
| IpFamily | IPv4, IPv6, IPv4MappedIPv6 |
| IsPublicIp | Public routable indicator |
| IsLoopback | Loopback indicator |
| UserName | Attempted or authenticated user |
| NormalizedUserName | Canonical user key (lowercase, domain-stripped) |
| Domain | Account domain |
| WorkstationName | Client workstation |
| ClientName | RDP client name |
| LogonType | Windows logon type |
| LogonId | TargetLogonId correlation key |
| LogonGuid | Logon GUID |
| SessionId | WTS/Terminal Services session ID |
| ProcessName | Related process |
| AuthPackage | NTLM/Kerberos/Negotiate/CredSSP |
| LogonProcessName | User32, Advapi, NtLmSsp, CredSSP |
| Status | Failure status hex |
| SubStatus | Failure substatus hex |
| SubStatusMeaning | Human-readable translation |
| Outcome | Failed, Succeeded, Informational, Denied, Unknown |
| EvidenceClass | AuthenticationFailure, AuthenticationSuccess, SessionStart, SessionLifecycle, Transport, PostCompromise, Tamper, Diagnostic |
| EventRole | Transport, PreAuth, CredentialValidation, Authentication, Session, Shell, Disconnect, Logoff, PostCompromise, Diagnostic |
| RdpRelevance | Strong, Probable, Possible, Weak, None |
| EnrichmentSource | DirectXml, SecurityFallbackIndex, Lsm21, Rcm1149, RdpCoreTs131, RdpCoreTs140, Gateway302, Krb4771, Ntlm4776, WtsSnapshot, TcpSnapshot, ActivityIdJoin, LogonIdChain, None |
| EnrichmentConfidence | High, Medium, Low, None |
| ConflictFlags | Conflicting data across sources |
| Diagnostics | Array of diagnostic codes |
| MitreTechniques | Mapped ATT&CK techniques |
| RawXmlCapped | Capped raw XML (≤64 KiB, gzipped) |
| DetailsJson | Capped structured details |

---

## 5. Collection Pipeline

### 5.1 Watcher Path

1. Start `EventLogWatcher` per channel with narrow XPath ID filter (never `*`).
2. In callback: synchronously copy all fields and `ToXml()` (EventRecord disappears after callback returns).
3. Push to bounded `Channel<RawEvent>` (capacity 4096, drop-oldest with `WatcherBackpressure` diagnostic).
4. Never await DB/IO inside callback.
5. Restart with exponential backoff (1s → 60s, jittered).

### 5.2 Backfill Path

1. Per-channel durable bookmark (RecordId/Timestamp/EventBookmark blob).
2. On start: bounded lookback (default 24h, hard cap 7d) for critical IDs.
3. Periodic catch-up every 60s.
4. Deduplicate by `(Channel, RecordId)` primary; `Hash` secondary.
5. Never query without XPath ID filter.

**Critical Backfill Targets:**

| Channel | Event IDs |
|---|---|
| Security | 4624, 4625, 4634, 4647, 4648, 4672, 4740, 4768, 4769, 4771, 4776, 4778, 4779, 4825 |
| LocalSessionManager/Operational | 21, 22, 23, 24, 25, 39, 40 |
| RemoteConnectionManager/Operational | 1148, 1149, 261 |
| RdpCoreTS/Operational | 65, 82, 131, 140, 141 |
| TerminalServices-Gateway/Operational | 302, 303, 304, 305 |

### 5.3 Snapshot Path

- WTS sessions every 5s (or on UI demand).
- TCP table every 5s.
- Registry port + audit policy every 60s.
- All flow to current-state tables only.

---

## 6. Correlation Algorithm

Given a target event T, build candidate set from events within the time window on relevant channels, then pick by priority:

### 6.1 Correlation Keys (Priority Order)

| Priority | Key | Confidence |
|---:|---|---|
| 1 | ActivityId (ETW GUID) match | High |
| 2 | TargetLogonId | High |
| 3 | SessionId + tight window | High |
| 4 | SourceIp + TargetUser + ±10s | High |
| 5 | SourceIp + ±10s (unique candidate) | Medium |
| 6 | WorkstationName + TargetUser + ±30s | Medium |
| 7 | TargetUser + ±30s (DC cross-host) | Medium |
| 8 | TCP RemoteAddress + ±10s | Low |

**Tie-breakers:** Closest `|Δt|`, then highest source confidence, then earliest RecordId.

### 6.2 Time Windows

| Relationship | Window | Rationale |
|---|---:|---|
| RdpCoreTS 131 → Security 4625 | −2s … +15s | IP arrives before LSA fail |
| RdpCoreTS 140 → 4625 SubStatus 0xC0000064 | −2s … +15s | Unknown user case |
| RCM 1149 → Security 4624 LT10 | 0 … +90s | NLA pass → LSA finalize |
| RCM 1149 → LSM 21 | 0 … +90s | Session creation after auth |
| Security 4624 → LSM 21 | 0 … +120s | Session create after logon |
| LSM 21 → LSM 22 | 0 … +60s | Shell ready |
| LSM 24/25 → Security 4779/4778 | ±60s | |
| Security 4634/4647 → LSM 23 | ±120s | |
| Gateway 302 → 4624 LT10 (SH side) | 0 … +30s | Gateway → Session Host chain |
| 4769 (TERMSRV/host) → 4624 LT10 | 0 … +30s | Kerberos RDP path |
| WTS snapshot → LSM 21 | ±120s | |
| TCP snapshot → transport event | ±10s | |
| Failures → success (compromise check) | 0 … −30min | Configurable lookback |

### 6.3 Enrichment Rules

1. **Direct XML always wins** within the same event.
2. **IP Authority Hierarchy:** LSM 21.Address > 4778/4779.ClientAddress > Gateway 302.ClientIP > RCM 1149.SourceAddress > RdpCoreTS 131/140.ClientIP > 4624/4625.IpAddress > 4771.IpAddress > TCP snapshot.
3. **Outcome Authority:** 4624/4625 > 4776/4771 > 1149+LSM21 combined > LSM alone > RdpCoreTS/TCP (NEVER set outcome).
4. **Username for failed attempts:** Only from 4625, 4776, 4771, 1148, RdpCoreTS 140. Never from WTS or TCP.
5. **NLA-stripped 4625 rule:** If 4625.IpAddress is absent and RdpCoreTS 131/140 exists within −2s…+15s with no other 4625 in window, attach IP at confidence `High`; if multiple candidates, `Medium` + `CorrelationAmbiguous` diagnostic.
6. **Event 1149 rule:** 1149 alone does NOT count as successful logon. Promotion to Successful requires correlation with 4624 LT10 OR LSM 21 within ±90s.
7. **TCP enrichment forbidden** for any field except IP, and only when `OwningProcess = TermService` and `LocalPort = resolvedRdpPort`.
8. **Conflicts remain visible:** If sources disagree on IP/user, mark `ConflictFlags` and show both in UI.
9. **No unique candidate = no enrichment:** If multiple candidate IPs/users exist in window, leave unknown rather than guess.

### 6.4 NLA Classification Rule

For 4624/4625 with LogonType=3:
- If `AuthenticationPackageName = Negotiate` AND `LogonProcessName` contains `CredSSP` → classify as RDP/NLA
- If correlated RdpCoreTS 131 or RCM 1149 exists within window → classify as RDP/NLA
- Otherwise → classify as non-RDP network logon

---

## 7. RDP Session State Machine

```
                                 ┌──────────────────────┐
   (RdpCoreTS 131)               │                      │
   ──────────────► [Connecting] ─┤  4625 / 1148 / 140   ├─► [FailedAuth] (terminal)
                                 │                      │
                                 └─► (4624 LT10 ∨ 1149) ─► [Authenticated]
                                                              │
                                                              ▼
                                                          (LSM 21)
                                                              │
                                                              ▼
                                                       [SessionOpen] ──(LSM 22)──► [ShellReady]
                                                              │
                                              ┌───────────────┼───────────────┐
                                              ▼               ▼               ▼
                                          (LSM 24)        (LSM 25)        (4634/4647)
                                              │               │               │
                                              ▼               ▼               ▼
                                       [Disconnected] ─► [SessionOpen]    [LoggedOff] (terminal)
```

`SessionKey = SHA1(HostName || WtsSessionId || LogonId || StartedUtc:rounded-1s)` — stable across service restarts.

---

## 8. Persisted Facts

### 8.1 AuthAttemptFact (atomic — counters derived from this)

| Field | Purpose |
|---|---|
| Id | PK |
| TimeUtc | Event time |
| SourceIp | Enriched source IP |
| TargetUser, TargetDomain | |
| AuthPackage | NTLM/Kerberos/Negotiate |
| Outcome | Succeeded / Failed / Denied |
| Status, SubStatus | |
| SubStatusMeaning | Human-readable |
| LogonType | |
| LogonId | Nullable |
| EvidenceEventId, EvidenceChannel, EvidenceRecordId | Exact provenance |
| EnrichmentSource, EnrichmentConfidence | |

**All counters in IpFact and UserIpFact are computed ONLY from AuthAttemptFact.** This makes counts auditable and reproducible.

### 8.2 IP Facts

| Field | Purpose |
|---|---|
| SourceIp | Canonical IP |
| FirstSeenUtc, LastSeenUtc | |
| FailedLogons | From AuthAttemptFact where Outcome=Failed |
| SuccessfulLogons | From AuthAttemptFact where Outcome=Succeeded |
| ActiveWindowFailures | Current detection window |
| DistinctUserCount | Password spray signal |
| AttemptedUserNames | Capped distinct list |
| DominantSubStatus | Most common failure reason |
| LastFailureStatus, LastFailureSubStatus | |
| LastSuccessUtc | |
| Classification | Benign/Suspicious/Attack/Compromise/Unknown |
| AttackScore | Numeric risk score |
| IsBlocked, IsWhitelisted | |
| BlockReason, BlockedUntilUtc | |
| GeoCountry, ASN | Optional enrichment |
| LastEnrichmentSource, LastConfidence | |

### 8.3 User/IP Facts

| Field | Purpose |
|---|---|
| SourceIp, NormalizedUserName, Domain | Composite key |
| FailedCount, SuccessCount | |
| FirstSeenUtc, LastSeenUtc | |
| LastStatus, LastSubStatus | |
| IsCompromiseCandidate | Success after repeated failures |
| FailureReasons | Aggregated reason list |

### 8.4 Session Facts

| Field | Purpose |
|---|---|
| SessionKey | SHA1-derived stable key |
| WtsSessionId | Runtime session ID |
| UserName, Domain | |
| SourceIp, SourcePort | |
| ClientName, WorkstationName | |
| State | Active, Disconnected, Ended, Unknown |
| StartedUtc, ShellStartedUtc | |
| LastReconnectUtc, LastDisconnectUtc | |
| EndedUtc, LastSeenUtc | |
| LogonId, LogonGuid | |
| AuthPackage, LogonType | |
| IsPrivileged | From 4672 |
| EnrichmentSource, EnrichmentConfidence | |
| ConflictFlags | |

### 8.5 Diagnostic Facts

| Diagnostic | Trigger |
|---|---|
| SecurityLogMissing | RdpCoreTS events present, no 4625/4624 in window |
| AuditPolicyMissing.Logon | `auditpol` reports Logon ≠ Success+Failure |
| AuditPolicyMissing.CredentialValidation | 4776 cannot be emitted |
| AuditPolicyMissing.Kerberos | 4771 cannot be emitted |
| NlaStripsIp | ≥5 4625 with absent IP and matching RdpCoreTS |
| SecurityReadDenied | Service lacks read access to Security channel |
| BookmarkStale | Bookmark RecordId < oldest available |
| LogRetentionGap | Cursor older than earliest retained event |
| ChannelDisabled | Required operational channel disabled |
| ParserFallbackUsed | Named XML parse failed |
| CorrelationAmbiguous | >1 candidate at same priority |
| CorrelationLowConfidence | Best candidate priority ≥6 |
| ClockSkewSuspected | Event time ordering abnormal |
| WatcherBackpressure | Bounded channel dropped events |
| GatewayChannelMissing | RD Gateway role detected, channel unreachable |
| SecurityLogCleared | Event 1102 observed |
| AuditPolicyChanged | Event 4719 observed |
| RdpPortMismatch | Registry vs actual listener differ |

---

## 9. Attack Classification

### 9.1 Brute Force — Single Account (T1110.001)

| Signal | Evidence |
|---|---|
| Pattern | High volume 4625 from same IP targeting 1-2 users |
| SubStatus | Mostly `0xC000006A` (bad password) |
| Window | 10 min sliding |
| Threshold | ≥10 failures, IP not whitelisted |
| Confidence | High if 4625 evidence; Medium if only 4771 |

### 9.2 Password Spray (T1110.003)

| Signal | Evidence |
|---|---|
| Pattern | Many distinct usernames from same IP, low per-user count |
| SubStatus | Mix of `0xC0000064` (no user) and `0xC000006A` (bad pwd) |
| Window | 30 min |
| Threshold | ≥8 distinct users AND max per-user ≤3 AND ≥90% failures |

### 9.3 User Enumeration

| Signal | Evidence |
|---|---|
| Pattern | Same IP, many usernames, SubStatus overwhelmingly `0xC0000064` |
| Distinction | Enumeration = almost all "no such user"; spray = mix with "bad password" |

### 9.4 Targeted Account Attack (T1110.001)

| Signal | Evidence |
|---|---|
| Pattern | ≥25 failures for one (SourceIp, TargetUser) with same SubStatus |
| Window | 24h |

### 9.5 Account Lockout Attack

| Signal | Evidence |
|---|---|
| Pattern | Multiple 4625 → 4740 lockout |
| Threshold | External IP caused lockout |

### 9.6 Successful Compromise After Brute-Force (T1078 + T1021.001)

| Signal | Evidence |
|---|---|
| Pattern | 4624 LT10 / LSM 21 from IP that had ≥3 prior failures for same user |
| Window | 30 min lookback from success |
| Severity | **Critical** — auto-escalate |

### 9.7 RDP Session Hijacking (T1563.002)

| Signal | Evidence |
|---|---|
| Pattern | Event 4778 (reconnect) where ClientName/ClientAddress unexpectedly changes |
| OR | Reconnect executed under NT AUTHORITY\SYSTEM (tscon.exe via service/PsExec) |
| AND | No preceding 4624 from that user for the new client |
| Detection | Compare 4778.ClientAddress against last known 4779.ClientAddress for same SessionId |

### 9.8 Restricted Admin Mode / Pass-the-Hash over RDP (T1550.002)

| Signal | Evidence |
|---|---|
| Pattern | 4624 LogonType 3 + AuthPackage=NTLM from external IP over RDP port |
| AND | No subsequent LogonType 10 for same user/time |
| AND | Restricted Admin Mode registry key enabled |
| Registry | `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\DisableRestrictedAdmin = 0` |

### 9.9 Post-Compromise Persistence (T1136.001 / T1098)

| Signal | Evidence |
|---|---|
| Pattern | 4720 (user created) / 4732 (added to group) / 4724 (password reset) within 24h of a high-risk RDP success |
| Join | By LogonId from the compromise session |

### 9.10 Infrastructure Tampering (T1562)

| Signal | Evidence |
|---|---|
| Log cleared | Event 1102 |
| Audit policy changed | Event 4719 disabling Logon auditing |
| Firewall opened | netsh adding rule for RDP port |
| NLA disabled | Registry `UserAuthentication` changed to 0 |
| RDP enabled | `fDenyTSConnections` changed to 0 |

### 9.11 Default Classification Table

| Condition | Classification |
|---|---|
| FailedLogons ≥ Th_high AND not whitelisted | Attack |
| FailedLogons ≥ Th_low AND < Th_high | Suspicious |
| SuccessfulLogons > 0 AND FailedLogons < Th_low | Legitimate |
| SuccessfulLogons > 0 AND prior FailedLogons ≥ 3 same IP | **Compromise Indicator** |
| Only RdpCoreTS/261 present, no Security data | Unknown + diagnostic |
| Whitelisted IP | Trusted (still log) |

Defaults: `Th_low = 5` failures/10min, `Th_high = 15` failures/10min — configurable.

---

## 10. Risk Scoring Model

| Signal | Points |
|---|---:|
| Each failed RDP authentication | +10 |
| Each additional distinct username | +5 |
| SubStatus 0xC0000064 (no such user) | +4 |
| SubStatus 0xC000006A (bad password) | +3 |
| Account lockout caused | +30 |
| Success after failures (same IP) | +50 |
| Privileged success (4672) after failures | +80 |
| RDP transport only (no auth evidence) | +1 |
| Post-compromise action (4720/4732) in session | +100 |
| Whitelisted IP | −∞ (suppress) |
| Known admin jump-host | −20 |
| Private trusted subnet | −30 |
| Security log cleared (host-level) | +100 |

| Score Range | Severity |
|---:|---|
| 0–19 | Informational |
| 20–49 | Suspicious |
| 50–79 | High |
| 80+ | Critical |

---

## 11. UI Projection Rules

### 11.1 Live Events

- Time, Event ID, Channel, Evidence Class, Outcome.
- Username, Domain, Source IP, LogonType.
- SubStatus + human-readable meaning.
- Session ID, Logon ID.
- Enrichment source badge (hoverable).
- Confidence indicator.
- Diagnostic message when fields are unknown (never blank cells).
- MITRE ATT&CK tags where applicable.

Example: `SourceIp: Unknown — Security 4625 IpAddress was stripped by NLA; no RdpCoreTS 131 found within ±15s`

### 11.2 Attack Statistics

Built from fact tables, not UI rows. Required columns:
- Source IP, Classification, Risk Score.
- Failed/Successful logons, Active window failures.
- Distinct usernames, Dominant SubStatus + meaning.
- First/Last seen, Duration.
- Blocked/Whitelisted state, Confidence.
- GeoCountry/ASN (if enriched).
- ATT&CK techniques.

### 11.3 Remote RDP Clients

Combines: WTS sessions + Session Facts + LSM 21 + Security 4624/4778 + RCM 1149 + Gateway 302 + TCP fallback.

Required columns:
- Session ID, User, Domain, State.
- Source IP (+ Relay IP if gateway), Client Name.
- Started, Last Active, Last Reconnect/Disconnect, Ended.
- Auth Package, NLA used, LogonType, Privileged.
- Confidence, Evidence source, Diagnostics.

### 11.4 Compromise Timeline

Per session: vertical swim-lane rendering:

`RdpCoreTS 131 → 1149 → 4624 → 4672 → LSM 21 → LSM 22 → [user actions: 4720, 4732…] → 4634 → LSM 23`

### 11.5 Overview Cards

From facts: Attacks today, Compromise candidates, Blocked IPs, Active sessions, Failed logons, Privileged sessions, Telemetry health, Last ingestion time.

---

## 12. Health Checks

| Check | Method | Pass Condition |
|---|---|---|
| Security channel readable | `EventLogSession.GetLogInformation` | No UnauthorizedAccessException |
| Audit Logon enabled | `auditpol /get /subcategory:"Logon"` | Success and Failure |
| Credential Validation audit | `auditpol /get /subcategory:"Credential Validation"` | Success and Failure |
| Kerberos AS audit (DC) | `auditpol /get /subcategory:"Kerberos Authentication Service"` | Success and Failure |
| Other Logon/Logoff audit | for 4778/4779 | Success |
| LSM channel enabled | `wevtutil gl …LocalSessionManager/Operational` | enabled:true |
| RCM channel enabled | likewise | |
| RdpCoreTS channel enabled | likewise | |
| Gateway channel (if role present) | likewise | |
| RDP listener active | `GetExtendedTcpTable` shows LISTEN on resolved port | |
| Registry port matches listener | Compare | |
| WTS query works | `WTSEnumerateSessions` returns | |
| Bookmark fresh | RecordId ≥ oldest retained record | |
| Time sync | `w32tm /query /status` offset <60s | |
| Service permissions | SeSecurityPrivilege or "Event Log Readers" on Security | |
| NLA state known | Registry UserAuthentication value read | |

**Remediation commands (examples):**

```powershell
# Enable Logon auditing
auditpol /set /subcategory:"Logon" /success:enable /failure:enable

# Enable Credential Validation auditing
auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable

# Enable Kerberos Authentication Service auditing (DC)
auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable

# Enable LSM channel
wevtutil sl "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" /e:true

# Grant service account Security log access
wevtutil sl Security /ca:"O:BAG:SYD:(A;;0x1;;;S-1-5-80-...)"

# Check NLA status
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name UserAuthentication
```

---

## 13. Performance Rules

- `EventLogWatcher` per channel with narrow XPath ID filter (never `*`).
- Bounded ingestion channel (4096 capacity, drop-oldest with diagnostic).
- Backfill batch size 256; commit every 256 events or 1s.
- Correlation buffer: per-IP time-bucket index, capped at 30min × 20,000 IPs, LRU eviction.
- Raw XML stored gzipped; cap at 64 KiB before compression.
- Indexes: `(TimeUtc)`, `(SourceIp, TimeUtc)`, `(NormalizedUserName, TimeUtc)`, `(EventId, TimeUtc)`, `(SessionId, TimeUtc)`, `(LogonId)`, `(EvidenceClass, TimeUtc)`.
- Never call `Get-WinEvent` from UI thread.
- Never issue backfill query without explicit EventID filter.
- Target: <5% CPU on 4-vCPU box, <200MB working set, <50MB/h DB growth.

---

## 14. Failure Modes

### 14.1 Only RdpCoreTS 131/261 Present
- Store as Transport/PreAuth. **Counters remain 0.** Diagnostic `SecurityLogMissing` raised. UI shows IP but user/outcome = `Unknown — Security audit disabled or unreadable`.

### 14.2 Security 4625 Without IP (NLA + NTLMv2)
- Apply NLA-strip enrichment rule (§6.3-5). If RdpCoreTS 131/140 found in −2s…+15s with unique candidate: attach at High confidence.
- If multiple candidates: Medium + `CorrelationAmbiguous`.
- If no RdpCoreTS: try 4771 cross-correlation (DC), else TCP low-confidence fallback.
- **Never recommend disabling NLA.** Surface diagnostic as informational.

### 14.3 Event 1149 Without Security 4624
- Store 1149 as pre-auth success evidence. Raise `AuditPolicyMissing.Logon` if no 4624 follows within 90s.
- Do not count as successful logon unless correlated with LSM 21.

### 14.4 LogonType 3 Without RDP Correlation
- Classify as non-RDP network logon. Do not include in RDP counters.

### 14.5 Session Without Address
- Query LSM 21 by SessionID → RCM 1149 → 4624 → 4778 → WTS → TCP.
- If all fail: `Unknown` with diagnostic.

### 14.6 Service Was Down
- Backfill 24h critical channels. Reconcile sessions. Mark retention gaps.

### 14.7 Security Log Cleared
- Ingest Event 1102. Raise Critical diagnostic. Mark counters potentially incomplete. Continue from new cursor.

### 14.8 RD Gateway Present But Channel Offline
- `GatewayChannelMissing`. SourceIp = gateway internal IP for all sessions. Label `IpIsRelay` in UI.

### 14.9 Mixed IPv4/IPv6
- Normalize `::ffff:x.x.x.x` to IPv4. Track native IPv6 separately. Merge IpFact by canonical form.

---

## 15. Blocking Policy

1. Never block from 131/261/TCP alone.
2. Block only from AuthAttemptFact evidence (4625/4776/4771).
3. Never block whitelisted, loopback, or configured trusted subnets.
4. Prefer temporary blocks with TTL.
5. Store every block action as a fact with reason and evidence.
6. Reconcile firewall state periodically.

| Pattern | Default Threshold |
|---|---:|
| Brute force | 10 failures / 5 min |
| Password spray | 15 users / 15 min |
| Targeted account | 8 failures same user / 5 min |
| Lockout-causing source | Immediate alert, block if policy enabled |

---

## 16. Quick Reference: "Where Does an RDP Login Leave a Footprint?"

| Stage | Success Events | Failure Events | Where IP Lives |
|---|---|---|---|
| TCP arrive | RdpCoreTS 131 | RdpCoreTS 131 | **RdpCoreTS 131** |
| NLA challenge | RCM 1149 | RCM 1148, RdpCoreTS 140 | RCM 1149, RdpCoreTS 140 |
| NTLM validation | 4776 (S) | 4776 (F) | — (Workstation only) |
| Kerberos validation | 4768/4769 | **4771** | **4771.IpAddress** |
| LSA logon | **4624 LT10** | **4625 LT10/3** | 4624/4625.IpAddress (often stripped under NLA) |
| Session creation | **LSM 21**, 22 | — | **LSM 21.Address** |
| Reconnect | 4778, LSM 25 | — | 4778.ClientAddress |
| Disconnect | 4779, LSM 24, 40 | — | 4779.ClientAddress |
| Logoff | 4634, 4647, LSM 23 | — | — |
| RD Gateway | **Gateway 302** | Gateway 304/305 | **Gateway 302.ClientIP (external)** |

**For any missing field on any event, walk this table to find the channel that knows it, then join using §6 rules.**

---

## 17. Acceptance Criteria

1. With NLA+NTLM: failed RDP produces row with TargetUser from 4625 and SourceIp from RdpCoreTS 131 (±15s), confidence High. No diagnostic.
2. With NLA+Kerberos: failed RDP produces row from 4771 on DC joined to host, confidence Medium.
3. RdpCoreTS 131/261 alone **never** increments FailedCount or SuccessCount.
4. Success after ≥3 failures from same IP raises Critical `CompromiseIndicator` alert with ATT&CK T1078+T1110.001+T1021.001.
5. RD Gateway 302 supplies external IP; SH row shows both ExternalIp and RelayIp.
6. Post-compromise events (4720/4732) linked to responsible session via LogonId.
7. Session Hijacking (4778 with changed ClientAddress/SYSTEM actor) raises dedicated alert.
8. Restricted Admin/PtH pattern (LT3+NTLM+RDP port, no LT10) raises dedicated alert.
9. Disabling Logon audit raises `AuditPolicyMissing.Logon` with one-click fix.
10. Service restart: backfill recovers all critical events; counters match continuous collection.
11. Live Events never displays blank cells — every absent field shows `Unknown — <reason>`.
12. SubStatus codes display human-readable translations (e.g., "Bad Password", "No Such User").
13. Pipeline: <5% CPU (4-vCPU), <200MB RAM, <50MB/h DB growth at 1000 events/min.
14. All counters reproducible from AuthAttemptFact; "rebuild facts" yields identical values.
15. Every classification decision has exportable evidence (EventId + RecordId + Channel) as JSON for IR handoff.

---

*End of v2.0. The mental model (§1), correlation algorithm (§6), session state machine (§7), and acceptance criteria (§17) form the immutable contract. Implementation details may evolve as Windows event schemas change.*
