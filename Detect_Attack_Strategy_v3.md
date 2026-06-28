# RdpAudit Attack Detection Strategy — v3.0

> **Version:** 3.0
> **Previous versions:** [v2.0](Detect_Attack_Strategy_v2.md)
> **Scope:** Windows 10/11, Windows Server 2012 R2 – 2025, RDS Session Host, RD Gateway, standalone hosts, domain-joined environments
> **Audience:** Senior Windows security engineers, detection engineers, SOC analysts, RdpAudit developers
> **Last updated:** 2026-05-26

---

## Table of Contents

1. [Mental Model: The RDP Authentication Stack](#1-mental-model-the-rdp-authentication-stack)
   - 1.1 [Stack Overview Table](#11-stack-overview-table)
   - 1.2 [The NLA Blindspot Explained](#12-the-nla-blindspot-explained)
   - 1.3 [Principle of Least Knowledge](#13-principle-of-least-knowledge)
2. [Objectives](#2-objectives)
3. [Data Sources](#3-data-sources)
   - 3.1 [Windows Security Log](#31-windows-security-log)
   - 3.2 [Terminal Services LocalSessionManager/Operational](#32-terminal-services-localsessionmanageroperational)
   - 3.3 [RemoteConnectionManager/Operational](#33-remoteconnectionmanageroperational)
   - 3.4 [RdpCoreTS/Operational](#34-rdpcoretsoperational)
   - 3.5 [TerminalServices-Gateway/Operational](#35-terminalservices-gatewayoperational)
   - 3.6 [NTLM Operational](#36-ntlm-operational)
   - 3.7 [WTS Active Session State (Snapshot)](#37-wts-active-session-state-snapshot)
   - 3.8 [TCP Connection Snapshot](#38-tcp-connection-snapshot)
4. [Unified Event Model](#4-unified-event-model)
   - 4.1 [Core Event Properties](#41-core-event-properties)
   - 4.2 [Extended Properties (v3.0 additions)](#42-extended-properties-v30-additions)
5. [Collection Pipeline](#5-collection-pipeline)
   - 5.1 [Watcher Path](#51-watcher-path)
   - 5.2 [Backfill Path](#52-backfill-path)
   - 5.3 [Snapshot Path](#53-snapshot-path)
6. [Correlation Algorithm](#6-correlation-algorithm)
   - 6.1 [Correlation Keys (Priority Order)](#61-correlation-keys-priority-order)
   - 6.2 [Time Windows](#62-time-windows)
   - 6.3 [Enrichment Rules](#63-enrichment-rules)
   - 6.4 [NLA Classification Rule](#64-nla-classification-rule)
7. [RDP Session State Machine](#7-rdp-session-state-machine)
   - 7.1 [State Diagram](#71-state-diagram)
   - 7.2 [State Definitions and Transition Rules](#72-state-definitions-and-transition-rules)
   - 7.3 [SessionKey Derivation](#73-sessionkey-derivation)
8. [Persisted Facts](#8-persisted-facts)
   - 8.1 [AuthAttemptFact](#81-authattempfact-atomic--counters-derived-from-this)
   - 8.2 [IP Facts](#82-ip-facts)
   - 8.3 [User/IP Facts](#83-userip-facts)
   - 8.4 [Session Facts](#84-session-facts)
   - 8.5 [Diagnostic Facts](#85-diagnostic-facts)
9. [Attack Classification](#9-attack-classification)
   - 9.1 [Brute Force — Single Account (T1110.001)](#91-brute-force--single-account-t1110001)
   - 9.2 [Password Spray (T1110.003)](#92-password-spray-t1110003)
   - 9.3 [User Enumeration](#93-user-enumeration)
   - 9.4 [Targeted Account Attack (T1110.001)](#94-targeted-account-attack-t1110001)
   - 9.5 [Account Lockout Attack](#95-account-lockout-attack)
   - 9.6 [Successful Compromise After Brute-Force (T1078 + T1021.001)](#96-successful-compromise-after-brute-force-t1078--t1021001)
   - 9.7 [RDP Session Hijacking (T1563.002)](#97-rdp-session-hijacking-t1563002)
   - 9.8 [Restricted Admin Mode / Pass-the-Hash over RDP (T1550.002)](#98-restricted-admin-mode--pass-the-hash-over-rdp-t1550002)
   - 9.9 [Post-Compromise Persistence (T1136.001 / T1098)](#99-post-compromise-persistence-t1136001--t1098)
   - 9.10 [Infrastructure Tampering (T1562)](#910-infrastructure-tampering-t1562)
   - 9.11 [Credential Stuffing / Spray from Covert Networks (T1110.004)](#911-credential-stuffing--spray-from-covert-networks-t1110004)
   - 9.12 [Default Classification Table](#912-default-classification-table)
10. [Risk Scoring Model](#10-risk-scoring-model)
    - 10.1 [Signal Scoring Table](#101-signal-scoring-table)
    - 10.2 [Severity Tiers and Response Actions](#102-severity-tiers-and-response-actions)
11. [UI Projection Rules](#11-ui-projection-rules)
    - 11.1 [Live Events](#111-live-events)
    - 11.2 [Attack Statistics](#112-attack-statistics)
    - 11.3 [Remote RDP Clients](#113-remote-rdp-clients)
    - 11.4 [Compromise Timeline (New)](#114-compromise-timeline-new)
    - 11.5 [Overview Cards](#115-overview-cards)
12. [Health Checks](#12-health-checks)
13. [Performance Rules](#13-performance-rules)
14. [Failure Modes](#14-failure-modes)
    - 14.1 [Only RdpCoreTS 131/261 Present](#141-only-rdpcorets-131261-present)
    - 14.2 [Security 4625 Without IP (NLA + NTLMv2)](#142-security-4625-without-ip-nla--ntlmv2)
    - 14.3 [Event 1149 Without Security 4624](#143-event-1149-without-security-4624)
    - 14.4 [LogonType 3 Without RDP Correlation](#144-logontype-3-without-rdp-correlation)
    - 14.5 [Session Without Address](#145-session-without-address)
    - 14.6 [Service Was Down](#146-service-was-down)
    - 14.7 [Security Log Cleared](#147-security-log-cleared)
    - 14.8 [RD Gateway Present But Channel Offline](#148-rd-gateway-present-but-channel-offline)
    - 14.9 [Mixed IPv4/IPv6](#149-mixed-ipv4ipv6)
15. [Blocking Policy](#15-blocking-policy)
16. [Quick Reference: Where Does an RDP Login Leave a Footprint?](#16-quick-reference-where-does-an-rdp-login-leave-a-footprint)
17. [Acceptance Criteria](#17-acceptance-criteria)

---

## 1. Mental Model: The RDP Authentication Stack

A correct and resilient detection strategy must be grounded in a precise understanding of the multi-layered RDP authentication architecture. The v2.0 approach relied heavily on a reactive model centered on post-authentication events. Version 3.0 formalises a **proactive, layered mental model** that deconstructs every RDP session into distinct stages — each with its own telemetry producers, data fields, and inherent blind spots.

This model explains why certain fields (most notably the **source IP address**) can be absent from some events, and how to reconstruct a complete picture by correlating evidence across layers. Every layer contributes unique data; loss of data at one layer necessitates enrichment from a preceding or succeeding layer.

### 1.1 Stack Overview Table

| # | Layer | Component(s) | Primary Channel(s) | Key Events | What It Knows |
|---:|---|---|---|---|---|
| 1 | **TCP/TLS Transport** | TermService, RdpCoreTS | RdpCoreTS/Operational | **131**, **140**, 65, 141 | Source IP, source port — **NOT** username |
| 2 | **RD Gateway** *(optional)* | TSGateway | TS-Gateway/Operational | **302**, **303**, 304, 305 | External client IP, target server, username |
| 3 | **NLA / CredSSP** | LSASS (SSP chain), Domain Controller | Security, NTLM/Operational, Kerberos/Operational | **1149**, **4776**, **4771**, 8001/8004 | Username, auth package, result — often **no IP** on target host |
| 4 | **Local Security Authority (LSA)** | LSA | Security | **4624**, **4625**, **4648**, 4634, 4647 | Outcome (Succeeded/Failed), LogonType, AuthPackage, TargetLogonId — **IP often stripped by NLA** |
| 5 | **Session / Shell** | Termsrv, Userinit | LSM/Operational, RCM/Operational | LSM **21/22/23/24/25/39/40**; RCM **1149**, 261 | SessionId, user, **client IP (LSM 21.Address — gold standard)** |

### 1.2 The NLA Blindspot Explained

With NLA enabled (default since Windows Server 2012), the CredSSP layer authenticates the user **before** a full logon ticket is created by the LSA. When NLA + NTLMv2 is in use:

- Failed logons manifest as **LogonType 3** (not 10) in Event ID 4625.
- The `IpAddress` field in 4625 is **frequently empty** — the IP was consumed at the transport layer.
- The IP must be **recovered** from `RdpCoreTS 131/140` via time-correlated enrichment (see [§6.3](#63-enrichment-rules)).

> ⚠️ **Never recommend disabling NLA as a workaround.** Surface the gap as a diagnostic and resolve it with proper cross-channel correlation.

### 1.3 Principle of Least Knowledge

Each layer only knows what it needs to know:

- **Transport layer** knows the IP but not the username.
- **LSA** knows the outcome and username but may have lost the IP.
- **Session Manager** knows the session identity and often the IP, but not the initial credentials.

The v3.0 strategy's power comes from stitching these partial truths together into a single, coherent narrative of every RDP connection attempt.

---

## 2. Objectives

- **Detect** brute-force, password spray, user enumeration, targeted account attacks, credential stuffing, post-compromise lateral movement, session hijacking, Pass-the-Hash, and infrastructure tampering — each as a distinct classification with **MITRE ATT&CK** mapping.
- **Capture the full RDP lifecycle**: TCP arrival → NLA challenge → credential validation → LSA logon → session creation → shell ready → reconnect/disconnect → logoff.
- **Survive audit-policy gaps**: degrade gracefully with explicit diagnostics when Security audit is disabled, NLA strips IPs, or logs have rolled over.
- **Never invent facts**: every field carries `EnrichmentSource` and `EnrichmentConfidence`. Counters increment only from authoritative evidence.
- **Detect advanced RDP attacks**: Session Hijacking (tscon.exe), Restricted Admin Mode / Pass-the-Hash, credential stuffing from covert networks, and post-compromise persistence.
- **Maintain data provenance**: every enriched field must be traceable back to its source event and confidence level.
- **Stay lightweight**: bounded backfill, indexed queries, batched writes, bounded correlation buffers, `<5% CPU` on a 4-vCPU box.

---

## 3. Data Sources

### 3.1 Windows Security Log

**Required Audit Policy (Advanced Audit Policy Configuration):**

| Subcategory | Required | Why It Is Critical |
|---|---|---|
| Logon | Success + Failure | Captures all 4624/4625/4648 — the basis for all attack detection |
| Logoff | Success | Logs 4634/4647 for accurate session duration calculation |
| Special Logon | Success | Captures 4672 — key indicator of admin rights within a compromised session |
| Other Logon/Logoff Events | Success | Captures 4778/4779 — essential for session continuity and hijacking detection |
| Credential Validation | Success + Failure | On DCs: captures 4776, the definitive NTLM credential validation record |
| Kerberos Authentication Service | Success + Failure | On DCs: captures 4768/4771. Event 4771 is invaluable — carries client IP during Kerberos failures |
| Account Lockout | Success | Captures 4740 — direct indicator of account lockout DoS |
| Security Group Management | Success | Captures 4732/4733 — primary indicator of post-compromise privilege escalation |

**Complete Event Table:**

| EID | Meaning | RDP Logon Types | Key Fields |
|---:|---|---|---|
| 4625 | Failed logon | **10** (RDP), **3** (NLA), 7 | TargetUserName, IpAddress (may be blank under NLA), Status, **SubStatus**, LogonType |
| 4624 | Successful logon | **10**, **3** (NLA), **7** (reconnect) | TargetUserName, IpAddress, **TargetLogonId**, AuthenticationPackageName |
| 4634 | Logoff | by TargetLogonId | Session duration closure |
| 4647 | User-initiated logoff | — | Stronger than 4634 for explicit sign-out |
| 4648 | Explicit credentials | — | Key indicator for Pass-the-Hash / lateral movement |
| 4672 | Special privileges assigned | — | Admin RDP sessions, sensitive privilege detection |
| 4776 | NTLM credential validation | — | TargetUserName, Workstation (no IP), Status |
| 4771 | Kerberos pre-auth failed | — | TargetUserName, **IpAddress** (carries client IP!), Status |
| 4768 | Kerberos TGT requested | — | TGT request monitoring; detects AS-REP Roasting abuse |
| 4769 | Kerberos service ticket | — | Kerberoasting detection |
| 4778 | Session reconnected | — | AccountName, **ClientName**, **ClientAddress** |
| 4779 | Session disconnected | — | AccountName, ClientName, ClientAddress |
| 4740 | Account locked out | — | TargetUserName, CallerComputerName |
| 4719 | Audit policy changed | — | Infrastructure tamper indicator |
| 4720 | User account created | — | Post-compromise persistence signal |
| 4724 | Account password reset | — | Post-compromise persistence signal |
| 4732 | Member added to group | — | Privilege escalation post-compromise |
| 4825 | RDP access denied | — | Authenticated but lacks Remote Desktop Users rights |
| 1102 | Security log cleared | — | **Critical** adversary TTP for evidence erasure |

**SubStatus Code Reference (Critical for Attack Classification):**

| SubStatus | Meaning | Attack Indicator |
|---|---|---|
| 0xC000006A | Wrong password | Brute-force / credential stuffing |
| 0xC0000064 | User does not exist | User enumeration / password spray |
| 0xC0000234 | Account locked out | Account lockout DoS / aggressive brute-force |
| 0xC0000072 | Account disabled | Stale account targeting |
| 0xC000006F | Outside logon hours | Legitimate restriction (not attack) |
| 0xC0000071 | Password expired | User friction (not attack) |
| 0xC0000133 | Clock skew | Diagnostic; can be exploited in replay attacks |
| 0xC000015B | Logon type not granted | Authorization failure, not credential failure |

**Logon Type Handling:**

| LogonType | Meaning | RDP Relevance |
|---:|---|---|
| 10 | RemoteInteractive | Strong RDP indicator (non-NLA or post-NLA session) |
| 3 | Network | **Can be NLA-RDP** when correlated with CredSSP/RdpCoreTS/RCM |
| 7 | Unlock | Reconnect/unlock, relevant with 4778/LSM 25 |

> **Rule:** Do not rely on LogonType 10 alone. With NLA enabled (default), RDP failures manifest as Type 3. Classification requires correlation with RdpCoreTS/RCM events.

**XML Parsing Rules:**

1. Parse via named `EventData/Data[@Name=…]` first; positional `Properties[i]` is fallback only (emit `ParserFallbackUsed` diagnostic).
2. Use XXE-safe XML settings: `DtdProcessing = Prohibit`, `XmlResolver = null`, max 256 KiB.
3. Capture `ToXml()` before `EventRecord` disposal; cap at 64 KiB.
4. Treat `IpAddress` values of `-`, `::1`, `127.0.0.1`, `0.0.0.0` as **absent** — flag for enrichment.

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
| 21 | Session logon succeeded | Session ID, user, **Address** (**gold standard** for client IP) |
| 22 | Shell start | Interactive session readiness confirmation |
| 23 | Session logoff | Session end |
| 24 | Session disconnected | Disconnect state |
| 25 | Session reconnected | Reconnect timeline |
| 39 | Session disconnected by another session | Console takeover / hijacking indicator |
| 40 | Session disconnect/reconnect reason | Reason code enrichment |

**LSM 40 Key Reason Codes:**

| Code | Meaning |
|---:|---|
| 0 | No additional information |
| 5 | Replaced by another connection |
| 11 | User-initiated disconnect |
| 12 | User-initiated logoff |

> **Note:** LSM 21 `Address` field contains the client IP for remote sessions, `LOCAL` for console sessions, and possibly IPv6 `::ffff:x.x.x.x` — normalize to IPv4.

---

### 3.3 RemoteConnectionManager/Operational

| EID | Meaning | Primary Use |
|---:|---|---|
| 1149 | User authentication succeeded (NLA phase) | Username, Domain, Source IP — **strongest pre-LSA IP source** |
| 1148 | TS auth pre-stage failure | Pre-4625 failure signal |
| 261 | Listener/transport event | Weak connection signal |

> **Critical:** Event 1149 fires when NLA authentication succeeds, but the overall login may still fail at a later stage (e.g., account disabled, no Remote Desktop Users membership). **Event 1149 alone must NOT be counted as a successful logon** — it requires correlation with 4624 or LSM 21 (see [§6.3, Rule 6](#63-enrichment-rules)).

---

### 3.4 RdpCoreTS/Operational

| EID | Meaning | Primary Use |
|---:|---|---|
| 65 | Connection arrival | Earliest IP fingerprint |
| 131 | Server accepted new TCP connection | **Always carries ClientIP:port** — primary IP enrichment for NLA-stripped 4625 |
| 140 | Connection failed / user not allowed | Carries source IP; proves unknown user when correlated with 4625 SubStatus 0xC0000064 |
| 141 | Disconnect after auth | Session teardown |
| 82 | Corrupt/malformed payload | Protocol fuzzing / non-standard client detection |

---

### 3.5 TerminalServices-Gateway/Operational (RD Gateway role only)

| EID | Meaning | Key Fields |
|---:|---|---|
| 302 | User connected to resource | **External client IP**, target server, username |
| 303 | User disconnected | Duration, bytes |
| 304 | Resource not authorized | Authorization failure |
| 305 | User failed CAP/RAP | Policy failure |

> **When RD Gateway is present, Event 302 is the ONLY place the real external client IP appears.** Session Hosts behind the gateway see only the gateway's internal IP. RdpAudit must support remote ingestion of gateway logs and maintain both `ExternalIp` (from 302) and `RelayIp` (gateway internal).

---

### 3.6 NTLM Operational (Microsoft-Windows-NTLM/Operational)

Events 8001/8002/8004 plus Security 4776 expose every NTLM authentication attempt. Required when AD policy "Restrict NTLM: Audit Incoming NTLM Traffic" is enabled.

- Source: `Workstation` field (NetBIOS name, not IP) — must pair with RdpCoreTS 131 for IP attribution.
- Useful for standalone hosts not backed by a domain controller.

---

### 3.7 WTS Active Session State (Snapshot)

| WTS Field | Purpose |
|---|---|
| Session ID | Runtime session key |
| Username | Current session user |
| Domain | Account domain |
| State | Active, Disconnected, Listen, Idle, Reset, Down |
| LogonTime | Session start |
| ConnectTime | Connection time |
| DisconnectTime | Disconnected duration |
| LastInputTime | Activity signal |
| ClientAddress | Best-effort active client IP |
| ClientName | Fallback correlation key |
| ProtocolType | RDP vs console |

> **Rules:** WTS is a snapshot, not history. It can refresh current state but cannot create session-fact rows. Session-fact creation must be triggered by LSM 21 or 4624 LogonType 10.

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

> **Rules:** Lowest-confidence source. **Never infer username or outcome.** Only enrich IP when `OwningProcess = TermService` AND `LocalPort = resolvedRdpPort` AND no other source available. TCP enrichment is **strictly forbidden** for any field except SourceIp.

---

## 4. Unified Event Model

### 4.1 Core Event Properties

| Property | Description |
|---|---|
| EventUid | Stable internal unique ID — SHA hash of source properties; prevents duplication |
| TimeUtc | UTC timestamp (preserve 100ns ticks) |
| IngestedUtc | Ingestion timestamp — distinguishes event time from processing time |
| Channel | Windows event channel |
| Provider | Provider name |
| EventId | Windows Event ID |
| RecordId | Event record ID |
| ActivityId | ETW correlation GUID — enables deterministic, time-window-free joins |
| RelatedActivityId | Related ETW GUID — completes the ETW correlation chain |
| SourceIp | Normalized source IP |
| SourcePort | Source port |
| IpFamily | IPv4, IPv6, IPv4MappedIPv6 |
| IsPublicIp | Public routable indicator — allows internet-facing vs internal filtering |
| IsLoopback | Loopback indicator |
| UserName | Attempted or authenticated user |
| NormalizedUserName | Canonical user key (lowercase, domain-stripped) — enables consistent correlation |
| Domain | Account domain |
| WorkstationName | Client workstation |
| ClientName | RDP client name |
| LogonType | Windows logon type |
| LogonId | TargetLogonId correlation key |
| LogonGuid | Logon GUID |
| SessionId | WTS/Terminal Services session ID |
| ProcessName | Related process |
| AuthPackage | NTLM / Kerberos / Negotiate / CredSSP |
| LogonProcessName | User32, Advapi, NtLmSsp, CredSSP |
| Status | Failure status hex |
| SubStatus | Failure substatus hex |
| SubStatusMeaning | Human-readable translation (e.g., "Bad Password", "No Such User") |
| Outcome | Failed, Succeeded, Informational, Denied, Unknown |
| EvidenceClass | AuthenticationFailure, AuthenticationSuccess, SessionStart, SessionLifecycle, Transport, PostCompromise, Tamper, Diagnostic |
| EventRole | Transport, PreAuth, CredentialValidation, Authentication, Session, Shell, Disconnect, Logoff, PostCompromise, Diagnostic |
| RdpRelevance | Strong, Probable, Possible, Weak, None |
| EnrichmentSource | DirectXml, SecurityFallbackIndex, Lsm21, Rcm1149, RdpCoreTs131, RdpCoreTs140, Gateway302, Krb4771, Ntlm4776, WtsSnapshot, TcpSnapshot, ActivityIdJoin, LogonIdChain, None |
| EnrichmentConfidence | High, Medium, Low, None |
| ConflictFlags | Array of strings (e.g., `['ConflictingIp', 'ConflictingUser']`) if sources disagree — never silently overwrite |
| Diagnostics | Array of diagnostic codes |
| MitreTechniques | Array of mapped ATT&CK technique IDs (e.g., T1110.001, T1563.002) |
| RawXmlCapped | Capped raw XML (≤64 KiB, gzipped) — preserves complete unaltered source for forensic deep dives |
| DetailsJson | Structured JSON of key-value pairs — enables efficient querying without re-parsing XML |

### 4.2 Extended Properties (v3.0 additions)

| Property | Description | Rationale |
|---|---|---|
| EventUid | Stable globally unique identifier derived from a hash of source properties | Prevents duplication in persisted facts |
| IngestedUtc | Timestamp of when the event was processed | Distinguishes event time from processing time |
| ActivityId | ETW correlation GUID from the event's provider | Enables deterministic joins between related events (e.g., RCM 1149 → LSM 21) |
| IsPublicIp | Boolean: is SourceIp a public, routable address? | Enables internet-facing vs internal analysis |
| NormalizedUserName | Canonicalized version of UserName (lowercase, domain-stripped) | Consistent correlation across different user representations |
| EvidenceClass | Categorical label for event's role | Groups events for rule application and UI visualization |
| EventRole | Granular label describing function in the RDP stack | Provides deeper semantic context |
| RdpRelevance | Qualitative score (Strong/Probable/Possible/Weak/None) | Helps prioritize events in noisy environments |
| ConflictFlags | Array of conflict indicators | Makes data integrity issues visible and auditable |
| MitreTechniques | Array of mapped ATT&CK technique IDs | Directly links detections to adversary TTPs for triage |

---

## 5. Collection Pipeline

### 5.1 Watcher Path

1. Start `EventLogWatcher` per channel with narrow XPath ID filter (never `*`).
2. In callback: synchronously copy all fields and `ToXml()` (EventRecord disappears after callback returns).
3. Push to bounded `Channel<RawEvent>` (capacity 4096, drop-oldest with `WatcherBackpressure` diagnostic).
4. **Never** await DB/IO inside callback.
5. Restart with exponential backoff (1s → 60s, jittered).

### 5.2 Backfill Path

1. Per-channel durable bookmark (RecordId / Timestamp / EventBookmark blob).
2. On start: bounded lookback (default 24h, hard cap 7d) for critical IDs.
3. Periodic catch-up every 60s.
4. Deduplicate by `(Channel, RecordId)` primary; `Hash` secondary.
5. **Never** query without XPath ID filter.
6. Backfill batch size 256; commit every 256 events or 1s.

**Critical Backfill Targets:**

| Channel | Event IDs |
|---|---|
| Security | 4624, 4625, 4634, 4647, 4648, 4672, 4719, 4720, 4724, 4732, 4740, 4768, 4769, 4771, 4776, 4778, 4779, 4825, 1102 |
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

Given a target event T, build a candidate set from events within the time window on relevant channels, then pick by the priority hierarchy below.

### 6.1 Correlation Keys (Priority Order)

| Priority | Key | Confidence | Notes |
|---:|---|---|---|
| 1 | **ActivityId (ETW GUID)** match | High | Deterministic; completely bypasses time-window guessing |
| 2 | **TargetLogonId** | High | Canonical key for LSA-related events chain |
| 3 | **SessionId + tight window** | High | Strong identifier once LSM 21 is present (0–120s) |
| 4 | **SourceIp + TargetUser ± 10s** | High | Tight probabilistic key |
| 5 | **SourceIp ± 10s** (unique candidate) | Medium | Single-IP disambiguation |
| 6 | **WorkstationName + TargetUser ± 30s** | Medium | Cross-host domain correlation |
| 7 | **TargetUser ± 30s** (DC cross-host) | Medium | Domain controller cross-correlation |
| 8 | **TCP RemoteAddress ± 10s** | Low | Last resort — never infers username or outcome |

**Tie-breakers:** Closest `|Δt|`, then highest source confidence, then earliest RecordId.

### 6.2 Time Windows

| Relationship | Window | Rationale |
|---|---:|---|
| RdpCoreTS 131 → Security 4625 | −2s … +15s | IP arrives before LSA fail; tight to reduce false positives |
| RdpCoreTS 140 → 4625 SubStatus 0xC0000064 | −2s … +15s | Proves user doesn't exist |
| RCM 1149 → Security 4624 LT10 | 0 … +90s | NLA pass → LSA finalize |
| RCM 1149 → LSM 21 | 0 … +90s | Session creation after NLA auth |
| Security 4624 → LSM 21 | 0 … +120s | Standard session creation delay |
| LSM 21 → LSM 22 | 0 … +60s | Shell initialization |
| LSM 24/25 → Security 4779/4778 | ±60s | Disconnect/reconnect pairing |
| Security 4634/4647 → LSM 23 | ±120s | Logoff correlation |
| Gateway 302 → 4624 LT10 (SH side) | 0 … +30s | Gateway → Session Host chain |
| 4769 (TERMSRV/host) → 4624 LT10 | 0 … +30s | Kerberos RDP path |
| WTS snapshot → LSM 21 | ±120s | State reconciliation |
| TCP snapshot → transport event | ±10s | Lowest confidence supplemental |
| Failures → success (compromise check) | 0 … −30min | Configurable lookback window |

### 6.3 Enrichment Rules

1. **Direct XML always wins** within the same event. Fields extracted directly from event XML take precedence over any correlated values.

2. **IP Authority Hierarchy:**
   `LSM 21.Address` > `4778/4779.ClientAddress` > `Gateway 302.ClientIP` > `RCM 1149.SourceAddress` > `RdpCoreTS 131/140.ClientIP` > `4624/4625.IpAddress` > `4771.IpAddress` > TCP snapshot.

3. **Outcome Authority Hierarchy:**
   `4624/4625` > `4776/4771` > `(1149 + LSM 21) combined` > `LSM alone` > `RdpCoreTS/TCP` (**NEVER** set outcome).

4. **Username for failed attempts:** Only from `4625`, `4776`, `4771`, `1148`, `RdpCoreTS 140`. **Never** from WTS or TCP snapshots — these sources do not contain credential information.

5. **NLA-stripped 4625 rule:** If `4625.IpAddress` is absent and `RdpCoreTS 131/140` exists within −2s…+15s with no other 4625 in that window:
   - **One candidate** → attach IP at `High` confidence.
   - **Multiple candidates** → `Medium` confidence + `CorrelationAmbiguous` diagnostic.
   - **No candidate** → try 4771 cross-correlation (DC), else TCP low-confidence fallback. Never recommend disabling NLA.

6. **Event 1149 rule:** 1149 alone does **NOT** count as a successful logon. Promotion to `Outcome = Succeeded` requires correlation with `4624 LT10` **OR** `LSM 21` within ±90s. This prevents false positives from NLA successes later denied by the LSA.

7. **TCP enrichment forbidden** for any field except `SourceIp`, and only when `OwningProcess = TermService` AND `LocalPort = resolvedRdpPort`.

8. **Conflicts remain visible:** If sources disagree on a critical field (e.g., SourceIp), populate `ConflictFlags`, preserve both values, and display both in the UI with their respective `EnrichmentSource` and `EnrichmentConfidence`. The system **never** silently chooses one over the other.

9. **No unique candidate = no enrichment:** If multiple candidate events exist at the same priority level, leave the field as `Unknown` rather than making a probabilistic guess. Data integrity over convenience.

### 6.4 NLA Classification Rule

For `4624/4625` events with `LogonType = 3`:

- If `AuthenticationPackageName = Negotiate` AND `LogonProcessName` contains `CredSSP` → classify as **RDP/NLA**
- If a correlated `RdpCoreTS 131` or `RCM 1149` event exists within the defined time window → classify as **RDP/NLA**
- Otherwise → classify as **non-RDP network logon** (do not include in RDP counters)

---

## 7. RDP Session State Machine

The RDP Session State Machine is a formal, deterministic model of the RDP connection lifecycle. It replaces probabilistic "correlation" with a testable, finite-state automaton.

### 7.1 State Diagram

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

### 7.2 State Definitions and Transition Rules

| State | Trigger | Description |
|---|---|---|
| **[Connecting]** | RdpCoreTS 131 | Initial state. Not yet associated with a user or logon ID |
| **[FailedAuth]** | 4625 / 1148 / 140 | Terminal state. No further transitions possible |
| **[Authenticated]** | 4624 LT10 or 1149 | User passed NLA challenge. Not yet a full session |
| **[SessionOpen]** | LSM 21 | Full Terminal Services session created with SessionId. First state where ClientAddress is definitively known |
| **[ShellReady]** | LSM 22 | Session is fully interactive and ready for user input |
| **[Disconnected]** | LSM 24 or 4779 | Session alive but user not connected |
| **[LoggedOff]** | 4634 or 4647 | Terminal state. Session completely terminated |

**Key Anomaly Detections:**

- `[SessionOpen]` → `[Disconnected]` → `[SessionOpen]` with **different `ClientAddress`** = **Session Hijacking indicator**
- `[Connecting]` → `[LoggedOff]` (direct, no session) = immediate disconnect after failed connection
- Rapid `[SessionOpen]` → `[Connecting]` cycle = potential session takeover attempt

### 7.3 SessionKey Derivation

```
SessionKey = SHA1(HostName || WtsSessionId || LogonId || StartedUtc:rounded-1s)
```

Stable across service restarts and log rotations. Used as the primary key in SessionFact.

---

## 8. Persisted Facts

Persisted facts are the operational, query-optimized tables that power the UI and alerting engine. **All counters and statistics are derived exclusively from `AuthAttemptFact`** — this is a critical invariant that ensures auditability and reproducibility.

### 8.1 AuthAttemptFact (Atomic — Counters Derived from This)

The single source of truth for all authentication activity. Every other fact table is a materialized view or aggregation of this base table.

| Field | Purpose |
|---|---|
| Id | PK — unique identifier |
| TimeUtc | Event time |
| SourceIp | Enriched source IP |
| TargetUser, TargetDomain | Attempted or authenticated user and domain |
| AuthPackage | NTLM / Kerberos / Negotiate |
| Outcome | Succeeded / Failed / Denied |
| Status, SubStatus | Raw status and sub-status codes |
| SubStatusMeaning | Human-readable translation |
| LogonType | Windows logon type |
| LogonId | Nullable correlation key |
| EvidenceEventId, EvidenceChannel, EvidenceRecordId | **Exact provenance for full forensic traceability** |
| EnrichmentSource, EnrichmentConfidence | Source and quality of enriched fields |

> **Invariant:** Rebuilding facts from scratch will always yield identical values. All counters in `IpFact` and `UserIpFact` are computed **only** from `AuthAttemptFact`.

### 8.2 IP Facts

| Field | Purpose |
|---|---|
| SourceIp | Canonical source IP |
| FirstSeenUtc, LastSeenUtc | Activity timeline |
| FailedLogons | Count from AuthAttemptFact where Outcome='Failed' |
| SuccessfulLogons | Count from AuthAttemptFact where Outcome='Succeeded' |
| ActiveWindowFailures | Rolling count in current detection window |
| DistinctUserCount | Password spray signal |
| AttemptedUserNames | Capped distinct list |
| DominantSubStatus | Most common failure reason |
| LastFailureStatus, LastFailureSubStatus | |
| LastSuccessUtc | |
| Classification | Benign / Suspicious / Attack / Compromise / Unknown |
| AttackScore | Numeric risk score (see [§10](#10-risk-scoring-model)) |
| IsBlocked, IsWhitelisted | Current firewall/blocklist state |
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
| IsCompromiseCandidate | True if SuccessCount > 0 AND FailedCount ≥ 3 for same (IP, User) |
| FailureReasons | Aggregated reason list (e.g., ["Bad Password", "No Such User"]) |

### 8.4 Session Facts

| Field | Purpose |
|---|---|
| SessionKey | SHA1-derived stable key (see [§7.3](#73-sessionkey-derivation)) |
| WtsSessionId | Runtime session ID |
| UserName, Domain | |
| SourceIp, SourcePort | |
| ClientName, WorkstationName | |
| State | Active, Disconnected, Ended, Unknown |
| StartedUtc, ShellStartedUtc | Key lifecycle timestamps |
| LastReconnectUtc, LastDisconnectUtc | |
| EndedUtc, LastSeenUtc | |
| LogonId, LogonGuid | LSA correlation keys |
| AuthPackage, LogonType | |
| IsPrivileged | From Event 4672 |
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
| ParserFallbackUsed | Named XML parse failed, positional fallback used |
| CorrelationAmbiguous | >1 candidate at same priority level |
| CorrelationLowConfidence | Best candidate priority ≥6 |
| ClockSkewSuspected | Event time ordering abnormal |
| WatcherBackpressure | Bounded channel dropped events |
| GatewayChannelMissing | RD Gateway role detected, channel unreachable |
| SecurityLogCleared | Event 1102 observed — **Critical** |
| AuditPolicyChanged | Event 4719 observed |
| RdpPortMismatch | Registry vs actual listener differ |

---

## 9. Attack Classification

The v3.0 classification framework provides a **granular, risk-scored, and MITRE ATT&CK-mapped taxonomy** of RDP-specific threats. Each classification is defined by a precise, evidence-based signal and a clear severity level.

### 9.1 Brute Force — Single Account (T1110.001)

| Signal | Evidence |
|---|---|
| Pattern | High volume of 4625 events from same IP targeting 1–2 users |
| SubStatus | Mostly `0xC000006A` (bad password) |
| Window | 10 min sliding |
| Threshold | ≥10 failures, IP not whitelisted |
| Severity | **High** |
| Confidence | High if 4625 evidence; Medium if only 4771 |

### 9.2 Password Spray (T1110.003)

| Signal | Evidence |
|---|---|
| Pattern | Many distinct usernames from same IP, low per-user count |
| SubStatus | Mix of `0xC0000064` (no user) and `0xC000006A` (bad pwd) |
| Window | 30 min |
| Threshold | ≥8 distinct users AND max per-user ≤3 AND ≥90% failures |
| Severity | **High** |

### 9.3 User Enumeration

| Signal | Evidence |
|---|---|
| Pattern | Same IP, many usernames, SubStatus overwhelmingly `0xC0000064` |
| Distinction | Enumeration = almost all "no such user"; spray = mix with "bad password" |
| Severity | **Medium** |

### 9.4 Targeted Account Attack (T1110.001)

| Signal | Evidence |
|---|---|
| Pattern | ≥25 failures for one (SourceIp, TargetUser) with same SubStatus |
| Window | 24h |
| Severity | **High** |

### 9.5 Account Lockout Attack

| Signal | Evidence |
|---|---|
| Pattern | Multiple 4625 events → 4740 lockout |
| Threshold | External IP caused lockout |
| Severity | **Critical** |

### 9.6 Successful Compromise After Brute-Force (T1078 + T1021.001)

| Signal | Evidence |
|---|---|
| Pattern | 4624 LT10 / LSM 21 from IP that had ≥3 prior failures for same user |
| Window | 30 min lookback from success |
| Severity | **Critical** — auto-escalate to highest priority |

### 9.7 RDP Session Hijacking (T1563.002)

| Signal | Evidence |
|---|---|
| Pattern | Event 4778 (reconnect) where `ClientName`/`ClientAddress` unexpectedly changes |
| OR | Reconnect executed under `NT AUTHORITY\SYSTEM` (tscon.exe via service/PsExec) |
| AND | No preceding 4624 from that user for the new client |
| Detection | Compare `4778.ClientAddress` against last known `4779.ClientAddress` for same SessionId |
| Severity | **Critical** |

### 9.8 Restricted Admin Mode / Pass-the-Hash over RDP (T1550.002)

| Signal | Evidence |
|---|---|
| Pattern | 4624 LogonType 3 + AuthPackage=NTLM from external IP over RDP port |
| AND | No subsequent LogonType 10 for same user/time |
| AND | Restricted Admin Mode registry key enabled |
| Registry | `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\DisableRestrictedAdmin = 0` |
| Severity | **Critical** |

### 9.9 Post-Compromise Persistence (T1136.001 / T1098)

| Signal | Evidence |
|---|---|
| Pattern | 4720 (user created) / 4732 (added to group) / 4724 (password reset) within 24h of a high-risk RDP success |
| Join | By LogonId from the compromise session |
| Severity | **Critical** |

### 9.10 Infrastructure Tampering (T1562)

| Signal | Evidence | Severity |
|---|---|---|
| Log cleared | Event 1102 | **Critical** |
| Audit policy changed | Event 4719 disabling Logon auditing | **Critical** |
| Firewall opened | netsh adding rule for RDP port | **High** |
| NLA disabled | Registry `UserAuthentication` changed to 0 | **High** |
| RDP enabled | `fDenyTSConnections` changed to 0 | **High** |

### 9.11 Credential Stuffing / Spray from Covert Networks (T1110.004)

| Signal | Evidence |
|---|---|
| Pattern | High-volume failures originating from Tor exit nodes, VPN providers, or known proxy ASNs |
| Detection | GeoIP/ASN enrichment: match SourceIp against threat intel feeds (Tor exit list, datacenter CIDRs) |
| Supporting | Multiple distinct usernames + SubStatus mix + rotating source IPs within small ASN block |
| Severity | **High** |

> **Note:** This pattern is characteristic of nation-state actors and automated credential stuffing toolkits. See [Microsoft Storm-0940](https://www.microsoft.com/en-us/security/blog/2024/10/31/chinese-threat-actor-storm-0940-uses-credentials-from-password-spray-attacks-from-a-covert-network/) for a real-world example.

### 9.12 Default Classification Table

| Condition | Classification |
|---|---|
| FailedLogons ≥ Th_high AND not whitelisted | **Attack** |
| FailedLogons ≥ Th_low AND < Th_high | **Suspicious** |
| SuccessfulLogons > 0 AND FailedLogons < Th_low | **Legitimate** |
| SuccessfulLogons > 0 AND prior FailedLogons ≥ 3 same IP | **Compromise Indicator** |
| Only RdpCoreTS/261 present, no Security data | **Unknown** + diagnostic |
| Whitelisted IP | **Trusted** (still log) |

Defaults: `Th_low = 5` failures/10min, `Th_high = 15` failures/10min — configurable.

---

## 10. Risk Scoring Model

The risk scoring model provides a **quantitative, objective measure of threat severity**, enabling automated triage and prioritization. Scores are calculated from the atomic events stored in `AuthAttemptFact`, ensuring reproducibility and auditability.

### 10.1 Signal Scoring Table

| Signal | Points | Rationale |
|---|---:|---|
| Each failed RDP authentication (4625, 4771, 4776) | +10 | Foundational signal for all attack types |
| Each additional distinct username targeted | +5 | Indicates broader campaign (password spraying) |
| SubStatus 0xC0000064 (no such user) | +4 | Strong indicator of user enumeration |
| SubStatus 0xC000006A (bad password) | +3 | Core signal for brute-force attacks |
| Account lockout caused (4740) | +30 | High-impact DoS activity |
| Successful login (4624) after ≥3 prior failures from same IP/user | +50 | Strong indicator of successful compromise |
| Privileged success (4624 with 4672) after failures | +80 | Compromise with immediate privilege escalation |
| RDP transport event only (no auth evidence) | +1 | Low-confidence signal; still indicates scanning |
| Post-compromise action (4720/4732) linked to session | +100 | Confirmed malicious activity within session |
| Security log cleared at host level (1102) | +100 | Major adversary TTP for erasing evidence |
| Whitelisted IP | −∞ (suppress) | Prevents alerts for trusted sources |
| Known admin jump-host | −20 | Reduces score for expected admin activity |
| Private trusted subnet | −30 | Discounts activity from known safe networks |

### 10.2 Severity Tiers and Response Actions

| Score Range | Severity | Recommended Action |
|---:|---|---|
| 0–19 | **Informational** | Log only. May indicate legitimate user error or automated scans |
| 20–49 | **Suspicious** | Generate alert for analyst review. Investigate source IP and user accounts |
| 50–79 | **High** | Escalate to Tier 1 SOC. Initiate IP blocking if policy allows |
| 80+ | **Critical** | **Immediate response.** Assume compromise. Isolate host, reset credentials, full investigation |

---

## 11. UI Projection Rules

All UI surfaces must be powered by the same reliable, normalized dataset — eliminating discrepancies and providing analysts with a **single source of truth**.

### 11.1 Live Events

Display normalized/enriched fields per row:

- Time, Event ID, Channel, Evidence Class, Outcome
- Username, Domain, Source IP, LogonType
- SubStatus + human-readable meaning
- Session ID, Logon ID
- `EnrichmentSource` badge (hoverable tooltip)
- `EnrichmentConfidence` indicator
- MITRE ATT&CK tags where applicable

> **Rule:** Blank cells are **strictly prohibited**. If a field cannot be determined, it must be displayed as `Unknown — <diagnostic_reason>`.
>
> Example: `SourceIp: Unknown — Security 4625 IpAddress was stripped by NLA; no RdpCoreTS 131 found within ±15s`

### 11.2 Attack Statistics

Built from `IpFact` and `UserIpFact` tables, **not by recounting UI rows**. This ensures statistics are consistent regardless of user filter choices.

Required columns:
- Source IP, Classification, Risk Score
- Failed/Successful logons, Active window failures
- Distinct usernames, Dominant SubStatus + meaning
- First/Last seen, Duration
- Blocked/Whitelisted state, Confidence
- GeoCountry/ASN (if enriched)
- MITRE ATT&CK technique tags

### 11.3 Remote RDP Clients

Composite view combining: WTS sessions + Session Facts + LSM 21 + Security 4624/4778 + RCM 1149 + Gateway 302 + TCP fallback.

Required columns:
- Session ID, User, Domain, State
- Source IP (+ Relay IP if gateway), Client Name
- Started, Last Active, Last Reconnect/Disconnect, Ended
- Auth Package, NLA used, LogonType, Privileged status
- Confidence, Evidence source, Diagnostics

> Works even if the service IPC path is temporarily unavailable by relying on local WTS query fallback, but prefers the richer historical data from SessionFact.

### 11.4 Compromise Timeline (New)

Per-session vertical swim-lane diagram for sessions classified as Compromise Candidates:

```
RdpCoreTS 131 → RCM 1149 → 4624 → 4672 → LSM 21 → LSM 22 → [User Actions: 4720, 4732…] → 4634 → LSM 23
```

Provides an instant at-a-glance reconstruction of the entire attack chain — from initial access through post-compromise activity — dramatically accelerating incident response and forensic analysis.

### 11.5 Overview Cards

Computed from fact tables:
- Attacks today
- Compromise candidates
- Blocked IPs
- Active sessions
- Failed logons (last 24h)
- Privileged sessions
- Telemetry health status
- Last ingestion timestamp

---

## 12. Health Checks

Health checks continuously verify the telemetry pipeline's usability and provide **immediate, actionable remediation**.

| Check | Method | Pass Condition | Remediation |
|---|---|---|---|
| Security channel readable | `EventLogSession.GetLogInformation` | No UnauthorizedAccessException | `wevtutil sl Security /ca:"O:BAG:SYD:(A;;0x1;;;S-1-5-80-...)"` |
| Audit Logon enabled | `auditpol /get /subcategory:"Logon"` | Success and Failure | `auditpol /set /subcategory:"Logon" /success:enable /failure:enable` |
| Credential Validation audit | `auditpol /get /subcategory:"Credential Validation"` | Success and Failure | `auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable` |
| Kerberos AS audit (DC) | `auditpol /get /subcategory:"Kerberos Authentication Service"` | Success and Failure | `auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable` |
| Other Logon/Logoff audit | for 4778/4779 | Success | `auditpol /set /subcategory:"Other Logon/Logoff Events" /success:enable` |
| LSM channel enabled | `wevtutil gl …LocalSessionManager/Operational` | `enabled:true` | `wevtutil sl "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" /e:true` |
| RCM channel enabled | `wevtutil gl …RemoteConnectionManager/Operational` | `enabled:true` | Same pattern |
| RdpCoreTS channel enabled | `wevtutil gl …RdpCoreTS/Operational` | `enabled:true` | Same pattern |
| Gateway channel (if role present) | `wevtutil gl …TerminalServices-Gateway/Operational` | `enabled:true` | Same pattern |
| RDP listener active | `GetExtendedTcpTable` | LISTEN on resolved port | `netsh advfirewall firewall add rule name="RDP" dir=in action=allow protocol=TCP localport=3389` |
| Registry port matches listener | Compare registry vs netstat | Values equal | Correct registry key or firewall rule |
| WTS query works | `WTSEnumerateSessions` | Returns sessions | `Add-WindowsFeature RSAT-Clustering-Mgmt-Consoles` |
| Bookmark fresh | RecordId ≥ oldest retained | Values match | Force backfill reset |
| Time sync | `w32tm /query /status` | Offset < 60s | `w32tm /resync /force` |
| NLA state known | Registry `UserAuthentication` | Value readable | Check service permissions |

```powershell
# Quick health check — enable all critical audit subcategories
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Logoff" /success:enable
auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable
auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable
auditpol /set /subcategory:"Other Logon/Logoff Events" /success:enable
auditpol /set /subcategory:"Account Lockout" /success:enable
auditpol /set /subcategory:"Security Group Management" /success:enable

# Enable operational channels
wevtutil sl "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" /e:true
wevtutil sl "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational" /e:true
wevtutil sl "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational" /e:true

# Check NLA status
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name UserAuthentication
```

---

## 13. Performance Rules

- `EventLogWatcher` per channel with **narrow XPath ID filter** (never `*`).
- Bounded ingestion channel (4096 capacity, drop-oldest with `WatcherBackpressure` diagnostic).
- Backfill batch size 256; commit every 256 events or 1s.
- Correlation buffer: per-IP time-bucket index, capped at 30min × 20,000 IPs, LRU eviction.
- Raw XML stored gzipped; cap at 64 KiB before compression.
- Indexes: `(TimeUtc)`, `(SourceIp, TimeUtc)`, `(NormalizedUserName, TimeUtc)`, `(EventId, TimeUtc)`, `(SessionId, TimeUtc)`, `(LogonId)`, `(EvidenceClass, TimeUtc)`.
- **Never** call `Get-WinEvent` from UI thread.
- **Never** issue backfill query without explicit EventID filter.
- **Target:** < 5% CPU on 4-vCPU box, < 200 MB working set, < 50 MB/h DB growth at 1000 events/min.

---

## 14. Failure Modes

### 14.1 Only RdpCoreTS 131/261 Present

Store as Transport/PreAuth evidence. **Counters remain 0.** Raise `SecurityLogMissing` diagnostic. UI shows IP but `UserName = Unknown — Security audit disabled or unreadable`, `Outcome = Unknown`.

### 14.2 Security 4625 Without IP (NLA + NTLMv2)

Apply NLA-strip enrichment rule ([§6.3, Rule 5](#63-enrichment-rules)):
- If `RdpCoreTS 131/140` found in −2s…+15s with **unique candidate** → attach at `High` confidence.
- If **multiple candidates** → `Medium` + `CorrelationAmbiguous` diagnostic.
- If **no candidate** → try 4771 cross-correlation (DC), then TCP low-confidence fallback.
- **Never recommend disabling NLA.** Surface as informational diagnostic.

### 14.3 Event 1149 Without Security 4624

Store 1149 as pre-auth success evidence. Raise `AuditPolicyMissing.Logon` if no 4624 follows within 90s. **Do not count as successful logon** unless correlated with LSM 21.

### 14.4 LogonType 3 Without RDP Correlation

Classify as non-RDP network logon. **Do not include in RDP counters.**

### 14.5 Session Without Address

Query chain: LSM 21 by SessionID → RCM 1149 → 4624 → 4778 → WTS → TCP.
If all fail: `Unknown` with appropriate diagnostic message.

### 14.6 Service Was Down

Run bounded backfill (default 24h, hard cap 7d) for all critical channels. Reconcile sessions. Mark retention gaps as `LogRetentionGap` diagnostics.

### 14.7 Security Log Cleared

Ingest Event 1102. Raise `Critical` diagnostic `SecurityLogCleared`. Mark counters as potentially incomplete. Continue from new cursor position.

### 14.8 RD Gateway Present But Channel Offline

Raise `GatewayChannelMissing`. All sessions: `SourceIp = gateway internal IP`. Label `IpIsRelay` in UI. Analyst must query gateway logs externally.

### 14.9 Mixed IPv4/IPv6

Normalize `::ffff:x.x.x.x` to IPv4. Track native IPv6 separately. Merge `IpFact` by canonical form.

---

## 15. Blocking Policy

1. **Never block** from `RdpCoreTS 131/261` or TCP snapshot alone.
2. **Block only** from `AuthAttemptFact` evidence (`4625` / `4776` / `4771`).
3. **Never block** whitelisted IPs, loopback (`127.0.0.1`, `::1`), or configured trusted subnets.
4. Prefer **temporary blocks with TTL** over permanent bans.
5. Store **every block action** as a fact with reason, evidence EventId, and RecordId.
6. **Reconcile firewall state** periodically against `IpFact.IsBlocked`.

| Pattern | Default Threshold |
|---|---:|
| Brute force | 10 failures / 5 min |
| Password spray | 15 users / 15 min |
| Targeted account | 8 failures same user / 5 min |
| Lockout-causing source | Immediate alert; block if policy enabled |

---

## 16. Quick Reference: Where Does an RDP Login Leave a Footprint?

This table is the **operational guide for analysts and developers**. It maps each stage of the RDP lifecycle to the events that leave a footprint, and — critically — where the necessary information resides.

| Stage | Success Events | Failure Events | Where IP Lives |
|---|---|---|---|
| TCP arrive | RdpCoreTS 131 | RdpCoreTS 131 | **RdpCoreTS 131** |
| NLA challenge | RCM 1149 | RCM 1148, RdpCoreTS 140 | RCM 1149, RdpCoreTS 140 |
| NTLM validation | 4776 (S) | 4776 (F) | — (Workstation only) |
| Kerberos validation | 4768/4769 | **4771** | **4771.IpAddress** |
| LSA logon | **4624 LT10** | **4625 LT10/3** | 4624/4625.IpAddress *(often stripped under NLA)* |
| Session creation | **LSM 21**, 22 | — | **LSM 21.Address** *(gold standard)* |
| Reconnect | 4778, LSM 25 | — | 4778.ClientAddress |
| Disconnect | 4779, LSM 24, 40 | — | 4779.ClientAddress |
| Logoff | 4634, 4647, LSM 23 | — | — |
| RD Gateway | **Gateway 302** | Gateway 304/305 | **Gateway 302.ClientIP** *(external — only source!)* |

> **For any missing field on any event: walk this table to find the channel that knows it, then join using [§6](#6-correlation-algorithm) rules.**

---

## 17. Acceptance Criteria

These are the immutable, testable contracts that define v3.0 success. All criteria must be verifiable programmatically.

1. With NLA+NTLM: failed RDP produces row with `TargetUser` from 4625 and `SourceIp` from RdpCoreTS 131 (±15s), confidence `High`. No diagnostic raised.
2. With NLA+Kerberos: failed RDP produces row from 4771 on DC joined to host, confidence `Medium`.
3. `RdpCoreTS 131/261` alone **never** increments `FailedCount` or `SuccessCount`.
4. Success after ≥3 failures from same IP raises `Critical` **CompromiseIndicator** alert with ATT&CK `T1078+T1110.001+T1021.001`.
5. RD Gateway 302 supplies external IP; Session Host row shows both `ExternalIp` and `RelayIp`.
6. Post-compromise events (`4720`/`4732`) linked to responsible session via `LogonId`.
7. Session Hijacking (`4778` with changed `ClientAddress`/SYSTEM actor) raises dedicated alert.
8. Restricted Admin/PtH pattern (LT3+NTLM+RDP port, no LT10) raises dedicated alert.
9. Disabling Logon audit raises `AuditPolicyMissing.Logon` with one-click remediation command.
10. Service restart: backfill recovers all critical events; counters match continuous collection.
11. Live Events **never** displays blank cells — every absent field shows `Unknown — <reason>`.
12. SubStatus codes display human-readable translations (e.g., "Bad Password", "No Such User").
13. Pipeline: < 5% CPU (4-vCPU), < 200 MB RAM, < 50 MB/h DB growth at 1000 events/min.
14. All counters reproducible from `AuthAttemptFact`; "rebuild facts" yields identical values.
15. Every classification decision has exportable evidence (`EventId + RecordId + Channel`) as JSON for IR handoff.
16. `ConflictFlags` is populated and both values displayed in UI whenever sources provide conflicting data for a key field.
17. Covert network / credential stuffing pattern (T1110.004) detected when ≥3 distinct external IPs from same ASN exhibit coordinated spray behavior within 60 min.

---

*End of v3.0. The mental model ([§1](#1-mental-model-the-rdp-authentication-stack)), correlation algorithm ([§6](#6-correlation-algorithm)), session state machine ([§7](#7-rdp-session-state-machine)), and acceptance criteria ([§17](#17-acceptance-criteria)) form the immutable contract. Implementation details may evolve as Windows event schemas change, but the core principles of data provenance, hierarchical correlation, and deterministic state reconstruction are permanent.*
