# RDPAudit — Windows RDP Security Monitoring & Auto-Block Platform

[![Version](https://img.shields.io/badge/version-2.0.0-blue.svg)](https://github.com/paulmann/RDPAudit)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![.NET](https://img.shields.io/badge/dotnet-8.0--windows-blue.svg)](https://dotnet.microsoft.com/)
[![Platform](https://img.shields.io/badge/platform-Windows%2010%2B%20%2F%20Server%202016%2B-blue.svg)](https://www.microsoft.com/windows/)
[![SQLite](https://img.shields.io/badge/sqlite-WAL%20mode-orange.svg)](https://sqlite.org/)

> **RDPAudit** is a production-ready Windows platform for monitoring RDP activity and responding to RDP-based threats.  
> It consists of a **Windows Service** (background event collection, 21 alert rules, automatic blocking) and a **WinForms Configurator** (GUI for management, statistics, diagnostics, and policy configuration).

---

## Table of Contents

- [1. Product Overview](#1-product-overview)
  - [1.1. Purpose](#11-purpose)
  - [1.2. Solution Architecture](#12-solution-architecture)
  - [1.3. Core Capabilities](#13-core-capabilities)
- [2. System Requirements](#2-system-requirements)
  - [2.1. Minimum Requirements](#21-minimum-requirements)
  - [2.2. Windows Auditing Requirements](#22-windows-auditing-requirements)
- [3. Solution Layout](#3-solution-layout)
  - [3.1. Projects and Layers](#31-projects-and-layers)
  - [3.2. Directory Structure](#32-directory-structure)
- [4. Quick Start](#4-quick-start)
  - [4.1. Build](#41-build)
  - [4.2. Install the Service](#42-install-the-service)
  - [4.3. First Launch of the Configurator](#43-first-launch-of-the-configurator)
- [5. RdpAudit.Service — Monitoring Service](#5-rdpauditservice--monitoring-service)
  - [5.1. Event Collection](#51-event-collection)
  - [5.2. Tracked Event IDs](#52-tracked-event-ids)
  - [5.3. Data Storage (SQLite)](#53-data-storage-sqlite)
  - [5.4. Alerting System — 21 Rules](#54-alerting-system--21-rules)
  - [5.5. Windows Firewall Auto-Blocking](#55-windows-firewall-auto-blocking)
  - [5.6. Named Pipe IPC](#56-named-pipe-ipc)
  - [5.7. Reliability and Resilience](#57-reliability-and-resilience)
- [6. RdpAudit.Configurator — GUI](#6-rdpauditconfigurator--gui)
  - [6.1. Overview Tab](#61-overview-tab)
  - [6.2. Prerequisites Tab](#62-prerequisites-tab)
  - [6.3. Audit Policy Tab](#63-audit-policy-tab)
  - [6.4. Service Tab](#64-service-tab)
  - [6.5. Settings Tab](#65-settings-tab)
  - [6.6. Live Events Tab](#66-live-events-tab)
  - [6.7. Firewall Tab](#67-firewall-tab)
  - [6.8. Attack Statistics Tab](#68-attack-statistics-tab)
  - [6.9. Remote RDP Clients Tab](#69-remote-rdp-clients-tab)
  - [6.10. AbuseIPDB Tab](#610-abuseipdb-tab)
  - [6.11. MikroTik Tab](#611-mikrotik-tab)
  - [6.12. Logs Tab](#612-logs-tab)
  - [6.13. Diagnostics Tab](#613-diagnostics-tab)
- [7. RdpAudit.Core — Shared Library](#7-rdpauditcore--shared-library)
  - [7.1. Data Models](#71-data-models)
  - [7.2. Entity Framework Core and Migrations](#72-entity-framework-core-and-migrations)
  - [7.3. IPC Contracts (MessagePack)](#73-ipc-contracts-messagepack)
- [8. External Integrations](#8-external-integrations)
  - [8.1. AbuseIPDB](#81-abuseipdb)
  - [8.2. MikroTik RouterOS v7](#82-mikrotik-routeros-v7)
- [9. Auto-Blocking Model](#9-auto-blocking-model)
  - [9.1. Trigger Thresholds](#91-trigger-thresholds)
  - [9.2. Local Windows Firewall](#92-local-windows-firewall)
  - [9.3. Remote MikroTik Firewall](#93-remote-mikrotik-firewall)
  - [9.4. Whitelist Protection for Trusted IPs](#94-whitelist-protection-for-trusted-ips)
- [10. Data Maintenance](#10-data-maintenance)
  - [10.1. Retention Pruning](#101-retention-pruning)
  - [10.2. Backup and Restore](#102-backup-and-restore)
- [11. Security and Auditing](#11-security-and-auditing)
  - [11.1. Access Control](#111-access-control)
  - [11.2. SACL Configuration](#112-sacl-configuration)
  - [11.3. Secret Protection (DPAPI)](#113-secret-protection-dpapi)
- [12. Configuration](#12-configuration)
  - [12.1. appsettings.json](#121-appsettingsjson)
  - [12.2. Environment Variables](#122-environment-variables)
- [13. Debugging and Diagnostics](#13-debugging-and-diagnostics)
  - [13.1. Console Mode](#131-console-mode)
  - [13.2. Serilog Logs](#132-serilog-logs)
  - [13.3. Direct SQLite Access](#133-direct-sqlite-access)
  - [13.4. Diagnostics Tab](#134-diagnostics-tab)
- [14. Build and Test](#14-build-and-test)
  - [14.1. Build](#141-build)
  - [14.2. Tests](#142-tests)
  - [14.3. Publish](#143-publish)
- [15. Troubleshooting](#15-troubleshooting)
- [16. Roadmap (v2.0 → v3.0)](#16-roadmap-v20--v30)
- [17. License and Author](#17-license-and-author)

---

## 1. Product Overview

### 1.1. Purpose

**RDPAudit** is designed to provide continuous monitoring of RDP activity on Windows servers and workstations. The product runs in the background as a system service, even when no interactive user is logged on, records connection attempts, authentication events, and high-value system changes, evaluates them through 21 security rules, and can automatically block attackers through Windows Firewall and/or MikroTik RouterOS.

**Typical use cases:**
- Protecting Internet-exposed RDP endpoints from brute-force attacks
- Supporting SOC2, ISO 27001, and internal audit requirements for privileged access
- Detecting account compromise patterns such as a successful logon after repeated failures
- Identifying accessibility binary backdoors such as Sticky Keys and Utilman abuse
- Detecting attacks against LSA/LSASS, Kerberos spraying, and RDP port changes
- Integrating with MikroTik so malicious IPs can be blocked at the network edge

### 1.2. Solution Architecture

```text
┌──────────────────────────────────────────────────────────────────┐
│                     Windows Event Log                            │
│  Security │ TerminalServices-RemoteConnectionManager │ LocalSession│
└───────────────────────────┬──────────────────────────────────────┘
                            │  EventLogWatcher
                            ▼
┌──────────────────────────────────────────────────────────────────┐
│               RdpAudit.Service  (Windows Service)                │
│                                                                  │
│  EventCollectorWorker ──► EventNormalizerWorker                  │
│                                   │                             │
│                                   ▼                             │
│                         AlertEvaluatorWorker ──► 21 Alert Rules  │
│                                   │                             │
│                                   ▼                             │
│                         FirewallAutoBlockWorker                  │
│                         (Windows FW + MikroTik REST)             │
│                                   │                             │
│                                   ▼                             │
│                    SQLite  (WAL, %ProgramData%\RdpAudit)         │
│                                   │                             │
│                         Named Pipe IPC Server                    │
└───────────────────────────────────┬──────────────────────────────┘
                                    │  MessagePack over NamedPipe
                                    ▼
┌──────────────────────────────────────────────────────────────────┐
│              RdpAudit.Configurator  (WinForms GUI)               │
│                                                                  │
│  Overview │ Prerequisites │ AuditPolicy │ Service │ Settings     │
│  LiveEvents │ Firewall │ AttackStatistics │ RemoteRdpClients     │
│  AbuseIPDB │ MikroTik │ Logs │ Diagnostics                       │
└──────────────────────────────────────────────────────────────────┘
```

### 1.3. Core Capabilities

- **Real-time monitoring** through `EventLogWatcher` subscriptions instead of polling
- **21 alert rules** covering brute force, LSASS attacks, Kerberos spraying, suspicious policy changes, and more
- **Automatic blocking** using per-IP Windows Firewall rules with manual reversal support
- **MikroTik integration** through RouterOS v7 REST APIs with DPAPI-protected credentials
- **AbuseIPDB reporting** with local deduplication and rate-limit awareness
- **Threat analytics** aggregated by IP, country, time range, and calculated threat level
- **Session-to-IP correlation** for mapping RDP sessions back to source addresses
- **Retention pruning** for long-term stability and reduced database growth
- **Backup and restore** for configuration state, with no plaintext secrets included
- **Secure Named Pipe IPC** restricted to `BUILTIN\Administrators`

---

## 2. System Requirements

### 2.1. Minimum Requirements

| Component | Requirement |
|-----------|-------------|
| OS | Windows 10 or Windows Server 2016 and newer (x64) |
| .NET Runtime | .NET 8.0 for Windows (x64) |
| Privileges | Local Administrator for service installation and system configuration |
| Disk | 200 MB for binaries plus room for the event database |
| Memory | 64 MB working set for the service under normal load |

### 2.2. Windows Auditing Requirements

RDPAudit depends on Windows Security Auditing to receive the events it analyzes. For correct operation, the following audit categories must be enabled:

| Audit Category | Subcategory GUID | Purpose |
|----------------|------------------|---------|
| Logon / Logoff | `{0CCE9215-69AE-11D9-BED3-505054503030}` | Events 4624, 4625, 4634 |
| Account Logon | `{0CCE9240-69AE-11D9-BED3-505054503030}` | Kerberos events |
| Process Creation | `{0CCE922B-69AE-11D9-BED3-505054503030}` | Event 4688 and process visibility |
| Object Access | `{0CCE9217-69AE-11D9-BED3-505054503030}` | SACL-backed events such as 4656 and 4663 |
| Policy Change | `{0CCE922F-69AE-11D9-BED3-505054503030}` | Firewall and policy change visibility |

The Configurator applies these settings automatically by calling `auditpol.exe` with GUID-based identifiers, which makes the process locale-independent.

---

## 3. Solution Layout

### 3.1. Projects and Layers

| Project | Type | Responsibility |
|--------|------|----------------|
| `RdpAudit.Core` | Class Library (`net8.0-windows`) | Entities, EF Core `DbContext`, migrations, MessagePack IPC contracts, shared helpers |
| `RdpAudit.Service` | Worker Service (`net8.0-windows`, `win-x64`) | Event collection, normalization, alert evaluation, auto-blocking, IPC server |
| `RdpAudit.Configurator` | WinForms App (`net8.0-windows`) | GUI, IPC client, prerequisite checks, service control, configuration workflows |
| `RdpAudit.Core.Tests` | xUnit | Core unit tests |
| `RdpAudit.Service.Tests` | xUnit | Alert rule tests, threshold validation, whitelist coverage, allocation checks |
| `RdpAudit.Benchmarks` | BenchmarkDotNet | Benchmark coverage for hot paths |

### 3.2. Directory Structure

```text
RdpAudit.sln
├── src/
│   ├── RdpAudit.Core/
│   │   ├── Models/              — Entities, enums, projections
│   │   ├── Data/                — AppDbContext, EF Core migrations
│   │   ├── IPC/                 — MessagePack request/response contracts
│   │   └── Services/            — Shared scoring, formatting, and support services
│   ├── RdpAudit.Service/
│   │   ├── Workers/             — BackgroundService workers
│   │   ├── Alerts/              — 21 alert rules
│   │   ├── Firewall/            — Windows Firewall and MikroTik providers
│   │   ├── Collectors/          — Event source wrappers
│   │   └── Program.cs           — DI, Serilog, host wiring
│   └── RdpAudit.Configurator/
│       ├── Forms/               — 13 GUI pages
│       ├── IPC/                 — Named Pipe client
│       └── Program.cs           — Elevation, startup, UI bootstrap
├── tests/
│   ├── RdpAudit.Core.Tests/
│   ├── RdpAudit.Service.Tests/
│   └── RdpAudit.Benchmarks/
├── docs/
│   ├── 90-windows-validation.md
│   └── 91-troubleshooting.md
└── publish.ps1
```

---

## 4. Quick Start

### 4.1. Build

```powershell
git clone https://github.com/paulmann/RDPAudit.git
cd RDPAudit
dotnet build RdpAudit.sln -c Release
```

### 4.2. Install the Service

```powershell
# Publish binaries
./publish.ps1

# Copy the service payload into Program Files
Copy-Item -Recurse publish/Service "$env:ProgramFiles\RdpAudit\Service"

# Install as a Windows Service manually, or use the Configurator UI
sc.exe create RdpAudit binPath= "$env:ProgramFiles\RdpAudit\Service\RdpAudit.Service.exe" start= auto
sc.exe description RdpAudit "RDP Security Monitoring & Auto-Block Service"
sc.exe start RdpAudit
```

### 4.3. First Launch of the Configurator

```powershell
publish/Configurator/RdpAudit.Configurator.exe
```

On first launch, the recommended sequence is:

1. Open **Prerequisites** and verify required channels and platform settings.
2. Open **Audit Policy** and apply the required audit subcategories through `auditpol.exe`.
3. Open **Service** and install or start the Windows Service.
4. Open **Settings** and tune alert thresholds, trusted IPs, retention, and integrations.

---

## 5. RdpAudit.Service — Monitoring Service

### 5.1. Event Collection

The service uses `System.Diagnostics.Eventing.Reader.EventLogWatcher` to subscribe to relevant events in real time. The design is already abstracted behind event source interfaces so the collection backend can later move to ETW-based ingestion without rewriting the rest of the pipeline.

**Monitored channels:**
- `Security`
- `Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational`
- `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational`

### 5.2. Tracked Event IDs

| Event ID | Channel | Description |
|----------|---------|-------------|
| 4624 | Security | Successful logon, especially Logon Type 10 |
| 4625 | Security | Failed logon |
| 4634 | Security | Logoff |
| 4647 | Security | User-initiated logoff |
| 4648 | Security | Logon with explicit credentials |
| 4688 | Security | Process creation |
| 4720 | Security | User account created |
| 4723 / 4724 | Security | Password change / password reset |
| 4740 | Security | Account lockout |
| 4769 | Security | Kerberos service ticket request |
| 4771 | Security | Kerberos pre-authentication failure |
| 4776 | Security | NTLM authentication |
| 4954 | Security | Windows Firewall rule or policy change |
| 1149 | TerminalServices-RCM | RDP connection with source IP |
| 21, 23, 24, 25 | TerminalServices-LSM | Session start, reconnect, disconnect, end |

### 5.3. Data Storage (SQLite)

The database is stored at `%ProgramData%\RdpAudit\rdpaudit.db`.

**SQLite settings:**
```sql
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
```

**Primary tables:**

| Table | Purpose |
|-------|---------|
| `RawEvents` | Normalized security and RDP events |
| `RdpConnectionFacts` | Connection facts with IP, user, and outcome |
| `AuthAttemptFacts` | Authentication attempt facts |
| `Sessions` | RDP session records |
| `SessionIpCorrelations` | Session-to-IP mapping |
| `AttackStats` | Aggregated attack statistics by source |
| `ActiveBlocks` | Currently active automatic blocks |
| `Alerts` | Alert history |
| `WhitelistEntries` | Trusted IP and CIDR entries |
| `BlocklistEntries` | Persistent block rules and sources |
| `AbuseIpDbReportHistory` | AbuseIPDB report history |
| `OperationLogs` | Operational log entries surfaced in the GUI |
| `DbProps` | Key-value metadata store |
| `Bookmarks` | Crash-recovery bookmarks for event processing |
| `LoginRules` | Work-hours and logon policy rules |

**Write strategy:** the hot path uses raw `SqliteCommand` with explicit transactions and batched writes.

**Bookmark durability:** bookmarks are flushed every 100 events and every 30 seconds, which minimizes loss after a crash or power interruption.

### 5.4. Alerting System — 21 Rules

Each rule is implemented as a dedicated alert evaluator and participates in a common rule pipeline.

| # | Rule ID | Severity | Description |
|---|---------|----------|-------------|
| 1 | `BRUTE_FORCE` | High | Failed logons from the same source exceed threshold |
| 2 | `BRUTE_FORCE_NTLM` | High | NTLM brute-force with cooldown logic |
| 3 | `KERBEROS_SPRAY` | High | Kerberos password spraying behavior |
| 4 | `SUCCESSFUL_AFTER_FAILS` | Medium | Successful logon after repeated failures |
| 5 | `OFF_HOURS_LOGIN` | Medium | Logon outside approved working hours |
| 6 | `ACCOUNT_LOCKOUT` | Medium | Account lockout event |
| 7 | `NEW_ACCOUNT_CREATED` | Medium | New local or domain account created |
| 8 | `PASSWORD_RESET` | Low | Password reset or password change |
| 9 | `MULTIPLE_ACCOUNTS_SAME_IP` | High | Username spray from one source IP |
| 10 | `STICKY_KEYS_BACKDOOR` | Critical | Accessibility-binary backdoor behavior |
| 11 | `LSASS_ACCESS` | Critical | Suspicious handle access to LSASS |
| 12 | `LSASS_PPL_TAMPER` | Critical | Attempt to weaken LSASS PPL protection |
| 13 | `RDP_PORT_CHANGED` | High | Registry-based RDP port change detected |
| 14 | `FIREWALL_RULE_CHANGED` | Medium | Firewall rule or policy changed |
| 15 | `EXPLICIT_CREDENTIALS` | Medium | Explicit credential usage pattern |
| 16 | `LOGON_TYPE_NETWORK` | Low | Network logon to a protected system |
| 17 | `CONCURRENT_SESSIONS` | Low | Excess concurrent session count |
| 18 | `GEO_ANOMALY` | Medium | Logon from a disallowed or unexpected geography |
| 19 | `IP_REPUTATION` | High | Source IP appears in known blocklists |
| 20 | `SESSION_HIJACK_SUSPECT` | High | Session correlation anomaly |
| 21 | `RAPID_RECONNECT` | Medium | Repeated reconnect activity from the same IP |

### 5.5. Windows Firewall Auto-Blocking

When rules such as `BRUTE_FORCE`, `BRUTE_FORCE_NTLM`, or `IP_REPUTATION` are triggered, the service can create a per-IP inbound block rule.

```powershell
netsh advfirewall firewall add rule `
  name="RdpAudit_Block_<IP>" `
  dir=in action=block remoteip=<IP> `
  protocol=any enable=yes
```

**Implementation characteristics:**
- Idempotent rule creation
- Input sanitization before shell execution
- Manual removal through the GUI
- Full auditing through `ActiveBlocks` and `OperationLogs`

### 5.6. Named Pipe IPC

**Pipe name:** `\\.\pipe\RdpAuditService`

**Security model:** only `BUILTIN\Administrators` are allowed to connect.

**Protocol:** MessagePack request and response contracts defined in `RdpAudit.Core`.

**Operational notes:**
- The GUI never writes service-owned configuration files directly.
- Settings are sent over IPC and committed atomically by the service.
- Connection deadlines prevent the Configurator from hanging indefinitely.

### 5.7. Reliability and Resilience

- Exponential backoff for transient database contention such as `SQLITE_BUSY`
- End-to-end `CancellationToken` propagation across async flows
- Graceful shutdown on service stop
- EF Core migrations applied at startup
- Event Log source registration during installation

---

## 6. RdpAudit.Configurator — GUI

The Configurator runs elevated and communicates with the service strictly through the Named Pipe IPC channel.

### 6.1. Overview Tab

The **Overview** tab is the operator dashboard. It summarizes service state, current block counts, recent alerts, and recent event volume.

### 6.2. Prerequisites Tab

The **Prerequisites** tab checks the required Windows conditions:
- Audit channels enabled
- Terminal Services channels enabled
- Audit policy correctly applied
- Service installed and reachable

Each failed prerequisite can be fixed directly from the UI.

### 6.3. Audit Policy Tab

The **Audit Policy** tab reads the current Windows audit configuration and applies the required subcategories through GUID-based `auditpol.exe` calls. It also handles SACL setup for high-value registry locations and IFEO paths tied to RDP abuse detection.

### 6.4. Service Tab

The **Service** tab supports:
- Install and uninstall
- Start, stop, restart
- Service status display
- Startup mode control

### 6.5. Settings Tab

The **Settings** tab exposes operational configuration, including:
- Alert thresholds
- Brute-force windows
- Work-hour definitions
- Data retention windows
- AbuseIPDB settings
- MikroTik settings
- Geolocation and whitelist settings

Changes are submitted over IPC and applied atomically by the service.

### 6.6. Live Events Tab

The **Live Events** tab provides a tail-style stream of real-time events with color coding for failures, warnings, and successful activity. It supports filtering by Event ID and source IP.

### 6.7. Firewall Tab

The **Firewall** tab surfaces active blocks from `ActiveBlocks` and supports:
- Viewing blocked IPs, reasons, and providers
- Manually adding block entries
- Removing blocks with confirmation
- Importing or exporting blocklists

### 6.8. Attack Statistics Tab

The **Attack Statistics** tab presents aggregated attack data:
- Top attacking IPs
- Threat level scoring
- Time-based charts
- Country-level grouping
- CSV export support

Threat level is calculated through the scoring logic in `AttackThreatScoring`.

### 6.9. Remote RDP Clients Tab

The **Remote RDP Clients** tab correlates source IPs, connection counts, usernames, and historical RDP sessions. It is intended to separate legitimate remote administration from noisy attack traffic.

### 6.10. AbuseIPDB Tab

The **AbuseIPDB** tab manages:
- API key configuration
- Manual and automatic report workflows
- Report history with deduplication
- Rate-limit-aware status and validation

Secrets are never displayed back in plaintext.

### 6.11. MikroTik Tab

The **MikroTik** tab configures RouterOS v7 REST integration:
- Router address and port
- DPAPI-protected credentials
- TLS validation behavior
- Address-list synchronization
- Connectivity testing

### 6.12. Logs Tab

The **Logs** tab displays operational entries from `OperationLogs`, grouped by severity:
- `Info`
- `Warning`
- `Error`
- `Critical`

### 6.13. Diagnostics Tab

The **Diagnostics** tab provides operator-facing health data:
- Worker state
- IPC health
- Database size and status
- Integration checks
- Diagnostic export support

---

## 7. RdpAudit.Core — Shared Library

### 7.1. Data Models

Key entities include:

| Type | Description |
|------|-------------|
| `RdpConnectionFact` | RDP connection fact record |
| `AuthAttemptFact` | Authentication attempt fact |
| `Session` | RDP session metadata |
| `SessionIpCorrelation` | Session-to-IP mapping |
| `AttackStat` | Aggregated attack metrics |
| `AttackThreatLevel` | Threat level enum |
| `AttackThreatScoring` | Threat scoring logic |
| `AttackStatProjection` | UI-facing attack statistics projection |
| `ActiveBlock` | Active block record |
| `BlocklistEntry` | Persistent blocklist entry |
| `WhitelistEntry` | Trusted IP or CIDR entry |
| `Alert` | Alert record |
| `AbuseReport` | AbuseIPDB report payload |
| `AbuseIpDbReportHistory` | Report history and deduplication |
| `RawEvent` | Normalized raw event record |
| `OperationLog` | Service operation log record |
| `LoginRule` | Time-based access rule |
| `Bookmark` | Event processing bookmark |
| `DbProp` | Key-value metadata record |
| `Address` | IP address and related metadata |

### 7.2. Entity Framework Core and Migrations

- EF Core 8 with SQLite
- `AppDbContext` for schema ownership and query support
- Automatic migration application at service startup
- EF Core reserved for configuration, migrations, and UI reads
- Hot-path writes handled through raw SQLite commands and explicit transactions

### 7.3. IPC Contracts (MessagePack)

IPC requests and responses are serialized with **MessagePack**. Representative contracts include:
- `GetStatusRequest` / `GetStatusResponse`
- `GetEventsRequest` / `GetEventsResponse`
- `GetFirewallBlocksRequest` / `GetFirewallBlocksResponse`
- `AddBlockRequest` / `AddBlockResponse`
- `RemoveBlockRequest` / `RemoveBlockResponse`
- `GetSettingsRequest` / `GetSettingsResponse`
- `SaveSettingsRequest` / `SaveSettingsResponse`
- `GetAttackStatsRequest` / `GetAttackStatsResponse`
- `GetOperationLogsRequest` / `GetOperationLogsResponse`

---

## 8. External Integrations

### 8.1. AbuseIPDB

RDPAudit can report attacking IPs to [AbuseIPDB](https://www.abuseipdb.com/) when brute-force or high-confidence malicious behavior is detected.

**Design notes:**
- API keys are stored as DPAPI-protected values
- Duplicate reports are suppressed through local history
- Rate limits are respected
- Report categories are configurable

### 8.2. MikroTik RouterOS v7

RDPAudit can push malicious IPs into a MikroTik address list through the RouterOS v7 REST API.

**Design notes:**
- Works over HTTPS REST endpoints
- Supports configurable TLS validation
- Stores credentials through DPAPI protection
- Avoids duplicate address-list entries
- Falls back gracefully when the router is unavailable

---

## 9. Auto-Blocking Model

### 9.1. Trigger Thresholds

Default behavior:
- **10 failed logons** from the same IP within **10 minutes** triggers a block
- Thresholds are configurable through **Settings**
- Whitelisted sources are excluded before a block is applied

### 9.2. Local Windows Firewall

```text
Provider: WindowsFirewallProvider
Action:   Create inbound rule "RdpAudit_Block_<IP>" (block, any protocol)
Reverse:  Remove rule by name
Verify:   netsh advfirewall firewall show rule name="RdpAudit_Block_<IP>"
```

### 9.3. Remote MikroTik Firewall

```text
Provider: MikroTikFirewallProvider
Action:   PUT /rest/ip/firewall/address-list { address: <IP>, list: "RdpAudit-Blocklist" }
Reverse:  DELETE /rest/ip/firewall/address-list/<id>
Verify:   GET /rest/ip/firewall/address-list?address=<IP>
```

### 9.4. Whitelist Protection for Trusted IPs

- Supports single IPs and CIDR ranges
- Evaluated before any block is created
- Managed through the GUI
- Stored in `WhitelistEntries` with audit-friendly metadata

---

## 10. Data Maintenance

### 10.1. Retention Pruning

A pruning worker periodically deletes stale records.

| Table | Default Retention | Configurable |
|-------|-------------------|-------------|
| `RawEvents` | 90 days | Yes |
| `Alerts` | 180 days | Yes |
| `AbuseIpDbReportHistory` | 365 days | Yes |
| `ActiveBlocks` (inactive) | 30 days | Yes |
| `AttackStats` | 365 days | Yes |

**Implementation notes:**
- Batched deletes
- Exponential backoff on `SQLITE_BUSY`
- Cancellation support
- Operation logging

### 10.2. Backup and Restore

The backup workflow captures configuration state, not the event database.

**Included in backup:**
- `appsettings.json` with DPAPI envelopes only
- Audit policy export
- Relevant registry keys
- Service configuration metadata

**Not included:**
- `rdpaudit.db`

A pre-restore safety snapshot is created before any restore operation is executed.

---

## 11. Security and Auditing

### 11.1. Access Control

| Component | Access Model |
|-----------|--------------|
| `RdpAudit.Service` | Runs as `SYSTEM` or a dedicated service identity |
| Named Pipe IPC | `BUILTIN\Administrators` only |
| `RdpAudit.Configurator` | Requires elevation |
| SQLite DB | Restricted to `SYSTEM` and `Administrators` |
| `appsettings.json` | Restricted to `SYSTEM` and `Administrators` |

### 11.2. SACL Configuration

The Configurator sets SACLs on high-value targets so sensitive changes become auditable:
- IFEO accessibility keys
- `RDP-Tcp` registry configuration
- `Lsa` registry configuration

This supports detection of Sticky Keys backdoors, RDP port changes, and LSASS/PPL tampering.

### 11.3. Secret Protection (DPAPI)

- AbuseIPDB keys and MikroTik credentials are protected with Windows DPAPI
- Only DPAPI envelopes are stored in configuration
- The GUI does not reveal plaintext secrets
- Backups include protected values, not decrypted ones

---

## 12. Configuration

### 12.1. appsettings.json

```jsonc
{
  "RdpAudit": {
    "DatabasePath": "%ProgramData%\\RdpAudit\\rdpaudit.db",
    "EnabledEventIds": ,
    "AlertRules": {
      "BruteForce": {
        "IsEnabled": true,
        "FailThreshold": 10,
        "WindowSeconds": 600
      },
      "OffHoursLogin": {
        "IsEnabled": true,
        "WorkHoursStart": "08:00",
        "WorkHoursEnd": "20:00",
        "WorkDays": ["Monday","Tuesday","Wednesday","Thursday","Friday"],
        "TimeZoneId": "UTC"
      }
    },
    "AutoBlock": {
      "IsEnabled": true,
      "Providers": ["WindowsFirewall"],
      "BlockTtlHours": 0
    },
    "Retention": {
      "RawEventsDays": 90,
      "AlertsDays": 180,
      "AttackStatsDays": 365
    },
    "AbuseIpDb": {
      "IsEnabled": false,
      "ApiKeyDpapi": "",
      "Categories": 
    },
    "MikroTik": {
      "IsEnabled": false,
      "Address": "",
      "Port": 443,
      "UsernameDpapi": "",
      "PasswordDpapi": "",
      "VerifyTls": true,
      "AddressListName": "RdpAudit-Blocklist"
    }
  },
  "Serilog": {
    "MinimumLevel": { "Default": "Information" },
    "WriteTo": [
      { "Name": "File", "Args": { "path": "%ProgramData%\\RdpAudit\\logs\\rdpaudit-.log", "rollingInterval": "Day" } },
      { "Name": "EventLog", "Args": { "source": "RdpAudit", "logName": "Application" } }
    ]
  }
}
```

### 12.2. Environment Variables

You can override configuration values through environment variables, which is useful for automated deployment and diagnostics:

```text
RDPAUDIT_RdpAudit__LogLevel=Debug
RDPAUDIT_RdpAudit__AlertRules__BruteForce__FailThreshold=5
```

---

## 13. Debugging and Diagnostics

### 13.1. Console Mode

When a debugger is attached, the service can run as a console application instead of a formal Windows Service.

```powershell
cd src\RdpAudit.Service
dotnet run --configuration Debug
```

### 13.2. Serilog Logs

Logs are written to:
- `%ProgramData%\RdpAudit\logs\rdpaudit-<date>.log`
- Windows Event Log → `Application`, source `RdpAudit`

To increase verbosity:

```powershell
$env:RDPAUDIT_RdpAudit__LogLevel = "Debug"
```

### 13.3. Direct SQLite Access

```powershell
& "C:\Program Files\DB Browser for SQLite\DB Browser for SQLite.exe" `
  "$env:ProgramData\RdpAudit\rdpaudit.db"
```

Useful queries:

```sql
SELECT * FROM RawEvents ORDER BY TimeUtc DESC LIMIT 100;

SELECT * FROM ActiveBlocks WHERE Status = 'Active';

SELECT SourceIp, SUM(FailCount) AS Fails
FROM AttackStats
GROUP BY SourceIp
ORDER BY Fails DESC
LIMIT 20;
```

### 13.4. Diagnostics Tab

The Diagnostics UI exposes:
- Events-per-second counters
- Worker status
- IPC state
- Database health
- External integration reachability

---

## 14. Build and Test

### 14.1. Build

```powershell
dotnet build RdpAudit.sln -c Release
dotnet build src/RdpAudit.Service/RdpAudit.Service.csproj -c Release
```

### 14.2. Tests

```powershell
dotnet test RdpAudit.sln -c Release
dotnet test RdpAudit.sln -c Release --collect:"XPlat Code Coverage"
dotnet test tests/RdpAudit.Service.Tests/RdpAudit.Service.Tests.csproj
```

Each alert-rule test should validate:
1. Threshold boundary behavior
2. Whitelist bypass behavior
3. Zero managed allocations across repeated evaluations

### 14.3. Publish

```powershell
./publish.ps1
```

Expected output:

```text
publish/
├── Service/
└── Configurator/
```

---

## 15. Troubleshooting

Detailed guidance: [`docs/91-troubleshooting.md`](docs/91-troubleshooting.md)

| Symptom | First Diagnostic Step |
|---------|-----------------------|
| Service does not start | Check `sc.exe query RdpAudit`, then review the Application Event Log |
| No live events appear | Open **Prerequisites** and confirm audit configuration |
| GUI cannot connect | Verify the service is running and the pipe ACL is correct |
| `sc.exe` returns 1639 | Re-check quoting in the service binary path |
| AbuseIPDB returns HTTP 429 | The API rate limit has been reached |
| MikroTik TLS failure | Disable verification for self-signed certs or install the CA cert |
| `SQLITE_BUSY` appears | Short-term contention is expected and retried automatically |
| Audit policy displays `?` | Re-apply through the Audit Policy tab |
| ProgramData ACL issues | Repair folder ACLs for `SYSTEM` and `Administrators` |

See also: [`docs/90-windows-validation.md`](docs/90-windows-validation.md)

---

## 16. Roadmap (v2.0 → v3.0)

| Feature | Status |
|---------|--------|
| ETW ingestion (`OpenTrace` / `ProcessTrace`) | Planned |
| Direct EVTX parsing with `Span<byte>` | Planned |
| Lock-free MPMC ring buffer | Planned |
| SIMD CIDR and parsing acceleration | Planned |
| Zero-allocation event normalization | Planned |
| Network-layer MS-RDPBCGR / RDPEUDP visibility | Research |
| Blazor-based web UI | Planned |
| Elastic / OpenSearch integration | Roadmap |
| Central multi-server collector | Roadmap |

---

## 17. License and Author

**License:** [MIT License](LICENSE)

**Author:** Mikhail Deynekin
- Website: [deynekin.com](https://deynekin.com)
- Email: [Mikhail@Deynekin.com](mailto:Mikhail@Deynekin.com)
- GitHub: [github.com/paulmann](https://github.com/paulmann)

**Repository:** [github.com/paulmann/RDPAudit](https://github.com/paulmann/RDPAudit)

**Related resources:**
- [Technical Specification v1.0](https://github.com/paulmann/1st-RDPMon/wiki/RdpAudit-Service-%E2%80%90-Technical-Specification-v1.0)
- [Technical Specification v2.0](https://github.com/paulmann/1st-RDPMon/wiki/RdpAudit-Service-%E2%80%90-Technical-Specification-v2.0)
- [Issues and Feature Requests](https://github.com/paulmann/RDPAudit/issues)

---

> © 2025–2026 Mikhail Deynekin. Released under the [MIT License](LICENSE).
