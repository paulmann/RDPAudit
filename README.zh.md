# RDPAudit — Windows RDP 安全监控与自动拦截平台

[![版本](https://img.shields.io/badge/version-2.0.2-blue.svg)](https://github.com/paulmann/RDPAudit)
[![许可证](https://img.shields.io/badge/License-BSL%201.1-blue.svg)](LICENSE)
[![.NET](https://img.shields.io/badge/dotnet-8.0--windows-blue.svg)](https://dotnet.microsoft.com/)
[![平台](https://img.shields.io/badge/platform-Windows%2010%2B%20%2F%20Server%202016%2B-blue.svg)](https://www.microsoft.com/windows/)
[![SQLite](https://img.shields.io/badge/sqlite-WAL%20mode-orange.svg)](https://sqlite.org/)

<!-- md-i18n:switcher -->
**其他语言：** [English](README.md) · [Deutsch](README.de.md) · 中文 · [हिन्दी](README.hi.md) · [Español](README.es.md) · [Русский](README.ru.md)

> **RDPAudit** 是一个可直接投产的 Windows 平台，用于监控 RDP 活动并对基于 RDP 的威胁做出响应。  
> 它由两部分组成：**Windows 服务**（后台事件采集、21 条告警规则、自动拦截）和 **WinForms 配置器**（用于管理、统计、诊断与策略配置的图形界面）。

---

## 目录

- [1. 产品概述](#1-产品概述)
  - [1.1. 用途](#11-用途)
  - [1.2. 解决方案架构](#12-解决方案架构)
  - [1.3. 核心能力](#13-核心能力)
- [2. 系统要求](#2-系统要求)
  - [2.1. 最低要求](#21-最低要求)
  - [2.2. Windows 审核要求](#22-windows-审核要求)
- [3. 解决方案布局](#3-解决方案布局)
  - [3.1. 项目与分层](#31-项目与分层)
  - [3.2. 目录结构](#32-目录结构)
- [4. 快速开始](#4-快速开始)
  - [4.1. 构建](#41-构建)
  - [4.2. 安装服务](#42-安装服务)
  - [4.3. Configurator 首次启动](#43-configurator-首次启动)
- [5. RdpAudit.Service — 监控服务](#5-rdpauditservice--监控服务)
  - [5.1. 事件采集](#51-事件采集)
  - [5.2. 跟踪的 Event ID](#52-跟踪的-event-id)
  - [5.3. 数据存储 (SQLite)](#53-数据存储-sqlite)
  - [5.4. 告警系统 — 21 条规则](#54-告警系统--21-条规则)
  - [5.5. Windows 防火墙自动拦截](#55-windows-防火墙自动拦截)
  - [5.6. 命名管道 IPC](#56-命名管道-ipc)
  - [5.7. 可靠性与容错](#57-可靠性与容错)
  - [5.8. REST API (只读)](#58-rest-api-只读)
- [6. RdpAudit.Configurator — 图形界面](#6-rdpauditconfigurator--图形界面)
  - [6.1. Overview 选项卡](#61-overview-选项卡)
  - [6.2. Prerequisites 选项卡](#62-prerequisites-选项卡)
  - [6.3. Audit Policy 选项卡](#63-audit-policy-选项卡)
  - [6.4. Service 选项卡](#64-service-选项卡)
  - [6.5. Settings 选项卡](#65-settings-选项卡)
  - [6.6. Live Events 选项卡](#66-live-events-选项卡)
  - [6.7. Firewall 选项卡](#67-firewall-选项卡)
  - [6.8. Attack Statistics 选项卡](#68-attack-statistics-选项卡)
  - [6.9. Remote RDP Clients 选项卡](#69-remote-rdp-clients-选项卡)
  - [6.10. AbuseIPDB 选项卡](#610-abuseipdb-选项卡)
  - [6.11. MikroTik 选项卡](#611-mikrotik-选项卡)
  - [6.12. Logs 选项卡](#612-logs-选项卡)
  - [6.13. Diagnostics 选项卡](#613-diagnostics-选项卡)
- [6.14. Session Map 选项卡](#614-session-map-选项卡)
- [6.15. Notifications 选项卡](#615-notifications-选项卡)
- [6.16. Web Access 选项卡](#616-web-access-选项卡)
- [7. RdpAudit.Core — 共享库](#7-rdpauditcore--共享库)
  - [7.1. 数据模型](#71-数据模型)
  - [7.2. Entity Framework Core 与迁移](#72-entity-framework-core-与迁移)
  - [7.3. IPC 契约 (MessagePack)](#73-ipc-契约-messagepack)
- [8. 外部集成](#8-外部集成)
  - [8.1. AbuseIPDB](#81-abuseipdb)
  - [8.2. MikroTik RouterOS v7](#82-mikrotik-routeros-v7)
- [9. 自动拦截模型](#9-自动拦截模型)
  - [9.1. 触发阈值](#91-触发阈值)
  - [9.2. 本地 Windows 防火墙](#92-本地-windows-防火墙)
  - [9.3. 远程 MikroTik 防火墙](#93-远程-mikrotik-防火墙)
  - [9.4. 受信任 IP 的白名单保护](#94-受信任-ip-的白名单保护)
- [10. 数据维护](#10-数据维护)
  - [10.1. 保留期清理](#101-保留期清理)
  - [10.2. 备份与恢复](#102-备份与恢复)
- [11. 安全与审核](#11-安全与审核)
  - [11.1. 访问控制](#111-访问控制)
  - [11.2. SACL 配置](#112-sacl-配置)
  - [11.3. 机密保护 (DPAPI)](#113-机密保护-dpapi)
- [12. 配置](#12-配置)
  - [12.1. appsettings.json](#121-appsettingsjson)
  - [12.2. 环境变量](#122-环境变量)
- [13. 调试与诊断](#13-调试与诊断)
  - [13.1. 控制台模式](#131-控制台模式)
  - [13.2. Serilog 日志](#132-serilog-日志)
  - [13.3. 直接访问 SQLite](#133-直接访问-sqlite)
  - [13.4. Diagnostics 选项卡](#134-diagnostics-选项卡)
- [14. 构建与测试](#14-构建与测试)
  - [14.1. 构建](#141-构建)
  - [14.2. 测试](#142-测试)
  - [14.3. 发布](#143-发布)
- [15. 故障排除](#15-故障排除)
- [16. 路线图 (v2.0 → v3.0)](#16-路线图-v20--v30)
- [17. 许可证与作者](#17-许可证与作者)

---

## 1. 产品概述

### 1.1. 用途

**RDPAudit** 用于对 Windows 服务器和工作站上的 RDP 活动进行持续监控。该产品以系统服务的方式在后台运行，即使没有任何交互用户登录也照常工作：它记录连接尝试、身份验证事件以及高价值的系统变更，通过 21 条安全规则对它们进行评估，并可以通过 Windows 防火墙和/或 MikroTik RouterOS 自动拦截攻击者。

**典型使用场景：**
- 保护暴露在互联网上的 RDP 端点，抵御暴力破解攻击
- 满足 SOC2、ISO 27001 以及内部审计对特权访问提出的要求
- 检测账户被攻破的特征，例如反复失败之后出现一次成功登录
- 识别可访问性二进制后门，例如粘滞键（Sticky Keys）与 Utilman 滥用
- 检测针对 LSA/LSASS 的攻击、Kerberos 喷洒以及 RDP 端口变更
- 与 MikroTik 集成，使恶意 IP 能够在网络边缘被拦截

### 1.2. 解决方案架构

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
│  EventCollectorHostedWorker ──► EventProcessorWorker              │
│                                   │                             │
│                                   ▼                             │
│                         AlertWorker ──► 21 Alert Rules            │
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

### 1.3. 核心能力

- **实时监控**：通过 `EventLogWatcher` 订阅事件，而不是轮询
- **21 条告警规则**：覆盖暴力破解、LSASS 攻击、Kerberos 喷洒、可疑的策略变更等
- **自动拦截**：按 IP 创建 Windows 防火墙规则，并支持手工回滚
- **MikroTik 集成**：通过 RouterOS v7 REST API 接入，凭据由 DPAPI 保护
- **AbuseIPDB 上报**：带本地去重与速率限制感知
- **威胁情报信誉查询**（Backlog #5）：后台调用 AbuseIPDB `/api/v2/check`，带磁盘缓存，并在“攻击统计”和“实时事件”中标记高风险
- **威胁分析**：按 IP、国家/地区、时间范围聚合，并计算威胁等级
- **会话与 IP 关联**：将 RDP 会话映射回源地址
- **保留期清理**：保证长期稳定运行，抑制数据库增长
- **备份与恢复**：覆盖配置状态，备份中不含明文机密
- **安全的命名管道 IPC**：仅允许 `BUILTIN\Administrators` 访问
- **只读 HTTPS REST API**（可选，默认关闭）：支持持有者令牌认证、按 IP 限速以及 OpenAPI 描述文件
- **SIEM 导出**（CEF / LEEF 2.0 / NDJSON）：从“实时事件”和“攻击统计”页面导出按 IP 的事件与关联告警

---

## 2. 系统要求

### 2.1. 最低要求

| 组件 | 要求 |
|-----------|-------------|
| 操作系统 | Windows 10 或 Windows Server 2016 及更高版本 (x64) |
| .NET 运行时 | .NET 8.0 for Windows (x64) |
| 权限 | 安装服务与配置系统需要本地管理员权限 |
| 磁盘 | 二进制文件占 200 MB，另需事件数据库所需空间 |
| 内存 | 正常负载下服务工作集 64 MB |

### 2.2. Windows 审核要求

RDPAudit 依赖 Windows 安全审核来接收它所分析的事件。为保证正常工作，必须启用以下审核类别：

| 审核类别 | 子类别 GUID | 用途 |
|----------------|------------------|---------|
| 登录/注销 | `{0CCE9215-69AE-11D9-BED3-505054503030}` | 事件 4624、4625、4634 |
| 账户登录 | `{0CCE9240-69AE-11D9-BED3-505054503030}` | Kerberos 事件 |
| 进程创建 | `{0CCE922B-69AE-11D9-BED3-505054503030}` | 事件 4688 与进程可见性 |
| 对象访问 | `{0CCE9217-69AE-11D9-BED3-505054503030}` | 依赖 SACL 的事件，例如 4656 与 4663 |
| 策略更改 | `{0CCE922F-69AE-11D9-BED3-505054503030}` | 防火墙与策略变更可见性 |

配置器通过带 GUID 标识符调用 `auditpol.exe` 自动应用这些设置，因此该过程与系统区域设置无关。

---

## 3. 解决方案布局

### 3.1. 项目与分层

| 项目 | 类型 | 职责 |
|--------|------|----------------|
| `RdpAudit.Core` | 类库 (`net8.0-windows`) | 实体、EF Core `DbContext`、迁移、MessagePack IPC 契约、共享辅助代码 |
| `RdpAudit.Service` | 工作服务 (`net8.0-windows`、`win-x64`) | 事件采集、规范化、告警评估、自动拦截、IPC 服务端 |
| `RdpAudit.Configurator` | WinForms 应用 (`net8.0-windows`) | 图形界面、IPC 客户端、先决条件检查、服务控制、配置流程 |
| `RdpAudit.Web` | ASP.NET Core 应用 (`net8.0-windows`) | 由 IIS 托管的只读网页仪表盘与回环 YARP 代理：从 DPAPI 保管库注入令牌、安全响应头、固定后端 TLS |
| `RdpAudit.Core.Tests` | xUnit | 核心单元测试 |
| `RdpAudit.Service.Tests` | xUnit | 告警规则测试、阈值校验、白名单覆盖、内存分配检查 |
| `RdpAudit.Web.Tests` | xUnit | Web 代理集成测试：主机过滤、令牌注入、静态 CSP/DOM 契约 |
| `RdpAudit.Benchmarks` | BenchmarkDotNet | 热点路径的基准测试覆盖 |

### 3.2. 目录结构

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
│   ├── RdpAudit.Web/
│   │   ├── wwwroot/             - Static dashboard (index.html + assets)
│   │   ├── Proxy/               - Loopback YARP proxy pipeline and security middleware
│   │   ├── Config/              - WebUiProxyOptions
│   │   └── Program.cs           - Fail-fast WebUI proxy host
│   └── RdpAudit.Configurator/
│       ├── Forms/               — 22 GUI pages
│       ├── IPC/                 — Named Pipe client
│       └── Program.cs           — Elevation, startup, UI bootstrap
├── tests/
│   ├── RdpAudit.Core.Tests/
│   ├── RdpAudit.Service.Tests/
│   ├── RdpAudit.Web.Tests/
│   └── RdpAudit.Benchmarks/
├── docs/
│   ├── 90-windows-validation.md
│   └── 91-troubleshooting.md
└── publish.ps1
```

---

## 4. 快速开始

### 4.1. 构建

```powershell
git clone https://github.com/paulmann/RDPAudit.git
cd RDPAudit
dotnet build RdpAudit.sln -c Release
```

### 4.2. 安装服务

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

### 4.3. Configurator 首次启动

```powershell
publish/Configurator/RdpAudit.Configurator.exe
```

首次启动时，建议按以下顺序操作：

1. 打开 **Prerequisites**，确认所需的通道与平台设置。
2. 打开 **Audit Policy**，通过 `auditpol.exe` 应用所需的审核子类别。
3. 打开 **Service**，安装或启动 Windows 服务。
4. 打开 **Settings**，调整告警阈值、受信任 IP、保留期与各项集成。

---

## 5. RdpAudit.Service — 监控服务

### 5.1. 事件采集

该服务使用 `System.Diagnostics.Eventing.Reader.EventLogWatcher` 实时订阅相关事件。该设计已经抽象到事件源接口之后，因此采集后端将来可以改为基于 ETW 的摄取方式，而无需重写管道其余部分。

**监控的通道：**
- `Security`
- `Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational`
- `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational`

### 5.2. 跟踪的 Event ID

| 事件 ID | 通道 | 说明 |
|----------|---------|-------------|
| 4624 | Security | 成功登录，尤其是登录类型 10 |
| 4625 | Security | 登录失败 |
| 4634 | Security | 注销 |
| 4647 | Security | 用户主动注销 |
| 4648 | Security | 使用显式凭据登录 |
| 4688 | Security | 进程创建 |
| 4720 | Security | 创建用户账户 |
| 4723 / 4724 | Security | 密码更改 / 密码重置 |
| 4740 | Security | 账户锁定 |
| 4769 | Security | Kerberos 服务票据请求 |
| 4771 | Security | Kerberos 预身份验证失败 |
| 4776 | Security | NTLM 身份验证 |
| 4954 | Security | Windows 防火墙规则或策略变更 |
| 1149 | TerminalServices-RCM | 带源 IP 的 RDP 连接 |
| 21, 23, 24, 25 | TerminalServices-LSM | 会话开始、重连、断开、结束 |

### 5.3. 数据存储 (SQLite)

数据库位于 `%ProgramData%\RdpAudit\rdpaudit.db`。

**SQLite 设置：**
```sql
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
```

**主要表：**

| 表 | 用途 |
|-------|---------|
| `RawEvents` | 规范化后的安全事件与 RDP 事件 |
| `RdpConnectionFacts` | 包含 IP、用户与结果的连接事实记录 |
| `AuthAttemptFacts` | 身份验证尝试事实记录 |
| `Sessions` | RDP 会话记录 |
| `SessionIpCorrelations` | 会话与 IP 的对应关系 |
| `AttackStats` | 按来源聚合的攻击统计 |
| `ActiveBlocks` | 当前生效的自动拦截记录 |
| `Alerts` | 告警历史 |
| `WhitelistEntries` | 受信任 IP 与 CIDR 条目 |
| `BlocklistEntries` | 持久化的拦截规则与来源 |
| `AbuseIpDbReportHistory` | AbuseIPDB 上报历史 |
| `OperationLogs` | 在图形界面中展示的操作日志条目 |
| `DbProps` | 键值元数据存储 |
| `Bookmarks` | 事件处理的崩溃恢复书签 |
| `LoginRules` | 工作时间与登录策略规则 |

**写入策略：** 热路径使用原生 `SqliteCommand`，配合显式事务与批量写入。

**书签持久性：** 书签每 100 个事件、且每 30 秒刷新一次，从而把崩溃或断电后的损失降到最低。

### 5.4. 告警系统 — 21 条规则

每条规则都实现为独立的告警评估器，并参与统一的规则管道。

| # | 规则 ID | 严重程度 | 说明 |
|---|---------|----------|-------------|
| 1 | `BRUTE_FORCE` | 高 | 同一来源的失败登录次数超过阈值 |
| 2 | `BRUTE_FORCE_NTLM` | 高 | 带冷却逻辑的 NTLM 暴力破解 |
| 3 | `KERBEROS_SPRAY` | 高 | Kerberos 密码喷洒行为 |
| 4 | `SUCCESSFUL_AFTER_FAILS` | 中 | 反复失败之后出现成功登录 |
| 5 | `OFF_HOURS_LOGIN` | 中 | 在批准的工作时间之外登录 |
| 6 | `ACCOUNT_LOCKOUT` | 中 | 账户锁定事件 |
| 7 | `NEW_ACCOUNT_CREATED` | 中 | 新建本地或域账户 |
| 8 | `PASSWORD_RESET` | 低 | 密码重置或密码更改 |
| 9 | `MULTIPLE_ACCOUNTS_SAME_IP` | 高 | 来自单一源 IP 的用户名喷洒 |
| 10 | `STICKY_KEYS_BACKDOOR` | 严重 | 可访问性二进制后门行为 |
| 11 | `LSASS_ACCESS` | 严重 | 对 LSASS 的可疑句柄访问 |
| 12 | `LSASS_PPL_TAMPER` | 严重 | 试图削弱 LSASS PPL 保护 |
| 13 | `RDP_PORT_CHANGED` | 高 | 检测到基于注册表的 RDP 端口变更 |
| 14 | `FIREWALL_RULE_CHANGED` | 中 | 防火墙规则或策略被更改 |
| 15 | `EXPLICIT_CREDENTIALS` | 中 | 显式凭据使用模式 |
| 16 | `LOGON_TYPE_NETWORK` | 低 | 对受保护系统的网络登录 |
| 17 | `CONCURRENT_SESSIONS` | 低 | 并发会话数量过多 |
| 18 | `GEO_ANOMALY` | 中 | 来自被禁止或异常地理位置的登录 |
| 19 | `IP_REPUTATION` | 高 | 源 IP 出现在已知黑名单中 |
| 20 | `SESSION_HIJACK_SUSPECT` | 高 | 会话关联异常 |
| 21 | `RAPID_RECONNECT` | 中 | 来自同一 IP 的反复重连活动 |

### 5.4.1. PRIVILEGED_LOGIN 加固

`PRIVILEGED_LOGIN` 规则（事件 4672 —— 登录时授予 SeDebug / SeTcb）针对服务启动时的已知 SID 风暴（大量没有源 IP 的相同 SYSTEM 告警）做了加固：

- **精确 SID 过滤** - `S-1-5-18`（SYSTEM）、`S-1-5-19`（LOCAL SERVICE）与 `S-1-5-20`（NETWORK SERVICE）会被拒绝；判定依据是从规范化后的 `Details` JSON（`subjectUserSid`）中读取的精确 SID，而不是本地化的账户名。
- **必须为网络上下文** - 事件必须带有非空的 `SourceIp`，并且登录类型为网络类型（3 / 7 / 10）。若缺少 `LogonType`（Windows 4672 本身没有该字段），则回退为通过 `SubjectLogonId == TargetLogonId` 关联相应的 Security 4624。
- **抑制窗口** - 同一（用户、源 IP、登录类型）组合的相同触发会在 `PrivilegedLoginSuppressionWindowMinutes`（默认 5）内被抑制；窗口结束后，由一条汇总告警携带被抑制的次数。
- **每分钟告警预算** - `PrivilegedLoginRateLimitPerMinute`（默认 20）限制输出总量；限流本身每分钟记录一次日志。
- **历史年龄闸门** - 早于 `AlertEventMaxAgeMinutes`（默认 5）的事件仍作为 `RawEvent` 事实持久化，但永不产生告警（由 `AlertWorker` 对所有规则统一施加）。
- **零分配拒绝路径** - `EvaluateAsync` 是非异步方法，返回缓存的空任务单例，因此被拒绝的评估不产生任何内存分配。

### 5.5. Windows 防火墙自动拦截

当 `BRUTE_FORCE`、`BRUTE_FORCE_NTLM` 或 `IP_REPUTATION` 等规则被触发时，服务可以创建按 IP 的入站拦截规则。

```powershell
netsh advfirewall firewall add rule `
  name="RdpAudit_Block_<IP>" `
  dir=in action=block remoteip=<IP> `
  protocol=any enable=yes
```

**实现特征：**
- 幂等的规则创建
- 执行 shell 命令前先做输入清理
- 可通过图形界面手工移除
- 通过 `ActiveBlocks` 与 `OperationLogs` 完成全程审计

### 5.6. 命名管道 IPC

**管道名称：** `\\.\pipe\RdpAuditService`

**安全模型：** 仅允许 `BUILTIN\Administrators` 连接。

**协议：** 请求与响应契约采用 `RdpAudit.Core` 中定义的 MessagePack。

**运行说明：**
- 图形界面从不直接写入服务所有的配置文件。
- 设置通过 IPC 发送，由服务以原子方式提交。
- 连接超时机制防止配置器无限期挂起。
- 管道由 `IpcServerWorker` 提供服务，它申请 `MaxConcurrent + 1` 个操作系统实例，使始终监听的备用管道不会与已连接的处理器争用。Win32 的 `ERROR_PIPE_BUSY`（231）被归类为“实例上限已满”，而不是 AV/EDR 拦截；随着处理器完成，饱和状态会自动解除。
- 每个工作实例都会把可观测的生命周期事实写入 `%ProgramData%\RdpAudit\logs\ipc-startup.log`：`instance constructed` / `ExecuteAsync entered` / `ExecuteAsync exiting (pid, instanceId, entryCount, exitCount, iteration, activeHandlers, livePipes, stoppingTokenCancelled, hostApplicationStoppingCancelled, exitReason, lifetimeMs)`。这些字段可以证明单个进程是否曾经运行过多个工作实例或宿主实例。

### 5.7. 可靠性与容错

- 针对 `SQLITE_BUSY` 等临时数据库争用采用指数退避
- 跨异步流的端到端 `CancellationToken` 传递
- 每个托管工作线程都包裹在 `TimedHostedService` 中，并写入 `startup-sequence.log` 的开始/结束/失败标记
- `IpcServerWorker` 记录每个实例的生命周期阶段信息，因此在同一 PID 中重复出现 `ExecuteAsync entered` 可以归因到一个或多个工作实例/宿主实例
- 服务停止时优雅关闭
- 启动时应用 EF Core 迁移
- 安装期间注册事件日志源

### 5.8. REST API (只读)

服务可以暴露一个**可选的只读 HTTPS REST API**（Kestrel，默认关闭），供监控代理与脚本使用。它只应答 `GET`/`HEAD`，并复用与命名管道相同的、已审计的读取命令，因此 REST 接口不存在任何写入路径。

- **端点**：`/healthz`（匿名）、`/api/status`、`/api/alerts`、`/api/sessions`、
  `/api/addresses`、`/api/attacks`、`/api/config`（机密已掩码）、
  `/api/events`（有界、可过滤、有序的分页），以及
  `/openapi/v1.json`（随仓库提交的 OpenAPI 3.0 描述文件）。
- **身份验证**：静态持有者令牌（`Api.Token`，由 DPAPI 保护）；返回 401 时附带
  `WWW-Authenticate: Bearer realm="rdpaudit"`。
- **传输**：仅 HTTPS。监听地址默认为 `127.0.0.1:8443`；`LocalMachine\My` 中的 TLS 证书
  通过 `Api.CertificateThumbprint` / `Api.CertificateSubject` 选择。
  非回环监听会在启动时记录一条明确的风险警告。
- **加固**：按 IP 的固定窗口限速（`Api.RateLimitPerMinute`）、
  连接数上限（`Api.MaxConnections`）、安全响应头，以及所有非 200 响应都使用 RFC 9457
  的 `problem+json` 错误体。
- **失败即关闭的启动**：`Api.Enabled=false`（默认）或任何前提条件缺失
  （令牌/证书/地址）都意味着完全不监听。

配置位于 `appsettings.json` 的 `Api` 段。完整参考：
`docs/40-options.md`（ApiOptions）与 `docs/51-rest-api.md`（端点、错误、
身份验证、运维）。

---

## 6. RdpAudit.Configurator — 图形界面

配置器以提权方式运行，并且严格通过命名管道 IPC 通道与服务通信。

### 6.1. Overview 选项卡

**Overview** 选项卡是运维仪表盘。它汇总服务状态、当前拦截数量、最近的告警以及近期的事件量。

### 6.2. Prerequisites 选项卡

**Prerequisites** 选项卡检查所需的 Windows 条件：
- 七个受监控的事件日志通道全部存在且已启用（Security、System，以及
  Terminal Services / RDP 各通道）
- 已应用所需的审核策略子类别（对象访问 + 五子类别基线）
- 服务已安装且可访问

被禁用的通道会提供一个 `wevtutil sl /enabled:true` 修复项。在某个 Windows 版本/SKU 上
不存在的通道（例如未安装 RD Gateway 角色的主机上的 `TerminalServices-Gateway`）
会被报告为缺失且不提供自动修复，因此该选项卡绝不会为当前 Windows 版本无法创建的通道
提供启用按钮。每个可修复的失败项都可以直接在界面中应用。

### 6.3. Audit Policy 选项卡

**Audit Policy** 选项卡读取当前的 Windows 审核配置，并通过基于 GUID 的 `auditpol.exe` 调用应用所需的子类别。它还负责为高价值注册表位置以及与 RDP 滥用检测相关的 IFEO 路径配置 SACL。

### 6.4. Service 选项卡

**Service** 选项卡支持：
- 安装与卸载
- 启动、停止、重启
- 服务状态显示
- 启动模式控制

### 6.5. Settings 选项卡

**Settings** 选项卡提供运行配置，包括：
- 告警阈值
- 暴力破解时间窗口
- 工作时间定义
- 数据保留期
- AbuseIPDB 设置
- MikroTik 设置
- 地理位置与白名单设置

更改通过 IPC 提交，由服务以原子方式应用。

### 6.6. Live Events 选项卡

**Live Events** 选项卡提供 tail 模式的实时事件流，并对失败、警告与成功活动做彩色区分。它支持按 Event ID 与源 IP 过滤。**High risk**（高风险）列显示每个源 IP 的缓存威胁情报标记（Stage 15）。

### 6.7. Firewall 选项卡

**Firewall** 选项卡展示来自 `ActiveBlocks` 的生效拦截记录，并支持：
- 查看被拦截的 IP、原因与提供方
- 手工添加拦截条目
- 经确认后移除拦截
- 导入或导出拦截列表

### 6.8. Attack Statistics 选项卡

**Attack Statistics** 选项卡呈现聚合后的攻击数据：
- 攻击来源 IP 排名
- 威胁等级评分
- 基于时间的图表
- 按国家/地区分组
- CSV 导出支持
- **High risk**（高风险）列，数据来自缓存的威胁情报标记（Stage 15）

威胁等级由 `AttackThreatScoring` 中的评分逻辑计算。

### 6.9. Remote RDP Clients 选项卡

**Remote RDP Clients** 选项卡关联源 IP、连接次数、用户名与历史 RDP 会话。它用于把合法的远程管理与噪声型攻击流量区分开。

### 6.10. AbuseIPDB 选项卡

**AbuseIPDB** 选项卡管理：
- API 密钥配置
- 手工与自动上报流程
- 带去重的上报历史
- 感知速率限制的状态与校验
- 威胁情报信誉查询（/api/v2/check），含缓存状态、每日用量与高风险阈值（Backlog #5）

机密信息永远不会以明文回显。

### 6.11. MikroTik 选项卡

**MikroTik** 选项卡配置 RouterOS v7 REST 集成：
- 路由器地址与端口
- 由 DPAPI 保护的凭据
- TLS 校验行为
- 地址列表同步
- 连通性测试

### 6.12. Logs 选项卡

**Logs** 选项卡显示 `OperationLogs` 中的操作条目，并按严重程度分组：
- `Info`
- `Warning`
- `Error`
- `Critical`

### 6.13. Diagnostics 选项卡

**Diagnostics** 选项卡向运维人员提供健康状态数据：
- 工作线程状态
- IPC 健康状况
- 数据库大小与状态
- 集成检查
- 诊断信息导出支持

### 6.14. Session Map 选项卡

**Session Map** 选项卡让 SOC 运维人员以时间线形式检视单个历史 RDP 会话（Backlog #6）。
从有界会话列表（由现有的 `ListConnectionFacts` 命令提供，支持 IP /
用户过滤）中选择一条事实记录，即会加载 `GetSessionTimeline` 响应，并同时以两种方式展示：

- **事件表格** - 时间、类型（登录开始 / 已连接 / 已重连 /
  已断开 / 注销 / 进程 / 文件 / 其他）、事件 ID、进程、对象
  以及显式的关联方法。由 `UserWindow` 关联的行以琥珀色着色，
  使较低的取证可信度始终可见；原始 DEBUG 明细文本仅在服务以 DEBUG 模式运行时
  通过工具提示提供。
- **甘特图面板** - 内置的 GDI+ 时间线，带 UTC 时间轴、
  彩色泳道、图例、用于标识活动会话的虚线“now”光束，以及当服务端活动上限
  （50..2000，默认 500）触发时显示的 `TRUNCATED` 标记。

该命令严格只读，不新增任何表或迁移；契约、关联规则、威胁模型与
回滚指引见 `docs/54-session-map.md`。

### 6.15. Notifications 选项卡

**Notifications** 选项卡配置提权运行的 `RdpAudit.Notifier` 托盘应用：

- **Enable tray notifier**（启用托盘通知器） - 总开关；关闭时通知器会静默退出。
- **Start with Windows**（随 Windows 启动） - 通过 `schtasks`（`ONLOGON`、`/RL HIGHEST`）注册 / 移除 `RdpAudit.Notifier` 登录任务。
- **Poll interval**（轮询间隔） - 服务轮询周期，单位为秒（限制在 1..60）。
- **Minimum severity**（最低严重程度） - 低于该严重程度的告警永不显示。
- **Max toasts per minute**（每分钟最大提示数） - 滑动窗口速率上限（限制在 1..60）；超出的告警会合并为一条汇总提示。
- **Use native toasts**（使用原生提示） - 优先使用 WinRT 提示而非托盘气泡；当原生通道不可用时，通知器会回退到气泡。
- **Alerts / Events 子选项卡** - 按规则与按事件的可见性映射。

保存 / 刷新通过 IPC 命令 `GetNotificationSettings`（78）与
`SaveNotificationSettings`（79）完成；服务会对取值做范围限制，把严重程度回退为 `High`，
并且只持久化 `appsettings.json` 中的 `RdpAudit.Notifications` 段。通知器通过命名管道轮询服务，
在服务不可达时降级到安全的轮询间隔，并且从不修改数据库。

---

### 6.16. Web Access 选项卡

**Web Access** 选项卡（紧跟在 **Service** 之后）是由 IIS 托管的只读网页仪表盘的入口。
它**隐私优先**：在运维人员明确选择启用之前，一切都保持关闭。

- **Show Web Access**（显示 Web Access） - 持久化运维人员的可见性选择；
  默认关闭，且仅在运维人员切换时才会存储。
- **Allow management from the web**（允许从 Web 进行管理） - 按阶段开启：
  可见但被锁定，直到后续的管理阶段解锁；在该闸门打开之前，存储的偏好永远不可能变为 true。
- **Refresh status**（刷新状态） - 重新运行失败即关闭的 IIS 探测（注册表 `InetStp`、
  只读的 `dism /English /Online /GetFeatureInfo`、W3SVC 服务检查），
  并显示一行结论。
- **Install IIS**（安装 IIS） - 由 `IisInstallPlan` 驱动的引导式幂等安装，
  它是运行前清单与实际执行流程的唯一权威来源。
  进度窗口会在任何操作开始前列出所有条目，并为每条目标上勾或叉：提权、
  静态 DISM 功能集（`IIS-WebServerRole`、
  `IIS-WebServer`、`IIS-StaticContent`、`IIS-DefaultDocument`、`IIS-HttpErrors`，通过
  `dism ... /NoRestart`）、IIS 管理工具（`IIS-WebServerManagementTools`、
  `IIS-ManagementScriptingTools`，它们提供“Configure IIS”所用的 `appcmd.exe`）、
  通过 `winget install --id Microsoft.DotNet.HostingBundle.8 --exact` 安装的
  ASP.NET Core Hosting Bundle（它是原生 `AspNetCoreModuleV2` 的唯一来源），
  以及最后对机器实际情况的验证。当模块已存在时会跳过该捆绑包步骤，
  因此同一台机器上的 winget 绝不会被调用两次；DISM 退出码 3010
  会作为要求重启的警告上报 —— 绝不报告为成功。
- **Configure IIS**（配置 IIS） - 引导式配置 `RdpAuditWebUi` 站点：需要
  提权以及 ASP.NET Core Module v2（Hosting Bundle），解析或
  创建回环 HTTPS 证书，把 Web 令牌仅以
  DPAPI 保护的封装形式存入服务的 `appsettings.json`，将
  RdpAudit.Web 负载展开到 `%ProgramData%\RdpAudit\WebUI`，把站点绑定到
  `https://127.0.0.1:443`，并重启服务。

两个流程按钮都会保持禁用，直到探测能够真正判定 IIS 状态。
浏览器始终看不到持有者令牌：进程内的 YARP 代理
从机器范围的 DPAPI 保管库注入令牌，并剥离浏览器提供的任何
`Authorization` 头；此外主机过滤器会拒绝非回环主机名（防御 DNS 重绑定）。

## 7. RdpAudit.Core — 共享库

### 7.1. 数据模型

关键实体包括：

| 类型 | 说明 |
|------|-------------|
| `RdpConnectionFact` | RDP 连接事实记录 |
| `AuthAttemptFact` | 身份验证尝试事实记录 |
| `Session` | RDP 会话元数据 |
| `SessionIpCorrelation` | 会话与 IP 的对应关系 |
| `AttackStat` | 聚合的攻击指标 |
| `AttackThreatLevel` | 威胁等级枚举 |
| `AttackThreatScoring` | 威胁评分逻辑 |
| `AttackStatProjection` | 面向前端的攻击统计投影 |
| `ActiveBlock` | 生效的拦截记录 |
| `BlocklistEntry` | 持久化拦截列表条目 |
| `WhitelistEntry` | 受信任 IP 或 CIDR 条目 |
| `Alert` | 告警记录 |
| `AbuseReport` | AbuseIPDB 上报载荷 |
| `AbuseIpDbReportHistory` | 上报历史与去重 |
| `RawEvent` | 规范化的原始事件记录 |
| `OperationLog` | 服务操作日志记录 |
| `LoginRule` | 基于时间的访问规则 |
| `Bookmark` | 事件处理书签 |
| `DbProp` | 键值元数据记录 |
| `ThreatIntelLookup` | 按 IP 缓存的 /api/v2/check 信誉快照（Stage 15） |
| `ThreatIntelUsageCounter` | 持久化的每日 /check 用量预算计数器（Stage 15） |
| `Address` | IP 地址及相关元数据 |

### 7.2. Entity Framework Core 与迁移

- 使用 SQLite 的 EF Core 8
- `AppDbContext` 负责架构所有权与查询支持
- 服务启动时自动应用迁移
- EF Core 仅用于配置、迁移与界面读取
- 热路径写入通过原生 SQLite 命令与显式事务完成

### 7.3. IPC 契约 (MessagePack)

IPC 请求与响应使用 **MessagePack** 序列化。代表性契约包括：
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

## 8. 外部集成

### 8.1. AbuseIPDB

当检测到暴力破解或高置信度的恶意行为时，RDPAudit 可以把攻击 IP 上报给 [AbuseIPDB](https://www.abuseipdb.com/)。

**设计说明：**
- API 密钥以 DPAPI 保护的值存储
- 重复上报通过本地历史记录抑制
- 遵守速率限制
- 上报类别可配置

RDPAudit 也可以在读取时查询 IP 信誉：可选的威胁情报功能
（`AbuseIpDb.CheckEnabled`）通过后台工作线程执行 GET /api/v2/check，
为公开攻击来源 IP 预热磁盘缓存，并在“攻击统计”与“实时事件”表格中
显示高风险标记。API 密钥仅在
`Key` 头中发送，且从不记入日志。

### 8.2. MikroTik RouterOS v7

RDPAudit 可以通过 RouterOS v7 REST API 把恶意 IP 推送到 MikroTik 地址列表。

**设计说明：**
- 通过 HTTPS REST 端点工作
- 支持可配置的 TLS 校验
- 通过 DPAPI 保护存储凭据
- 避免地址列表中出现重复条目
- 路由器不可用时优雅降级

---

## 9. 自动拦截模型

### 9.1. 触发阈值

默认行为：
- 同一 IP 在 **10 分钟**内出现 **10 次登录失败**即触发拦截
- 阈值可通过 **Settings** 配置
- 白名单来源在应用拦截之前被排除

### 9.2. 本地 Windows 防火墙

```text
Provider: WindowsFirewallProvider
Action:   Create inbound rule "RdpAudit_Block_<IP>" (block, any protocol)
Reverse:  Remove rule by name
Verify:   netsh advfirewall firewall show rule name="RdpAudit_Block_<IP>"
```

### 9.3. 远程 MikroTik 防火墙

```text
Provider: MikroTikFirewallProvider
Action:   PUT /rest/ip/firewall/address-list { address: <IP>, list: "RdpAudit-Blocklist" }
Reverse:  DELETE /rest/ip/firewall/address-list/<id>
Verify:   GET /rest/ip/firewall/address-list?address=<IP>
```

### 9.4. 受信任 IP 的白名单保护

- 支持单个 IP 与 CIDR 网段
- 在创建任何拦截之前先行评估
- 通过图形界面管理
- 存储在 `WhitelistEntries` 中，附带便于审计的元数据

---

## 10. 数据维护

### 10.1. 保留期清理

清理工作线程会定期删除过期记录。

| 表 | 默认保留期 | 可配置 |
|-------|-------------------|-------------|
| `RawEvents` | 90 天 | 是 |
| `Alerts` | 180 天 | 是 |
| `AbuseIpDbReportHistory` | 365 天 | 是 |
| `ActiveBlocks`（非活动） | 30 天 | 是 |
| `AttackStats` | 365 天 | 是 |

**实现说明：**
- 批量删除
- 遇 `SQLITE_BUSY` 时指数退避
- 支持取消
- 操作日志记录

### 10.2. 备份与恢复

备份流程捕获的是配置状态，而不是事件数据库。

**备份包含：**
- 仅含 DPAPI 封装的 `appsettings.json`
- 审核策略导出
- 相关注册表项
- 服务配置元数据

**不包含：**
- `rdpaudit.db`

在执行任何恢复操作之前，都会先创建一份恢复前的安全快照。

---

## 11. 安全与审核

### 11.1. 访问控制

| 组件 | 访问模型 |
|-----------|--------------|
| `RdpAudit.Service` | 以 `SYSTEM` 或专用服务身份运行 |
| 命名管道 IPC | 仅限 `BUILTIN\Administrators` |
| `RdpAudit.Configurator` | 需要提权 |
| SQLite 数据库 | 仅限 `SYSTEM` 与 `Administrators` |
| `appsettings.json` | 仅限 `SYSTEM` 与 `Administrators` |

### 11.2. SACL 配置

配置器会为高价值目标设置 SACL，使敏感变更变得可审计：
- IFEO 可访问性相关键
- `RDP-Tcp` 注册表配置
- `Lsa` 注册表配置

这为检测粘滞键后门、RDP 端口变更以及 LSASS/PPL 篡改提供了支持。

### 11.3. 机密保护 (DPAPI)

- AbuseIPDB 密钥与 MikroTik 凭据使用 Windows DPAPI 保护
- 配置中只存储 DPAPI 封装
- 图形界面不会显示明文机密
- 备份包含的是受保护的值，而不是解密后的值

---

## 12. 配置

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
    "Alerts": {
      "EnablePrivilegedLoginDetection": true,
      "PrivilegedLoginSuppressionWindowMinutes": 5,
      "PrivilegedLoginRateLimitPerMinute": 20,
      "AlertEventMaxAgeMinutes": 5
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
      "Enabled": false,
      "ReportAttacks": false,
      "ApiKey": "",
      "BaseUrl": "https://api.abuseipdb.com",
      "EndpointUrl": "https://api.abuseipdb.com/api/v2/report",
      "TimeoutSeconds": 15,
      "MaxReportsPerMinute": 60,
      "MaxReportsPerHour": 100,
      "MaxReportsPerDay": 500,
      "DeduplicationWindowMinutes": 15,
      "CacheLookups": true,
      "CacheTtlMinutes": 60,
      "ReportThreshold": 80,
      "MinThreatScore": 60.0,
      "MinFailedAttempts": 10,
      "ReportCategories": [18, 22],
      "ReportDedupeEnabled": true,
      "ReportCooldownHours": 24,
      "CheckEnabled": false,
      "CheckMaxLookupsPerMinute": 30,
      "CheckMaxLookupsPerDay": 500,
      "CheckMaxAgeInDays": 30,
      "CheckWorkerIntervalSeconds": 300
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

### 12.2. 环境变量

可以通过环境变量覆盖配置值，这在自动化部署与诊断时很有用：

```text
RDPAUDIT_RdpAudit__LogLevel=Debug
RDPAUDIT_RdpAudit__AlertRules__BruteForce__FailThreshold=5
```

---

## 13. 调试与诊断

### 13.1. 控制台模式

当附加了调试器时，服务可以作为控制台应用程序运行，而不必作为正式的 Windows 服务运行。

```powershell
cd src\RdpAudit.Service
dotnet run --configuration Debug
```

### 13.2. Serilog 日志

日志写入：
- `%ProgramData%\RdpAudit\logs\rdpaudit-<date>.log`
- Windows 事件日志 → `Application`，来源 `RdpAudit`

要提高详细程度：

```powershell
$env:RDPAUDIT_RdpAudit__LogLevel = "Debug"
```

### 13.3. 直接访问 SQLite

```powershell
& "C:\Program Files\DB Browser for SQLite\DB Browser for SQLite.exe" `
  "$env:ProgramData\RdpAudit\rdpaudit.db"
```

常用查询：

```sql
SELECT * FROM RawEvents ORDER BY TimeUtc DESC LIMIT 100;

SELECT * FROM ActiveBlocks WHERE Status = 'Active';

SELECT SourceIp, SUM(FailCount) AS Fails
FROM AttackStats
GROUP BY SourceIp
ORDER BY Fails DESC
LIMIT 20;
```

### 13.4. Diagnostics 选项卡

Diagnostics 界面提供：
- 每秒事件数计数器
- 工作线程状态
- IPC 状态
- 数据库健康状况
- 外部集成可达性

---

## 14. 构建与测试

### 14.1. 构建

```powershell
dotnet build RdpAudit.sln -c Release
dotnet build src/RdpAudit.Service/RdpAudit.Service.csproj -c Release
```

### 14.2. 测试

```powershell
dotnet test RdpAudit.sln -c Release
dotnet test RdpAudit.sln -c Release --collect:"XPlat Code Coverage"
dotnet test tests/RdpAudit.Service.Tests/RdpAudit.Service.Tests.csproj
```

每条告警规则测试都应验证：
1. 阈值边界行为
2. 白名单绕过行为
3. 重复评估过程中不产生托管内存分配

### 14.3. 发布

```powershell
./publish.ps1
```

预期输出：

```text
publish/
├── Service/
└── Configurator/
```

---

## 15. 故障排除

详细指引：[`docs/91-troubleshooting.md`](docs/91-troubleshooting.md)

| 症状 | 第一步诊断 |
|---------|-----------------------|
| 服务无法启动 | 运行 `sc.exe query RdpAudit`，然后查看应用程序事件日志 |
| 没有实时事件出现 | 打开 **Prerequisites** 并确认审核配置 |
| 图形界面无法连接 | 确认服务正在运行，且管道 ACL 正确 |
| `sc.exe` 返回 1639 | 重新检查服务二进制路径中的引号 |
| AbuseIPDB 返回 HTTP 429 | 已触达 API 速率限制 |
| MikroTik TLS 失败 | 对自签名证书关闭校验，或安装 CA 证书 |
| 出现 `SQLITE_BUSY` | 短期争用属预期现象，会自动重试 |
| 审核策略显示 `?` | 通过 Audit Policy 选项卡重新应用 |
| ProgramData ACL 问题 | 修复 `SYSTEM` 与 `Administrators` 的文件夹 ACL |

另见：[`docs/90-windows-validation.md`](docs/90-windows-validation.md)

---

## 16. 路线图 (v2.0 → v3.0)

| 功能 | 状态 |
|---------|--------|
| ETW 摄取（`OpenTrace` / `ProcessTrace`） | 计划中 |
| 使用 `Span<byte>` 直接解析 EVTX | 计划中 |
| 无锁 MPMC 环形缓冲区 | 计划中 |
| SIMD 与 CIDR 解析加速 | 计划中 |
| 零分配的事件规范化 | 计划中 |
| 网络层 MS-RDPBCGR / RDPEUDP 可见性 | 研究中 |
| 基于 Blazor 的 Web 界面 | 计划中 |
| Elastic / OpenSearch 集成 | 路线图 |
| 集中式多服务器采集器 | 路线图 |

---

## 17. 许可证与作者

**许可证：** [Business Source License 1.1](LICENSE)

RDPAudit Community 是源码可见的。您可以为非生产目的复制、修改、再分发和使用它；
写入 `LICENSE` 的 Additional Use Grant 还额外允许生产使用，但不包括将本软件作为商业托管或
管理服务提供给第三方。自 **2030-10-25** 起，该版本将转换为 Apache License 2.0。

Pro 与 Enterprise 版本为专有软件，**不**受本许可证约束 —— 它们各自
拥有自己的条款。哪项能力属于哪个版本，记录在
[docs/editions.md](docs/editions.md) 中。

**作者：** Mikhail Deynekin
- 网站：[deynekin.com](https://deynekin.com)
- 电子邮件：[Mikhail@Deynekin.com](mailto:Mikhail@Deynekin.com)
- GitHub：[github.com/paulmann](https://github.com/paulmann)

**仓库：** [github.com/paulmann/RDPAudit](https://github.com/paulmann/RDPAudit)

**相关资源：**
- [Technical Specification v1.0](https://github.com/paulmann/1st-RDPMon/wiki/RdpAudit-Service-%E2%80%90-Technical-Specification-v1.0)
- [Technical Specification v2.0](https://github.com/paulmann/1st-RDPMon/wiki/RdpAudit-Service-%E2%80%90-Technical-Specification-v2.0)
- [问题与功能请求](https://github.com/paulmann/RDPAudit/issues)

---

> © 2025–2026 Mikhail Deynekin. 依据 [Business Source License 1.1](LICENSE) 发布。
