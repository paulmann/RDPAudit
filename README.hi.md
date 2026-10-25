# RDPAudit — Windows RDP सुरक्षा निगरानी और ऑटो-ब्लॉक प्लेटफ़ॉर्म।

[![संस्करण](https://img.shields.io/badge/version-2.0.2-blue.svg)](https://github.com/paulmann/RDPAudit)
[![लाइसेंस](https://img.shields.io/badge/License-BSL%201.1-blue.svg)](LICENSE)
[![.NET](https://img.shields.io/badge/dotnet-8.0--windows-blue.svg)](https://dotnet.microsoft.com/)
[![प्लेटफ़ॉर्म](https://img.shields.io/badge/platform-Windows%2010%2B%20%2F%20Server%202016%2B-blue.svg)](https://www.microsoft.com/windows/)
[![SQLite](https://img.shields.io/badge/sqlite-WAL%20mode-orange.svg)](https://sqlite.org/)

<!-- md-i18n:switcher -->
**अन्य भाषाओं में:** [English](README.md) · [Deutsch](README.de.md) · [中文](README.zh.md) · हिन्दी · [Español](README.es.md) · [Русский](README.ru.md)

> **RDPAudit** RDP गतिविधि की निगरानी और RDP-आधारित ख़तरों का जवाब देने के लिए एक प्रोडक्शन-रेडी Windows प्लेटफ़ॉर्म है।
> इसमें एक **Windows Service** (बैकग्राउंड में इवेंट संग्रह, 21 अलर्ट नियम, स्वचालित ब्लॉकिंग) और एक **WinForms Configurator** (प्रबंधन, आँकड़े, डायग्नोस्टिक्स और पॉलिसी कॉन्फ़िगरेशन के लिए GUI) शामिल हैं।

---

## विषय-सूची

- [1. उत्पाद अवलोकन](#1-उत्पाद-अवलोकन)
  - [1.1. उद्देश्य](#11-उद्देश्य)
  - [1.2. समाधान आर्किटेक्चर](#12-समाधान-आर्किटेक्चर)
  - [1.3. मुख्य क्षमताएँ](#13-मुख्य-क्षमताएँ)
- [2. सिस्टम आवश्यकताएँ](#2-सिस्टम-आवश्यकताएँ)
  - [2.1. न्यूनतम आवश्यकताएँ](#21-न्यूनतम-आवश्यकताएँ)
  - [2.2. Windows ऑडिटिंग आवश्यकताएँ](#22-windows-ऑडिटिंग-आवश्यकताएँ)
- [3. समाधान की संरचना](#3-समाधान-की-संरचना)
  - [3.1. प्रोजेक्ट और लेयर](#31-प्रोजेक्ट-और-लेयर)
  - [3.2. डायरेक्टरी संरचना](#32-डायरेक्टरी-संरचना)
- [4. त्वरित शुरुआत](#4-त्वरित-शुरुआत)
  - [4.1. बिल्ड](#41-बिल्ड)
  - [4.2. सेवा इंस्टॉल करें](#42-सेवा-इंस्टॉल-करें)
  - [4.3. Configurator का पहला लॉन्च](#43-configurator-का-पहला-लॉन्च)
- [5. RdpAudit.Service — निगरानी सेवा](#5-rdpauditservice--निगरानी-सेवा)
  - [5.1. इवेंट संग्रह](#51-इवेंट-संग्रह)
  - [5.2. ट्रैक किए जाने वाले Event ID](#52-ट्रैक-किए-जाने-वाले-event-id)
  - [5.3. डेटा संग्रहण (SQLite)](#53-डेटा-संग्रहण-sqlite)
  - [5.4. अलर्ट सिस्टम — 21 नियम](#54-अलर्ट-सिस्टम--21-नियम)
  - [5.5. Windows Firewall ऑटो-ब्लॉकिंग](#55-windows-firewall-ऑटो-ब्लॉकिंग)
  - [5.6. Named Pipe IPC](#56-named-pipe-ipc)
  - [5.7. विश्वसनीयता और स्थिरता](#57-विश्वसनीयता-और-स्थिरता)
  - [5.8. REST API (केवल पढ़ने के लिए)](#58-rest-api-केवल-पढ़ने-के-लिए)
- [6. RdpAudit.Configurator — GUI](#6-rdpauditconfigurator--gui)
  - [6.1. Overview टैब](#61-overview-टैब)
  - [6.2. Prerequisites टैब](#62-prerequisites-टैब)
  - [6.3. Audit Policy टैब](#63-audit-policy-टैब)
  - [6.4. Service टैब](#64-service-टैब)
  - [6.5. Settings टैब](#65-settings-टैब)
  - [6.6. Live Events टैब](#66-live-events-टैब)
  - [6.7. Firewall टैब](#67-firewall-टैब)
  - [6.8. Attack Statistics टैब](#68-attack-statistics-टैब)
  - [6.9. Remote RDP Clients टैब](#69-remote-rdp-clients-टैब)
  - [6.10. AbuseIPDB टैब](#610-abuseipdb-टैब)
  - [6.11. MikroTik टैब](#611-mikrotik-टैब)
  - [6.12. Logs टैब](#612-logs-टैब)
  - [6.13. Diagnostics टैब](#613-diagnostics-टैब)
- [6.14. Session Map टैब](#614-session-map-टैब)
- [6.15. Notifications टैब](#615-notifications-टैब)
- [6.16. Web Access टैब](#616-web-access-टैब)
- [7. RdpAudit.Core — साझा लाइब्रेरी](#7-rdpauditcore--साझा-लाइब्रेरी)
  - [7.1. डेटा मॉडल](#71-डेटा-मॉडल)
  - [7.2. Entity Framework Core और माइग्रेशन](#72-entity-framework-core-और-माइग्रेशन)
  - [7.3. IPC कॉन्ट्रैक्ट (MessagePack)](#73-ipc-कॉन्ट्रैक्ट-messagepack)
- [8. बाहरी इंटीग्रेशन](#8-बाहरी-इंटीग्रेशन)
  - [8.1. AbuseIPDB](#81-abuseipdb)
  - [8.2. MikroTik RouterOS v7](#82-mikrotik-routeros-v7)
- [9. ऑटो-ब्लॉकिंग मॉडल](#9-ऑटो-ब्लॉकिंग-मॉडल)
  - [9.1. ट्रिगर थ्रेशोल्ड](#91-ट्रिगर-थ्रेशोल्ड)
  - [9.2. स्थानीय Windows Firewall](#92-स्थानीय-windows-firewall)
  - [9.3. दूरस्थ MikroTik Firewall](#93-दूरस्थ-mikrotik-firewall)
  - [9.4. विश्वसनीय IP के लिए whitelist सुरक्षा](#94-विश्वसनीय-ip-के-लिए-whitelist-सुरक्षा)
- [10. डेटा रखरखाव](#10-डेटा-रखरखाव)
  - [10.1. Retention प्रूनिंग](#101-retention-प्रूनिंग)
  - [10.2. बैकअप और रिस्टोर](#102-बैकअप-और-रिस्टोर)
- [11. सुरक्षा और ऑडिटिंग](#11-सुरक्षा-और-ऑडिटिंग)
  - [11.1. एक्सेस कंट्रोल](#111-एक्सेस-कंट्रोल)
  - [11.2. SACL कॉन्फ़िगरेशन](#112-sacl-कॉन्फ़िगरेशन)
  - [11.3. सीक्रेट सुरक्षा (DPAPI)](#113-सीक्रेट-सुरक्षा-dpapi)
- [12. कॉन्फ़िगरेशन](#12-कॉन्फ़िगरेशन)
  - [12.1. appsettings.json](#121-appsettingsjson)
  - [12.2. एनवायरनमेंट वेरिएबल](#122-एनवायरनमेंट-वेरिएबल)
- [13. डिबगिंग और डायग्नोस्टिक्स](#13-डिबगिंग-और-डायग्नोस्टिक्स)
  - [13.1. कंसोल मोड](#131-कंसोल-मोड)
  - [13.2. Serilog लॉग](#132-serilog-लॉग)
  - [13.3. SQLite से सीधी पहुँच](#133-sqlite-से-सीधी-पहुँच)
  - [13.4. Diagnostics टैब](#134-diagnostics-टैब)
- [14. बिल्ड और टेस्ट](#14-बिल्ड-और-टेस्ट)
  - [14.1. बिल्ड](#141-बिल्ड)
  - [14.2. टेस्ट](#142-टेस्ट)
  - [14.3. पब्लिश](#143-पब्लिश)
- [15. समस्या-निवारण](#15-समस्या-निवारण)
- [16. रोडमैप (v2.0 → v3.0)](#16-रोडमैप-v20--v30)
- [17. लाइसेंस और लेखक](#17-लाइसेंस-और-लेखक)

---

## 1. उत्पाद अवलोकन

### 1.1. उद्देश्य

**RDPAudit** Windows सर्वर और वर्कस्टेशन पर RDP गतिविधि की निरंतर निगरानी के लिए बनाया गया है। उत्पाद सिस्टम सेवा के रूप में बैकग्राउंड में चलता है — तब भी जब कोई इंटरैक्टिव उपयोगकर्ता लॉग ऑन न हो — कनेक्शन प्रयास, ऑथेंटिकेशन इवेंट और महत्वपूर्ण सिस्टम बदलाव रिकॉर्ड करता है, उन्हें 21 सुरक्षा नियमों से मूल्यांकित करता है, और Windows Firewall और/या MikroTik RouterOS के ज़रिए हमलावरों को स्वचालित रूप से ब्लॉक कर सकता है।

**सामान्य उपयोग परिदृश्य:**
- इंटरनेट पर खुले RDP एंडपॉइंट को brute-force हमलों से बचाना
- विशेषाधिकार प्राप्त एक्सेस के लिए SOC2, ISO 27001 और आंतरिक ऑडिट आवश्यकताओं का समर्थन करना
- खाता समझौते के पैटर्न पकड़ना, जैसे बार-बार विफलता के बाद सफल लॉगॉन
- Sticky Keys और Utilman दुरुपयोग जैसे accessibility बाइनरी बैकडोर की पहचान करना
- LSA/LSASS पर हमलों, Kerberos spraying और RDP पोर्ट बदलावों का पता लगाना
- MikroTik के साथ इंटीग्रेशन, ताकि दुर्भावनापूर्ण IP नेटवर्क एज पर ब्लॉक हो सकें

### 1.2. समाधान आर्किटेक्चर

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

### 1.3. मुख्य क्षमताएँ

- **रीयल-टाइम निगरानी** — पोलिंग के बजाय `EventLogWatcher` सब्सक्रिप्शन के ज़रिए
- **21 अलर्ट नियम** — brute force, LSASS हमले, Kerberos spraying, संदिग्ध पॉलिसी बदलाव और अन्य शामिल
- **स्वचालित ब्लॉकिंग** — प्रति-IP Windows Firewall नियम, मैनुअल रिवर्सल समर्थन के साथ
- **MikroTik इंटीग्रेशन** — RouterOS v7 REST API के ज़रिए, DPAPI-सुरक्षित क्रेडेंशियल के साथ
- **AbuseIPDB रिपोर्टिंग** — स्थानीय डीडुप्लिकेशन और रेट-लिमिट का ध्यान रखते हुए
- **Threat-intel रेपुटेशन जाँच** (Backlog #5) - बैकग्राउंड में AbuseIPDB /api/v2/check लुकअप, डिस्क कैश और Attack Statistics व Live Events पर High-risk चिह्न के साथ
- **ख़तरा विश्लेषण** — IP, देश और समय-सीमा के अनुसार एकत्रित, और गणना किया गया threat level
- **सेशन-से-IP सहसंबंध** — RDP सेशन को स्रोत पतों से जोड़ने के लिए
- **Retention प्रूनिंग** — दीर्घकालिक स्थिरता और डेटाबेस वृद्धि में कमी के लिए
- **बैकअप और रिस्टोर** — कॉन्फ़िगरेशन स्थिति के लिए, बिना किसी plaintext सीक्रेट के
- **सुरक्षित Named Pipe IPC** — केवल `BUILTIN\Administrators` तक सीमित
- **केवल-पढ़ने योग्य HTTPS REST API** (वैकल्पिक, डिफ़ॉल्ट रूप से बंद) — bearer-token ऑथ, प्रति-IP रेट लिमिट और एक OpenAPI डिस्क्रिप्टर
- **SIEM एक्सपोर्ट** (CEF / LEEF 2.0 / NDJSON) — Live Events और Attack Statistics पेजों से प्रति-IP इवेंट और सहसंबद्ध अलर्ट

---

## 2. सिस्टम आवश्यकताएँ

### 2.1. न्यूनतम आवश्यकताएँ

| घटक | आवश्यकता |
|-----------|-------------|
| OS | Windows 10 या Windows Server 2016 और उससे नया (x64) |
| .NET Runtime | Windows के लिए .NET 8.0 (x64) |
| Privileges | सेवा इंस्टॉलेशन और सिस्टम कॉन्फ़िगरेशन के लिए Local Administrator |
| Disk | बाइनरी के लिए 200 MB, साथ में इवेंट डेटाबेस के लिए जगह |
| Memory | सामान्य लोड पर सेवा के लिए 64 MB working set |

### 2.2. Windows ऑडिटिंग आवश्यकताएँ

RDPAudit अपने द्वारा विश्लेषित इवेंट प्राप्त करने के लिए Windows Security Auditing पर निर्भर है। सही संचालन के लिए निम्नलिखित ऑडिट श्रेणियाँ सक्षम होनी चाहिए:

| ऑडिट श्रेणी | सबकैटेगरी GUID | उद्देश्य |
|----------------|------------------|---------|
| Logon / Logoff | `{0CCE9215-69AE-11D9-BED3-505054503030}` | इवेंट 4624, 4625, 4634 |
| Account Logon | `{0CCE9240-69AE-11D9-BED3-505054503030}` | Kerberos इवेंट |
| Process Creation | `{0CCE922B-69AE-11D9-BED3-505054503030}` | इवेंट 4688 और प्रोसेस दृश्यता |
| Object Access | `{0CCE9217-69AE-11D9-BED3-505054503030}` | SACL-आधारित इवेंट, जैसे 4656 और 4663 |
| Policy Change | `{0CCE922F-69AE-11D9-BED3-505054503030}` | Firewall और पॉलिसी बदलाव की दृश्यता |

Configurator इन सेटिंग्स को GUID-आधारित पहचानकर्ताओं के साथ `auditpol.exe` कॉल करके स्वचालित रूप से लागू करता है, जिससे प्रक्रिया लोकेल-स्वतंत्र रहती है।

---

## 3. समाधान की संरचना

### 3.1. प्रोजेक्ट और लेयर

| प्रोजेक्ट | प्रकार | ज़िम्मेदारी |
|--------|------|----------------|
| `RdpAudit.Core` | Class Library (`net8.0-windows`) | एंटिटी, EF Core `DbContext`, माइग्रेशन, MessagePack IPC कॉन्ट्रैक्ट, साझा हेल्पर |
| `RdpAudit.Service` | Worker Service (`net8.0-windows`, `win-x64`) | इवेंट संग्रह, नॉर्मलाइज़ेशन, अलर्ट मूल्यांकन, ऑटो-ब्लॉकिंग, IPC सर्वर |
| `RdpAudit.Configurator` | WinForms App (`net8.0-windows`) | GUI, IPC क्लाइंट, पूर्वापेक्षा जाँच, सेवा नियंत्रण, कॉन्फ़िगरेशन वर्कफ़्लो |
| `RdpAudit.Web` | ASP.NET Core App (`net8.0-windows`) | IIS-होस्टेड केवल-पढ़ने योग्य वेब डैशबोर्ड और loopback YARP प्रॉक्सी: DPAPI वॉल्ट से bearer इंजेक्शन, सुरक्षा हेडर, पिन किया हुआ बैकएंड TLS |
| `RdpAudit.Core.Tests` | xUnit | Core यूनिट टेस्ट |
| `RdpAudit.Service.Tests` | xUnit | अलर्ट नियम टेस्ट, थ्रेशोल्ड वैलिडेशन, whitelist कवरेज, allocation जाँच |
| `RdpAudit.Web.Tests` | xUnit | वेब प्रॉक्सी इंटीग्रेशन टेस्ट: host फ़िल्टर, bearer इंजेक्शन, स्थिर CSP/DOM कॉन्ट्रैक्ट |
| `RdpAudit.Benchmarks` | BenchmarkDotNet | हॉट पाथ के लिए बेंचमार्क कवरेज |

### 3.2. डायरेक्टरी संरचना

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

## 4. त्वरित शुरुआत

### 4.1. बिल्ड

```powershell
git clone https://github.com/paulmann/RDPAudit.git
cd RDPAudit
dotnet build RdpAudit.sln -c Release
```

### 4.2. सेवा इंस्टॉल करें

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

### 4.3. Configurator का पहला लॉन्च

```powershell
publish/Configurator/RdpAudit.Configurator.exe
```

पहले लॉन्च पर सुझाया गया क्रम यह है:

1. **Prerequisites** खोलें और आवश्यक चैनल तथा प्लेटफ़ॉर्म सेटिंग जाँचें।
2. **Audit Policy** खोलें और `auditpol.exe` के ज़रिए आवश्यक ऑडिट सबकैटेगरी लागू करें।
3. **Service** खोलें और Windows Service इंस्टॉल या शुरू करें।
4. **Settings** खोलें और अलर्ट थ्रेशोल्ड, विश्वसनीय IP, retention तथा इंटीग्रेशन समायोजित करें।

---

## 5. RdpAudit.Service — निगरानी सेवा

### 5.1. इवेंट संग्रह

सेवा प्रासंगिक इवेंट को रीयल-टाइम में सब्सक्राइब करने के लिए `System.Diagnostics.Eventing.Reader.EventLogWatcher` का उपयोग करती है। डिज़ाइन पहले से ही इवेंट सोर्स इंटरफ़ेस के पीछे अमूर्त है, इसलिए संग्रह बैकएंड को बाद में ETW-आधारित इनजेशन पर ले जाया जा सकता है, बिना पाइपलाइन का शेष भाग दोबारा लिखे।

**निगरानी किए जाने वाले चैनल:**
- `Security`
- `Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational`
- `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational`

### 5.2. ट्रैक किए जाने वाले Event ID

| Event ID | Channel | विवरण |
|----------|---------|-------------|
| 4624 | Security | सफल लॉगॉन, विशेष रूप से Logon Type 10 |
| 4625 | Security | विफल लॉगॉन |
| 4634 | Security | लॉगॉफ़ |
| 4647 | Security | उपयोगकर्ता-आरंभित लॉगॉफ़ |
| 4648 | Security | स्पष्ट क्रेडेंशियल के साथ लॉगॉन |
| 4688 | Security | प्रोसेस निर्माण |
| 4720 | Security | उपयोगकर्ता खाता बनाया गया |
| 4723 / 4724 | Security | पासवर्ड बदलाव / पासवर्ड रीसेट |
| 4740 | Security | खाता लॉकआउट |
| 4769 | Security | Kerberos सर्विस टिकट अनुरोध |
| 4771 | Security | Kerberos pre-authentication विफलता |
| 4776 | Security | NTLM ऑथेंटिकेशन |
| 4954 | Security | Windows Firewall नियम या पॉलिसी बदलाव |
| 1149 | TerminalServices-RCM | स्रोत IP के साथ RDP कनेक्शन |
| 21, 23, 24, 25 | TerminalServices-LSM | सेशन आरंभ, रीकनेक्ट, डिस्कनेक्ट, समाप्ति |

### 5.3. डेटा संग्रहण (SQLite)

डेटाबेस `%ProgramData%\RdpAudit\rdpaudit.db` में रखा जाता है।

**SQLite सेटिंग:**
```sql
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
```

**मुख्य टेबल:**

| टेबल | उद्देश्य |
|-------|---------|
| `RawEvents` | नॉर्मलाइज़्ड सुरक्षा और RDP इवेंट |
| `RdpConnectionFacts` | IP, उपयोगकर्ता और परिणाम के साथ कनेक्शन फ़ैक्ट |
| `AuthAttemptFacts` | ऑथेंटिकेशन प्रयास फ़ैक्ट |
| `Sessions` | RDP सेशन रिकॉर्ड |
| `SessionIpCorrelations` | सेशन-से-IP मैपिंग |
| `AttackStats` | स्रोत के अनुसार एकत्रित हमला आँकड़े |
| `ActiveBlocks` | वर्तमान में सक्रिय स्वचालित ब्लॉक |
| `Alerts` | अलर्ट इतिहास |
| `WhitelistEntries` | विश्वसनीय IP और CIDR प्रविष्टियाँ |
| `BlocklistEntries` | स्थायी ब्लॉक नियम और स्रोत |
| `AbuseIpDbReportHistory` | AbuseIPDB रिपोर्ट इतिहास |
| `OperationLogs` | GUI में दिखने वाली ऑपरेशनल लॉग प्रविष्टियाँ |
| `DbProps` | की-वैल्यू मेटाडेटा स्टोर |
| `Bookmarks` | इवेंट प्रोसेसिंग के लिए क्रैश-रिकवरी बुकमार्क |
| `LoginRules` | कार्य-घंटे और लॉगॉन पॉलिसी नियम |

**राइट रणनीति:** हॉट पाथ स्पष्ट ट्रांज़ैक्शन और बैचेड राइट के साथ कच्चे `SqliteCommand` का उपयोग करता है।

**बुकमार्क टिकाऊपन:** बुकमार्क हर 100 इवेंट पर और हर 30 सेकंड में फ्लश होते हैं, जिससे क्रैश या बिजली जाने के बाद नुक़सान न्यूनतम रहता है।

### 5.4. अलर्ट सिस्टम — 21 नियम

हर नियम एक समर्पित अलर्ट इवैल्यूएटर के रूप में लागू है और एक साझा नियम पाइपलाइन में भाग लेता है।

| # | Rule ID | गंभीरता | विवरण |
|---|---------|----------|-------------|
| 1 | `BRUTE_FORCE` | उच्च | एक ही स्रोत से विफल लॉगॉन थ्रेशोल्ड पार करते हैं |
| 2 | `BRUTE_FORCE_NTLM` | उच्च | कूलडाउन लॉजिक के साथ NTLM brute-force |
| 3 | `KERBEROS_SPRAY` | उच्च | Kerberos पासवर्ड spraying व्यवहार |
| 4 | `SUCCESSFUL_AFTER_FAILS` | मध्यम | बार-बार विफलता के बाद सफल लॉगॉन |
| 5 | `OFF_HOURS_LOGIN` | मध्यम | स्वीकृत कार्य-घंटों के बाहर लॉगॉन |
| 6 | `ACCOUNT_LOCKOUT` | मध्यम | खाता लॉकआउट इवेंट |
| 7 | `NEW_ACCOUNT_CREATED` | मध्यम | नया स्थानीय या डोमेन खाता बना |
| 8 | `PASSWORD_RESET` | निम्न | पासवर्ड रीसेट या पासवर्ड बदलाव |
| 9 | `MULTIPLE_ACCOUNTS_SAME_IP` | उच्च | एक स्रोत IP से उपयोगकर्ता नाम spraying |
| 10 | `STICKY_KEYS_BACKDOOR` | क्रिटिकल | Accessibility-बाइनरी बैकडोर व्यवहार |
| 11 | `LSASS_ACCESS` | क्रिटिकल | LSASS तक संदिग्ध हैंडल एक्सेस |
| 12 | `LSASS_PPL_TAMPER` | क्रिटिकल | LSASS PPL सुरक्षा कमज़ोर करने का प्रयास |
| 13 | `RDP_PORT_CHANGED` | उच्च | रजिस्ट्री-आधारित RDP पोर्ट बदलाव मिला |
| 14 | `FIREWALL_RULE_CHANGED` | मध्यम | Firewall नियम या पॉलिसी बदली गई |
| 15 | `EXPLICIT_CREDENTIALS` | मध्यम | स्पष्ट क्रेडेंशियल उपयोग का पैटर्न |
| 16 | `LOGON_TYPE_NETWORK` | निम्न | संरक्षित सिस्टम पर नेटवर्क लॉगॉन |
| 17 | `CONCURRENT_SESSIONS` | निम्न | अत्यधिक समवर्ती सेशन संख्या |
| 18 | `GEO_ANOMALY` | मध्यम | अनुमत या अपेक्षित के बाहर के भूगोल से लॉगॉन |
| 19 | `IP_REPUTATION` | उच्च | स्रोत IP ज्ञात ब्लॉकलिस्ट में दिखता है |
| 20 | `SESSION_HIJACK_SUSPECT` | उच्च | सेशन सहसंबंध में विसंगति |
| 21 | `RAPID_RECONNECT` | मध्यम | एक ही IP से बार-बार रीकनेक्ट गतिविधि |

### 5.4.1. PRIVILEGED_LOGIN हार्डनिंग

`PRIVILEGED_LOGIN` नियम (Event 4672 - लॉगॉन पर दिए गए SeDebug / SeTcb) को सेवा-आरंभ के well-known-SID तूफ़ान (स्रोत IP के बिना एक जैसे SYSTEM अलर्ट) के विरुद्ध कठोर बनाया गया है:

- **सटीक SID फ़िल्टर** - `S-1-5-18` (SYSTEM), `S-1-5-19` (LOCAL SERVICE) और `S-1-5-20` (NETWORK SERVICE) को नॉर्मलाइज़्ड `Details` JSON (`subjectUserSid`) से पढ़े गए सटीक SID द्वारा अस्वीकार किया जाता है, स्थानीयकृत खाता नामों से कभी नहीं।
- **नेटवर्क संदर्भ अनिवार्य** - इवेंट में खाली न होने वाला `SourceIp` और नेटवर्क लॉगॉन प्रकार (3 / 7 / 10) होना चाहिए। `LogonType` न होने पर (Windows 4672 का अपना ऐसा फ़ील्ड नहीं है) `SubjectLogonId == TargetLogonId` के ज़रिए मिलते Security 4624 से सहसंबंध पर वापस जाया जाता है।
- **सप्रेशन विंडो** - प्रति (उपयोगकर्ता, स्रोत ip, लॉगॉन प्रकार) एक जैसे ट्रिगर `PrivilegedLoginSuppressionWindowMinutes` (डिफ़ॉल्ट 5) के भीतर दबा दिए जाते हैं; विंडो समाप्त होने पर एक ही सारांश अलर्ट दबाई गई संख्या लेकर आता है।
- **प्रति-मिनट अलर्ट बजट** - `PrivilegedLoginRateLimitPerMinute` (डिफ़ॉल्ट 20) आउटपुट को सीमित करता है; थ्रॉटलिंग प्रति मिनट एक बार लॉग होती है।
- **ऐतिहासिक आयु गेट** - `AlertEventMaxAgeMinutes` (डिफ़ॉल्ट 5) से पुराने इवेंट `RawEvent` फ़ैक्ट के रूप में सहेजे तो जाते हैं, पर कभी अलर्ट नहीं देते (`AlertWorker` इसे सभी नियमों पर लागू करता है)।
- **शून्य-एलोकेशन अस्वीकृति पथ** - `EvaluateAsync` एक non-async मेथड है जो कैश्ड null-task सिंगलटन लौटाता है, इसलिए अस्वीकृत मूल्यांकन कुछ भी एलोकेट नहीं करते।

### 5.5. Windows Firewall ऑटो-ब्लॉकिंग

जब `BRUTE_FORCE`, `BRUTE_FORCE_NTLM` या `IP_REPUTATION` जैसे नियम ट्रिगर होते हैं, तो सेवा प्रति-IP इनबाउंड ब्लॉक नियम बना सकती है।

```powershell
netsh advfirewall firewall add rule `
  name="RdpAudit_Block_<IP>" `
  dir=in action=block remoteip=<IP> `
  protocol=any enable=yes
```

**कार्यान्वयन विशेषताएँ:**
- इडेम्पोटेंट नियम निर्माण
- शेल निष्पादन से पहले इनपुट सैनिटाइज़ेशन
- GUI से मैनुअल हटाना
- `ActiveBlocks` और `OperationLogs` के ज़रिए पूरा ऑडिट

### 5.6. Named Pipe IPC

**Pipe नाम:** `\\.\pipe\RdpAuditService`

**सुरक्षा मॉडल:** केवल `BUILTIN\Administrators` को कनेक्ट करने की अनुमति है।

**प्रोटोकॉल:** `RdpAudit.Core` में परिभाषित MessagePack रिक्वेस्ट और रिस्पॉन्स कॉन्ट्रैक्ट।

**ऑपरेशनल नोट:**
- GUI सेवा के स्वामित्व वाली कॉन्फ़िगरेशन फ़ाइलें कभी सीधे नहीं लिखता।
- सेटिंग IPC पर भेजी जाती हैं और सेवा उन्हें परमाणु रूप से कमिट करती है।
- कनेक्शन समय-सीमाएँ Configurator को अनिश्चित काल तक अटकने से रोकती हैं।
- पाइप `IpcServerWorker` द्वारा परोसा जाता है, जो `MaxConcurrent + 1` OS इंस्टेंस माँगता है, ताकि हमेशा सुनने वाला स्टैंडबाय पाइप किसी जुड़े हैंडलर से कभी न टकराए। Win32 `ERROR_PIPE_BUSY` (231) को "instance cap reached" के रूप में वर्गीकृत किया जाता है, AV/EDR इंटरसेप्शन के रूप में नहीं; हैंडलर पूरे होने पर saturation स्वयं ख़त्म हो जाती है।
- हर worker इंस्टेंस `%ProgramData%\RdpAudit\logs\ipc-startup.log` में देखने योग्य लाइफ़साइकल फ़ैक्ट लिखता है: `instance constructed` / `ExecuteAsync entered` / `ExecuteAsync exiting (pid, instanceId, entryCount, exitCount, iteration, activeHandlers, livePipes, stoppingTokenCancelled, hostApplicationStoppingCancelled, exitReason, lifetimeMs)`। ये फ़ील्ड साबित करते हैं कि किसी एक प्रोसेस में कभी एक से अधिक worker या host इंस्टेंस चले या नहीं।

### 5.7. विश्वसनीयता और स्थिरता

- `SQLITE_BUSY` जैसे अस्थायी डेटाबेस विवाद के लिए एक्सपोनेंशियल बैकऑफ़
- async प्रवाहों में एंड-टू-एंड `CancellationToken` प्रसार
- हर होस्टेड worker `TimedHostedService` में लिपटा है और `startup-sequence.log` में begin/end/failure चिह्न लिखता है
- `IpcServerWorker` प्रति-इंस्टेंस लाइफ़साइकल ब्रेडक्रम्ब लॉग करता है, ताकि एक ही PID में दोहराया गया `ExecuteAsync entered` एक या कई worker/host इंस्टेंस को आरोपित किया जा सके
- सेवा रोकने पर सुगम शटडाउन
- स्टार्टअप पर EF Core माइग्रेशन लागू
- इंस्टॉलेशन के दौरान Event Log स्रोत पंजीकरण

### 5.8. REST API (केवल पढ़ने के लिए)

सेवा मॉनिटरिंग एजेंट और स्क्रिप्ट के लिए एक **वैकल्पिक केवल-पढ़ने योग्य HTTPS REST API** (Kestrel, डिफ़ॉल्ट रूप से
बंद) उजागर कर सकती है। यह केवल `GET`/`HEAD` का जवाब देती है और named pipe के समान
ऑडिट किए गए रीड कमांड का पुनरुपयोग करती है, इसलिए REST सतह पर कोई राइट पथ नहीं है।

- **एंडपॉइंट**: `/healthz` (अनॉनिमस), `/api/status`, `/api/alerts`, `/api/sessions`,
  `/api/addresses`, `/api/attacks`, `/api/config` (सीक्रेट मास्क किए गए),
  `/api/events` (सीमित, फ़िल्टर किया गया, क्रमबद्ध पेज) और
  `/openapi/v1.json` (कमिट किया गया OpenAPI 3.0 डिस्क्रिप्टर)।
- **ऑथेंटिकेशन**: स्थिर bearer टोकन (`Api.Token`, DPAPI-सुरक्षित), 401 पर
  `WWW-Authenticate: Bearer realm="rdpaudit"` के साथ।
- **ट्रांसपोर्ट**: केवल HTTPS। लिसनर डिफ़ॉल्ट रूप से `127.0.0.1:8443`; `LocalMachine\My` में
  मौजूद TLS सर्टिफ़िकेट `Api.CertificateThumbprint` / `Api.CertificateSubject` से चुना जाता है।
  Non-loopback लिसनर स्टार्टअप पर ख़तरे की स्पष्ट चेतावनी लॉग करते हैं।
- **हार्डनिंग**: प्रति-IP फ़िक्स्ड-विंडो रेट लिमिट (`Api.RateLimitPerMinute`),
  कनेक्शन कैप (`Api.MaxConnections`), सुरक्षा हेडर, और हर non-200 उत्तर के लिए RFC 9457
  `problem+json` त्रुटि बॉडी।
- **फ़ेल-क्लोज़्ड स्टार्टअप**: `Api.Enabled=false` (डिफ़ॉल्ट) या कोई भी अनुपलब्ध पूर्वापेक्षा
  (टोकन/सर्टिफ़िकेट/पता) का अर्थ है कोई लिसनर नहीं।

कॉन्फ़िगरेशन `appsettings.json` के `Api` सेक्शन में है। पूर्ण संदर्भ:
`docs/40-options.md` (ApiOptions) और `docs/51-rest-api.md` (एंडपॉइंट, त्रुटियाँ,
ऑथेंटिकेशन, ऑपरेशन)।

---

## 6. RdpAudit.Configurator — GUI

Configurator एलिवेटेड रूप में चलता है और सेवा से केवल Named Pipe IPC चैनल के ज़रिए संवाद करता है।

### 6.1. Overview टैब

**Overview** टैब ऑपरेटर डैशबोर्ड है। यह सेवा की स्थिति, वर्तमान ब्लॉक संख्याएँ, हाल के अलर्ट और हाल का इवेंट वॉल्यूम सारांशित करता है।

### 6.2. Prerequisites टैब

**Prerequisites** टैब आवश्यक Windows शर्तें जाँचता है:
- सभी सात निगरानी किए जाने वाले इवेंट-लॉग चैनल मौजूद और सक्षम (Security, System, और
  Terminal Services / RDP चैनल)
- आवश्यक ऑडिट-पॉलिसी सबकैटेगरी लागू (object access + पाँच-सबकैटेगरी
  बेसलाइन)
- सेवा इंस्टॉल और पहुँच योग्य

अक्षम चैनल के लिए `wevtutil sl /enabled:true` फ़िक्स दिया जाता है। इस Windows बिल्ड/SKU पर जो चैनल
मौजूद ही नहीं (उदाहरण के लिए RD Gateway भूमिका के बिना होस्ट पर `TerminalServices-Gateway`), वह
बिना किसी स्वचालित फ़िक्स के अनुपलब्ध बताया जाता है, इसलिए टैब ऐसे चैनल के लिए कभी एनेबल बटन
नहीं देता जिसे यह Windows संस्करण बना ही नहीं सकता। हर ठीक हो सकने वाली विफलता
UI से सीधे लागू की जा सकती है।

### 6.3. Audit Policy टैब

**Audit Policy** टैब वर्तमान Windows ऑडिट कॉन्फ़िगरेशन पढ़ता है और GUID-आधारित `auditpol.exe` कॉल के ज़रिए आवश्यक सबकैटेगरी लागू करता है। यह RDP दुरुपयोग पहचान से जुड़े मूल्यवान रजिस्ट्री स्थानों और IFEO पथों के लिए SACL सेटअप भी संभालता है।

### 6.4. Service टैब

**Service** टैब समर्थन देता है:
- इंस्टॉल और अनइंस्टॉल
- स्टार्ट, स्टॉप, रीस्टार्ट
- सेवा स्थिति प्रदर्शन
- स्टार्टअप मोड नियंत्रण

### 6.5. Settings टैब

**Settings** टैब ऑपरेशनल कॉन्फ़िगरेशन दिखाता है, जिनमें शामिल हैं:
- अलर्ट थ्रेशोल्ड
- Brute-force विंडो
- कार्य-घंटे की परिभाषाएँ
- डेटा retention विंडो
- AbuseIPDB सेटिंग
- MikroTik सेटिंग
- Geolocation और whitelist सेटिंग

बदलाव IPC पर भेजे जाते हैं और सेवा उन्हें परमाणु रूप से लागू करती है।

### 6.6. Live Events टैब

**Live Events** टैब रीयल-टाइम इवेंट की tail-शैली स्ट्रीम देता है, जिसमें विफलताओं, चेतावनियों और सफल गतिविधि के लिए रंग-कोडिंग है। यह Event ID और स्रोत IP के अनुसार फ़िल्टरिंग समर्थित करता है। एक **High risk** कॉलम हर स्रोत IP के लिए कैश्ड threat-intel चिह्न (Stage 15) दिखाता है।

### 6.7. Firewall टैब

**Firewall** टैब `ActiveBlocks` से सक्रिय ब्लॉक दिखाता है और समर्थन देता है:
- ब्लॉक किए गए IP, कारण और प्रोवाइडर देखना
- मैनुअल रूप से ब्लॉक प्रविष्टियाँ जोड़ना
- पुष्टि के साथ ब्लॉक हटाना
- ब्लॉकलिस्ट आयात या निर्यात करना

### 6.8. Attack Statistics टैब

**Attack Statistics** टैब एकत्रित हमला डेटा प्रस्तुत करता है:
- सबसे अधिक हमला करने वाले IP
- Threat level स्कोरिंग
- समय-आधारित चार्ट
- देश-स्तरीय समूहन
- CSV निर्यात समर्थन
- कैश्ड threat-intel चिह्न (Stage 15) पर आधारित **High risk** कॉलम

Threat level की गणना `AttackThreatScoring` में स्कोरिंग लॉजिक से होती है।

### 6.9. Remote RDP Clients टैब

**Remote RDP Clients** टैब स्रोत IP, कनेक्शन संख्या, उपयोगकर्ता नाम और ऐतिहासिक RDP सेशन का सहसंबंध बनाता है। इसका उद्देश्य वैध दूरस्थ प्रशासन को शोर भरे हमला ट्रैफ़िक से अलग करना है।

### 6.10. AbuseIPDB टैब

**AbuseIPDB** टैब प्रबंधित करता है:
- API कुंजी कॉन्फ़िगरेशन
- मैनुअल और स्वचालित रिपोर्ट वर्कफ़्लो
- डीडुप्लिकेशन के साथ रिपोर्ट इतिहास
- रेट-लिमिट का ध्यान रखने वाली स्थिति और वैलिडेशन
- Threat-intel रेपुटेशन जाँच (/api/v2/check) — कैश स्थिति, दैनिक उपयोग और High-risk थ्रेशोल्ड (Backlog #5)

सीक्रेट कभी plaintext में वापस प्रदर्शित नहीं होते।

### 6.11. MikroTik टैब

**MikroTik** टैब RouterOS v7 REST इंटीग्रेशन कॉन्फ़िगर करता है:
- राउटर पता और पोर्ट
- DPAPI-सुरक्षित क्रेडेंशियल
- TLS वैलिडेशन व्यवहार
- Address-list सिंक्रोनाइज़ेशन
- कनेक्टिविटी परीक्षण

### 6.12. Logs टैब

**Logs** टैब `OperationLogs` से ऑपरेशनल प्रविष्टियाँ गंभीरता के अनुसार समूहित करके दिखाता है:
- `Info`
- `Warning`
- `Error`
- `Critical`

### 6.13. Diagnostics टैब

**Diagnostics** टैब ऑपरेटर के लिए स्वास्थ्य डेटा देता है:
- Worker स्थिति
- IPC स्वास्थ्य
- डेटाबेस आकार और स्थिति
- इंटीग्रेशन जाँच
- डायग्नोस्टिक निर्यात समर्थन

### 6.14. Session Map टैब

**Session Map** टैब SOC ऑपरेटर को एक ऐतिहासिक RDP सेशन को कालानुक्रमिक
टाइमलाइन के रूप में देखने देता है (Backlog #6)। सीमित सेशन सूची (जो मौजूदा
`ListConnectionFacts` कमांड से IP / User फ़िल्टर के साथ परोसी जाती है) से कोई
फ़ैक्ट चुनने पर `GetSessionTimeline` उत्तर लोड होता है और दो रूपों में दिखता है:

- **इवेंट टेबल** - समय, प्रकार (logon start / connected / reconnected /
  disconnected / logoff / process / file / other), इवेंट id, प्रोसेस, ऑब्जेक्ट
  और स्पष्ट सहसंबंध विधि। `UserWindow`-सहसंबद्ध पंक्तियाँ एम्बर रंग में दिखती हैं,
  ताकि कम फ़ॉरेंसिक विश्वास हमेशा दिखे; कच्चा DEBUG विस्तृत टेक्स्ट केवल तब
  टूलटिप में मिलता है जब सेवा DEBUG मोड में चल रही हो।
- **Gantt पैनल** - अंतर्निहित GDI+ टाइमलाइन, UTC समय अक्ष के साथ,
  रंग-कोडित लेन, लेजेंड, सक्रिय सेशन के लिए बिंदुदार "now" बीम और
  `TRUNCATED` बैज जब सर्वर-साइड गतिविधि कैप (50..2000, डिफ़ॉल्ट 500)
  लग जाए।

कमांड पूरी तरह केवल-पढ़ने योग्य है और कोई टेबल या माइग्रेशन नहीं जोड़ती; कॉन्ट्रैक्ट, सहसंबंध नियम,
ख़तरा मॉडल और रोलबैक मार्गदर्शन के लिए `docs/54-session-map.md` देखें।

### 6.15. Notifications टैब

**Notifications** टैब एलिवेटेड `RdpAudit.Notifier` ट्रे ऐप कॉन्फ़िगर करता है:

- **Enable tray notifier** - मास्टर स्विच; बंद होने पर notifier चुपचाप बाहर निकल जाता है।
- **Start with Windows** - `schtasks` (`ONLOGON`, `/RL HIGHEST`) के ज़रिए `RdpAudit.Notifier` लॉगॉन टास्क पंजीकृत / हटाता है।
- **Poll interval** - सेवा पोलिंग की गति सेकंड में (1..60 तक सीमित)।
- **Minimum severity** - इस गंभीरता से नीचे के अलर्ट कभी नहीं दिखाए जाते।
- **Max toasts per minute** - स्लाइडिंग-विंडो रेट कैप (1..60 तक सीमित); अतिरिक्त अलर्ट एक सारांश टोस्ट में सिमट जाते हैं।
- **Use native toasts** - ट्रे बैलून टिप्स के बजाय WinRT टोस्ट को प्राथमिकता; नेटिव चैनल उपलब्ध न होने पर notifier बैलून पर वापस आ जाता है।
- **Alerts / Events उप-टैब** - प्रति-नियम और प्रति-इवेंट दृश्यता मैप।

Save / Refresh IPC कमांड `GetNotificationSettings` (78) और
`SaveNotificationSettings` (79) से गुज़रते हैं; सेवा मानों को सीमित करती है, गंभीरता को
`High` पर वापस लाती है और `appsettings.json` का केवल `RdpAudit.Notifications` सेक्शन
सहेजती है। Notifier named pipe पर सेवा को पोल करता है,
अपहुँच होने पर सुरक्षित अंतराल पर आ जाता है, और डेटाबेस को कभी नहीं बदलता।

---

### 6.16. Web Access टैब

**Web Access** टैब (**Service** के ठीक बाद रखा गया) केवल-पढ़ने योग्य IIS-होस्टेड वेब डैशबोर्ड का
प्रवेश बिंदु है। यह **privacy-first** है: जब तक ऑपरेटर स्पष्ट रूप से सहमति न दे, सब कुछ
बंद रहता है।

- **Show Web Access** - ऑपरेटर की दृश्यता पसंद सहेजता है; डिफ़ॉल्ट रूप से बंद
  और केवल तभी संग्रहीत होता है जब ऑपरेटर इसे टॉगल करता है।
- **Allow management from the web** - चरण-आधारित: दिखता है पर तब तक लॉक रहता है जब तक
  बाद का प्रबंधन चरण इसे खोल न दे; संग्रहीत पसंद उस गेट खुलने से पहले कभी
  true नहीं हो सकती।
- **Refresh status** - fail-closed IIS प्रोब दोबारा चलाता है (रजिस्ट्री `InetStp`,
  केवल-पढ़ने योग्य `dism /English /Online /Get-FeatureInfo`, W3SVC सेवा जाँच) और
  एक पंक्ति का निर्णय दिखाता है।
- **Install IIS** - `IisInstallPlan` द्वारा संचालित मार्गदर्शित, इडेम्पोटेंट इंस्टॉलेशन, जो
  प्री-रन चेकलिस्ट और निष्पादित वर्कफ़्लो दोनों के लिए एकमात्र सत्य-स्रोत है।
  प्रगति विंडो कुछ भी चलने से पहले हर मद सूचीबद्ध करती है और प्रति मद टिक या
  क्रॉस दिखाती है: elevation, स्थिर DISM फ़ीचर सेट (`IIS-WebServerRole`,
  `IIS-WebServer`, `IIS-StaticContent`, `IIS-DefaultDocument`, `IIS-HttpErrors` —
  `dism ... /NoRestart` के ज़रिए), IIS प्रबंधन टूल (`IIS-WebServerManagementTools`,
  `IIS-ManagementScriptingTools`, जो Configure IIS द्वारा उपयोग किया जाने वाला `appcmd.exe` देते हैं),
  `winget install --id Microsoft.DotNet.HostingBundle.8 --exact` से इंस्टॉल किया गया
  ASP.NET Core Hosting Bundle — नेटिव `AspNetCoreModuleV2` का एकमात्र स्रोत — और
  अंत में मशीन पर वास्तव में क्या है इसकी पुष्टि। बंडल चरण छोड़ दिया जाता है जब मॉड्यूल
  पहले से मौजूद हो, इसलिए एक ही मशीन के लिए winget दोबारा कभी नहीं बुलाया जाता, और DISM एग्ज़िट कोड 3010
  रीस्टार्ट माँगने वाली चेतावनी के रूप में बताया जाता है - सफलता के रूप में कभी नहीं।
- **Configure IIS** - `RdpAuditWebUi` साइट का मार्गदर्शित सेटअप: इसके लिए
  elevation और ASP.NET Core Module v2 (Hosting Bundle) आवश्यक हैं, loopback HTTPS सर्टिफ़िकेट
  खोजा या बनाया जाता है, वेब टोकन केवल सेवा `appsettings.json` में DPAPI-सुरक्षित
  envelope के रूप में संग्रहीत होता है, RdpAudit.Web पेलोड `%ProgramData%\RdpAudit\WebUI`
  में तैयार किया जाता है, साइट `https://127.0.0.1:443` पर बाइंड होती है और सेवा रीस्टार्ट होती है।

दोनों वर्कफ़्लो बटन तब तक अक्षम रहते हैं जब तक प्रोब IIS स्थिति वास्तव में घोषित न कर सके।
ब्राउज़र bearer टोकन कभी नहीं देखता: प्रोसेस के भीतर का YARP प्रॉक्सी उसे
मशीन-स्कोप DPAPI वॉल्ट से इंजेक्ट करता है और ब्राउज़र द्वारा भेजा गया कोई भी
`Authorization` हेडर हटा देता है; Host फ़िल्टर इसके अतिरिक्त गैर-loopback होस्ट
नाम अस्वीकार करता है (DNS-rebinding सुरक्षा)।

## 7. RdpAudit.Core — साझा लाइब्रेरी

### 7.1. डेटा मॉडल

मुख्य एंटिटी में शामिल हैं:

| प्रकार | विवरण |
|------|-------------|
| `RdpConnectionFact` | RDP कनेक्शन फ़ैक्ट रिकॉर्ड |
| `AuthAttemptFact` | ऑथेंटिकेशन प्रयास फ़ैक्ट |
| `Session` | RDP सेशन मेटाडेटा |
| `SessionIpCorrelation` | सेशन-से-IP मैपिंग |
| `AttackStat` | एकत्रित हमला मेट्रिक्स |
| `AttackThreatLevel` | Threat level enum |
| `AttackThreatScoring` | Threat स्कोरिंग लॉजिक |
| `AttackStatProjection` | UI के लिए हमला आँकड़ों का प्रोजेक्शन |
| `ActiveBlock` | सक्रिय ब्लॉक रिकॉर्ड |
| `BlocklistEntry` | स्थायी ब्लॉकलिस्ट प्रविष्टि |
| `WhitelistEntry` | विश्वसनीय IP या CIDR प्रविष्टि |
| `Alert` | अलर्ट रिकॉर्ड |
| `AbuseReport` | AbuseIPDB रिपोर्ट पेलोड |
| `AbuseIpDbReportHistory` | रिपोर्ट इतिहास और डीडुप्लिकेशन |
| `RawEvent` | नॉर्मलाइज़्ड कच्चा इवेंट रिकॉर्ड |
| `OperationLog` | सेवा ऑपरेशन लॉग रिकॉर्ड |
| `LoginRule` | समय-आधारित एक्सेस नियम |
| `Bookmark` | इवेंट प्रोसेसिंग बुकमार्क |
| `DbProp` | की-वैल्यू मेटाडेटा रिकॉर्ड |
| `ThreatIntelLookup` | प्रति IP कैश्ड /api/v2/check रेपुटेशन स्नैपशॉट (Stage 15) |
| `ThreatIntelUsageCounter` | सहेजा गया दैनिक /check उपयोग बजट काउंटर (Stage 15) |
| `Address` | IP पता और संबंधित मेटाडेटा |

### 7.2. Entity Framework Core और माइग्रेशन

- SQLite के साथ EF Core 8
- स्कीमा स्वामित्व और क्वेरी समर्थन के लिए `AppDbContext`
- सेवा स्टार्टअप पर स्वचालित माइग्रेशन लागू
- EF Core कॉन्फ़िगरेशन, माइग्रेशन और UI रीड के लिए आरक्षित
- हॉट-पाथ राइट कच्चे SQLite कमांड और स्पष्ट ट्रांज़ैक्शन से निपटाए जाते हैं

### 7.3. IPC कॉन्ट्रैक्ट (MessagePack)

IPC रिक्वेस्ट और रिस्पॉन्स **MessagePack** से सीरियलाइज़ होते हैं। प्रतिनिधि कॉन्ट्रैक्ट में शामिल हैं:
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

## 8. बाहरी इंटीग्रेशन

### 8.1. AbuseIPDB

RDPAudit brute-force या उच्च-विश्वास वाले दुर्भावनापूर्ण व्यवहार का पता चलने पर हमला करने वाले IP की रिपोर्ट [AbuseIPDB](https://www.abuseipdb.com/) को कर सकता है।

**डिज़ाइन नोट:**
- API कुंजियाँ DPAPI-सुरक्षित मानों के रूप में संग्रहीत होती हैं
- डुप्लिकेट रिपोर्ट स्थानीय इतिहास से दबा दी जाती हैं
- रेट लिमिट का पालन होता है
- रिपोर्ट श्रेणियाँ कॉन्फ़िगर करने योग्य हैं

RDPAudit पढ़ते समय IP रेपुटेशन भी देख सकता है: opt-in threat-intel फ़ीचर
(`AbuseIpDb.CheckEnabled`) बैकग्राउंड worker के ज़रिए GET /api/v2/check चलाता है,
सार्वजनिक हमला-स्रोत IP के लिए डिस्क कैश गर्म करता है, और
Attack Statistics तथा Live Events ग्रिड पर High-risk चिह्न दिखाता है। API कुंजी केवल
`Key` हेडर में भेजी जाती है और कभी लॉग नहीं होती।

### 8.2. MikroTik RouterOS v7

RDPAudit RouterOS v7 REST API के ज़रिए दुर्भावनापूर्ण IP को MikroTik address list में भेज सकता है।

**डिज़ाइन नोट:**
- HTTPS REST एंडपॉइंट पर काम करता है
- कॉन्फ़िगर करने योग्य TLS वैलिडेशन समर्थित
- क्रेडेंशियल DPAPI सुरक्षा के ज़रिए संग्रहीत
- address-list में डुप्लिकेट प्रविष्टियों से बचता है
- राउटर अनुपलब्ध होने पर सुगमता से वापस आ जाता है

---

## 9. ऑटो-ब्लॉकिंग मॉडल

### 9.1. ट्रिगर थ्रेशोल्ड

डिफ़ॉल्ट व्यवहार:
- एक ही IP से **10 विफल लॉगॉन** **10 मिनट** के भीतर ब्लॉक ट्रिगर करते हैं
- थ्रेशोल्ड **Settings** से कॉन्फ़िगर करने योग्य हैं
- ब्लॉक लगाने से पहले whitelist किए गए स्रोत बाहर कर दिए जाते हैं

### 9.2. स्थानीय Windows Firewall

```text
Provider: WindowsFirewallProvider
Action:   Create inbound rule "RdpAudit_Block_<IP>" (block, any protocol)
Reverse:  Remove rule by name
Verify:   netsh advfirewall firewall show rule name="RdpAudit_Block_<IP>"
```

### 9.3. दूरस्थ MikroTik Firewall

```text
Provider: MikroTikFirewallProvider
Action:   PUT /rest/ip/firewall/address-list { address: <IP>, list: "RdpAudit-Blocklist" }
Reverse:  DELETE /rest/ip/firewall/address-list/<id>
Verify:   GET /rest/ip/firewall/address-list?address=<IP>
```

### 9.4. विश्वसनीय IP के लिए whitelist सुरक्षा

- एकल IP और CIDR रेंज समर्थित
- कोई भी ब्लॉक बनने से पहले मूल्यांकन होता है
- GUI से प्रबंधित
- ऑडिट-अनुकूल मेटाडेटा के साथ `WhitelistEntries` में संग्रहीत

---

## 10. डेटा रखरखाव

### 10.1. Retention प्रूनिंग

एक प्रूनिंग worker समय-समय पर पुराने रिकॉर्ड हटाता है।

| टेबल | डिफ़ॉल्ट retention | कॉन्फ़िगर करने योग्य |
|-------|-------------------|-------------|
| `RawEvents` | 90 दिन | हाँ |
| `Alerts` | 180 दिन | हाँ |
| `AbuseIpDbReportHistory` | 365 दिन | हाँ |
| `ActiveBlocks` (निष्क्रिय) | 30 दिन | हाँ |
| `AttackStats` | 365 दिन | हाँ |

**कार्यान्वयन नोट:**
- बैचेड डिलीट
- `SQLITE_BUSY` पर एक्सपोनेंशियल बैकऑफ़
- कैंसिलेशन समर्थन
- ऑपरेशन लॉगिंग

### 10.2. बैकअप और रिस्टोर

बैकअप वर्कफ़्लो कॉन्फ़िगरेशन स्थिति लेता है, इवेंट डेटाबेस नहीं।

**बैकअप में शामिल:**
- केवल DPAPI envelope के साथ `appsettings.json`
- ऑडिट पॉलिसी निर्यात
- संबंधित रजिस्ट्री कुंजियाँ
- सेवा कॉन्फ़िगरेशन मेटाडेटा

**शामिल नहीं:**
- `rdpaudit.db`

किसी भी रिस्टोर ऑपरेशन से पहले प्री-रिस्टोर सुरक्षा स्नैपशॉट बनाया जाता है।

---

## 11. सुरक्षा और ऑडिटिंग

### 11.1. एक्सेस कंट्रोल

| घटक | एक्सेस मॉडल |
|-----------|--------------|
| `RdpAudit.Service` | `SYSTEM` या समर्पित सेवा पहचान के रूप में चलती है |
| Named Pipe IPC | केवल `BUILTIN\Administrators` |
| `RdpAudit.Configurator` | Elevation आवश्यक |
| SQLite DB | `SYSTEM` और `Administrators` तक सीमित |
| `appsettings.json` | `SYSTEM` और `Administrators` तक सीमित |

### 11.2. SACL कॉन्फ़िगरेशन

Configurator मूल्यवान लक्ष्यों पर SACL सेट करता है, ताकि संवेदनशील बदलाव ऑडिट-योग्य बनें:
- IFEO accessibility कुंजियाँ
- `RDP-Tcp` रजिस्ट्री कॉन्फ़िगरेशन
- `Lsa` रजिस्ट्री कॉन्फ़िगरेशन

यह Sticky Keys बैकडोर, RDP पोर्ट बदलाव और LSASS/PPL छेड़छाड़ का पता लगाने में सहायक है।

### 11.3. सीक्रेट सुरक्षा (DPAPI)

- AbuseIPDB कुंजियाँ और MikroTik क्रेडेंशियल Windows DPAPI से सुरक्षित
- कॉन्फ़िगरेशन में केवल DPAPI envelope संग्रहीत
- GUI plaintext सीक्रेट उजागर नहीं करता
- बैकअप में सुरक्षित मान जाते हैं, डिक्रिप्ट किए गए नहीं

---

## 12. कॉन्फ़िगरेशन

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

### 12.2. एनवायरनमेंट वेरिएबल

आप एनवायरनमेंट वेरिएबल के ज़रिए कॉन्फ़िगरेशन मान बदल सकते हैं, जो स्वचालित डिप्लॉयमेंट और डायग्नोस्टिक्स के लिए उपयोगी है:

```text
RDPAUDIT_RdpAudit__LogLevel=Debug
RDPAUDIT_RdpAudit__AlertRules__BruteForce__FailThreshold=5
```

---

## 13. डिबगिंग और डायग्नोस्टिक्स

### 13.1. कंसोल मोड

डिबगर जुड़ा होने पर सेवा औपचारिक Windows Service के बजाय कंसोल एप्लिकेशन के रूप में चल सकती है।

```powershell
cd src\RdpAudit.Service
dotnet run --configuration Debug
```

### 13.2. Serilog लॉग

लॉग यहाँ लिखे जाते हैं:
- `%ProgramData%\RdpAudit\logs\rdpaudit-<date>.log`
- Windows Event Log → `Application`, स्रोत `RdpAudit`

वर्बोसिटी बढ़ाने के लिए:

```powershell
$env:RDPAUDIT_RdpAudit__LogLevel = "Debug"
```

### 13.3. SQLite से सीधी पहुँच

```powershell
& "C:\Program Files\DB Browser for SQLite\DB Browser for SQLite.exe" `
  "$env:ProgramData\RdpAudit\rdpaudit.db"
```

उपयोगी क्वेरी:

```sql
SELECT * FROM RawEvents ORDER BY TimeUtc DESC LIMIT 100;

SELECT * FROM ActiveBlocks WHERE Status = 'Active';

SELECT SourceIp, SUM(FailCount) AS Fails
FROM AttackStats
GROUP BY SourceIp
ORDER BY Fails DESC
LIMIT 20;
```

### 13.4. Diagnostics टैब

Diagnostics UI दिखाता है:
- प्रति-सेकंड इवेंट काउंटर
- Worker स्थिति
- IPC स्थिति
- डेटाबेस स्वास्थ्य
- बाहरी इंटीग्रेशन की पहुँच

---

## 14. बिल्ड और टेस्ट

### 14.1. बिल्ड

```powershell
dotnet build RdpAudit.sln -c Release
dotnet build src/RdpAudit.Service/RdpAudit.Service.csproj -c Release
```

### 14.2. टेस्ट

```powershell
dotnet test RdpAudit.sln -c Release
dotnet test RdpAudit.sln -c Release --collect:"XPlat Code Coverage"
dotnet test tests/RdpAudit.Service.Tests/RdpAudit.Service.Tests.csproj
```

हर अलर्ट-नियम टेस्ट को यह सत्यापित करना चाहिए:
1. थ्रेशोल्ड सीमा व्यवहार
2. Whitelist बायपास व्यवहार
3. बार-बार मूल्यांकन में शून्य मैनेज्ड allocation

### 14.3. पब्लिश

```powershell
./publish.ps1
```

अपेक्षित आउटपुट:

```text
publish/
├── Service/
└── Configurator/
```

---

## 15. समस्या-निवारण

विस्तृत मार्गदर्शन: [`docs/91-troubleshooting.md`](docs/91-troubleshooting.md)

| लक्षण | पहला निदान कदम |
|---------|-----------------------|
| सेवा शुरू नहीं होती | `sc.exe query RdpAudit` जाँचें, फिर Application Event Log देखें |
| कोई live इवेंट नहीं दिखता | **Prerequisites** खोलें और ऑडिट कॉन्फ़िगरेशन की पुष्टि करें |
| GUI कनेक्ट नहीं हो पाता | जाँचें कि सेवा चल रही है और pipe ACL सही है |
| `sc.exe` 1639 लौटाता है | सेवा बाइनरी पथ में कोटिंग दोबारा जाँचें |
| AbuseIPDB HTTP 429 लौटाता है | API रेट लिमिट पूरी हो गई है |
| MikroTik TLS विफलता | self-signed सर्ट के लिए वैलिडेशन बंद करें या CA सर्ट इंस्टॉल करें |
| `SQLITE_BUSY` दिखता है | अल्पकालिक विवाद अपेक्षित है और स्वचालित रूप से दोबारा प्रयास होता है |
| Audit policy में `?` दिखता है | Audit Policy टैब से दोबारा लागू करें |
| ProgramData ACL समस्याएँ | `SYSTEM` और `Administrators` के लिए फ़ोल्डर ACL ठीक करें |

यह भी देखें: [`docs/90-windows-validation.md`](docs/90-windows-validation.md)

---

## 16. रोडमैप (v2.0 → v3.0)

| फ़ीचर | स्थिति |
|---------|--------|
| ETW इनजेशन (`OpenTrace` / `ProcessTrace`) | नियोजित |
| `Span<byte>` के साथ सीधा EVTX पार्सिंग | नियोजित |
| लॉक-फ़्री MPMC रिंग बफ़र | नियोजित |
| SIMD CIDR और पार्सिंग त्वरण | नियोजित |
| शून्य-एलोकेशन इवेंट नॉर्मलाइज़ेशन | नियोजित |
| नेटवर्क-लेयर MS-RDPBCGR / RDPEUDP दृश्यता | अनुसंधान |
| Blazor-आधारित वेब UI | नियोजित |
| Elastic / OpenSearch इंटीग्रेशन | रोडमैप |
| केंद्रीय मल्टी-सर्वर कलेक्टर | रोडमैप |

---

## 17. लाइसेंस और लेखक

**लाइसेंस:** [Business Source License 1.1](LICENSE)

RDPAudit Community सोर्स-अवेलेबल है। आप इसे गैर-प्रोडक्शन उद्देश्यों के लिए कॉपी, संशोधित, पुनर्वितरित और
उपयोग कर सकते हैं; `LICENSE` में लिखी गई Additional Use Grant इसके अतिरिक्त
प्रोडक्शन उपयोग की अनुमति देती है, सिवाय सॉफ़्टवेयर को तीसरे पक्ष को वाणिज्यिक होस्टेड या प्रबंधित
सेवा के रूप में देने के। **2030-10-25** को यह संस्करण Apache License 2.0 में बदल जाएगा।

Pro और Enterprise संस्करण स्वामित्व-स्वरूप (proprietary) हैं और इस लाइसेंस के **अंतर्गत नहीं** आते - हर एक
के अपने नियम हैं। कौन-सी क्षमता किस संस्करण की है, यह
[docs/editions.md](docs/editions.md) में प्रलेखित है।

**लेखक:** Mikhail Deynekin
- वेबसाइट: [deynekin.com](https://deynekin.com)
- ईमेल: [Mikhail@Deynekin.com](mailto:Mikhail@Deynekin.com)
- GitHub: [github.com/paulmann](https://github.com/paulmann)

**रिपॉज़िटरी:** [github.com/paulmann/RDPAudit](https://github.com/paulmann/RDPAudit)

**संबंधित संसाधन:**
- [Technical Specification v1.0](https://github.com/paulmann/1st-RDPMon/wiki/RdpAudit-Service-%E2%80%90-Technical-Specification-v1.0)
- [Technical Specification v2.0](https://github.com/paulmann/1st-RDPMon/wiki/RdpAudit-Service-%E2%80%90-Technical-Specification-v2.0)
- [Issues and Feature Requests](https://github.com/paulmann/RDPAudit/issues)

---

> © 2025–2026 Mikhail Deynekin. [Business Source License 1.1](LICENSE) के अंतर्गत जारी।
