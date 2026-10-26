# RDPAudit — Windows-RDP-Sicherheitsüberwachung & automatische Sperrplattform

[![Version](https://img.shields.io/badge/version-2.0.2-blue.svg)](https://github.com/paulmann/RDPAudit)
[![Lizenz](https://img.shields.io/badge/License-BSL%201.1-blue.svg)](LICENSE)
[![.NET](https://img.shields.io/badge/dotnet-8.0--windows-blue.svg)](https://dotnet.microsoft.com/)
[![Plattform](https://img.shields.io/badge/platform-Windows%2010%2B%20%2F%20Server%202016%2B-blue.svg)](https://www.microsoft.com/windows/)
[![SQLite](https://img.shields.io/badge/sqlite-WAL%20mode-orange.svg)](https://sqlite.org/)

<!-- md-i18n:switcher -->
**In anderen Sprachen:** [English](README.md) · Deutsch · [中文](README.zh.md) · [हिन्दी](README.hi.md) · [Español](README.es.md) · [Русский](README.ru.md)

> **Edition: Community.** Lokale Erkennung und lokale Reaktion auf einem Server. Was in diesem Build enthalten ist und was nicht: [README-EDITION.md](README-EDITION.md).

> **RDPAudit** ist eine produktionsreife Windows-Plattform zur Überwachung von RDP-Aktivitäten und zur Reaktion auf RDP-basierte Bedrohungen.  
> Sie besteht aus einem **Windows-Dienst** (Ereigniserfassung im Hintergrund, 21 Alarmregeln, automatische Sperrung) und einem **WinForms-Konfigurator** (GUI für Verwaltung, Statistik, Diagnose und Richtlinienkonfiguration).

---

## Inhaltsverzeichnis

- [1. Produktübersicht](#1-produktübersicht)
  - [1.1. Zweck](#11-zweck)
  - [1.2. Lösungsarchitektur](#12-lösungsarchitektur)
  - [1.3. Kernfunktionen](#13-kernfunktionen)
- [2. Systemanforderungen](#2-systemanforderungen)
  - [2.1. Mindestanforderungen](#21-mindestanforderungen)
  - [2.2. Anforderungen an die Windows-Auditierung](#22-anforderungen-an-die-windows-auditierung)
- [3. Aufbau der Lösung](#3-aufbau-der-lösung)
  - [3.1. Projekte und Schichten](#31-projekte-und-schichten)
  - [3.2. Verzeichnisstruktur](#32-verzeichnisstruktur)
- [4. Schnellstart](#4-schnellstart)
  - [4.1. Build](#41-build)
  - [4.2. Dienst installieren](#42-dienst-installieren)
  - [4.3. Erster Start des Konfigurators](#43-erster-start-des-konfigurators)
- [5. RdpAudit.Service — Überwachungsdienst](#5-rdpauditservice--überwachungsdienst)
  - [5.1. Ereigniserfassung](#51-ereigniserfassung)
  - [5.2. Erfasste Ereignis-IDs](#52-erfasste-ereignis-ids)
  - [5.3. Datenspeicherung (SQLite)](#53-datenspeicherung-sqlite)
  - [5.4. Alarmierungssystem — 21 Regeln](#54-alarmierungssystem--21-regeln)
  - [5.5. Automatische Sperrung über die Windows-Firewall](#55-automatische-sperrung-über-die-windows-firewall)
  - [5.6. Named-Pipe-IPC](#56-named-pipe-ipc)
  - [5.7. Zuverlässigkeit und Ausfallsicherheit](#57-zuverlässigkeit-und-ausfallsicherheit)
  - [5.8. REST-API (nur Lesen)](#58-rest-api-nur-lesen)
- [6. RdpAudit.Configurator — GUI](#6-rdpauditconfigurator--gui)
  - [6.1. Registerkarte Overview](#61-registerkarte-overview)
  - [6.2. Registerkarte Prerequisites](#62-registerkarte-prerequisites)
  - [6.3. Registerkarte Audit Policy](#63-registerkarte-audit-policy)
  - [6.4. Registerkarte Service](#64-registerkarte-service)
  - [6.5. Registerkarte Settings](#65-registerkarte-settings)
  - [6.6. Registerkarte Live Events](#66-registerkarte-live-events)
  - [6.7. Registerkarte Firewall](#67-registerkarte-firewall)
  - [6.8. Registerkarte Attack Statistics](#68-registerkarte-attack-statistics)
  - [6.9. Registerkarte Remote RDP Clients](#69-registerkarte-remote-rdp-clients)
  - [6.10. Registerkarte AbuseIPDB](#610-registerkarte-abuseipdb)
  - [6.11. Registerkarte MikroTik](#611-registerkarte-mikrotik)
  - [6.12. Registerkarte Logs](#612-registerkarte-logs)
  - [6.13. Registerkarte Diagnostics](#613-registerkarte-diagnostics)
- [6.14. Registerkarte Session Map](#614-registerkarte-session-map)
- [6.15. Registerkarte Notifications](#615-registerkarte-notifications)
- [6.16. Registerkarte Web Access](#616-registerkarte-web-access)
- [7. RdpAudit.Core — Gemeinsame Bibliothek](#7-rdpauditcore--gemeinsame-bibliothek)
  - [7.1. Datenmodelle](#71-datenmodelle)
  - [7.2. Entity Framework Core und Migrationen](#72-entity-framework-core-und-migrationen)
  - [7.3. IPC-Verträge (MessagePack)](#73-ipc-verträge-messagepack)
- [8. Externe Integrationen](#8-externe-integrationen)
  - [8.1. AbuseIPDB](#81-abuseipdb)
  - [8.2. MikroTik RouterOS v7](#82-mikrotik-routeros-v7)
- [9. Modell der automatischen Sperrung](#9-modell-der-automatischen-sperrung)
  - [9.1. Auslöseschwellen](#91-auslöseschwellen)
  - [9.2. Lokale Windows-Firewall](#92-lokale-windows-firewall)
  - [9.3. Remote-MikroTik-Firewall](#93-remote-mikrotik-firewall)
  - [9.4. Whitelist-Schutz für vertrauenswürdige IPs](#94-whitelist-schutz-für-vertrauenswürdige-ips)
- [10. Datenwartung](#10-datenwartung)
  - [10.1. Bereinigung nach Aufbewahrungsfristen](#101-bereinigung-nach-aufbewahrungsfristen)
  - [10.2. Sicherung und Wiederherstellung](#102-sicherung-und-wiederherstellung)
- [11. Sicherheit und Auditierung](#11-sicherheit-und-auditierung)
  - [11.1. Zugriffskontrolle](#111-zugriffskontrolle)
  - [11.2. SACL-Konfiguration](#112-sacl-konfiguration)
  - [11.3. Schutz von Geheimnissen (DPAPI)](#113-schutz-von-geheimnissen-dpapi)
- [12. Konfiguration](#12-konfiguration)
  - [12.1. appsettings.json](#121-appsettingsjson)
  - [12.2. Umgebungsvariablen](#122-umgebungsvariablen)
- [13. Debugging und Diagnose](#13-debugging-und-diagnose)
  - [13.1. Konsolenmodus](#131-konsolenmodus)
  - [13.2. Serilog-Protokolle](#132-serilog-protokolle)
  - [13.3. Direkter SQLite-Zugriff](#133-direkter-sqlite-zugriff)
  - [13.4. Registerkarte Diagnostics](#134-registerkarte-diagnostics)
- [14. Build und Test](#14-build-und-test)
  - [14.1. Build](#141-build)
  - [14.2. Tests](#142-tests)
  - [14.3. Veröffentlichen](#143-veröffentlichen)
- [15. Fehlerbehebung](#15-fehlerbehebung)
- [16. Roadmap (v2.0 → v3.0)](#16-roadmap-v20--v30)
- [17. Lizenz und Autor](#17-lizenz-und-autor)

---

## 1. Produktübersicht

### 1.1. Zweck

**RDPAudit** ist für die kontinuierliche Überwachung der RDP-Aktivität auf Windows-Servern und -Arbeitsplätzen ausgelegt. Das Produkt läuft im Hintergrund als Systemdienst, auch wenn kein interaktiver Benutzer angemeldet ist, zeichnet Verbindungsversuche, Authentifizierungsereignisse und sicherheitsrelevante Systemänderungen auf, bewertet sie über 21 Sicherheitsregeln und kann Angreifer automatisch über die Windows-Firewall und/oder MikroTik RouterOS sperren.

**Typische Einsatzszenarien:**
- Schutz von ins Internet exponierten RDP-Endpunkten vor Brute-Force-Angriffen
- Unterstützung von SOC2-, ISO 27001- und internen Audit-Anforderungen für privilegierten Zugriff
- Erkennung von Kompromittierungsmustern, etwa einer erfolgreichen Anmeldung nach wiederholten Fehlversuchen
- Identifikation von Hintertüren über Barrierefreiheits-Binärdateien wie Sticky Keys und Utilman-Missbrauch
- Erkennung von Angriffen auf LSA/LSASS, Kerberos-Spraying und Änderungen des RDP-Ports
- Integration mit MikroTik, damit bösartige IPs am Netzwerkrand gesperrt werden können

### 1.2. Lösungsarchitektur

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

### 1.3. Kernfunktionen

- **Echtzeitüberwachung** über `EventLogWatcher`-Abonnements statt Polling
- **21 Alarmregeln** für Brute-Force, LSASS-Angriffe, Kerberos-Spraying, verdächtige Richtlinienänderungen und weiteres
- **Automatische Sperrung** über IP-basierte Windows-Firewall-Regeln mit Unterstützung für manuelles Aufheben
- **MikroTik-Integration** über RouterOS-v7-REST-APIs mit DPAPI-geschützten Anmeldedaten
- **AbuseIPDB-Meldungen** mit lokaler Deduplizierung und Berücksichtigung von Ratenlimits
- **Reputationsprüfungen aus Threat-Intelligence-Daten** (Backlog #5) – Hintergrundabfragen an AbuseIPDB /api/v2/check mit Datenträger-Cache und einer Markierung **High risk** in Angriffsstatistik und Live-Ereignissen
- **Bedrohungsanalyse** aggregiert nach IP, Land, Zeitraum und berechnetem Bedrohungsgrad
- **Zuordnung von Sitzung zu IP**, um RDP-Sitzungen auf Quelladressen zurückzuführen
- **Bereinigung nach Aufbewahrungsfristen** für langfristige Stabilität und geringeres Datenbankwachstum
- **Sicherung und Wiederherstellung** des Konfigurationszustands, ohne Klartext-Geheimnisse
- **Sichere Named-Pipe-IPC**, beschränkt auf `BUILTIN\Administrators`
- **Schreibgeschützte HTTPS-REST-API** (optional, standardmäßig aus) mit Bearer-Token-Authentifizierung, Ratenbegrenzung pro IP und OpenAPI-Beschreibung
- **SIEM-Export** (CEF / LEEF 2.0 / NDJSON) der IP-bezogenen Ereignisse und korrelierten Alarme aus den Seiten Live Events und Attack Statistics

---

## 2. Systemanforderungen

### 2.1. Mindestanforderungen

| Komponente | Anforderung |
|-----------|-------------|
| Betriebssystem | Windows 10 oder Windows Server 2016 und neuer (x64) |
| .NET-Laufzeit | .NET 8.0 für Windows (x64) |
| Berechtigungen | Lokaler Administrator für Dienstinstallation und Systemkonfiguration |
| Datenträger | 200 MB für Binärdateien plus Platz für die Ereignisdatenbank |
| Arbeitsspeicher | 64 MB Working Set für den Dienst unter normaler Last |

### 2.2. Anforderungen an die Windows-Auditierung

RDPAudit ist auf die Windows-Sicherheitsauditierung angewiesen, um die Ereignisse zu erhalten, die es auswertet. Für den korrekten Betrieb müssen die folgenden Auditkategorien aktiviert sein:

| Auditkategorie | Unterkategorie-GUID | Zweck |
|----------------|------------------|---------|
| Anmeldung / Abmeldung | `{0CCE9215-69AE-11D9-BED3-505054503030}` | Ereignisse 4624, 4625, 4634 |
| Kontoanmeldung | `{0CCE9240-69AE-11D9-BED3-505054503030}` | Kerberos-Ereignisse |
| Prozesserstellung | `{0CCE922B-69AE-11D9-BED3-505054503030}` | Ereignis 4688 und Prozesssichtbarkeit |
| Objektzugriff | `{0CCE9217-69AE-11D9-BED3-505054503030}` | SACL-gestützte Ereignisse wie 4656 und 4663 |
| Richtlinienänderung | `{0CCE922F-69AE-11D9-BED3-505054503030}` | Sichtbarkeit von Firewall- und Richtlinienänderungen |

Der Konfigurator wendet diese Einstellungen automatisch an, indem er `auditpol.exe` mit GUID-basierten Bezeichnern aufruft, was den Vorgang unabhängig von der Systemsprache macht.

---

## 3. Aufbau der Lösung

### 3.1. Projekte und Schichten

| Projekt | Typ | Verantwortung |
|--------|------|----------------|
| `RdpAudit.Core` | Klassenbibliothek (`net8.0-windows`) | Entitäten, EF-Core-`DbContext`, Migrationen, MessagePack-IPC-Verträge, gemeinsame Hilfsfunktionen |
| `RdpAudit.Service` | Worker-Dienst (`net8.0-windows`, `win-x64`) | Ereigniserfassung, Normalisierung, Alarmbewertung, automatische Sperrung, IPC-Server |
| `RdpAudit.Configurator` | WinForms-Anwendung (`net8.0-windows`) | GUI, IPC-Client, Voraussetzungsprüfungen, Dienststeuerung, Konfigurationsabläufe |
| `RdpAudit.Web` | ASP.NET-Core-Anwendung (`net8.0-windows`) | In IIS gehostetes schreibgeschütztes Web-Dashboard und Loopback-YARP-Proxy: Bearer-Injektion aus dem DPAPI-Tresor, Sicherheitsheader, festgenageltes Backend-TLS |
| `RdpAudit.Core.Tests` | xUnit | Unit-Tests des Kerns |
| `RdpAudit.Service.Tests` | xUnit | Tests der Alarmregeln, Schwellenwertvalidierung, Whitelist-Abdeckung, Allokationsprüfungen |
| `RdpAudit.Web.Tests` | xUnit | Integrationstests des Web-Proxys: Host-Filter, Bearer-Injektion, statischer CSP/DOM-Vertrag |
| `RdpAudit.Benchmarks` | BenchmarkDotNet | Benchmark-Abdeckung der Hot Paths |

### 3.2. Verzeichnisstruktur

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

## 4. Schnellstart

### 4.1. Build

```powershell
git clone https://github.com/paulmann/RDPAudit.git
cd RDPAudit
dotnet build RdpAudit.sln -c Release
```

### 4.2. Dienst installieren

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

### 4.3. Erster Start des Konfigurators

```powershell
publish/Configurator/RdpAudit.Configurator.exe
```

Beim ersten Start ist die folgende Reihenfolge zu empfehlen:

1. **Prerequisites** öffnen und die erforderlichen Kanäle und Plattform-Einstellungen prüfen.
2. **Audit Policy** öffnen und die erforderlichen Audit-Unterkategorien über `auditpol.exe` anwenden.
3. **Service** öffnen und den Windows-Dienst installieren oder starten.
4. **Settings** öffnen und Alarmschwellenwerte, vertrauenswürdige IPs, Aufbewahrungsfristen und Integrationen abstimmen.

---

## 5. RdpAudit.Service — Überwachungsdienst

### 5.1. Ereigniserfassung

Der Dienst verwendet `System.Diagnostics.Eventing.Reader.EventLogWatcher`, um relevante Ereignisse in Echtzeit zu abonnieren. Das Design ist bereits hinter Schnittstellen für Ereignisquellen abstrahiert, sodass das Erfassungs-Backend später auf eine ETW-basierte Übernahme umziehen kann, ohne den Rest der Pipeline umzuschreiben.

**Überwachte Kanäle:**
- `Security`
- `Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational`
- `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational`

### 5.2. Erfasste Ereignis-IDs

| Ereignis-ID | Kanal | Beschreibung |
|----------|---------|-------------|
| 4624 | Security | Erfolgreiche Anmeldung, insbesondere Anmeldetyp 10 |
| 4625 | Security | Fehlgeschlagene Anmeldung |
| 4634 | Security | Abmeldung |
| 4647 | Security | Vom Benutzer ausgelöste Abmeldung |
| 4648 | Security | Anmeldung mit expliziten Anmeldedaten |
| 4688 | Security | Prozesserstellung |
| 4720 | Security | Benutzerkonto erstellt |
| 4723 / 4724 | Security | Passwortänderung / Passwortzurücksetzung |
| 4740 | Security | Kontosperrung |
| 4769 | Security | Anforderung eines Kerberos-Diensttickets |
| 4771 | Security | Fehler der Kerberos-Vorauthentifizierung |
| 4776 | Security | NTLM-Authentifizierung |
| 4954 | Security | Änderung einer Windows-Firewall-Regel oder -Richtlinie |
| 1149 | TerminalServices-RCM | RDP-Verbindung mit Quell-IP |
| 21, 23, 24, 25 | TerminalServices-LSM | Sitzungsbeginn, erneute Verbindung, Trennung, Ende |

### 5.3. Datenspeicherung (SQLite)

Die Datenbank liegt unter `%ProgramData%\RdpAudit\rdpaudit.db`.

**SQLite-Einstellungen:**
```sql
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
```

**Primärtabellen:**

| Tabelle | Zweck |
|-------|---------|
| `RawEvents` | Normalisierte Sicherheits- und RDP-Ereignisse |
| `RdpConnectionFacts` | Verbindungsfakten mit IP, Benutzer und Ergebnis |
| `AuthAttemptFacts` | Fakten zu Authentifizierungsversuchen |
| `Sessions` | Datensätze von RDP-Sitzungen |
| `SessionIpCorrelations` | Zuordnung von Sitzung zu IP |
| `AttackStats` | Aggregierte Angriffsstatistik nach Quelle |
| `ActiveBlocks` | Aktuell aktive automatische Sperrungen |
| `Alerts` | Alarmhistorie |
| `WhitelistEntries` | Einträge vertrauenswürdiger IPs und CIDR-Bereiche |
| `BlocklistEntries` | Dauerhafte Sperrregeln und ihre Quellen |
| `AbuseIpDbReportHistory` | Meldehistorie von AbuseIPDB |
| `OperationLogs` | Betriebsprotokolleinträge, die in der GUI erscheinen |
| `DbProps` | Schlüssel-Wert-Speicher für Metadaten |
| `Bookmarks` | Lesezeichen zur Absturzwiederherstellung der Ereignisverarbeitung |
| `LoginRules` | Regeln zu Arbeitszeiten und Anmelderichtlinie |

**Schreibstrategie:** Der Hot Path verwendet rohe `SqliteCommand`-Aufrufe mit expliziten Transaktionen und gebündelten Schreibvorgängen.

**Haltbarkeit der Lesezeichen:** Lesezeichen werden alle 100 Ereignisse und alle 30 Sekunden geschrieben, was Verluste nach einem Absturz oder einer Stromunterbrechung minimiert.

### 5.4. Alarmierungssystem — 21 Regeln

Jede Regel ist als eigener Alarm-Auswerter implementiert und nimmt an einer gemeinsamen Regel-Pipeline teil.

| # | Regel-ID | Schweregrad | Beschreibung |
|---|---------|----------|-------------|
| 1 | `BRUTE_FORCE` | Hoch | Fehlgeschlagene Anmeldungen von derselben Quelle überschreiten den Schwellenwert |
| 2 | `BRUTE_FORCE_NTLM` | Hoch | NTLM-Brute-Force mit Cooldown-Logik |
| 3 | `KERBEROS_SPRAY` | Hoch | Verhalten von Kerberos-Password-Spraying |
| 4 | `SUCCESSFUL_AFTER_FAILS` | Mittel | Erfolgreiche Anmeldung nach wiederholten Fehlversuchen |
| 5 | `OFF_HOURS_LOGIN` | Mittel | Anmeldung außerhalb der freigegebenen Arbeitszeiten |
| 6 | `ACCOUNT_LOCKOUT` | Mittel | Ereignis einer Kontosperrung |
| 7 | `NEW_ACCOUNT_CREATED` | Mittel | Neues lokales oder Domänenkonto erstellt |
| 8 | `PASSWORD_RESET` | Niedrig | Passwortzurücksetzung oder Passwortänderung |
| 9 | `MULTIPLE_ACCOUNTS_SAME_IP` | Hoch | Benutzernamen-Spraying von einer Quell-IP |
| 10 | `STICKY_KEYS_BACKDOOR` | Kritisch | Verhalten einer Hintertür über Barrierefreiheits-Binärdateien |
| 11 | `LSASS_ACCESS` | Kritisch | Verdächtiger Handle-Zugriff auf LSASS |
| 12 | `LSASS_PPL_TAMPER` | Kritisch | Versuch, den LSASS-PPL-Schutz zu schwächen |
| 13 | `RDP_PORT_CHANGED` | Hoch | Registry-basierte Änderung des RDP-Ports erkannt |
| 14 | `FIREWALL_RULE_CHANGED` | Mittel | Firewall-Regel oder -Richtlinie geändert |
| 15 | `EXPLICIT_CREDENTIALS` | Mittel | Muster der Nutzung expliziter Anmeldedaten |
| 16 | `LOGON_TYPE_NETWORK` | Niedrig | Netzwerkanmeldung an einem geschützten System |
| 17 | `CONCURRENT_SESSIONS` | Niedrig | Zu hohe Anzahl gleichzeitiger Sitzungen |
| 18 | `GEO_ANOMALY` | Mittel | Anmeldung aus einer unzulässigen oder unerwarteten Region |
| 19 | `IP_REPUTATION` | Hoch | Quell-IP erscheint in bekannten Sperrlisten |
| 20 | `SESSION_HIJACK_SUSPECT` | Hoch | Anomalie in der Sitzungskorrelation |
| 21 | `RAPID_RECONNECT` | Mittel | Wiederholte Wiederverbindungen von derselben IP |

### 5.4.1. Härtung von PRIVILEGED_LOGIN

Die Regel `PRIVILEGED_LOGIN` (Ereignis 4672 – bei der Anmeldung zugewiesenes SeDebug / SeTcb) ist gegen den Sturm wohlbekannter SIDs beim Dienststart gehärtet (identische SYSTEM-Alarme ohne Quell-IP):

- **Exakter SID-Filter** – `S-1-5-18` (SYSTEM), `S-1-5-19` (LOCAL SERVICE) und `S-1-5-20` (NETWORK SERVICE) werden über die exakte, aus dem normalisierten `Details`-JSON gelesene SID (`subjectUserSid`) zurückgewiesen, niemals über lokalisierte Kontonamen.
- **Netzwerkkontext erforderlich** – das Ereignis muss eine nicht leere `SourceIp` und einen Netzwerk-Anmeldetyp (3 / 7 / 10) tragen. Fehlt `LogonType` (Windows 4672 hat kein eigenes Feld), wird ersatzweise das passende Security-4624 über `SubjectLogonId == TargetLogonId` korreliert.
- **Unterdrückungsfenster** – identische Auslöser pro (Benutzer, Quell-IP, Anmeldetyp) werden innerhalb von `PrivilegedLoginSuppressionWindowMinutes` (Standard 5) unterdrückt; nach Ablauf des Fensters trägt ein einzelner Sammelalarm die unterdrückte Anzahl.
- **Alarmbudget pro Minute** – `PrivilegedLoginRateLimitPerMinute` (Standard 20) begrenzt die Ausgabe; eine Drosselung wird einmal pro Minute protokolliert.
- **Altersgrenze für historische Ereignisse** – Ereignisse, die älter als `AlertEventMaxAgeMinutes` (Standard 5) sind, bleiben als `RawEvent`-Fakten gespeichert, lösen jedoch nie einen Alarm aus (angewendet von `AlertWorker` auf alle Regeln).
- **Ablehnungspfad ohne Allokationen** – `EvaluateAsync` ist eine nicht asynchrone Methode, die ein zwischengespeichertes Null-Task-Singleton zurückgibt, sodass abgelehnte Auswertungen nichts allokieren.

### 5.5. Automatische Sperrung über die Windows-Firewall

Wenn Regeln wie `BRUTE_FORCE`, `BRUTE_FORCE_NTLM` oder `IP_REPUTATION` ausgelöst werden, kann der Dienst eine eingehende Sperrregel pro IP anlegen.

```powershell
netsh advfirewall firewall add rule `
  name="RdpAudit_Block_<IP>" `
  dir=in action=block remoteip=<IP> `
  protocol=any enable=yes
```

**Eigenschaften der Umsetzung:**
- Idempotente Regelerstellung
- Bereinigung der Eingaben vor der Ausführung in der Shell
- Manuelles Entfernen über die GUI
- Vollständige Auditierung über `ActiveBlocks` und `OperationLogs`

### 5.6. Named-Pipe-IPC

**Pipe-Name:** `\\.\pipe\RdpAuditService`

**Sicherheitsmodell:** Nur `BUILTIN\Administrators` dürfen sich verbinden.

**Protokoll:** In `RdpAudit.Core` definierte MessagePack-Anfrage- und -Antwortverträge.

**Betriebshinweise:**
- Die GUI schreibt niemals direkt in Konfigurationsdateien, die dem Dienst gehören.
- Einstellungen werden über IPC gesendet und vom Dienst atomar übernommen.
- Verbindungsfristen verhindern, dass der Konfigurator unbegrenzt hängt.
- Die Pipe wird von `IpcServerWorker` bedient, der `MaxConcurrent + 1` Betriebssysteminstanzen anfordert, damit die ständig lauschende Bereitschaftspipe nie mit einem verbundenen Handler konkurriert. Win32 `ERROR_PIPE_BUSY` (231) wird als "Instanzobergrenze erreicht" klassifiziert, nicht als Abfangen durch AV/EDR; die Sättigung baut sich automatisch ab, sobald Handler fertig werden.
- Jede Worker-Instanz schreibt beobachtbare Lebenszyklus-Fakten nach `%ProgramData%\RdpAudit\logs\ipc-startup.log`: `instance constructed` / `ExecuteAsync entered` / `ExecuteAsync exiting (pid, instanceId, entryCount, exitCount, iteration, activeHandlers, livePipes, stoppingTokenCancelled, hostApplicationStoppingCancelled, exitReason, lifetimeMs)`. Diese Felder belegen, ob ein Prozess jemals mehr als eine Worker- oder Host-Instanz ausgeführt hat.

### 5.7. Zuverlässigkeit und Ausfallsicherheit

- Exponentielles Backoff bei vorübergehenden Datenbankkonflikten wie `SQLITE_BUSY`
- End-to-End-Weitergabe von `CancellationToken` über asynchrone Abläufe
- Jeder gehostete Worker ist in `TimedHostedService` eingebunden und schreibt Beginn-, Ende- und Fehlermarken in `startup-sequence.log`
- `IpcServerWorker` protokolliert Lebenszyklus-Marken pro Instanz, sodass ein wiederholtes `ExecuteAsync entered` in einer PID einer oder mehreren Worker-/Host-Instanzen zugeordnet werden kann
- Sauberes Herunterfahren beim Stoppen des Dienstes
- EF-Core-Migrationen werden beim Start angewendet
- Registrierung der Ereignisprotokollquelle während der Installation

### 5.8. REST-API (nur Lesen)

Der Dienst kann eine **optionale schreibgeschützte HTTPS-REST-API** (Kestrel, standardmäßig
aus) für Überwachungsagenten und Skripte bereitstellen. Sie beantwortet nur `GET`/`HEAD` und
nutzt dieselben auditierten Lesebefehle wie die Named Pipe, sodass die REST-Oberfläche keine
Schreibpfade hat.

- **Endpunkte**: `/healthz` (anonym), `/api/status`, `/api/alerts`, `/api/sessions`,
  `/api/addresses`, `/api/attacks`, `/api/config` (Geheimnisse maskiert),
  `/api/events` (begrenzte, gefilterte, sortierte Seite) und
  `/openapi/v1.json` (eingecheckte OpenAPI-3.0-Beschreibung).
- **Authentifizierung**: statisches Bearer-Token (`Api.Token`, DPAPI-geschützt) mit
  `WWW-Authenticate: Bearer realm="rdpaudit"` bei 401.
- **Transport**: ausschließlich HTTPS. Der Listener verwendet standardmäßig `127.0.0.1:8443`;
  ein TLS-Zertifikat in `LocalMachine\My` wird über `Api.CertificateThumbprint` /
  `Api.CertificateSubject` ausgewählt. Nicht-Loopback-Listener protokollieren beim Start eine
  ausdrückliche Risikowarnung.
- **Härtung**: Ratenbegrenzung pro IP mit festem Fenster (`Api.RateLimitPerMinute`),
  Verbindungsobergrenze (`Api.MaxConnections`), Sicherheitsheader und RFC-9457-
  `problem+json`-Fehlerkörper für jede Antwort ungleich 200.
- **Fail-Closed-Start**: `Api.Enabled=false` (Standard) oder eine fehlende Voraussetzung
  (Token/Zertifikat/Adresse) bedeutet, dass gar kein Listener entsteht.

Die Konfiguration liegt im Abschnitt `Api` von `appsettings.json`. Vollständige Referenz:
`docs/40-options.md` (ApiOptions) und `docs/51-rest-api.md` (Endpunkte, Fehler,
Authentifizierung, Betrieb).

---

## 6. RdpAudit.Configurator — GUI

Der Konfigurator läuft mit erhöhten Rechten und kommuniziert mit dem Dienst ausschließlich über den Named-Pipe-IPC-Kanal.

### 6.1. Registerkarte Overview

Die Registerkarte **Overview** ist das Bedienfeld des Operators. Sie fasst Dienstzustand, aktuelle Sperrzahlen, die letzten Alarme und das aktuelle Ereignisvolumen zusammen.

### 6.2. Registerkarte Prerequisites

Die Registerkarte **Prerequisites** prüft die erforderlichen Windows-Bedingungen:
- Alle sieben überwachten Ereignisprotokollkanäle vorhanden und aktiviert (Security, System und
  die Kanäle der Terminaldienste / des RDP)
- Erforderliche Unterkategorien der Auditrichtlinie angewendet (Objektzugriff + die Basislinie
  aus fünf Unterkategorien)
- Dienst installiert und erreichbar

Ein deaktivierter Kanal bietet eine Korrektur über `wevtutil sl /enabled:true` an. Ein Kanal, der
auf diesem Windows-Build/SKU nicht existiert (zum Beispiel `TerminalServices-Gateway` auf einem
Host ohne RD-Gateway-Rolle), wird als fehlend gemeldet, ohne automatische Korrektur, sodass die
Registerkarte nie eine Aktivierungsschaltfläche für einen Kanal anbietet, den diese
Windows-Edition nicht erstellen kann. Jeder behebbare Fehler kann direkt aus der Oberfläche
angewendet werden.

### 6.3. Registerkarte Audit Policy

Die Registerkarte **Audit Policy** liest die aktuelle Windows-Auditkonfiguration und wendet die erforderlichen Unterkategorien über GUID-basierte `auditpol.exe`-Aufrufe an. Sie übernimmt außerdem die SACL-Einrichtung für sicherheitsrelevante Registrierungspfade und IFEO-Pfade, die für die Erkennung von RDP-Missbrauch relevant sind.

### 6.4. Registerkarte Service

Die Registerkarte **Service** unterstützt:
- Installation und Deinstallation
- Starten, Stoppen, Neustarten
- Anzeige des Dienststatus
- Steuerung des Startmodus

### 6.5. Registerkarte Settings

Die Registerkarte **Settings** stellt die Betriebskonfiguration bereit, darunter:
- Alarmschwellenwerte
- Brute-Force-Zeitfenster
- Definition der Arbeitszeiten
- Aufbewahrungsfristen für Daten
- AbuseIPDB-Einstellungen
- MikroTik-Einstellungen
- Einstellungen für Geolokalisierung und Whitelist

Änderungen werden über IPC übermittelt und vom Dienst atomar angewendet.

### 6.6. Registerkarte Live Events

Die Registerkarte **Live Events** bietet einen Tail-Stream der Echtzeitereignisse mit Farbkodierung für Fehler, Warnungen und erfolgreiche Aktivität. Sie unterstützt Filter nach Ereignis-ID und Quell-IP. Eine Spalte **High risk** zeigt die zwischengespeicherte Threat-Intelligence-Markierung (Stage 15) für jede Quell-IP.

### 6.7. Registerkarte Firewall

Die Registerkarte **Firewall** zeigt aktive Sperrungen aus `ActiveBlocks` und unterstützt:
- Anzeige gesperrter IPs, Gründe und Anbieter
- Manuelles Hinzufügen von Sperreinträgen
- Entfernen von Sperrungen mit Bestätigung
- Import und Export von Sperrlisten

### 6.8. Registerkarte Attack Statistics

Die Registerkarte **Attack Statistics** präsentiert aggregierte Angriffsdaten:
- IPs mit den meisten Angriffen
- Bewertung des Bedrohungsgrads
- Zeitbasierte Diagramme
- Gruppierung nach Land
- Unterstützung des CSV-Exports
- Spalte **High risk** gestützt auf die zwischengespeicherte Threat-Intelligence-Markierung (Stage 15)

Der Bedrohungsgrad wird über die Bewertungslogik in `AttackThreatScoring` berechnet.

### 6.9. Registerkarte Remote RDP Clients

Die Registerkarte **Remote RDP Clients** korreliert Quell-IPs, Verbindungszahlen, Benutzernamen und historische RDP-Sitzungen. Sie soll legitime Remote-Administration von verrauschtem Angriffsverkehr trennen.

### 6.10. Registerkarte AbuseIPDB

Die Registerkarte **AbuseIPDB** verwaltet:
- Konfiguration des API-Schlüssels
- Manuelle und automatische Meldeabläufe
- Meldehistorie mit Deduplizierung
- Ratenlimitbewussten Status und Validierung
- Reputationsprüfungen aus Threat-Intelligence-Daten (/api/v2/check) mit Cache-Status, Tagesverbrauch und der Schwelle für **High risk** (Backlog #5)

Geheimnisse werden nie im Klartext zurückgegeben.

### 6.11. Registerkarte MikroTik

Die Registerkarte **MikroTik** konfiguriert die RouterOS-v7-REST-Integration:
- Adresse und Port des Routers
- DPAPI-geschützte Anmeldedaten
- Verhalten der TLS-Validierung
- Synchronisierung der Adressliste
- Konnektivitätstests

### 6.12. Registerkarte Logs

Die Registerkarte **Logs** zeigt Betriebseinträge aus `OperationLogs`, gruppiert nach Schweregrad:
- `Info`
- `Warning`
- `Error`
- `Critical`

### 6.13. Registerkarte Diagnostics

Die Registerkarte **Diagnostics** liefert gesundheitsbezogene Daten für den Operator:
- Zustand der Worker
- Zustand der IPC
- Größe und Status der Datenbank
- Prüfungen der Integrationen
- Export von Diagnosedaten

### 6.14. Registerkarte Session Map

Die Registerkarte **Session Map** ermöglicht es einem SOC-Operator, eine historische RDP-Sitzung
als chronologische Zeitachse zu untersuchen (Backlog #6). Bei Auswahl eines Fakts aus der
begrenzten Sitzungsliste (bereitgestellt durch den bestehenden Befehl `ListConnectionFacts` mit
IP- und Benutzerfiltern) wird die Antwort von `GetSessionTimeline` geladen und zweifach
angezeigt:

- **Ereignistabelle** – Zeit, Art (Anmeldebeginn / verbunden / erneut verbunden /
  getrennt / Abmeldung / Prozess / Datei / sonstiges), Ereignis-ID, Prozess, Objekt
  und die ausdrückliche Korrelationsmethode. Zeilen, die über `UserWindow` korreliert wurden,
  sind bernsteinfarben getönt, damit die geringere forensische Aussagekraft immer sichtbar ist;
  der rohe DEBUG-Detailtext ist nur dann in einem Tooltip verfügbar, wenn der Dienst mit
  aktiviertem DEBUG-Modus läuft.
- **Gantt-Bereich** – eine integrierte GDI+-Zeitachse mit UTC-Zeitachse,
  farbkodierten Spuren, Legende, einem gestrichelten "Jetzt"-Strahl für aktive Sitzungen und einer
  Markierung `TRUNCATED`, wenn die serverseitige Obergrenze für Aktivitäten (50..2000, Standard 500)
  gegriffen hat.

Der Befehl ist strikt schreibgeschützt und fügt keine Tabellen oder Migrationen hinzu; Vertrag,
Korrelationsregeln, Bedrohungsmodell und Hinweise zur Rücknahme stehen in
`docs/54-session-map.md`.

### 6.15. Registerkarte Notifications

Die Registerkarte **Notifications** konfiguriert die mit erhöhten Rechten laufende Tray-Anwendung `RdpAudit.Notifier`:

- **Enable tray notifier** – Hauptschalter; wenn aus, beendet sich der Notifier still.
- **Start with Windows** – registriert bzw. entfernt die Anmeldeaufgabe `RdpAudit.Notifier` über `schtasks` (`ONLOGON`, `/RL HIGHEST`).
- **Poll interval** – Abfrageintervall des Dienstes in Sekunden (begrenzt auf 1..60).
- **Minimum severity** – Alarme unterhalb dieses Schweregrads werden nie angezeigt.
- **Max toasts per minute** – Ratenobergrenze über ein gleitendes Fenster (begrenzt auf 1..60); überzählige Alarme werden zu einem Sammel-Toast zusammengefasst.
- **Use native toasts** – bevorzugt WinRT-Toasts gegenüber Ballontips im Tray; der Notifier fällt auf Ballontips zurück, wenn der native Kanal nicht verfügbar ist.
- **Unterregisterkarten Alerts / Events** – Sichtbarkeitszuordnungen pro Regel und pro Ereignis.

Speichern und Aktualisieren laufen über die IPC-Befehle `GetNotificationSettings` (78) und
`SaveNotificationSettings` (79); der Dienst begrenzt die Werte, setzt den Schweregrad ersatzweise
auf `High` und speichert ausschließlich den Abschnitt `RdpAudit.Notifications` von
`appsettings.json`. Der Notifier fragt den Dienst über die Named Pipe ab, geht bei
Nichterreichbarkeit auf ein sicheres Intervall zurück und ändert niemals die Datenbank.

---

### 6.16. Registerkarte Web Access

Die Registerkarte **Web Access** (direkt nach **Service** platziert) ist der Einstiegspunkt für
das schreibgeschützte, in IIS gehostete Web-Dashboard. Sie ist **datenschutzorientiert**: alles
bleibt aus, bis der Operator ausdrücklich zustimmt.

- **Show Web Access** – speichert die Sichtbarkeitsentscheidung des Operators; standardmäßig
  aus und nur gespeichert, wenn der Operator sie umschaltet.
- **Allow management from the web** – phasenweise gesperrt: sichtbar, aber gesperrt, bis eine
  spätere Verwaltungsphase sie freigibt; die gespeicherte Einstellung kann nie wahr werden, bevor
  diese Sperre geöffnet ist.
- **Refresh status** – führt die Fail-Closed-IIS-Prüfung erneut aus (Registrierung `InetStp`,
  schreibgeschütztes `dism /English /Online /Get-FeatureInfo`, Prüfung des Dienstes W3SVC) und
  zeigt ein einzeiliges Urteil.
- **Install IIS** – geführte, idempotente Installation auf Basis von `IisInstallPlan`, der
  einzigen Quelle der Wahrheit sowohl für die Prüfliste vor dem Lauf als auch für den
  ausgeführten Ablauf. Das Fortschrittsfenster listet jeden Punkt auf, bevor etwas läuft, und
  zeichnet pro Punkt einen Haken oder ein Kreuz: erhöhte Rechte, die statische DISM-Featuremenge
  (`IIS-WebServerRole`, `IIS-WebServer`, `IIS-StaticContent`, `IIS-DefaultDocument`,
  `IIS-HttpErrors` über `dism ... /NoRestart`), die IIS-Verwaltungswerkzeuge
  (`IIS-WebServerManagementTools`, `IIS-ManagementScriptingTools`, die das von Configure IIS
  genutzte `appcmd.exe` bereitstellen), das über
  `winget install --id Microsoft.DotNet.HostingBundle.8 --exact` installierte ASP.NET Core
  Hosting Bundle als einzige Quelle des nativen `AspNetCoreModuleV2` und eine abschließende
  Prüfung dessen, was tatsächlich auf der Maschine vorhanden ist. Der Schritt für das Bundle
  wird übersprungen, wenn das Modul bereits vorhanden ist, sodass winget nie zweimal für dieselbe
  Maschine aufgerufen wird, und der DISM-Exitcode 3010 wird als Warnung mit der Bitte um einen
  Neustart gemeldet – nie als Erfolg.
- **Configure IIS** – geführte Einrichtung der Website `RdpAuditWebUi`: erfordert erhöhte Rechte
  plus das ASP.NET Core Module v2 (Hosting Bundle), ermittelt oder erstellt das
  Loopback-HTTPS-Zertifikat, speichert das Web-Token ausschließlich als DPAPI-geschützten
  Umschlag in der `appsettings.json` des Dienstes, stellt die Nutzlast von RdpAudit.Web nach
  `%ProgramData%\RdpAudit\WebUI` bereit, bindet die Website an
  `https://127.0.0.1:443` und startet den Dienst neu.

Beide Workflow-Schaltflächen bleiben deaktiviert, bis die Prüfung den IIS-Zustand tatsächlich
erklären kann. Der Browser sieht das Bearer-Token nie: Der prozessinterne YARP-Proxy fügt es aus
dem DPAPI-Tresor im Maschinenbereich ein und entfernt jeden vom Browser gelieferten
`Authorization`-Header; ein Host-Filter weist zusätzlich Nicht-Loopback-Hostnamen zurück
(Abwehr von DNS-Rebinding).

## 7. RdpAudit.Core — Gemeinsame Bibliothek

### 7.1. Datenmodelle

Zu den zentralen Entitäten gehören:

| Typ | Beschreibung |
|------|-------------|
| `RdpConnectionFact` | Datensatz eines RDP-Verbindungsfakts |
| `AuthAttemptFact` | Fakt eines Authentifizierungsversuchs |
| `Session` | Metadaten einer RDP-Sitzung |
| `SessionIpCorrelation` | Zuordnung von Sitzung zu IP |
| `AttackStat` | Aggregierte Angriffskennzahlen |
| `AttackThreatLevel` | Enumeration des Bedrohungsgrads |
| `AttackThreatScoring` | Logik der Bedrohungsbewertung |
| `AttackStatProjection` | Für die Oberfläche bestimmte Projektion der Angriffsstatistik |
| `ActiveBlock` | Datensatz einer aktiven Sperrung |
| `BlocklistEntry` | Eintrag einer dauerhaften Sperrliste |
| `WhitelistEntry` | Eintrag einer vertrauenswürdigen IP oder eines CIDR-Bereichs |
| `Alert` | Datensatz eines Alarms |
| `AbuseReport` | Nutzlast einer AbuseIPDB-Meldung |
| `AbuseIpDbReportHistory` | Meldehistorie und Deduplizierung |
| `RawEvent` | Normalisierter Rohereignis-Datensatz |
| `OperationLog` | Datensatz des Betriebsprotokolls des Dienstes |
| `LoginRule` | Zeitbasierte Zugriffsregel |
| `Bookmark` | Lesezeichen der Ereignisverarbeitung |
| `DbProp` | Schlüssel-Wert-Datensatz für Metadaten |
| `ThreatIntelLookup` | Zwischengespeicherter Reputations-Snapshot pro IP aus /api/v2/check (Stage 15) |
| `ThreatIntelUsageCounter` | Persistierter Tageszähler des /check-Budgets (Stage 15) |
| `Address` | IP-Adresse und zugehörige Metadaten |

### 7.2. Entity Framework Core und Migrationen

- EF Core 8 mit SQLite
- `AppDbContext` für die Hoheit über das Schema und die Abfrageunterstützung
- Automatische Anwendung von Migrationen beim Start des Dienstes
- EF Core bleibt für Konfiguration, Migrationen und Lesen in der Oberfläche reserviert
- Schreibvorgänge im Hot Path laufen über rohe SQLite-Befehle und explizite Transaktionen

### 7.3. IPC-Verträge (MessagePack)

IPC-Anfragen und -Antworten werden mit **MessagePack** serialisiert. Repräsentative Verträge sind:
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

## 8. Externe Integrationen

### 8.1. AbuseIPDB

RDPAudit kann angreifende IPs an [AbuseIPDB](https://www.abuseipdb.com/) melden, wenn Brute-Force- oder hochsicheres bösartiges Verhalten erkannt wird.

**Hinweise zum Entwurf:**
- API-Schlüssel werden als DPAPI-geschützte Werte gespeichert
- Doppelte Meldungen werden über die lokale Historie unterdrückt
- Ratenlimits werden eingehalten
- Meldekategorien sind konfigurierbar

RDPAudit kann die IP-Reputation auch lesend abfragen: Das optional zuschaltbare
Threat-Intelligence-Feature (`AbuseIpDb.CheckEnabled`) führt GET /api/v2/check über einen
Hintergrund-Worker aus, wärmt einen Datenträger-Cache für öffentliche IPs von Angriffsquellen und
zeigt eine Markierung **High risk** in den Tabellen Attack Statistics und Live Events. Der
API-Schlüssel wird nur im Header `Key` gesendet und nie protokolliert.

### 8.2. MikroTik RouterOS v7

RDPAudit kann bösartige IPs über die RouterOS-v7-REST-API in eine MikroTik-Adressliste eintragen.

**Hinweise zum Entwurf:**
- Arbeitet über HTTPS-REST-Endpunkte
- Unterstützt konfigurierbare TLS-Validierung
- Speichert Anmeldedaten DPAPI-geschützt
- Vermeidet doppelte Einträge in der Adressliste
- Fällt bei nicht erreichbarem Router sauber zurück

---

## 9. Modell der automatischen Sperrung

### 9.1. Auslöseschwellen

Standardverhalten:
- **10 fehlgeschlagene Anmeldungen** von derselben IP innerhalb von **10 Minuten** lösen eine Sperrung aus
- Schwellenwerte sind über **Settings** konfigurierbar
- Quellen auf der Whitelist werden ausgeschlossen, bevor eine Sperrung angewendet wird

### 9.2. Lokale Windows-Firewall

```text
Provider: WindowsFirewallProvider
Action:   Create inbound rule "RdpAudit_Block_<IP>" (block, any protocol)
Reverse:  Remove rule by name
Verify:   netsh advfirewall firewall show rule name="RdpAudit_Block_<IP>"
```

### 9.3. Remote-MikroTik-Firewall

```text
Provider: MikroTikFirewallProvider
Action:   PUT /rest/ip/firewall/address-list { address: <IP>, list: "RdpAudit-Blocklist" }
Reverse:  DELETE /rest/ip/firewall/address-list/<id>
Verify:   GET /rest/ip/firewall/address-list?address=<IP>
```

### 9.4. Whitelist-Schutz für vertrauenswürdige IPs

- Unterstützt einzelne IPs und CIDR-Bereiche
- Wird vor jeder Erstellung einer Sperrung ausgewertet
- Wird über die GUI verwaltet
- Wird in `WhitelistEntries` mit auditfreundlichen Metadaten gespeichert

---

## 10. Datenwartung

### 10.1. Bereinigung nach Aufbewahrungsfristen

Ein Worker für die Bereinigung löscht regelmäßig veraltete Datensätze.

| Tabelle | Standard-Aufbewahrung | Konfigurierbar |
|-------|-------------------|-------------|
| `RawEvents` | 90 Tage | Ja |
| `Alerts` | 180 Tage | Ja |
| `AbuseIpDbReportHistory` | 365 Tage | Ja |
| `ActiveBlocks` (inaktiv) | 30 Tage | Ja |
| `AttackStats` | 365 Tage | Ja |

**Hinweise zur Umsetzung:**
- Gebündelte Löschvorgänge
- Exponentielles Backoff bei `SQLITE_BUSY`
- Unterstützung von Abbruchsignalen
- Protokollierung der Vorgänge

### 10.2. Sicherung und Wiederherstellung

Der Sicherungsablauf erfasst den Konfigurationszustand, nicht die Ereignisdatenbank.

**In der Sicherung enthalten:**
- `appsettings.json` ausschließlich mit DPAPI-Umschlägen
- Export der Auditrichtlinie
- Relevante Registrierungsschlüssel
- Metadaten der Dienstkonfiguration

**Nicht enthalten:**
- `rdpaudit.db`

Vor jedem Wiederherstellungsvorgang wird ein Sicherheits-Snapshot erstellt.

---

## 11. Sicherheit und Auditierung

### 11.1. Zugriffskontrolle

| Komponente | Zugriffsmodell |
|-----------|--------------|
| `RdpAudit.Service` | Läuft als `SYSTEM` oder unter einer dedizierten Dienstidentität |
| Named-Pipe-IPC | Nur `BUILTIN\Administrators` |
| `RdpAudit.Configurator` | Erfordert erhöhte Rechte |
| SQLite-Datenbank | Beschränkt auf `SYSTEM` und `Administrators` |
| `appsettings.json` | Beschränkt auf `SYSTEM` und `Administrators` |

### 11.2. SACL-Konfiguration

Der Konfigurator setzt SACLs auf sicherheitsrelevanten Zielen, damit sensible Änderungen auditierbar werden:
- IFEO-Schlüssel für Barrierefreiheit
- Registrierungskonfiguration von `RDP-Tcp`
- Registrierungskonfiguration von `Lsa`

Dies unterstützt die Erkennung von Sticky-Keys-Hintertüren, Änderungen des RDP-Ports und Manipulationen an LSASS/PPL.

### 11.3. Schutz von Geheimnissen (DPAPI)

- AbuseIPDB-Schlüssel und MikroTik-Anmeldedaten sind mit Windows DPAPI geschützt
- In der Konfiguration liegen ausschließlich DPAPI-Umschläge
- Die GUI gibt keine Geheimnisse im Klartext preis
- Sicherungen enthalten geschützte Werte, keine entschlüsselten

---

## 12. Konfiguration

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

### 12.2. Umgebungsvariablen

Konfigurationswerte lassen sich über Umgebungsvariablen überschreiben, was für automatisierte Bereitstellung und Diagnose nützlich ist:

```text
RDPAUDIT_RdpAudit__LogLevel=Debug
RDPAUDIT_RdpAudit__AlertRules__BruteForce__FailThreshold=5
```

---

## 13. Debugging und Diagnose

### 13.1. Konsolenmodus

Wenn ein Debugger angehängt ist, kann der Dienst als Konsolenanwendung statt als förmlicher Windows-Dienst laufen.

```powershell
cd src\RdpAudit.Service
dotnet run --configuration Debug
```

### 13.2. Serilog-Protokolle

Protokolle werden geschrieben nach:
- `%ProgramData%\RdpAudit\logs\rdpaudit-<date>.log`
- Windows-Ereignisprotokoll → `Application`, Quelle `RdpAudit`

Zur Erhöhung der Ausführlichkeit:

```powershell
$env:RDPAUDIT_RdpAudit__LogLevel = "Debug"
```

### 13.3. Direkter SQLite-Zugriff

```powershell
& "C:\Program Files\DB Browser for SQLite\DB Browser for SQLite.exe" `
  "$env:ProgramData\RdpAudit\rdpaudit.db"
```

Nützliche Abfragen:

```sql
SELECT * FROM RawEvents ORDER BY TimeUtc DESC LIMIT 100;

SELECT * FROM ActiveBlocks WHERE Status = 'Active';

SELECT SourceIp, SUM(FailCount) AS Fails
FROM AttackStats
GROUP BY SourceIp
ORDER BY Fails DESC
LIMIT 20;
```

### 13.4. Registerkarte Diagnostics

Die Diagnoseoberfläche zeigt:
- Zähler für Ereignisse pro Sekunde
- Status der Worker
- Zustand der IPC
- Zustand der Datenbank
- Erreichbarkeit externer Integrationen

---

## 14. Build und Test

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

Jeder Test einer Alarmregel sollte prüfen:
1. Verhalten an der Schwellenwertgrenze
2. Verhalten bei Umgehung über die Whitelist
3. Keine verwalteten Allokationen über wiederholte Auswertungen hinweg

### 14.3. Veröffentlichen

```powershell
./publish.ps1
```

Erwartete Ausgabe:

```text
publish/
├── Service/
└── Configurator/
```

---

## 15. Fehlerbehebung

Ausführliche Hinweise: [`docs/91-troubleshooting.md`](docs/91-troubleshooting.md)

| Symptom | Erster Diagnoseschritt |
|---------|-----------------------|
| Dienst startet nicht | `sc.exe query RdpAudit` prüfen, dann das Anwendungsereignisprotokoll auswerten |
| Es erscheinen keine Live-Ereignisse | **Prerequisites** öffnen und die Auditkonfiguration bestätigen |
| GUI kann keine Verbindung herstellen | Prüfen, ob der Dienst läuft und die ACL der Pipe korrekt ist |
| `sc.exe` gibt 1639 zurück | Quotierung im Pfad der Dienstbinärdatei erneut prüfen |
| AbuseIPDB gibt HTTP 429 zurück | Das Ratenlimit der API ist erreicht |
| TLS-Fehler bei MikroTik | Validierung für selbstsignierte Zertifikate deaktivieren oder das CA-Zertifikat installieren |
| `SQLITE_BUSY` erscheint | Kurzfristige Konkurrenz ist zu erwarten und wird automatisch wiederholt |
| Auditrichtlinie zeigt `?` | Über die Registerkarte Audit Policy erneut anwenden |
| ACL-Probleme in ProgramData | Ordner-ACLs für `SYSTEM` und `Administrators` reparieren |

Siehe auch: [`docs/90-windows-validation.md`](docs/90-windows-validation.md)

---

## 16. Roadmap (v2.0 → v3.0)

| Funktion | Status |
|---------|--------|
| ETW-Übernahme (`OpenTrace` / `ProcessTrace`) | Geplant |
| Direktes Parsen von EVTX mit `Span<byte>` | Geplant |
| Sperrfreier MPMC-Ringpuffer | Geplant |
| SIMD-Beschleunigung von CIDR und Parsing | Geplant |
| Allokationsfreie Normalisierung von Ereignissen | Geplant |
| Sichtbarkeit auf Netzwerkebene für MS-RDPBCGR / RDPEUDP | Forschung |
| Web-Oberfläche auf Basis von Blazor | Geplant |
| Integration mit Elastic / OpenSearch | Roadmap |
| Zentraler Sammler für mehrere Server | Roadmap |

---

## 17. Lizenz und Autor

**Lizenz:** [Business Source License 1.1](LICENSE)

RDPAudit Community ist source-available. Sie dürfen die Software kopieren, ändern, weitergeben und für
Nicht-Produktionszwecke nutzen; die in `LICENSE` geschriebene Additional Use Grant erlaubt zusätzlich
die Produktionsnutzung, ausgenommen das Anbieten der Software an Dritte als kommerzieller gehosteter oder
verwalteter Dienst. Am **2030-10-25** wandelt sich diese Version in die Apache License 2.0 um.

Die Editionen Pro und Enterprise sind proprietär und **nicht** von dieser Lizenz abgedeckt – jede
führt eigene Bedingungen. Welche Funktion zu welcher Edition gehört, ist in
[docs/editions.md](docs/editions.md) dokumentiert.

**Autor:** Mikhail Deynekin
- Website: [deynekin.com](https://deynekin.com)
- E-Mail: [Mikhail@Deynekin.com](mailto:Mikhail@Deynekin.com)
- GitHub: [github.com/paulmann](https://github.com/paulmann)

**Repository:** [github.com/paulmann/RDPAudit](https://github.com/paulmann/RDPAudit)

**Weiterführende Ressourcen:**
- [Technische Spezifikation v1.0](https://github.com/paulmann/1st-RDPMon/wiki/RdpAudit-Service-%E2%80%90-Technical-Specification-v1.0)
- [Technische Spezifikation v2.0](https://github.com/paulmann/1st-RDPMon/wiki/RdpAudit-Service-%E2%80%90-Technical-Specification-v2.0)
- [Issues und Funktionswünsche](https://github.com/paulmann/RDPAudit/issues)

---

> © 2025–2026 Mikhail Deynekin. Veröffentlicht unter der [Business Source License 1.1](LICENSE).
