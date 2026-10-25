# RDPAudit — Plataforma de monitorización de seguridad RDP y bloqueo automático para Windows.

[![Versión](https://img.shields.io/badge/version-2.0.2-blue.svg)](https://github.com/paulmann/RDPAudit)
[![Licencia](https://img.shields.io/badge/License-BSL%201.1-blue.svg)](LICENSE)
[![.NET](https://img.shields.io/badge/dotnet-8.0--windows-blue.svg)](https://dotnet.microsoft.com/)
[![Plataforma](https://img.shields.io/badge/platform-Windows%2010%2B%20%2F%20Server%202016%2B-blue.svg)](https://www.microsoft.com/windows/)
[![SQLite](https://img.shields.io/badge/sqlite-WAL%20mode-orange.svg)](https://sqlite.org/)

<!-- md-i18n:switcher -->
**En otros idiomas:** [English](README.md) · [Deutsch](README.de.md) · [中文](README.zh.md) · [हिन्दी](README.hi.md) · Español · [Русский](README.ru.md)

> **RDPAudit** es una plataforma Windows lista para producción destinada a monitorizar la actividad RDP y responder a las amenazas basadas en RDP.  
> Consta de un **servicio de Windows** (recopilación de eventos en segundo plano, 21 reglas de alerta, bloqueo automático) y de un **Configurador WinForms** (GUI para gestión, estadísticas, diagnóstico y configuración de políticas).

---

## Índice

- [1. Descripción general del producto](#1-descripción-general-del-producto)
  - [1.1. Propósito](#11-propósito)
  - [1.2. Arquitectura de la solución](#12-arquitectura-de-la-solución)
  - [1.3. Capacidades principales](#13-capacidades-principales)
- [2. Requisitos del sistema](#2-requisitos-del-sistema)
  - [2.1. Requisitos mínimos](#21-requisitos-mínimos)
  - [2.2. Requisitos de auditoría de Windows](#22-requisitos-de-auditoría-de-windows)
- [3. Estructura de la solución](#3-estructura-de-la-solución)
  - [3.1. Proyectos y capas](#31-proyectos-y-capas)
  - [3.2. Estructura de directorios](#32-estructura-de-directorios)
- [4. Inicio rápido](#4-inicio-rápido)
  - [4.1. Compilación](#41-compilación)
  - [4.2. Instalación del servicio](#42-instalación-del-servicio)
  - [4.3. Primer arranque del Configurador](#43-primer-arranque-del-configurador)
- [5. RdpAudit.Service — Servicio de monitorización](#5-rdpauditservice--servicio-de-monitorización)
  - [5.1. Recopilación de eventos](#51-recopilación-de-eventos)
  - [5.2. Identificadores de evento seguidos](#52-identificadores-de-evento-seguidos)
  - [5.3. Almacenamiento de datos (SQLite)](#53-almacenamiento-de-datos-sqlite)
  - [5.4. Sistema de alertas — 21 reglas](#54-sistema-de-alertas--21-reglas)
  - [5.5. Bloqueo automático en el Firewall de Windows](#55-bloqueo-automático-en-el-firewall-de-windows)
  - [5.6. IPC por Named Pipe](#56-ipc-por-named-pipe)
  - [5.7. Fiabilidad y resiliencia](#57-fiabilidad-y-resiliencia)
  - [5.8. API REST (solo lectura)](#58-api-rest-solo-lectura)
- [6. RdpAudit.Configurator — GUI](#6-rdpauditconfigurator--gui)
  - [6.1. Pestaña Resumen](#61-pestaña-resumen)
  - [6.2. Pestaña Requisitos previos](#62-pestaña-requisitos-previos)
  - [6.3. Pestaña Política de auditoría](#63-pestaña-política-de-auditoría)
  - [6.4. Pestaña Servicio](#64-pestaña-servicio)
  - [6.5. Pestaña Configuración](#65-pestaña-configuración)
  - [6.6. Pestaña Eventos en vivo](#66-pestaña-eventos-en-vivo)
  - [6.7. Pestaña Firewall](#67-pestaña-firewall)
  - [6.8. Pestaña Estadísticas de ataque](#68-pestaña-estadísticas-de-ataque)
  - [6.9. Pestaña Clientes RDP remotos](#69-pestaña-clientes-rdp-remotos)
  - [6.10. Pestaña AbuseIPDB](#610-pestaña-abuseipdb)
  - [6.11. Pestaña MikroTik](#611-pestaña-mikrotik)
  - [6.12. Pestaña Registros](#612-pestaña-registros)
  - [6.13. Pestaña Diagnóstico](#613-pestaña-diagnóstico)
- [6.14. Pestaña Mapa de sesiones](#614-pestaña-mapa-de-sesiones)
- [6.15. Pestaña Notificaciones](#615-pestaña-notificaciones)
- [6.16. Pestaña Acceso web](#616-pestaña-acceso-web)
- [7. RdpAudit.Core — Biblioteca compartida](#7-rdpauditcore--biblioteca-compartida)
  - [7.1. Modelos de datos](#71-modelos-de-datos)
  - [7.2. Entity Framework Core y migraciones](#72-entity-framework-core-y-migraciones)
  - [7.3. Contratos IPC (MessagePack)](#73-contratos-ipc-messagepack)
- [8. Integraciones externas](#8-integraciones-externas)
  - [8.1. AbuseIPDB](#81-abuseipdb)
  - [8.2. MikroTik RouterOS v7](#82-mikrotik-routeros-v7)
- [9. Modelo de bloqueo automático](#9-modelo-de-bloqueo-automático)
  - [9.1. Umbrales de disparo](#91-umbrales-de-disparo)
  - [9.2. Firewall de Windows local](#92-firewall-de-windows-local)
  - [9.3. Firewall remoto MikroTik](#93-firewall-remoto-mikrotik)
  - [9.4. Protección de lista blanca para IP de confianza](#94-protección-de-lista-blanca-para-ip-de-confianza)
- [10. Mantenimiento de datos](#10-mantenimiento-de-datos)
  - [10.1. Depuración por retención](#101-depuración-por-retención)
  - [10.2. Copia de seguridad y restauración](#102-copia-de-seguridad-y-restauración)
- [11. Seguridad y auditoría](#11-seguridad-y-auditoría)
  - [11.1. Control de acceso](#111-control-de-acceso)
  - [11.2. Configuración de SACL](#112-configuración-de-sacl)
  - [11.3. Protección de secretos (DPAPI)](#113-protección-de-secretos-dpapi)
- [12. Configuración](#12-configuración)
  - [12.1. appsettings.json](#121-appsettingsjson)
  - [12.2. Variables de entorno](#122-variables-de-entorno)
- [13. Depuración y diagnóstico](#13-depuración-y-diagnóstico)
  - [13.1. Modo consola](#131-modo-consola)
  - [13.2. Registros de Serilog](#132-registros-de-serilog)
  - [13.3. Acceso directo a SQLite](#133-acceso-directo-a-sqlite)
  - [13.4. Pestaña Diagnóstico](#134-pestaña-diagnóstico)
- [14. Compilación y pruebas](#14-compilación-y-pruebas)
  - [14.1. Compilación](#141-compilación)
  - [14.2. Pruebas](#142-pruebas)
  - [14.3. Publicación](#143-publicación)
- [15. Resolución de problemas](#15-resolución-de-problemas)
- [16. Hoja de ruta (v2.0 → v3.0)](#16-hoja-de-ruta-v20--v30)
- [17. Licencia y autor](#17-licencia-y-autor)

---

## 1. Descripción general del producto

### 1.1. Propósito

**RDPAudit** está diseñado para monitorizar de forma continua la actividad RDP en servidores y estaciones de trabajo Windows. El producto se ejecuta en segundo plano como servicio del sistema, incluso cuando no hay ningún usuario interactivo con sesión iniciada, registra intentos de conexión, eventos de autenticación y cambios del sistema de alto valor, los evalúa mediante 21 reglas de seguridad y puede bloquear automáticamente a los atacantes a través del Firewall de Windows y/o de MikroTik RouterOS.

**Casos de uso típicos:**
- Proteger extremos RDP expuestos a Internet frente a ataques de fuerza bruta
- Cubrir los requisitos de SOC2, ISO 27001 y auditoría interna sobre el acceso privilegiado
- Detectar patrones de compromiso de cuenta, como un inicio de sesión correcto tras fallos repetidos
- Identificar puertas traseras en binarios de accesibilidad, como el abuso de Sticky Keys y Utilman
- Detectar ataques contra LSA/LSASS, pulverización Kerberos y cambios de puerto RDP
- Integrarse con MikroTik para bloquear IP maliciosas en el borde de la red

### 1.2. Arquitectura de la solución

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

### 1.3. Capacidades principales

- **Monitorización en tiempo real** mediante suscripciones `EventLogWatcher` en lugar de sondeo
- **21 reglas de alerta** que cubren fuerza bruta, ataques a LSASS, pulverización Kerberos, cambios de política sospechosos y más
- **Bloqueo automático** mediante reglas del Firewall de Windows por IP, con posibilidad de reversión manual
- **Integración con MikroTik** a través de las API REST de RouterOS v7 con credenciales protegidas con DPAPI
- **Reporte a AbuseIPDB** con deduplicación local y respeto de los límites de tasa
- **Comprobaciones de reputación de threat-intel** (Backlog #5) - consultas en segundo plano a AbuseIPDB /api/v2/check con caché en disco y una marca High risk en Attack Statistics y Live Events
- **Analítica de amenazas** agregada por IP, país, intervalo de tiempo y nivel de amenaza calculado
- **Correlación sesión-IP** para asociar las sesiones RDP con sus direcciones de origen
- **Depuración por retención** para la estabilidad a largo plazo y un crecimiento menor de la base de datos
- **Copia de seguridad y restauración** del estado de configuración, sin secretos en texto plano
- **IPC por Named Pipe seguro** restringido a `BUILTIN\Administrators`
- **API REST HTTPS de solo lectura** (opcional, desactivada por defecto) con autenticación por token bearer, limitación de tasa por IP y un descriptor OpenAPI
- **Exportación SIEM** (CEF / LEEF 2.0 / NDJSON) de los eventos por IP y de las alertas correlacionadas desde las páginas Live Events y Attack Statistics

---

## 2. Requisitos del sistema

### 2.1. Requisitos mínimos

| Componente | Requisito |
|-----------|-------------|
| SO | Windows 10 o Windows Server 2016 y posteriores (x64) |
| .NET Runtime | .NET 8.0 para Windows (x64) |
| Privilegios | Administrador local para la instalación del servicio y la configuración del sistema |
| Disco | 200 MB para los binarios más espacio para la base de datos de eventos |
| Memoria | 64 MB de working set para el servicio en carga normal |

### 2.2. Requisitos de auditoría de Windows

RDPAudit depende de la auditoría de seguridad de Windows para recibir los eventos que analiza. Para un funcionamiento correcto deben estar habilitadas las siguientes categorías de auditoría:

| Categoría de auditoría | GUID de subcategoría | Propósito |
|----------------|------------------|---------|
| Logon / Logoff | `{0CCE9215-69AE-11D9-BED3-505054503030}` | Eventos 4624, 4625, 4634 |
| Account Logon | `{0CCE9240-69AE-11D9-BED3-505054503030}` | Eventos Kerberos |
| Process Creation | `{0CCE922B-69AE-11D9-BED3-505054503030}` | Evento 4688 y visibilidad de procesos |
| Object Access | `{0CCE9217-69AE-11D9-BED3-505054503030}` | Eventos respaldados por SACL como 4656 y 4663 |
| Policy Change | `{0CCE922F-69AE-11D9-BED3-505054503030}` | Visibilidad de cambios de firewall y de política |

El Configurador aplica estos ajustes automáticamente mediante llamadas a `auditpol.exe` con identificadores basados en GUID, lo que hace que el proceso sea independiente de la configuración regional.

---

## 3. Estructura de la solución

### 3.1. Proyectos y capas

| Proyecto | Tipo | Responsabilidad |
|--------|------|----------------|
| `RdpAudit.Core` | Biblioteca de clases (`net8.0-windows`) | Entidades, `DbContext` de EF Core, migraciones, contratos IPC MessagePack, utilidades compartidas |
| `RdpAudit.Service` | Worker Service (`net8.0-windows`, `win-x64`) | Recopilación de eventos, normalización, evaluación de alertas, bloqueo automático, servidor IPC |
| `RdpAudit.Configurator` | Aplicación WinForms (`net8.0-windows`) | GUI, cliente IPC, comprobación de requisitos previos, control del servicio, flujos de configuración |
| `RdpAudit.Web` | Aplicación ASP.NET Core (`net8.0-windows`) | Panel web de solo lectura alojado en IIS y proxy YARP de loopback: inyección del token bearer desde el almacén DPAPI, cabeceras de seguridad, TLS del backend fijado |
| `RdpAudit.Core.Tests` | xUnit | Pruebas unitarias del núcleo |
| `RdpAudit.Service.Tests` | xUnit | Pruebas de reglas de alerta, validación de umbrales, cobertura de la lista blanca, comprobaciones de asignaciones |
| `RdpAudit.Web.Tests` | xUnit | Pruebas de integración del proxy web: filtro de host, inyección del token bearer, contrato estático de CSP/DOM |
| `RdpAudit.Benchmarks` | BenchmarkDotNet | Cobertura de benchmarks para las rutas críticas |

### 3.2. Estructura de directorios

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

## 4. Inicio rápido

### 4.1. Compilación

```powershell
git clone https://github.com/paulmann/RDPAudit.git
cd RDPAudit
dotnet build RdpAudit.sln -c Release
```

### 4.2. Instalación del servicio

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

### 4.3. Primer arranque del Configurador

```powershell
publish/Configurator/RdpAudit.Configurator.exe
```

En el primer arranque, la secuencia recomendada es:

1. Abra **Requisitos previos** y verifique los canales necesarios y los ajustes de plataforma.
2. Abra **Política de auditoría** y aplique las subcategorías de auditoría necesarias mediante `auditpol.exe`.
3. Abra **Servicio** e instale o inicie el servicio de Windows.
4. Abra **Configuración** y ajuste los umbrales de alerta, las IP de confianza, la retención y las integraciones.

---

## 5. RdpAudit.Service — Servicio de monitorización

### 5.1. Recopilación de eventos

El servicio usa `System.Diagnostics.Eventing.Reader.EventLogWatcher` para suscribirse a los eventos relevantes en tiempo real. El diseño ya está abstraído tras interfaces de origen de eventos, de modo que la parte de recopilación puede pasar más adelante a una ingesta basada en ETW sin reescribir el resto del pipeline.

**Canales monitorizados:**
- `Security`
- `Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational`
- `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational`

### 5.2. Identificadores de evento seguidos

| Event ID | Canal | Descripción |
|----------|---------|-------------|
| 4624 | Security | Inicio de sesión correcto, especialmente Logon Type 10 |
| 4625 | Security | Inicio de sesión fallido |
| 4634 | Security | Cierre de sesión |
| 4647 | Security | Cierre de sesión iniciado por el usuario |
| 4648 | Security | Inicio de sesión con credenciales explícitas |
| 4688 | Security | Creación de proceso |
| 4720 | Security | Cuenta de usuario creada |
| 4723 / 4724 | Security | Cambio de contraseña / restablecimiento de contraseña |
| 4740 | Security | Bloqueo de cuenta |
| 4769 | Security | Solicitud de ticket de servicio Kerberos |
| 4771 | Security | Fallo de preautenticación Kerberos |
| 4776 | Security | Autenticación NTLM |
| 4954 | Security | Cambio de regla o de política del Firewall de Windows |
| 1149 | TerminalServices-RCM | Conexión RDP con IP de origen |
| 21, 23, 24, 25 | TerminalServices-LSM | Inicio, reconexión, desconexión y fin de sesión |

### 5.3. Almacenamiento de datos (SQLite)

La base de datos se guarda en `%ProgramData%\RdpAudit\rdpaudit.db`.

**Ajustes de SQLite:**
```sql
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
```

**Tablas principales:**

| Tabla | Propósito |
|-------|---------|
| `RawEvents` | Eventos de seguridad y RDP normalizados |
| `RdpConnectionFacts` | Hechos de conexión con IP, usuario y resultado |
| `AuthAttemptFacts` | Hechos de intentos de autenticación |
| `Sessions` | Registros de sesiones RDP |
| `SessionIpCorrelations` | Correlación sesión-IP |
| `AttackStats` | Estadísticas de ataque agregadas por origen |
| `ActiveBlocks` | Bloqueos automáticos activos en este momento |
| `Alerts` | Historial de alertas |
| `WhitelistEntries` | Entradas de IP y CIDR de confianza |
| `BlocklistEntries` | Reglas de bloqueo persistentes y sus orígenes |
| `AbuseIpDbReportHistory` | Historial de reportes a AbuseIPDB |
| `OperationLogs` | Entradas del registro operativo mostradas en la GUI |
| `DbProps` | Almacén de metadatos clave-valor |
| `Bookmarks` | Marcadores de recuperación tras caída del procesamiento de eventos |
| `LoginRules` | Reglas de horario laboral y de política de inicio de sesión |

**Estrategia de escritura:** la ruta crítica usa `SqliteCommand` directo con transacciones explícitas y escrituras por lotes.

**Durabilidad de los marcadores:** los marcadores se vuelcan cada 100 eventos y cada 30 segundos, lo que minimiza las pérdidas tras una caída o un corte de corriente.

### 5.4. Sistema de alertas — 21 reglas

Cada regla se implementa como un evaluador de alertas dedicado y participa en un pipeline de reglas común.

| # | ID de regla | Severidad | Descripción |
|---|---------|----------|-------------|
| 1 | `BRUTE_FORCE` | Alta | Los inicios de sesión fallidos desde el mismo origen superan el umbral |
| 2 | `BRUTE_FORCE_NTLM` | Alta | Fuerza bruta NTLM con lógica de enfriamiento |
| 3 | `KERBEROS_SPRAY` | Alta | Comportamiento de pulverización de contraseñas Kerberos |
| 4 | `SUCCESSFUL_AFTER_FAILS` | Media | Inicio de sesión correcto tras fallos repetidos |
| 5 | `OFF_HOURS_LOGIN` | Media | Inicio de sesión fuera del horario laboral aprobado |
| 6 | `ACCOUNT_LOCKOUT` | Media | Evento de bloqueo de cuenta |
| 7 | `NEW_ACCOUNT_CREATED` | Media | Se ha creado una cuenta local o de dominio nueva |
| 8 | `PASSWORD_RESET` | Baja | Restablecimiento o cambio de contraseña |
| 9 | `MULTIPLE_ACCOUNTS_SAME_IP` | Alta | Pulverización de nombres de usuario desde una misma IP de origen |
| 10 | `STICKY_KEYS_BACKDOOR` | Crítica | Comportamiento de puerta trasera mediante binarios de accesibilidad |
| 11 | `LSASS_ACCESS` | Crítica | Acceso sospechoso a LSASS mediante handle |
| 12 | `LSASS_PPL_TAMPER` | Crítica | Intento de debilitar la protección PPL de LSASS |
| 13 | `RDP_PORT_CHANGED` | Alta | Cambio del puerto RDP detectado en el registro |
| 14 | `FIREWALL_RULE_CHANGED` | Media | Cambio de regla o de política del firewall |
| 15 | `EXPLICIT_CREDENTIALS` | Media | Patrón de uso de credenciales explícitas |
| 16 | `LOGON_TYPE_NETWORK` | Baja | Inicio de sesión de red en un sistema protegido |
| 17 | `CONCURRENT_SESSIONS` | Baja | Número excesivo de sesiones concurrentes |
| 18 | `GEO_ANOMALY` | Media | Inicio de sesión desde una ubicación geográfica no permitida o inesperada |
| 19 | `IP_REPUTATION` | Alta | La IP de origen aparece en listas de bloqueo conocidas |
| 20 | `SESSION_HIJACK_SUSPECT` | Alta | Anomalía en la correlación de sesiones |
| 21 | `RAPID_RECONNECT` | Media | Actividad de reconexión repetida desde la misma IP |

### 5.4.1. Endurecimiento de PRIVILEGED_LOGIN

La regla `PRIVILEGED_LOGIN` (evento 4672 - asignación de SeDebug / SeTcb en el inicio de sesión) está endurecida contra la tormenta de SID conocidos del arranque del servicio (alertas SYSTEM idénticas y sin IP de origen):

- **Filtro de SID exacto** - `S-1-5-18` (SYSTEM), `S-1-5-19` (LOCAL SERVICE) y `S-1-5-20` (NETWORK SERVICE) se rechazan por el SID exacto leído del JSON normalizado `Details` (`subjectUserSid`), nunca por nombres de cuenta localizados.
- **Contexto de red obligatorio** - el evento debe llevar un `SourceIp` no vacío y un tipo de inicio de sesión de red (3 / 7 / 10). Si falta `LogonType` (el 4672 de Windows no tiene campo propio), se recurre a correlacionar el 4624 de Security correspondiente mediante `SubjectLogonId == TargetLogonId`.
- **Ventana de supresión** - los disparadores idénticos por (usuario, ip de origen, tipo de inicio de sesión) se suprimen dentro de `PrivilegedLoginSuppressionWindowMinutes` (5 por defecto); al expirar la ventana, una única alerta resumen incluye el número de suprimidos.
- **Presupuesto de alertas por minuto** - `PrivilegedLoginRateLimitPerMinute` (20 por defecto) limita la salida; el estrangulamiento se registra una vez por minuto.
- **Filtro de antigüedad histórica** - los eventos más antiguos que `AlertEventMaxAgeMinutes` (5 por defecto) siguen persistiéndose como hechos `RawEvent` pero nunca generan alerta (lo aplica `AlertWorker` a todas las reglas).
- **Ruta de rechazo sin asignaciones** - `EvaluateAsync` es un método no async que devuelve una tarea nula singleton en caché, de modo que las evaluaciones rechazadas no asignan nada.

### 5.5. Bloqueo automático en el Firewall de Windows

Cuando se disparan reglas como `BRUTE_FORCE`, `BRUTE_FORCE_NTLM` o `IP_REPUTATION`, el servicio puede crear una regla de bloqueo entrante por IP.

```powershell
netsh advfirewall firewall add rule `
  name="RdpAudit_Block_<IP>" `
  dir=in action=block remoteip=<IP> `
  protocol=any enable=yes
```

**Características de la implementación:**
- Creación idempotente de reglas
- Saneamiento de la entrada antes de la ejecución en la shell
- Eliminación manual desde la GUI
- Auditoría completa mediante `ActiveBlocks` y `OperationLogs`

### 5.6. IPC por Named Pipe

**Nombre del pipe:** `\\.\pipe\RdpAuditService`

**Modelo de seguridad:** solo `BUILTIN\Administrators` puede conectarse.

**Protocolo:** contratos de petición y respuesta MessagePack definidos en `RdpAudit.Core`.

**Notas operativas:**
- La GUI nunca escribe directamente los archivos de configuración propiedad del servicio.
- Los ajustes se envían por IPC y el servicio los confirma de forma atómica.
- Los plazos de conexión impiden que el Configurador se quede colgado indefinidamente.
- El pipe lo sirve `IpcServerWorker`, que solicita `MaxConcurrent + 1` instancias del sistema operativo para que el pipe de reserva, siempre a la escucha, nunca compita con un manejador conectado. El error Win32 `ERROR_PIPE_BUSY` (231) se clasifica como «límite de instancias alcanzado», no como intercepción de antivirus o EDR; la saturación se drena automáticamente a medida que terminan los manejadores.
- Cada instancia de worker escribe hechos observables de su ciclo de vida en `%ProgramData%\RdpAudit\logs\ipc-startup.log`: `instance constructed` / `ExecuteAsync entered` / `ExecuteAsync exiting (pid, instanceId, entryCount, exitCount, iteration, activeHandlers, livePipes, stoppingTokenCancelled, hostApplicationStoppingCancelled, exitReason, lifetimeMs)`. Estos campos demuestran si un proceso llegó a ejecutar más de un worker o más de una instancia de host.

### 5.7. Fiabilidad y resiliencia

- Retroceso exponencial ante contención transitoria de la base de datos, como `SQLITE_BUSY`
- Propagación de `CancellationToken` de extremo a extremo en los flujos asíncronos
- Cada worker alojado se envuelve en `TimedHostedService` y escribe marcas de inicio, fin y fallo en `startup-sequence.log`
- `IpcServerWorker` registra rastros de ciclo de vida por instancia, de modo que un `ExecuteAsync entered` repetido en un mismo PID puede atribuirse a una o a varias instancias de worker/host
- Apagado ordenado al detener el servicio
- Migraciones de EF Core aplicadas en el arranque
- Registro del origen del registro de eventos durante la instalación

### 5.8. API REST (solo lectura)

El servicio puede exponer una **API REST HTTPS de solo lectura opcional** (Kestrel, desactivada por
defecto) para agentes de monitorización y scripts. Solo responde a `GET`/`HEAD` y reutiliza los
mismos comandos de lectura auditados que el named pipe, por lo que la superficie REST no tiene
rutas de escritura.

- **Endpoints**: `/healthz` (anónimo), `/api/status`, `/api/alerts`, `/api/sessions`,
  `/api/addresses`, `/api/attacks`, `/api/config` (secretos enmascarados),
  `/api/events` (página acotada, filtrada y ordenada) y
  `/openapi/v1.json` (descriptor OpenAPI 3.0 versionado en el repositorio).
- **Autenticación**: token bearer estático (`Api.Token`, protegido con DPAPI) con
  `WWW-Authenticate: Bearer realm="rdpaudit"` en las respuestas 401.
- **Transporte**: solo HTTPS. El listener usa `127.0.0.1:8443` por defecto; el certificado TLS de
  `LocalMachine\My` se selecciona mediante `Api.CertificateThumbprint` / `Api.CertificateSubject`.
  Los listeners que no son de loopback registran una advertencia de riesgo explícita en el arranque.
- **Endurecimiento**: limitación de tasa por IP con ventana fija (`Api.RateLimitPerMinute`),
  límite de conexiones (`Api.MaxConnections`), cabeceras de seguridad y cuerpos de error
  `problem+json` según RFC 9457 para toda respuesta que no sea 200.
- **Arranque fail-closed**: `Api.Enabled=false` (valor por defecto) o cualquier requisito previo
  ausente (token, certificado, dirección) implica que no se abre ningún listener.

La configuración está en la sección `Api` de `appsettings.json`. Referencia completa:
`docs/40-options.md` (ApiOptions) y `docs/51-rest-api.md` (endpoints, errores,
autenticación, operación).

---

## 6. RdpAudit.Configurator — GUI

El Configurador se ejecuta con elevación y se comunica con el servicio exclusivamente a través del canal IPC por Named Pipe.

### 6.1. Pestaña Resumen

La pestaña **Resumen** es el panel del operador. Resume el estado del servicio, el número de bloqueos activos, las alertas recientes y el volumen reciente de eventos.

### 6.2. Pestaña Requisitos previos

La pestaña **Requisitos previos** comprueba las condiciones de Windows necesarias:
- Los siete canales de registro de eventos monitorizados, presentes y habilitados (Security, System y
  los canales de Terminal Services / RDP)
- Las subcategorías de política de auditoría necesarias aplicadas (acceso a objetos + la base de
  cinco subcategorías)
- Servicio instalado y accesible

Un canal deshabilitado ofrece una corrección mediante `wevtutil sl /enabled:true`. Un canal que no
existe en esta compilación o edición de Windows (por ejemplo `TerminalServices-Gateway` en un host
sin el rol RD Gateway) se informa como ausente y sin corrección automática, de modo que la pestaña
nunca ofrece un botón de habilitación para un canal que esta edición de Windows no puede crear. Cada
fallo corregible puede aplicarse directamente desde la interfaz.

### 6.3. Pestaña Política de auditoría

La pestaña **Política de auditoría** lee la configuración de auditoría actual de Windows y aplica las subcategorías necesarias mediante llamadas a `auditpol.exe` basadas en GUID. También gestiona la configuración de SACL para ubicaciones del registro de alto valor y rutas IFEO relacionadas con la detección de abuso de RDP.

### 6.4. Pestaña Servicio

La pestaña **Servicio** permite:
- Instalar y desinstalar
- Iniciar, detener, reiniciar
- Mostrar el estado del servicio
- Controlar el modo de inicio

### 6.5. Pestaña Configuración

La pestaña **Configuración** expone la configuración operativa, incluidos:
- Umbrales de alerta
- Ventanas de fuerza bruta
- Definición de horarios laborales
- Ventanas de retención de datos
- Ajustes de AbuseIPDB
- Ajustes de MikroTik
- Ajustes de geolocalización y de lista blanca

Los cambios se envían por IPC y el servicio los aplica de forma atómica.

### 6.6. Pestaña Eventos en vivo

La pestaña **Eventos en vivo** ofrece un flujo de eventos en tiempo real tipo `tail`, con codificación por colores para fallos, advertencias y actividad correcta. Permite filtrar por Event ID y por IP de origen. Una columna **High risk** muestra la marca de threat-intel en caché (Stage 15) de cada IP de origen.

### 6.7. Pestaña Firewall

La pestaña **Firewall** muestra los bloqueos activos de `ActiveBlocks` y permite:
- Ver las IP bloqueadas, los motivos y los proveedores
- Añadir entradas de bloqueo manualmente
- Eliminar bloqueos con confirmación
- Importar o exportar listas de bloqueo

### 6.8. Pestaña Estadísticas de ataque

La pestaña **Estadísticas de ataque** presenta los datos de ataque agregados:
- IP atacantes principales
- Puntuación del nivel de amenaza
- Gráficos temporales
- Agrupación por país
- Soporte de exportación a CSV
- Columna **High risk** respaldada por la marca de threat-intel en caché (Stage 15)

El nivel de amenaza se calcula mediante la lógica de puntuación de `AttackThreatScoring`.

### 6.9. Pestaña Clientes RDP remotos

La pestaña **Clientes RDP remotos** correlaciona las IP de origen, el número de conexiones, los nombres de usuario y las sesiones RDP históricas. Su finalidad es separar la administración remota legítima del tráfico de ataque ruidoso.

### 6.10. Pestaña AbuseIPDB

La pestaña **AbuseIPDB** gestiona:
- La configuración de la clave de API
- Los flujos de reporte manuales y automáticos
- El historial de reportes con deduplicación
- El estado y la validación con conocimiento del límite de tasa
- Las comprobaciones de reputación de threat-intel (/api/v2/check) con estado de la caché, uso diario y umbral High-risk (Backlog #5)

Los secretos nunca se muestran de vuelta en texto plano.

### 6.11. Pestaña MikroTik

La pestaña **MikroTik** configura la integración REST de RouterOS v7:
- Dirección y puerto del router
- Credenciales protegidas con DPAPI
- Comportamiento de la validación TLS
- Sincronización de la address-list
- Prueba de conectividad

### 6.12. Pestaña Registros

La pestaña **Registros** muestra las entradas operativas de `OperationLogs`, agrupadas por severidad:
- `Info`
- `Warning`
- `Error`
- `Critical`

### 6.13. Pestaña Diagnóstico

La pestaña **Diagnóstico** proporciona datos de salud orientados al operador:
- Estado de los workers
- Salud del IPC
- Tamaño y estado de la base de datos
- Comprobaciones de integraciones
- Soporte de exportación de diagnóstico

### 6.14. Pestaña Mapa de sesiones

La pestaña **Mapa de sesiones** permite a un operador de SOC inspeccionar una sesión RDP
histórica como línea de tiempo cronológica (Backlog #6). Al seleccionar un hecho de la lista
acotada de sesiones (servida por el comando existente `ListConnectionFacts` con filtros de IP /
usuario) se carga la respuesta de `GetSessionTimeline` y se muestra dos veces:

- **Tabla de eventos** - hora, tipo (inicio de sesión / conectado / reconectado /
  desconectado / cierre de sesión / proceso / archivo / otro), event id, proceso, objeto
  y el método de correlación explícito. Las filas correlacionadas por `UserWindow` se tiñen
  de ámbar para que la menor confianza forense siempre sea visible; el detalle DEBUG en bruto está
  disponible en un tooltip solo cuando el servicio se ejecuta con el modo DEBUG activado.
- **Panel Gantt** - una línea de tiempo GDI+ integrada con eje temporal UTC,
  carriles codificados por color, leyenda, un haz discontinuo de «ahora» para las sesiones activas
  y una insignia `TRUNCATED` cuando se alcanza el límite de actividad del lado del servidor
  (50..2000, 500 por defecto).

El comando es estrictamente de solo lectura y no añade tablas ni migraciones; consulte
`docs/54-session-map.md` para el contrato, las reglas de correlación, el modelo de amenazas y
las indicaciones de reversión.

### 6.15. Pestaña Notificaciones

La pestaña **Notificaciones** configura la aplicación de bandeja `RdpAudit.Notifier`, que se ejecuta
con elevación:

- **Activar el notificador de bandeja** - interruptor maestro; cuando está desactivado, el notificador se cierra en silencio.
- **Iniciar con Windows** - registra o elimina la tarea de inicio de sesión `RdpAudit.Notifier` mediante `schtasks` (`ONLOGON`, `/RL HIGHEST`).
- **Intervalo de sondeo** - cadencia de sondeo del servicio en segundos (acotada a 1..60).
- **Severidad mínima** - las alertas por debajo de esta severidad nunca se muestran.
- **Máximo de avisos por minuto** - límite de tasa con ventana deslizante (acotado a 1..60); las alertas sobrantes se agrupan en un único aviso agregado.
- **Usar avisos nativos** - prefiere los avisos WinRT a los globos de la bandeja; el notificador vuelve a los globos cuando el canal nativo no está disponible.
- **Subpestañas Alertas / Eventos** - mapas de visibilidad por regla y por evento.

Guardar / Actualizar pasan por los comandos IPC `GetNotificationSettings` (78) y
`SaveNotificationSettings` (79); el servicio acota los valores, aplica `High` como severidad
de reserva y persiste únicamente la sección `RdpAudit.Notifications` de `appsettings.json`.
El notificador consulta el servicio por el named pipe, pasa a un intervalo seguro mientras
no es accesible y nunca modifica la base de datos.

---

### 6.16. Pestaña Acceso web

La pestaña **Acceso web** (situada justo después de **Servicio**) es el punto de entrada del
panel web de solo lectura alojado en IIS. Es **privacy-first**: todo permanece desactivado
hasta que el operador lo habilita explícitamente.

- **Mostrar acceso web** - guarda la elección de visibilidad del operador; desactivada por
  defecto y solo se almacena cuando el operador la cambia.
- **Permitir la gestión desde la web** - condicionada por fase: visible pero bloqueada hasta que
  una fase de gestión posterior la desbloquee; la preferencia almacenada nunca puede pasar a
  verdadera antes de que se abra esa puerta.
- **Actualizar estado** - vuelve a ejecutar la sonda fail-closed de IIS (registro `InetStp`,
  `dism /English /Online /Get-FeatureInfo` de solo lectura, comprobación del servicio W3SVC) y
  muestra un veredicto en una línea.
- **Instalar IIS** - instalación guiada e idempotente dirigida por `IisInstallPlan`, la
  única fuente de verdad tanto para la lista de comprobación previa como para el flujo ejecutado.
  La ventana de progreso enumera cada elemento antes de que se ejecute nada y pinta una marca o una
  cruz por elemento: elevación, el conjunto estático de características DISM (`IIS-WebServerRole`,
  `IIS-WebServer`, `IIS-StaticContent`, `IIS-DefaultDocument`, `IIS-HttpErrors` mediante
  `dism ... /NoRestart`), las herramientas de administración de IIS (`IIS-WebServerManagementTools`,
  `IIS-ManagementScriptingTools`, que proporcionan el `appcmd.exe` usado por Configurar IIS),
  el ASP.NET Core Hosting Bundle instalado con
  `winget install --id Microsoft.DotNet.HostingBundle.8 --exact` como única fuente
  del `AspNetCoreModuleV2` nativo, y una verificación final de lo que realmente hay en
  la máquina. El paso del bundle se omite cuando el módulo ya está presente, de modo que
  winget nunca se invoca dos veces en la misma máquina, y el código de salida 3010 de DISM se
  informa como una advertencia que pide reiniciar, nunca como éxito.
- **Configurar IIS** - configuración guiada del sitio `RdpAuditWebUi`: requiere
  elevación y el módulo ASP.NET Core v2 (Hosting Bundle), resuelve o
  crea el certificado HTTPS de loopback, almacena el token web únicamente como
  sobre protegido con DPAPI en el `appsettings.json` del servicio, copia los binarios de
  RdpAudit.Web en `%ProgramData%\RdpAudit\WebUI`, enlaza el sitio a
  `https://127.0.0.1:443` y reinicia el servicio.

Ambos botones de flujo permanecen deshabilitados hasta que la sonda puede declarar realmente el
estado de IIS. El navegador nunca ve el token bearer: el proxy YARP en proceso
lo inyecta desde el almacén DPAPI de ámbito de máquina y elimina cualquier cabecera
`Authorization` enviada por el navegador; además, un filtro de Host rechaza los nombres de host
que no son de loopback (defensa contra DNS rebinding).

## 7. RdpAudit.Core — Biblioteca compartida

### 7.1. Modelos de datos

Las entidades principales incluyen:

| Tipo | Descripción |
|------|-------------|
| `RdpConnectionFact` | Registro de hecho de conexión RDP |
| `AuthAttemptFact` | Hecho de intento de autenticación |
| `Session` | Metadatos de sesión RDP |
| `SessionIpCorrelation` | Correlación sesión-IP |
| `AttackStat` | Métricas de ataque agregadas |
| `AttackThreatLevel` | Enumeración de nivel de amenaza |
| `AttackThreatScoring` | Lógica de puntuación de amenazas |
| `AttackStatProjection` | Proyección de estadísticas de ataque para la interfaz |
| `ActiveBlock` | Registro de bloqueo activo |
| `BlocklistEntry` | Entrada persistente de la lista de bloqueo |
| `WhitelistEntry` | Entrada de IP o CIDR de confianza |
| `Alert` | Registro de alerta |
| `AbuseReport` | Carga útil de un reporte a AbuseIPDB |
| `AbuseIpDbReportHistory` | Historial de reportes y deduplicación |
| `RawEvent` | Registro de evento en bruto normalizado |
| `OperationLog` | Registro del log de operaciones del servicio |
| `LoginRule` | Regla de acceso basada en franjas horarias |
| `Bookmark` | Marcador de procesamiento de eventos |
| `DbProp` | Registro de metadatos clave-valor |
| `ThreatIntelLookup` | Instantánea de reputación de /api/v2/check en caché por IP (Stage 15) |
| `ThreatIntelUsageCounter` | Contador persistente del presupuesto diario de uso de /check (Stage 15) |
| `Address` | Dirección IP y metadatos asociados |

### 7.2. Entity Framework Core y migraciones

- EF Core 8 con SQLite
- `AppDbContext` como propietario del esquema y soporte de consultas
- Aplicación automática de migraciones en el arranque del servicio
- EF Core reservado para configuración, migraciones y lecturas de la interfaz
- Las escrituras de la ruta crítica se gestionan con comandos SQLite directos y transacciones explícitas

### 7.3. Contratos IPC (MessagePack)

Las peticiones y respuestas IPC se serializan con **MessagePack**. Entre los contratos representativos están:
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

## 8. Integraciones externas

### 8.1. AbuseIPDB

RDPAudit puede reportar las IP atacantes a [AbuseIPDB](https://www.abuseipdb.com/) cuando se detecta fuerza bruta o un comportamiento malicioso de alta confianza.

**Notas de diseño:**
- Las claves de API se almacenan como valores protegidos con DPAPI
- Los reportes duplicados se suprimen mediante el historial local
- Se respetan los límites de tasa
- Las categorías de reporte son configurables

RDPAudit también puede consultar la reputación de una IP en lectura: la función threat-intel opcional
(`AbuseIpDb.CheckEnabled`) ejecuta GET /api/v2/check mediante un worker en segundo plano,
precalienta una caché en disco para las IP públicas de origen de ataques y muestra una marca High-risk
en las rejillas de Attack Statistics y Live Events. La clave de API se envía solo en la
cabecera `Key` y nunca se registra en los logs.

### 8.2. MikroTik RouterOS v7

RDPAudit puede insertar IP maliciosas en una address-list de MikroTik a través de la API REST de RouterOS v7.

**Notas de diseño:**
- Funciona sobre endpoints REST HTTPS
- Admite validación TLS configurable
- Almacena las credenciales con protección DPAPI
- Evita entradas duplicadas en la address-list
- Se degrada de forma controlada cuando el router no está disponible

---

## 9. Modelo de bloqueo automático

### 9.1. Umbrales de disparo

Comportamiento por defecto:
- **10 inicios de sesión fallidos** desde la misma IP en **10 minutos** disparan un bloqueo
- Los umbrales se configuran en **Configuración**
- Las fuentes en la lista blanca se excluyen antes de aplicar un bloqueo

### 9.2. Firewall de Windows local

```text
Provider: WindowsFirewallProvider
Action:   Create inbound rule "RdpAudit_Block_<IP>" (block, any protocol)
Reverse:  Remove rule by name
Verify:   netsh advfirewall firewall show rule name="RdpAudit_Block_<IP>"
```

### 9.3. Firewall remoto MikroTik

```text
Provider: MikroTikFirewallProvider
Action:   PUT /rest/ip/firewall/address-list { address: <IP>, list: "RdpAudit-Blocklist" }
Reverse:  DELETE /rest/ip/firewall/address-list/<id>
Verify:   GET /rest/ip/firewall/address-list?address=<IP>
```

### 9.4. Protección de lista blanca para IP de confianza

- Admite IP individuales y rangos CIDR
- Se evalúa antes de crear cualquier bloqueo
- Se gestiona desde la GUI
- Se almacena en `WhitelistEntries` con metadatos aptos para auditoría

---

## 10. Mantenimiento de datos

### 10.1. Depuración por retención

Un worker de depuración elimina periódicamente los registros obsoletos.

| Tabla | Retención por defecto | Configurable |
|-------|-------------------|-------------|
| `RawEvents` | 90 días | Sí |
| `Alerts` | 180 días | Sí |
| `AbuseIpDbReportHistory` | 365 días | Sí |
| `ActiveBlocks` (inactivos) | 30 días | Sí |
| `AttackStats` | 365 días | Sí |

**Notas de implementación:**
- Borrados por lotes
- Retroceso exponencial ante `SQLITE_BUSY`
- Soporte de cancelación
- Registro de las operaciones

### 10.2. Copia de seguridad y restauración

El flujo de copia de seguridad captura el estado de configuración, no la base de datos de eventos.

**Incluido en la copia de seguridad:**
- `appsettings.json` solo con sobres DPAPI
- Exportación de la política de auditoría
- Claves del registro relevantes
- Metadatos de configuración del servicio

**No incluido:**
- `rdpaudit.db`

Antes de ejecutar cualquier restauración se crea una instantánea de seguridad previa.

---

## 11. Seguridad y auditoría

### 11.1. Control de acceso

| Componente | Modelo de acceso |
|-----------|--------------|
| `RdpAudit.Service` | Se ejecuta como `SYSTEM` o con una identidad de servicio dedicada |
| Named Pipe IPC | Solo `BUILTIN\Administrators` |
| `RdpAudit.Configurator` | Requiere elevación |
| Base de datos SQLite | Restringida a `SYSTEM` y `Administrators` |
| `appsettings.json` | Restringida a `SYSTEM` y `Administrators` |

### 11.2. Configuración de SACL

El Configurador establece SACL en objetivos de alto valor para que los cambios sensibles sean auditables:
- Claves de accesibilidad IFEO
- Configuración del registro `RDP-Tcp`
- Configuración del registro `Lsa`

Esto permite detectar puertas traseras de Sticky Keys, cambios de puerto RDP y manipulación de LSASS/PPL.

### 11.3. Protección de secretos (DPAPI)

- Las claves de AbuseIPDB y las credenciales de MikroTik se protegen con Windows DPAPI
- En la configuración solo se almacenan sobres DPAPI
- La GUI no revela secretos en texto plano
- Las copias de seguridad incluyen los valores protegidos, no los descifrados

---

## 12. Configuración

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

### 12.2. Variables de entorno

Puede sobrescribir valores de configuración mediante variables de entorno, lo que resulta útil para el despliegue automatizado y el diagnóstico:

```text
RDPAUDIT_RdpAudit__LogLevel=Debug
RDPAUDIT_RdpAudit__AlertRules__BruteForce__FailThreshold=5
```

---

## 13. Depuración y diagnóstico

### 13.1. Modo consola

Cuando hay un depurador asociado, el servicio puede ejecutarse como aplicación de consola en lugar de como servicio de Windows formal.

```powershell
cd src\RdpAudit.Service
dotnet run --configuration Debug
```

### 13.2. Registros de Serilog

Los registros se escriben en:
- `%ProgramData%\RdpAudit\logs\rdpaudit-<date>.log`
- Registro de eventos de Windows → `Application`, origen `RdpAudit`

Para aumentar el nivel de detalle:

```powershell
$env:RDPAUDIT_RdpAudit__LogLevel = "Debug"
```

### 13.3. Acceso directo a SQLite

```powershell
& "C:\Program Files\DB Browser for SQLite\DB Browser for SQLite.exe" `
  "$env:ProgramData\RdpAudit\rdpaudit.db"
```

Consultas útiles:

```sql
SELECT * FROM RawEvents ORDER BY TimeUtc DESC LIMIT 100;

SELECT * FROM ActiveBlocks WHERE Status = 'Active';

SELECT SourceIp, SUM(FailCount) AS Fails
FROM AttackStats
GROUP BY SourceIp
ORDER BY Fails DESC
LIMIT 20;
```

### 13.4. Pestaña Diagnóstico

La interfaz de Diagnóstico expone:
- Contadores de eventos por segundo
- Estado de los workers
- Estado del IPC
- Salud de la base de datos
- Accesibilidad de las integraciones externas

---

## 14. Compilación y pruebas

### 14.1. Compilación

```powershell
dotnet build RdpAudit.sln -c Release
dotnet build src/RdpAudit.Service/RdpAudit.Service.csproj -c Release
```

### 14.2. Pruebas

```powershell
dotnet test RdpAudit.sln -c Release
dotnet test RdpAudit.sln -c Release --collect:"XPlat Code Coverage"
dotnet test tests/RdpAudit.Service.Tests/RdpAudit.Service.Tests.csproj
```

Cada prueba de regla de alerta debe validar:
1. Comportamiento en el límite del umbral
2. Comportamiento de omisión por lista blanca
3. Cero asignaciones administradas en evaluaciones repetidas

### 14.3. Publicación

```powershell
./publish.ps1
```

Salida esperada:

```text
publish/
├── Service/
└── Configurator/
```

---

## 15. Resolución de problemas

Guía detallada: [`docs/91-troubleshooting.md`](docs/91-troubleshooting.md)

| Síntoma | Primer paso de diagnóstico |
|---------|-----------------------|
| El servicio no arranca | Compruebe `sc.exe query RdpAudit` y luego revise el registro de eventos Application |
| No aparecen eventos en vivo | Abra **Requisitos previos** y confirme la configuración de auditoría |
| La GUI no puede conectarse | Verifique que el servicio está en ejecución y que la ACL del pipe es correcta |
| `sc.exe` devuelve 1639 | Vuelva a comprobar el entrecomillado de la ruta del binario del servicio |
| AbuseIPDB devuelve HTTP 429 | Se ha alcanzado el límite de tasa de la API |
| Fallo TLS con MikroTik | Desactive la verificación para certificados autofirmados o instale el certificado de la CA |
| Aparece `SQLITE_BUSY` | La contención de corta duración es esperable y se reintenta automáticamente |
| La política de auditoría muestra `?` | Vuelva a aplicarla desde la pestaña Política de auditoría |
| Problemas de ACL en ProgramData | Repare las ACL de la carpeta para `SYSTEM` y `Administrators` |

Véase también: [`docs/90-windows-validation.md`](docs/90-windows-validation.md)

---

## 16. Hoja de ruta (v2.0 → v3.0)

| Característica | Estado |
|---------|--------|
| Ingesta mediante ETW (`OpenTrace` / `ProcessTrace`) | Planificado |
| Análisis directo de EVTX con `Span<byte>` | Planificado |
| Búfer circular MPMC sin bloqueos | Planificado |
| Aceleración SIMD de CIDR y del análisis | Planificado |
| Normalización de eventos sin asignaciones | Planificado |
| Visibilidad de capa de red MS-RDPBCGR / RDPEUDP | Investigación |
| Interfaz web basada en Blazor | Planificado |
| Integración con Elastic / OpenSearch | Hoja de ruta |
| Recolector central multiservidor | Hoja de ruta |

---

## 17. Licencia y autor

**Licencia:** [Business Source License 1.1](LICENSE)

RDPAudit Community tiene el código disponible. Puede copiarlo, modificarlo, redistribuirlo y usarlo con
fines que no sean de producción; la Additional Use Grant incluida en `LICENSE` permite además el uso
en producción, salvo ofrecer el software a terceros como servicio comercial alojado o gestionado.
El **2030-10-25** esta versión pasa a la Apache License 2.0.

Las ediciones Pro y Enterprise son propietarias y **no** están cubiertas por esta licencia; cada una
tiene sus propios términos. Qué capacidad pertenece a cada edición está documentado en
[docs/editions.md](docs/editions.md).

**Autor:** Mikhail Deynekin
- Sitio web: [deynekin.com](https://deynekin.com)
- Correo electrónico: [Mikhail@Deynekin.com](mailto:Mikhail@Deynekin.com)
- GitHub: [github.com/paulmann](https://github.com/paulmann)

**Repositorio:** [github.com/paulmann/RDPAudit](https://github.com/paulmann/RDPAudit)

**Recursos relacionados:**
- [Especificación técnica v1.0](https://github.com/paulmann/1st-RDPMon/wiki/RdpAudit-Service-%E2%80%90-Technical-Specification-v1.0)
- [Especificación técnica v2.0](https://github.com/paulmann/1st-RDPMon/wiki/RdpAudit-Service-%E2%80%90-Technical-Specification-v2.0)
- [Incidencias y solicitudes de funcionalidad](https://github.com/paulmann/RDPAudit/issues)

---

> © 2025–2026 Mikhail Deynekin. Publicado bajo la [Business Source License 1.1](LICENSE).
