# 1st-RDPMon — RdpAudit .NET 8 Solution

[![Version](https://img.shields.io/badge/version-2.0.0-blue.svg)](https://github.com/paulmann/RDPAudit)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![.NET](https://img.shields.io/badge/dotnet-8.0--windows-blue.svg)](https://dotnet.microsoft.com/)
[![Platform](https://img.shields.io/badge/platform-Windows%2010%2B%2FServer-blue.svg)](https://www.microsoft.com/windows/)
[![SQLite](https://img.shields.io/badge/sqlite-WAL-orange.svg)](https://sqlite.org/)

> **What is this repository?** It contains two generations of the same project:
>
> 1. **RdpAudit (v2)** — a production-grade .NET 8 Worker Service plus a WinForms Configurator
>    that monitors Windows RDP / Security / Terminal Services event channels in real time, raises
>    21 high-quality alert rules, persists to SQLite via EF Core, and exposes a named-pipe IPC
>    surface restricted to BUILTIN\Administrators. This is the actively developed flagship.
> 2. **1st-RdpMonSecurityAnalyzer.ps1 (v1)** — the original PowerShell analyzer that reads
>    Cameyo RDPMon's LiteDB. Documented below for historical reference.

## RdpAudit (v2) — at a glance

| Layer | Project | Responsibility |
|-------|---------|----------------|
| Service | `src/RdpAudit.Service` | Captures events with `EventLogWatcher`, batches into SQLite, runs 21 alert rules, hosts named-pipe IPC, applies firewall auto-blocks. |
| Configurator | `src/RdpAudit.Configurator` | WinForms UI: prerequisites, audit-policy / SACL apply, service install, settings, live event tail. Runs as `requireAdministrator`. |
| Core | `src/RdpAudit.Core` | EF Core 8 entities & migrations, IPC contracts, event catalog (GUID-based audit subcategories), shared utilities. |

### Quick start (RdpAudit)

```powershell
# 1. Build & publish single-file binaries
./publish.ps1

# 2. Copy the published Service folder under Program Files
Copy-Item -Recurse publish/Service "$env:ProgramFiles/RdpAudit/Service"

# 3. Use the Configurator to install the service, apply audit policy, and configure SACLs
publish/Configurator/RdpAudit.Configurator.exe
```

### Highlights of v2

- **Real audit-policy apply** via `auditpol.exe` with **GUID** subcategory identifiers (locale-independent).
- **Real SACL configuration** for IFEO accessibility binaries, RDP-Tcp, and LSA registry keys.
- **Real Windows Firewall block** (per-IP, sanitised arguments, idempotent add/remove) tied to brute-force thresholds.
- **Bookmark durability**: every 100 events **and** every 30 seconds — no more than 99 events lost on crash.
- **Bulk batch persistence**: one transaction, prefetched address map, single `AddRange/SaveChanges`.
- **EF Core migrations** applied on startup (no more `EnsureCreated` only).
- **Named-pipe IPC** with admin-only ACL, hard per-connection deadline, sanitised error text.
- **Atomic settings save** over IPC; UI never writes service-owned config files directly.
- 21 alert rules including `STICKY_KEYS_BACKDOOR`, `RDP_PORT_CHANGED`, `LSASS_PPL_TAMPER`,
  `LSASS_ACCESS` (bitwise mask check), `KERBEROS_SPRAY`, `BRUTE_FORCE_NTLM` with cooldown to
  prevent alert flood, `OFF_HOURS_LOGIN` with explicit time-zone (UTC by default).
- **External provider integrations.** AbuseIPDB reputation reporting with local dedup and
  rate-limit awareness (Stage 8); MikroTik RouterOS v7 REST firewall provider (Stage 9) with
  DPAPI-protected credentials and idempotent rule management.
- **Configurator UX.** Overview, Prerequisites, Audit Policy, Service, Settings, Live Events,
  Firewall, Attack Statistics, Remote RDP Clients, AbuseIPDB, MikroTik — each tab surfaces
  status / result feedback, destructive actions confirm with **No** as default, and no plaintext
  secret is ever displayed or copied to the clipboard.
- **Retention pruning** (Stage 10) for `RawEvents`, `Alerts`, `AbuseReports`, inactive
  `ActiveBlocks` and stale `AttackStats`. All deletes are batched, cancellable, and tolerate
  `SQLITE_BUSY` with exponential backoff so the writer lock is short on huge databases.
- **Backup / restore.** Snapshots capture `appsettings.json` (DPAPI envelopes only, never
  plaintext), audit policy CSV, RdpAudit registry keys (IFEO, RDP-Tcp, LSA, audit policy) and
  `sc.exe qc` configuration. Restore never touches the audit event database and always captures
  a pre-restore safety snapshot first.

### Build & test

```powershell
dotnet build  RdpAudit.sln -c Release
dotnet test   RdpAudit.sln -c Release
./publish.ps1
```

### Windows validation & troubleshooting

Stage 10 release-readiness ships two new operator-facing documents:

- [`docs/90-windows-validation.md`](docs/90-windows-validation.md) — end-to-end manual checklist
  to run on a Windows host before declaring a build shippable.
- [`docs/91-troubleshooting.md`](docs/91-troubleshooting.md) — common failures (ProgramData
  ACL, `sc.exe` 1639, locked publish files, audit-policy `?`, firewall unavailable, AbuseIPDB
  HTTP 429, MikroTik TLS / auth) with copy-paste fixes.

---

# 1st RDP Monitor Security Analyzer (legacy PowerShell, v1)

The remainder of this README documents the original PowerShell analyzer. It remains useful for
sites already running Cameyo RDPMon and is left here for backwards compatibility.

[![PowerShell](https://img.shields.io/badge/powershell-7.5%2B-blue.svg)](https://docs.microsoft.com/en-us/powershell/)
[![LiteDB](https://img.shields.io/badge/litedb-4.1.4-orange.svg)](https://www.nuget.org/packages/LiteDB)

- [1. Overview](#1-overview)
- [2. Key Features](#2-key-features)
- [3. System Requirements](#3-system-requirements)
- [4. Quick Start Guide](#4-quick-start-guide)
- [5. Installation & Setup](#5-installation--setup)
- [6. Understanding RDPMon & LiteDB Integration](#6-understanding-rdpmon--litedb-integration)
- [7. IP Banning Mechanism](#7-ip-banning-mechanism)
- [8. How It Works](#8-how-it-works)
- [9. Architecture & Components](#9-architecture--components)
- [10. Usage Examples](#10-usage-examples)
- [11. Parameters Reference](#11-parameters-reference)
- [12. Output Formats](#12-output-formats)
- [13. Advanced Scenarios](#13-advanced-scenarios)
- [14. Troubleshooting & Debugging](#14-troubleshooting--debugging)
- [15. Performance Optimization](#15-performance-optimization)
- [16. Security Considerations](#16-security-considerations)
- [17. Contributing](#17-contributing)
- [18. License & Acknowledgments](#18-license--acknowledgments)

***

## 1. Overview

**1st RDP Monitor Security Analyzer** (v1.0.0) is an enterprise-grade PowerShell module designed to query, analyze, and report on RDP authentication attempts stored in Cameyo RDPMon's LiteDB database. This advanced security tool provides comprehensive filtering, multiple output formats, modern HTML reporting with auto-refresh capabilities, and automatic LiteDB installation from GitHub releases for seamless deployment.

### Primary Purpose

The analyzer transforms raw RDP authentication data into actionable security intelligence, enabling security teams to:
- Identify brute force attacks and unauthorized access attempts
- Track suspicious login patterns from specific IP addresses
- Generate compliance-ready reports for security audits
- Automate security monitoring and incident response workflows
- Correlate RDP events with external threat intelligence

### Version Highlights (v1.0.0)

- ✨ **Advanced Debug Mode** - Step-by-step execution logging with timestamps
- 🔍 **Database Diagnostics** - Safe analysis of potentially corrupted databases
- 🛠️ **Emergency Recovery** - Export and repair functionality for damaged databases
- 📊 **Enhanced Analytics** - Improved charting and data visualization
- 🔄 **Automatic LiteDB Installation** - Seamless dependency management from GitHub
- 💾 **Multiple Output Formats** - Table, List, JSON, CSV, XML, HTML, Text, YAML, Markdown, and direct object access
- 🎨 **Modern HTML Interface** - Responsive design with Tailwind CSS and interactive charts
- ⚡ **Performance Optimizations** - Efficient event processing and memory management

***

## 2. Key Features

### 2.1 Comprehensive RDP Event Analysis

- **Event Type Filtering**: All, Attack, Legit, Unknown classifications
- **IP Address Matching**: Single IPs, CIDR ranges, wildcard patterns
- **Temporal Analysis**: Flexible time window filtering with start/end dates
- **Connection Details**: Failed/successful attempt counts, user names, connection types
- **Duration Calculation**: Automatic calculation of attack/session durations
- **DNS Resolution**: Optional hostname resolution for IP addresses

### 2.2 Advanced Database Integration

- **LiteDB 4.1.4 Compatibility**: Specifically designed for RDPMon's LiteDB version
- **Addr Collection Processing**: Extracts IP-based authentication data
- **Session Collection Parsing**: Analyzes detailed session information
- **Prop Collection Metadata**: Reads database statistics and metadata
- **Safe Database Access**: Read-only connections prevent data corruption
- **Database Diagnostics**: Safe structure analysis without accessing potentially corrupted records

### 2.3 Multiple Output Formats

- **Text**: Formatted console output with comprehensive summaries
- **CSV**: Structured data for Excel and analysis tools
- **JSON**: API-friendly format for integrations
- **XML**: Structured format for enterprise systems
- **HTML**: Interactive web reports with charts and filtering
- **YAML**: Configuration-friendly format
- **Markdown**: Documentation-ready output
- **Object**: Direct PowerShell object access for scripting

### 2.4 Enterprise Reporting Capabilities

- **Auto-Refresh HTML Reports**: Configurable refresh intervals (5-3600 seconds)
- **Responsive Design**: Mobile-friendly using Tailwind CSS CDN
- **Interactive Charts**: Chart.js integration for visual analysis
- **Summary Statistics**: Automatic calculation of key metrics
- **Color-Coded Results**: Visual distinction of attack vs. legitimate connections
- **Sortable Tables**: JavaScript-enabled sorting and filtering

### 2.5 Flexible Filtering & Customization

- **Connection Type Filter**: All, Attack, Legit, Unknown
- **Failed Attempt Threshold**: Minimum failed login count filtering
- **Custom Time Ranges**: Both relative (last N hours/days) and absolute (specific dates)
- **Output Sorting**: Sort by IP, FailCount, SuccessCount, FirstLocal, LastLocal, Duration
- **Result Limiting**: Configurable result set size
- **DNS Resolution**: Optional hostname lookup for IP addresses
- **Include Resolved**: Toggle for showing resolved hostnames in reports

### 2.6 Automatic Dependency Management

- **GitHub Integration**: Automatic LiteDB download from official releases
- **Version Management**: Support for specific LiteDB versions (default: 4.1.4 for RDPMon compatibility)
- **Force Reinstallation**: Option to rebuild LiteDB installation
- **Custom Installation Paths**: Flexible directory configuration
- **Fallback Mechanisms**: Multiple search paths and recovery options
- **Internet-Optional**: Skip installation if not available (SkipLiteDbInstall)

### 2.7 Advanced Debugging & Diagnostics

- **Debug Mode**: Detailed step-by-step execution logging
- **Phase Tracking**: Clear visibility into script execution phases
- **Operation Timing**: Performance metrics for each operation
- **Error Context**: Detailed error messages with resolution suggestions
- **Database Analysis**: Safe structure diagnosis without data loss
- **Progress Reporting**: Configurable progress indicators

### 2.8 Database Recovery Tools

- **Data Export**: Emergency export to CSV for damaged databases
- **Database Repair**: Rebuild corrupted LiteDB files
- **Safe Mode Analysis**: Read-only diagnostics for damaged data
- **Backup Creation**: Automatic backups before repair attempts
- **Recovery Verification**: Validation of repair success

***

## 3. System Requirements

### 3.1 Minimum Requirements

- **Operating System**: Windows 10, Windows Server 2012 R2 or later
- **PowerShell**: Version 7.5+ (PowerShell Core with `#requires -PSEdition Core`)
- **Memory**: 2 GB RAM minimum (4+ GB recommended for large databases)
- **Storage**: 500 MB free space for LiteDB and output files
- **Permissions**: Local Administrator privileges (required for Windows event log access in related operations)
- **.NET Framework**: Core .NET support through PowerShell 7.5+

### 3.2 Recommended Enterprise Configuration

- **Operating System**: Windows Server 2016/2019/2022
- **PowerShell**: PowerShell 7.5+ with latest security updates
- **Memory**: 8 GB RAM for processing large RDPMon databases
- **Storage**: SSD storage with 2+ GB free space
- **Network**: Stable internet connection for automatic LiteDB download
- **Antivirus**: May require exclusions for script execution

### 3.3 Dependency Requirements

- **LiteDB Assembly**: Version 4.1.4 (automatically installed from GitHub)
- **RDPMon Database**: Access to Cameyo RDPMon LiteDB database (.db file)
- **HTTP/HTTPS**: Internet connectivity for GitHub release downloads (optional, can skip with -SkipLiteDbInstall)
- **Character Encoding**: UTF-8 support for report generation

### 3.4 Feature-Specific Requirements

#### HTML Report Generation
- Modern web browser with JavaScript support
- Tailwind CSS CDN access (or offline CSS)
- Chart.js library (from CDN or locally hosted)

#### Database Repair & Recovery
- Write permissions to target directory for backup creation
- Sufficient disk space for database duplication during repair

#### Time-Based Filtering
- System clock accuracy for proper time range filtering
- Local timezone configuration

***

## 4. Quick Start Guide

### 4.1 Complete PowerShell Setup (5 Minutes)

**Step 1: Open PowerShell 7.5+ as Administrator**
```powershell
# Right-click PowerShell and select "Run as Administrator"
# OR open Command Prompt and type: pwsh -NoExit
```

**Step 2: Set Execution Policy**
```powershell
# Set execution policy for current user (recommended)
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser -Force

# Alternative: Bypass for single session only
powershell -ExecutionPolicy Bypass
```

**Step 3: Navigate to Script Directory**
```powershell
# Go to the directory containing the script
cd "C:\Path\To\Script"

# Validate PowerShell version compliance - ensures modern security features and performance
if ($PSVersionTable.PSVersion.Major -lt 7) {
    throw "PowerShell 7.0 or higher required for enhanced security modules and performance optimizations"
}

# Clean up previous installation artifacts to ensure fresh deployment
if (Test-Path "1st-RDPMon") {
    Remove-Item "1st-RDPMon" -Recurse -Force
}

# Fetch latest repository snapshot from GitHub main branch
# Using secure TLS 1.2+ protocol with automatic redirect handling
Invoke-WebRequest "https://github.com/paulmann/RDPAudit/archive/refs/heads/main.zip" -OutFile "tmp.zip"

# Extract archive contents while preserving directory structure and metadata
# Clean up temporary archive to maintain storage efficiency
Expand-Archive "tmp.zip" -DestinationPath .
Remove-Item "tmp.zip"

# Standardize directory naming convention for consistent tool access
Rename-Item "1st-RDPMon-main" "1st-RDPMon" -ErrorAction Stop

# Transition to tool directory for subsequent operations
Set-Location "1st-RDPMon"

# Execute primary analyzer with help parameter to verify functionality
# Using call operator (&) for secure script execution in isolated scope
& (Get-ChildItem -Recurse -Filter "1st-RdpMonSecurityAnalyzer.ps1" | Select-Object -First 1).FullName -?

# Provide deployment confirmation with comprehensive asset inventory
Write-Host "✅ Deployment completed: $((Get-ChildItem -Recurse -File | Measure-Object).Count) files initialized" -ForegroundColor Green
```

**Step 4: Verify LiteDB Availability**
```powershell
# Run with automatic LiteDB installation
.\1st-RdpMonSecurityAnalyzer.ps1 -DbPath "C:\Path\To\RdpMon.db" -AutoInstallLiteDb
```

**Step 5: Basic Analysis**
```powershell
# Quick console analysis (no file output)
.\1st-RdpMonSecurityAnalyzer.ps1 -DbPath "C:\Path\To\RdpMon.db" -Type All

# Generate HTML report
.\1st-RdpMonSecurityAnalyzer.ps1 -DbPath "C:\Path\To\RdpMon.db" -OutputFormat Html -ExportPath "report.html"
```

### 4.2 Basic Command Examples

```powershell
# ✅ Simplest usage - just specify database path
.\1st-RdpMonSecurityAnalyzer.ps1 -DbPath "C:\RdpMon\RdpMon.db"

# ✅ Generate interactive HTML report
.\1st-RdpMonSecurityAnalyzer.ps1 -DbPath "C:\RdpMon\RdpMon.db" -OutputFormat Html -ExportPath "daily-report.html"

# ✅ Export to JSON for integration
.\1st-RdpMonSecurityAnalyzer.ps1 -DbPath "C:\RdpMon\RdpMon.db" -OutputFormat Json -ExportPath "events.json"

# ✅ Analyze last 24 hours
.\1st-RdpMonSecurityAnalyzer.ps1 -DbPath "C:\RdpMon\RdpMon.db" -From (Get-Date).AddDays(-1) -To (Get-Date)

# ✅ Filter only attack attempts (failed logins)
.\1st-RdpMonSecurityAnalyzer.ps1 -DbPath "C:\RdpMon\RdpMon.db" -Type Attack -MinFails 5

# ✅ Sort by most active IPs
.\1st-RdpMonSecurityAnalyzer.ps1 -DbPath "C:\RdpMon\RdpMon.db" -SortBy FailCount -Descending

# ✅ With DNS resolution
.\1st-RdpMonSecurityAnalyzer.ps1 -DbPath "C:\RdpMon\RdpMon.db" -IncludeResolved
```

### 4.3 Permissions & Execution

#### Elevate to Administrator (If Needed)

```powershell
# Check if running as admin
$isAdmin = (New-Object Security.Principal.WindowsPrincipal(
    [Security.Principal.WindowsIdentity]::GetCurrent()
)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "Not running as administrator. Elevating..." -ForegroundColor Red
    Start-Process -FilePath "pwsh" -ArgumentList "-File `"$PSCommandPath`"" -Verb RunAs
    exit
}
```

#### Bypass Execution Policy (Temporary)

```powershell
# For a single command
powershell -ExecutionPolicy Bypass -Command ".\1st-RdpMonSecurityAnalyzer.ps1 -DbPath 'C:\RdpMon.db'"

# For a session
powershell -ExecutionPolicy Bypass -NoExit
# Then run your commands
```

#### Permanent Execution Policy (User-Scoped)

```powershell
# Recommended: RemoteSigned policy
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser -Force

# Verify
Get-ExecutionPolicy -Scope CurrentUser
```

### 4.4 First-Time Verification

```powershell
# 1. Verify RDPMon database exists
Test-Path "C:\Path\To\RdpMon.db" -PathType Leaf

# 2. Test script syntax
[System.Management.Automation.PSParser]::Tokenize((Get-Content "1st-RdpMonSecurityAnalyzer.ps1" -Raw), [ref]$null)

# 3. Run with debug information
.\1st-RdpMonSecurityAnalyzer.ps1 -DbPath "C:\RdpMon.db" -DebugMode

# 4. Generate sample report
.\1st-RdpMonSecurityAnalyzer.ps1 -DbPath "C:\RdpMon.db" -OutputFormat Html -ExportPath "test-report.html" -Limit 100
```

***

## 5. Installation & Setup

### 5.1 Deployment Methods

#### Method A: Automated One-Line Installation

```powershell
# Download, setup, and run with automatic LiteDB installation
$scriptUrl = "https://raw.githubusercontent.com/paulmann/RDPAudit/main/1st-RdpMonSecurityAnalyzer.ps1"
Invoke-WebRequest -Uri $scriptUrl -OutFile "1st-RdpMonSecurityAnalyzer.ps1"
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser -Force
.\1st-RdpMonSecurityAnalyzer.ps1 -DbPath "C:\RdpMon.db" -AutoInstallLiteDb -LiteDbVersion "4.1.4"
```

#### Method B: Enterprise Manual Installation

**Step 1: Create Directory Structure**
```powershell
# Create secure directory structure
$toolPath = "C:\Program Files\SecurityTools\1stRdpMonAnalyzer"
$reportPath = "C:\SecurityReports\RdpMonAnalysis"

New-Item -ItemType Directory -Path $toolPath -Force | Out-Null
New-Item -ItemType Directory -Path $reportPath -Force | Out-Null

# Set restrictive permissions
icacls $toolPath /inheritance:r /grant:r "Administrators:(OI)(CI)F" "System:(OI)(CI)F"
icacls $reportPath /grant:r "Administrators:(OI)(CI)F" "Everyone:(OI)(CI)M"
```

**Step 2: Download Script**
```powershell
# Download from GitHub
$scriptUrl = "https://raw.githubusercontent.com/paulmann/RDPAudit/main/1st-RdpMonSecurityAnalyzer.ps1"
$scriptPath = "$toolPath\1st-RdpMonSecurityAnalyzer.ps1"

Invoke-WebRequest -Uri $scriptUrl -OutFile $scriptPath -UseBasicParsing
Write-Host "Script downloaded to: $scriptPath" -ForegroundColor Green
```

**Step 3: Configure Execution**
```powershell
# Set execution policy for current user
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser -Force

# Verify
Get-ExecutionPolicy -Scope CurrentUser
```

**Step 4: Validate Installation**
```powershell
# Test script syntax
$null = [System.Management.Automation.PSParser]::Tokenize(
    (Get-Content $scriptPath -Raw), 
    [ref]$null
)
Write-Host "Script syntax validation: ✓ PASSED" -ForegroundColor Green

# Verify RDPMon database
if (Test-Path "C:\RdpMon\RdpMon.db") {
    Write-Host "RDPMon database found: ✓" -ForegroundColor Green
} else {
    Write-Host "WARNING: RDPMon database not found at standard location" -ForegroundColor Yellow
}
```

### 5.2 LiteDB Dependency Management

#### Understanding LiteDB Installation

LiteDB is a lightweight embedded NoSQL database used by Cameyo RDPMon to store RDP authentication records. This script requires **LiteDB version 4.1.4** for compatibility with RDPMon's database schema.

**Version Compatibility:**
- ✅ LiteDB 4.1.4 - **Recommended** (RDPMon compatible)
- ❌ LiteDB 5.x - Not compatible with RDPMon database format

#### Automatic Installation from GitHub

```powershell
# Option 1: Auto-install with default settings
.\1st-RdpMonSecurityAnalyzer.ps1 `
  -DbPath "C:\RdpMon\RdpMon.db" `
  -AutoInstallLiteDb

# Option 2: Specify custom installation directory
.\1st-RdpMonSecurityAnalyzer.ps1 `
  -DbPath "C:\RdpMon\RdpMon.db" `
  -AutoInstallLiteDb `
  -LiteDbInstallPath "C:\Libraries\LiteDB" `
  -LiteDbVersion "4.1.4"

# Option 3: Force reinstall (if corrupted)
.\1st-RdpMonSecurityAnalyzer.ps1 `
  -DbPath "C:\RdpMon\RdpMon.db" `
  -AutoInstallLiteDb `
  -ForceLiteDbInstall
```

#### Manual LiteDB Installation

```powershell
# Download LiteDB directly from NuGet
$liteDbUrl = "https://www.nuget.org/api/v2/package/LiteDB/4.1.4"
$liteDbPath = "$PSScriptRoot\LiteDB"
$tempFile = "$env:TEMP\LiteDB.4.1.4.nupkg"

# Create directory
New-Item -ItemType Directory -Path $liteDbPath -Force | Out-Null

# Download NuGet package (which is a ZIP file)
Invoke-WebRequest -Uri $liteDbUrl -OutFile $tempFile -UseBasicParsing

# Extract package
Expand-Archive -Path $tempFile -DestinationPath $liteDbPath -Force

# Find LiteDB.dll in extracted files
$dllFile = Get-ChildItem -Path $liteDbPath -Filter "LiteDB.dll" -Recurse | 
    Select-Object -First 1

if ($dllFile) {
    Write-Host "LiteDB installed: $($dllFile.FullName)" -ForegroundColor Green
} else {
    Write-Error "Failed to locate LiteDB.dll in extracted files"
}
```

#### Using Existing LiteDB Installation

```powershell
# If you already have LiteDB installed elsewhere
$existingLiteDbPath = "C:\MyLibraries\LiteDB\LiteDB.dll"

# Use it with the script
.\1st-RdpMonSecurityAnalyzer.ps1 `
  -DbPath "C:\RdpMon\RdpMon.db" `
  -LiteDbPath $existingLiteDbPath `
  -SkipLiteDbInstall
```

***

## 6. Understanding RDPMon & LiteDB Integration

### 6.1 What is Cameyo RDPMon?

**Cameyo RDPMon** is an advanced RDP monitoring solution that tracks all RDP connection attempts (successful and failed) on Windows systems. It maintains a detailed audit log in a LiteDB database, capturing:
- Source IP addresses of connection attempts
- User accounts used in logon attempts
- Timestamps of each connection attempt
- Logon success/failure status
- Connection duration and session details

### 6.2 LiteDB Database Structure

RDPMon uses LiteDB's document-based storage with the following collection structure:

#### Addr Collection (Primary Data)
```json
{
  "_id": "192.168.1.100",
  "FailCount": 45,
  "SuccessCount": 2,
  "First": "2025-12-20T10:30:15Z",
  "Last": "2025-12-28T23:45:00Z",
  "UserNames": ["admin", "root", "test"],
  "ConnectionType": "Attack"
}
```

**Field Descriptions:**
- `_id` - IP address (primary key)
- `FailCount` - Number of failed login attempts
- `SuccessCount` - Number of successful logins
- `First` - First connection attempt timestamp
- `Last` - Most recent connection attempt timestamp
- `UserNames` - Array of user accounts attempted
- `ConnectionType` - Classification (Attack/Legit/Mixed/Unknown)

#### Session Collection
Contains detailed session information including:
- Session ID
- Source IP address
- Username
- Session start/end times
- Session duration
- Session flags and Windows Terminal Services ID

#### Prop Collection (Metadata)
Stores database properties:
- `LastAddrChange` - Last modification to Addr collection
- `LastSessionChange` - Last modification to Session collection
- `LastProcessChange` - Last modification to Process collection
- Database version information

### 6.3 Script Integration with RDPMon

The script performs the following operations:

1. **Connects to LiteDB Database** (Read-only)
   ```powershell
   $connectionString = "Filename=$DbPath;ReadOnly=true;Utc=true"
   $database = [LiteDB.LiteDatabase]::new($connectionString)
   ```

2. **Queries Addr Collection** for IP-based statistics
   ```powershell
   $addrCollection = $database.GetCollection("Addr")
   $allRecords = $addrCollection.FindAll()
   ```

3. **Extracts and Processes Data**
   - Converts BsonDocuments to PowerShell objects
   - Applies filtering (Type, MinFails, time range)
   - Calculates statistics and metrics

4. **Generates Reports** in multiple formats
   - Formats data according to output format selection
   - Exports to file or displays in console
   - Creates interactive HTML reports if requested

### 6.4 Data Flow Diagram

```
┌─────────────────────────┐
│  RDPMon Service         │
│  (Monitors RDP Events)  │
└──────────┬──────────────┘
           │
           ▼
┌─────────────────────────┐
│  LiteDB Database        │
│  (RdpMon.db)            │
├─────────────────────────┤
│ Addr Collection         │
│ Session Collection      │
│ Prop Collection         │
└──────────┬──────────────┘
           │
           ▼
┌──────────────────────────────────┐
│ 1st RDP Monitor Analyzer         │
│ (This Script)                    │
├──────────────────────────────────┤
│ • Read RDPMon data               │
│ • Filter & analyze               │
│ • Calculate statistics           │
│ • Generate reports               │
└──────────┬───────────────────────┘
           │
           ▼
   ┌───────────────────────────────────────┐
   │  Output Formats                       │
   ├───────────────────────────────────────┤
   │ Table │ CSV │ JSON │ HTML │ Markdown │
   └───────────────────────────────────────┘
```

***

## 7. IP Banning Mechanism

### 7.1 Understanding IP Banning in RDPMon Context

The analyzer provides comprehensive data to support **manual IP banning decisions** based on RDP attack patterns. Here's how the process works:

### 7.2 Identifying Ban-Worthy IPs

The script helps identify IPs that should be banned by analyzing:

```powershell
# Identify high-risk IPs
$banCandidates = .\1st-RdpMonSecurityAnalyzer.ps1 `
  -DbPath "C:\RdpMon\RdpMon.db" `
  -Type Attack `
  -MinFails 10 `
  -OutputFormat Json | ConvertFrom-Json

# Filter IPs with specific attack patterns
$criticalAttacks = $banCandidates.AddrResults | 
  Where-Object { $_.FailCount -gt 50 -and $_.ConnectionType -eq "Attack" } |
  Sort-Object FailCount -Descending
```

**Ban Decision Criteria:**
- **FailCount > 50**: Multiple brute force attempts
- **Duration > 24 hours**: Persistent attack over time
- **Multiple user targets**: Attempts against various accounts
- **Known malicious IPs**: Cross-reference with threat intelligence

### 7.3 Manual Firewall Banning Process

#### Windows Firewall (Local)

```powershell
# Get high-risk IPs from analyzer
$riskyIPs = @("192.168.1.100", "203.0.113.45", "198.51.100.10")

# Create firewall rule for each IP
foreach ($ip in $riskyIPs) {
    $ruleName = "Block_RDP_Attack_$ip"
    
    New-NetFirewallRule `
        -DisplayName $ruleName `
        -Direction Inbound `
        -Action Block `
        -RemoteAddress $ip `
        -Protocol TCP `
        -LocalPort 3389 `
        -Enabled $true
    
    Write-Host "Blocked IP via firewall: $ip" -ForegroundColor Green
}

# List all blocking rules
Get-NetFirewallRule -DisplayName "Block_RDP_Attack_*" | Format-Table DisplayName, Enabled
```

#### Automated Ban List Management

```powershell
# Create dynamic ban list from analyzer output
function Update-RDPBanList {
    param(
        [string]$DbPath,
        [int]$FailThreshold = 50
    )
    
    # Get attack data
    $attackData = .\1st-RdpMonSecurityAnalyzer.ps1 `
        -DbPath $DbPath `
        -Type Attack `
        -MinFails $FailThreshold `
        -OutputFormat Json | ConvertFrom-Json
    
    # Extract IPs to ban
    $banIPs = $attackData.AddrResults | 
        Select-Object -ExpandProperty IP
    
    # Export to ban list file
    $banIPs | Out-File "C:\SecurityConfig\rdp_ban_list.txt" -Force
    
    # Create PowerShell script to apply bans
    $banScript = @"
# Auto-generated RDP ban list
# Generated: $(Get-Date)
`$banIPs = @(
    $($banIPs | ForEach-Object { "'$_'" } | Join-String -Separator ',')
)

foreach (`$ip in `$banIPs) {
    New-NetFirewallRule -DisplayName "Auto_Block_RDP_`$ip" `
        -Direction Inbound -Action Block -RemoteAddress `$ip `
        -Protocol TCP -LocalPort 3389 -Enabled `$true -ErrorAction SilentlyContinue
}
"@
    
    $banScript | Out-File "C:\SecurityConfig\apply_rdp_bans.ps1" -Force
    
    Write-Host "Ban list updated with $($banIPs.Count) IPs" -ForegroundColor Green
}

# Usage
Update-RDPBanList -DbPath "C:\RdpMon\RdpMon.db" -FailThreshold 50
```

#### IP Whitelist Protection

```powershell
# Whitelist legitimate IPs to prevent accidental blocking
$whitelistIPs = @(
    "10.0.0.5",      # Corporate VPN
    "203.0.113.1",   # Admin subnet
    "198.51.100.0/24" # Trusted network
)

# When creating ban rules, exclude whitelisted IPs
$analyzerOutput = .\1st-RdpMonSecurityAnalyzer.ps1 `
    -DbPath "C:\RdpMon\RdpMon.db" `
    -Type Attack `
    -OutputFormat Json | ConvertFrom-Json

$banIPs = $analyzerOutput.AddrResults | 
    Where-Object { $_.IP -notin $whitelistIPs } |
    Select-Object -ExpandProperty IP

Write-Host "IPs to ban (after whitelist filter): $($banIPs.Count)" -ForegroundColor Cyan
```

### 7.4 Third-Party Integration for IP Banning

#### Azure Sentinel Integration

```
# Send ban list to Azure Sentinel
function Send-BanListToAzureSentinel {
    param(
        [string]$DbPath,
        [string]$WorkspaceId,
        [string]$SharedKey
    )
    
    # Get attack data
    $attackData = .\1st-RdpMonSecurityAnalyzer.ps1 `
        -DbPath $DbPath `
        -Type Attack `
        -MinFails 10 `
        -OutputFormat Json | ConvertFrom-Json
    
    # Prepare JSON payload
    $banList = $attackData.AddrResults | Select-Object -Property @{
        Name = "TimeGenerated"
        Expression = { Get-Date -Format o }
    }, @{
        Name = "IpAddress"
        Expression = { $_.IP }
    }, @{
        Name = "FailureCount"
        Expression = { $_.FailCount }
    }, @{
        Name = "ActionType"
        Expression = { "RecommendedBan" }
    }
    
    # Send to Log Analytics
    $json = $banList | ConvertTo-Json
    
    $headers = @{
        "Log-Type" = "RDPMonBanList"
        "x-ms-date" = (Get-Date -Format r)
    }
    
    # Construct and send (requires Log Analytics integration)
    # This is a template - actual implementation requires Log Analytics API details
    
    Write-Host "Sent $($banList.Count) ban recommendations to Azure Sentinel" -ForegroundColor Green
}
```

#### Splunk Integration

```
# Stream attack data to Splunk HEC (HTTP Event Collector)
function Send-ToSplunk {
    param(
        [string]$DbPath,
        [string]$SplunkHecUrl,
        [string]$SplunkToken
    )
    
    # Get attack data
    $attackData = .\1st-RdpMonSecurityAnalyzer.ps1 `
        -DbPath $DbPath `
        -Type Attack `
        -OutputFormat Json | ConvertFrom-Json
    
    # Prepare headers
    $headers = @{
        "Authorization" = "Splunk $SplunkToken"
        "Content-Type" = "application/json"
    }
    
    # Send each event to Splunk
    foreach ($event in $attackData.AddrResults) {
        $splunkEvent = @{
            event = @{
                source = "RDPMon"
                sourcetype = "rdp:attack"
                host = $env:COMPUTERNAME
                time = [int](Get-Date -UFormat %s)
                data = $event
            }
        } | ConvertTo-Json
        
        try {
            Invoke-RestMethod -Uri $SplunkHecUrl -Method Post `
                -Headers $headers -Body $splunkEvent -ErrorAction Stop
        } catch {
            Write-Warning "Failed to send event to Splunk: $_"
        }
    }
    
    Write-Host "Sent attack data to Splunk HEC" -ForegroundColor Green
}
```

### 7.5 Ban List Export for External Systems

```
# Export ban list in various formats for different systems

# Format 1: CSV for Excel/database import
function Export-BanListCsv {
    param([string]$DbPath, [string]$OutputPath)
    
    .\1st-RdpMonSecurityAnalyzer.ps1 `
        -DbPath $DbPath `
        -Type Attack `
        -MinFails 10 `
        -OutputFormat Csv `
        -ExportPath $OutputPath
    
    Write-Host "Ban list exported to CSV: $OutputPath" -ForegroundColor Green
}

# Format 2: IP list for firewall blocklists
function Export-BanListIpOnly {
    param([string]$DbPath, [string]$OutputPath)
    
    $data = .\1st-RdpMonSecurityAnalyzer.ps1 `
        -DbPath $DbPath `
        -Type Attack `
        -MinFails 10 `
        -OutputFormat Json | ConvertFrom-Json
    
    $data.AddrResults.IP | Out-File -FilePath $OutputPath -Force
    
    Write-Host "IP blocklist exported to: $OutputPath" -ForegroundColor Green
}

# Format 3: JSON for API consumption
function Export-BanListJson {
    param([string]$DbPath, [string]$OutputPath)
    
    .\1st-RdpMonSecurityAnalyzer.ps1 `
        -DbPath $DbPath `
        -Type Attack `
        -MinFails 10 `
        -OutputFormat Json `
        -ExportPath $OutputPath
    
    Write-Host "Ban list exported to JSON: $OutputPath" -ForegroundColor Green
}

# Format 4: MikroTik firewall format
function Export-BanListMikroTik {
    param([string]$DbPath, [string]$OutputPath)
    
    $data = .\1st-RdpMonSecurityAnalyzer.ps1 `
        -DbPath $DbPath `
        -Type Attack `
        -MinFails 10 `
        -OutputFormat Json | ConvertFrom-Json
    
    $mikrotikScript = @"
# MikroTik firewall rules for RDP ban list
# Generated: $(Get-Date)
`n
"@
    
    foreach ($ip in $data.AddrResults.IP) {
        $mikrotikScript += "/ip firewall address-list add list=RDP_ATTACKERS address=$ip`n"
    }
    
    $mikrotikScript | Out-File -FilePath $OutputPath -Force
    
    Write-Host "MikroTik rules exported to: $OutputPath" -ForegroundColor Green
}
```

---

## 8. How It Works - Complete Architecture

### 8.1 Execution Flow Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│                      Script Initialization                          │
├─────────────────────────────────────────────────────────────────────┤
│ -  Validate PowerShell version (7.5+)                                │
│ -  Check parameter validity                                          │
│ -  Initialize global configuration                                   │
│ -  Set up debug/logging if enabled                                   │
└──────────────────────┬──────────────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    Dependency Resolution                            │
├─────────────────────────────────────────────────────────────────────┤
│ -  Check if LiteDB assembly is loaded                                │
│ -  Search standard locations for LiteDB.dll                          │
│ -  If not found and AutoInstallLiteDb:                               │
│   - Download v4.1.4 from GitHub releases                            │
│   - Extract to installation directory                               │
│   - Verify assembly integrity                                       │
└──────────────────────┬──────────────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────────────┐
│                   Database Connection                               │
├─────────────────────────────────────────────────────────────────────┤
│ -  Establish read-only connection to RDPMon.db                       │
│ -  Load LiteDB assembly if needed                                    │
│ -  Verify database accessibility                                     │
│ -  Run safe diagnostics on database structure                        │
└──────────────────────┬──────────────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────────────┐
│                   Data Extraction Phase                             │
├─────────────────────────────────────────────────────────────────────┤
│ -  Query Addr collection for IP-based data                           │
│ -  Extract Session collection for detailed sessions                  │
│ -  Read Prop collection for metadata                                 │
│ -  Convert BsonDocuments to PowerShell objects                       │
└──────────────────────┬──────────────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────────────┐
│                   Data Processing & Filtering                       │
├─────────────────────────────────────────────────────────────────────┤
│ -  Apply Type filter (All/Attack/Legit/Unknown)                      │
│ -  Filter by MinFails threshold                                      │
│ -  Apply date/time range filtering (From/To)                         │
│ -  Sort results (SortBy, Descending)                                 │
│ -  Apply limit to result set                                         │
│ -  Optionally resolve hostnames (IncludeResolved)                    │
│ -  Calculate metrics and statistics                                  │
└──────────────────────┬──────────────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────────────┐
│                   Output Format Selection                           │
├─────────────────────────────────────────────────────────────────────┤
│ -  Table: PowerShell Format-Table output                             │
│ -  List: Detailed list format                                        │
│ -  JSON: Structured JSON serialization                               │
│ -  CSV: Comma-separated values for Excel                             │
│ -  XML: XML document structure                                       │
│ -  HTML: Interactive web report with charts                          │
│ -  YAML: YAML configuration format                                   │
│ -  Text: Formatted text output                                       │
│ -  Markdown: Documentation-ready format                              │
│ -  Object: Raw PowerShell objects for scripting                      │
└──────────────────────┬──────────────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────────────┐
│                      Output Delivery                                │
├─────────────────────────────────────────────────────────────────────┤
│ If ExportPath specified:                                            │
│ -  Create output directory if needed                                 │
│ -  Write formatted data to file                                      │
│ -  Set appropriate file encoding (UTF-8)                             │
│                                                                     │
│ If console display requested:                                       │
│ -  Display results in console with color coding                      │
│ -  Show summary statistics                                           │
│ -  Display execution duration                                        │
└─────────────────────────────────────────────────────────────────────┘
```

### 8.2 Detailed Processing Steps

#### Step 1: LiteDB Loading

```
# Script attempts to load LiteDB in this order:
# 1. Check if already loaded in current domain
# 2. User-specified path (-LiteDbPath)
# 3. Script directory (./LiteDB/LiteDB.dll)
# 4. Database directory
# 5. Current directory
# 6. Windows PATH directories
# 7. Program Files directories
# 8. If AutoInstallLiteDb: Download and install from GitHub
```

#### Step 2: Database Query

```
# Read-only connection string
$connectionString = "Filename=$DbPath;ReadOnly=true;Utc=true"

# Opens database
$database = [LiteDB.LiteDatabase]::new($connectionString)

# Gets collections
$addrCollection = $database.GetCollection("Addr")
$sessionCollection = $database.GetCollection("Session")
$propCollection = $database.GetCollection("Prop")

# Queries all records
$allAddr = $addrCollection.FindAll()
$allSessions = $sessionCollection.FindAll()
```

#### Step 3: Data Transformation

```
# Converts each BsonDocument to PowerShell object
foreach ($record in $allAddr) {
    $psObject = @{
        IP = $record["_id"]
        FailCount = $record["FailCount"]
        SuccessCount = $record["SuccessCount"]
        FirstLocal = $record["First"]
        LastLocal = $record["Last"]
        UserNames = $record["UserNames"]
        ConnectionType = # Calculated from FailCount/SuccessCount
        Duration = # Calculated: Last - First
        Hostname = # Optionally resolved via DNS
    }
    
    # Apply filters
    if ($psObject.FailCount -ge $MinFails -and
        $psObject.LastLocal -ge $From -and
        $psObject.FirstLocal -le $To) {
        
        # Add to results
        $results += $psObject
    }
}
```

#### Step 4: Sorting and Limiting

```
# Sort results
$sorted = $results | Sort-Object -Property $SortBy `
    -Descending:$Descending

# Apply limit
$final = $sorted | Select-Object -First $Limit
```

#### Step 5: Report Generation

```
# Format according to OutputFormat
switch ($OutputFormat) {
    "Html" {
        $html = @"
        <!DOCTYPE html>
        <html>
        <head>
            <title>RDP Monitor Report</title>
            <link href="https://cdn.tailwindcss.com" rel="stylesheet">
            <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        </head>
        <body>
            <div class="container mx-auto p-6">
                <!-- Header -->
                <h1>RDP Security Analysis Report</h1>
                
                <!-- Statistics -->
                <div class="grid grid-cols-4 gap-4">
                    <!-- Summary cards -->
                </div>
                
                <!-- Charts -->
                anvas id="attackChart"></canvas>
                
                <!-- Table -->
                <table>
                    <!-- Data rows -->
                </table>
            </div>
        </body>
        </html>
        "@
        
        $html | Out-File -FilePath $ExportPath
    }
    
    "Csv" {
        $final | Export-Csv -Path $ExportPath -NoTypeInformation
    }
    
    "Json" {
        $final | ConvertTo-Json -Depth 5 | Out-File -FilePath $ExportPath
    }
    
    # ... other formats
}
```

---

## 9. Technical Components

### 9.1 Core Functions (Continued)

#### Process-EnhancedRdpMonData

**Purpose**: Applies filters and generates metrics

**Processing Steps**:
1. Apply type filtering (Attack/Legit/Mixed/Unknown)
2. Apply failure count threshold
3. Apply date/time range filtering
4. Calculate connection type classification
5. Resolve hostnames (if requested)
6. Generate statistical summaries
7. Create timeline data for charts

**Returns**: Hashtable with:
- AddrResults: Filtered IP records
- SessionResults: Filtered session records
- SummaryStats: Attack count, legit count, etc.
- EnhancedData: Chart data and statistics

#### ConvertTo-HtmlReport & ConvertTo-EnhancedHtmlReport

**Purpose**: Generate interactive HTML reports

**Features**:
- Responsive design with Tailwind CSS
- Interactive charts using Chart.js
- Color-coded result tables
- Auto-refresh capability
- Summary statistics display
- Mobile-friendly layout

### 9.2 Support Functions

#### Install-LiteDbAutomatically

```
# Downloads and installs LiteDB from GitHub
# Parameters:
#   -InstallPath: Directory to install to
#   -Version: Specific version (default: "4.1.4")
#   -Force: Force reinstallation
#   -NoProgress: Suppress progress indicators

# Returns: Path to installed LiteDB.dll assembly
```

#### Test-LiteDbInstallation

```
# Checks if LiteDB is properly installed
# Returns: Hashtable with:
#   Installed: Boolean
#   Version: Version number
#   AssemblyPath: Full path to assembly
#   IsValid: Can assembly be loaded
#   Error: Any error messages
```

#### Get-RdpMonDatabaseStructure

```
# Safely analyzes database structure
# Returns: Hashtable with:
#   Collections: List of collections
#   Structure: Detailed structure info
#   Errors: Any errors encountered
#   IsCorrupted: Boolean indicating corruption
```

#### Export-RdpMonDataToCsv

```
# Emergency export for corrupted databases
# Extracts readable data to CSV
# Skips corrupted records gracefully
```

#### Repair-RdpMonDatabase

```
# Attempts to repair corrupted database
# Process:
#   1. Opens corrupted database in read-only
#   2. Creates new database file
#   3. Copies readable records only
#   4. Creates backup of original
#   5. Returns path to repaired database
```

### 9.3 Output Formatters

| Format | Function | Use Case |
|--------|----------|----------|
| **Table** | Format-Table | Console display |
| **List** | Format-List | Detailed console view |
| **JSON** | ConvertTo-Json | API/SIEM integration |
| **CSV** | Export-Csv | Excel/data analysis |
| **XML** | ConvertTo-Xml | Enterprise systems |
| **HTML** | ConvertTo-HtmlReport | Web reports |
| **YAML** | Custom formatter | Configuration files |
| **Markdown** | Custom formatter | Documentation |
| **Text** | Custom formatter | Simple text output |

---

## 10. Usage Examples

### 10.1 Basic Analysis

```
# Simplest possible usage
.\1st-RdpMonSecurityAnalyzer.ps1 -DbPath "C:\RdpMon\RdpMon.db"

# View in console with color coding
.\1st-RdpMonSecurityAnalyzer.ps1 -DbPath "C:\RdpMon\RdpMon.db" -OutputFormat Table

# Export to file
.\1st-RdpMonSecurityAnalyzer.ps1 `
  -DbPath "C:\RdpMon\RdpMon.db" `
  -OutputFormat Csv `
  -ExportPath "rdpmon_report.csv"
```

### 10.2 Security Analysis

```
# Find all brute force attacks (50+ failures)
.\1st-RdpMonSecurityAnalyzer.ps1 `
  -DbPath "C:\RdpMon\RdpMon.db" `
  -Type Attack `
  -MinFails 50 `
  -OutputFormat Html `
  -ExportPath "brute_force_attacks.html"

# Identify persistent attackers (attacking for >7 days)
.\1st-RdpMonSecurityAnalyzer.ps1 `
  -DbPath "C:\RdpMon\RdpMon.db" `
  -From (Get-Date).AddDays(-30) `
  -OutputFormat Json | 
  ConvertFrom-Json |
  Select-Object -ExpandProperty AddrResults |
  Where-Object { $_.Duration.TotalDays -gt 7 }

# Find mixed activity (both success and failures = compromised account?)
.\1st-RdpMonSecurityAnalyzer.ps1 `
  -DbPath "C:\RdpMon\RdpMon.db" `
  -Type Legit `
  -MinFails 1 `
  -OutputFormat Csv `
  -ExportPath "suspicious_accounts.csv"
```

### 10.3 Threat Intelligence

```
# Get top 10 attacker IPs
.\1st-RdpMonSecurityAnalyzer.ps1 `
  -DbPath "C:\RdpMon\RdpMon.db" `
  -Type Attack `
  -SortBy FailCount `
  -Descending `
  -Limit 10 `
  -IncludeResolved

# Export for threat intelligence platform
.\1st-RdpMonSecurityAnalyzer.ps1 `
  -DbPath "C:\RdpMon\RdpMon.db" `
  -Type Attack `
  -OutputFormat Json `
  -ExportPath "threat_intel_export.json"
```

### 10.4 Compliance & Auditing

```
# 90-day audit trail
.\1st-RdpMonSecurityAnalyzer.ps1 `
  -DbPath "C:\RdpMon\RdpMon.db" `
  -From (Get-Date).AddDays(-90) `
  -OutputFormat Html `
  -ExportPath "quarterly_audit.html"

# Monthly report with auto-refresh
.\1st-RdpMonSecurityAnalyzer.ps1 `
  -DbPath "C:\RdpMon\RdpMon.db" `
  -From (Get-Date).AddMonths(-1) `
  -OutputFormat Html `
  -ExportPath "monthly_report.html" `
  -AutoRefreshInterval 300
```

### 10.5 Advanced Filtering

```
# Attacks in specific time window
.\1st-RdpMonSecurityAnalyzer.ps1 `
  -DbPath "C:\RdpMon\RdpMon.db" `
  -From "2025-12-20 00:00:00" `
  -To "2025-12-28 23:59:59" `
  -Type Attack

# Sort by duration (longest running attacks)
.\1st-RdpMonSecurityAnalyzer.ps1 `
  -DbPath "C:\RdpMon\RdpMon.db" `
  -SortBy Duration `
  -Descending `
  -Limit 20

# Limit to top 5 by success count
.\1st-RdpMonSecurityAnalyzer.ps1 `
  -DbPath "C:\RdpMon\RdpMon.db" `
  -SortBy SuccessCount `
  -Descending `
  -Limit 5 `
  -Type Legit
```

### 10.6 Database Troubleshooting

```
# Diagnose database issues
.\1st-RdpMonSecurityAnalyzer.ps1 `
  -DbPath "C:\RdpMon\RdpMon.db" `
  -DebugMode

# Emergency export from potentially corrupted database
.\1st-RdpMonSecurityAnalyzer.ps1 `
  -DbPath "C:\RdpMon\RdpMon.db" `
  -ExportRawData `
  -RawExportPath "emergency_backup.csv"

# Repair corrupted database
.\1st-RdpMonSecurityAnalyzer.ps1 `
  -DbPath "C:\RdpMon\RdpMon.db" `
  -RepairDatabase `
  -RepairOutputPath "C:\Backups\RdpMon_Repaired.db"
```

---

## 11. Parameters Reference

### 11.1 Database Parameters

| Parameter | Type | Required | Description | Example |
|-----------|------|----------|-------------|---------|
| `DbPath` | String | **YES** | Path to RDPMon LiteDB database file | `"C:\RdpMon\RdpMon.db"` |
| `LiteDbPath` | String | No | Custom path to LiteDB.dll or directory | `"C:\Libraries\LiteDB"` |
| `LiteDbInstallPath` | String | No | Installation directory for auto-install | `"C:\LiteDB"` |
| `AutoInstallLiteDb` | Switch | No | Download LiteDB from GitHub if missing | `-AutoInstallLiteDb` |
| `LiteDbVersion` | String | No | Specific LiteDB version to install | `-LiteDbVersion "4.1.4"` |
| `ForceLiteDbInstall` | Switch | No | Force reinstall even if exists | `-ForceLiteDbInstall` |
| `SkipLiteDbInstall` | Switch | No | Skip auto-installation | `-SkipLiteDbInstall` |

### 11.2 Filtering Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `Type` | String | "All" | Filter by type: All, Attack, Legit, Unknown |
| `MinFails` | Int32 | 0 | Minimum failed attempts to include |
| `From` | DateTime | MinValue | Start date filter (local time) |
| `To` | DateTime | MaxValue | End date filter (local time) |
| `Limit` | Int32 | MaxValue | Maximum results to return |
| `IncludeResolved` | Switch | $false | Include DNS-resolved hostnames |

### 11.3 Output Parameters

| Parameter | Type | Default | Options |
|-----------|------|---------|---------|
| `OutputFormat` | String | "Table" | Table, List, Json, Csv, Xml, Html, Text, Yaml, Markdown, Object |
| `ExportPath` | String | - | File path for output |
| `SortBy` | String | "LastLocal" | IP, FailCount, SuccessCount, FirstLocal, LastLocal, Duration |
| `Descending` | Switch | $false | Sort in reverse order |
| `AutoRefreshInterval` | Int32 | 30 | HTML report refresh in seconds (5-3600) |
| `HtmlTemplatePath` | String | - | Custom HTML template file |

### 11.4 Debugging Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `DebugMode` | Switch | $false | Enable detailed debug logging |
| `NoProgress` | Switch | $false | Disable progress bars |
| `GitHubToken` | String | - | GitHub API token for higher rate limits |
| `RepairDatabase` | Switch | $false | Attempt database repair |
| `RepairOutputPath` | String | - | Output path for repaired database |
| `ExportRawData` | Switch | $false | Export raw data from damaged DB |
| `RawExportPath` | String | "RdpMon_RawExport.csv" | Output path for raw export |

---

## 12. Output Formats

### 12.1 Table Format (Default)

```
IP Address     Type     Failed  Success  Total  First Attempt           Last Attempt            Duration
----------     ----     ------  -------  -----  --------------          ----------------        --------
192.168.1.100  Attack   145     0        145    2025-12-15 08:30:00     2025-12-28 18:45:00     13d 10h
10.0.0.50      Legit    5       12       17     2025-12-20 10:15:00     2025-12-28 14:20:00     8d 04h
203.0.113.25   Attack   89      0        89     2025-12-18 14:22:00     2025-12-28 09:55:00     10d
```

### 12.2 JSON Format

```
{
  "AddrResults": [
    {
      "IP": "192.168.1.100",
      "Hostname": null,
      "FailCount": 145,
      "SuccessCount": 0,
      "TotalAttempts": 145,
      "FirstLocal": "2025-12-15T08:30:00",
      "LastLocal": "2025-12-28T18:45:00",
      "ConnectionType": "Attack",
      "Duration": {
        "Days": 13,
        "Hours": 10,
        "Minutes": 15,
        "Seconds": 0,
        "TotalDays": 13.427083,
        "TotalHours": 322.25
      }
    }
  ],
  "SummaryStats": {
    "TotalRecords": 145,
    "UniqueIPs": 42,
    "AttackCount": 28,
    "LegitCount": 12,
    "MixedCount": 2
  }
}
```

### 12.3 CSV Format

```
IP,Type,FailCount,SuccessCount,TotalAttempts,FirstLocal,LastLocal,Duration
192.168.1.100,Attack,145,0,145,2025-12-15T08:30:00,2025-12-28T18:45:00,13.427083
10.0.0.50,Legit,5,12,17,2025-12-20T10:15:00,2025-12-28T14:20:00,8.176389
203.0.113.25,Attack,89,0,89,2025-12-18T14:22:00,2025-12-28T09:55:00,9.814167
```

### 12.4 HTML Format

Features:
- Responsive design with Tailwind CSS
- Interactive Chart.js visualizations
- Sortable data tables
- Auto-refresh capability
- Summary statistics
- Mobile-friendly layout
- Dark mode support
- Real-time filtering

---

## 13. Advanced Scenarios

### 13.1 Automated Daily Security Reports

```
# Create scheduled task for daily reports
$scriptPath = "C:\Scripts\1st-RdpMonSecurityAnalyzer.ps1"
$reportPath = "C:\Reports\Daily-$(Get-Date -Format 'yyyyMMdd').html"

$action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument `
  "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`" " + `
  "-DbPath `"C:\RdpMon\RdpMon.db`" " + `
  "-OutputFormat Html " + `
  "-ExportPath `"$reportPath`" " + `
  "-AutoRefreshInterval 300"

$trigger = New-ScheduledTaskTrigger -Daily -At "02:00"

Register-ScheduledTask -TaskName "RDP Security Daily Report" `
  -Action $action -Trigger $trigger -RunLevel Highest -Force

Write-Host "Daily report task created - runs at 2:00 AM daily" -ForegroundColor Green
```

### 13.2 Real-Time Monitoring with Alerts

```
# Monitor for new attacks and trigger alerts
function Start-RdpMonRealTimeMonitoring {
    param(
        [string]$DbPath,
        [int]$AlertThreshold = 50,
        [int]$CheckIntervalSeconds = 300
    )
    
    $lastCheck = Get-Date
    
    while ($true) {
        try {
            # Get current data
            $current = .\1st-RdpMonSecurityAnalyzer.ps1 `
                -DbPath $DbPath `
                -Type Attack `
                -MinFails $AlertThreshold `
                -OutputFormat Json | ConvertFrom-Json
            
            # Count critical attacks
            $criticalCount = ($current.AddrResults | 
                Where-Object { $_.FailCount -gt 100 }).Count
            
            if ($criticalCount -gt 0) {
                # Send alert
                $alertMessage = "ALERT: $criticalCount critical RDP attacks detected!"
                Write-Host $alertMessage -ForegroundColor Red
                
                # Could integrate with email/Teams/Slack here
                # Send-AlertToTeams -Message $alertMessage
                
                # Log to event log
                Write-EventLog -LogName "Application" `
                    -Source "RDPMonAnalyzer" `
                    -EventId 1001 `
                    -Message $alertMessage
            }
            
            # Wait for next check
            Start-Sleep -Seconds $CheckIntervalSeconds
            
        } catch {
            Write-Warning "Monitoring error: $_"
            Start-Sleep -Seconds 60
        }
    }
}

# Usage: Run in background
# Start-RdpMonRealTimeMonitoring -DbPath "C:\RdpMon\RdpMon.db" -AlertThreshold 50
```

### 13.3 SIEM Integration (Splunk/ELK)

```
# Export data to Splunk HEC
function Send-RdpMonToSplunk {
    param(
        [string]$DbPath,
        [string]$SplunkHecUrl,
        [string]$SplunkToken
    )
    
    $data = .\1st-RdpMonSecurityAnalyzer.ps1 `
        -DbPath $DbPath `
        -OutputFormat Json | ConvertFrom-Json
    
    $headers = @{
        "Authorization" = "Splunk $SplunkToken"
        "Content-Type" = "application/json"
    }
    
    foreach ($record in $data.AddrResults) {
        $event = @{
            event = $record
            source = "rdpmon"
            sourcetype = "rdp:attempt"
            host = $env:COMPUTERNAME
            time = [int](Get-Date -UFormat %s)
        } | ConvertTo-Json
        
        try {
            Invoke-RestMethod -Uri $SplunkHecUrl -Method Post `
                -Headers $headers -Body $event -ErrorAction Stop
        } catch {
            Write-Warning "Failed to send to Splunk: $_"
        }
    }
    
    Write-Host "Sent $($data.AddrResults.Count) records to Splunk" -ForegroundColor Green
}

# Usage
# Send-RdpMonToSplunk -DbPath "C:\RdpMon\RdpMon.db" `
#   -SplunkHecUrl "https://splunk.company.com:8088/services/collector" `
#   -SplunkToken "your-token-here"
```

### 13.4 Threat Intelligence Correlation

```
# Cross-reference with external threat intelligence
function Get-ThreatIntelligence {
    param(
        [string]$IpAddress,
        [string]$AbuseIpDbToken
    )
    
    # Query AbuseIPDB for IP reputation
    $uri = "https://api.abuseipdb.com/api/v2/check"
    
    $body = @{
        ipAddress = $IpAddress
        maxAgeInDays = 90
    }
    
    $headers = @{
        "Key" = $AbuseIpDbToken
        "Accept" = "application/json"
    }
    
    try {
        $response = Invoke-RestMethod -Uri $uri -Method Get `
            -Body $body -Headers $headers
        
        return @{
            IpAddress = $IpAddress
            AbuseScore = $response.data.abuseConfidenceScore
            TotalReports = $response.data.totalReports
            ReportCategories = $response.data.reports.categories
        }
    } catch {
        Write-Warning "Failed to query threat intelligence: $_"
        return $null
    }
}

# Correlate RDPMon attacks with threat intelligence
function Correlate-WithThreatIntel {
    param(
        [string]$DbPath,
        [string]$AbuseIpDbToken
    )
    
    $attacks = .\1st-RdpMonSecurityAnalyzer.ps1 `
        -DbPath $DbPath `
        -Type Attack `
        -MinFails 20 `
        -OutputFormat Json | ConvertFrom-Json
    
    $results = @()
    
    foreach ($attack in $attacks.AddrResults) {
        $intel = Get-ThreatIntelligence -IpAddress $attack.IP `
            -AbuseIpDbToken $AbuseIpDbToken
        
        $results += @{
            IP = $attack.IP
            LocalFailures = $attack.FailCount
            ExternalReports = $intel.TotalReports
            AbuseScore = $intel.AbuseScore
            RiskLevel = if ($intel.AbuseScore -gt 75) { "CRITICAL" } `
                       elseif ($intel.AbuseScore -gt 50) { "HIGH" } `
                       else { "MEDIUM" }
        }
    }
    
    return $results | Sort-Object -Property AbuseScore -Descending
}
```

### 13.5 Multi-Server Aggregation

```
# Aggregate RDP monitoring data from multiple servers
function Aggregate-RdpMonServers {
    param(
        [string[]]$ServerNames,
        [string]$OutputPath
    )
    
    $allData = @()
    
    foreach ($server in $ServerNames) {
        Write-Host "Collecting from $server..." -ForegroundColor Cyan
        
        try {
            # Copy remote database locally
            $remoteDb = "\\$server\C$\RdpMon\RdpMon.db"
            $localDb = "$env:TEMP\RdpMon_$server.db"
            
            Copy-Item -Path $remoteDb -Destination $localDb -Force
            
            # Analyze remote data
            $serverData = .\1st-RdpMonSecurityAnalyzer.ps1 `
                -DbPath $localDb `
                -OutputFormat Json | ConvertFrom-Json
            
            # Add server identifier
            $serverData.AddrResults | ForEach-Object {
                $_ | Add-Member -NotePropertyName "SourceServer" -NotePropertyValue $server
            }
            
            $allData += $serverData.AddrResults
            
        } catch {
            Write-Warning "Failed to collect from $server : $_"
        }
    }
    
    # Export aggregated data
    $allData | Sort-Object -Property FailCount -Descending |
        Export-Csv -Path $OutputPath -NoTypeInformation -Force
    
    Write-Host "Aggregated data from $($ServerNames.Count) servers" -ForegroundColor Green
    Write-Host "Results saved to: $OutputPath" -ForegroundColor Green
}

# Usage
# Aggregate-RdpMonServers -ServerNames @("SRV01", "SRV02", "SRV03") `
#   -OutputPath "C:\Reports\aggregated_rdp_attacks.csv"
```

---

## 14. Troubleshooting & Debugging

### 14.1 Common Issues & Solutions

#### Issue: "LiteDB assembly not found"

**Cause**: LiteDB.dll is not installed or not found in search paths

**Solutions**:

```
# Solution 1: Auto-install from GitHub
.\1st-RdpMonSecurityAnalyzer.ps1 `
  -DbPath "C:\RdpMon\RdpMon.db" `
  -AutoInstallLiteDb `
  -LiteDbVersion "4.1.4"

# Solution 2: Specify custom path
.\1st-RdpMonSecurityAnalyzer.ps1 `
  -DbPath "C:\RdpMon\RdpMon.db" `
  -LiteDbPath "C:\Libraries\LiteDB\LiteDB.dll"

# Solution 3: Manual download and install
$tempFile = "$env:TEMP\LiteDB.4.1.4.nupkg"
Invoke-WebRequest -Uri "https://www.nuget.org/api/v2/package/LiteDB/4.1.4" `
  -OutFile $tempFile
Expand-Archive -Path $tempFile -DestinationPath "$PSScriptRoot\LiteDB" -Force
```

#### Issue: "Database file not found"

**Cause**: RDPMon database path is incorrect

**Solutions**:

```
# Find RDPMon database location
Get-ChildItem -Path "C:\" -Name "RdpMon.db" -Recurse -ErrorAction SilentlyContinue

# Check common installation paths
Test-Path "C:\RdpMon\RdpMon.db"
Test-Path "C:\Program Files\Cameyo\RdpMon.db"
Test-Path "$env:APPDATA\Cameyo\RdpMon.db"
```

#### Issue: "Cannot open database - corrupted"

**Cause**: Database file is corrupted or locked

**Solutions**:

```
# Check if file is locked
Get-Process | Where-Object { $_.Handles -contains "RdpMon.db" }

# Stop RDPMon service if running
Stop-Service -Name "CameyoRdpMon" -Force -ErrorAction SilentlyContinue

# Attempt repair
.\1st-RdpMonSecurityAnalyzer.ps1 `
  -DbPath "C:\RdpMon\RdpMon.db" `
  -RepairDatabase `
  -RepairOutputPath "C:\RdpMon\RdpMon_Repaired.db"

# Or emergency export
.\1st-RdpMonSecurityAnalyzer.ps1 `
  -DbPath "C:\RdpMon\RdpMon.db" `
  -ExportRawData `
  -RawExportPath "emergency_data.csv"
```

#### Issue: "Execution policy prevents running"

**Cause**: PowerShell execution policy blocks script execution

**Solutions**:

```
# Check current policy
Get-ExecutionPolicy -Scope CurrentUser

# Set user-level policy
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser -Force

# Or bypass for single command
powershell -ExecutionPolicy Bypass -File "1st-RdpMonSecurityAnalyzer.ps1" `
  -DbPath "C:\RdpMon\RdpMon.db"
```

### 14.2 Debug Mode Detailed Output

```
# Enable comprehensive debugging
.\1st-RdpMonSecurityAnalyzer.ps1 `
  -DbPath "C:\RdpMon\RdpMon.db" `
  -DebugMode `
  -OutputFormat Html `
  -ExportPath "debug_report.html"

# This will show:
# - Script initialization details
# - LiteDB loading progress
# - Database connection info
# - Data extraction steps
# - Filter application
# - Output generation
# - Execution timing for each phase
```

## 14.3 Health Check Script

```
function Test-RdpMonAnalyzerHealth {
    Write-Host "🔍 RDP Monitor Analyzer Health Check" -ForegroundColor Cyan
    Write-Host "=" * 60
    
    $psVersion = $PSVersionTable.PSVersion
    Write-Host "PowerShell Version: $psVersion" -ForegroundColor $(
        if ($psVersion -ge "7.5") { "Green" } else { "Red" }
    )
    
    $scriptExists = Test-Path "1st-RdpMonSecurityAnalyzer.ps1"
    Write-Host "Script File: $(if($scriptExists) { '✓' } else { '✗' })" -ForegroundColor $(
        if ($scriptExists) { "Green" } else { "Red" }
    )
    
    $dbExists = Test-Path "C:\RdpMon\RdpMon.db"
    Write-Host "RDPMon Database: $(if($dbExists) { '✓' } else { '✗' })" -ForegroundColor $(
        if ($dbExists) { "Green" } else { "Red" }
    )
    
    try {
        $null = Add-Type -AssemblyName "LiteDB" -ErrorAction Stop
        Write-Host "LiteDB Assembly: ✓" -ForegroundColor Green
    } catch {
        Write-Host "LiteDB Assembly: ✗ (can auto-install)" -ForegroundColor Yellow
    }
    
    $policy = Get-ExecutionPolicy -Scope CurrentUser
    Write-Host "Execution Policy: $policy" -ForegroundColor $(
        if ($policy -in @("RemoteSigned", "Unrestricted", "Bypass")) { "Green" } else { "Red" }
    )
    
    try {
        $testFile = "$env:TEMP\rdpmon_test_$([guid]::NewGuid()).tmp"
        New-Item -Path $testFile -Force | Out-Null
        Remove-Item -Path $testFile -Force
        Write-Host "Write Permissions: ✓" -ForegroundColor Green
    } catch {
        Write-Host "Write Permissions: ✗" -ForegroundColor Red
    }
    
    Write-Host "=" * 60
    Write-Host "Health check complete." -ForegroundColor Cyan
}

Test-RdpMonAnalyzerHealth
```

## 15. Performance Optimization

### 15.1 Large Database Handling

```
function Process-LargeDatabase-ByMonth {
    param([string]$DbPath)
    
    $months = 12
    
    for ($i = 0; $i -lt $months; $i++) {
        $startDate = (Get-Date).AddMonths(-$i).AddDays(-30)
        $endDate = (Get-Date).AddMonths(-$i)
        
        Write-Host "Processing $($startDate.ToString('MMMM yyyy'))..." -ForegroundColor Cyan
        
        .\1st-RdpMonSecurityAnalyzer.ps1 `
            -DbPath $DbPath `
            -From $startDate `
            -To $endDate `
            -OutputFormat Csv `
            -ExportPath "rdpmon_$($startDate.ToString('yyyyMM')).csv"
    }
}

function Get-TopAttackers {
    param([string]$DbPath, [int]$Count = 100)
    
    .\1st-RdpMonSecurityAnalyzer.ps1 `
        -DbPath $DbPath `
        -Type Attack `
        -MinFails 50 `
        -SortBy FailCount `
        -Descending `
        -Limit $Count `
        -OutputFormat Json | ConvertFrom-Json
}

function Process-MultipleServers-Parallel {
    param(
        [string[]]$Servers,
        [string]$DbPath = "C:\RdpMon\RdpMon.db"
    )
    
    $scriptBlock = {
        param($Server, $DbPath, $ScriptPath)
        
        $remoteDb = "\\$Server\C$\$(($DbPath -split '\\')[-1])"
        
        if (Test-Path $remoteDb) {
            & $ScriptPath -DbPath $remoteDb -OutputFormat Json
        }
    }
    
    $results = Invoke-Command -ComputerName $Servers `
        -ScriptBlock $scriptBlock `
        -ArgumentList @($null, $DbPath, (Get-Location)) `
        -ThrottleLimit 10
    
    return $results
}
```

### 15.2 Memory Management

```
function Monitor-ScriptMemory {
    param([string]$DbPath)
    
    $process = Get-Process -Id $PID
    $initialMemory = $process.WorkingSet / 1MB
    
    Write-Host "Initial Memory: $initialMemory MB" -ForegroundColor Gray
    
    $result = .\1st-RdpMonSecurityAnalyzer.ps1 `
        -DbPath $DbPath `
        -OutputFormat Json | ConvertFrom-Json
    
    $process = Get-Process -Id $PID
    $finalMemory = $process.WorkingSet / 1MB
    $used = $finalMemory - $initialMemory
    
    Write-Host "Final Memory: $finalMemory MB" -ForegroundColor Gray
    Write-Host "Memory Used: $used MB" -ForegroundColor Green
    
    return $result
}

function Process-AndCleanup {
    param([string]$DbPath)
    
    try {
        $data = .\1st-RdpMonSecurityAnalyzer.ps1 `
            -DbPath $DbPath `
            -OutputFormat Json | ConvertFrom-Json
        
        return $data
    } finally {
        [gc]::Collect()
        [gc]::WaitForPendingFinalizers()
    }
}
```

### 15.3 Network Optimization

```
function Analyze-RemoteRdpMon {
    param(
        [string]$ComputerName,
        [string]$RemoteDbPath = "C:\RdpMon\RdpMon.db"
    )
    
    $cacheDir = "$env:TEMP\RdpMonCache"
    New-Item -ItemType Directory -Path $cacheDir -Force | Out-Null
    
    $cacheFile = Join-Path $cacheDir "RdpMon_$ComputerName.db"
    $remoteFile = "\\$ComputerName\$(($RemoteDbPath -split ':\\').Replace('\', '$'))"[1]
    
    if (-not (Test-Path $cacheFile) -or 
        ((Get-Item $cacheFile).LastWriteTime -lt (Get-Date).AddHours(-1))) {
        
        Write-Host "Updating cache from $ComputerName..." -ForegroundColor Cyan
        Copy-Item -Path $remoteFile -Destination $cacheFile -Force
    }
    
    .\1st-RdpMonSecurityAnalyzer.ps1 `
        -DbPath $cacheFile `
        -OutputFormat Json | ConvertFrom-Json
}
```

---

## 16. Security Considerations

### 16.1 Data Protection

```
function Protect-AnalysisReport {
    param(
        [string]$ReportPath,
        [string[]]$AdminGroupMembers
    )
    
    icacls $ReportPath /inheritance:r
    icacls $ReportPath /grant:r "Administrators:(F)"
    
    foreach ($user in $AdminGroupMembers) {
        icacls $ReportPath /grant:r "$user:(F)"
    }
    
    Write-Host "Report permissions secured: $ReportPath" -ForegroundColor Green
}

function Export-EncryptedReport {
    param(
        [string]$DbPath,
        [string]$OutputPath,
        [securestring]$EncryptionKey
    )
    
    $report = .\1st-RdpMonSecurityAnalyzer.ps1 `
        -DbPath $DbPath `
        -OutputFormat Json -ExportPath $OutputPath
    
    $plainText = Get-Content -Path $OutputPath -Raw
    $encryptedBytes = ConvertTo-SecureString -String $plainText -AsPlainText -Force
    $encryptedContent = $encryptedBytes | ConvertFrom-SecureString -SecureKey $EncryptionKey
    
    $encryptedContent | Out-File -FilePath "$OutputPath.encrypted" -Force
    Remove-Item -Path $OutputPath -Force
    
    Write-Host "Report encrypted: $OutputPath.encrypted" -ForegroundColor Green
}
```

### 16.2 Audit Logging

```
function Enable-RdpMonAuditLogging {
    if (-not [System.Diagnostics.EventLog]::SourceExists("RDPMonAnalyzer")) {
        New-EventLog -LogName "Application" -Source "RDPMonAnalyzer"
    }
    
    Write-Host "Audit logging enabled" -ForegroundColor Green
}

function Log-RdpMonExecution {
    param(
        [string]$DbPath,
        [string]$OutputFormat,
        [string]$ExportPath,
        [hashtable]$Filters
    )
    
    $message = @"
RDPMon Analysis Execution
Database: $DbPath
Format: $OutputFormat
Export: $ExportPath
Filters: $($Filters | ConvertTo-Json -Compress)
Timestamp: $(Get-Date -Format o)
User: $env:USERNAME
Computer: $env:COMPUTERNAME
"@
    
    Write-EventLog -LogName "Application" -Source "RDPMonAnalyzer" `
        -EventId 1000 -Message $message -EntryType Information
}
```

### 16.3 Access Control

```
function Set-RdpMonExecutionPolicy {
    param(
        [string[]]$AuthorizedUsers,
        [string]$ScriptPath
    )
    
    $allowedAccounts = $AuthorizedUsers | ForEach-Object { "BUILTIN\$_" }
    
    $acl = Get-Acl -Path $ScriptPath
    $acl.SetAccessRuleProtection($true, $false)
    
    foreach ($account in $allowedAccounts) {
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $account, "ReadAndExecute", "Allow"
        )
        $acl.AddAccessRule($rule)
    }
    
    Set-Acl -Path $ScriptPath -AclObject $acl
    
    Write-Host "Execution policy set for: $($allowedAccounts -join ', ')" -ForegroundColor Green
}
```

---

## 17. Contributing

### 17.1 Development Guidelines

```
git clone https://github.com/paulmann/RDPAudit.git
cd 1st-RDPMon

git checkout -b feature/your-feature-name

.\1st-RdpMonSecurityAnalyzer.ps1 -DbPath "test_database.db" -DebugMode
```

### 17.2 Testing Requirements

- Test with various database sizes (small, medium, large)
- Verify all output formats work correctly
- Test with corrupted database scenarios
- Validate parameter combinations
- Check memory usage and performance

### 17.3 Code Quality Standards

- Follow PowerShell best practices
- Use proper error handling with try/catch
- Include descriptive comments
- Maintain function documentation
- Use consistent naming conventions

### 17.4 Submission Process

1. Fork the repository
2. Create a feature branch
3. Make your improvements
4. Test thoroughly
5. Submit a pull request with detailed description

---

## 18. License & Acknowledgments

### 18.1 License

This project is licensed under the **MIT License**.

**MIT License Summary:**
- ✅ Commercial use permitted
- ✅ Modification allowed
- ✅ Distribution permitted
- ✅ Private use allowed
- ⚠️ Include license in distributions
- ⚠️ Include copyright notice

### 18.2 Copyright

Copyright © 2025 Mikhail Deynekin. All rights reserved.

**Author**: Mikhail Deynekin
- Email: [m@deynekin.com](mailto:m@deynekin.com)
- Website: [https://deynekin.com](https://deynekin.com)
- GitHub: [https://github.com/paulmann](https://github.com/paulmann)

### 18.3 Acknowledgments

- **Cameyo** - For the RDPMon monitoring solution
- **LiteDB Community** - For the lightweight database engine
- **PowerShell Team** - For the powerful scripting platform
- **Security Community** - For threat intelligence and best practices

### 18.4 Support & Documentation

- **GitHub Repository**: https://github.com/paulmann/RDPAudit
- **Issues & Support**: https://github.com/paulmann/RDPAudit/issues
- **Related Projects**:
  - [Get-Windows-Security-Events-By-IP](https://github.com/paulmann/Get-Windows-Security-Events-By-IP)
  - [sr-search-replace](https://github.com/paulmann/sr-search-replace)

---

## 🚀 Quick Start & Deployment

Get started in under a minute. This example uses the essential parameters for a security audit.

```powershell
# Download and execute the security analyzer
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/paulmann/RDPAudit/main/1st-RdpMonSecurityAnalyzer.ps1" `
    -OutFile "1st-RdpMonSecurityAnalyzer.ps1"

# Enable script execution (if needed)
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser -Force

# Run a comprehensive analysis with HTML report
.\1st-RdpMonSecurityAnalyzer.ps1 `
    -DbPath "C:\Logs\RdpMon.db" `
    -AutoInstallLiteDb `
    -OutputFormat Html `
    -ExportPath "Rdp_Security_Audit_Report.html"
```

> **Note:** Run PowerShell as Administrator for full system access. Use `-Help` parameter to see all advanced options.

---

## ⭐ Support the Project

If this tool has made your security auditing easier or helped secure your systems, please consider giving it a star on GitHub. It helps others discover the project and motivates further development.

[![GitHub Stars](https://img.shields.io/github/stars/paulmann/RDPAudit?style=social)](https://github.com/paulmann/RDPAudit/stargazers)

---

## 📬 Connect & Contribute

We welcome feedback, questions, and contributions to make this tool better for everyone.

| Channel | Purpose | Link |
| :--- | :--- | :--- |
| **🐛 Issues** | Report bugs, request features, or ask questions. | [GitHub Issues](https://github.com/paulmann/RDPAudit/issues) |
| **📧 Email** | For direct, private, or sensitive inquiries. | [m@deynekin.com](mailto:m@deynekin.com) |
| **💡 Suggestion** | Have an idea? Open an issue with the `enhancement` label. | [Open Suggestion](https://github.com/paulmann/RDPAudit/issues/new?labels=enhancement) |

**Before reporting an issue**, please check the existing issues to avoid duplicates.

---

**v1.0.0** • **December 2025** • **`Enterprise-Ready`** • **`Active`**  
**Transform RDP Monitoring into Actionable Security Intelligence.**

© 2025 Paulmann. This project is released under its respective [License](LICENSE).
