#Requires -Version 7.0
<#
.SYNOPSIS
	RdpAudit prerequisite checker and full installation script.

.DESCRIPTION
	Checks all required prerequisites, prints installed versions, offers to install
	missing components through winget, re-checks the environment, downloads the
	RdpAudit source tree, patches vulnerable package references, restores NuGet
	packages, builds Release, runs tests, publishes binaries and launches the
	Configurator executable.

.NOTES
	Author : Mikhail Deynekin - https://Deynekin.com - Mikhail@Deynekin.com
	Version: 1.5.0

.FEATURES
	Detects and reports any previously installed RdpAudit version (with version number).
	Gracefully stops the running Service, Configurator and MikroTik configurator,
	escalating to a forced termination only if they do not exit within a soft timeout.
	Ensures the build/runtime prerequisites required by the RdpAudit.Mikrotik module
	(Windows Desktop targeting pack, win-x64 restore, patched MessagePack) are present.
	Prints a final installation Summary describing what was done, installed, fixed and
	to which version the software was upgraded — including next-step guidance for a
	fresh, clean installation.
	Sync-Repository (v1.2.5) now verifies/repairs the remote origin URL, performs a
	full-refspec fetch to break --single-branch limitations, and uses a safe
	'checkout -B' so a missing local branch no longer aborts the installer.
	v1.5.0 adds RDPAudit 2.0 prerequisite awareness: ETW event channel probe for
	the five TerminalServices/RdpCoreTS providers, audit-policy probe (Logon /
	Special Logon / Object Access), Performance Log Users group membership probe,
	TraceEvent 3.2.5 NuGet cache verification and a new -IngestionMode parameter
	that writes the operator's transport choice (EventLog / Etw / Auto) into
	%ProgramData%\RdpAudit\appsettings.json without disturbing operator overrides.

.REQUIREMENTS
	PowerShell 7+
	Windows
	Administrator session
	Git
	.NET SDK 8+
	winget for automatic prerequisite installation
#>

[CmdletBinding()]
param(
	[string]$WorkDirectory = 'C:\1st_RdpMON',

	[string]$RepositoryUrl = 'https://github.com/paulmann/RDPAudit.git',

	# The RDPAudit 2.0 work lives on the feature/rdpaudit-2.0-event-collection branch
	# (SSH.NET 2026.0.0, current migration set, current test suite). 'main' is a legacy
	# 1.x tag that still pins the vulnerable SSH.NET 2024.1.0 (GHSA-q939-rpr3-3284) and
	# would fail 'dotnet restore' due to NU1903 (WarningsAsErrors). Override this
	# parameter explicitly if you need to build a different branch.
	[string]$RepositoryBranch = 'feature/rdpaudit-2.0-event-collection',

	[string]$SafeMessagePackVersion = '2.5.301',

	# Soft timeout (seconds) granted to running RdpAudit processes to exit gracefully
	# before the installer escalates to a forced termination. Defaults to 2 minutes.
	[int]$GracefulShutdownTimeoutSeconds = 120,

	[switch]$NonInteractive,

	[switch]$SkipLaunch,

	# Directory that will receive the RDPAudit_Install_<Date_Time>.log transcript file.
	# Defaults to '<WorkDirectory>\logs'. The directory is created on demand and is never
	# deleted or truncated by the installer, so previous runs remain available for review.
	[string]$LogDirectory = '',

	# When present, dotnet test streams every test outcome (Passed + Failed + Skipped) to
	# the console and transcript. Default behaviour is 'minimal' verbosity which only
	# reports Failed tests plus the final summary, keeping the transcript compact. The
	# machine-readable TRX result file is written to <LogDirectory>\test-results\ either
	# way, so the full list of Passed tests is always available for inspection.
	[switch]$VerboseTests,

	# When present, the host PowerShell process itself is terminated after a successful
	# installation (equivalent to typing 'exit' at the prompt). Useful for scripted /
	# unattended runs launched from a task scheduler or one-shot desktop shortcut where
	# leaving an open console window is undesirable. Without this switch the installer
	# simply returns control to the current prompt so the operator can keep working in
	# the same window. Failed runs are never auto-exited — the window always stays open
	# so the fatal error and log path remain visible.
	[switch]$ExitAfterInstall,

	# When present, perform a destructive clean install:
	#   1. Uninstall the RdpAudit Windows service (sc.exe delete) if it is registered.
	#   2. Delete the entire <WorkDirectory>\Service tree, including .git, publish and
	#      all locally built binaries. The subsequent 'git clone' will recreate it from
	#      scratch on the requested branch.
	#   3. Delete every RdpAudit database and migration-failure marker under
	#      %ProgramData%\RdpAudit (rdpaudit.db, rdpaudit.db-wal, rdpaudit.db-shm, all
	#      rdpaudit.db.*.bak backups, and migration-failure.marker.json). The
	#      appsettings.json / operator-authored configuration is preserved.
	# The transcript log directory (<LogDirectory>) is NEVER touched, so previous
	# installer runs remain reviewable. Fails the installation if the operator does
	# not confirm the destructive prompt (unless -NonInteractive is also set, in
	# which case confirmation is implied).
	[switch]$CleanInstall,

	# RDPAudit 2.0 event transport selector, written to
	# %ProgramData%\RdpAudit\appsettings.json (RdpAudit:IngestionMode) after a
	# successful publish. 'Auto' keeps the service self-selecting (ETW when the
	# process is elevated with ETW privileges, EventLogWatcher otherwise), 'Etw'
	# forces the hybrid ETW/EventLog routing implemented on
	# feature/rdpaudit-2.0-event-collection (commit 3c), 'EventLog' pins the
	# legacy v1.0 EventLogWatcher transport for regression testing. The value is
	# merged into an existing appsettings.json without disturbing operator
	# overrides.
	[ValidateSet('EventLog', 'Etw', 'Auto')]
	[string]$IngestionMode = 'Auto'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# ── Installation Transcript Log ──────────────────────────────────────────────

# Every run captures a full transcript to a timestamped file so the operator can
# review the entire installation output after the fact without having to keep the
# window open or copy from the console (which is fragile: selecting text pauses
# the console and any keypress can dismiss modal prompts). The file lives under
# <WorkDirectory>\logs by default and is created regardless of exit outcome.

if ([string]::IsNullOrWhiteSpace($LogDirectory)) {
	$LogDirectory = Join-Path -Path $WorkDirectory -ChildPath 'logs'
}

try {
	if (-not (Test-Path -LiteralPath $LogDirectory)) {
		New-Item -ItemType Directory -Path $LogDirectory -Force | Out-Null
	}
} catch {
	Write-Warning ("Could not create log directory '{0}': {1}. Falling back to TEMP." -f $LogDirectory, $_.Exception.Message)
	$LogDirectory = $env:TEMP
}

$script:InstallLogTimestamp = (Get-Date).ToString('yyyy-MM-dd_HH-mm-ss')
$script:InstallLogFile = Join-Path -Path $LogDirectory -ChildPath ("RDPAudit_Install_{0}.log" -f $script:InstallLogTimestamp)
$script:TranscriptStarted = $false

try {
	Start-Transcript -Path $script:InstallLogFile -Force -IncludeInvocationHeader | Out-Null
	$script:TranscriptStarted = $true
} catch {
	Write-Warning ("Could not start transcript at '{0}': {1}. Installation will continue without a log file." -f $script:InstallLogFile, $_.Exception.Message)
}

Write-Host ''
Write-Host ('Installation log: {0}' -f $script:InstallLogFile) -ForegroundColor Cyan
Write-Host ''

# ── Fields & Configuration ───────────────────────────────────────────────────

$script:RepositoryDirectory = Join-Path -Path $WorkDirectory -ChildPath 'Service'
$script:SolutionPath = Join-Path -Path $script:RepositoryDirectory -ChildPath 'RdpAudit.sln'
$script:PublishScriptPath = Join-Path -Path $script:RepositoryDirectory -ChildPath 'publish.ps1'
$script:ConfiguratorPath = Join-Path -Path $script:RepositoryDirectory -ChildPath 'publish\Configurator\RdpAudit.Configurator.exe'
$script:MikrotikExePath = Join-Path -Path $script:RepositoryDirectory -ChildPath 'publish\Mikrotik\RdpAudit.Mikrotik.exe'
$script:ServiceExePath = Join-Path -Path $script:RepositoryDirectory -ChildPath 'publish\Service\RdpAudit.Service.exe'
$script:PublishRoot = Join-Path -Path $script:RepositoryDirectory -ChildPath 'publish'
$script:MinimumDotNetSdkVersion = [Version]'8.0'
$script:WindowsServiceName = 'RdpAuditService'
$script:RequiredComponents = @('PowerShell 7+', 'Windows', 'Administrator', 'Git', '.NET SDK 8+')

# RDPAudit 2.0 event-transport prerequisites. Kept as script-scope constants so a
# single edit here propagates to the probe, the auto-repair routine and the
# Configurator wiki without introducing string drift.
$script:EtwRequiredEventChannels = @(
	'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational',
	'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational',
	'Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational',
	'Microsoft-Windows-TerminalServices-Gateway/Operational',
	'Microsoft-Windows-TerminalServices-RDPClient/Operational'
)

# Auditpol subcategory GUIDs. Names are locale-dependent (Russian Windows returns
# 'Вход в систему' instead of 'Logon'); GUIDs are stable across every locale and
# every Windows build from 2008 R2 onwards, so we probe and repair by GUID and
# only translate for the operator-facing log line.
$script:AuditpolRequiredSubcategories = @(
	[pscustomobject]@{ Name = 'Logon';           Guid = '{0CCE9215-69AE-11D9-BED3-505054503030}' },
	[pscustomobject]@{ Name = 'Special Logon';   Guid = '{0CCE921B-69AE-11D9-BED3-505054503030}' },
	[pscustomobject]@{ Name = 'Logoff';          Guid = '{0CCE9216-69AE-11D9-BED3-505054503030}' },
	[pscustomobject]@{ Name = 'File System';     Guid = '{0CCE921D-69AE-11D9-BED3-505054503030}' },
	[pscustomobject]@{ Name = 'Registry';        Guid = '{0CCE921E-69AE-11D9-BED3-505054503030}' }
)

$script:TraceEventPackageId = 'Microsoft.Diagnostics.Tracing.TraceEvent'
$script:TraceEventPackageVersion = '3.2.5'
$script:PerformanceLogUsersSid = 'S-1-5-32-559'

# Process image names (without extension) of every RdpAudit component that may be
# running and must be released before the publish folder can be rebuilt in place.
$script:ManagedProcessNames = @('RdpAudit.Service', 'RdpAudit.Configurator', 'RdpAudit.Mikrotik')

# Mutable installation state, consumed by the closing Summary report.
$script:InstallState = [pscustomobject]@{
	PreviousVersion = $null
	IsFreshInstall = $true
	TargetVersion = $null
	StoppedProcesses = New-Object System.Collections.Generic.List[string]
	ForcedProcesses = New-Object System.Collections.Generic.List[string]
	ServiceStopped = $false
	InstalledPrerequisites = New-Object System.Collections.Generic.List[string]
	Fixes = New-Object System.Collections.Generic.List[string]
	Actions = New-Object System.Collections.Generic.List[string]
	CleanInstallPerformed = $false
}

function Add-InstallAction {
	param([Parameter(Mandatory)][string]$Message)
	$script:InstallState.Actions.Add($Message)
}

function Add-InstallFix {
	param([Parameter(Mandatory)][string]$Message)
	$script:InstallState.Fixes.Add($Message)
}

# ── Console Output ───────────────────────────────────────────────────────────

function Write-Section {
	param(
		[Parameter(Mandatory)]
		[string]$Title
	)

	$line = '─' * 78
	Write-Host ''
	Write-Host $line -ForegroundColor Cyan
	Write-Host " $Title" -ForegroundColor Cyan
	Write-Host $line -ForegroundColor Cyan
}

function Write-Ok {
	param([Parameter(Mandatory)][string]$Message)
	Write-Host " [OK]  $Message" -ForegroundColor Green
}

function Write-Info {
	param([Parameter(Mandatory)][string]$Message)
	Write-Host " [..]  $Message" -ForegroundColor Gray
}

function Write-WarningMessage {
	param([Parameter(Mandatory)][string]$Message)
	Write-Host " [!!]  $Message" -ForegroundColor Yellow
}

function Write-ErrorMessage {
	param([Parameter(Mandatory)][string]$Message)
	Write-Host " [XX]  $Message" -ForegroundColor Red
}

# ── Version & Environment Helpers ────────────────────────────────────────────

function ConvertTo-VersionOrNull {
	param(
		[AllowNull()]
		[string]$Value
	)

	if ([string]::IsNullOrWhiteSpace($Value)) {
		return $null
	}

	$match = [regex]::Match($Value, '\d+(\.\d+){1,3}')
	if (-not $match.Success) {
		return $null
	}

	try {
		return [Version]$match.Value
	} catch {
		return $null
	}
}

function Test-IsAdministrator {
	if (-not $IsWindows) {
		return $false
	}

	$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
	$principal = [Security.Principal.WindowsPrincipal]::new($identity)

	return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-CommandVersionText {
	param(
		[Parameter(Mandatory)]
		[string]$CommandName,

		[Parameter(Mandatory)]
		[string[]]$Arguments
	)

	$command = Get-Command -Name $CommandName -ErrorAction SilentlyContinue
	if ($null -eq $command) {
		return $null
	}

	try {
		$output = & $CommandName @Arguments 2>$null
		if ($LASTEXITCODE -ne 0 -and $null -ne $LASTEXITCODE) {
			return $null
		}

		$text = ($output | Select-Object -First 1)
		if ([string]::IsNullOrWhiteSpace($text)) {
			return $null
		}

		return [string]$text
	} catch {
		return $null
	}
}

function Get-DotNetSdkInfo {
	$dotnetCommand = Get-Command -Name 'dotnet' -ErrorAction SilentlyContinue
	if ($null -eq $dotnetCommand) {
		return [pscustomobject]@{
			IsInstalled = $false
			DisplayText = 'NOT FOUND'
			BestVersion = $null
			AllVersions = @()
		}
	}

	$versions = @()

	try {
		$rawSdks = @(dotnet --list-sdks 2>$null)
		foreach ($sdkLine in $rawSdks) {
			$version = ConvertTo-VersionOrNull -Value $sdkLine
			if ($null -ne $version) {
				$versions += $version
			}
		}
	} catch {
		$versions = @()
	}

	if ($versions.Count -eq 0) {
		$singleVersionText = Get-CommandVersionText -CommandName 'dotnet' -Arguments @('--version')
		$singleVersion = ConvertTo-VersionOrNull -Value $singleVersionText
		if ($null -ne $singleVersion) {
			$versions += $singleVersion
		}
	}

	if ($versions.Count -eq 0) {
		return [pscustomobject]@{
			IsInstalled = $false
			DisplayText = 'NOT FOUND'
			BestVersion = $null
			AllVersions = @()
		}
	}

	$bestVersion = $versions | Sort-Object -Descending | Select-Object -First 1
	$displayText = (($versions | Sort-Object -Descending | ForEach-Object { $_.ToString() }) -join ', ')

	return [pscustomobject]@{
		IsInstalled = $true
		DisplayText = $displayText
		BestVersion = $bestVersion
		AllVersions = $versions
	}
}

function Get-MoqInstalledVersion {
	# Probes the NuGet global package cache for the highest installed Moq version.
	# This works even before the repository is cloned and without running a restore,
	# so the prerequisite table can report a real version number rather than just
	# 'NOT FOUND'. Falls back gracefully to $null when dotnet or the cache is absent.
	$dotnetCommand = Get-Command -Name 'dotnet' -ErrorAction SilentlyContinue
	if ($null -eq $dotnetCommand) {
		return $null
	}

	try {
		# Resolve the NuGet global packages root (respects NUGET_PACKAGES env override).
		$nugetRoot = $env:NUGET_PACKAGES
		if ([string]::IsNullOrWhiteSpace($nugetRoot)) {
			$nugetRoot = Join-Path -Path ([System.Environment]::GetFolderPath('UserProfile')) -ChildPath '.nuget\packages'
		}

		$moqRoot = Join-Path -Path $nugetRoot -ChildPath 'moq'
		if (-not (Test-Path -Path $moqRoot -PathType Container)) {
			return $null
		}

		# Each subdirectory name IS the package version (e.g. 4.20.72). Pick the highest.
		$versionDirs = @(Get-ChildItem -Path $moqRoot -Directory -ErrorAction SilentlyContinue)
		if ($versionDirs.Count -eq 0) {
			return $null
		}

		$best = $versionDirs `
			| ForEach-Object { ConvertTo-VersionOrNull -Value $_.Name } `
			| Where-Object { $null -ne $_ } `
			| Sort-Object -Descending `
			| Select-Object -First 1

		return $best
	} catch {
		return $null
	}
}

function New-PrerequisiteRecord {
	param(
		[Parameter(Mandatory)]
		[string]$Name,

		[Parameter(Mandatory)]
		[string]$Required,

		[Parameter(Mandatory)]
		[string]$Installed,

		[Parameter(Mandatory)]
		[bool]$IsSatisfied,

		[Parameter(Mandatory)]
		[bool]$IsMandatory,

		[AllowNull()]
		[string]$WingetId
	)

	return [pscustomobject]@{
		Name = $Name
		Required = $Required
		Installed = $Installed
		Status = if ($IsSatisfied) { 'OK' } else { 'MISSING' }
		IsSatisfied = $IsSatisfied
		IsMandatory = $IsMandatory
		WingetId = $WingetId
	}
}

# ── RDPAudit 2.0 ETW & Audit Prerequisites ───────────────────────────────────────

# Version: 1.0.0
# Returns a probe result for one Windows event log channel. Uses wevtutil.exe
# 'gl' (get-log) rather than Get-WinEvent so we succeed even on locked-down
# Server Core installations where the WinRM/WMI provider is disabled but the
# EventLog service itself is up. Values other than 'true' (including a missing
# channel, which prints an error on stderr and exits non-zero) are reported as
# disabled so the operator sees a clear MISSING row.
function Test-EtwChannelEnabled {
	param(
		[Parameter(Mandatory)]
		[string]$Channel
	)

	if (-not $IsWindows) {
		return [pscustomobject]@{ Channel = $Channel; IsEnabled = $false; Detail = 'NOT WINDOWS' }
	}

	$wevtutil = Get-Command -Name 'wevtutil.exe' -ErrorAction SilentlyContinue
	if ($null -eq $wevtutil) {
		return [pscustomobject]@{ Channel = $Channel; IsEnabled = $false; Detail = 'wevtutil.exe not found' }
	}

	try {
		$output = & wevtutil.exe gl $Channel 2>$null
		if ($LASTEXITCODE -ne 0 -or $null -eq $output) {
			return [pscustomobject]@{ Channel = $Channel; IsEnabled = $false; Detail = 'channel not found' }
		}
		$enabledLine = $output | Where-Object { $_ -match '^\s*enabled:\s*' } | Select-Object -First 1
		if ($null -eq $enabledLine) {
			return [pscustomobject]@{ Channel = $Channel; IsEnabled = $false; Detail = 'no enabled: line' }
		}
		$isEnabled = ($enabledLine -match '^\s*enabled:\s*true\s*$')
		return [pscustomobject]@{ Channel = $Channel; IsEnabled = $isEnabled; Detail = $enabledLine.Trim() }
	} catch {
		return [pscustomobject]@{ Channel = $Channel; IsEnabled = $false; Detail = $_.Exception.Message }
	}
}

# Version: 1.0.0
# Returns per-subcategory audit-policy state by GUID. auditpol.exe supports
# /r /csv for a stable machine-readable output that does not shift between
# Windows locales - column 5 ('Setting Value') is what we compare against
# 'Success and Failure', which is auditpol's canonical value for a fully
# enabled subcategory. We cannot rely on the locale-dependent display name of
# the subcategory itself, so we invoke auditpol once per required GUID.
function Get-AuditpolSubcategoryStatus {
	param(
		[Parameter(Mandatory)]
		[string]$SubcategoryGuid,

		[Parameter(Mandatory)]
		[string]$DisplayName
	)

	if (-not $IsWindows) {
		return [pscustomobject]@{ Name = $DisplayName; Guid = $SubcategoryGuid; IsEnabled = $false; Detail = 'NOT WINDOWS' }
	}

	$auditpol = Get-Command -Name 'auditpol.exe' -ErrorAction SilentlyContinue
	if ($null -eq $auditpol) {
		return [pscustomobject]@{ Name = $DisplayName; Guid = $SubcategoryGuid; IsEnabled = $false; Detail = 'auditpol.exe not found' }
	}

	try {
		$csv = & auditpol.exe /get /subcategory:$SubcategoryGuid /r 2>$null
		if ($LASTEXITCODE -ne 0 -or $null -eq $csv) {
			return [pscustomobject]@{ Name = $DisplayName; Guid = $SubcategoryGuid; IsEnabled = $false; Detail = 'auditpol query failed' }
		}
		$dataLine = $csv | Where-Object { $_ -match ',' -and $_ -notmatch '^Machine Name' } | Select-Object -First 1
		if ($null -eq $dataLine) {
			return [pscustomobject]@{ Name = $DisplayName; Guid = $SubcategoryGuid; IsEnabled = $false; Detail = 'empty auditpol row' }
		}
		$fields = $dataLine -split ','
		$setting = if ($fields.Length -ge 5) { $fields[4].Trim().Trim('"') } else { '' }
		$isEnabled = ($setting -match '^(Success and Failure|Success and failure)$')
		return [pscustomobject]@{ Name = $DisplayName; Guid = $SubcategoryGuid; IsEnabled = $isEnabled; Detail = $setting }
	} catch {
		return [pscustomobject]@{ Name = $DisplayName; Guid = $SubcategoryGuid; IsEnabled = $false; Detail = $_.Exception.Message }
	}
}

# Version: 1.0.0
# Returns $true when the current process token is a member of the built-in
# Performance Log Users group (SID S-1-5-32-559) OR is elevated as a member of
# Administrators. Either grants the SeSystemProfilePrivilege that TraceEvent's
# real-time session requires. We match by SID rather than translated name so
# the probe works on a Russian-language Windows install where the group is
# rendered as 'Пользователи журналов производительности'.
function Test-EtwPrivilegePresent {
	if (-not $IsWindows) {
		return $false
	}

	try {
		$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
		$principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
		if ($principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
			return $true
		}
		$perfSid = New-Object System.Security.Principal.SecurityIdentifier($script:PerformanceLogUsersSid)
		return $principal.IsInRole($perfSid)
	} catch {
		return $false
	}
}

# Version: 1.0.0
# Probes the NuGet global-packages cache for the exact TraceEvent version the
# 2.0 event-collection layer restores. dotnet restore will download it on the
# next build regardless, but reporting the cache state up-front tells the
# operator whether the first build will need network access. Same pattern as
# Get-MoqInstalledVersion.
function Get-TraceEventInstalledVersion {
	$dotnet = Get-Command -Name 'dotnet' -ErrorAction SilentlyContinue
	if ($null -eq $dotnet) {
		return $null
	}
	try {
		$nugetRoot = & dotnet nuget locals global-packages -l 2>$null
		if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($nugetRoot)) {
			return $null
		}
		$path = ($nugetRoot -replace '^\s*global-packages:\s*', '').Trim()
		if (-not (Test-Path -Path $path -PathType Container)) {
			return $null
		}
		$packageRoot = Join-Path -Path $path -ChildPath ($script:TraceEventPackageId.ToLowerInvariant())
		if (-not (Test-Path -Path $packageRoot -PathType Container)) {
			return $null
		}
		$versionDir = Join-Path -Path $packageRoot -ChildPath $script:TraceEventPackageVersion
		if (Test-Path -Path $versionDir -PathType Container) {
			return $script:TraceEventPackageVersion
		}
		return $null
	} catch {
		return $null
	}
}

# ── Prerequisite Checks ──────────────────────────────────────────────────────

function Get-PrerequisiteStatus {
	$items = @()

	$psVersion = $PSVersionTable.PSVersion
	$items += New-PrerequisiteRecord `
		-Name 'PowerShell 7+' `
		-Required '7.0+' `
		-Installed $psVersion.ToString() `
		-IsSatisfied ($psVersion.Major -ge 7) `
		-IsMandatory $true `
		-WingetId 'Microsoft.PowerShell'

	$windowsText = if ($IsWindows) { [System.Environment]::OSVersion.VersionString } else { 'NOT WINDOWS' }
	$items += New-PrerequisiteRecord `
		-Name 'Windows' `
		-Required 'Windows OS' `
		-Installed $windowsText `
		-IsSatisfied $IsWindows `
		-IsMandatory $true `
		-WingetId $null

	$isAdmin = Test-IsAdministrator
	$adminText = if ($isAdmin) { 'Elevated' } else { 'NOT ELEVATED' }
	$items += New-PrerequisiteRecord `
		-Name 'Administrator' `
		-Required 'Elevated session' `
		-Installed $adminText `
		-IsSatisfied $isAdmin `
		-IsMandatory $true `
		-WingetId $null

	$gitVersionText = Get-CommandVersionText -CommandName 'git' -Arguments @('--version')
	$gitInstalledText = if ([string]::IsNullOrWhiteSpace($gitVersionText)) { 'NOT FOUND' } else { $gitVersionText -replace '^git version\s+', '' }
	$items += New-PrerequisiteRecord `
		-Name 'Git' `
		-Required '2.x+' `
		-Installed $gitInstalledText `
		-IsSatisfied (-not [string]::IsNullOrWhiteSpace($gitVersionText)) `
		-IsMandatory $true `
		-WingetId 'Git.Git'

	$dotNet = Get-DotNetSdkInfo
	$dotNetOk = $false
	if ($dotNet.IsInstalled -and $null -ne $dotNet.BestVersion) {
		$dotNetOk = $dotNet.BestVersion -ge $script:MinimumDotNetSdkVersion
	}

	$items += New-PrerequisiteRecord `
		-Name '.NET SDK 8+' `
		-Required '8.0+' `
		-Installed $dotNet.DisplayText `
		-IsSatisfied $dotNetOk `
		-IsMandatory $true `
		-WingetId 'Microsoft.DotNet.SDK.8'

	# Moq is required by RdpAudit.Service.Tests. It is not a system-level tool but a
	# NuGet package; dotnet restore / Install-MoqPackage handles automatic acquisition.
	# We probe the NuGet global cache here so the operator can see at a glance whether
	# Moq is already present before any restore runs. IsMandatory = $false because the
	# package is automatically added by Install-MoqPackage during the build pipeline.
	$moqVersion = Get-MoqInstalledVersion
	$moqInstalled = $null -ne $moqVersion
	$moqInstalledText = if ($moqInstalled) { $moqVersion.ToString() } else { 'NOT FOUND (auto-added)' }
	$items += New-PrerequisiteRecord `
		-Name 'Moq (NuGet)' `
		-Required '4.x+ (NuGet cache)' `
		-Installed $moqInstalledText `
		-IsSatisfied $moqInstalled `
		-IsMandatory $false `
		-WingetId $null

	$wingetVersionText = Get-CommandVersionText -CommandName 'winget' -Arguments @('--version')
	$wingetInstalledText = if ([string]::IsNullOrWhiteSpace($wingetVersionText)) { 'NOT FOUND' } else { $wingetVersionText }
	$items += New-PrerequisiteRecord `
		-Name 'winget' `
		-Required 'Required only for auto-install' `
		-Installed $wingetInstalledText `
		-IsSatisfied (-not [string]::IsNullOrWhiteSpace($wingetVersionText)) `
		-IsMandatory $false `
		-WingetId $null

	# RDPAudit 2.0 ETW-transport prerequisites. All are IsMandatory=$false so a
	# missing channel or audit policy does not block the build: the service
	# still runs in EventLogWatcher mode, and Repair-Rdp2xPrerequisites offers
	# the operator an interactive fix immediately after the check.
	$channelStates = @(foreach ($channel in $script:EtwRequiredEventChannels) { Test-EtwChannelEnabled -Channel $channel })
	$channelsEnabled = @($channelStates | Where-Object { $_.IsEnabled }).Count
	$channelsTotal = $channelStates.Count
	$items += New-PrerequisiteRecord `
		-Name 'ETW event channels' `
		-Required 'TerminalServices+RdpCoreTS enabled' `
		-Installed ("{0}/{1} enabled" -f $channelsEnabled, $channelsTotal) `
		-IsSatisfied ($channelsEnabled -eq $channelsTotal) `
		-IsMandatory $false `
		-WingetId $null

	$auditStates = @(foreach ($sub in $script:AuditpolRequiredSubcategories) { Get-AuditpolSubcategoryStatus -SubcategoryGuid $sub.Guid -DisplayName $sub.Name })
	$auditEnabled = @($auditStates | Where-Object { $_.IsEnabled }).Count
	$auditTotal = $auditStates.Count
	$items += New-PrerequisiteRecord `
		-Name 'Audit policy' `
		-Required 'Logon/Logoff/File System' `
		-Installed ("{0}/{1} Success+Failure" -f $auditEnabled, $auditTotal) `
		-IsSatisfied ($auditEnabled -eq $auditTotal) `
		-IsMandatory $false `
		-WingetId $null

	$etwPrivilege = Test-EtwPrivilegePresent
	$etwPrivilegeText = if ($etwPrivilege) { 'Elevated' } else { 'NOT PRESENT' }
	$items += New-PrerequisiteRecord `
		-Name 'ETW privilege' `
		-Required 'Admin or Perf Log Users' `
		-Installed $etwPrivilegeText `
		-IsSatisfied $etwPrivilege `
		-IsMandatory $false `
		-WingetId $null

	$traceEventVersion = Get-TraceEventInstalledVersion
	$traceEventInstalledText = if ($null -ne $traceEventVersion) { $traceEventVersion } else { 'NOT FOUND (auto-added)' }
	$items += New-PrerequisiteRecord `
		-Name 'TraceEvent (NuGet)' `
		-Required ("{0} in cache" -f $script:TraceEventPackageVersion) `
		-Installed $traceEventInstalledText `
		-IsSatisfied ($null -ne $traceEventVersion) `
		-IsMandatory $false `
		-WingetId $null

	# Expose the underlying probe rows so Repair-Rdp2xPrerequisites can consume
	# them without repeating the wevtutil / auditpol invocations.
	$script:LastEtwChannelStates = $channelStates
	$script:LastAuditSubcategoryStates = $auditStates
	$script:LastEtwPrivilegePresent = $etwPrivilege

	return $items
}

function Show-PrerequisiteStatus {
	param(
		[Parameter(Mandatory)]
		[object[]]$Items
	)

	Write-Section 'Prerequisite Check'

	$format = '{0,-20} {1,-28} {2,-34} {3,-10}'
	Write-Host ($format -f 'Component', 'Required', 'Installed', 'Status') -ForegroundColor White
	Write-Host ($format -f '---------', '--------', '---------', '------') -ForegroundColor DarkGray

	foreach ($item in $Items) {
		$color = if ($item.IsSatisfied) {
			'Green'
		} elseif (-not $item.IsMandatory) {
			# Optional components that are absent are shown in yellow, not red,
			# to distinguish them from hard blockers.
			'Yellow'
		} else {
			'Red'
		}
		Write-Host ($format -f $item.Name, $item.Required, $item.Installed, $item.Status) -ForegroundColor $color
	}

	Write-Host ''
}

function Test-MandatoryPrerequisites {
	param(
		[Parameter(Mandatory)]
		[object[]]$Items
	)

	$missingMandatory = @($Items | Where-Object { $_.IsMandatory -and -not $_.IsSatisfied })
	return ($missingMandatory.Count -eq 0)
}

# ── User Interaction ─────────────────────────────────────────────────────────

function Confirm-Action {
	param(
		[Parameter(Mandatory)]
		[string]$Prompt,

		[bool]$DefaultYes = $false
	)

	if ($NonInteractive) {
		return $DefaultYes
	}

	$suffix = if ($DefaultYes) { '[Y/n]' } else { '[y/N]' }
	$answer = Read-Host "$Prompt $suffix"

	if ([string]::IsNullOrWhiteSpace($answer)) {
		return $DefaultYes
	}

	return ($answer -match '^(y|yes)$')
}

# ── External Process Runner ──────────────────────────────────────────────────

function Invoke-CheckedCommand {
	param(
		[Parameter(Mandatory)]
		[string]$FilePath,

		[Parameter(Mandatory)]
		[string[]]$Arguments,

		[Parameter(Mandatory)]
		[string]$FailureMessage,

		[string]$WorkingDirectory
	)

	$previousLocation = Get-Location

	try {
		if (-not [string]::IsNullOrWhiteSpace($WorkingDirectory)) {
			Set-Location -Path $WorkingDirectory
		}

		Write-Info ("Running: {0} {1}" -f $FilePath, ($Arguments -join ' '))
		& $FilePath @Arguments

		if ($LASTEXITCODE -ne 0) {
			throw "$FailureMessage Exit code: $LASTEXITCODE."
		}
	} finally {
		Set-Location -Path $previousLocation
	}
}

# ── Version Detection ──────────────────────────────────────────────────────────

function Get-FileVersionOrNull {
	param(
		[AllowNull()]
		[string]$Path
	)

	if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -Path $Path -PathType Leaf)) {
		return $null
	}

	try {
		$info = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($Path)
		$candidate = if (-not [string]::IsNullOrWhiteSpace($info.ProductVersion)) { $info.ProductVersion } else { $info.FileVersion }
		return ConvertTo-VersionOrNull -Value $candidate
	} catch {
		return $null
	}
}

function Get-InstalledRdpAuditVersion {
	# Best-effort discovery of any previously installed RdpAudit build. Looks at the
	# registered Windows service binary first (the authoritative installed artefact),
	# then falls back to whatever was previously published into the work directory.
	$candidatePaths = New-Object System.Collections.Generic.List[string]

	if ($IsWindows) {
		try {
			$service = Get-CimInstance -ClassName Win32_Service -Filter "Name='$($script:WindowsServiceName)'" -ErrorAction SilentlyContinue
			if ($null -ne $service -and -not [string]::IsNullOrWhiteSpace($service.PathName)) {
				$servicePath = $service.PathName.Trim('"')
				$match = [regex]::Match($servicePath, '^\s*"?(?<exe>.+?\.exe)"?')
				if ($match.Success) {
					$candidatePaths.Add($match.Groups['exe'].Value)
				}
			}
		} catch {
			# Service query is best-effort; ignore failures and rely on file probing.
		}
	}

	$candidatePaths.Add($script:ServiceExePath)
	$candidatePaths.Add($script:ConfiguratorPath)
	$candidatePaths.Add($script:MikrotikExePath)

	foreach ($path in $candidatePaths) {
		$version = Get-FileVersionOrNull -Path $path
		if ($null -ne $version) {
			return [pscustomobject]@{
				Version = $version
				Source = $path
			}
		}
	}

	return $null
}

function Get-TargetVersionFromSource {
	# Reads the central VersionPrefix from Directory.Build.props in the freshly synced
	# repository so the Summary can state the exact version the software is upgraded to.
	$propsPath = Join-Path -Path $script:RepositoryDirectory -ChildPath 'Directory.Build.props'
	if (-not (Test-Path -Path $propsPath -PathType Leaf)) {
		return $null
	}

	try {
		$content = Get-Content -Path $propsPath -Raw
		$match = [regex]::Match($content, '<VersionPrefix[^>]*>(?<v>\d+(\.\d+){1,3})</VersionPrefix>')
		if ($match.Success) {
			return ConvertTo-VersionOrNull -Value $match.Groups['v'].Value
		}
	} catch {
		return $null
	}

	return $null
}

function Show-ExistingInstallation {
	# Reports whether an older RdpAudit build is present BEFORE any change is made, so
	# the operator immediately sees the detected version number on startup.
	Write-Section 'Existing Installation'

	$existing = Get-InstalledRdpAuditVersion
	if ($null -eq $existing) {
		$script:InstallState.IsFreshInstall = $true
		$script:InstallState.PreviousVersion = $null
		Write-Ok 'No previous RdpAudit installation detected. This is a fresh, clean installation.'
		return
	}

	$script:InstallState.IsFreshInstall = $false
	$script:InstallState.PreviousVersion = $existing.Version
	Write-WarningMessage ("Detected an existing RdpAudit installation. Installed version: {0}" -f $existing.Version.ToString())
	Write-Info ("Detected from: {0}" -f $existing.Source)
}

# ── Process & Service Shutdown ───────────────────────────────────────────────

function Get-RunningManagedProcesses {
	# Returns the live RdpAudit component processes. Detection is scoped strictly to
	# the known image names so unrelated processes are never touched.
	$running = New-Object System.Collections.Generic.List[object]

	foreach ($name in $script:ManagedProcessNames) {
		$procs = @(Get-Process -Name $name -ErrorAction SilentlyContinue)
		foreach ($proc in $procs) {
			$running.Add($proc)
		}
	}

	# Emit the collection elements into the pipeline. Every call-site wraps the
	# result with @(...) so it always materializes as a real array — that keeps
	# '.Count' reliable for 0, 1 or N processes without double-wrapping an empty
	# array into a single Object[] element.
	return $running.ToArray()
}

function Stop-RdpAuditService {
	# Issues a soft stop to the Windows service via the Service Control Manager. This
	# is the SCM-sanctioned shutdown path: it lets the service flush its database and
	# release its event-log subscriptions cleanly, preserving the integrity of the
	# protection it provides. The service is NOT removed here — only stopped.
	if (-not $IsWindows) {
		return
	}

	$service = Get-Service -Name $script:WindowsServiceName -ErrorAction SilentlyContinue
	if ($null -eq $service) {
		return
	}

	if ($service.Status -eq 'Stopped') {
		Write-Info "Service '$($script:WindowsServiceName)' is already stopped."
		return
	}

	Write-Info "Requesting graceful stop of service '$($script:WindowsServiceName)' ..."
	try {
		Stop-Service -Name $script:WindowsServiceName -ErrorAction Stop
	} catch {
		Write-WarningMessage "Soft stop of the service did not complete immediately: $($_.Exception.Message)"
	}

	$deadline = (Get-Date).AddSeconds($GracefulShutdownTimeoutSeconds)
	while ((Get-Date) -lt $deadline) {
		$current = Get-Service -Name $script:WindowsServiceName -ErrorAction SilentlyContinue
		if ($null -eq $current -or $current.Status -eq 'Stopped') {
			Write-Ok "Service '$($script:WindowsServiceName)' stopped gracefully."
			$script:InstallState.ServiceStopped = $true
			return
		}
		Start-Sleep -Seconds 2
	}

	Write-WarningMessage "Service did not stop within the soft timeout; the underlying process will be force-terminated next."
}

function Stop-RdpAuditProcesses {
	# Releases every running RdpAudit component so the publish folder can be rebuilt.
	#
	# Strategy (security-aware, least-destructive first):
	#   1. Ask the Windows service to stop through the SCM (clean, integrity-preserving).
	#   2. Ask each GUI/console process to close its main window (cooperative exit).
	#   3. Poll for up to $GracefulShutdownTimeoutSeconds (default 120s) for a clean exit.
	#   4. Force-terminate only the stragglers, then verify the field is clear.
	Write-Section 'Stopping Running Components'

	$initial = @(Get-RunningManagedProcesses)
	$serviceExists = $false
	if ($IsWindows) {
		$serviceExists = $null -ne (Get-Service -Name $script:WindowsServiceName -ErrorAction SilentlyContinue)
	}

	if ($initial.Count -eq 0 -and -not $serviceExists) {
		Write-Ok 'No running RdpAudit components detected. Nothing to stop.'
		return
	}

	# Step 1 — graceful service stop (also signals the workers to release resources).
	Stop-RdpAuditService

	# Step 2 — cooperative window-close request to each live process.
	foreach ($proc in (Get-RunningManagedProcesses)) {
		try {
			Write-Info ("Sending graceful exit request to {0} (PID {1}) ..." -f $proc.ProcessName, $proc.Id)
			if (-not $proc.HasExited) {
				[void]$proc.CloseMainWindow()
			}
		} catch {
			Write-WarningMessage ("Could not send a graceful exit request to {0} (PID {1}): {2}" -f $proc.ProcessName, $proc.Id, $_.Exception.Message)
		}
	}

	# Step 3 — wait out the soft timeout for a fully cooperative shutdown.
	$deadline = (Get-Date).AddSeconds($GracefulShutdownTimeoutSeconds)
	while ((Get-Date) -lt $deadline) {
		$still = @(Get-RunningManagedProcesses)
		if ($still.Count -eq 0) {
			break
		}
		$remaining = [int]([Math]::Ceiling(($deadline - (Get-Date)).TotalSeconds))
		Write-Info ("Waiting for {0} component(s) to exit gracefully ({1}s remaining) ..." -f $still.Count, $remaining)
		Start-Sleep -Seconds 3
	}

	$survivors = @(Get-RunningManagedProcesses)
	foreach ($name in $script:ManagedProcessNames) {
		$wasRunning = $initial | Where-Object { $_.ProcessName -eq $name } | Select-Object -First 1
		$stillRunning = $survivors | Where-Object { $_.ProcessName -eq $name } | Select-Object -First 1
		if ($null -ne $wasRunning -and $null -eq $stillRunning -and -not $script:InstallState.StoppedProcesses.Contains($name)) {
			$script:InstallState.StoppedProcesses.Add($name)
		}
	}

	# Step 4 — force-terminate only the processes that ignored the soft request.
	if ($survivors.Count -gt 0) {
		Write-WarningMessage ("{0} component(s) did not exit within {1}s. Forcing termination now." -f $survivors.Count, $GracefulShutdownTimeoutSeconds)

		foreach ($proc in $survivors) {
			try {
				Write-WarningMessage ("Force-stopping {0} (PID {1}) ..." -f $proc.ProcessName, $proc.Id)
				Stop-Process -Id $proc.Id -Force -ErrorAction Stop
				if (-not $script:InstallState.ForcedProcesses.Contains($proc.ProcessName)) {
					$script:InstallState.ForcedProcesses.Add($proc.ProcessName)
				}
			} catch {
				throw ("Failed to force-stop {0} (PID {1}): {2}" -f $proc.ProcessName, $proc.Id, $_.Exception.Message)
			}
		}

		Start-Sleep -Seconds 2

		$final = @(Get-RunningManagedProcesses)
		if ($final.Count -gt 0) {
			$names = ($final | ForEach-Object { "$($_.ProcessName) (PID $($_.Id))" }) -join ', '
			throw "The following RdpAudit component(s) could not be terminated: $names. Close them manually and retry."
		}
	}

	Write-Ok 'All running RdpAudit components have been released.'
}

# ── Auto Installation ────────────────────────────────────────────────────────

function Install-MissingPrerequisites {

	param(
		[Parameter(Mandatory)]
		[object[]]$Items
	)

	$missingInstallable = @($Items | Where-Object { $_.IsMandatory -and -not $_.IsSatisfied -and -not [string]::IsNullOrWhiteSpace($_.WingetId) })
	$missingManual = @($Items | Where-Object { $_.IsMandatory -and -not $_.IsSatisfied -and [string]::IsNullOrWhiteSpace($_.WingetId) })

	if ($missingManual.Count -gt 0) {
		Write-Section 'Manual Requirements'
		foreach ($item in $missingManual) {
			Write-ErrorMessage "$($item.Name) is required and cannot be installed automatically by this script."
		}

		return $false
	}

	if ($missingInstallable.Count -eq 0) {
		Write-Ok 'No installable prerequisites are missing.'
		return $true
	}

	$wingetAvailable = $false
	$wingetRecord = $Items | Where-Object { $_.Name -eq 'winget' } | Select-Object -First 1
	if ($null -ne $wingetRecord -and $wingetRecord.IsSatisfied) {
		$wingetAvailable = $true
	}

	if (-not $wingetAvailable) {
		Write-ErrorMessage 'winget is not available. Install missing prerequisites manually, then run this script again.'
		return $false
	}

	Write-Section 'Missing Prerequisites'

	foreach ($item in $missingInstallable) {
		Write-WarningMessage "$($item.Name) is missing. winget id: $($item.WingetId)"
	}

	$installNow = Confirm-Action -Prompt 'Install missing prerequisites now?' -DefaultYes $false
	if (-not $installNow) {
		Write-Info 'Installation cancelled by user.'
		return $false
	}

	foreach ($item in $missingInstallable) {
		Write-Info "Installing $($item.Name) ..."
		Invoke-CheckedCommand `
			-FilePath 'winget' `
			-Arguments @(
				'install',
				'--id', $item.WingetId,
				'--exact',
				'--silent',
				'--accept-source-agreements',
				'--accept-package-agreements'
			) `
			-FailureMessage "winget failed to install $($item.Name)."
		Write-Ok "$($item.Name) installation command completed."
		$script:InstallState.InstalledPrerequisites.Add("$($item.Name) (winget id: $($item.WingetId))")
	}

	$machinePath = [System.Environment]::GetEnvironmentVariable('Path', 'Machine')
	$userPath = [System.Environment]::GetEnvironmentVariable('Path', 'User')
	$env:Path = "$machinePath;$userPath"

	return $true
}

# ── Repository Operations ────────────────────────────────────────────────────

function Invoke-CleanInstallPurge {
	# Version: 1.0.0
	#
	# Destructive pre-installation cleanup used ONLY when -CleanInstall is on the
	# command line. Callers MUST invoke Stop-RdpAuditProcesses first so that no
	# file handles remain on the service binaries or the SQLite database.
	#
	# What is removed:
	#   1. The Windows service registration (sc.exe delete <name>) if it exists.
	#   2. The whole <WorkDirectory>\Service tree (git checkout + publish output).
	#   3. Every RdpAudit database file under %ProgramData%\RdpAudit:
	#      rdpaudit.db, rdpaudit.db-wal, rdpaudit.db-shm, rdpaudit.db.*.bak.
	#   4. The migration-failure marker (migration-failure.marker.json).
	#
	# What is preserved:
	#   * <LogDirectory> — installer transcripts must survive so previous runs can
	#     be reviewed.
	#   * %ProgramData%\RdpAudit\appsettings.json and any other operator-authored
	#     configuration files. Only *.db* files and the migration marker are removed.
	Write-Section 'Clean Install — Purge Previous Installation'

	$confirmed = Confirm-Action -Prompt ("CLEAN INSTALL will DELETE '{0}' and every RdpAudit database under %ProgramData%\RdpAudit. This is irreversible. Continue?" -f $script:RepositoryDirectory) -DefaultYes $false
	if (-not $confirmed) {
		throw 'Clean install cancelled by operator.'
	}

	# 1. Remove Windows service registration so any leftover service entry does
	#    not point at bytes we are about to delete.
	try {
		$existingService = Get-Service -Name $script:WindowsServiceName -ErrorAction SilentlyContinue
		if ($null -ne $existingService) {
			Write-Info "Unregistering Windows service '$($script:WindowsServiceName)' ..."
			& sc.exe delete $script:WindowsServiceName | Out-Null
			if ($LASTEXITCODE -eq 0) {
				Write-Ok "Service '$($script:WindowsServiceName)' unregistered."
			} else {
				Write-WarningMessage "sc.exe delete '$($script:WindowsServiceName)' exited with code $LASTEXITCODE. Continuing anyway."
			}
		} else {
			Write-Info "Service '$($script:WindowsServiceName)' is not registered — nothing to unregister."
		}
	} catch {
		Write-WarningMessage ("Failed to query/remove service '{0}': {1}. Continuing anyway." -f $script:WindowsServiceName, $_.Exception.Message)
	}

	# 2. Delete the <WorkDirectory>\Service tree in full.
	if (Test-Path -LiteralPath $script:RepositoryDirectory) {
		Write-Info "Removing repository/publish directory: $($script:RepositoryDirectory)"
		try {
			Remove-Item -LiteralPath $script:RepositoryDirectory -Recurse -Force -ErrorAction Stop
			Write-Ok "Deleted: $($script:RepositoryDirectory)"
		} catch {
			throw ("Clean install could not delete '{0}': {1}. Close any Explorer / editor / terminal holding a file in that tree and re-run with -CleanInstall." -f $script:RepositoryDirectory, $_.Exception.Message)
		}
	} else {
		Write-Info "Repository/publish directory does not exist — nothing to delete: $($script:RepositoryDirectory)"
	}

	# 3. + 4. Delete databases and migration marker under %ProgramData%\RdpAudit.
	$programDataRoot = [Environment]::GetFolderPath('CommonApplicationData')
	$rdpAuditDataDirectory = Join-Path -Path $programDataRoot -ChildPath 'RdpAudit'

	if (Test-Path -LiteralPath $rdpAuditDataDirectory) {
		Write-Info "Purging databases and migration marker under: $rdpAuditDataDirectory"

		# Databases: rdpaudit.db + WAL/SHM sidecars + rdpaudit.db.*.bak rotated backups.
		$databasePatterns = @('rdpaudit.db', 'rdpaudit.db-wal', 'rdpaudit.db-shm', 'rdpaudit.db.*.bak')
		$removedDatabaseCount = 0
		foreach ($pattern in $databasePatterns) {
			$dbMatches = @(Get-ChildItem -LiteralPath $rdpAuditDataDirectory -Filter $pattern -File -ErrorAction SilentlyContinue)
			foreach ($dbFile in $dbMatches) {
				try {
					Remove-Item -LiteralPath $dbFile.FullName -Force -ErrorAction Stop
					Write-Ok ("  deleted: {0}" -f $dbFile.Name)
					$removedDatabaseCount++
				} catch {
					Write-WarningMessage ("  failed to delete '{0}': {1}" -f $dbFile.FullName, $_.Exception.Message)
				}
			}
		}
		if ($removedDatabaseCount -eq 0) {
			Write-Info '  no rdpaudit.db* files were present.'
		}

		# Migration failure marker.
		$migrationMarker = Join-Path -Path $rdpAuditDataDirectory -ChildPath 'migration-failure.marker.json'
		if (Test-Path -LiteralPath $migrationMarker) {
			try {
				Remove-Item -LiteralPath $migrationMarker -Force -ErrorAction Stop
				Write-Ok '  deleted: migration-failure.marker.json'
			} catch {
				Write-WarningMessage ("  failed to delete migration marker: {0}" -f $_.Exception.Message)
			}
		}

		Write-Ok 'Configuration files (appsettings.json etc.) preserved.'
	} else {
		Write-Info "No %ProgramData%\RdpAudit directory found — nothing to purge."
	}

	$script:InstallState.CleanInstallPerformed = $true
	Write-Ok 'Clean install pre-purge finished. Proceeding with a fresh installation.'
}

function Initialize-Workspace {
	Write-Section 'Workspace'

	if (-not (Test-Path -Path $WorkDirectory)) {
		Write-Info "Creating working directory: $WorkDirectory"
		New-Item -ItemType Directory -Force -Path $WorkDirectory | Out-Null
	} else {
		Write-Ok "Working directory exists: $WorkDirectory"
	}

	if (Test-Path -Path $script:RepositoryDirectory) {
		$gitDirectory = Join-Path -Path $script:RepositoryDirectory -ChildPath '.git'

		if (-not (Test-Path -Path $gitDirectory)) {
			$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
			$backupPath = "$($script:RepositoryDirectory).backup-$timestamp"
			Write-WarningMessage "Existing non-git directory found. Moving it to: $backupPath"
			Move-Item -Path $script:RepositoryDirectory -Destination $backupPath -Force
		}
	}
}

function Sync-Repository {
	# Version: 1.2.5
	# Fix 1 — verify and repair the remote origin URL before any fetch so stale clones
	#          (e.g. previously pointing at 1st-RDPMon) are silently corrected.
	# Fix 2 — fetch with a full refspec (+refs/heads/*:refs/remotes/origin/*) to unlock
	#          --single-branch clones that only carry one branch in their refspec.
	# Fix 3 — use 'checkout -B <branch> origin/<branch>' instead of a bare checkout
	#          so a missing local branch is created rather than failing with
	#          "pathspec did not match any file(s) known to git".
	Write-Section 'Repository'

	if (-not (Test-Path -Path (Join-Path -Path $script:RepositoryDirectory -ChildPath '.git'))) {
		Write-Info "Cloning $RepositoryBranch from $RepositoryUrl"
		Invoke-CheckedCommand `
			-FilePath 'git' `
			-Arguments @(
				'clone',
				'--branch', $RepositoryBranch,
				'--single-branch',
				$RepositoryUrl,
				$script:RepositoryDirectory
			) `
			-FailureMessage 'git clone failed.'
	} else {
		Write-Info 'Repository already exists. Verifying remote origin URL ...'

		# ── Fix 1: ensure origin points at the correct repository ─────────────
		$currentOrigin = (& git -C $script:RepositoryDirectory remote get-url origin 2>$null | Select-Object -First 1)
		if ($currentOrigin -ne $RepositoryUrl) {
			Write-WarningMessage ("Remote origin mismatch — found: '{0}', expected: '{1}'. Correcting ..." -f $currentOrigin, $RepositoryUrl)
			Invoke-CheckedCommand `
				-FilePath 'git' `
				-Arguments @('-C', $script:RepositoryDirectory, 'remote', 'set-url', 'origin', $RepositoryUrl) `
				-FailureMessage 'git remote set-url failed.'
			Write-Ok "Remote origin corrected to: $RepositoryUrl"
			Add-InstallFix ("Corrected remote origin from '{0}' to '{1}'" -f $currentOrigin, $RepositoryUrl)
		} else {
			Write-Ok "Remote origin is correct: $RepositoryUrl"
		}

		# ── Fix 2: full refspec fetch (breaks --single-branch limitation) ─────
		Write-Info 'Fetching all remote branches ...'
		Invoke-CheckedCommand `
			-FilePath 'git' `
			-Arguments @(
				'-C', $script:RepositoryDirectory,
				'fetch', 'origin',
				'+refs/heads/*:refs/remotes/origin/*'
			) `
			-FailureMessage 'git fetch failed.'

		# ── Fix 3: safe branch checkout (creates local branch when absent) ────
		Write-Info "Checking out branch '$RepositoryBranch' ..."
		Invoke-CheckedCommand `
			-FilePath 'git' `
			-Arguments @(
				'-C', $script:RepositoryDirectory,
				'checkout', '-B', $RepositoryBranch,
				"origin/$RepositoryBranch"
			) `
			-FailureMessage 'git checkout failed.'

		Invoke-CheckedCommand `
			-FilePath 'git' `
			-Arguments @('-C', $script:RepositoryDirectory, 'reset', '--hard', "origin/$RepositoryBranch") `
			-FailureMessage 'git reset failed.'

		Invoke-CheckedCommand `
			-FilePath 'git' `
			-Arguments @('-C', $script:RepositoryDirectory, 'clean', '-fdx') `
			-FailureMessage 'git clean failed.'
	}

	$branch = (& git -C $script:RepositoryDirectory branch --show-current 2>$null | Select-Object -First 1)
	$head = (& git -C $script:RepositoryDirectory log -1 --oneline 2>$null | Select-Object -First 1)

	Write-Ok "Branch: $branch"
	Write-Ok "HEAD  : $head"
}

# ── Package Patch ────────────────────────────────────────────────────────────

function Update-MessagePackPackageReference {
	Write-Section 'Security Patch'

	if (-not (Test-Path -Path $script:RepositoryDirectory)) {
		throw "Repository directory does not exist: $($script:RepositoryDirectory)"
	}

	$projectFiles = @(Get-ChildItem -Path $script:RepositoryDirectory -Filter '*.csproj' -Recurse -File)
	if ($projectFiles.Count -eq 0) {
		throw "No .csproj files found under $($script:RepositoryDirectory)."
	}

	$patchedCount = 0
	$packageReferencePattern = '(<PackageReference\s+Include="MessagePack"\s+Version=")([^"]+)(")'

	foreach ($projectFile in $projectFiles) {
		$content = Get-Content -Path $projectFile.FullName -Raw

		if ($content -notmatch 'Include="MessagePack"') {
			continue
		}

		$updated = [regex]::Replace(
			$content,
			$packageReferencePattern,
			{
				param($match)
				return $match.Groups[1].Value + $SafeMessagePackVersion + $match.Groups[3].Value
			}
		)

		if ($updated -ne $content) {
			Set-Content -Path $projectFile.FullName -Value $updated -NoNewline -Encoding UTF8
			$patchedCount++
			Write-Ok "Patched MessagePack in: $($projectFile.FullName)"
		}
	}

	if ($patchedCount -eq 0) {
		Write-WarningMessage 'No MessagePack package reference was patched. It may already be updated or defined in another format.'
	} else {
		Write-Ok "MessagePack references updated to version $SafeMessagePackVersion."
		Add-InstallFix "Patched $patchedCount project(s) to MessagePack $SafeMessagePackVersion (security)"
	}
}

# ── Test Dependencies ────────────────────────────────────────────────────────
function Install-MoqPackage {
	<#
	.SYNOPSIS
		Ensures the Moq package is present in RdpAudit.Service.Tests before build/test.
	.DESCRIPTION
		Parses the test project file via SelectNodes (handles multiple ItemGroup blocks),
		skips the dotnet-add step when Moq is already referenced, and records the action
		in the install state. Does NOT run a standalone restore — the full-solution restore
		in Invoke-RdpAuditBuildPipeline covers this project.
	#>
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$RepositoryRoot
	)

	Write-Section 'Test Dependencies'

	$testProj = Join-Path -Path $RepositoryRoot -ChildPath 'tests\RdpAudit.Service.Tests\RdpAudit.Service.Tests.csproj'

	if (-not (Test-Path -Path $testProj -PathType Leaf)) {
		Write-WarningMessage "Test project not found: $testProj — skipping Moq install."
		return
	}

	Write-Info 'Checking Moq package reference in test project ...'

	[xml]$xml = Get-Content -Path $testProj -Raw -Encoding UTF8

	# SelectNodes searches all ItemGroup elements regardless of their position in the
	# file. The naive $xml.Project.ItemGroup.PackageReference path returns $null when
	# there are multiple ItemGroup blocks — a common layout in SDK-style projects.
	$moqRef = $xml.SelectNodes('//PackageReference[@Include]') |
		Where-Object { $_.GetAttribute('Include') -ieq 'Moq' } |
		Select-Object -First 1

	if ($null -ne $moqRef) {
		$ver = $moqRef.GetAttribute('Version')
		$verText = if (-not [string]::IsNullOrWhiteSpace($ver)) { "v$ver" } else { 'version managed centrally' }
		Write-Ok "Moq already referenced ($verText) — nothing to install."
		return
	}

	Write-Info 'Moq reference not found. Adding via dotnet add package ...'

	Invoke-CheckedCommand `
		-FilePath 'dotnet' `
		-Arguments @('add', $testProj, 'package', 'Moq') `
		-FailureMessage 'Failed to add Moq to RdpAudit.Service.Tests.'

	Write-Ok 'Moq package reference added successfully.'

	# Verify the reference actually landed in the file — dotnet add can exit 0 even on
	# a Central Package Management project where it cannot write the version attribute.
	[xml]$xmlAfter = Get-Content -Path $testProj -Raw -Encoding UTF8
	$moqRefAfter = $xmlAfter.SelectNodes('//PackageReference[@Include]') |
		Where-Object { $_.GetAttribute('Include') -ieq 'Moq' } |
		Select-Object -First 1

	if ($null -eq $moqRefAfter) {
		throw (
			"Moq was NOT found in '$testProj' after 'dotnet add package Moq' reported success. " +
			'This usually means Central Package Management (CPM) is active and the version must ' +
			'be declared in Directory.Packages.props instead. Add <PackageVersion Include="Moq" Version="4.*" /> ' +
			'to Directory.Packages.props and re-run.'
		)
	}

	Add-InstallAction 'Added missing Moq package reference to RdpAudit.Service.Tests'

	# NOTE: No standalone 'dotnet restore' here.
	# Invoke-RdpAuditBuildPipeline runs 'dotnet restore RdpAudit.sln' as its first step,
	# which covers every project in the solution including the test project. A second
	# restore here would only add latency without providing any additional guarantee.
	Write-Info 'Moq restore will be handled by the full-solution restore in the build pipeline.'
}

function Set-DotNetSdkGlobalJson {
	Write-Section 'SDK Pin'

	$dotNet = Get-DotNetSdkInfo
	$sdk8Versions = @($dotNet.AllVersions | Where-Object { $_.Major -eq 8 } | Sort-Object -Descending)

	if ($sdk8Versions.Count -eq 0) {
		Write-WarningMessage 'No .NET SDK 8.x version found. Skipping global.json creation.'
		return
	}

	$selectedSdk = $sdk8Versions[0].ToString()
	$globalJsonPath = Join-Path -Path $script:RepositoryDirectory -ChildPath 'global.json'

	$globalJson = [ordered]@{
		sdk = [ordered]@{
			version = $selectedSdk
			rollForward = 'latestFeature'
		}
	}

	$json = $globalJson | ConvertTo-Json -Depth 5
	Set-Content -Path $globalJsonPath -Value $json -Encoding UTF8

	Write-Ok "Pinned .NET SDK via global.json: $selectedSdk"
	Add-InstallAction "Pinned .NET SDK via global.json ($selectedSdk)"
}

function Test-Ca1859PatchVerification {
	Write-Info 'Verifying CA1859 source patches ...'

	$checks = @(
		[pscustomobject]@{
			Path = Join-Path -Path $script:RepositoryDirectory -ChildPath 'src\RdpAudit.Service\Services\EnforcementReconciliationService.cs'
			Pattern = '\bIReadOnlyList\s*<\s*(?:RdpAudit\.Core\.Models\.)?ActiveBlock\s*>\s+rows\b'
			Description = 'IReadOnlyList<ActiveBlock> rows'
		},
		[pscustomobject]@{
			Path = Join-Path -Path $script:RepositoryDirectory -ChildPath 'tests\RdpAudit.Core.Tests\EventCatalogTests.cs'
			Pattern = '\bIReadOnlyList\s*<\s*string\s*>\s+channels\b'
			Description = 'IReadOnlyList<string> channels'
		}
	)

	foreach ($check in $checks) {
		$content = Get-Content -Path $check.Path -Raw
		if ($content -match $check.Pattern) {
			$lines = Select-String -Path $check.Path -Pattern $check.Pattern
			foreach ($line in $lines) {
				Write-ErrorMessage "Remaining CA1859 pattern in $($check.Path):$($line.LineNumber)"
				Write-Host "       $($line.Line.Trim())" -ForegroundColor DarkRed
			}

			throw "CA1859 verification failed: $($check.Description) still exists."
		}

		Write-Ok "Verified: $($check.Description) is not present."
	}
}

function Update-Ca1859SourceWarnings {
	Write-Section 'Analyzer Patch'

	$patches = @(
		[pscustomobject]@{
			Path = Join-Path -Path $script:RepositoryDirectory -ChildPath 'src\RdpAudit.Service\Services\EnforcementReconciliationService.cs'
			Pattern = '\b(?<prefix>(?:System\.Collections\.Generic\.)?)IReadOnlyList\s*<\s*(?<type>(?:RdpAudit\.Core\.Models\.)?ActiveBlock)\s*>\s+(?<name>rows)\b'
			Replacement = '${prefix}List<${type}> ${name}'
			Description = 'CA1859: replace IReadOnlyList<ActiveBlock> rows with List<ActiveBlock> rows'
		},
		[pscustomobject]@{
			Path = Join-Path -Path $script:RepositoryDirectory -ChildPath 'tests\RdpAudit.Core.Tests\EventCatalogTests.cs'
			Pattern = '\b(?<prefix>(?:System\.Collections\.Generic\.)?)IReadOnlyList\s*<\s*(?<type>string)\s*>\s+(?<name>channels)\b'
			Replacement = '${prefix}List<${type}> ${name}'
			Description = 'CA1859: replace IReadOnlyList<string> channels with List<string> channels'
		}
	)

	foreach ($patch in $patches) {
		if (-not (Test-Path -Path $patch.Path)) {
			throw "CA1859 patch target not found: $($patch.Path)"
		}

		$content = Get-Content -Path $patch.Path -Raw
		$patchMatches = [regex]::Matches($content, $patch.Pattern)

		if ($patchMatches.Count -eq 0) {
			Write-Ok "No offending pattern found: $($patch.Description)"
			continue
		}

		$updated = [regex]::Replace($content, $patch.Pattern, $patch.Replacement)
		Set-Content -Path $patch.Path -Value $updated -NoNewline -Encoding UTF8

		$verifyContent = Get-Content -Path $patch.Path -Raw
		$remainingMatches = [regex]::Matches($verifyContent, $patch.Pattern)

		if ($remainingMatches.Count -gt 0) {
			throw "CA1859 patch verification failed for $($patch.Path). Remaining matches: $($remainingMatches.Count)"
		}

		Write-Ok "Patched $($patchMatches.Count) occurrence(s): $($patch.Description)"
		Add-InstallFix $patch.Description
	}

	Test-Ca1859PatchVerification
}

# ── RDPAudit 2.0 Repair & Configuration ──────────────────────────────────────

# Version: 1.0.0
# Interactively repairs the non-mandatory RDPAudit 2.0 prerequisites: enables
# any disabled ETW event channels via wevtutil and turns on the required
# auditpol subcategories via GUID. Skipped in NonInteractive mode unless every
# prerequisite is already satisfied. The routine never fails the installer -
# it only records a warning and lets the operator run the fix by hand later.
function Repair-Rdp2xPrerequisites {
	if (-not $IsWindows) {
		Write-Info 'RDPAudit 2.0 repair skipped (not Windows).'
		return
	}

	$missingChannels = @($script:LastEtwChannelStates | Where-Object { -not $_.IsEnabled })
	$missingAudit = @($script:LastAuditSubcategoryStates | Where-Object { -not $_.IsEnabled })

	if ($missingChannels.Count -eq 0 -and $missingAudit.Count -eq 0) {
		Write-Ok 'RDPAudit 2.0 ETW channels and audit policy are already fully enabled.'
		return
	}

	Write-Section 'RDPAudit 2.0 Repair'

	if ($missingChannels.Count -gt 0) {
		Write-WarningMessage ("{0} ETW event channel(s) are disabled:" -f $missingChannels.Count)
		foreach ($ch in $missingChannels) {
			Write-Host ("    - {0}" -f $ch.Channel) -ForegroundColor Yellow
		}
	}

	if ($missingAudit.Count -gt 0) {
		Write-WarningMessage ("{0} audit subcategory/ies are not Success+Failure:" -f $missingAudit.Count)
		foreach ($sub in $missingAudit) {
			Write-Host ("    - {0} (current: {1})" -f $sub.Name, $sub.Detail) -ForegroundColor Yellow
		}
	}

	$doRepair = Confirm-Action -Prompt 'Enable the missing ETW channels and audit subcategories now?' -DefaultYes $true
	if (-not $doRepair) {
		Write-Info 'RDPAudit 2.0 repair skipped by operator. Configurator will still run in EventLogWatcher mode.'
		return
	}

	foreach ($ch in $missingChannels) {
		Write-Info ("Enabling channel: {0}" -f $ch.Channel)
		try {
			& wevtutil.exe sl $ch.Channel /e:true | Out-Null
			if ($LASTEXITCODE -eq 0) {
				Write-Ok ("Channel enabled: {0}" -f $ch.Channel)
				$script:InstallState.Fixes.Add(("Enabled ETW channel: {0}" -f $ch.Channel))
			} else {
				Write-WarningMessage ("wevtutil sl exited with code {0} for channel {1}." -f $LASTEXITCODE, $ch.Channel)
			}
		} catch {
			Write-WarningMessage ("Failed to enable {0}: {1}" -f $ch.Channel, $_.Exception.Message)
		}
	}

	foreach ($sub in $missingAudit) {
		Write-Info ("Enabling audit subcategory: {0} ({1})" -f $sub.Name, $sub.Guid)
		try {
			& auditpol.exe /set /subcategory:$($sub.Guid) /success:enable /failure:enable | Out-Null
			if ($LASTEXITCODE -eq 0) {
				Write-Ok ("Audit subcategory enabled: {0}" -f $sub.Name)
				$script:InstallState.Fixes.Add(("Enabled audit subcategory: {0}" -f $sub.Name))
			} else {
				Write-WarningMessage ("auditpol exited with code {0} for {1}." -f $LASTEXITCODE, $sub.Name)
			}
		} catch {
			Write-WarningMessage ("Failed to enable audit subcategory {0}: {1}" -f $sub.Name, $_.Exception.Message)
		}
	}
}

# Version: 1.0.0
# Merges the operator's -IngestionMode choice into the deployed appsettings.json
# WITHOUT disturbing operator overrides. The file lives under
# %ProgramData%\RdpAudit\appsettings.json and is created by publish.ps1 on the
# very first install; on subsequent installs it already contains custom values
# so we must (1) load the existing JSON, (2) upsert RdpAudit.IngestionMode,
# (3) save with the same encoding (UTF-8 without BOM, LF newlines, tab indent).
function Set-IngestionModeInAppSettings {
	if (-not $IsWindows) {
		Write-Info 'IngestionMode configuration skipped (not Windows).'
		return
	}

	$programData = [System.Environment]::GetFolderPath('CommonApplicationData')
	$configRoot = Join-Path -Path $programData -ChildPath 'RdpAudit'
	$configFile = Join-Path -Path $configRoot -ChildPath 'appsettings.json'

	try {
		if (-not (Test-Path -LiteralPath $configRoot)) {
			New-Item -ItemType Directory -Path $configRoot -Force | Out-Null
		}

		$existing = $null
		if (Test-Path -LiteralPath $configFile) {
			try {
				$raw = Get-Content -LiteralPath $configFile -Raw -ErrorAction Stop
				if (-not [string]::IsNullOrWhiteSpace($raw)) {
					$existing = $raw | ConvertFrom-Json -ErrorAction Stop
				}
			} catch {
				Write-WarningMessage ("Existing appsettings.json is not valid JSON ({0}). Rewriting with defaults." -f $_.Exception.Message)
				$existing = $null
			}
		}

		if ($null -eq $existing) {
			$existing = [pscustomobject]@{}
		}

		# Upsert RdpAudit section without dropping any operator-added keys.
		if ($existing.PSObject.Properties.Name -notcontains 'RdpAudit') {
			$existing | Add-Member -MemberType NoteProperty -Name 'RdpAudit' -Value ([pscustomobject]@{})
		}

		if ($existing.RdpAudit.PSObject.Properties.Name -contains 'IngestionMode') {
			$existing.RdpAudit.IngestionMode = $IngestionMode
		} else {
			$existing.RdpAudit | Add-Member -MemberType NoteProperty -Name 'IngestionMode' -Value $IngestionMode
		}

		$json = $existing | ConvertTo-Json -Depth 32
		# ConvertTo-Json emits 2-space indent. Convert those to tabs so the file
		# stays consistent with the rest of the codebase, then normalise line
		# endings. We rewrite line-by-line to avoid PowerShell's ScriptBlock
		# replacement quirk where `$_` inside the replacement refers to the Match
		# object, not to the ForEach-Object iterator variable.
		$normalizedLines = foreach ($line in ($json -split "`r?`n")) {
			$leadingSpaces = 0
			while ($leadingSpaces -lt $line.Length -and $line[$leadingSpaces] -eq ' ') {
				$leadingSpaces++
			}
			$tabCount = [Math]::Floor($leadingSpaces / 2)
			("`t" * $tabCount) + $line.Substring($leadingSpaces)
		}
		$json = $normalizedLines -join "`n"
		[System.IO.File]::WriteAllText($configFile, $json + "`n", (New-Object System.Text.UTF8Encoding($false)))

		Write-Ok ("IngestionMode = '{0}' written to {1}" -f $IngestionMode, $configFile)
		$script:InstallState.Actions.Add(("Wrote IngestionMode = {0} to {1}" -f $IngestionMode, $configFile))
	} catch {
		Write-WarningMessage ("Failed to write IngestionMode to {0}: {1}" -f $configFile, $_.Exception.Message)
	}
}

# Version: 1.0.0
# Sanity-checks that the exact TraceEvent version required by the RDPAudit 2.0
# event-collection layer is present in the NuGet global cache AFTER dotnet
# restore has completed. If not, dotnet restore silently used a satellite feed
# or a proxy corp mirror that resolved to a different version - report loudly
# but do not fail the pipeline (the assembly reference will fail dotnet build
# a few seconds later with a much clearer diagnostic).
function Test-TraceEventCacheAfterRestore {
	$version = Get-TraceEventInstalledVersion
	if ($null -eq $version) {
		Write-WarningMessage ("TraceEvent {0} is not in the NuGet global cache after restore. The 2.0 ETW transport will fail to load." -f $script:TraceEventPackageVersion)
		return
	}
	Write-Ok ("TraceEvent {0} present in NuGet cache." -f $version)
}

# ── Build Pipeline ───────────────────────────────────────────────────────────

function Invoke-RdpAuditBuildPipeline {
	Write-Section 'Validation'

	if (-not (Test-Path -Path $script:SolutionPath)) {
		throw "Solution file not found: $($script:SolutionPath)"
	}

	if (-not (Test-Path -Path $script:PublishScriptPath)) {
		throw "Publish script not found: $($script:PublishScriptPath)"
	}

	Write-Section 'dotnet restore'
	Invoke-CheckedCommand `
		-FilePath 'dotnet' `
		-Arguments @('restore', '.\RdpAudit.sln') `
		-WorkingDirectory $script:RepositoryDirectory `
		-FailureMessage 'dotnet restore failed.'

	# Verify the RDPAudit 2.0 ETW transport dependency landed in the NuGet cache
	# before dotnet build reads it. Non-fatal: dotnet build will surface a much
	# clearer diagnostic if the package really is missing.
	Test-TraceEventCacheAfterRestore

	Write-Section 'dotnet build'
	Invoke-CheckedCommand `
		-FilePath 'dotnet' `
		-Arguments @('build', '.\RdpAudit.sln', '-c', 'Release', '--no-restore') `
		-WorkingDirectory $script:RepositoryDirectory `
		-FailureMessage 'dotnet build failed.'

	Write-Section 'dotnet test'
	# --blame-hang-timeout <n> aborts a test that runs longer than the timeout AND prints the
	# assembly + test name that was running when the timeout fired, so we always know which
	# test hung the run.
	#
	# Console logger verbosity:
	#   * default (-VerboseTests NOT set)  — 'minimal' — only Failed tests + summary are
	#     streamed to the console/transcript. This keeps the RDPAudit_Install_*.log file
	#     small enough to skim even when hundreds of tests pass.
	#   * -VerboseTests                    — 'normal'  — every test outcome is streamed.
	#
	# The full result set (Passed / Failed / Skipped, per-test duration, stack traces) is
	# additionally captured to a TRX file under <LogDirectory>\test-results\ regardless of
	# verbosity, so no information is lost even in minimal mode.
	$testResultsDirectory = Join-Path -Path $LogDirectory -ChildPath 'test-results'
	try {
		if (-not (Test-Path -LiteralPath $testResultsDirectory)) {
			New-Item -ItemType Directory -Path $testResultsDirectory -Force | Out-Null
		}
	} catch {
		Write-WarningMessage ("Could not create test results directory '{0}': {1}. TRX file will be written to the repository default." -f $testResultsDirectory, $_.Exception.Message)
		$testResultsDirectory = $null
	}

	$trxFileName = "RDPAudit_Tests_{0}.trx" -f $script:InstallLogTimestamp
	$consoleVerbosity = if ($VerboseTests) { 'normal' } else { 'minimal' }

	if ($VerboseTests) {
		Write-Info 'Full test output enabled (-VerboseTests). Every Passed/Failed test will be streamed.'
	} else {
		Write-Info 'Compact test output (default). Only Failed tests will be streamed; full results in the TRX file.'
	}

	$testArguments = [System.Collections.Generic.List[string]]::new()
	$testArguments.Add('test')
	$testArguments.Add('.\RdpAudit.sln')
	$testArguments.Add('-c')
	$testArguments.Add('Release')
	$testArguments.Add('--no-build')
	$testArguments.Add('--blame-hang')
	$testArguments.Add('--blame-hang-timeout')
	$testArguments.Add('90s')
	$testArguments.Add('--logger')
	$testArguments.Add(("console;verbosity={0}" -f $consoleVerbosity))
	$testArguments.Add('--logger')
	$testArguments.Add(("trx;LogFileName={0}" -f $trxFileName))
	if ($testResultsDirectory) {
		$testArguments.Add('--results-directory')
		$testArguments.Add($testResultsDirectory)
	}

	Invoke-CheckedCommand `
		-FilePath 'dotnet' `
		-Arguments $testArguments.ToArray() `
		-WorkingDirectory $script:RepositoryDirectory `
		-FailureMessage 'dotnet test failed.'

	if ($testResultsDirectory) {
		$trxPath = Join-Path -Path $testResultsDirectory -ChildPath $trxFileName
		if (Test-Path -LiteralPath $trxPath) {
			Write-Ok ("Full test results (all outcomes) saved to: {0}" -f $trxPath)
		}
	}

	Write-Section 'publish.ps1'
	Invoke-CheckedCommand `
		-FilePath 'pwsh' `
		-Arguments @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', '.\publish.ps1') `
		-WorkingDirectory $script:RepositoryDirectory `
		-FailureMessage 'publish.ps1 failed.'
}

function Start-Configurator {
	if ($SkipLaunch) {
		Write-Info 'Configurator launch skipped by parameter.'
		return
	}

	Write-Section 'Launch Configurator'

	if (-not (Test-Path -Path $script:ConfiguratorPath)) {
		Write-WarningMessage "Configurator executable not found: $($script:ConfiguratorPath)"
		return
	}

	Write-Ok "Launching: $($script:ConfiguratorPath)"
	Start-Process -FilePath $script:ConfiguratorPath -WorkingDirectory (Split-Path -Path $script:ConfiguratorPath -Parent)
}

# ── MikroTik Module Build Prerequisites ───────────────────────────────────────

function Test-WindowsDesktopRuntimePresent {
	# The RdpAudit.Mikrotik module is a WinForms (net8.0-windows) application, so the
	# Windows Desktop targeting/runtime pack (Microsoft.WindowsDesktop.App) must be
	# available to compile and run it. This ships with the .NET 8 SDK, but we verify
	# it explicitly so a missing/partial SDK install is reported clearly.
	$dotnetCommand = Get-Command -Name 'dotnet' -ErrorAction SilentlyContinue
	if ($null -eq $dotnetCommand) {
		return $false
	}

	try {
		$runtimes = @(dotnet --list-runtimes 2>$null)
		foreach ($line in $runtimes) {
			if ($line -match '^Microsoft\.WindowsDesktop\.App\s+8\.') {
				return $true
			}
		}
	} catch {
		return $false
	}

	return $false
}

function Confirm-MikrotikBuildPrerequisites {
	# Verifies and, where possible, repairs everything the RdpAudit.Mikrotik module
	# needs to build and run, beyond the generic .NET SDK already validated earlier:
	#   - the Windows Desktop runtime pack (WinForms);
	#   - a win-x64 NuGet restore (the module declares <RuntimeIdentifier>win-x64);
	#   - the patched MessagePack reference (handled by Update-MessagePackPackageReference).
	Write-Section 'MikroTik Module Prerequisites'

	$projectPath = Join-Path -Path $script:RepositoryDirectory -ChildPath 'src\RdpAudit.Mikrotik\RdpAudit.Mikrotik.csproj'
	if (-not (Test-Path -Path $projectPath -PathType Leaf)) {
		Write-WarningMessage 'RdpAudit.Mikrotik project not found in this branch. Skipping module-specific prerequisites.'
		return
	}

	if (Test-WindowsDesktopRuntimePresent) {
		Write-Ok 'Windows Desktop runtime (Microsoft.WindowsDesktop.App 8.x) is available for the WinForms module.'
	} else {
		Write-WarningMessage 'Windows Desktop runtime 8.x was not detected. Ensuring the .NET 8 Desktop runtime is installed ...'

		$wingetRecord = @(Get-PrerequisiteStatus) | Where-Object { $_.Name -eq 'winget' } | Select-Object -First 1
		if ($null -ne $wingetRecord -and $wingetRecord.IsSatisfied) {
			Invoke-CheckedCommand `
				-FilePath 'winget' `
				-Arguments @(
					'install',
					'--id', 'Microsoft.DotNet.DesktopRuntime.8',
					'--exact',
					'--silent',
					'--accept-source-agreements',
					'--accept-package-agreements'
				) `
				-FailureMessage 'winget failed to install the .NET 8 Desktop runtime.'
			$script:InstallState.InstalledPrerequisites.Add('.NET 8 Desktop Runtime (Microsoft.DotNet.DesktopRuntime.8)')
			Write-Ok '.NET 8 Desktop runtime installation command completed.'
		} else {
			Write-WarningMessage 'winget is unavailable. The full .NET 8 SDK already includes the Windows Desktop pack; the build step will surface a clear error if it is genuinely missing.'
		}
	}

	# A win-x64-targeted restore guarantees the runtime-specific assets the module
	# needs are materialised before the Release build runs.
	Write-Info 'Restoring RdpAudit.Mikrotik for the win-x64 runtime ...'
	Invoke-CheckedCommand `
		-FilePath 'dotnet' `
		-Arguments @('restore', $projectPath, '-r', 'win-x64') `
		-WorkingDirectory $script:RepositoryDirectory `
		-FailureMessage 'win-x64 restore of RdpAudit.Mikrotik failed.'

	Write-Ok 'RdpAudit.Mikrotik module prerequisites are satisfied.'
	Add-InstallAction 'Verified RdpAudit.Mikrotik build prerequisites (Windows Desktop pack + win-x64 restore)'
}

# ── Installation Summary ─────────────────────────────────────────────────────

function Resolve-InstalledTargetVersion {
	# After publishing, read the actual version stamped into the produced binaries so
	# the Summary reports the genuine on-disk version rather than only the source value.
	$published = Get-FileVersionOrNull -Path $script:ConfiguratorPath
	if ($null -eq $published) {
		$published = Get-FileVersionOrNull -Path $script:ServiceExePath
	}
	if ($null -eq $published) {
		$published = Get-TargetVersionFromSource
	}

	$script:InstallState.TargetVersion = $published
}

function Show-InstallationSummary {
	Write-Section 'Installation Summary'

	$state = $script:InstallState

	# Mode and version transition.
	if ($state.IsFreshInstall) {
		Write-Host ' Mode               : Fresh, clean installation' -ForegroundColor White
	} else {
		$prev = if ($null -ne $state.PreviousVersion) { $state.PreviousVersion.ToString() } else { 'unknown' }
		Write-Host (' Mode               : Upgrade (previous version {0})' -f $prev) -ForegroundColor White
	}

	$target = if ($null -ne $state.TargetVersion) { $state.TargetVersion.ToString() } else { 'unknown' }
	Write-Host (' Updated to version : {0}' -f $target) -ForegroundColor White

	# What was done.
	Write-Host ''
	Write-Host ' Actions performed:' -ForegroundColor White
	$actions = @(
		'Synced repository to the target branch',
		'Restored, built and tested the solution in Release',
		'Published Service, Configurator and MikroTik binaries'
	)
	foreach ($extra in $state.Actions) { $actions += $extra }
	foreach ($action in $actions) { Write-Host "   - $action" -ForegroundColor Gray }

	# Components released at startup.
	if ($state.StoppedProcesses.Count -gt 0 -or $state.ForcedProcesses.Count -gt 0 -or $state.ServiceStopped) {
		Write-Host ''
		Write-Host ' Running components released:' -ForegroundColor White
		if ($state.ServiceStopped) { Write-Host "   - Service '$($script:WindowsServiceName)' stopped gracefully" -ForegroundColor Gray }
		foreach ($p in $state.StoppedProcesses) { Write-Host "   - $p exited gracefully" -ForegroundColor Gray }
		foreach ($p in $state.ForcedProcesses) { Write-Host "   - $p force-terminated (soft timeout exceeded)" -ForegroundColor Yellow }
	}

	# Clean install disclosure — makes destructive runs stand out in the transcript.
	if ($state.CleanInstallPerformed) {
		Write-Host ''
		Write-Host ' Clean install      : Previous <WorkDirectory>\Service tree and all rdpaudit.db* files were deleted before this run.' -ForegroundColor Yellow
	}

	# What was installed.
	Write-Host ''
	if ($state.InstalledPrerequisites.Count -gt 0) {
		Write-Host ' Installed:' -ForegroundColor White
		foreach ($p in $state.InstalledPrerequisites) { Write-Host "   - $p" -ForegroundColor Gray }
	} else {
		Write-Host ' Installed          : No new prerequisites were required.' -ForegroundColor Gray
	}

	# What was fixed.
	Write-Host ''
	if ($state.Fixes.Count -gt 0) {
		Write-Host ' Fixed / patched:' -ForegroundColor White
		foreach ($f in $state.Fixes) { Write-Host "   - $f" -ForegroundColor Gray }
	} else {
		Write-Host ' Fixed / patched    : No source or package fixes were necessary.' -ForegroundColor Gray
	}

	# Next-step guidance.
	Write-Host ''
	if ($state.IsFreshInstall) {
		Write-Host ' Next steps (fresh installation):' -ForegroundColor Cyan
		Write-Host '   1. The Configurator has been launched (unless -SkipLaunch was used).' -ForegroundColor Gray
		Write-Host '   2. In the Configurator, click the "Install" button to register and start' -ForegroundColor Gray
		Write-Host "      the '$($script:WindowsServiceName)' Windows service." -ForegroundColor Gray
		Write-Host '   3. Review the Prerequisites and Audit Policy pages and apply any fixes.' -ForegroundColor Gray
		Write-Host '   4. (Optional) Open the MikroTik setup wizard to bootstrap RouterOS-based' -ForegroundColor Gray
		Write-Host '      RDP blocking, then return to the Configurator to verify status.' -ForegroundColor Gray
	} else {
		Write-Host ' Next steps (upgrade):' -ForegroundColor Cyan
		Write-Host '   1. The updated binaries are published. The Configurator has been launched.' -ForegroundColor Gray
		Write-Host "   2. If the '$($script:WindowsServiceName)' service was stopped for the upgrade," -ForegroundColor Gray
		Write-Host '      start it again from the Configurator (or it will start on next boot).' -ForegroundColor Gray
		Write-Host '   3. Confirm the service status and recent activity in the Configurator.' -ForegroundColor Gray
	}

	Write-Host ''
}

# ── Main Flow ────────────────────────────────────────────────────────────────

function Invoke-Main {
	Write-Section 'RdpAudit Installer'

	Write-Info "Work directory     : $WorkDirectory"
	Write-Info "Repository         : $RepositoryUrl"
	Write-Info "Branch             : $RepositoryBranch"
	Write-Info "MessagePack target : $SafeMessagePackVersion"
	Write-Info "Graceful timeout   : $GracefulShutdownTimeoutSeconds second(s)"
	Write-Info "Ingestion mode     : $IngestionMode"

	# Report any previously installed build (with its version) before changing anything.
	Show-ExistingInstallation

	$prerequisites = @(Get-PrerequisiteStatus)
	Show-PrerequisiteStatus -Items $prerequisites

	if (-not (Test-MandatoryPrerequisites -Items $prerequisites)) {
		$installResult = Install-MissingPrerequisites -Items $prerequisites
		if (-not $installResult) {
			throw 'Prerequisites are not satisfied.'
		}

		Write-Section 'Re-check Prerequisites'
		$prerequisites = @(Get-PrerequisiteStatus)
		Show-PrerequisiteStatus -Items $prerequisites

		if (-not (Test-MandatoryPrerequisites -Items $prerequisites)) {
			throw 'Some mandatory prerequisites are still missing after installation.'
		}
	}

	Write-Ok 'All mandatory prerequisites are satisfied.'

	$proceed = Confirm-Action -Prompt 'Proceed with full RdpAudit installation?' -DefaultYes $true
	if (-not $proceed) {
		Write-Info 'Installation cancelled by user.'
		return
	}

	# Release any running components before touching the workspace so the publish
	# folder can be rebuilt in place. Graceful first, forced only after the timeout.
	Stop-RdpAuditProcesses

	if ($CleanInstall) {
		Invoke-CleanInstallPurge
	}

	Initialize-Workspace
	Sync-Repository
	Set-DotNetSdkGlobalJson
	Update-MessagePackPackageReference
	Update-Ca1859SourceWarnings
	Confirm-MikrotikBuildPrerequisites
	Install-MoqPackage -RepositoryRoot $script:RepositoryDirectory
	Repair-Rdp2xPrerequisites
	Invoke-RdpAuditBuildPipeline
	Set-IngestionModeInAppSettings
	Resolve-InstalledTargetVersion
	Start-Configurator

	Show-InstallationSummary

	Write-Section 'Completed'
	Write-Ok 'RdpAudit installation pipeline completed successfully.'
}

# Version: 1.3.0
# Terminates the installer without blocking on user input. Historical builds
# called $Host.UI.RawUI.ReadKey() at the end so a double-click launch would keep
# the console visible, but that call also captured any keypress (including the
# ones the operator uses to copy text with Ctrl+C / mouse selection + Enter),
# so the window would appear to close spontaneously. Now every run writes a
# complete transcript to RDPAudit_Install_<Date_Time>.log; the operator can
# review the file at their own pace, and the console window is returned to the
# shell so it stays fully interactive for further work.
function Stop-InstallationTranscript {
	if ($script:TranscriptStarted) {
		try {
			Stop-Transcript | Out-Null
		} catch {
			# Ignore — the transcript is best-effort and must never mask the real exit reason.
		}
		$script:TranscriptStarted = $false
	}
}

function Show-InstallationLogHint {
	param(
		[Parameter(Mandatory)][int]$ExitCode
	)

	Write-Host ''
	if ($ExitCode -eq 0) {
		Write-Host 'Installation completed. Returning to the shell prompt.' -ForegroundColor Green
	} else {
		Write-Host ("Installation FAILED with exit code {0}." -f $ExitCode) -ForegroundColor Red
	}
	Write-Host ("Full log saved to: {0}" -f $script:InstallLogFile) -ForegroundColor Cyan
	Write-Host ''
}

try {
	try {
		Invoke-Main
		$exitCode = 0
	} catch {
		Write-Section 'Fatal Error'
		Write-ErrorMessage $_.Exception.Message

		if ($null -ne $_.ScriptStackTrace) {
			Write-Host ''
			Write-Host $_.ScriptStackTrace -ForegroundColor DarkRed
		}

		$exitCode = 1
	}

	Show-InstallationLogHint -ExitCode $exitCode
} finally {
	Stop-InstallationTranscript
}

# When -ExitAfterInstall is set AND the installation succeeded, terminate the host
# PowerShell process itself so a scripted launch closes cleanly. Without the switch
# the script simply returns to the current prompt (regardless of outcome) so the
# operator can keep working in the same window. Failed runs never auto-close the
# host — the window must stay open so the fatal error and log path remain visible.
if ($ExitAfterInstall -and $exitCode -eq 0 -and $Host.Name -eq 'ConsoleHost') {
	Write-Host 'ExitAfterInstall requested — closing PowerShell host.' -ForegroundColor DarkGray
	[Environment]::Exit($exitCode)
}

exit $exitCode
