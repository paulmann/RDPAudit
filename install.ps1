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
	Author : Mikhail Deynekin — https://Deynekin.com — Mikhail@Deynekin.com
	Version: 1.2.4

.FEATURES
	Detects and reports any previously installed RdpAudit version (with version number).
	Gracefully stops the running Service, Configurator and MikroTik configurator,
	escalating to a forced termination only if they do not exit within a soft timeout.
	Ensures the build/runtime prerequisites required by the RdpAudit.Mikrotik module
	(Windows Desktop targeting pack, win-x64 restore, patched MessagePack) are present.
	Prints a final installation Summary describing what was done, installed, fixed and
	to which version the software was upgraded — including next-step guidance for a
	fresh, clean installation.

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

	[string]$RepositoryBranch = 'main',

	[string]$SafeMessagePackVersion = '2.5.301',

	# Soft timeout (seconds) granted to running RdpAudit processes to exit gracefully
	# before the installer escalates to a forced termination. Defaults to 2 minutes.
	[int]$GracefulShutdownTimeoutSeconds = 120,

	[switch]$NonInteractive,

	[switch]$SkipLaunch
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

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
		Write-Info 'Repository already exists. Fetching and resetting to remote branch.'
		Invoke-CheckedCommand `
			-FilePath 'git' `
			-Arguments @('-C', $script:RepositoryDirectory, 'fetch', 'origin', $RepositoryBranch) `
			-FailureMessage 'git fetch failed.'

		Invoke-CheckedCommand `
			-FilePath 'git' `
			-Arguments @('-C', $script:RepositoryDirectory, 'checkout', $RepositoryBranch) `
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

	Write-Section 'dotnet build'
	Invoke-CheckedCommand `
		-FilePath 'dotnet' `
		-Arguments @('build', '.\RdpAudit.sln', '-c', 'Release', '--no-restore') `
		-WorkingDirectory $script:RepositoryDirectory `
		-FailureMessage 'dotnet build failed.'

	Write-Section 'dotnet test'
	Invoke-CheckedCommand `
		-FilePath 'dotnet' `
		-Arguments @('test', '.\RdpAudit.sln', '-c', 'Release', '--no-build') `
		-WorkingDirectory $script:RepositoryDirectory `
		-FailureMessage 'dotnet test failed.'

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

	Initialize-Workspace
	Sync-Repository
	Set-DotNetSdkGlobalJson
	Update-MessagePackPackageReference
	Update-Ca1859SourceWarnings
	Confirm-MikrotikBuildPrerequisites
	Install-MoqPackage -RepositoryRoot $script:RepositoryDirectory
	Invoke-RdpAuditBuildPipeline
	Resolve-InstalledTargetVersion
	Start-Configurator

	Show-InstallationSummary

	Write-Section 'Completed'
	Write-Ok 'RdpAudit installation pipeline completed successfully.'
}

try {
	Invoke-Main
	exit 0
} catch {
	Write-Section 'Fatal Error'
	Write-ErrorMessage $_.Exception.Message

	if ($null -ne $_.ScriptStackTrace) {
		Write-Host ''
		Write-Host $_.ScriptStackTrace -ForegroundColor DarkRed
	}

	exit 1
}
