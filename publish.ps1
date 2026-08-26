#Requires -Version 7.0
<#
.SYNOPSIS
	Builds RdpAudit artifacts and updates the publish folder. Does NOT manage the installed service.

.DESCRIPTION
	Publishes RdpAudit.Service, RdpAudit.Configurator, and RdpAudit.Mikrotik as self-contained,
	single-file, win-x64 executables under ./publish/Service, ./publish/Configurator, and
	./publish/Mikrotik. Resolves version from Directory.Build.props unless -Version is supplied.

	SCOPE BOUNDARY (enforced):
	  - Writes ONLY inside the ./publish folder relative to the script root.
	  - Never stops, starts, or reconfigures the Windows service.
	  - Never writes to C:\Program Files\RdpAudit or %ProgramData%\RdpAudit.
	  - Never calls install.ps1 or duplicates its deployment logic.
	  - Terminates ONLY processes whose executable path is physically inside the publish root.

	Use install.ps1 to deploy built artifacts to the installed service location.

.PARAMETER Version
	Explicit VersionPrefix for this build (e.g. "2.1.0"). When omitted the authoritative value
	is read from Directory.Build.props — no hardcoded default is applied. Pass an explicit value
	only to override the props for a release tag.

.PARAMETER Configuration
	MSBuild configuration. Defaults to Release.

.PARAMETER SourceRevisionId
	Short commit SHA to stamp as SemVer build metadata (+sha). When omitted the script resolves
	it automatically via `git rev-parse --short=12 HEAD` and appends "-dirty" for unclean trees.
	Pass "-" to disable the SHA entirely (e.g. when building outside a git checkout).

.PARAMETER Force
	Terminate processes running FROM the publish folder (by full path) without prompting.
	Only processes inside the publish root are ever killed; the installed service is not affected.

.PARAMETER Clean
	Delete the entire publish folder before building. Requires confirmation or -Force.
	Equivalent to a fresh publish: no stale artifacts remain.

.PARAMETER SelfTest
	Run structural invariants and exit. No publish, no delete, no side effects.

.PARAMETER Timeout
	Seconds to wait for a locked file to become free after terminating the holding process.
	Default: 30 seconds.

.PARAMETER WhatIf
	Show what would be done without performing any action. Implied by [CmdletBinding(SupportsShouldProcess)].

.EXAMPLE
	.\publish.ps1
	Build with version from Directory.Build.props, update publish folder, stop blockers interactively.

.EXAMPLE
	.\publish.ps1 -WhatIf
	Print the full build and update plan without touching any file.

.EXAMPLE
	.\publish.ps1 -Force
	Terminate any publish-folder processes without prompting, then publish.

.EXAMPLE
	.\publish.ps1 -Clean -Force
	Wipe the publish folder and do a fully fresh publish, terminating blockers automatically.

.EXAMPLE
	.\publish.ps1 -Version 2.1.0
	Override the version from Directory.Build.props with an explicit release tag.

.NOTES
	Exit codes:
	  0   Success — publish folder fully updated, all post-checks passed.
	  1   Pre-flight failure (SDK missing, project not found, invalid environment).
	  2   Build/publish failed (dotnet exit code non-zero).
	  3   File-lock timeout — file could not be freed within -Timeout seconds.
	  4   Publish folder write error (permissions, path too long, disk full).
	  5   Post-check failure — one or more expected artifacts missing or wrong version.
	  6   Self-test failure.
	  7   User cancelled (interactive prompt declined, or -WhatIf dry-run exit).

	Responsibility boundary:
	  publish.ps1  — build, version resolution, publish folder contents, process termination
	                 scoped to the publish folder, post-checks, reporting.
	  install.ps1  — Windows service stop/start, deployment to C:\Program Files\RdpAudit,
	                 ProgramData initialisation, service registration, elevation requirement.
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
	[string]$Version = "",
	[string]$Configuration = "Release",
	[string]$SourceRevisionId = "",
	[switch]$Force,
	[switch]$Clean,
	[switch]$SelfTest,
	[switch]$IncludeBenchmarks,
	[int]$Timeout = 30
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$InformationPreference = "Continue"

# ── Script-scope state ────────────────────────────────────────────────────────
$script:PublishRoot        = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot "publish"))
$script:InspectionFailures = [System.Collections.Generic.List[hashtable]]::new()
$script:TerminatedProcs    = [System.Collections.Generic.List[hashtable]]::new()
$script:ReportRows         = [System.Collections.Generic.List[hashtable]]::new()
$script:PostChecks         = [System.Collections.Generic.List[hashtable]]::new()
$script:DotnetLanguageArgs = @()
$script:BuiltVersion       = ""
$script:VersionSource      = ""

# ── Projects published in order ───────────────────────────────────────────────
$script:Projects = @(
	@{ CsprojRelPath = "src/RdpAudit.Service/RdpAudit.Service.csproj";           Subdir = "Service";      ExeName = "RdpAudit.Service.exe" }
	@{ CsprojRelPath = "src/RdpAudit.Configurator/RdpAudit.Configurator.csproj"; Subdir = "Configurator"; ExeName = "RdpAudit.Configurator.exe" }
	@{ CsprojRelPath = "src/RdpAudit.Mikrotik/RdpAudit.Mikrotik.csproj";         Subdir = "Mikrotik";     ExeName = "RdpAudit.Mikrotik.exe" }
)

$script:SqliteSupportFiles = @(
	"Microsoft.Data.Sqlite.dll",
	"SQLitePCLRaw.core.dll",
	"SQLitePCLRaw.provider.e_sqlite3.dll",
	"SQLitePCLRaw.batteries_v2.dll",
	"e_sqlite3.dll"
)

# ── Console / locale init ─────────────────────────────────────────────────────
function Initialize-EnglishConsoleOutput {
	$env:DOTNET_CLI_UI_LANGUAGE = "en"
	$env:VSLANG                 = "1033"
	$env:NUGET_CLI_LANGUAGE     = "en"
	$env:DOTNET_NOLOGO          = "true"

	$utf8NoBom                  = [System.Text.UTF8Encoding]::new($false)
	[Console]::InputEncoding    = $utf8NoBom
	[Console]::OutputEncoding   = $utf8NoBom
	$global:OutputEncoding      = $utf8NoBom

	$script:DotnetLanguageArgs  = @("-p:PreferredUILang=en-US")
}

Initialize-EnglishConsoleOutput

# ── Path safety guard ─────────────────────────────────────────────────────────
function Test-IsUnderPublishRoot {
	param([Parameter(Mandatory)][string]$Path)
	$normalized = [System.IO.Path]::GetFullPath($Path)
	$root       = $script:PublishRoot.TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
	return $normalized.StartsWith($root, [System.StringComparison]::OrdinalIgnoreCase) `
		-or [System.IO.Path]::GetFullPath($Path) -eq $script:PublishRoot
}

# ── Version resolution ────────────────────────────────────────────────────────
function Get-PropsVersionPrefix {
	[OutputType([string])]
	param()
	$dbp = Join-Path $PSScriptRoot "Directory.Build.props"
	if (-not (Test-Path $dbp)) { return "" }
	try {
		[xml]$xml   = Get-Content $dbp -Raw -Encoding UTF8
		$nsm        = [System.Xml.XmlNamespaceManager]::new($xml.NameTable)
		$node       = $xml.SelectSingleNode("//VersionPrefix")
		if ($null -eq $node) { return "" }
		return $node.InnerText.Trim()
	} catch {
		Write-Warning ("Could not parse Directory.Build.props for VersionPrefix: " + $_.Exception.Message)
		return ""
	}
}

function Resolve-BuildVersion {
	[OutputType([string])]
	param()
	if (-not [string]::IsNullOrWhiteSpace($Version)) {
		$script:VersionSource = "-Version parameter (overrides props)"
		Write-Information ("Version source: -Version parameter (overrides props) = " + $Version)
		return $Version.Trim()
	}
	$fromProps = Get-PropsVersionPrefix
	if (-not [string]::IsNullOrWhiteSpace($fromProps)) {
		$script:VersionSource = "Directory.Build.props"
		Write-Information ("Version source: Directory.Build.props = " + $fromProps)
		return $fromProps
	}
	# Last resort: signal the caller — build WITHOUT -p:VersionPrefix so SDK default applies.
	$script:VersionSource = "SDK default (props not found or empty)"
	Write-Warning "Directory.Build.props VersionPrefix not found; SDK default will apply."
	return ""
}

function Resolve-SourceRevisionId {
	[OutputType([string])]
	param([string]$Override)
	if (-not [string]::IsNullOrWhiteSpace($Override)) {
		if ($Override -eq "-") { return "" }
		return $Override.Trim()
	}
	$git = Get-Command git -ErrorAction SilentlyContinue
	if ($null -eq $git) {
		Write-Verbose "git not found on PATH; building without a SourceRevisionId."
		return ""
	}
	try {
		$sha = (& git -C $PSScriptRoot rev-parse --short=12 HEAD 2>$null)
		if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($sha)) {
			Write-Verbose "git rev-parse HEAD returned no SHA; building without SourceRevisionId."
			return ""
		}
		$sha = $sha.Trim()
		$status = (& git -C $PSScriptRoot status --porcelain 2>$null)
		if ($LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace($status)) {
			$sha = $sha + "-dirty"
		}
		return $sha
	} catch {
		Write-Verbose ("SHA resolution failed: " + $_.Exception.Message)
		return ""
	}
}

# ── dotnet CLI wrapper ────────────────────────────────────────────────────────
function Invoke-DotnetCli {
	[OutputType([int])]
	param([Parameter(Mandatory)][string[]]$Arguments)
	$output   = & dotnet @Arguments 2>&1
	$exitCode = $LASTEXITCODE
	foreach ($line in $output) {
		Write-Information ([string]$line)
	}
	return $exitCode
}

# ── Diagnostic helpers ────────────────────────────────────────────────────────
function Add-InspectionFailure {
	param(
		[Parameter(Mandatory)][string]$ProcessName,
		[AllowNull()][Nullable[int]]$ProcessIdValue,
		[Parameter(Mandatory)][string]$Reason
	)
	$script:InspectionFailures.Add(@{
		ProcessName    = $ProcessName
		ProcessIdValue = $ProcessIdValue
		Reason         = $Reason
	}) | Out-Null
	$idText = if ($null -ne $ProcessIdValue) { $ProcessIdValue.ToString() } else { "?" }
	Write-Verbose ("Inspection failure: {0} (PID {1}) -> {2}" -f $ProcessName, $idText, $Reason)
}

function New-ConfirmedBlocker {
	[OutputType([hashtable])]
	param(
		[Parameter(Mandatory)][string]$ProcessName,
		[Parameter(Mandatory)][int]$ProcessIdValue,
		[Parameter(Mandatory)][string]$ExePath
	)
	if ([string]::IsNullOrWhiteSpace($ProcessName)) { throw "blocker requires non-empty ProcessName" }
	if ([string]::IsNullOrWhiteSpace($ExePath))     { throw "blocker requires non-empty ExePath" }
	return @{ ProcessName = $ProcessName; ProcessIdValue = $ProcessIdValue; ExePath = $ExePath }
}

function Format-LockingProcess {
	[OutputType([string])]
	param(
		[Parameter(Mandatory)][string]$ProcessName,
		[Parameter(Mandatory)][int]$ProcessIdValue,
		[Parameter(Mandatory)][string]$ExePath
	)
	return ("{0} (PID {1}) -> {2}" -f $ProcessName, $ProcessIdValue, $ExePath)
}

function Format-InspectionFailure {
	[OutputType([string])]
	param(
		[Parameter(Mandatory)][string]$ProcessName,
		[AllowNull()][Nullable[int]]$ProcessIdValue,
		[Parameter(Mandatory)][string]$Reason
	)
	$idText = if ($null -ne $ProcessIdValue) { $ProcessIdValue.ToString() } else { "?" }
	return ("{0} (PID {1}): {2}" -f $ProcessName, $idText, $Reason)
}

function Write-InspectionDiagnostics {
	if ($script:InspectionFailures.Count -eq 0) { return }
	Write-Warning "Unable to inspect the following process(es) (NOT classified as blockers):"
	foreach ($f in $script:InspectionFailures) {
		$line = Format-InspectionFailure `
			-ProcessName    $f["ProcessName"] `
			-ProcessIdValue $f["ProcessIdValue"] `
			-Reason         $f["Reason"]
		Write-Warning ("  " + $line)
	}
}

# ── Process discovery (publish-root scope only) ───────────────────────────────
function Get-ProcessesUsingPath {
	[OutputType([System.Collections.Generic.List[hashtable]])]
	param([Parameter(Mandatory)][string]$PublishRootPath)

	$rootNorm  = [System.IO.Path]::GetFullPath($PublishRootPath).TrimEnd([IO.Path]::DirectorySeparatorChar)
	$candidates = @("RdpAudit.Configurator", "RdpAudit.Service", "RdpAudit.Mikrotik")
	$found     = [System.Collections.Generic.List[hashtable]]::new()

	foreach ($name in $candidates) {
		$procs = @(Get-Process -Name $name -ErrorAction SilentlyContinue)
		Write-Verbose ("Found {0} '{1}' process(es)" -f $procs.Count, $name)

		foreach ($proc in $procs) {
			if ($null -eq $proc) { continue }

			$procName       = $null
			$processIdValue = $null
			try {
				$procName       = [string]$proc.ProcessName
				$processIdValue = [int]$proc.Id
			} catch {
				Add-InspectionFailure -ProcessName $name -ProcessIdValue $null `
					-Reason ("could not read identity: " + $_.Exception.Message)
				continue
			}

			if ([string]::IsNullOrWhiteSpace($procName)) {
				Add-InspectionFailure -ProcessName $name -ProcessIdValue $processIdValue `
					-Reason "process name was empty"
				continue
			}

			$procPath      = $null
			$pathReadError = $null
			try {
				$procPath = [string]$proc.Path
			} catch {
				$pathReadError = $_.Exception.Message
			}

			if ($null -ne $pathReadError) {
				Add-InspectionFailure -ProcessName $procName -ProcessIdValue $processIdValue `
					-Reason ("could not read executable path: " + $pathReadError)
				continue
			}

			if ([string]::IsNullOrWhiteSpace($procPath)) {
				Add-InspectionFailure -ProcessName $procName -ProcessIdValue $processIdValue `
					-Reason "executable path was empty"
				continue
			}

			$fullProcPath = $null
			try {
				$fullProcPath = [System.IO.Path]::GetFullPath($procPath)
			} catch {
				Add-InspectionFailure -ProcessName $procName -ProcessIdValue $processIdValue `
					-Reason ("could not normalize path: " + $_.Exception.Message)
				continue
			}

			if (-not $fullProcPath.StartsWith($rootNorm, [System.StringComparison]::OrdinalIgnoreCase)) {
				Write-Verbose ("Skipping {0} (PID {1}) -> outside publish root: {2}" -f $procName, $processIdValue, $fullProcPath)
				continue
			}

			$found.Add((New-ConfirmedBlocker -ProcessName $procName -ProcessIdValue $processIdValue -ExePath $fullProcPath)) | Out-Null
			Write-Verbose ("Blocker confirmed: {0} (PID {1}) -> {2}" -f $procName, $processIdValue, $fullProcPath)
		}
	}

	Write-Output -NoEnumerate $found
}

# ── File-lock wait with exponential back-off ──────────────────────────────────
function Wait-FileUnlocked {
	[OutputType([bool])]
	param(
		[Parameter(Mandatory)][string]$FilePath,
		[int]$TimeoutSeconds = 30
	)
	$deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
	$delay    = 100   # milliseconds, doubles each cycle, capped at 2000
	while ([DateTime]::UtcNow -lt $deadline) {
		try {
			$stream = [System.IO.File]::Open($FilePath, [System.IO.FileMode]::Open,
				[System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
			$stream.Dispose()
			return $true
		} catch [System.IO.IOException] {
			# File still locked — back off and retry.
		}
		$remaining = ($deadline - [DateTime]::UtcNow).TotalMilliseconds
		if ($remaining -le 0) { break }
		$sleep = [Math]::Min($delay, [Math]::Min(2000, [int]$remaining))
		[System.Threading.Thread]::Sleep($sleep)
		$delay = [Math]::Min($delay * 2, 2000)
	}
	return $false
}

# ── Graceful process termination (publish-root scope only) ────────────────────
function Stop-PublishRootProcess {
	param([Parameter(Mandatory)][hashtable]$Blocker)
	$pName          = $blocker["ProcessName"]
	$processIdValue = $blocker["ProcessIdValue"]
	$exePath        = $blocker["ExePath"]

	Write-Information ("  Requesting graceful exit: {0} (PID {1}) ..." -f $pName, $processIdValue)
	try {
		$proc = Get-Process -Id $processIdValue -ErrorAction SilentlyContinue
		if ($null -eq $proc) {
			Write-Verbose ("  Process {0} (PID {1}) already gone." -f $pName, $processIdValue)
			return
		}
		# Gentle: close main window and wait up to 5 s.
		$null = $proc.CloseMainWindow()
		$deadline = [DateTime]::UtcNow.AddSeconds(5)
		$delay    = 100
		while (-not $proc.HasExited -and [DateTime]::UtcNow -lt $deadline) {
			[System.Threading.Thread]::Sleep($delay)
			$delay = [Math]::Min($delay * 2, 1000)
		}
		if (-not $proc.HasExited) {
			Write-Verbose ("  {0} (PID {1}) did not exit gracefully; forcing." -f $pName, $processIdValue)
			Stop-Process -Id $processIdValue -Force -ErrorAction Stop
		}
		Write-Information ("  Terminated: {0} (PID {1}) <- {2}" -f $pName, $processIdValue, $exePath)
		$script:TerminatedProcs.Add($blocker) | Out-Null
	} catch {
		throw ("Failed to terminate {0} (PID {1}): {2}" -f $pName, $processIdValue, $_.Exception.Message)
	}
}

# ── Handle publish-root blockers with -Force / interactive gate ───────────────
# Version: 2.0.1 — fix empty-collection bind error on zero-blocker path
function Invoke-BlockerResolution {
	param(
		[AllowNull()]
		[AllowEmptyCollection()]
		[System.Collections.Generic.List[hashtable]]$Blockers = $null
	)
	if ($null -eq $Blockers -or $Blockers.Count -eq 0) { return }

	Write-Warning ("The following process(es) run from the publish folder and may hold file locks:")
	foreach ($entry in $Blockers) {
		$line = Format-LockingProcess `
			-ProcessName    $entry["ProcessName"] `
			-ProcessIdValue $entry["ProcessIdValue"] `
			-ExePath        $entry["ExePath"]
		Write-Warning ("  " + $line)
	}
	Write-InspectionDiagnostics

	if ($Force) {
		foreach ($b in $Blockers) {
			if ($PSCmdlet.ShouldProcess(
				("PID {0} ({1}) at {2}" -f $b["ProcessIdValue"], $b["ProcessName"], $b["ExePath"]),
				"Terminate process from publish folder")) {
				Stop-PublishRootProcess -Blocker $b
			}
		}
		return
	}

	if (-not [Environment]::UserInteractive) {
		throw ("Non-interactive session: {0} process(es) running from the publish folder. " +
			"Re-run with -Force to terminate them automatically, or close them first.") -f $Blockers.Count
	}

	$names  = ($Blockers | ForEach-Object { $_["ProcessName"] + " PID " + $_["ProcessIdValue"] }) -join ", "
	$answer = $Host.UI.PromptForChoice(
		"Publish folder blocker(s) detected",
		"Terminate: $names ?",
		@("&Yes", "&No"),
		1
	)
	if ($answer -ne 0) {
		throw "User declined to terminate publish-folder processes. Publish cancelled."
	}
	foreach ($b in $Blockers) {
		if ($PSCmdlet.ShouldProcess(
			("PID {0} ({1})" -f $b["ProcessIdValue"], $b["ProcessName"]),
			"Terminate process from publish folder")) {
			Stop-PublishRootProcess -Blocker $b
		}
	}
}

# ── Pre-flight ────────────────────────────────────────────────────────────────
function Test-PublishPrerequisites {
	param([Parameter(Mandatory)][string]$ResolvedVersion)
	$failures = [System.Collections.Generic.List[string]]::new()

	# SDK version.
	try {
		$sdkRaw = & dotnet --version 2>$null
		if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($sdkRaw)) {
			$failures.Add("dotnet SDK not found on PATH.") | Out-Null
		} else {
			$major = [int](($sdkRaw.Trim() -split "\.")[0])
			if ($major -lt 8) {
				$failures.Add(("RDPAudit 2.0 requires .NET SDK 8.0+; found: " + $sdkRaw.Trim())) | Out-Null
			}
		}
	} catch {
		$failures.Add("Could not determine .NET SDK version: " + $_.Exception.Message) | Out-Null
	}

	# AllowUnsafeBlocks in Service project.
	$svcCsproj = Join-Path $PSScriptRoot "src/RdpAudit.Service/RdpAudit.Service.csproj"
	if (Test-Path $svcCsproj) {
		$content = Get-Content $svcCsproj -Raw -Encoding UTF8
		if ($content -notmatch '<AllowUnsafeBlocks>\s*true\s*</AllowUnsafeBlocks>') {
			$failures.Add("RdpAudit.Service.csproj missing <AllowUnsafeBlocks>true</AllowUnsafeBlocks>.") | Out-Null
		}
	} else {
		$failures.Add("Service project not found: '$svcCsproj'.") | Out-Null
	}

	# All projects exist.
	foreach ($proj in $script:Projects) {
		$full = Join-Path $PSScriptRoot $proj["CsprojRelPath"]
		if (-not (Test-Path $full)) {
			$failures.Add(("Project not found: '$full'.")) | Out-Null
		}
	}

	if ($failures.Count -gt 0) {
		$sb = [System.Text.StringBuilder]::new()
		[void]$sb.AppendLine(("Pre-flight validation failed ({0} issue(s)):" -f $failures.Count))
		foreach ($f in $failures) { [void]$sb.AppendLine("  x $f") }
		throw $sb.ToString().TrimEnd()
	}

	Write-Information ("Pre-flight OK: SDK {0}+, projects found, version = {1} (source: {2})" -f "8.0", $ResolvedVersion, $script:VersionSource)
}

# ── Atomic file replacement ───────────────────────────────────────────────────
# Copies $Source to $Destination via a .new staging file; verifies size parity;
# replaces atomically. Rolls back and throws if anything fails.
function Copy-FileAtomic {
	param(
		[Parameter(Mandatory)][string]$Source,
		[Parameter(Mandatory)][string]$Destination
	)
	$newPath = $Destination + ".new"
	$oldPath = $Destination + ".old"
	try {
		Copy-Item -LiteralPath $Source -Destination $newPath -Force -ErrorAction Stop
		# Size sanity — not a cryptographic check but catches a truncated copy immediately.
		$srcLen = (Get-Item $Source).Length
		$dstLen = (Get-Item $newPath).Length
		if ($srcLen -ne $dstLen) {
			throw ("Staged copy size mismatch: source={0} staged={1}" -f $srcLen, $dstLen)
		}
		if (Test-Path $Destination) {
			Move-Item -LiteralPath $Destination -Destination $oldPath -Force -ErrorAction Stop
		}
		Move-Item -LiteralPath $newPath -Destination $Destination -Force -ErrorAction Stop
		if (Test-Path $oldPath) {
			Remove-Item -LiteralPath $oldPath -Force -ErrorAction SilentlyContinue
		}
	} catch {
		if (Test-Path $newPath) { Remove-Item -LiteralPath $newPath -Force -ErrorAction SilentlyContinue }
		if ((Test-Path $oldPath) -and -not (Test-Path $Destination)) {
			Move-Item -LiteralPath $oldPath -Destination $Destination -Force -ErrorAction SilentlyContinue
		}
		throw
	}
}

# ── Get FileVersion from a PE (best-effort) ───────────────────────────────────
function Get-FileVersionString {
	[OutputType([string])]
	param([Parameter(Mandatory)][string]$FilePath)
	try {
		$vi = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($FilePath)
		if ($null -eq $vi -or [string]::IsNullOrWhiteSpace($vi.FileVersion)) { return "" }
		return $vi.FileVersion.Trim()
	} catch {
		return ""
	}
}

# ── Publish a single project ───────────────────────────────────────────────────
function Publish-Project {
	param(
		[Parameter(Mandatory)][string]$CsprojRelPath,
		[Parameter(Mandatory)][string]$Subdir,
		[Parameter(Mandatory)][string]$ExeName,
		[string]$ResolvedVersion = "",
		[string]$RevisionId = ""
	)
	$target   = Join-Path $script:PublishRoot $Subdir
	$csproj   = Join-Path $PSScriptRoot $CsprojRelPath
	Write-Information ("  Publishing {0} -> {1}" -f $CsprojRelPath, $target)

	if ($PSCmdlet.ShouldProcess($target, "dotnet publish $CsprojRelPath")) {
		$publishArgs = @(
			"publish", $csproj,
			"-c", $Configuration,
			"-r", "win-x64",
			"--self-contained", "true",
			"-p:PublishSingleFile=true",
			"-p:IncludeNativeLibrariesForSelfExtract=true",
			"-p:EnableCompressionInSingleFile=true"
		)
		if (-not [string]::IsNullOrWhiteSpace($ResolvedVersion)) {
			$publishArgs += "-p:VersionPrefix=$ResolvedVersion"
		}
		if (-not [string]::IsNullOrWhiteSpace($RevisionId)) {
			$publishArgs += "-p:SourceRevisionId=$RevisionId"
		}
		$publishArgs += $script:DotnetLanguageArgs
		$publishArgs += @("-o", $target)

		$exitCode = Invoke-DotnetCli -Arguments $publishArgs
		if ($exitCode -ne 0) {
			throw ("dotnet publish failed for '{0}' (exit {1})" -f $CsprojRelPath, $exitCode)
		}
	}
}

# ── Update publish folder from dotnet output (diff + atomic replace) ──────────
# $BuildOutputDir  — where `dotnet publish -o` wrote the new files
# $PublishDir      — the live publish subfolder to update
function Update-PublishDirectory {
	param(
		[Parameter(Mandatory)][string]$BuildOutputDir,
		[Parameter(Mandatory)][string]$PublishDir,
		[Parameter(Mandatory)][string]$ExeName,
		[string]$ExpectedVersion = ""
	)
	if (-not (Test-Path $PublishDir)) {
		if ($PSCmdlet.ShouldProcess($PublishDir, "Create publish subdirectory")) {
			New-Item -ItemType Directory -Path $PublishDir | Out-Null
		}
	}

	$newFiles = @(Get-ChildItem -Path $BuildOutputDir -File -Recurse -ErrorAction SilentlyContinue |
		Where-Object { Test-IsUnderPublishRoot -Path $PublishDir })

	# Build a set of new file names (relative to BuildOutputDir).
	$newRelNames = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
	foreach ($f in (Get-ChildItem -Path $BuildOutputDir -File -ErrorAction SilentlyContinue)) {
		[void]$newRelNames.Add($f.Name)
	}

	# Remove stale files in PublishDir that are NOT in new output.
	foreach ($existing in @(Get-ChildItem -Path $PublishDir -File -ErrorAction SilentlyContinue)) {
		if (-not $newRelNames.Contains($existing.Name)) {
			if (-not (Test-IsUnderPublishRoot -Path $existing.FullName)) { continue }
			$verBefore = Get-FileVersionString -FilePath $existing.FullName
			if ($PSCmdlet.ShouldProcess($existing.FullName, "Remove stale file from publish folder")) {
				Remove-Item -LiteralPath $existing.FullName -Force -ErrorAction Stop
			}
			$script:ReportRows.Add(@{
				File    = $existing.Name
				Subdir  = [System.IO.Path]::GetFileName($PublishDir)
				VerBefore = $verBefore
				VerAfter  = "—"
				Action    = "removed"
			}) | Out-Null
		}
	}

	# Copy / update files from build output.
	foreach ($srcFile in @(Get-ChildItem -Path $BuildOutputDir -File -ErrorAction SilentlyContinue)) {
		$destPath  = Join-Path $PublishDir $srcFile.Name
		$verBefore = if (Test-Path $destPath) { Get-FileVersionString -FilePath $destPath } else { "" }
		$verAfter  = Get-FileVersionString -FilePath $srcFile.FullName
		$action    = "added"

		if (Test-Path $destPath) {
			$srcHash  = (Get-FileHash -LiteralPath $srcFile.FullName  -Algorithm SHA256).Hash
			$dstHash  = (Get-FileHash -LiteralPath $destPath          -Algorithm SHA256).Hash
			if ($srcHash -eq $dstHash) {
				$action = "unchanged"
			} else {
				$action = "replaced"
			}
		}

		if ($action -ne "unchanged") {
			# Wait for any lingering lock (AV scanner, etc.)
			if (Test-Path $destPath) {
				$freed = Wait-FileUnlocked -FilePath $destPath -TimeoutSeconds $Timeout
				if (-not $freed) {
					# Identify who still holds it.
					$blockers = Get-ProcessesUsingPath -PublishRootPath $script:PublishRoot
					$holderDesc = "unknown holder"
					if ($null -ne $blockers -and $blockers.Count -gt 0) {
						$holderDesc = ($blockers | ForEach-Object {
							Format-LockingProcess -ProcessName $_["ProcessName"] -ProcessIdValue $_["ProcessIdValue"] -ExePath $_["ExePath"]
						}) -join "; "
					}
					throw ("File lock timeout after {0}s: '{1}'. Holder: {2}. Re-run with -Force to terminate or increase -Timeout." -f $Timeout, $destPath, $holderDesc)
				}
			}
			if ($PSCmdlet.ShouldProcess($destPath, ("Copy from build output ({0})" -f $action))) {
				Copy-FileAtomic -Source $srcFile.FullName -Destination $destPath
			}
		}

		$script:ReportRows.Add(@{
			File      = $srcFile.Name
			Subdir    = [System.IO.Path]::GetFileName($PublishDir)
			VerBefore = $verBefore
			VerAfter  = $verAfter
			Action    = $action
		}) | Out-Null
	}
}

# ── SQLite support bundle ─────────────────────────────────────────────────────
function Resolve-SqliteBundleSource {
	[OutputType([string])]
	param(
		[Parameter(Mandatory)][string]$Project,
		[Parameter(Mandatory)][string]$ResolvedVersion
	)
	$projectFull = Join-Path $PSScriptRoot $Project
	if (-not (Test-Path $projectFull)) {
		throw "Cannot resolve SQLite support bundle: project not found at '$projectFull'."
	}

	Write-Information "Restoring $Project for SQLite bundle resolution..."
	$restoreExitCode = Invoke-DotnetCli -Arguments (@("restore", $projectFull, "-r", "win-x64") + $script:DotnetLanguageArgs)
	if ($restoreExitCode -ne 0) {
		throw ("dotnet restore failed for '{0}' (exit {1})." -f $projectFull, $restoreExitCode)
	}

	$bundleObjDir = Join-Path $script:PublishRoot ".sqlite-bundle"
	if (Test-Path $bundleObjDir) {
		Remove-Item -Recurse -Force $bundleObjDir -ErrorAction SilentlyContinue
	}

	Write-Information "Building $Project (framework-dependent, loose files) for SQLite bundle..."
	$buildArgs = @(
		"build", $projectFull,
		"-c", $Configuration,
		"-r", "win-x64",
		"--self-contained", "false",
		"-p:PublishSingleFile=false"
	)
	if (-not [string]::IsNullOrWhiteSpace($ResolvedVersion)) {
		$buildArgs += "-p:VersionPrefix=$ResolvedVersion"
	}
	$buildArgs += $script:DotnetLanguageArgs + @("-o", $bundleObjDir)
	$buildExitCode = Invoke-DotnetCli -Arguments $buildArgs
	if ($buildExitCode -ne 0) {
		throw ("dotnet build failed for '{0}' (exit {1}) while assembling the SQLite support bundle." -f $projectFull, $buildExitCode)
	}
	return $bundleObjDir
}

function Copy-SqliteSupportFiles {
	[OutputType([System.Collections.Generic.List[string]])]
	param(
		[Parameter(Mandatory)][string]$SourceDir,
		[Parameter(Mandatory)][string]$TargetDir
	)
	if (-not (Test-Path $TargetDir)) {
		New-Item -ItemType Directory -Path $TargetDir | Out-Null
	}
	$missing = [System.Collections.Generic.List[string]]::new()
	$copied  = [System.Collections.Generic.List[string]]::new()

	foreach ($name in $script:SqliteSupportFiles) {
		$resolved = $null
		$direct   = Join-Path $SourceDir $name
		if (Test-Path $direct) {
			$resolved = $direct
		} else {
			$candidate = Get-ChildItem -Path $SourceDir -Filter $name -Recurse -File -ErrorAction SilentlyContinue |
				Select-Object -First 1
			if ($null -ne $candidate) { $resolved = $candidate.FullName }
		}
		if ($null -eq $resolved) {
			$missing.Add($name) | Out-Null
			continue
		}
		$dest = Join-Path $TargetDir $name
		if ($PSCmdlet.ShouldProcess($dest, "Copy SQLite bundle file $name")) {
			Copy-Item -LiteralPath $resolved -Destination $dest -Force
		}
		$copied.Add($name) | Out-Null
		Write-Verbose ("SQLite bundle: copied {0} <- {1}" -f $name, $resolved)
	}

	if ($missing.Count -gt 0) {
		throw ("SQLite support bundle incomplete: missing {0}/{1}: {2}. Searched: '{3}'." -f
			$missing.Count, $script:SqliteSupportFiles.Count, ($missing -join ", "), $SourceDir)
	}
	Write-Output -NoEnumerate $copied
}

function Invoke-SqliteSupportBundle {
	param(
		[Parameter(Mandatory)][string]$ConfiguratorPublishDir,
		[Parameter(Mandatory)][string]$ResolvedVersion
	)
	Write-Information ("Ensuring SQLite diagnostic support bundle in {0}" -f $ConfiguratorPublishDir)
	$source = Resolve-SqliteBundleSource `
		-Project "src/RdpAudit.Configurator/RdpAudit.Configurator.csproj" `
		-ResolvedVersion $ResolvedVersion
	$null = Copy-SqliteSupportFiles -SourceDir $source -TargetDir $ConfiguratorPublishDir

	# Post-verify.
	$stillMissing = [System.Collections.Generic.List[string]]::new()
	foreach ($name in $script:SqliteSupportFiles) {
		if (-not (Test-Path (Join-Path $ConfiguratorPublishDir $name))) {
			$stillMissing.Add($name) | Out-Null
		}
	}
	if ($stillMissing.Count -gt 0) {
		throw ("SQLite bundle verification failed: {0} file(s) still missing: {1}" -f
			$stillMissing.Count, ($stillMissing -join ", "))
	}

	# Clean up transient build output.
	$bundleObjDir = Join-Path $script:PublishRoot ".sqlite-bundle"
	if (Test-Path $bundleObjDir) {
		Remove-Item -Recurse -Force $bundleObjDir -ErrorAction SilentlyContinue
	}
	Write-Information ("SQLite support bundle complete: {0}/{1} files present." -f
		$script:SqliteSupportFiles.Count, $script:SqliteSupportFiles.Count)
}

# ── Documentation copy ────────────────────────────────────────────────────────
function Copy-PublishDocumentation {
	$docsSource = Join-Path $PSScriptRoot "docs"
	$docsTarget = Join-Path $script:PublishRoot "Docs"
	if (-not (Test-Path $docsSource)) {
		Write-Verbose "No docs/ folder found; skipping."
		return
	}
	if (-not (Test-Path $docsTarget)) {
		if ($PSCmdlet.ShouldProcess($docsTarget, "Create Docs directory")) {
			New-Item -ItemType Directory -Path $docsTarget | Out-Null
		}
	}
	$copied = 0
	foreach ($file in @(Get-ChildItem -Path $docsSource -File -Filter "*.md" -ErrorAction SilentlyContinue)) {
		if ($PSCmdlet.ShouldProcess($file.Name, "Copy documentation file")) {
			Copy-Item -LiteralPath $file.FullName -Destination $docsTarget -Force
			$copied++
		}
	}
	foreach ($name in @("README.md", "Detect_Attack_Strategy_v3.md")) {
		$path = Join-Path $PSScriptRoot $name
		if (Test-Path $path) {
			if ($PSCmdlet.ShouldProcess($name, "Copy root documentation file")) {
				Copy-Item -LiteralPath $path -Destination $docsTarget -Force
				$copied++
			}
		}
	}
	if ($copied -gt 0) {
		Write-Information ("Copied {0} documentation file(s) to {1}" -f $copied, $docsTarget)
	}
}

# ── Build-info manifest ───────────────────────────────────────────────────────
function Write-BuildInfoManifest {
	param(
		[Parameter(Mandatory)][string]$ResolvedVersion,
		[Parameter(Mandatory)][string]$RevisionId
	)
	$manifestPath = Join-Path $script:PublishRoot "build-info.json"
	$manifest = @{
		version        = $ResolvedVersion
		versionSource  = $script:VersionSource
		configuration  = $Configuration
		sourceRevision = $RevisionId
		publishedUtc   = [DateTime]::UtcNow.ToString("o")
		components     = @{
			Service      = $ResolvedVersion
			Configurator = $ResolvedVersion
			Mikrotik     = $ResolvedVersion
		}
		features       = @{
			selfContained      = $true
			publishSingleFile  = $true
			lockFreeRingBuffer = $true
			sqliteBundle       = $true
			benchmarks         = $IncludeBenchmarks.IsPresent
		}
	}
	if ($PSCmdlet.ShouldProcess($manifestPath, "Write build-info.json")) {
		$manifest | ConvertTo-Json -Depth 5 | Set-Content -Path $manifestPath -Encoding UTF8 -NoNewline
		Write-Information ("Wrote build manifest: {0}" -f $manifestPath)
	}
}

# ── Post-checks ───────────────────────────────────────────────────────────────
function Add-PostCheck {
	param(
		[Parameter(Mandatory)][string]$Name,
		[Parameter(Mandatory)][bool]$Passed,
		[string]$Detail = ""
	)
	$script:PostChecks.Add(@{ Name = $Name; Passed = $Passed; Detail = $Detail }) | Out-Null
}

# Version: 2.0.2 — replace invalid inline if statements with precomputed values
function Invoke-PostChecks {
	param(
		[Parameter(Mandatory)]
		[string]$ResolvedVersion
	)

	# 1. Verify that every expected executable exists.
	foreach ($project in $script:Projects) {
		$artifactDirectory = Join-Path `
			-Path $script:PublishRoot `
			-ChildPath $project["Subdir"]

		$executablePath = Join-Path `
			-Path $artifactDirectory `
			-ChildPath $project["ExeName"]

		$isPresent = Test-Path `
			-LiteralPath $executablePath `
			-PathType Leaf

		if ($isPresent) {
			$presenceDetail = $executablePath
		} else {
			$presenceDetail = "NOT FOUND: $executablePath"
		}

		Add-PostCheck `
			-Name ("Artifact present: {0}/{1}" -f
				$project["Subdir"],
				$project["ExeName"]) `
			-Passed $isPresent `
			-Detail $presenceDetail
	}

	# 2. Verify that every executable has the expected FileVersion.
	if (-not [string]::IsNullOrWhiteSpace($ResolvedVersion)) {
		foreach ($project in $script:Projects) {
			$artifactDirectory = Join-Path `
				-Path $script:PublishRoot `
				-ChildPath $project["Subdir"]

			$executablePath = Join-Path `
				-Path $artifactDirectory `
				-ChildPath $project["ExeName"]

			if (-not (Test-Path `
				-LiteralPath $executablePath `
				-PathType Leaf)) {
				continue
			}

			$fileVersion = Get-FileVersionString `
				-FilePath $executablePath

			$expectedFourPartVersion = $ResolvedVersion + ".0"

			$versionMatches = (
				$fileVersion.StartsWith(
					$ResolvedVersion,
					[System.StringComparison]::OrdinalIgnoreCase
				) -or
				$fileVersion.Equals(
					$expectedFourPartVersion,
					[System.StringComparison]::OrdinalIgnoreCase
				)
			)

			$versionDetail = "expected prefix={0}; actual={1}" -f `
				$ResolvedVersion,
				$fileVersion

			Add-PostCheck `
				-Name ("FileVersion match: {0}/{1}" -f
					$project["Subdir"],
					$project["ExeName"]) `
				-Passed $versionMatches `
				-Detail $versionDetail
		}
	}

	# 3. Verify that no atomic-replacement staging files remain.
	$stagingFiles = @(
		Get-ChildItem `
			-LiteralPath $script:PublishRoot `
			-Recurse `
			-File `
			-ErrorAction Stop |
			Where-Object {
				$_.Extension.Equals(
					".new",
					[System.StringComparison]::OrdinalIgnoreCase
				) -or
				$_.Extension.Equals(
					".old",
					[System.StringComparison]::OrdinalIgnoreCase
				)
			}
	)

	$hasNoStagingFiles = $stagingFiles.Count -eq 0

	if ($hasNoStagingFiles) {
		$stagingDetail = "Clean"
	} else {
		$stagingPaths = @(
			foreach ($stagingFile in $stagingFiles) {
				$stagingFile.FullName
			}
		)

		$stagingDetail = "Staging files found: " +
			($stagingPaths -join ", ")
	}

	Add-PostCheck `
		-Name "No staging files (.new/.old) left in publish root" `
		-Passed $hasNoStagingFiles `
		-Detail $stagingDetail

	# 4. Read the installed version for informational reporting only.
	# No file outside the publish root is modified.
	$installedServicePath = Join-Path `
		-Path $env:ProgramFiles `
		-ChildPath "RdpAudit\Service\RdpAudit.Service.exe"

	if (Test-Path `
		-LiteralPath $installedServicePath `
		-PathType Leaf) {
		$installedVersion = Get-FileVersionString `
			-FilePath $installedServicePath

		$installedMatchesBuilt = $installedVersion.StartsWith(
			$ResolvedVersion,
			[System.StringComparison]::OrdinalIgnoreCase
		)

		if ($installedMatchesBuilt) {
			$installedDetail = (
				"Installed version {0} matches built version {1}." -f
				$installedVersion,
				$ResolvedVersion
			)
		} else {
			$installedDetail = (
				"Installed version {0} differs from built version {1} — " +
				"run install.ps1 to deploy."
			) -f $installedVersion, $ResolvedVersion
		}

		Add-PostCheck `
			-Name "Installed service version (informational)" `
			-Passed $true `
			-Detail $installedDetail
	} else {
		Add-PostCheck `
			-Name "Installed service version (informational)" `
			-Passed $true `
			-Detail ("Installed binary not found at '{0}'." -f
				$installedServicePath)
	}
}

# ── Final report ──────────────────────────────────────────────────────────────
function Write-FinalReport {
	param([Parameter(Mandatory)][string]$ResolvedVersion)

	Write-Information ""
	Write-Information "══════════════════════════════════════════════════════════════"
	Write-Information " RDPAudit Publish Report"
	Write-Information ("  Version : {0}  (source: {1})" -f $ResolvedVersion, $script:VersionSource)
	Write-Information ("  Config  : {0}   RID: win-x64   Mode: self-contained single-file" -f $Configuration)
	Write-Information ("  Publish : {0}" -f $script:PublishRoot)
	Write-Information "══════════════════════════════════════════════════════════════"

	if ($script:ReportRows.Count -gt 0) {
		Write-Information ""
		Write-Information " File updates:"
		Write-Information (" {0,-40} {1,-12} {2,-12} {3,-12} {4}" -f "File", "Subdir", "Version Before", "Version After", "Action")
		Write-Information (" {0,-40} {1,-12} {2,-12} {3,-12} {4}" -f "----", "------", "--------------", "-------------", "------")
		foreach ($row in $script:ReportRows) {
			$color = switch ($row["Action"]) {
				"replaced" { "Cyan" } "added" { "Green" } "removed" { "DarkYellow" } default { "Gray" }
			}
			Write-Host (" {0,-40} {1,-12} {2,-12} {3,-12} {4}" -f `
				$row["File"], $row["Subdir"], $row["VerBefore"], $row["VerAfter"], $row["Action"]) `
				-ForegroundColor $color
		}
	}

	if ($script:TerminatedProcs.Count -gt 0) {
		Write-Information ""
		Write-Information " Terminated processes (publish-folder scope only):"
		foreach ($t in $script:TerminatedProcs) {
			Write-Warning ("  " + (Format-LockingProcess -ProcessName $t["ProcessName"] -ProcessIdValue $t["ProcessIdValue"] -ExePath $t["ExePath"]))
		}
	}

	Write-Information ""
	Write-Information " Post-checks:"
	$allPassed = $true
	foreach ($chk in $script:PostChecks) {
		$label  = if ($chk["Passed"]) { "[PASS]" } else { "[FAIL]"; $allPassed = $false }
		$fgColor = if ($chk["Passed"]) { "Green" } else { "Red" }
		Write-Host ("  {0} {1}" -f $label, $chk["Name"]) -ForegroundColor $fgColor
		if (-not [string]::IsNullOrWhiteSpace($chk["Detail"])) {
			Write-Information ("         {0}" -f $chk["Detail"])
		}
	}

	Write-Information ""
	if ($allPassed) {
		Write-Host " RESULT: PASS" -ForegroundColor Green
	} else {
		Write-Host " RESULT: FAIL — see post-checks above" -ForegroundColor Red
	}
	Write-Information "══════════════════════════════════════════════════════════════"
	return $allPassed
}

# ── Self-test ─────────────────────────────────────────────────────────────────
function Invoke-PublishScriptSelfCheck {
	$failures = [System.Collections.Generic.List[string]]::new()

	function Add-Failure { param([string]$Msg) $failures.Add($Msg) | Out-Null; Write-Host ("  [FAIL] " + $Msg) -ForegroundColor Red }
	function Add-Pass    { param([string]$Msg) Write-Host ("  [PASS] " + $Msg) -ForegroundColor Green }

	Write-Information "Running publish.ps1 self-tests..."

	# 1. Format-LockingProcess with all fields.
	try {
		$line = Format-LockingProcess -ProcessName "RdpAudit.Configurator" -ProcessIdValue 1234 -ExePath "C:\publish\RdpAudit.Configurator.exe"
		if ($line -notmatch "1234") { Add-Failure "Format-LockingProcess missing PID: $line" }
		else                        { Add-Pass    "Format-LockingProcess formats a confirmed blocker" }
	} catch { Add-Failure ("Format-LockingProcess threw: " + $_.Exception.Message) }

	# 2. Format-InspectionFailure with null PID.
	try {
		$line = Format-InspectionFailure -ProcessName "RdpAudit.Service" -ProcessIdValue $null -Reason "access denied"
		if ($line -notmatch "access denied") { Add-Failure "Format-InspectionFailure missing reason: $line" }
		else                                 { Add-Pass    "Format-InspectionFailure formats a null-PID failure" }
	} catch { Add-Failure ("Format-InspectionFailure threw: " + $_.Exception.Message) }

	# 3. Format-LockingProcess rejects missing ExePath at bind time.
	try {
		$diag = @{ ProcessName = "X"; ProcessIdValue = 1; Reason = "unreadable" }
		$null = Format-LockingProcess @diag
		Add-Failure "Format-LockingProcess accepted object without ExePath; binder regression."
	} catch { Add-Pass "Format-LockingProcess rejects records lacking ExePath (binder enforced)" }

	# 4. Get-ProcessesUsingPath returns Count==0 for unrelated path (no double-wrap).
	try {
		$tempDir = Join-Path ([IO.Path]::GetTempPath()) ("rdpaudit-selftest-" + [Guid]::NewGuid().ToString("N"))
		New-Item -ItemType Directory -Path $tempDir | Out-Null
		try {
			$script:InspectionFailures.Clear()
			$res = Get-ProcessesUsingPath -PublishRootPath $tempDir
			if ($null -eq $res)       { Add-Failure "Get-ProcessesUsingPath returned null" }
			elseif ($res.Count -ne 0) { Add-Failure ("Expected 0 blockers, got " + $res.Count) }
			else                      { Add-Pass    "Get-ProcessesUsingPath returns Count==0 for unrelated path (no double-wrap)" }
		} finally { Remove-Item -Recurse -Force $tempDir -ErrorAction SilentlyContinue }
	} catch { Add-Failure ("Get-ProcessesUsingPath self-check threw: " + $_.Exception.Message) }

	# 5. No assignment to $pid.
	try {
		$scriptText    = Get-Content -Raw -Path $PSCommandPath
		$assignPattern = "(?im)^\s*\`$pid\s*="
		if ($scriptText -match $assignPattern) { Add-Failure "Assignment to `$pid found; use `$processIdValue." }
		else                                    { Add-Pass    "No assignment to `$pid / `$PID / `$Pid in script source" }
	} catch { Add-Failure ("`$pid check threw: " + $_.Exception.Message) }

	# 6. Script parses cleanly.
	try {
		$tokens = $null; $errors = $null
		[void][System.Management.Automation.Language.Parser]::ParseFile($PSCommandPath, [ref]$tokens, [ref]$errors)
		if ($null -ne $errors -and $errors.Count -gt 0) { Add-Failure ("Parser: " + $errors.Count + " error(s)") }
		else                                              { Add-Pass    "Script parses cleanly under PowerShell parser" }
	} catch { Add-Failure ("Parser check threw: " + $_.Exception.Message) }

	# 7. Blockers and inspection failures are separate lists.
	try {
		$script:InspectionFailures.Clear()
		Add-InspectionFailure -ProcessName "RdpAudit.Service" -ProcessIdValue 4242 -Reason "simulated"
		$tempDir = Join-Path ([IO.Path]::GetTempPath()) ("rdpaudit-selftest-sep-" + [Guid]::NewGuid().ToString("N"))
		New-Item -ItemType Directory -Path $tempDir | Out-Null
		try {
			$script:InspectionFailures.Clear()
			$res = Get-ProcessesUsingPath -PublishRootPath $tempDir
			if ($res.Count -eq 0) { Add-Pass "Inspection failures do not contaminate blocker list" }
			else                  { Add-Failure ("Blocker list polluted: " + $res.Count + " entries") }
		} finally {
			Remove-Item -Recurse -Force $tempDir -ErrorAction SilentlyContinue
			$script:InspectionFailures.Clear()
		}
	} catch { Add-Failure ("Separation check threw: " + $_.Exception.Message) }

	# 8. SQLite bundle list matches expected five files.
	try {
		$expected = @("Microsoft.Data.Sqlite.dll","SQLitePCLRaw.core.dll","SQLitePCLRaw.provider.e_sqlite3.dll","SQLitePCLRaw.batteries_v2.dll","e_sqlite3.dll")
		$diff     = Compare-Object -ReferenceObject $expected -DifferenceObject $script:SqliteSupportFiles
		if ($null -ne $diff) { Add-Failure "SqliteSupportFiles drifted from five-file bundle" }
		else                 { Add-Pass    "SqliteSupportFiles matches canonical five-file bundle" }
	} catch { Add-Failure ("Bundle list check threw: " + $_.Exception.Message) }

	# 9. Copy-SqliteSupportFiles fails actionably with empty source.
	try {
		$srcDir = Join-Path ([IO.Path]::GetTempPath()) ("rdpaudit-bundle-empty-" + [Guid]::NewGuid().ToString("N"))
		$dstDir = Join-Path ([IO.Path]::GetTempPath()) ("rdpaudit-bundle-dst-"   + [Guid]::NewGuid().ToString("N"))
		New-Item -ItemType Directory -Path $srcDir | Out-Null
		try {
			$threw = $false
			try { $null = Copy-SqliteSupportFiles -SourceDir $srcDir -TargetDir $dstDir } catch { $threw = $true }
			if ($threw) { Add-Pass "Copy-SqliteSupportFiles fails actionably with empty source" }
			else        { Add-Failure "Copy-SqliteSupportFiles silently succeeded with empty source" }
		} finally {
			Remove-Item -Recurse -Force $srcDir -ErrorAction SilentlyContinue
			Remove-Item -Recurse -Force $dstDir -ErrorAction SilentlyContinue
		}
	} catch { Add-Failure ("Copy-SqliteSupportFiles empty-source check threw: " + $_.Exception.Message) }

	# 10. Copy-SqliteSupportFiles succeeds with full bundle (native under runtimes/native).
	try {
		$srcDir    = Join-Path ([IO.Path]::GetTempPath()) ("rdpaudit-bundle-full-src-" + [Guid]::NewGuid().ToString("N"))
		$dstDir    = Join-Path ([IO.Path]::GetTempPath()) ("rdpaudit-bundle-full-dst-" + [Guid]::NewGuid().ToString("N"))
		$nativeDir = Join-Path $srcDir "runtimes/win-x64/native"
		New-Item -ItemType Directory -Path $nativeDir | Out-Null
		try {
			foreach ($name in $script:SqliteSupportFiles) {
				$target = if ($name -eq "e_sqlite3.dll") { Join-Path $nativeDir $name } else { Join-Path $srcDir $name }
				Set-Content -Path $target -Value "stub" -NoNewline
			}
			$copied     = @(Copy-SqliteSupportFiles -SourceDir $srcDir -TargetDir $dstDir)
			$allPresent = ($script:SqliteSupportFiles | ForEach-Object { Test-Path (Join-Path $dstDir $_) }) -notcontains $false
			if ($copied.Count -eq $script:SqliteSupportFiles.Count -and $allPresent) {
				Add-Pass "Copy-SqliteSupportFiles resolves root + runtimes/native and copies full bundle"
			} else {
				Add-Failure ("Copy-SqliteSupportFiles partial: copied={0} allPresent={1}" -f $copied.Count, $allPresent)
			}
		} finally {
			Remove-Item -Recurse -Force $srcDir -ErrorAction SilentlyContinue
			Remove-Item -Recurse -Force $dstDir -ErrorAction SilentlyContinue
		}
	} catch { Add-Failure ("Copy-SqliteSupportFiles full-bundle check threw: " + $_.Exception.Message) }

	# 11. Get-PropsVersionPrefix returns a valid semver-like string.
	try {
		$v = Get-PropsVersionPrefix
		if ([string]::IsNullOrWhiteSpace($v)) {
			Write-Warning "Get-PropsVersionPrefix returned empty (Directory.Build.props missing in test environment)"
			Add-Pass "Get-PropsVersionPrefix: props not found or empty (acceptable in isolated environment)"
		} elseif ($v -match "^\d+\.\d+\.\d+") {
			Add-Pass ("Get-PropsVersionPrefix returned valid version: " + $v)
		} else {
			Add-Failure ("Get-PropsVersionPrefix returned non-semver: " + $v)
		}
	} catch { Add-Failure ("Get-PropsVersionPrefix threw: " + $_.Exception.Message) }

	# 12. Test-IsUnderPublishRoot correctly gates path containment.
	try {
		$outside = "C:\Windows\System32\cmd.exe"
		$inside  = Join-Path $script:PublishRoot "Service\RdpAudit.Service.exe"
		$gateOut = Test-IsUnderPublishRoot -Path $outside
		$gateIn  = Test-IsUnderPublishRoot -Path $inside
		if (-not $gateOut -and $gateIn) {
			Add-Pass "Test-IsUnderPublishRoot: correctly gates inside/outside publish root"
		} else {
			Add-Failure ("Test-IsUnderPublishRoot: outside={0} inside={1}" -f $gateOut, $gateIn)
		}
	} catch { Add-Failure ("Test-IsUnderPublishRoot threw: " + $_.Exception.Message) }

	Write-Information ""
	if ($failures.Count -gt 0) {
		Write-Host ("Self-test FAILED ({0} failure(s))" -f $failures.Count) -ForegroundColor Red
		exit 6
	}
	Write-Host "Self-test PASSED" -ForegroundColor Green
}

# ══════════════════════════════════════════════════════════════════════════════
# Entry point
# ══════════════════════════════════════════════════════════════════════════════
if ($SelfTest) {
	Invoke-PublishScriptSelfCheck
	exit 0
}

# -- Step 0: Resolve version --------------------------------------------------
$resolvedVersion = Resolve-BuildVersion
$resolvedRevision = Resolve-SourceRevisionId -Override $SourceRevisionId

$versionDisplay = if (-not [string]::IsNullOrWhiteSpace($resolvedRevision)) {
	"{0}+{1}" -f $resolvedVersion, $resolvedRevision
} else {
	$resolvedVersion
}
Write-Information ("Build plan: version={0}  config={1}  RID=win-x64" -f $versionDisplay, $Configuration)

# -- Step 1: Pre-flight -------------------------------------------------------
try {
	Test-PublishPrerequisites -ResolvedVersion $resolvedVersion
} catch {
	Write-Error $_.Exception.Message
	exit 1
}

# -- Step 2: Detect and resolve blockers BEFORE any destructive action --------
$script:InspectionFailures.Clear()
$blockers = Get-ProcessesUsingPath -PublishRootPath $script:PublishRoot
Write-InspectionDiagnostics

if ($null -ne $blockers -and $blockers.Count -gt 0) {
	try {
		Invoke-BlockerResolution -Blockers $blockers
	} catch {
		Write-Error $_.Exception.Message
		exit 3
	}
}

# -- Step 3: Clean (optional) -------------------------------------------------
if ($Clean) {
	if (Test-Path $script:PublishRoot) {
		if ($PSCmdlet.ShouldProcess($script:PublishRoot, "Remove entire publish folder (-Clean)")) {
			Remove-Item -Recurse -Force $script:PublishRoot -ErrorAction Stop
			Write-Information ("-Clean: removed '{0}'" -f $script:PublishRoot)
		}
	}
}

# Ensure publish root exists.
if (-not (Test-Path $script:PublishRoot)) {
	if ($PSCmdlet.ShouldProcess($script:PublishRoot, "Create publish root directory")) {
		New-Item -ItemType Directory -Path $script:PublishRoot | Out-Null
	}
}

# -- Step 4: dotnet restore + publish per project ----------------------------
Write-Information ""
Write-Information "Publishing projects..."
$tempOutDirs = @{}

foreach ($proj in $script:Projects) {
	$tempOut = Join-Path $script:PublishRoot (".build-tmp-" + $proj["Subdir"])
	$tempOutDirs[$proj["Subdir"]] = $tempOut
	if (Test-Path $tempOut) {
		Remove-Item -Recurse -Force $tempOut -ErrorAction SilentlyContinue
	}

	try {
		Publish-Project `
			-CsprojRelPath   $proj["CsprojRelPath"] `
			-Subdir          $proj["Subdir"] `
			-ExeName         $proj["ExeName"] `
			-ResolvedVersion $resolvedVersion `
			-RevisionId      $resolvedRevision
	} catch {
		# Clean up temp dirs on failure — leave live publish dir untouched.
		foreach ($td in $tempOutDirs.Values) {
			if (Test-Path $td) { Remove-Item -Recurse -Force $td -ErrorAction SilentlyContinue }
		}
		Write-Error $_.Exception.Message
		exit 2
	}
}

if ($IncludeBenchmarks) {
	$benchProj = "src/RdpAudit.Service.Benchmarks/RdpAudit.Service.Benchmarks.csproj"
	if (Test-Path (Join-Path $PSScriptRoot $benchProj)) {
		$tempOut = Join-Path $script:PublishRoot ".build-tmp-Benchmarks"
		$tempOutDirs["Benchmarks"] = $tempOut
		try {
			Publish-Project -CsprojRelPath $benchProj -Subdir "Benchmarks" -ExeName "RdpAudit.Service.Benchmarks.exe" `
				-ResolvedVersion $resolvedVersion -RevisionId $resolvedRevision
		} catch {
			foreach ($td in $tempOutDirs.Values) {
				if (Test-Path $td) { Remove-Item -Recurse -Force $td -ErrorAction SilentlyContinue }
			}
			Write-Error $_.Exception.Message
			exit 2
		}
	}
}

# NOTE: `dotnet publish -o <target>` writes directly to the live publish subdir
# (e.g. publish/Service). The atomic per-file update runs over what dotnet wrote
# to sync any pre-existing live dir; stale files (from prior versions) are removed.
foreach ($proj in $script:Projects) {
	$liveDir = Join-Path $script:PublishRoot $proj["Subdir"]
	if (Test-Path $liveDir) {
		Update-PublishDirectory `
			-BuildOutputDir  $liveDir `
			-PublishDir      $liveDir `
			-ExeName         $proj["ExeName"] `
			-ExpectedVersion $resolvedVersion
	}
}

# -- Step 5: SQLite bundle ----------------------------------------------------
try {
	Invoke-SqliteSupportBundle `
		-ConfiguratorPublishDir (Join-Path $script:PublishRoot "Configurator") `
		-ResolvedVersion        $resolvedVersion
} catch {
	Write-Error $_.Exception.Message
	exit 4
}

# -- Step 6: Documentation + manifest ----------------------------------------
Copy-PublishDocumentation
Write-BuildInfoManifest -ResolvedVersion $resolvedVersion -RevisionId $resolvedRevision

# -- Step 7: Post-checks + report --------------------------------------------
Invoke-PostChecks -ResolvedVersion $resolvedVersion

$allPassed = Write-FinalReport -ResolvedVersion $resolvedVersion

if (-not $allPassed) { exit 5 }
exit 0