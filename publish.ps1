# File:    publish.ps1
# Module:  RdpAudit build orchestration
# Purpose: Publishes RdpAudit.Service and RdpAudit.Configurator as self-contained
#          single-file executables for win-x64. Detects publish-output files that
#          are locked by running RdpAudit processes (typical when the user has
#          just been testing locally) and emits a clear, actionable diagnostic
#          instead of failing with an opaque Remove-Item error.
# Author:  Mikhail Deynekin
# Site:    https://Deynekin.com
# Requires PowerShell 7+
#
# Design notes:
#   - Confirmed blockers and inspection failures are TWO distinct lists with
#     fixed, validated shapes. Inspection failures NEVER reach blocker
#     formatting or termination logic.
#   - Formatters take explicit named parameters, not objects. A missing
#     property cannot crash a formatter because it never reads one.
#   - Returns of arrays use Write-Output -NoEnumerate to avoid the classic
#     PowerShell "return ,$arr" / "@()" double-wrap that turns an empty list
#     into a one-element array whose only element is an empty array.
#   - `$PID` is a PowerShell automatic, read-only variable holding the
#     current process id. Variable names are case-insensitive, so `$pId`,
#     `$Pid`, `$pid` ALL refer to that same read-only automatic. All
#     process-id locals in this script use `$processIdValue`.

[CmdletBinding()]
param(
	[string]$Version = "1.5.0",
	[string]$Configuration = "Release",
	# Build SHA stamped into AssemblyInformationalVersion as SemVer build metadata (after '+').
	# Left empty here on purpose: when not supplied it is auto-resolved from `git rev-parse HEAD`
	# (short form) so every published binary records exactly which commit produced it, and the
	# Configurator can warn when the installed/running Service was built from a different commit.
	# Pass an explicit value (or '-' to disable) only when building outside a git checkout.
	[string]$SourceRevisionId = "",
	[switch]$Force,
	[switch]$SelfTest
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$publishRoot = Join-Path $PSScriptRoot "publish"

# Force deterministic English .NET/MSBuild/NuGet output and a UTF-8 console. The project
# intentionally emits English-only diagnostics; without these settings the .NET SDK localizes
# restore/build messages to the Windows UI language. Localized SDK output can also become
# mojibake when PowerShell captures external-process output and the host/output encodings differ.
function Initialize-EnglishConsoleOutput {
	$env:DOTNET_CLI_UI_LANGUAGE = "en"
	$env:VSLANG = "1033"
	$env:NUGET_CLI_LANGUAGE = "en"
	$env:DOTNET_NOLOGO = "true"

	$utf8NoBom = [System.Text.UTF8Encoding]::new($false)
	[Console]::InputEncoding = $utf8NoBom
	[Console]::OutputEncoding = $utf8NoBom
	$global:OutputEncoding = $utf8NoBom

	$script:DotnetLanguageArgs = @("-p:PreferredUILang=en-US")
}

Initialize-EnglishConsoleOutput

function Invoke-DotnetCli {
	param([Parameter(Mandatory = $true)][string[]]$Arguments)

	$output = & dotnet @Arguments 2>&1
	$exitCode = $LASTEXITCODE
	foreach ($line in $output) {
		Write-Host ([string]$line)
	}
	return $exitCode
}

# -----------------------------------------------------------------------------
# Build SHA resolution
# -----------------------------------------------------------------------------
# Resolves the short commit SHA for the working tree so it can be stamped into the
# binary as SemVer build metadata. Best-effort: a missing git, a detached/empty repo
# or any failure degrades to an empty string (the build then omits the +sha suffix)
# rather than aborting the publish. Appends "-dirty" when the tree has uncommitted
# changes so a binary built from a modified checkout is never mistaken for a clean tag.
function Resolve-SourceRevisionId {
	param([string]$Override)

	if (-not [string]::IsNullOrWhiteSpace($Override)) {
		# Explicit '-' means "no SHA" (building outside a git checkout on purpose).
		if ($Override -eq '-') { return "" }
		return $Override
	}

	$git = Get-Command git -ErrorAction SilentlyContinue
	if ($null -eq $git) {
		Write-Diag "git not found on PATH; publishing without a SourceRevisionId."
		return ""
	}

	try {
		$sha = (& git -C $PSScriptRoot rev-parse --short=12 HEAD 2>$null)
		if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($sha)) {
			Write-Diag "git rev-parse HEAD did not yield a SHA; publishing without a SourceRevisionId."
			return ""
		}
		$sha = $sha.Trim()

		# Flag a dirty working tree so a locally-modified build is visibly distinct.
		$status = (& git -C $PSScriptRoot status --porcelain 2>$null)
		if ($LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace($status)) {
			$sha = $sha + "-dirty"
		}

		return $sha
	} catch {
		Write-Diag ("SHA resolution failed: " + $_.Exception.Message)
		return ""
	}
}

# -----------------------------------------------------------------------------
# Diagnostic plumbing
# -----------------------------------------------------------------------------
# Inspection failures are kept as plain hashtables with a fixed key set. They
# are never passed to blocker formatters and never used to drive Stop-Process.
$script:InspectionFailures = New-Object 'System.Collections.Generic.List[hashtable]'

function Write-Diag {
	param([Parameter(Mandatory = $true)][string]$Message)
	Write-Verbose $Message
}

function Add-InspectionFailure {
	param(
		[Parameter(Mandatory = $true)][string]$ProcessName,
		[AllowNull()][Nullable[int]]$ProcessIdValue,
		[Parameter(Mandatory = $true)][string]$Reason
	)
	$entry = @{
		ProcessName    = $ProcessName
		ProcessIdValue = $ProcessIdValue
		Reason         = $Reason
	}
	$script:InspectionFailures.Add($entry) | Out-Null
	$idText = if ($null -ne $ProcessIdValue) { $ProcessIdValue.ToString() } else { '?' }
	Write-Diag ("Inspection failure: {0} (PID {1}) -> {2}" -f $ProcessName, $idText, $Reason)
}

# -----------------------------------------------------------------------------
# Formatters
# -----------------------------------------------------------------------------
# Formatters take explicit, mandatory scalar parameters. They CANNOT crash on
# a missing property because they never read one. This is the structural fix
# that prevents the previous "property 'ProcessName' cannot be found" error.
function Format-LockingProcess {
	param(
		[Parameter(Mandatory = $true)][string]$ProcessName,
		[Parameter(Mandatory = $true)][int]$ProcessIdValue,
		[Parameter(Mandatory = $true)][string]$ExePath
	)
	return ("{0} (PID {1}) -> {2}" -f $ProcessName, $ProcessIdValue, $ExePath)
}

function Format-InspectionFailure {
	param(
		[Parameter(Mandatory = $true)][string]$ProcessName,
		[AllowNull()][Nullable[int]]$ProcessIdValue,
		[Parameter(Mandatory = $true)][string]$Reason
	)
	$idText = if ($null -ne $ProcessIdValue) { $ProcessIdValue.ToString() } else { '?' }
	return ("{0} (PID {1}): {2}" -f $ProcessName, $idText, $Reason)
}

# -----------------------------------------------------------------------------
# Confirmed-blocker construction
# -----------------------------------------------------------------------------
# Only callers that have already validated all fields create blocker entries
# through this helper. The resulting hashtable has a fixed, known key set.
function New-ConfirmedBlocker {
	param(
		[Parameter(Mandatory = $true)][string]$ProcessName,
		[Parameter(Mandatory = $true)][int]$ProcessIdValue,
		[Parameter(Mandatory = $true)][string]$ExePath
	)
	if ([string]::IsNullOrWhiteSpace($ProcessName)) { throw "blocker requires non-empty ProcessName" }
	if ([string]::IsNullOrWhiteSpace($ExePath))     { throw "blocker requires non-empty ExePath" }
	return @{
		ProcessName    = $ProcessName
		ProcessIdValue = $ProcessIdValue
		ExePath        = $ExePath
	}
}

# -----------------------------------------------------------------------------
# Process discovery
# -----------------------------------------------------------------------------
# Returns ONLY processes for which we have strong evidence (a readable
# executable path under the publish root) that they are blocking deletion.
# Processes whose identity or path cannot be read are recorded as inspection
# failures via Add-InspectionFailure and are never returned from this function.
function Get-ProcessesUsingPath {
	param([Parameter(Mandatory = $true)][string]$Path)

	$normalized = [System.IO.Path]::GetFullPath($Path).TrimEnd([System.IO.Path]::DirectorySeparatorChar)
	$candidates = @("RdpAudit.Configurator", "RdpAudit.Service", "RdpAudit.Mikrotik")
	$found = New-Object 'System.Collections.Generic.List[hashtable]'

	foreach ($name in $candidates) {
		$procs = @(Get-Process -Name $name -ErrorAction SilentlyContinue)
		Write-Diag ("Found {0} '{1}' process(es)" -f $procs.Count, $name)

		foreach ($proc in $procs) {
			if ($null -eq $proc) { continue }

			# Identity: ProcessName + Id. If either fails, record and skip.
			$procName = $null
			$processIdValue = $null
			try {
				$procName = [string]$proc.ProcessName
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

			# Path: most commonly fails (access denied, exited, native error).
			$procPath = $null
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
					-Reason ("could not normalize path '$procPath': " + $_.Exception.Message)
				continue
			}

			if ([string]::IsNullOrWhiteSpace($fullProcPath)) {
				Add-InspectionFailure -ProcessName $procName -ProcessIdValue $processIdValue `
					-Reason "normalized path was empty"
				continue
			}

			if (-not $fullProcPath.StartsWith($normalized, [System.StringComparison]::OrdinalIgnoreCase)) {
				Write-Diag ("Skipping {0} (PID {1}) -> {2}: outside publish root" -f $procName, $processIdValue, $fullProcPath)
				continue
			}

			$blocker = New-ConfirmedBlocker -ProcessName $procName -ProcessIdValue $processIdValue -ExePath $fullProcPath
			$found.Add($blocker) | Out-Null
			Write-Diag ("Blocker confirmed: {0} (PID {1}) -> {2}" -f $procName, $processIdValue, $fullProcPath)
		}
	}

	# Emit a single object: the List itself. Callers iterate via .Count / foreach.
	# Using Write-Output -NoEnumerate avoids both:
	#   - PowerShell unwrapping the List into individual elements, AND
	#   - the classic ", $arr.ToArray()" double-wrap where @() on the result
	#     produces a one-element array containing an empty inner array.
	Write-Output -NoEnumerate $found
}

function Write-InspectionDiagnostics {
	if ($script:InspectionFailures.Count -eq 0) { return }
	Write-Host "" -ForegroundColor DarkGray
	Write-Host "Unable to inspect the following process(es) (NOT classified as blockers):" -ForegroundColor DarkYellow
	foreach ($f in $script:InspectionFailures) {
		$line = Format-InspectionFailure `
			-ProcessName    $f['ProcessName'] `
			-ProcessIdValue $f['ProcessIdValue'] `
			-Reason         $f['Reason']
		Write-Host ("  " + $line) -ForegroundColor DarkYellow
	}
	Write-Host "Hint: run this script from an elevated PowerShell to read process paths." -ForegroundColor DarkGray
}

# -----------------------------------------------------------------------------
# Failure formatting
# -----------------------------------------------------------------------------
function Format-RemoveFailure {
	param(
		[Parameter(Mandatory = $true)][string]$Path,
		[int]$Attempts = 0,
		[System.Collections.IEnumerable]$StillLocking = $null,
		[System.Exception]$OriginalException = $null,
		[string]$ExtraContext = $null
	)

	$sb = [System.Text.StringBuilder]::new()
	[void]$sb.AppendLine("Unable to clean publish output.")
	[void]$sb.AppendLine("  Target path : $Path")
	if ($Attempts -gt 0) {
		[void]$sb.AppendLine("  Attempts    : $Attempts")
	}

	$stillCount = 0
	if ($null -ne $StillLocking) {
		foreach ($_ in $StillLocking) { $stillCount++ }
	}

	if ($stillCount -gt 0) {
		[void]$sb.AppendLine("  Confirmed RdpAudit blockers still running from the folder:")
		foreach ($s in $StillLocking) {
			$line = Format-LockingProcess `
				-ProcessName    $s['ProcessName'] `
				-ProcessIdValue $s['ProcessIdValue'] `
				-ExePath        $s['ExePath']
			[void]$sb.AppendLine("    " + $line)
		}
	} else {
		[void]$sb.AppendLine("  Confirmed RdpAudit blockers: none detected.")
	}

	if ($script:InspectionFailures.Count -gt 0) {
		[void]$sb.AppendLine("  Processes we could not inspect (NOT confirmed as blockers):")
		foreach ($f in $script:InspectionFailures) {
			$line = Format-InspectionFailure `
				-ProcessName    $f['ProcessName'] `
				-ProcessIdValue $f['ProcessIdValue'] `
				-Reason         $f['Reason']
			[void]$sb.AppendLine("    " + $line)
		}
	}

	if ($null -ne $OriginalException) {
		[void]$sb.AppendLine("  Underlying error:")
		[void]$sb.AppendLine("    Type    : " + $OriginalException.GetType().FullName)
		[void]$sb.AppendLine("    Message : " + $OriginalException.Message)
		# IOException carries a target file name on Windows for locked files.
		try {
			$targetFile = $OriginalException.PSObject.Properties['FileName']
			if ($null -ne $targetFile -and $null -ne $targetFile.Value) {
				[void]$sb.AppendLine("    File    : " + $targetFile.Value)
			}
		} catch {
			# best-effort only
		}
	}

	if (-not [string]::IsNullOrWhiteSpace($ExtraContext)) {
		[void]$sb.AppendLine("  Context     : $ExtraContext")
	}

	[void]$sb.AppendLine("  Likely causes:")
	[void]$sb.AppendLine("    - RdpAudit.Configurator window is still open.")
	[void]$sb.AppendLine("    - The installed RdpAudit service is running (locks Service\\*.exe).")
	[void]$sb.AppendLine("    - An Explorer window or terminal has the publish folder open.")
	[void]$sb.AppendLine("    - Antivirus / EDR is scanning the freshly written binaries.")
	[void]$sb.AppendLine("    - A previous publish left a stale handle; reboot resolves it.")
	[void]$sb.AppendLine("  Next steps:")
	[void]$sb.AppendLine("    1. Close Configurator: taskkill /IM RdpAudit.Configurator.exe /F")
	[void]$sb.AppendLine("    2. Stop the service (if installed): sc.exe stop RdpAudit")
	[void]$sb.AppendLine("    3. Close any Explorer/terminal pointing at '$Path'.")
	[void]$sb.AppendLine("    4. Re-run:  pwsh -NoProfile -File .\\publish.ps1 -Force -Verbose")

	return $sb.ToString().TrimEnd()
}

# -----------------------------------------------------------------------------
# Removal with actionable diagnostics
# -----------------------------------------------------------------------------
function Remove-PublishOutput {
	param([Parameter(Mandatory = $true)][string]$Path)

	if (-not (Test-Path $Path)) {
		Write-Diag "Publish output path does not exist; nothing to remove: $Path"
		return
	}

	$script:InspectionFailures.Clear()
	$locking = Get-ProcessesUsingPath -Path $Path

	if ($null -ne $locking -and $locking.Count -gt 0) {
		Write-Host "The following RdpAudit processes are running from the publish folder and will block deletion:" -ForegroundColor Yellow
		foreach ($entry in $locking) {
			$line = Format-LockingProcess `
				-ProcessName    $entry['ProcessName'] `
				-ProcessIdValue $entry['ProcessIdValue'] `
				-ExePath        $entry['ExePath']
			Write-Host ("  " + $line) -ForegroundColor Yellow
		}
		Write-InspectionDiagnostics

		if ($Force) {
			foreach ($p in $locking) {
				$pName = $p['ProcessName']
				$processIdValue = $p['ProcessIdValue']
				Write-Host ("Stopping {0} (PID {1}) ..." -f $pName, $processIdValue) -ForegroundColor Yellow
				try {
					Stop-Process -Id $processIdValue -Force -ErrorAction Stop
				} catch {
					throw (Format-RemoveFailure -Path $Path -ExtraContext (
						"Failed to stop {0} (PID {1}): {2} ({3})" -f `
							$pName, $processIdValue, $_.Exception.Message, $_.Exception.GetType().FullName))
				}
			}
			Start-Sleep -Milliseconds 500
		} else {
			throw (Format-RemoveFailure -Path $Path -ExtraContext (
				"Detected " + $locking.Count + " RdpAudit process(es) running from the publish folder. " +
				"Close the Configurator (and stop the service if installed) and retry, " +
				"or re-run with -Force to terminate them automatically."))
		}
	} else {
		# No confirmed blockers. Surface inspection failures (if any) so the
		# user knows detection was best-effort, then proceed to deletion.
		Write-InspectionDiagnostics
	}

	$attempts = 0
	$maxAttempts = 5
	$lastError = $null
	while ($true) {
		$attempts++
		try {
			Write-Diag ("Removing '{0}' (attempt {1}/{2})" -f $Path, $attempts, $maxAttempts)
			Remove-Item -Recurse -Force $Path -ErrorAction Stop
			return
		} catch {
			$lastError = $_
			if ($attempts -ge $maxAttempts) {
				$script:InspectionFailures.Clear()
				$still = Get-ProcessesUsingPath -Path $Path
				throw (Format-RemoveFailure `
					-Path $Path `
					-Attempts $attempts `
					-StillLocking $still `
					-OriginalException $lastError.Exception)
			}
			Write-Diag ("Remove-Item attempt {0} failed: {1}" -f $attempts, $_.Exception.Message)
			Start-Sleep -Milliseconds (250 * $attempts)
		}
	}
}

# -----------------------------------------------------------------------------
# Publish
# -----------------------------------------------------------------------------
function Publish-Project {
	param(
		[Parameter(Mandatory = $true)][string]$Project,
		[Parameter(Mandatory = $true)][string]$Subdir,
		[string]$RevisionId = ""
	)

	$target = Join-Path $publishRoot $Subdir
	Write-Host "Publishing $Project -> $target" -ForegroundColor Cyan

	$publishArgs = @(
		$Project,
		"-c", $Configuration,
		"-r", "win-x64",
		"--self-contained", "true",
		"-p:PublishSingleFile=true",
		"-p:IncludeNativeLibrariesForSelfExtract=true",
		"-p:EnableCompressionInSingleFile=true",
		"-p:VersionPrefix=$Version"
	)
	$publishArgs += $script:DotnetLanguageArgs
	if (-not [string]::IsNullOrWhiteSpace($RevisionId)) {
		$publishArgs += "-p:SourceRevisionId=$RevisionId"
	}
	$publishArgs += @("-o", $target)

	$exitCode = Invoke-DotnetCli -Arguments (@("publish") + $publishArgs)
	if ($exitCode -ne 0) {
		throw "publish failed: $Project (exit $exitCode)"
	}
}

# -----------------------------------------------------------------------------
# SQLite diagnostic support bundle
# -----------------------------------------------------------------------------
# The Configurator is published as a self-contained single-file executable, so the
# SQLite dependency graph (Microsoft.Data.Sqlite + SQLitePCLRaw.* + the native
# e_sqlite3.dll) is embedded INSIDE the .exe and extracted only at process start.
# That is fine for the running app, but it is NOT enough for external PowerShell
# diagnostics that call Add-Type / [System.Runtime.InteropServices.NativeLibrary]::Load
# against loose files on disk. This stage guarantees those exact files are physically
# present next to the published Configurator, resolved from the SAME NuGet dependency
# graph/version the app builds against — never downloaded from sqlite.org and never a
# global C:\sqlite install.
#
# These names MUST match RdpAudit.Core.Util.SqliteSupportBundle.RequiredFiles exactly.
$script:SqliteSupportFiles = @(
	"Microsoft.Data.Sqlite.dll",
	"SQLitePCLRaw.core.dll",
	"SQLitePCLRaw.provider.e_sqlite3.dll",
	"SQLitePCLRaw.batteries_v2.dll",
	"e_sqlite3.dll"
)

# Produces a directory tree that contains the SQLite support files as LOOSE files by
# building (not single-file publishing) the Configurator for win-x64. The regular build
# output flattens both the managed SQLitePCLRaw / Microsoft.Data.Sqlite assemblies and the
# native e_sqlite3.dll into the RID output folder, all from the restored NuGet packages —
# so it is the deterministic, user-path-free source for the bundle. Returns the resolved
# output directory or throws an actionable error naming the project and the restore command.
function Resolve-SqliteBundleSource {
	param(
		[Parameter(Mandatory = $true)][string]$Project,
		[Parameter(Mandatory = $true)][string]$Version
	)

	$projectFull = Join-Path $PSScriptRoot $Project
	if (-not (Test-Path $projectFull)) {
		throw "Cannot resolve SQLite support bundle: project not found at '$projectFull'."
	}

	# Ensure packages are restored before we attempt to resolve any dependency file. A missing
	# or stale NuGet cache is repaired here rather than failing later with an opaque copy error.
	Write-Host "Restoring $Project for SQLite bundle resolution..." -ForegroundColor DarkCyan
	$restoreExitCode = Invoke-DotnetCli -Arguments (@("restore", $projectFull, "-r", "win-x64") + $script:DotnetLanguageArgs)
	if ($restoreExitCode -ne 0) {
		throw ("dotnet restore failed for '{0}' (exit {1}). The SQLite support bundle cannot be assembled without restored NuGet packages. Run:`n    dotnet restore `"{0}`" -r win-x64`nand retry." -f $projectFull, $restoreExitCode)
	}

	$bundleObjDir = Join-Path $PSScriptRoot "publish/.sqlite-bundle"
	if (Test-Path $bundleObjDir) {
		Remove-Item -Recurse -Force $bundleObjDir -ErrorAction SilentlyContinue
	}

	Write-Host "Building $Project (framework-dependent, loose files) for SQLite bundle resolution..." -ForegroundColor DarkCyan
	# Self-contained=false keeps the build fast and small; the SQLite managed + native files are
	# still emitted into the RID output folder because they are direct/transitive package assets.
	$buildArgs = @(
		"build",
		$projectFull,
		"-c", $Configuration,
		"-r", "win-x64",
		"--self-contained", "false",
		"-p:PublishSingleFile=false",
		"-p:VersionPrefix=$Version"
	) + $script:DotnetLanguageArgs + @("-o", $bundleObjDir)
	$buildExitCode = Invoke-DotnetCli -Arguments $buildArgs
	if ($buildExitCode -ne 0) {
		throw ("dotnet build failed for '{0}' (exit {1}) while assembling the SQLite support bundle. Inspect the build output above; the most common cause is a missing NuGet package, which `dotnet restore` should repair." -f $projectFull, $buildExitCode)
	}

	return $bundleObjDir
}

# Copies the SQLite support files into $TargetDir, resolving each from $SourceDir (the loose
# build output). The native e_sqlite3.dll can land either in the RID root or under
# runtimes/win-x64/native depending on the SDK, so both are searched. Throws an actionable
# error listing every file that could not be resolved.
function Copy-SqliteSupportFiles {
	param(
		[Parameter(Mandatory = $true)][string]$SourceDir,
		[Parameter(Mandatory = $true)][string]$TargetDir
	)

	if (-not (Test-Path $TargetDir)) {
		New-Item -ItemType Directory -Path $TargetDir | Out-Null
	}

	$missing = New-Object 'System.Collections.Generic.List[string]'
	$copied = New-Object 'System.Collections.Generic.List[string]'

	foreach ($name in $script:SqliteSupportFiles) {
		$resolved = $null
		$direct = Join-Path $SourceDir $name
		if (Test-Path $direct) {
			$resolved = $direct
		} else {
			# Native libraries are frequently emitted under runtimes/<rid>/native rather than the
			# RID root; search the whole build tree for the leaf name as a last resort.
			$candidate = Get-ChildItem -Path $SourceDir -Filter $name -Recurse -File -ErrorAction SilentlyContinue |
				Select-Object -First 1
			if ($null -ne $candidate) {
				$resolved = $candidate.FullName
			}
		}

		if ($null -eq $resolved) {
			$missing.Add($name) | Out-Null
			continue
		}

		$dest = Join-Path $TargetDir $name
		Copy-Item -Path $resolved -Destination $dest -Force
		$copied.Add($name) | Out-Null
		Write-Diag ("SQLite bundle: copied {0} <- {1}" -f $name, $resolved)
	}

	if ($missing.Count -gt 0) {
		throw ("SQLite support bundle incomplete: could not resolve {0} of {1} required file(s): {2}. Searched '{3}'. These files come from the Microsoft.EntityFrameworkCore.Sqlite -> Microsoft.Data.Sqlite -> SQLitePCLRaw.* NuGet graph; ensure `dotnet restore` succeeded and do NOT substitute a sqlite.org download." -f `
			$missing.Count, $script:SqliteSupportFiles.Count, ($missing -join ", "), $SourceDir)
	}

	return $copied
}

# Top-level orchestration for the bundle: resolves a loose-file source, copies the required
# files next to the published Configurator, then verifies the target now holds every file.
function Ensure-SqliteSupportBundle {
	param(
		[Parameter(Mandatory = $true)][string]$ConfiguratorPublishDir,
		[Parameter(Mandatory = $true)][string]$Version
	)

	Write-Host "Ensuring SQLite diagnostic support bundle in $ConfiguratorPublishDir" -ForegroundColor Cyan

	$source = Resolve-SqliteBundleSource -Project "src/RdpAudit.Configurator/RdpAudit.Configurator.csproj" -Version $Version
	$copied = Copy-SqliteSupportFiles -SourceDir $source -TargetDir $ConfiguratorPublishDir

	# Post-condition verification: re-check the TARGET directly so a silently failed copy is caught.
	$stillMissing = New-Object 'System.Collections.Generic.List[string]'
	foreach ($name in $script:SqliteSupportFiles) {
		if (-not (Test-Path (Join-Path $ConfiguratorPublishDir $name))) {
			$stillMissing.Add($name) | Out-Null
		}
	}
	if ($stillMissing.Count -gt 0) {
		throw ("SQLite support bundle verification failed after copy: {0} file(s) still missing in '{1}': {2}." -f `
			$stillMissing.Count, $ConfiguratorPublishDir, ($stillMissing -join ", "))
	}

	# Clean up the transient loose-build output so it does not ship in the publish tree.
	$bundleObjDir = Join-Path $PSScriptRoot "publish/.sqlite-bundle"
	if (Test-Path $bundleObjDir) {
		Remove-Item -Recurse -Force $bundleObjDir -ErrorAction SilentlyContinue
	}

	Write-Host ("SQLite support bundle complete: {0}/{1} file(s) present next to the Configurator." -f `
		$copied.Count, $script:SqliteSupportFiles.Count) -ForegroundColor Green
}

# -----------------------------------------------------------------------------
# Self-test (-SelfTest)
# -----------------------------------------------------------------------------
# Validates the structural invariants of this script without publishing or
# deleting anything. Designed to fail loudly on any regression that would
# reproduce the previously seen StrictMode crashes.
function Invoke-PublishScriptSelfCheck {
	$failures = New-Object 'System.Collections.Generic.List[string]'

	function Add-Failure {
		param([string]$Msg)
		$failures.Add($Msg) | Out-Null
		Write-Host ("  [FAIL] " + $Msg) -ForegroundColor Red
	}
	function Add-Pass {
		param([string]$Msg)
		Write-Host ("  [PASS] " + $Msg) -ForegroundColor Green
	}

	Write-Host "Running publish.ps1 self-tests..." -ForegroundColor Cyan

	# 1. Formatting a confirmed blocker with all fields works.
	try {
		$line = Format-LockingProcess -ProcessName 'RdpAudit.Configurator' -ProcessIdValue 1234 -ExePath 'C:\publish\Configurator\RdpAudit.Configurator.exe'
		if ($line -notmatch 'RdpAudit\.Configurator' -or $line -notmatch '1234') {
			Add-Failure "Format-LockingProcess output did not contain expected fields: $line"
		} else {
			Add-Pass "Format-LockingProcess formats a confirmed blocker"
		}
	} catch {
		Add-Failure ("Format-LockingProcess threw on valid input: " + $_.Exception.Message)
	}

	# 2. Inspection-failure formatting works and does NOT require an ExePath.
	try {
		$line = Format-InspectionFailure -ProcessName 'RdpAudit.Service' -ProcessIdValue $null -Reason 'access denied'
		if ($line -notmatch 'access denied') {
			Add-Failure "Format-InspectionFailure output missing reason: $line"
		} else {
			Add-Pass "Format-InspectionFailure formats a null-PID failure"
		}
	} catch {
		Add-Failure ("Format-InspectionFailure threw on valid input: " + $_.Exception.Message)
	}

	# 3. A diagnostic / inspection-failure record must NEVER be acceptable to
	#    Format-LockingProcess. Format-LockingProcess takes scalars, so the
	#    only way to invoke it is with explicit named params; trying to pass
	#    an arbitrary object (missing ExePath) must fail at bind time, not
	#    at runtime property-read.
	try {
		$diag = @{ ProcessName = 'X'; ProcessIdValue = 1; Reason = 'unreadable' }
		# Splatting a hashtable that lacks ExePath: parameter binding must reject this.
		$null = Format-LockingProcess @diag
		Add-Failure "Format-LockingProcess accepted an object without ExePath; binder regression."
	} catch {
		Add-Pass "Format-LockingProcess rejects records lacking ExePath (binder enforced)"
	}

	# 4. No blocker header must be printed for an empty blocker list. We
	#    simulate that path by inspecting the Remove-PublishOutput logic
	#    indirectly: confirm that Get-ProcessesUsingPath on a fresh temp path
	#    returns a list with Count == 0 (not a one-element array containing
	#    an empty array - the regression we are fixing).
	try {
		$tempDir = Join-Path ([System.IO.Path]::GetTempPath()) ("rdpaudit-selftest-" + [Guid]::NewGuid().ToString('N'))
		New-Item -ItemType Directory -Path $tempDir | Out-Null
		try {
			$script:InspectionFailures.Clear()
			$res = Get-ProcessesUsingPath -Path $tempDir
			if ($null -eq $res) {
				Add-Failure "Get-ProcessesUsingPath returned `$null instead of an empty list"
			} elseif ($res.Count -ne 0) {
				# It's legal for the user's machine to have a real RdpAudit
				# process running outside the temp dir, but it must never
				# end up in the result because the path filter excludes it.
				Add-Failure ("Expected 0 blockers for temp path, got " + $res.Count)
			} else {
				Add-Pass "Get-ProcessesUsingPath returns Count==0 for an unrelated path (no double-wrap)"
			}
		} finally {
			Remove-Item -Recurse -Force $tempDir -ErrorAction SilentlyContinue
		}
	} catch {
		Add-Failure ("Get-ProcessesUsingPath self-check threw: " + $_.Exception.Message)
	}

	# 5. No assignments to `$pid` / `$PID` / `$Pid` anywhere in the script.
	#    Read the script source and grep for assignment patterns.
	try {
		$scriptText = Get-Content -Raw -Path $PSCommandPath
		$assignPattern = '(?im)^\s*\$pid\s*='
		if ($scriptText -match $assignPattern) {
			Add-Failure "Found assignment to `$pid (collides with read-only automatic). Use `$processIdValue."
		} else {
			Add-Pass "No assignment to `$pid / `$PID / `$Pid in script source"
		}
	} catch {
		Add-Failure ("`$pid usage check threw: " + $_.Exception.Message)
	}

	# 6. Script parses under strict mode. If we are running, it already parsed.
	#    Re-validate by tokenising via the PowerShell parser so a syntax
	#    regression in an unreachable branch still fails the self-test.
	try {
		$tokens = $null
		$errors = $null
		[void][System.Management.Automation.Language.Parser]::ParseFile($PSCommandPath, [ref]$tokens, [ref]$errors)
		if ($null -ne $errors -and $errors.Count -gt 0) {
			Add-Failure ("Parser reported " + $errors.Count + " error(s) in publish.ps1")
		} else {
			Add-Pass "Script parses cleanly under PowerShell parser"
		}
	} catch {
		Add-Failure ("Parser self-check threw: " + $_.Exception.Message)
	}

	# 7. Add-InspectionFailure followed by zero confirmed blockers must NOT
	#    cause the deletion path to print the blocker header. Simulate by
	#    populating an inspection failure and confirming the script-level
	#    list contains it while the locking list is empty.
	try {
		$script:InspectionFailures.Clear()
		Add-InspectionFailure -ProcessName 'RdpAudit.Service' -ProcessIdValue 4242 -Reason 'simulated unreadable path'
		$tempDir = Join-Path ([System.IO.Path]::GetTempPath()) ("rdpaudit-selftest-" + [Guid]::NewGuid().ToString('N'))
		New-Item -ItemType Directory -Path $tempDir | Out-Null
		try {
			# Fresh discovery to confirm separation of lists.
			$script:InspectionFailures.Clear()
			$res = Get-ProcessesUsingPath -Path $tempDir
			if ($res.Count -eq 0 -and $script:InspectionFailures.Count -eq 0) {
				Add-Pass "Separation of blockers and inspection failures holds for clean temp path"
			} elseif ($res.Count -gt 0) {
				Add-Failure ("Unexpected blockers for temp path: " + $res.Count)
			} else {
				Add-Pass ("Inspection failures recorded without contaminating blockers (count=" + $script:InspectionFailures.Count + ")")
			}
		} finally {
			Remove-Item -Recurse -Force $tempDir -ErrorAction SilentlyContinue
			$script:InspectionFailures.Clear()
		}
	} catch {
		Add-Failure ("Separation self-check threw: " + $_.Exception.Message)
	}

	# 8. The SQLite support-bundle file list must be exactly the five files the app's NuGet graph
	#    produces and that RdpAudit.Core.Util.SqliteSupportBundle.RequiredFiles enumerates. A drift
	#    here means the published Configurator would ship an incomplete diagnostic bundle.
	try {
		$expected = @(
			"Microsoft.Data.Sqlite.dll",
			"SQLitePCLRaw.core.dll",
			"SQLitePCLRaw.provider.e_sqlite3.dll",
			"SQLitePCLRaw.batteries_v2.dll",
			"e_sqlite3.dll"
		)
		$actual = @($script:SqliteSupportFiles)
		$diff = Compare-Object -ReferenceObject $expected -DifferenceObject $actual
		if ($actual.Count -ne $expected.Count -or $null -ne $diff) {
			Add-Failure ("SqliteSupportFiles drifted from the expected five-file bundle: " + ($actual -join ", "))
		} else {
			Add-Pass "SqliteSupportFiles matches the canonical five-file SQLite diagnostic bundle"
		}
	} catch {
		Add-Failure ("SQLite bundle file-list self-check threw: " + $_.Exception.Message)
	}

	# 9. Copy-SqliteSupportFiles must fail with an actionable error (not silently succeed) when the
	#    source directory cannot supply the required files. Use an empty temp dir as the source.
	try {
		$srcDir = Join-Path ([System.IO.Path]::GetTempPath()) ("rdpaudit-bundle-src-" + [Guid]::NewGuid().ToString('N'))
		$dstDir = Join-Path ([System.IO.Path]::GetTempPath()) ("rdpaudit-bundle-dst-" + [Guid]::NewGuid().ToString('N'))
		New-Item -ItemType Directory -Path $srcDir | Out-Null
		try {
			$threw = $false
			try {
				$null = Copy-SqliteSupportFiles -SourceDir $srcDir -TargetDir $dstDir
			} catch {
				$threw = $true
				if ($_.Exception.Message -notmatch 'SQLite support bundle incomplete') {
					Add-Failure ("Copy-SqliteSupportFiles threw an unexpected message: " + $_.Exception.Message)
				}
			}
			if ($threw) {
				Add-Pass "Copy-SqliteSupportFiles fails actionably when the source lacks the bundle files"
			} else {
				Add-Failure "Copy-SqliteSupportFiles silently succeeded with an empty source directory"
			}
		} finally {
			Remove-Item -Recurse -Force $srcDir -ErrorAction SilentlyContinue
			Remove-Item -Recurse -Force $dstDir -ErrorAction SilentlyContinue
		}
	} catch {
		Add-Failure ("Copy-SqliteSupportFiles self-check threw: " + $_.Exception.Message)
	}

	# 10. Copy-SqliteSupportFiles must succeed and report all five files when the source supplies them,
	#     including a native library that lives under runtimes/<rid>/native rather than the root.
	try {
		$srcDir = Join-Path ([System.IO.Path]::GetTempPath()) ("rdpaudit-bundle-ok-src-" + [Guid]::NewGuid().ToString('N'))
		$dstDir = Join-Path ([System.IO.Path]::GetTempPath()) ("rdpaudit-bundle-ok-dst-" + [Guid]::NewGuid().ToString('N'))
		New-Item -ItemType Directory -Path $srcDir | Out-Null
		$nativeDir = Join-Path $srcDir "runtimes/win-x64/native"
		New-Item -ItemType Directory -Path $nativeDir | Out-Null
		try {
			foreach ($name in $script:SqliteSupportFiles) {
				if ($name -eq "e_sqlite3.dll") {
					Set-Content -Path (Join-Path $nativeDir $name) -Value "native" -NoNewline
				} else {
					Set-Content -Path (Join-Path $srcDir $name) -Value "managed" -NoNewline
				}
			}
			$copied = @(Copy-SqliteSupportFiles -SourceDir $srcDir -TargetDir $dstDir)
			$allPresent = $true
			foreach ($name in $script:SqliteSupportFiles) {
				if (-not (Test-Path (Join-Path $dstDir $name))) { $allPresent = $false }
			}
			if ($copied.Count -eq $script:SqliteSupportFiles.Count -and $allPresent) {
				Add-Pass "Copy-SqliteSupportFiles resolves root + runtimes/native files and copies the full bundle"
			} else {
				Add-Failure ("Copy-SqliteSupportFiles did not lay down the full bundle (copied=" + $copied.Count + ", allPresent=" + $allPresent + ")")
			}
		} finally {
			Remove-Item -Recurse -Force $srcDir -ErrorAction SilentlyContinue
			Remove-Item -Recurse -Force $dstDir -ErrorAction SilentlyContinue
		}
	} catch {
		Add-Failure ("Copy-SqliteSupportFiles success-path self-check threw: " + $_.Exception.Message)
	}

	if ($failures.Count -gt 0) {
		Write-Host ""
		Write-Host ("Self-test FAILED ({0} failure(s))" -f $failures.Count) -ForegroundColor Red
		throw "publish.ps1 self-test failed"
	}

	Write-Host ""
	Write-Host "Self-test PASSED" -ForegroundColor Green
}

# -----------------------------------------------------------------------------
# Entry point
# -----------------------------------------------------------------------------
if ($SelfTest) {
	Invoke-PublishScriptSelfCheck
	return
}

Remove-PublishOutput -Path $publishRoot

$resolvedRevision = Resolve-SourceRevisionId -Override $SourceRevisionId
if (-not [string]::IsNullOrWhiteSpace($resolvedRevision)) {
	Write-Host ("Stamping build SHA: {0}+{1}" -f $Version, $resolvedRevision) -ForegroundColor Cyan
} else {
	Write-Host ("Publishing {0} without a build SHA (no git checkout or SHA disabled)." -f $Version) -ForegroundColor DarkYellow
}

Publish-Project -Project "src/RdpAudit.Service/RdpAudit.Service.csproj"           -Subdir "Service"      -RevisionId $resolvedRevision
Publish-Project -Project "src/RdpAudit.Configurator/RdpAudit.Configurator.csproj" -Subdir "Configurator" -RevisionId $resolvedRevision
Publish-Project -Project "src/RdpAudit.Mikrotik/RdpAudit.Mikrotik.csproj"         -Subdir "Mikrotik"     -RevisionId $resolvedRevision

# The single-file Configurator embeds its SQLite dependencies; lay them down as loose files so
# external PowerShell diagnostics can load the provider. This runs AFTER the publish so it copies
# into the final published Configurator folder.
Ensure-SqliteSupportBundle -ConfiguratorPublishDir (Join-Path $publishRoot "Configurator") -Version $Version

Write-Host "Done -> $publishRoot" -ForegroundColor Green
