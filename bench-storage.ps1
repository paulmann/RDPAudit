# /* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
# Version: 1.0.0
# File   : bench-storage.ps1
# Project: RDPAudit
# Purpose: One-shot runner for the storage benchmark (tools/RdpAudit.StorageBenchmarks). It resolves a
#          usable .NET SDK, builds the tool, runs the binary it just built, and prints where the report
#          landed. It is a sibling of benchmarks.ps1 rather than an extra switch on it, so the
#          BenchmarkDotNet runner keeps its exact behaviour and its exact arguments.
# Depends: .NET 8 SDK, tools/RdpAudit.StorageBenchmarks/RdpAudit.StorageBenchmarks.csproj
# Extends: Pass -Quick for the fast profile. Unrecognised parameters are forwarded to the tool verbatim, so
#          this script never has to be edited when the tool gains an option; run the tool with --help for
#          the full list.
#
# Two environment traps this script works around, both recorded in BUGS.md:
#   B8  `dotnet restore` fails with "NuGet.targets(...): error : Value cannot be null. (Parameter 'path1')"
#       in a shell that does not export PROGRAMDATA / ALLUSERSPROFILE / PROGRAMFILES. NuGet's
#       NuGetEnvironment reads those variables directly instead of asking Windows for the known folder, so
#       Path.Combine(null, "NuGet") throws. The script exports them when they are missing.
#   B7  This repository produces two output trees on one machine. `dotnet run` resolves its path without
#       the platform the build used, so it looks in the platform-less tree and either fails or answers from
#       a stale binary. The script asks MSBuild for the real TargetPath and launches that.

[CmdletBinding()]
param(
	[switch] $Quick,
	[string] $Configuration = 'Release',
	[string] $Store,
	[string] $Out,
	[int] $Rows,
	[int] $Codes,
	[int] $Samples,
	[int] $Warmup = -1,
	[switch] $SkipShards,
	[switch] $AllowExistingStore,
	[switch] $NoBuild,
	[string] $DotNet,
	[Parameter(ValueFromRemainingArguments = $true)]
	[string[]] $ForwardedArgs
)

$ErrorActionPreference = 'Stop'
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$projectPath = Join-Path $scriptDir 'tools/RdpAudit.StorageBenchmarks/RdpAudit.StorageBenchmarks.csproj'

if (-not (Test-Path $projectPath)) {
	Write-Error "Storage benchmark project not found at $projectPath"
	exit 1
}

# ── Resolve a dotnet that actually has an SDK (B7) ───────────────────────────────
function Resolve-DotNetHost {
	param([string] $Explicit)

	$candidates = @()
	if ($Explicit) { $candidates += $Explicit }
	$candidates += 'C:\Program Files\dotnet\dotnet.exe'
	$fromPath = Get-Command dotnet -ErrorAction SilentlyContinue
	if ($fromPath) { $candidates += $fromPath.Source }

	foreach ($candidate in $candidates) {
		if (-not $candidate -or -not (Test-Path $candidate)) { continue }

		$sdks = & $candidate --list-sdks 2>$null
		if ($LASTEXITCODE -eq 0 -and $sdks) { return $candidate }

		Write-Host "==> '$candidate' has no usable SDK; trying the next candidate" -ForegroundColor Yellow
	}

	return $null
}

$dotnet = Resolve-DotNetHost -Explicit $DotNet
if (-not $dotnet) {
	Write-Error "No .NET SDK found. Install the .NET 8 SDK, or pass -DotNet <path to dotnet.exe>."
	exit 1
}

$env:DOTNET_ROOT = Split-Path -Parent $dotnet
$env:DOTNET_NOLOGO = '1'
$env:DOTNET_CLI_TELEMETRY_OPTOUT = '1'

# See the B8 note above: NuGet reads these variables directly.
$folderFallbacks = @{
	'PROGRAMDATA'       = 'C:\ProgramData'
	'ALLUSERSPROFILE'   = 'C:\ProgramData'
	'PROGRAMFILES'      = 'C:\Program Files'
	'ProgramFiles(x86)' = 'C:\Program Files (x86)'
}
foreach ($name in $folderFallbacks.Keys) {
	if (-not [Environment]::GetEnvironmentVariable($name)) {
		[Environment]::SetEnvironmentVariable($name, $folderFallbacks[$name], 'Process')
		Write-Host "==> exported $name for NuGet (this shell did not have it)" -ForegroundColor DarkGray
	}
}

Write-Host "==> dotnet: $dotnet" -ForegroundColor Cyan

if (-not $NoBuild) {
	Write-Host "==> Restoring and building $Configuration (Platform=x64)" -ForegroundColor Cyan

	& $dotnet restore $projectPath | Out-Host
	if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

	& $dotnet build $projectPath -c $Configuration -p:Platform=x64 --no-restore --nologo | Out-Host
	if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}

# ── Assemble the tool's arguments ────────────────────────────────────────────────
$toolArgs = @()
if ($Quick) { $toolArgs += '--quick' }
if ($Store) { $toolArgs += @('--store', $Store) }
if ($Out) { $toolArgs += @('--out', $Out) }
if ($PSBoundParameters.ContainsKey('Rows')) { $toolArgs += @('--rows', "$Rows") }
if ($PSBoundParameters.ContainsKey('Codes')) { $toolArgs += @('--codes', "$Codes") }
if ($PSBoundParameters.ContainsKey('Samples')) { $toolArgs += @('--samples', "$Samples") }
if ($Warmup -ge 0) { $toolArgs += @('--warmup', "$Warmup") }
if ($SkipShards) { $toolArgs += '--no-shards' }
if ($AllowExistingStore) { $toolArgs += '--allow-existing-store' }
if ($ForwardedArgs) { $toolArgs += $ForwardedArgs }

# ── Locate the binary that was actually built (B7) ───────────────────────────────
function Resolve-ToolExecutable {
	param([string] $DotNet, [string] $Project, [string] $Configuration)

	$targetPath = & $DotNet msbuild $Project -p:Configuration=$Configuration -p:Platform=x64 -getProperty:TargetPath -nologo 2>$null
	$resolved = $targetPath | Select-Object -Last 1
	if ($LASTEXITCODE -eq 0 -and $resolved -and (Test-Path $resolved)) {
		return $resolved.Trim()
	}

	# Fallback for an SDK without -getProperty: the newest matching artifact under the x64 tree.
	$binRoot = Join-Path (Split-Path -Parent $Project) "bin/x64/$Configuration"
	if (Test-Path $binRoot) {
		$found = Get-ChildItem -Path $binRoot -Recurse -Filter 'RdpAudit.StorageBenchmarks.exe' -ErrorAction SilentlyContinue |
			Sort-Object LastWriteTimeUtc -Descending |
			Select-Object -First 1
		if ($found) { return $found.FullName }
	}

	return $null
}

$toolTarget = Resolve-ToolExecutable -DotNet $dotnet -Project $projectPath -Configuration $Configuration
if (-not $toolTarget) {
	Write-Error "Could not locate the built benchmark artifact. Build it first (omit -NoBuild)."
	exit 1
}

Write-Host "==> Running $(Split-Path -Leaf $toolTarget)" -ForegroundColor Cyan
Write-Host "    profile: $(if ($Quick) { 'quick' } else { 'full' })" -ForegroundColor DarkGray
Write-Host "    arguments: $($toolArgs -join ' ')" -ForegroundColor DarkGray

# Launched through `dotnet <TargetPath>`: TargetPath is the managed assembly, and naming the host keeps the
# run pinned to the SDK-resolved runtime instead of to whatever the shell would associate with the file.
$previousPreference = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
try {
	$toolOutput = & $dotnet $toolTarget @toolArgs 2>&1
	$exitCode = $LASTEXITCODE
}
finally {
	$ErrorActionPreference = $previousPreference
}

if ($null -eq $exitCode) { $exitCode = 1 }
$toolOutput | Out-Host

# ── Say where the report landed ──────────────────────────────────────────────────
$reportLines = $toolOutput |
	Select-String -Pattern 'wrote\s+(.+report\.(md|json))' |
	ForEach-Object { $_.Matches[0].Groups[1].Value.Trim() }
if (-not $reportLines) {
	$reportLines = $toolOutput |
		Select-String -Pattern '^(Markdown report|JSON report|Settings fragment):\s*(.+)$' |
		ForEach-Object { $_.Matches[0].Groups[2].Value.Trim() }
}

Write-Host ''
if ($reportLines) {
	Write-Host 'Report written to:' -ForegroundColor Green
	foreach ($line in $reportLines) { Write-Host "  $line" -ForegroundColor Green }
	Write-Host '  Start with report.md; recommended-settings.json is the fragment you may merge by hand.' -ForegroundColor DarkGray
	Write-Host '  Nothing was applied. Read docs/92-storage-benchmarks-and-tuning.md before changing a setting.' -ForegroundColor DarkGray
}
elseif ($exitCode -eq 2) {
	Write-Host 'The run refused to start. Nothing was measured and nothing was written.' -ForegroundColor Yellow
}
else {
	Write-Host 'No report path was found in the output above; the exit code says whether the run finished.' -ForegroundColor Yellow
}

exit $exitCode
