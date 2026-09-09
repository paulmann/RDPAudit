# /* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
# Version: 1.0.0
# File   : benchmarks.ps1
# Project: RDPAudit
# Purpose: One-shot runner for the BenchmarkDotNet suite. Restores, builds in Release, and
#          launches BenchmarkSwitcher with any extra arguments forwarded to BenchmarkDotNet.
# Depends: .NET 8 SDK, tests/RdpAudit.Benchmarks/RdpAudit.Benchmarks.csproj
# Extends: Pass -Filter '*Ring*' to run a subset; -Filter '*' runs everything. Any argument
#          after -- is forwarded verbatim to BenchmarkDotNet (e.g. --job dry, --exporters json).

[CmdletBinding()]
param(
	[string] $Filter = '*',
	[string] $Configuration = 'Release',
	[Parameter(ValueFromRemainingArguments = $true)]
	[string[]] $ForwardedArgs
)

$ErrorActionPreference = 'Stop'
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$projectPath = Join-Path $scriptDir 'tests/RdpAudit.Benchmarks/RdpAudit.Benchmarks.csproj'

if (-not (Test-Path $projectPath)) {
	Write-Error "Benchmark project not found at $projectPath"
	exit 1
}

Write-Host "==> Restoring $projectPath" -ForegroundColor Cyan
dotnet restore $projectPath | Out-Host

Write-Host "==> Building $Configuration" -ForegroundColor Cyan
dotnet build $projectPath -c $Configuration --no-restore --nologo | Out-Host

Write-Host "==> Running BenchmarkDotNet (filter: $Filter)" -ForegroundColor Cyan
$runArgs = @('--no-build', '--no-restore', '-c', $Configuration, '--project', $projectPath, '--', '--filter', $Filter)
if ($ForwardedArgs) { $runArgs += $ForwardedArgs }

# BenchmarkDotNet insists on being run OUTSIDE the debugger and OUTSIDE tiered JIT;
# `dotnet run -c Release` already covers both.
dotnet run @runArgs
