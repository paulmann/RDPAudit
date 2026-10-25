#Requires -Version 7.6
#Requires -PSEdition Core

<#
.SYNOPSIS
    Checks the documentation contracts of the RDPAudit repository without a .NET SDK.

.DESCRIPTION
    The solution guards several document artefacts with xUnit scenario tests
    (RepositoryHygieneScenarioTests, DocumentationDriftScenarioTests). Those
    tests cannot run in an environment that has only the .NET runtime, so this
    script re-implements the same checks in pure PowerShell. Use it before
    committing documentation or source changes, and always before handing work
    to CI.

    Covered checks:
      1. CHANGELOG.md machine-journal format.
      2. docs/50-ipc.md mentions every IpcCommand enum name.
      3. docs/51-rest-api.md mentions every path in openapi-v1.json.
      4. README.md / README.ru.md use only current worker names.
      5. PROJECT_MAP.md lists every src/ and tests/ *.cs file.
      6. Any "// Version:" header is a canonical M.N.P triple.
      7. GitHub workflows stay on Windows runners.

    Read-only: the script never writes to the repository.

.OUTPUTS
    Exit code 0 when every check passes, 1 when at least one check fails.

.EXAMPLE
    pwsh -NoLogo -NoProfile -NonInteractive -File .\tools\Invoke-DocContractCheck.ps1

.EXAMPLE
    pwsh -NoLogo -NoProfile -NonInteractive -File .\tools\Invoke-DocContractCheck.ps1 -RepoRoot C:\1st_RdpMON\Service
#>

[CmdletBinding()]
param(
    [string] $RepoRoot = (Split-Path -Parent $PSScriptRoot),
    [int] $MaxExamples = 10
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$RepoRoot = [System.IO.Path]::GetFullPath($RepoRoot)

if (-not (Test-Path -LiteralPath (Join-Path $RepoRoot 'RdpAudit.sln') -PathType Leaf)) {
    throw "Not a RDPAudit repository root: $RepoRoot"
}

function Read-RepoText {
    param([Parameter(Mandatory)][string] $RelativePath)

    $full = Join-Path $RepoRoot $RelativePath
    if (-not (Test-Path -LiteralPath $full -PathType Leaf)) { return $null }
    return [System.IO.File]::ReadAllText($full)
}

function Get-RelativeRepoPath {
    param([Parameter(Mandatory)][string] $FullPath)

    return ([System.IO.Path]::GetRelativePath($RepoRoot, $FullPath)) -replace '\\', '/'
}

function Get-SourceFiles {
    param([Parameter(Mandatory)][string] $TopDirectory)

    $root = Join-Path $RepoRoot $TopDirectory
    if (-not (Test-Path -LiteralPath $root -PathType Container)) { return @() }

    return @(
        Get-ChildItem -LiteralPath $root -Recurse -File -Filter '*.cs' |
            Where-Object {
                $relative = Get-RelativeRepoPath $_.FullName
                $relative -notmatch '(^|/)(bin|obj)/'
            } |
            Sort-Object FullName
    )
}

function New-CheckResult {
    param(
        [Parameter(Mandatory)][string] $Name,
        [Parameter(Mandatory)][bool] $Ok,
        [string[]] $Details = @()
    )

    [pscustomobject]@{
        Name    = $Name
        Ok      = $Ok
        Details = $Details
    }
}

function Test-ChangelogFormat {
    $text = Read-RepoText 'CHANGELOG.md'
    if ($null -eq $text) {
        return New-CheckResult -Name 'CHANGELOG.md machine-journal format' -Ok $false -Details @('CHANGELOG.md is missing at the repository root.')
    }

    $lines = $text -split "`n"
    $problems = [System.Collections.Generic.List[string]]::new()

    if ($lines.Count -lt 3) { $problems.Add('CHANGELOG.md has fewer than 3 lines.') }
    if ($lines.Count -ge 1 -and $lines[0].Trim() -ne '# Service Changelog') { $problems.Add("line 1 must be '# Service Changelog', found: '$($lines[0].Trim())'") }
    if ($lines.Count -ge 3 -and $lines[2].Trim() -ne 'Automatically maintained by DevAgent.') { $problems.Add("line 3 must be 'Automatically maintained by DevAgent.', found: '$($lines[2].Trim())'") }

    for ($i = 3; $i -lt $lines.Count; $i++) {
        $line = $lines[$i]
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        if ($line -notmatch '^- \[\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\] \S') {
            $problems.Add("line $($i + 1) is not a journal entry: '$line'")
        }
    }

    return New-CheckResult -Name 'CHANGELOG.md machine-journal format' -Ok ($problems.Count -eq 0) -Details $problems
}

function Test-IpcOperatorReference {
    $source = Read-RepoText 'src/RdpAudit.Core/Ipc/IpcCommand.cs'
    if ($null -eq $source) {
        return New-CheckResult -Name 'docs/50-ipc.md covers every IpcCommand' -Ok $false -Details @('src/RdpAudit.Core/Ipc/IpcCommand.cs is missing.')
    }

    $document = Read-RepoText 'docs/50-ipc.md'
    if ($null -eq $document) {
        return New-CheckResult -Name 'docs/50-ipc.md covers every IpcCommand' -Ok $false -Details @('docs/50-ipc.md is missing.')
    }

    $enumMatch = [regex]::Match($source, 'enum\s+IpcCommand\s*\{(?<body>.*?)\n\}', 'Singleline')
    if (-not $enumMatch.Success) {
        return New-CheckResult -Name 'docs/50-ipc.md covers every IpcCommand' -Ok $false -Details @('Unable to locate the IpcCommand enum body; update this check after refactoring.')
    }

    $names = [System.Collections.Generic.List[string]]::new()
    foreach ($line in ($enumMatch.Groups['body'].Value -split "`n")) {
        $nameMatch = [regex]::Match($line, '^\s*(?<name>[A-Za-z_][A-Za-z0-9_]*)\s*=')
        if ($nameMatch.Success) { $names.Add($nameMatch.Groups['name'].Value) }
    }

    if ($names.Count -eq 0) {
        return New-CheckResult -Name 'docs/50-ipc.md covers every IpcCommand' -Ok $false -Details @('IpcCommand enum appears to declare no explicitly numbered members; update this check.')
    }

    $missing = @($names | Where-Object { -not $document.Contains($_) })
    return New-CheckResult -Name "docs/50-ipc.md covers every IpcCommand ($($names.Count) names)" -Ok ($missing.Count -eq 0) -Details $missing
}

function Test-RestApiDescriptorReference {
    $descriptorRelative = 'src/RdpAudit.Service/RestApi/openapi-v1.json'
    $descriptor = Read-RepoText $descriptorRelative
    if ($null -eq $descriptor) {
        return New-CheckResult -Name 'docs/51-rest-api.md covers every descriptor path' -Ok $false -Details @("$descriptorRelative is missing.")
    }

    $document = Read-RepoText 'docs/51-rest-api.md'
    if ($null -eq $document) {
        return New-CheckResult -Name 'docs/51-rest-api.md covers every descriptor path' -Ok $false -Details @('docs/51-rest-api.md is missing.')
    }

    $problems = [System.Collections.Generic.List[string]]::new()
    if (-not $document.Contains($descriptorRelative)) {
        $problems.Add("docs/51-rest-api.md must reference $descriptorRelative")
    }

    $spec = $descriptor | ConvertFrom-Json -AsHashtable
    if (-not $spec.ContainsKey('paths')) {
        return New-CheckResult -Name 'docs/51-rest-api.md covers every descriptor path' -Ok $false -Details @('openapi-v1.json has no "paths" object; update this check.')
    }

    foreach ($path in $spec['paths'].Keys) {
        if (-not $document.Contains('`' + $path + '`')) {
            $problems.Add("docs/51-rest-api.md does not mention path `$path` (backtick-quoted)")
        }
    }

    return New-CheckResult -Name "docs/51-rest-api.md covers every descriptor path ($($spec['paths'].Keys.Count) paths)" -Ok ($problems.Count -eq 0) -Details $problems
}

function Test-ReadmeWorkerNames {
    $retired = @('EventCollectorWorker', 'EventNormalizerWorker', 'AlertEvaluatorWorker')
    $current = @('EventCollectorHostedWorker', 'EventProcessorWorker', 'AlertWorker')
    $problems = [System.Collections.Generic.List[string]]::new()

    foreach ($readme in @('README.md', 'README.ru.md')) {
        $text = Read-RepoText $readme
        if ($null -eq $text) {
            $problems.Add("$readme is missing.")
            continue
        }

        foreach ($name in $retired) {
            if ([regex]::IsMatch($text, "\b$name\b")) { $problems.Add("$readme uses the retired worker name $name") }
        }

        foreach ($name in $current) {
            if (-not $text.Contains($name)) { $problems.Add("$readme must mention $name") }
        }
    }

    return New-CheckResult -Name 'README pipeline worker names are current' -Ok ($problems.Count -eq 0) -Details $problems
}

function Test-ProjectMapCoverage {
    $map = Read-RepoText 'PROJECT_MAP.md'
    if ($null -eq $map) {
        return New-CheckResult -Name 'PROJECT_MAP.md covers every source file' -Ok $false -Details @('PROJECT_MAP.md is missing.')
    }

    $files = @(Get-SourceFiles 'src') + @(Get-SourceFiles 'tests')
    $missing = [System.Collections.Generic.List[string]]::new()

    foreach ($file in $files) {
        $relative = Get-RelativeRepoPath $file.FullName
        if (-not $map.Contains($relative)) { $missing.Add($relative) }
    }

    return New-CheckResult -Name "PROJECT_MAP.md covers every source file ($($files.Count) files)" -Ok ($missing.Count -eq 0) -Details $missing
}

function Test-VersionHeaders {
    $files = @(Get-SourceFiles 'src') + @(Get-SourceFiles 'tests')
    $offenders = [System.Collections.Generic.List[string]]::new()

    foreach ($file in $files) {
        $lineNumber = 0
        foreach ($line in [System.IO.File]::ReadLines($file.FullName)) {
            $lineNumber++
            if ($line -notmatch '^\s*//\s*Version\s*:') { continue }
            if ($line -notmatch '^\s*//\s*Version\s*:\s*\d{1,3}\.\d{1,3}\.\d{1,3}\s*$') {
                $offenders.Add("$(Get-RelativeRepoPath $file.FullName):$lineNumber -> '$($line.Trim())'")
            }
        }
    }

    return New-CheckResult -Name 'Version headers are canonical triples or absent' -Ok ($offenders.Count -eq 0) -Details $offenders
}

function Test-CiRunners {
    $workflowsDirectory = Join-Path $RepoRoot '.github/workflows'
    if (-not (Test-Path -LiteralPath $workflowsDirectory -PathType Container)) {
        return New-CheckResult -Name 'CI workflows stay on Windows runners' -Ok $true -Details @('.github/workflows does not exist; nothing to check.')
    }

    $problems = [System.Collections.Generic.List[string]]::new()
    foreach ($workflow in (Get-ChildItem -LiteralPath $workflowsDirectory -File | Where-Object { $_.Extension -in @('.yml', '.yaml') })) {
        $lineNumber = 0
        foreach ($line in [System.IO.File]::ReadLines($workflow.FullName)) {
            $lineNumber++
            $runnerMatch = [regex]::Match($line, '^\s*runs-on\s*:\s*(?<runner>.+)$')
            if (-not $runnerMatch.Success) { continue }

            $runner = $runnerMatch.Groups['runner'].Value.Trim()
            if ($runner -notmatch 'windows') {
                $problems.Add("$(Get-RelativeRepoPath $workflow.FullName):$lineNumber runs on '$runner'")
            }
        }
    }

    return New-CheckResult -Name 'CI workflows stay on Windows runners' -Ok ($problems.Count -eq 0) -Details $problems
}

$checks = @(
    Test-ChangelogFormat
    Test-IpcOperatorReference
    Test-RestApiDescriptorReference
    Test-ReadmeWorkerNames
    Test-ProjectMapCoverage
    Test-VersionHeaders
    Test-CiRunners
)

$failed = 0
$padding = 0
foreach ($check in $checks) {
    if ($check.Name.Length -gt $padding) { $padding = $check.Name.Length }
}

Write-Host "RDPAudit documentation contract check"
Write-Host "repository: $RepoRoot"
Write-Host ''

foreach ($check in $checks) {
    if ($check.Ok) {
        Write-Host ("[PASS] " + $check.Name.PadRight($padding)) -ForegroundColor Green
        continue
    }

    $failed++
    Write-Host ("[FAIL] " + $check.Name.PadRight($padding)) -ForegroundColor Red
    $shown = @($check.Details | Select-Object -First $MaxExamples)
    foreach ($detail in $shown) { Write-Host "         $detail" }
    if ($check.Details.Count -gt $shown.Count) {
        Write-Host "         ... and $($check.Details.Count - $shown.Count) more"
    }
}

Write-Host ''
Write-Host ("checks: $($checks.Count), failed: $failed")

if ($failed -gt 0) {
    Write-Host 'Result: FAIL - fix the reported items before publishing or committing.' -ForegroundColor Red
    exit 1
}

Write-Host 'Result: PASS' -ForegroundColor Green
exit 0
