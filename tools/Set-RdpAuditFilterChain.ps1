#Requires -Version 5.1
<#
.SYNOPSIS
    Sets RdpAudit.mikroTik.filterChain (input | forward).

.DESCRIPTION
    Touches only that one value. Other sections are fingerprinted before the write and compared
    afterwards; on any difference the file is restored from the backup taken just before the change.

    Chain input matches traffic addressed to the router itself; chain forward matches traffic the
    router passes to the protected hosts. For blocking RDP clients, forward is the chain that sees
    them.

.EXAMPLE
    .\Set-RdpAuditFilterChain.ps1 -Chain forward
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][ValidateSet('input', 'forward')][string]$Chain,
    [string]$ConfigPath = 'C:\ProgramData\RdpAudit\appsettings.json',
    [switch]$DryRun
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $ConfigPath)) { throw "config file not found: $ConfigPath" }

$raw = [IO.File]::ReadAllText($ConfigPath)
$doc = $raw | ConvertFrom-Json

$before = @{}
foreach ($prop in $doc.RdpAudit.PSObject.Properties) {
    if ($prop.Name -eq 'mikroTik') { continue }
    $before[$prop.Name] = ($prop.Value | ConvertTo-Json -Depth 40 -Compress)
}
$mtBefore = ($doc.RdpAudit.mikroTik | ConvertTo-Json -Depth 40 -Compress)

$previous = [string]$doc.RdpAudit.mikroTik.filterChain
$doc.RdpAudit.mikroTik | Add-Member -MemberType NoteProperty -Name filterChain -Value $Chain -Force
Write-Output ("mikroTik.filterChain: {0} -> {1}" -f $previous, $Chain)
Write-Output ("filterAction={0} commentPrefix={1} host={2}" -f $doc.RdpAudit.mikroTik.filterAction, $doc.RdpAudit.mikroTik.commentPrefix, $doc.RdpAudit.mikroTik.host)

if ($DryRun) {
    Write-Output 'dry-run: file not changed'
    return
}

$stamp = (Get-Date).ToString('yyyyMMdd-HHmmss')
$backup = "$ConfigPath.bak-$stamp"
Copy-Item -LiteralPath $ConfigPath -Destination $backup -Force

$temp = "$ConfigPath.tmp-$stamp"
$utf8 = New-Object System.Text.UTF8Encoding($false)
[IO.File]::WriteAllText($temp, ($doc | ConvertTo-Json -Depth 40), $utf8)

if (([IO.File]::ReadAllText($temp) | ConvertFrom-Json).RdpAudit.mikroTik.filterChain -ne $Chain) {
    Remove-Item -LiteralPath $temp -Force
    throw 'temp file validation failed - config left untouched'
}

Move-Item -LiteralPath $temp -Destination $ConfigPath -Force

$after = ([IO.File]::ReadAllText($ConfigPath) | ConvertFrom-Json).RdpAudit
$broken = @()
foreach ($name in $before.Keys) {
    $now = $after.PSObject.Properties[$name]
    if ($null -eq $now) { $broken += "$name (section vanished)"; continue }
    if (($now.Value | ConvertTo-Json -Depth 40 -Compress) -ne $before[$name]) { $broken += $name }
}

if ($broken.Count -gt 0) {
    Copy-Item -LiteralPath $backup -Destination $ConfigPath -Force
    throw ("unrelated sections changed: {0}; config restored from {1}" -f ($broken -join ', '), $backup)
}

$mtAfter = ([IO.File]::ReadAllText($ConfigPath) | ConvertFrom-Json).RdpAudit.mikroTik | ConvertTo-Json -Depth 40 -Compress
Write-Output ("written; backup: {0}" -f $backup)
Write-Output ("unrelated sections unchanged: {0}; only chain differs in mikroTik: {1}" -f $before.Count, ($mtAfter -ne $mtBefore))
