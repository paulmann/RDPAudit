#Requires -Version 5.1
<#
.SYNOPSIS
    Sets RdpAudit.firewall.provider (None | Windows | MikroTik | Both).

.DESCRIPTION
    Touches only that one value. Other sections are fingerprinted before the write and compared
    afterwards; on any difference the file is restored from the backup taken just before the change.

.EXAMPLE
    .\Set-RdpAuditProvider.ps1 -Provider Both
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][ValidateSet('None', 'Windows', 'MikroTik', 'Both')][string]$Provider,
    [string]$ConfigPath = 'C:\ProgramData\RdpAudit\appsettings.json',
    [switch]$DryRun
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $ConfigPath)) { throw "config file not found: $ConfigPath" }

$raw = [IO.File]::ReadAllText($ConfigPath)
$doc = $raw | ConvertFrom-Json

$before = @{}
foreach ($prop in $doc.RdpAudit.PSObject.Properties) {
    if ($prop.Name -eq 'firewall') { continue }
    $before[$prop.Name] = ($prop.Value | ConvertTo-Json -Depth 40 -Compress)
}

$previous = [string]$doc.RdpAudit.firewall.provider
$doc.RdpAudit.firewall | Add-Member -MemberType NoteProperty -Name provider -Value $Provider -Force
Write-Output ("firewall.provider: {0} -> {1}" -f $previous, $Provider)

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

if (([IO.File]::ReadAllText($temp) | ConvertFrom-Json).RdpAudit.firewall.provider -ne $Provider) {
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

Write-Output ("written; backup: {0}; unrelated sections unchanged: {1}" -f $backup, $before.Count)
