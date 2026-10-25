#Requires -Version 5.1
<#
.SYNOPSIS
    Enables MikroTik blocking in the RdpAudit service appsettings.json.

.DESCRIPTION
    Changes exactly two things: RdpAudit.mikroTik (router address, service account, TLS,
    filter chain) and RdpAudit.firewall.provider. Every other section is fingerprinted before
    the write and compared afterwards; on any difference the file is restored from the backup
    taken just before the change.

.EXAMPLE
    .\Set-RdpAuditMikroTik.ps1 -Gateway 192.168.1.1 -UserName rdpaudit -Password '***'
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Gateway,
    [int]$Port = 443,
    [Parameter(Mandatory = $true)][string]$UserName,
    [Parameter(Mandatory = $true)][string]$Password,
    [string]$ConfigPath = 'C:\ProgramData\RdpAudit\appsettings.json',
    [string]$FilterChain = 'input',
    [string]$FilterAction = 'drop',
    [string]$CommentPrefix = 'RdpAudit',
    [string]$CommentTemplate = 'RdpAudit auto-block',
    [switch]$UseHttp,
    [switch]$ValidateCertificate,
    [switch]$DryRun
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $ConfigPath)) { throw "config file not found: $ConfigPath" }

$raw = [IO.File]::ReadAllText($ConfigPath)
$doc = $raw | ConvertFrom-Json

# Fingerprints of every section we are NOT changing.
$touched = @('mikroTik', 'firewall')
$before = @{}
foreach ($prop in $doc.RdpAudit.PSObject.Properties) {
    if ($touched -contains $prop.Name) { continue }
    $before[$prop.Name] = ($prop.Value | ConvertTo-Json -Depth 40 -Compress)
}

# Apply the new values.
$mt = $doc.RdpAudit.mikroTik
if ($null -eq $mt) {
    $mt = New-Object PSObject
    $doc.RdpAudit | Add-Member -MemberType NoteProperty -Name mikroTik -Value $mt -Force
}

$settings = [ordered]@{
    enabled                   = $true
    addAttackerRules          = $true
    baseUrl                   = ''
    useHttps                  = (-not $UseHttp)
    host                      = $Gateway
    port                      = $Port
    userName                  = $UserName
    password                  = $Password
    timeoutSeconds            = 15
    addressList               = 'rdpaudit-block'
    filterChain               = $FilterChain
    filterAction              = $FilterAction
    commentTemplate           = $CommentTemplate
    commentPrefix             = $CommentPrefix
    validateServerCertificate = [bool]$ValidateCertificate
    maxOperationsPerMinute    = 120
    blockDurationDays         = 0
    blockDurationHours        = 1
    blockDurationMinutes      = 0
}
foreach ($key in $settings.Keys) {
    $mt | Add-Member -MemberType NoteProperty -Name $key -Value $settings[$key] -Force
}

$doc.RdpAudit.firewall | Add-Member -MemberType NoteProperty -Name provider -Value 'MikroTik' -Force

Write-Output ("mikroTik -> enabled=true host={0} port={1} scheme={2} user={3} validateCert={4}" -f $Gateway, $Port, $(if ($UseHttp) { 'http' } else { 'https' }), $UserName, [bool]$ValidateCertificate)
Write-Output ("firewall.provider -> MikroTik (autoBlockBruteForce={0})" -f $doc.RdpAudit.firewall.autoBlockBruteForce)

if ($DryRun) {
    Write-Output 'dry-run: file not changed'
    return
}

$stamp = (Get-Date).ToString('yyyyMMdd-HHmmss')
$backup = "$ConfigPath.bak-$stamp"
Copy-Item -LiteralPath $ConfigPath -Destination $backup -Force

$text = $doc | ConvertTo-Json -Depth 40
$temp = "$ConfigPath.tmp-$stamp"
$utf8 = New-Object System.Text.UTF8Encoding($false)
[IO.File]::WriteAllText($temp, $text, $utf8)

$check = [IO.File]::ReadAllText($temp) | ConvertFrom-Json
if ($check.RdpAudit.mikroTik.host -ne $Gateway -or $check.RdpAudit.firewall.provider -ne 'MikroTik') {
    Remove-Item -LiteralPath $temp -Force
    throw 'temp file validation failed - config left untouched'
}

Move-Item -LiteralPath $temp -Destination $ConfigPath -Force

$after = ([IO.File]::ReadAllText($ConfigPath) | ConvertFrom-Json).RdpAudit
$broken = @()
foreach ($name in $before.Keys) {
    $now = $after.PSObject.Properties[$name]
    if ($null -eq $now) { $broken += "$name (section vanished)"; continue }
    $nowJson = ($now.Value | ConvertTo-Json -Depth 40 -Compress)
    if ($nowJson -ne $before[$name]) { $broken += $name }
}

if ($broken.Count -gt 0) {
    Copy-Item -LiteralPath $backup -Destination $ConfigPath -Force
    throw ("unrelated sections changed: {0}; config restored from {1}" -f ($broken -join ', '), $backup)
}

Write-Output ("written; backup: {0}" -f $backup)
Write-Output ("unrelated sections unchanged: {0}" -f $before.Count)
