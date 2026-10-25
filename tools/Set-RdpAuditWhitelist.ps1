#Requires -Version 5.1
<#
.SYNOPSIS
    Прописывает внутренние подсети в белый список блокировки RdpAudit.

.DESCRIPTION
    Правит только RdpAudit.firewall.whitelist. Остальные секции отпечатываются до записи и
    сверяются после; при расхождении файл восстанавливается из резервной копии.

    Белый список блокировки, а не тревог: тревоги по внутренним адресам продолжают создаваться,
    просто IP из этих диапазонов не отправляется в блокировку. Подавление тревог
    (Alerts.whitelistIps) намеренно не трогается — иначе реальный перебор изнутри перестанет
    быть виден.

.EXAMPLE
    .\Set-RdpAuditWhitelist.ps1 -Cidr '192.168.0.0/16','10.255.255.0/24'
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string[]]$Cidr,
    [string]$ConfigPath = 'C:\ProgramData\RdpAudit\appsettings.json',
    [switch]$DryRun
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $ConfigPath)) { throw "config file not found: $ConfigPath" }

$raw = [IO.File]::ReadAllText($ConfigPath)
$doc = $raw | ConvertFrom-Json

$touched = @('firewall')
$before = @{}
foreach ($prop in $doc.RdpAudit.PSObject.Properties) {
    if ($touched -contains $prop.Name) { continue }
    $before[$prop.Name] = ($prop.Value | ConvertTo-Json -Depth 40 -Compress)
}
$firewallBefore = ($doc.RdpAudit.firewall | ConvertTo-Json -Depth 40 -Compress)

$list = New-Object System.Collections.ArrayList
foreach ($entry in $Cidr) {
    if (-not [string]::IsNullOrWhiteSpace($entry)) { [void]$list.Add($entry.Trim()) }
}
$doc.RdpAudit.firewall | Add-Member -MemberType NoteProperty -Name whitelist -Value @($list) -Force

Write-Output ("firewall.whitelist -> {0}" -f (($list) -join ', '))
Write-Output ("firewall.provider  = {0}; alerts.whitelistIps untouched" -f $doc.RdpAudit.firewall.provider)

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
if (@($check.RdpAudit.firewall.whitelist).Count -ne $list.Count) {
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

$firewallAfter = ([IO.File]::ReadAllText($ConfigPath) | ConvertFrom-Json).RdpAudit.firewall | ConvertTo-Json -Depth 40 -Compress
Write-Output ("written; backup: {0}" -f $backup)
Write-Output ("unrelated sections unchanged: {0}; firewall section changed as intended: {1}" -f $before.Count, ($firewallAfter -ne $firewallBefore))
