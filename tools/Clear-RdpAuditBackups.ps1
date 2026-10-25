#Requires -Version 7.6
#Requires -PSEdition Core
<#
.SYNOPSIS
    Освобождает место в C:\ProgramData\RdpAudit\Backups, не теряя точку отката схемы.

.DESCRIPTION
    В каталоге Backups лежат три разных вида записей, и удалять их «по возрасту» нельзя:
      * снапшот продукта (каталог YYYYMMDD-HHMMSS с manifest.json и вложенным db\rdpaudit.db) —
        точка отката схемы, её делает инициализатор перед миграцией и её узнаёт Configurator;
      * копия, сделанная обновлением (service-before-* или ручной pre-*): папка службы и, если
        копировали БД, плоский rdpaudit.db рядом;
      * снимок состояния установки (каталог без БД: metadata.json, registry, service.config.txt,
        audit-policy.csv) — крошечный и исторический.
    Инструмент удаляет ТОЛЬКО payload БД (rdpaudit.db, -wal, -shm) из копий обновления, оставляя
    папку службы и всё остальное. Снапшот продукта не трогается никогда. Если снапшота продукта
    нет, чистка на этом хосте отменяется: остаться без единой копии БД нельзя.

.PARAMETER SandboxPath
    Прогон той же логики на локальном каталоге-песочнице (структура как у Backups), без сети.

.EXAMPLE
    .\Clear-RdpAuditBackups.ps1 -SandboxPath C:\Temp\sbx-backups -DryRun
.EXAMPLE
    .\Clear-RdpAuditBackups.ps1 -HostsFile .\fleet-hosts.txt -DryRun
.EXAMPLE
    .\Clear-RdpAuditBackups.ps1 -HostsFile .\fleet-hosts.txt -Confirm:$false
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [string[]]$Hosts = @(),
    [string]$HostsFile,
    [string]$User = 'md',
    [string]$KeyPath = (Join-Path ([Environment]::GetFolderPath('UserProfile')) '.ssh\id_zabbix_ops'),
    [string]$RemoteDataDir = 'C:\ProgramData\RdpAudit',
    [string]$SandboxPath,
    [switch]$DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:SshPath = 'C:\Program Files\Git\usr\bin\ssh.exe'

function Format-Size {
    param([int64]$Bytes)
    if ($Bytes -ge 1GB) { return ('{0:N2} ГБ' -f ($Bytes / 1GB)) }
    if ($Bytes -ge 1MB) { return ('{0:N1} МБ' -f ($Bytes / 1MB)) }
    return ('{0:N0} КБ' -f ($Bytes / 1KB))
}

function Invoke-Ssh {
    param([string]$Computer, [string]$Command)
    $raw = & $script:SshPath -i $KeyPath -o BatchMode=yes -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 "$User@$Computer" $Command 2>&1
    ($raw | ForEach-Object { $_.ToString() } | Where-Object { $_ -notmatch 'post-quantum|store now, decrypt later|openssh\.com/pq' })
}

function Get-Inventory {
    <# Записи Backups: имя, есть ли плоская копия БД, есть ли снапшот продукта с БД.
       На хосте это ОДИН ssh-вызов на инвентарь: два прохода с маркерами F:/N:. #>
    param([string]$Computer, [string]$BackupsRoot)

    if ($SandboxPath) {
        $dirs = Get-ChildItem -LiteralPath $BackupsRoot -Directory | Sort-Object Name -Descending
        foreach ($d in $dirs) {
            $flat = Join-Path $d.FullName 'rdpaudit.db'
            [pscustomobject]@{
                Name      = $d.Name
                HasFlat   = Test-Path -LiteralPath $flat
                HasNested = Test-Path -LiteralPath (Join-Path $d.FullName 'db\rdpaudit.db')
                DirPath   = $d.FullName
            }
        }
        return
    }

    $command = "for /d %A in ($BackupsRoot\*) do @if exist %~fA\rdpaudit.db echo F:%~nxA & echo --- & for /d %A in ($BackupsRoot\*) do @if exist %~fA\db\rdpaudit.db echo N:%~nxA"
    $lines = Invoke-Ssh -Computer $Computer -Command $command

    $flat = @{}
    $nested = @{}
    foreach ($line in $lines) {
        $text = $line.Trim()
        if ($text -like 'F:*') { $flat[$text.Substring(2).Trim()] = $true }
        elseif ($text -like 'N:*') { $nested[$text.Substring(2).Trim()] = $true }
    }

    $names = @($flat.Keys) + @($nested.Keys) | Sort-Object -Unique -Descending
    foreach ($name in $names) {
        [pscustomobject]@{
            Name      = $name
            HasFlat   = $flat.ContainsKey($name)
            HasNested = $nested.ContainsKey($name)
            DirPath   = "$BackupsRoot\$name"
        }
    }
}

function Remove-DbPayload {
    <# Удаляет payload БД одной копии. Возвращает фактически освобождённые байты (0 — не удалось). #>
    param([string]$Computer, [string]$DirPath, [switch]$Local)

    $files = @('rdpaudit.db', 'rdpaudit.db-wal', 'rdpaudit.db-shm')

    if ($Local) {
        $freed = [int64]0
        foreach ($file in $files) {
            $path = Join-Path $DirPath $file
            if (Test-Path -LiteralPath $path) {
                $freed += (Get-Item -LiteralPath $path).Length
                Remove-Item -LiteralPath $path -Force
            }
        }
        return $freed
    }

    $mainPath = "$DirPath\rdpaudit.db"
    $sizeLines = Invoke-Ssh -Computer $Computer -Command "for %A in ($mainPath) do @echo SIZE=%~zA"
    $expected = [int64]0
    foreach ($line in $sizeLines) { if ($line -match 'SIZE=(\d+)') { $expected = [int64]$Matches[1] } }

    [void](Invoke-Ssh -Computer $Computer -Command "del /f /q `"$mainPath`" `"$DirPath\rdpaudit.db-wal`" `"$DirPath\rdpaudit.db-shm`"")

    $still = Invoke-Ssh -Computer $Computer -Command "for %A in (`"$mainPath`") do @echo STILL=%~zA"
    foreach ($line in $still) { if ($line -match 'STILL=(\d+)') { return 0 } }
    return $expected
}

function Get-StripPlan {
    <# Возвращает записи, у которых можно убрать payload БД, либо $null с причиной отказа. #>
    param([object[]]$Entries)

    $keepers = @($Entries | Where-Object { $_.HasNested })
    if ($keepers.Count -eq 0) { return $null }
    $newestKeeper = ($keepers | Sort-Object Name -Descending | Select-Object -First 1).Name
    $targets = @($Entries | Where-Object { $_.HasFlat -and $_.Name -ne $newestKeeper })
    [pscustomobject]@{ Keep = $newestKeeper; Targets = $targets }
}

# ── Режим песочницы ────────────────────────────────────────────────────────────────────────
if ($SandboxPath) {
    if (-not (Test-Path -LiteralPath $SandboxPath)) { throw "нет каталога песочницы: $SandboxPath" }
    Write-Host "=== песочница: $SandboxPath ===" -ForegroundColor Cyan

    $entries = @(Get-Inventory -Computer '' -BackupsRoot $SandboxPath)
    $plan = Get-StripPlan -Entries $entries
    if ($null -eq $plan) { throw 'в песочнице нет снапшота продукта — чистка отменена' }
    Write-Host ("  снапшот продукта (сохраняется): {0}" -f $plan.Keep)

    $freed = [int64]0
    foreach ($entry in $plan.Targets) {
        if ($DryRun) {
            Write-Host ("  {0}: было бы удалено {1}" -f $entry.Name, (Format-Size (Get-Item -LiteralPath (Join-Path $entry.DirPath 'rdpaudit.db')).Length))
            continue
        }
        $bytes = Remove-DbPayload -Computer '' -DirPath $entry.DirPath -Local
        $freed += $bytes
        Write-Host ("  {0}: удалён payload БД, освобождено {1}" -f $entry.Name, (Format-Size $bytes)) -ForegroundColor Yellow
    }
    Write-Host ("  итого: {0}" -f (Format-Size $freed))
    return
}

# ── Хосты ──────────────────────────────────────────────────────────────────────────────────
if ($HostsFile) {
    if (-not (Test-Path -LiteralPath $HostsFile)) { throw "не найден список хостов: $HostsFile" }
    $Hosts = @($Hosts) + @(Get-Content -LiteralPath $HostsFile | ForEach-Object { $_.Trim() } | Where-Object { $_ -and -not $_.StartsWith('#') })
}

$Hosts = @($Hosts | ForEach-Object { $_ -split '[,;\s]+' } | ForEach-Object { $_.Trim() } | Where-Object { $_ } | Select-Object -Unique)
if ($Hosts.Count -eq 0) { throw 'не задан ни один хост: -Hosts или -HostsFile' }

$backupsRoot = "$RemoteDataDir\Backups"
$summary = [System.Collections.Generic.List[object]]::new()

foreach ($computer in $Hosts) {
    Write-Host ("=== {0} ===" -f $computer) -ForegroundColor Cyan
    $entries = @(Get-Inventory -Computer $computer -BackupsRoot $backupsRoot)
    if ($entries.Count -eq 0) {
        Write-Host '  в Backups нет каталогов'
        $summary.Add([pscustomobject]@{ Host = $computer; Freed = 0; Note = 'нет записей' })
        continue
    }

    $plan = Get-StripPlan -Entries $entries
    if ($null -eq $plan) {
        Write-Host '  НЕТ снапшота продукта с БД — чистка отменена (остаться без копии нельзя)' -ForegroundColor Red
        $summary.Add([pscustomobject]@{ Host = $computer; Freed = 0; Note = 'нет снапшота продукта — пропуск' })
        continue
    }

    Write-Host ("  копий с БД: {0}; снапшот {1} сохраняется; к удалению {2}" -f $entries.Count, $plan.Keep, $plan.Targets.Count)

    $freed = [int64]0
    $done = 0
    foreach ($entry in $plan.Targets) {
        if ($DryRun) {
            $size = Invoke-Ssh -Computer $computer -Command "for %A in ($($entry.DirPath)\rdpaudit.db) do @echo SIZE=%~zA"
            $bytes = [int64]0
            foreach ($line in $size) { if ($line -match 'SIZE=(\d+)') { $bytes = [int64]$Matches[1] } }
            Write-Host ("  удалить БД из {0} — {1}" -f $entry.Name, (Format-Size $bytes))
            continue
        }

        if (-not $PSCmdlet.ShouldProcess("$computer : $($entry.Name)", 'удалить payload БД')) { continue }

        $bytes = Remove-DbPayload -Computer $computer -DirPath $entry.DirPath
        if ($bytes -eq 0) {
            Write-Host ("  {0}: БД НЕ удалена (файл на месте)" -f $entry.Name) -ForegroundColor Red
            continue
        }
        $freed += $bytes
        $done++
        Write-Host ("  {0}: удалён payload БД, {1}" -f $entry.Name, (Format-Size $bytes)) -ForegroundColor Yellow
    }

    $summary.Add([pscustomobject]@{
            Host  = $computer
            Freed = $freed
            Note  = ("очищено {0}; снапшот {1} сохранён" -f $done, $plan.Keep)
        })
}

''
$summary | Select-Object Host, @{n = 'Освобождено'; e = { Format-Size $_.Freed } }, Note | Format-Table -AutoSize -Wrap
$totalFreed = ($summary | Measure-Object -Property Freed -Sum).Sum
Write-Host ("всего: {0}" -f (Format-Size ([int64]$totalFreed))) -ForegroundColor Green
