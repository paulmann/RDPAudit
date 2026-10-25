#Requires -Version 7.6
#Requires -PSEdition Core
<#
.SYNOPSIS
    Обновляет службу RdpAudit на нескольких Windows-машинах по SSH: бэкап, остановка, копирование,
    запуск, проверка. Один хост — один отчёт, откат — отдельным ключом.

.DESCRIPTION
    Процедура на каждом хосте:
      1. Предполёт: служба установлена и отвечает, SHA256 развёрнутого exe сверяется с публикацией (размер обманчив: разные сборки могут совпасть по длине).
      2. Бэкап папки службы в C:\ProgramData\RdpAudit\Backups\service-before-<stamp>. Копия БД по умолчанию
         НЕ делается: перед миграцией её и так снимает сам инициализатор (снапшот продукта), а лишняя копия
         на 2,5 ГБ только занимает место. Нужна — есть -IncludeDatabaseBackup.
      3. Остановка службы и ожидание STOPPED.
      4. Копирование публикации: scp во временный каталог, затем robocopy в папку службы (аддитивно,
         ничего не удаляется — откат остаётся тривиальным).
      5. Запуск, ожидание RUNNING, затем проверка ДОПИСАННЫХ строк лога: инициализация завершилась,
         миграция не провалилась, "table is locked" и "Persist batch of" отсутствуют.
    Хосты обрабатываются последовательно: параллельная остановка служб на одном шаблоне диска
    ничего не ускоряет, а диагностику делает хуже.

    Откат: -Rollback восстанавливает самый свежий каталог service-before-* и запускает службу.

.PARAMETER Hosts
    Адреса машин. Вместо списка можно дать -HostsFile с одним адресом в строке ('#' — комментарий).

.PARAMETER PublishPath
    Каталог публикации службы (там лежит RdpAudit.Service.exe). По умолчанию ..\publish\Service.

.PARAMETER DryRun
    Ничего не менять: только предполёт и план по каждому хосту.

.EXAMPLE
    .\Deploy-RdpAuditFleet.ps1 -Hosts 192.168.1.60,192.168.1.100 -DryRun

.EXAMPLE
    .\Deploy-RdpAuditFleet.ps1 -HostsFile .\fleet.txt -Confirm:$false
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [string[]]$Hosts = @(),
    [string]$HostsFile,
    [string]$PublishPath = (Join-Path $PSScriptRoot '..\publish\Service'),
    [string]$User = 'md',
    [string]$KeyPath = (Join-Path ([Environment]::GetFolderPath('UserProfile')) '.ssh\id_zabbix_ops'),
    [string]$ServiceName = 'RdpAuditService',
    [string]$RemoteServiceDir = 'C:\PROGRA~1\RdpAudit\Service',
    [string]$RemoteDataDir = 'C:\ProgramData\RdpAudit',
    [string]$JournalPath = (Join-Path ([IO.Path]::Combine([Environment]::GetFolderPath('LocalApplicationData'), 'RdpAuditFleet')) 'journal.jsonl'),
    [int]$StartTimeoutSeconds = 300,
    [switch]$DryRun,
    [switch]$IncludeDatabaseBackup,
    [switch]$Rollback
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:SshPath = 'C:\Program Files\Git\usr\bin\ssh.exe'
$script:ScpPath = 'C:\Program Files\Git\usr\bin\scp.exe'

if (-not (Test-Path -LiteralPath $script:SshPath)) { throw "не найден ssh: $script:SshPath" }
if (-not (Test-Path -LiteralPath $script:ScpPath)) { throw "не найден scp: $script:ScpPath" }
if (-not (Test-Path -LiteralPath $KeyPath)) { throw "не найден ключ: $KeyPath" }

if ($HostsFile) {
    if (-not (Test-Path -LiteralPath $HostsFile)) { throw "не найден список хостов: $HostsFile" }
    $fromFile = Get-Content -LiteralPath $HostsFile |
        ForEach-Object { $_.Trim() } |
        Where-Object { $_ -and -not $_.StartsWith('#') }
    $Hosts = @($Hosts) + @($fromFile)
}

$Hosts = @($Hosts |
    ForEach-Object { $_ -split '[,;\s]+' } |
    ForEach-Object { $_.Trim() } |
    Where-Object { $_ } |
    Select-Object -Unique)
if ($Hosts.Count -eq 0) { throw 'не задан ни один хост: -Hosts или -HostsFile' }

$localExe = Join-Path $PublishPath 'RdpAudit.Service.exe'
if (-not $Rollback -and -not (Test-Path -LiteralPath $localExe)) {
    throw "в публикации нет RdpAudit.Service.exe: $PublishPath (сначала publish.ps1)"
}

$localExeSize = if (Test-Path -LiteralPath $localExe) { (Get-Item -LiteralPath $localExe).Length } else { 0 }
$localExeHash = if (Test-Path -LiteralPath $localExe) { (Get-FileHash -LiteralPath $localExe -Algorithm SHA256).Hash } else { "" }
$localExeSha = if (Test-Path -LiteralPath $localExe) { (Get-FileHash -LiteralPath $localExe -Algorithm SHA256).Hash } else { '' }

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$results = [System.Collections.Generic.List[object]]::new()

function Invoke-Remote {
    <# Выполняет команду cmd на хосте. Возвращает вывод без предупреждений ssh и код возврата. #>
    param([string]$Computer, [string]$Command, [int]$TimeoutSeconds = 120)

    $arguments = @(
        '-i', $KeyPath,
        '-o', 'BatchMode=yes',
        '-o', 'StrictHostKeyChecking=accept-new',
        '-o', 'ConnectTimeout=10',
        "-o", "ServerAliveInterval=15",
        "$User@$Computer",
        $Command
    )

    $raw = & $script:SshPath @arguments 2>&1
    $exitCode = $LASTEXITCODE
    $text = ($raw | ForEach-Object {
            $line = $_.ToString()
            if ($line -match 'post-quantum|store now, decrypt later|openssh\.com/pq') { return }
            $line
        }) -join "`n"

    [pscustomobject]@{ Output = $text.Trim(); ExitCode = $exitCode }
}

function Get-ServiceState {
    param([string]$Computer)
    $r = Invoke-Remote -Computer $Computer -Command "sc query $ServiceName"
    if ($r.Output -match '(\d+)\s+(RUNNING|STOPPED|START_PENDING|STOP_PENDING|PAUSED)') {
        return $Matches[2]
    }

    # ssh вернул 255 — хост недоступен или ключ не принят; это не то же самое, что нет службы.
    if ($r.ExitCode -eq 255) { return 'UNREACHABLE' }
    return 'ABSENT'
}

function Wait-ServiceState {
    param([string]$Computer, [string]$Expected, [int]$TimeoutSeconds)
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    do {
        $state = Get-ServiceState -Computer $Computer
        if ($state -eq $Expected) { return $true }
        if ($state -eq 'ABSENT') { return $false }
        Start-Sleep -Seconds 3
    } while ((Get-Date) -lt $deadline)
    return $false
}

function Get-RemoteFileSize {
    param([string]$Computer, [string]$Path)
    $r = Invoke-Remote -Computer $Computer -Command "for %A in ($Path) do @echo SIZE=%~zA"
    if ($r.Output -match 'SIZE=(\d+)') { return [int64]$Matches[1] }
    return -1
}

function Get-RemoteFileHash {
    param([string]$Computer, [string]$Path)
    # certutil печатает хеш отдельной строкой; формат зависит от локали, поэтому берём первую
    # строку, целиком состоящую из 64 hex-символов.
    $r = Invoke-Remote -Computer $Computer -Command "certutil -hashfile $Path SHA256"
    foreach ($line in ($r.Output -split "\r?\n")) {
        $candidate = $line.Trim() -replace '\s', ''
        if ($candidate -match '^[0-9a-fA-F]{64}$') { return $candidate.ToUpperInvariant() }
    }
    return ""
}
function Get-RemoteLogLineCount {
    param([string]$Computer, [string]$Path)
    $r = Invoke-Remote -Computer $Computer -Command "find /c /v `"`" $Path"
    if ($r.Output -match ':\s*(\d+)\s*$') { return [int]$Matches[1] }
    if ($r.Output -match '^\s*(\d+)\s*$') { return [int]$Matches[1] }
    return 0
}

function Write-Journal {
    param([hashtable]$Record)
    $dir = [IO.Path]::GetDirectoryName($JournalPath)
    if ($dir -and -not (Test-Path -LiteralPath $dir)) { [void](New-Item -ItemType Directory -Path $dir -Force) }
    ($Record | ConvertTo-Json -Compress) | Add-Content -LiteralPath $JournalPath -Encoding utf8NoBOM
}

function Invoke-Rollback {
    param([string]$Computer, [string]$Result)

    $r = Invoke-Remote -Computer $Computer -Command "dir /b /ad /o-d $RemoteDataDir\Backups\service-before-*"
    if ($r.ExitCode -ne 0 -or -not $r.Output) { return 'нет каталога service-before-* — откат невозможен' }

    $newest = ($r.Output -split "`n" | Where-Object { $_.Trim() } | Select-Object -First 1).Trim()
    $backupDir = "$RemoteDataDir\Backups\$newest"

    [void](Invoke-Remote -Computer $Computer -Command "sc stop $ServiceName" -TimeoutSeconds 120)
    [void](Wait-ServiceState -Computer $Computer -Expected 'STOPPED' -TimeoutSeconds 120)
    $copy = Invoke-Remote -Computer $Computer -Command "robocopy $backupDir $RemoteServiceDir /E /NFL /NDL /NJH /NP /R:1 /W:1"
    if ($copy.ExitCode -ge 8) { return "robocopy из $backupDir не удался (код $($copy.ExitCode))" }
    [void](Invoke-Remote -Computer $Computer -Command "sc start $ServiceName")
    $up = Wait-ServiceState -Computer $Computer -Expected 'RUNNING' -TimeoutSeconds 120

    $state = Get-ServiceState -Computer $Computer
    if ($state -eq 'RUNNING') { return "откат выполнен из $newest, служба RUNNING" }
    return "откат выполнен из $newest, но служба в состоянии $state"
}

foreach ($computer in $Hosts) {
    $report = [ordered]@{
        Host    = $computer
        Before  = 'unknown'
        After   = 'unknown'
        Action  = ''
        Detail  = ''
    }

    Write-Host ("=== {0} ===" -f $computer) -ForegroundColor Cyan

    $state = Get-ServiceState -Computer $computer
    if ($state -eq 'UNREACHABLE') {
        $report.Action = 'unreachable'
        $report.Detail = 'нет SSH-доступа (хост выключен или ключ не авторизован)'
        Write-Host '  хост недоступен по SSH — пропуск' -ForegroundColor Yellow
        $results.Add([pscustomobject]$report)
        continue
    }
    if ($state -eq 'ABSENT') {
        $report.Action = 'skipped'
        $report.Detail = 'служба не установлена или хост недоступен'
        Write-Host '  служба не найдена — пропуск' -ForegroundColor Yellow
        $results.Add([pscustomobject]$report)
        continue
    }
    $report.Before = $state

    if ($Rollback) {
        $detail = Invoke-Rollback -Computer $computer
        $report.Action = 'rollback'
        $report.After = Get-ServiceState -Computer $computer
        $report.Detail = $detail
        Write-Host ("  {0}" -f $detail) -ForegroundColor Yellow
        $results.Add([pscustomobject]$report)
        Write-Journal @{ Time = (Get-Date).ToString('o'); Host = $computer; Action = 'rollback'; Detail = $detail }
        continue
    }

    $remoteExeSize = Get-RemoteFileSize -Computer $computer -Path "$RemoteServiceDir\RdpAudit.Service.exe"
    if ($remoteExeSize -lt 0) {
        $report.Action = 'skipped'
        $report.Detail = 'exe службы не найден по ожидаемому пути'
        Write-Host '  exe не найден — пропуск' -ForegroundColor Yellow
        $results.Add([pscustomobject]$report)
        continue
    }

    # Размер НЕ доказывает идентичность сборки: замерено 23.10.2026, две разные сборки имели
    # одинаковую длину 52 914 712 байт, и пропуск доставки оставил на хосте старый код.
    $remoteExeHash = Get-RemoteFileHash -Computer $computer -Path "$RemoteServiceDir\RdpAudit.Service.exe"
    if ($remoteExeHash -and $localExeHash -and $remoteExeHash -eq $localExeHash) {
        $report.Action = 'up-to-date'
        $report.Detail = ("уже развёрнута эта сборка (sha256 {0})" -f $remoteExeHash.Substring(0, 12))
        Write-Host ("  уже эта сборка: sha256 {0}… — пропуск" -f $remoteExeHash.Substring(0, 12)) -ForegroundColor Green
        $results.Add([pscustomobject]$report)
        continue
    }

    if (-not $remoteExeHash) {
        Write-Host ("  хеш удалённого exe не получен — доставка будет выполнена, размер {0} байт" -f $remoteExeSize) -ForegroundColor Yellow
    }

    Write-Host ("  служба: {0}; exe {1} байт → {2} байт" -f $state, $remoteExeSize, $localExeSize)

    if ($DryRun) {
        $report.Action = 'would-upgrade'
        $report.Detail = ("{0} → {1} байт; бэкап в {2}\Backups\service-before-{3}" -f $remoteExeSize, $localExeSize, $RemoteDataDir, $stamp)
        Write-Host '  DryRun: изменения не вносятся' -ForegroundColor Yellow
        $results.Add([pscustomobject]$report)
        continue
    }

    $target = "служба на $computer"
    if (-not $PSCmdlet.ShouldProcess($target, "обновить до сборки $localExeSha")) {
        $report.Action = 'declined'
        $results.Add([pscustomobject]$report)
        continue
    }

    # ── 1. Бэкап папки службы ───────────────────────────────────────────────────
    $backupDir = "$RemoteDataDir\Backups\service-before-$stamp"
    $backup = Invoke-Remote -Computer $computer -Command "robocopy $RemoteServiceDir $backupDir /E /NFL /NDL /NJH /NP /R:1 /W:1" -TimeoutSeconds 300
    if ($backup.ExitCode -ge 8) {
        $report.Action = 'failed'
        $report.Detail = "бэкап папки службы не удался (код $($backup.ExitCode)) — обновление отменено"
        Write-Host ("  {0}" -f $report.Detail) -ForegroundColor Red
        $results.Add([pscustomobject]$report)
        continue
    }
    Write-Host "  бэкап папки службы: $backupDir"

    # ── 2. Остановка ────────────────────────────────────────────────────────────
    [void](Invoke-Remote -Computer $computer -Command "sc stop $ServiceName")
    if (-not (Wait-ServiceState -Computer $computer -Expected 'STOPPED' -TimeoutSeconds 180)) {
        $report.Action = 'failed'
        $report.Detail = "служба не остановилась (состояние $(Get-ServiceState -Computer $computer))"
        Write-Host ("  {0}" -f $report.Detail) -ForegroundColor Red
        $results.Add([pscustomobject]$report)
        continue
    }
    Write-Host '  служба остановлена'

    # ── 3. Бэкап БД (opt-in; только при остановленной службе — WAL схлопнут) ────
    if ($IncludeDatabaseBackup) {
        $dbCopy = Invoke-Remote -Computer $computer -Command "copy /y $RemoteDataDir\rdpaudit.db $backupDir\rdpaudit.db" -TimeoutSeconds 900
        if ($dbCopy.ExitCode -ne 0) {
            [void](Invoke-Remote -Computer $computer -Command "sc start $ServiceName")
            $report.Action = 'failed'
            $report.Detail = 'копия БД не удалась — служба запущена обратно, обновление отменено'
            Write-Host ("  {0}" -f $report.Detail) -ForegroundColor Red
            $results.Add([pscustomobject]$report)
            continue
        }
        Write-Host '  копия БД сделана'
    }

    # ── 4. Доставка публикации ──────────────────────────────────────────────────
    $stageDir = "C:/Windows/Temp/rdpaudit-stage-$stamp"
    $stageWin = "C:\Windows\Temp\rdpaudit-stage-$stamp"
    & $script:ScpPath -i $KeyPath -o BatchMode=yes -o StrictHostKeyChecking=accept-new -r $PublishPath "$User@${computer}:$stageDir" 2>&1 |
        Where-Object { $_ -notmatch 'post-quantum|store now|openssh\.com/pq' } | Out-Null
    if ($LASTEXITCODE -ne 0) {
        [void](Invoke-Remote -Computer $computer -Command "sc start $ServiceName")
        $report.Action = 'failed'
        $report.Detail = "scp завершился с кодом $LASTEXITCODE — служба запущена обратно"
        Write-Host ("  {0}" -f $report.Detail) -ForegroundColor Red
        $results.Add([pscustomobject]$report)
        continue
    }

    $copy = Invoke-Remote -Computer $computer -Command "robocopy $stageWin $RemoteServiceDir /E /NFL /NDL /NJH /NP /R:1 /W:1" -TimeoutSeconds 300
    if ($copy.ExitCode -ge 8) {
        [void](Invoke-Remote -Computer $computer -Command "sc start $ServiceName")
        $report.Action = 'failed'
        $report.Detail = "robocopy в папку службы не удался (код $($copy.ExitCode)) — служба запущена обратно"
        Write-Host ("  {0}" -f $report.Detail) -ForegroundColor Red
        $results.Add([pscustomobject]$report)
        continue
    }

    $landedSize = Get-RemoteFileSize -Computer $computer -Path "$RemoteServiceDir\RdpAudit.Service.exe"
    if ($landedSize -ne $localExeSize) {
        [void](Invoke-Remote -Computer $computer -Command "sc start $ServiceName")
        $report.Action = 'failed'
        $report.Detail = ("после копирования размер exe {0} вместо {1} — служба запущена обратно" -f $landedSize, $localExeSize)
        Write-Host ("  {0}" -f $report.Detail) -ForegroundColor Red
        $results.Add([pscustomobject]$report)
        continue
    }
    Write-Host ("  сборка доставлена ({0} байт)" -f $landedSize)

    # ── 5. Запуск и проверка дописанных строк лога ──────────────────────────────
    $logPath = "$RemoteDataDir\Logs\service-" + (Get-Date -Format 'yyyyMMdd') + '.log'
    $linesBefore = Get-RemoteLogLineCount -Computer $computer -Path $logPath

    [void](Invoke-Remote -Computer $computer -Command "sc start $ServiceName")
    $running = Wait-ServiceState -Computer $computer -Expected 'RUNNING' -TimeoutSeconds $StartTimeoutSeconds
    [void](Start-Sleep -Seconds 15)

    $newLines = ''
    if ($linesBefore -gt 0) {
        $tail = Invoke-Remote -Computer $computer -Command "more +$linesBefore $logPath" -TimeoutSeconds 120
        $newLines = $tail.Output
    }

    $report.After = Get-ServiceState -Computer $computer
    $problems = [System.Collections.Generic.List[string]]::new()
    if (-not $running) { $problems.Add("служба не перешла в RUNNING (сейчас $($report.After))") }
    if ($newLines -match 'Database migration failed') { $problems.Add('миграция схемы провалилась') }
    if ($newLines -match 'Database initialization refused') { $problems.Add('инициализация БД отказала') }
    if ($newLines -match 'table is locked') { $problems.Add('SQLITE_LOCKED в логе после старта') }
    if ($newLines -match 'Persist batch of') { $problems.Add('сбой записи батча после старта') }
    if ($newLines -and $newLines -notmatch 'Database initialization completed successfully') {
        $problems.Add('в дописанных строках нет подтверждения инициализации')
    }

    if ($problems.Count -eq 0) {
        $report.Action = 'updated'
        $report.Detail = ("{0} → {1} байт; служба RUNNING; лог чист" -f $remoteExeSize, $landedSize)
        Write-Host '  обновлено, служба RUNNING, лог чист' -ForegroundColor Green
    }
    else {
        $report.Action = 'needs-attention'
        $report.Detail = ($problems -join '; ')
        Write-Host ("  ВНИМАНИЕ: {0}" -f $report.Detail) -ForegroundColor Red
        Write-Host ("  откат: .\Deploy-RdpAuditFleet.ps1 -Hosts {0} -Rollback -Confirm:`$false" -f $computer)
    }

    $results.Add([pscustomobject]$report)
    Write-Journal @{
        Time     = (Get-Date).ToString('o')
        Host     = $computer
        Action   = $report.Action
        BeforeB  = $remoteExeSize
        AfterB   = $landedSize
        Sha256   = $localExeSha
        Backup   = $backupDir
        Detail   = $report.Detail
    }
}

''
$results | Format-Table -AutoSize -Wrap

$failed = @($results | Where-Object { $_.Action -in @('failed', 'needs-attention', 'unreachable') })
$byAction = $results | Group-Object -Property Action | Sort-Object -Property Name
$byAction | ForEach-Object { Write-Host ("{0}: {1}" -f $_.Name, $_.Count) }
if ($failed.Count -gt 0) {
    Write-Host ("нужно внимание: {0} хост(ов)" -f $failed.Count) -ForegroundColor Red
    exit 1
}

Write-Host 'все хосты в порядке' -ForegroundColor Green
exit 0
