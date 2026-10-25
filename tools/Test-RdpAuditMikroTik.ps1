#Requires -Version 5.1
<#
.SYNOPSIS
    Проверяет, что REST-интерфейс MikroTik отвечает этой машине с учётной записью RdpAudit.

.DESCRIPTION
    Делает один GET /rest/system/resource по HTTPS с Basic-аутентификацией. Сертификат роутера
    самоподписанный (или подписан его внутренним CA), поэтому проверка цепочки отключена —
    это ровно то, что делает служба при validateServerCertificate=false. Проверяется то, что
    важно для эксплуатации: сеть, TLS, учётная запись и разрешение по адресу источника.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Gateway,
    [Parameter(Mandatory = $true)][string]$UserName,
    [Parameter(Mandatory = $true)][string]$Password,
    [int]$Port = 443
)

$ErrorActionPreference = 'Stop'

Add-Type -TypeDefinition @'
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class RdpAuditTrustAll : ICertificatePolicy
{
    public bool CheckValidationResult(ServicePoint sp, X509Certificate cert, WebRequest req, int problem) { return true; }
}
'@

[Net.ServicePointManager]::CertificatePolicy = New-Object RdpAuditTrustAll
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$b64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($UserName + ':' + $Password)))
$url = "https://${Gateway}:$Port/rest/system/resource"

try {
    $r = Invoke-RestMethod -Uri $url -Headers @{ Authorization = "Basic $b64" } -TimeoutSec 15 -UseBasicParsing
    Write-Output ("OK {0}: version={1} board={2} uptime={3}" -f $Gateway, $r.version, $r.'board-name', $r.uptime)
}
catch {
    $status = $null
    if ($_.Exception.Response) { $status = [int]$_.Exception.Response.StatusCode }
    Write-Output ("FAIL {0}: status={1} {2}" -f $Gateway, $status, $_.Exception.Message)
    exit 1
}
