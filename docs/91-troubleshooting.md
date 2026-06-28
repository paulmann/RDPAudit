# Troubleshooting

This guide covers the common failures we've seen during Stage 10 release-readiness testing and
how to resolve each one. Symptoms are written first so you can grep for the exact message you
see in the Configurator or the service log.

## 1. ProgramData ACL is wrong

**Symptom.** Service refuses to start. Event Log: `Access to the path
'C:\\ProgramData\\RdpAudit\\rdpaudit.db' is denied.`

**Cause.** The Configurator's first-run flow normally hardens
`%ProgramData%\RdpAudit\` to SYSTEM + BUILTIN\Administrators only. If the folder was
created out-of-band (e.g. an admin manually copied the binaries), inherited ACLs may
leave the directory readable by Users / Authenticated Users.

**Fix.**

```powershell
icacls "$env:ProgramData\RdpAudit" /inheritance:r `
    /grant:r "*S-1-5-18:(OI)(CI)F" `        # NT AUTHORITY\SYSTEM
    "*S-1-5-32-544:(OI)(CI)F"               # BUILTIN\Administrators
```

Then restart the service from the Configurator's Service tab.

## 2. `sc.exe` exit 1639 during install

**Symptom.** Service tab → Install fails with `sc.exe exit 1639` and the message
"Invalid command-line."

**Cause.** Historical regression where the install command embedded the binary path with
unescaped spaces. Fixed in commit `1b6c63c` (see `git log -- src/RdpAudit.Configurator/Services/InstallationService.cs`).

**Fix.** Ensure the Configurator is the published `RdpAudit.Configurator.exe` (>= Stage 1
fix) and not an older binary. The fixed code uses `ProcessStartInfo.ArgumentList` so spaces
are escaped automatically; nothing is concatenated into a shell string.

## 3. `publish.ps1` reports locked files

**Symptom.** `publish.ps1` aborts with `Cannot remove publish\Service — files are in use`.

**Cause.** A previous Configurator or Service process is still running and holding a
handle to a file inside `publish\`. The script's locked-file detector lists the responsible
PID(s) and executable paths in the diagnostics block.

**Fix.** Stop the named processes, then re-run. Typical commands:

```powershell
Get-Process RdpAudit.Configurator,RdpAudit.Service -ErrorAction SilentlyContinue | Stop-Process
./publish.ps1
```

For locked files outside this product (e.g. an open File Explorer preview), the
diagnostics block will list them under "Inspection failures" rather than "Blockers" —
those are advisory and the script will proceed once you close the inspecting process.

## 4. Audit policy "Current" column shows `?`

**Symptom.** Audit Policy tab refreshes but every subcategory's Current state is `?`.

**Cause.** Either `auditpol.exe` is unavailable in PATH (rare — only on stripped Server
Core installs) or the parser failed to map the localised "Inclusion Setting" column.

**Fix.** Confirm `auditpol /get /subcategory:*` works from an elevated prompt. If it does,
the parser falls back to `AuditQuerySystemPolicy` via `[LibraryImport]`; verify that
`advapi32.dll` exports both `AuditQuerySystemPolicy` and `AuditFree`. The fallback handles
en/ru/de/fr/es Windows builds — file a bug if your locale's "Success and Failure" wording
doesn't match.

## 5. Firewall provider unavailable

**Symptom.** Firewall tab status reads `Windows: Unavailable` or `MikroTik: NotConfigured`.

**Causes & fixes.**

* **Windows provider unavailable** — the Windows Firewall service (`MpsSvc`) is not
  running. Start it: `Start-Service MpsSvc`.
* **MikroTik NotConfigured** — no host or no protected password is set. Open the MikroTik
  tab and Save the settings.
* **MikroTik Unavailable** — TLS / cert / DNS failure. See section 7 below.

## 6. AbuseIPDB returns HTTP 429

**Symptom.** Status strip shows `AbuseIPDB rate limited (HTTP 429) — backing off`.

**Cause.** AbuseIPDB enforces per-IP rate limits and the local dedup window must respect
their 15-minutes-per-IP report rule. The client surfaces 429 without retrying so it never
amplifies the rate-limit violation.

**Fix.** Either wait for the API window to clear or tighten the local `MinThreatScore`
and `MinFailedAttempts` so fewer rows qualify. The local dedup window is enforced via the
`AbuseReports` table — bumping `DeduplicationWindowMinutes` further reduces churn.

## 7. MikroTik TLS / certificate / auth failures

**Symptom.** Test connection shows one of:

* `MikroTik: TLS handshake failed (RemoteCertificateNameMismatch)`
* `MikroTik: authentication failed (HTTP 401)`
* `MikroTik: connection refused` / `host unreachable`

**Causes & fixes.**

* **`RemoteCertificateNameMismatch` / `UntrustedRoot`.** The router's certificate isn't
  trusted by the Windows store. Either install the router's certificate into
  `LocalMachine\Root`, or — only if you've assessed the risk — uncheck
  `ValidateServerCertificate`. The service logs a WARN entry when validation is disabled
  so the operator action is auditable.
* **HTTP 401.** Username or password is wrong. The Configurator never echoes the
  plaintext; Save the credentials again. Confirm that the dedicated `rdpaudit` RouterOS
  user has at least `read,write,api,policy` permissions on `/ip/firewall/filter`.
* **Connection refused.** REST is disabled on the router (`/ip service print` should show
  `www-ssl` enabled and listening on the configured port). If you're behind a NAT,
  confirm the firewall on the router itself permits the Configurator host on the chosen
  port.

## 8. Service hangs at shutdown

**Symptom.** `Stop-Service RdpAudit` blocks for 30 s then reports a timeout.

**Cause.** A long-running worker (typically `MaintenanceWorker` doing a vacuum or an
`AbuseIpDbReportWorker` doing an HTTP call) hasn't observed the cancellation token yet.

**Fix.** No action required — the hosting infrastructure forces a stop after the host
shutdown timeout. If you see this repeatedly, file a bug with the matching service log
window so the offending worker can be identified.

## 9. `publish.ps1` fails the parser self-check

**Symptom.** `Self-test FAILED (1 failure(s))` with a parser error pointing at a recent
edit.

**Fix.** Run `pwsh -NoProfile -Command "$tokens=$null;$errors=$null;[System.Management.Automation.Language.Parser]::ParseFile('publish.ps1',[ref]$tokens,[ref]$errors); $errors"`
to see the exact diagnostics. The self-check is intentionally pedantic so syntax bugs in
unreachable branches still surface.

## 10. Configurator cannot find the Service distribution

**Symptom.** Overview tab shows `Service distribution: not found alongside the Configurator`.

**Cause.** The Configurator looks for a sibling `..\Service\RdpAudit.Service.exe` next to
its own executable. If you copied only one of the two folders, sibling discovery fails.

**Fix.** Either keep both `Service` and `Configurator` folders side by side under the same
parent (`...\RdpAudit\Service\` and `...\RdpAudit\Configurator\`) or use the Configurator's
"Browse..." control to point at an explicit Service location. The published layout from
`publish.ps1` is the canonical reference.

---

If a problem doesn't appear here, open a GitHub issue with:

1. The Configurator's full status-strip line.
2. The matching block from `%ProgramData%\RdpAudit\logs\service-*.log` (redact secrets if
   any survived — they shouldn't).
3. The output of `./publish.ps1 -SelfTest` so we can rule out a publish-script regression.
