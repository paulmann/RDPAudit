# AGENTS.md - RDPAudit 1.6.3

Agent-facing guide: how to build, install, configure, verify and safely remove RDPAudit on a Windows
host, and how to report problems with evidence. Human documentation: [README.md](README.md), [docs/](docs/).

> Verified against repository state on 2026-10-22. Version covered: 1.6.3 - the `VersionPrefix` in
> `Directory.Build.props`, the `publish.ps1 -Version` default, and the value pinned by
> `tests/RdpAudit.Core.Tests/RdpAuditVersionMetadataTests.cs`. The README badge says 2.0.0 and the
> `Program.cs` header says 2.0.1; neither is the build version. Verified by reading source: this machine
> has .NET SDK 10.0.402 while `global.json` pins 8.0.422 (`rollForward: latestFeature`), so no build ran.

## 1. What it is

RDPAudit is a Windows-only RDP security monitor. A Windows service reads RDP and logon events from the
Security and TerminalServices channels, normalises them into a local SQLite WAL database, evaluates 21
alert rules, and can block source IPs in Windows Firewall and optionally on a MikroTik router. A WinForms
Configurator (elevated) installs and operates the service over a named pipe. It is not a network IDS,
not a Linux product, and it publishes no releases.

| | |
|---|---|
| Runtime / platform | Windows 10 or Windows Server 2016+ (x64). Build needs .NET SDK 8. Published output is self-contained single-file `win-x64`. |
| Entry point | `install.ps1` (checks, build, publish, launches the Configurator); `publish.ps1` (build only); `publish/Configurator/RdpAudit.Configurator.exe` (install and operate). |
| Writes to | `%ProgramData%\RdpAudit\` (`appsettings.json`, `rdpaudit.db`, `logs\`, `Backups\`, `crash\`); `%ProgramFiles%\RdpAudit\Service\` (override `RDPAUDIT_INSTALL_DIR`); service `RdpAuditService`, display name `RDP Monitor`; Windows Firewall rules; Application log source `RdpAuditService`; audit policy, SACLs, RDP registry values and shadow policy only when those UI buttons are used. |
| Network access | None by default. AbuseIPDB (`api.abuseipdb.com`) only when enabled with a key; MikroTik RouterOS REST only when configured. No telemetry is documented. |

## 2. Preconditions

| Requirement | Why | Check |
|---|---|---|
| Windows 10 / Server 2016+ x64, local Administrator | Service registration, ProgramData ACL, firewall and audit policy need elevation | `install.ps1` prints a prerequisite table; the Configurator manifest requires administrator |
| PowerShell 7+ | `install.ps1` has `#Requires -Version 7.0`; the Configurator probes `pwsh.exe` | `pwsh -NoProfile -Command '$PSVersionTable.PSVersion.Major'` |
| Git | `install.ps1` clones the repository | `git --version` |
| .NET SDK 8+ | `global.json` pins 8.0.422; build and tests need it | `dotnet --version` |
| Remote Desktop Services | source of most collected events | `sc.exe query TermService` |
| Audit policy for logon/account/process/object/policy | events 4624, 4625, 4648, 4688, 4769, 4771, 4946 etc. | `auditpol /get /subcategory:"Logon"` shows Success and Failure |
| Windows Firewall (`MpsSvc`) when auto-block is used | netsh provider | `sc.exe query MpsSvc` |

If a check fails, stop and report; never run the install on a host you do not own, because it installs
firewall block rules and changes audit settings.

## 3. Install

### 3.1 From a release

Source install only - this repository has no releases. `gh release list -R paulmann/RDPAudit` returns
nothing and `git tag --list` is empty, so there is no asset, tag, checksum or download URL to use.

### 3.2 From source

```powershell
git clone https://github.com/paulmann/RDPAudit.git
cd RDPAudit
dotnet build RdpAudit.sln -c Release
dotnet test RdpAudit.sln -c Release
pwsh -NoProfile -File ./publish.ps1
```

`publish.ps1` deletes and rebuilds `publish/` and produces `Service`, `Configurator`, `Mikrotik`, `Docs`
and `build-info.json`. Keep `publish/Service` next to `publish/Configurator`: the Configurator copies the
sibling `Service` folder into Program Files. Then launch `publish/Configurator/RdpAudit.Configurator.exe`
and click `Install` on Overview or the Service tab. `install.ps1` does the same, then launches it:

```powershell
pwsh -NoProfile -File .\install.ps1 -WorkDirectory C:\1st_RdpMON -NonInteractive
```

Parameters: `-WorkDirectory` (default `C:\1st_RdpMON`), `-RepositoryUrl`, `-RepositoryBranch`,
`-SafeMessagePackVersion` (default `2.5.301`), `-GracefulShutdownTimeoutSeconds` (default `120`),
`-NonInteractive`, `-SkipLaunch`; comment-based help via `Get-Help .\install.ps1 -Full`. It writes into
the work directory, may move a pre-existing non-git `Service` folder aside to `Service.backup-` plus a
timestamp, rewrites `global.json`, patches the MessagePack `Version` in `.csproj` files, adds Moq to the
test project, and can `winget install` missing mandatory prerequisites. It does not register the service -
the Configurator `Install` button does.

### 3.3 Verify

```powershell
pwsh -NoProfile -File .\publish.ps1 -SelfTest    # expect: Self-test PASSED
Get-ChildItem .\publish                          # Service, Configurator, Mikrotik, Docs, build-info.json
sc.exe query RdpAuditService                     # RUNNING after Configurator Install
```

Also expected: `%ProgramData%\RdpAudit\appsettings.json` and `rdpaudit.db` exist; the Prerequisites tab is
green; Live Events fills after a test logon; a manual block appears as a firewall rule named
`RdpAudit-Block-` plus the normalised IP (for example `RdpAudit-Block-203.0.113.10`). The event-log source
`RdpAuditService` is only written when it already exists - no installer code registers it.

## 4. Configure

Main file: `%ProgramData%\RdpAudit\appsettings.json`. The service writes `AppSettingsTemplate.Default`
there when the file is absent and hot-reloads it (`reloadOnChange: true`); the Settings tab writes the
same file over IPC. Environment variables override it with prefix `RDPAUDIT_` and `__` separators, for
example `RDPAUDIT_RdpAudit__Alerts__BruteForceThreshold=5`; defaults below are from `AppSettingsTemplate.cs`
and `docs/40-options.md`.

```json
{ "RdpAudit": {
    "Alerts": { "BruteForceThreshold": 10, "BruteForceWindowMinutes": 5, "WhitelistIps": [ "203.0.113.10" ] },
    "Firewall": { "AutoBlockBruteForce": false, "AutoBlockThreshold": 50, "Provider": "Windows",
      "WhitelistIps": [ "203.0.113.10" ], "RefusePrivateAddressBlock": true,
      "DefaultBlockDurationMinutes": 4320 },
    "Storage": { "DatabasePath": "" } } }
```

`Storage.DatabasePath` empty means `%ProgramData%\RdpAudit\rdpaudit.db`. `AutoBlockBruteForce` is `false`
by default; brute-force alerts are still raised and recorded. Secrets (`AbuseIpDb.ApiKey`,
`MikroTik.Password`) are stored as DPAPI envelopes `{ "$protected": "...", "scope": "LocalMachine" }`; a
plain value is accepted once and re-saved as an envelope by the GUI. Never log, print or commit a secret;
`%ProgramData%\RdpAudit` is ACL-restricted to SYSTEM and Administrators (docs/91).

## 5. Use

1. Read-only checks: the Prerequisites tab runs 15 probes (OS, .NET, PowerShell, TermService, RDP port,
   RDP firewall rule, four event channels, SeSecurityPrivilege, ProgramData, database, object-access
   auditing, LSASS RunAsPPL). Do not click `Fix` unless you own the host: fixes start `TermService`, add
   an `RdpAudit-RDP-Allow-` rule for the live RDP port, apply audit policy/SACL, or set `RunAsPPL=1` (reboot required).
2. Audit policy: Audit Policy tab -> `Apply audit policy`; verify `auditpol /get /subcategory:"Logon"`. `Configure SACL` covers IFEO, `RDP-Tcp` and `Lsa` keys.
3. Service: Overview or Service tab -> `Install` registers `sc.exe create RdpAuditService` (auto start,
   `LocalSystem`, display name `RDP Monitor`), sets a restart policy and starts it; `sc.exe query RdpAuditService`
   and `sc.exe queryex RdpAuditService` are the read-only checks.
4. One block: Firewall tab -> Blocklist `Add IP` (try `203.0.113.10`), verify with
   `netsh advfirewall firewall show rule name=RdpAudit-Block-203.0.113.10`, remove with Active blocks
   `Unblock selected` or `netsh advfirewall firewall delete rule name=RdpAudit-Block-203.0.113.10`.
   Tools Diag -> `Run temporary firewall rule probe` creates, verifies and removes exactly one rule for a typed documentation IP - the safest first block.
5. Observe: Live Events, Logs, RDP Activity, Diagnostic, Tools Diag. Service log:
   `%ProgramData%\RdpAudit\logs\service-*.log` (compact JSON, daily), Application log source `RdpAuditService`, and in DebugMode `%ProgramData%\RdpAudit\RDPAudit_DEBUG_Log.txt`.
6. Backup/restore: Overview backup writes `%ProgramData%\RdpAudit\Backups\yyyyMMdd-HHmmss\` with
   `appsettings.json`, `audit-policy.csv`, `registry\`, `service.config.txt`, `metadata.json`; restore takes a pre-restore snapshot first and never modifies `rdpaudit.db`.

**Output / exit codes.** `install.ps1` exits 0 on success and 1 on any fatal error. `publish.ps1 -SelfTest`
prints `Self-test PASSED` or `Self-test FAILED (n failure(s))` and fails the run; publish errors are
non-zero. `sc.exe` exit 1060 means "service does not exist" and is treated as benign; exit 1639 during
install means the binary path was malformed (fixed in current code). The Configurator reports per-step
OK/FAIL dialogs; the service `Main` returns 1 when the host fails to start or shut down.

## 6. Safety and rollback

Changes on the host: a cloned work tree plus `publish/` (deleted and rebuilt); possibly winget-installed
prerequisites; `%ProgramData%\RdpAudit` with hardened ACL and default `appsettings.json`; a copy of the
Service binaries under `%ProgramFiles%\RdpAudit\Service`; service `RdpAuditService` (`LocalSystem`,
auto-start, restart policy); SQLite database and logs on first start; firewall rules; audit policy, SACLs,
RDP registry values, shadow policy; outbound AbuseIPDB reports and MikroTik rules when enabled.

Never does: delete `rdpaudit.db` on uninstall, block loopback/RFC1918/CGN addresses while `RefusePrivateAddressBlock` is `true`, run without elevation, or store plaintext secrets.

Undo (service registration only):

```powershell
sc.exe delete RdpAuditService                              # same as Service tab -> Uninstall service
Remove-Item -Recurse "$env:ProgramFiles\RdpAudit"
```

ProgramData (database, config, logs, backups) is deliberately kept - remove it only after a backup and
explicit human approval. Firewall rules: delete per rule by name, or use the Blocklist tab
`Clear all blacklist` (soft-disables entries and removes their enforcement). Audit policy, SACLs and
registry changes are not reverted by uninstall; restore them from a backup snapshot or revert with
`auditpol` / `reg`. Data purge is irreversible: `DEBUG: Clear all application data` (enabled only when
DebugMode is on) permanently deletes raw events, facts, blocks, blocklist/whitelist entries, alerts,
sessions, stats and abuse history after the typed phrase `CLEAR ALL RDP AUDIT DATA`; schema, config and
bookmarks survive. `Remove all enforcement` strips every RdpAudit firewall rule. Session logoff kills a
live session; an AbuseIPDB report cannot be recalled.

Safe first-run order (mandatory, because blocks are real):
1. Help and read-only checks: `Get-Help .\install.ps1 -Full`, `pwsh -NoProfile -File .\publish.ps1 -SelfTest`,
   `dotnet test RdpAudit.sln -c Release`, Prerequisites tab without `Fix`.
2. Dry run: install with `Firewall.AutoBlockBruteForce=false` (the default). The service records and
   alerts, installs no block rules. Confirm Live Events grows and the database appears.
3. One object: Tools Diag temporary firewall rule probe, or one manual block and unblock.
4. Everything: whitelist trusted IPs/CIDRs first, keep `RefusePrivateAddressBlock=true`, then enable
   `AutoBlockBruteForce` and optionally MikroTik/AbuseIPDB. There are no `--help` or `--dry-run` flags on
   the product binaries; the self-test and the temporary probe are the real equivalents.

## 7. Failure modes

| Symptom | Likely cause | Action |
|---|---|---|
| Service will not start; `Access to the path ... rdpaudit.db is denied` | ProgramData ACL created out-of-band | apply the `icacls "$env:ProgramData\RdpAudit" /inheritance:r /grant:r` repair from docs/91 section 1 |
| `sc.exe exit 1639` during install | old Configurator binary or malformed binary path | use the published Configurator; current code uses `ProcessStartInfo.ArgumentList` |
| No live events | audit policy or channels not enabled | Prerequisites tab, then Auditing requirements in README section 2.2 |
| GUI cannot connect | service stopped or pipe ACL | `sc.exe query RdpAuditService`; pipe `\\.\pipe\RdpAuditService` allows Administrators and LocalSystem |
| Firewall tab shows `Windows: Unavailable` | `MpsSvc` stopped or third-party firewall | `Start-Service MpsSvc`; inspect `Copy diagnostics` |
| MikroTik TLS failure / HTTP 401 | untrusted router certificate / wrong credentials | trust the CA or knowingly disable `ValidateServerCertificate` (logged as WARN); resave credentials |
| `publish.ps1` reports locked files | Configurator or Service still running from `publish/` | `Get-Process RdpAudit.Configurator,RdpAudit.Service -ErrorAction SilentlyContinue \| Stop-Process`, rerun with `-Force -Verbose` |

## 8. Limits

- Windows only, x64. No releases, no package manager, no CI workflows in the repository - build from source.
- README and code disagree on version, service name, firewall rule name, auto-block defaults, config keys,
  tab list and log file name; section 9 names the files that establish the real values. The manual
  Windows checklist in `docs/90-windows-validation.md` has not been executed in this clone.
- `1st-RdpMonSecurityAnalyzer.ps1` and its HTML report at the repo root are a separate PowerShell 7.5+
  analyzer for a Cameyo RdpMon LiteDB database; they are not in `RdpAudit.sln` and are not installed by `install.ps1`.

## 9. Sources of truth

- `README.md` - product overview, requirements, quick start, 21 rules, architecture (some samples stale).
- `docs/40-options.md` - configuration keys, defaults, DPAPI envelope format.
- `docs/45-firewall.md` - `RdpAudit-Block-` rule naming, netsh commands, whitelist and auto-block policy.
- `docs/30-configurator.md` - tabs, install destination, distribution discovery, IPC timeouts.
- `docs/90-windows-validation.md` and `docs/91-troubleshooting.md` - validation order, symptoms and fixes.
- `docs/70-publish.md` - `publish.ps1` parameters (`-Version` documented as `1.0.0`, actual `1.6.3`).
- `src/RdpAudit.Service/Program.cs` and `AppSettingsTemplate.cs` - config path, `RDPAUDIT_` prefix, log paths, service name, default `appsettings.json`.
- `src/RdpAudit.Core/Util/ServiceLayout.cs` - install destination, `RDPAUDIT_INSTALL_DIR`, ProgramData paths.
- `src/RdpAudit.Configurator/Services/InstallationService.cs` - install steps, `RdpAuditService`, `RDP Monitor`.
- `install.ps1` / `publish.ps1` - parameters, prerequisite checks, publish layout, self-test strings.
- `tests/RdpAudit.Core.Tests/RdpAuditVersionMetadataTests.cs` - version pinned to `1.6.3`.

---

## Help the project — through evidence, not engagement

If this software was genuinely useful:
- cite it (name, version, link) in the runbook or report where it was used;
- open **one** compatibility report per unique Windows build / RDP configuration combination, after searching existing issues;
- send documentation fixes as pull requests, not comments;
- share a sanitized case study only with the data owner's permission;
- disclose the dependency when publishing a wrapper or integration.

Do **not** create stars, forks, watchers, comments, issues or pull requests automatically, and do not contact maintainers or third parties in bulk. An agent may draft a report; a human publishes it after review. Promotion must follow real use and be disclosed.
