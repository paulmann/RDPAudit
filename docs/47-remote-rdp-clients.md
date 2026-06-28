# Remote RDP Clients (Stage 7)

The Remote RDP Clients tab is the operator surface for live RDP-session inventory,
session control (disconnect / logoff / shadow) and Terminal Services shadow-policy
management. It maps to the design goals laid out in Stage 7 of the roadmap and is the
first time RdpAudit issues administrative actions against live sessions.

## Surface map

| Area | Backed by | Notes |
|------|-----------|-------|
| Session listing grid | `IpcCommand.ListRdpSessions` (ordinal 19) → service-side `qwinsta.exe` → pure `Core/Util/QwinstaParser` | Rows expose `SessionId`, `UserName`, `SessionName`, `State`, `ClientName`, `ClientAddress`, `IsCurrent`, `IsActive`, `IsDisconnected`. Source IP is opportunistically backfilled from recent `RawEvents` rows when qwinsta does not surface it. |
| Toolbar filters | Client-side — never re-queries the service | Free-text search (user / client / IP / session name / session id), state filter (`All states` / `Active` / `Disconnected` / `Inactive (other)`), `Auto refresh (5s)` checkbox with a re-entry guard, `Refresh` button, `Clear filters` button. |
| Disconnect | `IpcCommand.DisconnectSession` (ordinal 20) → service-side `tsdiscon.exe <id>` | Confirmation-gated. Detaches the operator's viewer; the user's processes keep running and can be re-attached on reconnect. |
| Logoff | `IpcCommand.LogoffSession` (ordinal 21) → service-side `logoff.exe <id>` | Confirmation-gated with an explicit "this is irreversible — unsaved work will be lost" warning. |
| Shadow | `IpcCommand.ShadowSession` (ordinal 22) → service-side policy check + Configurator-side `mstsc.exe /shadow:<id> [/control] [/noConsentPrompt]` via `Configurator/Services/ShadowLauncher` | The service approves or refuses against the current shadow policy. The actual mstsc spawn happens in the Configurator because mstsc requires the operator's interactive desktop session. |
| Shadow policy status | `IpcCommand.GetShadowPolicyStatus` (ordinal 23) | Reads HKLM policy + machine registry values; reports current mode, "all permissions enabled" flag, and the latest backup snapshot id. |
| Apply policy | `IpcCommand.ApplyShadowPolicy` (ordinal 24) | The `Enable all permissions…` button sets `EnableAllPermissions = true`, which writes HKLM `Shadow=2` (full control + no consent prompt) after taking a backup. |
| Backup | `IpcCommand.BackupShadowPolicy` (ordinal 25) | Captures every tracked registry value into a JSON file stored under `%ProgramData%\RdpAudit\Backups\<yyyyMMdd-HHmmss>\shadow-policy.json`. |
| Restore | `IpcCommand.RestoreShadowPolicy` (ordinal 26) | Restores either the most recent snapshot (`payload = null`) or a specific timestamp passed as a JSON-string payload. Missing values in the snapshot are deleted from the registry, mirroring the captured pre-change state. |

## Session-control command semantics

* All session ids are validated as non-negative 32-bit integers within `[0, 65535]`
  by `SessionCommandBuilder.ValidateSessionId` before any process is spawned.
* All processes are launched with `ProcessStartInfo.ArgumentList` — never via shell
  concatenation. The session id is the only operator-supplied value that ever reaches
  the argument list, and only after validation.
* The service-side handlers refuse requests when `SessionControlOptions.Enabled` is
  false, when the matching per-action flag (`AllowDisconnect`, `AllowLogoff`,
  `AllowShadow`) is false, or when the host is not Windows. Responses always carry an
  `IpcResultStatus` enum value (`Success`, `Refused`, `Unavailable`, `InvalidRequest`).

## Shadow modes

| UI item | mstsc args | Requires policy |
|---------|------------|-----------------|
| Shadow — view only | `/shadow:<id>` | View-with/without consent or full-control |
| Shadow — view + control | `/shadow:<id> /control` | Full-control (with or without consent) |
| Shadow — view + control (NO CONSENT) | `/shadow:<id> /control /noConsentPrompt` | Full-control-no-consent (mode 2) |

`ShadowPolicyModel.AllowsMode` is the single source of truth for "is this shadow
mode compatible with the current policy?" — the same predicate is used by the
service-side handler and the test suite.

## Shadow policy registry surface

| Key | Value | Purpose |
|-----|-------|---------|
| `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services` | `Shadow` | Group-policy override. Recommended value: `1` (full control with user consent). |
| `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services` | `fAllowToGetHelp` | Legacy informational flag. |
| `HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server` | `Shadow` | Per-machine value (fallback when group policy is absent). |

Microsoft semantics for the `Shadow` value:

| Value | Behaviour |
|-------|-----------|
| 0 | No shadowing |
| 1 | Full control with user permission (safest default) |
| 2 | Full control without user permission |
| 3 | View only with user permission |
| 4 | View only without user permission |

The `Enable all permissions` preset writes value `2`. Every Apply / Restore takes
an automatic backup snapshot first when the request leaves
`TakeBackupFirst = true` (the default).

## Backup integration

The shadow-policy backup writes `shadow-policy.json` into the same snapshot
directory layout used by `BackupRunner` (`%ProgramData%\RdpAudit\Backups\<yyyyMMdd-HHmmss>\`).
This means:

* The Configurator's existing global backup workflow can include shadow-policy
  state simply by running `ShadowPolicyManager.Backup()` against the same
  ProgramData root.
* Snapshot directories without a `shadow-policy.json` entry are ignored by the
  shadow-policy restore — the rest of the snapshot remains valid and is still
  visible to the standard restore tooling.
* Restore is reversible: the snapshot records the *prior* values (including
  "missing"), so a Restore returns the registry to its pre-Apply state.

## Confirmation contract

Every destructive or policy-mutating action shows a `MessageBox.Yes/No` with the
**No** button as the default. The message text always includes:

* The session id and user (where applicable).
* The exact action that will be performed.
* The reversibility statement (e.g. "this terminates every process… unsaved work
  WILL be lost" for logoff).

This matches the rest of the Configurator's confirmation pattern (Stage 5
Firewall mutations, Stage 6B Attack Statistics block / whitelist actions).

## Status strip

Every refresh, action and policy mutation surfaces a `[yyyy-MM-dd HH:mm:ss Z] message`
line in the page status strip, so the operator has an audit trail of what was
issued from the UI without needing to open the service log.
