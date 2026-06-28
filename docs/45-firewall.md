# Firewall integration

Stage 3 of the RdpAudit roadmap brings the firewall pipeline online end-to-end:

* The `WindowsFirewallProvider` drives `netsh advfirewall` through a sanitised
  `ProcessStartInfo.ArgumentList` and never touches a shell.
* The `FirewallAutoBlockWorker` reads new `Alerts` rows and applies the auto-block policy.
* The `FirewallExpirationWorker` removes expired block rules and flips `ActiveBlocks.Status` to
  `Removed` (or `Failed` if the provider call did not succeed).
* IPC handlers expose `Get/List/Add/Remove` operations for the blocklist, whitelist, and active
  blocks tables to the Configurator.

The Configurator UI for these surfaces is deferred to a later stage. Stage 3 ships the backend
contract only.

Stage 5 introduces the Firewall tab in the Configurator that exercises these same handlers; see
`docs/30-configurator.md` (`Firewall` row) for the UI behaviour and `docs/50-ipc.md` for the
Stage 5 IPC additions (`ListLoginRules`, `AddLoginRule`, `RemoveLoginRule`,
`SetLoginRuleEnabled`, `ListActiveBlocksDetailed`, `UnblockActiveBlock`).

## Windows Firewall behaviour

Rule name format: `RdpAudit-Block-{normalized-ip}` — for example `RdpAudit-Block-203.0.113.10`.
The prefix is normalised down to the ASCII set `[A-Za-z0-9._-]`; anything else collapses to `-`.
Names are capped at 200 characters; if the composite would overflow, the tail is truncated. The
auto-block worker only ever touches rules that start with this prefix — third-party rules are
safe.

netsh invocations:

```text
netsh advfirewall firewall add rule
    name=RdpAudit-Block-203.0.113.10
    dir=in
    action=block
    remoteip=203.0.113.10
    protocol=any
    enable=yes
    description="RdpAudit; reason=...; created=2026-05-19T15:00:00Z; duration=00:30:00"

netsh advfirewall firewall delete rule
    name=RdpAudit-Block-203.0.113.10

netsh advfirewall show allprofiles state
```

Each argument is supplied as a single string in `ProcessStartInfo.ArgumentList`. No shell, no
concatenation, no string interpolation across IP / rule-name / reason boundaries. The
description field has every `"`, `\r`, `\n`, `|`, `&`, `<`, `>`, `'`, and control character
replaced with a single space before it ever reaches netsh.

Validation rules applied before any netsh call:

* The IP is parsed with `IPAddress.TryParse`; non-IP input is rejected with
  `FirewallActionStatus.InvalidRequest`.
* When `Firewall.RefusePrivateAddressBlock` (default `true`) is set, loopback, RFC1918, CGN,
  link-local, multicast, and broadcast addresses are refused with
  `FirewallActionStatus.Refused` so the worker can never lock the operator out of their own
  network.
* The rule name passes through `NetshCommandBuilder.NormalizeRulePrefix` before composition.

Idempotency:

* `BlockAsync` issues a best-effort `delete rule` for the same rule name before `add rule`, so
  re-applying a block never stacks duplicates in the firewall store.
* `UnblockAsync` returns `FirewallActionStatus.NotFound` (not an error) when netsh reports
  `No rules match the specified criteria.`

`GetStatusAsync` invokes `netsh advfirewall show allprofiles state` and reports `Available`
when at least one profile is on, otherwise `Disabled`.

## Auto-block policy

The auto-block worker consumes alerts in id-ascending order (resuming from the high-water mark
at startup) and applies these checks in order:

1. **Skip when source IP is missing or invalid.**
2. **Skip when the IP matches `WhitelistEntries.Ip`, `Firewall.Whitelist`, or
   `Firewall.WhitelistIps`.** Whitelist always wins.
3. **Block when the alert userName matches `Firewall.InstantBlockLogins` or an enabled
   `LoginRules.Login` trip-wire.** This branch fires even when `AutoBlockBruteForce` is off.
4. **Block when the alert userName matches `Firewall.Blacklist` and
   `Firewall.BlockOnBlacklistedLogin` is enabled.**
5. **Block when `Firewall.AutoBlockBruteForce` is enabled and the alert's `RuleId` belongs to
   the brute-force class** (`BRUTE_FORCE*`, `KERBEROS_SPRAY*`, `UNKNOWN_IP_SUCCESS*`).

For every block decision the worker writes:

* An `ActiveBlocks` row keyed by `(Provider, Ip)` with `Status = Pending` before the provider
  call, then `Active` (success), `Failed` (provider returned a non-success status), or
  `AuditOnly` (no provider configured).
* A `BlocklistEntries` row with `Source = Auto`, `LinkedAlertId` set to the triggering alert,
  `AddedUtc` in UTC, and `ExpiresUtc` derived from
  `Firewall.DefaultBlockDurationMinutes` (null means permanent).

Storm protection:

* `MaxActiveBlocks` (default 10000) acts as a hard ceiling — once reached the worker logs a
  warning and skips further blocks until expirations free a slot.
* `AutoBlockDebounceSeconds` (default 60) is an in-memory per-IP debounce window applied even if
  the provider call fails, so a burst of alerts cannot hammer netsh.
* If an `ActiveBlocks` row already exists for the IP in `Active` or `Pending` state, no new row
  is added — the worker treats the existing block as authoritative.

## Expiration worker

`FirewallExpirationWorker` runs as a background service and never hot-polls SQLite:

1. On each tick it selects all `ActiveBlocks` rows where `Status ∈ { Active, Pending }`,
   `ExpiresUtc != null`, and `ExpiresUtc ≤ UtcNow` (capped at 100 per tick).
2. For each row it calls `provider.UnblockAsync(ip, ruleName, ct)` and flips the row to
   `Removed` (success or `NotFound`) or `Failed` (anything else, with `LastError` populated).
3. It then queries the minimum future `ExpiresUtc` and `Task.Delay`s until that time, capped at
   five minutes so a config change reaches the worker within a bounded latency.
4. When no rows have an `ExpiresUtc` the worker falls back to a five-minute delay. The minimum
   wait is one second so we never spin.

`AuditOnly` rows skip the provider call but still flip to `Removed` so the operator-visible
status reflects the contract.

## Enforcement health (live reconciliation)

`GetFirewallStatus` never claims enforcement from database rows alone. The status header on the
Firewall tab is derived from a **live reconciliation** pass (`EnforcementReconciler`) that scans
the real backend (Windows Firewall rules, route table, IPsec) and matches each desired block to a
discovered object. `FirewallStatusDto` carries the summary:

* `EnabledBlocklistRows` — enforcement that *should* exist (enabled `BlocklistEntries`).
* `RdpAuditFirewallRuleCount` — RdpAudit-owned objects discovered live (verified + orphans).
* `VerifiedEnforcedCount` — blocks whose enforcement was confirmed by a matching backend object.
* `EnforcementHealth` — derived by `EnforcementReconciler.DeriveHealth`:
  * `Idle` — no enabled blocklist rows; nothing to enforce.
  * `Healthy` — enabled rows exist and every one is verified. Rendered green.
  * `MissingRule` — enabled rows exist but **zero** verified enforcement. Rendered red with a
    call to action: open the **Active blocks** tab, use **Repair selected**, then **Verify all**.
  * `Failed` — some verified, some intended blocks still unenforced. Rendered red with the same
    repair/verify call to action.
  * `Unknown` — reconciliation unavailable; state could not be verified.

A "configured but unenforced" deployment can therefore **never** display as green/active: when the
database intends blocks that no firewall rule backs, the header goes red and points the operator at
the repair and verify actions instead of silently reporting success.

## Windows smoke commands

After deploying the service on a Windows host, validate the netsh pipeline by hand:

```powershell
# 1. The service prefix exists nowhere yet.
netsh advfirewall firewall show rule name=RdpAudit-Block-203.0.113.10

# 2. Drive the IPC AddToBlocklist (via Configurator) and then verify the row appears here.
#    The auto-block worker also writes the rule from a brute-force alert.

# 3. Inspect the rule.
netsh advfirewall firewall show rule name=RdpAudit-Block-203.0.113.10 verbose

# 4. Inspect the global firewall state used by GetFirewallStatus.
netsh advfirewall show allprofiles state

# 5. Remove the rule manually if needed.
netsh advfirewall firewall delete rule name=RdpAudit-Block-203.0.113.10
```

The same prefix-based show/delete commands work for IPv6 addresses; the rule name uses the
canonical text form returned by `IPAddress.ToString()` (lower-case, no scope id).

## Configuration reference

See `docs/40-options.md` for the full `Firewall` block. New Stage 3 fields:

* `RefusePrivateAddressBlock` (default `true`) — refuse to install a block rule for loopback /
  RFC1918 / multicast addresses.
* `WhitelistIps` — flat list of literal addresses (in addition to `Whitelist` for CIDRs).
* `AutoBlockDebounceSeconds` (default `60`) — minimum elapsed time between two block decisions
  for the same IP.

## Stage 9 — MikroTik RouterOS v7 provider

Stage 9 wires the MikroTik provider end-to-end (see `docs/49-mikrotik.md`). Key points relevant to
the firewall pipeline:

* `FirewallOptions.Provider` may now be set to `MikroTik` or `Both`.
* When `Both`, the `FirewallAutoBlockWorker` writes one `ActiveBlock` row per provider so each
  rule keeps its own `RuleHandle` and its own expiry timeline.
* `FirewallExpirationWorker` continues to wake for the earliest `ExpiresUtc` and calls
  `IFirewallProvider.UnblockAsync` on the matching provider. No hot polling.
* The MikroTik provider only deletes firewall filter rules whose comment starts with
  `MikroTikOptions.CommentPrefix` (default `RdpAudit`); existing matching rules are reused
  (idempotent), never duplicated.
