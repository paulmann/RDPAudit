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

### Router-side provider enforces the same guard

`MikroTikFirewallProvider.BlockAsync` applies `Firewall.RefusePrivateAddressBlock` exactly like the
Windows provider: a loopback / RFC1918 / CGN / link-local address is answered with
`FirewallActionStatus.Refused` and the router is never touched. Without this the router — which is
strictly more destructive than a host rule — happily accepted a drop rule for a private address.

Measured 23.10.2026 on the branch router (192.168.1.1, RB2011 `flotskaya`): an NTLM-brute-force
alert attributed to the private admin workstation `192.168.31.100` produced
`RdpAudit-Block-192.168.31.100` in `chain=forward`, and management access to **every** host behind
that router (192.168.1.50 / .60 / .100) disappeared from the office LAN; a second rule for the
site's own public NAT `77.37.192.246` cut off the whole company. Both rules were removed manually
and the code guard now prevents the private case from recurring. A public address (including your
own NAT) is still blockable by design — put it in `Firewall.WhitelistIps` if it must never be
blocked.

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

### Whitelist content on this fleet

`Firewall.WhitelistIps` holds literal addresses that must never be auto-blocked, and
`Firewall.Whitelist` holds CIDR ranges (`Awaitable` blocking works off both). Current fleet values:

| Field | Values | Why |
|---|---|---|
| `whitelistIps` | `77.37.192.246`, `162.248.164.228`, `176.99.5.35`, `176.99.2.35` | office WAN (RDP/NAT for the whole company), German exit host, and the two production hosting servers (`batteryservice.ru`, `batterypassport.ru` and the sites on them) |
| `whitelist` | `192.168.0.0/16`, `10.0.0.0/8`, `172.16.0.0/12`, `10.255.255.0/24` | every internal network of the sites and the WireGuard hub |

Two notes from the 23.10.2026 cleanup: the file used to carry `192.168.0.0/16,10.255.255.0/24` as
**one** string, which matched nothing — each range must be its own array element; and the array under
`alerts` is a different list (`alerts.whitelistIps`) that does not gate blocking, so it must not be
confused with the firewall one.
### A correlated address never becomes a block

Auto-block acts only on an address that the triggering event actually carried. `Alert.SourceIpDerived`
is copied from `RawEvent.SourceIpDerived` (the flag the normaliser sets when the address came from
correlation rather than from the record), and `AutoBlockPolicy.Decide` returns
`Skip` with reason `derived-ip` for such an alert. The alert itself is still raised and still shows
the address — the operator keeps the signal, the firewall keeps its hands off a guess.

Measured 23.10.2026: Security 4776 carries no source address at all, the NTLM brute-force rule
correlated one anyway, and the auto-block installed `drop` rules on the branch router for a private
admin workstation and for the site's own public NAT — which cut the branch network off.
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

* An `ActiveBlocks` row keyed by `(Provider, Ip)` **only when a provider confirmed the block**
  (`Status = Active`), or `AuditOnly` when no provider is configured. A provider failure writes
  nothing: a row the OS cannot back would display an IP as blocked while the traffic still
  flows (Bug 1).
* A `BlocklistEntries` row with `Source = Auto`, `LinkedAlertId` set to the triggering alert,
  `AddedUtc` in UTC, and `ExpiresUtc` derived from
  `Firewall.DefaultBlockDurationMinutes` (null means permanent).

Because a failed attempt leaves no row, it is retried in memory: `FirewallAutoBlockWorker`
keeps a bounded queue (`MaxPendingRetries` = 256) and re-applies the same decision up to
`MaxRetryAttempts` = 3 times with a 30 s / 2 min / 5 min backoff. The queue is deliberately not
persistent — a restart drops it and the next alert for the same address re-triggers the policy —
but a single provider hiccup no longer loses the attempt silently.

Storm protection:

* `MaxActiveBlocks` (default 10000) acts as a hard ceiling — once reached the worker logs a
  warning and skips further blocks until expirations free a slot.
* `AutoBlockDebounceSeconds` (default 60) is an in-memory per-IP debounce window applied after a
  successful block, so a burst of alerts cannot hammer netsh; failed attempts are paced by the
  retry backoff above.
* If an `ActiveBlocks` row already exists for the IP in `Active` or `Pending` state, no new row
  is added — the worker treats the existing block as authoritative.

## Expiration worker

`FirewallExpirationWorker` runs as a background service and never hot-polls SQLite:

1. On each tick it selects all `ActiveBlocks` rows where `Status ∈ { Active, Pending, Failed }`,
   `ExpiresUtc != null`, and `ExpiresUtc ≤ UtcNow` (capped at 100 per tick). `Failed` is
   included on purpose: a block whose rule *was* installed but whose verification failed
   (scanner false negative, unreadable / localised netsh dump, parameter drift) is still live in
   the OS, and skipping it left that rule installed forever while the database had stopped
   tracking it.
2. For each row it calls `provider.UnblockAsync(ip, prefix, ct)` and flips the row to
   `Removed` (success or `NotFound`) or `Failed` (anything else, with `LastError` populated).
   The prefix is derived from the recorded `RuleHandle` (`"{prefix}-{ip}"`), so renaming
   `Firewall.BlockRuleName` cannot orphan a rule that is still blocking traffic; the configured
   prefix is the fallback and is retried when the first attempt returns `NotFound`.
3. It then queries the minimum future `ExpiresUtc` of `Active` / `Pending` rows and
   `Task.Delay`s until that time, capped at five minutes so a config change reaches the worker
   within a bounded latency. `Failed` rows deliberately do not drive the schedule: their
   `ExpiresUtc` is already past, so including them would collapse the wait to one second and
   spin the worker while a provider is down.
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
  A rule that exists but whose *effective* enforcement a third-party product may bypass (see
  below) counts here as enforced-with-caveat, so the header cannot claim `MissingRule` while the
  rules are right there.
* `ThirdPartyFirewallSuspected` / `ThirdPartyFirewallNote` (append-only keys 12 / 13) — the
  caveat itself: intended blocks exist, but a third-party security product may own packet
  filtering.
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

## Live-scan backend (PowerShell vs netsh)

Enforcement reconciliation enumerates the real firewall store through
`PowerShellFirewallRuleScanner`: the preferred backend is the locale-independent
`Get-NetFirewallRule | ConvertTo-Json` probe, with the legacy `netsh` text parse retained
as fallback (see `docs/40-options.md` for the related configuration keys).

To prevent a broken PowerShell host from being spawned on every reconciliation tick,
the scanner latches onto the netsh fallback after the first timeout or failure:

- `Firewall.PowerShellScanTimeoutSeconds` (default `30`) bounds each PowerShell probe.
- While latched, every scan is served by netsh and PowerShell is re-probed at most once
  per `Firewall.PowerShellRetryProbeIntervalMinutes` (default `15`) interval.
- The current backend ("PowerShellJson" / "NetshText") and the number of latch switch-overs
  are exposed via the IPC `GetStatus` payload (`FirewallScanBackend`, `FirewallScanSwitchCount`).

Both netsh queries whose output is *parsed* — the single-rule verification (`name=<X>`) and the
whole-store dump (`name=all`) — are spawned through the pinned-English console
(`cmd /d /c "chcp 437 >nul & netsh …"`, `TrustedEnglishConsoleTool`). On a localised host a
direct spawn returns translated labels ("Имя правила:", "Удалённый IP:"); the parser anchors on
English keys only, so such a dump parsed to zero rules and reconciliation then reported every
intended block as missing.

A zero-rule parse is therefore no longer trusted blindly: when the dump yields no rules **and**
carries none of the parser anchors (`Rule Name:`, `No rules match`), the scan reports
`Scannable = false` with an explanatory note. Reconciliation then treats enforcement as unknown
instead of `MissingRule` for every block — fail-closed, because an unreadable answer is never
"all clear".

## Third-party firewall coexistence (Kaspersky, ESET, Bitdefender)

RdpAudit only ever writes Windows Defender Firewall rules. When a third-party product
(Kaspersky Endpoint Security, Kaspersky Security for Windows Server, ESET, Bitdefender, …) is
installed, the rule still lands in the store, but the product may evaluate traffic first — so
"the rule exists" is not the same statement as "the packet is dropped". The product never
claims otherwise:

* `WindowsServiceThirdPartyFirewallProbe` collects services and CLI tools and derives the
  "KSWS manages the Windows Firewall" signal from the `kavfs*` service set — the same list the
  Configurator probe uses, so both halves of the product classify a host identically. Presence
  of the product is evidence of presence only, never proof of who filters traffic, and a
  Kaspersky Endpoint Security policy that manages the Windows Firewall exposes no service of
  that shape (so it is not claimed).
* `EnforcementReconciliationService` downgrades the confidence to
  `ExistsButProviderMayBypass` when a Windows Firewall profile is off **or** when the shared
  classifier reports a Kaspersky / unclassified third-party stack. The block stays `Active`
  (the rule exists), the health header stays honest (caveat counted as enforced-with-caveat),
  and the per-block line plus `ThirdPartyFirewallNote` state what is unproven.
* A Kaspersky policy that rejects rule writes surfaces as a provider failure: no row is written,
  the block is retried three times with backoff, and after the last attempt the worker logs an
  error pointing at the Firewall tab. **Repair** on the Active blocks tab re-installs the rule
  once the policy allows it.

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
