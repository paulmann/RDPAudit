# 94 — MikroTik rule placement: why an appended block rule never fires

Purpose: record the failure mode that made MikroTik auto-blocks exist on the router without ever
dropping a packet, the measurements that prove it, and the contract the code now enforces. Read this
together with `docs/49-mikrotik.md` (provider semantics) — this page covers placement and RouterOS
query matching only.

## Symptom

After configuring a MikroTik router through the Configurator (setup bundle) or the RdpAudit.Mikrotik
wizard, auto-blocks are reported as `Success`, the rules are visible in `/ip firewall filter` and
survive reboot — and the attacker keeps connecting. Nothing in the service log says anything is
wrong, because at the API level nothing failed.

## Root cause

RouterOS appends a new firewall filter rule to the **end** of the table. The Stage 9 client sent
`PUT /rest/ip/firewall/filter` with `chain`, `action`, `src-address` and `comment` only, so every
block rule landed behind the rest of the configuration. On a default configuration the input chain
terminates with

```
add action=drop chain=input comment="defconf: drop all not coming from LAN" in-interface-list=!LAN
```

so a rule placed after it is unreachable for exactly the traffic that matters — RDP attempts from the
internet. The rule is real, counted, and dead.

## Measurements (lab router RB2011UiAS, RouterOS 7.23.1, `defconf`, 12 filter rows)

| Operation | Result |
|---|---|
| `PUT /rest/ip/firewall/filter` without `place-before` | new row at **position 14 of 14**, after the terminal input drop at row 7 |
| `PUT` with `"place-before":"0"` | new row at **position 1**, ahead of every configuration rule |
| `PUT` with a misspelled property (`place-befor`) | HTTP 400 `unknown parameter` — an old firmware fails loudly instead of silently appending |
| `POST /rest/ip/firewall/filter/move` `destination=0` | HTTP 400 `failure: cannot move builtin` (row 1 is the builtin fasttrack-counter rule) |
| `POST …/move` `destination=1` | succeeds, the row moves to position 2 — the earliest position reachable by `move` |
| `/ip firewall filter add … place-before=0` (SSH CLI, what the wizard issues) | same result, position 1 |
| block rule at position 1, traffic to its port attempted | the rule's counter increments and the connection fails |
| address-list entry with `timeout=00:00:25` behind a top-placed `src-address-list` drop | drops while present, entry disappears on its own after 25 s |

## Contract enforced by the code

* `MikroTikAddFilterRequest.PlaceBefore` defaults to `"0"`, so every rule created by
  `MikroTikClient.AddBlockAsync` is inserted above the first row of the table. A call site cannot
  forget the placement: the safe value is the default.
* `BlockPlacement.FilterInputTop` (previously `FilterInputAppend`) now states the same requirement
  for the wizard's contour analysis. "Appending is sufficient" was wrong advice, not a preference.
* On reuse, `AddBlockAsync` asks RouterOS to move the existing rule towards the front
  (`POST /rest/ip/firewall/filter/move`, `destination=1`). The request is best-effort: a rejection is
  logged at debug level and never fails the block.
* `MikroTikSetupCommands` and the wizard's bootstrap already used `place-before=0`; that form is
  measured to work over both the REST and the CLI path.

## RouterOS query semantics (`find` / `where` / REST `?prop=`)

REST has no private query engine: `GET /rest/ip/firewall/filter?src-address=x` compiles to the same
matcher as CLI `find where src-address=x`. A **list-typed** property matches only a literal written
exactly the way the row stores it. Measured against a row carrying `src-address=203.0.113.10` and
`dst-port=8728`:

| Query | Rows |
|---|---|
| `src-address=203.0.113.10` | 1 |
| `src-address=203.0.113.0/24` (network) | **0** |
| `dst-port=8728` | 1 |
| `dst-port=8700-8800` (range) | **0** |
| `dst-port=80,8728` (list) | **0** |
| `src-address=!203.0.113.10` (negation) | **0** |
| `action=fasttrack-connection`, `chain=input`, `comment=RdpAudit …` | matches |
| `comment~"^RdpAudit"` | works in CLI/API `where`; **not** as a REST query parameter (returns 0) |

Consequence: never build a lookup, `set` or `remove` on a network/range/negation `where` clause —
it matches nothing and the command completes as a silent no-op. Read the menu with `print`, match in
C#, act on `.id`. `RollbackExecutor`, `IntegrationValidator` and `MikroTikClient` already follow this
rule; the table above is the reason to keep it that way.

## Known gaps (open)

### 1. A failed unblock is terminal (B32, P3, OPEN)

`FirewallExpirationWorker.ExpireOneAsync` sets `ActiveBlockStatus.Failed` the first time a provider
refuses an unblock, and the sweep only ever selects `Active`/`Pending` rows. A router reboot or a
network blip at the wrong moment therefore leaves the rule on the router permanently, and
`EnforcementReconciliationService` does not touch MikroTik rows at all (its own comment: "External
MikroTik backend is not live-scanned by the local reconciler."). The `ActiveBlockStatus.Failed`
doc-comment claims "retry policy will apply"; no such policy exists for this provider.

Planned fix (not applied — no compiler here, and it changes expiry semantics for every provider):
keep the row `Active`, stamp `LastAttemptUtc`/`LastError`, add a bounded retry window in the due
query, and only give up after the window elapses.

### 2. Configuration traps that make a correct client look broken (B33, P3, OPEN)

* The Configurator never writes `BaseUrl`, but `MikroTikUrlBuilder` lets a non-empty `BaseUrl` win
  over `Host`/`Port`/`UseHttps`. A value set once (by hand or by an older template) silently makes
  the Host/Port fields on the tab decorative.
* `MikroTikOptions.AddressList` defaults to `rdpaudit-block` while the wizard provisions
  `rdpaudit_rdp_blocklist`. Enforcement uses filter rules, so the value is currently informational —
  but the two names disagree for no reason.
* `MikroTikOptions.MaxOperationsPerMinute` is declared, persisted and cloned, and enforced nowhere.

## Verification performed against the lab router

RB2011UiAS, RouterOS 7.23.1, `defconf`, 12 filter rows, REST over HTTP (443 closed). Every step below
was executed against the live device, not simulated:

| Step | Result |
|---|---|
| `GET /rest/system/resource` (provider probe) | 200 |
| `PUT` block rule with the product body | row at position 1, above the terminal defconf drop at 7 |
| re-block of the same IP | owned rule matched, no duplicate row created |
| `POST …/filter/move` with `{".id":"*N","destination":"1"}` on an **appended** rule | 200, row moves to position 2–3 |
| the same `move` on a rule that already sits ahead of the builtin row | 400 `failure: cannot move builtin` — the rule is already where it has to be, so the client treats this as "no repositioning needed" |
| unblock as the pre-fix code built it (`%2A15`) | **400 `no such command prefix`** — delete never reached |
| unblock with the id verbatim (`*15`) | 200 verify + 200 delete, row gone, table back to 12 |
| rule at position 1, TCP attempt from the blocked address | connection refused, rule counter incremented |
| address-list entry with `timeout` behind a top-placed drop | drops while present, expires on its own |

## Verification

With a configured provider, on the router:

```
/ip firewall filter print
```

RdpAudit rules (`comment~"^RdpAudit"`) must appear at the top of the table, above
`defconf: drop all not coming from LAN`. After a real block, watch the counter:

```
/ip firewall filter print stats where comment~"^RdpAudit"
```

A counter that stays at zero while the attacker keeps connecting means the rule is misplaced, not
that the trigger failed.

## Rollback

The change touches no schema, no IPC ordinal and no persisted state. Reverting the payload default
restores the previous behaviour (rules appended to the end of the table); reverting the client
restores percent-escaped ids (blocks become unremovable again). Rules already inserted at the top
stay where they are and are removed by the normal expiry path.

A router that still carries rules created by a pre-fix build can be cleaned in one command:

```
/ip firewall filter remove [find comment~"^RdpAudit"]
```
