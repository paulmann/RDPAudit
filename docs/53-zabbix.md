# Zabbix integration

Status: implemented in the service, the IPC surface and a dedicated Configurator tab.
All protocol and API facts below were measured against the owner's live instance
(`https://22877.ru`, Zabbix 8.0.0, `api_jsonrpc.php`) on **2026-10-25**, not taken from documentation.

## 1. What problem this solves

A Windows fleet runs RDPAudit 2.0 on several machines. Each machine knows about its own attackers and
nothing about the others. An operator who wants one list of "what is being attacked right now, across
the whole fleet" needs a common place, and the organisation already has Zabbix.

So the product does two separate things:

1. **Push** — every machine forwards its RDP incidents to Zabbix as item values over the native sender
   protocol. This runs continuously and is what the tab configures.
2. **Provision** — once per fleet, an operator presses *Provision in Zabbix*. The service creates the
   host group, the host, the seven items, the trigger set and one shared dashboard through the
   JSON-RPC API. After that every machine lands in the same Problems list without manual Zabbix work.

## 2. Why the sender protocol and not the API

This was decided by measurement, not taste.

| Path | Result on 2026-10-25 |
|---|---|
| Sender protocol, TCP 10051, trapper item | works: `processed: 1; failed: 0; total: 1`, the trigger fired, `problem.get` returned the event, a value below the threshold closed it |
| `history.push` over HTTPS (port 443) | refused: `{"response":"success","data":[{"error":"Client IP is not in item's allowed hosts list."}]}` |
| `item.create` with `allowed_hosts` to open that list | refused: `Invalid parameter "/1": unexpected parameter "allowed_hosts"` |

Consequence: an external system cannot write item values through the web port, so the sender protocol
is the only supported delivery path. It needs **TCP 10051** from each monitored machine to the Zabbix
server or proxy.

Reachability was checked on the actual fleet the same day: `192.168.1.50`, `192.168.1.60` and
`192.168.3.100` all reach `192.168.31.31:10051`, and so does the workstation. From the public internet
the port is **not** open on `22877.ru` (the router forwards only 80/443), so a machine outside the LAN
would need a forward or a Zabbix proxy. The tab's *Test connection* names the port in the failure
message instead of saying "connection failed".

## 2.1 The allowed-hosts trap (measured, and the reason provisioning sets it)

A Zabbix trapper item is **not** open to whoever connects to port 10051. It carries an allowed-hosts
list whose default is loopback, and the server log says exactly that:

```
cannot process item "rdpaudit.agent.status" trap: connection from "192.168.31.100" rejected,
allowed hosts: "127.0.0.1,::1"
```

The trap is how it looks from the sender: the protocol answers `response: success` with
`processed: 0; failed: 7; total: 7`. Nothing is stored, nothing is logged on the sender, and the
symptom reads like a wrong item key.

So provisioning writes `trapper_hosts` on every item it creates. When `TrapperAllowedHosts` is empty
(its default) the service uses **this machine's own unicast addresses**, which is what a normal install
needs. The value is a union, never a replacement: if an operator already added entries, or the item
carries the `{$TRAPPER.ALLOWED_HOSTS}` macro, those entries stay and ours are appended. Existing items
of this integration whose list does not cover the machine are corrected and counted
(`items allowed-hosts widened N`) — that is maintenance of our own object, and no other setting of an
existing item is touched.

Set `TrapperAllowedHosts` explicitly (comma-separated hosts, addresses or CIDRs, `*` for any) when the
machine is seen through NAT and its source address is none of its local addresses.

## 3. The item set

Seven items per machine host, all of type **Zabbix trapper** (`value_type` 3 = unsigned, 4 = text):

| Key | Type | Meaning |
|---|---|---|
| `rdpaudit.incidents` | text | JSON document of the batch: every incident with id, rule, severity, address, account, message and the `ipDerived` flag |
| `rdpaudit.incidents.count` | unsigned | incidents in the batch |
| `rdpaudit.incidents.max_severity` | unsigned | highest Zabbix severity in the batch, **0 when the batch is empty** |
| `rdpaudit.push.sequence` | unsigned | monotonic counter, so a gap is visible even when two payloads are identical |
| `rdpaudit.agent.status` | unsigned | 1 on every cycle; a `nodata(15m)` trigger turns "the agent died" into a problem |
| `rdpaudit.machine.summary` | text | JSON: machine, version, uptime, counters, active blocks, pending backlog |
| `rdpaudit.blocks.active` | unsigned | enforced blocks right now |

`max_severity` is the item the trigger set keys off. It is deliberately a **level**, not a flag: the
value is the Zabbix severity of the worst incident in the batch.

## 4. The trigger set, and why the expressions are exclusive

Six triggers per host:

| Trigger | Expression | Priority |
|---|---|---|
| critical incident | `last(/host/rdpaudit.incidents.max_severity)=5` | Disaster |
| high incident | `…=4` | High |
| medium incident | `…=3` | Average |
| low incident | `…=2` | Warning |
| informational | `…=1` | Information |
| agent silent | `nodata(/host/rdpaudit.agent.status,15m)=1` | Average |

Expressions are `=N`, not `>=N`. With a `>=` chain one Disaster batch would open five problems at once
and the operator would see a single incident five times. Each exact level fires alone, and any value
below the floor closes it — which is why a quiet cycle still pushes `max_severity=0` rather than
skipping the push. Measured: pushing 4 opened one problem (severity 5); pushing 1 produced the recovery
event and `problem.get` came back empty.

Every trigger carries the tags `scope=rdpaudit`, `component=rdp-audit` and `trigger=<key>`.

## 5. "All machines in one window"

Three layers, in increasing order of usefulness:

1. **Host group** `RDPAudit` — every machine that runs the agent. The group name is configurable.
2. **Event tag** `scope=rdpaudit` — filters the Problems view to this integration only, so Zabbix's
   other monitoring does not drown the incident list.
3. **Shared dashboard** `RDPAudit fleet - incidents` — one Problems widget filtered by that tag.
   Created by the first provisioning; a second run recognises it by name and leaves it alone.

The tab's *Open all incidents* button opens
`/zabbix.php?action=problem.view&filter_set=1&tags[0][tag]=scope&tags[0][value]=rdpaudit&tags[0][operator]=1`,
verified to answer `200` on the live instance.

Trigger names carry the `{HOST.NAME}` macro, so the fleet-wide list reads
"RDPAudit: critical RDP security incident on win-bsg-50" instead of six identical rows.

## 6. Delivery semantics

The server's answer is **not** a delivery receipt:

```
{"response":"success","info":"processed: 0; failed: 1; total: 1; seconds spent: 0.000012"}
```

That is the answer the live server produced when the host was not yet known — every value rejected,
envelope says success. So the rule the code implements, and the tests pin:

* **delivered** = `failed == 0` **and** `total > 0` **and** `processed == total`;
* anything else is a failure, recorded with the server's own counters;
* the persisted position (`LastPushedAlertId`) advances **only** on delivery.

The position lives in `%ProgramData%\RdpAudit\zabbix-push-state.json`, written atomically (temp file
plus replace). A crash between "sent" and "recorded" re-sends the same batch, which overwrites the same
item values instead of duplicating them. An unreadable state file is moved aside with a timestamp and
the position restarts at zero — again re-sending rather than losing.

**A freshly provisioned host is not known to the trapper immediately.** Measured: the first pushes
after creation fail for about ten seconds while Zabbix syncs its configuration cache, and the answer
still says `success`. The tab reports "0 of 7 accepted" and the next cycle succeeds; nothing is lost.

## 7. Bounded backlog

`MaxBacklogIncidents` (default 500) caps what the machine is willing to queue for Zabbix. Above it the
push keeps the **newest** incidents, counts the rest as `skipped`, reports that count in the payload, in
the status DTO and in the log, and advances the position past them.

This is deliberate and documented rather than silent: Zabbix is a notification channel, while the local
SQLite database is the evidence store. An incident that never reached Zabbix is still in `Alerts`, still
queryable, and still subject to retention.

## 8. Configuration

Settings live in `RdpAudit:Zabbix` inside `%ProgramData%\RdpAudit\appsettings.json`:

| Key | Default | Notes |
|---|---|---|
| `Enabled` | `false` | fail-closed: nothing is sent until an operator turns it on |
| `ServerHost` / `ServerPort` | empty / `10051` | server or proxy that accepts the sender protocol |
| `HostName` | empty | technical name; empty means "use the machine name", sanitized either way |
| `HostGroup` | `RDPAudit` | group created during provisioning |
| `ApiUrl` | empty | frontend URL; the API endpoint is derived from it |
| `ApiToken` | empty | DPAPI envelope; preferred credential |
| `ApiUser` / `ApiPassword` | empty / empty | alternative credential; the password is an envelope |
| `ValidateServerCertificate` | `true` | the exemption exists for self-signed on-premises servers |
| `TimeoutSeconds` | `15` | one sender round-trip or one API call |
| `PushIntervalSeconds` | `60` | cadence; also the heartbeat cadence |
| `MinimumSeverity` | `Medium` | lower severities advance the position without being forwarded |
| `MaxIncidentsPerPush` | `20` | per-batch cap |
| `MaxBacklogIncidents` | `500` | backlog ceiling (section 7) |
| `ProvisionTriggers` / `CreateDashboard` | `true` / `true` | what provisioning creates |

Credentials are protected by `SettingsManager`, the same DPAPI path as the AbuseIPDB key and the
MikroTik password. `GetZabbixSettings` masks both fields; an unchanged field comes back as
`***configured***` and the stored envelope is written back verbatim, so saving the tab can never destroy
a token.

## 9. Host-name sanitization

The technical host name is embedded into trigger expressions of the form `last(/host/key)`. A name
containing `)`, `,`, `=` or `>` would rewrite the expression instead of naming a host. `ZabbixHostName`
therefore keeps only letters, digits, `.`, `_` and `-`, collapses runs of replacements and caps the
length at 128. `host/with)injection=5` becomes `host-with-injection-5`.

## 10. Operator procedure

1. Fill in the server, the frontend URL and an API token; **Save changes**.
2. **Test connection** — expect "sender reachable | API reachable (8.0.0, credential accepted)".
   If the sender is unreachable, open TCP 10051 from this machine to the server, or point the agent at a
   proxy; the API on 443 can be perfectly fine while the push path is closed.
3. **Provision in Zabbix** — idempotent; a second run reports "already present".
4. Wait about a minute for the configuration cache, then **Push now**: expect
   "Delivered — N incident(s), 7/7 value(s) accepted".
5. Turn on **Send RDP incidents to Zabbix** and save; the worker pushes every
   `PushIntervalSeconds` without a service restart.
6. **Open all incidents** — the fleet-wide Problems view.

## 11. What is deliberately not done

* No delete, no update of an existing object during provisioning — the API client is additive only, so
  an operator's local tuning of a trigger is never overwritten.
* No TLS on the sender path: the sender protocol is plain TCP by design; encryption is a proxy concern.
* No auto-block reaction to Zabbix. The integration reports; it never enforces. An acknowledgement in
  Zabbix does not unblock anything, and a Zabbix outage never blocks enforcement.
* No event-per-incident in Zabbix. A Zabbix problem is per-machine state (level plus heartbeat); the
  per-incident detail is the JSON item. One problem per incident would need a trapper item per
  incident, which Zabbix does not model.

## 12. Verification performed

| What | Result |
|---|---|
| Provisioning calls against Zabbix 8.0.0 | `hostgroup.create`, `host.create` (no interface), `item.create` (type 2, delay 0), `trigger.create` (with tags), `dashboard.create` (problems widget plus tag filter) all accepted |
| Sender protocol against the same server | known host `processed: 1; failed: 0`, unknown host and unknown key `failed: 1` |
| Incident lifecycle | value 4 → problem severity 5 open; value 1 → recovery event, no open problem |
| Fleet reachability of 10051 | `192.168.1.50`, `192.168.1.60`, `192.168.3.100`, workstation — all connect |
| Frontend links | filtered Problems view and dashboard view both `200` |
| Allowed hosts | item carries `trapper_hosts` from provisioning; before it did, the server rejected every value from `192.168.31.100` with `allowed hosts: "127.0.0.1,::1"` |
| Shipped-code end-to-end | `ZabbixApiClient.ProvisionAsync` → `ZabbixIncidentPayloadBuilder` → `ZabbixSenderClient`: 7 of 7 values accepted from this workstation, event 21399 opened at severity 4, event 21400 closed it, `problem.get` empty afterwards |
| Cleanup | every object created by the probes was deleted; no probe host or group left behind |
| Build | `dotnet build RdpAudit.sln -c Release -p:Platform=x64` — 0 warnings, 0 errors |
| Tests | new: 27 (Core), 12 (Service), 5 (Configurator); full suite green after the change |

## 13. Rollback

The integration is additive and can be switched off without touching data:

1. Clear `Enabled` (or set it back to `false` in `appsettings.json`) and save — nothing is sent.
2. Delete `%ProgramData%\RdpAudit\zabbix-push-state.json` to forget the position; the next enable
   re-sends the incidents that are still in the database rather than skipping them.
3. On the Zabbix side, disable the host or remove the trigger set; nothing else references an RDPAudit
   object there.
4. Removing the code does not migrate anything: this feature owns no database migration.
