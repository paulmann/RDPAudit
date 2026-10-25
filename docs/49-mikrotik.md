# 49 — MikroTik RouterOS v7 Integration

Stage 9 introduces an external firewall provider that drives a MikroTik RouterOS v7 device via its
REST API. When configured, the RdpAudit service writes per-IP firewall filter rules to the router
in addition to (or instead of) the local Windows firewall, and removes them automatically when the
configured block duration expires.

## Provider semantics

* **Endpoint composition** — either supply a freeform `BaseUrl` (`https://10.0.0.1:8443`) or let
  `Scheme/Host/Port` be composed by `MikroTikUrlBuilder`. The builder rejects unknown schemes,
  empty hosts, invalid host characters, out-of-range ports, and brackets IPv6 literals.
* **Authentication** — HTTP Basic with the configured `UserName` and the DPAPI-protected
  `Password`. The plaintext is never logged, never echoed in IPC payloads, never copied to the
  clipboard, and never written to appsettings without first being wrapped by `ISecretProtector`.
* **Probe endpoint** — `GET /rest/system/resource`. The probe is safe and read-only; failures map
  to controlled `MikroTikOutcome` values rather than throwing.
* **Block creation** — `PUT /rest/ip/firewall/filter` with body
  `{"chain":"<FilterChain>","action":"<FilterAction>","src-address":"<ip>","comment":"<prefix> ..."}`.
  The comment always starts with the configured `CommentPrefix` (default `RdpAudit`) and contains
  the UTC timestamp and the operator-supplied reason.
* **Idempotency** — before creating a rule the client lists owned rules
  (`GET /rest/ip/firewall/filter`) and reuses the existing row when its `src-address` and `chain`
  match. The provider then returns `FirewallActionStatus.Success` with the existing `RuleId`.
* **Block removal** — `DELETE /rest/ip/firewall/filter/<id>`. The client first performs a
  verifying `GET` and refuses to delete a row whose comment does not start with `CommentPrefix`.
  This guarantees the provider never touches a non-RdpAudit rule on the router.

## Configuration

```jsonc
"MikroTik": {
  "Enabled": false,
  "AddAttackerRules": true,
  "BaseUrl": "",            // wins over Scheme/Host/Port when set
  "UseHttps": true,
  "Host": "",
  "Port": 0,                // 0 = scheme default (443 / 80)
  "UserName": "",
  "Password": "",           // DPAPI-wrapped at rest
  "TimeoutSeconds": 15,
  "AddressList": "rdpaudit-block",
  "FilterChain": "input",
  "FilterAction": "drop",
  "CommentTemplate": "RdpAudit auto-block",
  "CommentPrefix": "RdpAudit",
  "ValidateServerCertificate": true,
  "MaxOperationsPerMinute": 120,
  "BlockDurationDays": 0,
  "BlockDurationHours": 1,
  "BlockDurationMinutes": 0
}
```

Block duration is the sum of the three TimeSpan components; when all components are zero the
service falls back to one hour to avoid permanent rules in the typical case.

## RouterOS v7 setup

The full copy-paste bundle is rendered on the MikroTik Configurator tab and produced by
`Core/MikroTik/MikroTikSetupCommands.BuildAll()`. The Configurator `Copy commands` button copies
the bundle verbatim; the bundle is also locked by `MikroTikSetupCommandsTests` so the placeholder
tokens never drift and no plaintext credential can be embedded.

Replace `<RDPAUDIT-HOST-IP>` with the IP of the RdpAudit host and `<STRONG-PASSWORD>` with a long
random password (≥ 24 chars) before pasting into the RouterOS terminal:

The bundle is generated, never copied by hand: `MikroTikSetupCommands.BuildAll()` produces it and
`MikroTikSetupCommandsTests` locks it (placeholders preserved, no credential embedded). Only the
load-bearing parts are quoted here; press `Copy commands` on the tab for the whole text.

The service user carries an address restriction. A full account without `address=` is the `S-01`
finding (critical) of the built-in audit, so the bundle must not produce one:

```
/user/add group=rdpaudit name=rdpaudit \
    password=<STRONG-PASSWORD> \
    address=<RDPAUDIT-HOST-IP>/32 \
    comment="RdpAudit service account"
```

Section 7 installs the blocking contour the standalone wizard uses — one address-list plus one drop
rule. The Service also writes its own per-IP rule (`src-address`, `place-before=0`); the contour
matters when the blocks are kept in a list:

```
/ip/firewall/address-list/add list=rdpaudit-block address=<RDPAUDIT-HOST-IP> timeout=00:01:00 comment="RdpAudit list anchor"
/ip/firewall/filter/add chain=forward action=drop src-address-list=rdpaudit-block comment="RdpAudit block list" place-before=0
```

* `chain=forward` drops attacker traffic aimed at the **hosts behind the router** — that is what
  protects RDP, and it is the placement the standalone wizard must use.
* `chain=input` drops traffic aimed at the **router itself** and nothing else: a contour installed
  only in `input` looks installed and protects no workstation.
* With fasttrack enabled, prefer `/ip/firewall/raw add chain=prerouting ...` over `filter`.

Security notes:

* The least-privilege policy bundle (`!ssh,!ftp,!telnet,!winbox,!web,!policy,!password,!sniff,!sensitive,!romon`)
  explicitly **denies** every shell-equivalent and credential-extraction capability — the
  `rdpaudit` user can only drive the REST endpoint and write firewall filter rules.
* `allowed-address` pins the REST service to the RdpAudit host's IP literal so a leaked
  credential cannot be replayed from any other origin.
* For production, bind a real certificate to `www-ssl` and pin `tls-version=only-1.2` (or
  `only-1.3` if the RouterOS build supports it). Leaving the Configurator's
  `Validate TLS certificate` toggle ticked enforces that the cert chain is honoured on
  every probe and block round-trip.
* The bundle never contains a real password — only the `<STRONG-PASSWORD>` placeholder. The
  `MikroTikSetupCommandsTests` suite asserts this explicitly.

## TTL cleanup

`FirewallExpirationWorker` sleeps until the earliest `ActiveBlocks.ExpiresUtc` for a row whose
status is `Active` or `Pending`, then calls the provider's `UnblockAsync`. The worker reuses the
existing next-expiration design — no hot polling — and falls back to a five-minute idle delay
when no blocks are due. Because the auto-block worker stores one `ActiveBlock` row per provider
(splitting `Both` into one row each for Windows and MikroTik) every rule has its own
`RuleHandle` and its own expiry timeline; a service restart picks up where it left off.

## IPC

* **GetMikroTikStatus (ordinal 29)** — returns `MikroTikStatusDto` with configuration flags,
  the resolved endpoint, the resolved scheme, the provider status (`Available`, `Unreachable`,
  `Disabled`, `NotConfigured`, `NotImplemented`), the active MikroTik block count, the configured
  chain/action/prefix/duration, and the last error. Never returns the password.
* **TestMikroTik (ordinal 30)** — runs a controlled `GET /rest/system/resource` probe and returns
  a `MikroTikTestResult` with `CredentialFormatValid`, `RemoteVerified`, the HTTP status, the
  sanitised endpoint and a human-readable message.

## Troubleshooting

| Symptom | Likely cause | Fix |
|---------|--------------|------|
| `MikroTikOutcome.NotConfigured` | Host or password missing, or URL composition failed | Re-open the MikroTik tab; check the status panel for the URL builder error |
| HTTP 401 from probe | Wrong username or password | Re-enter the password; remember it must be re-entered after Save (mask is opaque) |
| HTTP 403 from probe | Group policy missing `rest-api` | Re-create the user with the `policy=...,rest-api,...` group |
| TLS handshake failure | Bad certificate or self-signed cert | Either install a trusted cert OR untick "Validate TLS certificate" for lab use |
| Stale block stays on router | `ActiveBlock.RuleHandle` lost (DB reset) | The provider's `ListOwnedRulesAsync` only sees rules whose comment starts with the prefix; remove them manually with `/ip/firewall/filter remove [find comment~"^RdpAudit"]` |

## Stage-9 invariants

* No duplicate router rules — `AddBlockAsync` always lists owned rules before creating a new one.
* No deletion of non-RdpAudit rules — `RemoveBlockAsync` verifies the comment prefix before
  issuing `DELETE`.
* No request path built from an unchecked id — the rule id is concatenated into
  `/rest/ip/firewall/filter/<id>` and `Uri` normalises dot segments, so a value carrying `/` or
  `..` could address a different menu (for example `DELETE /rest/system/script`). The id must
  match a RouterOS handle (`*` plus hex digits) or the operation is refused before any request
  is built; `MikroTikClient.IsRouterOsRuleHandle` owns that rule.
* No plaintext password ever leaves the service host — Configurator only submits the password to
  the service via the existing SaveSettings IPC, which protects it with `ISecretProtector`.
* No hot polling — the expiration worker still waits on the earliest `ExpiresUtc`.

## Security audit: rules S-00 … S-35

The Configurator's `Security audit` button runs the RouterOS security catalogue against the configured
router and shows the report; the Service answers `GetMikroTikSecurityAudit` (95, long deadline). The
audit is **read-only by construction** — every call is a `GET`, and there is no apply variant.

The catalogue lives in code and is the single source of truth:
`src/RdpAudit.Core/MikroTik/SecurityAudit/SecurityAuditCatalog.cs` (37 entries: `S-00` … `S-35` plus
`S-27b`), the checks in `SecurityAuditEvaluator.cs`, the menu set in `SecurityAuditSections.cs`.
It was ported on 23.10.2026 from the validated Python reference (`rosctl/security.py`) that was
measured on a real RB2011 running RouterOS 7.23.1; that project is not a dependency and can be
removed — the behaviour it proved is reproduced by `tests/RdpAudit.Core.Tests/SecurityAuditTests.cs`.

Behaviour that must not be lost:

* **Risk index** `0..100`, weights fixed and tested: critical 40, high 15, medium 5, low 1, info 0,
  capped at 100. Verdict thresholds 0/15/40/70/100 (no findings · low · medium · high · critical).
* **Evidence is mandatory**: every finding carries `menu :: value`. A finding without proof is a
  report defect, not a style issue.
* **Silence is never compliance.** A menu that exists but cannot be read becomes `S-00` (high) and
  the rules over it do not run. A menu the device does not have (package absent) is listed under
  `unavailableMenus` and is not a finding. `system/resource` is read first as the probe: if the channel
  is broken the reply is `Unavailable` with the reason and **no findings at all**, so an empty report
  cannot be mistaken for a clean device.
* **Autofix classes** are `auto` / `manual` / `risky` / `none`, and only `auto` is a candidate for an
  automated pass. `manual` (rule order, account names, thresholds) and `risky` (cutting the channel
  in use — `api`, `admin`) are decisions, never defaults. This build applies nothing: the audit only
  reports.
* **No secrets in the report.** The SNMP community string (which *is* the password in v1/v2c), the
  `/system/note` text and every script secret are redacted: the finding names the object and the kind
  of secret (`script:backup-upload (password)`), never the value.
* **Bounded**: a 45-second budget for the menu walk, 60-second IPC deadline. Menus the budget did not
  reach are reported as unread (`S-00`), which keeps the coverage claim honest.

Two deliberate differences from the Python reference, both on the safe side: the reference prints the
SNMP community name and flags a disabled `admin` account; this port redacts the community name and
keeps the `admin` check as the reference does, so the two reports stay comparable.
