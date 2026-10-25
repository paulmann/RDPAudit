# Editions and the open-core split

This tree is the **Community** edition of RDPAudit. The split follows Stage 10 of the v3.0 plan:
one product line, three editions, one of which stays genuinely useful on a single server.

## How the split is enforced

The edition is a **compilation constant**, not a configuration switch:

* `Directory.Build.props` sets `RdpAuditEdition` (Community in this tree) and appends
  `RDPAUDIT_EDITION_<EDITION>` to `DefineConstants`.
* `RdpAudit.Core/Editions/EditionContext` turns that constant into `ProductEdition.Current`.
* The Service composition (`Program.cs`) only registers a gated component when the edition contains
  it, so a Community binary has no REST listener, no cross-host worker and no Zabbix worker to
  switch on. Editing `appsettings.json`, the settings document or the registry cannot add them.

Consequences worth knowing before changing anything here:

1. A gated worker is **absent** from a lower edition, so its unit tests construct it directly and
   still pass — they test behaviour, not the licence. The composition is what differs.
2. Every refusal is **loud**: `EditionAnnouncementWorker` logs the edition at startup and one
   warning per configured-but-absent capability, naming the edition that would work.
3. `GetEditionInfo` (IPC ordinal 102) answers from compile-time constants only, so it still works
   when the database, the provider or the network is degraded.

## Matrix

| Capability | Community | Pro | Enterprise |
|---|---|---|---|
| Local detection, 21 alert rules, local SQLite/WAL store | yes | yes | yes |
| Windows Firewall enforcement, whitelist, break-glass whitelist | yes | yes | yes |
| One MikroTik RouterOS v7 router (block + security audit) | yes | yes | yes |
| WinForms Configurator (22 tabs) | yes | yes | yes |
| Response dry-run (would-block without enforcement) | no | yes | yes |
| Read-only HTTPS REST API (`Api.Enabled`) | no | yes | yes |
| SIEM export (CEF / LEEF 2.0 / NDJSON) | no | yes | yes |
| Zabbix push channel and provisioning | no | yes | yes |
| Cross-host correlation (pull model), host budget 0 / 25 / 500 | no | yes | yes |
| Fleet collector, RBAC/SSO, HA collector, compliance reports | no | no | planned |

`planned` means: declared in the v3.0 roadmap, not implemented in any edition yet.
This tree is **Community**.

## Build

```powershell
dotnet restore RdpAudit.sln
dotnet build RdpAudit.sln -c Release --no-restore -p:Platform=x64
dotnet test  RdpAudit.sln -c Release --no-build -p:Platform=x64
```

This tree already pins its edition, so no extra property is needed. To build a different edition
from the same sources for comparison (for example in a lab):

```powershell
dotnet build RdpAudit.sln -c Release -p:Platform=x64 -p:RdpAuditEdition=Pro
```

A shipped package must be built from the tree that pins its own edition; overriding the property
on a release build would mislabel the artefact.

## Verify that a binary really is this edition

1. Configurator window title: `RdpAudit Configurator - <Edition>`.
2. Startup log / `startup-sequence.log`: `RDPAudit edition <Edition> (ordinal N, constant
   RDPAUDIT_EDITION_<EDITION>, licence ..., product version ...)`.
3. IPC: `GetEditionInfo` (102) returns the capability matrix, and the Configurator uses the same
   handler to draw the edition.
4. Tests: `tests/RdpAudit.Core.Tests/EditionsTests.cs` pins the matrix, the append-only ordinals and
   the "no capability without a declared minimum" rule.

## Licensing status

Decided on 25.10.2026.

* **Community ships the Business Source License 1.1** (`LICENSE`). Source-available: copy, modify,
  redistribute and non-production use are granted by the licence text itself; the `Additional Use
  Grant` in `LICENSE` allows production use as well, except offering the software to third parties
  as a commercial hosted or managed service. On **2030-10-25** this version converts to the
  **Apache License 2.0**.
* **Pro / Enterprise** carry a **placeholder** proprietary text, explicitly marked as not final
  legal text: seat counting, support scope, audit rights and liability must be written by the owner
  or counsel before distribution.
* **Earlier MIT grants are not revoked.** Code published under MIT before 25.10.2026 stays MIT for
  everyone who received it; this licence applies to this tree and to versions published from it.
  The pre-change repository, including its full history, is archived outside GitHub.
* The authoritative terms are the `LICENSE` file itself, not a badge or a sidebar label.

### What the Additional Use Grant deliberately does not allow

Offering RDPAudit Community as a paid hosted service to third parties. Everything else - including
running it in production on your own servers, for any number of hosts, at no cost - is permitted.
That is the point of an open core: the free edition must stay genuinely usable, or nobody builds
on it.
