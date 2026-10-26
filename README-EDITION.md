# RDPAudit 2.0 - Community edition

<!-- md-i18n:switcher -->
**Read this in:** English · [Deutsch](README-EDITION.de.md) · [中文](README-EDITION.zh.md) · [हिन्दी](README-EDITION.hi.md) · [Español](README-EDITION.es.md) · [Русский](README-EDITION.ru.md)

The free edition: one Windows server, local detection and local response, no fleet and no
integrations. This is the edition that must stay useful on its own - a single host with the
service, the Configurator and a Windows Firewall block is a complete product.

Included
--------
* Event collection: Security/RCM/LSM channels, hybrid ETW ingestion, ring buffer, WAL store.
* 21 alert rules, RDP activity statistics, session map, remote RDP client view.
* Windows Firewall enforcement with whitelist, CIDR ranges, break-glass whitelist and TTL.
* One MikroTik RouterOS v7 router: block rules plus the read-only security audit (S-00..S-35).
* WinForms Configurator (22 tabs) and the tray notifier.
* Local SQLite/WAL database with sharding, retention and backup/restore.

Not included (present in Pro)
-----------------------------
* Response dry-run (`Firewall.ResponseDryRun`).
* Read-only HTTPS REST API (`Api.Enabled`).
* SIEM export (CEF / LEEF 2.0 / NDJSON).
* Zabbix push channel and its provisioning commands.
* Cross-host correlation.

If any of those is configured here, the service starts normally, logs one explicit warning per
capability naming the edition that would work, and does nothing for it. It never refuses to start:
losing local detection because of a licensing mismatch would be worse than the mismatch.

Build and verify
----------------
    dotnet build RdpAudit.sln -c Release -p:Platform=x64
    dotnet test  RdpAudit.sln -c Release --no-build -p:Platform=x64

The window title ends with "- Community", and `GetEditionInfo` (IPC 102) reports which
capabilities this binary contains.
