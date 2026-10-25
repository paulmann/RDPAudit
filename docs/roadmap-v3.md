# docs/roadmap-v3.md - v3.0 plan mapped onto what actually exists

Source: the v3.0 development plan (ten stages). The column "state" is a statement about THIS
repository, verified against the code base, not an aspiration. A stage is "implemented" only when
there is a component, a gate and a test to point at.

| Stage | What the plan asks for | State in this tree | Edition |
|---|---|---|---|
| 1. Detection quality | confidence score, risk score, suppressions, baselines, reasoning trace, dry-run | **partial**: dry-run implemented (`Firewall.ResponseDryRun`, gated); alerts already carry reason tags, evidence and whitelist verdicts; scoring, suppressions and baselines are NOT implemented | dry-run: Pro+; the rest: all |
| 2. Safe response engine | TTL, rollback, break-glass, pre-flight, approval, audit journal | **partial**: TTL (default 3 days), manual unblock, whitelist and CIDR break-glass, `ActiveBlocks` lifecycle and the OperationLog audit trail exist; approval workflow and a one-command rollback journal are NOT implemented | core: all; dry-run rehearsal: Pro+ |
| 3. ETW and process context | Kernel-Process/File/Network providers, Threat-Intelligence, profiles, limits | **partial**: hybrid ETW ingestion of the existing security/RDP providers and zero-allocation normalization exist; kernel process/file/network providers and the Balanced/Security/Forensics profiles are NOT implemented | all |
| 4. Cross-host correlation | one IP across hosts, account across hosts, fail-then-success chains, incident model | **implemented (pull model)**: `CrossHostCorrelationWorker`, `CrossHostCorrelationEngine`, persisted facts/chains/links/host states; the incident entity as a first-class object is NOT implemented (chains are the current unit) | Pro (25 hosts) / Enterprise (500) |
| 5. Fleet management | optional Collector, mTLS transport, central incident store, policy distribution, fleet UI | **not implemented** - declared | Enterprise |
| 6. Integrations | Syslog CEF/LEEF, JSON HTTPS, WEF, OpenSearch, Sentinel, Wazuh, Graylog, Splunk HEC; multi-router MikroTik; AD response | **partial**: per-IP SIEM export (CEF/LEEF 2.0/NDJSON), the read-only REST API and the Zabbix sender are implemented; hub-style exports, multi-router MikroTik and AD actions are NOT implemented | Pro+ |
| 7. UI | Incident Console, entity cards, "why blocked", incident export, Blazor fleet UI | **partial**: 22-tab WinForms Configurator with RDP activity, session map, remote clients, database and diagnostics; Incident Console and the Blazor fleet UI are NOT implemented | all (current UI) |
| 8. Performance and reliability | bounded ring buffer, zero-allocation hot path, batched WAL writes, bookmarks, sharding, tiering, self-protection | **mostly implemented**: lock-free SPSC ring buffer, batched writes, bookmarks, shard ingestion, information-density retention, fingerprint chain, crash guard; cold tiering to Parquet and signed agent updates are NOT implemented | all |
| 9. Testing | unit, integration, adversarial, chaos | **partial**: 4400+ unit/integration tests including repository hygiene and documentation-drift contracts, adversarial rule tests and migration upgrade tests; a lab adversarial suite and chaos runs are NOT implemented | all |
| 10. Distribution and licensing | open-core split with Community / Pro / Enterprise | **implemented by this tree**: compile-time edition constants, capability matrix, composition gates, `GetEditionInfo` IPC, per-edition licences and edition documentation | all |

## What this means for the next increment

The order that follows from the table, cheapest first:

1. **Scoring and suppressions (Stage 1)** - pure Core logic plus one column each; they change the
   decision, not the plumbing, and they are the plan's own priority 1.
2. **Incident entity (Stage 4)** - turns existing correlation chains into the object the Incident
   Console and the collector both need.
3. **Multi-router MikroTik (Stage 6)** - the current options type describes one endpoint; widening
   it is a configuration-format change with a migration for existing settings documents.
4. **Kernel ETW providers (Stage 3)** - only after a resource-limit design exists, because an
   unbounded kernel provider on a busy server is how monitoring becomes the outage.
