# Alert rule catalogue

All 21 alert rules live under `src/RdpAudit.Service/Alerts/` and are registered in `Alerts/AlertRuleRegistration.cs`.

| RuleId | MITRE | Trigger event(s) | Severity | Logic |
|--------|-------|------------------|----------|-------|
| `BRUTE_FORCE_01` | T1110 | 4625 | High | ≥ N failures from same IP in window |
| `BRUTE_FORCE_NTLM` | T1110 | 4776 | Medium | ≥ N NTLM failures from same source |
| `PASS_THE_HASH` | T1550.002 | 4624 (Type 3/9, NTLM) | High | No preceding 4648 with matching LogonId |
| `GOLDEN_TICKET` | T1550.003 | 4769 | Critical | RC4 (`0x17`) ticket on AES-only domain |
| `OFF_HOURS_LOGIN` | T1133 | 4624 (Type 10) | Low | Outside business hours |
| `EXTERNAL_RDP_LOGIN` | T1133 | 1149 / 4624 | Medium | `IpClassifier.IsPublicIp == true` |
| `RDP_SESSION_HIJACK` | T1563.002 | 4688 | Critical | `tscon.exe` or `mstsc /shadow` |
| `RAPID_RECONNECT` | T1563.002 | 25 | Medium | Reconnect from different IP within N seconds of 24 |
| `UNKNOWN_IP_SUCCESS` | T1021.001 | 4624 | Low | First success from IP after ≥ N prior failures |
| `PRIVILEGED_LOGIN` | T1078 | 4672 | Medium | Sensitive privileges in details; hardened (see below) |
| `PROCESS_ANOMALY` | T1059 | 4688 | Medium | Shell child of svchost / mstsc / rdpclip / explorer |
| `LSASS_ACCESS` | T1003 | 4656 | Critical | Sensitive AccessMask on lsass with non-whitelisted accessor |
| `TASK_PERSISTENCE` | T1053 | 4698 | High | Scheduled task created |
| `TASK_MODIFIED` | T1053 | 4702 | Medium | Scheduled task updated |
| `SERVICE_INSTALL` | T1543 | 4697 | High | New service installed |
| `NEW_ACCOUNT` | T1136 | 4720 | High | New user account created |
| `PRIVILEGED_GROUP_CHANGE` | T1098.002 | 4728 / 4732 / 4756 | High | Addition to a configured privileged group |
| `STICKY_KEYS_BACKDOOR` | T1546.008 | 4657 / 4688 | Critical | IFEO modification on accessibility binary or shell from winlogon |
| `RDP_PORT_CHANGED` | T1572 | 4657 | Critical | Terminal Server `RDP-Tcp\PortNumber` modified |
| `LSASS_PPL_TAMPER` | T1003 | 4657 | Critical | LSA `RunAsPPL` modified |
| `KERBEROS_SPRAY` | T1110 | 4771 | High | ≥ N pre-auth failures from same IP |

## PRIVILEGED_LOGIN hardening

Event 4672 fires thousands of times in normal Windows operation (every service logon under `SYSTEM`, `LOCAL SERVICE`, `NETWORK SERVICE` assigns privileges), so the rule applies five gates before anything can alert:

1. **Well-known service SID filter.** SIDs `S-1-5-18` (SYSTEM), `S-1-5-19` (LOCAL SERVICE) and `S-1-5-20` (NETWORK SERVICE) are rejected unconditionally - they are normal service noise, never an attacker logon.
2. **Network-context requirement.** The event must carry a non-empty source IP and a network LogonType (`3`, `7`, `10`). A missing LogonType resolves the companion Security 4624 through `IAlertContext` before the event can alert.
3. **Per-key suppression window.** Identical (user, source IP, logon type) triggers inside `Alerts.PrivilegedLoginSuppressionWindowMinutes` (default 5) are counted but not alerted; one summary alert carrying the suppressed count is emitted when the window expires.
4. **Per-minute alert budget.** `Alerts.PrivilegedLoginRateLimitPerMinute` (default 20) caps how many alerts this rule can emit per minute; once exhausted, further alerts are dropped and the throttling fact is logged once per minute.
5. **Historical-event age gate.** `Alerts.AlertEventMaxAgeMinutes` (default 5) is applied by `AlertWorker` to every rule: older events (backfill / replay / first-start hydration) are persisted as facts but never alerted on.

All thresholds live in `AlertOptions` and are exposed in the default `appsettings.json` templates (`AppSettingsTemplate` for the service, `DefaultAppSettings` for the Configurator) - none are hard-coded. The rejection paths ahead of the alert decision are allocation-free so hostile event floods skip the rule without GC pressure.

## Adding a rule

1. Implement `IAlertRule` (or extend `AlertRuleBase`).
2. Use a unique SCREAMING_SNAKE_CASE `RuleId` and a stable enum mapping in `AlertSeverity`.
3. Register in `AlertRuleRegistration.Register`.
4. Add unit tests covering at minimum: below-threshold, at-threshold, whitelisted IP, wrong event id.

## LLM contract

- Rules must be pure: no I/O outside `IAlertContext` / `RawEvent` parameters.
- Each rule's `EvaluateAsync` must complete quickly; no `Task.Delay`, no expensive regex on every call.
- New thresholds must be added to `AlertOptions` with sane defaults — never hard-code.
