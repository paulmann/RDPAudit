# 48. AbuseIPDB integration

Stage 8 introduces the optional AbuseIPDB reputation / reporting integration. When enabled, the
RdpAudit service submits Stage 8 abuse reports to the public AbuseIPDB v2 API for hostile RDP
attack sources observed by the local monitor.

This integration is OFF by default. Reports are only sent when both an API key is configured **and**
the operator explicitly toggles **Report attacks to AbuseIPDB** in the Configurator.

## Threat model and privacy

The submitted report contains the source IP and aggregate evidence describing the observed RDP
attack. The submitted comment **never** contains:

* Passwords, tokens, hashes or any local credential material.
* Command-line content.
* Internal hostnames beyond the public IP being reported.
* Operator names or audit-log metadata that would identify a person.

Submitted fields:

* IP Address (the public hostile IP).
* Hostname (resolved reverse-DNS, or `Not resolved`).
* Connection Type: `RDP Attack` (constant).
* Failed Attempts (count).
* Successful Logins (count).
* First Seen / Last Seen (UTC timestamps).
* Usernames Attempted (up to five, deduplicated, control characters and delimiters stripped).
* Duration (Last Seen - First Seen, formatted).
* Attribution footer: `Reported via RDP Monitor https://github.com/paulmann/RDPAudit`.

Reports are deduplicated for a minimum of 15 minutes per IP (matching the AbuseIPDB server-side
limit) and rate-limited per hour and per day. Whitelisted IPs (database whitelist or
`Firewall.Whitelist*`) are never reported, regardless of threat score.

## Configuration

```json
"AbuseIpDb": {
	"Enabled": false,
	"ReportAttacks": false,
	"ApiKey": "",
	"BaseUrl": "https://api.abuseipdb.com",
	"EndpointUrl": "https://api.abuseipdb.com/api/v2/report",
	"TimeoutSeconds": 15,
	"MaxReportsPerMinute": 60,
	"MaxReportsPerHour": 100,
	"MaxReportsPerDay": 500,
	"DeduplicationWindowMinutes": 15,
	"CacheLookups": true,
	"CacheTtlMinutes": 60,
	"ReportThreshold": 80,
	"MinThreatScore": 60.0,
	"MinFailedAttempts": 10,
	"ReportCategories": [18, 22],
	"ReportDedupeEnabled": false,
	"ReportCooldownHours": 24
}
```

* `Enabled` — master switch. When false the HTTP client is never instantiated.
* `ReportAttacks` — when true (and `Enabled` is true) the report worker is permitted to submit.
* `ApiKey` — protected envelope (`{"$protected":"...","scope":"LocalMachine"}`). Plaintext keys
  supplied via Configurator are wrapped via DPAPI before persistence.
* `EndpointUrl` — the AbuseIPDB v2 report submission URL.
* `MinThreatScore`, `MinFailedAttempts` — local thresholds before an IP qualifies.
* `DeduplicationWindowMinutes` — minimum gap between successive reports of the same IP. Clamped to
  at least 15 minutes.
* `MaxReportsPerHour`, `MaxReportsPerDay` — local rate-limit caps. Both apply.
* `ReportCategories` — AbuseIPDB categories to submit (defaults to 18 SSH and 22 Brute-Force).
* `ReportDedupeEnabled` — when true, enforce a **success-filtered** per-IP cooldown ("1 report per
  1 IP" in the Configurator). Off by default.
* `ReportCooldownHours` — cooldown in hours (1..8760, default 24) before the **same** IP may be
  reported again *after a successful report*. Only consulted when `ReportDedupeEnabled` is true.

### Success-filtered report cooldown

The 15-minute `DeduplicationWindowMinutes` is an unconditional rate floor against *any* recent
attempt. `ReportDedupeEnabled` adds an independent, longer cooldown that is gated only on the most
recent **successful** report for the IP, persisted in the `AbuseIpDbReportHistory` table:

* Every report attempt — success or failure — is recorded in `AbuseIpDbReportHistory` (normalized
  IP, UTC timestamp, `Succeeded`, HTTP status, sanitised result/error, categories, SHA-256 hash of
  the comment, source tag). The API key is never written.
* Before submitting, when dedupe is enabled, the worker looks up the latest **successful** report
  for the normalized IP. If it falls within `ReportCooldownHours`, the worker suppresses the report
  with reason `WithinReportCooldown` — no HTTP call is made.
* **Failed** attempts never suppress a future report: a rejected / rate-limited / transport-error
  attempt leaves the IP eligible to be retried as soon as the 15-minute floor elapses.
* The cooldown is independent of the 15-minute floor; both must pass for a report to be sent.

The `ApiKey` field is **always** stored as an encrypted envelope on Windows hosts. On non-Windows
test hosts (no DPAPI), the SettingsManager logs a warning and persists plaintext **only** if no
secret protector is registered. The production service registers DPAPI unconditionally on Windows.

## API key — obtain and configure

1. Create an account at <https://www.abuseipdb.com/register>.
2. Open the API section, copy your personal v2 key (80 hex characters).
3. In the Configurator, open the **AbuseIPDB** tab.
4. Paste the key into the API key field (password-style by default).
5. Click **Save settings** — the key is sent to the service via IPC and DPAPI-wrapped at rest.
6. Click **Test key** — the service issues a safe read-only probe against `/api/v2/check`
   (loopback IP, no report submission). On success, tick **Report attacks to AbuseIPDB** and save.

## Reporting worker

`AbuseIpDbReportWorker` is a `BackgroundService` that periodically (every 5 minutes after a
1-minute startup delay) scans the materialised `AttackStats` table for IPs with `ThreatScore >=
MinThreatScore` and `Failed >= MinFailedAttempts`. For each candidate it applies the policy
decision (`AbuseIpDbPolicy.Decide`) and only submits when:

* `Enabled && ReportAttacks` is true.
* `ApiKey` is configured.
* The IP is public (`IpClassifier.IsPublicIp`).
* The IP is not whitelisted.
* Threat score and failed-attempt thresholds are met.
* The dedup window has elapsed since the last report for that IP.
* When `ReportDedupeEnabled` is true, no **successful** report exists for the IP within
  `ReportCooldownHours`.
* Hourly and daily caps have not been reached.

Outcome handling:

* `Accepted` (2xx) — recorded in `AbuseReports`, dedup window starts.
* `RateLimited` (429) — worker pauses for `Retry-After` (minimum 1 minute) and resumes on the next
  cycle. The HTTP outcome is recorded in `AbuseReports`.
* `ServerError` (5xx) — worker pauses for 10 minutes.
* `Rejected` (4xx) — operator-actionable error (typically bad key or malformed payload). Recorded
  for audit.
* `TransportError` — network / DNS / TLS / timeout failure. Recorded.

Every attempt — success or failure — produces an `AbuseReports` row so dedup, audit, status and
counter queries observe the same source of truth. When `ReportDedupeEnabled` is true, each attempt
*also* produces an `AbuseIpDbReportHistory` row, which is the source of truth for the
success-filtered cooldown described above.

## IPC commands

| Ordinal | Command                | Direction | Purpose                                              |
| ------- | ---------------------- | --------- | ---------------------------------------------------- |
| 27      | `GetAbuseIpDbStatus`   | C → S     | Returns `AbuseIpDbStatusDto` (no plaintext key).     |
| 28      | `TestAbuseIpDbKey`     | C → S     | Validates the configured key via a safe read-only probe. |

`GetAbuseIpDbStatus` reports `CredentialPresent`, `ReportingEnabled`, total/hour/day counters,
last response code / IP / error, dedup window and hourly/daily caps. The API key is never echoed.

`TestAbuseIpDbKey` performs a format check (80-hex canonical, 40..128 accepted) and, when the
client is available, calls `/api/v2/check?ipAddress=127.0.0.1` to confirm the key is accepted.
This call never submits an abuse report.

## Configurator tab

The **AbuseIPDB** tab includes:

* A read-only intro panel describing AbuseIPDB, privacy properties of the report payload, the
  steps to obtain a key, and the third-party data-sharing warning.
* A password-style API key input with a `Show key` toggle.
* A `Report attacks to AbuseIPDB` checkbox (enabled only after a key is configured).
* A `1 report per 1 IP` checkbox plus a `Cooldown hours before reporting same IP again` numeric
  input (1..8760). The numeric is enabled only while the checkbox is ticked. Invalid values are
  rejected before save. Both values round-trip via `GetAbuseIpDbStatus` so they re-display after a
  Configurator restart.
* Buttons: `Save settings`, `Test key`, `Refresh status`, `Clear key`.
* Status read-out: credential present / not configured, endpoint URL, counters, last report
  result, rate-limit state.
* Red warning text: reports are sent to a third-party service and include source IP + attack
  metadata.

The UI never persists or displays the API key plaintext. The service responds to `GetSettings`
with a masked string (`***configured***`) for any non-empty secret envelope; the Configurator
treats that placeholder as a do-not-overwrite sentinel.

## Troubleshooting

* **Test key returns HTTP 401 / 403** — the key is rejected by AbuseIPDB. Re-paste it and try
  again. The format validator passes any 40..128 hex string, but the canonical AbuseIPDB v2 key is
  exactly 80 hex characters.
* **Reports never submit even with a valid key** — confirm:
  * `Enabled` is true.
  * `ReportAttacks` is true.
  * `AttackStats.ThreatScore >= MinThreatScore` for the IP.
  * `AttackStats.Failed >= MinFailedAttempts`.
  * The IP is public (`IpClassifier.IsPublicIp`) and not whitelisted.
  * Hourly / daily caps have not been reached.
* **`AbuseReports` table grows quickly** — the maintenance worker does not currently prune it;
  rows are retained for audit. If volume becomes an issue, extend `MaintenanceWorker` with a
  retention policy.
* **Rate-limited (429) repeatedly** — lower `MaxReportsPerHour` and `MaxReportsPerDay` to reduce
  outbound pressure, or raise `MinThreatScore` and `MinFailedAttempts` to be more selective.

## Security guarantees

* The API key is **never** logged, never echoed in IPC responses, never copied to the clipboard,
  and never included in diagnostics bundles. The only place the plaintext lives in memory is the
  `Unprotect` call site immediately before the outbound HTTP call.
* The protected envelope is bound to `SecretScope.LocalMachine` so SYSTEM and Administrators on
  the same host can decrypt, but the envelope cannot be transferred to another machine without
  re-protecting.
* The submitted report comment is sanitised character-by-character before submission.
