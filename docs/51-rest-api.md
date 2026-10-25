# Read-only HTTPS REST API (Backlog #3)

RdpAudit exposes an **optional, strictly read-only** HTTPS REST API driven by Kestrel
inside the Windows service itself. It reuses the same audited read commands that back
`docs/50-ipc.md`: every `GET`/`HEAD` on the API is answered by the existing
`IpcDispatcher` handlers or by the dedicated read-only event reader, so the REST
surface adds **zero write paths** to the product.

The API is disabled by default. Until an operator enables it through the `Api`
configuration section, the service starts no HTTP(S) listener at all (fail-closed).

## Why this API exists

RdpAudit historically exposes operational reads only through a named pipe restricted to
`BUILTIN\Administrators` (`\\.\pipe\RdpAuditService`). That channel is excellent for the
interactive Configurator but impractical for monitoring agents and scripts. The REST API
lets an operator give a **read-only bearer token** to a monitoring tool so it can pull
status, alerts, sessions, configuration and raw events over HTTPS **without ever being
able to mutate state** - no settings, no blocks, no acknowledgements, no session control.

The canonical contract lives in `src/RdpAudit.Service/RestApi/openapi-v1.json`. The
service serves that same file verbatim at `/openapi/v1.json`, and the test suite locks
the committed file, the embedded copy and the runtime route table together
(`RestOpenApiDriftScenarioTests`) so they can never drift apart.

## Enabling the API

All settings come from the `Api` section of `%ProgramData%\RdpAudit\appsettings.json`
(see `docs/40-options.md` for the full field table). Minimum working configuration:

```json
"Api": {
  "Enabled": true,
  "Token": "<long random secret>",
  "ListenAddress": "127.0.0.1",
  "Port": 8443,
  "CertificateThumbprint": "<thumbprint of your server TLS certificate>"
}
```

There is no Configurator UI for the API in this delivery; the section is edited in
`appsettings.json` (or merged by the operator's configuration management). After
changing the file, restart the service.

On the first save the plaintext `Token` is wrapped into a protected DPAPI envelope by
`SettingsManager` exactly like `AbuseIpDb.ApiKey` and `MikroTik.Password`; the plaintext
is never logged, never echoed over IPC (`GetSettings` returns a masked value), and never
written into status DTOs.

### Startup decision (fail-closed)

`RestApiPlanBuilder.Build` evaluates the configuration once at startup and produces one
of three outcomes:

| Outcome | Meaning |
|---|---|
| `Disabled` | `Api.Enabled` is false - no listener is started. |
| `FailClosed` | A prerequisite is missing (invalid listen address, missing/unprotectable token, no matching certificate, untrusted certificate without the loopback opt-in, untrusted certificate on a non-loopback address) - no listener is started and the reason is logged as a warning. |
| `Listening` | Kestrel starts on `ResolvedAddress:Port` with the resolved token. |

All numeric settings are clamped by `ApiOptions.Resolve*` helpers: `Port` to 1..65535,
`MaxConnections` to 1..10 000, `RateLimitPerMinute` to 1..60 000. A blank
`ListenAddress` resolves to `127.0.0.1`.

### TLS certificate

* `CertificateThumbprint` - thumbprint of the server certificate in
  `LocalMachine\My`; takes precedence.
* `CertificateSubject` - fallback when `CertificateThumbprint` is blank.
* `AllowInsecureLoopback` - when `true`, an untrusted (e.g. self-signed) certificate is
  accepted **only on a loopback listener**. The host logs an explicit risk warning.

There is no plaintext-HTTP mode. Certificates are selected by the
`RestApiCertificateResolver` and attached to the Kestrel endpoint configuration at
startup.

## Authentication

Every endpoint except `GET /healthz` requires:

```
Authorization: Bearer <Api.Token>
```

Failures return `401 Unauthorized` with `WWW-Authenticate: Bearer realm="rdpaudit"` and
an RFC 9457 problem body. Requests for API-prefixed paths without a token never reach
an endpoint handler; the bearer middleware applies the simple constant-time token
comparison against the DPAPI-unwrapped startup token.

## Endpoints

| Method | Path | Purpose | Anonymous |
|---|---|---|---|
| `GET` / `HEAD` | `/healthz` | Liveness probe with `{"status":"ok","bindings":[...]}`. | yes |
| `GET` / `HEAD` | `/api/status` | Runtime service snapshot from `GetStatus`. | no |
| `GET` / `HEAD` | `/api/alerts` | Up to 200 newest alerts from `GetRecentAlerts`. | no |
| `GET` / `HEAD` | `/api/sessions` | Up to 500 newest RDP sessions from `GetSessions`. | no |
| `GET` / `HEAD` | `/api/addresses` | Up to 500 newest per-IP aggregates from `GetAddresses`. | no |
| `GET` / `HEAD` | `/api/attacks` | Filtered attack-statistics snapshot from `GetAttackStats`. | no |
| `GET` / `HEAD` | `/api/config` | Current settings from `GetSettings` with **all secrets masked**. | no |
| `GET` / `HEAD` | `/api/events` | Bounded, filtered page of raw telemetry. | no |
| `GET` / `HEAD` | `/openapi/v1.json` | This committed OpenAPI 3.0.3 descriptor. | no |

All other methods (`POST`, `PUT`, `DELETE`, ...) answer `405 Method Not Allowed` with a
problem body and an `Allow: GET, HEAD` header. Request bodies are never read - the API
surface has only read semantics by construction.

### `/api/events` query parameters

`/api/events` reads raw rows through `IPagedEventReader` (see below) with these query
parameters:

| Parameter | Type | Default | Meaning |
|---|---|---|---|
| `limit` | int32 | 100 | Page size; clamped to 1..500. |
| `offset` | int32 | 0 | Zero-based offset; clamped to 0..1 000 000. |
| `eventId` | int32 | - | Exact Windows event id. |
| `channel` | string | - | Exact event channel (max 256 characters). |
| `sourceIp` | string | - | Exact source IP; invalid literals are rejected with 400. |
| `userName` | string | - | SQL-escaped `Contains` filter (max 256 characters). |
| `sinceUtc` | date-time | - | Inclusive lower time bound. |
| `toUtc` | date-time | - | Inclusive upper time bound. |
| `includeExplain` | bool | false | Attach the SQLite `EXPLAIN QUERY PLAN` digest (`explainPlan`). |
| `includeDetails` | bool | false | Include the `details` column of each event. |

Response shape `PagedEventPage`: `offset`, `limit`, `total`, `events[]`, optional
`explainPlan[]`. Events are ordered `TimeUtc DESC, Id DESC`; pages are stable. An
inverted `sinceUtc > toUtc` window is swapped into chronological order by
`PagedEventsQuery.Normalize`; malformed instants in `sinceUtc`/`toUtc` produce
`400 Bad Request`.

### `/api/config`

Returns the masked settings document produced by `IpcDispatcher.GetMaskedSettings`
(the exact same shape the Configurator's Settings editor receives). The `Api.Token`,
`AbuseIpDb.ApiKey` and `MikroTik.Password` fields are replaced with a mask sentinel -
protecting the API against leaking its own credential back through its own channel.

### `/api/addresses`

Returns the per-IP reputation and activity aggregates produced by the existing
`GetAddresses` read command - up to 500 rows, most recent `LastSeen` first. The
response is a plain JSON array of `Address` entities (`id`, `ip`, `failCount`,
`successCount`, `firstSeen`, `lastSeen`, `threatScore`, `isBlocked`, `blockReason`,
`userNames`, `isPublicIp`).

### `/api/attacks`

Reads the materialised attack-statistics snapshot through the existing
`GetAttackStats` command. Query filters map one-to-one onto the
`AttackStatsRequest` payload:

| Parameter | Type | Default | Meaning |
|---|---|---|---|
| `ipQuery` | string | - | Case-insensitive `LIKE` substring on the row IP (max 256 characters, longer values ignored). |
| `minThreatScore` | number | - | Inclusive minimum `ThreatScore`; must be a finite number in 0..100. `NaN` and `±Infinity` parse as doubles but are rejected, because they compare false against every bound. |
| `onlyBlocked` | bool | false | Return only rows with `IsBlocked` set. |
| `sinceUtc` | date-time | now - 7 days | Inclusive lower bound on `LastSeenUtc`; must fall in 2000-01-01 .. 2100-01-01. |
| `untilUtc` | date-time | now | Inclusive upper bound on `LastSeenUtc`; same range, and not earlier than `sinceUtc`. |
| `limit` | int32 | 500 | Maximum rows returned; clamped to 1..2000. |

The window between `sinceUtc` and `untilUtc` is bounded at **366 days**. The window
selects the fact rows the summary is aggregated over, so an unbounded window would turn
one request into a full-table aggregation; the request is refused with `400` rather than
silently answered for a narrower window than the caller asked for.

Response shape `AttackStats`: `status`, `windowStartUtc`, `windowEndUtc`,
failure/success counters, `totalMatching`, `appliedLimit`, and `entries[]` of
`AttackStatEntry` rows (per-IP counters, `top10AttemptedLogins`, `threatScore`,
`threatLevel`, `isBlocked`, and the fact-derived fields). Entries are ordered most
recent `LastSeen` first. A malformed filter (`minThreatScore`, `sinceUtc`,
`untilUtc`, `limit`) is rejected with `400 Bad Request`.

## Error model

The API returns `application/problem+json` bodies for every non-200 response
(`RestApiProblem`, RFC 9457):

```json
{
  "type": "about:blank",
  "title": "Forbidden",
  "status": 403,
  "detail": "human-readable reason",
  "instance": "/api/events"
}
```

* `400` - invalid `/api/events` query parameters (bad `sourceIp`, bad time bounds,
  over-long text filters) or invalid `/api/attacks` filters (malformed
  `minThreatScore`, `sinceUtc`, `untilUtc` or `limit`).
* `401` - missing / invalid bearer token (with `WWW-Authenticate`).
* `404` - unknown non-API path (installed by the ASP.NET Core status-code pages so even
  framework pages return problems).
* `405` - undeclared method (with `Allow: GET, HEAD`).
* `429` - per-IP rate-limit budget exhausted (with `Retry-After` seconds).
* `500` - internal failure, e.g. the read-only event store could not be reached or an
  IPC read failed.

## Rate limiting

`RestApiRateLimitMiddleware` enforces a fixed-window budget per client IP with
`Api.RateLimitPerMinute` (default 60, clamped 1..60 000) requests per minute. Responses
include `Retry-After` seconds on `429`. Rate limiting precedes bearer authentication and
also covers the anonymous `/healthz` probe (reduced, but still bounded). Windows are
per-client-IP, and stale windows are pruned so memory stays bounded regardless of the
number of distinct clients.

## Request-reading is unprivileged by design

The event reader never writes. `PagedEventReader` resolves a dedicated **read-only**
`AuditDbContext` (`ReadOnlyAuditDbContextFactory`) for each page request: SQLite opens
with `Mode=ReadOnly` plus a pragma interceptor, so even accidental writes on this path
fail with `SQLITE_READONLY`. Queries are parameterised EF Core LINQ; the only raw SQL is
the planning-only `EXPLAIN QUERY PLAN`, built by stripping `.param` directives and never
receiving parameter values.

The remaining endpoints dispatch ordinary `IpcRequest`s against `IpcDispatcher`'s
existing read commands (`GetStatus`, `GetRecentAlerts`, `GetSessions`,
`GetAddresses`, `GetSettings`, `GetAttackStats`) - there is no way to inject a
mutation command through the REST mapper.

## Security posture

* Listener defaults to IPv4 **loopback** (`127.0.0.1`) on port `8443` - the safe
  deployment. Non-loopback listeners log an explicit warning at startup.
* All traffic is **HTTPS**. API endpoints never speak plaintext HTTP.
* `MaxConnections` (default 100) caps concurrent Kestrel connections in
  `ConfigureKestrel`.
* Security headers (`RestApiSecurityHeadersMiddleware`): `X-Content-Type-Options:
  nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, strict
  Content-Security-Policy.
* The dedicated `RestApiHostedService` builds and starts the WebApplication on a
  separate Kestrel endpoint and coordinates its lifetime with the host; ASP.NET Core
  log output is forwarded into the service logger assembly (`RestApiLogForwarder`)
  without exposing protected values.

## Configuration reference

See the `ApiOptions` table in `docs/40-options.md` (section "RdpAudit.Api").
