# Debug Mode

`DiagnosticsOptions.DebugMode` (`RdpAudit.Diagnostics.DebugMode = true` in `appsettings.json`) elevates internal trace channels to the maximum useful detail for troubleshooting **without** writing PII or credentials at Information level.

## What changes when DebugMode is on

| Toggle | Effect when `true` |
|--------|--------------------|
| `LogChannelDrops` (default `true`) | Each Channel<T> drop emits `LogWarning("Event channel full — dropped EventID {EventId} channel={Channel}", …)` |
| `LogAlertEvaluationTimings` (default `false`) | Per-rule evaluation `Stopwatch` is logged at Debug after each event |
| `LogEventXmlAtDebug` (default `false`) | The first `MaxXmlBytesAtDebug` bytes of each captured EventRecord XML go to the **Debug** sink only |

Sensitive data — command lines, credential fields, NTLM hashes, and full XML — must remain at `LogDebug` level. **Never raise these to `LogInformation`**.

## How to enable

```json
{
	"Serilog": { "MinimumLevel": { "Default": "Debug" } },
	"RdpAudit": {
		"Diagnostics": {
			"DebugMode": true,
			"LogEventXmlAtDebug": false,
			"LogAlertEvaluationTimings": true
		}
	}
}
```

The service watches this file via `reloadOnChange: true` and `IOptionsMonitor<RdpAuditOptions>` so toggling does not require a restart.

## LLM contract

When adding a new diagnostic, the rule of thumb is:

- Counters / channel state → `LogInformation` (always safe).
- Timings, retry attempts → `LogDebug` gated on `LogAlertEvaluationTimings`.
- Event payload contents, command lines, ticket details → `LogDebug` gated on `LogEventXmlAtDebug`.
