# Event Collection Operator Behavior

## Event Collection page

The Configurator exposes an **Event Collection** page. Each catalog row shows
the event ID, channel, display name, criticality, layer, enabled state,
retention days, and description.

Operators can:

- apply the Minimal, Essential, or Full preset;
- select rows and set one retention value for the selection;
- use zero retention days to retain an event forever;
- save changes through the service IPC boundary; and
- refresh the current service settings.

The page validates retention values as whole numbers from zero through 36,500.
A locally edited value is not durable until **Save changes** completes.

## Collection and retention behavior

The active source remains Windows Event Log capture. Flood guard settings are
part of the monitoring configuration and are applied before a DTO enters the
inner event pipe.

The retention worker runs once per minute. It removes at most the configured
maintenance batch size for each retained set, honors explicit non-zero
per-event overrides before the global event retention policy, and then requests
a passive WAL checkpoint. Retention does not run `VACUUM` automatically.

## Reliability signals and limits

A commit that covers a captured bookmark persists the associated raw event
batch and the bookmark together. If the transaction rolls back, the bookmark is
not advanced and the in-memory bookmark cache is restored.

The existing service status and diagnostics surfaces expose general capture and
drop information. Operators must not assume that the UI currently offers the
prototype's unimplemented per-bucket flood dashboard, shard counters,
subnet-aggregation indicators, sampled-event decorations, or shard drill-down
experience.
