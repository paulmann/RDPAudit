/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.2
// File   : UtcTimestampEnricher.cs
// Project: RdpAudit.Service (RdpAudit.Service.Infrastructure)
// Purpose: Serilog enricher that emits every event's timestamp as a UTC 'UtcTimestamp'
//          property for the DEBUG text mirror only. Program.ConfigureSerilog registers it
//          on the dedicated WriteTo.Logger sink for RDPAudit_DEBUG_Log.txt, whose
//          outputTemplate renders {UtcTimestamp:yyyy-MM-dd HH:mm:ss.fff'Z'}. The built-in
//          {Timestamp} token reads LogEvent.Timestamp directly (a property in the template
//          dictionary cannot shadow it), so this property carries the UTC form the template
//          consumes. The original timestamp stays untouched for every other sink.
// Depends: Serilog (ILogEventEnricher), Serilog.Events
// Extends: Add more normalization properties here when another sink needs a canonical form.

using System;
using Serilog.Core;
using Serilog.Events;

namespace RdpAudit.Service.Infrastructure;

/// <summary>
/// Adds a <c>UtcTimestamp</c> property carrying <see cref="LogEvent.Timestamp"/> converted
/// to UTC. Only the DEBUG mirror's output template reads it; the event's original timestamp
/// (possibly local) remains untouched so the structured log keeps the exact capture-time value.
/// </summary>
public sealed class UtcTimestampEnricher : ILogEventEnricher
{
	/// <inheritdoc />
	public void Enrich(LogEvent logEvent, ILogEventPropertyFactory propertyFactory)
	{
		logEvent.AddOrUpdateProperty(
			propertyFactory.CreateProperty("UtcTimestamp", logEvent.Timestamp.ToUniversalTime()));
	}
}
