// File:    src/RdpAudit.Service/Alerts/RapidReconnectRule.cs
// Module:  RdpAudit.Service.Alerts
// Purpose: Flags rapid reconnect (Event 25) within N seconds of a disconnect (24) from a different IP.
// Extends: RdpAudit.Core.Events.AlertRuleBase
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Events;
using RdpAudit.Core.Models;

namespace RdpAudit.Service.Alerts;

/// <summary>Flags rapid reconnect within N seconds of a disconnect from a different IP.</summary>
public sealed class RapidReconnectRule : AlertRuleBase
{
	public override string RuleId => "RAPID_RECONNECT";

	public override string Name => "Rapid RDP Reconnect from Different IP";

	public override AlertSeverity Severity => AlertSeverity.Medium;

	public override async Task<Alert?> EvaluateAsync(RawEvent evt, IAlertContext ctx, CancellationToken ct)
	{
		if (evt.EventId != 25 || evt.SessionId is null || string.IsNullOrEmpty(evt.SourceIp))
		{
			return null;
		}

		TimeSpan window = TimeSpan.FromSeconds(Math.Max(1, ctx.Options.Alerts.RapidReconnectSeconds));
		IReadOnlyList<RawEvent> recent = await ctx.GetRecentBySessionIdAsync(
			evt.SessionId.Value,
			20,
			window,
			ct).ConfigureAwait(false);

		RawEvent? lastDisconnect = recent
			.Where(e => e.EventId == 24)
			.OrderByDescending(e => e.TimeUtc)
			.FirstOrDefault();
		if (lastDisconnect is null)
		{
			return null;
		}

		if (string.Equals(lastDisconnect.SourceIp, evt.SourceIp, StringComparison.OrdinalIgnoreCase))
		{
			return null;
		}

		TimeSpan delta = evt.TimeUtc - lastDisconnect.TimeUtc;
		if (delta > window)
		{
			return null;
		}

		return CreateAlert(evt,
			$"Rapid reconnect on session {evt.SessionId} from {evt.SourceIp} {delta.TotalSeconds:0}s after disconnect from {lastDisconnect.SourceIp}",
			new { Seconds = delta.TotalSeconds, evt.SessionId, Mitre = "T1563.002" });
	}
}
