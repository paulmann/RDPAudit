// File:    src/RdpAudit.Service/Alerts/OffHoursLoginRule.cs
// Module:  RdpAudit.Service.Alerts
// Purpose: Flags interactive RDP logons (Type 10) outside the configured business hours.
//          Uses an explicit configured timezone (default UTC) so test stability and
//          server-locale changes do not affect detection.
// Extends: RdpAudit.Core.Events.AlertRuleBase
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Globalization;
using RdpAudit.Core.Config;
using RdpAudit.Core.Events;
using RdpAudit.Core.Models;

namespace RdpAudit.Service.Alerts;

/// <summary>Flags interactive RDP logons (Type 10) outside the configured business hours.</summary>
public sealed class OffHoursLoginRule : AlertRuleBase
{
	public override string RuleId => "OFF_HOURS_LOGIN";

	public override string Name => "Off-Hours Interactive Login";

	public override AlertSeverity Severity => AlertSeverity.Low;

	public override bool IsEnabled(RdpAuditOptions options) => options.Alerts.OffHoursAlertEnabled;

	public override Task<Alert?> EvaluateAsync(RawEvent evt, IAlertContext ctx, CancellationToken ct)
	{
		if (evt.EventId != 4624 || evt.LogonType != 10)
		{
			return Task.FromResult<Alert?>(null);
		}

		if (!string.IsNullOrEmpty(evt.UserName)
			&& ctx.Options.Alerts.WhitelistUsers.Contains(evt.UserName, StringComparer.OrdinalIgnoreCase))
		{
			return Task.FromResult<Alert?>(null);
		}

		TimeZoneInfo tz = ResolveTimeZone(ctx.Options.Alerts.OffHoursTimeZoneId);
		DateTime utc = evt.TimeUtc.Kind == DateTimeKind.Utc ? evt.TimeUtc : DateTime.SpecifyKind(evt.TimeUtc, DateTimeKind.Utc);
		DateTime zoned = TimeZoneInfo.ConvertTimeFromUtc(utc, tz);
		TimeSpan local = zoned.TimeOfDay;
		TimeSpan start = ctx.Options.Alerts.BusinessHoursStart;
		TimeSpan end = ctx.Options.Alerts.BusinessHoursEnd;

		bool isInside = start <= end
			? local >= start && local < end
			: local >= start || local < end;

		if (isInside)
		{
			return Task.FromResult<Alert?>(null);
		}

		return Task.FromResult<Alert?>(CreateAlert(evt,
			string.Format(CultureInfo.InvariantCulture,
				"Off-hours interactive logon by {0} from {1} at {2:HH:mm} ({3})",
				evt.UserName, evt.SourceIp ?? "(local)", zoned, tz.Id),
			new
			{
				ZonedTime = zoned,
				ZoneId = tz.Id,
				Mitre = "T1133",
			}));
	}

	internal static TimeZoneInfo ResolveTimeZone(string? id)
	{
		if (string.IsNullOrWhiteSpace(id))
		{
			return TimeZoneInfo.Utc;
		}

		if (string.Equals(id, "Local", StringComparison.OrdinalIgnoreCase))
		{
			return TimeZoneInfo.Local;
		}

		try
		{
			return TimeZoneInfo.FindSystemTimeZoneById(id);
		}
		catch (TimeZoneNotFoundException)
		{
			return TimeZoneInfo.Utc;
		}
		catch (InvalidTimeZoneException)
		{
			return TimeZoneInfo.Utc;
		}
	}
}
