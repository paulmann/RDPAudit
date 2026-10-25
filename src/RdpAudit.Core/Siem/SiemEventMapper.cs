// File:    src/RdpAudit.Core/Siem/SiemEventMapper.cs
// Module:  RdpAudit.Core.Siem
// Purpose: Pure mappers that turn IPC event and alert projections into the neutral SiemEvent
//          record consumed by the CEF / LEEF 2.0 / NDJSON serializers. Owns the single severity
//          table (RdpAudit AlertSeverity and event ids to the CEF/LEEF 0..10 scale) and the
//          event-name resolution through EventCatalog. No I/O and no culture-dependent numeric
//          rendering. The device version travels as a parameter supplied by the caller from IPC
//          ServiceStatus.Version and is never hardcoded.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Globalization;
using RdpAudit.Core.Events;
using RdpAudit.Core.Ipc.Contracts;
using RdpAudit.Core.Models;

namespace RdpAudit.Core.Siem;

/// <summary>Pure mapper from IPC projections to the neutral SIEM record.</summary>
public static class SiemEventMapper
{
	/// <summary>Device vendor used in the CEF/LEEF header. Stable product identity.</summary>
	public const string Vendor = "RdpAudit";

	/// <summary>Device product used in the CEF/LEEF header. Stable product identity.</summary>
	public const string Product = "RdpAudit";

	/// <summary>CEF/LEEF severity for failed-authentication event ids (4625, 4771, 4776).</summary>
	public const int EventSeverityFailedAuth = 5;

	/// <summary>CEF/LEEF severity for ordinary raw events rendered outside an alert.</summary>
	public const int EventSeverityInfo = 1;

	/// <summary>Maps an AlertSeverity value to the CEF/LEEF 0..10 scale:
	/// Info 1, Low 3, Medium 5, High 8, Critical 10.</summary>
	public static int SeverityForAlert(AlertSeverity severity) => severity switch
	{
		AlertSeverity.Info => 1,
		AlertSeverity.Low => 3,
		AlertSeverity.Medium => 5,
		AlertSeverity.High => 8,
		AlertSeverity.Critical => 10,
		_ => 1,
	};

	/// <summary>Maps a raw event id to the CEF/LEEF 0..10 scale. Failed-authentication event
	/// ids (4625 Failed logon, 4771 Kerberos pre-auth failure, 4776 NTLM validation failure)
	/// map to 5; every other event maps to 1.</summary>
	public static int SeverityForEvent(int eventId) => eventId switch
	{
		4625 => EventSeverityFailedAuth,
		4771 => EventSeverityFailedAuth,
		4776 => EventSeverityFailedAuth,
		_ => EventSeverityInfo,
	};

	/// <summary>Resolves the short human-readable event name from EventCatalog. Unknown event
	/// ids fall back to the literal form Windows event NNN.</summary>
	public static string NameForEvent(int eventId)
	{
		if (EventCatalog.TryGet(eventId, out EventDescriptor descriptor)
			&& !string.IsNullOrWhiteSpace(descriptor.Description))
		{
			return descriptor.Description;
		}

		return "Windows event " + eventId.ToString(CultureInfo.InvariantCulture);
	}

	/// <summary>Builds the neutral SIEM record for one RawEvent projection, enriched with the
	/// per-IP summary so every CEF/LEEF record stays self-contained (failed count, total events,
	/// attack classification).</summary>
	public static SiemEvent FromEvent(IpEventEntryDto entry, EventsForIpDto summary, string deviceVersion)
	{
		ArgumentNullException.ThrowIfNull(entry);
		ArgumentNullException.ThrowIfNull(summary);
		ArgumentNullException.ThrowIfNull(deviceVersion);

		return new SiemEvent
		{
			Type = SiemEventType.Event,
			SignatureId = "event:" + entry.EventId.ToString(CultureInfo.InvariantCulture),
			Name = NameForEvent(entry.EventId),
			Severity = SeverityForEvent(entry.EventId),
			TimeUtc = entry.TimeUtc,
			SourceIp = summary.Ip,
			SourceUser = entry.UserName,
			DestinationUser = entry.Domain,
			Channel = entry.Channel,
			LogonType = entry.LogonType,
			AuthPackage = entry.AuthPackage,
			ProcessName = entry.ProcessName,
			Status = entry.Status,
			AttackType = string.IsNullOrWhiteSpace(summary.AttackType) ? null : summary.AttackType,
			EventId = entry.EventId,
			FailedCount = summary.FailedCount,
			TotalEvents = summary.TotalEvents,
			ExternalId = entry.Id.ToString(CultureInfo.InvariantCulture),
			DeviceVendor = Vendor,
			DeviceProduct = Product,
			DeviceVersion = deviceVersion,
		};
	}

	/// <summary>Builds the neutral SIEM record for one correlated alert projection. The alert
	/// name falls back to the rule id when the message is empty; an empty rule id renders as
	/// the literal Unknown signature.</summary>
	public static SiemEvent FromAlert(AlertEntryDto alert, string deviceVersion)
	{
		ArgumentNullException.ThrowIfNull(alert);
		ArgumentNullException.ThrowIfNull(deviceVersion);

		string signatureId = string.IsNullOrWhiteSpace(alert.RuleId) ? "Unknown" : alert.RuleId;
		return new SiemEvent
		{
			Type = SiemEventType.Alert,
			SignatureId = signatureId,
			Name = string.IsNullOrWhiteSpace(alert.Message) ? signatureId : alert.Message,
			Severity = SeverityForAlert(alert.Severity),
			TimeUtc = alert.TimeUtc,
			SourceIp = alert.SourceIp ?? string.Empty,
			SourceUser = alert.UserName,
			Msg = alert.Message,
			ExternalId = alert.Id.ToString(CultureInfo.InvariantCulture),
			Acknowledged = alert.Acknowledged,
			TriggerEventId = alert.TriggerEventId,
			DeviceVendor = Vendor,
			DeviceProduct = Product,
			DeviceVersion = deviceVersion,
		};
	}
}
