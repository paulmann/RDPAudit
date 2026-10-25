// File:    src/RdpAudit.Core/Siem/LeefSerializer.cs
// Module:  RdpAudit.Core.Siem
// Purpose: Pure LEEF 2.0 renderer for the neutral SiemEvent stream: header
//          LEEF:2.0|Vendor|Product|Version|EventId| plus attribute key=value pairs separated by
//          TAB, devTime rendered as ISO-8601 UTC milliseconds (yyyy-MM-ddTHH:mm:ss.fffZ), one
//          record per line, LF line endings, no trailing newline. Header fields escape backslash
//          and pipe; attribute values escape backslash, caret and pipe; CR / LF / TAB are always
//          neutralised to a single space so an external value can never break the record or its
//          structure. No I/O.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Globalization;
using System.Text;

namespace RdpAudit.Core.Siem;

/// <summary>Pure LEEF 2.0 renderer. One line per event, LF line endings, no trailing newline.</summary>
public sealed class LeefSerializer : ISiemEventSerializer
{
	private const string LeefVersion = "LEEF:2.0";

	private const string IsoDateLayout = "yyyy-MM-ddTHH:mm:ss.fffZ";

	/// <inheritdoc />
	public string Format(IEnumerable<SiemEvent> events)
	{
		ArgumentNullException.ThrowIfNull(events);

		StringBuilder sb = new();
		foreach (SiemEvent e in events)
		{
			ArgumentNullException.ThrowIfNull(e);
			AppendRecord(sb, e);
			sb.Append('\n');
		}

		return sb.Length == 0 ? string.Empty : sb.ToString(0, sb.Length - 1);
	}

	private static void AppendRecord(StringBuilder sb, SiemEvent e)
	{
		sb.Append(LeefVersion)
			.Append('|').Append(SiemEscape.LeefHeader(e.DeviceVendor))
			.Append('|').Append(SiemEscape.LeefHeader(e.DeviceProduct))
			.Append('|').Append(SiemEscape.LeefHeader(e.DeviceVersion))
			.Append('|').Append(SiemEscape.LeefHeader(e.SignatureId));

		AppendAttribute(sb, "devTime", LeefDateUtc(e.TimeUtc));

		if (!string.IsNullOrEmpty(e.Name))
		{
			AppendAttribute(sb, "name", e.Name);
		}

		AppendAttribute(sb, "sev", e.Severity.ToString(CultureInfo.InvariantCulture));

		if (!string.IsNullOrEmpty(e.SourceIp))
		{
			AppendAttribute(sb, "src", e.SourceIp);
		}

		if (e.SourcePort is not null)
		{
			AppendAttribute(sb, "srcPort", e.SourcePort!.Value.ToString(CultureInfo.InvariantCulture));
		}

		if (!string.IsNullOrEmpty(e.SourceUser))
		{
			AppendAttribute(sb, "usrName", e.SourceUser);
		}

		if (!string.IsNullOrEmpty(e.DestinationUser))
		{
			AppendAttribute(sb, "dstUser", e.DestinationUser);
		}

		if (!string.IsNullOrEmpty(e.Channel))
		{
			AppendAttribute(sb, "channel", e.Channel);
		}

		if (e.LogonType is not null)
		{
			AppendAttribute(sb, "logonType", e.LogonType!.Value.ToString(CultureInfo.InvariantCulture));
		}

		if (!string.IsNullOrEmpty(e.AuthPackage))
		{
			AppendAttribute(sb, "authPackage", e.AuthPackage);
		}

		if (!string.IsNullOrEmpty(e.ProcessName))
		{
			AppendAttribute(sb, "processName", e.ProcessName);
		}

		if (!string.IsNullOrEmpty(e.Status))
		{
			AppendAttribute(sb, "status", e.Status);
		}

		if (!string.IsNullOrEmpty(e.AttackType))
		{
			AppendAttribute(sb, "cat", e.AttackType);
		}

		if (e.FailedCount is not null)
		{
			AppendAttribute(sb, "failedLogons", e.FailedCount!.Value.ToString(CultureInfo.InvariantCulture));
		}

		if (e.TotalEvents is not null)
		{
			AppendAttribute(sb, "totalEvents", e.TotalEvents!.Value.ToString(CultureInfo.InvariantCulture));
		}

		if (!string.IsNullOrEmpty(e.Msg))
		{
			AppendAttribute(sb, "msg", e.Msg);
		}

		if (!string.IsNullOrEmpty(e.ExternalId))
		{
			AppendAttribute(sb, "externalId", e.ExternalId);
		}

		if (e.EventId is not null)
		{
			AppendAttribute(sb, "eventId", e.EventId!.Value.ToString(CultureInfo.InvariantCulture));
		}

		if (e.TriggerEventId is not null)
		{
			AppendAttribute(sb, "triggerEventId", e.TriggerEventId!.Value.ToString(CultureInfo.InvariantCulture));
		}

		AppendAttribute(sb, "acknowledged", e.Acknowledged ? "true" : "false");

		AppendAttribute(sb, "recordType", e.Type == SiemEventType.Alert ? "alert" : "event");
	}

	private static void AppendAttribute(StringBuilder sb, string key, string value)
	{
		sb.Append('\t').Append(key).Append('=').Append(SiemEscape.LeefValue(value));
	}

	private static string LeefDateUtc(DateTime value)
	{
		DateTime utc = UtcNormalizingDateTimeConverter.ToUtc(value);
		return utc.ToString(IsoDateLayout, CultureInfo.InvariantCulture);
	}
}
