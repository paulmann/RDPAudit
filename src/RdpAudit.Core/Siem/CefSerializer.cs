// File:    src/RdpAudit.Core/Siem/CefSerializer.cs
// Module:  RdpAudit.Core.Siem
// Purpose: Pure CEF (Common Event Format) renderer for the neutral SiemEvent stream: one CEF
//          record per line, CEF:0 header, severity on the 0..10 scale, rt in epoch milliseconds,
//          deviceCustomDate1 rendered as 'MMM dd yyyy HH:mm:ss +00:00' (UTC). Header fields
//          escape backslash and pipe; extension values escape backslash, equals and pipe; CR / LF
//          / TAB are always neutralised to a single space so an external value can never break
//          the record structure. No I/O.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Globalization;
using System.Text;

namespace RdpAudit.Core.Siem;

/// <summary>Pure CEF 1.0 renderer. One line per event, LF line endings, no trailing newline.</summary>
public sealed class CefSerializer : ISiemEventSerializer
{
	private const string CefVersion = "CEF:0";

	private const string CefDateSuffixUtc = " +00:00";

	private const string CefDateLayout = "MMM dd yyyy HH:mm:ss";

	private const string RecordTypeEvent = "event";

	private const string RecordTypeAlert = "alert";

	private static readonly DateTime Epoch = new(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);

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
		sb.Append(CefVersion)
			.Append('|').Append(SiemEscape.CefHeader(e.DeviceVendor))
			.Append('|').Append(SiemEscape.CefHeader(e.DeviceProduct))
			.Append('|').Append(SiemEscape.CefHeader(e.DeviceVersion))
			.Append('|').Append(SiemEscape.CefHeader(e.SignatureId))
			.Append('|').Append(SiemEscape.CefHeader(e.Name))
			.Append('|').Append(e.Severity.ToString(CultureInfo.InvariantCulture));

		AppendExtension(sb, "rt", EpochMilliseconds(e.TimeUtc).ToString(CultureInfo.InvariantCulture));
		AppendExtension(sb, "deviceCustomDate1Label", "eventTime");
		AppendExtension(sb, "deviceCustomDate1", CefDateUtc(e.TimeUtc));

		if (!string.IsNullOrEmpty(e.SourceIp))
		{
			AppendExtension(sb, "src", e.SourceIp);
		}

		if (!string.IsNullOrEmpty(e.SourceUser))
		{
			AppendExtension(sb, "suser", e.SourceUser);
		}

		if (!string.IsNullOrEmpty(e.DestinationUser))
		{
			AppendExtension(sb, "duser", e.DestinationUser);
		}

		if (e.FailedCount is not null)
		{
			AppendExtension(sb, "cn1Label", "failedLogons");
			AppendExtension(sb, "cn1", e.FailedCount!.Value.ToString(CultureInfo.InvariantCulture));
		}

		if (e.TotalEvents is not null)
		{
			AppendExtension(sb, "cn2Label", "totalEvents");
			AppendExtension(sb, "cn2", e.TotalEvents!.Value.ToString(CultureInfo.InvariantCulture));
		}

		if (!string.IsNullOrEmpty(e.Channel))
		{
			AppendExtension(sb, "cs1Label", "channel");
			AppendExtension(sb, "cs1", e.Channel);
		}

		if (e.LogonType is not null)
		{
			AppendExtension(sb, "cs2Label", "logonType");
			AppendExtension(sb, "cs2", e.LogonType!.Value.ToString(CultureInfo.InvariantCulture));
		}

		if (!string.IsNullOrEmpty(e.AuthPackage))
		{
			AppendExtension(sb, "cs3Label", "authPackage");
			AppendExtension(sb, "cs3", e.AuthPackage);
		}

		if (!string.IsNullOrEmpty(e.ProcessName))
		{
			AppendExtension(sb, "cs4Label", "processName");
			AppendExtension(sb, "cs4", e.ProcessName);
		}

		if (!string.IsNullOrEmpty(e.Status))
		{
			AppendExtension(sb, "cs5Label", "status");
			AppendExtension(sb, "cs5", e.Status);
		}

		if (!string.IsNullOrEmpty(e.AttackType))
		{
			AppendExtension(sb, "cs6Label", "attackType");
			AppendExtension(sb, "cs6", e.AttackType);
		}

		if (!string.IsNullOrEmpty(e.Msg))
		{
			AppendExtension(sb, "msg", e.Msg);
		}

		if (!string.IsNullOrEmpty(e.ExternalId))
		{
			AppendExtension(sb, "cs7Label", "externalId");
			AppendExtension(sb, "cs7", e.ExternalId);
		}

		AppendExtension(sb, "cs8Label", "recordType");
		AppendExtension(sb, "cs8", e.Type == SiemEventType.Alert ? RecordTypeAlert : RecordTypeEvent);
	}

	private static void AppendExtension(StringBuilder sb, string key, string value)
	{
		sb.Append(' ').Append(key).Append('=').Append(SiemEscape.CefExtensionValue(value));
	}

	private static long EpochMilliseconds(DateTime value)
	{
		DateTime utc = UtcNormalizingDateTimeConverter.ToUtc(value);
		TimeSpan elapsed = utc - Epoch;
		return (long)Math.Round(elapsed.TotalMilliseconds, MidpointRounding.AwayFromZero);
	}

	private static string CefDateUtc(DateTime value)
	{
		DateTime utc = UtcNormalizingDateTimeConverter.ToUtc(value);
		return utc.ToString(CefDateLayout, CultureInfo.InvariantCulture) + CefDateSuffixUtc;
	}
}
