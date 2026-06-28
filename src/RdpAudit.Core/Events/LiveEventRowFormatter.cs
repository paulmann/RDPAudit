// File:    src/RdpAudit.Core/Events/LiveEventRowFormatter.cs
// Module:  RdpAudit.Core.Events
// Purpose: Pure formatters for the LiveEvents "Copy Event Details" context-menu action. Lives in
//          Core so the multiline and TSV serialisations are unit-testable without WinForms.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Globalization;
using System.Text;

namespace RdpAudit.Core.Events;

/// <summary>Multiline + TSV serialisation helpers for a <see cref="LiveEventRowView"/>.</summary>
public static class LiveEventRowFormatter
{
	private const string TimeFormat = "yyyy-MM-dd HH:mm:ss";

	private static readonly string[] HeaderFields =
	{
		"Id",
		"TimeUtc",
		"EventId",
		"Channel",
		"User",
		"Domain",
		"SourceIp",
		"LogonType",
		"AuthPackage",
		"Process",
	};

	/// <summary>
	/// Format a row as a human-readable multiline block suitable for clipboard paste into an
	/// incident note. Empty / null values are rendered as a literal dash so the reader can tell
	/// "field absent" apart from "field zero / blank string".
	/// </summary>
	public static string FormatMultiline(LiveEventRowView row)
	{
		ArgumentNullException.ThrowIfNull(row);

		StringBuilder sb = new();
		AppendLine(sb, "Id", row.Id.ToString(CultureInfo.InvariantCulture));
		AppendLine(sb, "TimeUtc", row.TimeUtc.ToString(TimeFormat, CultureInfo.InvariantCulture));
		AppendLine(sb, "EventId", row.EventId.ToString(CultureInfo.InvariantCulture));
		AppendLine(sb, "Channel", row.Channel);
		AppendLine(sb, "User", row.UserName);
		AppendLine(sb, "Domain", row.Domain);
		string? renderedIp = row.SourceIp;
		if (!string.IsNullOrWhiteSpace(renderedIp) && row.SourceIpDerived)
		{
			renderedIp = renderedIp + " (derived)";
		}
		AppendLine(sb, "SourceIp", renderedIp);
		AppendLine(sb, "LogonType", row.LogonType?.ToString(CultureInfo.InvariantCulture));
		AppendLine(sb, "AuthPackage", row.AuthPackage);
		AppendLine(sb, "Process", row.ProcessName);
		return sb.ToString().TrimEnd('\r', '\n');
	}

	/// <summary>
	/// Format a row as a single TSV record with a stable column order. The header line is emitted
	/// first when <paramref name="includeHeader"/> is set, which makes the output paste cleanly
	/// into Excel / a SOC ticket grid.
	/// </summary>
	public static string FormatTsv(LiveEventRowView row, bool includeHeader = true)
	{
		ArgumentNullException.ThrowIfNull(row);

		StringBuilder sb = new();
		if (includeHeader)
		{
			sb.AppendLine(string.Join('\t', HeaderFields));
		}

		sb.Append(row.Id.ToString(CultureInfo.InvariantCulture)).Append('\t');
		sb.Append(row.TimeUtc.ToString(TimeFormat, CultureInfo.InvariantCulture)).Append('\t');
		sb.Append(row.EventId.ToString(CultureInfo.InvariantCulture)).Append('\t');
		sb.Append(Sanitise(row.Channel)).Append('\t');
		sb.Append(Sanitise(row.UserName)).Append('\t');
		sb.Append(Sanitise(row.Domain)).Append('\t');
		sb.Append(Sanitise(row.SourceIp)).Append('\t');
		sb.Append(row.LogonType?.ToString(CultureInfo.InvariantCulture) ?? string.Empty).Append('\t');
		sb.Append(Sanitise(row.AuthPackage)).Append('\t');
		sb.Append(Sanitise(row.ProcessName));
		return sb.ToString();
	}

	private static void AppendLine(StringBuilder sb, string label, string? value)
	{
		string rendered = string.IsNullOrWhiteSpace(value) ? "-" : value!;
		sb.Append(label).Append(": ").AppendLine(rendered);
	}

	private static string Sanitise(string? value)
	{
		if (string.IsNullOrEmpty(value))
		{
			return string.Empty;
		}

		// Tabs / CR / LF would break the TSV row; replace with a single space so the structure is
		// preserved when the value is pasted into Excel or a ticket.
		return value
			.Replace('\t', ' ')
			.Replace('\r', ' ')
			.Replace('\n', ' ');
	}
}
