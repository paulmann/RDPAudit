// File:    src/RdpAudit.Core/Models/AttackStatRowFormatter.cs
// Module:  RdpAudit.Core.Models
// Purpose: Pure clipboard formatters for the Stage 6B Configurator Attack Statistics tab. Multiline
//          output is human-readable for incident notes; TSV output stays on a single row with a
//          stable header for paste into Excel / SOC ticket grids. Lifted into Core so the
//          serialisations are unit-testable without WinForms.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Globalization;
using System.Text;
using RdpAudit.Core.Ipc.Contracts;

namespace RdpAudit.Core.Models;

/// <summary>Multiline + TSV serialisation helpers for a single <see cref="AttackStatEntryDto"/>.</summary>
public static class AttackStatRowFormatter
{
	private const string TimeFormat = "yyyy-MM-dd HH:mm:ss";

	private static readonly string[] HeaderFields =
	{
		"Ip",
		"ThreatScore",
		"ThreatLevel",
		"TotalAttempts",
		"Failed",
		"Successful",
		"FirstSeenUtc",
		"LastSeenUtc",
		"DurationSeconds",
		"Top10AttemptedLogins",
		"LastLoginType",
		"IsBlocked",
		"LastUpdatedUtc",
	};

	/// <summary>
	/// Render an entry as a human-readable multiline block suitable for clipboard paste into an
	/// incident note. Empty / null values are rendered as a literal dash so the reader can tell
	/// "field absent" apart from "field zero / blank string".
	/// </summary>
	public static string FormatMultiline(AttackStatEntryDto entry)
	{
		ArgumentNullException.ThrowIfNull(entry);

		StringBuilder sb = new();
		AppendLine(sb, "Ip", entry.Ip);
		AppendLine(sb, "ThreatScore", entry.ThreatScore.ToString("F1", CultureInfo.InvariantCulture));
		AppendLine(sb, "ThreatLevel", entry.ThreatLevel.ToString());
		AppendLine(sb, "TotalAttempts", entry.TotalAttempts.ToString(CultureInfo.InvariantCulture));
		AppendLine(sb, "Failed", entry.Failed.ToString(CultureInfo.InvariantCulture));
		AppendLine(sb, "Successful", entry.Successful.ToString(CultureInfo.InvariantCulture));
		AppendLine(sb, "FirstSeenUtc", entry.FirstSeenUtc.ToString(TimeFormat, CultureInfo.InvariantCulture));
		AppendLine(sb, "LastSeenUtc", entry.LastSeenUtc.ToString(TimeFormat, CultureInfo.InvariantCulture));
		AppendLine(sb, "DurationSeconds", entry.DurationSeconds.ToString(CultureInfo.InvariantCulture));
		AppendLine(sb, "Top10AttemptedLogins", FormatTopLogins(entry.Top10AttemptedLogins));
		AppendLine(sb, "LastLoginType", entry.LastLoginType?.ToString(CultureInfo.InvariantCulture));
		AppendLine(sb, "IsBlocked", entry.IsBlocked ? "yes" : "no");
		AppendLine(sb, "LastUpdatedUtc", entry.LastUpdatedUtc.ToString(TimeFormat, CultureInfo.InvariantCulture));
		return sb.ToString().TrimEnd('\r', '\n');
	}

	/// <summary>
	/// Render an entry as a single TSV record with a stable column order. The header line is
	/// emitted first when <paramref name="includeHeader"/> is set, which makes the output paste
	/// cleanly into Excel / a SOC ticket grid.
	/// </summary>
	public static string FormatTsv(AttackStatEntryDto entry, bool includeHeader = true)
	{
		ArgumentNullException.ThrowIfNull(entry);

		StringBuilder sb = new();
		if (includeHeader)
		{
			sb.AppendLine(string.Join('\t', HeaderFields));
		}

		sb.Append(Sanitise(entry.Ip)).Append('\t');
		sb.Append(entry.ThreatScore.ToString("F1", CultureInfo.InvariantCulture)).Append('\t');
		sb.Append(entry.ThreatLevel.ToString()).Append('\t');
		sb.Append(entry.TotalAttempts.ToString(CultureInfo.InvariantCulture)).Append('\t');
		sb.Append(entry.Failed.ToString(CultureInfo.InvariantCulture)).Append('\t');
		sb.Append(entry.Successful.ToString(CultureInfo.InvariantCulture)).Append('\t');
		sb.Append(entry.FirstSeenUtc.ToString(TimeFormat, CultureInfo.InvariantCulture)).Append('\t');
		sb.Append(entry.LastSeenUtc.ToString(TimeFormat, CultureInfo.InvariantCulture)).Append('\t');
		sb.Append(entry.DurationSeconds.ToString(CultureInfo.InvariantCulture)).Append('\t');
		sb.Append(Sanitise(FormatTopLogins(entry.Top10AttemptedLogins))).Append('\t');
		sb.Append(entry.LastLoginType?.ToString(CultureInfo.InvariantCulture) ?? string.Empty).Append('\t');
		sb.Append(entry.IsBlocked ? "yes" : "no").Append('\t');
		sb.Append(entry.LastUpdatedUtc.ToString(TimeFormat, CultureInfo.InvariantCulture));
		return sb.ToString();
	}

	/// <summary>
	/// Renders the JSON-serialised <c>Top10AttemptedLogins</c> as a comma-separated list ready for
	/// grid display and clipboard paste. Returns an empty string when the input is null / empty /
	/// malformed JSON so the grid never shows a literal <c>[]</c>.
	/// </summary>
	public static string FormatTopLogins(string? serialised)
	{
		IReadOnlyList<string> logins = AttackStatProjection.DeserializeTopLogins(serialised);
		if (logins.Count == 0)
		{
			return string.Empty;
		}

		return string.Join(", ", logins);
	}

	/// <summary>Renders <c>DurationSeconds</c> as a compact <c>d.hh:mm:ss</c> string.</summary>
	public static string FormatDuration(long durationSeconds)
	{
		long seconds = durationSeconds < 0 ? 0 : durationSeconds;
		TimeSpan span = TimeSpan.FromSeconds(seconds);
		if (span.TotalDays >= 1)
		{
			return string.Format(
				CultureInfo.InvariantCulture,
				"{0}d {1:D2}:{2:D2}:{3:D2}",
				(int)span.TotalDays,
				span.Hours,
				span.Minutes,
				span.Seconds);
		}

		return string.Format(
			CultureInfo.InvariantCulture,
			"{0:D2}:{1:D2}:{2:D2}",
			span.Hours,
			span.Minutes,
			span.Seconds);
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
