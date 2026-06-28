// File:    src/RdpAudit.Core/Events/IpEventsExportFormatter.cs
// Module:  RdpAudit.Core.Events
// Purpose: Pure clipboard / file-export formatters for the Stage A "Export All IP Events" action.
//          Renders an EventsForIpDto plus its bounded RawEvents window into JSON / TXT / Markdown /
//          CSV. All non-CSV formats include the summary header (IP, attack type, first/last UTC,
//          failed/success counts, attempted usernames, duration, threat level, block status); CSV
//          stays a clean tabular event stream so it loads cleanly into Excel or downstream tools.
//          Embedded tabs / CR / LF are neutralised for TXT / CSV so a pasted row never breaks the
//          structure.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Globalization;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using RdpAudit.Core.Ipc.Contracts;

namespace RdpAudit.Core.Events;

/// <summary>Format kinds supported by <see cref="IpEventsExportFormatter"/>.</summary>
public enum IpEventsExportFormat
{
	Json = 0,
	Txt = 1,
	Markdown = 2,
	Csv = 3,
}

/// <summary>Pure clipboard / file-export formatter for the Stage A "Export All IP Events" action.</summary>
public static class IpEventsExportFormatter
{
	private const string TimeFormat = "yyyy-MM-dd HH:mm:ss";

	private static readonly JsonSerializerOptions JsonOptions = new()
	{
		WriteIndented = true,
		Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
	};

	private static readonly string[] CsvHeader =
	{
		"Id",
		"TimeUtc",
		"EventId",
		"Channel",
		"User",
		"Domain",
		"LogonType",
		"AuthPackage",
		"Process",
		"Status",
	};

	/// <summary>Renders <paramref name="dto"/> into <paramref name="format"/>. Throws <see cref="ArgumentNullException"/>
	/// when <paramref name="dto"/> is null and <see cref="ArgumentOutOfRangeException"/> when <paramref name="format"/>
	/// is not one of the defined enum values.</summary>
	public static string Format(EventsForIpDto dto, IpEventsExportFormat format)
	{
		ArgumentNullException.ThrowIfNull(dto);
		return format switch
		{
			IpEventsExportFormat.Json => FormatJson(dto),
			IpEventsExportFormat.Txt => FormatTxt(dto),
			IpEventsExportFormat.Markdown => FormatMarkdown(dto),
			IpEventsExportFormat.Csv => FormatCsv(dto),
			_ => throw new ArgumentOutOfRangeException(nameof(format), format, "Unsupported export format."),
		};
	}

	/// <summary>Returns the canonical file extension (lower-case, with leading dot) for a format.</summary>
	public static string GetFileExtension(IpEventsExportFormat format) => format switch
	{
		IpEventsExportFormat.Json => ".json",
		IpEventsExportFormat.Txt => ".txt",
		IpEventsExportFormat.Markdown => ".md",
		IpEventsExportFormat.Csv => ".csv",
		_ => throw new ArgumentOutOfRangeException(nameof(format), format, "Unsupported export format."),
	};

	/// <summary>Returns a SaveFileDialog filter line for a format, e.g. "JSON (*.json)|*.json".</summary>
	public static string GetSaveFileFilter(IpEventsExportFormat format) => format switch
	{
		IpEventsExportFormat.Json => "JSON (*.json)|*.json",
		IpEventsExportFormat.Txt => "Text (*.txt)|*.txt",
		IpEventsExportFormat.Markdown => "Markdown (*.md)|*.md",
		IpEventsExportFormat.Csv => "CSV (*.csv)|*.csv",
		_ => throw new ArgumentOutOfRangeException(nameof(format), format, "Unsupported export format."),
	};

	/// <summary>Builds a sensible default file name for the SaveFileDialog: <c>rdpaudit-events-{ip}-{utc}.{ext}</c>
	/// with non-filesystem-safe characters in the IP replaced by underscores.</summary>
	public static string GetDefaultFileName(EventsForIpDto dto, IpEventsExportFormat format, DateTime nowUtc)
	{
		ArgumentNullException.ThrowIfNull(dto);
		string safeIp = SanitiseFileNameSegment(dto.Ip);
		string stamp = nowUtc.ToString("yyyyMMdd-HHmmss", CultureInfo.InvariantCulture);
		return string.Format(CultureInfo.InvariantCulture,
			"rdpaudit-events-{0}-{1}{2}", safeIp, stamp, GetFileExtension(format));
	}

	private static string FormatJson(EventsForIpDto dto) =>
		JsonSerializer.Serialize(dto, JsonOptions);

	private static string FormatTxt(EventsForIpDto dto)
	{
		StringBuilder sb = new();
		sb.AppendLine("=== RdpAudit — IP events export ===");
		AppendSummaryLines(sb, dto, prefix: string.Empty);
		sb.AppendLine();
		sb.AppendLine("=== Events (newest first) ===");
		if (dto.Events.Count == 0)
		{
			sb.AppendLine("(no recorded events)");
			return sb.ToString().TrimEnd('\r', '\n');
		}

		foreach (IpEventEntryDto e in dto.Events)
		{
			sb.Append(e.TimeUtc.ToString(TimeFormat, CultureInfo.InvariantCulture))
				.Append("  id=").Append(e.Id.ToString(CultureInfo.InvariantCulture))
				.Append("  event=").Append(e.EventId.ToString(CultureInfo.InvariantCulture))
				.Append("  channel=").Append(SanitiseInline(e.Channel))
				.Append("  user=").Append(SanitiseInline(e.UserName))
				.Append("  domain=").Append(SanitiseInline(e.Domain))
				.Append("  logonType=").Append(e.LogonType?.ToString(CultureInfo.InvariantCulture) ?? "-")
				.Append("  auth=").Append(SanitiseInline(e.AuthPackage))
				.Append("  process=").Append(SanitiseInline(e.ProcessName))
				.Append("  status=").AppendLine(SanitiseInline(e.Status));
		}

		return sb.ToString().TrimEnd('\r', '\n');
	}

	private static string FormatMarkdown(EventsForIpDto dto)
	{
		StringBuilder sb = new();
		sb.AppendLine("# RdpAudit — IP events export");
		sb.AppendLine();
		sb.AppendLine("## Summary");
		sb.AppendLine();
		AppendSummaryLines(sb, dto, prefix: "- ");
		sb.AppendLine();
		sb.AppendLine("## Events (newest first)");
		sb.AppendLine();
		sb.AppendLine("| Time (UTC) | Id | Event | Channel | User | Domain | LogonType | Process | Status |");
		sb.AppendLine("|------------|----|-------|---------|------|--------|-----------|---------|--------|");
		foreach (IpEventEntryDto e in dto.Events)
		{
			sb.Append("| ").Append(e.TimeUtc.ToString(TimeFormat, CultureInfo.InvariantCulture))
				.Append(" | ").Append(e.Id.ToString(CultureInfo.InvariantCulture))
				.Append(" | ").Append(e.EventId.ToString(CultureInfo.InvariantCulture))
				.Append(" | ").Append(EscapeMarkdown(e.Channel))
				.Append(" | ").Append(EscapeMarkdown(e.UserName))
				.Append(" | ").Append(EscapeMarkdown(e.Domain))
				.Append(" | ").Append(e.LogonType?.ToString(CultureInfo.InvariantCulture) ?? string.Empty)
				.Append(" | ").Append(EscapeMarkdown(e.ProcessName))
				.Append(" | ").Append(EscapeMarkdown(e.Status))
				.AppendLine(" |");
		}

		if (dto.Events.Count == 0)
		{
			sb.AppendLine("| (no events) | | | | | | | | |");
		}

		return sb.ToString().TrimEnd('\r', '\n');
	}

	private static string FormatCsv(EventsForIpDto dto)
	{
		StringBuilder sb = new();
		// Clean tabular event rows — no summary header so the file loads directly into Excel.
		sb.AppendLine(string.Join(',', CsvHeader));
		foreach (IpEventEntryDto e in dto.Events)
		{
			AppendCsvCell(sb, e.Id.ToString(CultureInfo.InvariantCulture)); sb.Append(',');
			AppendCsvCell(sb, e.TimeUtc.ToString(TimeFormat, CultureInfo.InvariantCulture)); sb.Append(',');
			AppendCsvCell(sb, e.EventId.ToString(CultureInfo.InvariantCulture)); sb.Append(',');
			AppendCsvCell(sb, e.Channel); sb.Append(',');
			AppendCsvCell(sb, e.UserName); sb.Append(',');
			AppendCsvCell(sb, e.Domain); sb.Append(',');
			AppendCsvCell(sb, e.LogonType?.ToString(CultureInfo.InvariantCulture)); sb.Append(',');
			AppendCsvCell(sb, e.AuthPackage); sb.Append(',');
			AppendCsvCell(sb, e.ProcessName); sb.Append(',');
			AppendCsvCell(sb, e.Status);
			sb.AppendLine();
		}
		return sb.ToString();
	}

	private static void AppendSummaryLines(StringBuilder sb, EventsForIpDto dto, string prefix)
	{
		sb.Append(prefix).Append("IP: ").AppendLine(dto.Ip);
		sb.Append(prefix).Append("Attack type: ").AppendLine(string.IsNullOrEmpty(dto.AttackType) ? "(unclassified)" : dto.AttackType);
		sb.Append(prefix).Append("Threat level: ").AppendLine(string.IsNullOrEmpty(dto.ThreatLevel) ? "(unknown)" : dto.ThreatLevel);
		sb.Append(prefix).Append("Currently blocked: ").AppendLine(dto.IsBlocked ? "yes" : "no");
		sb.Append(prefix).Append("First seen (UTC): ").AppendLine(FormatNullableTime(dto.FirstSeenUtc));
		sb.Append(prefix).Append("Last seen (UTC): ").AppendLine(FormatNullableTime(dto.LastSeenUtc));
		sb.Append(prefix).Append("Active-window duration (seconds): ").AppendLine(dto.DurationSeconds.ToString(CultureInfo.InvariantCulture));
		sb.Append(prefix).Append("Failed logons: ").AppendLine(dto.FailedCount.ToString(CultureInfo.InvariantCulture));
		sb.Append(prefix).Append("Successful logons: ").AppendLine(dto.SuccessCount.ToString(CultureInfo.InvariantCulture));
		sb.Append(prefix).Append("Total events: ").AppendLine(dto.TotalEvents.ToString(CultureInfo.InvariantCulture));
		sb.Append(prefix).Append("Attempted user names: ").AppendLine(
			dto.AttemptedUserNames.Count == 0
				? "(none recorded)"
				: string.Join(", ", dto.AttemptedUserNames.Select(SanitiseInline)));
		sb.Append(prefix).Append("Exported at (UTC): ").AppendLine(dto.QueriedUtc.ToString(TimeFormat, CultureInfo.InvariantCulture));
	}

	private static string FormatNullableTime(DateTime? value) =>
		value is null ? "(none)" : value.Value.ToString(TimeFormat, CultureInfo.InvariantCulture);

	private static string SanitiseInline(string? value)
	{
		if (string.IsNullOrEmpty(value))
		{
			return "-";
		}

		StringBuilder sb = new(value.Length);
		foreach (char c in value)
		{
			if (c == '\r' || c == '\n' || c == '\t')
			{
				sb.Append(' ');
			}
			else
			{
				sb.Append(c);
			}
		}

		return sb.ToString();
	}

	private static void AppendCsvCell(StringBuilder sb, string? value)
	{
		if (string.IsNullOrEmpty(value))
		{
			return;
		}

		bool needsQuoting = false;
		foreach (char c in value)
		{
			if (c == ',' || c == '"' || c == '\r' || c == '\n')
			{
				needsQuoting = true;
				break;
			}
		}

		if (!needsQuoting)
		{
			sb.Append(value);
			return;
		}

		sb.Append('"');
		foreach (char c in value)
		{
			if (c == '"')
			{
				sb.Append('"').Append('"');
			}
			else if (c == '\r' || c == '\n')
			{
				sb.Append(' ');
			}
			else
			{
				sb.Append(c);
			}
		}
		sb.Append('"');
	}

	private static string EscapeMarkdown(string? value)
	{
		if (string.IsNullOrEmpty(value))
		{
			return string.Empty;
		}

		StringBuilder sb = new(value.Length);
		foreach (char c in value)
		{
			if (c == '|')
			{
				sb.Append("\\|");
			}
			else if (c == '\r' || c == '\n' || c == '\t')
			{
				sb.Append(' ');
			}
			else
			{
				sb.Append(c);
			}
		}
		return sb.ToString();
	}

	private static string SanitiseFileNameSegment(string raw)
	{
		if (string.IsNullOrEmpty(raw))
		{
			return "ip";
		}

		StringBuilder sb = new(raw.Length);
		foreach (char c in raw)
		{
			if (char.IsLetterOrDigit(c) || c == '.' || c == '-')
			{
				sb.Append(c);
			}
			else
			{
				sb.Append('_');
			}
		}
		return sb.ToString();
	}
}
