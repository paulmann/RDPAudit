// File:    src/RdpAudit.Core/Events/ConnectionFactsExportFormatter.cs
// Module:  RdpAudit.Core.Events
// Purpose: Pure clipboard / file-export formatters for the Stage IP-E "Export Connection Facts"
//          action. Renders a ConnectionFactsForIpDto plus its bounded ConnectionFactDto list into
//          JSON / TXT / Markdown / CSV. All non-CSV formats include the per-IP summary header
//          (IP, first/last seen, failed/successful totals, active status, fact count, generated
//          time). CSV stays a clean tabular fact stream — no prose preamble — so the file loads
//          directly into Excel or downstream tools. Embedded tabs / CR / LF / pipes are
//          neutralised so a pasted row never breaks the structure.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Globalization;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using RdpAudit.Core.Ipc.Contracts;

namespace RdpAudit.Core.Events;

/// <summary>Format kinds supported by <see cref="ConnectionFactsExportFormatter"/>.</summary>
public enum ConnectionFactsExportFormat
{
	Json = 0,
	Txt = 1,
	Markdown = 2,
	Csv = 3,
}

/// <summary>Pure clipboard / file-export formatter for the Stage IP-E "Export Connection Facts" action.</summary>
public static class ConnectionFactsExportFormatter
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
		"Ip",
		"UserName",
		"Domain",
		"WtsSessionId",
		"LogonId",
		"FirstSeenUtc",
		"LastSeenUtc",
		"ConnectedUtc",
		"AuthenticatedUtc",
		"DisconnectedUtc",
		"ReconnectedUtc",
		"LoggedOffUtc",
		"FailedLogons",
		"SuccessfulLogons",
		"ObservedEventIds",
		"UserNamesAttempted",
		"IsActive",
		"Classification",
		"IsPublic",
		"IsWhitelisted",
		"IsReportableToAbuseIPDB",
		"IsEligibleForAutoBlock",
	};

	/// <summary>Renders <paramref name="dto"/> into <paramref name="format"/>. Throws
	/// <see cref="ArgumentNullException"/> when <paramref name="dto"/> is null and
	/// <see cref="ArgumentOutOfRangeException"/> when <paramref name="format"/> is not a defined value.</summary>
	public static string Format(ConnectionFactsForIpDto dto, ConnectionFactsExportFormat format)
	{
		ArgumentNullException.ThrowIfNull(dto);
		return format switch
		{
			ConnectionFactsExportFormat.Json => FormatJson(dto),
			ConnectionFactsExportFormat.Txt => FormatTxt(dto),
			ConnectionFactsExportFormat.Markdown => FormatMarkdown(dto),
			ConnectionFactsExportFormat.Csv => FormatCsv(dto),
			_ => throw new ArgumentOutOfRangeException(nameof(format), format, "Unsupported export format."),
		};
	}

	/// <summary>Returns the canonical file extension (lower-case, with leading dot) for a format.</summary>
	public static string GetFileExtension(ConnectionFactsExportFormat format) => format switch
	{
		ConnectionFactsExportFormat.Json => ".json",
		ConnectionFactsExportFormat.Txt => ".txt",
		ConnectionFactsExportFormat.Markdown => ".md",
		ConnectionFactsExportFormat.Csv => ".csv",
		_ => throw new ArgumentOutOfRangeException(nameof(format), format, "Unsupported export format."),
	};

	/// <summary>Returns a SaveFileDialog filter line for a format, e.g. "JSON (*.json)|*.json".</summary>
	public static string GetSaveFileFilter(ConnectionFactsExportFormat format) => format switch
	{
		ConnectionFactsExportFormat.Json => "JSON (*.json)|*.json",
		ConnectionFactsExportFormat.Txt => "Text (*.txt)|*.txt",
		ConnectionFactsExportFormat.Markdown => "Markdown (*.md)|*.md",
		ConnectionFactsExportFormat.Csv => "CSV (*.csv)|*.csv",
		_ => throw new ArgumentOutOfRangeException(nameof(format), format, "Unsupported export format."),
	};

	/// <summary>Builds a sensible default file name: <c>rdpaudit-facts-{ip}-{utc}.{ext}</c>
	/// with non-filesystem-safe characters in the IP replaced by underscores.</summary>
	public static string GetDefaultFileName(ConnectionFactsForIpDto dto, ConnectionFactsExportFormat format, DateTime nowUtc)
	{
		ArgumentNullException.ThrowIfNull(dto);
		string safeIp = SanitiseFileNameSegment(dto.Ip);
		string stamp = nowUtc.ToString("yyyyMMdd-HHmmss", CultureInfo.InvariantCulture);
		return string.Format(CultureInfo.InvariantCulture,
			"rdpaudit-facts-{0}-{1}{2}", safeIp, stamp, GetFileExtension(format));
	}

	private static string FormatJson(ConnectionFactsForIpDto dto) =>
		JsonSerializer.Serialize(dto, JsonOptions);

	private static string FormatTxt(ConnectionFactsForIpDto dto)
	{
		StringBuilder sb = new();
		sb.AppendLine("=== RdpAudit — Connection facts export ===");
		AppendSummaryLines(sb, dto, prefix: string.Empty);
		sb.AppendLine();
		sb.AppendLine("=== Facts (LastSeenUtc desc) ===");
		if (dto.Facts.Count == 0)
		{
			sb.AppendLine("(no recorded facts)");
			return sb.ToString().TrimEnd('\r', '\n');
		}

		foreach (ConnectionFactDto f in dto.Facts)
		{
			sb.Append("first=").Append(f.FirstSeenUtc.ToString(TimeFormat, CultureInfo.InvariantCulture))
				.Append("  last=").Append(f.LastSeenUtc.ToString(TimeFormat, CultureInfo.InvariantCulture))
				.Append("  id=").Append(f.Id.ToString(CultureInfo.InvariantCulture))
				.Append("  ip=").Append(SanitiseInline(f.Ip))
				.Append("  user=").Append(SanitiseInline(f.UserName))
				.Append("  domain=").Append(SanitiseInline(f.Domain))
				.Append("  wts=").Append(f.WtsSessionId?.ToString(CultureInfo.InvariantCulture) ?? "-")
				.Append("  logonId=").Append(SanitiseInline(f.LogonId))
				.Append("  connected=").Append(FormatNullableTime(f.ConnectedUtc))
				.Append("  authenticated=").Append(FormatNullableTime(f.AuthenticatedUtc))
				.Append("  disconnected=").Append(FormatNullableTime(f.DisconnectedUtc))
				.Append("  reconnected=").Append(FormatNullableTime(f.ReconnectedUtc))
				.Append("  loggedOff=").Append(FormatNullableTime(f.LoggedOffUtc))
				.Append("  failed=").Append(f.FailedLogons.ToString(CultureInfo.InvariantCulture))
				.Append("  successful=").Append(f.SuccessfulLogons.ToString(CultureInfo.InvariantCulture))
				.Append("  events=").Append(SanitiseInline(f.ObservedEventIds))
				.Append("  attempted=").Append(SanitiseInline(f.UserNamesAttempted))
				.Append("  active=").AppendLine(f.IsActive ? "yes" : "no");
		}

		return sb.ToString().TrimEnd('\r', '\n');
	}

	private static string FormatMarkdown(ConnectionFactsForIpDto dto)
	{
		StringBuilder sb = new();
		sb.AppendLine("# RdpAudit — Connection facts export");
		sb.AppendLine();
		sb.AppendLine("## Summary");
		sb.AppendLine();
		AppendSummaryLines(sb, dto, prefix: "- ");
		sb.AppendLine();
		sb.AppendLine("## Facts (LastSeenUtc desc)");
		sb.AppendLine();
		sb.AppendLine("| First (UTC) | Last (UTC) | Id | IP | User | Domain | WTS | LogonId | Failed | Successful | Active | Events | Attempted |");
		sb.AppendLine("|-------------|------------|----|----|------|--------|-----|---------|--------|------------|--------|--------|-----------|");
		foreach (ConnectionFactDto f in dto.Facts)
		{
			sb.Append("| ").Append(f.FirstSeenUtc.ToString(TimeFormat, CultureInfo.InvariantCulture))
				.Append(" | ").Append(f.LastSeenUtc.ToString(TimeFormat, CultureInfo.InvariantCulture))
				.Append(" | ").Append(f.Id.ToString(CultureInfo.InvariantCulture))
				.Append(" | ").Append(EscapeMarkdown(f.Ip))
				.Append(" | ").Append(EscapeMarkdown(f.UserName))
				.Append(" | ").Append(EscapeMarkdown(f.Domain))
				.Append(" | ").Append(f.WtsSessionId?.ToString(CultureInfo.InvariantCulture) ?? string.Empty)
				.Append(" | ").Append(EscapeMarkdown(f.LogonId))
				.Append(" | ").Append(f.FailedLogons.ToString(CultureInfo.InvariantCulture))
				.Append(" | ").Append(f.SuccessfulLogons.ToString(CultureInfo.InvariantCulture))
				.Append(" | ").Append(f.IsActive ? "yes" : "no")
				.Append(" | ").Append(EscapeMarkdown(f.ObservedEventIds))
				.Append(" | ").Append(EscapeMarkdown(f.UserNamesAttempted))
				.AppendLine(" |");
		}

		if (dto.Facts.Count == 0)
		{
			sb.AppendLine("| (no facts) | | | | | | | | | | | | |");
		}

		return sb.ToString().TrimEnd('\r', '\n');
	}

	private static string FormatCsv(ConnectionFactsForIpDto dto)
	{
		StringBuilder sb = new();
		// Clean tabular fact rows — no summary preamble so the file loads directly into Excel.
		sb.AppendLine(string.Join(',', CsvHeader));
		foreach (ConnectionFactDto f in dto.Facts)
		{
			AppendCsvCell(sb, f.Id.ToString(CultureInfo.InvariantCulture)); sb.Append(',');
			AppendCsvCell(sb, f.Ip); sb.Append(',');
			AppendCsvCell(sb, f.UserName); sb.Append(',');
			AppendCsvCell(sb, f.Domain); sb.Append(',');
			AppendCsvCell(sb, f.WtsSessionId?.ToString(CultureInfo.InvariantCulture)); sb.Append(',');
			AppendCsvCell(sb, f.LogonId); sb.Append(',');
			AppendCsvCell(sb, f.FirstSeenUtc.ToString(TimeFormat, CultureInfo.InvariantCulture)); sb.Append(',');
			AppendCsvCell(sb, f.LastSeenUtc.ToString(TimeFormat, CultureInfo.InvariantCulture)); sb.Append(',');
			AppendCsvCell(sb, FormatNullableTimeForCsv(f.ConnectedUtc)); sb.Append(',');
			AppendCsvCell(sb, FormatNullableTimeForCsv(f.AuthenticatedUtc)); sb.Append(',');
			AppendCsvCell(sb, FormatNullableTimeForCsv(f.DisconnectedUtc)); sb.Append(',');
			AppendCsvCell(sb, FormatNullableTimeForCsv(f.ReconnectedUtc)); sb.Append(',');
			AppendCsvCell(sb, FormatNullableTimeForCsv(f.LoggedOffUtc)); sb.Append(',');
			AppendCsvCell(sb, f.FailedLogons.ToString(CultureInfo.InvariantCulture)); sb.Append(',');
			AppendCsvCell(sb, f.SuccessfulLogons.ToString(CultureInfo.InvariantCulture)); sb.Append(',');
			AppendCsvCell(sb, f.ObservedEventIds); sb.Append(',');
			AppendCsvCell(sb, f.UserNamesAttempted); sb.Append(',');
			AppendCsvCell(sb, f.IsActive ? "yes" : "no"); sb.Append(',');
			AppendCsvCell(sb, f.Classification); sb.Append(',');
			AppendCsvCell(sb, f.IsPublic ? "yes" : "no"); sb.Append(',');
			AppendCsvCell(sb, f.IsWhitelisted ? "yes" : "no"); sb.Append(',');
			AppendCsvCell(sb, f.IsReportableToAbuseIPDB ? "yes" : "no"); sb.Append(',');
			AppendCsvCell(sb, f.IsEligibleForAutoBlock ? "yes" : "no");
			sb.AppendLine();
		}
		return sb.ToString();
	}

	private static void AppendSummaryLines(StringBuilder sb, ConnectionFactsForIpDto dto, string prefix)
	{
		sb.Append(prefix).Append("IP: ").AppendLine(dto.Ip);
		sb.Append(prefix).Append("First seen (UTC): ").AppendLine(FormatNullableTime(dto.FirstSeenUtc));
		sb.Append(prefix).Append("Last seen (UTC): ").AppendLine(FormatNullableTime(dto.LastSeenUtc));
		sb.Append(prefix).Append("Failed logons: ").AppendLine(dto.FailedLogons.ToString(CultureInfo.InvariantCulture));
		sb.Append(prefix).Append("Successful logons: ").AppendLine(dto.SuccessfulLogons.ToString(CultureInfo.InvariantCulture));
		sb.Append(prefix).Append("Has active fact: ").AppendLine(dto.HasActiveFact ? "yes" : "no");
		sb.Append(prefix).Append("Fact count (returned): ").AppendLine(dto.Facts.Count.ToString(CultureInfo.InvariantCulture));
		sb.Append(prefix).Append("Total matching: ").AppendLine(dto.TotalMatching.ToString(CultureInfo.InvariantCulture));
		sb.Append(prefix).Append("Applied limit: ").AppendLine(dto.AppliedLimit.ToString(CultureInfo.InvariantCulture));
		sb.Append(prefix).Append("Generated (UTC): ").AppendLine(dto.QueriedUtc.ToString(TimeFormat, CultureInfo.InvariantCulture));
	}

	private static string FormatNullableTime(DateTime? value) =>
		value is null ? "(none)" : value.Value.ToString(TimeFormat, CultureInfo.InvariantCulture);

	private static string? FormatNullableTimeForCsv(DateTime? value) =>
		value?.ToString(TimeFormat, CultureInfo.InvariantCulture);

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
