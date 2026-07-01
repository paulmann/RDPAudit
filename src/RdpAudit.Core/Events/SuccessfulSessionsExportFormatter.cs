// File:    src/RdpAudit.Core/Events/SuccessfulSessionsExportFormatter.cs
// Module:  RdpAudit.Core.Events
// Purpose: Pure clipboard / file-export formatter for the "Export Successful RDP Sessions" action.
//          Takes the same ConnectionFactsForIpDto used by Export Connection Facts, keeps only the
//          facts that represent a genuinely successful RDP session (SuccessfulLogons > 0 OR a
//          Connected/Authenticated lifecycle timestamp is present), and renders — per session —
//          the exact evidence the "session is successful" decision was based on: the decision
//          event ids decoded to their meaning, and the lifecycle timestamps. Emits JSON / TXT /
//          Markdown / CSV. Embedded tabs / CR / LF / pipes are neutralised so a pasted row never
//          breaks the structure.
// Depends: ConnectionFactsForIpDto, ConnectionFactDto, LogonTypeCatalog, EventCatalog
// Extends: To change what "successful" means, edit IsSuccessful(). To add a new decision event id
//          or reword its meaning, edit DecisionEventMeaning(). Add new output columns in the CSV
//          header + FormatCsv row loop and in the TXT / Markdown renderers together.
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Globalization;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using RdpAudit.Core.Ipc.Contracts;

namespace RdpAudit.Core.Events;

/// <summary>Format kinds supported by <see cref="SuccessfulSessionsExportFormatter"/>.</summary>
public enum SuccessfulSessionsExportFormat
{
	Json = 0,
	Txt = 1,
	Markdown = 2,
	Csv = 3,
}

/// <summary>Pure file-export formatter for the "Export Successful RDP Sessions" action. Renders the
/// successful subset of a <see cref="ConnectionFactsForIpDto"/> together with the decision evidence
/// (which events proved the session succeeded) into JSON / TXT / Markdown / CSV.</summary>
public static class SuccessfulSessionsExportFormatter
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
		"SuccessfulLogons",
		"FailedLogons",
		"ConnectedUtc",
		"AuthenticatedUtc",
		"ReconnectedUtc",
		"DisconnectedUtc",
		"LoggedOffUtc",
		"FirstSeenUtc",
		"LastSeenUtc",
		"IsActive",
		"DecisionEventIds",
		"DecisionEvidence",
	};

	// ── Public API ───────────────────────────────────────────────────────────────

	/// <summary>Renders <paramref name="dto"/> into <paramref name="format"/>, keeping only successful
	/// sessions. Throws <see cref="ArgumentNullException"/> when <paramref name="dto"/> is null and
	/// <see cref="ArgumentOutOfRangeException"/> when <paramref name="format"/> is undefined.</summary>
	public static string Format(ConnectionFactsForIpDto dto, SuccessfulSessionsExportFormat format)
	{
		ArgumentNullException.ThrowIfNull(dto);
		List<ConnectionFactDto> successful = SelectSuccessful(dto);
		return format switch
		{
			SuccessfulSessionsExportFormat.Json => FormatJson(dto, successful),
			SuccessfulSessionsExportFormat.Txt => FormatTxt(dto, successful),
			SuccessfulSessionsExportFormat.Markdown => FormatMarkdown(dto, successful),
			SuccessfulSessionsExportFormat.Csv => FormatCsv(successful),
			_ => throw new ArgumentOutOfRangeException(nameof(format), format, "Unsupported export format."),
		};
	}

	/// <summary>Returns the canonical file extension (lower-case, with leading dot) for a format.</summary>
	public static string GetFileExtension(SuccessfulSessionsExportFormat format) => format switch
	{
		SuccessfulSessionsExportFormat.Json => ".json",
		SuccessfulSessionsExportFormat.Txt => ".txt",
		SuccessfulSessionsExportFormat.Markdown => ".md",
		SuccessfulSessionsExportFormat.Csv => ".csv",
		_ => throw new ArgumentOutOfRangeException(nameof(format), format, "Unsupported export format."),
	};

	/// <summary>Returns a SaveFileDialog filter line for a format, e.g. "JSON (*.json)|*.json".</summary>
	public static string GetSaveFileFilter(SuccessfulSessionsExportFormat format) => format switch
	{
		SuccessfulSessionsExportFormat.Json => "JSON (*.json)|*.json",
		SuccessfulSessionsExportFormat.Txt => "Text (*.txt)|*.txt",
		SuccessfulSessionsExportFormat.Markdown => "Markdown (*.md)|*.md",
		SuccessfulSessionsExportFormat.Csv => "CSV (*.csv)|*.csv",
		_ => throw new ArgumentOutOfRangeException(nameof(format), format, "Unsupported export format."),
	};

	/// <summary>Builds a default file name: <c>rdpaudit-successful-sessions-{ip}-{utc}.{ext}</c>.</summary>
	public static string GetDefaultFileName(ConnectionFactsForIpDto dto, SuccessfulSessionsExportFormat format, DateTime nowUtc)
	{
		ArgumentNullException.ThrowIfNull(dto);
		string safeIp = SanitiseFileNameSegment(dto.Ip);
		string stamp = nowUtc.ToString("yyyyMMdd-HHmmss", CultureInfo.InvariantCulture);
		return string.Format(CultureInfo.InvariantCulture,
			"rdpaudit-successful-sessions-{0}-{1}{2}", safeIp, stamp, GetFileExtension(format));
	}

	// ── Core Logic — selection & decision evidence ─────────────────────────────────

	/// <summary>Returns true when a fact represents a genuinely successful RDP session: either the
	/// aggregator counted at least one successful logon for it, or a positive lifecycle timestamp
	/// (connected / authenticated / reconnected) is present.</summary>
	public static bool IsSuccessful(ConnectionFactDto fact)
	{
		ArgumentNullException.ThrowIfNull(fact);
		return fact.SuccessfulLogons > 0
			|| fact.ConnectedUtc is not null
			|| fact.AuthenticatedUtc is not null
			|| fact.ReconnectedUtc is not null;
	}

	private static List<ConnectionFactDto> SelectSuccessful(ConnectionFactsForIpDto dto) =>
		dto.Facts.Where(IsSuccessful).ToList();

	/// <summary>Decodes one decision event id (as stored in <c>ObservedEventIds</c>) into the reason
	/// the aggregator treats it as a successful-session signal. Ids that are not success signals are
	/// still decoded to their catalog meaning so the operator sees the full evidence trail.</summary>
	private static string DecisionEventMeaning(int eventId) => eventId switch
	{
		4624 => "Security 4624 — successful logon (RDP-relevant logon type). Definitive authentication success.",
		1149 => "TS-RCM 1149 — RDP network connection authenticated (NLA / RD Gateway). Confirms a real connection.",
		21 => "TS-LSM 21 — session logon succeeded (with source IP). Confirms an interactive session was created.",
		25 => "TS-LSM 25 — session reconnection succeeded. Confirms the session was resumed.",
		22 => "TS-LSM 22 — shell (desktop) start notification. Corroborates an established session.",
		_ => CatalogMeaning(eventId),
	};

	/// <summary>Looks a raw event id up in <see cref="EventCatalog"/> for a friendly meaning, falling
	/// back to a neutral label for ids outside the catalog.</summary>
	private static string CatalogMeaning(int eventId)
	{
		foreach (EventDescriptor d in EventCatalog.All)
		{
			if (d.EventId == eventId)
			{
				return string.Format(CultureInfo.InvariantCulture, "Event {0} — {1}.", eventId, d.Description);
			}
		}

		return string.Format(CultureInfo.InvariantCulture, "Event {0} — contributing event (see raw logs).", eventId);
	}

	/// <summary>Parses the comma-separated <c>ObservedEventIds</c> into ordered, deduplicated ints.
	/// Non-numeric tokens are ignored so a malformed field can never throw.</summary>
	private static IReadOnlyList<int> ParseEventIds(string? observedEventIds)
	{
		if (string.IsNullOrWhiteSpace(observedEventIds))
		{
			return Array.Empty<int>();
		}

		List<int> ids = new();
		foreach (string token in observedEventIds.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
		{
			if (int.TryParse(token, NumberStyles.Integer, CultureInfo.InvariantCulture, out int id) && !ids.Contains(id))
			{
				ids.Add(id);
			}
		}

		return ids;
	}

	/// <summary>Builds a single-line evidence string joining each decision event id to its meaning.</summary>
	private static string BuildEvidenceInline(string? observedEventIds)
	{
		IReadOnlyList<int> ids = ParseEventIds(observedEventIds);
		if (ids.Count == 0)
		{
			return "(no contributing event ids recorded)";
		}

		return string.Join("; ", ids.Select(DecisionEventMeaning));
	}

	// ── Renderers ──────────────────────────────────────────────────────────────────

	private static string FormatJson(ConnectionFactsForIpDto dto, List<ConnectionFactDto> successful)
	{
		var payload = new
		{
			ip = dto.Ip,
			generatedUtc = dto.QueriedUtc,
			totalFactsReturned = dto.Facts.Count,
			successfulSessionCount = successful.Count,
			hasActiveFact = dto.HasActiveFact,
			note = "Only sessions with a positive success signal are included. 'decisionEvidence' lists the "
				+ "exact events the success decision was based on.",
			sessions = successful.Select(f => new
			{
				id = f.Id,
				ip = f.Ip,
				userName = f.UserName,
				domain = f.Domain,
				wtsSessionId = f.WtsSessionId,
				logonId = f.LogonId,
				successfulLogons = f.SuccessfulLogons,
				failedLogons = f.FailedLogons,
				connectedUtc = f.ConnectedUtc,
				authenticatedUtc = f.AuthenticatedUtc,
				reconnectedUtc = f.ReconnectedUtc,
				disconnectedUtc = f.DisconnectedUtc,
				loggedOffUtc = f.LoggedOffUtc,
				firstSeenUtc = f.FirstSeenUtc,
				lastSeenUtc = f.LastSeenUtc,
				isActive = f.IsActive,
				decisionEventIds = ParseEventIds(f.ObservedEventIds),
				decisionEvidence = ParseEventIds(f.ObservedEventIds).Select(id => new
				{
					eventId = id,
					meaning = DecisionEventMeaning(id),
				}),
			}),
		};

		return JsonSerializer.Serialize(payload, JsonOptions);
	}

	private static string FormatTxt(ConnectionFactsForIpDto dto, List<ConnectionFactDto> successful)
	{
		StringBuilder sb = new();
		sb.AppendLine("=== RdpAudit — Successful RDP sessions export ===");
		sb.Append("IP: ").AppendLine(dto.Ip);
		sb.Append("Generated (UTC): ").AppendLine(dto.QueriedUtc.ToString(TimeFormat, CultureInfo.InvariantCulture));
		sb.Append("Successful sessions: ").AppendLine(successful.Count.ToString(CultureInfo.InvariantCulture));
		sb.Append("Facts returned (all outcomes): ").AppendLine(dto.Facts.Count.ToString(CultureInfo.InvariantCulture));
		sb.AppendLine("A session is listed here only when it carries a positive success signal");
		sb.AppendLine("(SuccessfulLogons > 0 or a Connected / Authenticated / Reconnected timestamp).");
		sb.AppendLine();

		if (successful.Count == 0)
		{
			sb.AppendLine("=== Sessions ===");
			sb.AppendLine("(no successful RDP sessions recorded for this IP)");
			return sb.ToString().TrimEnd('\r', '\n');
		}

		int index = 0;
		foreach (ConnectionFactDto f in successful)
		{
			index++;
			sb.Append("--- Session #").Append(index.ToString(CultureInfo.InvariantCulture))
				.Append(" (fact id ").Append(f.Id.ToString(CultureInfo.InvariantCulture)).AppendLine(") ---");
			sb.Append("  User          : ").AppendLine(SanitiseInline(f.UserName));
			sb.Append("  Domain        : ").AppendLine(SanitiseInline(f.Domain));
			sb.Append("  WTS session   : ").AppendLine(f.WtsSessionId?.ToString(CultureInfo.InvariantCulture) ?? "-");
			sb.Append("  LogonId       : ").AppendLine(SanitiseInline(f.LogonId));
			sb.Append("  Successful    : ").AppendLine(f.SuccessfulLogons.ToString(CultureInfo.InvariantCulture));
			sb.Append("  Failed        : ").AppendLine(f.FailedLogons.ToString(CultureInfo.InvariantCulture));
			sb.Append("  Connected     : ").AppendLine(FormatNullableTime(f.ConnectedUtc));
			sb.Append("  Authenticated : ").AppendLine(FormatNullableTime(f.AuthenticatedUtc));
			sb.Append("  Reconnected   : ").AppendLine(FormatNullableTime(f.ReconnectedUtc));
			sb.Append("  Disconnected  : ").AppendLine(FormatNullableTime(f.DisconnectedUtc));
			sb.Append("  Logged off    : ").AppendLine(FormatNullableTime(f.LoggedOffUtc));
			sb.Append("  First seen    : ").AppendLine(f.FirstSeenUtc.ToString(TimeFormat, CultureInfo.InvariantCulture));
			sb.Append("  Last seen     : ").AppendLine(f.LastSeenUtc.ToString(TimeFormat, CultureInfo.InvariantCulture));
			sb.Append("  Active        : ").AppendLine(f.IsActive ? "yes" : "no");
			sb.AppendLine("  Decision — the success verdict is based on these events:");
			IReadOnlyList<int> ids = ParseEventIds(f.ObservedEventIds);
			if (ids.Count == 0)
			{
				sb.AppendLine("    (no contributing event ids recorded)");
			}
			else
			{
				foreach (int id in ids)
				{
					sb.Append("    • ").AppendLine(DecisionEventMeaning(id));
				}
			}

			sb.AppendLine();
		}

		return sb.ToString().TrimEnd('\r', '\n');
	}

	private static string FormatMarkdown(ConnectionFactsForIpDto dto, List<ConnectionFactDto> successful)
	{
		StringBuilder sb = new();
		sb.AppendLine("# RdpAudit — Successful RDP sessions export");
		sb.AppendLine();
		sb.AppendLine("## Summary");
		sb.AppendLine();
		sb.Append("- IP: ").AppendLine(dto.Ip);
		sb.Append("- Generated (UTC): ").AppendLine(dto.QueriedUtc.ToString(TimeFormat, CultureInfo.InvariantCulture));
		sb.Append("- Successful sessions: ").AppendLine(successful.Count.ToString(CultureInfo.InvariantCulture));
		sb.Append("- Facts returned (all outcomes): ").AppendLine(dto.Facts.Count.ToString(CultureInfo.InvariantCulture));
		sb.AppendLine("- A session is listed only when it carries a positive success signal "
			+ "(SuccessfulLogons > 0 or a Connected / Authenticated / Reconnected timestamp).");
		sb.AppendLine();
		sb.AppendLine("## Sessions");
		sb.AppendLine();
		sb.AppendLine("| # | Fact Id | User | Domain | WTS | LogonId | Successful | Connected (UTC) | Authenticated (UTC) | Active | Decision events (evidence) |");
		sb.AppendLine("|---|---------|------|--------|-----|---------|------------|-----------------|---------------------|--------|----------------------------|");

		if (successful.Count == 0)
		{
			sb.AppendLine("| — | | | | | | | | | | (no successful RDP sessions recorded) |");
			return sb.ToString().TrimEnd('\r', '\n');
		}

		int index = 0;
		foreach (ConnectionFactDto f in successful)
		{
			index++;
			sb.Append("| ").Append(index.ToString(CultureInfo.InvariantCulture))
				.Append(" | ").Append(f.Id.ToString(CultureInfo.InvariantCulture))
				.Append(" | ").Append(EscapeMarkdown(f.UserName))
				.Append(" | ").Append(EscapeMarkdown(f.Domain))
				.Append(" | ").Append(f.WtsSessionId?.ToString(CultureInfo.InvariantCulture) ?? string.Empty)
				.Append(" | ").Append(EscapeMarkdown(f.LogonId))
				.Append(" | ").Append(f.SuccessfulLogons.ToString(CultureInfo.InvariantCulture))
				.Append(" | ").Append(EscapeMarkdown(FormatNullableTime(f.ConnectedUtc)))
				.Append(" | ").Append(EscapeMarkdown(FormatNullableTime(f.AuthenticatedUtc)))
				.Append(" | ").Append(f.IsActive ? "yes" : "no")
				.Append(" | ").Append(EscapeMarkdown(BuildEvidenceInline(f.ObservedEventIds)))
				.AppendLine(" |");
		}

		return sb.ToString().TrimEnd('\r', '\n');
	}

	private static string FormatCsv(List<ConnectionFactDto> successful)
	{
		StringBuilder sb = new();
		sb.AppendLine(string.Join(',', CsvHeader));
		foreach (ConnectionFactDto f in successful)
		{
			AppendCsvCell(sb, f.Id.ToString(CultureInfo.InvariantCulture)); sb.Append(',');
			AppendCsvCell(sb, f.Ip); sb.Append(',');
			AppendCsvCell(sb, f.UserName); sb.Append(',');
			AppendCsvCell(sb, f.Domain); sb.Append(',');
			AppendCsvCell(sb, f.WtsSessionId?.ToString(CultureInfo.InvariantCulture)); sb.Append(',');
			AppendCsvCell(sb, f.LogonId); sb.Append(',');
			AppendCsvCell(sb, f.SuccessfulLogons.ToString(CultureInfo.InvariantCulture)); sb.Append(',');
			AppendCsvCell(sb, f.FailedLogons.ToString(CultureInfo.InvariantCulture)); sb.Append(',');
			AppendCsvCell(sb, FormatNullableTimeForCsv(f.ConnectedUtc)); sb.Append(',');
			AppendCsvCell(sb, FormatNullableTimeForCsv(f.AuthenticatedUtc)); sb.Append(',');
			AppendCsvCell(sb, FormatNullableTimeForCsv(f.ReconnectedUtc)); sb.Append(',');
			AppendCsvCell(sb, FormatNullableTimeForCsv(f.DisconnectedUtc)); sb.Append(',');
			AppendCsvCell(sb, FormatNullableTimeForCsv(f.LoggedOffUtc)); sb.Append(',');
			AppendCsvCell(sb, f.FirstSeenUtc.ToString(TimeFormat, CultureInfo.InvariantCulture)); sb.Append(',');
			AppendCsvCell(sb, f.LastSeenUtc.ToString(TimeFormat, CultureInfo.InvariantCulture)); sb.Append(',');
			AppendCsvCell(sb, f.IsActive ? "yes" : "no"); sb.Append(',');
			AppendCsvCell(sb, string.Join(' ', ParseEventIds(f.ObservedEventIds))); sb.Append(',');
			AppendCsvCell(sb, BuildEvidenceInline(f.ObservedEventIds));
			sb.AppendLine();
		}

		return sb.ToString();
	}

	// ── Helpers ──────────────────────────────────────────────────────────────────

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
			sb.Append(c is '\r' or '\n' or '\t' ? ' ' : c);
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
			if (c is ',' or '"' or '\r' or '\n')
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
			else if (c is '\r' or '\n')
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
			else if (c is '\r' or '\n' or '\t')
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
			sb.Append(char.IsLetterOrDigit(c) || c is '.' or '-' ? c : '_');
		}

		return sb.ToString();
	}
}
