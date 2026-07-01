// File:    src/RdpAudit.Core/Events/AuthSuccessExportFormatter.cs
// Module:  RdpAudit.Core.Events
// Purpose: Pure file-export formatter for the RDP Activity "Export Auth Success (per login)" action.
//          Renders an AuthSuccessSummaryDto — the per-login (NormalizedUserName) roll-up of
//          AuthAttemptFacts for one attacker IP — into JSON / TXT / Markdown / CSV. The report is
//          deliberately summary only: one row per account, never one row per attempt. Each login row
//          answers the incident-analyst questions "was this login's password guessed from this IP?",
//          "how many failed attempts did it take?", "how long did it take?", "which events/logon
//          types/auth packages proved the success?" and "which failure reasons were seen?". Embedded
//          tabs / CR / LF / pipes are neutralised so a pasted row never breaks the structure.
// Depends: AuthSuccessSummaryDto, AuthSuccessLoginDto, LogonTypeCatalog, EventCatalog
// Extends: To add a new per-login output column, add it to CsvHeader + FormatCsv + FormatTxt +
//          FormatMarkdown + FormatJson together. To reword a success-event meaning, edit
//          SuccessEventMeaning(). To decode a new logon type, extend LogonTypeCatalog (not here).
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Globalization;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using RdpAudit.Core.Ipc.Contracts;

namespace RdpAudit.Core.Events;

/// <summary>Format kinds supported by <see cref="AuthSuccessExportFormatter"/>.</summary>
public enum AuthSuccessExportFormat
{
	Json = 0,
	Txt = 1,
	Markdown = 2,
	Csv = 3,
}

/// <summary>Pure file-export formatter for the "Export Auth Success (per login)" action. Renders the
/// per-login roll-up carried by <see cref="AuthSuccessSummaryDto"/> together with the decision
/// evidence (which events / logon types proved each success) into JSON / TXT / Markdown / CSV.</summary>
public static class AuthSuccessExportFormatter
{
	private const string TimeFormat = "yyyy-MM-dd HH:mm:ss";

	private static readonly JsonSerializerOptions JsonOptions = new()
	{
		WriteIndented = true,
		Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
	};

	private static readonly string[] CsvHeader =
	{
		"NormalizedUserName",
		"DisplayUserName",
		"Domain",
		"AttackerIp",
		"HasSuccess",
		"SuccessfulAuthCount",
		"FailedAuthCount",
		"DeniedAuthCount",
		"TotalAuthCount",
		"FailedBeforeFirstSuccess",
		"SecondsToFirstSuccess",
		"TimeToFirstSuccess",
		"FirstSeenUtc",
		"LastSeenUtc",
		"FirstSuccessUtc",
		"LastSuccessUtc",
		"SuccessEventIds",
		"SuccessEventMeanings",
		"SuccessLogonTypes",
		"SuccessLogonTypeMeanings",
		"SuccessAuthPackages",
		"FailureReasons",
	};

	// ── Public API ───────────────────────────────────────────────────────────────

	/// <summary>Renders <paramref name="dto"/> into <paramref name="format"/>. Throws
	/// <see cref="ArgumentNullException"/> when <paramref name="dto"/> is null and
	/// <see cref="ArgumentOutOfRangeException"/> when <paramref name="format"/> is undefined.</summary>
	public static string Format(AuthSuccessSummaryDto dto, AuthSuccessExportFormat format)
	{
		ArgumentNullException.ThrowIfNull(dto);
		return format switch
		{
			AuthSuccessExportFormat.Json => FormatJson(dto),
			AuthSuccessExportFormat.Txt => FormatTxt(dto),
			AuthSuccessExportFormat.Markdown => FormatMarkdown(dto),
			AuthSuccessExportFormat.Csv => FormatCsv(dto),
			_ => throw new ArgumentOutOfRangeException(nameof(format), format, "Unsupported export format."),
		};
	}

	/// <summary>Returns the canonical file extension (lower-case, with leading dot) for a format.</summary>
	public static string GetFileExtension(AuthSuccessExportFormat format) => format switch
	{
		AuthSuccessExportFormat.Json => ".json",
		AuthSuccessExportFormat.Txt => ".txt",
		AuthSuccessExportFormat.Markdown => ".md",
		AuthSuccessExportFormat.Csv => ".csv",
		_ => throw new ArgumentOutOfRangeException(nameof(format), format, "Unsupported export format."),
	};

	/// <summary>Returns a SaveFileDialog filter line for a format, e.g. "JSON (*.json)|*.json".</summary>
	public static string GetSaveFileFilter(AuthSuccessExportFormat format) => format switch
	{
		AuthSuccessExportFormat.Json => "JSON (*.json)|*.json",
		AuthSuccessExportFormat.Txt => "Text (*.txt)|*.txt",
		AuthSuccessExportFormat.Markdown => "Markdown (*.md)|*.md",
		AuthSuccessExportFormat.Csv => "CSV (*.csv)|*.csv",
		_ => throw new ArgumentOutOfRangeException(nameof(format), format, "Unsupported export format."),
	};

	/// <summary>Builds a default file name: <c>rdpaudit-auth-success-{ip}-{utc}.{ext}</c>.</summary>
	public static string GetDefaultFileName(AuthSuccessSummaryDto dto, AuthSuccessExportFormat format, DateTime nowUtc)
	{
		ArgumentNullException.ThrowIfNull(dto);
		string safeIp = SanitiseFileNameSegment(dto.Ip);
		string stamp = nowUtc.ToString("yyyyMMdd-HHmmss", CultureInfo.InvariantCulture);
		return string.Format(CultureInfo.InvariantCulture,
			"rdpaudit-auth-success-{0}-{1}{2}", safeIp, stamp, GetFileExtension(format));
	}

	// ── Core Logic — decoding & evidence ───────────────────────────────────────────

	/// <summary>Decodes a success-bearing Windows event id into the reason it proves an authentication
	/// success, falling back to the shared <see cref="EventCatalog"/> for ids outside the core set.</summary>
	public static string SuccessEventMeaning(int eventId) => eventId switch
	{
		4624 => "Security 4624 — successful logon (credential validated at the auth layer).",
		4768 => "Security 4768 — Kerberos TGT issued (account credentials accepted by the KDC).",
		4769 => "Security 4769 — Kerberos service ticket issued (already-authenticated principal).",
		4776 => "Security 4776 — NTLM credential validation succeeded (domain / local account).",
		_ => CatalogMeaning(eventId),
	};

	private static string CatalogMeaning(int eventId)
	{
		foreach (EventDescriptor d in EventCatalog.All)
		{
			if (d.EventId == eventId)
			{
				return string.Format(CultureInfo.InvariantCulture, "Event {0} — {1}.", eventId, d.Description);
			}
		}

		return string.Format(CultureInfo.InvariantCulture, "Event {0} — success-bearing event (see raw logs).", eventId);
	}

	/// <summary>Formats a nullable seconds delta as a compact human-readable duration (e.g.
	/// "2d 03:14:07"); returns "(n/a)" when the login never succeeded.</summary>
	private static string FormatDuration(long? seconds)
	{
		if (seconds is null)
		{
			return "(n/a — never succeeded)";
		}

		TimeSpan span = TimeSpan.FromSeconds(seconds.Value);
		return span.TotalDays >= 1
			? string.Format(CultureInfo.InvariantCulture, "{0}d {1:00}:{2:00}:{3:00}",
				(int)span.TotalDays, span.Hours, span.Minutes, span.Seconds)
			: string.Format(CultureInfo.InvariantCulture, "{0:00}:{1:00}:{2:00}",
				span.Hours, span.Minutes, span.Seconds);
	}

	private static string DescribeLogonTypesInline(IReadOnlyList<int> codes)
	{
		if (codes.Count == 0)
		{
			return "(none)";
		}

		return string.Join("; ", codes.Select(c =>
		{
			LogonTypeInfo info = LogonTypeCatalog.Describe(c);
			return string.Format(CultureInfo.InvariantCulture, "{0} ({1})", info.Code, info.Name);
		}));
	}

	private static string DescribeSuccessEventsInline(IReadOnlyList<int> ids)
	{
		if (ids.Count == 0)
		{
			return "(no success event ids recorded)";
		}

		return string.Join("; ", ids.Select(SuccessEventMeaning));
	}

	// ── Renderers ──────────────────────────────────────────────────────────────────

	private static string FormatJson(AuthSuccessSummaryDto dto)
	{
		var payload = new
		{
			ip = dto.Ip,
			generatedUtc = dto.QueriedUtc,
			succeededLoginsOnly = dto.SucceededLoginsOnly,
			note = "Per-login summary. Each entry is one account rolled up from AuthAttemptFacts — "
				+ "never one row per attempt. 'failedBeforeFirstSuccess' and 'secondsToFirstSuccess' "
				+ "estimate how much effort / time the attacker needed to guess each password.",
			ipTotals = new
			{
				totalAuthFacts = dto.TotalAuthFacts,
				totalSuccessfulAuth = dto.TotalSuccessfulAuth,
				totalFailedAuth = dto.TotalFailedAuth,
				totalDeniedAuth = dto.TotalDeniedAuth,
				distinctLoginsObserved = dto.DistinctLoginsObserved,
				distinctSucceededLogins = dto.DistinctSucceededLogins,
				firstSeenUtc = dto.FirstSeenUtc,
				lastSeenUtc = dto.LastSeenUtc,
			},
			logins = dto.Logins.Select(l => new
			{
				normalizedUserName = l.NormalizedUserName,
				displayUserName = l.DisplayUserName,
				domain = l.Domain,
				attackerIp = dto.Ip,
				hasSuccess = l.HasSuccess,
				successfulAuthCount = l.SuccessfulAuthCount,
				failedAuthCount = l.FailedAuthCount,
				deniedAuthCount = l.DeniedAuthCount,
				totalAuthCount = l.TotalAuthCount,
				failedBeforeFirstSuccess = l.FailedBeforeFirstSuccess,
				secondsToFirstSuccess = l.SecondsToFirstSuccess,
				timeToFirstSuccess = FormatDuration(l.SecondsToFirstSuccess),
				firstSeenUtc = l.FirstSeenUtc,
				lastSeenUtc = l.LastSeenUtc,
				firstSuccessUtc = l.FirstSuccessUtc,
				lastSuccessUtc = l.LastSuccessUtc,
				successEventIds = l.SuccessEventIds,
				successEvidence = l.SuccessEventIds.Select(id => new
				{
					eventId = id,
					meaning = SuccessEventMeaning(id),
				}),
				successLogonTypes = l.SuccessLogonTypes.Select(t =>
				{
					LogonTypeInfo info = LogonTypeCatalog.Describe(t);
					return new { code = info.Code, name = info.Name, description = info.Description };
				}),
				successAuthPackages = l.SuccessAuthPackages,
				failureReasons = l.FailureReasons,
			}),
		};

		return JsonSerializer.Serialize(payload, JsonOptions);
	}

	private static string FormatTxt(AuthSuccessSummaryDto dto)
	{
		StringBuilder sb = new();
		sb.AppendLine("=== RdpAudit — Auth Success per-login export ===");
		sb.Append("Attacker IP: ").AppendLine(dto.Ip);
		sb.Append("Generated (UTC): ").AppendLine(dto.QueriedUtc.ToString(TimeFormat, CultureInfo.InvariantCulture));
		sb.Append("Scope: ").AppendLine(dto.SucceededLoginsOnly
			? "logins with at least one successful authentication only"
			: "every login observed from this IP");
		sb.AppendLine();
		sb.AppendLine("--- IP totals (from AuthAttemptFacts — matches the Auth Success / Auth Failed grid columns) ---");
		sb.Append("  Total auth facts        : ").AppendLine(dto.TotalAuthFacts.ToString(CultureInfo.InvariantCulture));
		sb.Append("  Successful              : ").AppendLine(dto.TotalSuccessfulAuth.ToString(CultureInfo.InvariantCulture));
		sb.Append("  Failed                  : ").AppendLine(dto.TotalFailedAuth.ToString(CultureInfo.InvariantCulture));
		sb.Append("  Denied                  : ").AppendLine(dto.TotalDeniedAuth.ToString(CultureInfo.InvariantCulture));
		sb.Append("  Distinct logins observed: ").AppendLine(dto.DistinctLoginsObserved.ToString(CultureInfo.InvariantCulture));
		sb.Append("  Logins with success     : ").AppendLine(dto.DistinctSucceededLogins.ToString(CultureInfo.InvariantCulture));
		sb.Append("  First seen (UTC)        : ").AppendLine(FormatNullableTime(dto.FirstSeenUtc));
		sb.Append("  Last seen (UTC)         : ").AppendLine(FormatNullableTime(dto.LastSeenUtc));
		sb.AppendLine();
		sb.AppendLine("A login is listed with HasSuccess=yes when its password was validated (or a Kerberos");
		sb.AppendLine("ticket was granted) from this IP. 'Failed before first success' and 'Time to first");
		sb.AppendLine("success' show how much effort / wall-clock time the attacker spent guessing it.");
		sb.AppendLine();

		if (dto.Logins.Count == 0)
		{
			sb.AppendLine("=== Logins ===");
			sb.AppendLine("(no matching logins for this IP)");
			return sb.ToString().TrimEnd('\r', '\n');
		}

		int index = 0;
		foreach (AuthSuccessLoginDto l in dto.Logins)
		{
			index++;
			sb.Append("--- Login #").Append(index.ToString(CultureInfo.InvariantCulture))
				.Append(" — ").Append(SanitiseInline(l.NormalizedUserName)).AppendLine(" ---");
			sb.Append("  Display name          : ").AppendLine(SanitiseInline(l.DisplayUserName));
			sb.Append("  Domain                : ").AppendLine(SanitiseInline(l.Domain));
			sb.Append("  Attacker IP           : ").AppendLine(dto.Ip);
			sb.Append("  Password guessed?     : ").AppendLine(l.HasSuccess ? "YES — credentials validated" : "no");
			sb.Append("  Successful auth       : ").AppendLine(l.SuccessfulAuthCount.ToString(CultureInfo.InvariantCulture));
			sb.Append("  Failed auth           : ").AppendLine(l.FailedAuthCount.ToString(CultureInfo.InvariantCulture));
			sb.Append("  Denied auth           : ").AppendLine(l.DeniedAuthCount.ToString(CultureInfo.InvariantCulture));
			sb.Append("  Total auth            : ").AppendLine(l.TotalAuthCount.ToString(CultureInfo.InvariantCulture));
			sb.Append("  Failed before success : ").AppendLine(l.FailedBeforeFirstSuccess.ToString(CultureInfo.InvariantCulture));
			sb.Append("  Time to first success : ").AppendLine(FormatDuration(l.SecondsToFirstSuccess));
			sb.Append("  First seen (UTC)      : ").AppendLine(FormatNullableTime(l.FirstSeenUtc));
			sb.Append("  Last seen (UTC)       : ").AppendLine(FormatNullableTime(l.LastSeenUtc));
			sb.Append("  First success (UTC)   : ").AppendLine(FormatNullableTime(l.FirstSuccessUtc));
			sb.Append("  Last success (UTC)    : ").AppendLine(FormatNullableTime(l.LastSuccessUtc));
			sb.Append("  Success logon types   : ").AppendLine(DescribeLogonTypesInline(l.SuccessLogonTypes));
			sb.Append("  Success auth packages : ").AppendLine(l.SuccessAuthPackages.Count == 0
				? "(none)"
				: SanitiseInline(string.Join(", ", l.SuccessAuthPackages)));
			sb.Append("  Failure reasons       : ").AppendLine(l.FailureReasons.Count == 0
				? "(none)"
				: SanitiseInline(string.Join(", ", l.FailureReasons)));
			sb.AppendLine("  Success events (the evidence the success verdict is based on):");
			if (l.SuccessEventIds.Count == 0)
			{
				sb.AppendLine("    (no success event ids recorded)");
			}
			else
			{
				foreach (int id in l.SuccessEventIds)
				{
					sb.Append("    • ").AppendLine(SuccessEventMeaning(id));
				}
			}

			sb.AppendLine();
		}

		return sb.ToString().TrimEnd('\r', '\n');
	}

	private static string FormatMarkdown(AuthSuccessSummaryDto dto)
	{
		StringBuilder sb = new();
		sb.AppendLine("# RdpAudit — Auth Success per-login export");
		sb.AppendLine();
		sb.AppendLine("## Summary");
		sb.AppendLine();
		sb.Append("- Attacker IP: ").AppendLine(dto.Ip);
		sb.Append("- Generated (UTC): ").AppendLine(dto.QueriedUtc.ToString(TimeFormat, CultureInfo.InvariantCulture));
		sb.Append("- Scope: ").AppendLine(dto.SucceededLoginsOnly
			? "logins with at least one successful authentication only"
			: "every login observed from this IP");
		sb.Append("- Total auth facts: ").AppendLine(dto.TotalAuthFacts.ToString(CultureInfo.InvariantCulture));
		sb.Append("- Successful / Failed / Denied: ")
			.Append(dto.TotalSuccessfulAuth.ToString(CultureInfo.InvariantCulture)).Append(" / ")
			.Append(dto.TotalFailedAuth.ToString(CultureInfo.InvariantCulture)).Append(" / ")
			.AppendLine(dto.TotalDeniedAuth.ToString(CultureInfo.InvariantCulture));
		sb.Append("- Distinct logins observed: ").AppendLine(dto.DistinctLoginsObserved.ToString(CultureInfo.InvariantCulture));
		sb.Append("- Logins with success (passwords guessed): ").AppendLine(dto.DistinctSucceededLogins.ToString(CultureInfo.InvariantCulture));
		sb.Append("- First / Last seen (UTC): ")
			.Append(FormatNullableTime(dto.FirstSeenUtc)).Append(" / ")
			.AppendLine(FormatNullableTime(dto.LastSeenUtc));
		sb.AppendLine();
		sb.AppendLine("Each row is one account rolled up from AuthAttemptFacts — never one row per attempt. "
			+ "`Failed before` and `Time to 1st success` estimate the effort / wall-clock time to guess each password.");
		sb.AppendLine();
		sb.AppendLine("## Logins");
		sb.AppendLine();
		sb.AppendLine("| # | Login | Domain | Guessed? | Success | Failed | Failed before | Time to 1st success | First success (UTC) | Last seen (UTC) | Success logon types | Success events (evidence) | Failure reasons |");
		sb.AppendLine("|---|-------|--------|----------|---------|--------|---------------|---------------------|---------------------|-----------------|---------------------|---------------------------|-----------------|");

		if (dto.Logins.Count == 0)
		{
			sb.AppendLine("| — | | | | | | | | | | | (no matching logins for this IP) | |");
			return sb.ToString().TrimEnd('\r', '\n');
		}

		int index = 0;
		foreach (AuthSuccessLoginDto l in dto.Logins)
		{
			index++;
			sb.Append("| ").Append(index.ToString(CultureInfo.InvariantCulture))
				.Append(" | ").Append(EscapeMarkdown(l.NormalizedUserName))
				.Append(" | ").Append(EscapeMarkdown(l.Domain))
				.Append(" | ").Append(l.HasSuccess ? "YES" : "no")
				.Append(" | ").Append(l.SuccessfulAuthCount.ToString(CultureInfo.InvariantCulture))
				.Append(" | ").Append(l.FailedAuthCount.ToString(CultureInfo.InvariantCulture))
				.Append(" | ").Append(l.FailedBeforeFirstSuccess.ToString(CultureInfo.InvariantCulture))
				.Append(" | ").Append(EscapeMarkdown(FormatDuration(l.SecondsToFirstSuccess)))
				.Append(" | ").Append(EscapeMarkdown(FormatNullableTime(l.FirstSuccessUtc)))
				.Append(" | ").Append(EscapeMarkdown(FormatNullableTime(l.LastSeenUtc)))
				.Append(" | ").Append(EscapeMarkdown(DescribeLogonTypesInline(l.SuccessLogonTypes)))
				.Append(" | ").Append(EscapeMarkdown(DescribeSuccessEventsInline(l.SuccessEventIds)))
				.Append(" | ").Append(EscapeMarkdown(l.FailureReasons.Count == 0 ? "(none)" : string.Join(", ", l.FailureReasons)))
				.AppendLine(" |");
		}

		return sb.ToString().TrimEnd('\r', '\n');
	}

	private static string FormatCsv(AuthSuccessSummaryDto dto)
	{
		StringBuilder sb = new();
		sb.AppendLine(string.Join(',', CsvHeader));
		foreach (AuthSuccessLoginDto l in dto.Logins)
		{
			AppendCsvCell(sb, l.NormalizedUserName); sb.Append(',');
			AppendCsvCell(sb, l.DisplayUserName); sb.Append(',');
			AppendCsvCell(sb, l.Domain); sb.Append(',');
			AppendCsvCell(sb, dto.Ip); sb.Append(',');
			AppendCsvCell(sb, l.HasSuccess ? "yes" : "no"); sb.Append(',');
			AppendCsvCell(sb, l.SuccessfulAuthCount.ToString(CultureInfo.InvariantCulture)); sb.Append(',');
			AppendCsvCell(sb, l.FailedAuthCount.ToString(CultureInfo.InvariantCulture)); sb.Append(',');
			AppendCsvCell(sb, l.DeniedAuthCount.ToString(CultureInfo.InvariantCulture)); sb.Append(',');
			AppendCsvCell(sb, l.TotalAuthCount.ToString(CultureInfo.InvariantCulture)); sb.Append(',');
			AppendCsvCell(sb, l.FailedBeforeFirstSuccess.ToString(CultureInfo.InvariantCulture)); sb.Append(',');
			AppendCsvCell(sb, l.SecondsToFirstSuccess?.ToString(CultureInfo.InvariantCulture)); sb.Append(',');
			AppendCsvCell(sb, l.SecondsToFirstSuccess is null ? null : FormatDuration(l.SecondsToFirstSuccess)); sb.Append(',');
			AppendCsvCell(sb, FormatNullableTimeForCsv(l.FirstSeenUtc)); sb.Append(',');
			AppendCsvCell(sb, FormatNullableTimeForCsv(l.LastSeenUtc)); sb.Append(',');
			AppendCsvCell(sb, FormatNullableTimeForCsv(l.FirstSuccessUtc)); sb.Append(',');
			AppendCsvCell(sb, FormatNullableTimeForCsv(l.LastSuccessUtc)); sb.Append(',');
			AppendCsvCell(sb, string.Join(' ', l.SuccessEventIds)); sb.Append(',');
			AppendCsvCell(sb, string.Join(" | ", l.SuccessEventIds.Select(SuccessEventMeaning))); sb.Append(',');
			AppendCsvCell(sb, string.Join(' ', l.SuccessLogonTypes)); sb.Append(',');
			AppendCsvCell(sb, string.Join(" | ", l.SuccessLogonTypes.Select(t =>
			{
				LogonTypeInfo info = LogonTypeCatalog.Describe(t);
				return string.Format(CultureInfo.InvariantCulture, "{0}={1}", info.Code, info.Name);
			}))); sb.Append(',');
			AppendCsvCell(sb, string.Join(" | ", l.SuccessAuthPackages)); sb.Append(',');
			AppendCsvCell(sb, string.Join(" | ", l.FailureReasons));
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
