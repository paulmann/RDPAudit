// File:    src/RdpAudit.Core/AbuseIpDb/AbuseIpDbCommentBuilder.cs
// Module:  RdpAudit.Core.AbuseIpDb
// Purpose: Pure helper that constructs the AbuseIPDB report "comment" body from RdpAudit evidence.
//          The comment is professional, sanitised, and intentionally free of local credentials,
//          command-line content, passwords, tokens, internal hostnames or operator personal data.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Globalization;
using System.Text;

namespace RdpAudit.Core.AbuseIpDb;

/// <summary>Pure helper that constructs the AbuseIPDB report "comment" body from RdpAudit evidence.</summary>
public static class AbuseIpDbCommentBuilder
{
	/// <summary>AbuseIPDB enforces 1024 byte limit on the comment; we stay safely under that.</summary>
	public const int MaxCommentLength = 1000;

	/// <summary>Per-username sanitisation cap. Long usernames are truncated with an ellipsis.</summary>
	public const int MaxUsernameLength = 32;

	/// <summary>Cap on the number of distinct usernames included in the evidence comment.</summary>
	public const int MaxUsernamesIncluded = 10;

	/// <summary>Public attribution footer linking back to the RdpAudit project on GitHub.</summary>
	public const string AttributionFooter = "Reported via RDP Monitor https://github.com/paulmann/RDPAudit";

	/// <summary>Builds a professional report comment from the supplied evidence.</summary>
	/// <param name="evidence">Evidence collected for the IP. Required.</param>
	/// <returns>Single-line comment safe to submit to AbuseIPDB.</returns>
	public static string Build(AbuseIpDbEvidence evidence)
	{
		ArgumentNullException.ThrowIfNull(evidence);

		StringBuilder sb = new();
		sb.Append("IP Address: ").Append(SanitizeIp(evidence.Ip)).Append(". ");
		sb.Append("Hostname: ").Append(string.IsNullOrWhiteSpace(evidence.Hostname) ? "Not resolved" : SanitizeFreeText(evidence.Hostname, 64)).Append(". ");
		sb.Append("Connection Type: RDP Attack. ");
		sb.Append("Failed Attempts: ").Append(evidence.FailedAttempts.ToString(CultureInfo.InvariantCulture)).Append(". ");
		sb.Append("Successful Logins: ").Append(evidence.SuccessfulLogins.ToString(CultureInfo.InvariantCulture)).Append(". ");
		sb.Append("First Seen: ").Append(evidence.FirstSeenUtc.ToString("u", CultureInfo.InvariantCulture)).Append(". ");
		sb.Append("Last Seen: ").Append(evidence.LastSeenUtc.ToString("u", CultureInfo.InvariantCulture)).Append(". ");

		string usernames = BuildUsernameList(evidence.UsernamesAttempted);
		sb.Append("Usernames Attempted: ").Append(usernames).Append(". ");

		TimeSpan duration = evidence.LastSeenUtc - evidence.FirstSeenUtc;
		if (duration < TimeSpan.Zero)
		{
			duration = TimeSpan.Zero;
		}
		sb.Append("Duration: ").Append(FormatDuration(duration)).Append(". ");

		sb.Append("Intensity: ").Append(FormatIntensity(evidence.FailedAttempts + evidence.SuccessfulLogins, duration)).Append(". ");

		string eventIds = FormatEventIds(evidence.EvidenceEventIds);
		if (eventIds.Length > 0)
		{
			sb.Append("Evidence Event IDs: ").Append(eventIds).Append(". ");
		}

		sb.Append(AttributionFooter);

		string result = sb.ToString();
		if (result.Length > MaxCommentLength)
		{
			result = result[..(MaxCommentLength - 3)] + "...";
		}
		return result;
	}

	/// <summary>Sanitises a username list down to the cap, deduplicated and truncated.</summary>
	internal static string BuildUsernameList(IEnumerable<string>? usernames)
	{
		if (usernames is null)
		{
			return "n/a";
		}

		List<string> cleaned = new();
		HashSet<string> seen = new(StringComparer.OrdinalIgnoreCase);
		foreach (string raw in usernames)
		{
			string sanitised = SanitizeUsername(raw);
			if (sanitised.Length == 0)
			{
				continue;
			}
			if (!seen.Add(sanitised))
			{
				continue;
			}
			cleaned.Add(sanitised);
			if (cleaned.Count >= MaxUsernamesIncluded)
			{
				break;
			}
		}

		if (cleaned.Count == 0)
		{
			return "n/a";
		}

		return string.Join(", ", cleaned);
	}

	/// <summary>Returns a single-line, control-character-free username, truncated to a safe cap.</summary>
	internal static string SanitizeUsername(string? raw)
	{
		if (string.IsNullOrWhiteSpace(raw))
		{
			return string.Empty;
		}

		StringBuilder sb = new(raw.Length);
		foreach (char c in raw)
		{
			if (char.IsControl(c) || c == ',' || c == ';' || c == '\n' || c == '\r' || c == '\t')
			{
				continue;
			}
			sb.Append(c);
		}

		string cleaned = sb.ToString().Trim();
		if (cleaned.Length == 0)
		{
			return string.Empty;
		}

		if (cleaned.Length > MaxUsernameLength)
		{
			cleaned = cleaned[..(MaxUsernameLength - 1)] + "…";
		}
		return cleaned;
	}

	/// <summary>Strips control characters and truncates free text destined for the report comment.</summary>
	internal static string SanitizeFreeText(string raw, int max)
	{
		StringBuilder sb = new(raw.Length);
		foreach (char c in raw)
		{
			if (char.IsControl(c))
			{
				continue;
			}
			sb.Append(c);
		}
		string cleaned = sb.ToString().Trim();
		if (cleaned.Length > max)
		{
			cleaned = cleaned[..(max - 1)] + "…";
		}
		return cleaned;
	}

	/// <summary>Returns the IP unchanged when textually safe; otherwise returns "invalid-ip".</summary>
	internal static string SanitizeIp(string? raw)
	{
		if (string.IsNullOrWhiteSpace(raw))
		{
			return "invalid-ip";
		}
		string trimmed = raw.Trim();
		foreach (char c in trimmed)
		{
			if (char.IsControl(c) || c == ' ' || c == ',' || c == ';')
			{
				return "invalid-ip";
			}
		}
		return trimmed;
	}

	/// <summary>Formats attempt intensity as attempts-per-hour, or a total when the window is sub-hour.</summary>
	internal static string FormatIntensity(long totalAttempts, TimeSpan window)
	{
		if (totalAttempts <= 0)
		{
			return "0 attempts";
		}
		double hours = window.TotalHours;
		if (hours < 1.0 / 60.0)
		{
			return string.Format(CultureInfo.InvariantCulture, "{0} attempts (burst)", totalAttempts);
		}
		double perHour = totalAttempts / hours;
		return string.Format(CultureInfo.InvariantCulture, "{0:0.#} attempts/hour", perHour);
	}

	/// <summary>Renders the distinct evidence Windows event IDs (e.g. 4625/4776/4624/4648), comma separated.</summary>
	internal static string FormatEventIds(IEnumerable<int>? eventIds)
	{
		if (eventIds is null)
		{
			return string.Empty;
		}
		List<string> distinct = new();
		HashSet<int> seen = new();
		foreach (int id in eventIds)
		{
			if (id <= 0 || !seen.Add(id))
			{
				continue;
			}
			distinct.Add(id.ToString(CultureInfo.InvariantCulture));
		}
		return distinct.Count == 0 ? string.Empty : string.Join(",", distinct);
	}

	private static string FormatDuration(TimeSpan span)
	{
		if (span.TotalDays >= 1.0)
		{
			return string.Format(CultureInfo.InvariantCulture, "{0}d {1}h", (int)span.TotalDays, span.Hours);
		}
		if (span.TotalHours >= 1.0)
		{
			return string.Format(CultureInfo.InvariantCulture, "{0}h {1}m", (int)span.TotalHours, span.Minutes);
		}
		if (span.TotalMinutes >= 1.0)
		{
			return string.Format(CultureInfo.InvariantCulture, "{0}m {1}s", (int)span.TotalMinutes, span.Seconds);
		}
		return string.Format(CultureInfo.InvariantCulture, "{0}s", (int)span.TotalSeconds);
	}
}

/// <summary>Plain-data evidence carried to <see cref="AbuseIpDbCommentBuilder.Build"/>.</summary>
public sealed class AbuseIpDbEvidence
{
	/// <summary>Source IP being reported.</summary>
	public string Ip { get; set; } = string.Empty;

	/// <summary>Optional reverse-DNS hostname, or empty when unresolved.</summary>
	public string Hostname { get; set; } = string.Empty;

	/// <summary>Failed logon attempt count.</summary>
	public long FailedAttempts { get; set; }

	/// <summary>Successful logon count.</summary>
	public long SuccessfulLogins { get; set; }

	/// <summary>UTC timestamp of the first observed attempt.</summary>
	public DateTime FirstSeenUtc { get; set; }

	/// <summary>UTC timestamp of the most recent observed attempt.</summary>
	public DateTime LastSeenUtc { get; set; }

	/// <summary>Usernames attempted during the observation window.</summary>
	public IReadOnlyList<string> UsernamesAttempted { get; set; } = Array.Empty<string>();

	/// <summary>Distinct Windows Security event IDs that constitute the evidence (e.g. 4625/4776/4624/4648).
	/// Empty when no specific event IDs are available.</summary>
	public IReadOnlyList<int> EvidenceEventIds { get; set; } = Array.Empty<int>();
}
