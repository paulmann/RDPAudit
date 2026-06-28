// File:    src/RdpAudit.Core/Models/AttackStatProjection.cs
// Module:  RdpAudit.Core.Models
// Purpose: Pure helper for AttackStat projection: serialises the top-10 attempted logins list to
//          JSON (and back) using a deterministic format, computes the active-window duration, and
//          centralises every code path that writes AttackStat columns so the format does not drift.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Globalization;
using System.Text;
using System.Text.Json;

namespace RdpAudit.Core.Models;

/// <summary>Pure helper for <see cref="AttackStat"/> projection and serialisation.</summary>
public static class AttackStatProjection
{
	/// <summary>Maximum number of logins kept in <see cref="AttackStat.Top10AttemptedLogins"/>.</summary>
	public const int TopLoginsLimit = 10;

	private static readonly JsonSerializerOptions SerializerOptions = new()
	{
		WriteIndented = false,
		Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
	};

	/// <summary>Serialises a sequence of login names to a JSON array, capped at <see cref="TopLoginsLimit"/>.</summary>
	/// <param name="logins">Login names, most-frequent first. Null or whitespace entries are skipped.</param>
	/// <returns>A JSON array literal (e.g. <c>["admin","root"]</c>) suitable for direct storage.</returns>
	public static string SerializeTopLogins(IEnumerable<string?> logins)
	{
		if (logins is null)
		{
			return "[]";
		}

		List<string> cleaned = new(TopLoginsLimit);
		foreach (string? login in logins)
		{
			if (string.IsNullOrWhiteSpace(login))
			{
				continue;
			}
			cleaned.Add(login);
			if (cleaned.Count >= TopLoginsLimit)
			{
				break;
			}
		}

		return JsonSerializer.Serialize(cleaned, SerializerOptions);
	}

	/// <summary>Deserialises the JSON array stored in <see cref="AttackStat.Top10AttemptedLogins"/>.</summary>
	/// <param name="json">JSON array literal previously produced by <see cref="SerializeTopLogins"/>.</param>
	/// <returns>Read-only list of login names. Empty when the input is null, empty, or malformed.</returns>
	public static IReadOnlyList<string> DeserializeTopLogins(string? json)
	{
		if (string.IsNullOrWhiteSpace(json))
		{
			return Array.Empty<string>();
		}

		try
		{
			List<string>? result = JsonSerializer.Deserialize<List<string>>(json, SerializerOptions);
			return result is null ? Array.Empty<string>() : result;
		}
		catch (JsonException)
		{
			return Array.Empty<string>();
		}
	}

	/// <summary>Computes the active-window duration in whole seconds, clamped at zero.</summary>
	public static long ComputeDurationSeconds(DateTime firstSeenUtc, DateTime lastSeenUtc)
	{
		long seconds = (long)(lastSeenUtc - firstSeenUtc).TotalSeconds;
		return seconds < 0 ? 0 : seconds;
	}

	/// <summary>
	/// Returns a deterministic top-N list of login names ordered by descending frequency, breaking
	/// ties alphabetically (ordinal, case-insensitive) so projections are byte-stable across runs.
	/// </summary>
	public static IReadOnlyList<string> ComputeTopLogins(IEnumerable<string?> attemptedLogins, int limit = TopLoginsLimit)
	{
		if (attemptedLogins is null)
		{
			return Array.Empty<string>();
		}

		Dictionary<string, int> counts = new(StringComparer.OrdinalIgnoreCase);
		foreach (string? login in attemptedLogins)
		{
			if (string.IsNullOrWhiteSpace(login))
			{
				continue;
			}
			counts[login] = counts.TryGetValue(login, out int existing) ? existing + 1 : 1;
		}

		return counts
			.OrderByDescending(kvp => kvp.Value)
			.ThenBy(kvp => kvp.Key, StringComparer.OrdinalIgnoreCase)
			.Take(limit)
			.Select(kvp => kvp.Key)
			.ToList();
	}

	/// <summary>Formats a UTC timestamp using the canonical "o" round-trip format for log lines.</summary>
	public static string FormatUtc(DateTime utc) =>
		utc.ToUniversalTime().ToString("o", CultureInfo.InvariantCulture);

	/// <summary>Computes a deterministic checksum for the projected row, useful for change detection.</summary>
	internal static string ComputeFingerprint(AttackStat stat)
	{
		ArgumentNullException.ThrowIfNull(stat);

		StringBuilder sb = new(256);
		sb.Append(stat.Ip).Append('|')
			.Append(stat.TotalAttempts).Append('|')
			.Append(stat.Successful).Append('|')
			.Append(stat.Failed).Append('|')
			.Append(FormatUtc(stat.FirstSeenUtc)).Append('|')
			.Append(FormatUtc(stat.LastSeenUtc)).Append('|')
			.Append(stat.DurationSeconds).Append('|')
			.Append(stat.Top10AttemptedLogins).Append('|')
			.Append(stat.LastLoginType?.ToString(CultureInfo.InvariantCulture) ?? "-").Append('|')
			.Append(stat.ThreatScore.ToString("R", CultureInfo.InvariantCulture)).Append('|')
			.Append(stat.IsBlocked ? '1' : '0');
		return sb.ToString();
	}
}
