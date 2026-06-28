// File:    src/RdpAudit.Service/Processors/SessionIpCorrelationUpserter.cs
// Module:  RdpAudit.Service.Processors
// Purpose: Batched merge layer that turns a set of direct-IP RawEvent rows into idempotent
//          upserts against the SessionIpCorrelations table. One logical upsert per unique
//          correlation key per batch; existing rows are refreshed in-place (LastSeenUtc /
//          ObservedEventIds) without producing duplicates. Hostnames never reach the table:
//          the caller is responsible for passing only validated IPs (PerEventIpResolver does
//          this on the hot path).
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Globalization;
using System.Net;
using Microsoft.EntityFrameworkCore;
using RdpAudit.Core.Data;
using RdpAudit.Core.Models;

namespace RdpAudit.Service.Processors;

/// <summary>Batched merge layer for <see cref="SessionIpCorrelation"/> rows.</summary>
public sealed class SessionIpCorrelationUpserter
{
	/// <summary>Hard cap on the number of comma-separated event ids retained in
	/// <see cref="SessionIpCorrelation.ObservedEventIds"/>. Older ids fall off the front when the
	/// column would otherwise exceed its 128-char budget.</summary>
	internal const int MaxObservedEventIds = 16;

	/// <summary>Maximum width of <see cref="SessionIpCorrelation.ObservedEventIds"/> on disk.
	/// Matches the EF column configuration.</summary>
	internal const int ObservedEventIdsMaxLength = 128;

	/// <summary>
	/// Apply a batch of correlation candidates to <paramref name="db"/>. Reads only the matching
	/// rows (single round-trip), then either updates them in place or queues a new entity for the
	/// batch's <c>SaveChangesAsync</c>. Caller must commit the surrounding transaction.
	/// </summary>
	public async Task ApplyAsync(
		AuditDbContext db,
		IReadOnlyCollection<SessionIpCorrelationCandidate> candidates,
		CancellationToken ct)
	{
		if (candidates.Count == 0)
		{
			return;
		}

		// 1) Deduplicate input by the strongest available key — at most one logical upsert per key
		//    per batch. The "winner" for each key is the most recent observation in the batch.
		Dictionary<string, SessionIpCorrelationCandidate> deduped = new(StringComparer.Ordinal);
		foreach (SessionIpCorrelationCandidate c in candidates)
		{
			if (!IsValidIp(c.Ip))
			{
				continue;
			}

			string? key = BuildKey(c);
			if (key is null)
			{
				continue;
			}

			if (deduped.TryGetValue(key, out SessionIpCorrelationCandidate existing))
			{
				if (c.ObservedUtc >= existing.ObservedUtc)
				{
					deduped[key] = c;
				}
			}
			else
			{
				deduped[key] = c;
			}
		}

		if (deduped.Count == 0)
		{
			return;
		}

		// 2) Fetch the union of candidate matches with a single query. Reading by the dominant keys
		//    (LogonId OR (WtsSessionId AND UserName)) keeps the query selective on the indexed
		//    columns; the in-memory matcher then picks the right row per candidate.
		HashSet<string> logonIds = new(StringComparer.OrdinalIgnoreCase);
		HashSet<(int Wts, string User)> wtsUserPairs = new();
		HashSet<string> userOnlyNames = new(StringComparer.OrdinalIgnoreCase);
		foreach (SessionIpCorrelationCandidate c in deduped.Values)
		{
			if (!string.IsNullOrWhiteSpace(c.LogonId))
			{
				logonIds.Add(NormalizeLogonId(c.LogonId!));
			}
			else if (c.WtsSessionId is int wts && !string.IsNullOrWhiteSpace(c.UserName))
			{
				wtsUserPairs.Add((wts, c.UserName!.Trim()));
			}
			else if (!string.IsNullOrWhiteSpace(c.UserName))
			{
				userOnlyNames.Add(c.UserName!.Trim());
			}
		}

		List<SessionIpCorrelation> matches = new();
		if (logonIds.Count > 0)
		{
			List<SessionIpCorrelation> rows = await db.SessionIpCorrelations
				.Where(r => r.LogonId != null && logonIds.Contains(r.LogonId))
				.ToListAsync(ct).ConfigureAwait(false);
			matches.AddRange(rows);
		}

		if (wtsUserPairs.Count > 0)
		{
			HashSet<int> wtsIds = new();
			HashSet<string> usernames = new(StringComparer.OrdinalIgnoreCase);
			foreach ((int w, string u) in wtsUserPairs)
			{
				wtsIds.Add(w);
				usernames.Add(u);
			}

			List<SessionIpCorrelation> rows = await db.SessionIpCorrelations
				.Where(r => r.WtsSessionId != null
					&& wtsIds.Contains(r.WtsSessionId.Value)
					&& r.UserName != null
					&& usernames.Contains(r.UserName))
				.ToListAsync(ct).ConfigureAwait(false);
			matches.AddRange(rows);
		}

		if (userOnlyNames.Count > 0)
		{
			List<SessionIpCorrelation> rows = await db.SessionIpCorrelations
				.Where(r => r.LogonId == null
					&& r.WtsSessionId == null
					&& r.UserName != null
					&& userOnlyNames.Contains(r.UserName))
				.ToListAsync(ct).ConfigureAwait(false);
			matches.AddRange(rows);
		}

		Dictionary<string, SessionIpCorrelation> matchByKey = new(StringComparer.Ordinal);
		foreach (SessionIpCorrelation row in matches)
		{
			string? key = BuildKey(new SessionIpCorrelationCandidate(
				row.LogonId,
				row.WtsSessionId,
				row.UserName,
				row.Domain,
				row.Ip,
				row.LastSeenUtc,
				EventId: 0,
				IsDirectObservation: row.IsDirectObservation));
			if (key is not null && !matchByKey.ContainsKey(key))
			{
				matchByKey[key] = row;
			}
		}

		// 3) Merge candidates into rows. New rows get queued via Add(); existing rows have their
		//    LastSeenUtc / IP / domain / observed-event-ids updated. We deliberately do NOT call
		//    SaveChangesAsync here — the surrounding batch transaction is responsible for that.
		foreach ((string key, SessionIpCorrelationCandidate c) in deduped)
		{
			if (matchByKey.TryGetValue(key, out SessionIpCorrelation? existing))
			{
				if (c.ObservedUtc > existing.LastSeenUtc)
				{
					existing.LastSeenUtc = c.ObservedUtc;
				}

				existing.Ip = c.Ip;
				if (!string.IsNullOrWhiteSpace(c.Domain) && string.IsNullOrWhiteSpace(existing.Domain))
				{
					existing.Domain = c.Domain;
				}

				existing.ObservedEventIds = AppendEventId(existing.ObservedEventIds, c.EventId);
				if (c.IsDirectObservation)
				{
					existing.IsDirectObservation = true;
				}
			}
			else
			{
				SessionIpCorrelation row = new()
				{
					LogonId = string.IsNullOrWhiteSpace(c.LogonId) ? null : NormalizeLogonId(c.LogonId!),
					WtsSessionId = c.WtsSessionId,
					UserName = string.IsNullOrWhiteSpace(c.UserName) ? null : c.UserName!.Trim(),
					Domain = string.IsNullOrWhiteSpace(c.Domain) ? null : c.Domain!.Trim(),
					Ip = c.Ip,
					FirstSeenUtc = c.ObservedUtc,
					LastSeenUtc = c.ObservedUtc,
					ObservedEventIds = AppendEventId(null, c.EventId),
					IsDirectObservation = c.IsDirectObservation,
				};
				db.SessionIpCorrelations.Add(row);
				matchByKey[key] = row;
			}
		}
	}

	internal static string? BuildKey(SessionIpCorrelationCandidate c)
	{
		if (!string.IsNullOrWhiteSpace(c.LogonId))
		{
			return "L:" + NormalizeLogonId(c.LogonId!);
		}

		if (c.WtsSessionId is int sid && !string.IsNullOrWhiteSpace(c.UserName))
		{
			return string.Create(
				CultureInfo.InvariantCulture,
				$"S:{sid}|{c.UserName!.Trim()}");
		}

		if (!string.IsNullOrWhiteSpace(c.UserName))
		{
			return "U:" + c.UserName!.Trim();
		}

		return null;
	}

	internal static string NormalizeLogonId(string logonId)
	{
		string trimmed = logonId.Trim();
		return trimmed.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
			? trimmed.ToLowerInvariant()
			: trimmed;
	}

	internal static bool IsValidIp(string? candidate)
	{
		if (string.IsNullOrWhiteSpace(candidate))
		{
			return false;
		}

		return IPAddress.TryParse(candidate, out _);
	}

	internal static string AppendEventId(string? current, int eventId)
	{
		if (eventId <= 0)
		{
			return current ?? string.Empty;
		}

		string token = eventId.ToString(CultureInfo.InvariantCulture);
		if (string.IsNullOrEmpty(current))
		{
			return token;
		}

		// Avoid duplicates; preserve insertion order. Comma-separated.
		string[] parts = current.Split(',', StringSplitOptions.RemoveEmptyEntries);
		List<string> kept = new(parts.Length + 1);
		foreach (string part in parts)
		{
			if (!string.Equals(part, token, StringComparison.Ordinal))
			{
				kept.Add(part);
			}
		}

		kept.Add(token);
		while (kept.Count > MaxObservedEventIds)
		{
			kept.RemoveAt(0);
		}

		string joined = string.Join(',', kept);
		while (joined.Length > ObservedEventIdsMaxLength && kept.Count > 1)
		{
			kept.RemoveAt(0);
			joined = string.Join(',', kept);
		}

		return joined;
	}
}

/// <summary>
/// Immutable description of one direct-IP observation produced by <c>EventNormalizer</c>. Carries
/// only the fields needed to key and stamp a correlation row.
/// </summary>
public readonly record struct SessionIpCorrelationCandidate(
	string? LogonId,
	int? WtsSessionId,
	string? UserName,
	string? Domain,
	string Ip,
	DateTime ObservedUtc,
	int EventId,
	bool IsDirectObservation);
