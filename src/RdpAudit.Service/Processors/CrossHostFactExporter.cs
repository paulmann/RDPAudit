/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// File   : CrossHostFactExporter.cs
// Project: RdpAudit.Service (RdpAudit.Service.Processors)
// Purpose: Agent-side half of the P4-18 pull transport. Exports bounded cross-host fact
//          projections from the LOCAL database for the GetCrossHostFacts IPC command:
//          AuthAttemptFact rows (4625 fails / 4624 successes, network logon types only)
//          plus privileged-logon RawEvent rows (4625→4624→4672 hop 3: Security 4672 with a
//          sensitive privilege and a network context). Every exported projection is a summary
//          carrying a stable SHA-256 DedupKey - never raw event XML - so the central service
//          can re-pull the same window without creating duplicate rows. Fail-closed by design:
//          anything malformed is silently skipped instead of being invented.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Globalization;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using RdpAudit.Core.Config;
using RdpAudit.Core.CrossHost;
using RdpAudit.Core.Data;
using RdpAudit.Core.Ipc.Contracts;
using RdpAudit.Core.Models;

namespace RdpAudit.Service.Processors;

/// <summary>Agent-side cross-host fact exporter (local half of GetCrossHostFacts).</summary>
public sealed class CrossHostFactExporter
{
	// Mirrors PrivilegedLoginRule.WatchedPrivileges: the sensitive privileges that qualify a
	// 4672 as lateral-movement evidence.
	private static readonly string[] SensitivePrivileges =
	{
		"SeDebugPrivilege",
		"SeTcbPrivilege",
		"SeImpersonatePrivilege",
		"SeBackupPrivilege",
		"SeRestorePrivilege",
		"SeTakeOwnershipPrivilege",
	};

	private const string PrivilegeListTokenCamel = "\"privilegeList\"";
	private const string PrivilegeListTokenPascal = "\"PrivilegeList\"";

	private readonly ILogger<CrossHostFactExporter> _logger;
	private readonly TimeProvider _timeProvider;

	public CrossHostFactExporter(ILogger<CrossHostFactExporter>? logger = null, TimeProvider? timeProvider = null)
	{
		_logger = logger ?? NullLogger<CrossHostFactExporter>.Instance;
		_timeProvider = timeProvider ?? TimeProvider.System;
	}

	/// <summary>
	/// Exports a bounded, ascending batch of local fact projections for the supplied request.
	/// <paramref name="request.SinceUtc"/> is an exclusive watermark; the effective cap is
	/// min(request.MaxFacts, options.ResolveMaxFactsPerPoll()). Returns Success with no facts
	/// when the window is empty. Never throws for data-level problems.
	/// </summary>
	public async Task<CrossHostFactsDto> ExportAsync(
		AuditDbContext db,
		CrossHostFactsRequest request,
		CrossHostOptions options,
		CancellationToken ct)
	{
		DateTime? sinceUtc = NormalizeWatermark(request.SinceUtc);
		int cap = ResolveCap(request.MaxFacts, options);
		DateTime nowUtc = _timeProvider.GetUtcNow().UtcDateTime;

		List<CrossHostFactDto> facts = new();

		facts.AddRange(await ExportAuthFactsAsync(db, sinceUtc, nowUtc, ct).ConfigureAwait(false));
		facts.AddRange(await ExportPrivilegedFactsAsync(db, sinceUtc, nowUtc, ct).ConfigureAwait(false));

		// Stable order for watermarking: TimeUtc ascending, then stable DedupKey as tiebreaker.
		facts.Sort((a, b) =>
		{
			int timeCompare = a.TimeUtc.CompareTo(b.TimeUtc);
			return timeCompare != 0
				? timeCompare
				: string.CompareOrdinal(a.DedupKey ?? string.Empty, b.DedupKey ?? string.Empty);
		});

		int taken = Math.Min(facts.Count, cap);
		if (taken < facts.Count)
		{
			facts.RemoveRange(taken, facts.Count - taken);
		}

		DateTime? latest = facts.Count > 0 ? facts[facts.Count - 1].TimeUtc : null;
		return new CrossHostFactsDto
		{
			Status = IpcResultStatus.Success,
			QueriedUtc = nowUtc,
			RequestId = request.RequestId,
			LatestFactUtc = latest,
			Facts = facts,
			Message = string.Format(
				CultureInfo.InvariantCulture,
				"cross-host facts: exported={0} capped={1} since={2}",
				facts.Count,
				cap,
				sinceUtc?.ToString("o", CultureInfo.InvariantCulture) ?? "(none)"),
		};
	}

	// ── AuthAttemptFact half: 4625 failures + 4624 successes ─────────────────

	private async Task<List<CrossHostFactDto>> ExportAuthFactsAsync(
		AuditDbContext db,
		DateTime? sinceUtc,
		DateTime nowUtc,
		CancellationToken ct)
	{
		IQueryable<AuthAttemptFact> q = db.AuthAttemptFacts
			.AsNoTracking()
			.Where(f => f.EvidenceEventId == 4624 || f.EvidenceEventId == 4625);

		if (sinceUtc.HasValue)
		{
			DateTime since = sinceUtc.Value;
			q = q.Where(f => f.TimeUtc > since);
		}

		List<AuthAttemptFact> rows = await q
			.OrderBy(f => f.TimeUtc)
			.ThenBy(f => f.Id)
			.ToListAsync(ct)
			.ConfigureAwait(false);

		List<CrossHostFactDto> result = new();
		foreach (AuthAttemptFact fact in rows)
		{
			if (!TryProjectAuthFact(fact, out CrossHostFactDto? dto))
			{
				continue;
			}

			result.Add(dto);
		}

		return result;
	}

	private static bool TryProjectAuthFact(AuthAttemptFact fact, out CrossHostFactDto dto)
	{
		dto = null!;
		CrossHostFactKind kind;
		switch ((fact.EvidenceEventId, fact.Outcome))
		{
			case (4625, AuthAttemptOutcome.Failed):
			case (4625, AuthAttemptOutcome.Denied):
				kind = CrossHostFactKind.FailedLogon;
				break;
			case (4624, AuthAttemptOutcome.Succeeded):
				kind = CrossHostFactKind.SuccessfulLogon;
				break;
			default:
				return false;
		}

		// Network context gate: an explicit non-network logon type (5 Service, etc.) proves the
		// event is not lateral movement. Null stays eligible (older 4625 rows / stripped payloads).
		// The set lives in AttackStatsAggregator.IsRemoteCapableLogonType so this gate and the
		// attribution gate in AuthAttemptFactUpserter cannot drift apart.
		if (fact.LogonType is int logonType && !AttackStatsAggregator.IsRemoteCapableLogonType(logonType))
		{
			return false;
		}

		string normalized = AuthAttemptFactUpserter.NormalizeUserName(fact.TargetUser) ?? string.Empty;
		if (normalized.Length == 0)
		{
			return false;
		}

		DateTime timeUtc = DateTime.SpecifyKind(fact.TimeUtc, DateTimeKind.Utc);
		CrossHostFactProjection projection = new CrossHostFactProjection
		{
			HostName = ResolveLocalHostName(),
			TimeUtc = timeUtc,
			UserName = fact.TargetUser,
			NormalizedUserName = normalized,
			SourceIp = fact.SourceIp,
			LogonType = fact.LogonType,
			Kind = kind,
			EventId = fact.EvidenceEventId,
		};

		dto = Project(projection);
		return true;
	}

	// ── RawEvent half: 4672 privileged logons ─────────────────────────────────

	private async Task<List<CrossHostFactDto>> ExportPrivilegedFactsAsync(
		AuditDbContext db,
		DateTime? sinceUtc,
		DateTime nowUtc,
		CancellationToken ct)
	{
		DateTime maxAgeCutoff = nowUtc.AddHours(-CrossHostChainRule.DefaultMaxFactAgeHours);

		IQueryable<RawEvent> q = db.RawEvents
			.AsNoTracking()
			.Where(e => e.EventId == 4672)
			.Where(e => e.TimeUtc >= maxAgeCutoff);

		if (sinceUtc.HasValue)
		{
			DateTime since = sinceUtc.Value;
			q = q.Where(e => e.TimeUtc > since);
		}

		List<RawEvent> rows = await q
			.OrderBy(e => e.TimeUtc)
			.ThenBy(e => e.Id)
			.ToListAsync(ct)
			.ConfigureAwait(false);

		List<CrossHostFactDto> result = new();
		foreach (RawEvent evt in rows)
		{
			if (!TryProjectPrivileged(evt, out CrossHostFactDto? dto))
			{
				continue;
			}

			result.Add(dto);
		}

		return result;
	}

	private static bool TryProjectPrivileged(RawEvent evt, out CrossHostFactDto dto)
	{
		dto = null!;

		// Network context is authoritative: no source IP means no lateral-movement evidence
		// (matches PrivilegedLoginRule's storm guard).
		if (string.IsNullOrWhiteSpace(evt.SourceIp))
		{
			return false;
		}

		string normalized = AuthAttemptFactUpserter.NormalizeUserName(evt.UserName) ?? string.Empty;
		if (normalized.Length == 0)
		{
			return false;
		}

		// Windows 4672 has no LogonType of its own; an explicit non-network value disqualifies
		// the row, while null stays eligible (the 4624 correlation runs on the central side).
		if (evt.LogonType is int logonType && logonType is not (3 or 7 or 10))
		{
			return false;
		}

		if (!ContainsSensitivePrivilege(evt.Details))
		{
			return false;
		}

		CrossHostFactProjection projection = new CrossHostFactProjection
		{
			HostName = ResolveLocalHostName(),
			TimeUtc = DateTime.SpecifyKind(evt.TimeUtc, DateTimeKind.Utc),
			UserName = evt.UserName,
			NormalizedUserName = normalized,
			SourceIp = evt.SourceIp,
			LogonType = evt.LogonType,
			Kind = CrossHostFactKind.PrivilegedLogon,
			EventId = 4672,
		};

		dto = Project(projection);
		return true;
	}

	// ── Shared projection helpers ─────────────────────────────────────────────

	private static CrossHostFactDto Project(CrossHostFactProjection projection)
	{
		return new CrossHostFactDto
		{
			HostName = projection.HostName,
			TimeUtc = projection.TimeUtc,
			UserName = projection.UserName,
			NormalizedUserName = projection.NormalizedUserName,
			SourceIp = projection.SourceIp,
			LogonType = projection.LogonType,
			Kind = projection.Kind,
			EventId = projection.EventId,
			DedupKey = projection.BuildDedupKey(),
		};
	}

	private static DateTime? NormalizeWatermark(DateTime? sinceUtc)
		=> sinceUtc.HasValue && sinceUtc.Value.Kind == DateTimeKind.Unspecified
			? DateTime.SpecifyKind(sinceUtc.Value, DateTimeKind.Utc)
			: sinceUtc;

	private static int ResolveCap(int requested, CrossHostOptions options)
	{
		int configuredCap = options.ResolveMaxFactsPerPoll();
		if (requested <= 0)
		{
			return configuredCap;
		}

		return Math.Min(requested, configuredCap);
	}

	private static string ResolveLocalHostName()
	{
		try
		{
			return Environment.MachineName;
		}
		catch
		{
			return "localhost";
		}
	}

	private static bool ContainsSensitivePrivilege(string? details)
	{
		if (string.IsNullOrWhiteSpace(details))
		{
			return false;
		}

		ReadOnlySpan<char> json = details;
		if (!TryGetJsonStringValue(json, PrivilegeListTokenCamel, out ReadOnlySpan<char> privilegeList)
			&& !TryGetJsonStringValue(json, PrivilegeListTokenPascal, out privilegeList))
		{
			return false;
		}

		foreach (string privilege in SensitivePrivileges)
		{
			if (privilegeList.Contains(privilege, StringComparison.Ordinal))
			{
				return true;
			}
		}

		return false;
	}

	private static bool TryGetJsonStringValue(
		ReadOnlySpan<char> json,
		ReadOnlySpan<char> token,
		out ReadOnlySpan<char> value)
	{
		value = default;
		int index = json.IndexOf(token);
		if (index < 0)
		{
			return false;
		}

		int cursor = index + token.Length;
		while (cursor < json.Length && char.IsWhiteSpace(json[cursor]))
		{
			cursor++;
		}

		if (cursor >= json.Length || json[cursor] != ':')
		{
			return false;
		}

		cursor++;
		while (cursor < json.Length && char.IsWhiteSpace(json[cursor]))
		{
			cursor++;
		}

		if (cursor >= json.Length || json[cursor] != '"')
		{
			return false;
		}

		cursor++;
		int start = cursor;
		while (cursor < json.Length && json[cursor] != '"')
		{
			cursor++;
		}

		if (cursor >= json.Length)
		{
			return false;
		}

		value = json[start..cursor];
		return true;
	}
}
