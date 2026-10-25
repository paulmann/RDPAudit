/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// File   : RawEventDecimationEngine.cs
// Project: RdpAudit.Core (RdpAudit.Core.Storage)
// Purpose: Frequency-oriented decimation of raw event telemetry. The retention worker runs this
//          after ordinary retention pruning; it shrinks monotonically high-frequency bursts of one
//          event id coming from one source IP by deleting only the middle of each burst, so the
//          head and tail rows always survive for forensics.
// Depends: AuditDbContext, DecimationOptions, Microsoft.Data.Sqlite, Microsoft.EntityFrameworkCore
// Extends: Add per-IP exclusion rules (whitelist) here when policy needs finer control.
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using RdpAudit.Core.Config;
using RdpAudit.Core.Data;
using System.Data;
namespace RdpAudit.Core.Storage;
/// <summary>
/// Pure SQL decimation engine for the <c>RawEvents</c> table. The engine works on the SAME
/// connection the open <see cref="AuditDbContext"/> uses, so its behaviour is deterministic and
/// testable on a shared in-memory SQLite database without a filesystem.
///
/// <para>
/// Contract: only rows inside the decimation window are ever touched. The window is
/// <c>[windowStartUtc, nowUtc - MinAgeDays)</c> - windowStartUtc is the ordinary retention cutoff
/// (the caller prunes older rows first, so passing the cutoff here is a defensive bound), and rows
/// newer than <c>MinAgeDays</c> are never candidates because investigators still need them verbatim.
/// Rows without a source IP are never candidates. For each event id whose eligible row count in the
/// window reaches <c>CandidateMinRows</c>, the engine groups rows per source IP into bursts (a
/// burst ends when the gap to the next row exceeds <c>BurstGapSeconds</c>) and deletes only rows
/// that fall outside both the first <c>HeadKeepPerBurst</c> and the last <c>TailKeepPerBurst</c>
/// rows of their burst. At most <c>MaxCandidateEventIds</c> event ids are processed per call; a
/// single call fully decimates the selected candidates. <c>BatchSize</c> bounds the size of each
/// individual DELETE statement so the SQLite writer lock stays short - the middle-row set is
/// computed exactly once against the original burst boundaries, then deleted in chunks without
/// re-ranking the survivors. This guarantees convergence: after the call, every burst is at, or
/// below, HeadKeep + TailKeep rows, and a repeated call deletes nothing for that event id.
/// </para>
///
/// <para>
/// Per-burst ranking is implemented in SQL with LAG + windowed SUM + ROW_NUMBER over the stored
/// ISO-8601 <c>TimeUtc</c> text (which sorts chronologically), and gaps are measured with
/// <c>julianday</c>, so the engine requires the standard SQLite build shipped with
/// Microsoft.Data.Sqlite (math functions included).
/// </para>
/// </summary>
public static class RawEventDecimationEngine
{
	// ── Public API ───────────────────────────────────────────────────────────────
	/// <summary>Runs one bounded decimation pass and returns the number of RawEvents rows deleted.</summary>
	/// <param name="db">Open <see cref="AuditDbContext"/> whose backing SQLite connection is used.</param>
	/// <param name="options">Decimation policy; consumed through the Resolve* clamps. Disabled => no-op.</param>
	/// <param name="windowStartUtc">Oldest inclusive timestamp of the decimation window (the ordinary retention cutoff).</param>
	/// <param name="nowUtc">Current UTC wall clock; the window's upper bound is nowUtc minus MinAgeDays.</param>
	/// <param name="cancellationToken">Cancellation token for every await.</param>
	public static async Task<long> RunAsync(
		AuditDbContext db,
		DecimationOptions options,
		DateTime windowStartUtc,
		DateTime nowUtc,
		CancellationToken cancellationToken)
	{
		ArgumentNullException.ThrowIfNull(db);
		ArgumentNullException.ThrowIfNull(options);
		if (!options.Enabled)
		{
			return 0;
		}
		int minAgeDays = options.ResolveMinAgeDays();
		int burstGapSeconds = options.ResolveBurstGapSeconds();
		int candidateMinRows = options.ResolveCandidateMinRows();
		int headKeep = options.ResolveHeadKeepPerBurst();
		int tailKeep = options.ResolveTailKeepPerBurst();
		int maxCandidates = options.ResolveMaxCandidateEventIds();
		int batchSize = options.ResolveBatchSize();
		DateTime minAgeCutoffUtc = nowUtc.AddDays(-minAgeDays);
		List<int> candidates = await GetCandidateEventIdsAsync(
			db,
			windowStartUtc,
			minAgeCutoffUtc,
			candidateMinRows,
			maxCandidates,
			cancellationToken).ConfigureAwait(false);
		if (candidates.Count == 0)
		{
			return 0;
		}
		bool openedHere = false;
		if (db.Database.GetDbConnection().State != ConnectionState.Open)
		{
			await db.Database.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
			openedHere = true;
		}
		try
		{
			SqliteConnection connection = (SqliteConnection)db.Database.GetDbConnection();
			long totalDeleted = 0;
			foreach (int eventId in candidates)
			{
				cancellationToken.ThrowIfCancellationRequested();
				long deleted = await DeleteMiddleOfBurstsAsync(
					db,
					connection,
					eventId,
					burstGapSeconds,
					headKeep,
					tailKeep,
					batchSize,
					windowStartUtc,
					minAgeCutoffUtc,
					cancellationToken).ConfigureAwait(false);
				totalDeleted += deleted;
			}
			return totalDeleted;
		}
		finally
		{
			if (openedHere)
			{
				await db.Database.CloseConnectionAsync().ConfigureAwait(false);
			}
		}
	}
	// ── Candidate selection ─────────────────────────────────────────────────────
	private static async Task<List<int>> GetCandidateEventIdsAsync(
		AuditDbContext db,
		DateTime windowStartUtc,
		DateTime minAgeCutoffUtc,
		int candidateMinRows,
		int maxCandidates,
		CancellationToken cancellationToken)
	{
		return await db.RawEvents
			.Where(item =>
				item.SourceIp != null &&
				item.SourceIp != string.Empty &&
				item.TimeUtc >= windowStartUtc &&
				item.TimeUtc < minAgeCutoffUtc)
			.GroupBy(item => item.EventId)
			.Where(group => group.Count() >= candidateMinRows)
			.OrderByDescending(group => group.Count())
			.ThenBy(group => group.Key)
			.Take(maxCandidates)
			.Select(group => group.Key)
			.ToListAsync(cancellationToken)
			.ConfigureAwait(false);
	}
	// ── Middle-row deletion ──────────────────────────────────────────────────────
	private static async Task<long> DeleteMiddleOfBurstsAsync(
		AuditDbContext db,
		SqliteConnection connection,
		int eventId,
		int burstGapSeconds,
		int headKeep,
		int tailKeep,
		int batchSize,
		DateTime windowStartUtc,
		DateTime minAgeCutoffUtc,
		CancellationToken cancellationToken)
	{
		List<long> middleIds = await FindMiddleOfBurstIdsAsync(
			connection,
			eventId,
			burstGapSeconds,
			headKeep,
			tailKeep,
			windowStartUtc,
			minAgeCutoffUtc,
			cancellationToken).ConfigureAwait(false);
		if (middleIds.Count == 0)
		{
			return 0;
		}
		long totalDeleted = 0;
		for (int offset = 0; offset < middleIds.Count; offset += batchSize)
		{
			cancellationToken.ThrowIfCancellationRequested();
			int count = Math.Min(batchSize, middleIds.Count - offset);
			List<long> chunk = middleIds.GetRange(offset, count);
			totalDeleted += await db.RawEvents
				.Where(item => chunk.Contains(item.Id))
				.ExecuteDeleteAsync(cancellationToken)
				.ConfigureAwait(false);
		}
		return totalDeleted;
	}
	private static async Task<List<long>> FindMiddleOfBurstIdsAsync(
		SqliteConnection connection,
		int eventId,
		int burstGapSeconds,
		int headKeep,
		int tailKeep,
		DateTime windowStartUtc,
		DateTime minAgeCutoffUtc,
		CancellationToken cancellationToken)
	{
		using SqliteCommand command = connection.CreateCommand();
		command.CommandText = """
			WITH eligible AS (
				SELECT re."Id",
					   re."SourceIp",
					   re."TimeUtc",
					   CASE
						   WHEN (julianday(re."TimeUtc") - julianday(LAG(re."TimeUtc") OVER (
							   PARTITION BY re."SourceIp"
							   ORDER BY re."TimeUtc", re."Id"
					   ))) * 86400.0 > $burstGapSeconds THEN 1
						   ELSE 0
				   END AS "GapStart"
				FROM "RawEvents" AS re
				WHERE re."EventId" = $eventId
				  AND re."SourceIp" IS NOT NULL
				  AND TRIM(re."SourceIp") <> ''
				  AND re."TimeUtc" >= $windowStart
				  AND re."TimeUtc" < $minAgeCutoff
			),
			bursts AS (
				SELECT "Id", "SourceIp", "TimeUtc",
					   COALESCE(SUM("GapStart") OVER (
						   PARTITION BY "SourceIp"
						   ORDER BY "TimeUtc", "Id"
						   ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW
				   ), 0) AS "BurstIndex"
				FROM eligible
			),
			ranked AS (
				SELECT "Id",
					   ROW_NUMBER() OVER (
						   PARTITION BY "SourceIp", "BurstIndex"
						   ORDER BY "TimeUtc", "Id"
				   ) AS "HeadRank",
					   ROW_NUMBER() OVER (
						   PARTITION BY "SourceIp", "BurstIndex"
						   ORDER BY "TimeUtc" DESC, "Id" DESC
				   ) AS "TailRank"
				FROM bursts
			)
			SELECT "Id" FROM ranked
			WHERE "HeadRank" > $headKeep AND "TailRank" > $tailKeep
			ORDER BY "Id";
			""";
		command.Parameters.AddWithValue("$eventId", eventId);
		command.Parameters.AddWithValue("$burstGapSeconds", burstGapSeconds);
		command.Parameters.AddWithValue("$windowStart", windowStartUtc);
		command.Parameters.AddWithValue("$minAgeCutoff", minAgeCutoffUtc);
		command.Parameters.AddWithValue("$headKeep", headKeep);
		command.Parameters.AddWithValue("$tailKeep", tailKeep);
		List<long> ids = new();
		await using (SqliteDataReader reader =
			await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false))
		{
			while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
			{
				ids.Add(reader.GetInt64(0));
			}
		}
		return ids;
	}
}
