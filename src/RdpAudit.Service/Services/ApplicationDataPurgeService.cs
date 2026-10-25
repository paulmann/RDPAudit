// File:    src/RdpAudit.Service/Services/ApplicationDataPurgeService.cs
// Module:  RdpAudit.Service.Services
// Purpose: Implements the DEBUG-gated full application-data cleanup (Req C). Transactionally clears the
//          accumulated RdpAudit operational tables (raw events, auth-attempt / connection facts, active
//          blocks, blocklist / whitelist entries, alerts, sessions, addresses, correlations, attack
//          stats, abuse reports / report history) while deliberately PRESERVING schema, EF migrations
//          history, configuration props (DbProps) and the event-log read bookmarks — so the service
//          keeps running against the same database, never re-reads the entire Security log, and never
//          becomes unreachable. On SQLite the purge is followed by a WAL checkpoint (TRUNCATE) and a
//          BOUNDED incremental vacuum: a full VACUUM is deliberately absent because it rewrites the
//          whole file and can hold the writer lock for minutes on a multi-gigabyte evidence store.
//          Every step is counted and recorded in the result DebugLog; the destructive trigger is the
//          typed confirmation phrase enforced on the client and re-validated in the dispatcher before
//          this service is ever called.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Globalization;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using RdpAudit.Core.Data;
using RdpAudit.Core.Ipc.Contracts;

namespace RdpAudit.Service.Services;

/// <summary>Transactionally clears accumulated RdpAudit operational data while preserving schema,
/// migrations, configuration and event-log bookmarks, then reclaims SQLite space with a WAL checkpoint
/// and a bounded incremental vacuum.
/// <para>
/// Space-reclamation policy (mirrors <c>docs/88-database-backup-and-restore.md</c>): the online path
/// never runs a full <c>VACUUM</c>. A full VACUUM rebuilds the entire database file inside a write
/// transaction, so on a multi-gigabyte evidence store it can hold the single writer for minutes and
/// stall ingestion — the exact freeze the no-freeze rule forbids. The online path therefore only
/// </para>
/// <list type="bullet">
/// <item><description>checkpoints the WAL with <c>TRUNCATE</c> (moves committed frames into the main
/// file and empties the <c>-wal</c> sidecar), and</description></item>
/// <item><description>releases up to a bounded number of freelist pages with
/// <c>PRAGMA incremental_vacuum(&lt;pages&gt;)</c>.</description></item>
/// </list>
/// <para>
/// The incremental vacuum only does anything when the store's auto-vacuum mode is
/// <c>INCREMENTAL</c>; on a store created without auto-vacuum it is a documented no-op and the freed
/// space stays inside the file until an offline compaction. Both facts are reported truthfully in
/// <see cref="AppDataPurgeResultDto.SpaceReclamation"/> instead of promising that the file shrank.
/// </para></summary>
public sealed class ApplicationDataPurgeService
{
	// ── Fields & DI ──────────────────────────────────────────────────────────────

	/// <summary>Free pages one bounded incremental vacuum may hand back to the filesystem after the
	/// purge. Deliberately identical to <c>DatabaseMaintenanceService.DefaultIncrementalVacuumPages</c>
	/// and to the daily maintenance worker's bound so the reclaim step can never hold the SQLite writer
	/// longer than a maintenance pass the operator already accepts.</summary>
	internal const int IncrementalVacuumPages = 5000;

	private readonly IDbContextFactory<AuditDbContext> _factory;
	private readonly ILogger<ApplicationDataPurgeService> _logger;
	private readonly TimeProvider _time;

	public ApplicationDataPurgeService(
		IDbContextFactory<AuditDbContext> factory,
		ILogger<ApplicationDataPurgeService> logger,
		TimeProvider? time = null)
	{
		ArgumentNullException.ThrowIfNull(factory);
		ArgumentNullException.ThrowIfNull(logger);
		_factory = factory;
		_logger = logger;
		_time = time ?? TimeProvider.System;
	}

	// ── Public API ───────────────────────────────────────────────────────────────

	/// <summary>Returns the exact SQL statements the online purge issues after its delete transaction
	/// commits, in order. Extracted so two properties are provable rather than merely intended:
	/// (1) the composition is deterministic and testable without a database, and (2) a full
	/// <c>VACUUM</c> is absent by construction — there is no code path in this service that can emit
	/// one. <paramref name="incrementalVacuumPages"/> is clamped to
	/// <see cref="IncrementalVacuumPages"/>, the same ceiling the maintenance surface uses.</summary>
	internal static IReadOnlyList<string> BuildSpaceReclamationStatements(int incrementalVacuumPages)
	{
		int pages = Math.Clamp(incrementalVacuumPages, 1, IncrementalVacuumPages);
		return
		[
			"PRAGMA wal_checkpoint(TRUNCATE);",
			string.Create(CultureInfo.InvariantCulture, $"PRAGMA incremental_vacuum({pages});"),
		];
	}

	/// <summary>Plain-language account of the space-reclamation outcome for the operator report. Every
	/// sentence is derived from an observed before/after reading — never from a PRAGMA that reports the
	/// connection's pending auto-vacuum setting — so the report cannot claim that the database file
	/// became smaller when only an offline compaction can achieve that.</summary>
	internal static string DescribeSpaceReclamation(
		bool walCheckpointed,
		bool incrementalVacuumed,
		int incrementalVacuumPages,
		long freeListPagesBefore,
		long freeListPagesAfter,
		long reclaimedFreePages)
	{
		string checkpoint = walCheckpointed
			? "WAL checkpoint (TRUNCATE) completed."
			: "WAL checkpoint (TRUNCATE) did not complete.";
		string vacuum;
		if (!incrementalVacuumed)
		{
			vacuum = "The bounded incremental vacuum did not complete.";
		}
		else if (reclaimedFreePages > 0)
		{
			vacuum = string.Create(
				CultureInfo.InvariantCulture,
				$"The bounded incremental vacuum returned {reclaimedFreePages} freelist page(s) to the filesystem within a budget of {incrementalVacuumPages} page(s).");
		}
		else if (freeListPagesBefore > 0)
		{
			vacuum = string.Create(
				CultureInfo.InvariantCulture,
				$"The bounded incremental vacuum released nothing although {freeListPagesBefore} freelist page(s) were available: this store's auto-vacuum mode is not INCREMENTAL, so the freed space stays allocated inside the file until an offline compaction.");
		}
		else
		{
			vacuum = "The bounded incremental vacuum had no freelist pages to release.";
		}

		string remaining = freeListPagesAfter < 0
			? "The freelist depth could not be read back."
			: string.Create(
				CultureInfo.InvariantCulture,
				$"{freeListPagesAfter} freelist page(s) remain inside the file.");

		return string.Join(
			" ",
			checkpoint,
			vacuum,
			remaining,
			"No full VACUUM is run on the live store; shrinking the file is an offline operation "
				+ "(Database tab -> Danger Zone -> 'Compact database (offline)').");
	}

	/// <summary>Clears every accumulated operational table inside a single transaction, recording the row
	/// count cleared per table, then (on SQLite) checkpoints the WAL and runs a bounded incremental
	/// vacuum to release already-freed pages. DbProps (schema/config), the EF migrations history and
	/// event-log Bookmarks are intentionally never touched so the service stays healthy and reachable.
	/// A full <c>VACUUM</c> is never issued here — see the class remarks for the lock-cost rationale.</summary>
	public async Task<AppDataPurgeResultDto> PurgeAllAsync(CancellationToken ct)
	{
		AppDataPurgeResultDto result = new();
		System.Text.StringBuilder log = new();
		void Trace(string line) => log.Append('[')
			.Append(_time.GetUtcNow().UtcDateTime.ToString("O", CultureInfo.InvariantCulture))
			.Append("] ").Append(line).Append('\n');

		Trace("PurgeAll starting.");

		await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);

		// Ordered so child / dependent tables are cleared before parents where relationships exist.
		// DbProps, Bookmarks and the EF migrations history are deliberately excluded to preserve schema,
		// configuration and event-log read positions.
		(string Name, Func<AuditDbContext, IQueryable<object>> Set)[] tables =
		{
			("RawEvents", c => c.RawEvents),
			("AuthAttemptFacts", c => c.AuthAttemptFacts),
			("RdpConnectionFacts", c => c.RdpConnectionFacts),
			("SessionIpCorrelations", c => c.SessionIpCorrelations),
			("Alerts", c => c.Alerts),
			("Sessions", c => c.Sessions),
			("ActiveBlocks", c => c.ActiveBlocks),
			("BlocklistEntries", c => c.BlocklistEntries),
			("WhitelistEntries", c => c.WhitelistEntries),
			("AbuseReports", c => c.AbuseReports),
			("AbuseIpDbReportHistory", c => c.AbuseIpDbReportHistory),
			("AttackStats", c => c.AttackStats),
			("Addresses", c => c.Addresses),
		};

		try
		{
			await using Microsoft.EntityFrameworkCore.Storage.IDbContextTransaction tx =
				await db.Database.BeginTransactionAsync(ct).ConfigureAwait(false);

			foreach ((string name, Func<AuditDbContext, IQueryable<object>> set) in tables)
			{
				ct.ThrowIfCancellationRequested();
				int rows = await set(db).ExecuteDeleteAsync(ct).ConfigureAwait(false);
				result.TablesCleared.Add(new PurgedTableDto { Table = name, RowsCleared = rows });
				Trace(string.Format(CultureInfo.InvariantCulture, "Cleared {0}: {1} row(s).", name, rows));
			}

			await tx.CommitAsync(ct).ConfigureAwait(false);
			Trace("Purge transaction committed.");
		}
		catch (OperationCanceledException)
		{
			throw;
		}
		catch (Exception ex)
		{
			_logger.LogError(ex, "Application data purge transaction failed");
			result.Errors++;
			result.Status = IpcResultStatus.Unavailable;
			result.Message = "Database error during application-data purge; the transaction was rolled back.";
			Trace("Purge transaction exception: " + ex.GetType().Name + ": " + ex.Message);
			result.DebugLog = log.ToString();
			return result;
		}

		// Reclaim space on SQLite. A WAL checkpoint and an incremental vacuum cannot run inside a
		// transaction, so they run after the commit. Failures here are non-fatal: the data is already
		// gone. The statement list is built by BuildSpaceReclamationStatements, which cannot emit a full
		// VACUUM - that is an offline-only operation (see the class remarks).
		if (db.Database.IsSqlite())
		{
			result.FreeListPagesBefore = await TryReadPragmaAsync(db, "PRAGMA freelist_count;", ct).ConfigureAwait(false);

			foreach (string statement in BuildSpaceReclamationStatements(IncrementalVacuumPages))
			{
				ct.ThrowIfCancellationRequested();
				try
				{
					await db.Database.ExecuteSqlRawAsync(statement, ct).ConfigureAwait(false);
					if (statement.Contains("wal_checkpoint", StringComparison.Ordinal))
					{
						result.WalCheckpointed = true;
						Trace("WAL checkpoint (TRUNCATE) completed.");
					}
					else
					{
						result.IncrementalVacuumed = true;
						result.IncrementalVacuumPages = IncrementalVacuumPages;
						Trace(string.Create(
							CultureInfo.InvariantCulture,
							$"Bounded incremental vacuum ({IncrementalVacuumPages} page(s)) completed."));
					}
				}
				catch (OperationCanceledException)
				{
					throw;
				}
				catch (Exception ex)
				{
					result.Errors++;
					Trace("Space-reclamation step failed (" + statement + "): "
						+ ex.GetType().Name + ": " + ex.Message);
					_logger.LogWarning(ex, "Space-reclamation step after purge failed: {Statement}", statement);
				}
			}

			result.FreeListPagesAfter = await TryReadPragmaAsync(db, "PRAGMA freelist_count;", ct).ConfigureAwait(false);
			result.ReclaimedFreePages =
				result.FreeListPagesBefore >= 0
				&& result.FreeListPagesAfter >= 0
				&& result.FreeListPagesAfter < result.FreeListPagesBefore
					? result.FreeListPagesBefore - result.FreeListPagesAfter
					: 0L;
			result.SpaceReclamation = DescribeSpaceReclamation(
				result.WalCheckpointed,
				result.IncrementalVacuumed,
				result.IncrementalVacuumPages,
				result.FreeListPagesBefore,
				result.FreeListPagesAfter,
				result.ReclaimedFreePages);
			Trace("Space reclamation: " + result.SpaceReclamation);
		}
		else
		{
			result.SpaceReclamation = "Non-SQLite provider; no WAL checkpoint / incremental vacuum was run.";
			Trace(result.SpaceReclamation);
		}

		int totalRows = result.TablesCleared.Sum(t => t.RowsCleared);
		result.Status = result.Errors > 0 ? IpcResultStatus.Unavailable : IpcResultStatus.Success;
		result.Message = string.Format(CultureInfo.InvariantCulture,
			"Cleared {0} row(s) across {1} table(s); WAL checkpointed: {2}; incremental vacuum: {3}; full VACUUM: {4}; errors: {5}.",
			totalRows, result.TablesCleared.Count, result.WalCheckpointed, result.IncrementalVacuumed,
			result.DatabaseVacuumed, result.Errors);
		Trace("Result: " + result.Message);
		result.DebugLog = log.ToString();
		_logger.LogInformation(
			"Application data purge completed: rows={Rows} tables={Tables} wal={Wal} incrementalVacuum={IVac} "
			+ "freeListPagesBefore={FreeBefore} freeListPagesAfter={FreeAfter} reclaimedPages={Reclaimed} errors={Err}",
			totalRows, result.TablesCleared.Count, result.WalCheckpointed, result.IncrementalVacuumed,
			result.FreeListPagesBefore, result.FreeListPagesAfter, result.ReclaimedFreePages, result.Errors);
		return result;
	}

	/// <summary>Reads a scalar PRAGMA that returns exactly one integer, returning -1 when the value
	/// cannot be read (a missing column, a provider without that pragma). Used only for the honest
	/// post-purge report, so a read failure must never fail the purge itself. The pragma text is a
	/// compile-time constant supplied by this class - no operator input reaches SQL.</summary>
	private static async Task<long> TryReadPragmaAsync(
		AuditDbContext db,
		string pragmaSql,
		CancellationToken ct)
	{
		try
		{
			await db.Database.OpenConnectionAsync(ct).ConfigureAwait(false);
			await using SqliteCommand command = ((SqliteConnection)db.Database.GetDbConnection()).CreateCommand();
#pragma warning disable CA2100 // Reviewed: the caller passes a constant pragma literal; no operator input reaches SQL.
			command.CommandText = pragmaSql;
#pragma warning restore CA2100
			object? value = await command.ExecuteScalarAsync(ct).ConfigureAwait(false);
			return value is null or DBNull
				? -1L
				: Convert.ToInt64(value, CultureInfo.InvariantCulture);
		}
		catch (OperationCanceledException)
		{
			throw;
		}
		catch (Exception)
		{
			return -1L;
		}
	}
}
