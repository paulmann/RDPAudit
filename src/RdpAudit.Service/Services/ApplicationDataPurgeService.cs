// File:    src/RdpAudit.Service/Services/ApplicationDataPurgeService.cs
// Module:  RdpAudit.Service.Services
// Purpose: Implements the DEBUG-gated full application-data cleanup (Req C). Transactionally clears the
//          accumulated RdpAudit operational tables (raw events, auth-attempt / connection facts, active
//          blocks, blocklist / whitelist entries, alerts, sessions, addresses, correlations, attack
//          stats, abuse reports / report history) while deliberately PRESERVING schema, EF migrations
//          history, configuration props (DbProps) and the event-log read bookmarks — so the service
//          keeps running against the same database, never re-reads the entire Security log, and never
//          becomes unreachable. On SQLite the purge is followed by a WAL checkpoint (TRUNCATE) and a
//          VACUUM to actually reclaim the freed pages. Every step is counted and recorded in the result
//          DebugLog; the destructive trigger is the typed confirmation phrase enforced on the client and
//          re-validated in the dispatcher before this service is ever called.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Globalization;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using RdpAudit.Core.Data;
using RdpAudit.Core.Ipc.Contracts;

namespace RdpAudit.Service.Services;

/// <summary>Transactionally clears accumulated RdpAudit operational data while preserving schema,
/// migrations, configuration and event-log bookmarks, then reclaims SQLite space via WAL checkpoint
/// and VACUUM.</summary>
public sealed class ApplicationDataPurgeService
{
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

	/// <summary>Clears every accumulated operational table inside a single transaction, recording the row
	/// count cleared per table, then (on SQLite) checkpoints the WAL and VACUUMs to reclaim space. DbProps
	/// (schema/config), the EF migrations history and event-log Bookmarks are intentionally never touched
	/// so the service stays healthy and reachable.</summary>
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

		// Reclaim space on SQLite. WAL checkpoint and VACUUM cannot run inside a transaction, so they run
		// after the commit. Failures here are non-fatal: the data is already gone.
		if (db.Database.IsSqlite())
		{
			try
			{
				await db.Database.ExecuteSqlRawAsync("PRAGMA wal_checkpoint(TRUNCATE);", ct).ConfigureAwait(false);
				result.WalCheckpointed = true;
				Trace("WAL checkpoint (TRUNCATE) completed.");
			}
			catch (OperationCanceledException)
			{
				throw;
			}
			catch (Exception ex)
			{
				result.Errors++;
				Trace("WAL checkpoint failed: " + ex.GetType().Name + ": " + ex.Message);
				_logger.LogWarning(ex, "WAL checkpoint after purge failed");
			}

			try
			{
				await db.Database.ExecuteSqlRawAsync("VACUUM;", ct).ConfigureAwait(false);
				result.DatabaseVacuumed = true;
				Trace("VACUUM completed.");
			}
			catch (OperationCanceledException)
			{
				throw;
			}
			catch (Exception ex)
			{
				result.Errors++;
				Trace("VACUUM failed: " + ex.GetType().Name + ": " + ex.Message);
				_logger.LogWarning(ex, "VACUUM after purge failed");
			}
		}
		else
		{
			Trace("Non-SQLite provider; skipped WAL checkpoint / VACUUM.");
		}

		int totalRows = result.TablesCleared.Sum(t => t.RowsCleared);
		result.Status = result.Errors > 0 ? IpcResultStatus.Unavailable : IpcResultStatus.Success;
		result.Message = string.Format(CultureInfo.InvariantCulture,
			"Cleared {0} row(s) across {1} table(s); WAL checkpointed: {2}; vacuumed: {3}. Errors: {4}.",
			totalRows, result.TablesCleared.Count, result.WalCheckpointed, result.DatabaseVacuumed, result.Errors);
		Trace("Result: " + result.Message);
		result.DebugLog = log.ToString();
		_logger.LogInformation(
			"Application data purge completed: rows={Rows} tables={Tables} wal={Wal} vacuum={Vac} errors={Err}",
			totalRows, result.TablesCleared.Count, result.WalCheckpointed, result.DatabaseVacuumed, result.Errors);
		return result;
	}
}
