/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : RetentionWorker.cs
// Project: RdpAudit.Service (RdpAudit.Service.Workers)
// Purpose: Incremental, cancellable, I/O-throttled retention pruner. Prunes per-event-id
//          retention windows honouring 0 = forever. Counter-preserving: never regresses
//          IpEventSummary.TotalEventCount or its first/last seen values.
// Depends: AuditDbContext, RetentionPolicyResolver, IShardMaintenance, ILogger
// Extends: When a new retained table is added (e.g. IncidentReplayCache), add a corresponding
//          PruneStep here rather than a new bulk DELETE elsewhere.

using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using RdpAudit.Core.Config;
using RdpAudit.Core.Data;

namespace RdpAudit.Service.Workers;

/// <summary>Incremental retention pruner. Wakes up every <c>TickInterval</c>, deletes at most
/// <see cref="StorageOptions.MaintenanceBatchSize"/> rows per pass per table, then yields back
/// to the ingestion path.</summary>
public sealed class RetentionWorker : BackgroundService
{
	// ── Fields & DI ──────────────────────────────────────────────────────────────

	private static readonly TimeSpan TickInterval = TimeSpan.FromMinutes(1);

	private readonly IDbContextFactory<AuditDbContext> _factory;
	private readonly IOptionsMonitor<RdpAuditOptions> _options;
	private readonly ILogger<RetentionWorker> _logger;

	// ── Construction ─────────────────────────────────────────────────────────────

	public RetentionWorker(
		IDbContextFactory<AuditDbContext> factory,
		IOptionsMonitor<RdpAuditOptions> options,
		ILogger<RetentionWorker> logger)
	{
		ArgumentNullException.ThrowIfNull(factory);
		ArgumentNullException.ThrowIfNull(options);
		ArgumentNullException.ThrowIfNull(logger);

		_factory = factory;
		_options = options;
		_logger = logger;
	}

	// ── Public API ───────────────────────────────────────────────────────────────

	/// <inheritdoc />
	protected override async Task ExecuteAsync(CancellationToken stoppingToken)
	{
		_logger.LogInformation("{Worker} starting", nameof(RetentionWorker));

		while (!stoppingToken.IsCancellationRequested)
		{
			try
			{
				await RunOnceAsync(stoppingToken).ConfigureAwait(false);
			}
			catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
			{
				break;
			}
			catch (Exception ex)
			{
				_logger.LogError(ex, "Retention pass failed; will retry after {Interval}", TickInterval);
			}

			try
			{
				await Task.Delay(TickInterval, stoppingToken).ConfigureAwait(false);
			}
			catch (OperationCanceledException)
			{
				break;
			}
		}
	}

	// ── Core Logic ───────────────────────────────────────────────────────────────

	private async Task RunOnceAsync(CancellationToken ct)
	{
		RdpAuditOptions options = _options.CurrentValue;
		int batchSize = Math.Max(1_000, options.Storage.MaintenanceBatchSize);
		int globalDefaultDays = Math.Max(1, options.Storage.EventRetentionDays);

		await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);
		SqliteConnection connection = (SqliteConnection)db.Database.GetDbConnection();
		if (connection.State != System.Data.ConnectionState.Open)
		{
			await connection.OpenAsync(ct).ConfigureAwait(false);
		}

		// Load per-event overrides once per pass (small table).
		Dictionary<int, int> perEventDays = await LoadOverridesAsync(connection, ct).ConfigureAwait(false);

		long nowTicks = DateTime.UtcNow.Ticks;
		long totalPruned = 0;

		totalPruned += await PruneRawEventsAsync(connection, perEventDays, globalDefaultDays, nowTicks, batchSize, ct)
			.ConfigureAwait(false);

		totalPruned += await PruneFactsAsync(connection, options, nowTicks, batchSize, ct).ConfigureAwait(false);

		if (totalPruned > 0)
		{
			_logger.LogInformation("Retention pass pruned {Rows} rows", totalPruned);
		}

		// WAL hygiene: hint an incremental checkpoint rather than a full VACUUM.
		await ExecuteNonQueryAsync(connection, "PRAGMA wal_checkpoint(PASSIVE);", ct).ConfigureAwait(false);
	}

	private static async Task<Dictionary<int, int>> LoadOverridesAsync(SqliteConnection connection, CancellationToken ct)
	{
		Dictionary<int, int> map = new();
		await using SqliteCommand cmd = connection.CreateCommand();
		cmd.CommandText = "SELECT EventId, RetentionDays FROM EventRetention;";
		await using SqliteDataReader reader = await cmd.ExecuteReaderAsync(ct).ConfigureAwait(false);
		while (await reader.ReadAsync(ct).ConfigureAwait(false))
		{
			map[reader.GetInt32(0)] = reader.GetInt32(1);
		}

		return map;
	}

	private async Task<long> PruneRawEventsAsync(
		SqliteConnection connection,
		Dictionary<int, int> perEventDays,
		int globalDefaultDays,
		long nowTicks,
		int batchSize,
		CancellationToken ct)
	{
		long totalPruned = 0;

		// Prune per-event id first (respect 0 = forever), then everything else against the
		// global default.
		foreach (KeyValuePair<int, int> kv in perEventDays)
		{
			if (kv.Value <= 0)
			{
				continue;
			}

			long cutoff = nowTicks - TimeSpan.FromDays(kv.Value).Ticks;
			totalPruned += await PruneRawEventsBatchAsync(
				connection,
				$"EventId = {kv.Key} AND TimeUtc < @cutoff",
				cutoff,
				batchSize,
				ct).ConfigureAwait(false);
		}

		// Global default sweep: skip event-ids that have an explicit override.
		long globalCutoff = nowTicks - TimeSpan.FromDays(globalDefaultDays).Ticks;
		if (perEventDays.Count == 0)
		{
			totalPruned += await PruneRawEventsBatchAsync(
				connection,
				"TimeUtc < @cutoff",
				globalCutoff,
				batchSize,
				ct).ConfigureAwait(false);
		}
		else
		{
			string inList = string.Join(",", perEventDays.Keys);
			totalPruned += await PruneRawEventsBatchAsync(
				connection,
				$"TimeUtc < @cutoff AND EventId NOT IN ({inList})",
				globalCutoff,
				batchSize,
				ct).ConfigureAwait(false);
		}

		return totalPruned;
	}

	private static async Task<long> PruneRawEventsBatchAsync(
		SqliteConnection connection,
		string whereClause,
		long cutoffTicks,
		int batchSize,
		CancellationToken ct)
	{
		string sql = $@"
DELETE FROM RawEvents
WHERE Id IN (
	SELECT Id FROM RawEvents WHERE {whereClause}
	ORDER BY TimeUtc ASC
	LIMIT $limit
);";

		await using SqliteCommand cmd = connection.CreateCommand();
		cmd.CommandText = sql;

		SqliteParameter pCutoff = cmd.CreateParameter();
		pCutoff.ParameterName = "@cutoff";
		pCutoff.Value = cutoffTicks;
		cmd.Parameters.Add(pCutoff);

		SqliteParameter pLimit = cmd.CreateParameter();
		pLimit.ParameterName = "$limit";
		pLimit.Value = batchSize;
		cmd.Parameters.Add(pLimit);

		return await cmd.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
	}

	private static async Task<long> PruneFactsAsync(
		SqliteConnection connection,
		RdpAuditOptions options,
		long nowTicks,
		int batchSize,
		CancellationToken ct)
	{
		long pruned = 0;
		int sessionDays = Math.Max(7, options.Storage.SessionIpCorrelationRetentionDays);
		int connDays = Math.Max(30, options.Storage.RdpConnectionFactRetentionDays);
		int attackDays = Math.Max(14, options.Storage.AttackStatRetentionDays);

		pruned += await PruneOneAsync(connection,
			"DELETE FROM SessionIpCorrelations WHERE LastSeenUtc < $cutoff LIMIT $limit;",
			nowTicks - TimeSpan.FromDays(sessionDays).Ticks,
			batchSize,
			ct).ConfigureAwait(false);

		pruned += await PruneOneAsync(connection,
			"DELETE FROM RdpConnectionFacts WHERE LastSeenUtc < $cutoff LIMIT $limit;",
			nowTicks - TimeSpan.FromDays(connDays).Ticks,
			batchSize,
			ct).ConfigureAwait(false);

		pruned += await PruneOneAsync(connection,
			"DELETE FROM AttackStats WHERE LastSeenUtc < $cutoff LIMIT $limit;",
			nowTicks - TimeSpan.FromDays(attackDays).Ticks,
			batchSize,
			ct).ConfigureAwait(false);

		return pruned;
	}

	private static async Task<long> PruneOneAsync(
		SqliteConnection connection,
		string sql,
		long cutoffTicks,
		int batchSize,
		CancellationToken ct)
	{
		await using SqliteCommand cmd = connection.CreateCommand();
		cmd.CommandText = sql;

		SqliteParameter pCutoff = cmd.CreateParameter();
		pCutoff.ParameterName = "$cutoff";
		pCutoff.Value = cutoffTicks;
		cmd.Parameters.Add(pCutoff);

		SqliteParameter pLimit = cmd.CreateParameter();
		pLimit.ParameterName = "$limit";
		pLimit.Value = batchSize;
		cmd.Parameters.Add(pLimit);

		return await cmd.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
	}

	private static async Task ExecuteNonQueryAsync(SqliteConnection connection, string sql, CancellationToken ct)
	{
		await using SqliteCommand cmd = connection.CreateCommand();
		cmd.CommandText = sql;
		await cmd.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
	}
}
