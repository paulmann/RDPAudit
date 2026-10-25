// File:    src/RdpAudit.Service/ProcessMonitoring/KnownProcessStore.cs
// Module:  RdpAudit.Service.ProcessMonitoring
// Purpose: EF Core-backed store for the process-monitoring feature (PROCESS_NEW alerts +
//          automated session close). Owns the KnownProcesses baseline upsert, the bounded
//          ProcessObservations journal, the persisted PROCESS_NEW Alert reads and the
//          ProcessAlertResponses auto-close lifecycle. The IPC request path reads ONLY
//          persisted rows through this store; the actual logoff attempt happens exclusively
//          in ProcessAlertAutoResponder via RdpSessionManager. Fail-closed throughout:
//          unknown or malformed rows never fabricate alert projections.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using RdpAudit.Core.Data;
using RdpAudit.Core.Ipc.Contracts;
using RdpAudit.Core.Models;
using RdpAudit.Core.ProcessMonitoring;
using RdpAudit.Core.Util;

namespace RdpAudit.Service.ProcessMonitoring;

/// <summary>EF Core-backed store for process monitoring (baseline, journal, alerts, auto-close).</summary>
public sealed partial class KnownProcessStore
{
	/// <summary>Alert rule id produced by process monitoring.</summary>
	public const string ProcessNewRuleId = "PROCESS_NEW";

	/// <summary>Service default list limit when a caller passes 0.</summary>
	public const int DefaultListLimit = 200;

	/// <summary>Hard list upper bound.</summary>
	public const int MaxListLimit = 500;

	/// <summary>Lower clamp for the observation-journal row cap.</summary>
	public const int MinObservationsCap = 100;

	/// <summary>Upper clamp for the observation-journal row cap.</summary>
	public const int MaxObservationsCap = 100000;

	private readonly IDbContextFactory<AuditDbContext> _factory;

	public KnownProcessStore(IDbContextFactory<AuditDbContext> factory)
	{
		ArgumentNullException.ThrowIfNull(factory);
		_factory = factory;
	}

	/// <summary>Reads the baseline row for one normalized identity; null when the identity has
	/// never been observed. Empty keys always report null (they never reach the baseline).</summary>
	public async Task<KnownProcess?> FindAsync(KnownProcessKey key, CancellationToken ct = default)
	{
		if (key.IsEmpty)
		{
			return null;
		}

		await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);
		return await db.KnownProcesses.AsNoTracking()
			.FirstOrDefaultAsync(k => k.ProcessName == key.ProcessName
				&& k.UserCategory == (int)key.UserCategory
				&& k.UserName == key.UserName, ct)
			.ConfigureAwait(false);
	}

	/// <summary>Upserts the baseline row for one observation and appends a ProcessObservations
	/// journal row, then trims the journal to the configured cap (oldest-first). Returns the
	/// journal row id. The baseline is keyed by the normalized (ProcessName, UserCategory,
	/// UserName) triplet, so repeated observations of the same identity update one row. A rare
	/// concurrent insert of the same key is retried once as an update (the unique index wins).</summary>
	public async Task<long> RecordObservationAsync(
		KnownProcessKey key,
		DateTime observedUtc,
		int? sessionId,
		long rawEventId,
		bool alerted,
		bool isForced,
		int maxObservations,
		CancellationToken ct = default)
	{
		if (key.IsEmpty)
		{
			throw new ArgumentException("An empty process identity cannot be recorded.", nameof(key));
		}

		int cap = Math.Clamp(maxObservations, MinObservationsCap, MaxObservationsCap);
		Exception? lastError = null;
		for (int attempt = 0; attempt < 2; attempt++)
		{
			try
			{
				await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);

				KnownProcess? row = await db.KnownProcesses
					.FirstOrDefaultAsync(k => k.ProcessName == key.ProcessName
						&& k.UserCategory == (int)key.UserCategory
						&& k.UserName == key.UserName, ct)
					.ConfigureAwait(false);

				if (row is null)
				{
					row = new KnownProcess
					{
						ProcessName = key.ProcessName,
						UserCategory = (int)key.UserCategory,
						UserName = key.UserName,
						FirstObservedUtc = observedUtc,
						LastObservedUtc = observedUtc,
						ObservationCount = 1,
						FirstObservedProcessId = rawEventId,
					};
					db.KnownProcesses.Add(row);
				}
				else
				{
					if (observedUtc < row.FirstObservedUtc)
					{
						row.FirstObservedUtc = observedUtc;
					}

					if (observedUtc > row.LastObservedUtc)
					{
						row.LastObservedUtc = observedUtc;
					}

					row.ObservationCount++;
					if (row.FirstObservedProcessId == 0 && rawEventId != 0)
					{
						row.FirstObservedProcessId = rawEventId;
					}
				}

				ProcessObservationRecord journal = new()
				{
					ObservedUtc = observedUtc,
					ProcessName = key.ProcessName,
					UserName = key.UserCategory == ProcessUserCategory.Interactive ? key.UserName : null,
					SessionId = sessionId,
					RawEventId = rawEventId,
					Alerted = alerted,
					IsForced = isForced,
				};
				db.ProcessObservations.Add(journal);

				await db.SaveChangesAsync(ct).ConfigureAwait(false);
				long recordingId = journal.Id;

				long count = await db.ProcessObservations.AsNoTracking().LongCountAsync(ct).ConfigureAwait(false);
				if (count > cap)
				{
					long cutoffId = await db.ProcessObservations.AsNoTracking()
						.OrderBy(r => r.Id)
						.Skip((int)(count - cap - 1))
						.Select(r => r.Id)
						.FirstAsync(ct)
						.ConfigureAwait(false);
					await db.ProcessObservations
						.Where(r => r.Id <= cutoffId)
						.ExecuteDeleteAsync(ct)
						.ConfigureAwait(false);
				}

				return recordingId;
			}
			catch (DbUpdateException ex)
			{
				// Lost a race against a concurrent baseline insert of the same key. The failed
				// unit of work is discarded; the retry re-reads and updates the winner's row.
				lastError = ex;
			}
		}

		throw new InvalidOperationException(
			"Concurrent baseline upsert kept failing; known-process recording aborted.", lastError);
	}

	/// <summary>Persisted process-monitoring counters backing the status IPC command.</summary>
	public sealed record ProcessMonitoringCounts
	{
		public long KnownProcessCount { get; init; }

		public long ObservationCount { get; init; }

		public long AlertsTotal { get; init; }

		public int AutoClosePending { get; init; }

		public int AutoCloseCompleted { get; init; }

		public int AutoCloseFailed { get; init; }

		public DateTime? LastAutoCloseUtc { get; init; }
	}

	/// <summary>Reads all persisted process-monitoring counters in one pass. Never touches
	/// session operations; purely a DB snapshot.</summary>
	public async Task<ProcessMonitoringCounts> GetStatusCountsAsync(CancellationToken ct = default)
	{
		await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);

		long known = await db.KnownProcesses.AsNoTracking().LongCountAsync(ct).ConfigureAwait(false);
		long observations = await db.ProcessObservations.AsNoTracking().LongCountAsync(ct).ConfigureAwait(false);
		long alerts = await db.Alerts.AsNoTracking()
			.LongCountAsync(a => a.RuleId == ProcessNewRuleId, ct)
			.ConfigureAwait(false);

		List<int> statuses = await db.ProcessAlertResponses.AsNoTracking()
			.Select(r => r.Status)
			.ToListAsync(ct)
			.ConfigureAwait(false);

		DateTime? lastClose = await db.ProcessAlertResponses.AsNoTracking()
			.Where(r => r.Status == (int)ProcessAutoCloseStatus.Completed && r.CompletedAtUtc != null)
			.MaxAsync(r => (DateTime?)r.CompletedAtUtc, ct)
			.ConfigureAwait(false);

		return new ProcessMonitoringCounts
		{
			KnownProcessCount = known,
			ObservationCount = observations,
			AlertsTotal = alerts,
			AutoClosePending = statuses.Count(s => s == (int)ProcessAutoCloseStatus.Queued),
			AutoCloseCompleted = statuses.Count(s => s == (int)ProcessAutoCloseStatus.Completed),
			AutoCloseFailed = statuses.Count(s => s == (int)ProcessAutoCloseStatus.Failed),
			LastAutoCloseUtc = lastClose,
		};
	}
}