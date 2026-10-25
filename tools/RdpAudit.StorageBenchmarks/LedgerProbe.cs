/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.2
// File   : LedgerProbe.cs
// Project: RdpAudit.StorageBenchmarks
// Purpose: Measures the deletion ledger's chained append through the REAL writer
//          (EventDeletionLedgerWriter.AppendAsync). The ledger is written once per retention batch inside
//          that batch's transaction, so the probe mirrors the granularity that matters: one BEGIN, one
//          chained append, one COMMIT per entry. A probe that appended a thousand entries in one
//          transaction would report a throughput the product never exhibits.
//          This matters because the ledger append is inside the writer-lock window the retention budget
//          bounds: the per-entry cost measured here is part of the batch cost the retention rules size
//          DeleteBatchRows against.
// Depends: EventDeletionLedgerWriter (internal, via InternalsVisibleTo), LedgerChainHasher
// Extends: Add a ledger metric by extending LedgerRunResult and the reduction at the end.

using System.Diagnostics;
using System.Globalization;
using Microsoft.Data.Sqlite;
using RdpAudit.Core.Diagnostics;
using RdpAudit.Core.Integrity;
using RdpAudit.Core.Models;
using RdpAudit.Core.Retention;
using RdpAudit.Service.Services;

namespace RdpAudit.StorageBenchmarks;

/// <summary>What one ledger run produced.</summary>
internal sealed record LedgerRunResult
{
	/// <summary>Entries appended in the run.</summary>
	public required int Entries { get; init; }

	/// <summary>Seconds the run took.</summary>
	public required double Seconds { get; init; }

	/// <summary>Per-entry append latency in milliseconds, including its own commit.</summary>
	public required List<double> EntryMilliseconds { get; init; }

	/// <summary>Entries per second.</summary>
	public double EntriesPerSecond => Seconds > 0d ? Entries / Seconds : 0d;
}

/// <summary>Measures chained ledger appends.</summary>
internal static class LedgerProbe
{
	/// <summary>Entries one run appends. Large enough to average out the first-entry cost, small enough
	/// that the probe does not dominate the run's time budget.</summary>
	public const int EntriesPerRun = 500;

	/// <summary>Runs the ledger measurements and returns their metrics.</summary>
	public static async Task<List<BenchmarkMeasurement>> RunAsync(
		BenchmarkStore store,
		BenchmarkSampleRecorder recorder,
		Action<string> log,
		CancellationToken cancellationToken)
	{
		ArgumentNullException.ThrowIfNull(store);
		ArgumentNullException.ThrowIfNull(recorder);
		ArgumentNullException.ThrowIfNull(log);

		BenchmarkSampleRun<LedgerRunResult> run = await recorder.MeasureAsync(
			StorageBenchmarkMetric.LedgerEntriesPerSecond,
			StorageBenchmarkUnit.EntriesPerSecond,
			(_, token) => AppendManyAsync(store, token),
			static result => result.EntriesPerSecond,
			note: string.Format(
				CultureInfo.InvariantCulture,
				"one transaction per entry, matching the retention batch that writes a ledger row inside its own transaction; {0} entries per run",
				EntriesPerRun),
			cancellationToken).ConfigureAwait(false);

		List<BenchmarkMeasurement> measurements = [run.Measurement];

		List<double> entryMilliseconds = [];
		foreach (LedgerRunResult result in run.Runs)
		{
			entryMilliseconds.AddRange(result.EntryMilliseconds);
		}

		BenchmarkMeasurement append = entryMilliseconds.Count > 0
			? BenchmarkMeasurement.FromSamples(
				StorageBenchmarkMetric.LedgerAppendMs,
				StorageBenchmarkUnit.Milliseconds,
				BenchmarkSampleSet.FromValues(entryMilliseconds, recorder.WarmupRuns * EntriesPerRun),
				"one sample per appended entry, pooled across the timed runs")
			: BenchmarkMeasurement.NotMeasured(
				StorageBenchmarkMetric.LedgerAppendMs,
				StorageBenchmarkUnit.Milliseconds,
				"the probe appended no entries");
		measurements.Add(append);

		log(string.Format(
			CultureInfo.InvariantCulture,
			"  ledger: {0}",
			run.Measurement.State == MeasurementState.Measured
				? string.Format(
					CultureInfo.InvariantCulture,
					"{0:0.###} entries/s, append median {1:0.###} ms / p95 {2:0.###} ms over {3} entries",
					run.Measurement.Value,
					append.Samples?.Median ?? 0d,
					append.Samples?.P95 ?? 0d,
					append.Samples?.SampleCount ?? 0)
				: run.Measurement.Note ?? "not measured"));

		return measurements;
	}

	private static async Task<LedgerRunResult> AppendManyAsync(BenchmarkStore store, CancellationToken cancellationToken)
	{
		DateTime nowUtc = DateTime.UtcNow;
		using SqliteConnection connection = SqliteBenchmarkFacts.Open(store.DatabasePath);

		string previousHash = await EventDeletionLedgerWriter
			.ReadChainHeadAsync(connection, null, cancellationToken)
			.ConfigureAwait(false);

		List<double> entryMilliseconds = new(EntriesPerRun);
		Stopwatch runWatch = Stopwatch.StartNew();
		for (int index = 0; index < EntriesPerRun; index++)
		{
			LedgerChainEntry entry = new(
				EventCode: 4625,
				Scope: (int)EventDeletionScope.PerIp,
				IpBinary16: null,
				WindowStartUtc: nowUtc.AddDays(-30),
				WindowEndUtc: nowUtc,
				RowsDeleted: 2_000,
				Trigger: (int)EventDeletionTrigger.OperatorRequest,
				RuleVersion: RetentionRuleVersion.Current,
				Reason: EventDeletionLedgerWriter.BuildReason("information-density", "OperatorRequest", "storage benchmark append"),
				InitiatedBy: "RdpAudit.StorageBenchmarks",
				CreatedUtc: nowUtc);

			Stopwatch entryWatch = Stopwatch.StartNew();
			using (SqliteTransaction transaction = connection.BeginTransaction())
			{
				previousHash = await EventDeletionLedgerWriter
					.AppendAsync(connection, transaction, entry, previousHash, cancellationToken)
					.ConfigureAwait(false);
				transaction.Commit();
			}

			entryWatch.Stop();
			entryMilliseconds.Add(entryWatch.Elapsed.TotalMilliseconds);
		}

		runWatch.Stop();
		return new LedgerRunResult
		{
			Entries = EntriesPerRun,
			Seconds = runWatch.Elapsed.TotalSeconds,
			EntryMilliseconds = entryMilliseconds,
		};
	}
}
