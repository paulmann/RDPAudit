/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.2
// File   : RetentionProbe.cs
// Project: RdpAudit.StorageBenchmarks
// Purpose: Measures the information-density retention pass through the REAL engine
//          (InformationDensityRetentionEngine), not through a reimplementation of it, so the published
//          throughput, batch cost and writer-lock hold describe the code that runs in production. Two
//          methodological points are load-bearing:
//            1. Every sample runs against its own copy of the seeded store. A pass removes rows, so a
//               second pass over the same store would face less work and the samples would not be
//               comparable. Copying is the cheapest way to give each sample identical starting state.
//            2. The dry run is evaluated and timed BEFORE the pass, against the same instant and the same
//               store, so the comparison between what the preview predicted and what the pass did is a
//               comparison of two answers to the same question rather than of two different states.
//          The writer-lock hold comes from the engine's own per-batch observation hook, which reports the
//          span of the delete-plus-ledger transaction the budget governs - the number the engine
//          otherwise computes and discards.
// Depends: InformationDensityRetentionEngine (internal, via InternalsVisibleTo), BenchmarkStore
// Extends: Add a retention metric by extending the per-sample record and the reduction at the end.

using System.Globalization;
using Microsoft.Data.Sqlite;
using RdpAudit.Core.Diagnostics;
using RdpAudit.Service.Services;

namespace RdpAudit.StorageBenchmarks;

/// <summary>What one retention pass sample produced.</summary>
internal sealed record RetentionPassSample
{
	/// <summary>Rows the planner said it would remove.</summary>
	public required long PlannedRows { get; init; }

	/// <summary>Rows the pass actually removed.</summary>
	public required long DeletedRows { get; init; }

	/// <summary>Seconds the pass took.</summary>
	public required double PassSeconds { get; init; }

	/// <summary>Committed delete-plus-ledger batches in the pass.</summary>
	public required int Batches { get; init; }

	/// <summary>Per-batch (rows, writer-lock milliseconds) as reported by the engine.</summary>
	public required List<(int Rows, long ElapsedMs)> BatchTelemetry { get; init; }

	/// <summary>Whether the pass stopped early because a batch exceeded the writer-lock budget.</summary>
	public required bool WriterLockBudgetExhausted { get; init; }

	/// <summary>Freelist bytes before the pass.</summary>
	public required long FreelistBytesBefore { get; init; }

	/// <summary>Freelist bytes after the pass.</summary>
	public required long FreelistBytesAfter { get; init; }

	/// <summary>Main-file bytes before the pass.</summary>
	public required long FileBytesBefore { get; init; }

	/// <summary>Main-file bytes after the pass.</summary>
	public required long FileBytesAfter { get; init; }

	/// <summary>Rows the dry run predicted.</summary>
	public required long PreviewPlannedRows { get; init; }

	/// <summary>Seconds the dry run took.</summary>
	public required double PreviewSeconds { get; init; }

	/// <summary>The trigger the evaluation reported.</summary>
	public required string Trigger { get; init; }
}

/// <summary>Measures the retention pass and its dry run.</summary>
internal static class RetentionProbe
{
	/// <summary>Delete batch size the probe measures at: the product default, so the measured per-batch
	/// cost describes the shape a default installation actually runs.</summary>
	public const int ProbeDeleteBatchRows = 2_000;

	/// <summary>Full batches the probe plans per code per pass. Planning a whole multiple of the batch
	/// size means almost every batch the engine commits is a full one, so the measured cost per batch
	/// describes a full batch rather than a tail fragment.</summary>
	public const int BatchesPerCode = 4;

	/// <summary>Runs the retention measurements and returns their metrics.</summary>
	public static async Task<List<BenchmarkMeasurement>> RunAsync(
		BenchmarkStore seedStore,
		StoreBlueprint blueprint,
		BenchmarkWorkspace workspace,
		int codes,
		BenchmarkSampleRecorder recorder,
		Action<string> log,
		CancellationToken cancellationToken)
	{
		ArgumentNullException.ThrowIfNull(seedStore);
		ArgumentNullException.ThrowIfNull(blueprint);
		ArgumentNullException.ThrowIfNull(workspace);
		ArgumentNullException.ThrowIfNull(recorder);
		ArgumentNullException.ThrowIfNull(log);

		List<RetentionPassSample> samples = [];
		List<(int Rows, long ElapsedMs)> warmupBatchTelemetry = [];

		int totalRuns = recorder.WarmupRuns + recorder.TimedRuns;
		for (int runIndex = 0; runIndex < totalRuns; runIndex++)
		{
			cancellationToken.ThrowIfCancellationRequested();
			bool warmup = runIndex < recorder.WarmupRuns;
			string phase = warmup
				? string.Format(CultureInfo.InvariantCulture, "warm-up {0}/{1}", runIndex + 1, recorder.WarmupRuns)
				: string.Format(CultureInfo.InvariantCulture, "sample {0}/{1}", runIndex - recorder.WarmupRuns + 1, recorder.TimedRuns);
			log(string.Format(CultureInfo.InvariantCulture, "  retention pass {0}: copying the seeded store", phase));

			string passDirectory = Path.Combine(
				workspace.RunDirectory,
				string.Format(CultureInfo.InvariantCulture, "retention-pass-{0:00}", runIndex));
			BenchmarkStore passStore = seedStore.CloneTo(passDirectory, blueprint);

			RetentionPassSample sample;
			try
			{
				sample = await RunOnePassAsync(passStore, log, cancellationToken).ConfigureAwait(false);
			}
			finally
			{
				// Each sample needs its own copy and none of them is needed afterwards, so the copy is
				// removed as soon as it has been measured. Ten measured passes over a single-gigabyte store
				// would otherwise leave ten copies of it on the volume being characterised.
				TryDeleteDirectory(passDirectory);
			}

			log(string.Format(
				CultureInfo.InvariantCulture,
				"  retention pass {0}: planned {1} rows, removed {2} in {3:0.###} s across {4} batches, reclaimed {5} freelist bytes",
				phase,
				sample.PlannedRows,
				sample.DeletedRows,
				sample.PassSeconds,
				sample.Batches,
				sample.FreelistBytesAfter - sample.FreelistBytesBefore));

			if (warmup)
			{
				warmupBatchTelemetry.AddRange(sample.BatchTelemetry);
			}
			else
			{
				samples.Add(sample);
			}
		}

		return Reduce(samples, warmupBatchTelemetry, recorder, codes);
	}

	private static async Task<RetentionPassSample> RunOnePassAsync(
		BenchmarkStore store,
		Action<string> log,
		CancellationToken cancellationToken)
	{
		InformationDensityRetentionEngine engine = new(store.Factory, store.OptionsMonitor);
		List<(int Rows, long ElapsedMs)> telemetry = [];
		engine.BatchCompleted = batch => telemetry.Add((batch.RowsDeleted, batch.ElapsedMs));

		// One instant for both the dry run and the pass, so the two answer the same question about the
		// same state. Two clock reads could straddle the age floor and make them disagree for a reason
		// that has nothing to do with the retention logic.
		DateTime nowUtc = DateTime.UtcNow;

		long freelistBefore;
		using (SqliteConnection observer = SqliteBenchmarkFacts.Open(store.DatabasePath))
		{
			freelistBefore = SqliteBenchmarkFacts.FreelistBytes(observer);
		}

		long fileBefore = SqliteBenchmarkFacts.DatabaseFileBytes(store.DatabasePath);

		(long previewPlannedRows, double previewMs) = await SqliteBenchmarkFacts.TimedAsync(async () =>
		{
			RetentionEvaluation preview = await engine.EvaluateForPreviewAsync(nowUtc, cancellationToken).ConfigureAwait(false);
			return preview.Plan.PlannedRows;
		}).ConfigureAwait(false);

		log(string.Format(
			CultureInfo.InvariantCulture,
			"    dry run evaluated in {0:0.###} s and predicted {1} rows",
			SqliteBenchmarkFacts.ToSeconds(previewMs),
			previewPlannedRows));

		RetentionEvaluation evaluation = await engine.EvaluateForPassAsync(nowUtc, cancellationToken).ConfigureAwait(false);

		long deletedRows = 0;
		bool budgetExhausted = false;
		double passMs = await SqliteBenchmarkFacts.TimedAsync(async () =>
		{
			RetentionExecutionResult result = await engine.ExecutePlanAsync(
				evaluation.Plan,
				evaluation.Trigger,
				evaluation.MinAgeCutoffUtc,
				evaluation.DeleteBatchRows,
				evaluation.MaxWriterLockMs,
				cancellationToken).ConfigureAwait(false);
			deletedRows = result.RowsDeleted;
			budgetExhausted = result.WriterLockBudgetExhausted;
		}).ConfigureAwait(false);

		long freelistAfter;
		using (SqliteConnection observer = SqliteBenchmarkFacts.Open(store.DatabasePath))
		{
			freelistAfter = SqliteBenchmarkFacts.FreelistBytes(observer);
		}

		return new RetentionPassSample
		{
			PlannedRows = evaluation.Plan.PlannedRows,
			DeletedRows = deletedRows,
			PassSeconds = SqliteBenchmarkFacts.ToSeconds(passMs),
			Batches = telemetry.Count,
			BatchTelemetry = telemetry,
			WriterLockBudgetExhausted = budgetExhausted,
			FreelistBytesBefore = freelistBefore,
			FreelistBytesAfter = freelistAfter,
			FileBytesBefore = fileBefore,
			FileBytesAfter = SqliteBenchmarkFacts.DatabaseFileBytes(store.DatabasePath),
			PreviewPlannedRows = previewPlannedRows,
			PreviewSeconds = SqliteBenchmarkFacts.ToSeconds(previewMs),
			Trigger = evaluation.Trigger.ToString(),
		};
	}

	private static List<BenchmarkMeasurement> Reduce(
		List<RetentionPassSample> samples,
		List<(int Rows, long ElapsedMs)> warmupBatchTelemetry,
		BenchmarkSampleRecorder recorder,
		int codes)
	{
		List<BenchmarkMeasurement> measurements = [];
		int discarded = recorder.WarmupRuns;
		if (samples.Count == 0)
		{
			measurements.Add(BenchmarkMeasurement.NotMeasured(
				StorageBenchmarkMetric.RetentionRowsPerSecond,
				StorageBenchmarkUnit.RowsPerSecond,
				"the run took no timed retention samples"));
			return measurements;
		}

		measurements.Add(Values(samples, StorageBenchmarkMetric.RetentionPlannedRows, StorageBenchmarkUnit.Rows, static sample => sample.PlannedRows, discarded, null));
		measurements.Add(Values(samples, StorageBenchmarkMetric.RetentionPreviewSeconds, StorageBenchmarkUnit.Seconds, static sample => sample.PreviewSeconds, discarded, null));
		measurements.Add(Values(samples, StorageBenchmarkMetric.RetentionPreviewPlannedRows, StorageBenchmarkUnit.Rows, static sample => sample.PreviewPlannedRows, discarded, null));

		List<RetentionPassSample> comparable = [.. samples.Where(static sample => sample.PreviewPlannedRows > 0)];
		measurements.Add(comparable.Count > 0
			? Values(
				comparable,
				StorageBenchmarkMetric.RetentionPreviewVolumeRatio,
				StorageBenchmarkUnit.Ratio,
				static sample => (double)sample.DeletedRows / sample.PreviewPlannedRows,
				discarded,
				"rows actually removed divided by the rows the dry run predicted, both measured against identical starting state")
			: BenchmarkMeasurement.NotMeasured(
				StorageBenchmarkMetric.RetentionPreviewVolumeRatio,
				StorageBenchmarkUnit.Ratio,
				"the dry run predicted no rows, so there was no volume to compare"));

		measurements.Add(Values(samples, StorageBenchmarkMetric.RetentionPassSeconds, StorageBenchmarkUnit.Seconds, static sample => sample.PassSeconds, discarded, null));
		measurements.Add(Values(
			samples,
			StorageBenchmarkMetric.RetentionRowsPerSecond,
			StorageBenchmarkUnit.RowsPerSecond,
			static sample => sample.PassSeconds > 0d ? sample.DeletedRows / sample.PassSeconds : 0d,
			discarded,
			null));
		measurements.Add(Values(samples, StorageBenchmarkMetric.RetentionBatches, StorageBenchmarkUnit.Count, static sample => sample.Batches, discarded, null));

		// Batch telemetry is pooled across every timed pass: each batch is its own observation of the same
		// operation, and the point of the pooled p95 is to bound the cost of one batch. The warm-up pass's
		// batches are counted as warm-up observations, not as samples.
		List<double> batchLockMs = [];
		List<double> batchRows = [];
		foreach (RetentionPassSample sample in samples)
		{
			foreach ((int rows, long elapsedMs) in sample.BatchTelemetry)
			{
				batchLockMs.Add(elapsedMs);
				batchRows.Add(rows);
			}
		}

		string? budgetNote = samples.Exists(static sample => sample.WriterLockBudgetExhausted)
			? "at least one pass stopped early because a batch exceeded the writer-lock budget, so its throughput understates what the machine can do"
			: null;

		if (batchLockMs.Count > 0)
		{
			measurements.Add(BenchmarkMeasurement.FromSamples(
				StorageBenchmarkMetric.RetentionBatchLockMs,
				StorageBenchmarkUnit.Milliseconds,
				BenchmarkSampleSet.FromValues(batchLockMs, warmupBatchTelemetry.Count),
				budgetNote));
			measurements.Add(BenchmarkMeasurement.FromSamples(
				StorageBenchmarkMetric.RetentionBatchRows,
				StorageBenchmarkUnit.Rows,
				BenchmarkSampleSet.FromValues(batchRows, warmupBatchTelemetry.Count),
				"observed rows per committed batch; a batch is smaller than the configured DeleteBatchRows when a code's remaining planned rows run out"));
		}
		else
		{
			measurements.Add(BenchmarkMeasurement.NotMeasured(
				StorageBenchmarkMetric.RetentionBatchLockMs,
				StorageBenchmarkUnit.Milliseconds,
				"the pass committed no batch that removed rows, so no writer-lock hold was observed"));
			measurements.Add(BenchmarkMeasurement.NotMeasured(
				StorageBenchmarkMetric.RetentionBatchRows,
				StorageBenchmarkUnit.Rows,
				"the pass committed no batch that removed rows"));
		}

		measurements.Add(Values(
			samples,
			StorageBenchmarkMetric.RetentionReclaimedBytes,
			StorageBenchmarkUnit.Bytes,
			static sample => sample.FreelistBytesAfter - sample.FreelistBytesBefore,
			discarded,
			"pages returned to the SQLite freelist, NOT bytes returned to the operating system"));
		measurements.Add(Values(
			samples,
			StorageBenchmarkMetric.RetentionReclaimedBytesPerSecond,
			StorageBenchmarkUnit.BytesPerSecond,
			static sample => sample.PassSeconds > 0d
				? (sample.FreelistBytesAfter - sample.FreelistBytesBefore) / sample.PassSeconds
				: 0d,
			discarded,
			null));
		measurements.Add(Values(samples, StorageBenchmarkMetric.RetentionStoreBytesBefore, StorageBenchmarkUnit.Bytes, static sample => sample.FileBytesBefore, discarded, null));
		measurements.Add(Values(
			samples,
			StorageBenchmarkMetric.RetentionStoreBytesAfter,
			StorageBenchmarkUnit.Bytes,
			static sample => sample.FileBytesAfter,
			discarded,
			string.Format(
				CultureInfo.InvariantCulture,
				"the main file does not shrink when rows are deleted; reclaimed pages move to the freelist and only an offline compaction returns them. Measured over {0} distinct (event id, channel) codes with trigger '{1}'.",
				codes,
				samples[0].Trigger)));

		return measurements;
	}

	private static BenchmarkMeasurement Values(
		List<RetentionPassSample> samples,
		string metric,
		string unit,
		Func<RetentionPassSample, double> selector,
		int discardedRuns,
		string? note)
	{
		List<double> values = new(samples.Count);
		foreach (RetentionPassSample sample in samples)
		{
			values.Add(selector(sample));
		}

		return BenchmarkMeasurement.FromSamples(metric, unit, BenchmarkSampleSet.FromValues(values, discardedRuns), note);
	}

	/// <summary>Removes a measured pass's copy. EF pools its connections, so the pool is cleared first or
	/// the store file is still held when the directory is removed.</summary>
	private static void TryDeleteDirectory(string directory)
	{
		SqliteBenchmarkFacts.ClearPools();
		try
		{
			if (Directory.Exists(directory))
			{
				Directory.Delete(directory, recursive: true);
			}
		}
		catch (IOException)
		{
			// Leftovers live under this run's own directory and are removed with it.
		}
		catch (UnauthorizedAccessException)
		{
			// Same rationale as above.
		}
	}
}
