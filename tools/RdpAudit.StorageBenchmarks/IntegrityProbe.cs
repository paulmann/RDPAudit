/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.2
// File   : IntegrityProbe.cs
// Project: RdpAudit.StorageBenchmarks
// Purpose: Measures the duration of the three integrity questions the product's maintenance command can
//          ask of a store: PRAGMA quick_check, PRAGMA integrity_check and PRAGMA foreign_key_check. The
//          statements are exactly the ones DatabaseMaintenanceService emits, and they are executed here
//          on a read-only connection rather than through that service, for one reason worth stating: the
//          service wraps every step in a 30-second timeout and reports "TimedOut" instead of a duration,
//          so a store whose full check takes longer than that could never be measured through it. The
//          report converts the measured duration back into that limit, which is itself a finding.
//          All three are read-only, so repeating them on the same store is a genuine repeat of the same
//          operation rather than a measurement of a warmed cache of work already done.
// Depends: SqliteBenchmarkFacts
// Extends: Add a pragma by adding it to PragmaTargets; keep the statement text identical to the service's.

using System.Diagnostics;
using System.Globalization;
using Microsoft.Data.Sqlite;
using RdpAudit.Core.Diagnostics;

namespace RdpAudit.StorageBenchmarks;

/// <summary>What one integrity run produced.</summary>
internal sealed record IntegrityRunResult
{
	/// <summary>Seconds the check took.</summary>
	public required double Seconds { get; init; }

	/// <summary>What the pragma reported: <c>ok</c>, a violation count, or the first diagnostic line.</summary>
	public required string Result { get; init; }
}

/// <summary>Measures the integrity-check durations.</summary>
internal static class IntegrityProbe
{
	/// <summary>Maximum diagnostic rows read from a pragma, mirroring the service's own bound on how many
	/// result lines it will report.</summary>
	public const int MaxResultRows = 100;

	/// <summary>Runs every integrity measurement and returns its metrics.</summary>
	public static async Task<List<BenchmarkMeasurement>> RunAsync(
		BenchmarkStore store,
		BenchmarkSampleRecorder recorder,
		Action<string> log,
		CancellationToken cancellationToken)
	{
		ArgumentNullException.ThrowIfNull(store);
		ArgumentNullException.ThrowIfNull(recorder);
		ArgumentNullException.ThrowIfNull(log);

		BenchmarkSampleRun<IntegrityRunResult> quick = await RunCheckAsync(
			store.DatabasePath,
			StorageBenchmarkMetric.IntegrityQuickCheckSeconds,
			"PRAGMA quick_check",
			recorder,
			"the product's PRAGMA quick_check; catches structural damage without the full scan",
			cancellationToken).ConfigureAwait(false);

		BenchmarkSampleRun<IntegrityRunResult> full = await RunCheckAsync(
			store.DatabasePath,
			StorageBenchmarkMetric.IntegrityFullCheckSeconds,
			"PRAGMA integrity_check",
			recorder,
			"the product's PRAGMA integrity_check; a full scan, and the measurement the schedule rule reads",
			cancellationToken).ConfigureAwait(false);

		BenchmarkSampleRun<IntegrityRunResult> foreignKeys = await RunCheckAsync(
			store.DatabasePath,
			StorageBenchmarkMetric.IntegrityForeignKeyCheckSeconds,
			"PRAGMA foreign_key_check",
			recorder,
			"the product's PRAGMA foreign_key_check",
			cancellationToken).ConfigureAwait(false);

		foreach (BenchmarkSampleRun<IntegrityRunResult> run in new[] { quick, full, foreignKeys })
		{
			log(string.Format(
				CultureInfo.InvariantCulture,
				"  {0}: {1}",
				run.Measurement.Metric,
				run.Runs.Count > 0
					? string.Format(CultureInfo.InvariantCulture, "{0:0.###} s ({1})", run.Runs[0].Seconds, run.Runs[0].Result)
					: run.Measurement.Note ?? "not measured"));
		}

		return [quick.Measurement, full.Measurement, foreignKeys.Measurement];
	}

	private static async Task<BenchmarkSampleRun<IntegrityRunResult>> RunCheckAsync(
		string databasePath,
		string metric,
		string pragma,
		BenchmarkSampleRecorder recorder,
		string note,
		CancellationToken cancellationToken)
		=> await recorder.MeasureAsync(
			metric,
			StorageBenchmarkUnit.Seconds,
			(_, _) => Task.FromResult(ExecutePragma(databasePath, pragma)),
			static result => result.Seconds,
			note,
			cancellationToken).ConfigureAwait(false);

	private static IntegrityRunResult ExecutePragma(string databasePath, string pragma)
	{
		using SqliteConnection connection = SqliteBenchmarkFacts.Open(databasePath);
		using SqliteCommand command = connection.CreateCommand();
		command.CommandText = pragma;

		Stopwatch watch = Stopwatch.StartNew();
		int rows = 0;
		string first = string.Empty;
		using (SqliteDataReader reader = command.ExecuteReader())
		{
			while (reader.Read() && rows < MaxResultRows)
			{
				if (rows == 0)
				{
					first = reader.IsDBNull(0) ? string.Empty : reader.GetString(0);
				}

				rows++;
			}
		}

		watch.Stop();

		string result = string.Equals(pragma, "PRAGMA foreign_key_check", StringComparison.Ordinal)
			? (rows == 0 ? "ok (no violations)" : string.Format(CultureInfo.InvariantCulture, "{0} violation row(s)", rows))
			: (string.IsNullOrEmpty(first) ? "no rows" : first);

		return new IntegrityRunResult
		{
			Seconds = watch.Elapsed.TotalSeconds,
			Result = result,
		};
	}
}
