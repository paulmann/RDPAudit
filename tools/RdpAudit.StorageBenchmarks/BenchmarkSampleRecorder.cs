/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.2
// File   : BenchmarkSampleRecorder.cs
// Project: RdpAudit.StorageBenchmarks
// Purpose: The one place that decides what "a sample" means. Every repeated measurement in this tool
//          goes through it: it runs the warm-up passes, discards them, then takes the timed samples and
//          reduces them with the same arithmetic for every metric. A probe that timed itself would be a
//          second definition of the methodology, and the report would then describe a method it did not
//          follow. A probe that throws is recorded as failed with its exception text - never as a zero,
//          which would read as "this machine is infinitely fast at it".
// Depends: BenchmarkMeasurement, BenchmarkSampleSet
// Extends: Add a statistic by extending BenchmarkSampleSet; never time a probe outside this class.

using System.Globalization;
using RdpAudit.Core.Diagnostics;

namespace RdpAudit.StorageBenchmarks;

/// <summary>The measurement plus the raw per-run results a probe may need to derive a second metric.</summary>
/// <typeparam name="TRun">What one run produced.</typeparam>
internal sealed record BenchmarkSampleRun<TRun>(BenchmarkMeasurement Measurement, List<TRun> Runs)
{
	/// <summary>True when the metric has a value.</summary>
	public bool HasValue => Measurement.State == MeasurementState.Measured;
}

/// <summary>Runs warm-up and timed samples and reduces them to one measurement.</summary>
internal sealed class BenchmarkSampleRecorder
{
	private readonly int _warmupRuns;
	private readonly int _timedRuns;
	private readonly Action<string> _log;

	/// <summary>Creates the recorder for one run.</summary>
	/// <param name="warmupRuns">Warm-up runs to perform and discard.</param>
	/// <param name="timedRuns">Timed runs to keep.</param>
	/// <param name="log">Progress sink; receives one line per phase.</param>
	public BenchmarkSampleRecorder(int warmupRuns, int timedRuns, Action<string> log)
	{
		ArgumentNullException.ThrowIfNull(log);
		if (timedRuns < 1)
		{
			throw new ArgumentOutOfRangeException(nameof(timedRuns), timedRuns, "At least one timed run is required.");
		}

		if (warmupRuns < 0)
		{
			throw new ArgumentOutOfRangeException(nameof(warmupRuns), warmupRuns, "Warm-up runs cannot be negative.");
		}

		_warmupRuns = warmupRuns;
		_timedRuns = timedRuns;
		_log = log;
	}

	/// <summary>Warm-up runs configured for this recorder.</summary>
	public int WarmupRuns => _warmupRuns;

	/// <summary>Timed runs configured for this recorder.</summary>
	public int TimedRuns => _timedRuns;

	/// <summary>
	/// Runs <paramref name="run"/> <see cref="WarmupRuns"/> times plus <see cref="TimedRuns"/> times and
	/// reduces the timed results with <paramref name="valueOf"/> into one measurement. Any exception fails
	/// the whole metric: a partial sample set would understate the spread and a probe that failed on the
	/// third of five runs has not measured the machine.
	/// </summary>
	/// <typeparam name="TRun">What one run produces.</typeparam>
	/// <param name="metric">Metric identifier.</param>
	/// <param name="unit">Unit of the reduced value.</param>
	/// <param name="run">One run, given its zero-based index.</param>
	/// <param name="valueOf">Reduces one run's result to the number being measured.</param>
	/// <param name="note">Optional qualification of the measured value.</param>
	/// <param name="cancellationToken">Cancellation.</param>
	public async Task<BenchmarkSampleRun<TRun>> MeasureAsync<TRun>(
		string metric,
		string unit,
		Func<int, CancellationToken, Task<TRun>> run,
		Func<TRun, double> valueOf,
		string? note,
		CancellationToken cancellationToken)
	{
		ArgumentNullException.ThrowIfNull(run);
		ArgumentNullException.ThrowIfNull(valueOf);

		List<TRun> runs = [];
		List<double> values = [];

		try
		{
			for (int index = 0; index < _warmupRuns; index++)
			{
				cancellationToken.ThrowIfCancellationRequested();
				_log(string.Format(CultureInfo.InvariantCulture, "    {0}: warm-up run {1}/{2}", metric, index + 1, _warmupRuns));
				await run(index, cancellationToken).ConfigureAwait(false);
			}

			for (int index = 0; index < _timedRuns; index++)
			{
				cancellationToken.ThrowIfCancellationRequested();
				_log(string.Format(CultureInfo.InvariantCulture, "    {0}: timed run {1}/{2}", metric, index + 1, _timedRuns));
				TRun result = await run(_warmupRuns + index, cancellationToken).ConfigureAwait(false);
				runs.Add(result);
				values.Add(valueOf(result));
			}
		}
		catch (OperationCanceledException)
		{
			throw;
		}
		catch (Exception ex)
		{
			return new BenchmarkSampleRun<TRun>(
				BenchmarkMeasurement.Failed(metric, unit, Describe(ex)),
				runs);
		}

		return new BenchmarkSampleRun<TRun>(
			BenchmarkMeasurement.FromSamples(metric, unit, BenchmarkSampleSet.FromValues(values, _warmupRuns), note),
			runs);
	}

	/// <summary>Renders an exception as the one line a report carries for a failed probe.</summary>
	public static string Describe(Exception exception)
	{
		ArgumentNullException.ThrowIfNull(exception);
		return string.Format(
			CultureInfo.InvariantCulture,
			"{0}: {1}",
			exception.GetType().Name,
			exception.Message);
	}
}
