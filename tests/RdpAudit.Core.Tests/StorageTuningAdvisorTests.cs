// File:    tests/RdpAudit.Core.Tests/StorageTuningAdvisorTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: Locks the recommendation rules that turn measured storage numbers into parameter advice.
//          Two properties matter more than any single number: a rule with a missing input must propose
//          NOTHING (an invented default wearing the label "measurement" is the failure this feature
//          exists to prevent), and a rule must stay inside the supported bounds of the setting it
//          advises on when the input is degenerate - zero, negative or absurdly large.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Reflection;
using System.Text.Json;
using RdpAudit.Core.Config;
using RdpAudit.Core.Diagnostics;
using Xunit;

namespace RdpAudit.Core.Tests;

/// <summary>Recommendation rules: boundaries, degenerate inputs and the absence of an input.</summary>
public class StorageTuningAdvisorTests
{
	private const long Gib = 1L << 30;

	// ── Shape of the advice ──────────────────────────────────────────────────────

	[Fact]
	public void Advise_WithNoMeasurements_ReturnsEveryRuleAsInsufficientDataWithNoValue()
	{
		IReadOnlyList<TuningRecommendation> advice = StorageTuningAdvisor.Advise(Machine(), []);

		Assert.Equal<IEnumerable<string>>(ExpectedParameters(), Parameters(advice));
		Assert.All(advice, recommendation =>
		{
			Assert.Equal(RecommendationState.InsufficientData, recommendation.State);
			Assert.Null(recommendation.Value);
			Assert.Null(recommendation.Unit);
			Assert.NotEmpty(recommendation.Inputs);
			Assert.NotEmpty(recommendation.Rule);
			Assert.NotEmpty(recommendation.Rationale);
			Assert.NotEmpty(recommendation.Caveat);
		});
	}

	[Fact]
	public void Advise_NamesTheMissingMetricForEveryInsufficientRule()
	{
		IReadOnlyList<TuningRecommendation> advice = StorageTuningAdvisor.Advise(Machine(), []);

		Assert.Contains(
			Find(advice, StorageTuningAdvisor.MaxWriterLockMsParameter).Inputs,
			entry => entry.Contains(StorageBenchmarkMetric.RetentionBatchLockMs, StringComparison.Ordinal));
		Assert.Contains(
			Find(advice, StorageTuningAdvisor.MaxRowsPerPassParameter).Inputs,
			entry => entry.Contains(StorageBenchmarkMetric.RetentionRowsPerSecond, StringComparison.Ordinal));
		Assert.Contains(
			Find(advice, StorageTuningAdvisor.BackupRetentionCopiesParameter).Inputs,
			entry => entry.Contains(StorageBenchmarkMetric.BackupSnapshotBytes, StringComparison.Ordinal));
		Assert.Contains(
			Find(advice, StorageTuningAdvisor.ShardingMinFreeDiskBytesParameter).Inputs,
			entry => entry.Contains(StorageBenchmarkMetric.BackupShardBytes, StringComparison.Ordinal));
		Assert.Contains(
			Find(advice, StorageTuningAdvisor.FullIntegrityScheduleParameter).Inputs,
			entry => entry.Contains(StorageBenchmarkMetric.IntegrityFullCheckSeconds, StringComparison.Ordinal));
	}

	[Fact]
	public void Advise_IsDeterministicAndDoesNotTouchTheFilesystem()
	{
		// The profile points at a volume and a store path that cannot exist. A rule that read either
		// would throw here, and a rule that carried state would answer differently the second time.
		MachineProfile machine = Machine();
		List<BenchmarkMeasurement> measurements = FullMeasurements();

		IReadOnlyList<TuningRecommendation> first = StorageTuningAdvisor.Advise(machine, measurements);
		IReadOnlyList<TuningRecommendation> second = StorageTuningAdvisor.Advise(machine, measurements);

		Assert.Equal(Render(first), Render(second));
		Assert.False(File.Exists(machine.StoreVolume.StorePath));
	}

	[Fact]
	public void Advisor_HasNoInstanceState()
	{
		Type advisor = typeof(StorageTuningAdvisor);

		Assert.True(
			advisor.IsAbstract && advisor.IsSealed,
			"The recommendation engine must be a static class so it has no instance state to hold I/O in.");
		Assert.All(
			advisor.GetMethods(BindingFlags.Public | BindingFlags.Static),
			method => Assert.True(method.IsStatic));
	}

	// ── Writer-lock budget ───────────────────────────────────────────────────────

	[Fact]
	public void WriterLockMs_IsThreeTimesTheMeasuredP95()
	{
		TuningRecommendation advice = Find(
			Advise(Measured(StorageBenchmarkMetric.RetentionBatchLockMs, StorageBenchmarkUnit.Milliseconds, 30d, 35d, 40d, 45d, 50d)),
			StorageTuningAdvisor.MaxWriterLockMsParameter);

		Assert.Equal(RecommendationState.Recommended, advice.State);
		Assert.Equal(150L, advice.Value);
		Assert.Equal("ms", advice.Unit);
	}

	[Fact]
	public void WriterLockMs_IsClampedUpToTheSupportedMinimum()
	{
		TuningRecommendation advice = Find(
			Advise(Measured(StorageBenchmarkMetric.RetentionBatchLockMs, StorageBenchmarkUnit.Milliseconds, 0.1d)),
			StorageTuningAdvisor.MaxWriterLockMsParameter);

		Assert.Equal(RetentionPolicyOptions.MinMaxWriterLockMs, advice.Value);
	}

	[Fact]
	public void WriterLockMs_IsClampedDownToTheSupportedMaximum()
	{
		TuningRecommendation advice = Find(
			Advise(Measured(StorageBenchmarkMetric.RetentionBatchLockMs, StorageBenchmarkUnit.Milliseconds, 100_000d)),
			StorageTuningAdvisor.MaxWriterLockMsParameter);

		Assert.Equal(RetentionPolicyOptions.MaxMaxWriterLockMs, advice.Value);
	}

	[Fact]
	public void WriterLockMs_TreatsANotMeasuredMetricAsNoInput()
	{
		IReadOnlyList<TuningRecommendation> advice = StorageTuningAdvisor.Advise(
			Machine(),
			[BenchmarkMeasurement.NotMeasured(StorageBenchmarkMetric.RetentionBatchLockMs, StorageBenchmarkUnit.Milliseconds, "the pass deleted nothing")]);

		TuningRecommendation writerLock = Find(advice, StorageTuningAdvisor.MaxWriterLockMsParameter);

		Assert.Equal(RecommendationState.InsufficientData, writerLock.State);
		Assert.Null(writerLock.Value);
	}

	[Fact]
	public void WriterLockMs_TreatsAFailedMetricAsNoInput()
	{
		IReadOnlyList<TuningRecommendation> advice = StorageTuningAdvisor.Advise(
			Machine(),
			[BenchmarkMeasurement.Failed(StorageBenchmarkMetric.RetentionBatchLockMs, StorageBenchmarkUnit.Milliseconds, "SqliteException: database is locked")]);

		Assert.Equal(RecommendationState.InsufficientData, Find(advice, StorageTuningAdvisor.MaxWriterLockMsParameter).State);
	}

	// ── Batch size ───────────────────────────────────────────────────────────────

	[Fact]
	public void DeleteBatchRows_IsSizedFromTheMeasuredCostPerRow()
	{
		// p95 50 ms for a 2 000-row batch is 0.025 ms/row; half of the recommended 150 ms budget is
		// 75 ms, which at that cost covers 3 000 rows.
		TuningRecommendation advice = Find(
			Advise(
				Measured(StorageBenchmarkMetric.RetentionBatchLockMs, StorageBenchmarkUnit.Milliseconds, 30d, 35d, 40d, 45d, 50d),
				Measured(StorageBenchmarkMetric.RetentionBatchRows, StorageBenchmarkUnit.Rows, 2_000d)),
			StorageTuningAdvisor.DeleteBatchRowsParameter);

		Assert.Equal(RecommendationState.Recommended, advice.State);
		Assert.Equal(3_000L, advice.Value);
		Assert.Equal("rows", advice.Unit);
	}

	[Fact]
	public void DeleteBatchRows_ZeroMeasuredBatchSizeIsNotExtrapolated()
	{
		TuningRecommendation advice = Find(
			Advise(
				Measured(StorageBenchmarkMetric.RetentionBatchLockMs, StorageBenchmarkUnit.Milliseconds, 50d),
				Measured(StorageBenchmarkMetric.RetentionBatchRows, StorageBenchmarkUnit.Rows, 0d)),
			StorageTuningAdvisor.DeleteBatchRowsParameter);

		Assert.Equal(RecommendationState.InsufficientData, advice.State);
		Assert.Null(advice.Value);
	}

	[Fact]
	public void DeleteBatchRows_ZeroMeasuredBatchHoldIsNotExtrapolated()
	{
		TuningRecommendation advice = Find(
			Advise(
				Measured(StorageBenchmarkMetric.RetentionBatchLockMs, StorageBenchmarkUnit.Milliseconds, 0d),
				Measured(StorageBenchmarkMetric.RetentionBatchRows, StorageBenchmarkUnit.Rows, 2_000d)),
			StorageTuningAdvisor.DeleteBatchRowsParameter);

		Assert.Equal(RecommendationState.InsufficientData, advice.State);
	}

	[Fact]
	public void DeleteBatchRows_IsClampedUpWhenTheMeasuredBatchIsFarTooCostly()
	{
		// A one-row batch costing 5 000 ms cannot be extrapolated into a sane batch, so the rule lands
		// on the smallest supported batch instead of proposing something below the bound.
		TuningRecommendation advice = Find(
			Advise(
				Measured(StorageBenchmarkMetric.RetentionBatchLockMs, StorageBenchmarkUnit.Milliseconds, 5_000d),
				Measured(StorageBenchmarkMetric.RetentionBatchRows, StorageBenchmarkUnit.Rows, 1d)),
			StorageTuningAdvisor.DeleteBatchRowsParameter);

		Assert.Equal(RetentionPolicyOptions.MinDeleteBatchRows, advice.Value);
	}

	[Fact]
	public void DeleteBatchRows_IsClampedDownWhenTheMeasuredBatchIsAbsurdlyCheap()
	{
		TuningRecommendation advice = Find(
			Advise(
				Measured(StorageBenchmarkMetric.RetentionBatchLockMs, StorageBenchmarkUnit.Milliseconds, 0.001d),
				Measured(StorageBenchmarkMetric.RetentionBatchRows, StorageBenchmarkUnit.Rows, 100_000d)),
			StorageTuningAdvisor.DeleteBatchRowsParameter);

		Assert.Equal(RetentionPolicyOptions.MaxDeleteBatchRows, advice.Value);
	}

	// ── Per-pass row budget ─────────────────────────────────────────────────────

	[Fact]
	public void MaxRowsPerPass_IsThroughputTimesTheTargetPassDuration()
	{
		// 12 340 rows/s over a 30 s target is 370 200 rows, rounded down to the 1 000-row step.
		TuningRecommendation advice = Find(
			Advise(Measured(StorageBenchmarkMetric.RetentionRowsPerSecond, StorageBenchmarkUnit.RowsPerSecond, 12_000d, 12_340d, 12_700d)),
			StorageTuningAdvisor.MaxRowsPerPassParameter);

		Assert.Equal(RecommendationState.Recommended, advice.State);
		Assert.Equal(370_000L, advice.Value);
	}

	[Fact]
	public void MaxRowsPerPass_ZeroThroughputIsNotExtrapolated()
	{
		TuningRecommendation advice = Find(
			Advise(Measured(StorageBenchmarkMetric.RetentionRowsPerSecond, StorageBenchmarkUnit.RowsPerSecond, 0d)),
			StorageTuningAdvisor.MaxRowsPerPassParameter);

		Assert.Equal(RecommendationState.InsufficientData, advice.State);
	}

	[Fact]
	public void MaxRowsPerPass_IsClampedDownForAnAbsurdThroughput()
	{
		TuningRecommendation advice = Find(
			Advise(Measured(StorageBenchmarkMetric.RetentionRowsPerSecond, StorageBenchmarkUnit.RowsPerSecond, 1e9d)),
			StorageTuningAdvisor.MaxRowsPerPassParameter);

		Assert.Equal(RetentionPolicyOptions.MaxMaxRowsPerPass, advice.Value);
	}

	// ── Free-space floors ───────────────────────────────────────────────────────

	[Fact]
	public void RetentionFreeSpaceFloor_CoversTheStoreAndOneSnapshotPlusHeadroom()
	{
		const long required = 1_000_000_000L + 1_200_000_000L + Gib;

		TuningRecommendation advice = Find(
			Advise(
				Measured(StorageBenchmarkMetric.RetentionStoreBytesBefore, StorageBenchmarkUnit.Bytes, 1_000_000_000d),
				Measured(StorageBenchmarkMetric.BackupSnapshotBytes, StorageBenchmarkUnit.Bytes, 1_200_000_000d)),
			StorageTuningAdvisor.RetentionMinFreeDiskBytesParameter);

		Assert.Equal(RecommendationState.Recommended, advice.State);
		Assert.NotNull(advice.Value);
		long value = advice.Value!.Value;
		Assert.True(value >= required, "The floor must cover the store, one snapshot and the headroom.");
		Assert.True(
			value - required < StorageTuningTargets.Default.ByteRoundStep,
			"The floor must be rounded up by less than one rounding step.");
	}

	[Fact]
	public void RetentionFreeSpaceFloor_IsDeclinedWhenItWouldClaimTooMuchOfTheVolume()
	{
		TuningRecommendation advice = Find(
			Advise(
				[
					Measured(StorageBenchmarkMetric.RetentionStoreBytesBefore, StorageBenchmarkUnit.Bytes, 1_000_000_000d),
					Measured(StorageBenchmarkMetric.BackupSnapshotBytes, StorageBenchmarkUnit.Bytes, 1_200_000_000d),
				],
				Machine(volumeTotalBytes: 4 * Gib)),
			StorageTuningAdvisor.RetentionMinFreeDiskBytesParameter);

		Assert.Equal(RecommendationState.Declined, advice.State);
		Assert.Null(advice.Value);
		Assert.Contains("Do not set this floor", advice.Rationale, StringComparison.Ordinal);
	}

	[Fact]
	public void BackupFreeSpaceFloor_CoversOneSnapshotPlusHeadroom()
	{
		const long required = 1_200_000_000L + Gib;

		TuningRecommendation advice = Find(
			Advise(Measured(StorageBenchmarkMetric.BackupSnapshotBytes, StorageBenchmarkUnit.Bytes, 1_200_000_000d)),
			StorageTuningAdvisor.BackupMinFreeDiskBytesParameter);

		Assert.Equal(RecommendationState.Recommended, advice.State);
		Assert.NotNull(advice.Value);
		Assert.True(advice.Value!.Value >= required);
	}

	[Fact]
	public void ShardingFreeSpaceFloor_IsInsufficientDataUntilTheShardTreeWasMeasured()
	{
		TuningRecommendation advice = Find(
			Advise(Measured(StorageBenchmarkMetric.BackupSnapshotBytes, StorageBenchmarkUnit.Bytes, 1_200_000_000d)),
			StorageTuningAdvisor.ShardingMinFreeDiskBytesParameter);

		Assert.Equal(RecommendationState.InsufficientData, advice.State);
	}

	[Fact]
	public void ShardingFreeSpaceFloor_IsRecommendedFromTheMeasuredShardTree()
	{
		TuningRecommendation advice = Find(
			Advise(Measured(StorageBenchmarkMetric.BackupShardBytes, StorageBenchmarkUnit.Bytes, 512_000_000d)),
			StorageTuningAdvisor.ShardingMinFreeDiskBytesParameter);

		Assert.Equal(RecommendationState.Recommended, advice.State);
		Assert.NotNull(advice.Value);
		Assert.True(advice.Value!.Value >= 512_000_000L + Gib);
	}

	// ── Snapshot retention ──────────────────────────────────────────────────────

	[Fact]
	public void RetentionCopies_DividesFreeSpaceByTheMeasuredSnapshotSize()
	{
		TuningRecommendation advice = Find(
			Advise(
				[Measured(StorageBenchmarkMetric.BackupSnapshotBytes, StorageBenchmarkUnit.Bytes, 1_000_000_000d)],
				Machine(freeBytes: 100_000_000_000L)),
			StorageTuningAdvisor.BackupRetentionCopiesParameter);

		// 100 000 000 000 free minus (one 1 000 000 000-byte snapshot plus 1 GiB of headroom) leaves
		// 97 926 258 176 usable bytes, which at 1 000 000 000 bytes per snapshot is 97 whole snapshots.
		Assert.Equal(RecommendationState.Recommended, advice.State);
		Assert.Equal(97L, advice.Value);
		Assert.Equal("copies", advice.Unit);
	}

	[Fact]
	public void RetentionCopies_NeverGoesBelowTheSupportedMinimum()
	{
		TuningRecommendation advice = Find(
			Advise(
				[Measured(StorageBenchmarkMetric.BackupSnapshotBytes, StorageBenchmarkUnit.Bytes, 1_000_000_000d)],
				Machine(freeBytes: 1_000_000_000L)),
			StorageTuningAdvisor.BackupRetentionCopiesParameter);

		Assert.Equal(BackupOptions.MinRetentionCopies, advice.Value);
		Assert.Contains("cannot hold a further snapshot", advice.Rationale, StringComparison.Ordinal);
	}

	[Fact]
	public void RetentionCopies_AnAbsurdSnapshotSizeCollapsesToTheSupportedMinimum()
	{
		TuningRecommendation advice = Find(
			Advise(Measured(StorageBenchmarkMetric.BackupSnapshotBytes, StorageBenchmarkUnit.Bytes, 1e18d)),
			StorageTuningAdvisor.BackupRetentionCopiesParameter);

		Assert.Equal(BackupOptions.MinRetentionCopies, advice.Value);
	}

	[Fact]
	public void RetentionCopies_IsClampedDownToTheSupportedMaximum()
	{
		TuningRecommendation advice = Find(
			Advise(
				[Measured(StorageBenchmarkMetric.BackupSnapshotBytes, StorageBenchmarkUnit.Bytes, 1d)],
				Machine(volumeTotalBytes: 500 * Gib, freeBytes: 400 * Gib)),
			StorageTuningAdvisor.BackupRetentionCopiesParameter);

		Assert.Equal(BackupOptions.MaxRetentionCopies, advice.Value);
	}

	// ── Full integrity-check schedule ───────────────────────────────────────────

	[Fact]
	public void IntegritySchedule_IsWeeklyWhenTheCheckIsCheap()
	{
		TuningRecommendation advice = Find(
			Advise(Measured(StorageBenchmarkMetric.IntegrityFullCheckSeconds, StorageBenchmarkUnit.Seconds, 12d)),
			StorageTuningAdvisor.FullIntegrityScheduleParameter);

		Assert.Equal(RecommendationState.Recommended, advice.State);
		Assert.Equal(7L, advice.Value);
		Assert.False(advice.IsConfigurationSetting);
		Assert.Contains("is inside the service's", advice.Rationale, StringComparison.Ordinal);
	}

	[Fact]
	public void IntegritySchedule_IsMonthlyWhenTheCheckIsExpensive()
	{
		TuningRecommendation advice = Find(
			Advise(Measured(StorageBenchmarkMetric.IntegrityFullCheckSeconds, StorageBenchmarkUnit.Seconds, 120d)),
			StorageTuningAdvisor.FullIntegrityScheduleParameter);

		Assert.Equal(RecommendationState.Recommended, advice.State);
		Assert.Equal(30L, advice.Value);
		Assert.Contains("reports TimedOut", advice.Rationale, StringComparison.Ordinal);
	}

	[Fact]
	public void IntegritySchedule_IsDeclinedWhenTheCheckIsProhibitive()
	{
		TuningRecommendation advice = Find(
			Advise(Measured(StorageBenchmarkMetric.IntegrityFullCheckSeconds, StorageBenchmarkUnit.Seconds, 1_200d)),
			StorageTuningAdvisor.FullIntegrityScheduleParameter);

		Assert.Equal(RecommendationState.Declined, advice.State);
		Assert.Null(advice.Value);
		Assert.Contains("Do not put it on a recurring schedule", advice.Rationale, StringComparison.Ordinal);
	}

	[Fact]
	public void IntegritySchedule_IsNeverAConfigurationSetting()
	{
		IReadOnlyList<TuningRecommendation> advice = StorageTuningAdvisor.Advise(Machine(), []);

		Assert.False(Find(advice, StorageTuningAdvisor.FullIntegrityScheduleParameter).IsConfigurationSetting);
	}

	// ── Invariants over a realistic input set ───────────────────────────────────

	[Fact]
	public void EveryRuleKeepsItsValueContract()
	{
		IReadOnlyList<TuningRecommendation> advice = StorageTuningAdvisor.Advise(Machine(), FullMeasurements());

		Assert.Equal<IEnumerable<string>>(ExpectedParameters(), Parameters(advice));
		Assert.All(advice, recommendation =>
		{
			Assert.NotEmpty(recommendation.Rule);
			Assert.NotEmpty(recommendation.Rationale);
			Assert.NotEmpty(recommendation.Inputs);
			Assert.NotEmpty(recommendation.Caveat);

			if (recommendation.State == RecommendationState.Recommended)
			{
				Assert.NotNull(recommendation.Value);
				Assert.NotNull(recommendation.Unit);
			}
			else
			{
				Assert.Null(recommendation.Value);
				Assert.Null(recommendation.Unit);
			}
		});
	}

	[Fact]
	public void EveryConfigurationRecommendationStaysInsideTheSupportedBounds()
	{
		IReadOnlyList<TuningRecommendation> advice = StorageTuningAdvisor.Advise(Machine(), FullMeasurements());

		Assert.InRange(
			Find(advice, StorageTuningAdvisor.DeleteBatchRowsParameter).Value!.Value,
			RetentionPolicyOptions.MinDeleteBatchRows,
			RetentionPolicyOptions.MaxDeleteBatchRows);
		Assert.InRange(
			Find(advice, StorageTuningAdvisor.MaxWriterLockMsParameter).Value!.Value,
			RetentionPolicyOptions.MinMaxWriterLockMs,
			RetentionPolicyOptions.MaxMaxWriterLockMs);
		Assert.InRange(
			Find(advice, StorageTuningAdvisor.MaxRowsPerPassParameter).Value!.Value,
			RetentionPolicyOptions.MinMaxRowsPerPass,
			RetentionPolicyOptions.MaxMaxRowsPerPass);
		Assert.InRange(
			Find(advice, StorageTuningAdvisor.BackupRetentionCopiesParameter).Value!.Value,
			BackupOptions.MinRetentionCopies,
			BackupOptions.MaxRetentionCopies);
	}

	[Fact]
	public void Advise_RejectsAMissingProfile()
	{
		Assert.Throws<ArgumentNullException>(() => StorageTuningAdvisor.Advise(null!, []));
	}

	[Fact]
	public void Advise_RejectsMissingMeasurements()
	{
		Assert.Throws<ArgumentNullException>(() => StorageTuningAdvisor.Advise(Machine(), null!));
	}

	// ── Fixtures ────────────────────────────────────────────────────────────────

	private static IEnumerable<string> ExpectedParameters() =>
	[
		StorageTuningAdvisor.MaxWriterLockMsParameter,
		StorageTuningAdvisor.DeleteBatchRowsParameter,
		StorageTuningAdvisor.MaxRowsPerPassParameter,
		StorageTuningAdvisor.RetentionMinFreeDiskBytesParameter,
		StorageTuningAdvisor.BackupMinFreeDiskBytesParameter,
		StorageTuningAdvisor.BackupRetentionCopiesParameter,
		StorageTuningAdvisor.ShardingMinFreeDiskBytesParameter,
		StorageTuningAdvisor.FullIntegrityScheduleParameter,
	];

	private static IEnumerable<string> Parameters(IReadOnlyList<TuningRecommendation> advice)
	{
		foreach (TuningRecommendation recommendation in advice)
		{
			yield return recommendation.Parameter;
		}
	}

	private static string Render(IReadOnlyList<TuningRecommendation> advice)
		=> JsonSerializer.Serialize(advice);

	private static TuningRecommendation Find(IReadOnlyList<TuningRecommendation> advice, string parameter)
	{
		foreach (TuningRecommendation recommendation in advice)
		{
			if (string.Equals(recommendation.Parameter, parameter, StringComparison.Ordinal))
			{
				return recommendation;
			}
		}

		throw new InvalidOperationException("No advice was produced for " + parameter + ".");
	}

	private static IReadOnlyList<TuningRecommendation> Advise(params BenchmarkMeasurement[] measurements)
		=> StorageTuningAdvisor.Advise(Machine(), measurements);

	private static IReadOnlyList<TuningRecommendation> Advise(BenchmarkMeasurement[] measurements, MachineProfile machine)
		=> StorageTuningAdvisor.Advise(machine, measurements);

	private static BenchmarkMeasurement Measured(string metric, string unit, params double[] values)
		=> BenchmarkMeasurement.FromSamples(metric, unit, BenchmarkSampleSet.FromValues(values));

	private static MachineProfile Machine(long volumeTotalBytes = 500 * Gib, long freeBytes = 400 * Gib)
		=> new()
		{
			OperatingSystem = "test os",
			OperatingSystemVersion = "10.0.0",
			OperatingSystemRelease = "test",
			Architecture = "X64",
			DotNetVersion = "8.0.0",
			ProcessorName = "test processor",
			ProcessorCount = 8,
			TotalPhysicalMemoryBytes = 16 * Gib,
			IsElevated = false,
			StoreVolume = new StoreVolumeProfile
			{
				// Deliberately a path that cannot exist: a rule that reads it would fail the test.
				StorePath = @"Z:\rdpaudit-benchmark-does-not-exist\rdpaudit.db",
				RootPath = "Z:\\",
				DriveType = "Fixed",
				FileSystem = "NTFS",
				TotalBytes = volumeTotalBytes,
				FreeBytes = freeBytes,
				IsSystemVolume = false,
				Ssd = SsdEvidence.Unknown("not collected by this test fixture"),
			},
			Unknowns = [],
		};

	private static List<BenchmarkMeasurement> FullMeasurements() =>
	[
		Measured(StorageBenchmarkMetric.SeedRowsPerSecond, StorageBenchmarkUnit.RowsPerSecond, 21_000d, 22_000d, 23_000d),
		Measured(StorageBenchmarkMetric.SeedStoreBytes, StorageBenchmarkUnit.Bytes, 1_000_000_000d),
		BenchmarkMeasurement.NotMeasured(StorageBenchmarkMetric.SeedSecondsPerMillionRows, StorageBenchmarkUnit.Seconds, "this profile seeded fewer than a million rows"),
		Measured(StorageBenchmarkMetric.RetentionRowsPerSecond, StorageBenchmarkUnit.RowsPerSecond, 12_000d, 12_340d, 12_700d),
		Measured(StorageBenchmarkMetric.RetentionReclaimedBytes, StorageBenchmarkUnit.Bytes, 400_000_000d),
		Measured(StorageBenchmarkMetric.RetentionBatchLockMs, StorageBenchmarkUnit.Milliseconds, 30d, 35d, 40d, 45d, 50d),
		Measured(StorageBenchmarkMetric.RetentionBatchRows, StorageBenchmarkUnit.Rows, 2_000d),
		Measured(StorageBenchmarkMetric.RetentionStoreBytesBefore, StorageBenchmarkUnit.Bytes, 1_000_000_000d),
		Measured(StorageBenchmarkMetric.LedgerEntriesPerSecond, StorageBenchmarkUnit.EntriesPerSecond, 900d, 950d),
		Measured(StorageBenchmarkMetric.BackupSnapshotBytes, StorageBenchmarkUnit.Bytes, 1_200_000_000d),
		Measured(StorageBenchmarkMetric.BackupSnapshotSeconds, StorageBenchmarkUnit.Seconds, 4.5d, 4.7d),
		Measured(StorageBenchmarkMetric.BackupShardBytes, StorageBenchmarkUnit.Bytes, 512_000_000d),
		Measured(StorageBenchmarkMetric.IntegrityQuickCheckSeconds, StorageBenchmarkUnit.Seconds, 0.4d, 0.5d),
		Measured(StorageBenchmarkMetric.IntegrityFullCheckSeconds, StorageBenchmarkUnit.Seconds, 12d, 13d),
	];
}
