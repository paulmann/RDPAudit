// File:    tests/RdpAudit.Core.Tests/StorageBenchmarkReportWriterTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: Locks the three artifacts a storage benchmark run produces. The JSON report has a schema,
//          so it is tested by round-trip rather than by spot-checking fields; the Markdown report is
//          tested for the sections an operator reads and for the "not measured" rendering that keeps a
//          missing number from looking like a small one; and the settings fragment is tested for the two
//          things that would make it dangerous - carrying operational advice or a value the rules
//          refused to stand behind.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Text.Json;
using RdpAudit.Core.Diagnostics;
using Xunit;

namespace RdpAudit.Core.Tests;

/// <summary>Report rendering: JSON round-trip, Markdown sections and the settings fragment.</summary>
public class StorageBenchmarkReportWriterTests
{
	// ── JSON round-trip ─────────────────────────────────────────────────────────

	[Fact]
	public void BuildJson_ThenParseJson_RoundTripsTheWholeDocument()
	{
		StorageBenchmarkReport original = Report();
		string json = StorageBenchmarkReportWriter.BuildJson(original);

		StorageBenchmarkReport? parsed = StorageBenchmarkReportWriter.ParseJson(json);

		Assert.NotNull(parsed);
		Assert.Equal(json, StorageBenchmarkReportWriter.BuildJson(parsed!));
	}

	[Fact]
	public void ParseJson_PreservesTheMeasurementStatesAndSampleStatistics()
	{
		StorageBenchmarkReport original = Report();
		string json = StorageBenchmarkReportWriter.BuildJson(original);

		StorageBenchmarkReport parsed = StorageBenchmarkReportWriter.ParseJson(json)!;

		Assert.Equal(original.Measurements.Count, parsed.Measurements.Count);
		for (int index = 0; index < original.Measurements.Count; index++)
		{
			BenchmarkMeasurement before = original.Measurements[index];
			BenchmarkMeasurement after = parsed.Measurements[index];
			Assert.Equal(before.Metric, after.Metric);
			Assert.Equal(before.State, after.State);
			Assert.Equal(before.Value, after.Value);
			Assert.Equal(before.Samples?.P95, after.Samples?.P95);
			Assert.Equal(before.Samples?.SampleCount, after.Samples?.SampleCount);
		}
	}

	[Fact]
	public void ParseJson_PreservesTheMachineProfile()
	{
		StorageBenchmarkReport original = Report();

		StorageBenchmarkReport parsed = StorageBenchmarkReportWriter.ParseJson(
			StorageBenchmarkReportWriter.BuildJson(original))!;

		Assert.Equal(original.Machine.OperatingSystem, parsed.Machine.OperatingSystem);
		Assert.Equal(original.Machine.ProcessorCount, parsed.Machine.ProcessorCount);
		Assert.Equal(original.Machine.StoreVolume.Ssd.Source, parsed.Machine.StoreVolume.Ssd.Source);
		Assert.Equal(original.Machine.StoreVolume.Ssd.IsSolidState, parsed.Machine.StoreVolume.Ssd.IsSolidState);
		Assert.Equal(original.Machine.StoreVolume.TotalBytes, parsed.Machine.StoreVolume.TotalBytes);
	}

	[Fact]
	public void ParseJson_RejectsGarbage()
	{
		Assert.Throws<JsonException>(() => StorageBenchmarkReportWriter.ParseJson("{ not json"));
	}

	[Fact]
	public void BuildJson_RejectsAMissingReport()
	{
		Assert.Throws<ArgumentNullException>(() => StorageBenchmarkReportWriter.BuildJson(null!));
	}

	// ── Markdown ────────────────────────────────────────────────────────────────

	[Fact]
	public void BuildMarkdown_HasEverySectionInOrder()
	{
		string markdown = StorageBenchmarkReportWriter.BuildMarkdown(Report());

		string[] headings =
		[
			"## 1. Machine profile",
			"## 2. Methodology",
			"## 3. Measured values",
			"## 4. Recommendations",
			"## 5. Limitations",
			"## 6. Scope — what this report is not",
		];

		int previous = -1;
		foreach (string heading in headings)
		{
			int at = markdown.IndexOf(heading, StringComparison.Ordinal);
			Assert.True(at > previous, heading + " is missing or out of order.");
			previous = at;
		}
	}

	[Fact]
	public void BuildMarkdown_StatesTheProfileAndTheStoreItMeasured()
	{
		StorageBenchmarkReport report = Report();

		string markdown = StorageBenchmarkReportWriter.BuildMarkdown(report);

		Assert.Contains(report.ProfileName, markdown, StringComparison.Ordinal);
		Assert.Contains(report.Machine.ProcessorName, markdown, StringComparison.Ordinal);
		Assert.Contains(report.StorePath, markdown, StringComparison.Ordinal);
	}

	[Fact]
	public void BuildMarkdown_RendersAnUnmeasuredMetricAsNotMeasuredWithItsReason()
	{
		string markdown = StorageBenchmarkReportWriter.BuildMarkdown(Report());

		Assert.Contains("_not measured_", markdown, StringComparison.Ordinal);
		Assert.Contains("the quick profile seeds fewer than a million rows", markdown, StringComparison.Ordinal);
	}

	[Fact]
	public void BuildMarkdown_RendersAFailedMetricAsFailedWithItsReason()
	{
		string markdown = StorageBenchmarkReportWriter.BuildMarkdown(Report());

		Assert.Contains("_failed_", markdown, StringComparison.Ordinal);
		Assert.Contains("SqliteException", markdown, StringComparison.Ordinal);
	}

	[Fact]
	public void BuildMarkdown_EscapesPipesSoACellCannotShiftTheColumns()
	{
		StorageBenchmarkReport report = Report() with
		{
			Measurements =
			[
				BenchmarkMeasurement.NotMeasured(
					StorageBenchmarkMetric.CompactionSeconds,
					StorageBenchmarkUnit.Seconds,
					"refused: the store | the copy | differs"),
			],
		};

		string markdown = StorageBenchmarkReportWriter.BuildMarkdown(report);

		Assert.Contains("the store \\| the copy \\| differs", markdown, StringComparison.Ordinal);
	}

	[Fact]
	public void BuildMarkdown_SaysTheRecommendationsWereNotApplied()
	{
		string markdown = StorageBenchmarkReportWriter.BuildMarkdown(Report());

		Assert.Contains("These are **not applied**", markdown, StringComparison.Ordinal);
		Assert.Contains("no code path that", markdown, StringComparison.Ordinal);
	}

	[Fact]
	public void BuildMarkdown_RejectsAMissingReport()
	{
		Assert.Throws<ArgumentNullException>(() => StorageBenchmarkReportWriter.BuildMarkdown(null!));
	}

	// ── Settings fragment ───────────────────────────────────────────────────────

	[Fact]
	public void RecommendedSettings_NestsEachSettingAtItsRealConfigurationPath()
	{
		StorageBenchmarkReport report = Report();

		using JsonDocument document = JsonDocument.Parse(StorageBenchmarkReportWriter.BuildRecommendedSettingsJson(report));
		JsonElement retention = document.RootElement
			.GetProperty("RdpAudit")
			.GetProperty("Storage")
			.GetProperty("RetentionPolicy");

		Assert.True(retention.TryGetProperty("DeleteBatchRows", out JsonElement deleteBatchRows));
		Assert.Equal(JsonValueKind.Number, deleteBatchRows.ValueKind);
		Assert.True(retention.TryGetProperty("MaxWriterLockMs", out _));
		Assert.True(retention.TryGetProperty("MaxRowsPerPass", out _));
		Assert.True(retention.TryGetProperty("MinFreeDiskBytes", out _));
		Assert.True(document.RootElement.GetProperty("RdpAudit").GetProperty("Storage").GetProperty("Backup").TryGetProperty("RetentionCopies", out _));
		Assert.True(document.RootElement.GetProperty("RdpAudit").GetProperty("Sharding").TryGetProperty("MinFreeDiskBytes", out _));
	}

	[Fact]
	public void RecommendedSettings_CarriesExactlyTheValuesTheRulesRecommended()
	{
		StorageBenchmarkReport report = Report();

		using JsonDocument document = JsonDocument.Parse(StorageBenchmarkReportWriter.BuildRecommendedSettingsJson(report));

		foreach (TuningRecommendation recommendation in report.Recommendations)
		{
			if (!recommendation.IsConfigurationSetting || recommendation.State != RecommendationState.Recommended)
			{
				continue;
			}

			JsonElement leaf = Navigate(document.RootElement, recommendation.Parameter);
			Assert.Equal(recommendation.Value, leaf.GetInt64());
		}
	}

	[Fact]
	public void RecommendedSettings_ExcludesOperationalAdvice()
	{
		StorageBenchmarkReport report = Report();
		Assert.Contains(
			report.Recommendations,
			recommendation => !recommendation.IsConfigurationSetting && recommendation.State == RecommendationState.Recommended);

		string fragment = StorageBenchmarkReportWriter.BuildRecommendedSettingsJson(report);

		Assert.DoesNotContain("Operations", fragment, StringComparison.Ordinal);
	}

	[Fact]
	public void RecommendedSettings_ExcludesDeclinedAndInsufficientRules()
	{
		StorageBenchmarkReport report = Report() with
		{
			Recommendations =
			[
				TuningRecommendation.Declined("RdpAudit:Storage:RetentionPolicy:MaxRowsPerPass", "rule", "why", ["metric"], "caveat"),
				TuningRecommendation.Insufficient("RdpAudit:Storage:Backup:RetentionCopies", "rule", "why", ["metric"]),
			],
		};

		string fragment = StorageBenchmarkReportWriter.BuildRecommendedSettingsJson(report);

		Assert.DoesNotContain("MaxRowsPerPass", fragment, StringComparison.Ordinal);
		Assert.DoesNotContain("RetentionCopies", fragment, StringComparison.Ordinal);
		Assert.Contains("_empty", fragment, StringComparison.Ordinal);
		Assert.DoesNotContain("\"RdpAudit\"", fragment, StringComparison.Ordinal);
	}

	[Fact]
	public void RecommendedSettings_SaysItWasNotApplied()
	{
		string fragment = StorageBenchmarkReportWriter.BuildRecommendedSettingsJson(Report());

		Assert.Contains("NOT applied automatically", fragment, StringComparison.Ordinal);
	}

	// ── File output ─────────────────────────────────────────────────────────────

	[Fact]
	public void WriteAll_WritesTheThreeArtifactsIntoTheRequestedDirectory()
	{
		string directory = Path.Combine(Path.GetTempPath(), "rdpaudit-benchmark-report-test-" + Guid.NewGuid().ToString("N"));

		try
		{
			IReadOnlyList<string> paths = StorageBenchmarkReportWriter.WriteAll(Report(), directory);

			Assert.Equal(3, paths.Count);
			Assert.EndsWith(StorageBenchmarkReportWriter.MarkdownFileName, paths[0], StringComparison.Ordinal);
			Assert.EndsWith(StorageBenchmarkReportWriter.JsonFileName, paths[1], StringComparison.Ordinal);
			Assert.EndsWith(StorageBenchmarkReportWriter.RecommendedSettingsFileName, paths[2], StringComparison.Ordinal);
			Assert.All(paths, path => Assert.True(File.Exists(path), path + " was not written."));
			Assert.Contains("## 3. Measured values", File.ReadAllText(paths[0]), StringComparison.Ordinal);
			Assert.NotNull(StorageBenchmarkReportWriter.ParseJson(File.ReadAllText(paths[1])));
		}
		finally
		{
			if (Directory.Exists(directory))
			{
				Directory.Delete(directory, recursive: true);
			}
		}
	}

	// ── Fixtures ────────────────────────────────────────────────────────────────

	private static JsonElement Navigate(JsonElement root, string parameter)
	{
		JsonElement current = root;
		foreach (string segment in parameter.Split(':', StringSplitOptions.RemoveEmptyEntries))
		{
			current = current.GetProperty(segment);
		}

		return current;
	}

	private static StorageBenchmarkReport Report()
	{
		MachineProfile machine = new()
		{
			OperatingSystem = "Microsoft Windows 11 Pro",
			OperatingSystemVersion = "10.0.26200",
			OperatingSystemRelease = "25H2",
			Architecture = "X64",
			DotNetVersion = "8.0.31",
			ProcessorName = "AMD Ryzen 7 5700X3D",
			ProcessorCount = 16,
			TotalPhysicalMemoryBytes = 32L << 30,
			IsElevated = false,
			StoreVolume = new StoreVolumeProfile
			{
				StorePath = @"C:\Temp\rdpaudit-benchmark\rdpaudit.db",
				RootPath = "C:\\",
				DriveType = "Fixed",
				FileSystem = "NTFS",
				TotalBytes = 500L << 30,
				FreeBytes = 400L << 30,
				IsSystemVolume = true,
				Ssd = new SsdEvidence
				{
					Source = SsdEvidenceSource.HardwareQuery,
					IsSolidState = true,
					Detail = "seek penalty property reports no penalty",
				},
			},
			Unknowns = ["physical memory: not collected"],
		};

		List<BenchmarkMeasurement> measurements =
		[
			BenchmarkMeasurement.FromSamples(
				StorageBenchmarkMetric.SeedRowsPerSecond,
				StorageBenchmarkUnit.RowsPerSecond,
				BenchmarkSampleSet.FromValues([21_000d, 22_000d, 23_000d], warmupCount: 1)),
			BenchmarkMeasurement.NotMeasured(
				StorageBenchmarkMetric.SeedSecondsPerMillionRows,
				StorageBenchmarkUnit.Seconds,
				"the quick profile seeds fewer than a million rows"),
			BenchmarkMeasurement.Failed(
				StorageBenchmarkMetric.CompactionSeconds,
				StorageBenchmarkUnit.Seconds,
				"SqliteException: unable to open database file"),
			BenchmarkMeasurement.FromSamples(
				StorageBenchmarkMetric.RetentionRowsPerSecond,
				StorageBenchmarkUnit.RowsPerSecond,
				BenchmarkSampleSet.FromValues([12_000d, 12_340d, 12_700d])),
			BenchmarkMeasurement.FromSamples(
				StorageBenchmarkMetric.RetentionBatchLockMs,
				StorageBenchmarkUnit.Milliseconds,
				BenchmarkSampleSet.FromValues([30d, 35d, 40d, 45d, 50d])),
			BenchmarkMeasurement.Scalar(StorageBenchmarkMetric.RetentionBatchRows, StorageBenchmarkUnit.Rows, 2_000d),
			BenchmarkMeasurement.Scalar(StorageBenchmarkMetric.RetentionStoreBytesBefore, StorageBenchmarkUnit.Bytes, 1_000_000_000d),
			BenchmarkMeasurement.Scalar(StorageBenchmarkMetric.BackupSnapshotBytes, StorageBenchmarkUnit.Bytes, 1_200_000_000d),
			BenchmarkMeasurement.Scalar(StorageBenchmarkMetric.BackupShardBytes, StorageBenchmarkUnit.Bytes, 512_000_000d),
			BenchmarkMeasurement.Scalar(StorageBenchmarkMetric.IntegrityFullCheckSeconds, StorageBenchmarkUnit.Seconds, 12d),
		];

		return new StorageBenchmarkReport
		{
			SchemaVersion = StorageBenchmarkReport.CurrentSchemaVersion,
			ToolName = "RdpAudit.StorageBenchmarks",
			ToolVersion = "1.0.0",
			ProfileName = "quick",
			ProfileDescription = "small store, few samples",
			GeneratedUtc = new DateTime(2026, 9, 15, 12, 0, 0, DateTimeKind.Utc),
			StorePath = machine.StoreVolume.StorePath,
			SeedRowCount = 200_000,
			SeedCodeCount = 16,
			TotalDurationMs = 61_000,
			Machine = machine,
			Methodology = new BenchmarkMethodology
			{
				WarmupRuns = 1,
				TimedRuns = 3,
				AggregationRule = "median of the timed samples",
				PercentileRule = "nearest rank",
				BatchLockRule = "per-batch transaction span reported by the engine",
				RecommendationRule = "pure rules over the measured metrics",
				Notes = ["no concurrent ingestion"],
			},
			Measurements = measurements,
			Recommendations = StorageTuningAdvisor.Advise(machine, measurements),
			Limitations = ["synthetic store", "no production load"],
		};
	}
}
