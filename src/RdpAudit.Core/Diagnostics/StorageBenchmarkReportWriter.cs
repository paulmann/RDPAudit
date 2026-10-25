/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.2
// File   : StorageBenchmarkReportWriter.cs
// Project: RdpAudit.Core (RdpAudit.Core.Diagnostics)
// Purpose: Renders a StorageBenchmarkReport three ways: a human-readable Markdown report, a versioned
//          machine-readable JSON document, and a settings fragment an operator can merge by hand. The
//          rendering is split into pure string builders and a thin file-writing shell so the exact text
//          of a report is unit-testable without touching a disk. The settings fragment is deliberately
//          the ONLY artifact that looks like configuration, and it is never read by anything: this
//          writer cannot apply a setting and no caller of it can either.
// Depends: StorageBenchmarkReport, System.Text.Json
// Extends: Add a report section by adding a builder method and calling it from BuildMarkdown; keep the
//          section order stable so two runs can be diffed.

using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace RdpAudit.Core.Diagnostics;

/// <summary>Renders benchmark reports as Markdown, JSON and a settings fragment.</summary>
public static class StorageBenchmarkReportWriter
{
	/// <summary>File name of the human-readable report.</summary>
	public const string MarkdownFileName = "report.md";

	/// <summary>File name of the machine-readable report.</summary>
	public const string JsonFileName = "report.json";

	/// <summary>File name of the recommended settings fragment.</summary>
	public const string RecommendedSettingsFileName = "recommended-settings.json";

	private static readonly JsonSerializerOptions ReportJsonOptions = new()
	{
		WriteIndented = true,
		PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
		DefaultIgnoreCondition = JsonIgnoreCondition.Never,
		Converters = { new JsonStringEnumConverter() },
	};

	private static readonly JsonSerializerOptions SettingsJsonOptions = new()
	{
		WriteIndented = true,
	};

	// ── Rendering ────────────────────────────────────────────────────────────────

	/// <summary>Renders the report as Markdown, including the machine profile, the methodology, the
	/// measurement table, the recommendations and the limitations, in that order.</summary>
	public static string BuildMarkdown(StorageBenchmarkReport report)
	{
		ArgumentNullException.ThrowIfNull(report);

		StringBuilder builder = new();
		builder.AppendLine("# RdpAudit storage benchmark report");
		builder.AppendLine();
		builder.AppendLine(Invariant($"- Tool: `{report.ToolName}` {report.ToolVersion}"));
		builder.AppendLine(Invariant($"- Report schema: `{report.SchemaVersion}`"));
		builder.AppendLine(Invariant($"- Profile: `{report.ProfileName}` — {report.ProfileDescription}"));
		builder.AppendLine(Invariant($"- Generated (UTC): {report.GeneratedUtc:yyyy-MM-dd HH:mm:ss}"));
		builder.AppendLine(Invariant($"- Total run time: {report.TotalDurationMs / 1000d:0.###} s"));
		builder.AppendLine(Invariant($"- Benchmark store: `{report.StorePath}` (created by this run, removed afterwards)"));
		builder.AppendLine(Invariant($"- Synthetic rows seeded: {report.SeedRowCount:N0} across {report.SeedCodeCount} distinct (event id, channel) codes"));
		builder.AppendLine();
		builder.AppendLine("> Every number below was measured on the machine described in section 1 during this run.");
		builder.AppendLine("> A metric the run did not reach is printed as `not measured` (or `failed`) with its reason;");
		builder.AppendLine("> nothing in this report is an estimate presented as a measurement.");
		builder.AppendLine();

		AppendMachineProfile(builder, report.Machine);
		AppendMethodology(builder, report.Methodology);
		AppendMeasurements(builder, report);
		AppendRecommendations(builder, report);
		AppendLimitations(builder, report);
		AppendScope(builder);

		return builder.ToString();
	}

	private static void AppendMachineProfile(StringBuilder builder, MachineProfile machine)
	{
		builder.AppendLine("## 1. Machine profile");
		builder.AppendLine();
		builder.AppendLine("| Fact | Value |");
		builder.AppendLine("| --- | --- |");
		AppendRow(builder, "Operating system", machine.OperatingSystem);
		AppendRow(builder, "OS version / build", machine.OperatingSystemVersion);
		AppendRow(builder, "OS release", machine.OperatingSystemRelease);
		AppendRow(builder, "Architecture", machine.Architecture);
		AppendRow(builder, ".NET runtime", machine.DotNetVersion);
		AppendRow(builder, "Processor", machine.ProcessorName);
		AppendRow(builder, "Logical processors", machine.ProcessorCount.ToString(CultureInfo.InvariantCulture));
		AppendRow(
			builder,
			"Physical memory",
			machine.TotalPhysicalMemoryBytes > 0
				? Invariant($"{machine.TotalPhysicalMemoryBytes / (double)(1L << 30):0.##} GiB ({machine.TotalPhysicalMemoryBytes} bytes)")
				: "unknown");
		AppendRow(builder, "Benchmark process elevated", machine.IsElevated ? "yes" : "no");
		AppendRow(builder, "Store volume root", machine.StoreVolume.RootPath);
		AppendRow(builder, "Store volume drive type", machine.StoreVolume.DriveType);
		AppendRow(builder, "Store volume filesystem", machine.StoreVolume.FileSystem);
		AppendRow(
			builder,
			"Store volume total",
			machine.StoreVolume.TotalBytes > 0 ? Invariant($"{machine.StoreVolume.TotalBytes:N0} bytes") : "unknown");
		AppendRow(
			builder,
			"Store volume free",
			machine.StoreVolume.FreeBytes > 0 ? Invariant($"{machine.StoreVolume.FreeBytes:N0} bytes") : "unknown");
		AppendRow(builder, "Store volume is the system volume", machine.StoreVolume.IsSystemVolume ? "yes" : "no");
		AppendRow(
			builder,
			"Store volume media",
			machine.StoreVolume.Ssd.IsSolidState is { } solid
				? Invariant($"{(solid ? "solid state" : "rotational")} ({machine.StoreVolume.Ssd.Source})")
				: Invariant($"unknown ({machine.StoreVolume.Ssd.Source})"));
		AppendRow(builder, "Media evidence", machine.StoreVolume.Ssd.Detail);
		builder.AppendLine();

		if (machine.Unknowns.Count > 0)
		{
			builder.AppendLine("Facts that could not be collected on this host:");
			builder.AppendLine();
			foreach (string unknown in machine.Unknowns)
			{
				builder.AppendLine(Invariant($"- {unknown}"));
			}

			builder.AppendLine();
		}
	}

	private static void AppendMethodology(StringBuilder builder, BenchmarkMethodology methodology)
	{
		builder.AppendLine("## 2. Methodology");
		builder.AppendLine();
		builder.AppendLine(Invariant($"- Warm-up runs per repeated measurement: **{methodology.WarmupRuns}** (discarded)."));
		builder.AppendLine(Invariant($"- Timed runs per repeated measurement: **{methodology.TimedRuns}** (kept)."));
		builder.AppendLine(Invariant($"- Value column: {methodology.AggregationRule}"));
		builder.AppendLine(Invariant($"- Percentiles: {methodology.PercentileRule}"));
		builder.AppendLine(Invariant($"- Writer-lock hold: {methodology.BatchLockRule}"));
		builder.AppendLine(Invariant($"- Recommendations: {methodology.RecommendationRule}"));
		builder.AppendLine();
		foreach (string note in methodology.Notes)
		{
			builder.AppendLine(Invariant($"- {note}"));
		}

		builder.AppendLine();
	}

	private static void AppendMeasurements(StringBuilder builder, StorageBenchmarkReport report)
	{
		builder.AppendLine("## 3. Measured values");
		builder.AppendLine();
		builder.AppendLine("`Samples` is the number of timed observations behind the value; the p95, min and max of the");
		builder.AppendLine("same sample set are in `report.json`.");
		builder.AppendLine();
		builder.AppendLine("| Metric | Value (median) | Unit | Samples | Note |");
		builder.AppendLine("| --- | ---: | --- | ---: | --- |");
		foreach (BenchmarkMeasurement measurement in report.Measurements)
		{
			string value = measurement.State switch
			{
				MeasurementState.Measured => FormatValue(measurement.Value),
				MeasurementState.Failed => "_failed_",
				_ => "_not measured_",
			};
			string samples = measurement.Samples is { } set
				? Invariant($"{set.SampleCount} (+{set.WarmupCount} warm-up)")
				: "—";
			builder.AppendLine(Invariant(
				$"| `{Cell(measurement.Metric)}` | {value} | {Cell(measurement.Unit)} | {samples} | {Cell(measurement.Note ?? string.Empty)} |"));
		}

		builder.AppendLine();
	}

	private static void AppendRecommendations(StringBuilder builder, StorageBenchmarkReport report)
	{
		builder.AppendLine("## 4. Recommendations");
		builder.AppendLine();
		builder.AppendLine("These are **not applied**. Nothing written them anywhere. Section 6 says what to do with them.");
		builder.AppendLine();
		builder.AppendLine("| Parameter | State | Value | Unit |");
		builder.AppendLine("| --- | --- | ---: | --- |");
		foreach (TuningRecommendation recommendation in report.Recommendations)
		{
			builder.AppendLine(Invariant(
				$"| `{Cell(recommendation.Parameter)}` | {recommendation.State} | {Cell(recommendation.State == RecommendationState.Recommended ? FormatValue(recommendation.Value) : "—")} | {Cell(recommendation.Unit ?? "—")} |"));
		}

		builder.AppendLine();

		foreach (TuningRecommendation recommendation in report.Recommendations)
		{
			builder.AppendLine(Invariant($"### `{recommendation.Parameter}` — {recommendation.State}"));
			builder.AppendLine();
			builder.AppendLine(Invariant($"- **Value:** {recommendation.DescribeValue()}"));
			builder.AppendLine(Invariant($"- **Rule:** {recommendation.Rule}"));
			builder.AppendLine(Invariant($"- **Why:** {recommendation.Rationale}"));
			if (recommendation.Inputs.Count > 0)
			{
				builder.AppendLine(recommendation.State == RecommendationState.InsufficientData
					? "- **Missing measured input:**"
					: "- **Measured inputs:**");
				foreach (string input in recommendation.Inputs)
				{
					builder.AppendLine(Invariant($"  - {input}"));
				}
			}

			builder.AppendLine(Invariant($"- **Caveat:** {recommendation.Caveat}"));
			builder.AppendLine();
		}
	}

	private static void AppendLimitations(StringBuilder builder, StorageBenchmarkReport report)
	{
		builder.AppendLine("## 5. Limitations");
		builder.AppendLine();
		foreach (string limitation in report.Limitations)
		{
			builder.AppendLine(Invariant($"- {limitation}"));
		}

		builder.AppendLine();
	}

	private static void AppendScope(StringBuilder builder)
	{
		builder.AppendLine("## 6. Scope — what this report is not");
		builder.AppendLine();
		builder.AppendLine("- Nothing here was applied. The recommendations are text; this tool has no code path that");
		builder.AppendLine("  writes appsettings.json, the registry or any live configuration.");
		builder.AppendLine("- The numbers come from a synthetic store this run created and deleted, not from the");
		builder.AppendLine("  production store, and the machine was not under production load while it ran.");
		builder.AppendLine("- This is not a substitute for watching the production service. It bounds what the hardware");
		builder.AppendLine("  can do; only production telemetry says what the store actually does under real ingestion,");
		builder.AppendLine("  real alert volume and real backup concurrency.");
		builder.AppendLine("- A recommendation to *lower* a limit is not a claim that the current value is unsafe: the");
		builder.AppendLine("  supported bounds in the product remain the authority on safety.");
		builder.AppendLine();
		builder.AppendLine("To apply a recommendation, edit `appsettings.json` yourself, restart the service and watch the");
		builder.AppendLine("retention and backup telemetry afterwards. See `docs/92-storage-benchmarks-and-tuning.md`.");
		builder.AppendLine();
	}

	// ── Serialization ────────────────────────────────────────────────────────────

	/// <summary>Serializes the report as indented JSON with camel-case names and enums as strings.</summary>
	public static string BuildJson(StorageBenchmarkReport report)
	{
		ArgumentNullException.ThrowIfNull(report);
		return JsonSerializer.Serialize(report, ReportJsonOptions);
	}

	/// <summary>Deserializes a document produced by <see cref="BuildJson"/>.</summary>
	public static StorageBenchmarkReport? ParseJson(string json)
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(json);
		return JsonSerializer.Deserialize<StorageBenchmarkReport>(json, ReportJsonOptions);
	}

	/// <summary>
	/// Builds the settings fragment: the recommended configuration settings only, nested the way
	/// appsettings.json nests them. Operational advice and text-form rules are excluded, because a
	/// fragment an operator may paste must contain nothing but real settings. The leading underscore
	/// keys are provenance notes; the configuration binder ignores keys it does not know, and they can
	/// be deleted before merging.
	/// </summary>
	public static string BuildRecommendedSettingsJson(StorageBenchmarkReport report)
	{
		ArgumentNullException.ThrowIfNull(report);

		Dictionary<string, object> root = new(StringComparer.Ordinal)
		{
			["_notice"] = "Recommended values measured by RdpAudit.StorageBenchmarks on this machine. NOT applied automatically: merge the RdpAudit object into appsettings.json by hand, then restart the service and watch the retention and backup telemetry. Delete the underscore keys when merging.",
			["_generatedUtc"] = report.GeneratedUtc.ToString("O", CultureInfo.InvariantCulture),
			["_profile"] = report.ProfileName,
			["_reportSchema"] = report.SchemaVersion,
		};

		int applied = 0;
		foreach (TuningRecommendation recommendation in report.Recommendations)
		{
			if (!recommendation.IsConfigurationSetting
				|| recommendation.State != RecommendationState.Recommended
				|| recommendation.Value is not { } value)
			{
				continue;
			}

			InsertSetting(root, recommendation.Parameter, value);
			applied++;
		}

		if (applied == 0)
		{
			root["_empty"] = "This run produced no configuration recommendations: every rule either lacked its measured input or declined. The report explains which.";
		}

		return JsonSerializer.Serialize(root, SettingsJsonOptions);
	}

	/// <summary>Inserts <paramref name="value"/> at the dotted path (colon-separated, e.g.
	/// <c>RdpAudit:Storage:RetentionPolicy:DeleteBatchRows</c>), creating intermediate objects.</summary>
	private static void InsertSetting(Dictionary<string, object> root, string parameter, long value)
	{
		string[] segments = parameter.Split(':', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
		if (segments.Length == 0)
		{
			return;
		}

		Dictionary<string, object> current = root;
		for (int index = 0; index < segments.Length - 1; index++)
		{
			string segment = segments[index];
			if (current.TryGetValue(segment, out object? existing) && existing is Dictionary<string, object> child)
			{
				current = child;
				continue;
			}

			Dictionary<string, object> created = new(StringComparer.Ordinal);
			current[segment] = created;
			current = created;
		}

		current[segments[^1]] = value;
	}

	// ── File output ──────────────────────────────────────────────────────────────

	/// <summary>Writes the Markdown report into <paramref name="directory"/> and returns its path.</summary>
	public static string WriteMarkdown(StorageBenchmarkReport report, string directory)
		=> WriteText(directory, MarkdownFileName, BuildMarkdown(report));

	/// <summary>Writes the JSON report into <paramref name="directory"/> and returns its path.</summary>
	public static string WriteJson(StorageBenchmarkReport report, string directory)
		=> WriteText(directory, JsonFileName, BuildJson(report));

	/// <summary>Writes the settings fragment into <paramref name="directory"/> and returns its path.</summary>
	public static string WriteRecommendedSettings(StorageBenchmarkReport report, string directory)
		=> WriteText(directory, RecommendedSettingsFileName, BuildRecommendedSettingsJson(report));

	/// <summary>Writes all three artifacts and returns their paths in report, JSON, settings order.</summary>
	public static IReadOnlyList<string> WriteAll(StorageBenchmarkReport report, string directory)
	{
		ArgumentNullException.ThrowIfNull(report);
		return
		[
			WriteMarkdown(report, directory),
			WriteJson(report, directory),
			WriteRecommendedSettings(report, directory),
		];
	}

	private static string WriteText(string directory, string fileName, string content)
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(directory);
		string fullDirectory = Path.GetFullPath(directory);
		Directory.CreateDirectory(fullDirectory);
		string path = Path.Combine(fullDirectory, fileName);
		File.WriteAllText(path, content);
		return path;
	}

	// ── Formatting helpers ───────────────────────────────────────────────────────

	private static string FormatValue(double? value)
		=> value is { } number ? number.ToString("#,0.###", CultureInfo.InvariantCulture) : "—";

	private static string FormatValue(long? value)
		=> value is { } number ? number.ToString("N0", CultureInfo.InvariantCulture) : "—";

	private static void AppendRow(StringBuilder builder, string fact, string value)
		=> builder.AppendLine(Invariant($"| {Cell(fact)} | {Cell(value)} |"));

	/// <summary>Escapes a value for a Markdown table cell so a stray pipe cannot shift the columns.</summary>
	private static string Cell(string text)
		=> text.Replace("|", "\\|", StringComparison.Ordinal)
			.Replace("\r", " ", StringComparison.Ordinal)
			.Replace("\n", " ", StringComparison.Ordinal);

	private static string Invariant(FormattableString text)
		=> text.ToString(CultureInfo.InvariantCulture);
}
