/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.2
// File   : MachineProfileProbe.cs
// Project: RdpAudit.StorageBenchmarks
// Purpose: Collects the machine profile a report opens with, and measures the store volume: its type, its
//          capacity and the latency of a small write that has actually been flushed to the device.
//          The write probe is deliberately a flushed write rather than a buffered one. A buffered write
//          measures the page cache, which every machine wins; a write followed by FlushFileBuffers measures
//          the device, which is the thing a store's throughput actually depends on. The solid-state verdict
//          is taken from the hardware query when the platform answers it and only falls back to an
//          inference from that measurement - labelled as an inference, because a measured latency is
//          evidence about behaviour, not a fact about the device.
// Depends: WindowsFacts, SqliteBenchmarkFacts
// Extends: Add a volume fact by measuring it here; never report a fact this probe did not obtain.

using System.Globalization;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using RdpAudit.Core.Diagnostics;

namespace RdpAudit.StorageBenchmarks;

/// <summary>What the volume probe measured.</summary>
internal sealed record VolumeProbeResult
{
	/// <summary>Latency of one small flushed write.</summary>
	public required BenchmarkMeasurement WriteLatency { get; init; }

	/// <summary>Flushed small writes per second.</summary>
	public required BenchmarkMeasurement WriteIops { get; init; }

	/// <summary>The volume profile, with the media verdict this probe settled on.</summary>
	public required StoreVolumeProfile Volume { get; init; }

	/// <summary>Facts this probe could not establish, to be appended to the profile's own list.</summary>
	public required IReadOnlyList<string> Unknowns { get; init; }
}

/// <summary>Builds the machine profile and probes the store volume.</summary>
[SupportedOSPlatform("windows")]
internal static class MachineProfileProbe
{
	/// <summary>Flushed writes one sample performs. Sized so a sample is long enough to average out timer
	/// resolution and short enough that the probe does not dominate the run.</summary>
	public const int WritesPerSample = 256;

	/// <summary>Bytes per probe write: one small write, the shape an event insert has.</summary>
	public const int ProbeWriteBytes = 4096;

	/// <summary>Flushed-write latency below which the volume is inferred to be solid state. A rotational
	/// disk needs a head seek and a rotational delay for every flushed write, which puts it far above this;
	/// solid state devices land far below it. Stated here because the inference has to be auditable.</summary>
	public const double SolidStateLatencyThresholdMs = 2.0;

	/// <summary>Builds the machine profile for the volume hosting <paramref name="storePath"/>.</summary>
	public static MachineProfile BuildProfile(string storePath)
	{
		ArgumentNullException.ThrowIfNullOrWhiteSpace(storePath);
		List<string> unknowns = [];

		string productName = WindowsFacts.TryReadProductName(out string name) ? name : "unknown";
		if (productName == "unknown")
		{
			unknowns.Add("operating system product name: the registry key is unreadable");
		}

		string build = WindowsFacts.ReadBuildNumber();
		string release = WindowsFacts.ReadReleaseName();
		if (string.IsNullOrEmpty(build))
		{
			unknowns.Add("operating system build number: the registry key is unreadable");
		}

		if (string.IsNullOrEmpty(release))
		{
			release = "unknown";
		}

		string processorName = WindowsFacts.TryReadProcessorName(out string processor) ? processor : "unknown";
		if (processorName == "unknown")
		{
			unknowns.Add("processor model: neither the registry key nor PROCESSOR_IDENTIFIER was readable");
		}

		long memory = 0L;
		if (!WindowsFacts.TryReadPhysicalMemoryBytes(out memory))
		{
			unknowns.Add("installed physical memory: neither GlobalMemoryStatusEx nor the runtime reported a figure");
		}

		StoreVolumeProfile volume = BuildVolumeProfile(storePath, unknowns, SsdEvidence.Unknown("not queried yet"));

		return new MachineProfile
		{
			OperatingSystem = productName,
			OperatingSystemVersion = string.Format(
				CultureInfo.InvariantCulture,
				"{0} (build {1})",
				Environment.OSVersion.Version.ToString(),
				string.IsNullOrEmpty(build) ? "unknown" : build),
			OperatingSystemRelease = release,
			Architecture = RuntimeInformation.ProcessArchitecture.ToString(),
			DotNetVersion = RuntimeInformation.FrameworkDescription,
			ProcessorName = processorName,
			ProcessorCount = Environment.ProcessorCount,
			TotalPhysicalMemoryBytes = memory,
			IsElevated = WindowsFacts.IsElevated(),
			StoreVolume = volume,
			Unknowns = unknowns,
		};
	}

	/// <summary>Measures the store volume and settles the media verdict.</summary>
	public static async Task<VolumeProbeResult> MeasureVolumeAsync(
		string storePath,
		MachineProfile profile,
		BenchmarkSampleRecorder latencyRecorder,
		CancellationToken cancellationToken)
	{
		ArgumentNullException.ThrowIfNull(profile);
		ArgumentNullException.ThrowIfNull(latencyRecorder);

		string probePath = Path.Combine(Path.GetDirectoryName(storePath) ?? storePath, "volume-probe.bin");

		BenchmarkSampleRun<double> latency = await latencyRecorder.MeasureAsync(
			StorageBenchmarkMetric.VolumeWriteLatencyMs,
			StorageBenchmarkUnit.Milliseconds,
			(_, token) => Task.Run(() => MeasureWriteLatency(probePath, token), token),
			static result => result,
			string.Format(
				CultureInfo.InvariantCulture,
				"each sample is the mean latency of {0} writes of {1} bytes, each followed by a flush to the device",
				WritesPerSample,
				ProbeWriteBytes),
			cancellationToken).ConfigureAwait(false);

		TryDelete(probePath);

		BenchmarkMeasurement iops = latency.Measurement.State == MeasurementState.Measured
			? BenchmarkMeasurement.FromSamples(
				StorageBenchmarkMetric.VolumeWriteIops,
				StorageBenchmarkUnit.OperationsPerSecond,
				BenchmarkSampleSet.FromValues(
					[.. latency.Runs.Select(static ms => ms > 0d ? 1000d / ms : 0d)],
					latencyRecorder.WarmupRuns),
				"flushed writes per second, derived from the measured mean latency of one flushed write")
			: BenchmarkMeasurement.NotMeasured(
				StorageBenchmarkMetric.VolumeWriteIops,
				StorageBenchmarkUnit.OperationsPerSecond,
				"the write-latency probe did not complete");

		List<string> extraUnknowns = [];
		SsdEvidence ssd = ResolveSsdEvidence(profile.StoreVolume.RootPath, latency.Measurement, extraUnknowns);
		StoreVolumeProfile volume = profile.StoreVolume with { Ssd = ssd };

		return new VolumeProbeResult
		{
			WriteLatency = latency.Measurement,
			WriteIops = iops,
			Volume = volume,
			Unknowns = extraUnknowns,
		};
	}

	/// <summary>Reads the volume facts for the volume hosting <paramref name="storePath"/>.</summary>
	public static StoreVolumeProfile BuildVolumeProfile(string storePath, List<string> unknowns, SsdEvidence ssd)
	{
		ArgumentNullException.ThrowIfNull(unknowns);
		string full = Path.GetFullPath(storePath);
		string root = Path.GetPathRoot(full) ?? string.Empty;

		string driveType = "unknown";
		string fileSystem = "unknown";
		long totalBytes = 0L;
		long freeBytes = 0L;

		try
		{
			DriveInfo drive = new(root);
			driveType = drive.DriveType.ToString();
			if (drive.IsReady)
			{
				fileSystem = drive.DriveFormat;
				totalBytes = drive.TotalSize;
				freeBytes = drive.AvailableFreeSpace;
			}
			else
			{
				unknowns.Add(string.Format(CultureInfo.InvariantCulture, "store volume {0} is not ready; capacity and filesystem are unknown", root));
			}
		}
		catch (IOException ex)
		{
			unknowns.Add("store volume capacity: " + ex.Message);
		}
		catch (ArgumentException ex)
		{
			unknowns.Add("store volume capacity: " + ex.Message);
		}
		catch (UnauthorizedAccessException ex)
		{
			unknowns.Add("store volume capacity: " + ex.Message);
		}

		return new StoreVolumeProfile
		{
			StorePath = full,
			RootPath = root,
			DriveType = driveType,
			FileSystem = fileSystem,
			TotalBytes = totalBytes,
			FreeBytes = freeBytes,
			IsSystemVolume = IsSystemVolume(root),
			Ssd = ssd,
		};
	}

	/// <summary>Re-reads the volume's capacity and free space, so the report sizes its recommendations
	/// against the space that is actually left once the store exists at its measured size.</summary>
	public static StoreVolumeProfile RefreshFreeSpace(StoreVolumeProfile volume)
	{
		ArgumentNullException.ThrowIfNull(volume);
		try
		{
			DriveInfo drive = new(volume.RootPath);
			return drive.IsReady
				? volume with { TotalBytes = drive.TotalSize, FreeBytes = drive.AvailableFreeSpace, FileSystem = drive.DriveFormat }
				: volume;
		}
		catch (IOException)
		{
			return volume;
		}
		catch (ArgumentException)
		{
			return volume;
		}
		catch (UnauthorizedAccessException)
		{
			return volume;
		}
	}

	/// <summary>True when <paramref name="root"/> is the volume Windows itself is installed on.</summary>
	public static bool IsSystemVolume(string root)
	{
		if (string.IsNullOrEmpty(root))
		{
			return false;
		}

		string windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
		string systemRoot = string.IsNullOrEmpty(windows) ? string.Empty : Path.GetPathRoot(windows) ?? string.Empty;
		return string.Equals(root, systemRoot, StringComparison.OrdinalIgnoreCase);
	}

	private static SsdEvidence ResolveSsdEvidence(string volumeRoot, BenchmarkMeasurement latency, List<string> unknowns)
	{
		SsdEvidence hardware = WindowsFacts.TryReadSsdEvidence(volumeRoot);
		if (hardware.Source == SsdEvidenceSource.HardwareQuery)
		{
			return hardware;
		}

		unknowns.Add("store volume media type: " + hardware.Detail);
		if (latency.State != MeasurementState.Measured || latency.Samples is not { } samples)
		{
			return hardware;
		}

		double median = samples.Median;
		bool solid = median < SolidStateLatencyThresholdMs;
		return new SsdEvidence
		{
			Source = SsdEvidenceSource.WriteLatencyInference,
			IsSolidState = solid,
			Detail = string.Format(
				CultureInfo.InvariantCulture,
				"the hardware query did not answer ({0}), so the media type is inferred from the measured median flushed-write latency of {1:0.###} ms against the {2:0.###} ms threshold: this volume behaves like {3} storage",
				hardware.Detail,
				median,
				SolidStateLatencyThresholdMs,
				solid ? "solid state" : "rotational"),
		};
	}

	private static double MeasureWriteLatency(string probePath, CancellationToken cancellationToken)
	{
		using FileStream stream = new(probePath, FileMode.Create, FileAccess.Write, FileShare.None, ProbeWriteBytes, FileOptions.WriteThrough);
		byte[] payload = new byte[ProbeWriteBytes];
		long startTicks = 0;
		for (int index = 0; index < WritesPerSample; index++)
		{
			cancellationToken.ThrowIfCancellationRequested();
			stream.Position = 0;
			stream.Write(payload, 0, payload.Length);
			stream.Flush(flushToDisk: true);
			if (index == 0)
			{
				startTicks = System.Diagnostics.Stopwatch.GetTimestamp();
			}
		}

		double elapsedMs = (System.Diagnostics.Stopwatch.GetTimestamp() - startTicks)
			* 1000d
			/ System.Diagnostics.Stopwatch.Frequency;
		return elapsedMs / (WritesPerSample - 1);
	}

	private static void TryDelete(string path)
	{
		try
		{
			if (File.Exists(path))
			{
				File.Delete(path);
			}
		}
		catch (IOException)
		{
			// The probe file lives next to the benchmark store and is removed with it.
		}
		catch (UnauthorizedAccessException)
		{
			// Same rationale as above.
		}
	}
}
