/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.2
// File   : MachineProfile.cs
// Project: RdpAudit.Core (RdpAudit.Core.Diagnostics)
// Purpose: The machine a storage benchmark ran on, as data. Numbers without the host that produced
//          them cannot be compared or acted on, so every report opens with this profile. The type is
//          deliberately collection-free: the runner collects the facts (registry, Windows API,
//          DriveInfo) and this type only carries them, which keeps the report writer and the
//          recommendation engine free of any platform call. Anything that could not be collected is
//          reported as unknown and named in Unknowns rather than guessed.
// Depends: System.Globalization
// Extends: Add a collected fact as a property plus an entry in the runner's collector; never make the
//          report fail because one fact was unavailable.

namespace RdpAudit.Core.Diagnostics;

/// <summary>How solid-state evidence about the store volume was obtained.</summary>
public enum SsdEvidenceSource
{
	/// <summary>No evidence could be collected; the volume's media type is unknown.</summary>
	Unknown = 0,

	/// <summary>The volume's physical disk was queried for its seek-penalty property, which is the
	/// authoritative answer.</summary>
	HardwareQuery = 1,

	/// <summary>The media type was inferred from the measured latency of small flushed writes. This is
	/// an inference from a measurement, not a hardware fact, and is labelled as such.</summary>
	WriteLatencyInference = 2,
}

/// <summary>What is known about whether the store volume is solid state, and how it is known.</summary>
public sealed record SsdEvidence
{
	/// <summary>How the conclusion was reached.</summary>
	public required SsdEvidenceSource Source { get; init; }

	/// <summary>True when the volume is solid state, false when it is not, null when unknown.</summary>
	public bool? IsSolidState { get; init; }

	/// <summary>Human-readable explanation, including the raw property value or measured latency the
	/// conclusion rests on.</summary>
	public required string Detail { get; init; }

	/// <summary>Builds the "nothing could be determined" evidence.</summary>
	public static SsdEvidence Unknown(string detail)
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(detail);
		return new SsdEvidence { Source = SsdEvidenceSource.Unknown, IsSolidState = null, Detail = detail };
	}
}

/// <summary>The volume that hosts the benchmark store.</summary>
public sealed record StoreVolumeProfile
{
	/// <summary>Absolute path of the benchmark store.</summary>
	public required string StorePath { get; init; }

	/// <summary>Volume root, e.g. <c>C:\</c>.</summary>
	public required string RootPath { get; init; }

	/// <summary>Drive type as reported by the platform (<c>Fixed</c>, <c>Removable</c>,
	/// <c>Network</c>, <c>NoRootDirectory</c>, <c>Unknown</c>).</summary>
	public required string DriveType { get; init; }

	/// <summary>Filesystem name, e.g. <c>NTFS</c>; <c>unknown</c> when the volume is not ready.</summary>
	public required string FileSystem { get; init; }

	/// <summary>Total bytes of the volume; zero when the volume could not be inspected.</summary>
	public required long TotalBytes { get; init; }

	/// <summary>Free bytes available to this process; zero when the volume could not be inspected.</summary>
	public required long FreeBytes { get; init; }

	/// <summary>True when the store volume is the volume Windows itself is installed on.</summary>
	public required bool IsSystemVolume { get; init; }

	/// <summary>Solid-state evidence for the volume.</summary>
	public required SsdEvidence Ssd { get; init; }
}

/// <summary>
/// The host a storage benchmark ran on, plus what could not be determined about it.
/// </summary>
public sealed record MachineProfile
{
	/// <summary>Operating system description, e.g. <c>Microsoft Windows 11 Pro</c>.</summary>
	public required string OperatingSystem { get; init; }

	/// <summary>Operating system version and build, e.g. <c>10.0.26200</c>.</summary>
	public required string OperatingSystemVersion { get; init; }

	/// <summary>Marketing release name when the registry carries one (e.g. <c>24H2</c>), otherwise
	/// <c>unknown</c>.</summary>
	public required string OperatingSystemRelease { get; init; }

	/// <summary>Process architecture, e.g. <c>X64</c>.</summary>
	public required string Architecture { get; init; }

	/// <summary>.NET runtime version the benchmark executed on.</summary>
	public required string DotNetVersion { get; init; }

	/// <summary>Processor model string; <c>unknown</c> when the registry key is unreadable.</summary>
	public required string ProcessorName { get; init; }

	/// <summary>Logical processor count visible to the process.</summary>
	public required int ProcessorCount { get; init; }

	/// <summary>Installed physical memory in bytes; zero when it could not be read.</summary>
	public required long TotalPhysicalMemoryBytes { get; init; }

	/// <summary>True when the benchmark process held an elevated token. The runner is designed to need
	/// no elevation, so the report states which of the two it actually was.</summary>
	public required bool IsElevated { get; init; }

	/// <summary>The volume hosting the benchmark store.</summary>
	public required StoreVolumeProfile StoreVolume { get; init; }

	/// <summary>Facts that could not be collected, one line each. Empty when the profile is complete.</summary>
	public required IReadOnlyList<string> Unknowns { get; init; }
}
