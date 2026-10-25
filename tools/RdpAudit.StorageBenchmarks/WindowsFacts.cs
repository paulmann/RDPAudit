/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.2
// File   : WindowsFacts.cs
// Project: RdpAudit.StorageBenchmarks
// Purpose: The platform facts a machine profile needs, collected without administrator rights and
//          without assuming any of them can be collected. Every read is independently guarded: a host
//          where an API is unavailable or a registry key is missing yields "unknown" for that one fact
//          rather than a failed run or a plausible-looking substitute. The media-type question is the
//          only one that needs a device IOCTL, and it is the authoritative answer where it works - the
//          volume's physical disk is asked whether it incurs a seek penalty, which is what separates
//          solid state from rotational without guessing from a model string.
// Depends: kernel32 (LibraryImport), Microsoft.Win32.Registry
// Extends: Add a fact as a Try* method returning false when it cannot be read; never let a fact throw
//          into a report.

using System.Globalization;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;
using RdpAudit.Core.Diagnostics;

namespace RdpAudit.StorageBenchmarks;

/// <summary>Operating-system, processor, memory and media facts, collected defensively.</summary>
[SupportedOSPlatform("windows")]
internal static partial class WindowsFacts
{
	private const string WindowsVersionKey = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion";
	private const string ProcessorKey = @"HARDWARE\DESCRIPTION\System\CentralProcessor\0";

	/// <summary>Windows 11 starts at this build number; the registry's ProductName still says "Windows 10"
	/// on those hosts, so the reported name is corrected against the build number the same way Microsoft
	/// documents the boundary.</summary>
	private const int Windows11FirstBuild = 22000;

	private const uint FileReadAttributes = 0x0000_0080;
	private const uint OpenExisting = 3;
	private const uint ShareReadWrite = 0x0000_0003;
	private const uint IoctlVolumeGetVolumeDiskExtents = 0x0056_0000;
	private const uint IoctlStorageQueryProperty = 0x002D_1400;
	private const uint StorageDeviceSeekPenaltyProperty = 7;
	private const uint PropertyStandardQuery = 0;

	/// <summary>Bytes of <c>DEVICE_SEEK_PENALTY_DESCRIPTOR</c> the query must return to be believed.</summary>
	private const uint SeekPenaltyDescriptorBytes = 9;

	/// <summary>Offset of the <c>IncursSeekPenalty</c> flag inside <c>DEVICE_SEEK_PENALTY_DESCRIPTOR</c>,
	/// after the two <c>ULONG</c> members the structure declares first.</summary>
	private const int SeekPenaltyDescriptorFlagOffset = 8;

	/// <summary>Reads the marketing product name, corrected for the Windows 11 boundary. Returns false
	/// when the key is unreadable.</summary>
	public static bool TryReadProductName(out string productName)
	{
		productName = string.Empty;
		if (!TryReadRegistry(WindowsVersionKey, "ProductName", out string raw) || string.IsNullOrWhiteSpace(raw))
		{
			return false;
		}

		if (raw.StartsWith("Windows 10", StringComparison.OrdinalIgnoreCase)
			&& TryReadRegistry(WindowsVersionKey, "CurrentBuildNumber", out string buildText)
			&& int.TryParse(buildText, NumberStyles.None, CultureInfo.InvariantCulture, out int build)
			&& build >= Windows11FirstBuild)
		{
			productName = "Windows 11" + raw["Windows 10".Length..];
			return true;
		}

		productName = raw;
		return true;
	}

	/// <summary>Reads the release name a host carries in the registry, or the empty string.</summary>
	public static string ReadReleaseName()
	{
		if (TryReadRegistry(WindowsVersionKey, "DisplayVersion", out string display) && !string.IsNullOrWhiteSpace(display))
		{
			return display;
		}

		return TryReadRegistry(WindowsVersionKey, "ReleaseId", out string releaseId) ? releaseId : string.Empty;
	}

	/// <summary>Reads the operating-system build number, or the empty string.</summary>
	public static string ReadBuildNumber()
		=> TryReadRegistry(WindowsVersionKey, "CurrentBuildNumber", out string build) ? build : string.Empty;

	/// <summary>Reads the processor model string, with the environment identifier as a fallback.</summary>
	public static bool TryReadProcessorName(out string processorName)
	{
		if (TryReadRegistry(ProcessorKey, "ProcessorNameString", out string fromRegistry) && !string.IsNullOrWhiteSpace(fromRegistry))
		{
			processorName = fromRegistry.Trim();
			return true;
		}

		processorName = Environment.GetEnvironmentVariable("PROCESSOR_IDENTIFIER") ?? string.Empty;
		return !string.IsNullOrWhiteSpace(processorName);
	}

	/// <summary>Reads installed physical memory through the platform API, falling back to the runtime's
	/// own view of the memory available to the process.</summary>
	public static bool TryReadPhysicalMemoryBytes(out long bytes)
	{
		bytes = 0L;
		try
		{
			MemoryStatusEx status = default;
			status.Length = (uint)Marshal.SizeOf<MemoryStatusEx>();
			if (GlobalMemoryStatusEx(ref status) && status.TotalPhys > 0)
			{
				bytes = (long)status.TotalPhys;
				return true;
			}
		}
		catch (DllNotFoundException)
		{
			// Fall through to the runtime's own figure.
		}
		catch (EntryPointNotFoundException)
		{
			// Fall through to the runtime's own figure.
		}

		long available = GC.GetGCMemoryInfo().TotalAvailableMemoryBytes;
		if (available > 0)
		{
			bytes = available;
			return true;
		}

		return false;
	}

	/// <summary>True when the current process holds an elevated token.</summary>
	public static bool IsElevated()
	{
		try
		{
			using WindowsIdentity identity = WindowsIdentity.GetCurrent();
			return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
		}
		catch (UnauthorizedAccessException)
		{
			return false;
		}
		catch (InvalidOperationException)
		{
			return false;
		}
	}

	/// <summary>
	/// Asks the physical disk behind <paramref name="volumeRoot"/> whether it incurs a seek penalty - the
	/// authoritative solid-state signal. Returns <see cref="SsdEvidence.Unknown"/> with the reason when any
	/// step of the query is unavailable, which is expected on a locked-down host and is not an error.
	/// </summary>
	public static SsdEvidence TryReadSsdEvidence(string volumeRoot)
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(volumeRoot);

		string volumeDevice = @"\\.\" + volumeRoot.TrimEnd('\\');
		uint diskNumber;
		try
		{
			using SafeFileHandle volume = CreateFile(
				volumeDevice,
				FileReadAttributes,
				ShareReadWrite,
				0,
				OpenExisting,
				0,
				0);
			if (volume.IsInvalid)
			{
				return SsdEvidence.Unknown(string.Format(
					CultureInfo.InvariantCulture,
					"cannot open {0} to identify the physical disk (Win32 error {1})",
					volumeDevice,
					Marshal.GetLastWin32Error()));
			}

			if (!TryReadDiskNumber(volume, out diskNumber))
			{
				return SsdEvidence.Unknown(string.Format(
					CultureInfo.InvariantCulture,
					"the volume-to-disk query failed on {0} (Win32 error {1})",
					volumeDevice,
					Marshal.GetLastWin32Error()));
			}
		}
		catch (DllNotFoundException ex)
		{
			return SsdEvidence.Unknown("kernel32 is unavailable: " + ex.Message);
		}

		string diskDevice = @"\\.\PhysicalDrive" + diskNumber.ToString(CultureInfo.InvariantCulture);
		try
		{
			using SafeFileHandle disk = CreateFile(
				diskDevice,
				FileReadAttributes,
				ShareReadWrite,
				0,
				OpenExisting,
				0,
				0);
			if (disk.IsInvalid)
			{
				return SsdEvidence.Unknown(string.Format(
					CultureInfo.InvariantCulture,
					"cannot open {0} to query its media type (Win32 error {1})",
					diskDevice,
					Marshal.GetLastWin32Error()));
			}

			if (!TryReadSeekPenalty(disk, out bool incursSeekPenalty))
			{
				return SsdEvidence.Unknown(string.Format(
					CultureInfo.InvariantCulture,
					"the seek-penalty query failed on {0} (Win32 error {1})",
					diskDevice,
					Marshal.GetLastWin32Error()));
			}

			return new SsdEvidence
			{
				Source = SsdEvidenceSource.HardwareQuery,
				IsSolidState = !incursSeekPenalty,
				Detail = string.Format(
					CultureInfo.InvariantCulture,
					"{0} reports IncursSeekPenalty={1} for {2}, so this volume is {3}",
					diskDevice,
					incursSeekPenalty,
					volumeRoot,
					incursSeekPenalty ? "rotational" : "solid state"),
			};
		}
		catch (DllNotFoundException ex)
		{
			return SsdEvidence.Unknown("kernel32 is unavailable: " + ex.Message);
		}
	}

	private static unsafe bool TryReadDiskNumber(SafeFileHandle volume, out uint diskNumber)
	{
		diskNumber = 0;
		Span<byte> buffer = stackalloc byte[512];
		fixed (byte* output = buffer)
		{
			if (!DeviceIoControl(volume, IoctlVolumeGetVolumeDiskExtents, null, 0, output, (uint)buffer.Length, out uint returned, 0)
				|| returned < sizeof(uint) + 8)
			{
				return false;
			}

			// VOLUME_DISK_EXTENTS: DWORD NumberOfDiskExtents, then DISK_EXTENT { DWORD DiskNumber, LARGE_INTEGER, LARGE_INTEGER }.
			if (BitConverter.ToUInt32(buffer[..4]) == 0)
			{
				return false;
			}

			diskNumber = BitConverter.ToUInt32(buffer.Slice(4, 4));
			return true;
		}
	}

	private static unsafe bool TryReadSeekPenalty(SafeFileHandle disk, out bool incursSeekPenalty)
	{
		incursSeekPenalty = false;

		// STORAGE_PROPERTY_QUERY { PropertyId, QueryType, AdditionalParameters[1] }
		Span<byte> query = stackalloc byte[12];
		query.Clear();
		BitConverter.TryWriteBytes(query[..4], StorageDeviceSeekPenaltyProperty);
		BitConverter.TryWriteBytes(query.Slice(4, 4), PropertyStandardQuery);

		Span<byte> descriptor = stackalloc byte[16];
		fixed (byte* input = query)
		fixed (byte* output = descriptor)
		{
			if (!DeviceIoControl(disk, IoctlStorageQueryProperty, input, (uint)query.Length, output, (uint)descriptor.Length, out uint returned, 0)
				|| returned < SeekPenaltyDescriptorBytes)
			{
				return false;
			}
		}

		// DEVICE_SEEK_PENALTY_DESCRIPTOR is { ULONG Version; ULONG Size; BOOLEAN IncursSeekPenalty; }:
		// the flag is the THIRD member, at offset 8, and reading offset 0 would report the Version field
		// as the media type.
		incursSeekPenalty = descriptor[SeekPenaltyDescriptorFlagOffset] != 0;
		return true;
	}

	private static bool TryReadRegistry(string subKey, string valueName, out string value)
	{
		value = string.Empty;
		try
		{
			using RegistryKey? key = Registry.LocalMachine.OpenSubKey(subKey);
			if (key?.GetValue(valueName) is not { } raw)
			{
				return false;
			}

			value = Convert.ToString(raw, CultureInfo.InvariantCulture) ?? string.Empty;
			return !string.IsNullOrEmpty(value);
		}
		catch (System.Security.SecurityException)
		{
			return false;
		}
		catch (UnauthorizedAccessException)
		{
			return false;
		}
		catch (IOException)
		{
			return false;
		}
	}

	[StructLayout(LayoutKind.Sequential)]
	private struct MemoryStatusEx
	{
		public uint Length;
		public uint MemoryLoad;
		public ulong TotalPhys;
		public ulong AvailPhys;
		public ulong TotalPageFile;
		public ulong AvailPageFile;
		public ulong TotalVirtual;
		public ulong AvailVirtual;
		public ulong AvailExtendedVirtual;
	}

	[LibraryImport("kernel32.dll", SetLastError = true)]
	[return: MarshalAs(UnmanagedType.Bool)]
	private static partial bool GlobalMemoryStatusEx(ref MemoryStatusEx lpBuffer);

	[LibraryImport("kernel32.dll", EntryPoint = "CreateFileW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
	private static partial SafeFileHandle CreateFile(
		string lpFileName,
		uint dwDesiredAccess,
		uint dwShareMode,
		nint lpSecurityAttributes,
		uint dwCreationDisposition,
		uint dwFlagsAndAttributes,
		nint hTemplateFile);

	[LibraryImport("kernel32.dll", SetLastError = true)]
	[return: MarshalAs(UnmanagedType.Bool)]
	private static unsafe partial bool DeviceIoControl(
		SafeFileHandle hDevice,
		uint dwIoControlCode,
		byte* lpInBuffer,
		uint nInBufferSize,
		byte* lpOutBuffer,
		uint nOutBufferSize,
		out uint lpBytesReturned,
		nint lpOverlapped);
}
