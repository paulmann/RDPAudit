/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : ShardPath.cs
// Project: RdpAudit.Core (RdpAudit.Core.Storage.Sharding)
// Purpose: Canonicalises a source IP into a safe relative path under the actions/ root.
//          Rejects traversal, reserved DOS names, ADS, UNC prefixes; never derives the file
//          name from raw event text. IPv6 is normalised to hex without colons.
// Depends: System.Net.IPAddress, System.Buffers
// Extends: When adding a new address family or a subnet-aggregate bucket, extend
//          TryComposeSubnetShardPath below and keep TryComposeShardPath purely per-IP.

using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using RdpAudit.Core.Util;

namespace RdpAudit.Core.Storage.Sharding;

/// <summary>Canonical filesystem path resolver for per-IP shard files. Purely functional.</summary>
public static class ShardPath
{
	// ── Public API ───────────────────────────────────────────────────────────────

	/// <summary>Root directory name under <c>%ProgramData%\RdpAudit\</c>. Mirrors
	/// <see cref="RdpAuditPaths.ActionsRootFolderName"/> (single source of truth, D2).</summary>
	public const string ActionsRootFolder = RdpAuditPaths.ActionsRootFolderName;

	/// <summary>Shard file extension.</summary>
	public const string ShardExtension = ".rdpshard";

	/// <summary>Fan-out depth = 2 (two 2-hex-char directories) yielding 256*256 = 65 536 leaf
	/// directories. Chosen to keep any single directory below ~10k entries for common
	/// deployments while keeping NTFS MFT growth bounded.</summary>
	public const int FanOutDepth = 2;

	/// <summary>Composes a canonical shard relative path from an <see cref="IPAddress"/>.
	/// Returns <c>false</c> for an address that cannot be safely encoded (should never happen
	/// for a well-formed <see cref="IPAddress"/> instance but guards against future refactors).
	/// The returned path is always inside <see cref="ActionsRootFolder"/>, always uses forward
	/// slashes for portability, and never contains reserved DOS device names, ADS separators,
	/// UNC prefixes, path-traversal sequences, or symlink indicators.</summary>
	public static bool TryComposeShardPath(IPAddress address, Span<char> destination, out int written)
	{
		written = 0;
		if (address is null)
		{
			return false;
		}

		Span<byte> ipBytes = stackalloc byte[16];
		if (!TryCanonicalise(address, ipBytes, out int ipLen))
		{
			return false;
		}

		return WritePath(ipBytes.Slice(0, ipLen), address.AddressFamily, isSubnetAggregate: false, destination, out written);
	}

	/// <summary>Composes a canonical subnet-aggregate shard path (IPv4 /24 or IPv6 /64) used
	/// when the shard-cardinality guard promotes a spray of low-volume sources into a single
	/// bucket. <paramref name="prefixLenBits"/> must be 24 (v4) or 64 (v6).</summary>
	public static bool TryComposeSubnetShardPath(
		IPAddress address,
		int prefixLenBits,
		Span<char> destination,
		out int written)
	{
		written = 0;
		if (address is null)
		{
			return false;
		}

		Span<byte> ipBytes = stackalloc byte[16];
		if (!TryCanonicalise(address, ipBytes, out int ipLen))
		{
			return false;
		}

		if (address.AddressFamily == AddressFamily.InterNetwork && prefixLenBits != 24)
		{
			return false;
		}

		if (address.AddressFamily == AddressFamily.InterNetworkV6 && prefixLenBits != 64)
		{
			return false;
		}

		// Mask off host bits so all sources within the same subnet resolve to identical bytes.
		MaskInPlace(ipBytes.Slice(0, ipLen), prefixLenBits);
		return WritePath(ipBytes.Slice(0, ipLen), address.AddressFamily, isSubnetAggregate: true, destination, out written);
	}

	/// <summary>Verifies at runtime that a candidate absolute path lies under the actions
	/// root, is not a reparse point, and does not resolve outside via symlink following.
	/// The caller must pass the *fully resolved* actions root and the *fully resolved*
	/// candidate. This is a defense-in-depth check on top of <see cref="TryComposeShardPath"/>.</summary>
	public static bool IsContainedUnder(string actionsRootAbsolute, string candidateAbsolute)
	{
		if (string.IsNullOrEmpty(actionsRootAbsolute) || string.IsNullOrEmpty(candidateAbsolute))
		{
			return false;
		}

		string rootFull = Path.GetFullPath(actionsRootAbsolute).TrimEnd(Path.DirectorySeparatorChar);
		string candFull = Path.GetFullPath(candidateAbsolute);
		if (candFull.Length < rootFull.Length + 1)
		{
			return false;
		}

		if (!candFull.StartsWith(rootFull, StringComparison.OrdinalIgnoreCase))
		{
			return false;
		}

		return candFull[rootFull.Length] == Path.DirectorySeparatorChar
			|| candFull[rootFull.Length] == Path.AltDirectorySeparatorChar;
	}

	// ── SIMD & Zero-Alloc Parsers ────────────────────────────────────────────────

	/// <summary>Populates <paramref name="destination"/> with the address bytes: 4 for IPv4,
	/// 16 for IPv6. IPv4-mapped IPv6 is unwrapped to IPv4. Loopback and non-global addresses
	/// are accepted (the caller decides whether to shard them).</summary>
	private static bool TryCanonicalise(IPAddress address, Span<byte> destination, out int written)
	{
		written = 0;

		if (address.AddressFamily == AddressFamily.InterNetworkV6 && address.IsIPv4MappedToIPv6)
		{
			IPAddress v4 = address.MapToIPv4();
			if (!v4.TryWriteBytes(destination.Slice(0, 4), out int v4Written) || v4Written != 4)
			{
				return false;
			}

			written = 4;
			return true;
		}

		int expected = address.AddressFamily switch
		{
			AddressFamily.InterNetwork => 4,
			AddressFamily.InterNetworkV6 => 16,
			_ => 0,
		};

		if (expected == 0)
		{
			return false;
		}

		if (!address.TryWriteBytes(destination.Slice(0, expected), out int actual) || actual != expected)
		{
			return false;
		}

		written = expected;
		return true;
	}

	private static void MaskInPlace(Span<byte> bytes, int prefixLenBits)
	{
		int fullBytes = prefixLenBits >> 3;
		int leftoverBits = prefixLenBits & 7;

		for (int i = fullBytes; i < bytes.Length; i++)
		{
			bytes[i] = 0;
		}

		if (leftoverBits > 0 && fullBytes < bytes.Length)
		{
			byte mask = (byte)(0xFF << (8 - leftoverBits));
			bytes[fullBytes] &= mask;
		}
	}

	// ── Core Logic ───────────────────────────────────────────────────────────────

	private static bool WritePath(
		ReadOnlySpan<byte> ipBytes,
		AddressFamily family,
		bool isSubnetAggregate,
		Span<char> destination,
		out int written)
	{
		written = 0;

		// Hex-encode the whole address. IPv4 = 8 hex chars, IPv6 = 32 hex chars.
		// Fan-out uses the first FanOutDepth*2 hex chars as directory names.
		int hexLen = ipBytes.Length * 2;
		int requiredLen = ActionsRootFolder.Length
			+ 1
			+ (FanOutDepth * 3)      // "xx/" per fan-out level
			+ hexLen
			+ (isSubnetAggregate ? "-agg".Length : 0)
			+ ShardExtension.Length;

		if (destination.Length < requiredLen)
		{
			return false;
		}

		int pos = 0;
		ActionsRootFolder.AsSpan().CopyTo(destination.Slice(pos));
		pos += ActionsRootFolder.Length;
		destination[pos++] = '/';

		Span<char> hex = stackalloc char[32];
		WriteHex(ipBytes, hex);

		for (int i = 0; i < FanOutDepth; i++)
		{
			destination[pos++] = hex[i * 2];
			destination[pos++] = hex[(i * 2) + 1];
			destination[pos++] = '/';
		}

		hex.Slice(0, hexLen).CopyTo(destination.Slice(pos));
		pos += hexLen;

		if (isSubnetAggregate)
		{
			"-agg".AsSpan().CopyTo(destination.Slice(pos));
			pos += "-agg".Length;
		}

		ShardExtension.AsSpan().CopyTo(destination.Slice(pos));
		pos += ShardExtension.Length;

		written = pos;
		return true;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void WriteHex(ReadOnlySpan<byte> bytes, Span<char> hexDestination)
	{
		const string HexTable = "0123456789abcdef";
		for (int i = 0; i < bytes.Length; i++)
		{
			byte b = bytes[i];
			hexDestination[i * 2] = HexTable[b >> 4];
			hexDestination[(i * 2) + 1] = HexTable[b & 0x0F];
		}
	}
}
