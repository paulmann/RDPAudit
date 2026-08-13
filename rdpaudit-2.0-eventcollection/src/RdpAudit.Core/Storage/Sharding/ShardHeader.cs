/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : ShardHeader.cs
// Project: RdpAudit.Core (RdpAudit.Core.Storage.Sharding)
// Purpose: Double-buffered, CRC-validated shard file header. Torn-write survivable: a partial
//          crash during header flip is detected by CRC mismatch on the active copy, and the
//          reader falls back to the inactive copy.
// Depends: System.Buffers.Binary, System.IO.Hashing
// Extends: When adding a new metadata field, extend HeaderPayload, bump FormatVersion, and
//          keep the header size a multiple of 64 bytes to preserve cache alignment.

using System.Buffers.Binary;
using System.IO.Hashing;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace RdpAudit.Core.Storage.Sharding;

/// <summary>
/// Fixed-size, double-buffered shard file header. Layout on disk:
/// <code>
///   [ 0.. 63]  HeaderCopyA (payload 60 B + CRC32C 4 B)
///   [64..127]  HeaderCopyB (payload 60 B + CRC32C 4 B)
///   [128..]    Records region: N * ShardRecord.SizeBytes bytes, treated as a ring
///              whose head/tail live in the payload above.
/// </code>
/// On write, the writer flips between A and B: it writes the *inactive* copy first with the new
/// generation counter, fsyncs, then updates the active-copy pointer via an atomic 32-bit write.
/// The reader picks the copy whose CRC verifies AND whose Generation is highest.
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 1, Size = 64)]
public readonly struct HeaderCopy
{
	/// <summary>Payload bytes (60). Layout defined by <see cref="HeaderPayload"/>.</summary>
	public readonly HeaderPayload Payload;

	/// <summary>CRC32C over the 60-byte payload. Non-zero on write.</summary>
	public readonly uint Crc32C;

	public HeaderCopy(HeaderPayload payload, uint crc32c)
	{
		Payload = payload;
		Crc32C = crc32c;
	}
}

/// <summary>60-byte header payload. Fields are little-endian on disk.</summary>
[StructLayout(LayoutKind.Sequential, Pack = 1, Size = 60)]
public readonly struct HeaderPayload
{
	/// <summary>Magic value <c>"RDPS"</c> = 0x53504452 (little-endian).</summary>
	public readonly uint Magic;

	/// <summary>Shard format version; bump on any layout change.</summary>
	public readonly uint FormatVersion;

	/// <summary>Record size in bytes; must equal <see cref="ShardRecord.SizeBytes"/>.</summary>
	public readonly uint RecordSize;

	/// <summary>Ring capacity in records.</summary>
	public readonly uint Capacity;

	/// <summary>Head record index (oldest live record). 0..Capacity-1.</summary>
	public readonly uint Head;

	/// <summary>Tail record index (next write slot). 0..Capacity-1.</summary>
	public readonly uint Tail;

	/// <summary>Number of live records currently in the ring. 0..Capacity.</summary>
	public readonly uint Count;

	/// <summary>Monotonic generation counter bumped on every successful header flip.</summary>
	public readonly ulong Generation;

	/// <summary>Total events ever ingested for this shard (survives eviction).</summary>
	public readonly ulong TotalIngested;

	/// <summary>Total events evicted from this shard by ring overflow.</summary>
	public readonly ulong TotalEvicted;

	/// <summary>String heap size in bytes.</summary>
	public readonly uint HeapBytes;

	/// <summary>Reserved for future flags.</summary>
	public readonly uint Flags;

	public HeaderPayload(
		uint magic,
		uint formatVersion,
		uint recordSize,
		uint capacity,
		uint head,
		uint tail,
		uint count,
		ulong generation,
		ulong totalIngested,
		ulong totalEvicted,
		uint heapBytes,
		uint flags)
	{
		Magic = magic;
		FormatVersion = formatVersion;
		RecordSize = recordSize;
		Capacity = capacity;
		Head = head;
		Tail = tail;
		Count = count;
		Generation = generation;
		TotalIngested = totalIngested;
		TotalEvicted = totalEvicted;
		HeapBytes = heapBytes;
		Flags = flags;
	}
}

/// <summary>Static helpers for reading, validating, and writing shard headers.</summary>
public static class ShardHeader
{
	/// <summary>Magic constant "RDPS" as little-endian uint32.</summary>
	public const uint Magic = 0x53504452u;

	/// <summary>Current shard format version.</summary>
	public const uint CurrentFormatVersion = 1u;

	/// <summary>Size in bytes of the on-disk header region (two copies).</summary>
	public const int HeaderRegionBytes = 128;

	// ── Public API ───────────────────────────────────────────────────────────────

	/// <summary>Computes the CRC32C over a 60-byte payload view.</summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static uint ComputePayloadCrc(ReadOnlySpan<byte> payloadBytes)
		=> Crc32C.HashToUInt32(payloadBytes);

	/// <summary>Selects the valid header copy from the 128-byte header region. Returns
	/// <c>true</c> if at least one copy is valid; the caller receives the more recent one.</summary>
	public static bool TrySelectValidCopy(ReadOnlySpan<byte> headerRegion, out HeaderPayload payload)
	{
		payload = default;
		if (headerRegion.Length < HeaderRegionBytes)
		{
			return false;
		}

		ReadOnlySpan<byte> aBytes = headerRegion.Slice(0, 64);
		ReadOnlySpan<byte> bBytes = headerRegion.Slice(64, 64);

		bool aValid = TryParseCopy(aBytes, out HeaderPayload aPayload);
		bool bValid = TryParseCopy(bBytes, out HeaderPayload bPayload);

		if (!aValid && !bValid)
		{
			return false;
		}

		if (aValid && (!bValid || aPayload.Generation >= bPayload.Generation))
		{
			payload = aPayload;
			return true;
		}

		payload = bPayload;
		return true;
	}

	// ── SIMD & Zero-Alloc Parsers ────────────────────────────────────────────────

	/// <summary>Parses one 64-byte header copy and verifies its CRC.</summary>
	private static bool TryParseCopy(ReadOnlySpan<byte> copy, out HeaderPayload payload)
	{
		payload = default;
		if (copy.Length < 64)
		{
			return false;
		}

		ReadOnlySpan<byte> payloadBytes = copy.Slice(0, 60);
		uint expectedCrc = BinaryPrimitives.ReadUInt32LittleEndian(copy.Slice(60, 4));
		uint actualCrc = Crc32C.HashToUInt32(payloadBytes);
		if (expectedCrc != actualCrc)
		{
			return false;
		}

		payload = MemoryMarshal.Read<HeaderPayload>(payloadBytes);
		if (payload.Magic != Magic || payload.RecordSize != ShardRecord.SizeBytes)
		{
			return false;
		}

		return true;
	}

	/// <summary>Emits one 64-byte header copy into <paramref name="destination"/>.</summary>
	public static void WriteCopy(Span<byte> destination, in HeaderPayload payload)
	{
		if (destination.Length < 64)
		{
			throw new ArgumentException("Destination too small for header copy.", nameof(destination));
		}

		Span<byte> payloadBytes = destination.Slice(0, 60);
		MemoryMarshal.Write(payloadBytes, in payload);

		uint crc = Crc32C.HashToUInt32(payloadBytes);
		BinaryPrimitives.WriteUInt32LittleEndian(destination.Slice(60, 4), crc);
	}
}
