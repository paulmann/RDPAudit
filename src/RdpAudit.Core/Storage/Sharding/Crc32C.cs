/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : Crc32C.cs
// Project: RdpAudit.Core (RdpAudit.Core.Storage.Sharding)
// Purpose: Hardware-accelerated CRC-32C (Castagnoli, polynomial 0x1EDC6F41) used to detect
//          torn writes and bit rot in shard headers and records.
// Depends: System.Runtime.Intrinsics.X86.Sse42, System.Buffers.Binary.BinaryPrimitives
// Extends: Add an Arm64 Crc32 path here when RdpAudit targets ARM; the software fallback and
//          the public surface stay unchanged.

using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics.X86;

namespace RdpAudit.Core.Storage.Sharding;

/// <summary>
/// CRC-32C (Castagnoli) checksum over a byte span.
/// </summary>
/// <remarks>
/// <para>
/// This is deliberately NOT <c>System.IO.Hashing.Crc32</c>. That type implements CRC-32/IEEE
/// (reflected polynomial 0xEDB88320), whereas the shard format specifies CRC-32C (reflected
/// polynomial 0x82F63B78). The two produce different digests for the same input, so a shard
/// written with one and verified with the other would fail every integrity check.
/// </para>
/// <para>
/// CRC-32C is chosen because it has a dedicated x86 instruction (<c>SSE4.2 CRC32</c>) and a
/// better Hamming distance than IEEE at the record sizes this format uses. On hardware without
/// SSE4.2 the software fallback below produces bit-identical results, so shards remain portable.
/// </para>
/// <para>All methods are allocation-free and safe to call from the hot path.</para>
/// </remarks>
public static class Crc32C
{
	// ── Fields ───────────────────────────────────────────────────────────────────

	/// <summary>Reflected CRC-32C polynomial.</summary>
	private const uint ReflectedPolynomial = 0x82F63B78u;

	/// <summary>Standard CRC seed; the digest is the one's complement of the running value.</summary>
	private const uint Seed = 0xFFFFFFFFu;

	/// <summary>
	/// Byte-wise lookup table for the software fallback. Built once at type initialisation —
	/// the hot path only reads it, so this costs a single 1 KiB allocation for the process.
	/// </summary>
	private static readonly uint[] Table = BuildTable();

	// ── Public API ───────────────────────────────────────────────────────────────

	/// <summary>
	/// Computes the CRC-32C digest of <paramref name="source"/>.
	/// </summary>
	/// <param name="source">Bytes to checksum. May be empty.</param>
	/// <returns>The digest. An empty input yields <c>0</c>.</returns>
	public static uint HashToUInt32(ReadOnlySpan<byte> source)
		=> ~Append(Seed, source);

	/// <summary>
	/// Continues a running CRC-32C over an additional chunk, for callers that checksum a
	/// logical record assembled from several spans without concatenating them first.
	/// </summary>
	/// <param name="runningValue">
	/// The previous running value, or <see cref="InitialValue"/> to start a new digest.
	/// </param>
	/// <param name="source">The next chunk of bytes.</param>
	/// <returns>The updated running value. Pass it to <see cref="Finalize"/> when done.</returns>
	public static uint Append(uint runningValue, ReadOnlySpan<byte> source)
	{
		uint crc = runningValue;

		// x64 path: eight bytes per instruction. The 64-bit form returns a ulong whose upper
		// half is always zero, so the narrowing cast is lossless.
		if (Sse42.X64.IsSupported)
		{
			while (source.Length >= sizeof(ulong))
			{
				ulong chunk = BinaryPrimitives.ReadUInt64LittleEndian(source);
				crc = (uint)Sse42.X64.Crc32(crc, chunk);
				source = source.Slice(sizeof(ulong));
			}
		}

		if (Sse42.IsSupported)
		{
			while (source.Length >= sizeof(uint))
			{
				uint chunk = BinaryPrimitives.ReadUInt32LittleEndian(source);
				crc = Sse42.Crc32(crc, chunk);
				source = source.Slice(sizeof(uint));
			}

			for (int i = 0; i < source.Length; i++)
			{
				crc = Sse42.Crc32(crc, source[i]);
			}

			return crc;
		}

		return AppendSoftware(crc, source);
	}

	/// <summary>Seed for an incremental digest built with <see cref="Append"/>.</summary>
	public static uint InitialValue => Seed;

	/// <summary>Converts a running value from <see cref="Append"/> into the final digest.</summary>
	/// <param name="runningValue">The accumulated running value.</param>
	/// <returns>The CRC-32C digest.</returns>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static uint Finalize(uint runningValue) => ~runningValue;

	// ── Software Fallback ────────────────────────────────────────────────────────

	/// <summary>
	/// Table-driven CRC-32C for hardware without SSE4.2. Produces digests identical to the
	/// intrinsic path so shard files stay portable across machines.
	/// </summary>
	private static uint AppendSoftware(uint crc, ReadOnlySpan<byte> source)
	{
		// Hoist the bounds check out of the loop: the JIT cannot prove the index is in range
		// because the table index is data-dependent.
		ref uint table = ref MemoryMarshal.GetArrayDataReference(Table);

		for (int i = 0; i < source.Length; i++)
		{
			byte index = (byte)(crc ^ source[i]);
			crc = Unsafe.Add(ref table, index) ^ (crc >> 8);
		}

		return crc;
	}

	/// <summary>Builds the 256-entry reflected CRC-32C table.</summary>
	private static uint[] BuildTable()
	{
		uint[] table = new uint[256];

		for (uint i = 0; i < 256u; i++)
		{
			uint entry = i;

			for (int bit = 0; bit < 8; bit++)
			{
				entry = (entry & 1u) != 0u
					? (entry >> 1) ^ ReflectedPolynomial
					: entry >> 1;
			}

			table[i] = entry;
		}

		return table;
	}
}
