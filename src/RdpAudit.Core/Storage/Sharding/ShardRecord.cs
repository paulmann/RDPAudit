/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.1
// File   : ShardRecord.cs
// Project: RdpAudit.Core (RdpAudit.Core.Storage.Sharding)
// Purpose: Fixed 128-byte on-disk record layout for the per-IP shard file. Cache-line aligned,
//          reinterpret-castable from a memory-mapped Span<byte>, no managed references.
// Depends: System.Runtime.InteropServices, Crc32C
// Extends: When adding a new field, bump the shard format version in ShardHeader and add
//          reading logic that keeps old records forward-compatible; never mutate the layout.

using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

using System.Diagnostics.CodeAnalysis;

namespace RdpAudit.Core.Storage.Sharding;

/// <summary>
/// Fixed 128-byte on-disk record for the per-IP shard file. Packed sequential layout keeps the
/// record cache-line friendly (two records per 256-byte prefetch on modern x86, one per line on
/// ARM64), and lets the reader reinterpret a <see cref="ReadOnlySpan{Byte}"/> view of the mapped
/// file as a <see cref="ReadOnlySpan{ShardRecord}"/> without allocation.
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 1, Size = 128)]
public readonly struct ShardRecord : IEquatable<ShardRecord>
{
	/// <summary>Monotonic ingestion sequence assigned inside the durability boundary. Used to
	/// join a shard record back to <c>RawEvents.IngestionSequence</c> for reconciliation.</summary>
	public readonly long Sequence;

	/// <summary>UTC ticks (100-ns) of the event as reported by the log.</summary>
	public readonly long TimeUtcTicks;

	/// <summary>Windows Event Log event id.</summary>
	public readonly int EventId;

	/// <summary>Channel encoded to the compact <see cref="Sharding.ChannelCode"/> enum.</summary>
	public readonly ushort ChannelCode;

	/// <summary>Event layer classification (<c>AuthLayer</c>, <c>SessionLayer</c>, …).</summary>
	public readonly byte EventLayer;

	/// <summary>SourceIp confidence 0..255 (0 = unknown, 255 = authoritative).</summary>
	public readonly byte SourceIpConfidence;

	/// <summary>Windows LogonType (0 = not applicable).</summary>
	public readonly byte LogonType;

	/// <summary>Windows sub-status low byte; NT status is denormalised into ShardStatusHigh + this.</summary>
	public readonly byte SubStatusLow;

	/// <summary>High word of the NT status.</summary>
	public readonly ushort StatusHigh;

	/// <summary>Windows session id or -1 if none.</summary>
	public readonly int SessionId;

	/// <summary>Windows logon id or 0 if none.</summary>
	public readonly long LogonId;

	/// <summary>Offset into the shard string heap for the UserName, or -1.</summary>
	public readonly int UserNameHeapOffset;

	/// <summary>Offset into the shard string heap for the WorkstationName, or -1.</summary>
	public readonly int WorkstationNameHeapOffset;

	/// <summary>Offset into the shard string heap for the ProcessName, or -1.</summary>
	public readonly int ProcessNameHeapOffset;

	/// <summary>Offset into the shard string heap for the DomainName, or -1.</summary>
	public readonly int DomainNameHeapOffset;

	/// <summary>Offset into the shard string heap for the ActivityId GUID string, or -1.</summary>
	public readonly int ActivityIdHeapOffset;

	/// <summary>Reserved bit-flags: bit0 success, bit1 failure, bit2 subnetAggregate, bit3 truncated.</summary>
	public readonly uint Flags;

	/// <summary>Reserved for future use; zero on write.</summary>
	private readonly long _reserved0;

	private readonly long _reserved1;

	private readonly int _reserved2;

	/// <summary>CRC32C computed over the previous 124 bytes of this record. Non-zero on write;
	/// mismatch on read marks the record as torn and it is skipped/quarantined.</summary>
	public readonly uint Crc32C;

	// ── Construction ─────────────────────────────────────────────────────────────

	public ShardRecord(
		long sequence,
		long timeUtcTicks,
		int eventId,
		ushort channelCode,
		byte eventLayer,
		byte sourceIpConfidence,
		byte logonType,
		byte subStatusLow,
		ushort statusHigh,
		int sessionId,
		long logonId,
		int userNameHeapOffset,
		int workstationNameHeapOffset,
		int processNameHeapOffset,
		int domainNameHeapOffset,
		int activityIdHeapOffset,
		uint flags,
		uint crc32c)
	{
		Sequence = sequence;
		TimeUtcTicks = timeUtcTicks;
		EventId = eventId;
		ChannelCode = channelCode;
		EventLayer = eventLayer;
		SourceIpConfidence = sourceIpConfidence;
		LogonType = logonType;
		SubStatusLow = subStatusLow;
		StatusHigh = statusHigh;
		SessionId = sessionId;
		LogonId = logonId;
		UserNameHeapOffset = userNameHeapOffset;
		WorkstationNameHeapOffset = workstationNameHeapOffset;
		ProcessNameHeapOffset = processNameHeapOffset;
		DomainNameHeapOffset = domainNameHeapOffset;
		ActivityIdHeapOffset = activityIdHeapOffset;
		Flags = flags;
		_reserved0 = 0;
		_reserved1 = 0;
		_reserved2 = 0;
		Crc32C = crc32c;
	}

	// ── Public API ───────────────────────────────────────────────────────────────

	/// <summary>Size in bytes of a single shard record on disk. Compile-time constant.</summary>
	public const int SizeBytes = 128;

	/// <summary>Offset of <see cref="Crc32C"/> from the record base, in bytes.</summary>
	public const int Crc32COffset = 124;

	/// <summary>Creates a record with the CRC32C required by the on-disk format.</summary>
	public static ShardRecord Create(
		long sequence,
		long timeUtcTicks,
		int eventId,
		ushort channelCode,
		byte eventLayer,
		byte sourceIpConfidence,
		byte logonType,
		byte subStatusLow,
		ushort statusHigh,
		int sessionId,
		long logonId,
		int userNameHeapOffset,
		int workstationNameHeapOffset,
		int processNameHeapOffset,
		int domainNameHeapOffset,
		int activityIdHeapOffset,
		uint flags)
	{
		ShardRecord draft = new(
			sequence, timeUtcTicks, eventId, channelCode, eventLayer, sourceIpConfidence,
			logonType, subStatusLow, statusHigh, sessionId, logonId, userNameHeapOffset,
			workstationNameHeapOffset, processNameHeapOffset, domainNameHeapOffset,
			activityIdHeapOffset, flags, crc32c: 0);
		uint crc32c = global::RdpAudit.Core.Storage.Sharding.Crc32C.HashToUInt32(AsBytes(in draft).Slice(0, Crc32COffset));
		return new ShardRecord(
			sequence, timeUtcTicks, eventId, channelCode, eventLayer, sourceIpConfidence,
			logonType, subStatusLow, statusHigh, sessionId, logonId, userNameHeapOffset,
			workstationNameHeapOffset, processNameHeapOffset, domainNameHeapOffset,
			activityIdHeapOffset, flags, crc32c);
	}

	/// <summary>Reinterprets a <see cref="ReadOnlySpan{Byte}"/> as a
	/// <see cref="ReadOnlySpan{ShardRecord}"/> without copying. Caller guarantees the source
	/// is properly aligned (memory-mapped files satisfy this by construction on Windows).</summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static ReadOnlySpan<ShardRecord> CastFrom(ReadOnlySpan<byte> bytes)
		=> MemoryMarshal.Cast<byte, ShardRecord>(bytes);

	/// <summary>Reinterprets a single record as its byte view for CRC computation and writing.</summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static ReadOnlySpan<byte> AsBytes(in ShardRecord record)
		=> MemoryMarshal.CreateReadOnlySpan(
			ref Unsafe.As<ShardRecord, byte>(ref Unsafe.AsRef(in record)),
			SizeBytes);

	// ── Equality ─────────────────────────────────────────────────────────────────

	/// <summary>Compares this value with <paramref name="other"/> by on-disk byte image.</summary>
	/// <param name="other">Value to compare against.</param>
	/// <returns><c>true</c> when both serialise to identical bytes.</returns>
	public bool Equals(ShardRecord other) => BlittableEquality.Equals(in this, in other);

	/// <inheritdoc />
	public override bool Equals(object? obj) => obj is ShardRecord other && Equals(other);

	/// <inheritdoc />
	public override int GetHashCode() => BlittableEquality.GetHashCode(in this);

	/// <summary>Byte-image equality operator.</summary>
	/// <param name="left">Left operand.</param>
	/// <param name="right">Right operand.</param>
	/// <returns><c>true</c> when both serialise to identical bytes.</returns>
	public static bool operator ==(ShardRecord left, ShardRecord right) => left.Equals(right);

	/// <summary>Byte-image inequality operator.</summary>
	/// <param name="left">Left operand.</param>
	/// <param name="right">Right operand.</param>
	/// <returns><c>true</c> when the byte images differ.</returns>
	public static bool operator !=(ShardRecord left, ShardRecord right) => !left.Equals(right);
}

/// <summary>Compact channel code baked into <see cref="ShardRecord.ChannelCode"/>.</summary>
[SuppressMessage("Design", "CA1028:Enum storage should be Int32", Justification =
	"The narrow underlying type is a storage contract, not an oversight: values are persisted verbatim into fixed-size shard records and audit rows, where widening to Int32 would inflate every record and break binary compatibility with shards already on disk.")]
public enum ChannelCode : ushort
{
	Unknown = 0,
	Security = 1,
	TsLocal = 2,
	TsRemote = 3,
	RdpCore = 4,
	TsGateway = 5,
	TsClient = 6,
	System = 7,
}
