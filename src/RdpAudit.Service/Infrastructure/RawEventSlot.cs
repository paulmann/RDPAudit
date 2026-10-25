/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.1

#pragma warning disable CA1815 // Override equals and operator equals on value types

using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace RdpAudit.Service.Infrastructure;

[StructLayout(LayoutKind.Explicit, Size = 8192)]
public unsafe struct RawEventSlot
{
    /// <summary>Payload capacity of one ring slot in bytes. Must match
    /// <c>UnmanagedSpscRingBuffer.SlotSize</c> and <c>UnmanagedMpmcRingBuffer.SlotSize</c>.</summary>
    public const int SizeBytes = 8192;

    /// <summary>
    /// Maximum characters for Channel Name (128 chars * 2 bytes = 256 bytes).
    /// </summary>
    public const int MaxChannelNameChars = 128;

    /// <summary>Offset of the XML payload buffer: 64-bit sequence (8 B) + payload length/event id
    /// (8 B) + timestamp (8 B) + channel (128 chars = 256 B) + the 8-byte Windows RecordId.</summary>
    public const int XmlPayloadOffset = 288;

    /// <summary>
    /// Maximum characters for the XML payload: (8192 - 288) / 2 = 3952. The previous 4096-byte slot
    /// capped the XML at 1910 chars, which a realistic Security 4624/4625 payload (~1.7-2.2 KB)
    /// exceeds: the trailing EventData fields — including IpAddress — were silently dropped.
    /// </summary>
    public const int MaxXmlPayloadChars = (SizeBytes - XmlPayloadOffset) / 2;

    /// <summary>High bit of <see cref="PayloadLength"/>: the source XML was longer than the slot.
    /// Surfaced to the normalizer so a lost source IP becomes SourceIpUnresolved instead of
    /// disappearing without a trace.</summary>
    public const uint TruncatedFlag = 0x8000_0000u;

    /// <summary>Number of payload characters encoded in <paramref name="payloadLength"/>.</summary>
    public static int PayloadCharCount(uint payloadLength) => (int)(payloadLength & ~TruncatedFlag);

    /// <summary>True when <paramref name="payloadLength"/> marks a truncated payload.</summary>
    public static bool IsTruncated(uint payloadLength) => (payloadLength & TruncatedFlag) != 0;

    // =====================================================================
    // HEADER: 24 bytes (Offsets 0 to 23)
    // =====================================================================
    
    /// <summary>
    /// Monotonic sequence number for ordering and gap detection. 64-bit so the ring-side counter
    /// cannot wrap at 2^32 (the previous uint cast wrapped after ~4.29e9 events, after which the
    /// bookmark ledger's ordering was meaningless).
    /// </summary>
    [FieldOffset(0)]
    public long SequenceNumber;

    /// <summary>
    /// Actual length of the XML payload in characters.
    /// </summary>
    [FieldOffset(8)]
    public uint PayloadLength;

    /// <summary>
    /// Windows Event Log Event ID.
    /// </summary>
    [FieldOffset(12)]
    public int EventId;

    /// <summary>
    /// Event timestamp in UTC ticks.
    /// </summary>
    [FieldOffset(16)]
    public long TimestampTicks;

    // =====================================================================
    // PAYLOAD: 4076 bytes (Offsets 20 to 4095)
    // =====================================================================

    /// <summary>
    /// Fixed-size buffer for the Event Log Channel Name.
    /// </summary>
    [FieldOffset(24)]
    public fixed char ChannelName[MaxChannelNameChars];

    /// <summary>Windows event-log RecordId of the source record (0 when the transport has none, e.g.
    /// ETW). Carried through the ring so persistence can deduplicate an event forwarded by both the
    /// live watcher and a backfill worker.</summary>
    [FieldOffset(280)]
    public long RecordId;

    /// <summary>
    /// Fixed-size buffer for the XML Event Payload.
    /// </summary>
    [FieldOffset(288)]
    public fixed char XmlPayload[MaxXmlPayloadChars];

    /// <summary>
    /// Gets a <see cref="Span{T}"/> over the Channel Name buffer for zero-alloc reads/writes.
    /// </summary>
    /// <returns>A span representing the channel name memory.</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public readonly Span<char> GetChannelNameSpan()
    {
        fixed (char* ptr = ChannelName)
        {
            return new Span<char>(ptr, MaxChannelNameChars);
        }
    }

    /// <summary>
    /// Gets a <see cref="Span{T}"/> over the XML Payload buffer for zero-alloc reads/writes.
    /// </summary>
    /// <returns>A span representing the XML payload memory.</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public readonly Span<char> GetXmlPayloadSpan()
    {
        fixed (char* ptr = XmlPayload)
        {
            return new Span<char>(ptr, MaxXmlPayloadChars);
        }
    }
}
