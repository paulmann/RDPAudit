/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.1

#pragma warning disable CA1815 // Override equals and operator equals on value types

using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace RdpAudit.Service.Infrastructure;

[StructLayout(LayoutKind.Explicit, Size = 4096)]
public unsafe struct RawEventSlot
{
    /// <summary>
    /// Maximum characters for Channel Name (128 chars * 2 bytes = 256 bytes).
    /// </summary>
    public const int MaxChannelNameChars = 128;

    /// <summary>
    /// Maximum characters for XML Payload.
    /// Math correction: The original specification requested 1960 chars, but 1960 * 2 bytes = 3920 bytes.
    /// 276 (offset) + 3920 = 4196 bytes, which exceeds the 4096-byte slot limit and causes a compiler error.
    /// Adjusted to 1910 chars (1910 * 2 = 3820 bytes; 276 + 3820 = 4096 bytes) 
    /// to strictly maintain the 4096-byte fixed size constraint required by the ring buffer.
    /// </summary>
    public const int MaxXmlPayloadChars = 1910;

    // =====================================================================
    // HEADER: 20 bytes (Offsets 0 to 19)
    // =====================================================================
    
    /// <summary>
    /// Monotonic sequence number for ordering and gap detection.
    /// </summary>
    [FieldOffset(0)]
    public uint SequenceNumber;

    /// <summary>
    /// Actual length of the XML payload in characters.
    /// </summary>
    [FieldOffset(4)]
    public uint PayloadLength;

    /// <summary>
    /// Event timestamp in UTC ticks.
    /// </summary>
    [FieldOffset(8)]
    public long TimestampTicks;

    /// <summary>
    /// Windows Event Log Event ID.
    /// </summary>
    [FieldOffset(16)]
    public int EventId;

    // =====================================================================
    // PAYLOAD: 4076 bytes (Offsets 20 to 4095)
    // =====================================================================

    /// <summary>
    /// Fixed-size buffer for the Event Log Channel Name.
    /// </summary>
    [FieldOffset(20)]
    public fixed char ChannelName[MaxChannelNameChars];

    /// <summary>
    /// Fixed-size buffer for the XML Event Payload.
    /// </summary>
    [FieldOffset(276)]
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
