/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.3

using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Threading;
using RdpAudit.Core.Events;

namespace RdpAudit.Service.Infrastructure;

public static class RawEventSerializer
{
    private static long _sequenceCounter;

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static RawEventSlot Serialize(RawEventDto dto)
    {
        RawEventSlot slot = default;

        // Stamp the monotonic ingestion sequence on both the slot and the source DTO so the
        // caller can correlate a queued event with the bookmark/shard durability boundary even
        // before the consumer deserializes it. Kept 64-bit: a uint cast wrapped at 2^32 events.
        long sequence = Interlocked.Increment(ref _sequenceCounter);
        slot.SequenceNumber = sequence;
        dto.IngestionSequence = sequence;
        
        slot.TimestampTicks = dto.TimeUtc.Ticks; 
        slot.EventId = dto.EventId;
        slot.RecordId = dto.RecordId ?? 0L;

        ReadOnlySpan<char> channelSpan = dto.Channel.AsSpan();
        if (!channelSpan.IsEmpty)
        {
            int copyLen = Math.Min(channelSpan.Length, RawEventSlot.MaxChannelNameChars);
            Span<char> destChannel = slot.GetChannelNameSpan();
            channelSpan.Slice(0, copyLen).CopyTo(destChannel);
            if (copyLen < RawEventSlot.MaxChannelNameChars) destChannel[copyLen] = '\0';
        }

        ReadOnlySpan<char> payloadSpan = dto.XmlPayload.AsSpan();
        if (!payloadSpan.IsEmpty)
        {
            int copyLen = Math.Min(payloadSpan.Length, RawEventSlot.MaxXmlPayloadChars);
            bool truncated = payloadSpan.Length > copyLen;
            slot.PayloadLength = (uint)copyLen | (truncated ? RawEventSlot.TruncatedFlag : 0u);
            dto.XmlTruncated = truncated;
            payloadSpan.Slice(0, copyLen).CopyTo(slot.GetXmlPayloadSpan());
        }

        return slot;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static RawEventDto Deserialize(in RawEventSlot slot)
    {
        ReadOnlySpan<char> channelSpan = slot.GetChannelNameSpan();
        int channelLength = channelSpan.IndexOf('\0');
        if (channelLength == -1) channelLength = RawEventSlot.MaxChannelNameChars;
        
        string channel = channelLength > 0 ? new string(channelSpan.Slice(0, channelLength)) : string.Empty;

        string xmlPayload = string.Empty;
        bool truncated = RawEventSlot.IsTruncated(slot.PayloadLength);
        int payloadLength = RawEventSlot.PayloadCharCount(slot.PayloadLength);
        if (payloadLength > 0)
        {
            if (payloadLength > RawEventSlot.MaxXmlPayloadChars) payloadLength = RawEventSlot.MaxXmlPayloadChars;
            xmlPayload = new string(slot.GetXmlPayloadSpan().Slice(0, payloadLength));
        }

        return new RawEventDto
        {
            TimeUtc = new DateTime(slot.TimestampTicks, DateTimeKind.Utc),
            EventId = slot.EventId,
            Channel = channel,
            XmlPayload = xmlPayload,
            XmlTruncated = truncated,
            RecordId = slot.RecordId == 0 ? null : slot.RecordId,

            // Carried across the ring so the consumer can detect gaps (dropped slots) and so the
            // unified commit in EventProcessorWorker can key the bookmark on a stable ordinal.
            IngestionSequence = slot.SequenceNumber
        };
    }
}