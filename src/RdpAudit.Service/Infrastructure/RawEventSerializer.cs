/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.2

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

        slot.SequenceNumber = (uint)Interlocked.Increment(ref _sequenceCounter);
        
        slot.TimestampTicks = dto.TimeUtc.Ticks; 
        slot.EventId = dto.EventId;

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
            slot.PayloadLength = (uint)copyLen;
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
        int payloadLength = (int)slot.PayloadLength;
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
            XmlPayload = xmlPayload
        };
    }
}