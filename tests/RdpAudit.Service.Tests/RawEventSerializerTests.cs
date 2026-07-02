/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.1

using System;
using RdpAudit.Core.Events;
using RdpAudit.Service.Infrastructure;
using Xunit;

namespace RdpAudit.Service.Tests;

public sealed class RawEventSerializerTests
{
    [Fact]
    public void RoundTrip_PreservesAllFields()
    {
        var dto = new RawEventDto
        {
            TimeUtc = DateTime.UtcNow,
            EventId = 4625,
            Channel = "Security",
            XmlPayload = "<Event><System><EventID>4625</EventID></System></Event>"
        };

        RawEventSlot slot = RawEventSerializer.Serialize(dto);
        RawEventDto result = RawEventSerializer.Deserialize(in slot);

        Assert.Equal(dto.TimeUtc.Ticks, result.TimeUtc.Ticks);
        Assert.Equal(dto.EventId, result.EventId);
        Assert.Equal(dto.Channel, result.Channel);
        Assert.Equal(dto.XmlPayload, result.XmlPayload);
    }

    [Fact]
    public void Serialize_TruncatesLongChannelName_Gracefully()
    {
        string longChannel = new string('A', RawEventSlot.MaxChannelNameChars + 100);
        var dto = new RawEventDto { TimeUtc = DateTime.UtcNow, EventId = 1, Channel = longChannel, XmlPayload = "test" };

        RawEventSlot slot = RawEventSerializer.Serialize(dto);
        RawEventDto result = RawEventSerializer.Deserialize(in slot);

        Assert.Equal(RawEventSlot.MaxChannelNameChars, result.Channel!.Length);
    }

    [Fact]
    public void Serialize_TruncatesLongXmlPayload_Gracefully()
    {
        string longXml = new string('X', RawEventSlot.MaxXmlPayloadChars + 500);
        var dto = new RawEventDto { TimeUtc = DateTime.UtcNow, EventId = 1, Channel = "Security", XmlPayload = longXml };

        RawEventSlot slot = RawEventSerializer.Serialize(dto);
        RawEventDto result = RawEventSerializer.Deserialize(in slot);

        Assert.Equal(RawEventSlot.MaxXmlPayloadChars, result.XmlPayload!.Length);
        Assert.Equal((uint)RawEventSlot.MaxXmlPayloadChars, slot.PayloadLength);
    }

    [Fact]
    public void Serialize_HandlesNullStrings_Safely()
    {
        var dto = new RawEventDto { TimeUtc = DateTime.UtcNow, EventId = 1, Channel = null!, XmlPayload = null! };

        RawEventSlot slot = RawEventSerializer.Serialize(dto);
        RawEventDto result = RawEventSerializer.Deserialize(in slot);

        Assert.Equal(string.Empty, result.Channel);
        Assert.Equal(string.Empty, result.XmlPayload);
    }
    
    [Fact]
    public void Deserialize_RespectsPayloadLength_IgnoresGarbageData()
    {
        var dto = new RawEventDto { TimeUtc = DateTime.UtcNow, EventId = 1, Channel = "Sec", XmlPayload = "Short" };
        RawEventSlot slot = RawEventSerializer.Serialize(dto);
        
        Span<char> payloadSpan = slot.GetXmlPayloadSpan();
        for (int i = 5; i < payloadSpan.Length; i++) payloadSpan[i] = 'Z';
        
        RawEventDto result = RawEventSerializer.Deserialize(in slot);
        Assert.Equal("Short", result.XmlPayload);
    }
}