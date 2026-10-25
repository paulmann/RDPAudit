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
        Assert.True(result.XmlTruncated);
        Assert.True(RawEventSlot.IsTruncated(slot.PayloadLength));
        Assert.Equal(RawEventSlot.MaxXmlPayloadChars, RawEventSlot.PayloadCharCount(slot.PayloadLength));
    }

    [Fact]
    public void Serialize_KeepsXmlLongerThanTheOld1910Cap_AndIpAddressSurvives()
    {
        // A realistic Security 4625 XML is ~1.7-2.2 KB. The old 4096-byte slot cut the payload at
        // 1910 chars, which dropped the trailing IpAddress field. The 8 KB slot must carry the whole
        // event and the normalizer must still be able to read the source IP out of it.
        string longXml =
            "<Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\">"
            + "<System><EventID>4625</EventID></System><EventData>"
            + "<Data Name=\"TargetUserName\">" + new string('a', 2000) + "</Data>"
            + "<Data Name=\"IpAddress\">203.0.113.7</Data>"
            + "</EventData></Event>";

        Assert.True(longXml.Length > 1910, "fixture must exceed the historical truncation point");
        Assert.True(longXml.Length <= RawEventSlot.MaxXmlPayloadChars, "fixture must fit the new slot");

        var dto = new RawEventDto { TimeUtc = DateTime.UtcNow, EventId = 4625, Channel = "Security", XmlPayload = longXml };

        RawEventSlot slot = RawEventSerializer.Serialize(dto);
        RawEventDto result = RawEventSerializer.Deserialize(in slot);

        Assert.False(result.XmlTruncated);
        Assert.Equal(longXml, result.XmlPayload);

        System.Xml.XmlDocument? doc = EventXmlParser.ParseSafe(result.XmlPayload!);
        Assert.NotNull(doc);
        Assert.Equal("203.0.113.7", EventXmlParser.GetData(doc, "IpAddress"));
    }

    [Fact]
    public void RecordId_RoundTrips()
    {
        var dto = new RawEventDto { TimeUtc = DateTime.UtcNow, EventId = 4625, Channel = "Security", XmlPayload = "<Event/>", RecordId = 424242 };
        RawEventSlot slot = RawEventSerializer.Serialize(dto);
        RawEventDto result = RawEventSerializer.Deserialize(in slot);
        Assert.Equal(424242, result.RecordId);
    }

    [Fact]
    public void NullRecordId_RoundTripsAsNull()
    {
        // ETW / synthetic events carry no Windows RecordId; it must survive as null, not as zero.
        var dto = new RawEventDto { TimeUtc = DateTime.UtcNow, EventId = 1, Channel = "ETW", XmlPayload = "<Event/>" };
        RawEventSlot slot = RawEventSerializer.Serialize(dto);
        RawEventDto result = RawEventSerializer.Deserialize(in slot);
        Assert.Null(result.RecordId);
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

    [Fact]
    public void Sequence_IsSixtyFourBit_AndRoundTripsAboveUintMax()
    {
        // A uint cast wrapped the ring sequence at 2^32, after which the bookmark ledger's ordering
        // was meaningless. The slot now carries the full 64-bit counter.
        System.Reflection.FieldInfo counter = typeof(RawEventSerializer)
            .GetField("_sequenceCounter", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static)!;
        Assert.NotNull(counter);
        counter.SetValue(null, (long)uint.MaxValue);

        var dto = new RawEventDto { TimeUtc = DateTime.UtcNow, EventId = 1, Channel = "Security", XmlPayload = "<Event/>" };
        RawEventSlot slot = RawEventSerializer.Serialize(dto);
        RawEventDto restored = RawEventSerializer.Deserialize(in slot);

        Assert.True(dto.IngestionSequence > uint.MaxValue, "The sequence must not wrap at 2^32.");
        Assert.Equal(dto.IngestionSequence, restored.IngestionSequence);
    }
}