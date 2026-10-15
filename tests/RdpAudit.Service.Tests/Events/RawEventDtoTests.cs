/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.3
// File   : RawEventDtoTests.cs
// Project: RdpAudit.Service.Tests (RdpAudit.Service.Tests.Events)
// Purpose: Verifies default-safe event DTO fields and serializer sequence stamping.
// Depends: RawEventDto, RawEventSerializer, RawEventSlot, EventLayer, xUnit
// Extends: Add a default and serialization assertion for every newly persisted ingestion field.

using RdpAudit.Core.Events;
using RdpAudit.Service.Infrastructure;
using Xunit;

namespace RdpAudit.Service.Tests.Events;

public sealed class RawEventDtoTests
{
	[Fact]
	public void LegacyObjectInitializer_ContinuesToAssignCaptureFields()
	{
		DateTime timestamp = new(2026, 8, 14, 0, 0, 0, DateTimeKind.Utc);
		RawEventDto dto = new()
		{
			EventId = 4625,
			Channel = "Security",
			TimeUtc = timestamp,
			XmlPayload = "<Event/>",
		};

		Assert.Equal(4625, dto.EventId);
		Assert.Equal("Security", dto.Channel);
		Assert.Equal(timestamp, dto.TimeUtc);
		Assert.Equal("<Event/>", dto.XmlPayload);
	}

	[Fact]
	public void NewInstance_HasSafeDefaultsForOptionalFields()
	{
		RawEventDto dto = new();

		Assert.Equal(string.Empty, dto.Channel);
		Assert.Equal(string.Empty, dto.XmlPayload);
		Assert.Null(dto.SourceIp);
		Assert.Null(dto.UserName);
		Assert.Null(dto.Domain);
		Assert.Null(dto.ActivityId);
		Assert.Null(dto.LogonId);
		Assert.Null(dto.SessionId);
		Assert.Equal(0L, dto.IngestionSequence);
		Assert.Equal(EventLayer.Unknown, dto.EventLayer);
		Assert.Null(dto.SourceIpBinary);
		Assert.Equal((byte)0, dto.SourceIpAddressFamily);
		Assert.Equal((byte)0, dto.SourceIpConfidence);
		Assert.Null(dto.BookmarkXml);
	}

	[Fact]
	public void ExtensionFields_AreSettableWithoutTransformingValues()
	{
		Guid activityId = Guid.Parse("11111111-2222-3333-4444-555555555555");
		byte[] sourceIp = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 0, 2, 10];
		RawEventDto dto = new()
		{
			ActivityId = activityId,
			LogonId = 0x1234_5678L,
			SessionId = 7,
			IngestionSequence = 42,
			EventLayer = EventLayer.Authentication,
			SourceIpBinary = sourceIp,
			SourceIpAddressFamily = 4,
			SourceIpConfidence = 100,
			BookmarkXml = "<Bookmark RecordId='42'/>",
		};

		Assert.Equal(activityId, dto.ActivityId);
		Assert.Equal(0x1234_5678L, dto.LogonId);
		Assert.Equal(7, dto.SessionId);
		Assert.Equal(42L, dto.IngestionSequence);
		Assert.Equal(EventLayer.Authentication, dto.EventLayer);
		Assert.Same(sourceIp, dto.SourceIpBinary);
		Assert.Equal((byte)4, dto.SourceIpAddressFamily);
		Assert.Equal((byte)100, dto.SourceIpConfidence);
		Assert.Equal("<Bookmark RecordId='42'/>", dto.BookmarkXml);
	}

	[Fact]
	public void Serialize_StampsAndPreservesTheIngestionSequenceAcrossTheRingSlot()
	{
		RawEventDto dto = new()
		{
			EventId = 4624,
			Channel = "Security",
			TimeUtc = new DateTime(2026, 8, 14, 1, 2, 3, DateTimeKind.Utc),
			XmlPayload = "<Event><EventData /></Event>",
		};

		RawEventSlot slot = RawEventSerializer.Serialize(dto);
		RawEventDto restored = RawEventSerializer.Deserialize(in slot);

		Assert.True(dto.IngestionSequence > 0, "The serializer must stamp a non-zero sequence.");
		Assert.Equal(dto.IngestionSequence, restored.IngestionSequence);
		Assert.Equal(dto.EventId, restored.EventId);
		Assert.Equal(dto.Channel, restored.Channel);
		Assert.Equal(dto.TimeUtc, restored.TimeUtc);
		Assert.Equal(dto.XmlPayload, restored.XmlPayload);
	}
}
