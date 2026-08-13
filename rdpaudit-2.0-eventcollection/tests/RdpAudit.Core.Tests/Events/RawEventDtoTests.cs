/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : RawEventDtoTests.cs
// Project: RdpAudit.Core.Tests (RdpAudit.Core.Tests.Events)
// Purpose: Contract tests for RawEventDto: the v1.0 four-field object-initialiser must keep
//          working (backward compatibility) and every new v2.0/v2.2 field must default to a
//          safe "not set" value so partial constructions cannot leak stale correlation ids
//          into persisted rows. Also covers BookmarkXml round-trip semantics used by
//          EventProcessorWorker's unified-commit path.
// Depends: xUnit, RdpAudit.Core.Events
// Extends: Add a coverage row here whenever a new nullable/defaulted field is introduced.

using RdpAudit.Core.Events;
using Xunit;

namespace RdpAudit.Core.Tests.Events;

public sealed class RawEventDtoTests
{
	[Fact]
	public void LegacyObjectInitializer_StillCompilesAndAssignsCoreFields()
	{
		// This mirrors exactly what EventCollectorWorker.TryCaptureDto does today.
		RawEventDto dto = new()
		{
			EventId = 4625,
			Channel = "Security",
			TimeUtc = new DateTime(2026, 8, 13, 10, 30, 0, DateTimeKind.Utc),
			XmlPayload = "<Event/>",
		};

		Assert.Equal(4625, dto.EventId);
		Assert.Equal("Security", dto.Channel);
		Assert.Equal(DateTimeKind.Utc, dto.TimeUtc.Kind);
		Assert.Equal("<Event/>", dto.XmlPayload);
	}

	[Fact]
	public void NewInstance_HasSafeDefaults_ForEveryNewField()
	{
		RawEventDto dto = new();

		Assert.Null(dto.ActivityId);
		Assert.Null(dto.LogonId);
		Assert.Null(dto.SessionId);
		Assert.Equal(0L, dto.IngestionSequence);
		Assert.Equal(EventLayer.Unknown, dto.EventLayer);
		Assert.Null(dto.SourceIpBinary);
		Assert.Equal(0, dto.SourceIpAddressFamily);
		Assert.Equal(0, dto.SourceIpConfidence);

		// v2.2 field: bookmark must default to null so processors can distinguish
		// "no bookmark captured" (skip unified-commit path) from "empty bookmark"
		// (a bug — EventLogWatcher never produces an empty string).
		Assert.Null(dto.BookmarkXml);

		// v1.0 optional fields still default the same way.
		Assert.Null(dto.SourceIp);
		Assert.Null(dto.UserName);
		Assert.Null(dto.Domain);
	}

	[Fact]
	public void BookmarkXml_IsRoundTrippableViaSetter()
	{
		// The bookmark XML is what EventLogWatcher.Bookmark serialises to. Its exact
		// shape is opaque to the processor — it is passed through verbatim to the
		// BookmarkStore. This test just proves the property is a plain settable string,
		// preserving whatever bytes the collector captured.
		const string bookmark =
			"<BookmarkList><Bookmark Channel='Security' RecordId='9876' IsCurrent='true'/></BookmarkList>";

		RawEventDto dto = new()
		{
			EventId = 4624,
			Channel = "Security",
			TimeUtc = DateTime.UtcNow,
			BookmarkXml = bookmark,
		};

		Assert.Equal(bookmark, dto.BookmarkXml);

		// Same DTO must accept a fresh bookmark (later event on same channel replaces
		// the earlier one during processor batch-collection).
		dto.BookmarkXml =
			"<BookmarkList><Bookmark Channel='Security' RecordId='9877' IsCurrent='true'/></BookmarkList>";
		Assert.Contains("9877", dto.BookmarkXml);
	}

	[Fact]
	public void AllExtensionFields_AreRoundTrippableViaSetters()
	{
		Guid activityId = Guid.NewGuid();
		byte[] ip = new byte[16];
		ip[10] = 0xFF;
		ip[11] = 0xFF;
		ip[12] = 192;
		ip[13] = 168;
		ip[14] = 1;
		ip[15] = 42;

		RawEventDto dto = new()
		{
			EventId = 4624,
			Channel = "Security",
			TimeUtc = DateTime.UtcNow,
			ActivityId = activityId,
			LogonId = 0x1234_5678L,
			SessionId = 7,
			IngestionSequence = 999_001L,
			EventLayer = EventLayer.Authentication,
			SourceIpBinary = ip,
			SourceIpAddressFamily = 4,
			SourceIpConfidence = 100,
			BookmarkXml = "<BookmarkList/>",
		};

		Assert.Equal(activityId, dto.ActivityId);
		Assert.Equal(0x1234_5678L, dto.LogonId);
		Assert.Equal(7, dto.SessionId);
		Assert.Equal(999_001L, dto.IngestionSequence);
		Assert.Equal(EventLayer.Authentication, dto.EventLayer);
		Assert.Same(ip, dto.SourceIpBinary);
		Assert.Equal(16, dto.SourceIpBinary!.Length);
		Assert.Equal(4, dto.SourceIpAddressFamily);
		Assert.Equal(100, dto.SourceIpConfidence);
		Assert.Equal("<BookmarkList/>", dto.BookmarkXml);
	}
}
