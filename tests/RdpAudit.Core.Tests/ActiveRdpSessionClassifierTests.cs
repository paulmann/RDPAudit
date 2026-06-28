// File:    tests/RdpAudit.Core.Tests/ActiveRdpSessionClassifierTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: v1.2.2 — pin the operator-visible "active RDP" / Current? semantics. The previous
//          mapper propagated the raw qwinsta ">" marker into IsCurrent, which under
//          LocalSystem points at session 0 ("services"). These tests use the exact qwinsta /
//          quser fixtures from the v1.2.2 brief and assert that:
//            * Session 15 md rdp-tcp#117 Active classifies as the active RDP session.
//            * services/0 is never current — even when the qwinsta marker is on it.
//            * console/1 is never current.
//            * listen rows 65536 / 65537 are never current.
//            * disconnected rows are never current.
//            * a row with no username is never current.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Ipc.Contracts;
using RdpAudit.Core.Util;
using Xunit;

namespace RdpAudit.Core.Tests;

public class ActiveRdpSessionClassifierTests
{
	private const string QwinstaSample = """
 SESSIONNAME       USERNAME                 ID  STATE   TYPE        DEVICE
 services                                    0  Disc
 console                                     1  Conn
 af                                          2  Disc
 mid                                        14  Disc
>rdp-tcp#117        md                       15  Active
 31c5ce94259d4...                        65536  Listen
 rdp-tcp                                  65537  Listen
""";

	[Fact]
	public void Classify_ActiveRdpRow_WithUserAndOperatorSessionId_IsCurrent()
	{
		QwinstaSessionRow row = new(
			SessionName: "rdp-tcp#117",
			UserName: "md",
			SessionId: 15,
			State: "Active",
			IsCurrent: true);
		ActiveRdpClassification result = ActiveRdpSessionClassifier.Classify(row);
		Assert.True(result.IsActiveRdp);
		Assert.Null(result.RejectionReason);
	}

	[Fact]
	public void Classify_ServicesRowSession0_IsNeverCurrent_EvenWithRawMarker()
	{
		QwinstaSessionRow row = new("services", string.Empty, 0, "Disc", IsCurrent: true);
		ActiveRdpClassification result = ActiveRdpSessionClassifier.Classify(row);
		Assert.False(result.IsActiveRdp);
		Assert.NotNull(result.RejectionReason);
	}

	[Fact]
	public void Classify_ConsoleSession1_IsNeverCurrent()
	{
		QwinstaSessionRow row = new("console", string.Empty, 1, "Conn", false);
		ActiveRdpClassification result = ActiveRdpSessionClassifier.Classify(row);
		Assert.False(result.IsActiveRdp);
	}

	[Fact]
	public void Classify_ListenRow_65536_IsNeverCurrent()
	{
		QwinstaSessionRow row = new("31c5ce94259d4...", string.Empty, 65536, "Listen", false);
		ActiveRdpClassification result = ActiveRdpSessionClassifier.Classify(row);
		Assert.False(result.IsActiveRdp);
	}

	[Fact]
	public void Classify_ListenRow_65537_IsNeverCurrent()
	{
		QwinstaSessionRow row = new("rdp-tcp", string.Empty, 65537, "Listen", false);
		ActiveRdpClassification result = ActiveRdpSessionClassifier.Classify(row);
		Assert.False(result.IsActiveRdp);
	}

	[Fact]
	public void Classify_DisconnectedUserRow_IsNeverCurrent()
	{
		QwinstaSessionRow row = new(string.Empty, "carol", 14, "Disc", false);
		ActiveRdpClassification result = ActiveRdpSessionClassifier.Classify(row);
		Assert.False(result.IsActiveRdp);
	}

	[Fact]
	public void Classify_ActiveRowWithEmptyUserName_IsNeverCurrent()
	{
		QwinstaSessionRow row = new("rdp-tcp#5", string.Empty, 5, "Active", false);
		ActiveRdpClassification result = ActiveRdpSessionClassifier.Classify(row);
		Assert.False(result.IsActiveRdp);
		Assert.Equal("UserName empty", result.RejectionReason);
	}

	[Fact]
	public void Classify_ActiveConsoleStation_IsNeverCurrent_EvenWithUserName()
	{
		// SessionName = "console" disqualifies even on Active state.
		QwinstaSessionRow row = new("console", "admin", 1, "Active", false);
		ActiveRdpClassification result = ActiveRdpSessionClassifier.Classify(row);
		Assert.False(result.IsActiveRdp);
	}

	[Fact]
	public void Parser_PlusMapper_OnRealQwinstaSample_MarksOnlySession15ActiveRdp()
	{
		// Drive the full Parser → Mapper pipeline so we catch any regression where the
		// active-RDP semantics drift apart between unit and integration paths.
		// v1.3.8 — the mapper no longer owns IsCurrent (that is now scoped to the operator by
		// CurrentRdpSessionMatcher), so every row must have IsCurrent == false here. IsActiveRdp
		// remains the "is this an active RDP session" flag and must be set only on session 15.
		IReadOnlyList<QwinstaSessionRow> rows = QwinstaParser.Parse(QwinstaSample);
		IReadOnlyList<RdpSessionDto> dtos = QwinstaSessionMapper.MapAll(rows);

		RdpSessionDto? session15 = null;
		foreach (RdpSessionDto dto in dtos)
		{
			// The mapper never sets IsCurrent now — that is the operator-scoped matcher's job.
			Assert.False(dto.IsCurrent);

			if (dto.SessionId == 15)
			{
				session15 = dto;
				continue;
			}

			// Every other row — services/0, console/1, af/2, mid/14, listeners — must
			// be excluded from the active-RDP set.
			Assert.False(dto.IsActiveRdp);
		}

		Assert.NotNull(session15);
		Assert.True(session15!.IsActiveRdp);
		Assert.Equal("md", session15.UserName);
		Assert.Equal("rdp-tcp#117", session15.SessionName);
	}

	[Fact]
	public void Parser_PlusMapper_ServicesRowWithRawMarker_DoesNotMarkActiveRdp()
	{
		// Service-side marker test from the v1.2.2 brief: qwinsta marks ">services" but
		// the real session is rdp-tcp#117 / id 15 / Active. The pipeline must mark id 15
		// as active RDP and leave services false. The raw marker is preserved for diagnostics.
		const string sample = """
 SESSIONNAME       USERNAME                 ID  STATE   TYPE        DEVICE
>services                                    0  Disc
 rdp-tcp#117        md                       15  Active
""";

		IReadOnlyList<QwinstaSessionRow> rows = QwinstaParser.Parse(sample);
		IReadOnlyList<RdpSessionDto> dtos = QwinstaSessionMapper.MapAll(rows);

		RdpSessionDto services = dtos.Single(d => d.SessionId == 0);
		RdpSessionDto md = dtos.Single(d => d.SessionId == 15);

		// The raw query-current marker WAS on services — preserve it for diagnostics.
		Assert.True(services.IsQueryCurrent);
		// But ActiveRdp must NOT be on services, and the mapper sets IsCurrent on nobody.
		Assert.False(services.IsActiveRdp);
		Assert.False(services.IsCurrent);

		Assert.True(md.IsActiveRdp);
		Assert.False(md.IsCurrent);
	}

	[Fact]
	public void Parser_PlusMapper_MultipleActiveRdpSessions_AllMarkedActiveRdp()
	{
		// Two concurrent active RDP user sessions — both must classify as active RDP,
		// neither one should be elected over the other (no winner-take-all semantics).
		QwinstaSessionRow a = new("rdp-tcp#10", "alice", 10, "Active", false);
		QwinstaSessionRow b = new("rdp-tcp#11", "bob", 11, "Active", false);
		QwinstaSessionRow listener = new("rdp-tcp", string.Empty, 65537, "Listen", false);

		IReadOnlyList<RdpSessionDto> dtos = QwinstaSessionMapper.MapAll(new[] { a, b, listener });

		Assert.True(dtos.Single(d => d.SessionId == 10).IsActiveRdp);
		Assert.True(dtos.Single(d => d.SessionId == 11).IsActiveRdp);
		Assert.False(dtos.Single(d => d.SessionId == 65537).IsActiveRdp);

		// None are operator-Current at the mapper level.
		Assert.All(dtos, d => Assert.False(d.IsCurrent));
	}
}
