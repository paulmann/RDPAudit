// File:    tests/RdpAudit.Core.Tests/QwinstaSessionMapperTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: Locks the QwinstaSessionMapper that converts pure parser rows into
//          RdpSessionDto instances used by both the service-side and Configurator-side
//          session-listing paths. Guarantees state normalisation, IsActive / IsDisconnected
//          derivation, IsActiveRdp calculation and raw-query-current propagation remain
//          stable while the operator-scoped IsCurrent flag is owned by CurrentRdpSessionMatcher.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Ipc.Contracts;
using RdpAudit.Core.Util;
using Xunit;

namespace RdpAudit.Core.Tests;

public class QwinstaSessionMapperTests
{
	[Fact]
	public void Map_NormalisesActiveState_AndLeavesOperatorCurrentUnset()
	{
		QwinstaSessionRow row = new("rdp-tcp#3", "alice", 3, "Active", false);
		RdpSessionDto dto = QwinstaSessionMapper.Map(row);
		Assert.Equal(3, dto.SessionId);
		Assert.Equal("alice", dto.UserName);
		Assert.Equal("Active", dto.State);
		Assert.True(dto.IsActive);
		Assert.False(dto.IsDisconnected);
		// v1.3.8 — an Active rdp-tcp# row with a non-empty user and a SessionId in the
		// operator range is an active RDP session, but it is not necessarily the operator's
		// current session. CurrentRdpSessionMatcher owns the narrower operator-scoped flag.
		Assert.True(dto.IsActiveRdp);
		Assert.False(dto.IsCurrent);
	}

	[Fact]
	public void Map_NormalisesDiscState_AndSetsIsDisconnected()
	{
		QwinstaSessionRow row = new(string.Empty, "carol", 4, "Disc", false);
		RdpSessionDto dto = QwinstaSessionMapper.Map(row);
		Assert.Equal("Disconnected", dto.State);
		Assert.False(dto.IsActive);
		Assert.True(dto.IsDisconnected);
	}

	[Fact]
	public void Map_PropagatesQueryCurrentMarker_WithoutSettingOperatorCurrent()
	{
		// v1.3.8 — the raw qwinsta ">" marker flows onto IsQueryCurrent only. Operator-
		// visible Current? is gated on the validated Configurator process identity/session.
		QwinstaSessionRow row = new("rdp-tcp#7", "admin", 7, "Active", true);
		RdpSessionDto dto = QwinstaSessionMapper.Map(row);
		Assert.True(dto.IsQueryCurrent);
		Assert.False(dto.IsCurrent);
		Assert.True(dto.IsActiveRdp);
	}

	[Fact]
	public void Map_NeverMarksServicesSessionAsCurrent_EvenWhenRawMarkerIsSet()
	{
		// The smoking gun behaviour the v1.2.2 brief calls out: under LocalSystem the
		// qwinsta ">" marker lands on session 0 ("services"). The operator-visible
		// Current? must NEVER be true for session 0, regardless of the raw marker.
		QwinstaSessionRow row = new("services", string.Empty, 0, "Disconnected", true);
		RdpSessionDto dto = QwinstaSessionMapper.Map(row);
		Assert.True(dto.IsQueryCurrent);
		Assert.False(dto.IsCurrent);
		Assert.False(dto.IsActiveRdp);
	}

	[Fact]
	public void Map_ListenRows_AreNeverActiveRdp()
	{
		QwinstaSessionRow listen = new("rdp-tcp", string.Empty, 65537, "Listen", false);
		RdpSessionDto dto = QwinstaSessionMapper.Map(listen);
		Assert.False(dto.IsCurrent);
		Assert.False(dto.IsActiveRdp);
	}

	[Fact]
	public void Map_ConsoleSession_IsNeverActiveRdp()
	{
		QwinstaSessionRow console = new("console", string.Empty, 1, "Conn", false);
		RdpSessionDto dto = QwinstaSessionMapper.Map(console);
		Assert.False(dto.IsCurrent);
		Assert.False(dto.IsActiveRdp);
	}

	[Fact]
	public void MapAll_PreservesRowOrder()
	{
		QwinstaSessionRow a = new("rdp-tcp#1", "alice", 1, "Active", false);
		QwinstaSessionRow b = new("rdp-tcp#2", "bob", 2, "Disc", false);
		IReadOnlyList<RdpSessionDto> result = QwinstaSessionMapper.MapAll(new[] { a, b });
		Assert.Equal(2, result.Count);
		Assert.Equal(1, result[0].SessionId);
		Assert.Equal(2, result[1].SessionId);
	}

	[Fact]
	public void Map_UnknownStateRetainedVerbatim_AndFlagsClear()
	{
		QwinstaSessionRow row = new("rdp-tcp#3", "alice", 3, "WeirdState", false);
		RdpSessionDto dto = QwinstaSessionMapper.Map(row);
		Assert.Equal("WeirdState", dto.State);
		Assert.False(dto.IsActive);
		Assert.False(dto.IsDisconnected);
	}
}
