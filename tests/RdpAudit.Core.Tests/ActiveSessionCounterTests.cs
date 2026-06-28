// File:    tests/RdpAudit.Core.Tests/ActiveSessionCounterTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: Pins the Overview "Active sessions" KPI to the same rule the Remote RDP
//          Clients tab applies. Reproduces the operator's observed regression — two
//          active RDP rows (af, md) but Overview displaying 0 — and asserts the
//          centralized counter returns 2.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Ipc.Contracts;
using RdpAudit.Core.Util;
using Xunit;

namespace RdpAudit.Core.Tests;

public class ActiveSessionCounterTests
{
	[Fact]
	public void CountActiveUserSessions_OperatorSample_ReturnsTwo()
	{
		// Mirrors the operator's screenshot — two active RDP sessions (af, md) plus the
		// usual listener / services / console rows that Overview must NOT count.
		IReadOnlyList<RdpSessionDto> sessions = new[]
		{
			Active(id: 2, user: "af", session: "rdp-tcp#1"),
			Active(id: 3, user: "md", session: "rdp-tcp#21"),
			NonUserActive(id: 0, session: "services"),
			NonUserActive(id: 1, session: "console"),
			Listen(id: 65536, session: "rdp-tcp"),
			Disconnected(id: 4, user: "carol"),
		};

		Assert.Equal(2, ActiveSessionCounter.CountActiveUserSessions(sessions));
	}

	[Fact]
	public void CountActiveUserSessions_EmptyList_ReturnsZero()
	{
		Assert.Equal(0, ActiveSessionCounter.CountActiveUserSessions(Array.Empty<RdpSessionDto>()));
	}

	[Fact]
	public void CountActiveUserSessions_ListenerOnly_ReturnsZero()
	{
		IReadOnlyList<RdpSessionDto> sessions = new[]
		{
			Listen(id: 65536, session: "rdp-tcp"),
			NonUserActive(id: 0, session: "services"),
		};
		Assert.Equal(0, ActiveSessionCounter.CountActiveUserSessions(sessions));
	}

	[Fact]
	public void CountActiveUserSessions_ActiveButEmptyUser_ExcludedFromCount()
	{
		// A row with State=Active but no user (e.g. console with auto-logoff) must not
		// inflate the KPI — that's the same exclusion the Remote RDP Clients tab applies.
		IReadOnlyList<RdpSessionDto> sessions = new[]
		{
			NonUserActive(id: 1, session: "console"),
			Active(id: 2, user: "af", session: "rdp-tcp#1"),
		};
		Assert.Equal(1, ActiveSessionCounter.CountActiveUserSessions(sessions));
	}

	private static RdpSessionDto Active(int id, string user, string session) => new()
	{
		SessionId = id,
		UserName = user,
		SessionName = session,
		State = "Active",
		IsActive = true,
		IsDisconnected = false,
	};

	private static RdpSessionDto NonUserActive(int id, string session) => new()
	{
		SessionId = id,
		UserName = string.Empty,
		SessionName = session,
		State = "Active",
		IsActive = true,
		IsDisconnected = false,
	};

	private static RdpSessionDto Listen(int id, string session) => new()
	{
		SessionId = id,
		UserName = string.Empty,
		SessionName = session,
		State = "Listen",
		IsActive = false,
		IsDisconnected = false,
	};

	private static RdpSessionDto Disconnected(int id, string user) => new()
	{
		SessionId = id,
		UserName = user,
		SessionName = string.Empty,
		State = "Disconnected",
		IsActive = false,
		IsDisconnected = true,
	};
}
