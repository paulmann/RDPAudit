// File:    tests/RdpAudit.Core.Tests/ActiveRdpTcpEnricherTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: Validates the pure ActiveRdpTcpEnricher against the user's exact field diagnostic
//          and the surrounding edge cases. The canonical scenario is: one active RDP user
//          session (md, id 3, rdp-tcp#26) and one established remote TCP endpoint
//          (77.37.192.246:7337) on the local RDP listener port — the enricher must assign
//          the IP to that single session. Multi-session / multi-endpoint cases must remain
//          blank, and disconnected / listener / no-user rows must never be touched.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Collections.Generic;
using RdpAudit.Core.Ipc.Contracts;
using RdpAudit.Core.Util;
using Xunit;

namespace RdpAudit.Core.Tests;

public class ActiveRdpTcpEnricherTests
{
	private static RdpSessionDto ActiveRdpRow(int id, string user, string? clientIp = null) =>
		new()
		{
			SessionId = id,
			UserName = user,
			SessionName = "rdp-tcp#" + id.ToString(System.Globalization.CultureInfo.InvariantCulture),
			State = "Active",
			IsActive = true,
			IsDisconnected = false,
			ClientAddress = clientIp,
		};

	private static RdpSessionDto DisconnectedRdpRow(int id, string user) =>
		new()
		{
			SessionId = id,
			UserName = user,
			SessionName = "rdp-tcp#" + id.ToString(System.Globalization.CultureInfo.InvariantCulture),
			State = "Disconnected",
			IsActive = false,
			IsDisconnected = true,
		};

	private static RdpSessionDto ListenerRow(int id) =>
		new()
		{
			SessionId = id,
			UserName = string.Empty,
			SessionName = "rdp-tcp",
			State = "Listen",
			IsActive = false,
			IsDisconnected = false,
		};

	[Fact]
	public void Enrich_OperatorDiagnostic_AssignsSingleEndpointToSingleActiveSession()
	{
		List<RdpSessionDto> sessions = new()
		{
			ListenerRow(65536),
			DisconnectedRdpRow(2, "af"),
			ActiveRdpRow(3, "md"),
		};
		List<ActiveRdpTcpEndpoint> endpoints = new()
		{
			new ActiveRdpTcpEndpoint("77.37.192.246", 7337),
		};

		ActiveRdpTcpEnrichmentResult result = ActiveRdpTcpEnricher.Enrich(sessions, endpoints);

		Assert.Equal(1, result.IpsAssigned);
		Assert.Equal(ActiveRdpTcpEnrichmentOutcome.SingleUnambiguousAssignment, result.Outcome);
		Assert.Equal("77.37.192.246", sessions[2].ClientAddress);
		Assert.Null(sessions[1].ClientAddress);
	}

	[Fact]
	public void Enrich_DisconnectedSessionAndOneEndpoint_DoesNotAssign()
	{
		List<RdpSessionDto> sessions = new()
		{
			DisconnectedRdpRow(2, "af"),
		};
		List<ActiveRdpTcpEndpoint> endpoints = new()
		{
			new ActiveRdpTcpEndpoint("77.37.192.246", 7337),
		};

		ActiveRdpTcpEnrichmentResult result = ActiveRdpTcpEnricher.Enrich(sessions, endpoints);

		Assert.Equal(0, result.IpsAssigned);
		Assert.Null(sessions[0].ClientAddress);
	}

	[Fact]
	public void Enrich_MultipleActiveAndMultipleEndpoints_LeavesBlank()
	{
		List<RdpSessionDto> sessions = new()
		{
			ActiveRdpRow(3, "md"),
			ActiveRdpRow(4, "bob"),
		};
		List<ActiveRdpTcpEndpoint> endpoints = new()
		{
			new ActiveRdpTcpEndpoint("77.37.192.246", 7337),
			new ActiveRdpTcpEndpoint("8.8.8.8", 50001),
		};

		ActiveRdpTcpEnrichmentResult result = ActiveRdpTcpEnricher.Enrich(sessions, endpoints);

		Assert.Equal(0, result.IpsAssigned);
		Assert.Equal(ActiveRdpTcpEnrichmentOutcome.AmbiguousMultipleSessions, result.Outcome);
		Assert.Null(sessions[0].ClientAddress);
		Assert.Null(sessions[1].ClientAddress);
	}

	[Fact]
	public void Enrich_ActiveSessionAlreadyHasClientIp_NotOverwritten()
	{
		List<RdpSessionDto> sessions = new()
		{
			ActiveRdpRow(3, "md", clientIp: "10.0.0.5"),
		};
		List<ActiveRdpTcpEndpoint> endpoints = new()
		{
			new ActiveRdpTcpEndpoint("77.37.192.246", 7337),
		};

		ActiveRdpTcpEnrichmentResult result = ActiveRdpTcpEnricher.Enrich(sessions, endpoints);

		Assert.Equal(0, result.IpsAssigned);
		Assert.Equal(ActiveRdpTcpEnrichmentOutcome.AlreadyEnriched, result.Outcome);
		Assert.Equal("10.0.0.5", sessions[0].ClientAddress);
	}

	[Fact]
	public void Enrich_LoopbackEndpoint_FilteredOut()
	{
		List<RdpSessionDto> sessions = new()
		{
			ActiveRdpRow(3, "md"),
		};
		List<ActiveRdpTcpEndpoint> endpoints = new()
		{
			new ActiveRdpTcpEndpoint("127.0.0.1", 50001),
		};

		ActiveRdpTcpEnrichmentResult result = ActiveRdpTcpEnricher.Enrich(sessions, endpoints);

		Assert.Equal(0, result.IpsAssigned);
		Assert.Equal(ActiveRdpTcpEnrichmentOutcome.NoEligibleEndpoint, result.Outcome);
		Assert.Null(sessions[0].ClientAddress);
	}

	[Fact]
	public void Enrich_WildcardZero_FilteredOut()
	{
		List<RdpSessionDto> sessions = new()
		{
			ActiveRdpRow(3, "md"),
		};
		List<ActiveRdpTcpEndpoint> endpoints = new()
		{
			new ActiveRdpTcpEndpoint("0.0.0.0", 50001),
		};

		ActiveRdpTcpEnrichmentResult result = ActiveRdpTcpEnricher.Enrich(sessions, endpoints);
		Assert.Equal(0, result.IpsAssigned);
	}

	[Fact]
	public void Enrich_RepeatedSamePeer_StillCountsAsOneEndpoint()
	{
		List<RdpSessionDto> sessions = new()
		{
			ActiveRdpRow(3, "md"),
		};
		// Same remote IP twice (two simultaneous TCP connections from the same peer).
		// The enricher dedupes by IP so this still resolves unambiguously.
		List<ActiveRdpTcpEndpoint> endpoints = new()
		{
			new ActiveRdpTcpEndpoint("77.37.192.246", 7337),
			new ActiveRdpTcpEndpoint("77.37.192.246", 7338),
		};

		ActiveRdpTcpEnrichmentResult result = ActiveRdpTcpEnricher.Enrich(sessions, endpoints);
		Assert.Equal(1, result.IpsAssigned);
		Assert.Equal("77.37.192.246", sessions[0].ClientAddress);
	}

	[Fact]
	public void Enrich_NoEndpoints_StatusIsNoEligibleEndpoint()
	{
		List<RdpSessionDto> sessions = new()
		{
			ActiveRdpRow(3, "md"),
		};

		ActiveRdpTcpEnrichmentResult result = ActiveRdpTcpEnricher.Enrich(sessions, System.Array.Empty<ActiveRdpTcpEndpoint>());
		Assert.Equal(ActiveRdpTcpEnrichmentOutcome.NoEligibleEndpoint, result.Outcome);
	}

	[Fact]
	public void IsActiveRdpUserSession_ExcludesListenerServicesConsole()
	{
		Assert.False(ActiveRdpTcpEnricher.IsActiveRdpUserSession(ListenerRow(65536)));
		Assert.False(ActiveRdpTcpEnricher.IsActiveRdpUserSession(new RdpSessionDto
		{
			SessionId = 0,
			UserName = string.Empty,
			SessionName = "services",
			IsActive = false,
		}));
		Assert.False(ActiveRdpTcpEnricher.IsActiveRdpUserSession(new RdpSessionDto
		{
			SessionId = 1,
			UserName = "alice",
			SessionName = "console",
			IsActive = true,
		}));
	}
}
