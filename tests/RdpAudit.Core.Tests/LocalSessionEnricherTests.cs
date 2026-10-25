// File:    tests/RdpAudit.Core.Tests/LocalSessionEnricherTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: Covers the pure local-fallback enricher used by the Configurator when the service
//          IPC is unreachable. Validates the documented match order: SessionIpCorrelation by
//          (WtsSessionId, UserName), then RdpConnectionFact by (WtsSessionId, UserName), then
//          unambiguous recent RdpConnectionFact by UserName. Listener / console / services
//          rows must not be enriched. Authoritative live values must never be overwritten.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Ipc.Contracts;
using RdpAudit.Core.Models;
using RdpAudit.Core.Util;
using Xunit;

namespace RdpAudit.Core.Tests;

public class LocalSessionEnricherTests
{
	private static RdpSessionDto MakeSession(int id, string user, string sessionName, string state = "Active", bool isActive = true)
		=> new()
		{
			SessionId = id,
			UserName = user,
			SessionName = sessionName,
			State = state,
			IsActive = isActive,
			IsDisconnected = !isActive && state == "Disc",
		};

	[Fact]
	public void Enrich_SessionWithCorrelation_PopulatesClientIp()
	{
		List<RdpSessionDto> sessions = new()
		{
			MakeSession(2, "af", "rdp-tcp#1"),
		};
		List<SessionIpCorrelation> correlations = new()
		{
			new SessionIpCorrelation
			{
				WtsSessionId = 2,
				UserName = "af",
				Ip = "1.2.3.4",
				FirstSeenUtc = new DateTime(2026, 5, 25, 8, 0, 0, DateTimeKind.Utc),
				LastSeenUtc = new DateTime(2026, 5, 25, 9, 0, 0, DateTimeKind.Utc),
			},
		};
		List<RdpConnectionFact> facts = new()
		{
			new RdpConnectionFact
			{
				WtsSessionId = 2,
				UserName = "af",
				Ip = "1.2.3.4",
				FirstSeenUtc = new DateTime(2026, 5, 20, 8, 0, 0, DateTimeKind.Utc),
				LastSeenUtc = new DateTime(2026, 5, 25, 9, 0, 0, DateTimeKind.Utc),
				FailedLogons = 5,
				SuccessfulLogons = 2,
				UserNamesAttempted = "af,administrator",
			},
		};

		LocalSessionEnrichmentResult result = LocalSessionEnricher.Enrich(sessions, correlations, facts);

		Assert.Equal(1, result.CandidateRdpSessions);
		Assert.Equal(1, result.IpAssignedFromFacts);
		Assert.Equal(1, result.HistoricalApplied);
		Assert.True(result.AnyApplied);
		Assert.Equal("1.2.3.4", sessions[0].ClientAddress);
		Assert.Equal(5, sessions[0].HistoricalFailedLogons);
		Assert.Equal(2, sessions[0].HistoricalSuccessfulLogons);
		Assert.Equal("af,administrator", sessions[0].HistoricalUserNamesAttempted);
		Assert.Equal(new DateTime(2026, 5, 20, 8, 0, 0, DateTimeKind.Utc), sessions[0].HistoricalFirstSeenUtc);
	}

	[Fact]
	public void Enrich_FactByWtsSessionIdAndUser_FillsIpWhenNoCorrelation()
	{
		List<RdpSessionDto> sessions = new()
		{
			MakeSession(3, "md", "rdp-tcp#23"),
		};
		List<RdpConnectionFact> facts = new()
		{
			new RdpConnectionFact
			{
				WtsSessionId = 3,
				UserName = "md",
				Ip = "203.0.113.7",
				FirstSeenUtc = new DateTime(2026, 5, 24, 0, 0, 0, DateTimeKind.Utc),
				LastSeenUtc = new DateTime(2026, 5, 25, 0, 0, 0, DateTimeKind.Utc),
				FailedLogons = 1,
				SuccessfulLogons = 4,
			},
		};

		LocalSessionEnrichmentResult result = LocalSessionEnricher.Enrich(
			sessions, Array.Empty<SessionIpCorrelation>(), facts);

		Assert.Equal("203.0.113.7", sessions[0].ClientAddress);
		Assert.Equal(1, sessions[0].HistoricalFailedLogons);
		Assert.Equal(4, sessions[0].HistoricalSuccessfulLogons);
		Assert.Equal(1, result.IpAssignedFromFacts);
		Assert.Equal(1, result.HistoricalApplied);
	}

	[Fact]
	public void Enrich_UnambiguousRecentFactByUser_FillsIp()
	{
		List<RdpSessionDto> sessions = new()
		{
			MakeSession(7, "alice", "rdp-tcp#5"),
		};
		List<RdpConnectionFact> facts = new()
		{
			new RdpConnectionFact
			{
				WtsSessionId = 99, // different session id
				UserName = "alice",
				Ip = "198.51.100.42",
				FirstSeenUtc = new DateTime(2026, 5, 1, 0, 0, 0, DateTimeKind.Utc),
				LastSeenUtc = new DateTime(2026, 5, 23, 0, 0, 0, DateTimeKind.Utc),
				FailedLogons = 0,
				SuccessfulLogons = 3,
			},
		};

		LocalSessionEnricher.Enrich(sessions, Array.Empty<SessionIpCorrelation>(), facts);

		Assert.Equal("198.51.100.42", sessions[0].ClientAddress);
	}

	[Fact]
	public void Enrich_AmbiguousFactsByUser_LeavesIpBlank()
	{
		List<RdpSessionDto> sessions = new()
		{
			MakeSession(7, "alice", "rdp-tcp#5"),
		};
		List<RdpConnectionFact> facts = new()
		{
			new RdpConnectionFact
			{
				WtsSessionId = 90, UserName = "alice", Ip = "198.51.100.42",
				FirstSeenUtc = DateTime.UtcNow, LastSeenUtc = DateTime.UtcNow,
			},
			new RdpConnectionFact
			{
				WtsSessionId = 91, UserName = "alice", Ip = "192.0.2.42",
				FirstSeenUtc = DateTime.UtcNow, LastSeenUtc = DateTime.UtcNow,
			},
		};

		LocalSessionEnricher.Enrich(sessions, Array.Empty<SessionIpCorrelation>(), facts);

		Assert.True(string.IsNullOrEmpty(sessions[0].ClientAddress));
	}

	[Fact]
	public void Enrich_NeverOverwritesAuthoritativeLiveClientAddress()
	{
		RdpSessionDto session = MakeSession(2, "af", "rdp-tcp#1");
		session.ClientAddress = "10.0.0.1"; // live value
		List<RdpSessionDto> sessions = new() { session };
		List<SessionIpCorrelation> correlations = new()
		{
			new SessionIpCorrelation { WtsSessionId = 2, UserName = "af", Ip = "1.2.3.4",
				FirstSeenUtc = DateTime.UtcNow, LastSeenUtc = DateTime.UtcNow },
		};

		LocalSessionEnricher.Enrich(sessions, correlations, Array.Empty<RdpConnectionFact>());

		Assert.Equal("10.0.0.1", sessions[0].ClientAddress);
	}

	[Theory]
	[InlineData("console")]
	[InlineData("services")]
	[InlineData("")]
	public void Enrich_DoesNotTouchNonRdpRows(string sessionName)
	{
		List<RdpSessionDto> sessions = new()
		{
			MakeSession(0, "SYSTEM", sessionName, state: "Disc", isActive: false),
		};
		List<RdpConnectionFact> facts = new()
		{
			new RdpConnectionFact
			{
				WtsSessionId = 0, UserName = "SYSTEM", Ip = "203.0.113.1",
				FirstSeenUtc = DateTime.UtcNow, LastSeenUtc = DateTime.UtcNow,
			},
		};

		LocalSessionEnrichmentResult result = LocalSessionEnricher.Enrich(
			sessions, Array.Empty<SessionIpCorrelation>(), facts);

		Assert.Equal(0, result.CandidateRdpSessions);
		Assert.Equal(0, result.IpAssignedFromFacts);
		Assert.True(string.IsNullOrEmpty(sessions[0].ClientAddress));
		Assert.Null(sessions[0].HistoricalFirstSeenUtc);
	}

	[Fact]
	public void Enrich_NoFacts_LeavesFieldsBlankAndReportsZeroApplied()
	{
		List<RdpSessionDto> sessions = new()
		{
			MakeSession(2, "af", "rdp-tcp#1"),
		};

		LocalSessionEnrichmentResult result = LocalSessionEnricher.Enrich(
			sessions, Array.Empty<SessionIpCorrelation>(), Array.Empty<RdpConnectionFact>());

		Assert.Equal(1, result.CandidateRdpSessions);
		Assert.Equal(0, result.IpAssignedFromFacts);
		Assert.Equal(0, result.HistoricalApplied);
		Assert.False(result.AnyApplied);
		Assert.True(string.IsNullOrEmpty(sessions[0].ClientAddress));
		Assert.Equal(0, sessions[0].HistoricalFailedLogons);
	}

	[Fact]
	public void IsRdpClientRow_TrueForRdpTcp_FalseForListenerOrConsole()
	{
		Assert.True(LocalSessionEnricher.IsRdpClientRow(MakeSession(2, "af", "rdp-tcp#1")));
		Assert.True(LocalSessionEnricher.IsRdpClientRow(MakeSession(3, "md", "RDP-Tcp#23")));
		Assert.False(LocalSessionEnricher.IsRdpClientRow(MakeSession(1, "user", "console")));
		Assert.False(LocalSessionEnricher.IsRdpClientRow(MakeSession(0, "SYSTEM", "services")));
		Assert.False(LocalSessionEnricher.IsRdpClientRow(MakeSession(65536, string.Empty, string.Empty)));
	}
}
