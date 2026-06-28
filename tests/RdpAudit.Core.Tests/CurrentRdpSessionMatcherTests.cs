// File:    tests/RdpAudit.Core.Tests/CurrentRdpSessionMatcherTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: v1.3.8 — pin the operator-scoped "Current?" semantics. The RDP Clients tab must flag
//          Current only for the session owned by the user running the Configurator, identified by
//          the running process SessionId and the normalized current Windows identity. These tests
//          use the exact affected-host fixture from the brief: users pk (SessionId 13, Disc),
//          md (rdp-tcp#68, SessionId 14, Active), af (SessionId 15, Disc); current process
//          SessionId 14; identity XEON\md; $env:USERNAME md. Only md / 14 may be Current.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Ipc.Contracts;
using RdpAudit.Core.Util;
using Xunit;

namespace RdpAudit.Core.Tests;

public class CurrentRdpSessionMatcherTests
{
	private static RdpSessionDto Session(int id, string user, string sessionName, string state)
	{
		// Build the DTO exactly as QwinstaSessionMapper.Map would: IsActiveRdp from the classifier,
		// IsCurrent left false for the matcher to own.
		ActiveRdpClassification c = ActiveRdpSessionClassifier.Classify(id, sessionName, user, state);
		return new RdpSessionDto
		{
			SessionId = id,
			UserName = user,
			SessionName = sessionName,
			State = state,
			IsActive = string.Equals(state, "Active", StringComparison.OrdinalIgnoreCase),
			IsDisconnected = string.Equals(state, "Disconnected", StringComparison.OrdinalIgnoreCase),
			IsActiveRdp = c.IsActiveRdp,
			IsCurrent = false,
		};
	}

	private static List<RdpSessionDto> AffectedHostSessions() => new()
	{
		Session(13, "pk", "rdp-tcp#65", "Disconnected"),
		Session(14, "md", "rdp-tcp#68", "Active"),
		Session(15, "af", "rdp-tcp#70", "Disconnected"),
	};

	[Fact]
	public void Match_OnAffectedHost_OnlyOperatorSessionIsCurrent()
	{
		List<RdpSessionDto> sessions = AffectedHostSessions();
		OperatorSessionContext ctx = new(ProcessSessionId: 14, IdentityName: @"XEON\md", UserName: "md");

		CurrentRdpMatchResult result = CurrentRdpSessionMatcher.ApplyTo(sessions, ctx);

		Assert.Equal(1, result.CurrentCount);
		Assert.Equal(CurrentMatchRule.SessionId, result.RuleUsed);
		Assert.True(sessions.Single(s => s.SessionId == 14).IsCurrent);
		Assert.False(sessions.Single(s => s.SessionId == 13).IsCurrent);
		Assert.False(sessions.Single(s => s.SessionId == 15).IsCurrent);
	}

	[Fact]
	public void Match_DisconnectedUsers_AreNeverCurrent()
	{
		List<RdpSessionDto> sessions = AffectedHostSessions();
		// Even if the operator session id pointed at a disconnected row, it must not become Current
		// because a disconnected row is not an eligible active RDP session.
		OperatorSessionContext ctx = new(ProcessSessionId: 13, IdentityName: @"XEON\pk", UserName: "pk");

		CurrentRdpSessionMatcher.ApplyTo(sessions, ctx);

		Assert.False(sessions.Single(s => s.SessionId == 13).IsCurrent);
		Assert.False(sessions.Single(s => s.SessionId == 15).IsCurrent);
	}

	[Fact]
	public void Match_ActiveButForeignSession_IsNotCurrent()
	{
		// Two active RDP sessions; the operator is md/14. The foreign active session (bob/20) must
		// NOT be Current. Active status alone is not enough.
		List<RdpSessionDto> sessions = new()
		{
			Session(14, "md", "rdp-tcp#68", "Active"),
			Session(20, "bob", "rdp-tcp#80", "Active"),
		};
		OperatorSessionContext ctx = new(ProcessSessionId: 14, IdentityName: @"XEON\md", UserName: "md");

		CurrentRdpSessionMatcher.ApplyTo(sessions, ctx);

		Assert.True(sessions.Single(s => s.SessionId == 14).IsCurrent);
		Assert.False(sessions.Single(s => s.SessionId == 20).IsCurrent);
		Assert.Equal(1, sessions.Count(s => s.IsCurrent));
	}

	[Fact]
	public void Match_DomainQualifiedIdentity_ComparesLeafAndQualified()
	{
		// SessionId unknown — must fall back to identity. qwinsta reports the bare leaf "md";
		// the operator identity is the domain-qualified "XEON\md". They must match.
		List<RdpSessionDto> sessions = new()
		{
			Session(14, "md", "rdp-tcp#68", "Active"),
			Session(20, "af", "rdp-tcp#80", "Active"),
		};
		OperatorSessionContext ctx = new(ProcessSessionId: -1, IdentityName: @"XEON\md", UserName: "md");

		CurrentRdpMatchResult result = CurrentRdpSessionMatcher.ApplyTo(sessions, ctx);

		Assert.Equal(CurrentMatchRule.Identity, result.RuleUsed);
		Assert.True(sessions.Single(s => s.SessionId == 14).IsCurrent);
		Assert.False(sessions.Single(s => s.SessionId == 20).IsCurrent);
	}

	[Fact]
	public void Match_IdentityFallback_DoesNotMatchDisconnectedSameUser()
	{
		// If the only same-username row is disconnected, identity fallback must not flag it.
		List<RdpSessionDto> sessions = new()
		{
			Session(14, "md", "rdp-tcp#68", "Disconnected"),
		};
		OperatorSessionContext ctx = new(ProcessSessionId: -1, IdentityName: @"XEON\md", UserName: "md");

		CurrentRdpSessionMatcher.ApplyTo(sessions, ctx);

		Assert.False(sessions.Single(s => s.SessionId == 14).IsCurrent);
	}

	[Fact]
	public void Match_SessionIdWins_OverSameUsernameInAnotherSession()
	{
		// Same user logged into two active sessions; the process SessionId disambiguates so only
		// the operator's actual session is Current, not the other same-username session.
		List<RdpSessionDto> sessions = new()
		{
			Session(14, "md", "rdp-tcp#68", "Active"),
			Session(21, "md", "rdp-tcp#90", "Active"),
		};
		OperatorSessionContext ctx = new(ProcessSessionId: 14, IdentityName: @"XEON\md", UserName: "md");

		CurrentRdpMatchResult result = CurrentRdpSessionMatcher.ApplyTo(sessions, ctx);

		Assert.Equal(CurrentMatchRule.SessionId, result.RuleUsed);
		Assert.True(sessions.Single(s => s.SessionId == 14).IsCurrent);
		Assert.False(sessions.Single(s => s.SessionId == 21).IsCurrent);
	}

	[Fact]
	public void NormalizeAndLeaf_HandleQualifiedUpnAndBare()
	{
		Assert.Equal("md", CurrentRdpSessionMatcher.LeafUserName(@"XEON\md"));
		Assert.Equal("md", CurrentRdpSessionMatcher.LeafUserName("md@xeon.local"));
		Assert.Equal("md", CurrentRdpSessionMatcher.LeafUserName("md"));
		Assert.Equal(@"XEON\md", CurrentRdpSessionMatcher.NormalizeIdentity(@"XEON\md"));
		Assert.Equal(string.Empty, CurrentRdpSessionMatcher.LeafUserName(null));
	}

	[Fact]
	public void Describe_IncludesContextDiagnostics()
	{
		List<RdpSessionDto> sessions = AffectedHostSessions();
		OperatorSessionContext ctx = new(ProcessSessionId: 14, IdentityName: @"XEON\md", UserName: "md");
		CurrentRdpMatchResult result = CurrentRdpSessionMatcher.Match(sessions, ctx);

		string text = result.Describe();
		Assert.Contains("SessionId=14", text, StringComparison.Ordinal);
		Assert.Contains(@"XEON\md", text, StringComparison.Ordinal);
		Assert.Contains("username=md", text, StringComparison.Ordinal);
		Assert.Contains("rule=SessionId", text, StringComparison.Ordinal);
	}
}
