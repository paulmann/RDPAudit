// File:    tests/RdpAudit.Service.Tests/ExternalRdpLoginRuleMessageTests.cs
// Module:  RdpAudit.Service.Tests
// Purpose: v1.2.0 fix. The alert message produced by ExternalRdpLoginRule must never end in a
//          trailing blank "as " when the user name is missing — operators were seeing literal
//          messages like "External RDP login from public IP 1.2.3.4 as " in the Service tab.
//          Pin the safe message shape here so a future regression is caught at build time.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Service.Alerts;
using Xunit;

namespace RdpAudit.Service.Tests;

public class ExternalRdpLoginRuleMessageTests
{
	[Fact]
	public void Message_WithKnownUser_ContainsAsClause()
	{
		string m = ExternalRdpLoginRule.BuildMessage("203.0.113.10", "alice");
		Assert.Equal("External RDP login from public IP 203.0.113.10 as alice", m);
	}

	[Theory]
	[InlineData(null)]
	[InlineData("")]
	[InlineData("   ")]
	[InlineData("-")]
	[InlineData("N/A")]
	[InlineData("n/a")]
	public void Message_WithBlankOrSentinelUser_OmitsAsClause(string? userName)
	{
		string m = ExternalRdpLoginRule.BuildMessage("203.0.113.10", userName);
		Assert.DoesNotContain(" as ", m, StringComparison.Ordinal);
		Assert.False(m.EndsWith("as ", StringComparison.Ordinal));
		Assert.False(m.EndsWith("as", StringComparison.Ordinal));
		Assert.Equal("External RDP login from public IP 203.0.113.10", m);
	}

	[Fact]
	public void Message_WithMissingIp_StillProducesReadableMessage()
	{
		string m = ExternalRdpLoginRule.BuildMessage(null, null);
		Assert.False(m.EndsWith("as ", StringComparison.Ordinal));
		Assert.Contains("(unknown IP)", m, StringComparison.Ordinal);
	}
}
