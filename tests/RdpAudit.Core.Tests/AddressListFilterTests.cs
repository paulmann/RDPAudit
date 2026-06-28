// File:    tests/RdpAudit.Core.Tests/AddressListFilterTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: Locks the Stage 5 Firewall-tab filter predicate and IP / login normalisation helpers
//          extracted into Core so they can be unit tested without a UI host.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Util;
using Xunit;

namespace RdpAudit.Core.Tests;

public class AddressListFilterTests
{
	[Fact]
	public void EmptyQuery_MatchesEverything()
	{
		AddressListFilter filter = new() { Query = null };
		Assert.True(filter.IsEmpty);
		Assert.True(filter.Matches("203.0.113.10", "manual", "Configurator"));
		Assert.True(filter.Matches((string?)null));
	}

	[Fact]
	public void WhitespaceQuery_MatchesEverything()
	{
		AddressListFilter filter = new() { Query = "   " };
		Assert.True(filter.IsEmpty);
		Assert.True(filter.Matches("anything", "fields"));
	}

	[Fact]
	public void Query_IsCaseInsensitiveSubstring()
	{
		AddressListFilter filter = new() { Query = "MANUAL" };
		Assert.False(filter.IsEmpty);
		Assert.True(filter.Matches("203.0.113.10", "Manual operator add", "Configurator"));
		Assert.False(filter.Matches("198.51.100.5", "auto", "AutoBlock"));
	}

	[Fact]
	public void Query_AppliesToAnyField()
	{
		AddressListFilter filter = new() { Query = "AutoBlock" };
		Assert.True(filter.Matches("203.0.113.10", "manual", "AutoBlock"));
		Assert.True(filter.Matches("203.0.113.10", "AutoBlock decision", null));
	}

	[Fact]
	public void Matches_ToleratesNullFields()
	{
		AddressListFilter filter = new() { Query = "abc" };
		Assert.False(filter.Matches(null, null, null));
	}

	[Theory]
	[InlineData("203.0.113.10", true)]
	[InlineData("  198.51.100.5  ", true)]
	[InlineData("::1", true)]
	[InlineData("2001:db8::1", true)]
	[InlineData("not-an-ip", false)]
	[InlineData(" ", false)]
	[InlineData(null, false)]
	public void IsValidIp_RecognisesIpv4AndIpv6(string? input, bool expected)
	{
		Assert.Equal(expected, AddressListFilter.IsValidIp(input));
	}

	[Fact]
	public void NormalizeIp_CanonicalisesIpv6()
	{
		string normalised = AddressListFilter.NormalizeIp("  2001:db8:0:0:0:0:0:1  ");
		Assert.Equal("2001:db8::1", normalised);
	}

	[Fact]
	public void NormalizeIp_ThrowsOnInvalid()
	{
		Assert.Throws<FormatException>(() => AddressListFilter.NormalizeIp("not.an.ip.1"));
	}

	[Theory]
	[InlineData("Administrator", "administrator")]
	[InlineData("  ROOT  ", "root")]
	[InlineData("guest", "guest")]
	public void NormalizeLogin_TrimsAndLowercases(string input, string expected)
	{
		Assert.Equal(expected, AddressListFilter.NormalizeLogin(input));
	}

	[Fact]
	public void NormalizeLogin_RejectsControlCharacters()
	{
		Assert.Throws<FormatException>(() => AddressListFilter.NormalizeLogin("admin"));
	}
}
