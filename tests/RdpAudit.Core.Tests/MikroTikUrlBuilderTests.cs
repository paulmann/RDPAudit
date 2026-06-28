// File:    tests/RdpAudit.Core.Tests/MikroTikUrlBuilderTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: Pure URL composition tests for the Stage 9 MikroTik integration. Verifies the builder
//          honours BaseUrl when supplied, composes Scheme/Host/Port correctly when not, rejects
//          unsupported schemes, validates host syntax, brackets IPv6 literals, and combines REST
//          paths defensively.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Config;
using RdpAudit.Core.MikroTik;
using Xunit;

namespace RdpAudit.Core.Tests;

public class MikroTikUrlBuilderTests
{
	[Fact]
	public void Build_UsesBaseUrl_WhenSupplied()
	{
		MikroTikOptions opts = new()
		{
			BaseUrl = "https://10.0.0.1:8443/",
			Host = "ignored-host",
			UseHttps = false,
		};

		MikroTikUrlBuilder.Result r = MikroTikUrlBuilder.Build(opts);

		Assert.True(r.Ok);
		Assert.Equal("https://10.0.0.1:8443", r.Url);
	}

	[Fact]
	public void Build_ComposesFromHostAndPort_WhenBaseUrlEmpty()
	{
		MikroTikOptions opts = new()
		{
			Host = "router.lab",
			UseHttps = true,
			Port = 0,
		};

		MikroTikUrlBuilder.Result r = MikroTikUrlBuilder.Build(opts);

		Assert.True(r.Ok);
		Assert.Equal("https://router.lab", r.Url);
	}

	[Fact]
	public void Build_HonoursExplicitPort()
	{
		MikroTikOptions opts = new()
		{
			Host = "10.0.0.5",
			UseHttps = false,
			Port = 8080,
		};

		MikroTikUrlBuilder.Result r = MikroTikUrlBuilder.Build(opts);

		Assert.True(r.Ok);
		Assert.Equal("http://10.0.0.5:8080", r.Url);
	}

	[Fact]
	public void Build_WrapsIpv6_InBrackets()
	{
		MikroTikOptions opts = new()
		{
			Host = "fd00::1",
			UseHttps = true,
		};

		MikroTikUrlBuilder.Result r = MikroTikUrlBuilder.Build(opts);

		Assert.True(r.Ok);
		Assert.StartsWith("https://[fd00::1]", r.Url, System.StringComparison.OrdinalIgnoreCase);
	}

	[Fact]
	public void Build_FailsOnEmptyHost()
	{
		MikroTikOptions opts = new();
		MikroTikUrlBuilder.Result r = MikroTikUrlBuilder.Build(opts);

		Assert.False(r.Ok);
		Assert.NotNull(r.Error);
	}

	[Fact]
	public void Build_RejectsNonHttpScheme()
	{
		MikroTikOptions opts = new() { BaseUrl = "ftp://router/" };
		MikroTikUrlBuilder.Result r = MikroTikUrlBuilder.Build(opts);

		Assert.False(r.Ok);
		Assert.NotNull(r.Error);
	}

	[Fact]
	public void Build_RejectsInvalidHostCharacters()
	{
		MikroTikOptions opts = new() { Host = "router with space" };
		MikroTikUrlBuilder.Result r = MikroTikUrlBuilder.Build(opts);

		Assert.False(r.Ok);
	}

	[Fact]
	public void Build_RejectsPortOutOfRange()
	{
		MikroTikOptions opts = new() { Host = "router", Port = 70000 };
		MikroTikUrlBuilder.Result r = MikroTikUrlBuilder.Build(opts);

		Assert.False(r.Ok);
	}

	[Theory]
	[InlineData("https://router", "system/resource", "https://router/rest/system/resource")]
	[InlineData("https://router/", "ip/firewall/filter", "https://router/rest/ip/firewall/filter")]
	[InlineData("http://10.0.0.1:8080", "rest/system/resource", "http://10.0.0.1:8080/rest/system/resource")]
	[InlineData("http://10.0.0.1", "/ip/firewall/filter", "http://10.0.0.1/rest/ip/firewall/filter")]
	public void CombineRestPath_ProducesExpectedUrl(string baseUrl, string path, string expected)
	{
		string actual = MikroTikUrlBuilder.CombineRestPath(baseUrl, path);
		Assert.Equal(expected, actual);
	}

	[Fact]
	public void ComposedBlockDuration_FallsBackToOneHour_WhenAllZero()
	{
		MikroTikOptions opts = new() { BlockDurationDays = 0, BlockDurationHours = 0, BlockDurationMinutes = 0 };
		System.TimeSpan d = opts.ComposedBlockDuration();
		Assert.Equal(System.TimeSpan.FromHours(1), d);
	}

	[Fact]
	public void ComposedBlockDuration_SumsComponents()
	{
		MikroTikOptions opts = new() { BlockDurationDays = 1, BlockDurationHours = 2, BlockDurationMinutes = 30 };
		System.TimeSpan d = opts.ComposedBlockDuration();
		Assert.Equal(System.TimeSpan.FromDays(1) + System.TimeSpan.FromHours(2) + System.TimeSpan.FromMinutes(30), d);
	}

	[Fact]
	public void DescribeEndpoint_PrefersBaseUrl()
	{
		MikroTikOptions opts = new() { BaseUrl = "https://router:8443", Host = "ignored" };
		Assert.Equal("https://router:8443", opts.DescribeEndpoint());
	}

	[Fact]
	public void DescribeEndpoint_ComposesWithoutPortWhenZero()
	{
		MikroTikOptions opts = new() { Host = "router.lab", UseHttps = false, Port = 0 };
		Assert.Equal("http://router.lab", opts.DescribeEndpoint());
	}
}
