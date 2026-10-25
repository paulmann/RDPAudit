// File:    tests/RdpAudit.Core.Tests/ApiOptionsTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: Locks the REST API option defaults and clamping policy: disabled by default,
//          loopback listen address by default, the [1..65535] port range, the
//          [1..10,000] connection range, the [1..60,000] per-IP rate-limit range and the
//          loopback detection used by the fail-closed listener startup. A regression here
//          could silently expose the API on a non-loopback address or disable the rate
//          limiter that bounds per-IP traffic.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Config;
using Xunit;

namespace RdpAudit.Core.Tests;

/// <summary>Pins the REST API option defaults and clamping behaviour.</summary>
public class ApiOptionsTests
{
	[Fact]
	public void Defaults_AreDisabledOnLoopbackWithSafeWideSettings()
	{
		ApiOptions options = new();
		Assert.False(options.Enabled);
		Assert.Equal(string.Empty, options.Token);
		Assert.Equal(ApiOptions.DefaultListenAddress, options.ListenAddress);
		Assert.Equal(ApiOptions.DefaultPort, options.Port);
		Assert.False(options.AllowInsecureLoopback);
		Assert.Equal(100, options.MaxConnections);
		Assert.Equal(60, options.RateLimitPerMinute);
	}

	[Theory]
	[InlineData(0, 1)]
	[InlineData(-500, 1)]
	[InlineData(1, 1)]
	[InlineData(8443, 8443)]
	[InlineData(65535, 65535)]
	[InlineData(65536, 65535)]
	[InlineData(int.MaxValue, 65535)]
	public void ResolvePort_ClampsToSupportedRange(int input, int expected)
	{
		ApiOptions options = new() { Port = input };
		Assert.Equal(expected, options.ResolvePort());
	}

	[Theory]
	[InlineData(0, 1)]
	[InlineData(-10, 1)]
	[InlineData(1, 1)]
	[InlineData(100, 100)]
	[InlineData(10000, 10000)]
	[InlineData(10001, 10000)]
	public void ResolveMaxConnections_ClampsToSupportedRange(int input, int expected)
	{
		ApiOptions options = new() { MaxConnections = input };
		Assert.Equal(expected, options.ResolveMaxConnections());
	}

	[Theory]
	[InlineData(0, 1)]
	[InlineData(-3, 1)]
	[InlineData(1, 1)]
	[InlineData(120, 120)]
	[InlineData(60000, 60000)]
	[InlineData(60001, 60000)]
	public void ResolveRateLimitPerMinute_ClampsToSupportedRange(int input, int expected)
	{
		ApiOptions options = new() { RateLimitPerMinute = input };
		Assert.Equal(expected, options.ResolveRateLimitPerMinute());
	}

	[Theory]
	[InlineData("", ApiOptions.DefaultListenAddress)]
	[InlineData("   ", ApiOptions.DefaultListenAddress)]
	[InlineData("127.0.0.1", "127.0.0.1")]
	[InlineData(" 10.0.0.5 ", "10.0.0.5")]
	[InlineData("::1", "::1")]
	[InlineData("0.0.0.0", "0.0.0.0")]
	public void ResolveListenAddress_FallsBackToLoopbackOrTrims(string? input, string expected)
	{
		ApiOptions options = new() { ListenAddress = input ?? string.Empty };
		Assert.Equal(expected, options.ResolveListenAddress());
	}

	[Theory]
	[InlineData("127.0.0.1", true)]
	[InlineData("localhost", true)]
	[InlineData("LOCALHOST", true)]
	[InlineData("::1", true)]
	[InlineData("", true)]
	[InlineData("0.0.0.0", false)]
	[InlineData("10.0.0.5", false)]
	[InlineData("192.168.1.10", false)]
	[InlineData("rdpaudit.example.com", false)]
	public void IsLoopback_RecognisesOnlyLoopbackLiterals(string listenAddress, bool expected)
	{
		ApiOptions options = new() { ListenAddress = listenAddress };
		Assert.Equal(expected, options.IsLoopback());
	}

	[Fact]
	public void Constants_ExposeSupportedBounds()
	{
		Assert.Equal(1, ApiOptions.MinPort);
		Assert.Equal(65535, ApiOptions.MaxPort);
		Assert.Equal(1, ApiOptions.MinMaxConnections);
		Assert.Equal(10_000, ApiOptions.MaxMaxConnections);
		Assert.Equal(1, ApiOptions.MinRateLimitPerMinute);
		Assert.Equal(60_000, ApiOptions.MaxRateLimitPerMinute);
		Assert.Equal("127.0.0.1", ApiOptions.DefaultListenAddress);
		Assert.Equal(8443, ApiOptions.DefaultPort);
	}

	[Fact]
	public void RdpAuditOptions_ExposesApi_WithSafeDefaults()
	{
		RdpAuditOptions root = new();
		Assert.NotNull(root.Api);
		Assert.False(root.Api.Enabled);
	}
}
