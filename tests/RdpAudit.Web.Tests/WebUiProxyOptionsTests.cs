// File:    tests/RdpAudit.Web.Tests/WebUiProxyOptionsTests.cs
// Module:  RdpAudit.Web.Tests
// Purpose: Pins the security invariants of WebUiProxyOptions.Resolve() (plan step 12 hardening):
//          loopback-only backend unless AllowNonLoopbackBackend is deliberately set, strict
//          40-hex thumbprint validation, trailing-slash normalization, and the fail-safe
//          AllowInlineScripts default. A manual appsettings edit that tries to point the proxy
//          (which holds the shared bearer token) at a non-loopback host must fail closed at boot.
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Web.Config;
using Xunit;

namespace RdpAudit.Web.Tests;

public sealed class WebUiProxyOptionsTests
{
	[Theory]
	[InlineData("https://127.0.0.1:8443")]
	[InlineData("http://127.0.0.1:9999")]
	[InlineData("https://127.1.2.3:443")]
	[InlineData("https://localhost:8443")]
	[InlineData("http://localhost:1234")]
	[InlineData("https://[::1]:8443")]
	public void Resolve_AcceptsLoopbackBackends(string url)
	{
		WebUiProxyOptions options = new() { BackendBaseUrl = url };

		options.Resolve();

		Assert.Equal(url.TrimEnd('/'), options.ResolvedBackendBaseUrl);
		Assert.False(options.AllowInlineScripts);
		Assert.Equal(string.Empty, options.ResolvedBackendCertificateThumbprint);
	}

	[Theory]
	[InlineData("https://192.168.1.10:8443")]
	[InlineData("http://10.0.0.5:8443")]
	[InlineData("https://evil.example.com:8443")]
	[InlineData("https://127.0.0.1.evil.example.com")]
	public void Resolve_NonLoopbackBackend_FailsClosed(string url)
	{
		WebUiProxyOptions options = new() { BackendBaseUrl = url };

		InvalidOperationException ex = Assert.Throws<InvalidOperationException>(() => options.Resolve());

		Assert.Contains("loopback", ex.Message, StringComparison.OrdinalIgnoreCase);
	}

	[Fact]
	public void Resolve_NonLoopbackBackend_WithExplicitOptIn_IsAccepted()
	{
		WebUiProxyOptions options = new()
		{
			BackendBaseUrl = "https://192.168.1.10:8443",
			AllowNonLoopbackBackend = true,
		};

		options.Resolve();

		Assert.Equal("https://192.168.1.10:8443", options.ResolvedBackendBaseUrl);
	}

	[Theory]
	[InlineData("")]
	[InlineData("   ")]
	[InlineData("ftp://127.0.0.1:8443")]
	[InlineData("127.0.0.1:8443")]
	public void Resolve_InvalidBackendUrl_Fails(string url)
	{
		WebUiProxyOptions options = new() { BackendBaseUrl = url };

		Assert.Throws<InvalidOperationException>(() => options.Resolve());
	}

	[Fact]
	public void Resolve_BackendUrl_WithTrailingSlash_IsNormalized()
	{
		WebUiProxyOptions options = new() { BackendBaseUrl = "https://127.0.0.1:8443/" };

		options.Resolve();

		Assert.Equal("https://127.0.0.1:8443", options.ResolvedBackendBaseUrl);
	}

	[Theory]
	[InlineData("AB12")]
	[InlineData("ZZZZ")]
	[InlineData("AB12CD34EF56AB12CD34EF56AB12CD34EF56AB12CD34")] // 40 chars, invalid hex
	public void Resolve_MalformedThumbprint_Fails(string thumbprint)
	{
		WebUiProxyOptions options = new() { BackendCertificateThumbprint = thumbprint };

		InvalidOperationException ex = Assert.Throws<InvalidOperationException>(() => options.Resolve());

		Assert.Contains("thumbprint", ex.Message, StringComparison.OrdinalIgnoreCase);
	}

	[Fact]
	public void Resolve_Thumbprint_IsNormalizedToUpperCase()
	{
		WebUiProxyOptions options = new()
		{
			BackendCertificateThumbprint = "ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12",
		};

		options.Resolve();

		Assert.Equal("AB12CD34EF56AB12CD34EF56AB12CD34EF56AB12", options.ResolvedBackendCertificateThumbprint);
	}

	[Fact]
	public void Resolve_BlankThumbprint_LeavesPinEmpty()
	{
		WebUiProxyOptions options = new() { BackendCertificateThumbprint = "   " };

		options.Resolve();

		Assert.Equal(string.Empty, options.ResolvedBackendCertificateThumbprint);
	}
}
