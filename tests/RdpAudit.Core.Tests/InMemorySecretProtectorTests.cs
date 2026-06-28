// File:    tests/RdpAudit.Core.Tests/InMemorySecretProtectorTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: Round-trip tests for the non-production InMemorySecretProtector. Covers envelope
//          detection, protect/unprotect parity, and pass-through of unwrapped plaintext values.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Security;
using Xunit;

namespace RdpAudit.Core.Tests;

/// <summary>Round-trip tests for the non-production InMemorySecretProtector.</summary>
public class InMemorySecretProtectorTests
{
	[Theory]
	[InlineData("api-key-1234")]
	[InlineData("π€†öl/secret")]
	[InlineData("aB9!@#$%^&*()_+-={}[]|:;\"'<>,.?/")]
	public void ProtectUnprotect_RoundTripsExactly(string plaintext)
	{
		InMemorySecretProtector p = new();

		string envelope = p.Protect(plaintext);
		Assert.True(p.IsProtectedEnvelope(envelope));
		Assert.DoesNotContain(plaintext, envelope, StringComparison.Ordinal);

		string recovered = p.Unprotect(envelope);
		Assert.Equal(plaintext, recovered);
	}

	[Fact]
	public void Unprotect_PassesThroughPlaintextValues()
	{
		InMemorySecretProtector p = new();

		// Migration scenario: appsettings.json still holds the raw value.
		Assert.Equal("plain-secret", p.Unprotect("plain-secret"));
	}

	[Fact]
	public void IsAvailable_AlwaysTrue()
	{
		Assert.True(new InMemorySecretProtector().IsAvailable);
	}

	[Fact]
	public void Protect_AlwaysProducesEnvelope()
	{
		InMemorySecretProtector p = new();
		string envelope = p.Protect("anything");
		Assert.True(ProtectedEnvelope.IsEnvelope(envelope));
	}

	[Fact]
	public void IsProtectedEnvelope_FalseForPlaintext()
	{
		InMemorySecretProtector p = new();
		Assert.False(p.IsProtectedEnvelope("not-an-envelope"));
		Assert.False(p.IsProtectedEnvelope(string.Empty));
		Assert.False(p.IsProtectedEnvelope(null));
	}
}
