// File:    tests/RdpAudit.Core.Tests/ProtectedEnvelopeTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: Validates the JSON envelope helper used to wrap protected configuration secrets.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Text;
using RdpAudit.Core.Security;
using Xunit;

namespace RdpAudit.Core.Tests;

/// <summary>Validates the JSON envelope helper used to wrap protected configuration secrets.</summary>
public class ProtectedEnvelopeTests
{
	[Theory]
	[InlineData("", false)]
	[InlineData("   ", false)]
	[InlineData("not-json", false)]
	[InlineData("\"abc\"", false)]
	[InlineData("{\"foo\":\"bar\"}", false)]
	[InlineData("{\"$protected\":\"YWJj\"}", true)]
	[InlineData("{\"$protected\":\"YWJj\",\"scope\":\"LocalMachine\"}", true)]
	[InlineData("{\"$protected\":123}", false)]
	public void IsEnvelope_Detects(string value, bool expected)
	{
		Assert.Equal(expected, ProtectedEnvelope.IsEnvelope(value));
	}

	[Fact]
	public void Create_RoundTrips_PreservesCipherBytes()
	{
		byte[] cipher = Encoding.UTF8.GetBytes("not-a-real-secret");

		string envelope = ProtectedEnvelope.Create(cipher, SecretScope.LocalMachine);
		Assert.True(ProtectedEnvelope.IsEnvelope(envelope));
		Assert.Contains("\"$protected\":", envelope, StringComparison.Ordinal);
		Assert.Contains("\"scope\":\"LocalMachine\"", envelope, StringComparison.Ordinal);

		(byte[] parsedCipher, SecretScope scope) = ProtectedEnvelope.Parse(envelope);
		Assert.Equal(cipher, parsedCipher);
		Assert.Equal(SecretScope.LocalMachine, scope);
	}

	[Fact]
	public void Parse_RecognisesCurrentUserScope()
	{
		string envelope = ProtectedEnvelope.Create(new byte[] { 1, 2, 3 }, SecretScope.CurrentUser);
		(byte[] cipher, SecretScope scope) = ProtectedEnvelope.Parse(envelope);

		Assert.Equal(new byte[] { 1, 2, 3 }, cipher);
		Assert.Equal(SecretScope.CurrentUser, scope);
	}

	[Fact]
	public void Parse_ThrowsOnBadBase64()
	{
		string envelope = "{\"$protected\":\"not-base64!!!\",\"scope\":\"LocalMachine\"}";
		Assert.Throws<SecretProtectionException>(() => ProtectedEnvelope.Parse(envelope));
	}

	[Fact]
	public void Parse_ThrowsOnMissingMarker()
	{
		string envelope = "{\"scope\":\"LocalMachine\"}";
		Assert.Throws<SecretProtectionException>(() => ProtectedEnvelope.Parse(envelope));
	}

	[Fact]
	public void Parse_ThrowsOnInvalidJson()
	{
		Assert.Throws<SecretProtectionException>(() => ProtectedEnvelope.Parse("{ not json"));
	}
}
