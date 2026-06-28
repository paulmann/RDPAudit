// File:    tests/RdpAudit.Core.Tests/AbuseIpDbApiKeyValidatorTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: Unit tests for the pure AbuseIPDB API key format validator.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.AbuseIpDb;
using Xunit;

namespace RdpAudit.Core.Tests;

/// <summary>Unit tests for <see cref="AbuseIpDbApiKeyValidator"/>.</summary>
public class AbuseIpDbApiKeyValidatorTests
{
	[Fact]
	public void IsLikelyValid_NullOrEmpty_ReturnsFalse()
	{
		Assert.False(AbuseIpDbApiKeyValidator.IsLikelyValid(null));
		Assert.False(AbuseIpDbApiKeyValidator.IsLikelyValid(""));
		Assert.False(AbuseIpDbApiKeyValidator.IsLikelyValid("   "));
	}

	[Fact]
	public void IsLikelyValid_CanonicalLengthHex_ReturnsTrue()
	{
		string key = new('a', AbuseIpDbApiKeyValidator.CanonicalKeyLength);
		Assert.True(AbuseIpDbApiKeyValidator.IsLikelyValid(key));
	}

	[Fact]
	public void IsLikelyValid_NonHexChar_ReturnsFalse()
	{
		string baseKey = new('a', AbuseIpDbApiKeyValidator.CanonicalKeyLength - 1);
		string key = baseKey + "z";
		Assert.False(AbuseIpDbApiKeyValidator.IsLikelyValid(key));
	}

	[Fact]
	public void IsLikelyValid_TooShort_ReturnsFalse()
	{
		Assert.False(AbuseIpDbApiKeyValidator.IsLikelyValid(new string('a', 10)));
	}

	[Fact]
	public void IsLikelyValid_TooLong_ReturnsFalse()
	{
		Assert.False(AbuseIpDbApiKeyValidator.IsLikelyValid(new string('a', 200)));
	}
}
