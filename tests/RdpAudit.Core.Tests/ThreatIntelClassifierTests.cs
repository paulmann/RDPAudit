// File:    tests/RdpAudit.Core.Tests/ThreatIntelClassifierTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: Unit coverage for ThreatIntelClassifier - the fail-closed High-risk decision rule and
//          the score clamp. A High-risk mark must be derivable only from a successful, public,
//          non-whitelisted, at-or-above-threshold lookup; every other path (errors, missing
//          fields, limits) must yield false so broken provider data can never manufacture a mark.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.ThreatIntel;
using Xunit;

namespace RdpAudit.Core.Tests;

/// <summary>Unit coverage for <see cref="ThreatIntelClassifier"/>.</summary>
public class ThreatIntelClassifierTests
{
	private const int Threshold = 80;

	[Fact]
	public void IsHighRisk_SuccessPublicNotWhitelistedAboveThreshold_ReturnsTrue()
	{
		ThreatIntelLookupResult result = new()
		{
			Outcome = ThreatIntelLookupOutcome.Success,
			Ip = "203.0.113.9",
			IsPublic = true,
			IsWhitelisted = false,
			AbuseConfidenceScore = 95,
		};

		Assert.True(ThreatIntelClassifier.IsHighRisk(result, Threshold));
	}

	[Fact]
	public void IsHighRisk_ScoreAtThreshold_ReturnsTrue()
	{
		ThreatIntelLookupResult result = new()
		{
			Outcome = ThreatIntelLookupOutcome.Success,
			IsPublic = true,
			IsWhitelisted = false,
			AbuseConfidenceScore = Threshold,
		};

		Assert.True(ThreatIntelClassifier.IsHighRisk(result, Threshold));
	}

	[Fact]
	public void IsHighRisk_ScoreBelowThreshold_ReturnsFalse()
	{
		ThreatIntelLookupResult result = new()
		{
			Outcome = ThreatIntelLookupOutcome.Success,
			IsPublic = true,
			IsWhitelisted = false,
			AbuseConfidenceScore = Threshold - 1,
		};

		Assert.False(ThreatIntelClassifier.IsHighRisk(result, Threshold));
	}

	[Theory]
	[InlineData(ThreatIntelLookupOutcome.Rejected)]
	[InlineData(ThreatIntelLookupOutcome.RateLimited)]
	[InlineData(ThreatIntelLookupOutcome.ServerError)]
	[InlineData(ThreatIntelLookupOutcome.TransportError)]
	[InlineData(ThreatIntelLookupOutcome.NotConfigured)]
	[InlineData(ThreatIntelLookupOutcome.MalformedResponse)]
	public void IsHighRisk_NonSuccessOutcome_ReturnsFalse(ThreatIntelLookupOutcome outcome)
	{
		ThreatIntelLookupResult result = new()
		{
			Outcome = outcome,
			IsPublic = true,
			IsWhitelisted = false,
			AbuseConfidenceScore = 100,
		};

		Assert.False(ThreatIntelClassifier.IsHighRisk(result, Threshold));
	}

	[Fact]
	public void IsHighRisk_NullResult_ReturnsFalse()
	{
		Assert.False(ThreatIntelClassifier.IsHighRisk(null, Threshold));
	}

	[Fact]
	public void IsHighRisk_WhitelistedTrue_ReturnsFalse()
	{
		ThreatIntelLookupResult result = new()
		{
			Outcome = ThreatIntelLookupOutcome.Success,
			IsPublic = true,
			IsWhitelisted = true,
			AbuseConfidenceScore = 100,
		};

		Assert.False(ThreatIntelClassifier.IsHighRisk(result, Threshold));
	}

	[Fact]
	public void IsHighRisk_PrivateIpReportedNotPublic_ReturnsFalse()
	{
		ThreatIntelLookupResult result = new()
		{
			Outcome = ThreatIntelLookupOutcome.Success,
			IsPublic = false,
			IsWhitelisted = false,
			AbuseConfidenceScore = 100,
		};

		Assert.False(ThreatIntelClassifier.IsHighRisk(result, Threshold));
	}

	[Fact]
	public void IsHighRisk_MissingPublicFlag_ReturnsFalse()
	{
		ThreatIntelLookupResult result = new()
		{
			Outcome = ThreatIntelLookupOutcome.Success,
			IsPublic = null,
			IsWhitelisted = false,
			AbuseConfidenceScore = 100,
		};

		Assert.False(ThreatIntelClassifier.IsHighRisk(result, Threshold));
	}

	[Fact]
	public void IsHighRisk_MissingScore_ReturnsFalse()
	{
		ThreatIntelLookupResult result = new()
		{
			Outcome = ThreatIntelLookupOutcome.Success,
			IsPublic = true,
			IsWhitelisted = false,
			AbuseConfidenceScore = null,
		};

		Assert.False(ThreatIntelClassifier.IsHighRisk(result, Threshold));
	}

	[Theory]
	[InlineData(-1000, 0)]
	[InlineData(-1, 0)]
	[InlineData(0, 0)]
	[InlineData(50, 50)]
	[InlineData(100, 100)]
	[InlineData(101, 100)]
	[InlineData(10000, 100)]
	public void ClampScore_EnforcesBand(int input, int expected)
	{
		Assert.Equal(expected, ThreatIntelClassifier.ClampScore(input));
	}
}
