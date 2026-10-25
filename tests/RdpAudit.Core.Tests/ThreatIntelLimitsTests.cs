// File:    tests/RdpAudit.Core.Tests/ThreatIntelLimitsTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: Unit coverage for ThreatIntelLimits - the single place that clamps the Backlog #5
//          Check* configuration values. Verifies the documented bands for per-minute rate, daily
//          budget, maxAgeInDays and worker interval, so a misconfigured appsettings.json can never
//          produce a runaway loop or an overflowing daily budget counter.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.ThreatIntel;
using Xunit;

namespace RdpAudit.Core.Tests;

/// <summary>Unit coverage for <see cref="ThreatIntelLimits"/>.</summary>
public class ThreatIntelLimitsTests
{
	[Theory]
	[InlineData(0, ThreatIntelLimits.MinLookupsPerMinute)]
	[InlineData(-5, ThreatIntelLimits.MinLookupsPerMinute)]
	[InlineData(1, 1)]
	[InlineData(30, 30)]
	[InlineData(300, 300)]
	[InlineData(301, 300)]
	[InlineData(100000, 300)]
	public void ClampLookupsPerMinute_EnsuresBand(int input, int expected)
	{
		Assert.Equal(expected, ThreatIntelLimits.ClampLookupsPerMinute(input));
	}

	[Theory]
	[InlineData(0, ThreatIntelLimits.MinLookupsPerDay)]
	[InlineData(-1, ThreatIntelLimits.MinLookupsPerDay)]
	[InlineData(1, 1)]
	[InlineData(500, 500)]
	[InlineData(994, 994)]
	[InlineData(995, 995)]
	[InlineData(996, 995)]
	[InlineData(100000, 995)]
	public void ClampLookupsPerDay_EnsuresBand(int input, int expected)
	{
		Assert.Equal(expected, ThreatIntelLimits.ClampLookupsPerDay(input));
	}

	[Theory]
	[InlineData(0, ThreatIntelLimits.MinMaxAgeInDays)]
	[InlineData(-10, ThreatIntelLimits.MinMaxAgeInDays)]
	[InlineData(1, 1)]
	[InlineData(30, 30)]
	[InlineData(365, 365)]
	[InlineData(366, 365)]
	[InlineData(10000, 365)]
	public void ClampMaxAgeInDays_EnsuresBand(int input, int expected)
	{
		Assert.Equal(expected, ThreatIntelLimits.ClampMaxAgeInDays(input));
	}

	[Theory]
	[InlineData(0, ThreatIntelLimits.MinWorkerIntervalSeconds)]
	[InlineData(-1, ThreatIntelLimits.MinWorkerIntervalSeconds)]
	[InlineData(29, 30)]
	[InlineData(30, 30)]
	[InlineData(300, 300)]
	[InlineData(86400, 86400)]
	[InlineData(86401, 86400)]
	[InlineData(1000000, 86400)]
	public void ClampWorkerIntervalSeconds_EnsuresBand(int input, int expected)
	{
		Assert.Equal(expected, ThreatIntelLimits.ClampWorkerIntervalSeconds(input));
	}
}
