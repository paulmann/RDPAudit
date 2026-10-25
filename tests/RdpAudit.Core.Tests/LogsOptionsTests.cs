// File:    tests/RdpAudit.Core.Tests/LogsOptionsTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: Locks the operation-log viewing-depth and page-size policy: the 60-day default that
//          bounds the Logs tab and retention pass, the [1, 3650] depth clamp, the [1, 1000] page-size
//          clamp, and the "0 or negative means use the default" semantics the IPC handler relies on.
//          If these regress, the Logs tab could ask the service to scan or serialize the whole table.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Config;
using Xunit;

namespace RdpAudit.Core.Tests;

/// <summary>Pins the Logs viewing-depth / retention / page-size defaults and clamping.</summary>
public class LogsOptionsTests
{
	[Fact]
	public void Defaults_AreSixtyDaysAndFiveHundredPageSize()
	{
		LogsOptions options = new();
		Assert.Equal(60, options.ViewDepthDays);
		Assert.Equal(60, options.RetentionDays);
		Assert.Equal(60, LogsOptions.DefaultDepthDays);
		Assert.Equal(500, options.DefaultPageSize);
	}

	[Theory]
	[InlineData(0, 1)]
	[InlineData(-5, 1)]
	[InlineData(1, 1)]
	[InlineData(60, 60)]
	[InlineData(3650, 3650)]
	[InlineData(99999, 3650)]
	public void ResolveViewDepthDays_ClampsToSupportedRange(int input, int expected)
	{
		LogsOptions options = new() { ViewDepthDays = input };
		Assert.Equal(expected, options.ResolveViewDepthDays());
	}

	[Theory]
	[InlineData(0, 1)]
	[InlineData(3651, 3650)]
	[InlineData(45, 45)]
	public void ResolveRetentionDays_ClampsToSupportedRange(int input, int expected)
	{
		LogsOptions options = new() { RetentionDays = input };
		Assert.Equal(expected, options.ResolveRetentionDays());
	}

	[Theory]
	[InlineData(1, true)]
	[InlineData(3650, true)]
	[InlineData(0, false)]
	[InlineData(3651, false)]
	public void IsValidDepth_HonoursInclusiveBounds(int value, bool expected)
	{
		Assert.Equal(expected, LogsOptions.IsValidDepth(value));
	}

	[Theory]
	[InlineData(0, 500)]      // 0 -> default page size
	[InlineData(-10, 500)]    // negative -> default page size
	[InlineData(250, 250)]    // in range
	[InlineData(5000, 1000)]  // above max -> clamped to MaxPageSize
	public void ResolvePageSize_UsesDefaultForNonPositiveAndClampsToMax(int requested, int expected)
	{
		LogsOptions options = new();
		Assert.Equal(expected, options.ResolvePageSize(requested));
	}

	[Fact]
	public void ResolveDefaultPageSize_IsClampedDefault()
	{
		LogsOptions options = new() { DefaultPageSize = 500 };
		Assert.Equal(500, options.ResolveDefaultPageSize());
		Assert.Equal(1000, LogsOptions.MaxPageSize);
	}
}
