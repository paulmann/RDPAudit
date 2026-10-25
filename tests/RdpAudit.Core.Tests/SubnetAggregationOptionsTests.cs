/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : SubnetAggregationOptionsTests.cs
// Project: RdpAudit.Core.Tests
// Purpose: Locks the cardinality-guard thresholds: the guard is off by default, and a hand-edited
//          appsettings.json cannot push a threshold outside the range the sink can enforce.
// Depends: SubnetAggregationOptions
// Extends: System.Object

using RdpAudit.Core.Config;
using Xunit;

namespace RdpAudit.Core.Tests;

public sealed class SubnetAggregationOptionsTests
{
	/// <summary>Given the shipped defaults, when they are resolved, then the guard is off and every
	/// threshold is inside its supported range - so the default configuration cannot route a source
	/// into an aggregate bucket.</summary>
	[Fact]
	public void Defaults_DisableTheGuardAndKeepEveryThresholdInRange()
	{
		SubnetAggregationOptions options = new();

		Assert.False(options.Enabled);
		Assert.Equal(4096, options.ResolveTotalFileThreshold());
		Assert.Equal(64, options.ResolveNewFilesPerIntervalLimit());
		Assert.Equal(60, options.ResolveIntervalSeconds());
		Assert.Equal(8, options.ResolveMinSourceRowsPerInterval());
	}

	/// <summary>Given a hand-edited document with out-of-range thresholds, when they are resolved, then
	/// each one is clamped to the supported range instead of being honoured.</summary>
	[Fact]
	public void HandEditedDocument_IsClampedToTheSupportedRange()
	{
		SubnetAggregationOptions options = new()
		{
			TotalFileThreshold = 0,
			NewFilesPerIntervalLimit = 0,
			IntervalSeconds = 0,
			MinSourceRowsPerInterval = -3,
		};

		Assert.Equal(SubnetAggregationOptions.MinTotalFileThreshold, options.ResolveTotalFileThreshold());
		Assert.Equal(SubnetAggregationOptions.MinNewFilesPerIntervalLimit, options.ResolveNewFilesPerIntervalLimit());
		Assert.Equal(SubnetAggregationOptions.MinIntervalSeconds, options.ResolveIntervalSeconds());
		Assert.Equal(0, options.ResolveMinSourceRowsPerInterval());

		options.TotalFileThreshold = int.MaxValue;
		options.NewFilesPerIntervalLimit = int.MaxValue;
		options.IntervalSeconds = int.MaxValue;
		options.MinSourceRowsPerInterval = int.MaxValue;

		Assert.Equal(SubnetAggregationOptions.MaxTotalFileThreshold, options.ResolveTotalFileThreshold());
		Assert.Equal(SubnetAggregationOptions.MaxNewFilesPerIntervalLimit, options.ResolveNewFilesPerIntervalLimit());
		Assert.Equal(SubnetAggregationOptions.MaxIntervalSeconds, options.ResolveIntervalSeconds());
		Assert.Equal(SubnetAggregationOptions.MaxMinSourceRowsPerInterval, options.ResolveMinSourceRowsPerInterval());
	}
}
