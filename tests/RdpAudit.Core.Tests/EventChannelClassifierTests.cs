// File:    tests/RdpAudit.Core.Tests/EventChannelClassifierTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: Pins the D7 three-state health classification of event-log channel prerequisites.
//          The PrerequisiteChecker catches EventLogNotFoundException for channels that do not exist
//          on this Windows build/SKU (Missing, no fix offered) and distinguishes them from channels
//          that merely need enabling (Disabled, wevtutil fix) or are healthy (Ok). This file tests
//          the pure fold without any Windows dependency.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Events;
using Xunit;

namespace RdpAudit.Core.Tests;

/// <summary>Verifies the pure event-channel health fold used by the Prerequisites tab.</summary>
public class EventChannelClassifierTests
{
	[Theory]
	[InlineData(true, true, EventChannelHealth.Ok)]
	[InlineData(true, false, EventChannelHealth.Disabled)]
	[InlineData(false, false, EventChannelHealth.Missing)]
	// A "missing but enabled" observation is logically impossible; the classifier must still
	// prefer Missing so a false positive can never produce an Ok row.
	[InlineData(false, true, EventChannelHealth.Missing)]
	public void Classify_MapsObservationsToVerdict(bool exists, bool enabled, EventChannelHealth expected)
	{
		Assert.Equal(expected, EventChannelClassifier.Classify(exists, enabled));
	}

	[Fact]
	public void Classify_AllThreeStates_AreReachable()
	{
		EventChannelHealth[] produced =
		{
			EventChannelClassifier.Classify(true, true),
			EventChannelClassifier.Classify(true, false),
			EventChannelClassifier.Classify(false, false),
		};

		Assert.Contains(EventChannelHealth.Ok, produced);
		Assert.Contains(EventChannelHealth.Disabled, produced);
		Assert.Contains(EventChannelHealth.Missing, produced);
	}
}
