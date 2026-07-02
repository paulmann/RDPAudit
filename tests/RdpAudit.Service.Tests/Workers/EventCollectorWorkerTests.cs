/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.1
// File   : EventCollectorWorkerTests.cs
// Project: RdpAudit.Service.Tests (RdpAudit.Service.Tests)
// Purpose: Verifies EventCollectorWorker diagnostic status formatting for skipped optional channels.
// Depends: EventCollectorWorker, Xunit
// Extends: Add new tests here when channel-status rendering rules or optional-channel diagnostics change.

using RdpAudit.Service.Workers;

namespace RdpAudit.Service.Tests.Workers;

public sealed class EventCollectorWorkerTests
{
	[Theory]
	[InlineData("Channel not found: test", "SkippedUnavailable: Channel not found: test")]
	[InlineData("", "SkippedUnavailable")]
	public void BuildSkippedUnavailableStatus_ReturnsExpectedValue(
		string reason,
		string expected)
	{
		string actual = EventCollectorWorker.BuildSkippedUnavailableStatus(reason);

		Assert.Equal(expected, actual);
	}

	[Fact]
	public void BuildSkippedUnavailableStatus_TruncatesLongReason()
	{
		string reason = new string('X', 200);

		string actual = EventCollectorWorker.BuildSkippedUnavailableStatus(reason);

		Assert.StartsWith("SkippedUnavailable: ", actual);
		Assert.EndsWith("...", actual);
		Assert.True(actual.Length <= "SkippedUnavailable: ".Length + 123);
	}
}
