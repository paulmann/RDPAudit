// File:    tests/RdpAudit.Service.Tests/EventProcessorWorkerStage6Tests.cs
// Module:  RdpAudit.Service.Tests
// Purpose: Stage 6 unit tests for EventProcessorWorker helpers — the Address.UserNames
//          append helper used to populate per-IP attempted-user history.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Service.Workers;
using Xunit;

namespace RdpAudit.Service.Tests;

public class EventProcessorWorkerStage6Tests
{
	[Fact]
	public void AppendAddressUserName_NullOrBlank_ReturnsCurrent()
	{
		Assert.Null(EventProcessorWorker.AppendAddressUserName(null, null));
		Assert.Null(EventProcessorWorker.AppendAddressUserName(null, "   "));
		Assert.Equal("alice", EventProcessorWorker.AppendAddressUserName("alice", null));
	}

	[Fact]
	public void AppendAddressUserName_AppendsAndDeduplicatesCaseInsensitive()
	{
		string? cur = null;
		cur = EventProcessorWorker.AppendAddressUserName(cur, "alice");
		cur = EventProcessorWorker.AppendAddressUserName(cur, "ALICE");
		cur = EventProcessorWorker.AppendAddressUserName(cur, "bob");
		Assert.Equal("ALICE,bob", cur);
	}

	[Fact]
	public void AppendAddressUserName_RespectsLengthCap()
	{
		string? cur = null;
		// Fill with names long enough that we will eventually trim the front.
		for (int i = 0; i < 200; i++)
		{
			cur = EventProcessorWorker.AppendAddressUserName(cur, $"user{i:D6}");
		}

		Assert.NotNull(cur);
		Assert.True(cur!.Length <= EventProcessorWorker.AddressUserNamesMaxLength);
	}
}
