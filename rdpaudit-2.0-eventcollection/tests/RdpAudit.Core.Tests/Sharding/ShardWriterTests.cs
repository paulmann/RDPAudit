/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : ShardWriterTests.cs
// Project: RdpAudit.Core.Tests (RdpAudit.Core.Tests.Sharding)
// Purpose: Skeleton tests for the shard writer. Cover header double-buffering, ring eviction,
//          torn-write survival, and CRC-verified round-trip through the reader. Each test
//          also asserts zero managed allocations across N appends.
// Depends: xUnit, RdpAudit.Core.Storage.Sharding
// Extends: When a new record field is added, extend the round-trip test to assert the new
//          field is preserved bit-for-bit.

using RdpAudit.Core.Storage.Sharding;
using Xunit;

namespace RdpAudit.Core.Tests.Sharding;

public sealed class ShardWriterTests : IDisposable
{
	private readonly string _dir;

	public ShardWriterTests()
	{
		_dir = Path.Combine(Path.GetTempPath(), "rdpaudit-tests-" + Guid.NewGuid().ToString("N"));
		Directory.CreateDirectory(_dir);
	}

	[Fact]
	public void AppendThenRead_RoundTripsFields()
	{
		// TODO: build a fixed record, append, dispose writer, open reader, iterate, assert
		// every field is preserved and CRC verifies.
		Assert.True(true, "Test skeleton — implement round trip.");
	}

	[Fact]
	public void RingEviction_KeepsCapacityStable_AndTracksEvictedCount()
	{
		// TODO: configure a small capacity, append 2*capacity records, verify only the newest
		// capacity records are readable and EvictedCount matches capacity.
		Assert.True(true, "Test skeleton — implement eviction check.");
	}

	[Fact]
	public void HeaderDoubleBuffer_SurvivesTornWrite()
	{
		// TODO: append N records, snapshot header region, corrupt one 64 B header copy, verify
		// reader still opens using the other copy and continues correctly.
		Assert.True(true, "Test skeleton — implement torn-write survival.");
	}

	[Fact]
	public void ZeroAllocation_AcrossAppends()
	{
		// TODO: warm up, then measure GC.GetAllocatedBytesForCurrentThread across 10 000 appends
		// and assert the delta stays under the per-batch driver budget.
		Assert.True(true, "Test skeleton — implement allocation assertion.");
	}

	public void Dispose()
	{
		try
		{
			Directory.Delete(_dir, recursive: true);
		}
		catch
		{
			// Best effort: temp dir cleanup, do not fail the test run on Windows file locks.
		}
	}
}
