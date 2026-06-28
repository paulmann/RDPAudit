// File:    tests/RdpAudit.Service.Tests/SecurityBackfillWorkerTests.cs
// Module:  RdpAudit.Service.Tests
// Purpose: Pure-helper tests for the Security backfill worker. The EventLogReader poll path is
//          Windows-only and exercised by manual QA on a real host; here we lock the XPath shape
//          and the in-memory dedup ring contract that bound the worker's CPU/memory footprint.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using RdpAudit.Core.Config;
using RdpAudit.Service.Workers;
using Xunit;

namespace RdpAudit.Service.Tests;

public class SecurityBackfillWorkerTests
{
	private static SecurityBackfillWorker NewWorker()
	{
		EventChannel channel = new(new OptionsWrapper<RdpAuditOptions>(new RdpAuditOptions()));
		ServiceMetrics metrics = new();
		IOptionsMonitor<RdpAuditOptions> opts = new TestOptionsMonitor<RdpAuditOptions>(new RdpAuditOptions());
		return new SecurityBackfillWorker(channel, metrics, NullLogger<SecurityBackfillWorker>.Instance, opts);
	}

	[Fact]
	public void BuildXPath_CoversFullV3SecuritySet_AndIncludesTimeBound()
	{
		// Detect_Attack_Strategy_v3.md §5.2 "Critical Backfill Targets": the Security channel
		// backfill must enumerate every authentication, post-compromise, lockout, NTLM/Kerberos,
		// session-lifecycle, and tampering event needed for attack classification. The list is
		// asserted in full here so a future regression that silently narrows it (the same defect
		// this test was rewritten to prevent) fails immediately.
		int[] expected =
		{
			4624, 4625, 4634, 4647, 4648, 4672,
			4719, 4720, 4724, 4732, 4740,
			4768, 4769, 4771, 4776,
			4778, 4779,
			4825,
			1102,
		};

		DateTime since = new(2026, 5, 20, 12, 0, 0, DateTimeKind.Utc);
		string xpath = SecurityBackfillWorker.BuildXPath(since);

		foreach (int id in expected)
		{
			Assert.Contains("EventID=" + id, xpath);
		}

		// Time literal must be invariant ISO-8601 with millisecond precision and explicit Z.
		Assert.Contains("2026-05-20T12:00:00.000Z", xpath);

		// The full set is exposed for tests so the v3 contract is one read away.
		Assert.Equal(expected.OrderBy(x => x), SecurityBackfillWorker.BackfillEventIds.OrderBy(x => x));
	}

	[Fact]
	public void TryMarkSeen_DeduplicatesByRecordId()
	{
		SecurityBackfillWorker worker = NewWorker();
		Assert.True(worker.TryMarkSeen(42L));
		Assert.False(worker.TryMarkSeen(42L));
		Assert.True(worker.TryMarkSeen(43L));
	}

	[Fact]
	public void TryMarkSeen_RingEvictsOldestPastCapacity()
	{
		SecurityBackfillWorker worker = NewWorker();
		for (long i = 0; i < SecurityBackfillWorker.SeenRingCapacity + 100; i++)
		{
			Assert.True(worker.TryMarkSeen(i));
		}

		// The first 100 ids should have been evicted FIFO; calling TryMarkSeen with one of them
		// should succeed again (it is "new" relative to the ring).
		Assert.True(worker.TryMarkSeen(0L));
		Assert.True(worker.TryMarkSeen(50L));
		// A recently-added id is still in the ring.
		Assert.False(worker.TryMarkSeen(SecurityBackfillWorker.SeenRingCapacity + 50L));
	}

	private sealed class TestOptionsMonitor<T> : IOptionsMonitor<T>
	{
		public TestOptionsMonitor(T value)
		{
			CurrentValue = value;
		}

		public T CurrentValue { get; }

		public T Get(string? name) => CurrentValue;

		public IDisposable? OnChange(Action<T, string?> listener) => null;
	}
}
