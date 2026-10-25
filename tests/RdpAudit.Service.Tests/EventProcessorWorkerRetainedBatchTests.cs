// File:    tests/RdpAudit.Service.Tests/EventProcessorWorkerRetainedBatchTests.cs
// Module:  RdpAudit.Service.Tests
// Purpose: Guards the head-of-line retention rule: a batch whose persistence failed with retries
//          exhausted is kept in memory for retry instead of being discarded. Discarding it was the
//          2026-10-23 defect - the bookmark ledger watermark could advance past sequences that never
//          reached the database, which turns a transient outage into a permanent audit gap.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Reflection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;
using RdpAudit.Core.Config;
using RdpAudit.Core.Data;
using RdpAudit.Core.Events;
using RdpAudit.Core.Models;
using RdpAudit.Service.Workers;
using Xunit;

namespace RdpAudit.Service.Tests;

/// <summary>Locks the retention decision that keeps a failed batch alive.</summary>
public class EventProcessorWorkerRetainedBatchTests
{
	private static readonly MethodInfo RetainFailedBatchMethod = typeof(EventProcessorWorker)
		.GetMethod("RetainFailedBatch", BindingFlags.NonPublic | BindingFlags.Instance)!;

	private static readonly FieldInfo RetainedBatchField = typeof(EventProcessorWorker)
		.GetField("_retainedBatch", BindingFlags.NonPublic | BindingFlags.Instance)!;

	private static readonly FieldInfo RetainedSinceField = typeof(EventProcessorWorker)
		.GetField("_retainedSinceTimestamp", BindingFlags.NonPublic | BindingFlags.Instance)!;

	private readonly ServiceMetrics _metrics = new();
	private readonly Mock<IOptionsMonitor<RdpAuditOptions>> _options = new();

	public EventProcessorWorkerRetainedBatchTests()
	{
		_options.SetupGet(monitor => monitor.CurrentValue).Returns(new RdpAuditOptions());
	}

	private EventProcessorWorker CreateWorker() => new(
		Mock.Of<IEventPipe>(),
		null!,
		null!,
		null!,
		null!,
		null!,
		null!,
		_metrics,
		Mock.Of<ILogger<EventProcessorWorker>>(),
		_options.Object,
		Mock.Of<IOperationLogWriter>());

	private static List<RawEventDto> Batch(long firstSequence, int count)
	{
		List<RawEventDto> batch = new(count);
		for (int i = 0; i < count; i++)
		{
			batch.Add(new RawEventDto
			{
				EventId = 4624,
				Channel = "Security",
				IngestionSequence = firstSequence + i,
			});
		}

		return batch;
	}

	/// <summary>The failed batch stays reachable and the retention is counted, so a database outage
	/// costs throughput, never evidence.</summary>
	[Fact]
	public void RetainFailedBatch_KeepsTheBatchAndCountsIt()
	{
		EventProcessorWorker worker = CreateWorker();
		List<RawEventDto> batch = Batch(100, 3);

		RetainFailedBatchMethod.Invoke(worker, [batch]);

		Assert.Same(batch, RetainedBatchField.GetValue(worker));
		Assert.Equal(1, _metrics.PersistBatchRetainedCount);
	}

	/// <summary>A repeated failure must not replace the held batch or restart its stall clock: the age
	/// is measured from the first failed attempt, so the escalation cannot be postponed forever.</summary>
	[Fact]
	public void RetainFailedBatch_SecondFailureKeepsTheFirstBatchAndItsTimestamp()
	{
		EventProcessorWorker worker = CreateWorker();
		List<RawEventDto> first = Batch(100, 2);

		RetainFailedBatchMethod.Invoke(worker, [first]);
		long firstTimestamp = (long)RetainedSinceField.GetValue(worker)!;

		RetainFailedBatchMethod.Invoke(worker, [Batch(200, 2)]);

		Assert.Same(first, RetainedBatchField.GetValue(worker));
		Assert.Equal(firstTimestamp, (long)RetainedSinceField.GetValue(worker)!);
		Assert.Equal(1, _metrics.PersistBatchRetainedCount);
	}
}
