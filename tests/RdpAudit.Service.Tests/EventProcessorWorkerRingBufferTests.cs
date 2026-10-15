/* Project: RDPAudit 2.0 | Module: RdpAudit.Service.Tests.EventProcessor | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.1.0

// File:    tests/RdpAudit.Service.Tests/EventProcessorWorkerRingBufferTests.cs
// Module:  RdpAudit.Service.Tests
// Purpose: Validates EventProcessorWorker integration with the Lock-Free SPSC Ring Buffer.
//          v2.1.0 (iter17): worker now consumes via IEventPipe (RingBufferEventPipe over the
//          same EventChannel-backed ring). The test writes through channel.Channel.TryWrite
//          as before — the pipe is a thin adapter and reads out of the exact same physical
//          ring, so the reflection-invoked DrainBatchAsync still observes every enqueued DTO.

using System;
using System.Collections.Generic;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;
using RdpAudit.Core.Config;
using RdpAudit.Core.Events;
using RdpAudit.Service.Infrastructure;
using RdpAudit.Service.Workers;
using Xunit;

namespace RdpAudit.Service.Tests;

/// <summary>
/// Unit tests for <see cref="EventProcessorWorker"/> integration with the Lock-Free SPSC Ring Buffer.
/// </summary>
public sealed class EventProcessorWorkerRingBufferTests
{
    private readonly Mock<ILogger<EventProcessorWorker>> _loggerMock;
    private readonly ServiceMetrics _metrics;

    public EventProcessorWorkerRingBufferTests()
    {
        _loggerMock = new Mock<ILogger<EventProcessorWorker>>();
        _metrics = new ServiceMetrics();
    }

    // iter17: worker constructor takes IEventPipe instead of EventChannel. We wire a real
    // RingBufferEventPipe around the caller's EventChannel so tests keep writing through
    // channel.Channel.TryWrite while the worker reads through the pipe abstraction — the
    // pipe forwards to channel.Channel internally, so there is exactly one ring in play.
    private EventProcessorWorker CreateWorker(EventChannel channel, IOptionsMonitor<RdpAuditOptions> optionsMonitor)
    {
        IEventPipe pipe = new RingBufferEventPipe(channel);
        return new EventProcessorWorker(
            pipe,
            null!, // IDbContextFactory
            null!, // EventNormalizer
            null!, // SessionIpCorrelationUpserter
            null!, // RdpConnectionFactUpserter
            null!, // AuthAttemptFactUpserter
            null!, // SecurityCorrelationWatchdog
            _metrics,
            _loggerMock.Object,
            optionsMonitor,
            null!  // IOperationLogWriter
        );
    }

    [Fact]
    public async Task DrainBatchAsync_EmptyBuffer_ReturnsEmptyListAfterTimeout()
    {
        var options = new RdpAuditOptions 
        { 
            Monitoring = new MonitoringOptions { BatchSize = 10, BatchTimeoutMilliseconds = 50 } 
        };
        
        var optionsMonitorMock = new Mock<IOptionsMonitor<RdpAuditOptions>>();
        optionsMonitorMock.Setup(x => x.CurrentValue).Returns(options);
        
        var channel = new EventChannel(Options.Create(options));
        var worker = CreateWorker(channel, optionsMonitorMock.Object);

        var result = await InvokeDrainBatchAsync(worker, CancellationToken.None);

        Assert.Empty(result);
        Assert.Equal(0, _metrics.RingBufferReadCount);
    }

    [Fact]
    public async Task DrainBatchAsync_BufferHasEvents_ReturnsBatchAndIncrementsMetrics()
    {
        var options = new RdpAuditOptions 
        { 
            Monitoring = new MonitoringOptions { BatchSize = 10, BatchTimeoutMilliseconds = 100 } 
        };
        
        var optionsMonitorMock = new Mock<IOptionsMonitor<RdpAuditOptions>>();
        optionsMonitorMock.Setup(x => x.CurrentValue).Returns(options);
        
        var channel = new EventChannel(Options.Create(options));
        var worker = CreateWorker(channel, optionsMonitorMock.Object);

        for (int i = 0; i < 5; i++)
        {
            channel.Channel.TryWrite(new RawEventDto 
            { 
                EventId = 4625, 
                Channel = "Security", 
                XmlPayload = "<Event/>",
                TimeUtc = DateTime.UtcNow
            });
        }

        var result = await InvokeDrainBatchAsync(worker, CancellationToken.None);

        Assert.Equal(5, result.Count);
        Assert.Equal(5, _metrics.RingBufferReadCount);
    }

    [Fact]
    public async Task DrainBatchAsync_RespectsMaxBatchSize()
    {
        var options = new RdpAuditOptions 
        { 
            Monitoring = new MonitoringOptions { BatchSize = 3, BatchTimeoutMilliseconds = 100 } 
        };
        
        var optionsMonitorMock = new Mock<IOptionsMonitor<RdpAuditOptions>>();
        optionsMonitorMock.Setup(x => x.CurrentValue).Returns(options);
        
        var channel = new EventChannel(Options.Create(options));
        var worker = CreateWorker(channel, optionsMonitorMock.Object);

        for (int i = 0; i < 10; i++)
        {
            channel.Channel.TryWrite(new RawEventDto 
            { 
                EventId = 4625, 
                Channel = "Security", 
                XmlPayload = "<Event/>",
                TimeUtc = DateTime.UtcNow
            });
        }

        var result = await InvokeDrainBatchAsync(worker, CancellationToken.None);
        Assert.Equal(3, result.Count);
    }

    private static Task<List<RawEventDto>> InvokeDrainBatchAsync(EventProcessorWorker worker, CancellationToken ct)
    {
        MethodInfo method = typeof(EventProcessorWorker).GetMethod("DrainBatchAsync", BindingFlags.NonPublic | BindingFlags.Instance)!;
        return (Task<List<RawEventDto>>)method.Invoke(worker, new object[] { ct })!;
    }
}