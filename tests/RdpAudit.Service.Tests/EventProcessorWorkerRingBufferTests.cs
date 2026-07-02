/* Project: RDPAudit 2.0 | Module: RdpAudit.Service.Tests.EventProcessor | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.2

// File:    tests/RdpAudit.Service.Tests/EventProcessorWorkerRingBufferTests.cs
// Module:  RdpAudit.Service.Tests
// Purpose: Validates EventProcessorWorker integration with the Lock-Free SPSC Ring Buffer.

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

    private EventProcessorWorker CreateWorker(EventChannel channel, IOptionsMonitor<RdpAuditOptions> optionsMonitor) => new(
        channel,
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