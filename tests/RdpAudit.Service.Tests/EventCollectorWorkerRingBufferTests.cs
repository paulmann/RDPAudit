/* Project: RDPAudit 2.0 | Module: RdpAudit.Service.Tests.EventCollector | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.6

using System;
using System.Diagnostics.Eventing.Reader;
using System.Reflection;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;
using RdpAudit.Core.Config;
using RdpAudit.Core.Data;
using RdpAudit.Core.Events;
using RdpAudit.Service.Collectors;
using RdpAudit.Service.Infrastructure;
using RdpAudit.Service.Workers;
using Xunit;

namespace RdpAudit.Service.Tests;

/// <summary>
/// Unit tests for EventCollectorWorker integration with the Lock-Free SPSC Ring Buffer.
/// </summary>
public sealed class EventCollectorWorkerRingBufferTests
{
    private readonly Mock<ILogger<EventCollectorWorker>> _loggerMock;
    private readonly Mock<IOptionsMonitor<RdpAuditOptions>> _optionsMonitorMock;
    private readonly ServiceMetrics _metrics;
    private readonly Mock<IDbContextFactory<AuditDbContext>> _dbFactoryMock;
    private readonly Mock<IOperationLogWriter> _opLogMock;
    private readonly RdpAuditOptions _options;

    public EventCollectorWorkerRingBufferTests()
    {
        _loggerMock = new Mock<ILogger<EventCollectorWorker>>();
        _options = new RdpAuditOptions
        {
            Monitoring = new MonitoringOptions { ChannelCapacity = 2, BatchSize = 10 },
            Diagnostics = new DiagnosticsOptions { LogChannelDrops = true }
        };
        _optionsMonitorMock = new Mock<IOptionsMonitor<RdpAuditOptions>>();
        _optionsMonitorMock.Setup(x => x.CurrentValue).Returns(_options);
        _metrics = new ServiceMetrics();
        _dbFactoryMock = new Mock<IDbContextFactory<AuditDbContext>>();
        _opLogMock = new Mock<IOperationLogWriter>();
    }

    private EventCollectorWorker CreateWorker(EventChannel channel) => new(
        channel,
        null!, 
        _metrics,
        _loggerMock.Object,
        _optionsMonitorMock.Object,
        new ChannelHealthPolicy(),
        _dbFactoryMock.Object,
        _opLogMock.Object);

    [Fact]
    public void EventChannel_WrapsRingBufferEventChannel()
    {
        var channel = new EventChannel(Options.Create(_options));
        Assert.IsType<RingBufferEventChannel>(channel.Channel);
    }

    [Fact]
    public void EventChannel_EnforcesMinimumCapacity_PowerOfTwo()
    {
        // Arrange: Config requests capacity = 2
        var channel = new EventChannel(Options.Create(_options));

        // Assert: EventChannel enforces Math.Max(1000, capacity) then rounds to next power of 2.
        // Math.Max(1000, 2) = 1000 -> next power of 2 = 1024
        Assert.Equal(1024, channel.Channel.Capacity);
    }

    [Fact]
    public void EventChannel_LargeCapacity_RoundsToNextPowerOfTwo()
    {
        // Arrange: Config requests capacity = 2000
        var largeOptions = new RdpAuditOptions
        {
            Monitoring = new MonitoringOptions { ChannelCapacity = 2000, BatchSize = 10 }
        };
        var channel = new EventChannel(Options.Create(largeOptions));

        // Assert: 2000 -> next power of 2 = 2048
        Assert.Equal(2048, channel.Channel.Capacity);
    }

    [Fact]
    public void EventChannel_InitialOverflowCount_IsZero()
    {
        var channel = new EventChannel(Options.Create(_options));
        Assert.Equal(0, channel.Channel.OverflowCount);
    }

    [Fact]
    public void EventChannel_MultipleChannels_AreIndependent()
    {
        var channel1 = new EventChannel(Options.Create(_options));
        var channel2 = new EventChannel(Options.Create(_options));

        Assert.NotSame(channel1.Channel, channel2.Channel);
    }
}