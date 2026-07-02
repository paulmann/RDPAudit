/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0

using System;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Jobs;
using RdpAudit.Core.Events;
using RdpAudit.Service.Infrastructure;

namespace RdpAudit.Service.Benchmarks;

/// <summary>
/// BenchmarkDotNet suite comparing the legacy System.Threading.Channels implementation 
/// against the new Lock-Free SPSC Unmanaged Ring Buffer.
/// Measures write latency, SPSC throughput, and GC allocation pressure.
/// </summary>
[MemoryDiagnoser]
[ThreadingDiagnoser]
[SimpleJob(RuntimeMoniker.Net80, invocationCount: 1, warmupCount: 1, targetCount: 10)]
public class RingBufferBenchmark
{
    private const int TotalEvents = 1_000_000;
    private const int Capacity = 1024;

    private Channel<RawEventDto> _systemChannel = null!;
    private RingBufferEventChannel _ringBufferChannel = null!;
    private RawEventDto _sampleDto = null!;

    [GlobalSetup]
    public void Setup()
    {
        _sampleDto = new RawEventDto
        {
            SequenceNumber = 1,
            TimestampTicks = DateTime.UtcNow.Ticks,
            EventId = 4625,
            Channel = "Security",
            XmlPayload = "<Event><System><EventID>4625</EventID></System></Event>"
        };

        // Baseline: System.Threading.Channels with DropOldest policy
        _systemChannel = Channel.CreateBounded<RawEventDto>(new BoundedChannelOptions(Capacity)
        {
            FullMode = BoundedChannelFullMode.DropOldest,
            SingleReader = true,
            SingleWriter = true
        });

        // Challenger: Lock-Free Unmanaged SPSC Ring Buffer
        _ringBufferChannel = new RingBufferEventChannel(Capacity);
    }

    [GlobalCleanup]
    public void Cleanup()
    {
        _ringBufferChannel?.Dispose();
    }

    // =====================================================================
    // PRODUCER LATENCY (Write-Only, measures DropOldest overhead)
    // The buffer fills up after 1024 events, then drops oldest for the rest.
    // This isolates the pure write + drop-oldest overhead without consumer interference.
    // =====================================================================

    [Benchmark(Baseline = true, Description = "System.Channels Write (DropOldest)")]
    public void SystemChannels_Write()
    {
        ChannelWriter<RawEventDto> writer = _systemChannel.Writer;
        for (int i = 0; i < TotalEvents; i++)
        {
            writer.TryWrite(_sampleDto);
        }
    }

    [Benchmark(Description = "RingBuffer Write (DropOldest)")]
    public void RingBuffer_Write()
    {
        for (int i = 0; i < TotalEvents; i++)
        {
            _ringBufferChannel.TryWrite(_sampleDto);
        }
    }

    // =====================================================================
    // SPSC THROUGHPUT (1 Producer, 1 Consumer)
    // Measures end-to-end pipeline throughput under continuous load.
    // =====================================================================

    [Benchmark(Description = "System.Channels SPSC Throughput")]
    public async Task SystemChannels_SPSC()
    {
        int readCount = 0;
        ChannelReader<RawEventDto> reader = _systemChannel.Reader;
        ChannelWriter<RawEventDto> writer = _systemChannel.Writer;

        Task consumer = Task.Run(async () =>
        {
            while (Volatile.Read(ref readCount) < TotalEvents)
            {
                if (await reader.WaitToReadAsync())
                {
                    while (reader.TryRead(out _))
                    {
                        Interlocked.Increment(ref readCount);
                    }
                }
            }
        });

        for (int i = 0; i < TotalEvents; i++)
        {
            writer.TryWrite(_sampleDto);
        }

        await consumer;
    }

    [Benchmark(Description = "RingBuffer SPSC Throughput")]
    public async Task RingBuffer_SPSC()
    {
        int readCount = 0;
        
        Task consumer = Task.Run(() =>
        {
            SpinWait spinner = new();
            while (Volatile.Read(ref readCount) < TotalEvents)
            {
                if (_ringBufferChannel.TryRead(out _))
                {
                    Interlocked.Increment(ref readCount);
                    spinner.Reset();
                }
                else
                {
                    spinner.SpinOnce();
                }
            }
        });

        for (int i = 0; i < TotalEvents; i++)
        {
            _ringBufferChannel.TryWrite(_sampleDto);
        }

        await consumer;
    }
}