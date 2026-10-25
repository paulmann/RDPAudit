/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.1.0
// File   : RingBufferBenchmark.cs
// Project: RdpAudit.Benchmarks (RdpAudit.Benchmarks)
// Purpose: Throughput and allocation benchmarks comparing System.Threading.Channels
//          (baseline v1.0), UnmanagedSpscRingBuffer (v2.0 SPSC), and UnmanagedMpmcRingBuffer
//          (v2.0 Vyukov MPMC). Also covers the multi-producer contention scenario.
// Depends: BenchmarkDotNet, RingBufferEventChannel, MpmcEventChannel, RawEventDto
// Extends: Add a new [Benchmark] method for every backend flavour or contention scenario
//          we care to measure; keep the sample DTO identical across all methods so results
//          stay comparable.

using System;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Jobs;
using RdpAudit.Core.Events;
using RdpAudit.Service.Infrastructure;

namespace RdpAudit.Benchmarks;

/// <summary>
/// Compares baseline <see cref="Channel{T}"/> against the v2.0 lock-free ring buffers under
/// both SPSC and MPMC producer patterns. All benchmarks push the same <c>TotalEvents</c>
/// and are configured to overflow the ring so the DropOldest path is fully exercised.
/// </summary>
[MemoryDiagnoser]
[ThreadingDiagnoser]
[SimpleJob(RuntimeMoniker.Net80, warmupCount: 2, iterationCount: 5, invocationCount: 1)]
public class RingBufferBenchmark : IDisposable
{
	private const int TotalEvents = 1_000_000;
	private const int Capacity    = 1024;
	private const int ProducerCount = 4;

	private Channel<RawEventDto> _sysChannelSpsc  = null!;
	private Channel<RawEventDto> _sysChannelMpmc  = null!;
	private RingBufferEventChannel _spsc          = null!;
	private MpmcEventChannel _mpmc                = null!;
	private RawEventDto _sample                   = null!;

	[GlobalSetup]
	public void Setup()
	{
		_sample = new RawEventDto
		{
			EventId    = 4625,
			Channel    = "Security",
			TimeUtc    = DateTime.UtcNow,
			XmlPayload = "<Event><System><EventID>4625</EventID></System></Event>",
		};

		_sysChannelSpsc = Channel.CreateBounded<RawEventDto>(new BoundedChannelOptions(Capacity)
		{
			FullMode     = BoundedChannelFullMode.DropOldest,
			SingleReader = true,
			SingleWriter = true,
		});

		_sysChannelMpmc = Channel.CreateBounded<RawEventDto>(new BoundedChannelOptions(Capacity)
		{
			FullMode     = BoundedChannelFullMode.DropOldest,
			SingleReader = true,
			SingleWriter = false,
		});

		_spsc = new RingBufferEventChannel(Capacity);
		_mpmc = new MpmcEventChannel(Capacity);
	}

	[GlobalCleanup]
	public void Cleanup()
	{
		Dispose();
	}

	public void Dispose()
	{
		_spsc?.Dispose();
		_mpmc?.Dispose();
		GC.SuppressFinalize(this);
	}

	// ── Single-Producer Write ────────────────────────────────────────────────────
	//
	// All three backends receive TotalEvents from one thread. The ring fills to Capacity
	// then every subsequent write must fall through the DropOldest fast path.

	[Benchmark(Baseline = true, Description = "SystemChannels_Spsc")]
	public void SystemChannels_Spsc_Write()
	{
		ChannelWriter<RawEventDto> writer = _sysChannelSpsc.Writer;
		for (int i = 0; i < TotalEvents; i++)
		{
			writer.TryWrite(_sample);
		}
	}

	[Benchmark(Description = "Spsc_Write")]
	public void Spsc_Write()
	{
		for (int i = 0; i < TotalEvents; i++)
		{
			_spsc.TryWrite(_sample);
		}
	}

	[Benchmark(Description = "Mpmc_Write_Serial")]
	public void Mpmc_Write_Serial()
	{
		for (int i = 0; i < TotalEvents; i++)
		{
			_mpmc.TryWrite(_sample);
		}
	}

	// ── Multi-Producer Write (4 producers x TotalEvents / 4) ─────────────────────
	//
	// Realistic v2.0 hot path: EventCollectorHostedWorker + SecurityBackfillWorker +
	// TerminalServicesBackfillWorker + the ETW consumer all writing simultaneously.

	[Benchmark(Description = "SystemChannels_Mpmc_4Producers")]
	public void SystemChannels_Mpmc_4Producers()
	{
		RunParallelWrites(ProducerCount, TotalEvents / ProducerCount, (int _) =>
		{
			ChannelWriter<RawEventDto> writer = _sysChannelMpmc.Writer;
			return writer.TryWrite(_sample);
		});
	}

	[Benchmark(Description = "Mpmc_4Producers")]
	public void Mpmc_4Producers()
	{
		RunParallelWrites(ProducerCount, TotalEvents / ProducerCount, (int _) =>
			_mpmc.TryWrite(_sample));
	}

	// ── Helpers ──────────────────────────────────────────────────────────────────
	//
	// Fan out `producers` threads, each pushing `perProducer` events via `writeOnce`.
	// Kept out of the hot per-event path so the delegate is only invoked, never captured
	// into the measured loop.

	private static void RunParallelWrites(int producers, int perProducer, Func<int, bool> writeOnce)
	{
		var tasks = new Task[producers];
		for (int p = 0; p < producers; p++)
		{
			int producerId = p;
			tasks[p] = Task.Run(() =>
			{
				for (int i = 0; i < perProducer; i++)
				{
					_ = writeOnce(producerId);
				}
			});
		}
		Task.WaitAll(tasks);
	}
}
