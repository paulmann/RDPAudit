/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : EventFloodGuard.cs
// Project: RdpAudit.Core (RdpAudit.Core.Events)
// Purpose: Low-overhead sliding-window counters per channel and per source IP. Detects log
//          floods aimed at drowning the collector; keeps aggregate first/last/count even while
//          per-event detail is sampled down.
// Depends: System.Threading, System.Runtime.CompilerServices
// Extends: When a new axis is added (per-user, per-target-account), extend WindowKey without
//          changing the fixed-slot core to preserve the zero-alloc property.

using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace RdpAudit.Core.Events;

/// <summary>Result of a single hit against the guard.</summary>
public enum FloodDecision : byte
{
	/// <summary>Below any threshold; record the event in full.</summary>
	Accept = 0,

	/// <summary>Above the soft threshold; sample this event (record 1 in N).</summary>
	Sample = 1,

	/// <summary>Above the hard threshold; drop per-event detail but keep aggregate counters.</summary>
	AggregateOnly = 2,
}

/// <summary>Fixed-size bucket keyed by a hash of (channel, sourceIp). Cache-line padded to
/// eliminate false sharing under contended writes.</summary>
[StructLayout(LayoutKind.Explicit, Size = 64)]
internal struct FloodBucket
{
	[FieldOffset(0)]  public long WindowStartTicks;
	[FieldOffset(8)]  public long HitsInWindow;
	[FieldOffset(16)] public long FirstSeenTicks;
	[FieldOffset(24)] public long LastSeenTicks;
	[FieldOffset(32)] public int  KeyHash;
	[FieldOffset(36)] public int  ChannelCode;
	// 24 bytes of padding remain to fill the cache line.
}

/// <summary>
/// Sliding-window rate limiter used to detect and dampen log floods. Deliberately fixed-size
/// (power-of-two number of buckets, hash-collision tolerant) so a spraying attacker cannot
/// cause unbounded memory growth by fabricating source IPs.
/// </summary>
public sealed class EventFloodGuard
{
	// ── Fields & DI ──────────────────────────────────────────────────────────────

	private readonly FloodBucket[] _buckets;
	private readonly int _mask;
	private readonly long _windowTicks;
	private readonly long _softThreshold;
	private readonly long _hardThreshold;
	private readonly int _sampleEveryN;

	// ── Construction ─────────────────────────────────────────────────────────────

	/// <summary>Creates a guard with the given fixed bucket count (rounded to the next power of
	/// two, minimum 1024), sliding window duration, and thresholds.</summary>
	public EventFloodGuard(
		int bucketCount = 4096,
		TimeSpan window = default,
		long softThreshold = 1000,
		long hardThreshold = 10_000,
		int sampleEveryN = 32)
	{
		int rounded = NextPowerOfTwo(Math.Max(1024, bucketCount));
		_buckets = new FloodBucket[rounded];
		_mask = rounded - 1;
		_windowTicks = (window == default ? TimeSpan.FromSeconds(10) : window).Ticks;
		_softThreshold = softThreshold;
		_hardThreshold = hardThreshold;
		_sampleEveryN = Math.Max(2, sampleEveryN);
	}

	// ── Public API ───────────────────────────────────────────────────────────────

	/// <summary>Registers one event hit and returns whether it should be accepted, sampled, or
	/// aggregate-only. Zero managed allocations.</summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public FloodDecision Hit(int channelCode, ReadOnlySpan<byte> sourceIpBytes, long nowUtcTicks, out long aggregateHits)
	{
		int keyHash = ComputeKeyHash(channelCode, sourceIpBytes);
		int index = keyHash & _mask;

		ref FloodBucket bucket = ref _buckets[index];

		long windowStart = Volatile.Read(ref bucket.WindowStartTicks);
		if (windowStart == 0L || (nowUtcTicks - windowStart) > _windowTicks)
		{
			// Reset the bucket. Racy on purpose: exactness is not a security property; the
			// worst-case error is a slightly late alert, not a missed one, because HitsInWindow
			// keeps counting even across a stale window bound.
			Interlocked.Exchange(ref bucket.WindowStartTicks, nowUtcTicks);
			Interlocked.Exchange(ref bucket.HitsInWindow, 0L);
			Interlocked.Exchange(ref bucket.FirstSeenTicks, nowUtcTicks);
			Volatile.Write(ref bucket.KeyHash, keyHash);
			Volatile.Write(ref bucket.ChannelCode, channelCode);
		}

		aggregateHits = Interlocked.Increment(ref bucket.HitsInWindow);
		Volatile.Write(ref bucket.LastSeenTicks, nowUtcTicks);

		if (aggregateHits >= _hardThreshold)
		{
			return FloodDecision.AggregateOnly;
		}

		if (aggregateHits >= _softThreshold)
		{
			return ((aggregateHits % _sampleEveryN) == 0) ? FloodDecision.Sample : FloodDecision.AggregateOnly;
		}

		return FloodDecision.Accept;
	}

	/// <summary>Snapshots the current bucket state for diagnostics. Copies out fields; not for
	/// use in the hot path.</summary>
	public void SnapshotHot(Action<int, int, long, long, long> forEachHotBucket)
	{
		ArgumentNullException.ThrowIfNull(forEachHotBucket);

		for (int i = 0; i < _buckets.Length; i++)
		{
			long hits = Volatile.Read(ref _buckets[i].HitsInWindow);
			if (hits < _softThreshold)
			{
				continue;
			}

			forEachHotBucket(
				Volatile.Read(ref _buckets[i].ChannelCode),
				Volatile.Read(ref _buckets[i].KeyHash),
				hits,
				Volatile.Read(ref _buckets[i].FirstSeenTicks),
				Volatile.Read(ref _buckets[i].LastSeenTicks));
		}
	}

	// ── SIMD & Zero-Alloc Parsers ────────────────────────────────────────────────

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static int ComputeKeyHash(int channelCode, ReadOnlySpan<byte> sourceIpBytes)
	{
		// FNV-1a over channelCode + address bytes. Chosen for zero-alloc, hash-collision tolerant
		// behaviour under adversarial inputs (attacker cannot easily force all keys onto one
		// bucket because we mix in channelCode plus the address bytes bit-by-bit).
		const int FnvOffsetBasis = unchecked((int)2166136261);
		const int FnvPrime = 16777619;

		int hash = FnvOffsetBasis;
		hash = (hash ^ (byte)(channelCode & 0xFF)) * FnvPrime;
		hash = (hash ^ (byte)((channelCode >> 8) & 0xFF)) * FnvPrime;

		for (int i = 0; i < sourceIpBytes.Length; i++)
		{
			hash = (hash ^ sourceIpBytes[i]) * FnvPrime;
		}

		return hash;
	}

	// ── Core Logic ───────────────────────────────────────────────────────────────

	private static int NextPowerOfTwo(int value)
	{
		if (value <= 0) return 1;
		value--;
		value |= value >> 1;
		value |= value >> 2;
		value |= value >> 4;
		value |= value >> 8;
		value |= value >> 16;
		value++;
		return value;
	}
}
