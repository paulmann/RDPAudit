/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.1
// File   : EventFloodGuard.cs
// Project: RdpAudit.Core (RdpAudit.Core.Events)
// Purpose: Bounds per-channel and per-source event flood accounting without allocating on the ingestion path.
// Depends: System.Threading, System.Runtime.CompilerServices, EventCatalog, EventCriticality
// Extends: Add new protected evidence event identifiers to EventFloodGuardPolicy when their lifecycle semantics require unconditional retention.

using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace RdpAudit.Core.Events;

/// <summary>Result of one event hit against <see cref="EventFloodGuard"/>.</summary>
[SuppressMessage("Design", "CA1028:Enum storage should be Int32", Justification =
	"The byte storage is intentional because this decision is carried on the ingestion hot path and has only three stable states; widening it would add avoidable bandwidth to a high-frequency, cache-sensitive operation.")]
public enum FloodDecision : byte
{
	/// <summary>Below the sampling threshold; retain full event detail.</summary>
	Accept = 0,

	/// <summary>Selected periodic sample above the soft threshold; retain full event detail.</summary>
	Sample = 1,

	/// <summary>Retain aggregate accounting only; do not enqueue event detail.</summary>
	AggregateOnly = 2,
}

/// <summary>
/// Identifies events which must always retain full detail even during an ingestion flood.
/// </summary>
public static class EventFloodGuardPolicy
{
	/// <summary>
	/// Returns whether an event carries authentication or session evidence that must bypass
	/// pre-pipeline sampling.
	/// </summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static bool MustBypass(int eventId)
	{
		if (eventId is 4624 or 4625 or 4634 or 4647 or 4648 or 4776 or 4778 or 4779)
		{
			return true;
		}

		return EventCatalog.CriticalityOf(eventId) >= EventCriticality.High;
	}
}

/// <summary>
/// Sliding-window event-rate limiter. Its fixed-size, collision-tolerant buckets prevent an
/// attacker from causing unbounded memory growth by varying source addresses.
/// </summary>
public sealed class EventFloodGuard
{
	private const int MinimumBucketCount = 1_024;
	private const int MaximumBucketCount = 1_048_576;

	[StructLayout(LayoutKind.Explicit, Size = 64)]
	private struct FloodBucket
	{
		// All long fields used by Interlocked are naturally eight-byte aligned. The two identity
		// fields are plain Int32 values at offsets 32 and 36 and are never passed to Interlocked.
		[FieldOffset(0)]
		internal long WindowStartTicks;

		[FieldOffset(8)]
		internal long HitsInWindow;

		[FieldOffset(16)]
		internal long FirstSeenTicks;

		[FieldOffset(24)]
		internal long LastSeenTicks;

		[FieldOffset(32)]
		internal int KeyHash;

		[FieldOffset(36)]
		internal int ChannelCode;
	}

	// ── Fields & DI ──────────────────────────────────────────────────────────────

	private readonly FloodBucket[] _buckets;
	private readonly int _mask;
	private readonly long _windowTicks;
	private readonly long _softThreshold;
	private readonly long _hardThreshold;
	private readonly int _sampleEveryN;

	// ── Construction ─────────────────────────────────────────────────────────────

	/// <summary>Creates a fixed-size guard with bounded configuration values.</summary>
	public EventFloodGuard(
		int bucketCount = 4_096,
		TimeSpan window = default,
		long softThreshold = 1_000,
		long hardThreshold = 10_000,
		int sampleEveryN = 32)
	{
		TimeSpan effectiveWindow = window == default ? TimeSpan.FromSeconds(10) : window;
		if (effectiveWindow <= TimeSpan.Zero)
		{
			throw new ArgumentOutOfRangeException(nameof(window), window, "The flood guard window must be positive.");
		}

		int boundedBucketCount = Math.Clamp(bucketCount, MinimumBucketCount, MaximumBucketCount);
		int roundedBucketCount = NextPowerOfTwo(boundedBucketCount);

		_softThreshold = Math.Max(1L, softThreshold);
		_hardThreshold = Math.Max(_softThreshold + 1L, hardThreshold);
		_sampleEveryN = Math.Max(2, sampleEveryN);
		_windowTicks = effectiveWindow.Ticks;
		_buckets = new FloodBucket[roundedBucketCount];
		_mask = roundedBucketCount - 1;
	}

	// ── Public API ───────────────────────────────────────────────────────────────

	/// <summary>
	/// Records one channel/source hit and returns whether its full detail should be retained.
	/// The method performs no managed allocations.
	/// </summary>
	[SuppressMessage("Design", "CA1021:Avoid out parameters", Justification =
		"The out value exposes the aggregate count without a result object or tuple allocation on the event-ingestion hot path.")]
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public FloodDecision Hit(int channelCode, ReadOnlySpan<byte> sourceIpBytes, long nowUtcTicks, out long aggregateHits)
	{
		int keyHash = ComputeKeyHash(channelCode, sourceIpBytes);
		ref FloodBucket bucket = ref _buckets[keyHash & _mask];

		long windowStartTicks = Volatile.Read(ref bucket.WindowStartTicks);
		int storedKeyHash = Volatile.Read(ref bucket.KeyHash);
		int storedChannelCode = Volatile.Read(ref bucket.ChannelCode);

		bool firstSeen = windowStartTicks == 0L
			|| nowUtcTicks - windowStartTicks > _windowTicks
			|| storedKeyHash != keyHash
			|| storedChannelCode != channelCode;

		if (firstSeen)
		{
			ResetBucket(ref bucket, keyHash, channelCode, nowUtcTicks);
		}

		aggregateHits = Interlocked.Increment(ref bucket.HitsInWindow);
		Volatile.Write(ref bucket.LastSeenTicks, nowUtcTicks);

		if (firstSeen)
		{
			return FloodDecision.Accept;
		}

		if (aggregateHits >= _hardThreshold)
		{
			return FloodDecision.AggregateOnly;
		}

		if (aggregateHits >= _softThreshold)
		{
			return aggregateHits % _sampleEveryN == 0
				? FloodDecision.Sample
				: FloodDecision.AggregateOnly;
		}

		return FloodDecision.Accept;
	}

	/// <summary>Enumerates diagnostic snapshots for buckets at or above the soft threshold.</summary>
	public void SnapshotHot(Action<int, int, long, long, long> forEachHotBucket)
	{
		ArgumentNullException.ThrowIfNull(forEachHotBucket);

		for (int index = 0; index < _buckets.Length; index++)
		{
			ref FloodBucket bucket = ref _buckets[index];
			long hits = Volatile.Read(ref bucket.HitsInWindow);
			if (hits < _softThreshold)
			{
				continue;
			}

			forEachHotBucket(
				Volatile.Read(ref bucket.ChannelCode),
				Volatile.Read(ref bucket.KeyHash),
				hits,
				Volatile.Read(ref bucket.FirstSeenTicks),
				Volatile.Read(ref bucket.LastSeenTicks));
		}
	}

	// ── Core Logic ───────────────────────────────────────────────────────────────

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void ResetBucket(ref FloodBucket bucket, int keyHash, int channelCode, long nowUtcTicks)
	{
		Interlocked.Exchange(ref bucket.HitsInWindow, 0L);
		Interlocked.Exchange(ref bucket.FirstSeenTicks, nowUtcTicks);
		Volatile.Write(ref bucket.LastSeenTicks, nowUtcTicks);
		Volatile.Write(ref bucket.KeyHash, keyHash);
		Volatile.Write(ref bucket.ChannelCode, channelCode);
		Interlocked.Exchange(ref bucket.WindowStartTicks, nowUtcTicks);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static int ComputeKeyHash(int channelCode, ReadOnlySpan<byte> sourceIpBytes)
	{
		const int FnvOffsetBasis = unchecked((int)2_166_136_261);
		const int FnvPrime = 16_777_619;

		int hash = FnvOffsetBasis;
		hash = (hash ^ (byte)channelCode) * FnvPrime;
		hash = (hash ^ (byte)(channelCode >> 8)) * FnvPrime;
		hash = (hash ^ (byte)(channelCode >> 16)) * FnvPrime;
		hash = (hash ^ (byte)(channelCode >> 24)) * FnvPrime;

		for (int index = 0; index < sourceIpBytes.Length; index++)
		{
			hash = (hash ^ sourceIpBytes[index]) * FnvPrime;
		}

		return hash;
	}

	private static int NextPowerOfTwo(int value)
	{
		value--;
		value |= value >> 1;
		value |= value >> 2;
		value |= value >> 4;
		value |= value >> 8;
		value |= value >> 16;
		return value + 1;
	}
}
