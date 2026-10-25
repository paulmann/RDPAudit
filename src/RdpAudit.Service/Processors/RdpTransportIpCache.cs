// File:    src/RdpAudit.Service/Processors/RdpTransportIpCache.cs
// Module:  RdpAudit.Service.Processors
// Purpose: Bounded, time-windowed cache of RdpCoreTS 131/140 (and TS-RCM 261) source IP
//          observations used to enrich NLA-stripped Security 4625 / 4624 events whose
//          IpAddress field arrived blank. Per Detect_Attack_Strategy_v3.md §6.3 rule 5: a
//          unique candidate inside the −2s … +15s window attaches IP at High confidence;
//          multiple candidates attach at Medium and raise the CorrelationAmbiguous diagnostic.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Collections.Concurrent;

namespace RdpAudit.Service.Processors;

/// <summary>Confidence level returned by <see cref="RdpTransportIpCache.FindCandidate"/>.</summary>
public enum TransportIpConfidence
{
	/// <summary>No candidate found in the configured window.</summary>
	None = 0,

	/// <summary>One and only one candidate matched — attach IP, mark "High".</summary>
	UniqueHighConfidence = 1,

	/// <summary>Multiple candidates matched — attach the closest IP, mark "Medium" with
	/// CorrelationAmbiguous.</summary>
	AmbiguousMediumConfidence = 2,
}

/// <summary>Result of a transport-IP lookup.</summary>
/// <param name="Ip">Recovered source IP, when any candidate matched.</param>
/// <param name="Confidence">Confidence per v3 §6.3 rule 5.</param>
/// <param name="EvidenceEventId">EventID that supplied the IP (131 / 140 / 261). 0 when no match.</param>
public readonly record struct TransportIpLookup(string? Ip, TransportIpConfidence Confidence, int EvidenceEventId);

/// <summary>
/// In-process, bounded ring of recent RdpCoreTS 131 / 140 (and TS-RCM 261) observations.
/// Lookups apply the v3 §6.2 window (−2s … +15s) measured against the event timestamp of the
/// caller, NOT wall-clock time — backfill replay and tests must produce stable correlations
/// regardless of when they run.
/// </summary>
public sealed class RdpTransportIpCache
{
	/// <summary>Lookback before the caller's event time (v3 §6.2: "−2s").</summary>
	internal static readonly TimeSpan LookbackBefore = TimeSpan.FromSeconds(2);

	/// <summary>Lookahead after the caller's event time (v3 §6.2: "+15s"). In practice the caller
	/// is the failing Security 4625 — RdpCoreTS 131 always precedes — but a small forward window
	/// is preserved to tolerate clock drift between TermService and LSASS.</summary>
	internal static readonly TimeSpan LookaheadAfter = TimeSpan.FromSeconds(15);

	/// <summary>Maximum number of observations retained. Older entries fall off FIFO once
	/// capacity is exceeded; sized for sustained 1000 events/min hosts.</summary>
	internal const int Capacity = 4096;

	private readonly ConcurrentQueue<TransportObservation> _queue = new();
	private readonly object _trimGate = new();

	/// <summary>Record one IP-bearing transport observation. Null / blank ips are ignored.</summary>
	public void Record(string? ip, DateTime timeUtc, int evidenceEventId)
	{
		if (string.IsNullOrWhiteSpace(ip))
		{
			return;
		}

		_queue.Enqueue(new TransportObservation(ip.Trim(), timeUtc, evidenceEventId));
		TrimIfOverflow();
	}

	/// <summary>Find a transport-IP candidate for an event at <paramref name="targetTimeUtc"/>.</summary>
	public TransportIpLookup FindCandidate(DateTime targetTimeUtc)
	{
		DateTime windowStart = targetTimeUtc - LookbackBefore;
		DateTime windowEnd = targetTimeUtc + LookaheadAfter;

		string? bestIp = null;
		int bestEventId = 0;
		TimeSpan bestDelta = TimeSpan.MaxValue;
		bool ambiguous = false;
		string? secondaryIp = null;

		foreach (TransportObservation obs in _queue)
		{
			if (obs.TimeUtc < windowStart || obs.TimeUtc > windowEnd)
			{
				continue;
			}

			TimeSpan delta = (obs.TimeUtc - targetTimeUtc).Duration();
			if (bestIp is null)
			{
				bestIp = obs.Ip;
				bestEventId = obs.EvidenceEventId;
				bestDelta = delta;
				continue;
			}

			// Same IP arriving multiple times for the same connection burst is not ambiguous —
			// it's the same attacker. Only treat distinct IPs as ambiguous candidates.
			if (string.Equals(bestIp, obs.Ip, StringComparison.OrdinalIgnoreCase))
			{
				if (delta < bestDelta)
				{
					bestDelta = delta;
					bestEventId = obs.EvidenceEventId;
				}

				continue;
			}

			// Distinct IP candidate: ambiguous. Keep the closer-in-time one but flag.
			ambiguous = true;
			if (delta < bestDelta)
			{
				secondaryIp = bestIp;
				bestIp = obs.Ip;
				bestEventId = obs.EvidenceEventId;
				bestDelta = delta;
			}
			else if (secondaryIp is null)
			{
				secondaryIp = obs.Ip;
			}
		}

		if (bestIp is null)
		{
			return new TransportIpLookup(null, TransportIpConfidence.None, 0);
		}

		TransportIpConfidence confidence = ambiguous
			? TransportIpConfidence.AmbiguousMediumConfidence
			: TransportIpConfidence.UniqueHighConfidence;
		return new TransportIpLookup(bestIp, confidence, bestEventId);
	}

	/// <summary>Drop observations older than the lookback window relative to <paramref name="nowUtc"/>.</summary>
	public void Sweep(DateTime nowUtc)
	{
		DateTime cutoff = nowUtc - TimeSpan.FromMinutes(5);
		while (_queue.TryPeek(out TransportObservation head) && head.TimeUtc < cutoff)
		{
			_queue.TryDequeue(out _);
		}
	}

	/// <summary>Internal: current number of observations (tests / metrics).</summary>
	internal int Count => _queue.Count;

	private void TrimIfOverflow()
	{
		if (_queue.Count <= Capacity)
		{
			return;
		}

		// Single-thread the trim to bound CPU; if another caller is already trimming we let it.
		if (!Monitor.TryEnter(_trimGate))
		{
			return;
		}

		try
		{
			while (_queue.Count > Capacity && _queue.TryDequeue(out _))
			{
			}
		}
		finally
		{
			Monitor.Exit(_trimGate);
		}
	}

	private readonly record struct TransportObservation(string Ip, DateTime TimeUtc, int EvidenceEventId);
}
