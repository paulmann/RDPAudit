/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.1
// File   : FloodGuardEventPipe.cs
// Project: RdpAudit.Service (RdpAudit.Service.Infrastructure)
// Purpose: Applies EventFloodGuard before a bounded event pipe so floods cannot evict higher-value evidence.
// Depends: IEventPipe, EventFloodGuard, RdpAuditOptions, ServiceMetrics, IPAddress
// Extends: Update TryGetSourceIpBytes when a new event source supplies a canonical source-address representation.

using System.Net;
using System.Runtime.CompilerServices;
using Microsoft.Extensions.Options;
using RdpAudit.Core.Config;
using RdpAudit.Core.Events;

namespace RdpAudit.Service.Infrastructure;

/// <summary>
/// Decorates the physical event pipe with pre-enqueue flood protection. Events without an
/// authoritative source address are retained because they cannot be keyed safely.
/// </summary>
public sealed class FloodGuardEventPipe : IEventPipe
{
	// ── Fields & DI ──────────────────────────────────────────────────────────────

	private readonly IEventPipe _inner;
	private readonly EventFloodGuard _guard;
	private readonly IOptionsMonitor<RdpAuditOptions> _options;
	private readonly ServiceMetrics _metrics;

	// ── Construction ─────────────────────────────────────────────────────────────

	/// <summary>Creates the flood-protected view of the physical event pipe.</summary>
	public FloodGuardEventPipe(
		IEventPipe inner,
		EventFloodGuard guard,
		IOptionsMonitor<RdpAuditOptions> options,
		ServiceMetrics metrics)
	{
		ArgumentNullException.ThrowIfNull(inner);
		ArgumentNullException.ThrowIfNull(guard);
		ArgumentNullException.ThrowIfNull(options);
		ArgumentNullException.ThrowIfNull(metrics);

		_inner = inner;
		_guard = guard;
		_options = options;
		_metrics = metrics;
	}

	// ── Public API ───────────────────────────────────────────────────────────────

	/// <inheritdoc />
	public int Capacity => _inner.Capacity;

	/// <inheritdoc />
	public long OverflowCount => _inner.OverflowCount;

	/// <inheritdoc />
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public bool TryWrite(RawEventDto dto)
	{
		ArgumentNullException.ThrowIfNull(dto);

		if (!_options.CurrentValue.Monitoring.FloodGuardEnabled
			|| EventFloodGuardPolicy.MustBypass(dto.EventId))
		{
			return _inner.TryWrite(dto);
		}

		Span<byte> sourceIpBytes = stackalloc byte[16];
		if (!TryGetSourceIpBytes(dto, sourceIpBytes, out int sourceIpLength))
		{
			return _inner.TryWrite(dto);
		}

		FloodDecision decision = _guard.Hit(
			ComputeChannelCode(dto.Channel),
			sourceIpBytes[..sourceIpLength],
			DateTime.UtcNow.Ticks,
			out _);

		if (decision == FloodDecision.AggregateOnly)
		{
			_metrics.IncrementFloodSuppressed();
			return true;
		}

		if (decision == FloodDecision.Sample)
		{
			_metrics.IncrementFloodSampled();
		}

		return _inner.TryWrite(dto);
	}

	/// <inheritdoc />
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public bool TryRead(out RawEventDto dto)
		=> _inner.TryRead(out dto);

	/// <inheritdoc />
	public ValueTask<bool> WaitToReadAsync(TimeSpan timeout, CancellationToken ct)
		=> _inner.WaitToReadAsync(timeout, ct);

	// ── SIMD & Zero-Alloc Parsers ────────────────────────────────────────────────

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static bool TryGetSourceIpBytes(RawEventDto dto, Span<byte> destination, out int written)
	{
		byte[]? binary = dto.SourceIpBinary;
		if (binary is not null && binary.Length is 4 or 16)
		{
			binary.CopyTo(destination);
			written = binary.Length;
			return true;
		}

		if (string.IsNullOrWhiteSpace(dto.SourceIp))
		{
			dto.SourceIp = EventXmlParser.ExtractSourceIp(
				EventXmlParser.ParseSafe(dto.XmlPayload),
				dto.EventId);
		}

		if (string.IsNullOrWhiteSpace(dto.SourceIp)
			|| !IPAddress.TryParse(dto.SourceIp, out IPAddress? sourceIp))
		{
			written = 0;
			return false;
		}

		return sourceIp.TryWriteBytes(destination, out written);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static int ComputeChannelCode(string channel)
	{
		const int FnvOffsetBasis = unchecked((int)2_166_136_261);
		const int FnvPrime = 16_777_619;

		int hash = FnvOffsetBasis;
		ReadOnlySpan<char> characters = channel.AsSpan();
		for (int index = 0; index < characters.Length; index++)
		{
			hash = (hash ^ characters[index]) * FnvPrime;
		}

		return hash;
	}
}
