/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.2.0
// File   : PagedEventsQuery.cs
// Project: RdpAudit.Core (RdpAudit.Core.RestApi)
// Purpose: Normalized, clamped query contract for the read-only REST /events endpoint. Every
//          bound here is sanitized BEFORE any SQL is built: page size, offset, channel,
//          event id, canonical source IP, user-name contains needle and the SinceUtc/ToUtc
//          window. The reader runs <see cref="Normalize"/> first, so a hostile or oversized
//          request can never scan or serialize the whole RawEvents table.
// Depends: RdpAudit.Core.Util
// Extends: System.Object

using RdpAudit.Core.Util;

namespace RdpAudit.Core.RestApi;

/// <summary>Bounded, clamped query for the /events endpoint. Normalize() yields the effective values.</summary>
public sealed class PagedEventsQuery
{
	/// <summary>Default page size when the caller supplies none.</summary>
	public const int DefaultPageSize = 100;

	/// <summary>Hard upper bound for one page.</summary>
	public const int MaxPageSize = 500;

	/// <summary>Hard upper bound for the offset.</summary>
	public const int MaxOffset = 1_000_000;

	/// <summary>Maximum accepted channel text length (mirrors the RawEvents column bound).</summary>
	public const int MaxChannelLength = 256;

	/// <summary>Maximum accepted user-name needle length.</summary>
	public const int MaxUserNameLength = 256;

	/// <summary>Maximum canonical IP string length (covers the longest IPv6 form).</summary>
	public const int MaxSourceIpLength = 45;

	public int Limit { get; init; } = DefaultPageSize;

	public int Offset { get; init; }

	public string? Channel { get; init; }

	public int? EventId { get; init; }

	public string? SourceIp { get; init; }

	public string? UserNameContains { get; init; }

	public DateTime? SinceUtc { get; init; }

	public DateTime? ToUtc { get; init; }

	public bool IncludeExplain { get; init; }

	public bool IncludeDetails { get; init; }

	/// <summary>
	/// Returns a fully clamped, sanitized copy: page size inside [1, 500], offset inside
	/// [0, 1_000_000], empty / over-long text filters dropped, the source IP collapsed to its
	/// canonical form via <see cref="IpNormalizer"/>, instants normalized to UTC and an inverted
	/// SinceUtc / ToUtc window swapped into chronological order.
	/// </summary>
	public PagedEventsQuery Normalize()
	{
		int limit = Limit;
		if (limit < 1)
		{
			limit = DefaultPageSize;
		}
		else if (limit > MaxPageSize)
		{
			limit = MaxPageSize;
		}

		int offset = Math.Clamp(Offset, 0, MaxOffset);

		string? channel = NormalizeText(Channel, MaxChannelLength);
		int? eventId = EventId is > 0 ? EventId : null;

		string? sourceIp = IpNormalizer.Normalize(SourceIp);
		if (sourceIp is not null && sourceIp.Length > MaxSourceIpLength)
		{
			sourceIp = null;
		}

		string? userNameContains = NormalizeText(UserNameContains, MaxUserNameLength);

		DateTime? sinceUtc = NormalizeInstant(SinceUtc);
		DateTime? toUtc = NormalizeInstant(ToUtc);
		if (sinceUtc.HasValue && toUtc.HasValue && sinceUtc.Value > toUtc.Value)
		{
			(sinceUtc, toUtc) = (toUtc, sinceUtc);
		}

		return new PagedEventsQuery
		{
			Limit = limit,
			Offset = offset,
			Channel = channel,
			EventId = eventId,
			SourceIp = sourceIp,
			UserNameContains = userNameContains,
			SinceUtc = sinceUtc,
			ToUtc = toUtc,
			IncludeExplain = IncludeExplain,
			IncludeDetails = IncludeDetails,
		};
	}

	private static string? NormalizeText(string? value, int maxLength)
	{
		if (string.IsNullOrWhiteSpace(value))
		{
			return null;
		}

		string trimmed = StripControlCharacters(value.Trim());
		if (trimmed.Length == 0 || trimmed.Length > maxLength)
		{
			return null;
		}

		return trimmed;
	}

	/// <summary>Removes C0 control characters and DEL from a free-text filter value.</summary>
	/// <remarks>
	/// A line break inside a filter value is not a legal character in any channel or user name this
	/// product stores, and it breaks the line-oriented handling of the generated SQL text
	/// (<c>PagedEventReader.StripParamDirectives</c>), so the whole C0 set and DEL are dropped rather
	/// than passed through to the query generator.
	/// </remarks>
	public static string StripControlCharacters(string value)
	{
		ArgumentNullException.ThrowIfNull(value);

		char[]? buffer = null;
		int written = 0;
		for (int i = 0; i < value.Length; i++)
		{
			char c = value[i];
			if (c < ' ' || c == '\u007F')
			{
				buffer ??= value.ToCharArray();
				continue;
			}

			if (buffer is not null)
			{
				buffer[written] = c;
			}

			written++;
		}

		return buffer is null ? value : new string(buffer, 0, written);
	}

	private static DateTime? NormalizeInstant(DateTime? value)
	{
		if (!value.HasValue)
		{
			return null;
		}

		DateTime instant = value.Value;
		if (instant.Kind == DateTimeKind.Local)
		{
			return instant.ToUniversalTime();
		}

		if (instant.Kind == DateTimeKind.Unspecified)
		{
			return DateTime.SpecifyKind(instant, DateTimeKind.Utc);
		}

		return instant;
	}
}
