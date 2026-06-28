// File:    src/RdpAudit.Core/Events/LiveEventFilter.cs
// Module:  RdpAudit.Core.Events
// Purpose: Pure, UI-agnostic filter specification + predicate for the LiveEvents grid. Stage 4
//          extracts this into Core so it can be unit-tested independently of WinForms and the
//          Configurator project.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Globalization;

namespace RdpAudit.Core.Events;

/// <summary>
/// Immutable filter spec for the LiveEvents grid. All fields combine with AND semantics: a row
/// must satisfy every non-empty field to be included. Empty / null fields are treated as
/// "do not filter on this field".
/// </summary>
/// <remarks>
/// Stage 4 evaluates the predicate client-side over the most recent rows returned by the
/// existing <c>GetRecentEvents</c> IPC. Server-side filtering remains an explicit extension
/// point: when the IPC contract grows a server-side query, the matching parameters here can be
/// forwarded to the service without changing call sites.
/// </remarks>
public sealed class LiveEventFilter
{
	/// <summary>Filter by source IP (case-insensitive contains). Empty = all IPs.</summary>
	public string? Ip { get; init; }

	/// <summary>Filter by user / login (case-insensitive contains). Empty = all users.</summary>
	public string? User { get; init; }

	/// <summary>Filter by exact event id. Null = all event ids.</summary>
	public int? EventId { get; init; }

	/// <summary>Filter by event channel (case-insensitive contains). Empty = all channels.</summary>
	public string? Channel { get; init; }

	/// <summary>
	/// Free-text filter applied across IP / user / channel / domain / process / auth package
	/// (case-insensitive contains). Empty = no text filter.
	/// </summary>
	public string? Text { get; init; }

	/// <summary>
	/// Only include events whose <c>TimeUtc</c> is at or after this instant. Null = no lower bound.
	/// </summary>
	public DateTime? SinceUtc { get; init; }

	/// <summary>
	/// Only include events whose <c>TimeUtc</c> is at or before this instant. Null = no upper bound.
	/// </summary>
	public DateTime? UntilUtc { get; init; }

	/// <summary>True when every field is empty / null and the filter accepts all rows.</summary>
	public bool IsEmpty =>
		string.IsNullOrWhiteSpace(Ip)
		&& string.IsNullOrWhiteSpace(User)
		&& EventId is null
		&& string.IsNullOrWhiteSpace(Channel)
		&& string.IsNullOrWhiteSpace(Text)
		&& SinceUtc is null
		&& UntilUtc is null;

	/// <summary>Evaluate the predicate against a single row projection.</summary>
	public bool Matches(LiveEventRowView row)
	{
		ArgumentNullException.ThrowIfNull(row);

		if (!string.IsNullOrWhiteSpace(Ip)
			&& !ContainsIgnoreCase(row.SourceIp, Ip!))
		{
			return false;
		}

		if (!string.IsNullOrWhiteSpace(User)
			&& !ContainsIgnoreCase(row.UserName, User!))
		{
			return false;
		}

		if (EventId is int wantedId && row.EventId != wantedId)
		{
			return false;
		}

		if (!string.IsNullOrWhiteSpace(Channel)
			&& !ContainsIgnoreCase(row.Channel, Channel!))
		{
			return false;
		}

		if (!string.IsNullOrWhiteSpace(Text))
		{
			string needle = Text!;
			bool textHit =
				ContainsIgnoreCase(row.SourceIp, needle)
				|| ContainsIgnoreCase(row.UserName, needle)
				|| ContainsIgnoreCase(row.Channel, needle)
				|| ContainsIgnoreCase(row.Domain, needle)
				|| ContainsIgnoreCase(row.ProcessName, needle)
				|| ContainsIgnoreCase(row.AuthPackage, needle)
				|| ContainsIgnoreCase(row.EventId.ToString(CultureInfo.InvariantCulture), needle);
			if (!textHit)
			{
				return false;
			}
		}

		if (SinceUtc is DateTime since && row.TimeUtc < since)
		{
			return false;
		}

		if (UntilUtc is DateTime until && row.TimeUtc > until)
		{
			return false;
		}

		return true;
	}

	private static bool ContainsIgnoreCase(string? haystack, string needle)
	{
		if (string.IsNullOrEmpty(haystack))
		{
			return false;
		}

		return haystack.Contains(needle, StringComparison.OrdinalIgnoreCase);
	}
}

/// <summary>
/// Read-only projection of the LiveEvents row consumed by <see cref="LiveEventFilter"/>. Keeping
/// this in Core means the predicate is unit-testable without referencing the WinForms grid
/// binding type that lives in the Configurator assembly.
/// </summary>
public sealed class LiveEventRowView
{
	public long Id { get; init; }

	public int EventId { get; init; }

	public string? Channel { get; init; }

	public DateTime TimeUtc { get; init; }

	public string? SourceIp { get; init; }

	/// <summary>True when <see cref="SourceIp"/> was attached via session correlation.</summary>
	public bool SourceIpDerived { get; init; }

	public string? UserName { get; init; }

	/// <summary>Windows LogonId hex string (e.g. "0x42"). May be null.</summary>
	public string? LogonId { get; init; }

	public string? Domain { get; init; }

	public int? LogonType { get; init; }

	public string? AuthPackage { get; init; }

	public string? ProcessName { get; init; }
}
