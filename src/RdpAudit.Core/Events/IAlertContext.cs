// File:    src/RdpAudit.Core/Events/IAlertContext.cs
// Module:  RdpAudit.Core.Events
// Purpose: Lookup primitives provided to alert rules (recent events, address reputation, options).
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Config;
using RdpAudit.Core.Models;

namespace RdpAudit.Core.Events;

/// <summary>Lookup primitives provided to alert rules.</summary>
public interface IAlertContext
{
	RdpAuditOptions Options { get; }

	Task<IReadOnlyList<RawEvent>> GetRecentByIpAsync(
		string ip,
		int count,
		TimeSpan window,
		CancellationToken ct = default);

	Task<IReadOnlyList<RawEvent>> GetRecentByUserAsync(
		string user,
		int count,
		TimeSpan window,
		CancellationToken ct = default);

	Task<IReadOnlyList<RawEvent>> GetRecentBySessionIdAsync(
		int sessionId,
		int count,
		TimeSpan window,
		CancellationToken ct = default);

	/// <summary>Returns recent events for <paramref name="user"/> whose <c>TimeUtc</c> falls inside
	/// <c>[anchorUtc - before, anchorUtc + after]</c>. Anchoring the window to the event being
	/// evaluated (rather than the wall clock) lets a rule correlate with events that ran
	/// milliseconds earlier even when the alert is processed long after the fact (backlog /
	/// replay). The default implementation falls back to the wall-clock lookup so existing
	/// implementors keep working; the EF-backed context overrides it with an event-anchored query.</summary>
	Task<IReadOnlyList<RawEvent>> GetRecentByUserAroundAsync(
		string user,
		int count,
		DateTime anchorUtc,
		TimeSpan before,
		TimeSpan after,
		CancellationToken ct = default)
		=> GetRecentByUserAsync(user, count, before + after, ct);

	Task<Address?> GetAddressAsync(string ip, CancellationToken ct = default);
}
