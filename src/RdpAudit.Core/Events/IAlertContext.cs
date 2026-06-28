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

	Task<Address?> GetAddressAsync(string ip, CancellationToken ct = default);
}
