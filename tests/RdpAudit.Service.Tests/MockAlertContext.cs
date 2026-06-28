// File:    tests/RdpAudit.Service.Tests/MockAlertContext.cs
// Module:  RdpAudit.Service.Tests
// Purpose: In-memory IAlertContext used by the alert-rule unit tests.
// Extends: RdpAudit.Core.Events.IAlertContext
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Config;
using RdpAudit.Core.Events;
using RdpAudit.Core.Models;

namespace RdpAudit.Service.Tests;

/// <summary>In-memory IAlertContext used by the alert-rule unit tests.</summary>
internal sealed class MockAlertContext : IAlertContext
{
	private readonly IEnumerable<RawEvent> _byIp;
	private readonly IEnumerable<RawEvent> _byUser;
	private readonly IEnumerable<RawEvent> _bySession;
	private readonly Address? _address;

	public RdpAuditOptions Options { get; }

	public MockAlertContext(
		RdpAuditOptions? options = null,
		IEnumerable<RawEvent>? byIp = null,
		IEnumerable<RawEvent>? byUser = null,
		IEnumerable<RawEvent>? bySession = null,
		Address? address = null)
	{
		_byIp = byIp ?? Array.Empty<RawEvent>();
		_byUser = byUser ?? Array.Empty<RawEvent>();
		_bySession = bySession ?? Array.Empty<RawEvent>();
		_address = address;
		Options = options ?? new RdpAuditOptions();
	}

	public Task<IReadOnlyList<RawEvent>> GetRecentByIpAsync(string ip, int count, TimeSpan window, CancellationToken ct = default)
		=> Task.FromResult<IReadOnlyList<RawEvent>>(_byIp.Take(count).ToList());

	public Task<IReadOnlyList<RawEvent>> GetRecentByUserAsync(string user, int count, TimeSpan window, CancellationToken ct = default)
		=> Task.FromResult<IReadOnlyList<RawEvent>>(_byUser.Take(count).ToList());

	public Task<IReadOnlyList<RawEvent>> GetRecentBySessionIdAsync(int sessionId, int count, TimeSpan window, CancellationToken ct = default)
		=> Task.FromResult<IReadOnlyList<RawEvent>>(_bySession.Take(count).ToList());

	public Task<Address?> GetAddressAsync(string ip, CancellationToken ct = default)
		=> Task.FromResult(_address);
}
