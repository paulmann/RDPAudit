// File:    src/RdpAudit.Service/Alerts/DbAlertContext.cs
// Module:  RdpAudit.Service.Alerts
// Purpose: EF Core-backed IAlertContext used by AlertWorker when evaluating rules.
// Extends: RdpAudit.Core.Events.IAlertContext
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using RdpAudit.Core.Config;
using RdpAudit.Core.Data;
using RdpAudit.Core.Events;
using RdpAudit.Core.Models;

namespace RdpAudit.Service.Alerts;

/// <summary>EF Core-backed IAlertContext used by AlertWorker when evaluating rules.</summary>
public sealed class DbAlertContext : IAlertContext
{
	private readonly IDbContextFactory<AuditDbContext> _factory;
	private readonly IOptionsMonitor<RdpAuditOptions> _options;

	public DbAlertContext(IDbContextFactory<AuditDbContext> factory, IOptionsMonitor<RdpAuditOptions> options)
	{
		_factory = factory;
		_options = options;
	}

	public RdpAuditOptions Options => _options.CurrentValue;

	public async Task<IReadOnlyList<RawEvent>> GetRecentByIpAsync(
		string ip,
		int count,
		TimeSpan window,
		CancellationToken ct = default)
	{
		await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);
		DateTime cutoff = DateTime.UtcNow - window;
		return await db.RawEvents.AsNoTracking()
			.Where(e => e.SourceIp == ip && e.TimeUtc >= cutoff)
			.OrderByDescending(e => e.TimeUtc)
			.Take(count)
			.ToListAsync(ct)
			.ConfigureAwait(false);
	}

	public async Task<IReadOnlyList<RawEvent>> GetRecentByUserAsync(
		string user,
		int count,
		TimeSpan window,
		CancellationToken ct = default)
	{
		await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);
		DateTime cutoff = DateTime.UtcNow - window;
		return await db.RawEvents.AsNoTracking()
			.Where(e => e.UserName == user && e.TimeUtc >= cutoff)
			.OrderByDescending(e => e.TimeUtc)
			.Take(count)
			.ToListAsync(ct)
			.ConfigureAwait(false);
	}

	public async Task<IReadOnlyList<RawEvent>> GetRecentBySessionIdAsync(
		int sessionId,
		int count,
		TimeSpan window,
		CancellationToken ct = default)
	{
		await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);
		DateTime cutoff = DateTime.UtcNow - window;
		return await db.RawEvents.AsNoTracking()
			.Where(e => e.SessionId == sessionId && e.TimeUtc >= cutoff)
			.OrderByDescending(e => e.TimeUtc)
			.Take(count)
			.ToListAsync(ct)
			.ConfigureAwait(false);
	}

	public async Task<Address?> GetAddressAsync(string ip, CancellationToken ct = default)
	{
		await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);
		return await db.Addresses.AsNoTracking()
			.FirstOrDefaultAsync(a => a.Ip == ip, ct)
			.ConfigureAwait(false);
	}
}
