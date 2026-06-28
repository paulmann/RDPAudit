// File:    src/RdpAudit.Core/Data/AuditDbInitializer.cs
// Module:  RdpAudit.Core.Data
// Purpose: Applies EF Core migrations on startup so production upgrades pick up new schema
//          changes; falls back to EnsureCreated() only when no migrations are defined.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

namespace RdpAudit.Core.Data;

/// <summary>Applies EF Core migrations on startup, with EnsureCreated() as a tested fallback.</summary>
public sealed class AuditDbInitializer
{
	private readonly IDbContextFactory<AuditDbContext> _factory;
	private readonly ILogger<AuditDbInitializer> _logger;

	public AuditDbInitializer(IDbContextFactory<AuditDbContext> factory, ILogger<AuditDbInitializer> logger)
	{
		_factory = factory;
		_logger = logger;
	}

	public async Task EnsureCreatedAsync(CancellationToken ct = default)
	{
		await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);

		IEnumerable<string> defined = db.Database.GetMigrations();
		if (defined.Any())
		{
			List<string> pending = (await db.Database.GetPendingMigrationsAsync(ct).ConfigureAwait(false)).ToList();
			if (pending.Count > 0)
			{
				_logger.LogInformation("Applying {Count} pending EF migrations: {Migrations}",
					pending.Count, string.Join(", ", pending));
				await db.Database.MigrateAsync(ct).ConfigureAwait(false);
			}
			else
			{
				_logger.LogInformation("Schema up-to-date; no pending migrations.");
			}
		}
		else
		{
			bool created = await db.Database.EnsureCreatedAsync(ct).ConfigureAwait(false);
			_logger.LogInformation("No migrations defined; EnsureCreatedAsync executed (created={Created})", created);
		}
	}
}
