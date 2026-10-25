/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.2
// File   : DirectDbContextFactory.cs
// Project: RdpAudit.StorageBenchmarks
// Purpose: An IDbContextFactory over one fixed SQLite path. The real retention engine asks a factory
//          for contexts; production registers EF's pooled factory through the service host. The runner
//          needs the engine, not the host, so this is the smallest thing that satisfies the interface -
//          and it deliberately applies the SAME options construction the service uses
//          (AuditDbContextOptionsFactory.Create with the write-enabling pragma interceptor), so the
//          benchmark store carries production's WAL, synchronous and auto_vacuum settings.
// Depends: AuditDbContext, Microsoft.EntityFrameworkCore
// Extends: System.Object

using Microsoft.EntityFrameworkCore;
using RdpAudit.Core.Data;

namespace RdpAudit.StorageBenchmarks;

/// <summary>Creates <see cref="AuditDbContext"/> instances over one fixed store.</summary>
internal sealed class DirectDbContextFactory : IDbContextFactory<AuditDbContext>
{
	private readonly DbContextOptions<AuditDbContext> _options;

	/// <summary>Creates the factory over the options built for the benchmark store.</summary>
	public DirectDbContextFactory(DbContextOptions<AuditDbContext> options)
	{
		ArgumentNullException.ThrowIfNull(options);
		_options = options;
	}

	/// <inheritdoc />
	public AuditDbContext CreateDbContext() => new(_options);

	/// <inheritdoc />
	public Task<AuditDbContext> CreateDbContextAsync(CancellationToken cancellationToken = default)
		=> Task.FromResult(CreateDbContext());
}
