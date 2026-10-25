/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.2.0
// File   : ReadOnlyAuditDbContextFactory.cs
// Project: RdpAudit.Service (RdpAudit.Service.RestApi)
// Purpose: IDbContextFactory<AuditDbContext> that produces contexts whose connection string is
//          Mode=ReadOnly. Used exclusively by the REST /events reader so that every query it
//          issues is guaranteed side-effect free at the SQLite level, even if a future bug adds a
//          write call. The database path is resolved fresh on each create call so an
//          appsettings.json reload is honoured without a service restart.
// Depends: RdpAudit.Core.Config, RdpAudit.Core.Data
// Extends: IDbContextFactory<AuditDbContext>

using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using RdpAudit.Core.Config;
using RdpAudit.Core.Data;

namespace RdpAudit.Service.RestApi;

public sealed class ReadOnlyAuditDbContextFactory : IDbContextFactory<AuditDbContext>
{
	private readonly IOptionsMonitor<RdpAuditOptions> _options;

	public ReadOnlyAuditDbContextFactory(IOptionsMonitor<RdpAuditOptions> options)
	{
		_options = options ?? throw new ArgumentNullException(nameof(options));
	}

	public AuditDbContext CreateDbContext() => new(BuildOptions());

	public Task<AuditDbContext> CreateDbContextAsync(CancellationToken cancellationToken = default)
	{
		cancellationToken.ThrowIfCancellationRequested();
		return Task.FromResult(new AuditDbContext(BuildOptions()));
	}

	private DbContextOptions<AuditDbContext> BuildOptions()
	{
		string dbPath = Path.GetFullPath(_options.CurrentValue.Storage.ResolveDatabasePath());
		return AuditDbContextOptionsFactory.CreateReadOnly(
			dbPath,
			new ReadOnlySqlitePragmaInterceptor());
	}
}
