// File:    src/RdpAudit.Core/Data/AuditDbContext.cs
// Module:  RdpAudit.Core.Data
// Purpose: Primary EF Core DbContext for the RdpAudit SQLite database.
// Extends: Microsoft.EntityFrameworkCore.DbContext
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using Microsoft.EntityFrameworkCore;
using RdpAudit.Core.Models;

namespace RdpAudit.Core.Data;

/// <summary>Primary EF Core DbContext for the RdpAudit SQLite database.</summary>
public sealed class AuditDbContext : DbContext
{
	public AuditDbContext(DbContextOptions<AuditDbContext> options) : base(options)
	{
	}

	public DbSet<RawEvent> RawEvents => Set<RawEvent>();

	public DbSet<Session> Sessions => Set<Session>();

	public DbSet<Address> Addresses => Set<Address>();

	public DbSet<Alert> Alerts => Set<Alert>();

	public DbSet<Bookmark> Bookmarks => Set<Bookmark>();

	public DbSet<DbProp> DbProps => Set<DbProp>();

	public DbSet<BlocklistEntry> BlocklistEntries => Set<BlocklistEntry>();

	public DbSet<WhitelistEntry> WhitelistEntries => Set<WhitelistEntry>();

	public DbSet<LoginRule> LoginRules => Set<LoginRule>();

	public DbSet<ActiveBlock> ActiveBlocks => Set<ActiveBlock>();

	public DbSet<AbuseReport> AbuseReports => Set<AbuseReport>();

	public DbSet<AbuseIpDbReportHistory> AbuseIpDbReportHistory => Set<AbuseIpDbReportHistory>();

	public DbSet<AttackStat> AttackStats => Set<AttackStat>();

	public DbSet<SessionIpCorrelation> SessionIpCorrelations => Set<SessionIpCorrelation>();

	public DbSet<RdpConnectionFact> RdpConnectionFacts => Set<RdpConnectionFact>();

	public DbSet<AuthAttemptFact> AuthAttemptFacts => Set<AuthAttemptFact>();

	public DbSet<OperationLog> OperationLogs => Set<OperationLog>();

	protected override void OnModelCreating(ModelBuilder modelBuilder)
	{
		base.OnModelCreating(modelBuilder);
		modelBuilder.ApplyConfigurationsFromAssembly(typeof(AuditDbContext).Assembly);
	}
}
