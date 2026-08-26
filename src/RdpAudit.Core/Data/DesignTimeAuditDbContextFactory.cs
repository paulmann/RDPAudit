// File:    src/RdpAudit.Core/Data/DesignTimeAuditDbContextFactory.cs
// Module:  RdpAudit.Core.Data
// Purpose: Allows `dotnet ef` tooling to instantiate AuditDbContext at design time.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace RdpAudit.Core.Data;

/// <summary>Allows `dotnet ef` tooling to instantiate AuditDbContext at design time.</summary>
public sealed class DesignTimeAuditDbContextFactory : IDesignTimeDbContextFactory<AuditDbContext>
{
	public AuditDbContext CreateDbContext(string[] args)
	{
		DbContextOptionsBuilder<AuditDbContext> builder = new DbContextOptionsBuilder<AuditDbContext>()
			.UseSqlite("Data Source=:memory:");
		AuditDbContextOptions.ApplyWarningPolicy(builder);
		return new AuditDbContext(builder.Options);
	}
}
