/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 1.0.0
// File   : DatabaseIntegrityCheckResultConfiguration.cs
// Project: RdpAudit.Core (RdpAudit.Core.Data.Configurations)
// Purpose: Maps the durable integrity-check journal to its SQLite schema and the one index the
//          Database-tab overview needs.
// Depends: DatabaseIntegrityCheckResult, IEntityTypeConfiguration
// Extends: Mirror any appended DatabaseIntegrityCheckResult property here before generating a migration.

using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using RdpAudit.Core.Models;

namespace RdpAudit.Core.Data.Configurations;

/// <summary>EF Core entity configuration for <see cref="DatabaseIntegrityCheckResult"/>.</summary>
public sealed class DatabaseIntegrityCheckResultConfiguration : IEntityTypeConfiguration<DatabaseIntegrityCheckResult>
{
	/// <inheritdoc />
	public void Configure(EntityTypeBuilder<DatabaseIntegrityCheckResult> b)
	{
		b.ToTable("DatabaseIntegrityCheckResult");
		b.HasKey(e => e.Id);
		b.Property(e => e.Id).ValueGeneratedOnAdd();
		b.Property(e => e.Kind)
			.HasConversion<int>()
			.IsRequired();
		b.Property(e => e.StartedUtc).IsRequired();
		b.Property(e => e.CompletedUtc).IsRequired();
		b.Property(e => e.Outcome)
			.HasConversion<int>()
			.IsRequired();
		b.Property(e => e.Detail).IsRequired().HasMaxLength(4096);
		b.Property(e => e.DurationMs).IsRequired();
		b.Property(e => e.InitiatedBy).IsRequired().HasMaxLength(256);

		// "What did the newest check of each kind report" - one index seek per kind for the overview.
		b.HasIndex(e => new { e.Kind, e.CompletedUtc });
	}
}
