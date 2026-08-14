/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : IngestionSequenceConfiguration.cs
// Project: RdpAudit.Core (RdpAudit.Core.Data.Configurations)
// Purpose: Maps the singleton durable ingestion sequence sidecar to SQLite.
// Depends: IngestionSequence, IEntityTypeConfiguration
// Extends: Preserve the seeded singleton row when changing sequence allocation behavior.

using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using RdpAudit.Core.Models;

namespace RdpAudit.Core.Data.Configurations;

/// <summary>EF Core mapping for <see cref="IngestionSequence"/>.</summary>
public sealed class IngestionSequenceConfiguration : IEntityTypeConfiguration<IngestionSequence>
{
	/// <inheritdoc />
	public void Configure(EntityTypeBuilder<IngestionSequence> builder)
	{
		builder.ToTable("IngestionSequence");
		builder.HasKey(entity => entity.Id);
		builder.Property(entity => entity.Id).ValueGeneratedNever();
		builder.Property(entity => entity.NextValue).HasDefaultValue(1L);
		builder.HasData(new IngestionSequence { Id = 1, NextValue = 1L });
	}
}
