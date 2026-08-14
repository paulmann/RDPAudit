/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : EventCollectionAuditConfiguration.cs
// Project: RdpAudit.Core (RdpAudit.Core.Data.Configurations)
// Purpose: Maps append-only collection-policy audit records to SQLite.
// Depends: EventCollectionAudit, IEntityTypeConfiguration
// Extends: Add indexes here for new audit query paths before generating a migration.

using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using RdpAudit.Core.Models;

namespace RdpAudit.Core.Data.Configurations;

/// <summary>EF Core mapping for <see cref="EventCollectionAudit"/>.</summary>
public sealed class EventCollectionAuditConfiguration : IEntityTypeConfiguration<EventCollectionAudit>
{
	/// <inheritdoc />
	public void Configure(EntityTypeBuilder<EventCollectionAudit> builder)
	{
		builder.ToTable("EventCollectionAudit");
		builder.HasKey(entity => entity.Id);
		builder.Property(entity => entity.Id).ValueGeneratedOnAdd();
		builder.Property(entity => entity.InvokerSid).IsRequired().HasMaxLength(128);
		builder.Property(entity => entity.InvokerAccount).IsRequired().HasMaxLength(260);
		builder.Property(entity => entity.OldValue).HasMaxLength(512);
		builder.Property(entity => entity.NewValue).HasMaxLength(512);
		builder.Property(entity => entity.Note).HasMaxLength(512);
		builder.HasIndex(entity => entity.OccurredUtc);
	}
}
