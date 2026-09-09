/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : EventRetentionConfiguration.cs
// Project: RdpAudit.Core (RdpAudit.Core.Data.Configurations)
// Purpose: Maps per-event retention overrides to SQLite.
// Depends: EventRetention, IEntityTypeConfiguration
// Extends: Add scoped retention dimensions here when the policy model gains them.

using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using RdpAudit.Core.Models;

namespace RdpAudit.Core.Data.Configurations;

/// <summary>EF Core mapping for <see cref="EventRetention"/>.</summary>
public sealed class EventRetentionConfiguration : IEntityTypeConfiguration<EventRetention>
{
	/// <inheritdoc />
	public void Configure(EntityTypeBuilder<EventRetention> builder)
	{
		builder.ToTable("EventRetention");
		builder.HasKey(entity => entity.EventId);
		builder.Property(entity => entity.EventId).ValueGeneratedNever();
	}
}
