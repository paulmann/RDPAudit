/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : EventEnablementConfiguration.cs
// Project: RdpAudit.Core (RdpAudit.Core.Data.Configurations)
// Purpose: Maps per-event collection enablement overrides to SQLite.
// Depends: EventEnablement, IEntityTypeConfiguration
// Extends: Add scope dimensions here if enablement becomes channel-specific.

using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using RdpAudit.Core.Models;

namespace RdpAudit.Core.Data.Configurations;

/// <summary>EF Core mapping for <see cref="EventEnablement"/>.</summary>
public sealed class EventEnablementConfiguration : IEntityTypeConfiguration<EventEnablement>
{
	/// <inheritdoc />
	public void Configure(EntityTypeBuilder<EventEnablement> builder)
	{
		builder.ToTable("EventEnablement");
		builder.HasKey(entity => entity.EventId);
		builder.Property(entity => entity.EventId).ValueGeneratedNever();
	}
}
