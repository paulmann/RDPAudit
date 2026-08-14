/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : IpEventTypeCounterConfiguration.cs
// Project: RdpAudit.Core (RdpAudit.Core.Data.Configurations)
// Purpose: Maps per-IP and per-event identifier counters to their composite SQLite key.
// Depends: IpEventTypeCounter, IEntityTypeConfiguration
// Extends: Preserve the composite key when extending counter statistics.

using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using RdpAudit.Core.Models;

namespace RdpAudit.Core.Data.Configurations;

/// <summary>EF Core mapping for <see cref="IpEventTypeCounter"/>.</summary>
public sealed class IpEventTypeCounterConfiguration : IEntityTypeConfiguration<IpEventTypeCounter>
{
	/// <inheritdoc />
	public void Configure(EntityTypeBuilder<IpEventTypeCounter> builder)
	{
		builder.ToTable("IpEventTypeCounter");
		builder.HasKey(entity => new { entity.IpBinary16, entity.EventId });
		builder.Property(entity => entity.IpBinary16).IsRequired().HasMaxLength(16).IsFixedLength();
		builder.Property(entity => entity.Count).HasDefaultValue(0L);
		builder.HasIndex(entity => new { entity.EventId, entity.LastUtc });
	}
}
