/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : IpEventSummaryConfiguration.cs
// Project: RdpAudit.Core (RdpAudit.Core.Data.Configurations)
// Purpose: Maps the durable per-IP event summary model to its SQLite schema and query indexes.
// Depends: IpEventSummary, IEntityTypeConfiguration
// Extends: Mirror any appended IpEventSummary property here before generating a migration.

using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using RdpAudit.Core.Models;

namespace RdpAudit.Core.Data.Configurations;

/// <summary>EF Core mapping for <see cref="IpEventSummary"/>.</summary>
public sealed class IpEventSummaryConfiguration : IEntityTypeConfiguration<IpEventSummary>
{
	/// <inheritdoc />
	public void Configure(EntityTypeBuilder<IpEventSummary> builder)
	{
		builder.ToTable("IpEventSummary");
		builder.HasKey(entity => entity.IpBinary16);
		builder.Property(entity => entity.IpBinary16).IsRequired().HasMaxLength(16).IsFixedLength();
		builder.Property(entity => entity.IpText).IsRequired().HasMaxLength(45);
		builder.Property(entity => entity.AddressFamily).IsRequired();
		builder.Property(entity => entity.FirstEventUtc).IsRequired();
		builder.Property(entity => entity.FirstEventId).IsRequired();
		builder.Property(entity => entity.FirstEventSequence).IsRequired();
		builder.Property(entity => entity.FirstEventSnapshot).IsRequired();
		builder.Property(entity => entity.LastEventUtc).IsRequired();
		builder.Property(entity => entity.LastEventId).IsRequired();
		builder.Property(entity => entity.LastEventSequence).IsRequired();
		builder.Property(entity => entity.LastEventSnapshot).IsRequired();
		builder.Property(entity => entity.TotalEventCount).HasDefaultValue(0L);
		builder.Property(entity => entity.SuccessCount).HasDefaultValue(0L);
		builder.Property(entity => entity.FailureCount).HasDefaultValue(0L);
		builder.Property(entity => entity.ShardRelativePath).IsRequired().HasMaxLength(260);
		builder.Property(entity => entity.ShardRecordCount).HasDefaultValue(0L);
		builder.Property(entity => entity.ShardBytes).HasDefaultValue(0L);
		builder.Property(entity => entity.ShardFormatVersion).HasDefaultValue(1);
		builder.Property(entity => entity.ShardEvictedCount).HasDefaultValue(0L);
		builder.Property(entity => entity.IsSubnetAggregate).HasDefaultValue(false);
		builder.Property(entity => entity.Flags).HasDefaultValue(0);
		builder.HasIndex(entity => entity.LastEventUtc);
		builder.HasIndex(entity => entity.IpText).IsUnique();
	}
}
