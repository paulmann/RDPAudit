// File:    src/RdpAudit.Core/Data/Configurations/CrossHostLinkConfiguration.cs
// Module:  RdpAudit.Core.Data.Configurations
// Purpose: EF Core entity configuration for CrossHostLink. Links are cascade-deleted with their
//          chain; the composite index supports the per-chain ordered hop lookups used by the UI.
// Extends: Microsoft.EntityFrameworkCore.IEntityTypeConfiguration{CrossHostLink}
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using RdpAudit.Core.Models;

namespace RdpAudit.Core.Data.Configurations;

/// <summary>EF Core entity configuration for <see cref="CrossHostLink"/>.</summary>
public sealed class CrossHostLinkConfiguration : IEntityTypeConfiguration<CrossHostLink>
{
	public void Configure(EntityTypeBuilder<CrossHostLink> b)
	{
		b.ToTable("CrossHostLinks");
		b.HasKey(e => e.Id);
		b.Property(e => e.Id).ValueGeneratedOnAdd();
		b.Property(e => e.Ordinal).IsRequired();
		b.Property(e => e.HostName).IsRequired().HasMaxLength(256);
		b.Property(e => e.Kind).HasConversion<int>().IsRequired();
		b.Property(e => e.EventId).IsRequired();
		b.Property(e => e.TimeUtc).IsRequired();
		b.Property(e => e.SourceIp).HasMaxLength(45);
		b.Property(e => e.UserName).HasMaxLength(256);

		b.HasOne(e => e.Chain)
			.WithMany(c => c.Links)
			.HasForeignKey(e => e.CrossHostChainId)
			.OnDelete(DeleteBehavior.Cascade)
			.IsRequired();

		b.HasIndex(e => new { e.CrossHostChainId, e.Ordinal }).IsUnique();
		b.HasIndex(e => new { e.HostName, e.TimeUtc });
	}
}
