// File:    src/RdpAudit.Core/Data/Configurations/CrossHostFactConfiguration.cs
// Module:  RdpAudit.Core.Data.Configurations
// Purpose: EF Core entity configuration for CrossHostFact. The unique DedupKey index enforces
//          one-row-per-observation at the database boundary; the remaining indexes match the
//          correlation worker/pull query patterns (per-host scans, per-user scans).
// Extends: Microsoft.EntityFrameworkCore.IEntityTypeConfiguration{CrossHostFact}
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using RdpAudit.Core.Models;

namespace RdpAudit.Core.Data.Configurations;

/// <summary>EF Core entity configuration for <see cref="CrossHostFact"/>.</summary>
public sealed class CrossHostFactConfiguration : IEntityTypeConfiguration<CrossHostFact>
{
	public void Configure(EntityTypeBuilder<CrossHostFact> b)
	{
		b.ToTable("CrossHostFacts");
		b.HasKey(e => e.Id);
		b.Property(e => e.Id).ValueGeneratedOnAdd();
		b.Property(e => e.HostName).IsRequired().HasMaxLength(256);
		b.Property(e => e.TimeUtc).IsRequired();
		b.Property(e => e.UserName).HasMaxLength(256);
		b.Property(e => e.NormalizedUserName).HasMaxLength(256);
		b.Property(e => e.SourceIp).HasMaxLength(45);
		b.Property(e => e.Kind).HasConversion<int>().IsRequired();
		b.Property(e => e.EventId).IsRequired();
		b.Property(e => e.DedupKey).HasMaxLength(64);
		b.Property(e => e.IngestedUtc).IsRequired();

		b.HasIndex(e => e.DedupKey).IsUnique();
		b.HasIndex(e => new { e.HostName, e.TimeUtc });
		b.HasIndex(e => new { e.NormalizedUserName, e.TimeUtc });
		b.HasIndex(e => new { e.Kind, e.HostName });
	}
}
