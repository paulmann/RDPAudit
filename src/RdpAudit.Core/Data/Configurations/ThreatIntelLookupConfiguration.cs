// File:    src/RdpAudit.Core/Data/Configurations/ThreatIntelLookupConfiguration.cs
// Module:  RdpAudit.Core.Data.Configurations
// Purpose: EF Core entity configuration for ThreatIntelLookup.
// Extends: Microsoft.EntityFrameworkCore.IEntityTypeConfiguration{ThreatIntelLookup}
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using RdpAudit.Core.Models;

namespace RdpAudit.Core.Data.Configurations;

/// <summary>EF Core entity configuration for <see cref="ThreatIntelLookup"/>.</summary>
public sealed class ThreatIntelLookupConfiguration : IEntityTypeConfiguration<ThreatIntelLookup>
{
	public void Configure(EntityTypeBuilder<ThreatIntelLookup> b)
	{
		b.ToTable("ThreatIntelLookups");
		b.HasKey(x => x.Ip);
		b.Property(x => x.Ip).IsRequired().HasMaxLength(45);
		b.Property(x => x.LookedUpUtc).IsRequired();
		b.Property(x => x.Outcome).IsRequired();
		b.Property(x => x.UsageType).HasMaxLength(128);
		b.Property(x => x.CountryCode).HasMaxLength(8);
		b.HasIndex(x => x.NextRetryUtc);
		b.HasIndex(x => x.LookedUpUtc);
	}
}
