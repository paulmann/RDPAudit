// File:    src/RdpAudit.Core/Data/Configurations/ThreatIntelUsageCounterConfiguration.cs
// Module:  RdpAudit.Core.Data.Configurations
// Purpose: EF Core entity configuration for ThreatIntelUsageCounter.
// Extends: Microsoft.EntityFrameworkCore.IEntityTypeConfiguration{ThreatIntelUsageCounter}
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using RdpAudit.Core.Models;

namespace RdpAudit.Core.Data.Configurations;

/// <summary>EF Core entity configuration for <see cref="ThreatIntelUsageCounter"/>.</summary>
public sealed class ThreatIntelUsageCounterConfiguration : IEntityTypeConfiguration<ThreatIntelUsageCounter>
{
	public void Configure(EntityTypeBuilder<ThreatIntelUsageCounter> b)
	{
		b.ToTable("ThreatIntelUsageCounters");
		b.HasKey(x => x.DayDateUtc);
		b.Property(x => x.DayDateUtc).IsRequired().HasMaxLength(10);
		b.Property(x => x.Count).IsRequired();
	}
}
