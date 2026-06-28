// File:    src/RdpAudit.Core/Data/Configurations/AttackStatConfiguration.cs
// Module:  RdpAudit.Core.Data.Configurations
// Purpose: EF Core entity configuration for AttackStat.
// Extends: Microsoft.EntityFrameworkCore.IEntityTypeConfiguration{AttackStat}
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using RdpAudit.Core.Models;

namespace RdpAudit.Core.Data.Configurations;

/// <summary>EF Core entity configuration for <see cref="AttackStat"/>.</summary>
public sealed class AttackStatConfiguration : IEntityTypeConfiguration<AttackStat>
{
	public void Configure(EntityTypeBuilder<AttackStat> b)
	{
		b.ToTable("AttackStats");
		b.HasKey(x => x.Ip);
		b.Property(x => x.Ip).IsRequired().HasMaxLength(45);
		b.Property(x => x.Top10AttemptedLogins).IsRequired().HasMaxLength(4096);
		b.HasIndex(x => x.LastSeenUtc);
		b.HasIndex(x => x.ThreatScore);
		b.HasIndex(x => x.IsBlocked);
	}
}
