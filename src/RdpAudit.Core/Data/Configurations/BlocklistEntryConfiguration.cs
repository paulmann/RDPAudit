// File:    src/RdpAudit.Core/Data/Configurations/BlocklistEntryConfiguration.cs
// Module:  RdpAudit.Core.Data.Configurations
// Purpose: EF Core entity configuration for BlocklistEntry.
// Extends: Microsoft.EntityFrameworkCore.IEntityTypeConfiguration{BlocklistEntry}
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using RdpAudit.Core.Models;

namespace RdpAudit.Core.Data.Configurations;

/// <summary>EF Core entity configuration for <see cref="BlocklistEntry"/>.</summary>
public sealed class BlocklistEntryConfiguration : IEntityTypeConfiguration<BlocklistEntry>
{
	public void Configure(EntityTypeBuilder<BlocklistEntry> b)
	{
		b.ToTable("BlocklistEntries");
		b.HasKey(x => x.Id);
		b.Property(x => x.Id).ValueGeneratedOnAdd();
		b.Property(x => x.Ip).HasMaxLength(45);
		b.Property(x => x.Login).HasMaxLength(256);
		b.Property(x => x.Reason).IsRequired().HasMaxLength(1024);
		b.Property(x => x.Source).HasConversion<int>();
		b.HasIndex(x => x.Ip);
		b.HasIndex(x => x.Login);
		b.HasIndex(x => x.ExpiresUtc);
		b.HasIndex(x => new { x.IsEnabled, x.ExpiresUtc });
	}
}
