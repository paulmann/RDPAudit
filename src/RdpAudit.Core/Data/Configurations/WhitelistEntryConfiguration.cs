// File:    src/RdpAudit.Core/Data/Configurations/WhitelistEntryConfiguration.cs
// Module:  RdpAudit.Core.Data.Configurations
// Purpose: EF Core entity configuration for WhitelistEntry.
// Extends: Microsoft.EntityFrameworkCore.IEntityTypeConfiguration{WhitelistEntry}
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using RdpAudit.Core.Models;

namespace RdpAudit.Core.Data.Configurations;

/// <summary>EF Core entity configuration for <see cref="WhitelistEntry"/>.</summary>
public sealed class WhitelistEntryConfiguration : IEntityTypeConfiguration<WhitelistEntry>
{
	public void Configure(EntityTypeBuilder<WhitelistEntry> b)
	{
		b.ToTable("WhitelistEntries");
		b.HasKey(x => x.Id);
		b.Property(x => x.Id).ValueGeneratedOnAdd();
		b.Property(x => x.Ip).IsRequired().HasMaxLength(45);
		b.Property(x => x.Note).HasMaxLength(512);
		b.Property(x => x.AddedBy).HasMaxLength(256);
		b.HasIndex(x => x.Ip).IsUnique();
	}
}
