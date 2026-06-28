// File:    src/RdpAudit.Core/Data/Configurations/AddressConfiguration.cs
// Module:  RdpAudit.Core.Data.Configurations
// Purpose: EF Core entity configuration for Address.
// Extends: Microsoft.EntityFrameworkCore.IEntityTypeConfiguration{Address}
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using RdpAudit.Core.Models;

namespace RdpAudit.Core.Data.Configurations;

/// <summary>EF Core entity configuration for <see cref="Address"/>.</summary>
public sealed class AddressConfiguration : IEntityTypeConfiguration<Address>
{
	public void Configure(EntityTypeBuilder<Address> b)
	{
		b.ToTable("Addresses");
		b.HasKey(a => a.Id);
		b.Property(a => a.Id).ValueGeneratedOnAdd();
		b.Property(a => a.Ip).IsRequired().HasMaxLength(45);
		b.Property(a => a.BlockReason).HasMaxLength(512);
		b.Property(a => a.UserNames).HasMaxLength(8192);
		b.HasIndex(a => a.Ip).IsUnique();
		b.HasIndex(a => a.IsBlocked);
		b.HasIndex(a => a.LastSeen);
	}
}
