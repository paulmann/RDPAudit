// File:    src/RdpAudit.Core/Data/Configurations/DbPropConfiguration.cs
// Module:  RdpAudit.Core.Data.Configurations
// Purpose: EF Core entity configuration for DbProp.
// Extends: Microsoft.EntityFrameworkCore.IEntityTypeConfiguration{DbProp}
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using RdpAudit.Core.Models;

namespace RdpAudit.Core.Data.Configurations;

/// <summary>EF Core entity configuration for <see cref="DbProp"/>.</summary>
public sealed class DbPropConfiguration : IEntityTypeConfiguration<DbProp>
{
	public void Configure(EntityTypeBuilder<DbProp> b)
	{
		b.ToTable("DbProps");
		b.HasKey(p => p.Key);
		b.Property(p => p.Key).HasMaxLength(128);
		b.Property(p => p.Value).HasMaxLength(8192);
	}
}
