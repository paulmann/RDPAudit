// File:    src/RdpAudit.Core/Data/Configurations/LoginRuleConfiguration.cs
// Module:  RdpAudit.Core.Data.Configurations
// Purpose: EF Core entity configuration for LoginRule.
// Extends: Microsoft.EntityFrameworkCore.IEntityTypeConfiguration{LoginRule}
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using RdpAudit.Core.Models;

namespace RdpAudit.Core.Data.Configurations;

/// <summary>EF Core entity configuration for <see cref="LoginRule"/>.</summary>
public sealed class LoginRuleConfiguration : IEntityTypeConfiguration<LoginRule>
{
	public void Configure(EntityTypeBuilder<LoginRule> b)
	{
		b.ToTable("LoginRules");
		b.HasKey(x => x.Id);
		b.Property(x => x.Id).ValueGeneratedOnAdd();
		b.Property(x => x.Login).IsRequired().HasMaxLength(256);
		b.Property(x => x.DisplayLogin).HasMaxLength(256);
		b.Property(x => x.Note).HasMaxLength(512);
		b.Property(x => x.TriggerCount).HasDefaultValue(0L);
		b.Property(x => x.LastSourceIp).HasMaxLength(45);
		b.HasIndex(x => x.Login).IsUnique();
		b.HasIndex(x => x.Enabled);
	}
}
