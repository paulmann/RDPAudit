// File:    src/RdpAudit.Core/Data/Configurations/AlertConfiguration.cs
// Module:  RdpAudit.Core.Data.Configurations
// Purpose: EF Core entity configuration for Alert.
// Extends: Microsoft.EntityFrameworkCore.IEntityTypeConfiguration{Alert}
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using RdpAudit.Core.Models;

namespace RdpAudit.Core.Data.Configurations;

/// <summary>EF Core entity configuration for <see cref="Alert"/>.</summary>
public sealed class AlertConfiguration : IEntityTypeConfiguration<Alert>
{
	public void Configure(EntityTypeBuilder<Alert> b)
	{
		b.ToTable("Alerts");
		b.HasKey(a => a.Id);
		b.Property(a => a.Id).ValueGeneratedOnAdd();
		b.Property(a => a.RuleId).IsRequired().HasMaxLength(64);
		b.Property(a => a.SourceIp).HasMaxLength(45);
		b.Property(a => a.UserName).HasMaxLength(256);
		b.Property(a => a.Message).IsRequired().HasMaxLength(2048);
		b.Property(a => a.Details).HasMaxLength(65536);
		b.HasIndex(a => new { a.TimeUtc, a.Severity });
		b.HasIndex(a => new { a.RuleId, a.TimeUtc });
		b.HasIndex(a => a.Acknowledged);
	}
}
