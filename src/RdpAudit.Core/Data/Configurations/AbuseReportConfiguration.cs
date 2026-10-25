// File:    src/RdpAudit.Core/Data/Configurations/AbuseReportConfiguration.cs
// Module:  RdpAudit.Core.Data.Configurations
// Purpose: EF Core entity configuration for AbuseReport.
// Extends: Microsoft.EntityFrameworkCore.IEntityTypeConfiguration{AbuseReport}
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using RdpAudit.Core.Models;

namespace RdpAudit.Core.Data.Configurations;

/// <summary>EF Core entity configuration for <see cref="AbuseReport"/>.</summary>
public sealed class AbuseReportConfiguration : IEntityTypeConfiguration<AbuseReport>
{
	public void Configure(EntityTypeBuilder<AbuseReport> b)
	{
		b.ToTable("AbuseReports");
		b.HasKey(x => x.Id);
		b.Property(x => x.Id).ValueGeneratedOnAdd();
		b.Property(x => x.Ip).IsRequired().HasMaxLength(45);
		b.Property(x => x.Categories).IsRequired().HasMaxLength(256);
		b.Property(x => x.Error).HasMaxLength(2048);
		b.HasIndex(x => new { x.Ip, x.ReportedUtc });
		b.HasIndex(x => x.ReportedUtc);
	}
}
