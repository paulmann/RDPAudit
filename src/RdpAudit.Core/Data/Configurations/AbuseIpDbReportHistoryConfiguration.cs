// File:    src/RdpAudit.Core/Data/Configurations/AbuseIpDbReportHistoryConfiguration.cs
// Module:  RdpAudit.Core.Data.Configurations
// Purpose: EF Core entity configuration for AbuseIpDbReportHistory. Indexes the latest-successful
//          report lookup by IP that drives the report cooldown / dedupe.
// Extends: Microsoft.EntityFrameworkCore.IEntityTypeConfiguration{AbuseIpDbReportHistory}
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using RdpAudit.Core.Models;

namespace RdpAudit.Core.Data.Configurations;

/// <summary>EF Core entity configuration for <see cref="AbuseIpDbReportHistory"/>.</summary>
public sealed class AbuseIpDbReportHistoryConfiguration : IEntityTypeConfiguration<AbuseIpDbReportHistory>
{
	public void Configure(EntityTypeBuilder<AbuseIpDbReportHistory> b)
	{
		b.ToTable("AbuseIpDbReportHistory");
		b.HasKey(x => x.Id);
		b.Property(x => x.Id).ValueGeneratedOnAdd();
		b.Property(x => x.IpAddress).IsRequired().HasMaxLength(45);
		b.Property(x => x.ResultCode).HasMaxLength(64);
		b.Property(x => x.ErrorMessage).HasMaxLength(2048);
		b.Property(x => x.AbuseCategories).IsRequired().HasMaxLength(256);
		b.Property(x => x.CommentHash).HasMaxLength(64);
		b.Property(x => x.Source).HasMaxLength(64);

		// v1.2.6 report-log columns.
		b.Property(x => x.Action).HasConversion<int>();
		b.Property(x => x.Reason).HasMaxLength(64);
		b.Property(x => x.Classification).HasConversion<int>();
		b.Property(x => x.ReportId).HasMaxLength(128);
		b.Property(x => x.UsernamesSample).HasMaxLength(512);
		b.Property(x => x.CommentPreview).HasMaxLength(512);

		// Drives the success-filtered cooldown lookup: latest successful report for an IP.
		b.HasIndex(x => new { x.IpAddress, x.Succeeded, x.ReportedAtUtc });
		b.HasIndex(x => x.ReportedAtUtc);
	}
}
