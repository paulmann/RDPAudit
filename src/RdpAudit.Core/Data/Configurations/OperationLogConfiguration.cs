// File:    src/RdpAudit.Core/Data/Configurations/OperationLogConfiguration.cs
// Module:  RdpAudit.Core.Data.Configurations
// Purpose: EF Core entity configuration for OperationLog. Indexes are tuned for the Logs tab's
//          frequent filters: newest-first by time, by severity within a time range, and by
//          source / operation within a time range.
// Extends: Microsoft.EntityFrameworkCore.IEntityTypeConfiguration{OperationLog}
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using RdpAudit.Core.Models;

namespace RdpAudit.Core.Data.Configurations;

/// <summary>EF Core entity configuration for <see cref="OperationLog"/>.</summary>
public sealed class OperationLogConfiguration : IEntityTypeConfiguration<OperationLog>
{
	public void Configure(EntityTypeBuilder<OperationLog> b)
	{
		b.ToTable("OperationLogs");
		b.HasKey(o => o.Id);
		b.Property(o => o.Id).ValueGeneratedOnAdd();
		b.Property(o => o.Source).IsRequired().HasMaxLength(64);
		b.Property(o => o.Operation).IsRequired().HasMaxLength(128);
		b.Property(o => o.Message).IsRequired().HasMaxLength(2048);
		b.Property(o => o.DetailsJson).HasMaxLength(65536);
		b.Property(o => o.ExceptionType).HasMaxLength(256);
		b.Property(o => o.ExceptionMessage).HasMaxLength(2048);
		b.Property(o => o.StackTrace).HasMaxLength(65536);
		b.Property(o => o.CorrelationId).HasMaxLength(64);
		b.Property(o => o.Actor).HasMaxLength(256);

		// Newest-first listing and time-window retention pruning.
		b.HasIndex(o => o.TimeUtc);
		// Severity filtering within a time window (Logs tab severity dropdown + depth days).
		b.HasIndex(o => new { o.Severity, o.TimeUtc });
		// Source / operation filtering within a time window.
		b.HasIndex(o => new { o.Source, o.TimeUtc });
		b.HasIndex(o => new { o.Operation, o.TimeUtc });
	}
}
