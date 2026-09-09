/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.1
// File   : RawEventConfiguration.cs
// Project: RdpAudit.Core (RdpAudit.Core.Data.Configurations)
// Purpose: Maps normalized raw events and their ingestion metadata to the SQLite schema.
// Depends: RawEvent, IEntityTypeConfiguration
// Extends: Mirror every new RawEvent persistence property here before generating a migration.
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using RdpAudit.Core.Models;

namespace RdpAudit.Core.Data.Configurations;

/// <summary>EF Core entity configuration for <see cref="RawEvent"/>.</summary>
public sealed class RawEventConfiguration : IEntityTypeConfiguration<RawEvent>
{
	public void Configure(EntityTypeBuilder<RawEvent> b)
	{
		b.ToTable("RawEvents");
		b.HasKey(e => e.Id);
		b.Property(e => e.Id).ValueGeneratedOnAdd();
		b.Property(e => e.Channel).IsRequired().HasMaxLength(256);
		b.Property(e => e.IngestionSequence).HasDefaultValue(0L);
		b.Property(e => e.EventLayer).HasDefaultValue(0);
		b.Property(e => e.SourceIpBinary).HasMaxLength(16).IsFixedLength();
		b.Property(e => e.UserName).HasMaxLength(256);
		b.Property(e => e.Domain).HasMaxLength(256);
		b.Property(e => e.SourceIp).HasMaxLength(45);
		b.Property(e => e.SourceIpDerived).HasDefaultValue(false);
		b.Property(e => e.SourceIpUnresolved).HasDefaultValue(false);
		b.Property(e => e.LogonId).HasMaxLength(32);
		b.Property(e => e.AuthPackage).HasMaxLength(64);
		b.Property(e => e.Status).HasMaxLength(64);
		b.Property(e => e.ProcessName).HasMaxLength(1024);
		b.Property(e => e.CommandLine).HasMaxLength(8192);
		b.Property(e => e.ObjectName).HasMaxLength(1024);
		b.Property(e => e.AccessMask).HasMaxLength(32);
		b.Property(e => e.Details).HasMaxLength(65536);

		b.HasIndex(e => new { e.EventId, e.TimeUtc });
		b.HasIndex(e => new { e.SourceIp, e.TimeUtc });
		b.HasIndex(e => new { e.LogonId, e.TimeUtc });
		b.HasIndex(e => new { e.SessionId, e.TimeUtc });
		b.HasIndex(e => new { e.Processed, e.TimeUtc });
		b.HasIndex(e => new { e.ObjectName, e.EventId });
		// Uniqueness applies only to sequences the ingestion worker actually assigned (> 0).
		// The default 0 marks legacy or synthetic rows and is intentionally excluded from the constraint.
		b.HasIndex(e => e.IngestionSequence).IsUnique().HasFilter("\"IngestionSequence\" > 0");
		b.HasIndex(e => new { e.SourceIpBinary, e.TimeUtc });

		b.HasOne(e => e.Address)
			.WithMany()
			.HasForeignKey(e => e.AddressId)
			.OnDelete(DeleteBehavior.SetNull);

		b.HasOne(e => e.SessionRef)
			.WithMany()
			.HasForeignKey(e => e.SessionRefId)
			.OnDelete(DeleteBehavior.SetNull);
	}
}
