// File:    src/RdpAudit.Core/Data/Configurations/RawEventConfiguration.cs
// Module:  RdpAudit.Core.Data.Configurations
// Purpose: EF Core entity configuration for RawEvent.
// Extends: Microsoft.EntityFrameworkCore.IEntityTypeConfiguration{RawEvent}
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

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
