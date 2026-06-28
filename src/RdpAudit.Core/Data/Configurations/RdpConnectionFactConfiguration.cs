// File:    src/RdpAudit.Core/Data/Configurations/RdpConnectionFactConfiguration.cs
// Module:  RdpAudit.Core.Data.Configurations
// Purpose: EF Core entity configuration for RdpConnectionFact — narrow schema with indexes
//          tuned for Remote RDP Clients and Attack Statistics historical lookups.
// Extends: Microsoft.EntityFrameworkCore.IEntityTypeConfiguration{RdpConnectionFact}
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using RdpAudit.Core.Models;

namespace RdpAudit.Core.Data.Configurations;

/// <summary>EF Core entity configuration for <see cref="RdpConnectionFact"/>.</summary>
public sealed class RdpConnectionFactConfiguration : IEntityTypeConfiguration<RdpConnectionFact>
{
	public void Configure(EntityTypeBuilder<RdpConnectionFact> b)
	{
		b.ToTable("RdpConnectionFacts");
		b.HasKey(e => e.Id);
		b.Property(e => e.Id).ValueGeneratedOnAdd();
		b.Property(e => e.Ip).IsRequired().HasMaxLength(45);
		b.Property(e => e.UserName).HasMaxLength(256);
		b.Property(e => e.Domain).HasMaxLength(256);
		b.Property(e => e.LogonId).HasMaxLength(32);
		b.Property(e => e.ObservedEventIds).HasMaxLength(256);
		b.Property(e => e.UserNamesAttempted).HasMaxLength(1024);
		b.Property(e => e.IsActive).HasDefaultValue(false);
		b.Property(e => e.FailedLogons).HasDefaultValue(0);
		b.Property(e => e.SuccessfulLogons).HasDefaultValue(0);

		b.HasIndex(e => new { e.Ip, e.LastSeenUtc });
		b.HasIndex(e => new { e.WtsSessionId, e.UserName });
		b.HasIndex(e => e.LogonId);
		b.HasIndex(e => e.LastSeenUtc);
		b.HasIndex(e => new { e.UserName, e.LastSeenUtc });
	}
}
