// File:    src/RdpAudit.Core/Data/Configurations/AuthAttemptFactConfiguration.cs
// Module:  RdpAudit.Core.Data.Configurations
// Purpose: EF Core entity configuration for AuthAttemptFact. Indexes match the v3 query patterns
//          (per-IP and per-user counter aggregation, correlation watchdog scans).
// Extends: Microsoft.EntityFrameworkCore.IEntityTypeConfiguration{AuthAttemptFact}
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using RdpAudit.Core.Models;

namespace RdpAudit.Core.Data.Configurations;

/// <summary>EF Core entity configuration for <see cref="AuthAttemptFact"/>.</summary>
public sealed class AuthAttemptFactConfiguration : IEntityTypeConfiguration<AuthAttemptFact>
{
	public void Configure(EntityTypeBuilder<AuthAttemptFact> b)
	{
		b.ToTable("AuthAttemptFacts");
		b.HasKey(e => e.Id);
		b.Property(e => e.Id).ValueGeneratedOnAdd();
		b.Property(e => e.TimeUtc).IsRequired();
		b.Property(e => e.SourceIp).HasMaxLength(45);
		b.Property(e => e.TargetUser).HasMaxLength(256);
		b.Property(e => e.TargetDomain).HasMaxLength(256);
		b.Property(e => e.NormalizedUserName).HasMaxLength(256);
		b.Property(e => e.WorkstationName).HasMaxLength(256);
		b.Property(e => e.AuthPackage).HasMaxLength(64);
		b.Property(e => e.LogonId).HasMaxLength(32);
		b.Property(e => e.Status).HasMaxLength(64);
		b.Property(e => e.SubStatus).HasMaxLength(64);
		b.Property(e => e.SubStatusMeaning).HasMaxLength(128);
		b.Property(e => e.EvidenceChannel).HasMaxLength(256);
		b.Property(e => e.EnrichmentSource).HasMaxLength(64);
		b.Property(e => e.EnrichmentConfidence).HasMaxLength(16);
		b.Property(e => e.Outcome)
			.HasConversion<int>()
			.IsRequired();
		b.Property(e => e.IpFromCorrelation).HasDefaultValue(false);
		b.Property(e => e.NeedsCorrelation).HasDefaultValue(false);
		b.Property(e => e.IngestedUtc).IsRequired();

		// v3 query indexes: aggregate-by-IP, aggregate-by-user, correlation watchdog.
		b.HasIndex(e => new { e.SourceIp, e.TimeUtc });
		b.HasIndex(e => new { e.NormalizedUserName, e.TimeUtc });
		b.HasIndex(e => new { e.Outcome, e.TimeUtc });
		b.HasIndex(e => new { e.NeedsCorrelation, e.TimeUtc });
		b.HasIndex(e => e.EvidenceRawEventId).IsUnique(false);
	}
}
