// File:    src/RdpAudit.Core/Data/Configurations/SessionIpCorrelationConfiguration.cs
// Module:  RdpAudit.Core.Data.Configurations
// Purpose: EF Core entity configuration for SessionIpCorrelation.
// Extends: Microsoft.EntityFrameworkCore.IEntityTypeConfiguration{SessionIpCorrelation}
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using RdpAudit.Core.Models;

namespace RdpAudit.Core.Data.Configurations;

/// <summary>EF Core entity configuration for <see cref="SessionIpCorrelation"/>.</summary>
public sealed class SessionIpCorrelationConfiguration : IEntityTypeConfiguration<SessionIpCorrelation>
{
	public void Configure(EntityTypeBuilder<SessionIpCorrelation> b)
	{
		b.ToTable("SessionIpCorrelations");
		b.HasKey(e => e.Id);
		b.Property(e => e.Id).ValueGeneratedOnAdd();
		b.Property(e => e.LogonId).HasMaxLength(32);
		b.Property(e => e.UserName).HasMaxLength(256);
		b.Property(e => e.Domain).HasMaxLength(256);
		b.Property(e => e.Ip).IsRequired().HasMaxLength(45);
		b.Property(e => e.ObservedEventIds).HasMaxLength(128);
		b.Property(e => e.IsDirectObservation).HasDefaultValue(false);

		b.HasIndex(e => e.LogonId);
		b.HasIndex(e => new { e.WtsSessionId, e.UserName });
		b.HasIndex(e => new { e.Ip, e.LastSeenUtc });
		b.HasIndex(e => new { e.UserName, e.LastSeenUtc });
		b.HasIndex(e => e.LastSeenUtc);
	}
}
