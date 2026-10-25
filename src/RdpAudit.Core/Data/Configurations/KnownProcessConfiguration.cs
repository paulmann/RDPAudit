// File:    src/RdpAudit.Core/Data/Configurations/KnownProcessConfiguration.cs
// Module:  RdpAudit.Core.Data.Configurations
// Purpose: EF Core entity configuration for KnownProcess - the persistent process-identity
//          baseline. The unique index (ProcessName, UserCategory, UserName) is the lookup key
//          NewProcessRule and KnownProcessStore upsert against; SQLite unique-index semantics
//          match the project's other bespoke-key tables.
// Extends: Microsoft.EntityFrameworkCore.IEntityTypeConfiguration{KnownProcess}
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using RdpAudit.Core.Models;

namespace RdpAudit.Core.Data.Configurations;

/// <summary>EF Core entity configuration for <see cref="KnownProcess"/>.</summary>
public sealed class KnownProcessConfiguration : IEntityTypeConfiguration<KnownProcess>
{
	public void Configure(EntityTypeBuilder<KnownProcess> b)
	{
		b.ToTable("KnownProcesses");
		b.HasKey(x => x.Id);
		b.Property(x => x.ProcessName).IsRequired().HasMaxLength(260);
		b.Property(x => x.UserCategory).IsRequired();
		b.Property(x => x.UserName).IsRequired().HasMaxLength(256);
		b.Property(x => x.FirstObservedUtc).IsRequired();
		b.Property(x => x.LastObservedUtc).IsRequired();
		b.Property(x => x.ObservationCount).IsRequired();
		b.Property(x => x.FirstObservedProcessId).IsRequired();
		b.HasIndex(x => new { x.ProcessName, x.UserCategory, x.UserName }).IsUnique();
		b.HasIndex(p => p.LastObservedUtc);
	}
}
