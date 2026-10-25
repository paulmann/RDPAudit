// File:    src/RdpAudit.Core/Data/Configurations/CrossHostHostStateConfiguration.cs
// Module:  RdpAudit.Core.Data.Configurations
// Purpose: EF Core entity configuration for CrossHostHostState. One state row per configured
//          agent host, with a unique HostName index and a last-polled index for health scans.
// Extends: Microsoft.EntityFrameworkCore.IEntityTypeConfiguration{CrossHostHostState}
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using RdpAudit.Core.Models;

namespace RdpAudit.Core.Data.Configurations;

/// <summary>EF Core entity configuration for <see cref="CrossHostHostState"/>.</summary>
public sealed class CrossHostHostStateConfiguration : IEntityTypeConfiguration<CrossHostHostState>
{
	public void Configure(EntityTypeBuilder<CrossHostHostState> b)
	{
		b.ToTable("CrossHostHostStates");
		b.HasKey(e => e.Id);
		b.Property(e => e.Id).ValueGeneratedOnAdd();
		b.Property(e => e.HostName).IsRequired().HasMaxLength(256);
		b.Property(e => e.Availability).HasConversion<int>().IsRequired();
		b.Property(e => e.LastError).HasMaxLength(1024);
		b.Property(e => e.LastPolledUtc).IsRequired();

		b.HasIndex(e => e.HostName).IsUnique();
		b.HasIndex(e => e.LastPolledUtc);
	}
}
