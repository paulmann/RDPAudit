// File:    src/RdpAudit.Core/Data/Configurations/SessionConfiguration.cs
// Module:  RdpAudit.Core.Data.Configurations
// Purpose: EF Core entity configuration for Session.
// Extends: Microsoft.EntityFrameworkCore.IEntityTypeConfiguration{Session}
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using RdpAudit.Core.Models;

namespace RdpAudit.Core.Data.Configurations;

/// <summary>EF Core entity configuration for <see cref="Session"/>.</summary>
public sealed class SessionConfiguration : IEntityTypeConfiguration<Session>
{
	public void Configure(EntityTypeBuilder<Session> b)
	{
		b.ToTable("Sessions");
		b.HasKey(s => s.Id);
		b.Property(s => s.Id).ValueGeneratedOnAdd();
		b.Property(s => s.UserName).HasMaxLength(256);
		b.Property(s => s.Domain).HasMaxLength(256);
		b.Property(s => s.SourceIp).HasMaxLength(45);
		b.Property(s => s.LogonId).HasMaxLength(32);
		b.Property(s => s.Flags).HasMaxLength(256);
		b.HasIndex(s => new { s.WtsSessionId, s.ConnectUtc });
		b.HasIndex(s => new { s.UserName, s.ConnectUtc });
		b.HasIndex(s => s.Status);
	}
}
