// File:    src/RdpAudit.Core/Data/Configurations/ActiveBlockConfiguration.cs
// Module:  RdpAudit.Core.Data.Configurations
// Purpose: EF Core entity configuration for ActiveBlock.
// Extends: Microsoft.EntityFrameworkCore.IEntityTypeConfiguration{ActiveBlock}
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using RdpAudit.Core.Models;

namespace RdpAudit.Core.Data.Configurations;

/// <summary>EF Core entity configuration for <see cref="ActiveBlock"/>.</summary>
public sealed class ActiveBlockConfiguration : IEntityTypeConfiguration<ActiveBlock>
{
	public void Configure(EntityTypeBuilder<ActiveBlock> b)
	{
		b.ToTable("ActiveBlocks");
		b.HasKey(x => x.Id);
		b.Property(x => x.Id).ValueGeneratedOnAdd();
		b.Property(x => x.Ip).IsRequired().HasMaxLength(45);
		b.Property(x => x.Provider).HasConversion<int>();
		b.Property(x => x.RuleHandle).HasMaxLength(256);
		b.Property(x => x.Reason).IsRequired().HasMaxLength(1024);
		b.Property(x => x.Status).HasConversion<int>();
		b.Property(x => x.LastError).HasMaxLength(2048);
		b.Property(x => x.BackendCommand).HasMaxLength(2048);
		b.Property(x => x.BackendStdoutPreview).HasMaxLength(1024);
		b.Property(x => x.BackendStderrPreview).HasMaxLength(1024);
		b.Property(x => x.ScannerBackend).HasMaxLength(64);
		b.Property(x => x.VerifierReason).HasMaxLength(512);
		b.HasIndex(x => new { x.Provider, x.Ip }).IsUnique();
		b.HasIndex(x => x.ExpiresUtc);
		b.HasIndex(x => x.Status);
		b.HasIndex(x => new { x.Provider, x.RuleHandle });
	}
}
