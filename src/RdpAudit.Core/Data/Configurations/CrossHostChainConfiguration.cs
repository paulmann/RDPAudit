// File:    src/RdpAudit.Core/Data/Configurations/CrossHostChainConfiguration.cs
// Module:  RdpAudit.Core.Data.Configurations
// Purpose: EF Core entity configuration for CrossHostChain. The unique per-rule ChainKey
//          constraint makes chain persistence idempotent at the database boundary; the rule
//          index supports the Configurator chain list filtered by rule.
// Extends: Microsoft.EntityFrameworkCore.IEntityTypeConfiguration{CrossHostChain}
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using RdpAudit.Core.Models;

namespace RdpAudit.Core.Data.Configurations;

/// <summary>EF Core entity configuration for <see cref="CrossHostChain"/>.</summary>
public sealed class CrossHostChainConfiguration : IEntityTypeConfiguration<CrossHostChain>
{
	public void Configure(EntityTypeBuilder<CrossHostChain> b)
	{
		b.ToTable("CrossHostChains");
		b.HasKey(e => e.Id);
		b.Property(e => e.Id).ValueGeneratedOnAdd();
		b.Property(e => e.ChainKey).IsRequired().HasMaxLength(64);
		b.Property(e => e.RuleId).IsRequired().HasMaxLength(64);
		b.Property(e => e.NormalizedUserName).HasMaxLength(256);
		b.Property(e => e.FirstSeenUtc).IsRequired();
		b.Property(e => e.LastSeenUtc).IsRequired();
		b.Property(e => e.Score).IsRequired();
		b.Property(e => e.FailedAttemptCount).IsRequired();
		b.Property(e => e.DetectedUtc).IsRequired();
		b.Property(e => e.AlertId);
		b.Property(e => e.IsAcknowledged).IsRequired();

		// Retention prunes old alerts independently of chains; the chain must survive, hence
		// SetNull rather than Cascade/Restrict (the chain row keeps its history and ack state).
		b.HasOne(e => e.Alert)
			.WithMany()
			.HasForeignKey(e => e.AlertId)
			.OnDelete(DeleteBehavior.SetNull);

		// A chain is identified by (rule, key): the engine refreshes a row instead of inserting.
		b.HasIndex(e => new { e.RuleId, e.ChainKey }).IsUnique();
		b.HasIndex(e => new { e.RuleId, e.LastSeenUtc });
		b.HasIndex(e => e.AlertId);
	}
}
