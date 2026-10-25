/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : EventDeletionLedgerConfiguration.cs
// Project: RdpAudit.Core (RdpAudit.Core.Data.Configurations)
// Purpose: Maps the append-only evidence-deletion ledger to its SQLite schema and indexes.
// Depends: EventDeletionLedger, IEntityTypeConfiguration
// Extends: Mirror any appended EventDeletionLedger property here before generating a migration.

using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using RdpAudit.Core.Models;

namespace RdpAudit.Core.Data.Configurations;

/// <summary>EF Core entity configuration for <see cref="EventDeletionLedger"/>.</summary>
public sealed class EventDeletionLedgerConfiguration : IEntityTypeConfiguration<EventDeletionLedger>
{
	/// <inheritdoc />
	public void Configure(EntityTypeBuilder<EventDeletionLedger> b)
	{
		b.ToTable("EventDeletionLedger");
		b.HasKey(e => e.Id);
		b.Property(e => e.Id).ValueGeneratedOnAdd();
		b.Property(e => e.EventCode).IsRequired();
		b.Property(e => e.Scope)
			.HasConversion<int>()
			.IsRequired();
		b.Property(e => e.IpBinary16).HasMaxLength(16).IsFixedLength().IsRequired(false);
		b.Property(e => e.WindowStartUtc).IsRequired();
		b.Property(e => e.WindowEndUtc).IsRequired();
		b.Property(e => e.RowsDeleted).IsRequired();
		b.Property(e => e.Trigger)
			.HasConversion<int>()
			.IsRequired();
		b.Property(e => e.RuleVersion).IsRequired();
		b.Property(e => e.Reason).IsRequired().HasMaxLength(512);
		b.Property(e => e.InitiatedBy).IsRequired().HasMaxLength(256);
		b.Property(e => e.CreatedUtc).IsRequired();

		// Hash-chain link (Stage 18). Nullable on purpose: rows written before the chain existed keep
		// null in both columns, and the verifier reports them as unverifiable rather than as a break.
		b.Property(e => e.PreviousHash).IsRequired(false).HasMaxLength(64);
		b.Property(e => e.EntryHash).IsRequired(false).HasMaxLength(64);

		// "What was deleted for this code, and when was it recorded" - the per-code ledger view and
		// the timeline-gap lookup.
		b.HasIndex(e => new { e.EventCode, e.CreatedUtc });

		// "What did the most recent passes remove" - the append-order scan used by the Ledger tab and
		// by operator diagnostics without a code filter.
		b.HasIndex(e => e.CreatedUtc);

		// "What was deleted for this address" - subject-oriented review and the per-IP gap lookup.
		b.HasIndex(e => e.IpBinary16);
	}
}
