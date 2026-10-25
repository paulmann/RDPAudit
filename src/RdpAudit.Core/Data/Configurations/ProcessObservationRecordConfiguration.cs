// File:    src/RdpAudit.Core/Data/Configurations/ProcessObservationRecordConfiguration.cs
// Module:  RdpAudit.Core.Data.Configurations
// Purpose: EF Core entity configuration for ProcessObservationRecord - the bounded append-only
//          journal of process observations. Backs diagnostics and the Configurator's
//          process-monitoring alert list.
// Extends: Microsoft.EntityFrameworkCore.IEntityTypeConfiguration{ProcessObservationRecord}
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using RdpAudit.Core.Models;

namespace RdpAudit.Core.Data.Configurations;

/// <summary>EF Core entity configuration for <see cref="ProcessObservationRecord"/>.</summary>
public sealed class ProcessObservationRecordConfiguration : IEntityTypeConfiguration<ProcessObservationRecord>
{
	public void Configure(EntityTypeBuilder<ProcessObservationRecord> b)
	{
		b.ToTable("ProcessObservations");
		b.HasKey(x => x.Id);
		b.Property(x => x.ObservedUtc).IsRequired();
		b.Property(x => x.ProcessName).IsRequired().HasMaxLength(260);
		b.Property(x => x.UserName).HasMaxLength(256);
		b.Property(x => x.RawEventId).IsRequired();
		b.Property(x => x.Alerted).IsRequired();
		b.Property(x => x.IsForced).IsRequired();
		b.HasIndex(x => x.ObservedUtc);
		b.HasIndex(x => x.ProcessName);
	}
}
