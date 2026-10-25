// File:    src/RdpAudit.Core/Data/Configurations/ProcessAlertResponseConfiguration.cs
// Module:  RdpAudit.Core.Data.Configurations
// Purpose: EF Core entity configuration for ProcessAlertResponse - one row per PROCESS_NEW alert
//          describing the automated session-close attempt. AlertId is the primary key so exactly
//          one response state can exist per alert.
// Extends: Microsoft.EntityFrameworkCore.IEntityTypeConfiguration{ProcessAlertResponse}
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using RdpAudit.Core.Models;

namespace RdpAudit.Core.Data.Configurations;

/// <summary>EF Core entity configuration for <see cref="ProcessAlertResponse"/>.</summary>
public sealed class ProcessAlertResponseConfiguration : IEntityTypeConfiguration<ProcessAlertResponse>
{
	public void Configure(EntityTypeBuilder<ProcessAlertResponse> b)
	{
		b.ToTable("ProcessAlertResponses");
		b.HasKey(x => x.AlertId);
		b.Property(x => x.SessionId).IsRequired();
		b.Property(x => x.Status).IsRequired();
		b.Property(x => x.ResultText).HasMaxLength(2048);
		b.Property(x => x.RequestedAtUtc).IsRequired();
		b.Property(x => x.CompletedAtUtc).IsRequired(false);
		b.HasIndex(x => x.Status);
		b.HasIndex(x => x.RequestedAtUtc);
	}
}
