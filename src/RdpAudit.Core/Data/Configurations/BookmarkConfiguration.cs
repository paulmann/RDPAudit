// File:    src/RdpAudit.Core/Data/Configurations/BookmarkConfiguration.cs
// Module:  RdpAudit.Core.Data.Configurations
// Purpose: EF Core entity configuration for Bookmark.
// Extends: Microsoft.EntityFrameworkCore.IEntityTypeConfiguration{Bookmark}
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using RdpAudit.Core.Models;

namespace RdpAudit.Core.Data.Configurations;

/// <summary>EF Core entity configuration for <see cref="Bookmark"/>.</summary>
public sealed class BookmarkConfiguration : IEntityTypeConfiguration<Bookmark>
{
	public void Configure(EntityTypeBuilder<Bookmark> b)
	{
		b.ToTable("Bookmarks");
		b.HasKey(x => x.Channel);
		b.Property(x => x.Channel).HasMaxLength(256);
		b.Property(x => x.BookmarkXml).IsRequired().HasMaxLength(8192);
	}
}
