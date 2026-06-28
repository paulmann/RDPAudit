// File:    src/RdpAudit.Core/Models/Bookmark.cs
// Module:  RdpAudit.Core.Models
// Purpose: Persisted EventLogWatcher bookmark for a single channel.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

namespace RdpAudit.Core.Models;

/// <summary>Persisted EventLogWatcher bookmark for a single channel.</summary>
public sealed class Bookmark
{
	public string Channel { get; set; } = string.Empty;

	public string BookmarkXml { get; set; } = string.Empty;

	public DateTime UpdatedUtc { get; set; }
}
