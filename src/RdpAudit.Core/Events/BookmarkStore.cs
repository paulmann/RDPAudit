// File:    src/RdpAudit.Core/Events/BookmarkStore.cs
// Module:  RdpAudit.Core.Events
// Purpose: Thread-safe persisted store of EventLogWatcher bookmark XML strings keyed by channel.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using RdpAudit.Core.Data;
using RdpAudit.Core.Models;

namespace RdpAudit.Core.Events;

/// <summary>
/// Thread-safe persisted store of EventLogWatcher bookmark XML strings keyed by channel.
/// Reads come from the in-memory cache; writes are flushed both to memory and to the database.
/// </summary>
public sealed class BookmarkStore
{
	private readonly IDbContextFactory<AuditDbContext> _factory;
	private readonly ILogger<BookmarkStore> _logger;
	private readonly Dictionary<string, string> _cache = new(StringComparer.OrdinalIgnoreCase);
	private readonly object _gate = new();

	public BookmarkStore(IDbContextFactory<AuditDbContext> factory, ILogger<BookmarkStore> logger)
	{
		_factory = factory;
		_logger = logger;
	}

	public async Task LoadAllAsync(CancellationToken ct = default)
	{
		await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);
		List<Bookmark> rows = await db.Bookmarks.AsNoTracking().ToListAsync(ct).ConfigureAwait(false);
		lock (_gate)
		{
			_cache.Clear();
			foreach (Bookmark row in rows)
			{
				_cache[row.Channel] = row.BookmarkXml;
			}
		}

		_logger.LogInformation("Loaded {Count} channel bookmarks", rows.Count);
	}

	public string? GetBookmarkXml(string channel)
	{
		lock (_gate)
		{
			return _cache.TryGetValue(channel, out string? xml) ? xml : null;
		}
	}

	public async Task SaveBookmarkAsync(string channel, string xml, CancellationToken ct = default)
	{
		lock (_gate)
		{
			_cache[channel] = xml;
		}

		await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);
		Bookmark? row = await db.Bookmarks.FirstOrDefaultAsync(b => b.Channel == channel, ct).ConfigureAwait(false);
		if (row is null)
		{
			row = new Bookmark { Channel = channel, BookmarkXml = xml, UpdatedUtc = DateTime.UtcNow };
			db.Bookmarks.Add(row);
		}
		else
		{
			row.BookmarkXml = xml;
			row.UpdatedUtc = DateTime.UtcNow;
		}

		await db.SaveChangesAsync(ct).ConfigureAwait(false);
	}

	/// <summary>
	/// Deletes the persisted bookmark for <paramref name="channel"/> from the in-memory cache and
	/// the database. Used to recover from a stale/invalid bookmark that bricks watcher arming.
	/// </summary>
	public async Task DeleteBookmarkAsync(string channel, CancellationToken ct = default)
	{
		lock (_gate)
		{
			_cache.Remove(channel);
		}

		await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);
		Bookmark? row = await db.Bookmarks.FirstOrDefaultAsync(b => b.Channel == channel, ct).ConfigureAwait(false);
		if (row is not null)
		{
			db.Bookmarks.Remove(row);
			await db.SaveChangesAsync(ct).ConfigureAwait(false);
		}
	}
}
