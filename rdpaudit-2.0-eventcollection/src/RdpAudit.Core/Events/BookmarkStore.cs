/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : BookmarkStore.cs
// Project: RdpAudit.Core (RdpAudit.Core.Events)
// Purpose: Thread-safe persisted store of EventLogWatcher bookmark XML strings keyed by channel.
//          v2.0 adds raw-SQLite UPSERT that shares an external SqliteTransaction with the event
//          batch, so bookmarks and their events cross a single durability boundary. The legacy EF
//          API (SaveBookmarkAsync, DeleteBookmarkAsync, LoadAllAsync, GetBookmarkXml) is preserved
//          bit-for-bit so existing callers keep working during the migration.
// Depends: AuditDbContext, Bookmark, SqliteConnection, SqliteTransaction, IDbContextFactory<T>
// Extends: When adding a new bookmark-adjacent artefact (e.g. shard-cursor watermark) that must
//          participate in the same commit, add a peer UPSERT method that takes the same
//          (SqliteConnection, SqliteTransaction) pair and follow the identical cache-update
//          ordering: UpdateCache(...) BEFORE tx.Begin, MarkCommitted(...) AFTER tx.Commit.

using System.Globalization;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using RdpAudit.Core.Data;
using RdpAudit.Core.Models;

namespace RdpAudit.Core.Events;

/// <summary>
/// Thread-safe persisted store of EventLogWatcher bookmark XML strings keyed by channel.
/// </summary>
/// <remarks>
/// <para>
/// Read path: in-memory cache, protected by <c>_gate</c>. Reads never touch the database.
/// </para>
/// <para>
/// Legacy write path (<see cref="SaveBookmarkAsync"/>, <see cref="DeleteBookmarkAsync"/>):
/// mutates the cache under the gate and then commits its own EF transaction. Suitable for
/// background flush loops and administrative deletes that are not correlated with an event
/// batch. Kept intact for backwards compatibility with <c>SecurityBackfillWorker</c> and the
/// legacy <c>PeriodicTimer</c> flush loop inside <c>EventCollectorWorker</c>.
/// </para>
/// <para>
/// Unified-commit write path (v2.0, <see cref="SaveInSameTransactionAsync"/>): the caller opens
/// a <see cref="SqliteConnection"/>, begins a <see cref="SqliteTransaction"/>, writes the event
/// batch inside it, and then calls <see cref="SaveInSameTransactionAsync"/> for each channel
/// whose bookmark advanced. The bookmark UPSERT and the event INSERTs cross the same
/// <c>COMMIT</c>, so a crash between the two is impossible: either both are durable or neither
/// is. The cache is updated separately via <see cref="UpdateCache"/> BEFORE the transaction
/// begins, so concurrent readers see the freshest bookmark immediately; if the transaction
/// rolls back, <see cref="RollbackCache"/> restores the previously committed value.
/// </para>
/// </remarks>
public sealed class BookmarkStore
{
	// ── Fields & DI ──────────────────────────────────────────────────────────────

	private readonly IDbContextFactory<AuditDbContext> _factory;
	private readonly ILogger<BookmarkStore> _logger;
	private readonly Dictionary<string, string> _cache = new(StringComparer.OrdinalIgnoreCase);
	private readonly object _gate = new();

	// ── Construction ─────────────────────────────────────────────────────────────

	public BookmarkStore(IDbContextFactory<AuditDbContext> factory, ILogger<BookmarkStore> logger)
	{
		_factory = factory;
		_logger = logger;
	}

	// ── Legacy Public API (preserved bit-for-bit) ────────────────────────────────

	/// <summary>Loads every persisted bookmark from the database into the in-memory cache.</summary>
	/// <remarks>
	/// Call once during service startup after the database is migrated. The cache is cleared
	/// before reload, so this method is safe to call after a bookmark-related corruption event.
	/// </remarks>
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

	/// <summary>Returns the cached bookmark XML for <paramref name="channel"/>, or <c>null</c> if none is cached.</summary>
	public string? GetBookmarkXml(string channel)
	{
		lock (_gate)
		{
			return _cache.TryGetValue(channel, out string? xml) ? xml : null;
		}
	}

	/// <summary>
	/// Legacy self-contained save. Updates the cache and commits its own EF transaction. Callers
	/// that need bookmark durability tied to an event batch MUST use
	/// <see cref="SaveInSameTransactionAsync"/> instead.
	/// </summary>
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

	// ── v2.0 Unified-Commit API ──────────────────────────────────────────────────

	/// <summary>
	/// Optimistically updates the in-memory cache for <paramref name="channel"/>. Call this
	/// immediately BEFORE beginning the <see cref="SqliteTransaction"/> that will
	/// <see cref="SaveInSameTransactionAsync">persist the bookmark</see>. Returns the previously
	/// cached value (or <c>null</c>), which the caller should keep and pass to
	/// <see cref="RollbackCache"/> if the transaction is rolled back.
	/// </summary>
	/// <remarks>
	/// Rationale: readers (e.g. watcher-arming code paths) must never observe a stale bookmark
	/// when a fresher one is already committed to disk. Updating the cache before the commit
	/// guarantees that ordering; the small window in which the cache is ahead of the database
	/// is closed either by <see cref="MarkCommitted"/> (on success — no-op today, reserved for
	/// future observability) or <see cref="RollbackCache"/> (on failure, which restores the
	/// previously cached value).
	/// </remarks>
	public string? UpdateCache(string channel, string xml)
	{
		if (channel is null) throw new ArgumentNullException(nameof(channel));
		if (xml is null) throw new ArgumentNullException(nameof(xml));

		lock (_gate)
		{
			_cache.TryGetValue(channel, out string? previous);
			_cache[channel] = xml;
			return previous;
		}
	}

	/// <summary>
	/// Restores the cache entry for <paramref name="channel"/> to <paramref name="previousXml"/>
	/// after a rolled-back unified commit. If <paramref name="previousXml"/> is <c>null</c>, the
	/// cache entry is removed entirely (there was no prior value at the time of
	/// <see cref="UpdateCache"/>).
	/// </summary>
	public void RollbackCache(string channel, string? previousXml)
	{
		if (channel is null) throw new ArgumentNullException(nameof(channel));

		lock (_gate)
		{
			if (previousXml is null)
			{
				_cache.Remove(channel);
			}
			else
			{
				_cache[channel] = previousXml;
			}
		}
	}

	/// <summary>
	/// Marker for a successfully committed unified transaction. Kept as an explicit hook so that
	/// future observability (metrics, structured audit trail) can distinguish committed
	/// bookmarks from optimistically cached ones without changing the cache-update contract.
	/// </summary>
	public void MarkCommitted(string channel)
	{
		// Reserved for future metrics/audit integration. Intentionally a no-op today; the cache
		// is already correct because UpdateCache ran before tx.Begin.
		_ = channel;
	}

	/// <summary>
	/// UPSERTs <paramref name="xml"/> into the <c>Bookmarks</c> table through
	/// <paramref name="conn"/> and <paramref name="tx"/> without opening a new connection or
	/// starting a new transaction. The caller keeps ownership of both objects; this method does
	/// not commit, roll back, or dispose them, and does not touch the in-memory cache.
	/// </summary>
	/// <remarks>
	/// <para>
	/// The UPSERT is expressed as a single <c>INSERT ... ON CONFLICT DO UPDATE</c> statement so
	/// that the caller pays exactly one round-trip regardless of whether the row already
	/// exists. The <c>UpdatedUtc</c> column is written as an ISO 8601 round-trip
	/// string (<c>"o"</c> format) to remain byte-identical to what
	/// <c>Microsoft.EntityFrameworkCore.Sqlite</c> emits, so legacy reads through
	/// <see cref="AuditDbContext"/> keep working.
	/// </para>
	/// <para>
	/// Cache ordering (mandatory): call <see cref="UpdateCache"/> BEFORE
	/// <paramref name="tx"/>'s enclosing <c>BeginTransaction</c> and
	/// <see cref="RollbackCache"/> AFTER <paramref name="tx"/>'s <c>Rollback</c> on failure.
	/// </para>
	/// </remarks>
	public async Task SaveInSameTransactionAsync(
		SqliteConnection conn,
		SqliteTransaction tx,
		string channel,
		string xml,
		CancellationToken ct = default)
	{
		if (conn is null) throw new ArgumentNullException(nameof(conn));
		if (tx is null) throw new ArgumentNullException(nameof(tx));
		if (channel is null) throw new ArgumentNullException(nameof(channel));
		if (xml is null) throw new ArgumentNullException(nameof(xml));

		if (conn.State != System.Data.ConnectionState.Open)
		{
			throw new InvalidOperationException("SqliteConnection must be Open before SaveInSameTransactionAsync.");
		}

		if (!object.ReferenceEquals(tx.Connection, conn))
		{
			throw new ArgumentException("SqliteTransaction is not bound to the supplied SqliteConnection.", nameof(tx));
		}

		string updatedUtc = DateTime.UtcNow.ToString("o", CultureInfo.InvariantCulture);

		await using SqliteCommand cmd = conn.CreateCommand();
		cmd.Transaction = tx;
		cmd.CommandText =
			"INSERT INTO \"Bookmarks\" (\"Channel\", \"BookmarkXml\", \"UpdatedUtc\") " +
			"VALUES ($channel, $xml, $updated) " +
			"ON CONFLICT(\"Channel\") DO UPDATE SET " +
			"\"BookmarkXml\" = excluded.\"BookmarkXml\", " +
			"\"UpdatedUtc\"  = excluded.\"UpdatedUtc\";";
		cmd.Parameters.Add("$channel", SqliteType.Text).Value = channel;
		cmd.Parameters.Add("$xml", SqliteType.Text).Value = xml;
		cmd.Parameters.Add("$updated", SqliteType.Text).Value = updatedUtc;

		await cmd.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
	}

	/// <summary>
	/// Batched form of <see cref="SaveInSameTransactionAsync"/>. Every bookmark in
	/// <paramref name="bookmarks"/> is UPSERTed against the shared connection/transaction pair
	/// with a single prepared <see cref="SqliteCommand"/>, so the whole batch pays only one
	/// round-trip per row plus one prepare. Cache ordering is the caller's responsibility (see
	/// <see cref="SaveInSameTransactionAsync"/>).
	/// </summary>
	public async Task SaveBatchInSameTransactionAsync(
		SqliteConnection conn,
		SqliteTransaction tx,
		IReadOnlyDictionary<string, string> bookmarks,
		CancellationToken ct = default)
	{
		if (conn is null) throw new ArgumentNullException(nameof(conn));
		if (tx is null) throw new ArgumentNullException(nameof(tx));
		if (bookmarks is null) throw new ArgumentNullException(nameof(bookmarks));
		if (bookmarks.Count == 0) return;

		if (conn.State != System.Data.ConnectionState.Open)
		{
			throw new InvalidOperationException("SqliteConnection must be Open before SaveBatchInSameTransactionAsync.");
		}

		if (!object.ReferenceEquals(tx.Connection, conn))
		{
			throw new ArgumentException("SqliteTransaction is not bound to the supplied SqliteConnection.", nameof(tx));
		}

		await using SqliteCommand cmd = conn.CreateCommand();
		cmd.Transaction = tx;
		cmd.CommandText =
			"INSERT INTO \"Bookmarks\" (\"Channel\", \"BookmarkXml\", \"UpdatedUtc\") " +
			"VALUES ($channel, $xml, $updated) " +
			"ON CONFLICT(\"Channel\") DO UPDATE SET " +
			"\"BookmarkXml\" = excluded.\"BookmarkXml\", " +
			"\"UpdatedUtc\"  = excluded.\"UpdatedUtc\";";

		SqliteParameter pChannel = cmd.Parameters.Add("$channel", SqliteType.Text);
		SqliteParameter pXml = cmd.Parameters.Add("$xml", SqliteType.Text);
		SqliteParameter pUpdated = cmd.Parameters.Add("$updated", SqliteType.Text);
		cmd.Prepare();

		string updatedUtc = DateTime.UtcNow.ToString("o", CultureInfo.InvariantCulture);

		foreach (KeyValuePair<string, string> entry in bookmarks)
		{
			ct.ThrowIfCancellationRequested();

			pChannel.Value = entry.Key;
			pXml.Value = entry.Value;
			pUpdated.Value = updatedUtc;

			await cmd.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
		}
	}
}
