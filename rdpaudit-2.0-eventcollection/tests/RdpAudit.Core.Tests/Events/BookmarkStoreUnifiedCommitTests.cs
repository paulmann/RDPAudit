/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : BookmarkStoreUnifiedCommitTests.cs
// Project: RdpAudit.Core.Tests (RdpAudit.Core.Tests.Events)
// Purpose: Contract tests for BookmarkStore.SaveInSameTransactionAsync and its cache-update
//          helpers (UpdateCache, RollbackCache, MarkCommitted). Pins the durability boundary
//          shared between the event batch and the bookmark UPSERT: on commit, both are visible;
//          on rollback, neither is. Also verifies that legacy EF API keeps working alongside
//          the new raw-SQLite path.
// Depends: xUnit, Microsoft.Data.Sqlite, Microsoft.EntityFrameworkCore, AuditDbContext,
//          BookmarkStore, TestDbContextFactory (test-local)
// Extends: When adding a peer artefact that participates in the unified commit (e.g. shard
//          watermark), add an analogous test class that exercises the same rollback-vs-commit
//          matrix so the durability contract remains explicit.

using System.Collections.Concurrent;
using System.Globalization;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.Extensions.Logging.Abstractions;
using RdpAudit.Core.Data;
using RdpAudit.Core.Events;
using RdpAudit.Core.Models;
using Xunit;

namespace RdpAudit.Core.Tests.Events;

public sealed class BookmarkStoreUnifiedCommitTests : IAsyncLifetime
{
	// ── Test fixture: a single shared-cache in-memory SQLite database per test class ────
	// The fixture keeps ONE keep-alive connection open for the entirety of the test so the
	// in-memory database survives across the ephemeral DbContext instances created by the
	// pooled factory. Each test creates its own bookmarks by unique channel name to avoid
	// cross-test collisions without needing an EnsureDeleted cycle.

	private const string ConnectionString = "Data Source=file:bookmark-store-tests?mode=memory&cache=shared";

	private SqliteConnection _keepAlive = null!;
	private TestDbContextFactory _factory = null!;
	private BookmarkStore _store = null!;

	public async Task InitializeAsync()
	{
		_keepAlive = new SqliteConnection(ConnectionString);
		await _keepAlive.OpenAsync().ConfigureAwait(false);

		_factory = new TestDbContextFactory(ConnectionString);
		await using AuditDbContext bootstrap = _factory.CreateDbContext();
		await bootstrap.Database.EnsureCreatedAsync().ConfigureAwait(false);

		_store = new BookmarkStore(_factory, NullLogger<BookmarkStore>.Instance);
	}

	public async Task DisposeAsync()
	{
		await _keepAlive.DisposeAsync().ConfigureAwait(false);
	}

	// ── Helpers ─────────────────────────────────────────────────────────────────

	private async Task<SqliteConnection> OpenSharedConnectionAsync()
	{
		SqliteConnection conn = new(ConnectionString);
		await conn.OpenAsync().ConfigureAwait(false);
		return conn;
	}

	private async Task<(string? xml, DateTime? updatedUtc)> ReadBookmarkDirectAsync(string channel)
	{
		await using SqliteConnection conn = await OpenSharedConnectionAsync().ConfigureAwait(false);
		await using SqliteCommand cmd = conn.CreateCommand();
		cmd.CommandText = "SELECT \"BookmarkXml\", \"UpdatedUtc\" FROM \"Bookmarks\" WHERE \"Channel\" = $c LIMIT 1;";
		cmd.Parameters.Add("$c", SqliteType.Text).Value = channel;

		await using SqliteDataReader reader = await cmd.ExecuteReaderAsync().ConfigureAwait(false);
		if (!await reader.ReadAsync().ConfigureAwait(false))
		{
			return (null, null);
		}

		string xml = reader.GetString(0);
		string updatedRaw = reader.GetString(1);
		DateTime updated = DateTime.Parse(updatedRaw, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind);
		return (xml, updated);
	}

	private static SqliteCommand InsertDummyRawEventCommand(SqliteConnection conn, SqliteTransaction tx, string channel)
	{
		SqliteCommand cmd = conn.CreateCommand();
		cmd.Transaction = tx;
		// Minimal INSERT into the RawEvents table shipped by AuditDbContext.EnsureCreated so we
		// can prove the bookmark and the event share the same COMMIT. Column list is intentionally
		// narrow: only NOT NULL columns without server-side defaults are populated. Every other
		// column is either nullable or has a schema-provided default (Processed=false,
		// SourceIpDerived=false, SourceIpUnresolved=false).
		cmd.CommandText =
			"INSERT INTO \"RawEvents\" (\"Channel\", \"EventId\", \"TimeUtc\", \"Processed\") " +
			"VALUES ($channel, 0, $ts, 0);";
		cmd.Parameters.Add("$channel", SqliteType.Text).Value = channel;
		cmd.Parameters.Add("$ts", SqliteType.Text).Value =
			DateTime.UtcNow.ToString("o", CultureInfo.InvariantCulture);
		return cmd;
	}

	// ── Tests: happy path ───────────────────────────────────────────────────────

	[Fact]
	public async Task SaveInSameTransactionAsync_PersistsBookmarkOnCommit()
	{
		const string channel = "Ch/Commit1";
		const string xml = "<BookmarkList><Bookmark Channel='c1' RecordId='42'/></BookmarkList>";

		await using SqliteConnection conn = await OpenSharedConnectionAsync().ConfigureAwait(false);
		await using SqliteTransaction tx = (SqliteTransaction)await conn.BeginTransactionAsync().ConfigureAwait(false);

		_store.UpdateCache(channel, xml);
		await _store.SaveInSameTransactionAsync(conn, tx, channel, xml).ConfigureAwait(false);
		await tx.CommitAsync().ConfigureAwait(false);
		_store.MarkCommitted(channel);

		(string? persisted, DateTime? updated) = await ReadBookmarkDirectAsync(channel).ConfigureAwait(false);
		Assert.Equal(xml, persisted);
		Assert.NotNull(updated);
		Assert.Equal(xml, _store.GetBookmarkXml(channel));
	}

	[Fact]
	public async Task SaveInSameTransactionAsync_UpsertsExistingRow()
	{
		const string channel = "Ch/Upsert";
		const string first = "<Bookmark v='1'/>";
		const string second = "<Bookmark v='2'/>";

		await _store.SaveBookmarkAsync(channel, first).ConfigureAwait(false); // seed via legacy path
		Assert.Equal(first, _store.GetBookmarkXml(channel));

		await using SqliteConnection conn = await OpenSharedConnectionAsync().ConfigureAwait(false);
		await using SqliteTransaction tx = (SqliteTransaction)await conn.BeginTransactionAsync().ConfigureAwait(false);
		_store.UpdateCache(channel, second);
		await _store.SaveInSameTransactionAsync(conn, tx, channel, second).ConfigureAwait(false);
		await tx.CommitAsync().ConfigureAwait(false);

		(string? persisted, _) = await ReadBookmarkDirectAsync(channel).ConfigureAwait(false);
		Assert.Equal(second, persisted);
		Assert.Equal(second, _store.GetBookmarkXml(channel));

		// And the legacy read path (EF, no-tracking) sees the same row.
		await using AuditDbContext db = _factory.CreateDbContext();
		Bookmark? row = await db.Bookmarks.AsNoTracking().FirstOrDefaultAsync(b => b.Channel == channel).ConfigureAwait(false);
		Assert.NotNull(row);
		Assert.Equal(second, row!.BookmarkXml);
	}

	[Fact]
	public async Task SaveInSameTransactionAsync_ShareCommitBoundaryWithRawEventInsert()
	{
		const string channel = "Ch/Unified";
		const string xml = "<Bookmark unified='1'/>";

		await using SqliteConnection conn = await OpenSharedConnectionAsync().ConfigureAwait(false);
		await using SqliteTransaction tx = (SqliteTransaction)await conn.BeginTransactionAsync().ConfigureAwait(false);

		_store.UpdateCache(channel, xml);

		// 1) Insert a dummy raw event under the same transaction.
		await using (SqliteCommand insertEvent = InsertDummyRawEventCommand(conn, tx, channel))
		{
			await insertEvent.ExecuteNonQueryAsync().ConfigureAwait(false);
		}

		// 2) Persist the bookmark under the same transaction.
		await _store.SaveInSameTransactionAsync(conn, tx, channel, xml).ConfigureAwait(false);

		// Before commit, the row exists inside the transaction but NOT to a second connection.
		(string? beforeCommit, _) = await ReadBookmarkDirectAsync(channel).ConfigureAwait(false);
		Assert.Null(beforeCommit);

		await tx.CommitAsync().ConfigureAwait(false);
		_store.MarkCommitted(channel);

		// After commit, both artefacts are visible.
		(string? afterCommit, _) = await ReadBookmarkDirectAsync(channel).ConfigureAwait(false);
		Assert.Equal(xml, afterCommit);

		await using SqliteConnection verify = await OpenSharedConnectionAsync().ConfigureAwait(false);
		await using SqliteCommand countCmd = verify.CreateCommand();
		countCmd.CommandText = "SELECT COUNT(*) FROM \"RawEvents\" WHERE \"Channel\" = $c;";
		countCmd.Parameters.Add("$c", SqliteType.Text).Value = channel;
		object? countObj = await countCmd.ExecuteScalarAsync().ConfigureAwait(false);
		long count = Convert.ToInt64(countObj, CultureInfo.InvariantCulture);
		Assert.Equal(1, count);
	}

	// ── Tests: rollback semantics ───────────────────────────────────────────────

	[Fact]
	public async Task SaveInSameTransactionAsync_RollbackDropsBookmarkFromStore()
	{
		const string channel = "Ch/Rollback1";
		const string xml = "<Bookmark rollback='1'/>";

		await using SqliteConnection conn = await OpenSharedConnectionAsync().ConfigureAwait(false);
		await using SqliteTransaction tx = (SqliteTransaction)await conn.BeginTransactionAsync().ConfigureAwait(false);

		string? previous = _store.UpdateCache(channel, xml);
		await _store.SaveInSameTransactionAsync(conn, tx, channel, xml).ConfigureAwait(false);
		await tx.RollbackAsync().ConfigureAwait(false);
		_store.RollbackCache(channel, previous);

		(string? persisted, _) = await ReadBookmarkDirectAsync(channel).ConfigureAwait(false);
		Assert.Null(persisted);
		Assert.Null(_store.GetBookmarkXml(channel));
	}

	[Fact]
	public async Task RollbackCache_RestoresPreviousBookmark_WhenTransactionRollsBack()
	{
		const string channel = "Ch/Rollback2";
		const string prior = "<Bookmark prior='1'/>";
		const string attempted = "<Bookmark attempted='2'/>";

		await _store.SaveBookmarkAsync(channel, prior).ConfigureAwait(false); // seed
		Assert.Equal(prior, _store.GetBookmarkXml(channel));

		await using SqliteConnection conn = await OpenSharedConnectionAsync().ConfigureAwait(false);
		await using SqliteTransaction tx = (SqliteTransaction)await conn.BeginTransactionAsync().ConfigureAwait(false);

		string? previous = _store.UpdateCache(channel, attempted);
		Assert.Equal(prior, previous); // must observe the seeded value
		Assert.Equal(attempted, _store.GetBookmarkXml(channel));

		await _store.SaveInSameTransactionAsync(conn, tx, channel, attempted).ConfigureAwait(false);
		await tx.RollbackAsync().ConfigureAwait(false);
		_store.RollbackCache(channel, previous);

		Assert.Equal(prior, _store.GetBookmarkXml(channel));
		(string? persisted, _) = await ReadBookmarkDirectAsync(channel).ConfigureAwait(false);
		Assert.Equal(prior, persisted);
	}

	// ── Tests: boundary error handling ──────────────────────────────────────────

	[Fact]
	public async Task SaveInSameTransactionAsync_Throws_WhenConnectionNotOpen()
	{
		// The method reports the closed-connection failure BEFORE it validates the transaction
		// binding, so we do not need a transaction that is actually attached to the closed
		// connection. Any live transaction on any other open connection is enough to satisfy the
		// null-guard and let the state check fire.
		SqliteConnection closedConn = new(ConnectionString);
		Assert.Equal(System.Data.ConnectionState.Closed, closedConn.State);

		await using SqliteConnection openConn = await OpenSharedConnectionAsync().ConfigureAwait(false);
		await using SqliteTransaction liveTx =
			(SqliteTransaction)await openConn.BeginTransactionAsync().ConfigureAwait(false);

		try
		{
			await Assert.ThrowsAsync<InvalidOperationException>(async () =>
			{
				await _store.SaveInSameTransactionAsync(closedConn, liveTx, "Ch/Closed", "<x/>").ConfigureAwait(false);
			}).ConfigureAwait(false);
		}
		finally
		{
			await liveTx.RollbackAsync().ConfigureAwait(false);
			await closedConn.DisposeAsync().ConfigureAwait(false);
		}
	}

	[Fact]
	public async Task SaveInSameTransactionAsync_Throws_WhenTransactionBoundToDifferentConnection()
	{
		await using SqliteConnection connA = await OpenSharedConnectionAsync().ConfigureAwait(false);
		await using SqliteConnection connB = await OpenSharedConnectionAsync().ConfigureAwait(false);
		await using SqliteTransaction txA = (SqliteTransaction)await connA.BeginTransactionAsync().ConfigureAwait(false);

		await Assert.ThrowsAsync<ArgumentException>(async () =>
		{
			await _store.SaveInSameTransactionAsync(connB, txA, "Ch/Mismatch", "<x/>").ConfigureAwait(false);
		}).ConfigureAwait(false);

		await txA.RollbackAsync().ConfigureAwait(false);
	}

	// ── Tests: batched write ────────────────────────────────────────────────────

	[Fact]
	public async Task SaveBatchInSameTransactionAsync_PersistsEveryBookmarkOnCommit()
	{
		Dictionary<string, string> input = new(StringComparer.OrdinalIgnoreCase)
		{
			["Ch/Batch/A"] = "<A/>",
			["Ch/Batch/B"] = "<B/>",
			["Ch/Batch/C"] = "<C/>",
		};

		await using SqliteConnection conn = await OpenSharedConnectionAsync().ConfigureAwait(false);
		await using SqliteTransaction tx = (SqliteTransaction)await conn.BeginTransactionAsync().ConfigureAwait(false);

		foreach (KeyValuePair<string, string> entry in input)
		{
			_store.UpdateCache(entry.Key, entry.Value);
		}

		await _store.SaveBatchInSameTransactionAsync(conn, tx, input).ConfigureAwait(false);
		await tx.CommitAsync().ConfigureAwait(false);

		foreach (KeyValuePair<string, string> entry in input)
		{
			(string? persisted, _) = await ReadBookmarkDirectAsync(entry.Key).ConfigureAwait(false);
			Assert.Equal(entry.Value, persisted);
			Assert.Equal(entry.Value, _store.GetBookmarkXml(entry.Key));
		}
	}

	[Fact]
	public async Task SaveBatchInSameTransactionAsync_EmptyDictionary_IsNoop()
	{
		await using SqliteConnection conn = await OpenSharedConnectionAsync().ConfigureAwait(false);
		await using SqliteTransaction tx = (SqliteTransaction)await conn.BeginTransactionAsync().ConfigureAwait(false);

		await _store.SaveBatchInSameTransactionAsync(
			conn,
			tx,
			new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)).ConfigureAwait(false);

		await tx.CommitAsync().ConfigureAwait(false);
		// No exceptions is the assertion.
	}

	// ── Tests: concurrent readers/writers ───────────────────────────────────────

	[Fact]
	public async Task UpdateCacheAndSave_AreSafeUnderConcurrentInvocations()
	{
		const int channels = 8;
		string[] channelNames = new string[channels];
		for (int i = 0; i < channels; i++)
		{
			channelNames[i] = $"Ch/Concurrent/{i}";
		}

		ConcurrentBag<Exception> failures = new();
		Task[] tasks = new Task[channels];
		for (int i = 0; i < channels; i++)
		{
			int idx = i;
			tasks[i] = Task.Run(async () =>
			{
				try
				{
					await using SqliteConnection conn = await OpenSharedConnectionAsync().ConfigureAwait(false);
					await using SqliteTransaction tx = (SqliteTransaction)await conn.BeginTransactionAsync().ConfigureAwait(false);
					string xml = $"<Bookmark idx='{idx}'/>";
					_store.UpdateCache(channelNames[idx], xml);
					await _store.SaveInSameTransactionAsync(conn, tx, channelNames[idx], xml).ConfigureAwait(false);
					await tx.CommitAsync().ConfigureAwait(false);
				}
				catch (Exception ex)
				{
					failures.Add(ex);
				}
			});
		}

		await Task.WhenAll(tasks).ConfigureAwait(false);
		Assert.Empty(failures);

		for (int i = 0; i < channels; i++)
		{
			(string? persisted, _) = await ReadBookmarkDirectAsync(channelNames[i]).ConfigureAwait(false);
			Assert.Equal($"<Bookmark idx='{i}'/>", persisted);
		}
	}

	// ── Tests: legacy API compatibility ─────────────────────────────────────────

	[Fact]
	public async Task LegacySaveBookmarkAsync_StillWorksAlongsideRawPath()
	{
		const string channelLegacy = "Ch/LegacyCoexist/Legacy";
		const string channelRaw = "Ch/LegacyCoexist/Raw";

		await _store.SaveBookmarkAsync(channelLegacy, "<legacy/>").ConfigureAwait(false);

		await using (SqliteConnection conn = await OpenSharedConnectionAsync().ConfigureAwait(false))
		await using (SqliteTransaction tx = (SqliteTransaction)await conn.BeginTransactionAsync().ConfigureAwait(false))
		{
			_store.UpdateCache(channelRaw, "<raw/>");
			await _store.SaveInSameTransactionAsync(conn, tx, channelRaw, "<raw/>").ConfigureAwait(false);
			await tx.CommitAsync().ConfigureAwait(false);
		}

		Assert.Equal("<legacy/>", _store.GetBookmarkXml(channelLegacy));
		Assert.Equal("<raw/>", _store.GetBookmarkXml(channelRaw));

		// LoadAllAsync must surface both, unified through the EF read path.
		BookmarkStore reloaded = new(_factory, NullLogger<BookmarkStore>.Instance);
		await reloaded.LoadAllAsync().ConfigureAwait(false);
		Assert.Equal("<legacy/>", reloaded.GetBookmarkXml(channelLegacy));
		Assert.Equal("<raw/>", reloaded.GetBookmarkXml(channelRaw));
	}

	[Fact]
	public async Task LegacyDeleteBookmarkAsync_RemovesRawWrittenBookmark()
	{
		const string channel = "Ch/DeleteRaw";
		await using (SqliteConnection conn = await OpenSharedConnectionAsync().ConfigureAwait(false))
		await using (SqliteTransaction tx = (SqliteTransaction)await conn.BeginTransactionAsync().ConfigureAwait(false))
		{
			_store.UpdateCache(channel, "<x/>");
			await _store.SaveInSameTransactionAsync(conn, tx, channel, "<x/>").ConfigureAwait(false);
			await tx.CommitAsync().ConfigureAwait(false);
		}

		Assert.Equal("<x/>", _store.GetBookmarkXml(channel));

		await _store.DeleteBookmarkAsync(channel).ConfigureAwait(false);

		Assert.Null(_store.GetBookmarkXml(channel));
		(string? persisted, _) = await ReadBookmarkDirectAsync(channel).ConfigureAwait(false);
		Assert.Null(persisted);
	}

	// ── Test-local DbContext factory ────────────────────────────────────────────

	private sealed class TestDbContextFactory : IDbContextFactory<AuditDbContext>
	{
		private readonly DbContextOptions<AuditDbContext> _options;

		public TestDbContextFactory(string connectionString)
		{
			DbContextOptionsBuilder<AuditDbContext> builder = new();
			builder.UseSqlite(connectionString);
			builder.EnableSensitiveDataLogging(false);
			_options = builder.Options;
		}

		public AuditDbContext CreateDbContext() => new(_options);

		public Task<AuditDbContext> CreateDbContextAsync(CancellationToken cancellationToken = default)
			=> Task.FromResult(CreateDbContext());
	}
}
