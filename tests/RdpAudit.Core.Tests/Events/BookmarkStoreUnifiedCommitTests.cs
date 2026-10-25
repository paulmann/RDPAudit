/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.3
// File   : BookmarkStoreUnifiedCommitTests.cs
// Project: RdpAudit.Core.Tests (RdpAudit.Core.Tests.Events)
// Purpose: Verifies that event rows and bookmarks share one SQLite commit boundary.
// Depends: AuditDbContext, BookmarkStore, SqliteConnection, xUnit
// Extends: Add a commit and rollback assertion when another durable cursor joins the batch transaction.

using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using RdpAudit.Core.Data;
using RdpAudit.Core.Events;
using Xunit;

namespace RdpAudit.Core.Tests.Events;

public sealed class BookmarkStoreUnifiedCommitTests : IDisposable
{
	private readonly SqliteConnection _connection;
	private readonly TestDbContextFactory _factory;
	private readonly BookmarkStore _store;

	public BookmarkStoreUnifiedCommitTests()
	{
		_connection = new SqliteConnection("DataSource=:memory:");
		_connection.Open();
		DbContextOptions<AuditDbContext> options = new DbContextOptionsBuilder<AuditDbContext>()
			.UseSqlite(_connection)
			.Options;
		using AuditDbContext db = new(options);
		db.Database.EnsureCreated();
		_factory = new TestDbContextFactory(options);
		_store = new BookmarkStore(_factory, NullLogger<BookmarkStore>.Instance);
	}

	[Fact]
	public async Task SaveInSameTransactionAsync_CommitMakesBookmarkAndEventVisibleTogether()
	{
		const string channel = "Security";
		const string bookmark = "<Bookmark RecordId='700'/>";

		string? previous = _store.UpdateCache(channel, bookmark);
		await using SqliteTransaction transaction = (SqliteTransaction)await _connection.BeginTransactionAsync();
		await InsertRawEventAsync(transaction, channel, 700);
		await _store.SaveInSameTransactionAsync(_connection, transaction, channel, bookmark);
		await transaction.CommitAsync();
		_store.MarkCommitted(channel);

		Assert.Equal(bookmark, await ReadBookmarkAsync(channel));
		Assert.Equal(1, await CountEventsAsync(channel));
		Assert.Equal(bookmark, _store.GetBookmarkXml(channel));
		Assert.Null(previous);
	}

	[Fact]
	public async Task SaveInSameTransactionAsync_RollbackLeavesNeitherBookmarkNorEvent()
	{
		const string channel = "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational";
		const string bookmark = "<Bookmark RecordId='701'/>";

		string? previous = _store.UpdateCache(channel, bookmark);
		await using SqliteTransaction transaction = (SqliteTransaction)await _connection.BeginTransactionAsync();
		await InsertRawEventAsync(transaction, channel, 701);
		await _store.SaveInSameTransactionAsync(_connection, transaction, channel, bookmark);
		await transaction.RollbackAsync();
		_store.RollbackCache(channel, previous);

		Assert.Null(await ReadBookmarkAsync(channel));
		Assert.Equal(0, await CountEventsAsync(channel));
		Assert.Null(_store.GetBookmarkXml(channel));
	}

	[Fact]
	public async Task SaveInSameTransactionAsync_RollbackRestoresPreviouslyCommittedBookmark()
	{
		const string channel = "Security";
		const string committed = "<Bookmark RecordId='1'/>";
		const string attempted = "<Bookmark RecordId='2'/>";

		await _store.SaveBookmarkAsync(channel, committed);
		string? previous = _store.UpdateCache(channel, attempted);
		await using SqliteTransaction transaction = (SqliteTransaction)await _connection.BeginTransactionAsync();
		await _store.SaveInSameTransactionAsync(_connection, transaction, channel, attempted);
		await transaction.RollbackAsync();
		_store.RollbackCache(channel, previous);

		Assert.Equal(committed, await ReadBookmarkAsync(channel));
		Assert.Equal(committed, _store.GetBookmarkXml(channel));
	}

	[Fact]
	public async Task SaveBatchInSameTransactionAsync_CommitPersistsEveryBookmark()
	{
		IReadOnlyDictionary<string, string> bookmarks = new Dictionary<string, string>
		{
			["Security"] = "<Bookmark RecordId='10'/>",
			["System"] = "<Bookmark RecordId='11'/>",
		};

		await using SqliteTransaction transaction = (SqliteTransaction)await _connection.BeginTransactionAsync();
		await _store.SaveBatchInSameTransactionAsync(_connection, transaction, bookmarks);
		await transaction.CommitAsync();

		foreach (KeyValuePair<string, string> bookmark in bookmarks)
		{
			Assert.Equal(bookmark.Value, await ReadBookmarkAsync(bookmark.Key));
		}
	}

	public void Dispose() => _connection.Dispose();

	private async Task InsertRawEventAsync(SqliteTransaction transaction, string channel, long sequence)
	{
		await using SqliteCommand command = _connection.CreateCommand();
		command.Transaction = transaction;
		command.CommandText = "INSERT INTO \"RawEvents\" (\"Channel\", \"EventId\", \"TimeUtc\", \"IngestionSequence\", \"Processed\") VALUES ($channel, 4625, $timeUtc, $sequence, 0);";
		command.Parameters.AddWithValue("$channel", channel);
		command.Parameters.AddWithValue("$timeUtc", DateTime.UtcNow);
		command.Parameters.AddWithValue("$sequence", sequence);
		await command.ExecuteNonQueryAsync();
	}

	private async Task<string?> ReadBookmarkAsync(string channel)
	{
		await using SqliteCommand command = _connection.CreateCommand();
		command.CommandText = "SELECT \"BookmarkXml\" FROM \"Bookmarks\" WHERE \"Channel\" = $channel;";
		command.Parameters.AddWithValue("$channel", channel);
		object? value = await command.ExecuteScalarAsync();
		return value as string;
	}

	private async Task<long> CountEventsAsync(string channel)
	{
		await using SqliteCommand command = _connection.CreateCommand();
		command.CommandText = "SELECT COUNT(*) FROM \"RawEvents\" WHERE \"Channel\" = $channel;";
		command.Parameters.AddWithValue("$channel", channel);
		return (long)(await command.ExecuteScalarAsync() ?? 0L);
	}

	private sealed class TestDbContextFactory(DbContextOptions<AuditDbContext> options) : IDbContextFactory<AuditDbContext>
	{
		public AuditDbContext CreateDbContext() => new(options);

		public Task<AuditDbContext> CreateDbContextAsync(CancellationToken cancellationToken = default)
			=> Task.FromResult(CreateDbContext());
	}
}
