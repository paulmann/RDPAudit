/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// File   : RawEventRecordIdDedupTests.cs
// Project: RdpAudit.Service.Tests (RdpAudit.Service.Tests)
// Purpose: Locks the exactly-once dedup that stops the live EventLogWatcher and a backfill worker
//          from persisting the same Windows record twice. Covers the in-memory dedup helper
//          (already-persisted row, in-batch duplicate, same RecordId at a different TimeUtc after a
//          log rotation, and rows without a RecordId) and the partial unique index that backstops it.
// Depends: EventProcessorWorker.DedupeByRecordIdAsync, AuditDbContext, Microsoft.Data.Sqlite
// Extends: Add a case when the dedup key gains another column.
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using RdpAudit.Core.Data;
using RdpAudit.Core.Models;
using RdpAudit.Service.Workers;
using Xunit;

namespace RdpAudit.Service.Tests;

public sealed class RawEventRecordIdDedupTests
{
	private static async Task<(AuditDbContext Db, SqliteConnection Conn)> CreateDbAsync()
	{
		SqliteConnection conn = new("DataSource=:memory:");
		await conn.OpenAsync();
		DbContextOptions<AuditDbContext> options = new DbContextOptionsBuilder<AuditDbContext>()
			.UseSqlite(conn)
			.Options;

		AuditDbContext db = new(options);
		await db.Database.EnsureCreatedAsync();
		return (db, conn);
	}

	[Fact]
	public async Task Dedupe_KeepsNewRows_DropsPersistedAndInBatchDuplicates()
	{
		(AuditDbContext db, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			DateTime t = new(2026, 10, 23, 12, 0, 0, DateTimeKind.Utc);
			db.RawEvents.Add(new RawEvent { EventId = 4625, Channel = "Security", TimeUtc = t, RecordId = 100 });
			await db.SaveChangesAsync();

			List<RawEvent> batch = new()
			{
				// Already persisted (the backfill re-read the same record the live watcher ingested).
				new RawEvent { EventId = 4625, Channel = "Security", TimeUtc = t, RecordId = 100 },
				// New.
				new RawEvent { EventId = 4625, Channel = "Security", TimeUtc = t, RecordId = 101 },
				// Duplicate of the previous row inside the same batch.
				new RawEvent { EventId = 4625, Channel = "Security", TimeUtc = t, RecordId = 101 },
				// Same RecordId at a different time: a rotated/cleared log restarts ids, so this is NOT a duplicate.
				new RawEvent { EventId = 4625, Channel = "Security", TimeUtc = t.AddSeconds(1), RecordId = 100 },
				// No RecordId (ETW / synthetic): always kept.
				new RawEvent { EventId = 4625, Channel = "Security", TimeUtc = t },
			};

			List<RawEvent> kept = await EventProcessorWorker.DedupeByRecordIdAsync(db, batch, CancellationToken.None);

			Assert.Equal(3, kept.Count);
			Assert.Contains(kept, e => e.RecordId == 101);
			Assert.Contains(kept, e => e.RecordId == 100 && e.TimeUtc == t.AddSeconds(1));
			Assert.Contains(kept, e => e.RecordId is null);
		}
		finally
		{
			await db.DisposeAsync();
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task UniqueIndex_RejectsTheSameChannelRecordIdAndTime()
	{
		(AuditDbContext db, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			DateTime t = new(2026, 10, 23, 12, 0, 0, DateTimeKind.Utc);
			db.RawEvents.Add(new RawEvent { EventId = 4625, Channel = "Security", TimeUtc = t, RecordId = 100 });
			await db.SaveChangesAsync();

			db.RawEvents.Add(new RawEvent { EventId = 4625, Channel = "Security", TimeUtc = t, RecordId = 100 });
			await Assert.ThrowsAsync<DbUpdateException>(() => db.SaveChangesAsync());
		}
		finally
		{
			await db.DisposeAsync();
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task NullRecordId_DoesNotCollide()
	{
		// The partial index must not treat two ETW rows with the same channel/time as duplicates.
		(AuditDbContext db, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			DateTime t = new(2026, 10, 23, 12, 0, 0, DateTimeKind.Utc);
			db.RawEvents.Add(new RawEvent { EventId = 4625, Channel = "Security", TimeUtc = t });
			db.RawEvents.Add(new RawEvent { EventId = 4625, Channel = "Security", TimeUtc = t });
			await db.SaveChangesAsync();

			Assert.Equal(2, await db.RawEvents.CountAsync());
		}
		finally
		{
			await db.DisposeAsync();
			await conn.DisposeAsync();
		}
	}
}
