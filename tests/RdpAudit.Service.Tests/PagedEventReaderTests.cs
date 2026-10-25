// File:    tests/RdpAudit.Service.Tests/PagedEventReaderTests.cs
// Module:  RdpAudit.Service.Tests
// Purpose: Unit/contract tests for the REST /events reader: deterministic paging under the
//          (TimeUtc DESC, Id DESC) total order, filter application, clamp guarantees, and the
//          read-only guarantee of the Mode=ReadOnly context factory (a write through the RO
//          connection must fail with SQLITE_READONLY while reads keep working).
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using RdpAudit.Core.Config;
using RdpAudit.Core.Data;
using RdpAudit.Core.Models;
using RdpAudit.Core.RestApi;
using RdpAudit.Service.RestApi;
using Xunit;

namespace RdpAudit.Service.Tests;

/// <summary>Contract tests for <see cref="PagedEventReader"/> over a file-backed SQLite database.</summary>
public class PagedEventReaderTests
{
	private sealed class LocalOptionsMonitor : IOptionsMonitor<RdpAuditOptions>
	{
		public LocalOptionsMonitor(RdpAuditOptions value) => CurrentValue = value;
		public RdpAuditOptions CurrentValue { get; }
		public RdpAuditOptions Get(string? name) => CurrentValue;
		public IDisposable? OnChange(Action<RdpAuditOptions, string?> listener) => null;
	}

	private static async Task<string> SeedAsync(int rowCount)
	{
		string dbPath = Path.Combine(Path.GetTempPath(), "rdpaudit-paged-events-" + Guid.NewGuid().ToString("N") + ".db");
		{
			// Open once so EnsureCreatedAsync can create the file, then close immediately:
			// the WAL-capable contexts below open their own pooled connections.
			await using SqliteConnection conn = new(AuditDbContextOptionsFactory.BuildConnectionString(dbPath));
			await conn.OpenAsync();
		}

		DbContextOptions<AuditDbContext> ensure = AuditDbContextOptionsFactory.Create(dbPath);
		await using AuditDbContext init = new(ensure);
		await init.Database.EnsureCreatedAsync();

		DateTime start = new(2026, 9, 1, 10, 0, 0, DateTimeKind.Utc);
		await using (AuditDbContext db = new(ensure))
		{
			for (int i = 1; i <= rowCount; i++)
			{
				RawEvent e = new()
				{
					EventId = (i % 5 == 0) ? 2000 : 4625,
					Channel = (i % 7 == 0) ? "System" : "Security",
					TimeUtc = start.AddMinutes(-i),
					IngestionSequence = i,
					EventLayer = 3,
					SourceIp = i % 3 == 0 ? "10.0.0." + ((i % 250) + 1).ToString(System.Globalization.CultureInfo.InvariantCulture) : "192.168.1." + (i % 250).ToString(System.Globalization.CultureInfo.InvariantCulture),
					SourceIpDerived = false,
					SourceIpUnresolved = false,
					UserName = "user" + (i % 9).ToString(System.Globalization.CultureInfo.InvariantCulture),
					Domain = "DOM" + (i % 4).ToString(System.Globalization.CultureInfo.InvariantCulture),
					Details = "details-" + i.ToString(System.Globalization.CultureInfo.InvariantCulture),
					Processed = false,
				};
				db.RawEvents.Add(e);
			}

			await db.SaveChangesAsync();
		}

		return dbPath;
	}

	private static ReadOnlyAuditDbContextFactory CreateRoFactory(string dbPath)
	{
		RdpAuditOptions options = new();
		options.Storage.DatabasePath = dbPath;
		return new ReadOnlyAuditDbContextFactory(new LocalOptionsMonitor(options));
	}

	private static async Task<List<RawEvent>> AllRowsAsync(string dbPath)
	{
		await using AuditDbContext db = new(AuditDbContextOptionsFactory.Create(dbPath));
		return await db.RawEvents.AsNoTracking().OrderBy(e => e.Id).ToListAsync();
	}

	private static void TryDeleteFile(string dbPath)
	{
		try
		{
			if (File.Exists(dbPath)) File.Delete(dbPath);
			if (File.Exists(dbPath + "-wal")) File.Delete(dbPath + "-wal");
			if (File.Exists(dbPath + "-shm")) File.Delete(dbPath + "-shm");
		}
		catch
		{
			// Best-effort temp cleanup.
		}
	}

	[Fact]
	public async Task ReadPageAsync_OrdersNewestFirst_WithIdTieBreak_AndDoesNotOverlap()
	{
		string dbPath = await SeedAsync(25);
		try
		{
			PagedEventReader reader = new(CreateRoFactory(dbPath));
			PagedEventPage page0 = await reader.ReadPageAsync(new PagedEventsQuery { Limit = 10 }, CancellationToken.None);
			PagedEventPage page1 = await reader.ReadPageAsync(new PagedEventsQuery { Limit = 10, Offset = 10 }, CancellationToken.None);
			PagedEventPage page2 = await reader.ReadPageAsync(new PagedEventsQuery { Limit = 10, Offset = 20 }, CancellationToken.None);

			Assert.Equal(25, page0.Total);
			Assert.Equal(10, page0.Events.Count);
			Assert.Equal(10, page1.Events.Count);
			Assert.Equal(5, page2.Events.Count);

			for (int i = 1; i < page0.Events.Count; i++)
			{
				Assert.True(page0.Events[i - 1].TimeUtc >= page0.Events[i].TimeUtc);
				if (page0.Events[i - 1].TimeUtc == page0.Events[i].TimeUtc)
				{
					Assert.True(page0.Events[i - 1].Id > page0.Events[i].Id);
				}
			}

			HashSet<long> all = [.. page0.Events.Select(e => e.Id), .. page1.Events.Select(e => e.Id), .. page2.Events.Select(e => e.Id)];
			Assert.Equal(25, all.Count);
		}
		finally
		{
			TryDeleteFile(dbPath);
		}
	}

	[Fact]
	public async Task ReadPageAsync_AppliesAllFilters()
	{
		string dbPath = await SeedAsync(40);
		try
		{
			List<RawEvent> baseline = await AllRowsAsync(dbPath);
			PagedEventReader reader = new(CreateRoFactory(dbPath));

			int e2000 = baseline.Count(e => e.EventId == 2000);
			PagedEventPage byEvent = await reader.ReadPageAsync(new PagedEventsQuery { EventId = 2000, Limit = 500 }, CancellationToken.None);
			Assert.Equal(e2000, byEvent.Total);
			Assert.All(byEvent.Events, e => Assert.Equal(2000, e.EventId));

			int system = baseline.Count(e => e.Channel == "System");
			PagedEventPage byChannel = await reader.ReadPageAsync(new PagedEventsQuery { Channel = "System", Limit = 500 }, CancellationToken.None);
			Assert.Equal(system, byChannel.Total);

			string needle = "user3";
			int byName = baseline.Count(e => e.UserName == needle);
			PagedEventPage byUserName = await reader.ReadPageAsync(new PagedEventsQuery { UserNameContains = needle, Limit = 500 }, CancellationToken.None);
			Assert.Equal(byName, byUserName.Total);

			DateTime windowStart = new(2026, 8, 31, 0, 0, 0, DateTimeKind.Utc);
			int inWindow = baseline.Count(e => e.TimeUtc >= windowStart && e.TimeUtc <= new DateTime(2026, 9, 2, 0, 0, 0, DateTimeKind.Utc));
			PagedEventPage byWindow = await reader.ReadPageAsync(new PagedEventsQuery
			{
				SinceUtc = windowStart,
				ToUtc = new DateTime(2026, 9, 2, 0, 0, 0, DateTimeKind.Utc),
				Limit = 500,
			}, CancellationToken.None);
			Assert.Equal(inWindow, byWindow.Total);

			string ip = baseline.Where(e => e.SourceIp is not null).Select(e => e.SourceIp!).First();
			int byIp = baseline.Count(e => e.SourceIp == ip);
			PagedEventPage bySourceIp = await reader.ReadPageAsync(new PagedEventsQuery { SourceIp = ip, Limit = 500 }, CancellationToken.None);
			Assert.Equal(byIp, bySourceIp.Total);
		}
		finally
		{
			TryDeleteFile(dbPath);
		}
	}

	[Fact]
	public async Task ReadPageAsync_ClampsLimitAndOffset()
	{
		string dbPath = await SeedAsync(7);
		try
		{
			PagedEventReader reader = new(CreateRoFactory(dbPath));
			PagedEventPage huge = await reader.ReadPageAsync(new PagedEventsQuery { Limit = 99_999, Offset = -10 }, CancellationToken.None);
			Assert.Equal(PagedEventsQuery.MaxPageSize, huge.Limit);
			Assert.Equal(0, huge.Offset);
			Assert.Equal(7, huge.Total);

			PagedEventPage zero = await reader.ReadPageAsync(new PagedEventsQuery { Limit = 0, Offset = 10_000_000 }, CancellationToken.None);
			Assert.Equal(PagedEventsQuery.DefaultPageSize, zero.Limit);
			Assert.Equal(PagedEventsQuery.MaxOffset, zero.Offset);
			Assert.Empty(zero.Events);
		}
		finally
		{
			TryDeleteFile(dbPath);
		}
	}

	[Fact]
	public async Task ReadPageAsync_ExplainPlan_ReturnsDetailLines_WithoutExecuting()
	{
		string dbPath = await SeedAsync(11);
		try
		{
			PagedEventReader reader = new(CreateRoFactory(dbPath));
			PagedEventPage page = await reader.ReadPageAsync(
				new PagedEventsQuery { IncludeExplain = true, EventId = 4625, Limit = 5 },
				CancellationToken.None);

			Assert.Equal(5, page.Events.Count);
			Assert.NotEmpty(page.ExplainPlan);
			Assert.Contains(page.ExplainPlan, line => line.Contains("RawEvents", StringComparison.OrdinalIgnoreCase));
		}
		finally
		{
			TryDeleteFile(dbPath);
		}
	}

	[Fact]
	public async Task ReadPageAsync_ProjectsDetails_OnlyWhenRequested()
	{
		string dbPath = await SeedAsync(5);
		try
		{
			PagedEventReader reader = new(CreateRoFactory(dbPath));
			PagedEventPage without = await reader.ReadPageAsync(new PagedEventsQuery { Limit = 5 }, CancellationToken.None);
			Assert.All(without.Events, e => Assert.Null(e.Details));

			PagedEventPage with = await reader.ReadPageAsync(new PagedEventsQuery { Limit = 5, IncludeDetails = true }, CancellationToken.None);
			Assert.All(with.Events, e => Assert.NotNull(e.Details));
		}
		finally
		{
			TryDeleteFile(dbPath);
		}
	}

	[Fact]
	public async Task ReadOnlyFactory_ReadsData_ButWritesFailWithSqliteReadOnly()
	{
		string dbPath = await SeedAsync(4);
		try
		{
			await using AuditDbContext ro = CreateRoFactory(dbPath).CreateDbContext();

			int readCount = await ro.RawEvents.CountAsync();
			Assert.Equal(4, readCount);

			ro.RawEvents.Add(new RawEvent
			{
				EventId = 1,
				Channel = "Security",
				TimeUtc = DateTime.UtcNow,
				Processed = false,
			});

			Exception thrown = await Assert.ThrowsAnyAsync<Exception>(() => ro.SaveChangesAsync());
			SqliteException? sqlite = thrown as SqliteException
				?? (thrown as DbUpdateException)?.InnerException as SqliteException
				?? thrown.InnerException as SqliteException;
			Assert.NotNull(sqlite);
			Assert.Equal(8, sqlite!.SqliteErrorCode); // SQLITE_READONLY
		}
		finally
		{
			TryDeleteFile(dbPath);
		}
	}

	[Fact]
	public async Task Reader_RejectsNullQuery_AndNullFactory()
	{
		Assert.Throws<ArgumentNullException>(() => new PagedEventReader(null!));
		string dbPath = Path.Combine(Path.GetTempPath(), "rdpaudit-paged-nullarg-" + Guid.NewGuid().ToString("N") + ".db");
		try
		{
			await SeedAsync(1);
			PagedEventReader reader = new(CreateRoFactory(dbPath));
			await Assert.ThrowsAsync<ArgumentNullException>(() => reader.ReadPageAsync(null!, CancellationToken.None));
		}
		finally
		{
			TryDeleteFile(dbPath);
		}
	}

	[Fact]
	public void Normalize_StripsControlCharactersFromTextFilters()
	{
		// A line break inside a filter value used to reach the generated SQL text, where the
		// parameter directives are processed line by line (StripParamDirectives); the resulting
		// statement was unparsable and the endpoint answered 500 instead of a page.
		PagedEventsQuery normalized = new PagedEventsQuery
		{
			Limit = 10,
			UserNameContains = "a\nb\tc",
			Channel = "Security\u0000",
		}.Normalize();

		Assert.Equal("abc", normalized.UserNameContains);
		Assert.Equal("Security", normalized.Channel);
		Assert.DoesNotContain('\n', PagedEventsQuery.StripControlCharacters("a\nb"));
		Assert.Equal(string.Empty, PagedEventsQuery.StripControlCharacters("\r\n\t"));
	}
}
