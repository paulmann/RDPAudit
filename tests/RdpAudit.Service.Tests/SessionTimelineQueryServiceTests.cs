// File:    tests/RdpAudit.Service.Tests/SessionTimelineQueryServiceTests.cs
// Module:  RdpAudit.Service.Tests
// Purpose: Unit coverage for the Session Map query service (Backlog #6): fact lookup by id,
//          cap clamping (default 500, floor 50, ceiling 2000), index-friendly correlation
//          pre-filtering (LogonId > SessionId > UserName+Domain), session-window gating,
//          chronological Take ordering, pre-cap TotalMatching, Other-events filtering and
//          DEBUG-gated Details projection over an in-memory SQLite database.
// Depends: SessionTimelineQueryService, AuditDbContext, RdpConnectionFact, RawEvent, xunit
// Extends: Add a test whenever the query shape or the correlation pre-filter changes.

using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using RdpAudit.Core.Data;
using RdpAudit.Core.Models;
using RdpAudit.Core.Sessions;
using RdpAudit.Service.Sessions;
using Xunit;

namespace RdpAudit.Service.Tests;

public sealed class SessionTimelineQueryServiceTests
{
	private static readonly DateTime T0 = new(2026, 2, 1, 8, 0, 0, DateTimeKind.Utc);

	private sealed class TestDbContextFactory : IDbContextFactory<AuditDbContext>
	{
		private readonly DbContextOptions<AuditDbContext> _options;
		public TestDbContextFactory(DbContextOptions<AuditDbContext> options) => _options = options;
		public AuditDbContext CreateDbContext() => new(_options);
	}

	private sealed class TestScope : IAsyncDisposable
	{
		public SqliteConnection Connection { get; }
		public IDbContextFactory<AuditDbContext> Factory { get; }
		public SessionTimelineQueryService Service { get; }

		public TestScope(SqliteConnection conn, DbContextOptions<AuditDbContext> options)
		{
			Connection = conn;
			Factory = new TestDbContextFactory(options);
			Service = new SessionTimelineQueryService(Factory);
		}

		public async ValueTask DisposeAsync()
		{
			await Connection.DisposeAsync();
		}
	}

	private static async Task<TestScope> CreateScopeAsync()
	{
		SqliteConnection conn = new("DataSource=:memory:");
		await conn.OpenAsync();
		DbContextOptions<AuditDbContext> options = new DbContextOptionsBuilder<AuditDbContext>()
			.UseSqlite(conn)
			.Options;

		await using (AuditDbContext init = new(options))
		{
			await init.Database.EnsureCreatedAsync();
		}

		return new TestScope(conn, options);
	}

	private static async Task<long> SeedFactAsync(TestScope scope, Action<RdpConnectionFact>? mutate = null)
	{
		await using AuditDbContext db = scope.Factory.CreateDbContext();
		RdpConnectionFact fact = new()
		{
			Ip = "203.0.113.9",
			UserName = "alice",
			Domain = "ACME",
			LogonId = "0x1A2B",
			WtsSessionId = 3,
			FirstSeenUtc = T0.AddMinutes(0),
			LastSeenUtc = T0.AddMinutes(30),
			AuthenticatedUtc = T0.AddMinutes(2),
			ConnectedUtc = T0.AddMinutes(5),
			LoggedOffUtc = T0.AddMinutes(30),
			IsActive = false,
		};
		mutate?.Invoke(fact);
		db.RdpConnectionFacts.Add(fact);
		await db.SaveChangesAsync();
		return fact.Id;
	}

	private static async Task SeedRawEventAsync(
		TestScope scope,
		int eventId,
		int minutes,
		string? logonId = "0x1A2B",
		int? sessionId = null,
		string? user = "alice",
		string? domain = "ACME",
		string? details = "<Event/>",
		string? processName = null,
		string? commandLine = null,
		string? objectName = null)
	{
		await using AuditDbContext db = scope.Factory.CreateDbContext();
		db.RawEvents.Add(new RawEvent
		{
			EventId = eventId,
			Channel = "Security",
			TimeUtc = T0.AddMinutes(minutes),
			LogonId = logonId,
			SessionId = sessionId,
			UserName = user,
			Domain = domain,
			Details = details,
			ProcessName = processName,
			CommandLine = commandLine,
			ObjectName = objectName,
		});
		await db.SaveChangesAsync();
	}

	// ── Cap resolution ───────────────────────────────────────────────────────────

	[Theory]
	[InlineData(0, 500)]
	[InlineData(-1, 500)]
	[InlineData(1, 50)]
	[InlineData(49, 50)]
	[InlineData(50, 50)]
	[InlineData(300, 300)]
	[InlineData(2000, 2000)]
	[InlineData(3000, 2000)]
	public void ResolveCap_ClampsToDocumentedWindow(int requested, int expected)
		=> Assert.Equal(expected, SessionTimelineQueryService.ResolveCap(requested));

	// ── Fact lookup ──────────────────────────────────────────────────────────────

	[Fact]
	public async Task LoadAsync_UnknownFactId_ReturnsNullFact()
	{
		await using TestScope scope = await CreateScopeAsync();

		SessionTimelineQueryResult result = await scope.Service.LoadAsync(9999, 0, false, false, CancellationToken.None);

		Assert.Null(result.Fact);
		Assert.Empty(result.Slices);
		Assert.Equal(500, result.AppliedCap);
	}

	[Fact]
	public async Task LoadAsync_KnownFactId_ReturnsFact()
	{
		await using TestScope scope = await CreateScopeAsync();
		long id = await SeedFactAsync(scope);

		SessionTimelineQueryResult result = await scope.Service.LoadAsync(id, 0, false, false, CancellationToken.None);

		Assert.NotNull(result.Fact);
		Assert.Equal(id, result.Fact.Id);
	}

	// ── Correlation pre-filter ────────────────────────────────────────────────────

	[Fact]
	public async Task LoadAsync_LogonIdMatch_SelectsOnlyMatching()
	{
		await using TestScope scope = await CreateScopeAsync();
		long id = await SeedFactAsync(scope);
		await SeedRawEventAsync(scope, 4688, 10, logonId: "0x1A2B");          // hit
		await SeedRawEventAsync(scope, 4688, 12, logonId: "0x9999");          // miss: other logon
		await SeedRawEventAsync(scope, 4688, 15, logonId: "0x1A2B", user: "bob", domain: "OTHER"); // hit (logon wins)

		SessionTimelineQueryResult result = await scope.Service.LoadAsync(id, 0, false, false, CancellationToken.None);

		Assert.Equal(2, result.Slices.Count);
		Assert.All(result.Slices, s => Assert.Equal("0x1A2B", s.LogonId));
		Assert.Equal(2, result.TotalMatching);
	}

	[Fact]
	public async Task LoadAsync_SessionIdMatch_SelectedWhenNoLogonOnFact()
	{
		await using TestScope scope = await CreateScopeAsync();
		long id = await SeedFactAsync(scope, f => f.LogonId = null);
		await SeedRawEventAsync(scope, 4688, 10, logonId: null, sessionId: 3);   // hit
		await SeedRawEventAsync(scope, 4688, 12, logonId: null, sessionId: 99);  // miss

		SessionTimelineQueryResult result = await scope.Service.LoadAsync(id, 0, false, false, CancellationToken.None);

		SessionTimelineRawEventSlice slice = Assert.Single(result.Slices);
		Assert.Equal(3, slice.SessionId);
	}

	[Fact]
	public async Task LoadAsync_UserDomainFallback_WhenFactHasNeitherKey()
	{
		await using TestScope scope = await CreateScopeAsync();
		long id = await SeedFactAsync(scope, f => { f.LogonId = null; f.WtsSessionId = null; });
		await SeedRawEventAsync(scope, 5145, 10, logonId: null, sessionId: null); // hit
		await SeedRawEventAsync(scope, 5145, 12, logonId: null, sessionId: null, user: "bob"); // miss

		SessionTimelineQueryResult result = await scope.Service.LoadAsync(id, 0, false, false, CancellationToken.None);

		SessionTimelineRawEventSlice slice = Assert.Single(result.Slices);
		Assert.Equal("alice", slice.UserName);
	}

	[Fact]
	public async Task LoadAsync_WindowOutside_IsExcluded()
	{
		await using TestScope scope = await CreateScopeAsync();
		long id = await SeedFactAsync(scope);
		await SeedRawEventAsync(scope, 4688, -5);  // before FirstSeenUtc
		await SeedRawEventAsync(scope, 4688, 45);  // after LoggedOffUtc
		await SeedRawEventAsync(scope, 4688, 10);  // inside

		SessionTimelineQueryResult result = await scope.Service.LoadAsync(id, 0, false, false, CancellationToken.None);

		SessionTimelineRawEventSlice slice = Assert.Single(result.Slices);
		Assert.Equal(T0.AddMinutes(10), slice.TimeUtc);
	}

	// ── Other events + cap ordering ──────────────────────────────────────────────

	[Fact]
	public async Task LoadAsync_OtherEvents_HiddenByDefault()
	{
		await using TestScope scope = await CreateScopeAsync();
		long id = await SeedFactAsync(scope);
		await SeedRawEventAsync(scope, 4688, 10);   // process
		await SeedRawEventAsync(scope, 4624, 12);   // other (correlated)

		SessionTimelineQueryResult hidden = await scope.Service.LoadAsync(id, 0, false, false, CancellationToken.None);
		SessionTimelineQueryResult shown = await scope.Service.LoadAsync(id, 0, true, false, CancellationToken.None);

		Assert.Single(hidden.Slices);
		Assert.Equal(2, shown.Slices.Count);
	}

	[Fact]
	public async Task LoadAsync_TakeCap_OrderedByTime()
	{
		await using TestScope scope = await CreateScopeAsync();
		long id = await SeedFactAsync(scope, f =>
		{
			f.LastSeenUtc = T0.AddMinutes(120);
			f.LoggedOffUtc = T0.AddMinutes(120);
		});
		for (int i = 0; i < 60; i++)
		{
			await SeedRawEventAsync(scope, 4688, 5 + i);
		}

		SessionTimelineQueryResult result = await scope.Service.LoadAsync(id, 50, false, false, CancellationToken.None);

		Assert.Equal(50, result.Slices.Count);
		Assert.Equal(60, result.TotalMatching);
		Assert.Equal(50, result.AppliedCap);
		Assert.Equal(result.Slices.Select(s => s.TimeUtc).OrderBy(t => t),
			result.Slices.Select(s => s.TimeUtc));
	}

	// ── DEBUG-gated details ──────────────────────────────────────────────────────

	[Fact]
	public async Task LoadAsync_Details_GatedByDebugMode()
	{
		await using TestScope scope = await CreateScopeAsync();
		long id = await SeedFactAsync(scope);
		await SeedRawEventAsync(scope, 4688, 10, details: "<Event>secret</Event>");

		SessionTimelineQueryResult normal = await scope.Service.LoadAsync(id, 0, false, debugMode: false, CancellationToken.None);
		SessionTimelineQueryResult debug = await scope.Service.LoadAsync(id, 0, false, debugMode: true, CancellationToken.None);

		Assert.Null(Assert.Single(normal.Slices).Details);
		Assert.Equal("<Event>secret</Event>", Assert.Single(debug.Slices).Details);
	}

	[Fact]
	public async Task LoadAsync_ProcessFileFields_AreProjected()
	{
		await using TestScope scope = await CreateScopeAsync();
		long id = await SeedFactAsync(scope);
		await SeedRawEventAsync(scope, 4688, 10, processName: "cmd.exe", commandLine: "cmd.exe /c whoami");
		await SeedRawEventAsync(scope, 5145, 12, objectName: "C:\\share\\file.txt");

		SessionTimelineQueryResult result = await scope.Service.LoadAsync(id, 0, false, false, CancellationToken.None);

		SessionTimelineRawEventSlice process = result.Slices.Single(s => s.EventId == 4688);
		SessionTimelineRawEventSlice file = result.Slices.Single(s => s.EventId == 5145);
		Assert.Equal("cmd.exe", process.ProcessName);
		Assert.Equal("cmd.exe /c whoami", process.CommandLine);
		Assert.Equal("C:\\share\\file.txt", file.ObjectName);
	}
}
