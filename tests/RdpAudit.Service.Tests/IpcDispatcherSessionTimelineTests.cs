// File:    tests/RdpAudit.Service.Tests/IpcDispatcherSessionTimelineTests.cs
// Module:  RdpAudit.Service.Tests
// Purpose: End-to-end IPC dispatcher coverage for Backlog #6 (GetSessionTimeline, ordinal 72):
//          full-cycle success shape (lifecycle + process/file nodes with correlation labels),
//          unknown fact id typed NotFound, empty fact without activity, server-side cap clamping,
//          IncludeOtherEvents filtering, controlled JSON errors and MessagePack round-trips for
//          the new request/response contracts.
// Depends: IpcDispatcher, SessionTimelineDto, AuditDbContext, xunit
// Extends: Add a test whenever the timeline DTO keys or the correlation rules change.

using System.Text.Json;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using MessagePack;
using RdpAudit.Core.Config;
using RdpAudit.Core.Data;
using RdpAudit.Core.Firewall;
using RdpAudit.Core.Ipc;
using RdpAudit.Core.Ipc.Contracts;
using RdpAudit.Core.Models;
using RdpAudit.Core.Sessions;
using RdpAudit.Core.Util;
using RdpAudit.Service.Ipc;
using RdpAudit.Service.Services;
using Xunit;

namespace RdpAudit.Service.Tests;

public sealed class IpcDispatcherSessionTimelineTests
{
	private static readonly DateTime T0 = new(2026, 3, 1, 10, 0, 0, DateTimeKind.Utc);

	private sealed class TestDbContextFactory : IDbContextFactory<AuditDbContext>
	{
		private readonly DbContextOptions<AuditDbContext> _options;
		public TestDbContextFactory(DbContextOptions<AuditDbContext> options) => _options = options;
		public AuditDbContext CreateDbContext() => new(_options);
	}

	private sealed class StaticOptionsMonitorLocal<T> : IOptionsMonitor<T>
	{
		public StaticOptionsMonitorLocal(T value) => CurrentValue = value;
		public T CurrentValue { get; }
		public T Get(string? name) => CurrentValue;
		public IDisposable? OnChange(Action<T, string?> listener) => null;
	}

	private sealed class TestScope : IAsyncDisposable
	{
		public SqliteConnection Connection { get; }
		public IDbContextFactory<AuditDbContext> Factory { get; }
		public IpcDispatcher Dispatcher { get; }

		public TestScope(SqliteConnection conn, IDbContextFactory<AuditDbContext> factory, IpcDispatcher dispatcher)
		{
			Connection = conn;
			Factory = factory;
			Dispatcher = dispatcher;
		}

		public async ValueTask DisposeAsync() => await Connection.DisposeAsync();
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

		IDbContextFactory<AuditDbContext> factory = new TestDbContextFactory(options);
		ServiceMetrics metrics = new();
		StaticOptionsMonitorLocal<RdpAuditOptions> mon = new(new RdpAuditOptions());
		SettingsManager settings = new(NullLogger<SettingsManager>.Instance);
		FirewallManager manager = new(NullLogger<FirewallManager>.Instance);
		IpcDispatcher dispatcher = new(factory, metrics, mon, settings, manager,
			Array.Empty<IFirewallProvider>(), NullLogger<IpcDispatcher>.Instance);

		return new TestScope(conn, factory, dispatcher);
	}

	private static async Task<long> SeedFullSessionAsync(TestScope scope)
	{
		await using AuditDbContext db = scope.Factory.CreateDbContext();
		RdpConnectionFact fact = new()
		{
			Ip = "203.0.113.42",
			UserName = "admin",
			Domain = "CORP",
			LogonId = "0x42A1",
			WtsSessionId = 7,
			FirstSeenUtc = T0,
			LastSeenUtc = T0.AddMinutes(20),
			AuthenticatedUtc = T0.AddMinutes(1),
			ConnectedUtc = T0.AddMinutes(2),
			DisconnectedUtc = T0.AddMinutes(12),
			LoggedOffUtc = T0.AddMinutes(20),
			IsActive = false,
		};
		db.RdpConnectionFacts.Add(fact);

		db.RawEvents.Add(new RawEvent { EventId = 4688, Channel = "Security", TimeUtc = T0.AddMinutes(5), LogonId = "0x42A1", UserName = "admin", Domain = "CORP", ProcessName = "cmd.exe", CommandLine = "cmd.exe /c whoami" });
		db.RawEvents.Add(new RawEvent { EventId = 5145, Channel = "Security", TimeUtc = T0.AddMinutes(8), LogonId = "0x42A1", UserName = "admin", Domain = "CORP", ObjectName = "C:\\share\\x.txt" });
		db.RawEvents.Add(new RawEvent { EventId = 4624, Channel = "Security", TimeUtc = T0.AddMinutes(1), LogonId = "0x42A1", UserName = "admin", Domain = "CORP" });
		await db.SaveChangesAsync();
		return fact.Id;
	}

	private static Task<IpcResponse> DispatchTimelineAsync(IpcDispatcher dispatcher, long sessionId, int cap = 0, bool includeOther = false)
	{
		string payload = JsonSerializer.Serialize(new GetSessionTimelineRequest
		{
			SessionId = sessionId,
			ActivityCap = cap,
			IncludeOtherEvents = includeOther,
		}, JsonOptions.Default);

		return dispatcher.DispatchAsync(new IpcRequest { Command = IpcCommand.GetSessionTimeline, Payload = payload }, CancellationToken.None);
	}

	private static SessionTimelineDto Deserialize(IpcResponse response)
		=> JsonSerializer.Deserialize<SessionTimelineDto>(response.Payload!, JsonOptions.Default)!;

	// ── Success paths ────────────────────────────────────────────────────────────

	[Fact]
	public async Task GetSessionTimeline_FullCycle_ContainsLifecycleAndActivityInOrder()
	{
		await using TestScope scope = await CreateScopeAsync();
		long id = await SeedFullSessionAsync(scope);

		IpcResponse response = await DispatchTimelineAsync(scope.Dispatcher, id);

		Assert.True(response.Success, response.Error);
		SessionTimelineDto dto = Deserialize(response);
		Assert.Equal(IpcResultStatus.Success, dto.Status);
		Assert.Equal(id, dto.SessionId);
		Assert.Equal("203.0.113.42", dto.Ip);
		Assert.Equal("admin", dto.UserName);
		Assert.Equal(T0.AddMinutes(1), dto.StartUtc);
		Assert.Equal(T0.AddMinutes(20), dto.EndUtc);
		Assert.False(dto.IsActive);

		List<SessionTimelineEventKind> kinds = dto.Events.Select(e => e.Kind).ToList();
		Assert.Equal(new[]
		{
			SessionTimelineEventKind.LogonStart,
			SessionTimelineEventKind.Connected,
			SessionTimelineEventKind.Process,
			SessionTimelineEventKind.File,
			SessionTimelineEventKind.Disconnected,
			SessionTimelineEventKind.Logoff,
		}, kinds);

		SessionTimelineEventDto process = dto.Events.Single(e => e.Kind == SessionTimelineEventKind.Process);
		Assert.Equal(SessionTimelineCorrelationMethod.LogonId, process.CorrelationMethod);
		Assert.Equal("cmd.exe", process.ProcessName);
		Assert.Equal("cmd.exe /c whoami", process.CommandLine);

		SessionTimelineEventDto file = dto.Events.Single(e => e.Kind == SessionTimelineEventKind.File);
		Assert.Equal("C:\\share\\x.txt", file.ObjectName);
		Assert.Equal(2, dto.TotalMatching);
	}

	[Fact]
	public async Task GetSessionTimeline_EmptyFactWithoutActivity_ReturnsNormalResponse()
	{
		await using TestScope scope = await CreateScopeAsync();
		long id = await SeedFullSessionAsync(scope);
		// Use a session id with no events at all: seed a bare fact.
		await using (AuditDbContext db = scope.Factory.CreateDbContext())
		{
			RdpConnectionFact bare = new()
			{
				Ip = "198.51.100.7",
				UserName = "bob",
				Domain = "CORP",
				LogonId = "0xB0B",
				FirstSeenUtc = T0.AddHours(-1),
				LastSeenUtc = T0.AddMinutes(-30),
				LoggedOffUtc = T0.AddMinutes(-30),
				IsActive = false,
			};
			db.RdpConnectionFacts.Add(bare);
			await db.SaveChangesAsync();

			IpcResponse response = await DispatchTimelineAsync(scope.Dispatcher, bare.Id);
			Assert.True(response.Success, response.Error);
			SessionTimelineDto dto = Deserialize(response);
			Assert.Equal(IpcResultStatus.Success, dto.Status);
			Assert.DoesNotContain(dto.Events, e => e.CorrelationMethod != SessionTimelineCorrelationMethod.Lifecycle);
			Assert.Equal(0, dto.TotalMatching);
			Assert.False(dto.Truncated);
		}
	}

	[Fact]
	public async Task GetSessionTimeline_UnknownFactId_ReturnsTypedNotFound()
	{
		await using TestScope scope = await CreateScopeAsync();

		IpcResponse response = await DispatchTimelineAsync(scope.Dispatcher, 999_999);

		Assert.True(response.Success, response.Error);
		SessionTimelineDto dto = Deserialize(response);
		Assert.Equal(IpcResultStatus.NotFound, dto.Status);
		Assert.Equal(999_999, dto.SessionId);
		Assert.NotNull(dto.Message);
	}

	// ── Cap clamping + IncludeOtherEvents ────────────────────────────────────────

	[Theory]
	[InlineData(0, 500)]
	[InlineData(1, 50)]
	[InlineData(99_999, 2000)]
	[InlineData(300, 300)]
	public async Task GetSessionTimeline_ActivityCap_IsClampedServerSide(int requested, int expected)
	{
		await using TestScope scope = await CreateScopeAsync();
		long id = await SeedFullSessionAsync(scope);

		IpcResponse response = await DispatchTimelineAsync(scope.Dispatcher, id, cap: requested);

		SessionTimelineDto dto = Deserialize(response);
		Assert.Equal(expected, dto.AppliedCap);
	}

	[Fact]
	public async Task GetSessionTimeline_OtherEvents_HiddenByDefault()
	{
		await using TestScope scope = await CreateScopeAsync();
		long id = await SeedFullSessionAsync(scope);

		IpcResponse hiddenResp = await DispatchTimelineAsync(scope.Dispatcher, id, includeOther: false);
		IpcResponse shownResp = await DispatchTimelineAsync(scope.Dispatcher, id, includeOther: true);

		SessionTimelineDto hidden = Deserialize(hiddenResp);
		SessionTimelineDto shown = Deserialize(shownResp);
		Assert.DoesNotContain(hidden.Events, e => e.Kind == SessionTimelineEventKind.Other);
		Assert.Contains(shown.Events, e => e.Kind == SessionTimelineEventKind.Other
			&& e.EventId == 4624);
	}

	// ── Controlled request errors ────────────────────────────────────────────────

	[Fact]
	public async Task GetSessionTimeline_MissingPayload_FailsControlled()
	{
		await using TestScope scope = await CreateScopeAsync();

		IpcResponse response = await scope.Dispatcher.DispatchAsync(
			new IpcRequest { Command = IpcCommand.GetSessionTimeline, Payload = null },
			CancellationToken.None);

		Assert.False(response.Success);
		Assert.Contains("payload", response.Error, StringComparison.OrdinalIgnoreCase);
	}

	// ── MessagePack round-trips ──────────────────────────────────────────────────

	[Fact]
	public void MessagePack_SessionTimelineDtos_RoundTrip()
	{
		GetSessionTimelineRequest request = new() { SessionId = 77, ActivityCap = 120, IncludeOtherEvents = true };
		SessionTimelineDto dto = new()
		{
			Status = IpcResultStatus.Success,
			QueriedUtc = T0,
			SessionId = 77,
			Ip = "203.0.113.42",
			UserName = "admin",
			Domain = "CORP",
			WtsSessionId = 7,
			LogonId = "0x42A1",
			StartUtc = T0,
			EndUtc = T0.AddMinutes(20),
			IsActive = false,
			DurationSeconds = 1200,
			TotalMatching = 3,
			Truncated = false,
			AppliedCap = 500,
			Message = "ok",
		};
		dto.Events.Add(new SessionTimelineEventDto
		{
			TimeUtc = T0.AddMinutes(5),
			Kind = SessionTimelineEventKind.Process,
			EventId = 4688,
			Channel = "Security",
			CorrelationMethod = SessionTimelineCorrelationMethod.LogonId,
			ProcessName = "cmd.exe",
			CommandLine = "cmd.exe /c whoami",
		});

		byte[] reqBytes = MessagePackSerializer.Serialize(request);
		byte[] dtoBytes = MessagePackSerializer.Serialize(dto);
		GetSessionTimelineRequest reqBack = MessagePackSerializer.Deserialize<GetSessionTimelineRequest>(reqBytes);
		SessionTimelineDto dtoBack = MessagePackSerializer.Deserialize<SessionTimelineDto>(dtoBytes);

		Assert.Equal(77, reqBack.SessionId);
		Assert.Equal(120, reqBack.ActivityCap);
		Assert.True(reqBack.IncludeOtherEvents);
		Assert.Equal(dto.SessionId, dtoBack.SessionId);
		Assert.Equal(dto.Status, dtoBack.Status);
		Assert.Equal(dto.AppliedCap, dtoBack.AppliedCap);
		Assert.Single(dtoBack.Events);
		Assert.Equal(SessionTimelineEventKind.Process, dtoBack.Events[0].Kind);
		Assert.Equal("cmd.exe", dtoBack.Events[0].ProcessName);
	}
}
