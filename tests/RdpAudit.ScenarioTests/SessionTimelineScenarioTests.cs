// File:    tests/RdpAudit.ScenarioTests/SessionTimelineScenarioTests.cs
// Module:  RdpAudit.ScenarioTests
// Purpose: Tier 3 end-to-end scenario coverage for Backlog #6 Session Map timeline. Seeds an
//          in-memory SQLite audit database with one full connection fact plus its correlated
//          RawEvents (4624 logon, 4688 process, 4663 object access, 4778/4779 reconnect /
//          disconnect, 4634 logoff), plus adversarial noise (other LogonId, out-of-window),
//          drives the real IPC dispatcher for GetSessionTimeline (72), and asserts the complete
//          lifecycle + activity phases, chronological ordering, explicit correlation-method
//          labels, window/noise filtering, truncation counters and typed NotFound.
// Extends: System.Object
// Author:  RdpAudit Team
// Site:    https://Deynekin.com

using System.Text.Json;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using RdpAudit.Core.Config;
using RdpAudit.Core.Data;
using RdpAudit.Core.Firewall;
using RdpAudit.Core.Ipc;
using RdpAudit.Core.Ipc.Contracts;
using RdpAudit.Core.Models;
using RdpAudit.Core.Sessions;
using RdpAudit.Core.Util;
using RdpAudit.Service;
using RdpAudit.Service.Ipc;
using RdpAudit.Service.Services;
using Xunit;

namespace RdpAudit.ScenarioTests;

/// <summary>End-to-end user scenario for "Open Session Map, select a session, read the timeline":
/// service-side fact + activity become one ordered GetSessionTimeline response without pipes or dialogs.</summary>
public sealed class SessionTimelineScenarioTests
{
	private static readonly DateTime T0 = new(2026, 4, 2, 14, 0, 0, DateTimeKind.Utc);

	private sealed class TestDbContextFactory : IDbContextFactory<AuditDbContext>
	{
		private readonly DbContextOptions<AuditDbContext> _options;

		public TestDbContextFactory(DbContextOptions<AuditDbContext> options) => _options = options;

		public AuditDbContext CreateDbContext() => new(_options);
	}

	private sealed class StaticOptionsMonitor : IOptionsMonitor<RdpAuditOptions>
	{
		private readonly RdpAuditOptions _value;

		public StaticOptionsMonitor(RdpAuditOptions value) => _value = value;

		public RdpAuditOptions CurrentValue => _value;

		public RdpAuditOptions Get(string? name) => _value;

		public IDisposable? OnChange(Action<RdpAuditOptions, string?> listener) => null;
	}

	private static async Task<(IDbContextFactory<AuditDbContext> Factory, SqliteConnection Connection)> CreateDbAsync()
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

		return (new TestDbContextFactory(options), conn);
	}

	private static IpcDispatcher CreateDispatcher(IDbContextFactory<AuditDbContext> factory)
	{
		ServiceMetrics metrics = new();
		StaticOptionsMonitor monitor = new(new RdpAuditOptions());
		SettingsManager settings = new(NullLogger<SettingsManager>.Instance);
		FirewallManager firewall = new(NullLogger<FirewallManager>.Instance);
		return new IpcDispatcher(factory, metrics, monitor, settings, firewall,
			Array.Empty<IFirewallProvider>(), NullLogger<IpcDispatcher>.Instance);
	}

	private static async Task<long> SeedFullSessionAsync(IDbContextFactory<AuditDbContext> factory)
	{
		await using AuditDbContext db = factory.CreateDbContext();

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
			ReconnectedUtc = T0.AddMinutes(9),
			DisconnectedUtc = T0.AddMinutes(12),
			LoggedOffUtc = T0.AddMinutes(20),
			IsActive = false,
		};
		db.RdpConnectionFacts.Add(fact);

		db.RawEvents.Add(new RawEvent { EventId = 4624, Channel = "Security", TimeUtc = T0.AddMinutes(1), LogonId = "0x42A1", UserName = "admin", Domain = "CORP" });
		db.RawEvents.Add(new RawEvent { EventId = 4688, Channel = "Security", TimeUtc = T0.AddMinutes(5), LogonId = "0x42A1", UserName = "admin", Domain = "CORP", ProcessName = "cmd.exe", CommandLine = "cmd.exe /c whoami" });
		db.RawEvents.Add(new RawEvent { EventId = 4663, Channel = "Security", TimeUtc = T0.AddMinutes(6), LogonId = "0x42A1", UserName = "admin", Domain = "CORP", ObjectName = "C:\\share\\x.txt", AccessMask = "0x100080" });
		db.RawEvents.Add(new RawEvent { EventId = 4778, Channel = "Security", TimeUtc = T0.AddMinutes(9), LogonId = "0x42A1", UserName = "admin", Domain = "CORP" });
		db.RawEvents.Add(new RawEvent { EventId = 4779, Channel = "Security", TimeUtc = T0.AddMinutes(12), LogonId = "0x42A1", UserName = "admin", Domain = "CORP" });
		db.RawEvents.Add(new RawEvent { EventId = 4634, Channel = "Security", TimeUtc = T0.AddMinutes(20), LogonId = "0x42A1", UserName = "admin", Domain = "CORP" });

		// Adversarial noise: correct window but different LogonId must never attach.
		db.RawEvents.Add(new RawEvent { EventId = 4688, Channel = "Security", TimeUtc = T0.AddMinutes(7), LogonId = "0x9999", UserName = "admin", Domain = "CORP", ProcessName = "evil.exe" });

		// Out-of-window evidence sharing the same LogonId must never attach.
		db.RawEvents.Add(new RawEvent { EventId = 4688, Channel = "Security", TimeUtc = T0.AddMinutes(50), LogonId = "0x42A1", UserName = "admin", Domain = "CORP", ProcessName = "late.exe" });

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

		return dispatcher.DispatchAsync(
			new IpcRequest { Command = IpcCommand.GetSessionTimeline, Payload = payload },
			CancellationToken.None);
	}

	private static SessionTimelineDto Deserialize(IpcResponse response)
		=> JsonSerializer.Deserialize<SessionTimelineDto>(response.Payload!, JsonOptions.Default)!;

	// ── Scenario 1: happy path - full lifecycle + activity, in order ─────────────────

	[Fact]
	public async Task FullSession_RealDispatcher_ReturnsOrderedLifecycleAndActivity()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		await using (conn)
		{
			long id = await SeedFullSessionAsync(factory);
			IpcDispatcher dispatcher = CreateDispatcher(factory);

			IpcResponse response = await DispatchTimelineAsync(dispatcher, id, includeOther: true);

			Assert.True(response.Success, response.Error);
			SessionTimelineDto timeline = Deserialize(response);
			Assert.Equal(IpcResultStatus.Success, timeline.Status);
			Assert.Equal("203.0.113.42", timeline.Ip);
			Assert.Equal(T0.AddMinutes(1), timeline.StartUtc);
			Assert.Equal(T0.AddMinutes(20), timeline.EndUtc);
			Assert.False(timeline.IsActive);
			Assert.Equal(19 * 60, timeline.DurationSeconds);

			// Lifecycle phases from the fact, in chronological order.
			List<SessionTimelineEventDto> lifecycle = timeline.Events
				.Where(e => e.CorrelationMethod == SessionTimelineCorrelationMethod.Lifecycle)
				.ToList();
			Assert.Equal(new[]
			{
				SessionTimelineEventKind.LogonStart,
				SessionTimelineEventKind.Connected,
				SessionTimelineEventKind.Reconnected,
				SessionTimelineEventKind.Disconnected,
				SessionTimelineEventKind.Logoff,
			}, lifecycle.Select(e => e.Kind).ToArray());

			// Activity nodes with explicit correlation labels.
			SessionTimelineEventDto process = Assert.Single(timeline.Events, e => e.EventId == 4688);
			Assert.Equal(SessionTimelineEventKind.Process, process.Kind);
			Assert.Equal(SessionTimelineCorrelationMethod.LogonId, process.CorrelationMethod);
			Assert.Equal("cmd.exe", process.ProcessName);
			Assert.Equal("cmd.exe /c whoami", process.CommandLine);

			SessionTimelineEventDto file = Assert.Single(timeline.Events, e => e.EventId == 4663);
			Assert.Equal(SessionTimelineEventKind.File, file.Kind);
			Assert.Equal("C:\\share\\x.txt", file.ObjectName);

			// Other (includeOther=true) carries the correlated Security phases.
			Assert.Contains(timeline.Events, e => e.Kind == SessionTimelineEventKind.Other && e.EventId == 4624);

			// Adversarial: wrong LogonId and out-of-window rows never attach.
			Assert.DoesNotContain(timeline.Events, e => e.ProcessName == "evil.exe");
			Assert.DoesNotContain(timeline.Events, e => e.ProcessName == "late.exe");

			// Whole timeline is chronologically stable.
			DateTime[] times = timeline.Events.Select(e => e.TimeUtc).ToArray();
			Assert.Equal(times.OrderBy(t => t), times);

			// TotalMatching counts every correlated in-window candidate (includeOther=true).
			Assert.Equal(6, timeline.TotalMatching);
			Assert.False(timeline.Truncated);
			Assert.Equal(500, timeline.AppliedCap);
		}
	}

	// ── Scenario 2: default hides Other; explicit flag reveals it ────────────────────

	[Fact]
	public async Task DefaultQuery_HidesOtherEvents()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		await using (conn)
		{
			long id = await SeedFullSessionAsync(factory);
			IpcDispatcher dispatcher = CreateDispatcher(factory);

			SessionTimelineDto hidden = Deserialize(await DispatchTimelineAsync(dispatcher, id));
			SessionTimelineDto shown = Deserialize(await DispatchTimelineAsync(dispatcher, id, includeOther: true));

			Assert.DoesNotContain(hidden.Events, e => e.Kind == SessionTimelineEventKind.Other);
			Assert.Contains(shown.Events, e => e.Kind == SessionTimelineEventKind.Other);
			Assert.Equal(2, hidden.TotalMatching); // only 4688 + 4663
			Assert.Equal(6, shown.TotalMatching);
		}
	}

	// ── Scenario 3: bounded + truncation, server-side clamp ───────────────────────────

	[Fact]
	public async Task BusySession_CapIsClampedAndTruncated()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		await using (conn)
		{
			long id = await SeedFullSessionAsync(factory);

			await using (AuditDbContext db = factory.CreateDbContext())
			{
				for (int i = 0; i < 70; i++)
				{
					db.RawEvents.Add(new RawEvent
					{
						EventId = 4688,
						Channel = "Security",
						TimeUtc = T0.AddMinutes(4).AddSeconds(i),
						LogonId = "0x42A1",
						UserName = "admin",
						Domain = "CORP",
						ProcessName = "busy.exe",
					});
				}

				await db.SaveChangesAsync();
			}

			IpcDispatcher dispatcher = CreateDispatcher(factory);
			SessionTimelineDto timeline = Deserialize(await DispatchTimelineAsync(dispatcher, id, cap: 50));

			Assert.Equal(50, timeline.AppliedCap);
			Assert.Equal(72, timeline.TotalMatching); // 4688 + 4663 + 70 busy
			Assert.True(timeline.Truncated);
			Assert.Equal(50, timeline.Events.Count(e => e.CorrelationMethod != SessionTimelineCorrelationMethod.Lifecycle));
		}
	}

	// ── Scenario 4: typed NotFound for an unknown fact ───────────────────────────────

	[Fact]
	public async Task UnknownSession_ReturnsTypedNotFound()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		await using (conn)
		{
			IpcDispatcher dispatcher = CreateDispatcher(factory);

			SessionTimelineDto timeline = Deserialize(await DispatchTimelineAsync(dispatcher, 999_999));

			Assert.Equal(IpcResultStatus.NotFound, timeline.Status);
			Assert.Equal(999_999, timeline.SessionId);
			Assert.NotNull(timeline.Message);
		}
	}
}
