// File:    tests/RdpAudit.Service.Tests/NewProcessRuleTests.cs
// Module:  RdpAudit.Service.Tests
// Purpose: Unit tests for NewProcessRule: event-id gating, baseline-window "new" semantics,
//          system-process silencing, and observation recording into the in-memory SQLite store.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using RdpAudit.Core.Config;
using RdpAudit.Core.Data;
using RdpAudit.Core.Models;
using RdpAudit.Service.Alerts;
using RdpAudit.Service.ProcessMonitoring;
using Xunit;

namespace RdpAudit.Service.Tests;

public class NewProcessRuleTests
{
	private static readonly DateTime StartUtc = new(2026, 9, 12, 10, 0, 0, DateTimeKind.Utc);

	private sealed class TestDbContextFactory : IDbContextFactory<AuditDbContext>
	{
		private readonly DbContextOptions<AuditDbContext> _options;
		public TestDbContextFactory(DbContextOptions<AuditDbContext> options) => _options = options;
		public AuditDbContext CreateDbContext() => new(_options);
	}

	private static async Task<(KnownProcessStore Store, IDbContextFactory<AuditDbContext> Factory, SqliteConnection Conn)> CreateStoreAsync()
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
		return (new KnownProcessStore(factory), factory, conn);
	}

	private static RawEvent ProcessEvent(string processName, string? userName = "alice", string? domain = "TARGET", int? sessionId = 2, long id = 42) =>
		new()
		{
			Id = id,
			EventId = 4688,
			Channel = "Security",
			TimeUtc = StartUtc,
			ProcessName = processName,
			UserName = userName,
			Domain = domain,
			SessionId = sessionId,
		};

	[Fact]
	public async Task RuleId_IsProcessNew()
	{
		(KnownProcessStore store, _, SqliteConnection conn) = await CreateStoreAsync();
		await using (conn.ConfigureAwait(false))
		{
			Assert.Equal("PROCESS_NEW", new NewProcessRule(store).RuleId);
		}
	}

	[Fact]
	public async Task IsEnabled_ReflectsProcessMonitoringEnabled()
	{
		(KnownProcessStore store, _, SqliteConnection conn) = await CreateStoreAsync();
		await using (conn.ConfigureAwait(false))
		{
			var rule = new NewProcessRule(store);
			Assert.True(rule.IsEnabled(new RdpAuditOptions()));
			Assert.False(rule.IsEnabled(new RdpAuditOptions { ProcessMonitoring = new ProcessMonitoringOptions { Enabled = false } }));
		}
	}

	[Fact]
	public async Task WrongEventId_ReturnsNull()
	{
		(KnownProcessStore store, _, SqliteConnection conn) = await CreateStoreAsync();
		await using (conn.ConfigureAwait(false))
		{
			var rule = new NewProcessRule(store);
			RawEvent evt = ProcessEvent("calc.exe");
			evt.EventId = 4624;
			Assert.Null(await rule.EvaluateAsync(evt, new MockAlertContext(), default));
		}
	}

	[Fact]
	public async Task BlankProcessName_ReturnsNull_NoRowsPersisted()
	{
		(KnownProcessStore store, IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateStoreAsync();
		await using (conn.ConfigureAwait(false))
		{
			var rule = new NewProcessRule(store);
			Assert.Null(await rule.EvaluateAsync(ProcessEvent("   "), new MockAlertContext(), default));

			await using AuditDbContext db = await factory.CreateDbContextAsync();
			Assert.Equal(0, await db.KnownProcesses.CountAsync());
			Assert.Equal(0, await db.ProcessObservations.CountAsync());
		}
	}

	[Fact]
	public async Task DisabledMonitoring_ReturnsNull_NoRowsPersisted()
	{
		(KnownProcessStore store, IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateStoreAsync();
		await using (conn.ConfigureAwait(false))
		{
			var options = new RdpAuditOptions { ProcessMonitoring = new ProcessMonitoringOptions { Enabled = false } };
			var ctx = new MockAlertContext(options);
			Assert.Null(await new NewProcessRule(store).EvaluateAsync(ProcessEvent("calc.exe"), ctx, default));

			await using AuditDbContext db = await factory.CreateDbContextAsync();
			Assert.Equal(0, await db.KnownProcesses.CountAsync());
			Assert.Equal(0, await db.ProcessObservations.CountAsync());
		}
	}

	[Fact]
	public async Task FirstObservation_RaisesAlert_AndRecordsObservation()
	{
		(KnownProcessStore store, IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateStoreAsync();
		await using (conn.ConfigureAwait(false))
		{
			RawEvent evt = ProcessEvent("C:\\Temp\\mystery.exe");
			Alert? alert = await new NewProcessRule(store).EvaluateAsync(evt, new MockAlertContext(), default);

			Assert.NotNull(alert);
			Assert.Equal("PROCESS_NEW", alert!.RuleId);
			Assert.Equal(AlertSeverity.High, alert.Severity);
			Assert.Contains("mystery.exe", alert.Message);

			await using AuditDbContext db = await factory.CreateDbContextAsync();
			KnownProcess? baseline = await db.KnownProcesses.AsNoTracking().FirstOrDefaultAsync();
			Assert.NotNull(baseline);
			Assert.Equal("mystery.exe", baseline!.ProcessName);
			Assert.Equal(1, baseline.ObservationCount);

			ProcessObservationRecord? journal = await db.ProcessObservations.AsNoTracking().FirstOrDefaultAsync();
			Assert.NotNull(journal);
			Assert.True(journal!.Alerted);
			Assert.Equal(42, journal.RawEventId);
		}
	}

	[Fact]
	public async Task RecentObservation_WithinWindow_ReturnsNull_CountIncremented()
	{
		(KnownProcessStore store, IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateStoreAsync();
		await using (conn.ConfigureAwait(false))
		{
			var rule = new NewProcessRule(store);
			RawEvent first = ProcessEvent("known.exe");
			Assert.NotNull(await rule.EvaluateAsync(first, new MockAlertContext(), default));

			RawEvent second = ProcessEvent("known.exe", id: 43);
			second.TimeUtc = StartUtc.AddMinutes(10);
			Assert.Null(await rule.EvaluateAsync(second, new MockAlertContext(), default));

			await using AuditDbContext db = await factory.CreateDbContextAsync();
			KnownProcess? baseline = await db.KnownProcesses.AsNoTracking().FirstOrDefaultAsync();
			Assert.NotNull(baseline);
			Assert.Equal(2, baseline!.ObservationCount);
			Assert.Equal(second.TimeUtc, baseline.LastObservedUtc);
		}
	}

	[Fact]
	public async Task StaleObservation_OutsideWindow_RaisesAlertAgain()
	{
		(KnownProcessStore store, _, SqliteConnection conn) = await CreateStoreAsync();
		await using (conn.ConfigureAwait(false))
		{
			var rule = new NewProcessRule(store);
			RawEvent first = ProcessEvent("old.exe");
			first.TimeUtc = StartUtc.AddDays(-30);
			Assert.NotNull(await rule.EvaluateAsync(first, new MockAlertContext(), default));

			RawEvent second = ProcessEvent("old.exe", id: 43);
			second.TimeUtc = StartUtc;
			Alert? stale = await rule.EvaluateAsync(second, new MockAlertContext(), default);
			Assert.NotNull(stale);
			Assert.Equal("PROCESS_NEW", stale!.RuleId);
		}
	}

	[Fact]
	public async Task SystemProcess_WhenSilenced_RecordsButNoAlert()
	{
		(KnownProcessStore store, IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateStoreAsync();
		await using (conn.ConfigureAwait(false))
		{
			var options = new RdpAuditOptions
			{
				ProcessMonitoring = new ProcessMonitoringOptions { EnableAlertOnSystemProcesses = false },
			};
			RawEvent evt = ProcessEvent("svchost.exe", userName: "SYSTEM", domain: null, sessionId: null);

			Assert.Null(await new NewProcessRule(store).EvaluateAsync(evt, new MockAlertContext(options), default));

			await using AuditDbContext db = await factory.CreateDbContextAsync();
			Assert.Equal(1, await db.KnownProcesses.CountAsync());
			ProcessObservationRecord? journal = await db.ProcessObservations.AsNoTracking().FirstOrDefaultAsync();
			Assert.NotNull(journal);
			Assert.False(journal!.Alerted);
		}
	}

	[Fact]
	public async Task SystemProcess_WhenEnabled_RaisesAlert()
	{
		(KnownProcessStore store, _, SqliteConnection conn) = await CreateStoreAsync();
		await using (conn.ConfigureAwait(false))
		{
			RawEvent evt = ProcessEvent("mystery-svc.exe", userName: "SYSTEM", domain: null, sessionId: null);

			Alert? alert = await new NewProcessRule(store).EvaluateAsync(evt, new MockAlertContext(), default);

			Assert.NotNull(alert);
		}
	}

	[Fact]
	public async Task InteractiveVsSystem_AreSeparateBaselineIdentities()
	{
		(KnownProcessStore store, _, SqliteConnection conn) = await CreateStoreAsync();
		await using (conn.ConfigureAwait(false))
		{
			var rule = new NewProcessRule(store);

			Assert.NotNull(await rule.EvaluateAsync(ProcessEvent("shared.exe", userName: "SYSTEM", domain: null, sessionId: null), new MockAlertContext(), default));
			Assert.NotNull(await rule.EvaluateAsync(ProcessEvent("shared.exe", userName: "alice", domain: "TARGET", sessionId: 2, id: 43), new MockAlertContext(), default));
		}
	}
}
