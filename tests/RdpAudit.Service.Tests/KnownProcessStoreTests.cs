// File:    tests/RdpAudit.Service.Tests/KnownProcessStoreTests.cs
// Module:  RdpAudit.Service.Tests
// Purpose: Unit tests for the process-monitoring KnownProcessStore against an in-memory SQLite
//          database matching the Stage16 schema: baseline upsert semantics, observation-journal
//          trimming, fail-closed PROCESS_NEW alert reads and the append-only auto-close lifecycle
//          (arm / cancel / finalize / queued jobs).
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using RdpAudit.Core.Data;
using RdpAudit.Core.Models;
using RdpAudit.Core.ProcessMonitoring;
using RdpAudit.Service.ProcessMonitoring;
using Xunit;

namespace RdpAudit.Service.Tests;

public class KnownProcessStoreTests
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

	private static async Task<long> InsertAlertAsync(
		IDbContextFactory<AuditDbContext> factory,
		string ruleId,
		DateTime timeUtc,
		long triggerEventId = 42)
	{
		await using AuditDbContext db = await factory.CreateDbContextAsync();
		Alert alert = new()
		{
			RuleId = ruleId,
			Severity = AlertSeverity.Medium,
			TimeUtc = timeUtc,
			UserName = "TARGET\\jeff",
			Message = "test alert",
			TriggerEventId = triggerEventId,
		};
		db.Alerts.Add(alert);
		await db.SaveChangesAsync();
		return alert.Id;
	}

	[Fact]
	public async Task FindAsync_EmptyKey_ReturnsNull()
	{
		(KnownProcessStore store, _, SqliteConnection conn) = await CreateStoreAsync();
		await using (conn.ConfigureAwait(false))
		{
			Assert.Null(await store.FindAsync(new KnownProcessKey(string.Empty, ProcessUserCategory.System, string.Empty)));
		}
	}

	[Fact]
	public async Task RecordObservationAsync_EmptyKey_Throws()
	{
		(KnownProcessStore store, _, SqliteConnection conn) = await CreateStoreAsync();
		await using (conn.ConfigureAwait(false))
		{
			await Assert.ThrowsAsync<ArgumentException>(
				async () => await store.RecordObservationAsync(
				new KnownProcessKey(string.Empty, ProcessUserCategory.System, string.Empty), StartUtc, null, 0, false, false, 5000));
		}
	}

	[Fact]
	public async Task RecordObservationAsync_NewKey_CreatesBaselineAndJournal()
	{
		(KnownProcessStore store, IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateStoreAsync();
		await using (conn.ConfigureAwait(false))
		{
			KnownProcessKey key = KnownProcessKey.Build("C:\\Windows\\mystery.exe", null, null);
			long journalId = await store.RecordObservationAsync(key, StartUtc, 1, 700, false, false, 5000);

			Assert.True(journalId > 0);

			KnownProcess? row = await store.FindAsync(key);
			Assert.NotNull(row);
			Assert.Equal("mystery.exe", row!.ProcessName);
			Assert.Equal((int)ProcessUserCategory.System, row.UserCategory);
			Assert.Equal(string.Empty, row.UserName);
			Assert.Equal(1, row.ObservationCount);
			Assert.Equal(StartUtc, row.FirstObservedUtc);
			Assert.Equal(StartUtc, row.LastObservedUtc);
			Assert.Equal(700, row.FirstObservedProcessId);

			await using AuditDbContext db = await factory.CreateDbContextAsync();
			ProcessObservationRecord? journal = await db.ProcessObservations.AsNoTracking()
				.FirstOrDefaultAsync(r => r.Id == journalId);
			Assert.NotNull(journal);
			Assert.Equal("mystery.exe", journal!.ProcessName);
			Assert.Null(journal.UserName);
			Assert.Equal(1, journal.SessionId);
			Assert.Equal(700, journal.RawEventId);
		}
	}

	[Fact]
	public async Task RecordObservationAsync_ExistingKey_UpdatesBaselineCounters()
	{
		(KnownProcessStore store, _, SqliteConnection conn) = await CreateStoreAsync();
		await using (conn.ConfigureAwait(false))
		{
			KnownProcessKey key = KnownProcessKey.Build("narrator.exe", "SYSTEM", null);
			DateTime first = StartUtc;
			DateTime second = StartUtc.AddMinutes(5);

			await store.RecordObservationAsync(key, first, 1, 100, false, false, 5000);
			await store.RecordObservationAsync(key, second, 1, 101, true, false, 5000);

			KnownProcess? row = await store.FindAsync(key);
			Assert.NotNull(row);
			Assert.Equal(2, row!.ObservationCount);
			Assert.Equal(first, row.FirstObservedUtc);
			Assert.Equal(second, row.LastObservedUtc);
			Assert.Equal(100, row.FirstObservedProcessId);
		}
	}

	[Fact]
	public async Task RecordObservationAsync_InteractiveUser_JournalCarriesIdentity()
	{
		(KnownProcessStore store, IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateStoreAsync();
		await using (conn.ConfigureAwait(false))
		{
			KnownProcessKey key = KnownProcessKey.Build("powershell.exe", "Jeff", "TARGET");
			await store.RecordObservationAsync(key, StartUtc, 3, 200, true, false, 5000);

			KnownProcess? row = await store.FindAsync(key);
			Assert.NotNull(row);
			Assert.Equal("target\\jeff", row!.UserName);
			Assert.Equal((int)ProcessUserCategory.Interactive, row.UserCategory);

			await using AuditDbContext db = await factory.CreateDbContextAsync();
			ProcessObservationRecord? journal = await db.ProcessObservations.AsNoTracking()
				.FirstOrDefaultAsync(r => r.ProcessName == "powershell.exe");
			Assert.NotNull(journal);
			Assert.Equal("target\\jeff", journal!.UserName);
			Assert.Equal(3, journal.SessionId);
			Assert.Equal(200, journal.RawEventId);
			Assert.True(journal.Alerted);
			Assert.False(journal.IsForced);
		}
	}

	[Fact]
	public async Task RecordObservationAsync_ForcedReport_MarksJournal()
	{
		(KnownProcessStore store, IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateStoreAsync();
		await using (conn.ConfigureAwait(false))
		{
			KnownProcessKey key = KnownProcessKey.Build("whoami.exe", "Jeff", "TARGET");
			await store.RecordObservationAsync(key, StartUtc, null, 0, false, true, 5000);

			await using AuditDbContext db = await factory.CreateDbContextAsync();
			ProcessObservationRecord? journal = await db.ProcessObservations.AsNoTracking()
				.FirstOrDefaultAsync(r => r.ProcessName == "whoami.exe");
			Assert.NotNull(journal);
			Assert.True(journal!.IsForced);
			Assert.False(journal.Alerted);
			Assert.Equal(0, journal.RawEventId);
			Assert.Null(journal.SessionId);
		}
	}

	[Fact]
	public async Task RecordObservationAsync_TrimmedJournal_DropsOldestRows()
	{
		(KnownProcessStore store, IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateStoreAsync();
		await using (conn.ConfigureAwait(false))
		{
			await using (AuditDbContext db = await factory.CreateDbContextAsync())
			{
				for (int i = 1; i <= 101; i++)
				{
					db.ProcessObservations.Add(new ProcessObservationRecord
					{
						Id = i,
						ObservedUtc = StartUtc.AddSeconds(i),
						ProcessName = "pre" + i + ".exe",
					});
				}

				await db.SaveChangesAsync();
			}

			long newestId = await store.RecordObservationAsync(
				KnownProcessKey.Build("trimtarget.exe", null, null),
				StartUtc.AddSeconds(200),
				null,
				999,
				false,
				false,
				maxObservations: 100);

			Assert.Equal(102, newestId);

			await using (AuditDbContext verify = await factory.CreateDbContextAsync())
			{
				List<ProcessObservationRecord> rows = await verify.ProcessObservations.AsNoTracking()
					.OrderBy(r => r.Id)
					.ToListAsync();
				Assert.Equal(100, rows.Count);
				Assert.Equal(3, rows[0].Id);
				Assert.Equal(102, rows[^1].Id);
			}
		}
	}

	[Fact]
	public async Task GetStatusCountsAsync_AggregatesPersistedState()
	{
		(KnownProcessStore store, IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateStoreAsync();
		await using (conn.ConfigureAwait(false))
		{
			await store.RecordObservationAsync(KnownProcessKey.Build("one.exe", null, null), StartUtc, null, 1, false, false, 5000);
			await store.RecordObservationAsync(KnownProcessKey.Build("two.exe", "Jeff", "TARGET"), StartUtc, 2, 2, true, false, 5000);

			long alertA = await InsertAlertAsync(factory, KnownProcessStore.ProcessNewRuleId, StartUtc.AddMinutes(1));
			long alertB = await InsertAlertAsync(factory, KnownProcessStore.ProcessNewRuleId, StartUtc.AddMinutes(2));
			await InsertAlertAsync(factory, "OTHER_RULE", StartUtc.AddMinutes(3));

			await store.QueueAutoCloseAsync(alertA, 1, StartUtc);
			await store.QueueAutoCloseAsync(alertB, -1, StartUtc);
			DateTime completedAt = StartUtc.AddMinutes(4);
			Assert.True(await store.FinalizeAutoCloseAsync(alertB, ProcessAutoCloseStatus.Completed, "logged off", completedAt));

			KnownProcessStore.ProcessMonitoringCounts counts = await store.GetStatusCountsAsync();
			Assert.Equal(2, counts.KnownProcessCount);
			Assert.Equal(2, counts.ObservationCount);
			Assert.Equal(2, counts.AlertsTotal);
			Assert.Equal(1, counts.AutoClosePending);
			Assert.Equal(1, counts.AutoCloseCompleted);
			Assert.Equal(0, counts.AutoCloseFailed);
			Assert.NotNull(counts.LastAutoCloseUtc);
			Assert.True(Math.Abs((counts.LastAutoCloseUtc!.Value - completedAt).TotalSeconds) < 1);
		}
	}

	[Fact]
	public async Task ListProcessAlertsAsync_ReturnsOnlyProcessNewNewestFirst()
	{
		(KnownProcessStore store, IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateStoreAsync();
		await using (conn.ConfigureAwait(false))
		{
			DateTime t1 = StartUtc.AddMinutes(1);
			DateTime t2 = StartUtc.AddMinutes(2);
			DateTime t3 = StartUtc.AddMinutes(3);
			await InsertAlertAsync(factory, KnownProcessStore.ProcessNewRuleId, t1);
			await InsertAlertAsync(factory, KnownProcessStore.ProcessNewRuleId, t3);
			await InsertAlertAsync(factory, KnownProcessStore.ProcessNewRuleId, t2);
			await InsertAlertAsync(factory, "OTHER_RULE", StartUtc.AddMinutes(4));

			(int total, List<KnownProcessStore.ProcessAlertRow> rows) = await store.ListProcessAlertsAsync(10);

			Assert.Equal(3, total);
			Assert.Equal(3, rows.Count);
			Assert.Equal(t3, rows[0].Alert.TimeUtc);
			Assert.Equal(t2, rows[1].Alert.TimeUtc);
			Assert.Equal(t1, rows[2].Alert.TimeUtc);
			Assert.All(rows, row => Assert.Equal(KnownProcessStore.ProcessNewRuleId, row.Alert.RuleId));
		}
	}

	[Fact]
	public async Task ListProcessAlertsAsync_ZeroLimit_UsesDefault()
	{
		(KnownProcessStore store, IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateStoreAsync();
		await using (conn.ConfigureAwait(false))
		{
			await InsertAlertAsync(factory, KnownProcessStore.ProcessNewRuleId, StartUtc);

			(int total, List<KnownProcessStore.ProcessAlertRow> rows) = await store.ListProcessAlertsAsync(0);

			Assert.Equal(1, total);
			Assert.Single(rows);
		}
	}

	[Fact]
	public async Task GetProcessAlertAsync_UnknownId_ReturnsNull()
	{
		(KnownProcessStore store, _, SqliteConnection conn) = await CreateStoreAsync();
		await using (conn.ConfigureAwait(false))
		{
			Assert.Null(await store.GetProcessAlertAsync(424242));
		}
	}

	[Fact]
	public async Task GetProcessAlertAsync_NonProcessNewAlert_ReturnsNull()
	{
		(KnownProcessStore store, IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateStoreAsync();
		await using (conn.ConfigureAwait(false))
		{
			long foreignId = await InsertAlertAsync(factory, "OTHER_RULE", StartUtc);

			Assert.Null(await store.GetProcessAlertAsync(foreignId));
		}
	}

	[Fact]
	public async Task GetProcessAlertAsync_Existing_ReturnsAlertAndResponse()
	{
		(KnownProcessStore store, IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateStoreAsync();
		await using (conn.ConfigureAwait(false))
		{
			long alertId = await InsertAlertAsync(factory, KnownProcessStore.ProcessNewRuleId, StartUtc);
			await store.QueueAutoCloseAsync(alertId, 7, StartUtc);

			KnownProcessStore.ProcessAlertRow? row = await store.GetProcessAlertAsync(alertId);

			Assert.NotNull(row);
			Assert.Equal(alertId, row!.Alert.Id);
			Assert.NotNull(row.Response);
			Assert.Equal((int)ProcessAutoCloseStatus.Queued, row.Response!.Status);
			Assert.Equal(7, row.Response.SessionId);
		}
	}

	[Fact]
	public async Task QueueAutoCloseAsync_UnknownAlert_NotArmed()
	{
		(KnownProcessStore store, _, SqliteConnection conn) = await CreateStoreAsync();
		await using (conn.ConfigureAwait(false))
		{
			KnownProcessStore.AutoCloseArmOutcome outcome = await store.QueueAutoCloseAsync(999, 1, StartUtc);

			Assert.False(outcome.Armed);
			Assert.False(outcome.AlertFound);
		}
	}

	[Fact]
	public async Task QueueAutoCloseAsync_NewAlert_ArmsOnce()
	{
		(KnownProcessStore store, IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateStoreAsync();
		await using (conn.ConfigureAwait(false))
		{
			long alertId = await InsertAlertAsync(factory, KnownProcessStore.ProcessNewRuleId, StartUtc);

			KnownProcessStore.AutoCloseArmOutcome first = await store.QueueAutoCloseAsync(alertId, -1, StartUtc);
			KnownProcessStore.AutoCloseArmOutcome second = await store.QueueAutoCloseAsync(alertId, -1, StartUtc);

			Assert.True(first.Armed);
			Assert.True(first.AlertFound);
			Assert.False(first.AlreadyQueuedOrFinal);
			Assert.False(second.Armed);
			Assert.True(second.AlreadyQueuedOrFinal);

			ProcessAlertResponse? response = await store.GetResponseAsync(alertId);
			Assert.NotNull(response);
			Assert.Equal((int)ProcessAutoCloseStatus.Queued, response!.Status);
			Assert.Equal(-1, response.SessionId);
			Assert.Null(response.CompletedAtUtc);
		}
	}

	[Fact]
	public async Task CancelAutoCloseAsync_Queued_CancelsWithNote()
	{
		(KnownProcessStore store, IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateStoreAsync();
		await using (conn.ConfigureAwait(false))
		{
			long alertId = await InsertAlertAsync(factory, KnownProcessStore.ProcessNewRuleId, StartUtc);
			await store.QueueAutoCloseAsync(alertId, 2, StartUtc);

			KnownProcessStore.AutoCloseCancelOutcome outcome = await store.CancelAutoCloseAsync(alertId, StartUtc.AddMinutes(1), "testing");

			Assert.True(outcome.Cancelled);
			Assert.True(outcome.AlertFound);
			Assert.False(outcome.WasFinal);

			ProcessAlertResponse? response = await store.GetResponseAsync(alertId);
			Assert.NotNull(response);
			Assert.Equal((int)ProcessAutoCloseStatus.Failed, response!.Status);
			Assert.StartsWith("Cancelled by operator", response.ResultText);
		}
	}

	[Fact]
	public async Task CancelAutoCloseAsync_FinalState_LeftUntouched()
	{
		(KnownProcessStore store, IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateStoreAsync();
		await using (conn.ConfigureAwait(false))
		{
			long alertId = await InsertAlertAsync(factory, KnownProcessStore.ProcessNewRuleId, StartUtc);
			await store.QueueAutoCloseAsync(alertId, 2, StartUtc);
			await store.FinalizeAutoCloseAsync(alertId, ProcessAutoCloseStatus.Completed, "done", StartUtc.AddMinutes(1));

			KnownProcessStore.AutoCloseCancelOutcome outcome = await store.CancelAutoCloseAsync(alertId, StartUtc.AddMinutes(2), "late");

			Assert.False(outcome.Cancelled);
			Assert.True(outcome.WasFinal);

			ProcessAlertResponse? response = await store.GetResponseAsync(alertId);
			Assert.NotNull(response);
			Assert.Equal((int)ProcessAutoCloseStatus.Completed, response!.Status);
			Assert.Equal("done", response.ResultText);
		}
	}

	[Fact]
	public async Task FinalizeAutoCloseAsync_QueuedStatus_Throws()
	{
		(KnownProcessStore store, IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateStoreAsync();
		await using (conn.ConfigureAwait(false))
		{
			long alertId = await InsertAlertAsync(factory, KnownProcessStore.ProcessNewRuleId, StartUtc);
			await store.QueueAutoCloseAsync(alertId, 2, StartUtc);

			await Assert.ThrowsAsync<ArgumentException>(
				async () => await store.FinalizeAutoCloseAsync(alertId, ProcessAutoCloseStatus.Queued, "x", StartUtc));
		}
	}

	[Fact]
	public async Task FinalizeAutoCloseAsync_Queued_TransitionsExactlyOnce()
	{
		(KnownProcessStore store, IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateStoreAsync();
		await using (conn.ConfigureAwait(false))
		{
			long alertId = await InsertAlertAsync(factory, KnownProcessStore.ProcessNewRuleId, StartUtc);
			await store.QueueAutoCloseAsync(alertId, 2, StartUtc);

			bool first = await store.FinalizeAutoCloseAsync(alertId, ProcessAutoCloseStatus.Completed, "ok", StartUtc.AddMinutes(1));
			bool second = await store.FinalizeAutoCloseAsync(alertId, ProcessAutoCloseStatus.Failed, "late overwrite", StartUtc.AddMinutes(2));

			Assert.True(first);
			Assert.False(second);

			ProcessAlertResponse? response = await store.GetResponseAsync(alertId);
			Assert.NotNull(response);
			Assert.Equal((int)ProcessAutoCloseStatus.Completed, response!.Status);
			Assert.Equal("ok", response.ResultText);
		}
	}

	[Fact]
	public async Task GetQueuedAutoCloseJobsAsync_ReturnsOldestFirstWithAlert()
	{
		(KnownProcessStore store, IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateStoreAsync();
		await using (conn.ConfigureAwait(false))
		{
			long alertA = await InsertAlertAsync(factory, KnownProcessStore.ProcessNewRuleId, StartUtc.AddMinutes(1));
			long alertB = await InsertAlertAsync(factory, KnownProcessStore.ProcessNewRuleId, StartUtc.AddMinutes(2));

			await store.QueueAutoCloseAsync(alertA, 2, StartUtc.AddMinutes(-2));
			await store.QueueAutoCloseAsync(alertB, 3, StartUtc.AddMinutes(-1));
			await store.FinalizeAutoCloseAsync(alertA, ProcessAutoCloseStatus.Completed, "done", StartUtc);

			List<KnownProcessStore.QueuedAutoCloseJob> jobs = await store.GetQueuedAutoCloseJobsAsync(5);

			KnownProcessStore.QueuedAutoCloseJob job = Assert.Single(jobs);
			Assert.Equal(alertB, job.Response.AlertId);
			Assert.Equal(alertB, job.Alert.Id);
			Assert.Equal(3, job.Response.SessionId);
		}
	}
}
