// File:    tests/RdpAudit.Service.Tests/ProcessAlertAutoResponderTests.cs
// Module:  RdpAudit.Service.Tests
// Purpose: Unit tests for ProcessAlertAutoResponder against an in-memory SQLite database
//          matching the Stage16 schema. Covers the two pass duties: (1) automatic arming of
//          fresh PROCESS_NEW alerts from their Details JSON session id, gated by
//          ProcessMonitoring.AutoCloseSessionOnNewProcess / SessionControl gates and exempting
//          alerts that already carry a response row; (2) rate-limited execution of queued
//          responses through the real RdpSessionManager wired to a fake external-command
//          runner, including the no-manager, refused-logon and invalid-session-id outcomes.
//          The clock is a fake TimeProvider so window rotation and the per-minute rate cap
//          are deterministic.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using RdpAudit.Core.Config;
using RdpAudit.Core.Data;
using RdpAudit.Core.Models;
using RdpAudit.Core.ProcessMonitoring;
using RdpAudit.Core.Util;
using RdpAudit.Service.ProcessMonitoring;
using RdpAudit.Service.Services;
using RdpAudit.Service.Workers;
using Xunit;

namespace RdpAudit.Service.Tests;

public class ProcessAlertAutoResponderTests
{
	private static readonly DateTime NowUtc = new(2026, 9, 13, 12, 0, 0, DateTimeKind.Utc);

	private sealed class TestDbContextFactory : IDbContextFactory<AuditDbContext>
	{
		private readonly DbContextOptions<AuditDbContext> _options;
		public TestDbContextFactory(DbContextOptions<AuditDbContext> options) => _options = options;
		public AuditDbContext CreateDbContext() => new(_options);
	}

	private sealed class FakeTimeProvider : TimeProvider
	{
		private DateTimeOffset _now = new(NowUtc, TimeSpan.Zero);

		public override DateTimeOffset GetUtcNow() => _now;

		public void Advance(TimeSpan delta) => _now = _now.Add(delta);
	}

	private sealed class StaticMonitor : IOptionsMonitor<RdpAuditOptions>
	{
		public StaticMonitor(RdpAuditOptions value) => CurrentValue = value;
		public RdpAuditOptions CurrentValue { get; }
		public RdpAuditOptions Get(string? name) => CurrentValue;
		public IDisposable? OnChange(Action<RdpAuditOptions, string?> listener) => null;
	}

	private sealed class FakeRunner : IExternalCommandRunner
	{
		public List<string> LogoffArgs { get; } = new();
		public bool NextSuccess { get; set; } = true;
		public string? NextMessage { get; set; }
		public int LogoffCallCount => LogoffArgs.Count;

		public Task<ExternalCommandResult> RunDirectAsync(
			string commandLabel,
			string executable,
			IReadOnlyList<string> arguments,
			TimeSpan timeout,
			CancellationToken ct)
		{
			if (executable == "logoff.exe")
			{
				string captured = arguments.Count == 0 ? string.Empty : arguments[0];
				LogoffArgs.Add(captured);
			}

			return Task.FromResult(new ExternalCommandResult(
				commandLabel,
				executable,
				NextSuccess ? 0 : 1,
				string.Empty,
				NextSuccess ? string.Empty : NextMessage ?? "The session id specified cannot be found.",
				false,
				TimeSpan.Zero,
				false));
		}

		public Task<ExternalCommandResult> RunEnglishConsoleAsync(
			TrustedEnglishConsoleTool tool,
			EnglishConsoleArgs? args,
			TimeSpan timeout,
			CancellationToken ct)
		{
			// The responder must never enumerate sessions - only direct logoff spawns are allowed.
			throw new InvalidOperationException("Responder must not call the English console path.");
		}
	}

	private static async Task<(
		IDbContextFactory<AuditDbContext> Factory,
		KnownProcessStore Store,
		SqliteConnection Conn)> CreateDbAsync()
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
		return (factory, new KnownProcessStore(factory), conn);
	}

	private static async Task<long> InsertAlertAsync(
		IDbContextFactory<AuditDbContext> factory,
		DateTime timeUtc,
		string? detailsJson)
	{
		await using AuditDbContext db = await factory.CreateDbContextAsync();
		Alert alert = new()
		{
			RuleId = KnownProcessStore.ProcessNewRuleId,
			Severity = AlertSeverity.High,
			TimeUtc = timeUtc,
			UserName = "TARGET\\jeff",
			Message = "New process detected",
			Details = detailsJson,
			TriggerEventId = 42,
		};
		db.Alerts.Add(alert);
		await db.SaveChangesAsync();
		return alert.Id;
	}

	private static RdpAuditOptions NewOptions(
		bool processMonitoringEnabled = true,
		bool autoClose = true,
		bool sessionControlEnabled = true,
		bool allowLogoff = true,
		int maxAutoClosePerMinute = 10)
	{
		return new RdpAuditOptions
		{
			ProcessMonitoring = new ProcessMonitoringOptions
			{
				Enabled = processMonitoringEnabled,
				AutoCloseSessionOnNewProcess = autoClose,
				MaxAutoCloseOperationsPerMinute = maxAutoClosePerMinute,
			},
			SessionControl = new SessionControlOptions
			{
				Enabled = sessionControlEnabled,
				AllowLogoff = allowLogoff,
			},
		};
	}

	private static (
		ProcessAlertAutoResponder Responder,
		FakeRunner Runner,
		FakeTimeProvider Time,
		RdpAuditOptions Options) Build(
			KnownProcessStore store,
			IDbContextFactory<AuditDbContext> factory,
			FakeTimeProvider time,
			RdpAuditOptions options,
			bool withSessionManager = true)
	{
		FakeRunner runner = new();
		RdpSessionManager? sessions = withSessionManager
			? new RdpSessionManager(NullLogger<RdpSessionManager>.Instance, runner)
			: null;
		var responder = new ProcessAlertAutoResponder(
			store,
			factory,
			new StaticMonitor(options),
			NullLogger<ProcessAlertAutoResponder>.Instance,
			sessions,
			time);
		return (responder, runner, time, options);
	}

	private static async Task<ProcessAlertResponse?> GetResponseAsync(
		IDbContextFactory<AuditDbContext> factory,
		long alertId)
	{
		await using AuditDbContext db = await factory.CreateDbContextAsync();
		return await db.ProcessAlertResponses.AsNoTracking()
			.FirstOrDefaultAsync(r => r.AlertId == alertId);
	}

	[Fact]
	public async Task RunOnceAsync_ProcessMonitoringDisabled_DoesNothing()
	{
		(IDbContextFactory<AuditDbContext> factory, KnownProcessStore store, SqliteConnection conn) = await CreateDbAsync();
		await using (conn.ConfigureAwait(false))
		{
			long alertId = await InsertAlertAsync(factory, NowUtc, "{\"sessionId\":1}");
			FakeTimeProvider time = new();
			(ProcessAlertAutoResponder responder, FakeRunner runner, _, _) = Build(
				store, factory, time, NewOptions(processMonitoringEnabled: false));

			int finalized = await responder.RunOnceAsync(CancellationToken.None);

			Assert.Equal(0, finalized);
			Assert.Equal(0, runner.LogoffCallCount);
			Assert.Null(await GetResponseAsync(factory, alertId));
		}
	}

	[Fact]
	public async Task RunOnceAsync_FreshAlert_ArmsAndLogsOff()
	{
		(IDbContextFactory<AuditDbContext> factory, KnownProcessStore store, SqliteConnection conn) = await CreateDbAsync();
		await using (conn.ConfigureAwait(false))
		{
			long alertId = await InsertAlertAsync(factory, NowUtc.AddMinutes(-1), "{\"sessionId\":7}");
			FakeTimeProvider time = new();
			(ProcessAlertAutoResponder responder, FakeRunner runner, _, _) = Build(store, factory, time, NewOptions());

			int finalized = await responder.RunOnceAsync(CancellationToken.None);

			Assert.Equal(1, finalized);
			Assert.Single(runner.LogoffArgs);
			Assert.Equal("7", runner.LogoffArgs[0]);
			ProcessAlertResponse? response = await GetResponseAsync(factory, alertId);
			Assert.NotNull(response);
			Assert.Equal(7, response!.SessionId);
			Assert.Equal((int)ProcessAutoCloseStatus.Completed, response.Status);
			Assert.Equal("Session 7 logged off automatically.", response.ResultText);
		}
	}

	[Fact]
	public async Task RunOnceAsync_StaleAlert_IsNotArmed()
	{
		(IDbContextFactory<AuditDbContext> factory, KnownProcessStore store, SqliteConnection conn) = await CreateDbAsync();
		await using (conn.ConfigureAwait(false))
		{
			long alertId = await InsertAlertAsync(factory, NowUtc.AddMinutes(-10), "{\"sessionId\":3}");
			FakeTimeProvider time = new();
			(ProcessAlertAutoResponder responder, FakeRunner runner, _, _) = Build(store, factory, time, NewOptions());

			int finalized = await responder.RunOnceAsync(CancellationToken.None);

			Assert.Equal(0, finalized);
			Assert.Equal(0, runner.LogoffCallCount);
			Assert.Null(await GetResponseAsync(factory, alertId));
		}
	}

	[Theory]
	[InlineData(null)]
	[InlineData("")]
	[InlineData("not-json")]
	[InlineData("{\"sessionId\":-1}")]
	[InlineData("{\"sessionId\":65536}")]
	[InlineData("{\"processName\":\"x.exe\"}")]
	public async Task RunOnceAsync_AlertWithoutValidSession_NeverArmed(string? detailsJson)
	{
		(IDbContextFactory<AuditDbContext> factory, KnownProcessStore store, SqliteConnection conn) = await CreateDbAsync();
		await using (conn.ConfigureAwait(false))
		{
			long alertId = await InsertAlertAsync(factory, NowUtc.AddSeconds(-30), detailsJson);
			FakeTimeProvider time = new();
			(ProcessAlertAutoResponder responder, FakeRunner runner, _, _) = Build(store, factory, time, NewOptions());

			int finalized = await responder.RunOnceAsync(CancellationToken.None);

			Assert.Equal(0, finalized);
			Assert.Equal(0, runner.LogoffCallCount);
			Assert.Null(await GetResponseAsync(factory, alertId));
		}
	}

	[Fact]
	public async Task RunOnceAsync_AlertWithExistingResponse_IsNotReArmed()
	{
		(IDbContextFactory<AuditDbContext> factory, KnownProcessStore store, SqliteConnection conn) = await CreateDbAsync();
		await using (conn.ConfigureAwait(false))
		{
			long alertId = await InsertAlertAsync(factory, NowUtc.AddSeconds(-30), "{\"sessionId\":4}");
			await store.QueueAutoCloseAsync(alertId, 4, NowUtc.AddSeconds(-40));
			await store.FinalizeAutoCloseAsync(alertId, ProcessAutoCloseStatus.Completed, "operator test", NowUtc.AddSeconds(-30));
			long queuedAlertId = await InsertAlertAsync(factory, NowUtc.AddSeconds(-20), "{\"sessionId\":5}");
			await store.QueueAutoCloseAsync(queuedAlertId, 5, NowUtc);
			FakeTimeProvider time = new();
			(ProcessAlertAutoResponder responder, FakeRunner runner, _, _) = Build(store, factory, time, NewOptions());

			int finalized = await responder.RunOnceAsync(CancellationToken.None);

			// Only the previously queued job is finalised; the completed response was not re-armed.
			Assert.Equal(1, finalized);
			Assert.Single(runner.LogoffArgs);
			Assert.Equal("5", runner.LogoffArgs[0]);
			ProcessAlertResponse? first = await GetResponseAsync(factory, alertId);
			Assert.Equal((int)ProcessAutoCloseStatus.Completed, first!.Status);
			Assert.Equal("operator test", first.ResultText);
		}
	}

	[Fact]
	public async Task RunOnceAsync_AutoCloseOff_ManualJobsStillExecute()
	{
		(IDbContextFactory<AuditDbContext> factory, KnownProcessStore store, SqliteConnection conn) = await CreateDbAsync();
		await using (conn.ConfigureAwait(false))
		{
			long freshAlertId = await InsertAlertAsync(factory, NowUtc.AddSeconds(-30), "{\"sessionId\":6}");
			long manualAlertId = await InsertAlertAsync(factory, NowUtc.AddSeconds(-20), "{\"sessionId\":9}");
			await store.QueueAutoCloseAsync(manualAlertId, 9, NowUtc);
			FakeTimeProvider time = new();
			(ProcessAlertAutoResponder responder, FakeRunner runner, _, _) = Build(
				store, factory, time, NewOptions(autoClose: false));

			int finalized = await responder.RunOnceAsync(CancellationToken.None);

			Assert.Equal(1, finalized);
			Assert.Equal("9", runner.LogoffArgs[0]);
			Assert.Null(await GetResponseAsync(factory, freshAlertId));
		}
	}

	[Theory]
	[InlineData(false, true)]
	[InlineData(true, false)]
	public async Task RunOnceAsync_SessionControlGatesClosed_DefersBothDuties(bool controlEnabled, bool allowLogoff)
	{
		(IDbContextFactory<AuditDbContext> factory, KnownProcessStore store, SqliteConnection conn) = await CreateDbAsync();
		await using (conn.ConfigureAwait(false))
		{
			long freshAlertId = await InsertAlertAsync(factory, NowUtc.AddSeconds(-30), "{\"sessionId\":8}");
			FakeTimeProvider time = new();
			(ProcessAlertAutoResponder responder, FakeRunner runner, _, _) = Build(
				store, factory, time, NewOptions(sessionControlEnabled: controlEnabled, allowLogoff: allowLogoff));

			int finalized = await responder.RunOnceAsync(CancellationToken.None);

			Assert.Equal(0, finalized);
			Assert.Equal(0, runner.LogoffCallCount);
			Assert.Null(await GetResponseAsync(factory, freshAlertId));
		}
	}

	[Fact]
	public async Task RunOnceAsync_QueuedJobWithInvalidSession_IsFailedWithoutLogoff()
	{
		(IDbContextFactory<AuditDbContext> factory, KnownProcessStore store, SqliteConnection conn) = await CreateDbAsync();
		await using (conn.ConfigureAwait(false))
		{
			long alertId = await InsertAlertAsync(factory, NowUtc, "{\"sessionId\":2}");
			await store.QueueAutoCloseAsync(alertId, -1, NowUtc);
			FakeTimeProvider time = new();
			(ProcessAlertAutoResponder responder, FakeRunner runner, _, _) = Build(store, factory, time, NewOptions());

			int finalized = await responder.RunOnceAsync(CancellationToken.None);

			Assert.Equal(1, finalized);
			Assert.Equal(0, runner.LogoffCallCount);
			ProcessAlertResponse? response = await GetResponseAsync(factory, alertId);
			Assert.Equal((int)ProcessAutoCloseStatus.Failed, response!.Status);
			Assert.Contains("no valid target session id", response.ResultText, StringComparison.Ordinal);
		}
	}

	[Fact]
	public async Task RunOnceAsync_NoSessionManager_QueuedJobFailed()
	{
		(IDbContextFactory<AuditDbContext> factory, KnownProcessStore store, SqliteConnection conn) = await CreateDbAsync();
		await using (conn.ConfigureAwait(false))
		{
			long alertId = await InsertAlertAsync(factory, NowUtc, "{\"sessionId\":1}");
			await store.QueueAutoCloseAsync(alertId, 1, NowUtc);
			FakeTimeProvider time = new();
			(ProcessAlertAutoResponder responder, _, _, _) = Build(
				store, factory, time, NewOptions(), withSessionManager: false);

			int finalized = await responder.RunOnceAsync(CancellationToken.None);

			Assert.Equal(1, finalized);
			ProcessAlertResponse? response = await GetResponseAsync(factory, alertId);
			Assert.Equal((int)ProcessAutoCloseStatus.Failed, response!.Status);
			Assert.Contains("session manager is unavailable", response.ResultText, StringComparison.Ordinal);
		}
	}

	[Fact]
	public async Task RunOnceAsync_LogoffRefused_QueuedJobFailedWithDiagnostic()
	{
		(IDbContextFactory<AuditDbContext> factory, KnownProcessStore store, SqliteConnection conn) = await CreateDbAsync();
		await using (conn.ConfigureAwait(false))
		{
			long alertId = await InsertAlertAsync(factory, NowUtc, "{\"sessionId\":12}");
			await store.QueueAutoCloseAsync(alertId, 12, NowUtc);
			FakeTimeProvider time = new();
			(ProcessAlertAutoResponder responder, FakeRunner runner, _, _) = Build(store, factory, time, NewOptions());
			runner.NextSuccess = false;
			runner.NextMessage = "The session id specified cannot be found.";

			int finalized = await responder.RunOnceAsync(CancellationToken.None);

			Assert.Equal(1, finalized);
			Assert.Equal("12", runner.LogoffArgs[0]);
			ProcessAlertResponse? response = await GetResponseAsync(factory, alertId);
			Assert.Equal((int)ProcessAutoCloseStatus.Failed, response!.Status);
			Assert.Contains("The session id specified cannot be found.", response.ResultText, StringComparison.Ordinal);
		}
	}

	[Fact]
	public async Task RunOnceAsync_RateLimit_PausesBeyondCapAndRotatesWindow()
	{
		(IDbContextFactory<AuditDbContext> factory, KnownProcessStore store, SqliteConnection conn) = await CreateDbAsync();
		await using (conn.ConfigureAwait(false))
		{
			FakeTimeProvider time = new();
			int[] sessions = { 21, 22, 23, 24, 25 };
			foreach (int sid in sessions)
			{
				long alertId = await InsertAlertAsync(factory, NowUtc, "{\"sessionId\":" + sid + "}");
				await store.QueueAutoCloseAsync(alertId, sid, NowUtc);
			}

			int maxPerMinute = 2;
			(ProcessAlertAutoResponder responder, FakeRunner runner, _, _) = Build(
				store, factory, time, NewOptions(maxAutoClosePerMinute: maxPerMinute));

			int firstPass = await responder.RunOnceAsync(CancellationToken.None);
			time.Advance(TimeSpan.FromSeconds(61));
			int secondPass = await responder.RunOnceAsync(CancellationToken.None);

			Assert.Equal(maxPerMinute, firstPass);
			Assert.Equal(maxPerMinute, secondPass);
			Assert.Equal(4, runner.LogoffCallCount);
			int remainingQueued = 0;
			await using (AuditDbContext db = await factory.CreateDbContextAsync())
			{
				remainingQueued = await db.ProcessAlertResponses
					.CountAsync(r => r.Status == (int)ProcessAutoCloseStatus.Queued);
			}

			Assert.Equal(sessions.Length - 2 * maxPerMinute, remainingQueued);
		}
	}
}
