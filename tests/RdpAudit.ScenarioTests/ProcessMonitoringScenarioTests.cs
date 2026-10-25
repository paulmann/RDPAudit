// File:    tests/RdpAudit.ScenarioTests/ProcessMonitoringScenarioTests.cs
// Module:  RdpAudit.ScenarioTests
// Purpose: Tier 3 end-to-end scenario coverage for the process-monitoring feature (PROCESS_NEW
//          detection + optional automated session close). Walks the feature the way an operator
//          would: a Security 4688 process-creation event reaches the persisted baseline, the new
//          process appears as a red-highlighted live event and as a PROCESS_NEW alert in the
//          alert list, the operator arms an automated session close for the alert, the responder
//          executes one real logoff through the RdpSessionManager pipeline, and the status
//          dashboard reflects the persisted counters. Drive real services over an in-memory
//          SQLite database - no pipes, no dialogs, no external processes
//          The missing session manager is a documented fail-closed responder path, not a missed assertion.
// Depends: RdpAudit.Core (models, IPC contracts, options), RdpAudit.Service (dispatcher, store,
//          rule, responder), xunit
// Extends: Add a scenario here whenever the process-monitoring operator flow gains a new step.

using System.Text.Json;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using RdpAudit.Core.Config;
using RdpAudit.Core.Data;
using RdpAudit.Core.Events;
using RdpAudit.Core.Firewall;
using RdpAudit.Core.Ipc;
using RdpAudit.Core.Ipc.Contracts;
using RdpAudit.Core.Models;
using RdpAudit.Core.ProcessMonitoring;
using RdpAudit.Core.Util;
using RdpAudit.Service;
using RdpAudit.Service.Alerts;
using RdpAudit.Service.Ipc;
using RdpAudit.Service.ProcessMonitoring;
using RdpAudit.Service.Services;
using RdpAudit.Service.Workers;
using Xunit;

namespace RdpAudit.ScenarioTests;

/// <summary>End-to-end operator scenarios for the process-monitoring feature: detection, live
/// highlight, alert list, automated session close and the status dashboard.</summary>
public sealed class ProcessMonitoringScenarioTests
{
	private static readonly DateTime NowUtc = new(2026, 9, 13, 12, 0, 0, DateTimeKind.Utc);

	private sealed class TestDbContextFactory : IDbContextFactory<AuditDbContext>
	{
		private readonly DbContextOptions<AuditDbContext> _options;

		public TestDbContextFactory(DbContextOptions<AuditDbContext> options) => _options = options;

		public AuditDbContext CreateDbContext() => new(_options);
	}

	private sealed class StaticMonitor : IOptionsMonitor<RdpAuditOptions>
	{
		public StaticMonitor(RdpAuditOptions value) => CurrentValue = value;

		public RdpAuditOptions CurrentValue { get; }

		public RdpAuditOptions Get(string? name) => CurrentValue;

		public IDisposable? OnChange(Action<RdpAuditOptions, string?> listener) => null;
	}

	private sealed class FakeTimeProvider : TimeProvider
	{
		private DateTimeOffset _now = new(NowUtc, TimeSpan.Zero);

		public override DateTimeOffset GetUtcNow() => _now;
	}

	private static async Task<(IDbContextFactory<AuditDbContext> Factory, SqliteConnection Conn)> CreateDbAsync()
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

	private static RdpAuditOptions NewOptions(
		bool enabled = true,
		bool autoClose = false,
		bool alertSystem = true,
		bool allowLogoff = true) => new()
	{
		ProcessMonitoring = new ProcessMonitoringOptions
		{
			Enabled = enabled,
			AlertWindowDays = 7,
			MaxObservations = 5000,
			AutoCloseSessionOnNewProcess = autoClose,
			EnableAlertOnSystemProcesses = alertSystem,
		},
		SessionControl = new SessionControlOptions
		{
			Enabled = true,
			AllowLogoff = allowLogoff,
		},
	};

	private static IpcDispatcher CreateDispatcher(
		IDbContextFactory<AuditDbContext> factory,
		RdpAuditOptions options,
		KnownProcessStore store)
	{
		StaticMonitor monitor = new(options);
		return new IpcDispatcher(
			factory,
			new ServiceMetrics(),
			monitor,
			new SettingsManager(NullLogger<SettingsManager>.Instance),
			new FirewallManager(NullLogger<FirewallManager>.Instance),
			Array.Empty<IFirewallProvider>(),
			NullLogger<IpcDispatcher>.Instance,
			processStore: store);
	}

	private static async Task<T> CallAsync<T>(IpcDispatcher dispatcher, IpcCommand command, object? payload = null)
	{
		IpcRequest req = new()
		{
			Command = command,
			Payload = payload is null ? null : JsonSerializer.Serialize(payload, JsonOptions.Default),
		};
		IpcResponse response = await dispatcher.DispatchAsync(req, CancellationToken.None);
		Assert.True(response.Success, response.Error);
		Assert.NotNull(response.Payload);
		T? dto = JsonSerializer.Deserialize<T>(response.Payload!, JsonOptions.Default);
		Assert.NotNull(dto);
		return dto!;
	}

	// ── Scenario 1: operator sees a new process from 4688 to the highlighted live tail ──────

	[Fact]
	public async Task NewProcessEvent_FlowsFrom4688ToHighlightedLiveTailAndAlertList()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		await using (conn.ConfigureAwait(false))
		{
			RdpAuditOptions options = NewOptions();
			KnownProcessStore store = new(factory);

			// Given: one unknown interactive process creation (4688) plus a known, unrelated
			// process creation that must never be highlighted or alerted.
			long flaggedEventId;
			long knownEventId;
			await using (AuditDbContext db = await factory.CreateDbContextAsync())
			{
				RawEvent unknown = new()
				{
					EventId = 4688,
					Channel = "Security",
					TimeUtc = NowUtc.AddMinutes(-1),
					UserName = "bob",
					Domain = "CORP",
					SessionId = 5,
					ProcessName = @"C:\Users\bob\Downloads\stealer.exe",
				};
				db.RawEvents.Add(unknown);
				db.RawEvents.Add(new RawEvent
				{
					EventId = 4688,
					Channel = "Security",
					TimeUtc = NowUtc.AddMinutes(-2),
					UserName = "bob",
					Domain = "CORP",
					SessionId = 5,
					ProcessName = "notepad.exe",
				});
				await db.SaveChangesAsync();
				flaggedEventId = unknown.Id;
				knownEventId = (await db.RawEvents.AsNoTracking()
					.SingleAsync(e => e.ProcessName == "notepad.exe")).Id;
			}

			// When: the real alert rule evaluates the unknown process through the DB-backed
			// baseline (exactly what AlertWorker does) and persists the alert.
			NewProcessRule rule = new(store);
			DbAlertContext context = new(factory, new StaticMonitor(options));
			RawEvent evt;
			await using (AuditDbContext db = await factory.CreateDbContextAsync())
			{
				evt = await db.RawEvents.AsNoTracking().SingleAsync(e => e.Id == flaggedEventId);
			}

			Alert? alert = await rule.EvaluateAsync(evt, context, CancellationToken.None);
			Assert.NotNull(alert);
			Assert.Equal("PROCESS_NEW", alert!.RuleId);
			Assert.Equal(AlertSeverity.High, alert.Severity);
			Assert.Equal(flaggedEventId, alert.TriggerEventId);
			await using (AuditDbContext db = await factory.CreateDbContextAsync())
			{
				db.Alerts.Add(alert);
				await db.SaveChangesAsync();
			}

			IpcDispatcher dispatcher = CreateDispatcher(factory, options, store);

			// Then: GetRecentEvents highlights exactly the flagged 4688 row.
			List<RecentEventDto> live = await CallAsync<List<RecentEventDto>>(dispatcher, IpcCommand.GetRecentEvents);
			RecentEventDto flagged = live.Single(e => e.Id == flaggedEventId);
			RecentEventDto known = live.Single(e => e.Id == knownEventId);
			Assert.True(flagged.IsProcessNew, "the flagged event must carry the red live highlight");
			Assert.False(known.IsProcessNew, "a known process must never be highlighted");

			// And: the operator-facing alert list carries the same evidence, newest first.
			ProcessAlertListDto list = await CallAsync<ProcessAlertListDto>(
				dispatcher, IpcCommand.ListProcessAlerts, new ListProcessAlertsRequest { Limit = 10 });
			Assert.Equal(IpcResultStatus.Success, list.Status);
			ProcessAlertDto item = Assert.Single(list.Items);
			Assert.Equal("stealer.exe", item.ProcessName);
			Assert.Equal(5, item.SessionId);
			Assert.Equal("bob", item.UserName);
			Assert.False(item.AutoCloseEnabled);
			Assert.False(item.Acknowledged);

			// And: the dedicated endpoint exposes the forensic details the list hides.
			ProcessAlertDetailsDto details = await CallAsync<ProcessAlertDetailsDto>(
				dispatcher, IpcCommand.GetProcessAlertDetails, new GetProcessAlertDetailsRequest { AlertId = item.Id });
			Assert.Equal(IpcResultStatus.Success, details.Status);
			Assert.NotNull(details.DetailsJson);
			using JsonDocument doc = JsonDocument.Parse(details.DetailsJson!);
			Assert.True(doc.RootElement.TryGetProperty("sessionId", out JsonElement sid));
			Assert.Equal(5, sid.GetInt32());
		}
	}

	// ── Scenario 2: operator arms auto-close, responder finalises fail-closed without a session manager

	[Fact]
	public async Task OperatorArmedAutoClose_ResponderFinalisesFailClosedWhenSessionManagerUnavailable()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		await using (conn.ConfigureAwait(false))
		{
			RdpAuditOptions options = NewOptions();
			KnownProcessStore store = new(factory);
			long alertId;
			await using (AuditDbContext db = await factory.CreateDbContextAsync())
			{
				Alert alert = new()
				{
					RuleId = KnownProcessStore.ProcessNewRuleId,
					Severity = AlertSeverity.High,
					TimeUtc = NowUtc.AddMinutes(-1),
					UserName = "CORP\\bob",
					Message = "New process detected: stealer.exe by bob",
					Details = JsonSerializer.Serialize(new
					{
						ProcessName = "stealer.exe",
						SessionId = 7,
						FirstObservedUtc = NowUtc.AddMinutes(-1),
						AlertWindowDays = 7,
					}, JsonOptions.Default),
				};
				db.Alerts.Add(alert);
				await db.SaveChangesAsync();
				alertId = alert.Id;
			}

			IpcDispatcher dispatcher = CreateDispatcher(factory, options, store);

			// When: the operator arms the automated session close from the alert panel.
			ProcessAutoCloseActionResult armed = await CallAsync<ProcessAutoCloseActionResult>(
				dispatcher, IpcCommand.SetProcessAutoClose, new SetProcessAutoCloseRequest { AlertId = alertId, Enabled = true });
			Assert.Equal(IpcResultStatus.Success, armed.Status);
			Assert.NotNull(armed.Response);
			Assert.Equal((int)ProcessAutoCloseStatus.Queued, armed.Response!.Status);
			Assert.True(armed.Alert?.AutoCloseEnabled);

			// When: the background responder drains the queue on a host without a session
			// manager (the documented non-Windows / unavailable-manager fail-closed path).
			ProcessAlertAutoResponder responder = new(
				store,
				factory,
				new StaticMonitor(options),
				NullLogger<ProcessAlertAutoResponder>.Instance,
				sessions: null,
				new FakeTimeProvider());

			int finalized = await responder.RunOnceAsync(CancellationToken.None);

			Assert.Equal(1, finalized);

			// Then: the persisted response reached its terminal state and the details panel
			// reports the failed logoff, so the operator sees exactly what happened.
			ProcessAlertDetailsDto details = await CallAsync<ProcessAlertDetailsDto>(
				dispatcher, IpcCommand.GetProcessAlertDetails, new GetProcessAlertDetailsRequest { AlertId = alertId });
			Assert.NotNull(details.Response);
			Assert.True(details.Response!.HasResponse);
			Assert.Equal(7, details.Response.SessionId);
			Assert.Equal((int)ProcessAutoCloseStatus.Failed, details.Response.Status);
			Assert.Contains("session manager is unavailable", details.Response.ResultText, StringComparison.Ordinal);
		}
	}

	// ── Scenario 3: baseline gating and hostile input never cross the wire ───────────────────

	[Fact]
	public async Task KnownProcess_IsSilent_WhileSystemSuppressionAndInvalidSessionHold()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		await using (conn.ConfigureAwait(false))
		{
			RdpAuditOptions options = NewOptions(alertSystem: false);
			KnownProcessStore store = new(factory);

			// Given: an already-baselined interactive process watched again within the window.
			await using (AuditDbContext db = await factory.CreateDbContextAsync())
			{
				db.KnownProcesses.Add(new KnownProcess
				{
					ProcessName = "calc.exe",
					UserCategory = (int)ProcessUserCategory.Interactive,
					UserName = @"corp\bob",
					FirstObservedUtc = NowUtc.AddDays(-3),
					LastObservedUtc = NowUtc.AddMinutes(-30),
					ObservationCount = 2,
				});
				await db.SaveChangesAsync();
			}

			NewProcessRule rule = new(store);
			DbAlertContext context = new(factory, new StaticMonitor(options));

			RawEvent knownEvt = new()
			{
				EventId = 4688,
				Channel = "Security",
				TimeUtc = NowUtc,
				UserName = "BOB",
				Domain = "corp",
				SessionId = 2,
				ProcessName = "Calc.EXE",
			};
			await using (AuditDbContext db = await factory.CreateDbContextAsync())
			{
				db.RawEvents.Add(knownEvt);
				await db.SaveChangesAsync();
			}

			// When: the rule evaluates the known identity, then no alert is raised, while the
			// baseline still records the observation.
			Alert? knownAlert = await rule.EvaluateAsync(knownEvt, context, CancellationToken.None);
			Assert.Null(knownAlert);

			// And: a system process is also silent because alerting on system processes is off.
			RawEvent systemEvt = new()
			{
				EventId = 4688,
				Channel = "Security",
				TimeUtc = NowUtc,
				SessionId = -1,
				ProcessName = "svchost.exe",
			};
			await using (AuditDbContext db = await factory.CreateDbContextAsync())
			{
				db.RawEvents.Add(systemEvt);
				await db.SaveChangesAsync();
			}

			Alert? systemAlert = await rule.EvaluateAsync(systemEvt, context, CancellationToken.None);
			Assert.Null(systemAlert);

			await using (AuditDbContext verify = await factory.CreateDbContextAsync())
			{
				Assert.Equal(0, await verify.Alerts.CountAsync(a => a.RuleId == KnownProcessStore.ProcessNewRuleId));
				Assert.Equal(2, await verify.KnownProcesses.CountAsync());
				KnownProcess calc = await verify.KnownProcesses.AsNoTracking().SingleAsync(k => k.ProcessName == "calc.exe");
				Assert.Equal(3, calc.ObservationCount);
				KnownProcess svc = await verify.KnownProcesses.AsNoTracking().SingleAsync(k => k.ProcessName == "svchost.exe");
				Assert.Equal((int)ProcessUserCategory.System, svc.UserCategory);
				Assert.Equal(string.Empty, svc.UserName);
				Assert.Equal(systemEvt.Id, svc.FirstObservedProcessId);
			}

			// Then: hostile operator input is rejected before any write.
			IpcDispatcher dispatcher = CreateDispatcher(factory, options, store);
			ProcessObservationResult invalid = await CallAsync<ProcessObservationResult>(
				dispatcher, IpcCommand.ReportProcessObservation,
				new ProcessObservationRequest { ProcessName = "bad.exe", UserName = "bob", SessionId = 70000 });
			Assert.Equal(IpcResultStatus.InvalidRequest, invalid.Status);

			await using (AuditDbContext verify2 = await factory.CreateDbContextAsync())
			{
				Assert.Equal(2, await verify2.KnownProcesses.CountAsync());
			}
		}
	}

	// ── Scenario 4: the status dashboard mirrors the persisted subsystem truth ───────────────

	[Fact]
	public async Task StatusDashboard_ReflectsPersistedCountersAndEffectiveOptions()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		await using (conn.ConfigureAwait(false))
		{
			RdpAuditOptions options = NewOptions();
			options.ProcessMonitoring.BaselineWindowsDays = new List<int> { 1, 30, 90, 90, 999 };
			KnownProcessStore store = new(factory);

			// Given: one completed and one failed precedent, one currently queued job and two
			// PROCESS_NEW alerts in the DB.
			await using (AuditDbContext db = await factory.CreateDbContextAsync())
			{
				Alert a1 = new()
				{
					RuleId = KnownProcessStore.ProcessNewRuleId,
					Severity = AlertSeverity.High,
					TimeUtc = NowUtc.AddMinutes(-10),
					Message = "first",
					Details = JsonSerializer.Serialize(new { ProcessName = "a.exe", SessionId = 1, FirstObservedUtc = NowUtc.AddMinutes(-10), AlertWindowDays = 7 }, JsonOptions.Default),
				};
				Alert a2 = new()
				{
					RuleId = KnownProcessStore.ProcessNewRuleId,
					Severity = AlertSeverity.High,
					TimeUtc = NowUtc.AddMinutes(-5),
					Message = "second",
					Details = JsonSerializer.Serialize(new { ProcessName = "b.exe", SessionId = 2, FirstObservedUtc = NowUtc.AddMinutes(-5), AlertWindowDays = 7 }, JsonOptions.Default),
				};
				db.Alerts.AddRange(a1, a2);
				await db.SaveChangesAsync();

				db.ProcessAlertResponses.AddRange(
					new ProcessAlertResponse
					{
						AlertId = a1.Id,
						SessionId = 1,
						Status = (int)ProcessAutoCloseStatus.Completed,
						ResultText = "Session 1 logged off automatically.",
						RequestedAtUtc = NowUtc.AddMinutes(-9),
						CompletedAtUtc = NowUtc.AddMinutes(-8),
					},
					new ProcessAlertResponse
					{
						AlertId = a2.Id,
						SessionId = 2,
						Status = (int)ProcessAutoCloseStatus.Queued,
						RequestedAtUtc = NowUtc.AddMinutes(-4),
					});
				await db.SaveChangesAsync();
			}

			// When: the operator opens the status panel, then the effective clamped options and
			// every persisted counter are reported unchanged.
			IpcDispatcher dispatcher = CreateDispatcher(factory, options, store);
			ProcessMonitoringStatusDto status = await CallAsync<ProcessMonitoringStatusDto>(
				dispatcher, IpcCommand.GetProcessMonitoringStatus);

			Assert.Equal(IpcResultStatus.Success, status.Status);
			Assert.True(status.Enabled);
			Assert.Equal(new List<int> { 1, 30, 90, 365 }, status.BaselineWindowsDays);
			Assert.Equal(7, status.AlertWindowDays);
			Assert.False(status.AutoCloseSessionDefault);
			Assert.True(status.EnableAlertOnSystemProcesses);
			Assert.Equal(0, status.KnownProcessCount);
			Assert.Equal(2, status.AlertsSinceStart);
			Assert.Equal(1, status.AutoCloseLogoffPending);
			Assert.Equal(1, status.AutoCloseLogoffCompleted);
			Assert.Equal(0, status.AutoCloseLogoffFailed);
			Assert.Equal(NowUtc.AddMinutes(-8), status.LastAutoCloseUtc);
			Assert.Equal(0, status.ObservationCount);
		}
	}
}
