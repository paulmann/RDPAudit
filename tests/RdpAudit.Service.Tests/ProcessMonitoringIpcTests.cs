// File:    tests/RdpAudit.Service.Tests/ProcessMonitoringIpcTests.cs
// Module:  RdpAudit.Service.Tests
// Purpose: End-to-end IPC dispatcher coverage for the process-monitoring commands (73..77):
//          forced operator observations feeding the same baseline evaluation NewProcessRule uses,
//          alert listing/details, and the append-only operator-managed auto-close lifecycle.
//          Seeds an in-memory SQLite database, drives the real dispatcher and asserts both
//          success payloads and fail-closed validation / policy paths.
// Extends: System.Object
// Author:  Mikhail Deynekin
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
using RdpAudit.Core.ProcessMonitoring;
using RdpAudit.Core.Util;
using RdpAudit.Service.Ipc;
using RdpAudit.Service.ProcessMonitoring;
using RdpAudit.Service.Services;
using Xunit;

namespace RdpAudit.Service.Tests;

public class ProcessMonitoringIpcTests
{
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

	private record struct TestContext(
		IpcDispatcher Dispatcher,
		IDbContextFactory<AuditDbContext> Factory,
		SqliteConnection Conn);

	private static TestContext CreateHost(RdpAuditOptions options, IDbContextFactory<AuditDbContext> factory, SqliteConnection conn)
	{
		ServiceMetrics metrics = new();
		StaticOptionsMonitorLocal<RdpAuditOptions> monitor = new(options);
		SettingsManager settings = new(NullLogger<SettingsManager>.Instance);
		FirewallManager firewall = new(NullLogger<FirewallManager>.Instance);
		KnownProcessStore store = new(factory);
		IpcDispatcher dispatcher = new(
			factory,
			metrics,
			monitor,
			settings,
			firewall,
			Array.Empty<IFirewallProvider>(),
			NullLogger<IpcDispatcher>.Instance,
			processStore: store);
		return new TestContext(dispatcher, factory, conn);
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

	private static RdpAuditOptions MakeOptions(bool monitoringEnabled = true, bool allowLogoff = true, bool alertSystem = true) => new()
	{
		ProcessMonitoring = new ProcessMonitoringOptions
		{
			Enabled = monitoringEnabled,
			AlertWindowDays = 7,
			MaxObservations = 5000,
			EnableAlertOnSystemProcesses = alertSystem,
		},
		SessionControl = new SessionControlOptions
		{
			Enabled = true,
			AllowLogoff = allowLogoff,
		},
	};

	[Fact]
	public async Task ReportProcessObservation_UnknownInteractiveProcess_RaisesAlertAndRecordsBaseline()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			TestContext host = CreateHost(MakeOptions(), factory, conn);
			ProcessObservationResult result = await CallAsync<ProcessObservationResult>(host.Dispatcher, IpcCommand.ReportProcessObservation,
				new ProcessObservationRequest
				{
					ProcessName = @"C:\Temp\evil-tool.exe",
					UserName = "operator",
					Domain = "LAB",
					SessionId = 3,
					AutoClose = false,
				});

			Assert.Equal(IpcResultStatus.Success, result.Status);
			Assert.False(result.IsAlreadyKnown);
			Assert.True(result.IsNew);
			Assert.True(result.RecordingId > 0);
			Assert.NotNull(result.Alert);
			Assert.Equal("evil-tool.exe", result.Alert.ProcessName);
			Assert.Equal(3, result.Alert.SessionId);
			Assert.Equal("PROCESS_NEW", result.Alert.RuleId);
			Assert.False(result.AutoCloseQueued);

			await using AuditDbContext db = factory.CreateDbContext();
			Alert? persisted = await db.Alerts.SingleOrDefaultAsync(a => a.RuleId == "PROCESS_NEW");
			Assert.NotNull(persisted);
			Assert.False(persisted.Acknowledged);
			KnownProcess? baseline = await db.KnownProcesses.AsNoTracking().SingleAsync();
			Assert.Equal("evil-tool.exe", baseline.ProcessName);
			Assert.Equal(@"lab\operator", baseline.UserName);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task ReportProcessObservation_KnownProcess_DoesNotRaiseAlert()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			DateTime now = DateTime.UtcNow;
			await using (AuditDbContext db = factory.CreateDbContext())
			{
				db.KnownProcesses.Add(new KnownProcess
				{
					ProcessName = "svc-host.exe",
					UserCategory = (int)ProcessUserCategory.Interactive,
					UserName = @"lab\operator",
					FirstObservedUtc = now.AddDays(-2),
					LastObservedUtc = now.AddDays(-1),
					ObservationCount = 12,
				});
				await db.SaveChangesAsync();
			}

			TestContext host = CreateHost(MakeOptions(), factory, conn);
			ProcessObservationResult result = await CallAsync<ProcessObservationResult>(host.Dispatcher, IpcCommand.ReportProcessObservation,
				new ProcessObservationRequest
				{
					ProcessName = "Svc-Host.exe",
					UserName = "OPERATOR",
					Domain = "lab",
					SessionId = 2,
				});

			Assert.Equal(IpcResultStatus.Success, result.Status);
			Assert.True(result.IsAlreadyKnown);
			Assert.False(result.IsNew);
			Assert.Null(result.Alert);
			Assert.False(result.AutoCloseQueued);

			await using AuditDbContext verifyDb = factory.CreateDbContext();
			Assert.False(await verifyDb.Alerts.AnyAsync(a => a.RuleId == "PROCESS_NEW"));
			Assert.Equal(1, await verifyDb.KnownProcesses.AsNoTracking().CountAsync());
			Assert.Equal(13, (await verifyDb.KnownProcesses.AsNoTracking().SingleAsync()).ObservationCount);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task ReportProcessObservation_InvalidSessionId_ReturnsInvalidRequestWithoutWrites()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			TestContext host = CreateHost(MakeOptions(), factory, conn);
			ProcessObservationResult result = await CallAsync<ProcessObservationResult>(host.Dispatcher, IpcCommand.ReportProcessObservation,
				new ProcessObservationRequest
				{
					ProcessName = "tool.exe",
					UserName = "u",
					Domain = "d",
					SessionId = 70000,
				});

			Assert.Equal(IpcResultStatus.InvalidRequest, result.Status);
			await using AuditDbContext db = factory.CreateDbContext();
			Assert.Equal(0, await db.KnownProcesses.CountAsync());
			Assert.Equal(0, await db.ProcessObservations.CountAsync());
			Assert.Equal(0, await db.Alerts.CountAsync());
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task ReportProcessObservation_AutoCloseWithoutSessionId_ReturnsInvalidRequest()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			TestContext host = CreateHost(MakeOptions(), factory, conn);
			ProcessObservationResult result = await CallAsync<ProcessObservationResult>(host.Dispatcher, IpcCommand.ReportProcessObservation,
				new ProcessObservationRequest
				{
					ProcessName = "tool.exe",
					UserName = "u",
					Domain = "d",
					SessionId = -1,
					AutoClose = true,
				});

			Assert.Equal(IpcResultStatus.InvalidRequest, result.Status);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task ReportProcessObservation_AutoCloseWhenLogoffDisabled_ReturnsRefusedAndRaisesAlertWithoutResponse()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			TestContext host = CreateHost(MakeOptions(allowLogoff: false), factory, conn);
			ProcessObservationResult result = await CallAsync<ProcessObservationResult>(host.Dispatcher, IpcCommand.ReportProcessObservation,
				new ProcessObservationRequest
				{
					ProcessName = "tool.exe",
					UserName = "u",
					Domain = "d",
					SessionId = 4,
					AutoClose = true,
				});

			Assert.Equal(IpcResultStatus.Refused, result.Status);
			await using AuditDbContext db = factory.CreateDbContext();
			Assert.Equal(0, await db.ProcessAlertResponses.CountAsync());
			Assert.Equal(0, await db.KnownProcesses.CountAsync());
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task ReportProcessObservation_SystemProcessWithAlertSystemOff_RecordsWithoutAlert()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			TestContext host = CreateHost(MakeOptions(alertSystem: false), factory, conn);
			ProcessObservationResult result = await CallAsync<ProcessObservationResult>(host.Dispatcher, IpcCommand.ReportProcessObservation,
				new ProcessObservationRequest
				{
					ProcessName = "svchost.exe",
					SessionId = -1,
				});

			Assert.Equal(IpcResultStatus.Success, result.Status);
			Assert.True(result.IsNew);
			Assert.Null(result.Alert);
			await using AuditDbContext db = factory.CreateDbContext();
			Assert.Equal(0, await db.Alerts.CountAsync());
			Assert.Equal(1, await db.KnownProcesses.CountAsync());
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task ReportProcessObservation_AutoCloseArmsQueuedResponse()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			TestContext host = CreateHost(MakeOptions(), factory, conn);
			ProcessObservationResult result = await CallAsync<ProcessObservationResult>(host.Dispatcher, IpcCommand.ReportProcessObservation,
				new ProcessObservationRequest
				{
					ProcessName = "evil-tool.exe",
					UserName = "operator",
					Domain = "LAB",
					SessionId = 3,
					AutoClose = true,
				});

			Assert.Equal(IpcResultStatus.Success, result.Status);
			Assert.True(result.AutoCloseQueued);
			Assert.NotNull(result.Alert);
			Assert.True(result.Alert.AutoCloseEnabled);

			await using AuditDbContext db = factory.CreateDbContext();
			ProcessAlertResponse row = await db.ProcessAlertResponses.AsNoTracking().SingleAsync();
			Assert.Equal(result.Alert.Id, row.AlertId);
			Assert.Equal(3, row.SessionId);
			Assert.Equal((int)ProcessAutoCloseStatus.Queued, row.Status);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task ReportProcessObservation_DisabledFeature_ReturnsRefused()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			TestContext host = CreateHost(MakeOptions(monitoringEnabled: false), factory, conn);
			ProcessObservationResult result = await CallAsync<ProcessObservationResult>(host.Dispatcher, IpcCommand.ReportProcessObservation,
				new ProcessObservationRequest { ProcessName = "tool.exe", SessionId = -1 });

			Assert.Equal(IpcResultStatus.Refused, result.Status);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task ReportProcessObservation_MalformedPayload_ReturnsControlledError()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			TestContext host = CreateHost(MakeOptions(), factory, conn);
			IpcRequest req = new()
			{
				Command = IpcCommand.ReportProcessObservation,
				Payload = "{not-json",
			};
			IpcResponse response = await host.Dispatcher.DispatchAsync(req, CancellationToken.None);
			Assert.False(response.Success);
			Assert.Contains("not valid JSON", response.Error);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	private static long SeedProcessAlert(IDbContextFactory<AuditDbContext> factory, int sessionId, string detailsJson)
	{
		using AuditDbContext db = factory.CreateDbContext();
		Alert alert = new()
		{
			RuleId = "PROCESS_NEW",
			Severity = AlertSeverity.High,
			TimeUtc = DateTime.UtcNow.AddMinutes(-5),
			UserName = "operator",
			Message = "New process detected: seed.exe",
			Details = detailsJson,
			TriggerEventId = 99,
		};
		db.Alerts.Add(alert);
		db.SaveChanges();
		return alert.Id;
	}

	private static string DetailsJson(int sessionId) => JsonSerializer.Serialize(new
	{
		ProcessName = "seed.exe",
		SessionId = sessionId,
		FirstObservedUtc = DateTime.UtcNow.AddMinutes(-5),
		AlertWindowDays = 7,
	}, JsonOptions.Default);

	[Fact]
	public async Task ListProcessAlerts_ReturnsNewestFirstWithTotalAndResponseState()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			long idA = SeedProcessAlert(factory, 1, DetailsJson(1));
			long idB = SeedProcessAlert(factory, 2, DetailsJson(2));

			TestContext host = CreateHost(MakeOptions(), factory, conn);
			await host.Dispatcher.DispatchAsync(new IpcRequest
			{
				Command = IpcCommand.SetProcessAutoClose,
				Payload = JsonSerializer.Serialize(new SetProcessAutoCloseRequest { AlertId = idB, Enabled = true }, JsonOptions.Default),
			}, CancellationToken.None);

			ProcessAlertListDto list = await CallAsync<ProcessAlertListDto>(host.Dispatcher, IpcCommand.ListProcessAlerts,
				new ListProcessAlertsRequest { Limit = 10 });

			Assert.Equal(IpcResultStatus.Success, list.Status);
			Assert.Equal(2, list.Total);
			Assert.Equal(2, list.Items.Count);
			Assert.Equal(idB, list.Items[0].Id);
			Assert.True(list.Items[0].AutoCloseEnabled);
			Assert.Equal(idA, list.Items[1].Id);
			Assert.False(list.Items[1].AutoCloseEnabled);
			Assert.Equal("seed.exe", list.Items[0].ProcessName);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task GetProcessAlertDetails_NonProcessAlert_ReturnsNotFound()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			await using (AuditDbContext db = factory.CreateDbContext())
			{
				db.Alerts.Add(new Alert
				{
					RuleId = "BruteForce",
					Severity = AlertSeverity.High,
					TimeUtc = DateTime.UtcNow,
					Message = "other alert",
					TriggerEventId = 7,
				});
				await db.SaveChangesAsync();
			}

			long otherId;
			await using (AuditDbContext db = factory.CreateDbContext())
			{
				otherId = (await db.Alerts.AsNoTracking().SingleAsync()).Id;
			}

			TestContext host = CreateHost(MakeOptions(), factory, conn);
			ProcessAlertDetailsDto details = await CallAsync<ProcessAlertDetailsDto>(host.Dispatcher, IpcCommand.GetProcessAlertDetails,
				new GetProcessAlertDetailsRequest { AlertId = otherId });

			Assert.Equal(IpcResultStatus.NotFound, details.Status);
			Assert.Null(details.Alert);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task SetProcessAutoClose_ArmThenCancel_TransitionsThroughQueuedToFailed()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			long alertId = SeedProcessAlert(factory, 3, DetailsJson(3));
			TestContext host = CreateHost(MakeOptions(), factory, conn);

			ProcessAutoCloseActionResult armed = await CallAsync<ProcessAutoCloseActionResult>(host.Dispatcher, IpcCommand.SetProcessAutoClose,
				new SetProcessAutoCloseRequest { AlertId = alertId, Enabled = true });
			Assert.Equal(IpcResultStatus.Success, armed.Status);
			Assert.NotNull(armed.Response);
			Assert.Equal(3, armed.Response.SessionId);
			Assert.Equal((int)ProcessAutoCloseStatus.Queued, armed.Response.Status);
			Assert.True(armed.Alert?.AutoCloseEnabled);

			ProcessAutoCloseActionResult cancelled = await CallAsync<ProcessAutoCloseActionResult>(host.Dispatcher, IpcCommand.SetProcessAutoClose,
				new SetProcessAutoCloseRequest { AlertId = alertId, Enabled = false, Reason = "tests" });
			Assert.Equal(IpcResultStatus.Success, cancelled.Status);
			Assert.NotNull(cancelled.Response);
			Assert.Equal((int)ProcessAutoCloseStatus.Failed, cancelled.Response.Status);
			Assert.Contains("tests", cancelled.Response.ResultText);
			Assert.False(cancelled.Alert?.AutoCloseEnabled);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task SetProcessAutoClose_CancelWhenNeverArmed_ReturnsRefused()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			long alertId = SeedProcessAlert(factory, 1, DetailsJson(1));
			TestContext host = CreateHost(MakeOptions(), factory, conn);

			ProcessAutoCloseActionResult cancelled = await CallAsync<ProcessAutoCloseActionResult>(host.Dispatcher, IpcCommand.SetProcessAutoClose,
				new SetProcessAutoCloseRequest { AlertId = alertId, Enabled = false });

			Assert.Equal(IpcResultStatus.Refused, cancelled.Status);
			Assert.Contains("No automated response", cancelled.Message);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task SetProcessAutoClose_CancelAfterFinal_ReturnsRefused()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			long alertId = SeedProcessAlert(factory, 1, DetailsJson(1));

			// Finalizes the response directly through the store (fail->panic path of the responder).
			KnownProcessStore store = new(factory);
			_ = await store.FinalizeAutoCloseAsync(alertId, ProcessAutoCloseStatus.Completed, "done", DateTime.UtcNow);
			// No response existed before, so seed one explicitly.
			await using (AuditDbContext db = factory.CreateDbContext())
			{
				db.ProcessAlertResponses.Add(new ProcessAlertResponse
				{
					AlertId = alertId,
					SessionId = 1,
					Status = (int)ProcessAutoCloseStatus.Failed,
					ResultText = "Cancelled by operator: earlier",
					RequestedAtUtc = DateTime.UtcNow.AddMinutes(-3),
					CompletedAtUtc = DateTime.UtcNow.AddMinutes(-2),
				});
				await db.SaveChangesAsync();
			}

			TestContext host = CreateHost(MakeOptions(), factory, conn);
			ProcessAutoCloseActionResult cancelled = await CallAsync<ProcessAutoCloseActionResult>(host.Dispatcher, IpcCommand.SetProcessAutoClose,
				new SetProcessAutoCloseRequest { AlertId = alertId, Enabled = false });

			Assert.Equal(IpcResultStatus.Refused, cancelled.Status);
			Assert.Contains("already finished", cancelled.Message);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task SetProcessAutoClose_LogoffDisabledByPolicy_ReturnsRefused()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			long alertId = SeedProcessAlert(factory, 2, DetailsJson(2));
			TestContext host = CreateHost(MakeOptions(allowLogoff: false), factory, conn);

			ProcessAutoCloseActionResult armed = await CallAsync<ProcessAutoCloseActionResult>(host.Dispatcher, IpcCommand.SetProcessAutoClose,
				new SetProcessAutoCloseRequest { AlertId = alertId, Enabled = true });

			Assert.Equal(IpcResultStatus.Refused, armed.Status);
			Assert.Null(armed.Response);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task GetProcessMonitoringStatus_ReflectsOptionsAndPersistedCounters()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			SeedProcessAlert(factory, 1, DetailsJson(1));
			TestContext host = CreateHost(MakeOptions(alertSystem: false), factory, conn);

			ProcessMonitoringStatusDto status = await CallAsync<ProcessMonitoringStatusDto>(host.Dispatcher, IpcCommand.GetProcessMonitoringStatus);

			Assert.Equal(IpcResultStatus.Success, status.Status);
			Assert.True(status.Enabled);
			Assert.Equal(new List<int> { 7, 30, 365 }, status.BaselineWindowsDays);
			Assert.Equal(7, status.AlertWindowDays);
			Assert.False(status.EnableAlertOnSystemProcesses);
			Assert.Equal(0, status.KnownProcessCount);
			Assert.Equal(1, status.AlertsSinceStart);
			Assert.Equal(0, status.AutoCloseLogoffPending);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}
}
