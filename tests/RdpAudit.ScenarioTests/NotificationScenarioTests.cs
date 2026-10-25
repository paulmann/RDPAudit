// File:    tests/RdpAudit.ScenarioTests/NotificationScenarioTests.cs
// Module:  RdpAudit.ScenarioTests
// Purpose: Tier 3 end-to-end scenarios for toast notifications: the operator config flow over
//          IPC 78/79 with file persistence and restart reload, the service-fed polling pipeline
//          (filter, dedup, native-flag push) through the real wire payloads, flood-cap
//          aggregation, and degradation to the last known policy when the settings fetch fails.
//          Drives the real IpcDispatcher, the real NotificationPoller pipeline and an in-memory
//          SQLite database - no pipes, no dialogs, no external processes.
// Depends: RdpAudit.Core (models, options, IPC contracts), RdpAudit.Service (dispatcher,
//          settings persistence), RdpAudit.Notifier (poller pipeline), xunit
// Extends: Add a scenario here whenever the notification operator flow gains a new step.

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
using RdpAudit.Core.Util;
using RdpAudit.Notifier.Ipc;
using RdpAudit.Notifier.Notifications;
using RdpAudit.Service;
using RdpAudit.Service.Ipc;
using RdpAudit.Service.Services;
using Xunit;

namespace RdpAudit.ScenarioTests;

/// <summary>End-to-end operator scenarios for toast notifications: settings over IPC with
/// persistent reload, the notifier polling pipeline, flood-cap aggregation and degradation.</summary>
public sealed class NotificationScenarioTests
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

	private sealed class FixedTimeProvider : TimeProvider
	{
		public override DateTimeOffset GetUtcNow() => new(NowUtc, TimeSpan.Zero);
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
		string minimumSeverity = "High",
		int maxToastsPerMinute = 10,
		bool useNativeToasts = false,
		Dictionary<string, bool>? showAlerts = null) => new()
	{
		Notifications = new NotificationOptions
		{
			EnableTrayNotifier = enabled,
			MinimumSeverity = minimumSeverity,
			MaxToastsPerMinute = maxToastsPerMinute,
			UseNativeToasts = useNativeToasts,
			ShowAlerts = showAlerts ?? new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase),
		},
	};

	private static RdpAuditOptions OptionsFrom(NotificationOptions notifications) => new() { Notifications = notifications };
	private sealed class DispatcherAlertSource(IpcDispatcher dispatcher) : IAlertSource
	{
		public bool FailSettings { get; set; }

		public bool FailAlerts { get; set; }

		public async Task<NotificationSettingsDto?> FetchSettingsAsync(CancellationToken ct)
		{
			if (FailSettings)
			{
				return null;
			}

			IpcResponse response = await dispatcher.DispatchAsync(new IpcRequest { Command = IpcCommand.GetNotificationSettings }, ct);
			if (!response.Success || response.Payload is null)
			{
				return null;
			}

			return JsonSerializer.Deserialize<NotificationSettingsDto>(response.Payload, JsonOptions.Default);
		}

		public async Task<List<Alert>?> FetchRecentAlertsAsync(CancellationToken ct)
		{
			if (FailAlerts)
			{
				return null;
			}

			IpcResponse response = await dispatcher.DispatchAsync(new IpcRequest { Command = IpcCommand.GetRecentAlerts }, ct);
			if (!response.Success || response.Payload is null)
			{
				return null;
			}

			return JsonSerializer.Deserialize<List<Alert>>(response.Payload, JsonOptions.Default);
		}
	}

	private sealed class RecordingSink : INotificationSink
	{
		public List<long> Shown { get; } = [];

		public List<int> Aggregates { get; } = [];

		public bool PreferNativeToasts { get; set; }

		public bool Show(Alert alert)
		{
			Shown.Add(alert.Id);
			return true;
		}

		public void ShowAggregate(int count) => Aggregates.Add(count);
	}
	private static IpcDispatcher CreateDispatcher(
		IDbContextFactory<AuditDbContext> factory,
		RdpAuditOptions options,
		string settingsPath) => new(
			factory,
			new ServiceMetrics(),
			new StaticMonitor(options),
			new SettingsManager(NullLogger<SettingsManager>.Instance, protector: null, overridePath: settingsPath),
			new FirewallManager(NullLogger<FirewallManager>.Instance),
			Array.Empty<IFirewallProvider>(),
			NullLogger<IpcDispatcher>.Instance);

	private static string CreateSettingsPath()
	{
		string dir = Path.Combine(Path.GetTempPath(), "RdpAuditScenarioTests", Guid.NewGuid().ToString("N"));
		Directory.CreateDirectory(dir);
		return Path.Combine(dir, "appsettings.json");
	}

	private static void TryCleanup(string? targetPath)
	{
		try
		{
			string? dir = targetPath is null ? null : Path.GetDirectoryName(targetPath);
			if (dir is not null && Directory.Exists(dir))
			{
				Directory.Delete(dir, recursive: true);
			}
		}
		catch
		{
			// best effort.
		}
	}

	private static async Task<NotificationSettingsDto> SaveAsync(IpcDispatcher dispatcher, NotificationSettingsDto request)
	{
		IpcResponse response = await dispatcher.DispatchAsync(
			new IpcRequest
			{
				Command = IpcCommand.SaveNotificationSettings,
				Payload = JsonSerializer.Serialize(request, JsonOptions.Default),
			},
			CancellationToken.None);
		Assert.True(response.Success, response.Error);
		Assert.NotNull(response.Payload);
		return JsonSerializer.Deserialize<NotificationSettingsDto>(response.Payload!, JsonOptions.Default)!;
	}

	private static async Task<NotificationSettingsDto> GetAsync(IpcDispatcher dispatcher)
	{
		IpcResponse response = await dispatcher.DispatchAsync(
			new IpcRequest { Command = IpcCommand.GetNotificationSettings },
			CancellationToken.None);
		Assert.True(response.Success, response.Error);
		Assert.NotNull(response.Payload);
		return JsonSerializer.Deserialize<NotificationSettingsDto>(response.Payload!, JsonOptions.Default)!;
	}

	private static Alert MakeAlert(long id, string ruleId = "BRUTE_FORCE", AlertSeverity severity = AlertSeverity.High)
		=> new()
		{
			Id = id,
			RuleId = ruleId,
			Severity = severity,
			TimeUtc = NowUtc,
			Message = "alert " + id,
		};

	private static NotificationPoller CreatePoller(
		IAlertSource source,
		RecordingSink sink,
		TimeProvider? timeProvider = null)
		=> new(source, sink, timeProvider);

	private static async Task InsertAlertAsync(IDbContextFactory<AuditDbContext> factory, Alert alert)
	{
		await using AuditDbContext db = await factory.CreateDbContextAsync();
		db.Alerts.Add(alert);
		await db.SaveChangesAsync();
	}
	private static string CreateUnusedSettingsPath()
		=> Path.Combine(Path.GetTempPath(), "RdpAuditScenarioTests", Guid.NewGuid().ToString("N"), "appsettings.json");

	// ── Scenario 1: operator config round-trips through the settings file ──────────────────

	[Fact]
	public async Task OperatorConfig_RoundTripsThroughFileAndRestart()
	{
		string path = CreateSettingsPath();
		File.WriteAllText(path, """
			{
				"RdpAudit": {
					"Storage": { "DatabasePath": "C:/Data/rdpaudit.db" }
				}
			}
			""");
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		await using (conn.ConfigureAwait(false))
		{
			try
			{
				// Given: a fresh service with no settings file reports the documented defaults.
				IpcDispatcher first = CreateDispatcher(factory, NewOptions(), path);
				NotificationSettingsDto defaults = await GetAsync(first);
				Assert.True(defaults.EnableTrayNotifier);
				Assert.Equal("High", defaults.MinimumSeverity);
				Assert.Equal(10, defaults.MaxToastsPerMinute);

				// When: the operator saves edits from the Notifications tab.
				NotificationSettingsDto saved = await SaveAsync(first, new NotificationSettingsDto
				{
					EnableTrayNotifier = true,
					StartWithWindows = false,
					PollIntervalSeconds = 42,
					MinimumSeverity = "Medium",
					MaxToastsPerMinute = 3,
					UseNativeToasts = true,
					ShowAlerts = new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase)
					{
						["BRUTE_FORCE"] = false,
					},
				});
				Assert.False(saved.StartWithWindows);
				Assert.Equal(42, saved.PollIntervalSeconds);
				Assert.Equal(3, saved.MaxToastsPerMinute);
				Assert.True(saved.UseNativeToasts);

				// Then: the file carries the merged section and keeps the unrelated one.
				string persisted = File.ReadAllText(path);
				Assert.Contains("\"Notifications\"", persisted, StringComparison.Ordinal);
				Assert.Contains("C:/Data/rdpaudit.db", persisted, StringComparison.Ordinal);
				Assert.DoesNotContain("\"MikroTik\"", persisted, StringComparison.Ordinal);

				// And: a restarted dispatcher bound to the on-disk section reports exactly
				// what the operator saved (the production reload reads appsettings.json; the
				// strict configuration-host binding lives in Program.cs outside scenario scope).
				using JsonDocument doc = JsonDocument.Parse(persisted);
				NotificationOptions reloaded = JsonSerializer.Deserialize<NotificationOptions>(
					doc.RootElement.GetProperty("RdpAudit").GetProperty("Notifications").GetRawText(),
					JsonOptions.Default)!;
				Assert.NotNull(reloaded);
				IpcDispatcher second = CreateDispatcher(factory, OptionsFrom(reloaded), path);
				NotificationSettingsDto effect = await GetAsync(second);
				Assert.True(effect.EnableTrayNotifier);
				Assert.False(effect.StartWithWindows);
				Assert.Equal(42, effect.PollIntervalSeconds);
				Assert.Equal("Medium", effect.MinimumSeverity);
				Assert.Equal(3, effect.MaxToastsPerMinute);
				Assert.True(effect.UseNativeToasts);
				Assert.True(effect.ShowAlerts["BRUTE_FORCE"] == false);
			}
			finally
			{
				TryCleanup(path);
			}
		}
	}

	// ── Scenario 2: service-fed alerts flow through the notifier pipeline ─────────────────

	[Fact]
	public async Task ServiceFedAlerts_FlowThroughFilterAndDedup()
	{
		string path = CreateSettingsPath();
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		await using (conn.ConfigureAwait(false))
		{
			try
			{
				// Given: two alerts - a high and a low one (low below the default high threshold).
				await InsertAlertAsync(factory, MakeAlert(1, "BRUTE_FORCE", AlertSeverity.High));
				await InsertAlertAsync(factory, MakeAlert(2, "BRUTE_FORCE", AlertSeverity.Low));

				IpcDispatcher dispatcher = CreateDispatcher(factory, NewOptions(), path);
				DispatcherAlertSource source = new(dispatcher);
				RecordingSink sink = new();
				NotificationPoller poller = CreatePoller(source, sink, new FixedTimeProvider());

				// When: the tray poller ticks twice.
				await poller.TickAsync(CancellationToken.None);
				await poller.TickAsync(CancellationToken.None);

				// Then: exactly the visible new alert was shown, deduplicated across ticks.
				Assert.Equal([1L], sink.Shown);
				Assert.Empty(sink.Aggregates);

				// And: a fresh high alert arriving later is still shown once.
				await InsertAlertAsync(factory, MakeAlert(3, "BRUTE_FORCE", AlertSeverity.High));
				await poller.TickAsync(CancellationToken.None);
				Assert.Equal([1L, 3L], sink.Shown);
				Assert.Empty(sink.Aggregates);
			}
			finally
			{
				TryCleanup(path);
			}
		}
	}

	// ── Scenario 3: flood cap collapses the surplus into one aggregate toast ─────────────

	[Fact]
	public async Task FloodCap_CollapsesSurplusIntoAggregateAndPushesFlags()
	{
		string path = CreateSettingsPath();
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		await using (conn.ConfigureAwait(false))
		{
			try
			{
				// Given: a policy with a small cap and a visibility exception for one rule.
				IpcDispatcher dispatcher = CreateDispatcher(
					factory,
					NewOptions(maxToastsPerMinute: 2, minimumSeverity: "High", useNativeToasts: true),
					path);
				DispatcherAlertSource source = new(dispatcher);
				RecordingSink sink = new();
				NotificationPoller poller = CreatePoller(source, sink, new FixedTimeProvider());

				// When: the first tick delivers two alerts (cap full).
				await InsertAlertAsync(factory, MakeAlert(1));
				await InsertAlertAsync(factory, MakeAlert(2));
				await poller.TickAsync(CancellationToken.None);

				Assert.Equal(new HashSet<long> { 1L, 2L }, sink.Shown.ToHashSet());
				Assert.Empty(sink.Aggregates);
				Assert.True(sink.PreferNativeToasts);

				// When: three more alerts arrive before the window drains.
				await InsertAlertAsync(factory, MakeAlert(3));
				await InsertAlertAsync(factory, MakeAlert(4));
				await InsertAlertAsync(factory, MakeAlert(5));
				await poller.TickAsync(CancellationToken.None);

				// Then: every surplus alert collapsed into one aggregate toast.
				Assert.Equal(new HashSet<long> { 1L, 2L }, sink.Shown.ToHashSet());
				Assert.Equal([3], sink.Aggregates);
				Assert.True(sink.PreferNativeToasts);
			}
			finally
			{
				TryCleanup(path);
			}
		}
	}

	// ── Scenario 4: settings fetch failure degrades to the last known policy ──────────────

	[Fact]
	public async Task SettingsFailure_DegradesToLastKnownPolicy()
	{
		string path = CreateSettingsPath();
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		await using (conn.ConfigureAwait(false))
		{
			try
			{
				await InsertAlertAsync(factory, MakeAlert(1, "BRUTE_FORCE", AlertSeverity.High));
				IpcDispatcher dispatcher = CreateDispatcher(factory, NewOptions(), path);
				DispatcherAlertSource source = new(dispatcher);
				RecordingSink sink = new();
				NotificationPoller poller = CreatePoller(source, sink, new FixedTimeProvider());

				// Given: one healthy tick establishes the policy.
				await poller.TickAsync(CancellationToken.None);
				Assert.True(poller.LastTickSucceeded);
				Assert.Equal([1L], sink.Shown);

				// When: the settings fetch starts failing (service unreachable).
				source.FailSettings = true;
				await poller.TickAsync(CancellationToken.None);

				// Then: reachability is reported false, the previous policy still applied,
				// and the already-shown alert is not re-shown.
				Assert.False(poller.LastTickSucceeded);
				Assert.Equal([1L], sink.Shown);
				Assert.Empty(sink.Aggregates);
				Assert.Equal(5, poller.CurrentPollIntervalSeconds);
			}
			finally
			{
				TryCleanup(path);
			}
		}
	}
}