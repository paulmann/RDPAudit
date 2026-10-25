// File:    tests/RdpAudit.Service.Tests/IpcDispatcherDatabaseTests.cs
// Module:  RdpAudit.Service.Tests
// Purpose: Verifies the Stage 2a Database-tab IPC surface (ordinals 80-84) through the real
//          dispatcher: GetDatabaseOverview, GetRetentionPolicy, PreviewRetention and
//          GetDeletionLedger are read-only and report bounded, honest results; SaveRetentionPolicy
//          round-trips through appsettings.json and the EventRetention table, clamps out-of-range
//          values, and refuses an invalid request without writing anything at all.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.IO;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using RdpAudit.Core.Config;
using RdpAudit.Core.Data;
using RdpAudit.Core.Ipc;
using RdpAudit.Core.Integrity;
using RdpAudit.Core.Ipc.Contracts;
using RdpAudit.Core.Models;
using RdpAudit.Core.Retention;
using RdpAudit.Core.Util;
using RdpAudit.Service.Ipc;
using RdpAudit.Service.Services;
using Xunit;

namespace RdpAudit.Service.Tests;

public sealed class IpcDispatcherDatabaseTests : IDisposable
{
	// ── Fields & DI ──────────────────────────────────────────────────────────────

	private readonly SqliteConnection _connection;
	private readonly IDbContextFactory<AuditDbContext> _factory;
	private readonly string _directory;
	private readonly string _settingsPath;
	private readonly string _programDataRoot;
	private readonly RdpAuditOptions _fallbackOptions;

	public IpcDispatcherDatabaseTests()
	{
		_connection = new SqliteConnection("DataSource=:memory:");
		_connection.Open();
		DbContextOptions<AuditDbContext> options = new DbContextOptionsBuilder<AuditDbContext>()
			.UseSqlite(_connection)
			.Options;
		using (AuditDbContext db = new(options))
		{
			db.Database.EnsureCreated();
		}

		_factory = new TestDbContextFactory(options);

		string directory = Path.Combine(Path.GetTempPath(), "rdpaudit-db-ipc-" + Guid.NewGuid().ToString("N"));
		Directory.CreateDirectory(directory);
		_directory = directory;
		_programDataRoot = Path.Combine(directory, "programdata");
		Directory.CreateDirectory(_programDataRoot);
		_settingsPath = Path.Combine(directory, "appsettings.json");

		_fallbackOptions = new RdpAuditOptions();
		_fallbackOptions.Storage.DatabasePath = Path.Combine(directory, "rdpaudit.db");
		_fallbackOptions.Storage.EventRetentionDays = 365;

		// The document points every filesystem-consuming section at the test's own temp tree, so the
		// overview never measures - or walks - the real machine's evidence store.
		File.WriteAllText(_settingsPath, $$"""
			{
				"RdpAudit": {
					"Storage": {
						"DatabasePath": "{{Path.Combine(directory, "rdpaudit.db").Replace("\\", "\\\\")}}",
						"EventRetentionDays": 365,
						"LogRetentionDays": 90,
						"AlertRetentionDays": 730
					},
					"Sharding": {
						"Enabled": false,
						"ActionsRoot": "{{Path.Combine(_programDataRoot, "actions").Replace("\\", "\\\\")}}"
					},
					"Notifications": { "EnableTrayNotifier": true }
				}
			}
			""");
	}

	public void Dispose()
	{
		_connection.Dispose();
		SqliteConnection.ClearAllPools();
		try
		{
			Directory.Delete(_directory, recursive: true);
		}
		catch (IOException)
		{
		}
		catch (UnauthorizedAccessException)
		{
		}
	}

	// ── GetDatabaseOverview ──────────────────────────────────────────────────────

	/// <summary>Given a store with rows and a ledger entry, when the operator asks for the overview,
	/// then the counts, the ledger aggregate and the sections come back - and the command writes
	/// nothing: no ledger row, no operation-log row, no schema change.</summary>
	[Fact]
	public async Task GetDatabaseOverview_ReportsCountsAndLedgerAggregate_WithoutWriting()
	{
		SeedRawEvents(4625, 3);
		SeedLedgerEntry(4625, rowsDeleted: 41, DateTime.UtcNow.AddMinutes(-5));
		SeedLedgerEntry(4624, rowsDeleted: 8, DateTime.UtcNow.AddMinutes(-1));
		IpcDispatcher dispatcher = CreateDispatcher();

		IpcResponse response = await dispatcher.DispatchAsync(
			new IpcRequest { Command = IpcCommand.GetDatabaseOverview },
			CancellationToken.None);

		Assert.True(response.Success);
		DatabaseOverviewDto dto = Deserialize<DatabaseOverviewDto>(response.Payload);
		DatabaseTableRowCountDto rawEvents = Assert.Single(dto.TableRowCounts, row => row.Table == "RawEvents");
		Assert.Equal(3, rawEvents.RowCount);
		Assert.Equal(2, dto.LedgerEntryCount);
		Assert.Equal(49, dto.LedgerRowsDeleted);
		Assert.NotNull(dto.LedgerLastCreatedUtc);
		Assert.False(dto.MigrationFailureMarkerPresent);
		Assert.False(dto.ShardingEnabled);
		Assert.Equal(4096, dto.MaxShardFiles);
		Assert.Equal(0, dto.DatabaseBytes);
		Assert.True(dto.Sections.Count >= 6);
		Assert.False(dto.IsPartial);
		Assert.Empty(dto.Warnings);
		Assert.All(dto.Sections, section => Assert.Equal("Completed", section.Status));
		Assert.True(dto.QueriedUtc > DateTime.UtcNow.AddMinutes(-1));
		Assert.Equal(0, CountOperationLogs());
	}

	/// <summary>Given a service that had to keep a failed batch and later escalated it, when the overview is
	/// built, then those counters reach the Database tab. They are the only client-visible evidence that the
	/// ingest worker paused instead of discarding events, so a wiring regression here would silently turn a
	/// real persistence stall back into an invisible one.</summary>
	[Fact]
	public async Task GetDatabaseOverview_ReportsTheIngestPersistenceCounters()
	{
		ServiceMetrics metrics = new();
		metrics.IncrementPersistBatchRetained();
		metrics.IncrementPersistBatchRetained();
		metrics.IncrementPersistBatchStalled();

		IpcDispatcher dispatcher = CreateDispatcher(metrics: metrics);

		IpcResponse response = await dispatcher.DispatchAsync(
			new IpcRequest { Command = IpcCommand.GetDatabaseOverview },
			CancellationToken.None);

		Assert.True(response.Success);
		DatabaseOverviewDto dto = Deserialize<DatabaseOverviewDto>(response.Payload);
		Assert.Equal(2, dto.PersistBatchRetainedCount);
		Assert.Equal(1, dto.PersistBatchStalledCount);
	}

	/// <summary>Given a written migration-failure marker, when the overview is built, then the marker
	/// state and its message are reported, so a partial store is never presented as healthy.</summary>
	[Fact]
	public async Task GetDatabaseOverview_ReportsTheMigrationFailureMarker()
	{
		DatabaseMigrationFailureMarker.Write(_programDataRoot, new MigrationFailureMarkerPayload
		{
			TimestampUtc = new DateTime(2026, 9, 13, 4, 0, 0, DateTimeKind.Utc),
			DatabasePath = "C:\\ProgramData\\RdpAudit\\rdpaudit.db",
			PendingMigrations = ["20260915000000_Stage18Example"],
			ExceptionType = "SqliteException",
			ExceptionMessage = "no such column: Enabled",
		});
		IpcDispatcher dispatcher = CreateDispatcher();

		IpcResponse response = await dispatcher.DispatchAsync(
			new IpcRequest { Command = IpcCommand.GetDatabaseOverview },
			CancellationToken.None);

		DatabaseOverviewDto dto = Deserialize<DatabaseOverviewDto>(response.Payload);
		Assert.True(dto.MigrationFailureMarkerPresent);
		Assert.Equal(new DateTime(2026, 9, 13, 4, 0, 0, DateTimeKind.Utc), dto.MigrationFailureUtc);
		Assert.Equal("no such column: Enabled", dto.MigrationFailureMessage);
		Assert.Single(dto.MigrationFailurePendingMigrations);
	}

	/// <summary>Given a store the database sections cannot read at all, when the overview is built,
	/// then the filesystem sections still report, every failing section is named with its error and
	/// the snapshot is marked partial - a degraded store never fails the whole command.</summary>
	[Fact]
	public async Task GetDatabaseOverview_WhenASectionFails_ReturnsAPartialSnapshot()
	{
		IpcDispatcher dispatcher = CreateDispatcherWithThrowingFactory();

		IpcResponse response = await dispatcher.DispatchAsync(
			new IpcRequest { Command = IpcCommand.GetDatabaseOverview },
			CancellationToken.None);

		Assert.True(response.Success);
		DatabaseOverviewDto dto = Deserialize<DatabaseOverviewDto>(response.Payload);
		Assert.True(dto.IsPartial);
		Assert.Equal(IpcResultStatus.Unavailable, dto.Status);
		Assert.NotEmpty(dto.Warnings);
		foreach (string section in new[] { "DbCounts", "Growth", "Schema", "Ledger" })
		{
			DatabaseOverviewSectionDto failed = Assert.Single(dto.Sections, entry => entry.Section == section);
			Assert.Equal("Failed", failed.Status);
			Assert.NotNull(failed.Error);
		}

		// The sections that do not need the database still answered, so the partial snapshot is useful.
		DatabaseOverviewSectionDto files = Assert.Single(dto.Sections, entry => entry.Section == "DbFiles");
		Assert.Equal("Completed", files.Status);
		Assert.Equal(0, dto.DatabaseBytes);
		Assert.Empty(dto.TableRowCounts);
	}

	/// <summary>Given a host that did not register the overview service, when the command arrives,
	/// then the answer is a typed Unavailable rather than an exception.</summary>
	[Fact]
	public async Task GetDatabaseOverview_WithoutTheService_ReportsUnavailable()
	{
		IpcDispatcher dispatcher = CreateDispatcher(includeDatabaseServices: false);

		IpcResponse response = await dispatcher.DispatchAsync(
			new IpcRequest { Command = IpcCommand.GetDatabaseOverview },
			CancellationToken.None);

		Assert.True(response.Success);
		DatabaseOverviewDto dto = Deserialize<DatabaseOverviewDto>(response.Payload);
		Assert.Equal(IpcResultStatus.Unavailable, dto.Status);
		Assert.Contains("not available", dto.Message!, StringComparison.OrdinalIgnoreCase);
	}

	// ── GetRetentionPolicy ───────────────────────────────────────────────────────

	/// <summary>Given default settings and no per-event overrides, when the policy is read, then the
	/// effective clamped defaults are reported and the overrides are reported as genuinely empty
	/// rather than unavailable.</summary>
	[Fact]
	public async Task GetRetentionPolicy_ReportsEffectiveDefaultsAndAnEmptyOverrideSet()
	{
		IpcDispatcher dispatcher = CreateDispatcher();

		IpcResponse response = await dispatcher.DispatchAsync(
			new IpcRequest { Command = IpcCommand.GetRetentionPolicy },
			CancellationToken.None);

		Assert.True(response.Success);
		RetentionPolicyDto dto = Deserialize<RetentionPolicyDto>(response.Payload);
		Assert.Equal(IpcResultStatus.Success, dto.Status);
		Assert.False(dto.Policy.Enabled);
		Assert.False(dto.Policy.PressureDeletionAllowed);
		Assert.Equal(512, dto.Policy.EffectiveTailKeepPerCode);
		Assert.Equal(1_000, dto.Policy.EffectiveCandidateMinRows);
		Assert.Equal(7, dto.Policy.EffectiveMinAgeDays);
		Assert.Equal(RetentionPolicyOptions.DefaultProtectedEventIds.Length, dto.Policy.EffectiveProtectedEventIds.Count);
		Assert.Equal(RetentionPolicyOptions.MinTailKeepPerCode, dto.Policy.Bounds.MinTailKeepPerCode);
		Assert.Equal(365, dto.GlobalWindows.EventRetentionDays);
		Assert.Equal(730, dto.GlobalWindows.AlertRetentionDays);
		Assert.Empty(dto.EventWindows);
		Assert.False(dto.EventWindowsUnavailable);
		Assert.Equal(_settingsPath, dto.ConfigPath);
	}

	/// <summary>Given a persisted per-event override, when the policy is read, then the override is
	/// reported with the catalog metadata the editor renders next to it.</summary>
	[Fact]
	public async Task GetRetentionPolicy_EnrichesPersistedOverridesFromTheCatalog()
	{
		SeedEventRetention(4625, 14);
		IpcDispatcher dispatcher = CreateDispatcher();

		IpcResponse response = await dispatcher.DispatchAsync(
			new IpcRequest { Command = IpcCommand.GetRetentionPolicy },
			CancellationToken.None);

		RetentionPolicyDto dto = Deserialize<RetentionPolicyDto>(response.Payload);
		EventRetentionWindowDto window = Assert.Single(dto.EventWindows);
		Assert.Equal(4625, window.EventId);
		Assert.Equal(14, window.RetentionDays);
		Assert.Equal("Security", window.Channel);
		Assert.False(string.IsNullOrWhiteSpace(window.DisplayName));
		Assert.True(window.DefaultRetentionDays > 0);
		Assert.NotNull(window.UpdatedUtc);
	}

	// ── SaveRetentionPolicy ──────────────────────────────────────────────────────

	/// <summary>Given an operator edit, when it is saved, then the effective clamped values come back,
	/// appsettings.json carries the new retention section while every other section survives, the
	/// per-event override lands in EventRetention, an OperationLog row names the invoker - and the
	/// following read reflects what was written.</summary>
	[Fact]
	public async Task SaveRetentionPolicy_RoundTripsThroughTheSettingsFileAndTheEventTable()
	{
		IpcDispatcher dispatcher = CreateDispatcher();
		RetentionPolicyMutationRequest request = new()
		{
			Policy = new RetentionPolicyValuesDto
			{
				Enabled = true,
				TailKeepPerCode = 1_000,
				CandidateMinRows = 5_000,
				MinAgeDays = 14,
				MaxRowsPerPass = 20_000,
				MaxWriterLockMs = 500,
				DeleteBatchRows = 3_000,
				MaxDatabaseBytes = 8_000_000_000,
				MaxRawEventRows = 5_000_000,
				MinFreeDiskBytes = 1_000_000_000,
			},
			GlobalWindows = new RetentionWindowsDto
			{
				EventRetentionDays = 400,
				AlertRetentionDays = 500,
				AbuseReportRetentionDays = 300,
				ActiveBlockRetentionDays = 60,
				AttackStatRetentionDays = 200,
				SessionIpCorrelationRetentionDays = 45,
				RdpConnectionFactRetentionDays = 120,
				LogRetentionDays = 60,
			},
			EventWindows = [new EventRetentionWindowDto { EventId = 4625, RetentionDays = 30 }],
			EventWindowsReplaceAll = true,
		};

		IpcResponse response = await dispatcher.DispatchAsync(
			new IpcRequest
			{
				Command = IpcCommand.SaveRetentionPolicy,
				Payload = JsonSerializer.Serialize(request, JsonOptions.Default),
			},
			CancellationToken.None,
			callerIdentity: "XEON\\md");

		Assert.True(response.Success);
		RetentionPolicyDto saved = Deserialize<RetentionPolicyDto>(response.Payload);
		Assert.Equal(IpcResultStatus.Success, saved.Status);
		Assert.True(saved.Policy.Enabled);
		Assert.True(saved.Policy.PressureDeletionAllowed);
		Assert.Equal(1_000, saved.Policy.EffectiveTailKeepPerCode);
		Assert.Equal(5_000, saved.Policy.EffectiveCandidateMinRows);
		Assert.Equal(14, saved.Policy.EffectiveMinAgeDays);
		Assert.Equal(400, saved.GlobalWindows.EventRetentionDays);
		EventRetentionWindowDto window = Assert.Single(saved.EventWindows);
		Assert.Equal(4625, window.EventId);
		Assert.Equal(30, window.RetentionDays);

		// The settings document kept every unrelated section and gained the retention block.
		JsonNode root = JsonNode.Parse(File.ReadAllText(_settingsPath))!;
		Assert.True(root["RdpAudit"]!["Notifications"]!["EnableTrayNotifier"]!.GetValue<bool>());
		JsonNode storage = root["RdpAudit"]!["Storage"]!;
		Assert.Equal(400, storage["EventRetentionDays"]!.GetValue<int>());
		Assert.True(storage["RetentionPolicy"]!["Enabled"]!.GetValue<bool>());
		Assert.Equal(1_000, storage["RetentionPolicy"]!["TailKeepPerCode"]!.GetValue<int>());
		Assert.Equal("PerCode", storage["RetentionPolicy"]!["AnchorScope"]!.GetValue<string>());

		// The override is durable and the audit row names the operator.
		using (AuditDbContext db = _factory.CreateDbContext())
		{
			EventRetention row = Assert.Single(db.EventRetentions.AsNoTracking().Where(r => r.EventId == 4625));
			Assert.Equal(30, row.RetentionDays);
		}

		OperationLog audit = Assert.Single(ReadOperationLogs());
		Assert.Equal("Retention", audit.Source);
		Assert.Equal("SaveRetentionPolicy", audit.Operation);
		Assert.Equal("Operator:XEON\\md", audit.Actor);
		Assert.Contains("old=[", audit.Message, StringComparison.Ordinal);
		Assert.Contains("new=[", audit.Message, StringComparison.Ordinal);

		// save -> get: the read path now reports exactly what was written.
		IpcResponse readBack = await dispatcher.DispatchAsync(
			new IpcRequest { Command = IpcCommand.GetRetentionPolicy },
			CancellationToken.None);
		RetentionPolicyDto read = Deserialize<RetentionPolicyDto>(readBack.Payload);
		Assert.True(read.Policy.Enabled);
		Assert.Equal(1_000, read.Policy.TailKeepPerCode);
		Assert.Equal(400, read.GlobalWindows.EventRetentionDays);
		Assert.Single(read.EventWindows);
	}

	/// <summary>Given values outside their supported ranges, when they are saved, then the service
	/// clamps them through the Resolve* contract and writes the clamped values, so a hand-edited
	/// out-of-range document cannot be produced through IPC.</summary>
	[Fact]
	public async Task SaveRetentionPolicy_ClampsOutOfRangeValues()
	{
		IpcDispatcher dispatcher = CreateDispatcher();
		RetentionPolicyMutationRequest request = new()
		{
			Policy = new RetentionPolicyValuesDto
			{
				Enabled = true,
				TailKeepPerCode = 0,
				CandidateMinRows = 1,
				MinAgeDays = 0,
				MaxRowsPerPass = 0,
				MaxWriterLockMs = 1,
				DeleteBatchRows = 1,
				MaxDatabaseBytes = -1,
				MaxRawEventRows = -1,
				MinFreeDiskBytes = -1,
			},
		};

		IpcResponse response = await dispatcher.DispatchAsync(
			new IpcRequest
			{
				Command = IpcCommand.SaveRetentionPolicy,
				Payload = JsonSerializer.Serialize(request, JsonOptions.Default),
			},
			CancellationToken.None);

		Assert.True(response.Success);
		RetentionPolicyDto saved = Deserialize<RetentionPolicyDto>(response.Payload);
		Assert.Equal(RetentionPolicyOptions.MinTailKeepPerCode, saved.Policy.EffectiveTailKeepPerCode);
		Assert.Equal(RetentionPolicyOptions.MinCandidateMinRows, saved.Policy.EffectiveCandidateMinRows);
		Assert.Equal(RetentionPolicyOptions.MinMinAgeDays, saved.Policy.EffectiveMinAgeDays);
		Assert.Equal(RetentionPolicyOptions.MinMaxRowsPerPass, saved.Policy.EffectiveMaxRowsPerPass);
		Assert.Equal(RetentionPolicyOptions.MinMaxWriterLockMs, saved.Policy.EffectiveMaxWriterLockMs);
		Assert.Equal(RetentionPolicyOptions.MinDeleteBatchRows, saved.Policy.EffectiveDeleteBatchRows);
		Assert.Equal(0, saved.Policy.EffectiveMaxDatabaseBytes);
		Assert.Equal(0, saved.Policy.EffectiveMaxRawEventRows);
		Assert.Equal(0, saved.Policy.EffectiveMinFreeDiskBytes);
		Assert.False(saved.Policy.HasAnyPressureTrigger);

		JsonNode storage = JsonNode.Parse(File.ReadAllText(_settingsPath))!["RdpAudit"]!["Storage"]!;
		Assert.Equal(RetentionPolicyOptions.MinTailKeepPerCode, storage["RetentionPolicy"]!["TailKeepPerCode"]!.GetValue<int>());
		Assert.Equal(0, storage["RetentionPolicy"]!["MaxDatabaseBytes"]!.GetValue<long>());
	}

	/// <summary>Given a structurally invalid request, when it is saved, then the whole request is
	/// refused and nothing changes: the settings document is byte-identical, no override row exists
	/// and no audit row was written. A partial write is exactly what must not happen.</summary>
	[Theory]
	[InlineData("""{ "policy": { "enabled": true }, "eventWindows": [ { "eventId": 999999, "retentionDays": 10 } ] }""")]
	[InlineData("""{ "policy": { "enabled": true }, "eventWindows": [ { "eventId": 4625, "retentionDays": 10 }, { "eventId": 4625, "retentionDays": 20 } ] }""")]
	[InlineData("""{ "policy": { "enabled": true }, "eventWindows": [ { "eventId": 4625, "retentionDays": -1 } ] }""")]
	[InlineData("""{ "policy": { "enabled": true }, "eventWindows": [ { "eventId": 4625, "retentionDays": 40000 } ] }""")]
	[InlineData("""{ "policy": { "enabled": true }, "globalWindows": { "logRetentionDays": -5 } }""")]
	[InlineData("""{ "policy": { "enabled": true, "anchorScope": 99 } }""")]
	[InlineData("""{ "policy": { "enabled": true, "protectedEventIds": [0] } }""")]
	[InlineData("""{ }""")]
	public async Task SaveRetentionPolicy_RefusesInvalidInput_WithoutWritingAnything(string payload)
	{
		string before = File.ReadAllText(_settingsPath);
		IpcDispatcher dispatcher = CreateDispatcher();

		IpcResponse response = await dispatcher.DispatchAsync(
			new IpcRequest { Command = IpcCommand.SaveRetentionPolicy, Payload = payload },
			CancellationToken.None);

		Assert.False(response.Success);
		Assert.False(string.IsNullOrWhiteSpace(response.Error));
		Assert.Equal(before, File.ReadAllText(_settingsPath));
		using AuditDbContext db = _factory.CreateDbContext();
		Assert.Empty(db.EventRetentions.AsNoTracking());
		Assert.Equal(0, CountOperationLogs());
	}

	/// <summary>Given the per-event list in merge mode, when only some overrides are supplied, then
	/// the stored ones that were not mentioned survive - only the replace-all mode prunes.</summary>
	[Fact]
	public async Task SaveRetentionPolicy_MergesOverrides_UnlessReplaceAllIsRequested()
	{
		SeedEventRetention(4624, 60);
		SeedEventRetention(4625, 60);
		IpcDispatcher dispatcher = CreateDispatcher();

		IpcResponse merged = await dispatcher.DispatchAsync(
			new IpcRequest
			{
				Command = IpcCommand.SaveRetentionPolicy,
				Payload = """{ "eventWindows": [ { "eventId": 4625, "retentionDays": 10 } ] }""",
			},
			CancellationToken.None);

		Assert.True(merged.Success);
		RetentionPolicyDto afterMerge = Deserialize<RetentionPolicyDto>(merged.Payload);
		Assert.Equal(2, afterMerge.EventWindows.Count);

		IpcResponse replaced = await dispatcher.DispatchAsync(
			new IpcRequest
			{
				Command = IpcCommand.SaveRetentionPolicy,
				Payload = """{ "eventWindows": [ { "eventId": 4625, "retentionDays": 10 } ], "eventWindowsReplaceAll": true }""",
			},
			CancellationToken.None);

		Assert.True(replaced.Success);
		RetentionPolicyDto afterReplace = Deserialize<RetentionPolicyDto>(replaced.Payload);
		EventRetentionWindowDto only = Assert.Single(afterReplace.EventWindows);
		Assert.Equal(4625, only.EventId);
	}

	/// <summary>Given a host without the retention policy service, when the mutating command
	/// arrives, then it is refused loudly instead of silently succeeding.</summary>
	[Fact]
	public async Task SaveRetentionPolicy_WithoutTheService_IsRefused()
	{
		IpcDispatcher dispatcher = CreateDispatcher(includeDatabaseServices: false);

		IpcResponse response = await dispatcher.DispatchAsync(
			new IpcRequest
			{
				Command = IpcCommand.SaveRetentionPolicy,
				Payload = """{ "policy": { "enabled": true } }""",
			},
			CancellationToken.None);

		Assert.False(response.Success);
		Assert.Contains("not available", response.Error!, StringComparison.OrdinalIgnoreCase);
		Assert.Equal(0, CountOperationLogs());
	}

	/// <summary>
	/// Given the real reload pipeline (AddJsonFile with reloadOnChange plus IOptionsMonitor), when a
	/// retention policy is saved, then the running service observes the new policy without a restart -
	/// the mechanism the Database tab relies on to make a save take effect immediately.
	/// </summary>
	[Fact]
	public async Task SaveRetentionPolicy_IsPickedUpByAReloadingOptionsMonitorWithoutARestart()
	{
		IConfigurationRoot configuration = new ConfigurationBuilder()
			.AddJsonFile(_settingsPath, optional: false, reloadOnChange: true)
			.Build();
		using ServiceProvider provider = new ServiceCollection()
			.AddOptions()
			.Configure<RdpAuditOptions>(configuration.GetSection(RdpAuditOptions.SectionName))
			.BuildServiceProvider();
		IOptionsMonitor<RdpAuditOptions> monitor = provider.GetRequiredService<IOptionsMonitor<RdpAuditOptions>>();
		Assert.False(monitor.CurrentValue.Storage.RetentionPolicy.Enabled);

		SettingsManager settings = new(
			NullLogger<SettingsManager>.Instance,
			protector: null,
			overridePath: _settingsPath);
		RetentionPolicyService service = new(
			_factory,
			monitor,
			settings,
			NullLogger<RetentionPolicyService>.Instance,
			new DbOperationLogWriter(_factory, monitor, NullLogger<DbOperationLogWriter>.Instance));

		RetentionPolicyDto saved = await service.SaveAsync(
			new RetentionPolicyMutationRequest
			{
				Policy = new RetentionPolicyValuesDto { Enabled = true, TailKeepPerCode = 900 },
			},
			"Operator:XEON\\md",
			CancellationToken.None);
		Assert.Equal(IpcResultStatus.Success, saved.Status);

		RdpAuditOptions? reloaded = null;
		for (int attempt = 0; attempt < 100 && reloaded is null; attempt++)
		{
			await Task.Delay(100);
			if (monitor.CurrentValue.Storage.RetentionPolicy.Enabled)
			{
				reloaded = monitor.CurrentValue;
			}
		}

		Assert.NotNull(reloaded);
		Assert.Equal(900, reloaded!.Storage.RetentionPolicy.TailKeepPerCode);
		(configuration as IDisposable)?.Dispose();
	}

	/// <summary>Given a save without a caller identity on the pipe, when it is audited, then the row
	/// names the service identity with its prefix instead of inventing an operator.</summary>
	[Fact]
	public async Task SaveRetentionPolicy_WithoutACallerIdentity_AuditsTheServiceIdentity()
	{
		IpcDispatcher dispatcher = CreateDispatcher();

		IpcResponse response = await dispatcher.DispatchAsync(
			new IpcRequest
			{
				Command = IpcCommand.SaveRetentionPolicy,
				Payload = """{ "policy": { "enabled": true } }""",
			},
			CancellationToken.None);

		Assert.True(response.Success);
		OperationLog audit = Assert.Single(ReadOperationLogs());
		Assert.StartsWith("Service:", audit.Actor, StringComparison.Ordinal);
	}

	// ── PreviewRetention ─────────────────────────────────────────────────────────

	/// <summary>Given the default (disabled) policy, when the preview runs, then it says so instead
	/// of reporting a silent zero, and it writes nothing.</summary>
	[Fact]
	public async Task PreviewRetention_WithTheDefaultPolicy_ReportsNothingToDelete()
	{
		SeedRawEvents(4625, 5);
		IpcDispatcher dispatcher = CreateDispatcher();

		IpcResponse response = await dispatcher.DispatchAsync(
			new IpcRequest { Command = IpcCommand.PreviewRetention },
			CancellationToken.None);

		Assert.True(response.Success);
		RetentionPreviewDto preview = Deserialize<RetentionPreviewDto>(response.Payload);
		Assert.Equal(IpcResultStatus.Success, preview.Status);
		Assert.False(preview.PolicyEnabled);
		Assert.Equal(0, preview.WouldDeleteRows);
		Assert.Null(preview.EstimatedReclaimedBytes);
		Assert.Empty(preview.Steps);
		Assert.False(string.IsNullOrWhiteSpace(preview.ReclaimedBytesNote));
		Assert.Equal(0, CountOperationLogs());
	}

	/// <summary>Given an enabled policy over a compressible store, when the preview runs, then it
	/// predicts the rows a pass would remove and stays read-only.</summary>
	[Fact]
	public async Task PreviewRetention_PredictsThePlan_WithoutDeletingAnything()
	{
		SeedRawEvents(4625, 300, daysAgo: 60);
		IpcDispatcher dispatcher = CreateDispatcher(enableRetention: true);

		IpcResponse response = await dispatcher.DispatchAsync(
			new IpcRequest { Command = IpcCommand.PreviewRetention },
			CancellationToken.None);

		Assert.True(response.Success);
		RetentionPreviewDto preview = Deserialize<RetentionPreviewDto>(response.Payload);
		Assert.True(preview.PolicyEnabled);
		Assert.True(preview.TriggerWouldFire);
		Assert.Equal(EventDeletionTrigger.RawEventRows, preview.Trigger);
		Assert.Equal(294, preview.WouldDeleteRows);
		Assert.Single(preview.Steps);
		Assert.Equal(RetentionRuleVersion.Current, preview.RuleVersion);

		using AuditDbContext db = _factory.CreateDbContext();
		Assert.Equal(300, db.RawEvents.AsNoTracking().LongCount(row => row.EventId == 4625));
		Assert.Empty(db.EventDeletionLedger.AsNoTracking());
	}

	/// <summary>Given a store that cannot be examined, when the preview runs, then it reports an
	/// unavailable status with an explanation instead of throwing at the dispatcher.</summary>
	[Fact]
	public async Task PreviewRetention_WhenTheStoreFails_ReportsUnavailable()
	{
		IpcDispatcher dispatcher = CreateDispatcherWithThrowingFactory();

		IpcResponse response = await dispatcher.DispatchAsync(
			new IpcRequest { Command = IpcCommand.PreviewRetention },
			CancellationToken.None);

		Assert.True(response.Success);
		RetentionPreviewDto preview = Deserialize<RetentionPreviewDto>(response.Payload);
		Assert.Equal(IpcResultStatus.Unavailable, preview.Status);
		Assert.Contains("could not be examined", preview.Message!, StringComparison.OrdinalIgnoreCase);
	}

	// ── GetDeletionLedger ────────────────────────────────────────────────────────

	/// <summary>Given a ledger with several entries, when it is queried, then the page is newest
	/// first, the total is reported across all pages, and the filters narrow the set.</summary>
	[Fact]
	public async Task GetDeletionLedger_PagesFiltersAndOrdersNewestFirst()
	{
		DateTime nowUtc = DateTime.UtcNow;
		SeedLedgerEntry(4625, 100, nowUtc.AddHours(-5));
		SeedLedgerEntry(4625, 200, nowUtc.AddHours(-4));
		SeedLedgerEntry(4624, 300, nowUtc.AddHours(-3));
		SeedLedgerEntry(4624, 400, nowUtc.AddHours(-2));
		SeedLedgerEntry(4720, 500, nowUtc.AddHours(-1), scope: EventDeletionScope.PerIp);
		IpcDispatcher dispatcher = CreateDispatcher();

		IpcResponse first = await dispatcher.DispatchAsync(
			new IpcRequest
			{
				Command = IpcCommand.GetDeletionLedger,
				Payload = """{ "page": 0, "pageSize": 2 }""",
			},
			CancellationToken.None);

		Assert.True(first.Success);
		DeletionLedgerPageDto page = Deserialize<DeletionLedgerPageDto>(first.Payload);
		Assert.Equal(5, page.TotalMatching);
		Assert.Equal(2, page.Items.Count);
		Assert.Equal(500, page.Items[0].RowsDeleted);
		Assert.Equal(400, page.Items[1].RowsDeleted);
		Assert.True(page.HasMore);

		IpcResponse last = await dispatcher.DispatchAsync(
			new IpcRequest
			{
				Command = IpcCommand.GetDeletionLedger,
				Payload = """{ "page": 2, "pageSize": 2 }""",
			},
			CancellationToken.None);

		DeletionLedgerPageDto lastPage = Deserialize<DeletionLedgerPageDto>(last.Payload);
		Assert.Single(lastPage.Items);
		Assert.Equal(100, lastPage.Items[0].RowsDeleted);
		Assert.False(lastPage.HasMore);

		IpcResponse filtered = await dispatcher.DispatchAsync(
			new IpcRequest
			{
				Command = IpcCommand.GetDeletionLedger,
				Payload = """{ "eventCode": 4624, "pageSize": 10 }""",
			},
			CancellationToken.None);

		DeletionLedgerPageDto byCode = Deserialize<DeletionLedgerPageDto>(filtered.Payload);
		Assert.Equal(2, byCode.TotalMatching);
		Assert.All(byCode.Items, item => Assert.Equal(4624, item.EventCode));

		IpcResponse ranged = await dispatcher.DispatchAsync(
			new IpcRequest
			{
				Command = IpcCommand.GetDeletionLedger,
				Payload = JsonSerializer.Serialize(
					new DeletionLedgerQueryRequest
					{
						FromUtc = nowUtc.AddHours(-3).AddMinutes(-1),
						ToUtc = nowUtc.AddHours(-1).AddMinutes(1),
					},
					JsonOptions.Default),
			},
			CancellationToken.None);

		DeletionLedgerPageDto byRange = Deserialize<DeletionLedgerPageDto>(ranged.Payload);
		Assert.Equal(3, byRange.TotalMatching);

		IpcResponse byScope = await dispatcher.DispatchAsync(
			new IpcRequest
			{
				Command = IpcCommand.GetDeletionLedger,
				Payload = """{ "scope": "PerIp" }""",
			},
			CancellationToken.None);

		DeletionLedgerPageDto perIp = Deserialize<DeletionLedgerPageDto>(byScope.Payload);
		DeletionLedgerEntryDto entry = Assert.Single(perIp.Items);
		Assert.Equal(EventDeletionScope.PerIp, entry.Scope);
		Assert.Equal("0A00002A", entry.IpHex);

		// A client can never ask for an unbounded page: the server clamps the size.
		IpcResponse clamped = await dispatcher.DispatchAsync(
			new IpcRequest
			{
				Command = IpcCommand.GetDeletionLedger,
				Payload = """{ "pageSize": 1000000 }""",
			},
			CancellationToken.None);

		DeletionLedgerPageDto clampedPage = Deserialize<DeletionLedgerPageDto>(clamped.Payload);
		Assert.Equal(DeletionLedgerQueryService.MaxPageSize, clampedPage.PageSize);
		Assert.Equal(5, clampedPage.Items.Count);
	}

	/// <summary>Given no payload at all, when the ledger is queried, then the first page is served
	/// with the default size instead of the command failing on a missing body.</summary>
	[Fact]
	public async Task GetDeletionLedger_WithoutAPayload_ServesTheFirstPage()
	{
		SeedLedgerEntry(4625, 10, DateTime.UtcNow.AddMinutes(-1));
		IpcDispatcher dispatcher = CreateDispatcher();

		IpcResponse response = await dispatcher.DispatchAsync(
			new IpcRequest { Command = IpcCommand.GetDeletionLedger },
			CancellationToken.None);

		Assert.True(response.Success);
		DeletionLedgerPageDto page = Deserialize<DeletionLedgerPageDto>(response.Payload);
		Assert.Equal(IpcResultStatus.Success, page.Status);
		Assert.Equal(DeletionLedgerQueryService.DefaultPageSize, page.PageSize);
		Assert.Equal(0, page.Page);
		Assert.Single(page.Items);
	}

	/// <summary>Given a malformed address filter, when the ledger is queried, then the request is
	/// refused rather than answered with an empty page that would read as "nothing was deleted".</summary>
	[Fact]
	public async Task GetDeletionLedger_WithAnInvalidFilter_IsRefused()
	{
		SeedLedgerEntry(4625, 10, DateTime.UtcNow.AddMinutes(-1));
		IpcDispatcher dispatcher = CreateDispatcher();

		IpcResponse response = await dispatcher.DispatchAsync(
			new IpcRequest
			{
				Command = IpcCommand.GetDeletionLedger,
				Payload = """{ "ipHex": "not-hex" }""",
			},
			CancellationToken.None);

		Assert.False(response.Success);
		Assert.Contains("hexadecimal", response.Error!, StringComparison.OrdinalIgnoreCase);

		IpcResponse inverted = await dispatcher.DispatchAsync(
			new IpcRequest
			{
				Command = IpcCommand.GetDeletionLedger,
				Payload = """{ "notValidJson":  }""",
			},
			CancellationToken.None);

		Assert.False(inverted.Success);
	}

	/// <summary>Given a host without the ledger service, when the command arrives, then the answer is
	/// a typed Unavailable.</summary>
	[Fact]
	public async Task GetDeletionLedger_WithoutTheService_ReportsUnavailable()
	{
		IpcDispatcher dispatcher = CreateDispatcher(includeDatabaseServices: false);

		IpcResponse response = await dispatcher.DispatchAsync(
			new IpcRequest { Command = IpcCommand.GetDeletionLedger },
			CancellationToken.None);

		Assert.True(response.Success);
		DeletionLedgerPageDto page = Deserialize<DeletionLedgerPageDto>(response.Payload);
		Assert.Equal(IpcResultStatus.Unavailable, page.Status);
	}

	/// <summary>Given the four read-only commands, when they all run against a store with evidence,
	/// then the store is untouched: no row removed, no ledger row, no operation-log row.</summary>
	[Fact]
	public async Task ReadOnlyCommands_LeaveTheStoreAndTheAuditLogUntouched()
	{
		SeedRawEvents(4625, 10);
		IpcDispatcher dispatcher = CreateDispatcher(enableRetention: true);

		foreach (IpcCommand command in new[]
		{
			IpcCommand.GetDatabaseOverview,
			IpcCommand.GetRetentionPolicy,
			IpcCommand.PreviewRetention,
			IpcCommand.GetDeletionLedger,
		})
		{
			IpcResponse response = await dispatcher.DispatchAsync(
				new IpcRequest { Command = command },
				CancellationToken.None);
			Assert.True(response.Success, command + " failed: " + response.Error);
		}

		using AuditDbContext db = _factory.CreateDbContext();
		Assert.Equal(10, db.RawEvents.AsNoTracking().LongCount());
		Assert.Empty(db.EventDeletionLedger.AsNoTracking());
		Assert.Equal(0, CountOperationLogs());
	}

	// ── GetDiagnostics: the store-integrity verdict (B25) ────────────────────────

	/// <summary>Given a healthy store and a host that carries the fingerprint store, when the operator asks
	/// for diagnostics, then the tamper verdict is in the snapshot with its own completed section - the
	/// Diagnostic tab is where an operator lands after an unexplained restart, so the verdict arrives with
	/// the restart evidence instead of only in the Database tab.</summary>
	[Fact]
	public async Task GetDiagnostics_ReportsTheStoreIntegrityVerdict()
	{
		StoreFingerprintStore fingerprints = CreateFingerprints();
		fingerprints.Write(NewFingerprint(rows: 10), cleanShutdown: true);
		IpcDispatcher dispatcher = CreateDispatcher(fingerprints: fingerprints);

		IpcResponse response = await dispatcher.DispatchAsync(
			new IpcRequest { Command = IpcCommand.GetDiagnostics },
			CancellationToken.None);

		Assert.True(response.Success, response.Error);
		DiagnosticsSnapshotDto dto = Deserialize<DiagnosticsSnapshotDto>(response.Payload);
		Assert.Equal("ok", dto.FingerprintChainState);
		Assert.Equal(1, dto.FingerprintChainEntryCount);
		Assert.False(dto.FingerprintChainMirrorAvailable);
		Assert.NotNull(dto.FingerprintCleanShutdownUtc);
		Assert.False(dto.IntegrityAnomalyMarkerPresent);
		Assert.True(dto.LedgerChainIntact);
		Assert.NotNull(dto.LedgerChainMessage);
		Assert.Equal(0, dto.LedgerChainedRows);
		Assert.Contains(dto.SectionTimings, timing => timing.Section == "StoreFingerprint" && timing.Status == "Completed");
		Assert.Contains(dto.SectionTimings, timing => timing.Section == "StoreIntegrity" && timing.Status == "Completed");
	}

	/// <summary>Given a chain whose recorded entries are gone, when diagnostics is built, then the verdict
	/// that travels to the Configurator is the alarming one, not "no fingerprint yet".</summary>
	[Fact]
	public async Task GetDiagnostics_ReportsADeletedChainAsMissing()
	{
		StoreFingerprintStore fingerprints = CreateFingerprints();
		fingerprints.Write(NewFingerprint(rows: 10), cleanShutdown: true);
		fingerprints.Write(NewFingerprint(rows: 12), cleanShutdown: false);
		foreach (string entry in Directory.GetFiles(fingerprints.ChainDirectory, "fingerprint-*.json"))
		{
			File.Delete(entry);
		}

		IpcDispatcher dispatcher = CreateDispatcher(fingerprints: fingerprints);
		IpcResponse response = await dispatcher.DispatchAsync(
			new IpcRequest { Command = IpcCommand.GetDiagnostics },
			CancellationToken.None);

		DiagnosticsSnapshotDto dto = Deserialize<DiagnosticsSnapshotDto>(response.Payload);
		Assert.Equal("missing", dto.FingerprintChainState);
		Assert.Equal(0, dto.FingerprintChainEntryCount);
		Assert.NotNull(dto.FingerprintChainMessage);
	}

	/// <summary>Given an anomaly marker left by the last start-up comparison, when diagnostics is built, then
	/// its presence and its detail reach the snapshot, so the Configurator can show what was found without
	/// opening the marker file.</summary>
	[Fact]
	public async Task GetDiagnostics_ReportsTheAnomalyMarkerAndItsDetail()
	{
		StoreFingerprintStore fingerprints = CreateFingerprints();
		fingerprints.Write(NewFingerprint(rows: 10), cleanShutdown: true);
		fingerprints.WriteAnomalyMarker(new StoreIntegrityReport(
			Compared: true,
			BaselineWasCleanShutdown: true,
			BaselineCapturedUtc: DateTime.UtcNow.AddHours(-1),
			Anomalies: [new StoreIntegrityAnomaly(StoreIntegritySeverity.Strong, "RawEvents", "Row count fell by 120.")],
			LedgerChainIntact: true,
			Message: "RawEvents row count fell by 120 while the service was stopped."));

		IpcDispatcher dispatcher = CreateDispatcher(fingerprints: fingerprints);
		IpcResponse response = await dispatcher.DispatchAsync(
			new IpcRequest { Command = IpcCommand.GetDiagnostics },
			CancellationToken.None);

		DiagnosticsSnapshotDto dto = Deserialize<DiagnosticsSnapshotDto>(response.Payload);
		Assert.True(dto.IntegrityAnomalyMarkerPresent);
		Assert.NotNull(dto.IntegrityAnomalyDetail);
		Assert.Contains("fell by 120", dto.IntegrityAnomalyDetail, StringComparison.Ordinal);
	}

	/// <summary>Given a host that does NOT carry the fingerprint store, when diagnostics is built, then the
	/// chain state stays null - an absence the Configurator renders as UNKNOWN. The section still completes,
	/// so the absence is reported as "not verified" rather than as a failed section or, worse, as a pass.</summary>
	[Fact]
	public async Task GetDiagnostics_WithoutTheFingerprintStore_LeavesTheVerdictUnreported()
	{
		IpcDispatcher dispatcher = CreateDispatcher();
		IpcResponse response = await dispatcher.DispatchAsync(
			new IpcRequest { Command = IpcCommand.GetDiagnostics },
			CancellationToken.None);

		DiagnosticsSnapshotDto dto = Deserialize<DiagnosticsSnapshotDto>(response.Payload);
		Assert.Null(dto.FingerprintChainState);
		Assert.Null(dto.FingerprintChainMirrorAvailable);
		Assert.Equal(0, dto.FingerprintChainEntryCount);
		Assert.Contains(dto.SectionTimings, timing => timing.Section == "StoreFingerprint" && timing.Status == "Completed");
	}

	/// <summary>Given a store the database-backed diagnostics sections cannot read at all, when the snapshot
	/// is built, then every failing section is named with its error and the snapshot is partial - while the
	/// fingerprint verdict, which is read from disk, still arrives: the one reading that explains a broken
	/// store must not depend on that store.</summary>
	[Fact]
	public async Task GetDiagnostics_WhenTheStoreCannotBeRead_StillReportsTheFingerprintVerdict()
	{
		StoreFingerprintStore fingerprints = CreateFingerprints();
		fingerprints.Write(NewFingerprint(rows: 10), cleanShutdown: true);
		IpcDispatcher dispatcher = CreateDispatcher(
			factory: new ThrowingDbContextFactory(),
			fingerprints: fingerprints);

		IpcResponse response = await dispatcher.DispatchAsync(
			new IpcRequest { Command = IpcCommand.GetDiagnostics },
			CancellationToken.None);

		Assert.True(response.Success, response.Error);
		DiagnosticsSnapshotDto dto = Deserialize<DiagnosticsSnapshotDto>(response.Payload);
		Assert.True(dto.IsPartial);

		DiagnosticsSectionTiming ledger = Assert.Single(
			dto.SectionTimings, timing => timing.Section == "StoreIntegrity");
		Assert.Equal("Failed", ledger.Status);
		Assert.False(string.IsNullOrWhiteSpace(ledger.Error));
		Assert.Null(dto.LedgerChainIntact);
		Assert.NotEmpty(dto.RecentPipelineErrors);

		Assert.Equal("ok", dto.FingerprintChainState);
		Assert.Contains(dto.SectionTimings, timing => timing.Section == "StoreFingerprint" && timing.Status == "Completed");
	}

	// ── Harness ──────────────────────────────────────────────────────────────────

	/// <summary>The fingerprint store over the test's own ProgramData tree, with no protector and no mirror
	/// sink: the plain-JSON tip is readable, and the mirror reports itself as unavailable, which is the
	/// honest "the sealed tip is the only second store" limitation rather than a silent absence.</summary>
	private StoreFingerprintStore CreateFingerprints() => new(
		new FakePathsProvider(new RdpAuditPaths(_programDataRoot)),
		NullLogger<StoreFingerprintStore>.Instance);

	private static StoreFingerprint NewFingerprint(long rows) => new()
	{
		CapturedUtc = DateTime.UtcNow,
		CleanShutdown = true,
		CapturedBy = "Shutdown",
		DatabaseBytes = 4096 + rows,
		WalBytes = 64,
		DatabaseLastWriteUtc = DateTime.UtcNow,
		LastIngestionSequence = rows,
		TableRowCounts = new Dictionary<string, long>(StringComparer.Ordinal) { ["RawEvents"] = rows },
		AppliedMigrations = ["20260504215120_InitialCreate"],
		LedgerChainedRows = 0,
		LedgerUnchainedRows = 0,
		LedgerChainIntact = true,
	};

	private IpcDispatcher CreateDispatcher(
		bool includeDatabaseServices = true,
		bool enableRetention = false,
		IDbContextFactory<AuditDbContext>? factory = null,
		StoreFingerprintStore? fingerprints = null,
		ServiceMetrics? metrics = null)
		=> BuildDispatcher(
			factory ?? _factory,
			includeDatabaseServices,
			enableRetention,
			_fallbackOptions,
			fingerprints,
			metrics);

	private IpcDispatcher CreateDispatcherWithThrowingFactory()
		=> BuildDispatcher(
			new ThrowingDbContextFactory(),
			includeDatabaseServices: true,
			enableRetention: true,
			_fallbackOptions);

	private IpcDispatcher BuildDispatcher(
		IDbContextFactory<AuditDbContext> factory,
		bool includeDatabaseServices,
		bool enableRetention,
		RdpAuditOptions baseline,
		StoreFingerprintStore? fingerprints = null,
		ServiceMetrics? metrics = null)
	{
		ServiceMetrics effectiveMetrics = metrics ?? new ServiceMetrics();
		if (enableRetention)
		{
			// The options monitor binds from the settings file, exactly like the service's
			// reloadOnChange provider, so an enabled policy has to live in the document.
			EnableRetentionInSettingsFile();
		}

		RdpAuditOptions fallback = new()
		{
			Storage = new StorageOptions
			{
				DatabasePath = baseline.Storage.DatabasePath,
				EventRetentionDays = 365,
			},
		};

		// The monitor re-reads the settings file on every access, so save -> get round-trips in the
		// test exactly the way the service's reloadOnChange does in production.
		FileBackedOptionsMonitor monitor = new(_settingsPath, fallback);
		SettingsManager settings = new(
			NullLogger<SettingsManager>.Instance,
			protector: null,
			overridePath: _settingsPath);
		DbOperationLogWriter operationLog = new(factory, monitor, NullLogger<DbOperationLogWriter>.Instance);

		DatabaseOverviewService? overview = null;
		RetentionPolicyService? policy = null;
		RetentionPreviewService? preview = null;
		DeletionLedgerQueryService? ledger = null;
		if (includeDatabaseServices)
		{
			overview = new DatabaseOverviewService(
				factory,
				monitor,
				NullLogger<DatabaseOverviewService>.Instance,
				new FakePathsProvider(new RdpAuditPaths(_programDataRoot)),
				metrics: effectiveMetrics);
			policy = new RetentionPolicyService(
				factory,
				monitor,
				settings,
				NullLogger<RetentionPolicyService>.Instance,
				operationLog);
			preview = new RetentionPreviewService(factory, monitor, NullLogger<RetentionPreviewService>.Instance);
			ledger = new DeletionLedgerQueryService(factory);
		}

		return new IpcDispatcher(
			factory,
			effectiveMetrics,
			monitor,
			settings,
			new FirewallManager(NullLogger<FirewallManager>.Instance),
			Array.Empty<RdpAudit.Core.Firewall.IFirewallProvider>(),
			NullLogger<IpcDispatcher>.Instance,
			databaseOverview: overview,
			retentionPolicy: policy,
			retentionPreview: preview,
			deletionLedger: ledger,
			fingerprints: fingerprints);
	}

	/// <summary>Adds the information-density policy the retention tests need to the settings document
	/// once, so the options monitor serves an enabled policy the way a real installation would.</summary>
	private void EnableRetentionInSettingsFile()
	{
		JsonNode root = JsonNode.Parse(File.ReadAllText(_settingsPath))!;
		JsonObject storage = (JsonObject)root["RdpAudit"]!["Storage"]!;
		if (storage["RetentionPolicy"] is not null)
		{
			return;
		}

		storage["RetentionPolicy"] = new JsonObject
		{
			["Enabled"] = true,
			["TailKeepPerCode"] = 5,
			["CandidateMinRows"] = 100,
			["MinAgeDays"] = 7,
			["MaxRowsPerPass"] = 1_000,
			["DeleteBatchRows"] = 1_000,
			["MaxWriterLockMs"] = 60_000,
			["MaxRawEventRows"] = 1,
		};
		File.WriteAllText(_settingsPath, root.ToJsonString(JsonOptions.Indented));
	}

	private void SeedRawEvents(int eventId, int count, int daysAgo = 1)
	{
		DateTime startUtc = DateTime.UtcNow.AddDays(-daysAgo);
		using AuditDbContext db = _factory.CreateDbContext();
		for (int index = 0; index < count; index++)
		{
			db.RawEvents.Add(new RawEvent
			{
				EventId = eventId,
				Channel = "Security",
				TimeUtc = startUtc.AddMinutes(index),
			});
		}

		db.SaveChanges();
	}

	private void SeedEventRetention(int eventId, int retentionDays)
	{
		using AuditDbContext db = _factory.CreateDbContext();
		db.EventRetentions.Add(new EventRetention
		{
			EventId = eventId,
			RetentionDays = retentionDays,
			UpdatedUtc = DateTime.UtcNow.Ticks,
		});
		db.SaveChanges();
	}

	private void SeedLedgerEntry(
		int eventCode,
		long rowsDeleted,
		DateTime createdUtc,
		EventDeletionScope scope = EventDeletionScope.Global)
	{
		using AuditDbContext db = _factory.CreateDbContext();
		db.EventDeletionLedger.Add(new EventDeletionLedger
		{
			EventCode = eventCode,
			Scope = scope,
			IpBinary16 = scope == EventDeletionScope.PerIp ? [0x0A, 0x00, 0x00, 0x2A] : null,
			WindowStartUtc = createdUtc.AddDays(-30),
			WindowEndUtc = createdUtc.AddDays(-29),
			RowsDeleted = rowsDeleted,
			Trigger = EventDeletionTrigger.DatabaseBytes,
			RuleVersion = RetentionRuleVersion.Current,
			Reason = "IDR-1 information-density retention",
			InitiatedBy = "Service",
			CreatedUtc = createdUtc,
		});
		db.SaveChanges();
	}

	private long CountOperationLogs()
	{
		using AuditDbContext db = _factory.CreateDbContext();
		return db.OperationLogs.AsNoTracking().LongCount();
	}

	private List<OperationLog> ReadOperationLogs()
	{
		using AuditDbContext db = _factory.CreateDbContext();
		return [.. db.OperationLogs.AsNoTracking().OrderBy(row => row.Id)];
	}

	private static T Deserialize<T>(string? payload)
	{
		Assert.False(string.IsNullOrWhiteSpace(payload));
		return JsonSerializer.Deserialize<T>(payload!, JsonOptions.Default)!;
	}

	// ── Test doubles ─────────────────────────────────────────────────────────────

	private sealed class TestDbContextFactory : IDbContextFactory<AuditDbContext>
	{
		private readonly DbContextOptions<AuditDbContext> _options;

		public TestDbContextFactory(DbContextOptions<AuditDbContext> options) => _options = options;

		public AuditDbContext CreateDbContext() => new(_options);
	}

	/// <summary>A factory that cannot produce a context, used to drive the degraded paths.</summary>
	private sealed class ThrowingDbContextFactory : IDbContextFactory<AuditDbContext>
	{
		public AuditDbContext CreateDbContext() => throw new InvalidOperationException("store unavailable");
	}

	private sealed class FakePathsProvider : IRdpAuditPathsProvider
	{
		public FakePathsProvider(RdpAuditPaths paths) => Paths = paths;

		public RdpAuditPaths Paths { get; }
	}

	/// <summary>Options monitor that binds <c>RdpAuditOptions</c> from the settings file on every
	/// read, standing in for the service's <c>reloadOnChange</c> configuration provider.</summary>
	private sealed class FileBackedOptionsMonitor : IOptionsMonitor<RdpAuditOptions>
	{
		private readonly string _path;
		private readonly RdpAuditOptions _fallback;

		public FileBackedOptionsMonitor(string path, RdpAuditOptions fallback)
		{
			_path = path;
			_fallback = fallback;
		}

		public RdpAuditOptions CurrentValue
		{
			get
			{
				try
				{
					if (!File.Exists(_path))
					{
						return _fallback;
					}

					JsonNode? root = JsonNode.Parse(File.ReadAllText(_path));
					JsonNode? section = root?[RdpAuditOptions.SectionName];
					if (section is null)
					{
						return _fallback;
					}

					return JsonSerializer.Deserialize<RdpAuditOptions>(
						section.ToJsonString(JsonOptions.Default),
						JsonOptions.Default) ?? _fallback;
				}
				catch (JsonException)
				{
					return _fallback;
				}
				catch (IOException)
				{
					return _fallback;
				}
			}
		}

		public RdpAuditOptions Get(string? name) => CurrentValue;

		public IDisposable? OnChange(Action<RdpAuditOptions, string?> listener) => null;
	}
}
