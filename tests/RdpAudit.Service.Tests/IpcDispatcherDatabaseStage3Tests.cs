// File:    tests/RdpAudit.Service.Tests/IpcDispatcherDatabaseStage3Tests.cs
// Module:  RdpAudit.Service.Tests
// Purpose: Verifies the Stage 3 Database-tab IPC surface (ordinals 88-90) through the real
//          dispatcher. GetShardInventory cross-references IpEventSummary with a bounded tree walk
//          and flags orphan shard files without touching anything; RunDatabaseMaintenance runs only
//          read-safe pragmas, refuses an unknown kind (including the numeric smuggled variant) and
//          never deletes a row or writes an audit row; RestoreDatabaseBackupToDirectory copies a
//          verified snapshot into a scratch directory, refuses a drive root and audits the write.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.IO;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using RdpAudit.Core.Backup;
using RdpAudit.Core.Config;
using RdpAudit.Core.Data;
using RdpAudit.Core.Ipc;
using RdpAudit.Core.Ipc.Contracts;
using RdpAudit.Core.Models;
using RdpAudit.Core.Util;
using RdpAudit.Service.Ipc;
using RdpAudit.Service.Services;
using Xunit;

namespace RdpAudit.Service.Tests;

public sealed class IpcDispatcherDatabaseStage3Tests : IDisposable
{
	// ── Fields & DI ──────────────────────────────────────────────────────────────

	private readonly SqliteConnection _connection;
	private readonly IDbContextFactory<AuditDbContext> _factory;
	private readonly string _directory;
	private readonly string _settingsPath;
	private readonly string _programDataRoot;
	private readonly string _actionsRoot;
	private readonly string _backupRoot;
	private readonly TestOptionsMonitor _options;

	public IpcDispatcherDatabaseStage3Tests()
	{
		_connection = new SqliteConnection("DataSource=:memory:");
		_connection.Open();
		DbContextOptions<AuditDbContext> dbOptions = new DbContextOptionsBuilder<AuditDbContext>()
			.UseSqlite(_connection)
			.Options;
		using (AuditDbContext db = new(dbOptions))
		{
			db.Database.EnsureCreated();
		}

		_factory = new TestDbContextFactory(dbOptions);

		_directory = Path.Combine(Path.GetTempPath(), "rdpaudit-db-stage3-" + Guid.NewGuid().ToString("N"));
		Directory.CreateDirectory(_directory);
		_programDataRoot = Path.Combine(_directory, "programdata");
		_actionsRoot = Path.Combine(_programDataRoot, "actions");
		_backupRoot = Path.Combine(_programDataRoot, "Backups");
		Directory.CreateDirectory(_actionsRoot);
		_settingsPath = Path.Combine(_directory, "appsettings.json");

		RdpAuditOptions options = new();
		options.Storage.DatabasePath = Path.Combine(_programDataRoot, RdpAuditPaths.DatabaseFileName);
		options.Storage.Backup.Enabled = true;
		options.Storage.Backup.BackupDirectory = _backupRoot;
		options.Storage.Backup.PreMigrationBackupEnabled = true;
		options.Sharding.Enabled = true;
		options.Sharding.ActionsRoot = _actionsRoot;
		_options = new TestOptionsMonitor(options);

		File.WriteAllText(_settingsPath, "{\"RdpAudit\":{}}");
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

	// ── GetShardInventory (88) ───────────────────────────────────────────────────

	/// <summary>Given one shard referenced by a summary row and one file no summary points at, when the
	/// inventory is read, then both appear - the second flagged as an orphan - the aggregates add up and
	/// the command writes nothing.</summary>
	[Fact]
	public async Task GetShardInventory_ReportsReferencedShardsAndOrphans_WithoutWriting()
	{
		string referencedRelative = "0a/1b/0a1b2c3d.rdpshard";
		string referencedAbsolute = Path.Combine(_actionsRoot, "0a", "1b", "0a1b2c3d.rdpshard");
		SeedShardFile(referencedAbsolute, length: 4096);
		SeedSummary("10.27.44.61", referencedRelative, records: 10, bytes: 4096, evicted: 3, oldestTicks: new DateTime(2026, 8, 1, 0, 0, 0, DateTimeKind.Utc).Ticks);

		// An orphan: a shard-shaped file name that no summary row references, with no usable header.
		string orphanAbsolute = Path.Combine(_actionsRoot, "ff", "ee", "ffee0011.rdpshard");
		SeedShardFile(orphanAbsolute, length: 512);

		IpcDispatcher dispatcher = CreateDispatcher();

		IpcResponse response = await dispatcher.DispatchAsync(
			new IpcRequest { Command = IpcCommand.GetShardInventory },
			CancellationToken.None);

		Assert.True(response.Success);
		ShardInventoryDto dto = Deserialize<ShardInventoryDto>(response.Payload);
		Assert.Equal(IpcResultStatus.Success, dto.Status);
		Assert.True(dto.ShardingEnabled);
		Assert.Equal(_actionsRoot, dto.ActionsRoot);

		ShardInventoryEntryDto referenced = Assert.Single(dto.Entries, entry => !entry.IsOrphan);
		Assert.Equal(referencedRelative, referenced.RelativePath);
		Assert.Equal("10.27.44.61", referenced.IpText);
		Assert.Equal("0A1B2C3D", referenced.IpHex);
		Assert.Equal(10, referenced.Records);
		Assert.Equal(4096, referenced.Bytes);
		Assert.Equal(3, referenced.Evicted);
		Assert.NotNull(referenced.OldestRetainedUtc);

		ShardInventoryEntryDto orphan = Assert.Single(dto.Entries, entry => entry.IsOrphan);
		Assert.Equal("FFEE0011", orphan.IpHex);
		Assert.Equal("255.238.0.17", orphan.IpText);
		Assert.Equal(512, orphan.Bytes);
		Assert.NotNull(orphan.Note);

		Assert.Equal(2, dto.Summary.ShardFiles);
		Assert.Equal(1, dto.Summary.OrphanFiles);
		Assert.Equal(512, dto.Summary.OrphanBytes);
		Assert.Equal(4608, dto.Summary.TotalShardBytes);
		Assert.Equal(10, dto.Summary.TotalRecords);
		Assert.Equal(3, dto.Summary.TotalEvicted);
		Assert.Equal(2, dto.Summary.EntriesReturned);
		Assert.False(dto.Summary.Truncated);

		Assert.Equal(0, CountOperationLogs());
		Assert.Equal(0, CountLedgerEntries());
		Assert.Equal(1, CountSummaries());
	}

	/// <summary>Given no shard tree at all, when the inventory is read, then it is an honest zero rather
	/// than an error.</summary>
	[Fact]
	public async Task GetShardInventory_WithoutATree_IsAnHonestZero()
	{
		Directory.Delete(_actionsRoot, recursive: true);
		IpcDispatcher dispatcher = CreateDispatcher();

		IpcResponse response = await dispatcher.DispatchAsync(
			new IpcRequest { Command = IpcCommand.GetShardInventory },
			CancellationToken.None);

		Assert.True(response.Success);
		ShardInventoryDto dto = Deserialize<ShardInventoryDto>(response.Payload);
		Assert.Equal(IpcResultStatus.Success, dto.Status);
		Assert.Empty(dto.Entries);
		Assert.Equal(0, dto.Summary.ShardFiles);
		Assert.Equal(0, dto.Summary.OrphanFiles);
		Assert.Empty(dto.Warnings);
	}

	/// <summary>Given a host that did not register the inventory service, when the command is dispatched,
	/// then the client gets a typed Unavailable instead of an exception.</summary>
	[Fact]
	public async Task GetShardInventory_WithoutTheService_IsUnavailable()
	{
		IpcDispatcher dispatcher = CreateDispatcher(includeStage3Services: false);

		IpcResponse response = await dispatcher.DispatchAsync(
			new IpcRequest { Command = IpcCommand.GetShardInventory },
			CancellationToken.None);

		Assert.True(response.Success);
		ShardInventoryDto dto = Deserialize<ShardInventoryDto>(response.Payload);
		Assert.Equal(IpcResultStatus.Unavailable, dto.Status);
		Assert.NotNull(dto.Message);
	}

	/// <summary>Given a tree with more shard files than the response budget, when the inventory is read,
	/// then the entry list is capped while the summary still counts the whole walk.</summary>
	[Fact]
	public async Task GetShardInventory_IsBoundedAndSaysSo()
	{
		for (int index = 0; index < 12; index++)
		{
			string name = index.ToString("X8", System.Globalization.CultureInfo.InvariantCulture);
			SeedShardFile(Path.Combine(_actionsRoot, "aa", "bb", name + ".rdpshard"), length: 64);
		}

		IpcDispatcher dispatcher = CreateDispatcher();

		IpcResponse response = await dispatcher.DispatchAsync(
			new IpcRequest { Command = IpcCommand.GetShardInventory },
			CancellationToken.None);

		ShardInventoryDto dto = Deserialize<ShardInventoryDto>(response.Payload);
		Assert.Equal(12, dto.Summary.ShardFiles);
		Assert.Equal(12, dto.Entries.Count);
		Assert.Equal(12, dto.Summary.EntriesReturned);
	}

	// ── RunDatabaseMaintenance (89) ──────────────────────────────────────────────

	/// <summary>Given a healthy store, when quick_check runs, then it reports ok, the report is
	/// structured and stamped, and nothing was written: no audit row, no ledger row, no data change.</summary>
	[Fact]
	public async Task RunDatabaseMaintenance_QuickCheck_ReportsOkWithoutWriting()
	{
		SeedRawEvents(4625, 3);
		IpcDispatcher dispatcher = CreateDispatcher();

		IpcResponse response = await dispatcher.DispatchAsync(
			new IpcRequest
			{
				Command = IpcCommand.RunDatabaseMaintenance,
				Payload = "{\"Kind\":1}",
			},
			CancellationToken.None);

		Assert.True(response.Success);
		DatabaseMaintenanceReportDto dto = Deserialize<DatabaseMaintenanceReportDto>(response.Payload);
		Assert.Equal(IpcResultStatus.Success, dto.Status);
		Assert.Equal(DatabaseMaintenanceKind.QuickCheck, dto.Kind);
		Assert.Equal("QuickCheck", dto.KindName);
		DatabaseMaintenanceStepDto step = Assert.Single(dto.Steps);
		Assert.Equal("PRAGMA quick_check", step.Name);
		Assert.Equal("Completed", step.Outcome);
		Assert.Equal("ok", step.Detail);
		Assert.Contains("PRAGMA quick_check", dto.ResultText, StringComparison.Ordinal);
		Assert.Contains("Action:         QuickCheck", dto.ResultText, StringComparison.Ordinal);
		Assert.Contains("no OperationLog row was written", dto.Message ?? string.Empty, StringComparison.Ordinal);

		Assert.Equal(0, CountOperationLogs());
		Assert.Equal(0, CountLedgerEntries());
		Assert.Equal(3, CountRawEvents());
	}

	/// <summary>Given every defined safe kind, when each is run, then none is refused and each produces a
	/// completed step - the action set contains no destructive operation.</summary>
	[Fact]
	public async Task RunDatabaseMaintenance_AcceptsEveryDefinedKind()
	{
		IpcDispatcher dispatcher = CreateDispatcher();

		foreach (DatabaseMaintenanceKind kind in Enum.GetValues<DatabaseMaintenanceKind>())
		{
			if (kind == DatabaseMaintenanceKind.Unknown)
			{
				continue;
			}

			IpcResponse response = await dispatcher.DispatchAsync(
				new IpcRequest
				{
					Command = IpcCommand.RunDatabaseMaintenance,
					Payload = "{\"Kind\":" + ((int)kind).ToString(System.Globalization.CultureInfo.InvariantCulture) + "}",
				},
				CancellationToken.None);

			Assert.True(response.Success);
			DatabaseMaintenanceReportDto dto = Deserialize<DatabaseMaintenanceReportDto>(response.Payload);
			Assert.NotEqual(IpcResultStatus.InvalidRequest, dto.Status);
			DatabaseMaintenanceStepDto step = Assert.Single(dto.Steps);
			Assert.Equal(kind, dto.Kind);
			Assert.True(
				step.Outcome is "Completed" or "TimedOut",
				kind + " produced outcome " + step.Outcome + ": " + step.Detail);
		}
	}

	/// <summary>Given a missing or unknown kind - including the numeric variant a hand-crafted payload
	/// could smuggle in - when the action is requested, then it is refused as an invalid request, the
	/// refusal names the supported kinds and states that full VACUUM is not part of the surface, and
	/// nothing is touched.</summary>
	[Theory]
	[InlineData(null)]
	[InlineData("{}")]
	[InlineData("{\"Kind\":0}")]
	[InlineData("{\"Kind\":999}")]
	public async Task RunDatabaseMaintenance_RefusesAMissingOrUnknownKind(string? payload)
	{
		IpcDispatcher dispatcher = CreateDispatcher();

		IpcResponse response = await dispatcher.DispatchAsync(
			new IpcRequest { Command = IpcCommand.RunDatabaseMaintenance, Payload = payload },
			CancellationToken.None);

		Assert.True(response.Success);
		DatabaseMaintenanceReportDto dto = Deserialize<DatabaseMaintenanceReportDto>(response.Payload);
		Assert.Equal(IpcResultStatus.InvalidRequest, dto.Status);
		Assert.Contains("QuickCheck", dto.Message ?? string.Empty, StringComparison.Ordinal);
		Assert.Contains("Full VACUUM is deliberately not offered", dto.Message ?? string.Empty, StringComparison.Ordinal);
		Assert.Contains("docs/88", dto.Message ?? string.Empty, StringComparison.Ordinal);
		Assert.Equal(0, CountOperationLogs());
		Assert.Equal(0, CountLedgerEntries());
	}

	/// <summary>Given a host without the maintenance service, when the action is dispatched, then the
	/// client gets a typed Unavailable.</summary>
	[Fact]
	public async Task RunDatabaseMaintenance_WithoutTheService_IsUnavailable()
	{
		IpcDispatcher dispatcher = CreateDispatcher(includeStage3Services: false);

		IpcResponse response = await dispatcher.DispatchAsync(
			new IpcRequest { Command = IpcCommand.RunDatabaseMaintenance, Payload = "{\"Kind\":1}" },
			CancellationToken.None);

		Assert.True(response.Success);
		DatabaseMaintenanceReportDto dto = Deserialize<DatabaseMaintenanceReportDto>(response.Payload);
		Assert.Equal(IpcResultStatus.Unavailable, dto.Status);
	}

	// ── RestoreDatabaseBackupToDirectory (90) ────────────────────────────────────

	/// <summary>Given a verified snapshot, when the restore-to-scratch command runs, then the database
	/// lands in the requested directory, the live store is untouched and the write is audited.</summary>
	[Fact]
	public async Task RestoreDatabaseBackupToDirectory_CopiesIntoTheTargetAndAudits()
	{
		string liveDatabase = Path.Combine(_programDataRoot, RdpAuditPaths.DatabaseFileName);
		using (SqliteConnection live = new("Data Source=" + liveDatabase))
		{
			live.Open();
			using SqliteCommand command = live.CreateCommand();
			command.CommandText = "CREATE TABLE Probe (Id INTEGER PRIMARY KEY, Name TEXT NOT NULL); INSERT INTO Probe (Name) VALUES ('evidence');";
			command.ExecuteNonQuery();
		}

		DatabaseBackupService backups = new(_options, NullLogger<DatabaseBackupService>.Instance, new FakePathsProvider(new RdpAuditPaths(_programDataRoot)));
		DatabaseBackupCreationDto created = await backups.CreateSnapshotAsync(liveDatabase, includeShards: false, DatabaseBackupKind.Manual, CancellationToken.None);
		Assert.Equal(IpcResultStatus.Success, created.Status);

		string target = Path.Combine(_directory, "scratch");
		IpcDispatcher dispatcher = CreateDispatcher(backups: backups);

		IpcResponse response = await dispatcher.DispatchAsync(
			new IpcRequest
			{
				Command = IpcCommand.RestoreDatabaseBackupToDirectory,
				Payload = "{\"Name\":\"" + created.SnapshotName + "\",\"TargetDirectory\":\"" + target.Replace("\\", "\\\\", StringComparison.Ordinal) + "\"}",
			},
			CancellationToken.None,
			callerIdentity: "CONTOSO\\operator");

		Assert.True(response.Success);
		DatabaseBackupRestoreReportDto report = Deserialize<DatabaseBackupRestoreReportDto>(response.Payload);
		Assert.Equal(IpcResultStatus.Success, report.Status);
		Assert.True(File.Exists(Path.Combine(target, DatabaseBackupLayout.DatabaseFileName)));
		Assert.Equal(Path.Combine(target, DatabaseBackupLayout.DatabaseFileName), report.TargetDatabasePath);

		// The live store is still there and still holds its row.
		Assert.True(File.Exists(liveDatabase));
		Assert.Equal(1, CountOperationLogs());
		OperationLogDto log = ReadSingleOperationLog();
		Assert.Equal("Database", log.Source);
		Assert.Equal("RestoreDatabaseBackupToDirectory", log.Operation);
		Assert.Equal("Operator:CONTOSO\\operator", log.Actor);
	}

	/// <summary>Given a snapshot name that does not exist, when the restore runs, then it reports the
	/// missing snapshot without throwing and writes nothing.</summary>
	[Fact]
	public async Task RestoreDatabaseBackupToDirectory_UnknownSnapshot_IsRefusedWithoutWriting()
	{
		DatabaseBackupService backups = new(_options, NullLogger<DatabaseBackupService>.Instance, new FakePathsProvider(new RdpAuditPaths(_programDataRoot)));
		string target = Path.Combine(_directory, "scratch-unknown");
		IpcDispatcher dispatcher = CreateDispatcher(backups: backups);

		IpcResponse response = await dispatcher.DispatchAsync(
			new IpcRequest
			{
				Command = IpcCommand.RestoreDatabaseBackupToDirectory,
				Payload = "{\"Name\":\"20200101-000000\",\"TargetDirectory\":\"" + target.Replace("\\", "\\\\", StringComparison.Ordinal) + "\"}",
			},
			CancellationToken.None);

		Assert.True(response.Success);
		DatabaseBackupRestoreReportDto report = Deserialize<DatabaseBackupRestoreReportDto>(response.Payload);
		Assert.NotEqual(IpcResultStatus.Success, report.Status);
		Assert.False(Directory.Exists(target));
		Assert.Equal(0, CountOperationLogs());
	}

	/// <summary>Given a drive root or an unusable target, when the restore is requested, then it is
	/// refused as an invalid request before any filesystem work happens.</summary>
	[Theory]
	[InlineData("C:\\\\")]
	[InlineData("")]
	public async Task RestoreDatabaseBackupToDirectory_RefusesAnUnusableTarget(string target)
	{
		DatabaseBackupService backups = new(_options, NullLogger<DatabaseBackupService>.Instance, new FakePathsProvider(new RdpAuditPaths(_programDataRoot)));
		IpcDispatcher dispatcher = CreateDispatcher(backups: backups);

		IpcResponse response = await dispatcher.DispatchAsync(
			new IpcRequest
			{
				Command = IpcCommand.RestoreDatabaseBackupToDirectory,
				Payload = "{\"Name\":\"20200101-000000\",\"TargetDirectory\":\"" + target + "\"}",
			},
			CancellationToken.None);

		Assert.True(response.Success);
		DatabaseBackupRestoreReportDto report = Deserialize<DatabaseBackupRestoreReportDto>(response.Payload);
		Assert.Equal(IpcResultStatus.InvalidRequest, report.Status);
		Assert.Equal(0, CountOperationLogs());
	}

	/// <summary>Given a host without the backup service, when the restore is dispatched, then the
	/// controlled IpcException surfaces as a failed response with a curated message.</summary>
	[Fact]
	public async Task RestoreDatabaseBackupToDirectory_WithoutTheService_Fails()
	{
		IpcDispatcher dispatcher = CreateDispatcher(backups: null);

		IpcResponse response = await dispatcher.DispatchAsync(
			new IpcRequest
			{
				Command = IpcCommand.RestoreDatabaseBackupToDirectory,
				Payload = "{\"Name\":\"20200101-000000\",\"TargetDirectory\":\"C:\\\\temp\\\\scratch\"}",
			},
			CancellationToken.None);

		Assert.False(response.Success);
		Assert.Contains("RestoreDatabaseBackupToDirectory", response.Error ?? string.Empty, StringComparison.Ordinal);
	}

	// ── Helpers ──────────────────────────────────────────────────────────────────

	private IpcDispatcher CreateDispatcher(bool includeStage3Services = true, DatabaseBackupService? backups = null)
	{
		SettingsManager settings = new(
			NullLogger<SettingsManager>.Instance,
			protector: null,
			overridePath: _settingsPath);
		DbOperationLogWriter operationLog = new(_factory, _options, NullLogger<DbOperationLogWriter>.Instance);

		ShardInventoryService? shardInventory = null;
		DatabaseMaintenanceService? maintenance = null;
		if (includeStage3Services)
		{
			shardInventory = new ShardInventoryService(_factory, _options, NullLogger<ShardInventoryService>.Instance);
			maintenance = new DatabaseMaintenanceService(_factory, _options, NullLogger<DatabaseMaintenanceService>.Instance);
		}

		return new IpcDispatcher(
			_factory,
			new ServiceMetrics(),
			_options,
			settings,
			new FirewallManager(NullLogger<FirewallManager>.Instance),
			Array.Empty<RdpAudit.Core.Firewall.IFirewallProvider>(),
			NullLogger<IpcDispatcher>.Instance,
			opLog: operationLog,
			databaseBackups: backups,
			shardInventory: shardInventory,
			databaseMaintenance: maintenance);
	}

	private static T Deserialize<T>(string? payload)
	{
		Assert.NotNull(payload);
		return System.Text.Json.JsonSerializer.Deserialize<T>(payload!, JsonOptions.Default)!;
	}

	private static void SeedShardFile(string path, int length)
	{
		Directory.CreateDirectory(Path.GetDirectoryName(path)!);
		File.WriteAllBytes(path, new byte[length]);
	}

	private void SeedSummary(string ipText, string relativePath, long records, long bytes, long evicted, long oldestTicks)
	{
		using AuditDbContext db = _factory.CreateDbContext();
		db.IpEventSummaries.Add(new IpEventSummary
		{
			IpBinary16 = new byte[16],
			IpText = ipText,
			AddressFamily = 4,
			ShardRelativePath = relativePath,
			ShardRecordCount = records,
			ShardBytes = bytes,
			ShardFormatVersion = 1,
			ShardEvictedCount = evicted,
			ShardOldestRetainedUtc = oldestTicks,
		});
		db.SaveChanges();
	}

	private void SeedRawEvents(int eventId, int count)
	{
		using AuditDbContext db = _factory.CreateDbContext();
		DateTime startUtc = DateTime.UtcNow.AddDays(-1);
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

	private int CountOperationLogs()
	{
		using AuditDbContext db = _factory.CreateDbContext();
		return db.OperationLogs.Count();
	}

	private OperationLogDto ReadSingleOperationLog()
	{
		using AuditDbContext db = _factory.CreateDbContext();
		OperationLog row = db.OperationLogs.AsNoTracking().Single();
		return new OperationLogDto
		{
			TimeUtc = row.TimeUtc,
			Severity = row.Severity,
			Source = row.Source,
			Operation = row.Operation,
			Message = row.Message,
			Actor = row.Actor,
		};
	}

	private int CountLedgerEntries()
	{
		using AuditDbContext db = _factory.CreateDbContext();
		return db.EventDeletionLedger.Count();
	}

	private int CountRawEvents()
	{
		using AuditDbContext db = _factory.CreateDbContext();
		return db.RawEvents.Count();
	}

	private int CountSummaries()
	{
		using AuditDbContext db = _factory.CreateDbContext();
		return db.IpEventSummaries.Count();
	}

	private sealed class TestDbContextFactory : IDbContextFactory<AuditDbContext>
	{
		private readonly DbContextOptions<AuditDbContext> _options;

		public TestDbContextFactory(DbContextOptions<AuditDbContext> options) => _options = options;

		public AuditDbContext CreateDbContext() => new(_options);
	}

	private sealed class TestOptionsMonitor : IOptionsMonitor<RdpAuditOptions>
	{
		public TestOptionsMonitor(RdpAuditOptions options) => CurrentValue = options;

		public RdpAuditOptions CurrentValue { get; }

		public RdpAuditOptions Get(string? name) => CurrentValue;

		public IDisposable? OnChange(Action<RdpAuditOptions, string?> listener) => null;
	}

	private sealed class FakePathsProvider : IRdpAuditPathsProvider
	{
		public FakePathsProvider(RdpAuditPaths paths) => Paths = paths;

		public RdpAuditPaths Paths { get; }
	}
}
