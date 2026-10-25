/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : IpcDispatcherDatabaseBackupTests.cs
// Project: RdpAudit.Service.Tests (RdpAudit.Service.Tests)
// Purpose: Drives the three new Database-tab commands through the real dispatcher (ordinals 85-87).
//          CreateDatabaseBackup must be the only one that mutates, it must refuse a host whose snapshot
//          feature is switched off without writing anything, and a successful create must leave an
//          OperationLog row carrying the invoking identity, the snapshot count before and after and the
//          resulting path. ListDatabaseBackups and VerifyDatabaseBackup must stay read-only, must report
//          an Unavailable typed answer on a host that did not register the service instead of throwing,
//          and must distinguish "no snapshot yet" from "the snapshot is damaged".
// Depends: IpcDispatcher, DatabaseBackupService, DbOperationLogWriter, AuditDbContext, xUnit
// Extends: Add a scenario here whenever a backup command gains a branch that changes what it writes.

using System.Text.Json;
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

public sealed class IpcDispatcherDatabaseBackupTests : IDisposable
{
	// ── Fields & DI ──────────────────────────────────────────────────────────────

	private readonly string _root;
	private readonly string _backupRoot;
	private readonly string _databasePath;
	private readonly RdpAuditOptions _options;
	private readonly DbContextOptions<AuditDbContext> _dbOptions;
	private readonly IDbContextFactory<AuditDbContext> _factory;
	private readonly DatabaseBackupService _backups;

	public IpcDispatcherDatabaseBackupTests()
	{
		_root = Path.Combine(Path.GetTempPath(), "rdpaudit-backup-ipc-" + Guid.NewGuid().ToString("N"));
		_backupRoot = Path.Combine(_root, "Backups");
		string storeDirectory = Path.Combine(_root, "store");
		Directory.CreateDirectory(storeDirectory);
		_databasePath = Path.Combine(storeDirectory, "rdpaudit.db");

		_dbOptions = new DbContextOptionsBuilder<AuditDbContext>()
			.UseSqlite($"Data Source={_databasePath};Cache=Shared")
			.AddInterceptors(new SqlitePragmaInterceptor())
			.Options;
		_factory = new FileDbContextFactory(_dbOptions);

		_options = new RdpAuditOptions();
		_options.Storage.DatabasePath = _databasePath;
		_options.Storage.Backup.Enabled = true;
		_options.Storage.Backup.BackupDirectory = _backupRoot;

		_backups = new DatabaseBackupService(
			new StubOptionsMonitor(_options),
			NullLogger<DatabaseBackupService>.Instance,
			new FakePathsProvider(new RdpAuditPaths(_root)));
	}

	public void Dispose()
	{
		try
		{
			Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
			if (Directory.Exists(_root))
			{
				Directory.Delete(_root, recursive: true);
			}
		}
		catch (IOException)
		{
		}
		catch (UnauthorizedAccessException)
		{
		}
	}

	// ── CreateDatabaseBackup ─────────────────────────────────────────────────────

	/// <summary>Given the snapshot feature enabled, when the command runs, then a snapshot is published,
	/// the answer reports its path and digests, and exactly one OperationLog row records the invoking
	/// identity, the snapshot count before and after and the artifact path.</summary>
	[Fact]
	public async Task CreateDatabaseBackup_WritesTheSnapshotAndAuditsIt()
	{
		await MigrateAllAsync();
		IpcDispatcher dispatcher = CreateDispatcher();

		IpcResponse response = await dispatcher.DispatchAsync(
			new IpcRequest
			{
				Command = IpcCommand.CreateDatabaseBackup,
				Payload = JsonSerializer.Serialize(new CreateDatabaseBackupRequest(), JsonOptions.Default),
			},
			CancellationToken.None,
			callerIdentity: "CONTOSO\\operator");

		Assert.True(response.Success);
		DatabaseBackupCreationDto dto = Deserialize<DatabaseBackupCreationDto>(response.Payload);
		Assert.Equal(IpcResultStatus.Success, dto.Status);
		Assert.Equal(DatabaseBackupKind.Manual, dto.Kind);
		Assert.True(File.Exists(Path.Combine(dto.SnapshotDirectory, "db", "rdpaudit.db")));
		Assert.Equal(0, dto.SnapshotCountBefore);
		Assert.Equal(1, dto.SnapshotCountAfter);
		Assert.False(string.IsNullOrWhiteSpace(dto.DatabaseSha256));

		List<OperationLog> rows = ReadOperationLogs();
		OperationLog audit = Assert.Single(rows);
		Assert.Equal("Database", audit.Source);
		Assert.Equal("CreateDatabaseBackup", audit.Operation);
		Assert.Equal("Operator:CONTOSO\\operator", audit.Actor);
		Assert.Contains("snapshotsBefore=0", audit.Message, StringComparison.Ordinal);
		Assert.Contains("snapshotsAfter=1", audit.Message, StringComparison.Ordinal);
		Assert.Contains(dto.SnapshotDirectory, audit.Message, StringComparison.Ordinal);
		Assert.Contains(dto.DatabaseSha256, audit.Message, StringComparison.Ordinal);

		// Structured details are a DEBUG-only column by design (the OperationLog writer drops them when
		// DebugMode is off), so the guaranteed audit facts live in the message the assertion above pins.
		Assert.Null(audit.DetailsJson);
	}

	/// <summary>Given the snapshot feature switched off, when the command runs, then it is refused with a
	/// message naming the setting, no snapshot is written and no audit row claims otherwise: a refused
	/// action changed nothing, so it must not look like an executed one.</summary>
	[Fact]
	public async Task CreateDatabaseBackup_WhenTheFeatureIsDisabled_RefusesWithoutWritingAnything()
	{
		await MigrateAllAsync();
		_options.Storage.Backup.Enabled = false;
		IpcDispatcher dispatcher = CreateDispatcher();

		IpcResponse response = await dispatcher.DispatchAsync(
			new IpcRequest { Command = IpcCommand.CreateDatabaseBackup },
			CancellationToken.None);

		Assert.True(response.Success);
		DatabaseBackupCreationDto dto = Deserialize<DatabaseBackupCreationDto>(response.Payload);
		Assert.Equal(IpcResultStatus.Refused, dto.Status);
		Assert.Contains("Storage:Backup:Enabled", dto.Message!, StringComparison.Ordinal);
		Assert.False(Directory.Exists(_backupRoot));
		Assert.Empty(ReadOperationLogs());
	}

	/// <summary>Given a host that did not register the snapshot service, when the command runs, then the
	/// dispatcher returns a controlled error rather than an unhandled exception, so a stale client gets a
	/// readable reason.</summary>
	[Fact]
	public async Task CreateDatabaseBackup_WithoutTheService_ReturnsAControlledError()
	{
		IpcDispatcher dispatcher = CreateDispatcher(includeBackups: false);

		IpcResponse response = await dispatcher.DispatchAsync(
			new IpcRequest { Command = IpcCommand.CreateDatabaseBackup },
			CancellationToken.None);

		Assert.False(response.Success);
		Assert.Contains("not available in this host", response.Error!, StringComparison.Ordinal);
	}

	/// <summary>Given a malformed payload, when the create command runs, then it is refused as invalid
	/// input before anything is written.</summary>
	[Fact]
	public async Task CreateDatabaseBackup_WithAMalformedPayload_IsRefused()
	{
		await MigrateAllAsync();
		IpcDispatcher dispatcher = CreateDispatcher();

		IpcResponse response = await dispatcher.DispatchAsync(
			new IpcRequest { Command = IpcCommand.CreateDatabaseBackup, Payload = "{ not json" },
			CancellationToken.None);

		Assert.False(response.Success);
		Assert.False(Directory.Exists(_backupRoot));
	}

	// ── ListDatabaseBackups ──────────────────────────────────────────────────────

	/// <summary>Given no snapshots exist, when the list is requested, then it is an honest empty
	/// inventory that still reports the effective settings, and nothing on disk changes.</summary>
	[Fact]
	public async Task ListDatabaseBackups_OnAFreshHost_ReturnsAnEmptyInventory()
	{
		await MigrateAllAsync();
		IpcDispatcher dispatcher = CreateDispatcher();

		IpcResponse response = await dispatcher.DispatchAsync(
			new IpcRequest { Command = IpcCommand.ListDatabaseBackups },
			CancellationToken.None);

		Assert.True(response.Success);
		DatabaseBackupListDto dto = Deserialize<DatabaseBackupListDto>(response.Payload);
		Assert.Equal(IpcResultStatus.Success, dto.Status);
		Assert.Empty(dto.Entries);
		Assert.Equal(0, dto.TotalCount);
		Assert.False(dto.Truncated);
		Assert.True(dto.Enabled);
		Assert.True(dto.PreMigrationBackupEnabled);
		Assert.Equal(5, dto.RetentionCopies);
		Assert.Equal(Path.GetFullPath(_backupRoot), dto.BackupDirectory);

		// Read-only: an inventory never creates the backup root, let alone a snapshot.
		Assert.False(Directory.Exists(_backupRoot));
		Assert.Empty(ReadOperationLogs());
	}

	/// <summary>Given a snapshot exists, when the list is requested, then it appears newest first with
	/// its manifest verdict, and the command did not create, verify or delete anything.</summary>
	[Fact]
	public async Task ListDatabaseBackups_AfterACreate_ReturnsTheSnapshot()
	{
		await MigrateAllAsync();
		DatabaseBackupCreationDto created = await CreateSnapshotDirectlyAsync();
		IpcDispatcher dispatcher = CreateDispatcher();

		IpcResponse response = await dispatcher.DispatchAsync(
			new IpcRequest { Command = IpcCommand.ListDatabaseBackups },
			CancellationToken.None);

		DatabaseBackupListDto dto = Deserialize<DatabaseBackupListDto>(response.Payload);
		DatabaseBackupEntryDto entry = Assert.Single(dto.Entries);
		Assert.Equal(created.SnapshotName, entry.Name);
		Assert.True(entry.ManifestValid);
		Assert.Equal(DatabaseBackupKind.Manual, entry.Kind);
		Assert.Equal(created.DatabaseSha256, entry.DatabaseSha256);
		Assert.True(entry.RowCounts.ContainsKey("RawEvents"));
	}

	/// <summary>Given a host that did not register the service, when the list is requested, then the
	/// answer is a typed Unavailable instead of an exception.</summary>
	[Fact]
	public async Task ListDatabaseBackups_WithoutTheService_ReportsUnavailable()
	{
		IpcDispatcher dispatcher = CreateDispatcher(includeBackups: false);

		IpcResponse response = await dispatcher.DispatchAsync(
			new IpcRequest { Command = IpcCommand.ListDatabaseBackups },
			CancellationToken.None);

		Assert.True(response.Success);
		DatabaseBackupListDto dto = Deserialize<DatabaseBackupListDto>(response.Payload);
		Assert.Equal(IpcResultStatus.Unavailable, dto.Status);
		Assert.Contains("not available", dto.Message!, StringComparison.OrdinalIgnoreCase);
	}

	// ── VerifyDatabaseBackup ─────────────────────────────────────────────────────

	/// <summary>Given a sound snapshot and no payload, when verification runs, then the newest snapshot is
	/// verified end to end - digest, quick_check and the schema comparison against the running
	/// binaries.</summary>
	[Fact]
	public async Task VerifyDatabaseBackup_WithoutAName_VerifiesTheNewestSnapshot()
	{
		await MigrateAllAsync();
		await CreateSnapshotDirectlyAsync();
		IpcDispatcher dispatcher = CreateDispatcher();

		IpcResponse response = await dispatcher.DispatchAsync(
			new IpcRequest { Command = IpcCommand.VerifyDatabaseBackup },
			CancellationToken.None);

		Assert.True(response.Success);
		DatabaseBackupVerificationDto dto = Deserialize<DatabaseBackupVerificationDto>(response.Payload);
		Assert.Equal(IpcResultStatus.Success, dto.Status);
		Assert.Equal(DatabaseSnapshotVerdict.Ok, dto.Verdict);
		Assert.True(dto.IsUsable);
		Assert.Equal("ok", dto.QuickCheckResult);
		Assert.Equal(SchemaCompatibilityVerdict.Compatible, dto.SchemaVerdict);
		Assert.Equal(dto.ExpectedSha256, dto.ActualSha256);
		Assert.Empty(ReadOperationLogs());
	}

	/// <summary>Given no snapshot exists at all, when verification runs, then it is a typed NotFound that
	/// says there is nothing to verify - not an error and not a false "ok".</summary>
	[Fact]
	public async Task VerifyDatabaseBackup_WithNoSnapshots_ReportsNotFound()
	{
		IpcDispatcher dispatcher = CreateDispatcher();

		IpcResponse response = await dispatcher.DispatchAsync(
			new IpcRequest { Command = IpcCommand.VerifyDatabaseBackup },
			CancellationToken.None);

		Assert.True(response.Success);
		DatabaseBackupVerificationDto dto = Deserialize<DatabaseBackupVerificationDto>(response.Payload);
		Assert.Equal(IpcResultStatus.NotFound, dto.Status);
		Assert.False(dto.IsUsable);
	}

	/// <summary>Given a snapshot name that does not exist, when verification runs, then it is refused by
	/// name, so a client cannot mistake a typo for a healthy snapshot.</summary>
	[Fact]
	public async Task VerifyDatabaseBackup_WithAnUnknownName_ReportsNotFound()
	{
		await MigrateAllAsync();
		await CreateSnapshotDirectlyAsync();
		IpcDispatcher dispatcher = CreateDispatcher();

		IpcResponse response = await dispatcher.DispatchAsync(
			new IpcRequest
			{
				Command = IpcCommand.VerifyDatabaseBackup,
				Payload = JsonSerializer.Serialize(
					new VerifyDatabaseBackupRequest { Name = "20200101-000000" },
					JsonOptions.Default),
			},
			CancellationToken.None);

		DatabaseBackupVerificationDto dto = Deserialize<DatabaseBackupVerificationDto>(response.Payload);
		Assert.Equal(IpcResultStatus.NotFound, dto.Status);
		Assert.Contains("20200101-000000", dto.Message!, StringComparison.Ordinal);
	}

	/// <summary>Given a snapshot whose database was modified after it was taken, when verification runs,
	/// then the verdict is a hash mismatch and both digests are reported - the command still succeeds,
	/// because the verification did its job.</summary>
	[Fact]
	public async Task VerifyDatabaseBackup_OnATamperedSnapshot_ReportsAHashMismatch()
	{
		await MigrateAllAsync();
		DatabaseBackupCreationDto created = await CreateSnapshotDirectlyAsync();
		string snapshotDatabase = Path.Combine(created.SnapshotDirectory, "db", "rdpaudit.db");
		using (FileStream stream = new(snapshotDatabase, FileMode.Open, FileAccess.ReadWrite))
		{
			stream.Position = stream.Length / 2;
			int original = stream.ReadByte();
			stream.Position = stream.Length / 2;
			stream.WriteByte((byte)(original ^ 0xFF));
		}

		IpcDispatcher dispatcher = CreateDispatcher();
		IpcResponse response = await dispatcher.DispatchAsync(
			new IpcRequest { Command = IpcCommand.VerifyDatabaseBackup },
			CancellationToken.None);

		DatabaseBackupVerificationDto dto = Deserialize<DatabaseBackupVerificationDto>(response.Payload);
		Assert.Equal(IpcResultStatus.Success, dto.Status);
		Assert.Equal(DatabaseSnapshotVerdict.HashMismatch, dto.Verdict);
		Assert.False(dto.IsUsable);
		Assert.Equal(created.DatabaseSha256, dto.ExpectedSha256);
	}

	/// <summary>Given a host that did not register the service, when verification is requested, then the
	/// answer is a typed Unavailable instead of an exception.</summary>
	[Fact]
	public async Task VerifyDatabaseBackup_WithoutTheService_ReportsUnavailable()
	{
		IpcDispatcher dispatcher = CreateDispatcher(includeBackups: false);

		IpcResponse response = await dispatcher.DispatchAsync(
			new IpcRequest { Command = IpcCommand.VerifyDatabaseBackup },
			CancellationToken.None);

		Assert.True(response.Success);
		DatabaseBackupVerificationDto dto = Deserialize<DatabaseBackupVerificationDto>(response.Payload);
		Assert.Equal(IpcResultStatus.Unavailable, dto.Status);
	}

	/// <summary>Given a malformed payload, when verification runs, then it is refused as invalid input
	/// rather than silently verifying the newest snapshot.</summary>
	[Fact]
	public async Task VerifyDatabaseBackup_WithAMalformedPayload_IsRefused()
	{
		IpcDispatcher dispatcher = CreateDispatcher();

		IpcResponse response = await dispatcher.DispatchAsync(
			new IpcRequest { Command = IpcCommand.VerifyDatabaseBackup, Payload = "[1,2,3]" },
			CancellationToken.None);

		Assert.False(response.Success);
	}

	// ── Harness ──────────────────────────────────────────────────────────────────

	private IpcDispatcher CreateDispatcher(bool includeBackups = true)
	{
		StubOptionsMonitor monitor = new(_options);
		SettingsManager settings = new(NullLogger<SettingsManager>.Instance, protector: null);
		DbOperationLogWriter operationLog = new(_factory, monitor, NullLogger<DbOperationLogWriter>.Instance);

		return new IpcDispatcher(
			_factory,
			new ServiceMetrics(),
			monitor,
			settings,
			new FirewallManager(NullLogger<FirewallManager>.Instance),
			Array.Empty<RdpAudit.Core.Firewall.IFirewallProvider>(),
			NullLogger<IpcDispatcher>.Instance,
			opLog: operationLog,
			databaseBackups: includeBackups ? _backups : null);
	}

	private async Task MigrateAllAsync()
	{
		await using AuditDbContext db = new(_dbOptions);
		await db.Database.MigrateAsync(CancellationToken.None);
	}

	private async Task<DatabaseBackupCreationDto> CreateSnapshotDirectlyAsync()
	{
		await using AuditDbContext db = new(_dbOptions);
		if (!db.RawEvents.Any())
		{
			db.RawEvents.Add(new RawEvent
			{
				EventId = 4625,
				Channel = "Security",
				TimeUtc = DateTime.UtcNow,
			});
			await db.SaveChangesAsync(CancellationToken.None);
		}

		return await _backups.CreateSnapshotAsync(
			_databasePath,
			includeShards: false,
			DatabaseBackupKind.Manual,
			CancellationToken.None);
	}

	private List<OperationLog> ReadOperationLogs()
	{
		using AuditDbContext db = new(_dbOptions);
		return [.. db.OperationLogs.AsNoTracking().OrderBy(row => row.Id)];
	}

	private static T Deserialize<T>(string? payload)
	{
		Assert.False(string.IsNullOrWhiteSpace(payload));
		return JsonSerializer.Deserialize<T>(payload!, JsonOptions.Default)!;
	}

	// ── Test doubles ─────────────────────────────────────────────────────────────

	private sealed class FileDbContextFactory : IDbContextFactory<AuditDbContext>
	{
		private readonly DbContextOptions<AuditDbContext> _options;

		public FileDbContextFactory(DbContextOptions<AuditDbContext> options) => _options = options;

		public AuditDbContext CreateDbContext() => new(_options);
	}

	private sealed class FakePathsProvider : IRdpAuditPathsProvider
	{
		public FakePathsProvider(RdpAuditPaths paths) => Paths = paths;

		public RdpAuditPaths Paths { get; }
	}

	private sealed class StubOptionsMonitor : IOptionsMonitor<RdpAuditOptions>
	{
		private readonly RdpAuditOptions _options;

		public StubOptionsMonitor(RdpAuditOptions options) => _options = options;

		public RdpAuditOptions CurrentValue => _options;

		public RdpAuditOptions Get(string? name) => _options;

		public IDisposable? OnChange(Action<RdpAuditOptions, string?> listener) => null;
	}
}
