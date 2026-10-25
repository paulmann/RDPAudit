/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : AuditDbInitializerCompositionTests.cs
// Project: RdpAudit.Service.Tests (RdpAudit.Service.Tests)
// Purpose: Proves the dependency-injection wiring the mandatory pre-migration snapshot depends on. The
//          initializer takes its snapshot provider as an optional third constructor parameter, and the
//          whole protection is silently worthless if the container resolves the two-parameter constructor
//          instead. This test builds the same registration shape the service host uses, resolves
//          AuditDbInitializer through it, runs it against a database with one pending migration, and
//          asserts that the snapshot the provider was asked for actually exists on disk as a
//          PreMigration snapshot. No reflection into private state: the evidence is the artifact.
// Depends: AuditDbInitializer, DatabaseBackupService, ServiceCollection, AuditDbContext, xUnit
// Extends: Extend this test whenever AuditDbInitializer gains another host-provided dependency, so a
//          missing registration fails here instead of silently disabling a startup guarantee.

using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using RdpAudit.Core.Backup;
using RdpAudit.Core.Config;
using RdpAudit.Core.Data;
using RdpAudit.Core.Util;
using RdpAudit.Service.Services;
using Xunit;

namespace RdpAudit.Service.Tests;

public sealed class AuditDbInitializerCompositionTests : IDisposable
{
	// ── Fields & DI ──────────────────────────────────────────────────────────────

	private readonly string _root;
	private readonly string _backupRoot;
	private readonly string _databasePath;
	private readonly DbContextOptions<AuditDbContext> _dbOptions;
	private readonly RdpAuditOptions _options;

	public AuditDbInitializerCompositionTests()
	{
		_root = Path.Combine(Path.GetTempPath(), "rdpaudit-composition-" + Guid.NewGuid().ToString("N"));
		_backupRoot = Path.Combine(_root, "Backups");
		Directory.CreateDirectory(_root);
		_databasePath = Path.Combine(_root, "rdpaudit.db");

		_dbOptions = new DbContextOptionsBuilder<AuditDbContext>()
			.UseSqlite($"Data Source={_databasePath};Cache=Shared")
			.AddInterceptors(new SqlitePragmaInterceptor())
			.Options;

		_options = new RdpAuditOptions();
		_options.Storage.DatabasePath = _databasePath;
		_options.Storage.Backup.BackupDirectory = _backupRoot;
	}

	public void Dispose()
	{
		try
		{
			SqliteConnection.ClearAllPools();
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

	/// <summary>
	/// Given the service host's registration shape, when AuditDbInitializer is resolved from the
	/// container and applied to a database with one pending migration, then the pre-migration snapshot
	/// exists on disk with a PreMigration manifest. That can only happen if the container injected the
	/// snapshot provider, which is what this test exists to hold.
	/// </summary>
	[Fact]
	public async Task ServiceProvider_InjectsThePreMigrationBackupProviderIntoTheInitializer()
	{
		List<string> known = KnownMigrations();
		Assert.True(known.Count >= 2, "The suite needs at least two migrations to leave one pending.");
		MigrateTo(known[^2]);

		ServiceCollection services = new();
		services.AddLogging();
		services.AddSingleton<IDbContextFactory<AuditDbContext>>(new FileDbContextFactory(_dbOptions));
		services.AddSingleton<IOptionsMonitor<RdpAuditOptions>>(new StubOptionsMonitor(_options));
		services.AddSingleton<IRdpAuditPathsProvider>(new FakePathsProvider(new RdpAuditPaths(_root)));
		// The three registration lines that matter, copied from Program.RegisterServices: the snapshot
		// engine is one singleton serving two roles.
		services.AddSingleton<DatabaseBackupService>();
		services.AddSingleton<IPreMigrationBackupProvider>(sp => sp.GetRequiredService<DatabaseBackupService>());
		services.AddSingleton<AuditDbInitializer>();

		await using ServiceProvider provider = services.BuildServiceProvider();
		IPreMigrationBackupProvider injected = provider.GetRequiredService<IPreMigrationBackupProvider>();
		Assert.Same(provider.GetRequiredService<DatabaseBackupService>(), injected);
		Assert.True(injected.IsEnabled, "The pre-migration snapshot must be enabled by default.");

		AuditDbInitializer initializer = provider.GetRequiredService<AuditDbInitializer>();
		await initializer.EnsureCreatedAsync(CancellationToken.None);

		Assert.Equal(known.Count, AppliedMigrationCount());
		string snapshot = Assert.Single(Directory.GetDirectories(_backupRoot));
		Assert.True(
			DatabaseBackupManifestCodec.TryRead(
				Path.Combine(snapshot, DatabaseBackupLayout.ManifestFileName),
				out DatabaseBackupManifest? manifest,
				out string? error),
			"Expected a readable snapshot manifest: " + error);
		Assert.Equal(DatabaseBackupKind.PreMigration, manifest!.Kind);
		Assert.Equal(known.Count - 1, manifest.AppliedMigrationCount);
		Assert.False(File.Exists(Path.Combine(_root, DatabaseMigrationFailureMarker.FileName)));
	}

	// ── Harness ──────────────────────────────────────────────────────────────────

	private List<string> KnownMigrations()
	{
		using AuditDbContext db = new(_dbOptions);
		return [.. db.Database.GetMigrations()];
	}

	private void MigrateTo(string targetMigration)
	{
		using AuditDbContext db = new(_dbOptions);
		db.GetService<IMigrator>().Migrate(targetMigration);
	}

	private int AppliedMigrationCount()
	{
		using Microsoft.Data.Sqlite.SqliteConnection connection = new($"Data Source={_databasePath};Cache=Private;Pooling=False");
		connection.Open();
		using Microsoft.Data.Sqlite.SqliteCommand command = connection.CreateCommand();
		command.CommandText = "SELECT COUNT(*) FROM \"__EFMigrationsHistory\";";
		return Convert.ToInt32(command.ExecuteScalar(), System.Globalization.CultureInfo.InvariantCulture);
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
