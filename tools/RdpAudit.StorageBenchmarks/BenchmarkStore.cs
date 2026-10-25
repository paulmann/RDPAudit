/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.2
// File   : BenchmarkStore.cs
// Project: RdpAudit.StorageBenchmarks
// Purpose: One benchmark store: its directory, the real product options that point at it, and the
//          DbContext factory the real product services consume. A probe never builds its own context
//          options - it asks a BenchmarkStore - so every measured operation ran against a store built
//          exactly the way the service builds one (same connection string, same WAL/synchronous/
//          auto_vacuum pragmas through the product's own SqlitePragmaInterceptor).
//          The repetition model lives here too: a retention sample needs the SAME starting state as the
//          previous sample, so each sample runs against its own copy of the seeded store rather than
//          against the remains of the last pass.
// Depends: AuditDbContextOptionsFactory, SqlitePragmaInterceptor, RdpAuditOptions
// Extends: Add a store-level fact as a method here; never open a connection to the benchmark database
//          from a probe without going through this type.

using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using RdpAudit.Core.Config;
using RdpAudit.Core.Data;
using RdpAudit.Core.Util;

namespace RdpAudit.StorageBenchmarks;

/// <summary>
/// The configuration every store in a run shares: the retention policy, backup settings and sharding
/// settings the probes drive. Directory-valued settings are already resolved to this run's workspace.
/// </summary>
internal sealed record StoreBlueprint
{
	/// <summary>Retention policy the retention probes evaluate and execute.</summary>
	public required RetentionPolicyOptions Retention { get; init; }

	/// <summary>Backup settings, with the backup root pointed at this run's snapshot directory.</summary>
	public required BackupOptions Backup { get; init; }

	/// <summary>Sharding settings, with the actions root pointed at this run's shard tree.</summary>
	public required ShardingOptions Sharding { get; init; }
}

/// <summary>A store this run owns, with the product options and context factory that address it.</summary>
internal sealed class BenchmarkStore
{
	private BenchmarkStore(string directory, StoreBlueprint blueprint)
	{
		Directory = Path.GetFullPath(directory);
		DatabasePath = Path.Combine(Directory, RdpAuditPaths.DatabaseFileName);
		Options = new RdpAuditOptions
		{
			Storage = new StorageOptions
			{
				DatabasePath = DatabasePath,
				RetentionPolicy = blueprint.Retention,
				Backup = blueprint.Backup,
			},
			Sharding = blueprint.Sharding,
		};
		OptionsMonitor = new SimpleOptionsMonitor<RdpAuditOptions>(Options);
		Factory = new DirectDbContextFactory(
			AuditDbContextOptionsFactory.Create(DatabasePath, new SqlitePragmaInterceptor()));
	}

	/// <summary>Directory holding the database.</summary>
	public string Directory { get; }

	/// <summary>Absolute path of the database file.</summary>
	public string DatabasePath { get; }

	/// <summary>The product options every probe reads its settings from.</summary>
	public RdpAuditOptions Options { get; }

	/// <summary>Monitor wrapper handed to the real product services.</summary>
	public IOptionsMonitor<RdpAuditOptions> OptionsMonitor { get; }

	/// <summary>Context factory handed to the real product services.</summary>
	public DirectDbContextFactory Factory { get; }

	/// <summary>Creates the store handle for <paramref name="directory"/>; creates no file yet.</summary>
	public static BenchmarkStore Create(string directory, StoreBlueprint blueprint)
	{
		ArgumentNullException.ThrowIfNull(blueprint);
		return new BenchmarkStore(directory, blueprint);
	}

	/// <summary>Applies the product's EF migrations, producing an empty store with the production schema.</summary>
	public async Task MigrateAsync(CancellationToken cancellationToken)
	{
		await using AuditDbContext db = await Factory.CreateDbContextAsync(cancellationToken).ConfigureAwait(false);
		await db.Database.MigrateAsync(cancellationToken).ConfigureAwait(false);
	}

	/// <summary>Counts the raw-event rows in the store.</summary>
	public async Task<long> CountRawEventsAsync(CancellationToken cancellationToken)
	{
		await using AuditDbContext db = await Factory.CreateDbContextAsync(cancellationToken).ConfigureAwait(false);
		return await db.RawEvents.LongCountAsync(cancellationToken).ConfigureAwait(false);
	}

	/// <summary>Copies this store's database family into <paramref name="destinationDirectory"/>, so a
	/// repeated measurement starts from byte-identical state instead of from the remains of the last
	/// pass. The source is only read.</summary>
	public BenchmarkStore CloneTo(string destinationDirectory, StoreBlueprint blueprint)
	{
		// Fully qualified: this type exposes a Directory property that would otherwise shadow the type.
		System.IO.Directory.CreateDirectory(destinationDirectory);
		CopyFamily(Directory, destinationDirectory);
		return Create(destinationDirectory, blueprint);
	}

	/// <summary>Copies the database file and its <c>-wal</c> and <c>-shm</c> sidecars.</summary>
	public static void CopyFamily(string sourceDirectory, string destinationDirectory)
	{
		foreach (string suffix in new[] { string.Empty, "-wal", "-shm" })
		{
			string source = Path.Combine(sourceDirectory, RdpAuditPaths.DatabaseFileName + suffix);
			if (File.Exists(source))
			{
				File.Copy(source, Path.Combine(destinationDirectory, RdpAuditPaths.DatabaseFileName + suffix), overwrite: true);
			}
		}
	}
}
