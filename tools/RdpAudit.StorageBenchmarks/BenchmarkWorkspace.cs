/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.2
// File   : BenchmarkWorkspace.cs
// Project: RdpAudit.StorageBenchmarks
// Purpose: The safety boundary of the whole tool, and the reason it can be run on a production host.
//          Everything this run creates lives under one directory it owns, and the two ways a benchmark
//          could damage a live installation are refused before a single file is opened:
//            - a --store directory that already holds rdpaudit.db is refused unless the operator says
//              --allow-existing-store, and even then the run works on a COPY and never opens the
//              original for writing;
//            - any store or report path inside the production %ProgramData%\RdpAudit tree is refused
//              unconditionally, with no override, because that tree is the evidence store.
//          The production directory is only ever READ as a string here; no file under it is created,
//          opened, moved or deleted.
// Depends: RdpAuditPaths (for the production root and the database file name)
// Extends: Add a path this run owns by adding it here; never let a probe invent its own directory.

using System.Globalization;
using RdpAudit.Core.Util;

namespace RdpAudit.StorageBenchmarks;

/// <summary>Outcome of preparing a workspace: either one, or the reason the run refused to start.</summary>
internal sealed record BenchmarkWorkspaceResult
{
	/// <summary>The prepared workspace, or null when the run was refused.</summary>
	public BenchmarkWorkspace? Workspace { get; init; }

	/// <summary>The refusal, in operator-facing language, or null when the run may proceed.</summary>
	public string? Refusal { get; init; }
}

/// <summary>
/// The directories one benchmark run owns, plus the guards that decide whether it may start.
/// </summary>
internal sealed class BenchmarkWorkspace : IDisposable
{
	/// <summary>Sub-directory of the work root holding reports. Reports outlive the run, so they are
	/// deliberately NOT inside the run directory that <see cref="Dispose"/> removes.</summary>
	public const string ReportsFolderName = "reports";

	private readonly bool _ownsStoreDirectory;

	private BenchmarkWorkspace(
		string runDirectory,
		string storeDirectory,
		string reportDirectory,
		string actionsRoot,
		string snapshotRoot,
		bool ownsStoreDirectory,
		string? copiedFrom)
	{
		RunDirectory = runDirectory;
		StoreDirectory = storeDirectory;
		ReportDirectory = reportDirectory;
		ActionsRoot = actionsRoot;
		SnapshotRoot = snapshotRoot;
		_ownsStoreDirectory = ownsStoreDirectory;
		CopiedFrom = copiedFrom;
	}

	/// <summary>Directory this run created and will remove. Null-free; always set. When the operator
	/// supplied an empty <c>--store</c> directory the store does NOT live here.</summary>
	public string RunDirectory { get; }

	/// <summary>Directory holding the benchmark database.</summary>
	public string StoreDirectory { get; }

	/// <summary>Absolute path of the benchmark database file.</summary>
	public string DatabasePath => Path.Combine(StoreDirectory, RdpAuditPaths.DatabaseFileName);

	/// <summary>Directory the reports are written to. Survives <see cref="Dispose"/>.</summary>
	public string ReportDirectory { get; }

	/// <summary>Shard tree this run creates for the shard-inclusive snapshot probe.</summary>
	public string ActionsRoot { get; }

	/// <summary>Snapshot root this run writes into (the product's backup root).</summary>
	public string SnapshotRoot { get; }

	/// <summary>The <c>--store</c> directory an existing database was copied from, or null.</summary>
	public string? CopiedFrom { get; }

	/// <summary>True when <see cref="Dispose"/> removes the store directory because this run invented it.</summary>
	public bool OwnsStoreDirectory => _ownsStoreDirectory;

	/// <summary>
	/// Prepares a workspace for <paramref name="options"/>, or explains why the run must not start.
	/// Never throws for an operator error.
	/// </summary>
	public static BenchmarkWorkspaceResult Prepare(StorageBenchmarkOptions options)
	{
		ArgumentNullException.ThrowIfNull(options);

		if (options.StoreDirectory is { } requestedStore)
		{
			string storeFull = Path.GetFullPath(requestedStore);
			if (IsInsideProductionDataDirectory(storeFull))
			{
				return Refuse(storeFull, isStore: true);
			}

			string databasePath = Path.Combine(storeFull, RdpAuditPaths.DatabaseFileName);
			bool hasDatabase = File.Exists(databasePath);
			if (hasDatabase && !options.AllowExistingStore)
			{
				return new BenchmarkWorkspaceResult
				{
					Refusal = string.Format(
						CultureInfo.InvariantCulture,
						"""
						Refusing to start: '{0}' already contains a database ({1}).

						A storage benchmark creates, fills and deletes its own store. If that store is a live one,
						the run would delete evidence. Nothing was touched.

						Options:
						  - point --store at an empty directory, or omit --store to let the run use a temporary one;
						  - or pass --allow-existing-store, which makes the run COPY that database into a temporary
						    directory and measure the copy. The original file is never opened for writing.
						""",
						storeFull,
						databasePath),
				};
			}

			string runDirectory = CreateDirectory(options.WorkRoot, "run");
			string storeDirectory = storeFull;
			string? copiedFrom = null;
			if (hasDatabase)
			{
				// The operator allowed an existing store. Measure a copy: the original is never opened.
				storeDirectory = Path.Combine(runDirectory, "store-copy");
				CopyDirectoryFamily(storeFull, storeDirectory);
				copiedFrom = storeFull;
			}
			else
			{
				Directory.CreateDirectory(storeDirectory);
			}

			return Build(runDirectory, storeDirectory, options, ownsStoreDirectory: false, copiedFrom);
		}

		string ownedRunDirectory = CreateDirectory(options.WorkRoot, "run");
		string ownedStoreDirectory = Path.Combine(ownedRunDirectory, "store");
		Directory.CreateDirectory(ownedStoreDirectory);
		return Build(ownedRunDirectory, ownedStoreDirectory, options, ownsStoreDirectory: true, copiedFrom: null);
	}

	private static BenchmarkWorkspaceResult Build(
		string runDirectory,
		string storeDirectory,
		StorageBenchmarkOptions options,
		bool ownsStoreDirectory,
		string? copiedFrom)
	{
		string actionsRoot = Path.Combine(runDirectory, "actions");
		string snapshotRoot = Path.Combine(runDirectory, "snapshots");
		Directory.CreateDirectory(actionsRoot);
		Directory.CreateDirectory(snapshotRoot);

		string reportDirectory = options.OutputDirectory is { } requestedOutput
			? Path.GetFullPath(requestedOutput)
			: Path.Combine(options.WorkRoot, ReportsFolderName, DateTime.UtcNow.ToString("yyyyMMdd-HHmmss", CultureInfo.InvariantCulture));

		if (IsInsideProductionDataDirectory(reportDirectory))
		{
			return Refuse(Path.GetFullPath(options.OutputDirectory!), isStore: false);
		}

		return new BenchmarkWorkspaceResult
		{
			Workspace = new BenchmarkWorkspace(
				runDirectory,
				storeDirectory,
				reportDirectory,
				actionsRoot,
				snapshotRoot,
				ownsStoreDirectory,
				copiedFrom),
		};
	}

	private static BenchmarkWorkspaceResult Refuse(string path, bool isStore)
		=> new()
		{
			Refusal = string.Format(
				CultureInfo.InvariantCulture,
				"""
				Refusing to start: '{0}' is inside the production RdpAudit data directory ({1}).

				That directory is the live evidence store. This tool never reads or writes it, and there is no
				option to override that: the {2} must be somewhere else.
				""",
				path,
				Path.GetFullPath(RdpAuditPaths.Default.ProgramDataDirectory),
				isStore ? "benchmark store" : "report directory"),
		};

	/// <summary>True when <paramref name="candidate"/> is the production RdpAudit directory or below it.</summary>
	public static bool IsInsideProductionDataDirectory(string candidate)
	{
		string production = Path.GetFullPath(RdpAuditPaths.Default.ProgramDataDirectory);
		string full = Path.GetFullPath(candidate);
		return full.Equals(production, StringComparison.OrdinalIgnoreCase)
			|| full.StartsWith(production + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
	}

	private static string CreateDirectory(string parent, string prefix)
	{
		string parentFull = Path.GetFullPath(parent);
		Directory.CreateDirectory(parentFull);
		string name = string.Format(
			CultureInfo.InvariantCulture,
			"{0}-{1}-{2}",
			prefix,
			DateTime.UtcNow.ToString("yyyyMMdd-HHmmss", CultureInfo.InvariantCulture),
			Guid.NewGuid().ToString("N")[..8]);
		string directory = Path.Combine(parentFull, name);
		Directory.CreateDirectory(directory);
		return directory;
	}

	/// <summary>
	/// Copies a database family (the database plus its write-ahead log and shared-memory sidecar) into
	/// <paramref name="destination"/>. The source files are opened read-only by the copy itself and are
	/// never modified.
	/// </summary>
	private static void CopyDirectoryFamily(string sourceDirectory, string destinationDirectory)
	{
		Directory.CreateDirectory(destinationDirectory);
		foreach (string file in Directory.EnumerateFiles(sourceDirectory, "*", SearchOption.TopDirectoryOnly))
		{
			File.Copy(file, Path.Combine(destinationDirectory, Path.GetFileName(file)), overwrite: true);
		}
	}

	/// <summary>
	/// Removes the directories this run created for itself. Reports and an operator-supplied store are
	/// deliberately left in place: the first is the deliverable, and the second belongs to the operator.
	/// Best-effort by design - a benchmark that has already written its report must not fail because a
	/// file handle lingered.
	/// </summary>
	public void Dispose()
	{
		// EF pools its SQLite connections, and a pooled connection keeps a handle on the store file; the
		// directories below cannot be removed until those handles are gone.
		SqliteBenchmarkFacts.ClearPools();
		TryDeleteDirectory(RunDirectory);
		if (_ownsStoreDirectory)
		{
			TryDeleteDirectory(StoreDirectory);
		}
	}

	private static void TryDeleteDirectory(string directory)
	{
		for (int attempt = 0; attempt < 10; attempt++)
		{
			try
			{
				if (Directory.Exists(directory))
				{
					Directory.Delete(directory, recursive: true);
				}

				return;
			}
			catch (IOException)
			{
				SqliteBenchmarkFacts.ClearPools();
				Thread.Sleep(200);
			}
			catch (UnauthorizedAccessException)
			{
				SqliteBenchmarkFacts.ClearPools();
				Thread.Sleep(200);
			}
		}
	}
}
