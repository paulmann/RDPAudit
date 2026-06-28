// File:    src/RdpAudit.Core/Util/SqliteSupportBundle.cs
// Module:  RdpAudit.Core.Util
// Purpose: Single source of truth for the SQLite support files that MUST sit physically next to
//          the published Configurator so external PowerShell diagnostics (Add-Type /
//          NativeLibrary.Load against Microsoft.Data.Sqlite + SQLitePCLRaw + e_sqlite3) can load
//          the provider without manual copying. These are the same assemblies and native library
//          the app itself resolves from the NuGet dependency graph (Microsoft.EntityFrameworkCore.Sqlite
//          -> Microsoft.Data.Sqlite -> SQLitePCLRaw.*); they are NOT downloaded from sqlite.org and
//          do NOT depend on a global C:\sqlite install. publish.ps1 (Ensure-SqliteSupportBundle), the
//          Configurator install/repair validation, and the Diagnostic-tab preflight all consume this
//          one list so the required set can never drift between the build, the installer, and the UI.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Globalization;

namespace RdpAudit.Core.Util;

/// <summary>Result of verifying that a directory contains the full SQLite diagnostic support bundle.</summary>
/// <param name="Directory">The directory that was inspected.</param>
/// <param name="Complete">True when every required file is present.</param>
/// <param name="PresentFiles">Required files that were found, with their resolved full paths.</param>
/// <param name="MissingFiles">Required file names that were not found in the directory.</param>
public sealed record SqliteSupportBundleStatus(
	string Directory,
	bool Complete,
	IReadOnlyList<SqliteSupportFile> PresentFiles,
	IReadOnlyList<string> MissingFiles);

/// <summary>A single resolved bundle file — its required name and the full path it was found at.</summary>
/// <param name="FileName">The required leaf file name (e.g. <c>e_sqlite3.dll</c>).</param>
/// <param name="FullPath">The resolved absolute path on disk.</param>
public sealed record SqliteSupportFile(string FileName, string FullPath);

/// <summary>Canonical list of the SQLite diagnostic support files and a directory verifier.</summary>
public static class SqliteSupportBundle
{
	/// <summary>The managed Microsoft.Data.Sqlite assembly — the ADO.NET surface
	/// <c>Add-Type</c> targets in PowerShell diagnostics.</summary>
	public const string MicrosoftDataSqlite = "Microsoft.Data.Sqlite.dll";

	/// <summary>SQLitePCLRaw core — the managed marshalling layer between Microsoft.Data.Sqlite
	/// and the native provider.</summary>
	public const string SqlitePclRawCore = "SQLitePCLRaw.core.dll";

	/// <summary>SQLitePCLRaw provider that binds to the bundled <c>e_sqlite3</c> native build.</summary>
	public const string SqlitePclRawProviderESqlite3 = "SQLitePCLRaw.provider.e_sqlite3.dll";

	/// <summary>SQLitePCLRaw batteries — registers the provider via <c>Batteries_V2.Init()</c>.</summary>
	public const string SqlitePclRawBatteriesV2 = "SQLitePCLRaw.batteries_v2.dll";

	/// <summary>The native SQLite engine the provider P/Invokes into.</summary>
	public const string NativeESqlite3 = "e_sqlite3.dll";

	/// <summary>Every file that must be present next to the Configurator, in a fixed, stable order.
	/// This is the authoritative set consumed by the build, the installer, the diagnostics UI and
	/// the tests — adding a new dependency means adding it here exactly once.</summary>
	public static IReadOnlyList<string> RequiredFiles { get; } = new[]
	{
		MicrosoftDataSqlite,
		SqlitePclRawCore,
		SqlitePclRawProviderESqlite3,
		SqlitePclRawBatteriesV2,
		NativeESqlite3,
	};

	/// <summary>Verifies that <paramref name="directory"/> contains every required bundle file.
	/// Pure and bounded: it performs at most one existence check per required file and never throws
	/// — a missing directory simply reports every file as missing. Returns the present/missing
	/// split so callers can render an exact, actionable diagnostic.</summary>
	public static SqliteSupportBundleStatus Verify(string directory)
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(directory);

		List<SqliteSupportFile> present = new(RequiredFiles.Count);
		List<string> missing = new();

		foreach (string fileName in RequiredFiles)
		{
			string candidate = Path.Combine(directory, fileName);
			if (File.Exists(candidate))
			{
				present.Add(new SqliteSupportFile(fileName, Path.GetFullPath(candidate)));
			}
			else
			{
				missing.Add(fileName);
			}
		}

		return new SqliteSupportBundleStatus(directory, missing.Count == 0, present, missing);
	}

	/// <summary>Builds a single-line, English summary of a missing-file set suitable for an
	/// install error or a log entry. Returns an empty string when nothing is missing.</summary>
	public static string DescribeMissing(SqliteSupportBundleStatus status)
	{
		ArgumentNullException.ThrowIfNull(status);
		if (status.Complete)
		{
			return string.Empty;
		}

		return string.Format(
			CultureInfo.InvariantCulture,
			"SQLite support bundle incomplete in '{0}'. Missing {1} of {2} required file(s): {3}. Re-run publish.ps1 (Ensure-SqliteSupportBundle stage) so the Configurator carries the SQLitePCLRaw / Microsoft.Data.Sqlite assemblies and e_sqlite3.dll.",
			status.Directory,
			status.MissingFiles.Count,
			RequiredFiles.Count,
			string.Join(", ", status.MissingFiles));
	}
}
