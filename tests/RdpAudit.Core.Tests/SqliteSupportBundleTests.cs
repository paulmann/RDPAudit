// File:    tests/RdpAudit.Core.Tests/SqliteSupportBundleTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: Pins the canonical SQLite diagnostic support bundle contract consumed by publish.ps1
//          (Ensure-SqliteSupportBundle), the Configurator install/repair validation and the
//          Diagnostic-tab preflight. These tests guarantee the required-file set cannot silently
//          drift (count, exact leaf names, stable order) and that Verify / DescribeMissing behave
//          correctly for complete, partial and missing-directory inputs without throwing.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Util;
using Xunit;

namespace RdpAudit.Core.Tests;

/// <summary>Unit tests for <see cref="SqliteSupportBundle"/>.</summary>
public class SqliteSupportBundleTests
{
	[Fact]
	public void RequiredFiles_AreTheCanonicalFiveInStableOrder()
	{
		Assert.Equal(5, SqliteSupportBundle.RequiredFiles.Count);
		Assert.Equal(
			new[]
			{
				"Microsoft.Data.Sqlite.dll",
				"SQLitePCLRaw.core.dll",
				"SQLitePCLRaw.provider.e_sqlite3.dll",
				"SQLitePCLRaw.batteries_v2.dll",
				"e_sqlite3.dll",
			},
			SqliteSupportBundle.RequiredFiles);
	}

	[Fact]
	public void Constants_MatchTheRequiredFileNames()
	{
		Assert.Equal("Microsoft.Data.Sqlite.dll", SqliteSupportBundle.MicrosoftDataSqlite);
		Assert.Equal("SQLitePCLRaw.core.dll", SqliteSupportBundle.SqlitePclRawCore);
		Assert.Equal("SQLitePCLRaw.provider.e_sqlite3.dll", SqliteSupportBundle.SqlitePclRawProviderESqlite3);
		Assert.Equal("SQLitePCLRaw.batteries_v2.dll", SqliteSupportBundle.SqlitePclRawBatteriesV2);
		Assert.Equal("e_sqlite3.dll", SqliteSupportBundle.NativeESqlite3);
	}

	[Fact]
	public void Verify_AllFilesPresent_ReportsComplete()
	{
		string dir = CreateTempDirectory();
		try
		{
			foreach (string file in SqliteSupportBundle.RequiredFiles)
			{
				File.WriteAllText(Path.Combine(dir, file), "stub");
			}

			SqliteSupportBundleStatus status = SqliteSupportBundle.Verify(dir);

			Assert.True(status.Complete);
			Assert.Empty(status.MissingFiles);
			Assert.Equal(SqliteSupportBundle.RequiredFiles.Count, status.PresentFiles.Count);
			Assert.All(status.PresentFiles, f => Assert.True(Path.IsPathRooted(f.FullPath)));
			Assert.Equal(string.Empty, SqliteSupportBundle.DescribeMissing(status));
		}
		finally
		{
			Directory.Delete(dir, recursive: true);
		}
	}

	[Fact]
	public void Verify_SomeFilesMissing_ReportsExactMissingSet()
	{
		string dir = CreateTempDirectory();
		try
		{
			// Lay down only the first two of the five required files.
			File.WriteAllText(Path.Combine(dir, SqliteSupportBundle.MicrosoftDataSqlite), "stub");
			File.WriteAllText(Path.Combine(dir, SqliteSupportBundle.SqlitePclRawCore), "stub");

			SqliteSupportBundleStatus status = SqliteSupportBundle.Verify(dir);

			Assert.False(status.Complete);
			Assert.Equal(2, status.PresentFiles.Count);
			Assert.Equal(
				new[]
				{
					SqliteSupportBundle.SqlitePclRawProviderESqlite3,
					SqliteSupportBundle.SqlitePclRawBatteriesV2,
					SqliteSupportBundle.NativeESqlite3,
				},
				status.MissingFiles);

			string summary = SqliteSupportBundle.DescribeMissing(status);
			Assert.Contains("Missing 3 of 5", summary, StringComparison.Ordinal);
			Assert.Contains(SqliteSupportBundle.NativeESqlite3, summary, StringComparison.Ordinal);
			Assert.Contains("publish.ps1", summary, StringComparison.Ordinal);
		}
		finally
		{
			Directory.Delete(dir, recursive: true);
		}
	}

	[Fact]
	public void Verify_MissingDirectory_ReportsAllMissingWithoutThrowing()
	{
		string dir = Path.Combine(Path.GetTempPath(), "rdpaudit-bundle-missing-" + Guid.NewGuid().ToString("N"));

		SqliteSupportBundleStatus status = SqliteSupportBundle.Verify(dir);

		Assert.False(status.Complete);
		Assert.Empty(status.PresentFiles);
		Assert.Equal(SqliteSupportBundle.RequiredFiles.Count, status.MissingFiles.Count);
		Assert.Equal(SqliteSupportBundle.RequiredFiles, status.MissingFiles);
	}

	[Fact]
	public void Verify_NullOrWhitespaceDirectory_Throws()
	{
		Assert.ThrowsAny<ArgumentException>(() => SqliteSupportBundle.Verify("   "));
	}

	private static string CreateTempDirectory()
	{
		string dir = Path.Combine(Path.GetTempPath(), "rdpaudit-bundle-" + Guid.NewGuid().ToString("N"));
		Directory.CreateDirectory(dir);
		return dir;
	}
}
