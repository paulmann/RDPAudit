/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : SchemaCompatibilityTests.cs
// Project: RdpAudit.Core.Tests (RdpAudit.Core.Tests)
// Purpose: Verifies the pure decision at the heart of the downgrade guard. A database that is level with
//          or behind the binaries must be allowed to start (the initializer migrates forward); a database
//          carrying a migration the binaries do not know must be refused, because starting an older build
//          against a newer schema is a silent downgrade. An empty history is a new database and therefore
//          compatible, while a history that could not be read and a history holding non-migration entries
//          are reported as their own verdicts rather than being folded into "compatible".
// Depends: RdpAudit.Core.Backup.SchemaCompatibility, xUnit
// Extends: Add a verdict case here when the guard learns a new refusal reason.

using RdpAudit.Core.Backup;
using Xunit;

namespace RdpAudit.Core.Tests;

/// <summary>Pure-logic tests for <see cref="SchemaCompatibility"/>.</summary>
public sealed class SchemaCompatibilityTests
{
	private static readonly string[] Binaries =
	[
		"20260504215120_InitialCreate",
		"20260519152135_Stage2FirewallStats",
		"20260601000000_Stage18Later",
	];

	[Fact]
	public void Evaluate_AllowsADatabaseThatIsLevelWithTheBinaries()
	{
		SchemaCompatibilityResult result = SchemaCompatibility.Evaluate(Binaries, Binaries, @"C:\rdpaudit.db");

		Assert.Equal(SchemaCompatibilityVerdict.Compatible, result.Verdict);
		Assert.True(result.IsCompatible);
		Assert.False(result.MustRefuseStartup);
		Assert.Empty(result.UnknownAppliedMigrations);
		Assert.Contains(@"C:\rdpaudit.db", result.Message, StringComparison.Ordinal);
	}

	[Fact]
	public void Evaluate_AllowsADatabaseThatIsBehindTheBinaries()
	{
		// Two of three migrations applied: the initializer will apply the third. This is the normal
		// upgrade path and must never be treated as an error.
		string[] applied = [Binaries[0], Binaries[1]];

		SchemaCompatibilityResult result = SchemaCompatibility.Evaluate(applied, Binaries);

		Assert.Equal(SchemaCompatibilityVerdict.Compatible, result.Verdict);
		Assert.False(result.MustRefuseStartup);
	}

	[Fact]
	public void Evaluate_RefusesADatabaseThatIsAheadOfTheBinaries()
	{
		List<string> applied = [.. Binaries, "20270101000000_FromANewerBuild"];

		SchemaCompatibilityResult result = SchemaCompatibility.Evaluate(applied, Binaries, @"C:\rdpaudit.db");

		Assert.Equal(SchemaCompatibilityVerdict.DatabaseAheadOfBinaries, result.Verdict);
		Assert.False(result.IsCompatible);
		Assert.True(result.MustRefuseStartup);
		Assert.Equal(["20270101000000_FromANewerBuild"], result.UnknownAppliedMigrations);
		Assert.Contains("20270101000000_FromANewerBuild", result.Message, StringComparison.Ordinal);
		Assert.Contains("downgrading the binaries is not supported", result.Message, StringComparison.OrdinalIgnoreCase);
	}

	[Fact]
	public void Evaluate_ReportsEveryUnknownMigrationInApplyOrder()
	{
		string[] applied =
		[
			Binaries[0],
			"20270101000000_FirstUnknown",
			Binaries[1],
			"20270202000000_SecondUnknown",
		];

		SchemaCompatibilityResult result = SchemaCompatibility.Evaluate(applied, Binaries);

		Assert.Equal(SchemaCompatibilityVerdict.DatabaseAheadOfBinaries, result.Verdict);
		Assert.Equal(
			["20270101000000_FirstUnknown", "20270202000000_SecondUnknown"],
			result.UnknownAppliedMigrations);
	}

	[Fact]
	public void Evaluate_TreatsAnEmptyHistoryAsANewDatabase()
	{
		SchemaCompatibilityResult result = SchemaCompatibility.Evaluate([], Binaries, @"C:\rdpaudit.db");

		Assert.Equal(SchemaCompatibilityVerdict.Compatible, result.Verdict);
		Assert.True(result.IsCompatible);
		Assert.Contains("new database", result.Message, StringComparison.OrdinalIgnoreCase);
	}

	[Fact]
	public void Evaluate_RefusesADatabaseWhenTheBinariesDefineNoMigrationsAtAll()
	{
		// A history with rows and a binary set with none cannot be a supported combination: nothing in
		// this build can prove it understands the schema it found.
		SchemaCompatibilityResult result = SchemaCompatibility.Evaluate(["20260504215120_InitialCreate"], []);

		Assert.Equal(SchemaCompatibilityVerdict.DatabaseAheadOfBinaries, result.Verdict);
		Assert.True(result.MustRefuseStartup);
	}

	[Fact]
	public void Evaluate_ReportsAnUnreadableHistorySeparatelyFromAnEmptyOne()
	{
		SchemaCompatibilityResult result = SchemaCompatibility.Evaluate(null, Binaries, @"C:\rdpaudit.db");

		Assert.Equal(SchemaCompatibilityVerdict.HistoryUnavailable, result.Verdict);
		Assert.False(result.IsCompatible);
		Assert.False(result.MustRefuseStartup);
		Assert.Contains("could not be read", result.Message, StringComparison.Ordinal);
	}

	[Fact]
	public void Evaluate_RefusesADamagedHistoryInsteadOfGuessing()
	{
		string[] applied = [Binaries[0], "", Binaries[1]];

		SchemaCompatibilityResult result = SchemaCompatibility.Evaluate(applied, Binaries, @"C:\rdpaudit.db");

		Assert.Equal(SchemaCompatibilityVerdict.HistoryInvalid, result.Verdict);
		Assert.True(result.MustRefuseStartup);
		Assert.Contains("not migration ids", result.Message, StringComparison.Ordinal);
	}

	[Fact]
	public void Evaluate_RefusesANullHistoryEntry()
	{
		string?[] applied = [Binaries[0], null, Binaries[1]];

		SchemaCompatibilityResult result = SchemaCompatibility.Evaluate(applied!, Binaries);

		Assert.Equal(SchemaCompatibilityVerdict.HistoryInvalid, result.Verdict);
		Assert.True(result.MustRefuseStartup);
	}

	[Fact]
	public void Evaluate_RejectsANullBinaryMigrationList()
	{
		// The binaries always know their own migration list; a null one is a programming error, not a
		// state to be reported as a verdict.
		Assert.Throws<ArgumentNullException>(() => SchemaCompatibility.Evaluate(Binaries, null!));
	}

	[Fact]
	public void Evaluate_IgnoresBlankBinaryEntriesInsteadOfRefusing()
	{
		string[] binaries = [Binaries[0], "", Binaries[1], Binaries[2]];

		SchemaCompatibilityResult result = SchemaCompatibility.Evaluate(Binaries, binaries);

		Assert.Equal(SchemaCompatibilityVerdict.Compatible, result.Verdict);
	}

	[Fact]
	public void Evaluate_NamesTheMigratedDatabaseInTheRefusal()
	{
		SchemaCompatibilityResult result = SchemaCompatibility.Evaluate(
			["20270101000000_FromANewerBuild"],
			Binaries,
			@"D:\Evidence\rdpaudit.db");

		Assert.Contains(@"D:\Evidence\rdpaudit.db", result.Message, StringComparison.Ordinal);
	}

	[Fact]
	public void Evaluate_StillReadsAsProseWithoutADatabasePath()
	{
		SchemaCompatibilityResult result = SchemaCompatibility.Evaluate([], Binaries);

		Assert.Equal(SchemaCompatibilityVerdict.Compatible, result.Verdict);
		Assert.Contains("the database", result.Message, StringComparison.Ordinal);
	}
}
