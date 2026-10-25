/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 1.0.0
// File   : StoreIntegrityComparerTests.cs
// Project: RdpAudit.Core.Tests
// Purpose: Pins the offline-change detection rules (Requirement R23) from both sides. Each attack that must
//          be caught is asserted to produce an anomaly, and each LEGITIMATE change that must not be reported
//          is asserted to produce none - because the failure mode that matters here is an alarm nobody reads.
//          Specifically covered: a clean start with no change (no anomaly), retention deleting rows while the
//          SERVICE runs (no anomaly against a periodic baseline), a legitimate migration upgrade (no anomaly),
//          and - against a clean-shutdown baseline - rows disappearing, the migration list changing, the
//          ingestion sequence advancing and the ledger shrinking (all anomalies).
// Depends: StoreIntegrityComparer, xUnit
// Extends: Add the counterfactual for every new rule: a case that must fire and a case that must stay silent.

using RdpAudit.Core.Integrity;
using Xunit;

namespace RdpAudit.Core.Tests;

public sealed class StoreIntegrityComparerTests
{
	private static readonly DateTime BaselineUtc = new(2026, 9, 15, 10, 0, 0, DateTimeKind.Utc);

	// ── Baselines ────────────────────────────────────────────────────────────────

	/// <summary>Given there is no stored fingerprint, when the current state is compared, then nothing is
	/// reported and the report says "nothing to compare against" rather than "clean".</summary>
	[Fact]
	public void Compare_WithoutABaseline_IsNotComparedAndReportsNoAnomalies()
	{
		StoreIntegrityReport report = StoreIntegrityComparer.Compare(null, Fingerprint());

		Assert.False(report.Compared);
		Assert.Empty(report.Anomalies);
		Assert.False(report.HasAnomalies);
		Assert.Contains("nothing to compare", report.Message, StringComparison.OrdinalIgnoreCase);
	}

	/// <summary>Given a clean shutdown produced the baseline, when the next start sees the same store, then
	/// no anomaly is reported. This is the "no false positives on a clean start" acceptance case.</summary>
	[Fact]
	public void Compare_AgainstAnUnchangedCleanBaseline_ReportsNothing()
	{
		StoreFingerprint baseline = Fingerprint(cleanShutdown: true);

		StoreIntegrityReport report = StoreIntegrityComparer.Compare(baseline, Fingerprint());

		Assert.True(report.Compared);
		Assert.Empty(report.Anomalies);
		Assert.False(report.HasAnomalies);
		Assert.True(report.LedgerChainIntact);
	}

	/// <summary>A fingerprint written by a different layout version is not compared: reading it with today's
	/// field meanings would invent anomalies out of a format change.</summary>
	[Fact]
	public void Compare_AgainstAnOlderFormatVersion_IsNotCompared()
	{
		StoreFingerprint baseline = Fingerprint(cleanShutdown: true) with { FormatVersion = 0 };

		StoreIntegrityReport report = StoreIntegrityComparer.Compare(baseline, Fingerprint());

		Assert.False(report.Compared);
		Assert.Empty(report.Anomalies);
	}

	// ── The false positives that must not happen ─────────────────────────────────

	/// <summary>Given the baseline is a PERIODIC fingerprint - taken while the service was running - when
	/// rows have since been removed by retention, then nothing is reported: retention legitimately deletes
	/// rows while the service runs, and a periodic baseline cannot prove otherwise. Reporting it would fire
	/// on every restart after a crash and train the operator to ignore the alarm.</summary>
	[Fact]
	public void Compare_WithAPeriodicBaselineAndFewerRows_StaysSilent()
	{
		StoreFingerprint baseline = Fingerprint(cleanShutdown: false);
		StoreFingerprint current = Fingerprint() with { TableRowCounts = Counts(rawEvents: 100) };

		StoreIntegrityReport report = StoreIntegrityComparer.Compare(baseline, current);

		Assert.True(report.Compared);
		Assert.False(report.HasAnomalies);
		Assert.Empty(report.Anomalies);
	}

	/// <summary>Given binaries were upgraded, when the migration history has grown by appending, then nothing
	/// is reported: migrations are only ever appended, so a longer list that starts with the old one is the
	/// normal shape of an upgrade.</summary>
	[Fact]
	public void Compare_WhenMigrationsWereAppended_StaysSilent()
	{
		StoreFingerprint baseline = Fingerprint(cleanShutdown: true);
		StoreFingerprint current = Fingerprint() with
		{
			AppliedMigrations = ["20260101000000_Initial", "20260915120000_Stage18LedgerChain"],
		};

		StoreIntegrityReport report = StoreIntegrityComparer.Compare(baseline, current);

		Assert.False(report.HasAnomalies);
	}

	/// <summary>Given an offline compaction, when the database file is smaller, then the observation is
	/// Information only: shrinking the file is exactly what the compaction is for.</summary>
	[Fact]
	public void Compare_WhenTheFileShrank_ReportsInformationOnly()
	{
		StoreFingerprint baseline = Fingerprint(cleanShutdown: true);
		StoreFingerprint current = Fingerprint() with { DatabaseBytes = 500, WalBytes = 0 };

		StoreIntegrityReport report = StoreIntegrityComparer.Compare(baseline, current);

		Assert.False(report.HasAnomalies);
		StoreIntegrityAnomaly anomaly = Assert.Single(report.Anomalies);
		Assert.Equal(StoreIntegritySeverity.Information, anomaly.Severity);
		Assert.Equal("DatabaseShrank", anomaly.Kind);
	}

	/// <summary>Given more rows than the baseline, when the store is compared, then nothing is reported:
	/// growth is what an evidence store does.</summary>
	[Fact]
	public void Compare_WithMoreRows_StaysSilent()
	{
		StoreFingerprint baseline = Fingerprint(cleanShutdown: true);
		StoreFingerprint current = Fingerprint() with { TableRowCounts = Counts(rawEvents: 5_000) };

		StoreIntegrityReport report = StoreIntegrityComparer.Compare(baseline, current);

		Assert.False(report.HasAnomalies);
	}

	// ── The attacks that must be caught ──────────────────────────────────────────

	/// <summary>Given a clean-shutdown baseline, when rows disappeared while the service was stopped, then a
	/// Strong anomaly names the table and the number of rows. Nothing in the product removes evidence while
	/// the service is not running.</summary>
	[Fact]
	public void Compare_WithACleanBaselineAndFewerRows_ReportsAStrongAnomaly()
	{
		StoreFingerprint baseline = Fingerprint(cleanShutdown: true);
		StoreFingerprint current = Fingerprint() with { TableRowCounts = Counts(rawEvents: 100) };

		StoreIntegrityReport report = StoreIntegrityComparer.Compare(baseline, current);

		Assert.True(report.HasStrongAnomalies);
		StoreIntegrityAnomaly anomaly = Assert.Single(report.Anomalies, entry => entry.Kind == "RowsRemovedWhileStopped");
		Assert.Equal(StoreIntegritySeverity.Strong, anomaly.Severity);
		Assert.Contains("RawEvents", anomaly.Detail, StringComparison.Ordinal);
		Assert.Contains("older snapshot", anomaly.Detail, StringComparison.Ordinal);
	}

	/// <summary>Given the ledger lost entries, when the store is compared, then it is a Strong anomaly even
	/// against a periodic baseline: the ledger is append-only, so a shorter one is never a retention effect
	/// (retention adds ledger rows, it does not remove them).</summary>
	[Fact]
	public void Compare_WhenTheLedgerShrank_ReportsAStrongAnomalyEvenAgainstAPeriodicBaseline()
	{
		StoreFingerprint baseline = Fingerprint(cleanShutdown: false);
		StoreFingerprint current = Fingerprint() with { LedgerChainedRows = 1 };

		StoreIntegrityReport report = StoreIntegrityComparer.Compare(baseline, current);

		Assert.True(report.HasStrongAnomalies);
		Assert.Contains(report.Anomalies, entry => entry.Kind == "LedgerShrank");
	}

	/// <summary>Given the ledger's hash chain does not verify, when the store is compared, then it is a Strong
	/// anomaly regardless of the baseline and regardless of how many rows the ledger holds.</summary>
	[Fact]
	public void Compare_WhenTheLedgerChainIsBroken_ReportsAStrongAnomaly()
	{
		StoreFingerprint current = Fingerprint() with { LedgerChainIntact = false };

		StoreIntegrityReport report = StoreIntegrityComparer.Compare(Fingerprint(cleanShutdown: false), current);

		Assert.True(report.HasStrongAnomalies);
		Assert.False(report.LedgerChainIntact);
		Assert.Contains(report.Anomalies, entry => entry.Kind == "LedgerChainBroken");
	}

	/// <summary>Given the migration history was rolled back or replaced, when the store is compared, then a
	/// Strong anomaly is reported: appending is the only supported change.</summary>
	[Theory]
	[InlineData(new[] { "20260101000000_Initial" }, new[] { "20260101000000_Renamed" })]
	[InlineData(new[] { "20260101000000_Initial", "20260915120000_Stage18LedgerChain" }, new[] { "20260101000000_Initial" })]
	public void Compare_WhenTheMigrationHistoryIsNotAnExtension_ReportsAnAnomaly(
		string[] baselineMigrations,
		string[] currentMigrations)
	{
		StoreFingerprint baseline = Fingerprint(cleanShutdown: true) with { AppliedMigrations = [.. baselineMigrations] };
		StoreFingerprint current = Fingerprint() with { AppliedMigrations = [.. currentMigrations] };

		StoreIntegrityReport report = StoreIntegrityComparer.Compare(baseline, current);

		Assert.True(report.HasStrongAnomalies);
		Assert.Contains(report.Anomalies, entry => entry.Kind == "MigrationHistoryChanged");
	}

	/// <summary>Given a clean-shutdown baseline, when the ingestion sequence advanced, then rows were written
	/// offline - which is reported. The same observation against a periodic baseline is withheld, because the
	/// service was still writing when that baseline was taken.</summary>
	[Fact]
	public void Compare_WhenTheIngestionSequenceAdvanced_ReportsOnlyAgainstACleanBaseline()
	{
		StoreFingerprint cleanBaseline = Fingerprint(cleanShutdown: true);
		StoreFingerprint periodicBaseline = Fingerprint(cleanShutdown: false);
		StoreFingerprint current = Fingerprint() with { LastIngestionSequence = 5_000 };

		Assert.Contains(
			StoreIntegrityComparer.Compare(cleanBaseline, current).Anomalies,
			entry => entry.Kind == "IngestionSequenceAdvanced");
		Assert.DoesNotContain(
			StoreIntegrityComparer.Compare(periodicBaseline, current).Anomalies,
			entry => entry.Kind == "IngestionSequenceAdvanced");
	}

	/// <summary>Given the database file was written after the clean-shutdown baseline, when the store is
	/// compared, then a Strong anomaly is reported and its detail tells the operator that a restore or an
	/// offline compaction produces the same observation - so a deliberate operation is acknowledged rather
	/// than mistaken for an intrusion.</summary>
	[Fact]
	public void Compare_WhenTheFileWasWrittenAfterACleanBaseline_ReportsItWithTheBenignExplanation()
	{
		StoreFingerprint baseline = Fingerprint(cleanShutdown: true);
		StoreFingerprint current = Fingerprint() with { DatabaseLastWriteUtc = BaselineUtc.AddMinutes(30) };

		StoreIntegrityReport report = StoreIntegrityComparer.Compare(baseline, current);

		StoreIntegrityAnomaly anomaly = Assert.Single(report.Anomalies, entry => entry.Kind == "DatabaseModifiedOffline");
		Assert.Equal(StoreIntegritySeverity.Strong, anomaly.Severity);
		Assert.Contains("restore or an offline compaction also produces this observation", anomaly.Detail, StringComparison.Ordinal);
	}

	/// <summary>Given a table vanished entirely, when the store is compared, then it is reported by name
	/// rather than as a row-count difference.</summary>
	[Fact]
	public void Compare_WhenATableVanished_ReportsItByName()
	{
		StoreFingerprint baseline = Fingerprint(cleanShutdown: true);
		Dictionary<string, long> counts = Counts();
		counts.Remove("Alerts");
		StoreFingerprint current = Fingerprint() with { TableRowCounts = counts };

		StoreIntegrityReport report = StoreIntegrityComparer.Compare(baseline, current);

		Assert.Contains(report.Anomalies, entry => entry.Kind == "TableVanished");
	}

	// ── Fixtures ─────────────────────────────────────────────────────────────────

	private static StoreFingerprint Fingerprint(bool cleanShutdown = false) => new()
	{
		CapturedUtc = BaselineUtc,
		CleanShutdown = cleanShutdown,
		CapturedBy = cleanShutdown ? "Shutdown" : "Schedule",
		DatabaseBytes = 1_000,
		WalBytes = 100,
		DatabaseLastWriteUtc = BaselineUtc.AddMinutes(-1),
		LastIngestionSequence = 1_000,
		TableRowCounts = Counts(),
		AppliedMigrations = ["20260101000000_Initial"],
		LedgerChainedRows = 5,
		LedgerUnchainedRows = 0,
		LedgerChainHead = "a" + new string('0', 63),
		LedgerChainIntact = true,
	};

	private static Dictionary<string, long> Counts(long rawEvents = 1_000) => new(StringComparer.Ordinal)
	{
		["RawEvents"] = rawEvents,
		["Alerts"] = 10,
		["EventDeletionLedger"] = 5,
	};
}
