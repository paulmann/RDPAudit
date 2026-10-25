/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : StoreIntegrityRenderingTests.cs
// Project: RdpAudit.Configurator.Tests
// Purpose: B25 regression, pure-renderer half. The two monospace reports (Database-tab overview and
//          Diagnostic snapshot) and the band/severity vocabulary they share are plain functions, so they are
//          asserted directly, without a window handle and without the STA harness: the section is present,
//          it carries the real values, and a verdict that was not obtained renders as UNKNOWN rather than as
//          `ok`. The escalation rule itself is tested where it lives (StoreFingerprintChainVerdict), because
//          that is the function both pages call and the only place a state becomes a severity.
// Depends: DatabasePage, DiagnosticsReportFormatter, StoreFingerprintChainVerdict, xunit
// Extends: Add a case here for every value the integrity sections grow.

using RdpAudit.Configurator.Forms;
using RdpAudit.Core.Integrity;
using RdpAudit.Core.Ipc.Contracts;
using RdpAudit.Core.Models;
using Xunit;

namespace RdpAudit.Configurator.Tests;

public sealed class StoreIntegrityRenderingTests
{
	// ── The escalation rule ──────────────────────────────────────────────────────

	/// <summary>Given each of the five chain states plus the two "no reading" shapes, when the band is
	/// computed, then only `ok` is neutral, `interrupted` is a warning, every other reported state is an
	/// error, and an absent or unrecognised reading is never `ok`.</summary>
	[Theory]
	[InlineData("ok", StoreIntegrityVerdictBand.Ok)]
	[InlineData("interrupted", StoreIntegrityVerdictBand.Warning)]
	[InlineData("missing", StoreIntegrityVerdictBand.Error)]
	[InlineData("unreadable", StoreIntegrityVerdictBand.Error)]
	[InlineData("chain-broken", StoreIntegrityVerdictBand.Error)]
	[InlineData("unverified", StoreIntegrityVerdictBand.Error)]
	[InlineData("something-this-build-does-not-know", StoreIntegrityVerdictBand.Error)]
	[InlineData("", StoreIntegrityVerdictBand.Unknown)]
	[InlineData(null, StoreIntegrityVerdictBand.Unknown)]
	public void BandOf_FollowsTheFiveStatesAndFailsClosed(string? state, StoreIntegrityVerdictBand expected)
	{
		Assert.Equal(expected, StoreFingerprintChainVerdict.BandOf(state));
		Assert.False(
			expected == StoreIntegrityVerdictBand.Unknown && StoreFingerprintChainVerdict.BandOf(state) == StoreIntegrityVerdictBand.Ok,
			"An absent verdict must never be graded as ok.");
	}

	/// <summary>Given a snapshot that did not produce the verdict, when the band is computed from the
	/// producer-side facts, then it is UNKNOWN even when the state field happens to hold `ok`: the section
	/// that produces the verdict has to have completed.</summary>
	[Theory]
	[InlineData(false, true, "ok")]
	[InlineData(true, false, "ok")]
	[InlineData(true, true, "")]
	[InlineData(true, true, null)]
	public void BandForReport_IsUnknownWhenNoVerdictWasObtained(bool succeeded, bool sectionCompleted, string? state)
	{
		Assert.Equal(
			StoreIntegrityVerdictBand.Unknown,
			StoreFingerprintChainVerdict.BandForReport(succeeded, sectionCompleted, state));
	}

	/// <summary>Given a state the service did report, when it is named for the wire and for the operator,
	/// then the wire name is the lower-case token the DTO carries and the phrase describes the state.</summary>
	[Fact]
	public void StateNamesAndPhrases_CoverEveryState()
	{
		Assert.Equal("ok", StoreFingerprintChainVerdict.NameOf(StoreFingerprintChainState.Ok));
		Assert.Equal("missing", StoreFingerprintChainVerdict.NameOf(StoreFingerprintChainState.Missing));
		Assert.Equal("unreadable", StoreFingerprintChainVerdict.NameOf(StoreFingerprintChainState.Unreadable));
		Assert.Equal("chain-broken", StoreFingerprintChainVerdict.NameOf(StoreFingerprintChainState.ChainBroken));
		Assert.Equal("interrupted", StoreFingerprintChainVerdict.NameOf(StoreFingerprintChainState.Interrupted));

		Assert.Contains("cut short", StoreFingerprintChainVerdict.Describe("interrupted"), StringComparison.Ordinal);
		Assert.Contains("MISSING", StoreFingerprintChainVerdict.Describe("missing"), StringComparison.Ordinal);
		Assert.Contains("BROKEN", StoreFingerprintChainVerdict.Describe("chain-broken"), StringComparison.Ordinal);
		Assert.Contains("could not be read", StoreFingerprintChainVerdict.Describe("unreadable"), StringComparison.Ordinal);
		Assert.Contains("NOT verified", StoreFingerprintChainVerdict.Describe(null), StringComparison.Ordinal);
		Assert.Contains("not a pass", StoreFingerprintChainVerdict.Describe(null), StringComparison.Ordinal);
		Assert.Equal("unknown", StoreFingerprintChainVerdict.LabelOf(null));
		Assert.Equal("unknown", StoreFingerprintChainVerdict.LabelOf("  "));
	}

	// ── Database-tab overview report ─────────────────────────────────────────────

	/// <summary>Given a complete overview, when it is rendered, then the integrity section is present with
	/// the verdict, the state and entry count, the fingerprint timestamps, the anomaly marker and the ledger
	/// chain, and it carries the same "as of" stamp as the rest of the report.</summary>
	[Fact]
	public void FormatOverview_RendersTheIntegritySection()
	{
		DatabaseOverviewDto dto = NewOverview();

		string report = DatabasePage.FormatOverview(dto);

		Assert.Contains("Integrity / tamper evidence", report, StringComparison.Ordinal);
		Assert.Contains("2026-09-15 08:00:00", report, StringComparison.Ordinal);
		Assert.Contains("Verdict:                        OK", report, StringComparison.Ordinal);
		Assert.Contains("Fingerprint chain state:        ok", report, StringComparison.Ordinal);
		Assert.Contains("Fingerprint chain entries:      2", report, StringComparison.Ordinal);
		Assert.Contains("The store-fingerprint chain verifies: 2 entr(ies).", report, StringComparison.Ordinal);
		Assert.Contains("Fingerprint mirror:             available outside the integrity folder", report, StringComparison.Ordinal);
		Assert.Contains("Last clean-shutdown fingerprint:2026-09-15 07:00:00", report, StringComparison.Ordinal);
		Assert.Contains("Last periodic fingerprint:      2026-09-15 06:00:00", report, StringComparison.Ordinal);
		Assert.Contains("Anomaly marker:                 absent", report, StringComparison.Ordinal);
		Assert.Contains("Ledger chain intact:            yes", report, StringComparison.Ordinal);
		Assert.Contains("Ledger chained rows:            10", report, StringComparison.Ordinal);
		Assert.Contains("Last quick check:               Ok at 2026-09-15 05:00:00 (120 ms, Schedule)", report, StringComparison.Ordinal);
		Assert.Contains("Last full integrity check:      never run (the full check is opt-in)", report, StringComparison.Ordinal);
	}

	/// <summary>Given an overview whose chain state was never reported, when it is rendered, then the section
	/// says UNKNOWN and "this is NOT a pass" instead of leaving the line blank or reading as ok.</summary>
	[Fact]
	public void FormatOverview_WithoutAVerdict_SaysUnknownAndNotAPass()
	{
		DatabaseOverviewDto dto = NewOverview();
		dto.FingerprintChainState = null;
		dto.FingerprintChainMirrorAvailable = null;
		dto.LedgerChainIntact = null;
		dto.LedgerChainedRows = -1;
		dto.LedgerUnchainedRows = -1;

		string report = DatabasePage.FormatOverview(dto);

		Assert.Contains("Verdict:                        UNKNOWN", report, StringComparison.Ordinal);
		Assert.Contains("Fingerprint chain state:        unknown (not reported — this is NOT a pass)", report, StringComparison.Ordinal);
		Assert.Contains("Fingerprint mirror:             unknown (the chain was not verified)", report, StringComparison.Ordinal);
		Assert.Contains("Ledger chain intact:            not inspected (this is not a pass)", report, StringComparison.Ordinal);
		Assert.Contains("Ledger chained rows:            not inspected", report, StringComparison.Ordinal);
	}

	/// <summary>Given an overview the service marked Unavailable, when it is rendered, then the section does
	/// not present the chain state as a pass even though the field is populated.</summary>
	[Fact]
	public void FormatOverview_UnavailableSnapshot_IsUnknownInTheSection()
	{
		DatabaseOverviewDto dto = NewOverview();
		dto.Status = IpcResultStatus.Unavailable;

		string report = DatabasePage.FormatOverview(dto);

		Assert.Contains("Verdict:                        UNKNOWN", report, StringComparison.Ordinal);
		Assert.Contains("the service reported Unavailable for this snapshot", report, StringComparison.Ordinal);
		Assert.DoesNotContain("Verdict:                        OK", report, StringComparison.Ordinal);
	}

	/// <summary>Given an alerting chain, when the overview is rendered, then the section is an ERROR and the
	/// anomaly marker's detail is printed, so the operator reads the finding without opening a file.</summary>
	[Fact]
	public void FormatOverview_ChainBrokenWithAMarker_ShowsTheErrorAndTheMarkerDetail()
	{
		DatabaseOverviewDto dto = NewOverview();
		dto.FingerprintChainState = "chain-broken";
		dto.FingerprintChainMessage = "Entry 2 does not link to entry 1.";
		dto.IntegrityAnomalyMarkerPresent = true;
		dto.IntegrityAnomalyDetail = "RawEvents row count fell by 120.";
		dto.LedgerChainIntact = false;
		dto.LedgerChainMessage = "The ledger chain does not verify: entry 4 digest mismatch.";
		dto.LedgerUnchainedRows = 3;

		string report = DatabasePage.FormatOverview(dto);

		Assert.Contains("Verdict:                        ERROR", report, StringComparison.Ordinal);
		Assert.Contains("Fingerprint chain state:        chain-broken", report, StringComparison.Ordinal);
		Assert.Contains("Anomaly marker:                 PRESENT", report, StringComparison.Ordinal);
		Assert.Contains("RawEvents row count fell by 120.", report, StringComparison.Ordinal);
		Assert.Contains("Ledger chain intact:            NO — the chain does not verify", report, StringComparison.Ordinal);
		Assert.Contains("Ledger unchained rows:          3 (written before the chain existed: not verifiable, not a break)", report, StringComparison.Ordinal);
		Assert.Contains("Entry 2 does not link to entry 1.", report, StringComparison.Ordinal);
	}

	/// <summary>Given a snapshot whose fingerprint section did not complete, when the verdict is asked for,
	/// then it is UNKNOWN and the headline names the missing section rather than the state field.</summary>
	[Fact]
	public void IntegrityVerdictOf_WithoutACompletedFingerprintSection_IsUnknown()
	{
		DatabaseOverviewDto dto = NewOverview();
		dto.Sections.Clear();
		dto.Sections.Add(new DatabaseOverviewSectionDto { Section = "DbFiles", Status = "Completed" });
		dto.IsPartial = true;

		(StoreIntegrityVerdictBand band, string headline, _) = DatabasePage.IntegrityVerdictOf(dto);

		Assert.Equal(StoreIntegrityVerdictBand.Unknown, band);
		Assert.Contains("no completed 'Fingerprint' section", headline, StringComparison.Ordinal);
		Assert.Contains("partial", headline, StringComparison.Ordinal);
	}

	// ── Diagnostic-tab report ────────────────────────────────────────────────────

	/// <summary>Given a diagnostics snapshot that carried the integrity fields, when it is rendered, then the
	/// Diagnostic report has its own integrity section with the verdict, the state, the mirror, the marker and
	/// the ledger chain - the same facts the Database tab shows, so an operator who lands on this tab after an
	/// unexpected restart does not have to switch tabs to see the verdict.</summary>
	[Fact]
	public void DiagnosticsReport_RendersTheIntegritySection()
	{
		DiagnosticsSnapshotDto dto = NewDiagnostics();

		string report = DiagnosticsReportFormatter.Format(dto);

		Assert.Contains("Store integrity / tamper evidence", report, StringComparison.Ordinal);
		Assert.Contains("Verdict:                        ERROR", report, StringComparison.Ordinal);
		Assert.Contains("Fingerprint chain state:        chain-broken", report, StringComparison.Ordinal);
		Assert.Contains("Fingerprint chain entries:      2", report, StringComparison.Ordinal);
		Assert.Contains("Fingerprint mirror:             available outside the integrity folder", report, StringComparison.Ordinal);
		Assert.Contains("Anomaly marker:                 PRESENT", report, StringComparison.Ordinal);
		Assert.Contains("RawEvents row count fell by 120.", report, StringComparison.Ordinal);
		Assert.Contains("Ledger chain intact:            NO — the chain does not verify", report, StringComparison.Ordinal);
		Assert.Contains("Ledger chained rows:            10", report, StringComparison.Ordinal);
		Assert.Contains("Last quick check:               Ok at 2026-09-15 05:00:00 (120 ms, Schedule)", report, StringComparison.Ordinal);
		Assert.Contains("Last full integrity check:      never run (the full check is opt-in)", report, StringComparison.Ordinal);
		Assert.Contains("Snapshot partial:               no", report, StringComparison.Ordinal);
		Assert.Contains("[OK ] StoreFingerprint", report, StringComparison.Ordinal);
	}

	/// <summary>Given a diagnostics snapshot whose fingerprint section failed, when it is rendered, then the
	/// verdict is UNKNOWN, the reason names the missing section and the section's own outcome is printed so
	/// the reason is visible rather than asserted.</summary>
	[Fact]
	public void DiagnosticsReport_WhenTheFingerprintSectionFailed_SaysUnknownAndShowsWhy()
	{
		DiagnosticsSnapshotDto dto = NewDiagnostics();
		dto.IsPartial = true;
		dto.SectionTimings.Clear();
		dto.SectionTimings.Add(new DiagnosticsSectionTiming
		{
			Section = DiagnosticsReportFormatter.StoreFingerprintSectionName,
			Status = "Failed",
			DurationMs = 3,
			Error = "UnauthorizedAccessException",
		});

		string report = DiagnosticsReportFormatter.Format(dto);

		Assert.Contains("Verdict:                        UNKNOWN", report, StringComparison.Ordinal);
		Assert.Contains("no completed 'StoreFingerprint' section", report, StringComparison.Ordinal);
		Assert.Contains("NOT verified", report, StringComparison.Ordinal);
		Assert.Contains("Snapshot partial:               yes", report, StringComparison.Ordinal);
		Assert.Contains("[!! ] StoreFingerprint  Failed (3 ms) — UnauthorizedAccess", report, StringComparison.Ordinal);
		Assert.DoesNotContain("Verdict:                        OK", report, StringComparison.Ordinal);
	}

	/// <summary>Given a diagnostics snapshot that carries no integrity fields at all (a host that predates
	/// them), when it is rendered, then the section is still present and says UNKNOWN: an older service must
	/// not make the report look like a verified store.</summary>
	[Fact]
	public void DiagnosticsReport_WithoutAnyIntegrityFields_SaysUnknown()
	{
		DiagnosticsSnapshotDto dto = new()
		{
			Status = IpcResultStatus.Success,
			GeneratedUtc = new DateTime(2026, 9, 15, 8, 0, 0, DateTimeKind.Utc),
		};

		string report = DiagnosticsReportFormatter.Format(dto);

		Assert.Contains("Store integrity / tamper evidence", report, StringComparison.Ordinal);
		Assert.Contains("Verdict:                        UNKNOWN", report, StringComparison.Ordinal);
		Assert.Contains("Fingerprint chain state:        unknown (not reported — this is NOT a pass)", report, StringComparison.Ordinal);
		Assert.Contains("Ledger chain intact:            not inspected (this is not a pass)", report, StringComparison.Ordinal);
		Assert.Contains("Ledger chained rows:            not inspected", report, StringComparison.Ordinal);
	}

	/// <summary>Given a snapshot the service marked Unavailable, when the diagnostic report renders, then the
	/// verdict is UNKNOWN however the state field reads.</summary>
	[Fact]
	public void DiagnosticsReport_UnavailableSnapshot_IsUnknown()
	{
		DiagnosticsSnapshotDto dto = NewDiagnostics();
		dto.Status = IpcResultStatus.Unavailable;

		string report = DiagnosticsReportFormatter.Format(dto);

		Assert.Contains("Verdict:                        UNKNOWN", report, StringComparison.Ordinal);
		Assert.Contains("the service reported Unavailable for this snapshot", report, StringComparison.Ordinal);
	}

	/// <summary>Given a chain that was cut short, when the diagnostic report renders, then it is a WARNING -
	/// distinguishable from both `ok` and the tamper accusations.</summary>
	[Fact]
	public void DiagnosticsReport_InterruptedState_IsAWarning()
	{
		DiagnosticsSnapshotDto dto = NewDiagnostics();
		dto.FingerprintChainState = "interrupted";

		string report = DiagnosticsReportFormatter.Format(dto);

		Assert.Contains("Verdict:                        WARNING", report, StringComparison.Ordinal);
		Assert.Contains("cut short", report, StringComparison.Ordinal);
		Assert.DoesNotContain("Verdict:                        OK", report, StringComparison.Ordinal);
	}

	// ── Fixtures ─────────────────────────────────────────────────────────────────

	private static DatabaseOverviewDto NewOverview()
	{
		DatabaseOverviewDto dto = new()
		{
			Status = IpcResultStatus.Success,
			QueriedUtc = new DateTime(2026, 9, 15, 8, 0, 0, DateTimeKind.Utc),
			DatabasePath = @"C:\evidence\rdpaudit.db",
			FingerprintChainState = "ok",
			FingerprintChainEntryCount = 2,
			FingerprintChainMessage = "The store-fingerprint chain verifies: 2 entr(ies).",
			FingerprintChainMirrorAvailable = true,
			FingerprintCleanShutdownUtc = new DateTime(2026, 9, 15, 7, 0, 0, DateTimeKind.Utc),
			FingerprintPeriodicUtc = new DateTime(2026, 9, 15, 6, 0, 0, DateTimeKind.Utc),
			LedgerChainIntact = true,
			LedgerChainedRows = 10,
			LedgerUnchainedRows = 0,
			LastQuickCheck = new DatabaseIntegrityCheckRowDto
			{
				Kind = nameof(DatabaseIntegrityCheckKind.QuickCheck),
				Outcome = "Ok",
				CompletedUtc = new DateTime(2026, 9, 15, 5, 0, 0, DateTimeKind.Utc),
				DurationMs = 120,
				InitiatedBy = "Schedule",
				Detail = "no errors",
			},
		};
		dto.Sections.Add(new DatabaseOverviewSectionDto
		{
			Section = "Ledger",
			Status = "Completed",
			DurationMs = 4,
		});
		dto.Sections.Add(new DatabaseOverviewSectionDto
		{
			Section = DatabasePage.FingerprintSectionName,
			Status = "Completed",
			DurationMs = 6,
		});
		return dto;
	}

	private static DiagnosticsSnapshotDto NewDiagnostics()
	{
		DiagnosticsSnapshotDto dto = new()
		{
			Status = IpcResultStatus.Success,
			GeneratedUtc = new DateTime(2026, 9, 15, 8, 0, 0, DateTimeKind.Utc),
			FingerprintChainState = "chain-broken",
			FingerprintChainEntryCount = 2,
			FingerprintChainMessage = "Entry 2 does not link to entry 1.",
			FingerprintChainMirrorAvailable = true,
			FingerprintCleanShutdownUtc = new DateTime(2026, 9, 15, 7, 0, 0, DateTimeKind.Utc),
			FingerprintPeriodicUtc = new DateTime(2026, 9, 15, 6, 0, 0, DateTimeKind.Utc),
			IntegrityAnomalyMarkerPresent = true,
			IntegrityAnomalyDetail = "RawEvents row count fell by 120.",
			LedgerChainIntact = false,
			LedgerChainedRows = 10,
			LedgerUnchainedRows = 0,
			LedgerChainMessage = "The ledger chain does not verify: entry 4 digest mismatch.",
			LastQuickCheck = new DiagnosticsIntegrityCheckRow
			{
				Kind = nameof(DatabaseIntegrityCheckKind.QuickCheck),
				Outcome = "Ok",
				CompletedUtc = new DateTime(2026, 9, 15, 5, 0, 0, DateTimeKind.Utc),
				DurationMs = 120,
				InitiatedBy = "Schedule",
				Detail = "no errors",
			},
		};
		dto.SectionTimings.Add(new DiagnosticsSectionTiming
		{
			Section = DiagnosticsReportFormatter.StoreFingerprintSectionName,
			Status = "Completed",
			DurationMs = 6,
		});
		dto.SectionTimings.Add(new DiagnosticsSectionTiming
		{
			Section = DiagnosticsReportFormatter.StoreIntegritySectionName,
			Status = "Completed",
			DurationMs = 9,
		});
		return dto;
	}
}
