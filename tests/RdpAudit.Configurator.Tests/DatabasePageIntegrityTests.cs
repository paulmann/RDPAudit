/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : DatabasePageIntegrityTests.cs
// Project: RdpAudit.Configurator.Tests
// Purpose: B25 regression: the store-integrity verdict the service computes on every start-up must be
//          VISIBLE in the Configurator. These tests drive the Database tab through the existing IIpcClient
//          seam and assert what an operator sees for each of the five fingerprint-chain states, the
//          severity the banner gives each one (ok neutral, interrupted a warning, everything else an error),
//          and - the case the tab got wrong before - that a verdict which was NOT obtained is never shown as
//          `ok`: an unavailable service, a rejected command, a DTO the service marked Unavailable, a partial
//          snapshot without a completed fingerprint section and a null state all render UNKNOWN.
//          The WinForms parts run through StaTestHarness, which owns the STA thread and pumps the message
//          queue, so the page's `ConfigureAwait(true)` continuations execute instead of deadlocking the pump.
// Depends: DatabasePage, StoreFingerprintChainVerdict, IIpcClient, StaTestHarness, xunit
// Extends: Add a case here for every new chain state, band or "no verdict" path.

using System.Runtime.Versioning;
using System.Windows.Forms;
using RdpAudit.Configurator.Forms;
using RdpAudit.Configurator.Ipc;
using RdpAudit.Configurator.Theming;
using RdpAudit.Core.Integrity;
using RdpAudit.Core.Ipc;
using RdpAudit.Core.Ipc.Contracts;
using Xunit;

namespace RdpAudit.Configurator.Tests;

[SupportedOSPlatform("windows")]
public sealed class DatabasePageIntegrityTests
{
	private readonly StaTestHarness _ui = new(nameof(DatabasePageIntegrityTests));

	// ── The five states: banner severity and report text ─────────────────────────

	/// <summary>Given the service reports a verifying chain, when the overview renders, then the banner is in
	/// the NEUTRAL treatment and names the state, and the report carries the state, the entry count and the
	/// chain message.</summary>
	[Fact]
	public void OkState_ShowsTheNeutralBannerAndTheChainFacts()
	{
		_ui.Run(() =>
		{
			using DatabasePage page = NewPage(Answering(Overview("ok", entries: 3)));
			_ui.Await(page.RefreshOverviewAsync(), "RefreshOverviewAsync");

			Assert.Equal(StoreIntegrityVerdictBand.Ok, page.IntegrityBannerBand);
			Assert.False(page.IntegrityBannerShowsAlarm);
			Assert.Contains("fingerprint chain: ok", page.IntegrityBannerText, StringComparison.Ordinal);
			Assert.Contains("(3 entr(ies))", page.IntegrityBannerText, StringComparison.Ordinal);

			string report = ReportText(page, "Integrity / tamper evidence");
			Assert.Contains("Fingerprint chain state:        ok", report, StringComparison.Ordinal);
			Assert.Contains("Fingerprint chain entries:      3", report, StringComparison.Ordinal);
			Assert.Contains("Fingerprint chain message:", report, StringComparison.Ordinal);
			Assert.Contains("Ledger chain intact:            yes", report, StringComparison.Ordinal);
		});
	}

	/// <summary>Given a chain whose recorded entries are gone, when the overview renders, then the banner is
	/// an ERROR (not a warning, not neutral) and the report says which state was reported.</summary>
	[Theory]
	[InlineData("missing")]
	[InlineData("unreadable")]
	[InlineData("chain-broken")]
	public void ErrorStates_ShowTheErrorBannerAndTheState(string state)
	{
		_ui.Run(() =>
		{
			using DatabasePage page = NewPage(Answering(Overview(state, entries: 0)));
			_ui.Await(page.RefreshOverviewAsync(), "RefreshOverviewAsync");

			Assert.Equal(StoreIntegrityVerdictBand.Error, page.IntegrityBannerBand);
			Assert.True(page.IntegrityBannerShowsAlarm);
			Assert.Contains("fingerprint chain: " + state, page.IntegrityBannerText, StringComparison.Ordinal);
			Assert.Contains("as of ", page.IntegrityBannerText, StringComparison.Ordinal);

			string report = ReportText(page, "Integrity / tamper evidence");
			Assert.Contains("Fingerprint chain state:        " + state, report, StringComparison.Ordinal);
			Assert.Contains("ERROR", report, StringComparison.Ordinal);
		});
	}

	/// <summary>Given a capture was cut short, when the overview renders, then the banner is a WARNING: it is
	/// reported, but it is not the "rolled back or replaced" accusation that colours the other non-ok states
	/// red. A crash must not look like tampering (B24).</summary>
	[Fact]
	public void InterruptedState_IsAWarningNotAnError()
	{
		_ui.Run(() =>
		{
			using DatabasePage page = NewPage(Answering(Overview("interrupted", entries: 4)));
			_ui.Await(page.RefreshOverviewAsync(), "RefreshOverviewAsync");

			Assert.Equal(StoreIntegrityVerdictBand.Warning, page.IntegrityBannerBand);
			Assert.True(page.IntegrityBannerShowsAlarm);
			Assert.NotEqual(StoreIntegrityVerdictBand.Error, page.IntegrityBannerBand);
			Assert.Contains("fingerprint chain: interrupted", page.IntegrityBannerText, StringComparison.Ordinal);
			Assert.Contains("cut short", page.IntegrityBannerText, StringComparison.Ordinal);

			Assert.Contains("WARNING", ReportText(page, "Integrity / tamper evidence"), StringComparison.Ordinal);
		});
	}

	/// <summary>Given the service reported a state this build does not recognise, when the overview renders,
	/// then it is escalated rather than washed out: an unknown value must never be treated as a pass.</summary>
	[Fact]
	public void UnrecognisedState_IsEscalatedNotNeutralised()
	{
		_ui.Run(() =>
		{
			using DatabasePage page = NewPage(Answering(Overview("something-new", entries: 1)));
			_ui.Await(page.RefreshOverviewAsync(), "RefreshOverviewAsync");

			Assert.Equal(StoreIntegrityVerdictBand.Error, page.IntegrityBannerBand);
			Assert.True(page.IntegrityBannerShowsAlarm);
			Assert.Contains("something-new", page.IntegrityBannerText, StringComparison.Ordinal);
		});
	}

	// ── "No verdict" is never "ok" ───────────────────────────────────────────────

	/// <summary>Given the service cannot be reached, when the operator refreshes, then the banner says
	/// UNKNOWN in the error treatment and explicitly NOT a pass - the tab must never keep a stale "ok" up
	/// when it has no answer.</summary>
	[Fact]
	public void UnreachableService_ShowsUnknownNotOk()
	{
		_ui.Run(() =>
		{
			FakeIpc ipc = new FakeIpc()
				.Fail(IpcCommand.GetDatabaseOverview, IpcCallOutcome.ConnectFailed, "pipe not found");
			using DatabasePage page = NewPage(ipc);

			_ui.Await(page.RefreshOverviewAsync(), "RefreshOverviewAsync");

			Assert.Equal(StoreIntegrityVerdictBand.Unknown, page.IntegrityBannerBand);
			Assert.NotEqual(StoreIntegrityVerdictBand.Ok, page.IntegrityBannerBand);
			Assert.True(page.IntegrityBannerShowsAlarm);
			Assert.Contains("UNKNOWN", page.IntegrityBannerText, StringComparison.Ordinal);
			Assert.Contains("NOT verified", page.IntegrityBannerText, StringComparison.Ordinal);
			Assert.DoesNotContain("Store integrity: OK", page.IntegrityBannerText, StringComparison.Ordinal);
		});
	}

	/// <summary>Given the service rejects the overview with its own error, when the operator refreshes, then
	/// the banner is still UNKNOWN: a rejected command produced no verdict, whatever the reason.</summary>
	[Fact]
	public void RejectedOverview_ShowsUnknownNotOk()
	{
		_ui.Run(() =>
		{
			FakeIpc ipc = new FakeIpc()
				.Fail(IpcCommand.GetDatabaseOverview, IpcCallOutcome.ServiceError, "store locked by compaction");
			using DatabasePage page = NewPage(ipc);

			_ui.Await(page.RefreshOverviewAsync(), "RefreshOverviewAsync");

			Assert.Equal(StoreIntegrityVerdictBand.Unknown, page.IntegrityBannerBand);
			Assert.Contains("store locked by compaction", page.IntegrityBannerText, StringComparison.Ordinal);
		});
	}

	/// <summary>Given the service answered but marked the snapshot Unavailable, when the overview renders,
	/// then no verdict was obtained and the banner says so even though the fingerprint fields are populated:
	/// the producer told us it could not read the store.</summary>
	[Fact]
	public void UnavailableSnapshot_ShowsUnknownEvenWithAPopulatedState()
	{
		_ui.Run(() =>
		{
			DatabaseOverviewDto dto = Overview("ok", entries: 2);
			dto.Status = IpcResultStatus.Unavailable;
			using DatabasePage page = NewPage(new FakeIpc().On(IpcCommand.GetDatabaseOverview, dto));

			_ui.Await(page.RefreshOverviewAsync(), "RefreshOverviewAsync");

			Assert.Equal(StoreIntegrityVerdictBand.Unknown, page.IntegrityBannerBand);
			Assert.Contains("Unavailable", page.IntegrityBannerText, StringComparison.Ordinal);
			Assert.Contains("UNKNOWN", ReportText(page, "Integrity / tamper evidence"), StringComparison.Ordinal);
		});
	}

	/// <summary>Given a partial snapshot whose fingerprint section never completed, when the overview renders,
	/// then the banner shows UNKNOWN rather than the state field's value: the section that produces the
	/// verdict did not run, so there is nothing to report.</summary>
	[Fact]
	public void PartialSnapshotWithoutTheFingerprintSection_ShowsUnknown()
	{
		_ui.Run(() =>
		{
			DatabaseOverviewDto dto = Overview("ok", entries: 2);
			dto.IsPartial = true;
			dto.Sections.Clear();
			dto.Sections.Add(new DatabaseOverviewSectionDto
			{
				Section = DatabasePage.FingerprintSectionName,
				Status = "TimedOut",
				DurationMs = 8000,
				Error = "budget",
			});
			dto.Warnings.Add("Database overview section 'Fingerprint' timed out.");

			using DatabasePage page = NewPage(new FakeIpc().On(IpcCommand.GetDatabaseOverview, dto));
			_ui.Await(page.RefreshOverviewAsync(), "RefreshOverviewAsync");

			Assert.Equal(StoreIntegrityVerdictBand.Unknown, page.IntegrityBannerBand);
			Assert.Contains("no completed 'Fingerprint' section", page.IntegrityBannerText, StringComparison.Ordinal);
			Assert.Contains("partial", page.IntegrityBannerText, StringComparison.OrdinalIgnoreCase);
		});
	}

	/// <summary>Given a host that reported no chain state at all, when the overview renders, then the banner
	/// is UNKNOWN: a null state is an absence of information, not an intact chain.</summary>
	[Fact]
	public void NullState_ShowsUnknownNotOk()
	{
		_ui.Run(() =>
		{
			DatabaseOverviewDto dto = Overview("ok", entries: 0);
			dto.FingerprintChainState = null;
			using DatabasePage page = NewPage(new FakeIpc().On(IpcCommand.GetDatabaseOverview, dto));

			_ui.Await(page.RefreshOverviewAsync(), "RefreshOverviewAsync");

			Assert.Equal(StoreIntegrityVerdictBand.Unknown, page.IntegrityBannerBand);
			Assert.Contains("not reported", page.IntegrityBannerText, StringComparison.Ordinal);
			Assert.Contains("not reported — this is NOT a pass", ReportText(page, "Integrity / tamper evidence"), StringComparison.Ordinal);
		});
	}

	/// <summary>Given the snapshot is partial but its fingerprint section DID complete, when the overview
	/// renders, then the real verdict is kept (an alarm must not be downgraded because an unrelated section
	/// timed out) and the partiality is stated instead of being hidden.</summary>
	[Fact]
	public void PartialSnapshotWithACompletedFingerprintSection_KeepsTheVerdictAndSaysItIsPartial()
	{
		_ui.Run(() =>
		{
			DatabaseOverviewDto dto = Overview("chain-broken", entries: 2);
			dto.IsPartial = true;
			dto.Warnings.Add("Database overview section 'ShardTree' timed out.");

			using DatabasePage page = NewPage(new FakeIpc().On(IpcCommand.GetDatabaseOverview, dto));
			_ui.Await(page.RefreshOverviewAsync(), "RefreshOverviewAsync");

			Assert.Equal(StoreIntegrityVerdictBand.Error, page.IntegrityBannerBand);
			Assert.Contains("snapshot partial", page.IntegrityBannerText, StringComparison.Ordinal);
			Assert.Contains("snapshot partial", ReportText(page, "Integrity / tamper evidence"), StringComparison.Ordinal);
		});
	}

	// ── The anomaly marker ───────────────────────────────────────────────────────

	/// <summary>Given the start-up comparison left an anomaly marker, when the overview renders, then both
	/// the banner and the report say the marker is present and the report carries its detail, so the operator
	/// does not have to open the marker file to learn what was found.</summary>
	[Fact]
	public void AnomalyMarker_ReachesTheBannerAndTheReportWithItsDetail()
	{
		_ui.Run(() =>
		{
			DatabaseOverviewDto dto = Overview("chain-broken", entries: 2);
			dto.IntegrityAnomalyMarkerPresent = true;
			dto.IntegrityAnomalyDetail = "RawEvents row count fell by 120 while the service was stopped.";

			using DatabasePage page = NewPage(new FakeIpc().On(IpcCommand.GetDatabaseOverview, dto));
			_ui.Await(page.RefreshOverviewAsync(), "RefreshOverviewAsync");

			Assert.Contains("anomaly marker: PRESENT", page.IntegrityBannerText, StringComparison.Ordinal);

			string report = ReportText(page, "Integrity / tamper evidence");
			Assert.Contains("Anomaly marker:                 PRESENT", report, StringComparison.Ordinal);
			Assert.Contains("RawEvents row count fell by 120 while the service was stopped.", report, StringComparison.Ordinal);
		});
	}

	/// <summary>Given no marker file exists, when the overview renders, then the marker line says absent
	/// rather than staying silent - an operator must be able to tell "nothing was found" from "nobody looked".
	/// </summary>
	[Fact]
	public void AbsentAnomalyMarker_IsStatedAsAbsent()
	{
		_ui.Run(() =>
		{
			using DatabasePage page = NewPage(Answering(Overview("ok", entries: 1)));
			_ui.Await(page.RefreshOverviewAsync(), "RefreshOverviewAsync");

			Assert.Contains("anomaly marker: absent", page.IntegrityBannerText, StringComparison.Ordinal);
			Assert.Contains("Anomaly marker:                 absent", ReportText(page, "Integrity / tamper evidence"), StringComparison.Ordinal);
		});
	}

	// ── The banner is a fixed band, not a line in the scrolled report ─────────────

	/// <summary>Given the Overview tab, when the page is built, then the banner sits in its own docked band
	/// OUTSIDE the scrolling report, so the verdict is on screen at the default scroll position - which is
	/// the whole point of the finding: a verdict buried in a monospace dump is a verdict nobody reads.</summary>
	[Fact]
	public void Banner_IsDockedOutsideTheScrollingReport()
	{
		_ui.Run(() =>
		{
			using DatabasePage page = NewPage(new FakeIpc());
			TabPage overview = FindTab(page, "Overview");

			Control banner = FindControlWithText(overview, "Store integrity:")
				?? throw new Xunit.Sdk.XunitException("The Overview tab no longer renders a store-integrity banner.");

			Panel panel = Assert.IsType<Panel>(banner.Parent);
			Assert.Equal(DockStyle.Fill, banner.Dock);
			Assert.Equal(DockStyle.Top, panel.Dock);

			// The band is not inside the report TextBox, it is a sibling above it.
			Control? report = AllControls(overview).OfType<TextBox>().FirstOrDefault();
			Assert.NotNull(report);
			Assert.NotEqual(report, panel);
			Assert.False(IsDescendantOf(panel, report!));
		});
	}

	/// <summary>Given nothing has been read yet, when the page is built, then the banner already refuses to
	/// look healthy: it says the tamper evidence is UNVERIFIED rather than showing a neutral band.</summary>
	[Fact]
	public void FreshPage_DoesNotShowANeutralBanner()
	{
		_ui.Run(() =>
		{
			using DatabasePage page = NewPage(new FakeIpc());

			Assert.Equal(StoreIntegrityVerdictBand.Unknown, page.IntegrityBannerBand);
			Assert.True(page.IntegrityBannerShowsAlarm);
			Assert.Contains("UNVERIFIED", page.IntegrityBannerText, StringComparison.Ordinal);
		});
	}

	/// <summary>Given MainForm has themed the page (the dark theme paints every container surface), when the
	/// banner has already decided a band, then the theme does not repaint it into the neutral face - a verdict
	/// that theming could wash out would make an unread alarm and a pass look identical.</summary>
	[Fact]
	public void Banner_SurvivesTheDarkTheme()
	{
		_ui.Run(() =>
		{
			using DatabasePage page = NewPage(new FakeIpc());
			DarkTheme.Apply(page);

			Assert.Equal(DatabasePage.IntegrityBannerBackFor(page.IntegrityBannerBand), page.IntegrityBannerBackColor);
			Assert.True(page.IntegrityBannerShowsAlarm);
		});
	}

	/// <summary>Given the theme was applied first, when an ok verdict arrives, then the banner switches to the
	/// neutral face - the band, not the theme, is what decides the colour.</summary>
	[Fact]
	public void Banner_AfterTheDarkTheme_FollowsTheReportedBand()
	{
		_ui.Run(() =>
		{
			using DatabasePage page = NewPage(Answering(Overview("ok", entries: 2)));
			DarkTheme.Apply(page);
			_ui.Await(page.RefreshOverviewAsync(), "RefreshOverviewAsync");

			Assert.Equal(StoreIntegrityVerdictBand.Ok, page.IntegrityBannerBand);
			Assert.Equal(DatabasePage.IntegrityBannerBackFor(StoreIntegrityVerdictBand.Ok), page.IntegrityBannerBackColor);
			Assert.False(page.IntegrityBannerShowsAlarm);
		});
	}

	// ── Fixtures and helpers ─────────────────────────────────────────────────────

	/// <summary>An overview whose fingerprint section completed, so the verdict is a real reading. The chain
	/// state, the entry count and the section status are the only knobs the banner cares about.</summary>
	private static DatabaseOverviewDto Overview(string chainState, int entries)
	{
		DatabaseOverviewDto dto = new()
		{
			Status = IpcResultStatus.Success,
			QueriedUtc = new DateTime(2026, 9, 15, 8, 0, 0, DateTimeKind.Utc),
			DatabasePath = @"C:\evidence\rdpaudit.db",
			FingerprintChainState = chainState,
			FingerprintChainEntryCount = entries,
			FingerprintChainMessage = "The store-fingerprint chain verifies: " + entries + " entr(ies).",
			FingerprintChainMirrorAvailable = true,
			FingerprintCleanShutdownUtc = new DateTime(2026, 9, 15, 7, 0, 0, DateTimeKind.Utc),
			FingerprintPeriodicUtc = new DateTime(2026, 9, 15, 6, 0, 0, DateTimeKind.Utc),
			LedgerChainIntact = true,
			LedgerChainedRows = 10,
			LedgerUnchainedRows = 0,
			LedgerChainMessage = "The deletion ledger chain verifies: 10 entr(ies).",
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

	private static DatabasePage NewPage(IIpcClient ipc) => new(ipc);

	/// <summary>A client that answers the overview command with the supplied snapshot and nothing else.</summary>
	private static FakeIpc Answering(DatabaseOverviewDto overview) =>
		new FakeIpc().On(IpcCommand.GetDatabaseOverview, overview);

	private static TabPage FindTab(Control root, string title)
		=> AllControls(root).OfType<TabControl>()
			.SelectMany(control => control.TabPages.Cast<TabPage>())
			.Single(page => string.Equals(page.Text, title, StringComparison.Ordinal));

	private static Control? FindControlWithText(Control root, string text)
		=> AllControls(root)
			.FirstOrDefault(control => (control.Text ?? string.Empty).Contains(text, StringComparison.Ordinal));

	private static bool IsDescendantOf(Control control, Control candidateAncestor)
	{
		for (Control? parent = control.Parent; parent is not null; parent = parent.Parent)
		{
			if (ReferenceEquals(parent, candidateAncestor))
			{
				return true;
			}
		}

		return false;
	}

	private static IEnumerable<Control> AllControls(Control root)
	{
		foreach (Control child in root.Controls)
		{
			yield return child;
			foreach (Control nested in AllControls(child))
			{
				yield return nested;
			}
		}
	}

	private static string ReportText(DatabasePage page, string marker)
	{
		TextBox match = AllControls(page)
			.OfType<TextBox>()
			.FirstOrDefault(box => box.Text.Contains(marker, StringComparison.Ordinal))
			?? throw new Xunit.Sdk.XunitException(
				"No report containing \"" + marker + "\" was rendered.");
		return match.Text;
	}

	/// <summary>Records every command and answers from a canned table, exactly like the other Database-tab
	/// tests: a command with no canned answer fails as "service unreachable", so a missing fake surfaces
	/// instead of silently returning an empty success.</summary>
	private sealed class FakeIpc : IIpcClient
	{
		private readonly Dictionary<IpcCommand, object> _answers = new();
		private readonly Dictionary<IpcCommand, (IpcCallOutcome Outcome, string? Error)> _failures = new();

		public FakeIpc On<T>(IpcCommand command, T value)
			where T : class
		{
			_answers[command] = value;
			return this;
		}

		public FakeIpc Fail(IpcCommand command, IpcCallOutcome outcome, string? error)
		{
			_failures[command] = (outcome, error);
			return this;
		}

		public Task<IpcCallResult<T>> SendDetailedAsync<T>(
			IpcCommand command, object? payload = null, CancellationToken ct = default)
		{
			if (_failures.TryGetValue(command, out (IpcCallOutcome Outcome, string? Error) failure))
			{
				return Task.FromResult(Result<T>(command, failure.Outcome, default, failure.Error));
			}

			if (_answers.TryGetValue(command, out object? answer))
			{
				return Task.FromResult(answer is T typed
					? Result<T>(command, IpcCallOutcome.Success, typed, null)
					: Result<T>(command, IpcCallOutcome.SuccessNoPayload, default, null));
			}

			return Task.FromResult(Result<T>(
				command, IpcCallOutcome.ConnectFailed, default, "no canned answer for " + command));
		}

		private static IpcCallResult<T> Result<T>(
			IpcCommand command, IpcCallOutcome outcome, T? value, string? error)
			=> new(
				command,
				outcome,
				value,
				error,
				outcome == IpcCallOutcome.Success ? null : "FakeIpc",
				DateTime.UtcNow,
				durationMs: 1,
				timeoutMs: 5000,
				pipeConnected: outcome != IpcCallOutcome.ConnectFailed,
				responseReceived: outcome == IpcCallOutcome.Success);
	}
}
