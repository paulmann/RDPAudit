/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : DatabasePageTests.cs
// Project: RdpAudit.Configurator.Tests
// Purpose: Stage 3 verification for the Database tab. Asserts the inner-tab structure and order, the
//          Danger Zone gate (locked without DEBUG+elevation, unlocked with both, and fail-closed when
//          the service cannot be asked), the presence of the typed confirmation phrases on the
//          destructive actions, the "purge by subject is not implemented" stub, the retention
//          editor's control <-> contract mapping and the old -> new diff, the pure renderers
//          (overview, preview, verification, restore report, CSV, byte formatting), the ledger
//          filter mapping and the busy gate that rejects a second overlapping operation. No window
//          handle is created and no live pipe is required: the page is constructed and exercised on
//          an STA thread through its internal members.
//          Every asynchronous page call goes through StaTestHarness.Await, which PUMPS the message
//          queue of the STA thread that owns the page's WindowsFormsSynchronizationContext. Blocking
//          that thread with Wait()/GetAwaiter().GetResult() deadlocks the page against its own
//          ConfigureAwait(true) continuation - the exact hang that made this class non-terminating.
// Depends: DatabasePage, StaTestHarness, WinForms, xunit
// Extends: Add the matching assertion whenever a new inner tab or destructive action is introduced.

using System.Runtime.Versioning;
using RdpAudit.Configurator.Forms;
using RdpAudit.Configurator.Ipc;
using RdpAudit.Core.Config;
using RdpAudit.Core.Ipc;
using RdpAudit.Core.Ipc.Contracts;
using RdpAudit.Core.Models;
using RdpAudit.Core.Retention;
using System.Windows.Forms;
using Xunit;

namespace RdpAudit.Configurator.Tests;

[SupportedOSPlatform("windows")]
public sealed class DatabasePageTests
{
	/// <summary>Per-class STA host: every body runs on an STA thread whose message queue is pumped while
	/// the test waits, so a page continuation can never be starved. The harness also caps the whole
	/// class (test bodies at 30 s, one awaited operation at 20 s, the class at 2 minutes).</summary>
	private readonly StaTestHarness _ui = new(nameof(DatabasePageTests));

	private static DatabasePage NewPage() => new(new IpcClient());

	private static IEnumerable<Control> AllControls(Control root)
	{
		foreach (Control child in root.Controls)
		{
			yield return child;
			foreach (Control grand in AllControls(child))
			{
				yield return grand;
			}
		}
	}

	private static Button? FindButton(Control root, string textPrefix) =>
		AllControls(root).OfType<Button>().FirstOrDefault(button =>
			(button.Text ?? string.Empty).StartsWith(textPrefix, StringComparison.Ordinal));

	/// <summary>Finds a button inside ONE inner tab. Needed because two tabs legitimately expose the
	/// same action text ("Restore over live database…" is present in both Backup & Restore and the
	/// Danger Zone), so a page-wide search would be ambiguous.</summary>
	private static Button FindButtonInTab(Control root, string tabTitle, string textPrefix)
	{
		TabPage tab = AllControls(root).OfType<TabControl>()
			.SelectMany(control => control.TabPages.Cast<TabPage>())
			.Single(page => string.Equals(page.Text, tabTitle, StringComparison.Ordinal));
		return AllControls(tab).OfType<Button>().First(button =>
			(button.Text ?? string.Empty).StartsWith(textPrefix, StringComparison.Ordinal));
	}

	// ── Structure ────────────────────────────────────────────────────────────────

	/// <summary>Given the tab is built, when the page is constructed, then it carries exactly the seven
	/// specified inner tabs in the specified order.</summary>
	[Fact]
	public void Page_BuildsTheSevenInnerTabsInOrder()
	{
		_ui.Run(() =>
		{
			using DatabasePage page = NewPage();
			TabControl? tabs = AllControls(page).OfType<TabControl>().SingleOrDefault();
			Assert.NotNull(tabs);
			Assert.Equal(
				DatabasePage.InnerTabTitles,
				tabs!.TabPages.Cast<TabPage>().Select(p => p.Text));
			Assert.Equal(
				new[] { "Overview", "Retention", "Maintenance", "Backup & Restore", "Shards", "Danger Zone", "Ledger" },
				DatabasePage.InnerTabTitles);
		});
	}

	[Fact]
	public void Page_Constructor_ThrowsOnNullIpcClient()
	{
		_ui.Run(() => Assert.Throws<ArgumentNullException>(() => new DatabasePage(null!)));
	}

	/// <summary>Every data view is stampable: the page must carry the "as of" labels the requirement
	/// asks for, one per view.</summary>
	[Fact]
	public void Page_CarriesAsOfStamps()
	{
		_ui.Run(() =>
		{
			using DatabasePage page = NewPage();
			Label[] stamps = AllControls(page).OfType<Label>()
				.Where(label => (label.Text ?? string.Empty).StartsWith("as of", StringComparison.Ordinal))
				.ToArray();
			Assert.True(stamps.Length >= 4, "Expected an 'as of' stamp for the overview, backups, shards and ledger views.");
		});
	}

	// ── Danger Zone gates and phrases ────────────────────────────────────────────

	/// <summary>Given DEBUG mode and elevation are absent, when the gate is applied, then every
	/// destructive button is disabled and the page reports the zone as locked.</summary>
	[Fact]
	public void DangerZone_WithoutDebugAndElevation_IsLocked()
	{
		_ui.Run(() =>
		{
			using DatabasePage page = NewPage();
			Assert.False(page.DangerZoneUnlocked);

			page.ApplyDangerZoneGate(debugMode: false, elevated: false);
			Assert.False(page.DangerZoneUnlocked);
			Assert.False(FindButtonInTab(page, "Danger Zone", "Back up and reset database").Enabled);
			Assert.False(FindButtonInTab(page, "Danger Zone", "Clear all application data").Enabled);
			Assert.False(FindButtonInTab(page, "Danger Zone", "Restore over live database").Enabled);
		});
	}

	/// <summary>Given only DEBUG mode is on, when the gate is applied, then the zone stays locked:
	/// elevation is required separately.</summary>
	[Fact]
	public void DangerZone_WithDebugButNoElevation_StaysLocked()
	{
		_ui.Run(() =>
		{
			using DatabasePage page = NewPage();
			page.ApplyDangerZoneGate(debugMode: true, elevated: false);
			Assert.False(page.DangerZoneUnlocked);
			Assert.False(FindButtonInTab(page, "Danger Zone", "Back up and reset database").Enabled);
		});
	}

	/// <summary>Given DEBUG mode and elevation are both present, when the gate is applied, then the
	/// destructive buttons are enabled.</summary>
	[Fact]
	public void DangerZone_WithDebugAndElevation_IsUnlocked()
	{
		_ui.Run(() =>
		{
			using DatabasePage page = NewPage();
			page.ApplyDangerZoneGate(debugMode: true, elevated: true);
			Assert.True(page.DangerZoneUnlocked);
			Assert.True(FindButtonInTab(page, "Danger Zone", "Back up and reset database").Enabled);
			Assert.True(FindButtonInTab(page, "Danger Zone", "Clear all application data").Enabled);
			Assert.True(FindButtonInTab(page, "Danger Zone", "Restore over live database").Enabled);
		});
	}

	/// <summary>Given the service cannot be reached, when the gate is re-resolved, then it stays
	/// locked: the DEBUG switch is read from the service, so a transport failure must fail closed.</summary>
	[Fact]
	public void DangerZone_GateRefresh_FailsClosedWithoutAService()
	{
		_ui.Run(() =>
		{
			using DatabasePage page = NewPage();
			page.ApplyDangerZoneGate(debugMode: true, elevated: true);
			_ui.Await(page.RefreshDangerZoneGateAsync(), "RefreshDangerZoneGateAsync");
			Assert.False(page.DangerZoneUnlocked);
			Assert.False(FindButtonInTab(page, "Danger Zone", "Clear all application data").Enabled);
			Assert.Contains("Locked", page.DangerZoneGateText, StringComparison.Ordinal);
		});
	}

	/// <summary>Given the destructive actions, when the phrases are inspected, then each is present and
	/// the application-data phrase is exactly the one the service re-validates server-side.</summary>
	[Fact]
	public void DangerZone_TypedPhrases_ArePresentAndMatchTheServerContract()
	{
		Assert.Equal("CLEAR ALL RDP AUDIT DATA", DatabasePage.ClearAllDataPhrase);
		Assert.False(string.IsNullOrWhiteSpace(DatabasePage.ResetDatabasePhrase));
		Assert.False(string.IsNullOrWhiteSpace(DatabasePage.RestoreOverLivePhrase));
		Assert.NotEqual(DatabasePage.ClearAllDataPhrase, DatabasePage.ResetDatabasePhrase);
		Assert.NotEqual(DatabasePage.ClearAllDataPhrase, DatabasePage.RestoreOverLivePhrase);
	}

	/// <summary>Given the danger zone is built, when it is inspected, then "Purge by subject" and the
	/// offline compaction are offered as gated actions with their typed phrases, and the explanatory text
	/// states what a subject purge deliberately does not touch.</summary>
	[Fact]
	public void DangerZone_OffersPurgeBySubjectAndOfflineCompaction()
	{
		_ui.Run(() =>
		{
			using DatabasePage page = NewPage();
			Assert.Contains(
				AllControls(page).OfType<Label>(),
				label => string.Equals(label.Text, DatabasePage.PurgeStubText, StringComparison.Ordinal));

			Button purge = FindButtonInTab(page, "Danger Zone", "Purge by subject");
			Button compact = FindButtonInTab(page, "Danger Zone", "Compact database (offline)");

			// Locked until DEBUG mode and elevation are both present.
			Assert.False(purge.Enabled);
			Assert.False(compact.Enabled);

			page.ApplyDangerZoneGate(debugMode: true, elevated: true);
			Assert.True(purge.Enabled);
			Assert.True(compact.Enabled);

			// The phrases the operator must type are the ones the server re-validates.
			Assert.Equal("PURGE SUBJECT DATA", DatabasePage.PurgeSubjectPhrase);
			Assert.Equal("COMPACT RDP AUDIT DATABASE", DatabasePage.CompactOfflinePhrase);
		});
	}

	/// <summary>Given no snapshot has been loaded, when the page is constructed, then the restore
	/// actions are disabled: they have nothing to act on.</summary>
	[Fact]
	public void BackupTab_RestoreActions_AreDisabledWithoutASnapshot()
	{
		_ui.Run(() =>
		{
			using DatabasePage page = NewPage();
			page.ApplyDangerZoneGate(debugMode: true, elevated: true);
			Assert.False(FindButtonInTab(page, "Backup & Restore", "Restore to folder").Enabled);
			Assert.False(FindButtonInTab(page, "Backup & Restore", "Verify selected").Enabled);
		});
	}

	// ── Overview reachability ────────────────────────────────────────────────────

	/// <summary>Given the service is unreachable, when the overview is refreshed, then the page reports
	/// the failure in its status instead of silently showing an empty report, and it does so in bounded
	/// time: the awaited call runs while the STA message queue is pumped, which is the only way a
	/// ConfigureAwait(true) continuation of a page can ever resume in a test.</summary>
	[Fact]
	public void Overview_WithoutAService_ReportsAnErrorStatus()
	{
		_ui.Run(() =>
		{
			using DatabasePage page = NewPage();
			_ui.Await(page.RefreshOverviewAsync(), "RefreshOverviewAsync");
			Assert.Contains("unavailable", page.StatusText, StringComparison.OrdinalIgnoreCase);

			// The status is a real sentence with the page's UTC stamp, not an empty or placeholder line.
			Assert.StartsWith("[", page.StatusText, StringComparison.Ordinal);
			Assert.Contains("service unreachable", page.StatusText, StringComparison.OrdinalIgnoreCase);
		});
	}

	/// <summary>Given a refresh has finished, when the page is asked again, then the operation runs a
	/// second time: the pump-based await must leave the page in a usable state rather than half-busy.</summary>
	[Fact]
	public void Overview_AfterADegradedRefresh_RemainsReusable()
	{
		_ui.Run(() =>
		{
			using DatabasePage page = NewPage();
			_ui.Await(page.RefreshOverviewAsync(), "first RefreshOverviewAsync");
			_ui.Await(page.RefreshOverviewAsync(), "second RefreshOverviewAsync");
			Assert.Contains("unavailable", page.StatusText, StringComparison.OrdinalIgnoreCase);

			// EndBusy ran after the first call, so the second one was accepted rather than refused by the
			// re-entrancy guard.
			Assert.DoesNotContain("Operation in progress", page.StatusText, StringComparison.Ordinal);
		});
	}

	// ── Busy gate ────────────────────────────────────────────────────────────────

	/// <summary>Given an operation is in flight, when the tab is disposed before the call returns (the
	/// operator closed the window during a long integrity check), then the page reports nothing it cannot
	/// report and never lets an exception escape: an async void event handler that throws would be fatal,
	/// because the application installs no global handler.</summary>
	[Fact]
	public void OperationDisposedWhileInFlight_DoesNotEscape()
	{
		_ui.Run(() =>
		{
			DatabasePage page = NewPage();
			Task refresh = page.RefreshOverviewAsync();
			page.Dispose();
			_ui.Await(refresh, "RefreshOverviewAsync after the tab was disposed");
			_ui.Pump(20);
		});
	}

	/// <summary>Given a long operation is in flight, when the operator clicks again, then the second
	/// operation is refused and the action surface is disabled until the first one ends - and the cancel
	/// button, which lives in the operation bar OUTSIDE the disabled tab control, stays clickable.
	/// A cancel control inside a disabled container would report Enabled == false, so this placement is
	/// what keeps a 60 s maintenance call cancellable.</summary>
	[Fact]
	public void BusyGate_RefusesASecondOperationAndKeepsCancelReachable()
	{
		_ui.Run(() =>
		{
			using DatabasePage page = NewPage();
			TabControl innerTabs = AllControls(page).OfType<TabControl>().Single();
			Button cancel = FindButton(page, "Cancel running operation")
				?? throw new Xunit.Sdk.XunitException("The Database page no longer offers a cancel button.");

			Assert.True(page.BeginBusy());
			Assert.False(innerTabs.Enabled);

			// The cancel affordance is not inside the disabled container, so it is genuinely reachable.
			Assert.True(cancel.Enabled);
			Assert.DoesNotContain(innerTabs.TabPages.Cast<TabPage>(), tab => AllControls(tab).Contains(cancel));

			Assert.False(page.BeginBusy());
			Assert.Contains("Operation in progress", page.StatusText, StringComparison.Ordinal);

			page.EndBusy();
			Assert.True(innerTabs.Enabled);
			Assert.False(cancel.Enabled);
		});
	}

	// ── Pure renderers and mappings ──────────────────────────────────────────────

	[Fact]
	public void DescribeBytes_ReportsUnknownForNegativeAndFormatsRealSizes()
	{
		Assert.Equal("unknown", DatabasePage.DescribeBytes(-1));
		Assert.Contains("0 B", DatabasePage.DescribeBytes(0), StringComparison.Ordinal);
		Assert.Contains("KiB", DatabasePage.DescribeBytes(2048), StringComparison.Ordinal);
		Assert.Contains("MiB", DatabasePage.DescribeBytes(5 * 1024 * 1024), StringComparison.Ordinal);
	}

	/// <summary>Given a store whose auto-vacuum mode is NONE and which holds free pages, when the overview
	/// is rendered, then the panel states the mode, the free pages and the reclaimable bytes, and repeats
	/// the service's sentence that online release is impossible on this store (B27) - the operator must not
	/// have to read a log to learn that "released nothing" is the store's header talking.</summary>
	[Fact]
	public void FormatOverview_ShowsTheAutoVacuumModeAndTheOfflineOnlyHint()
	{
		DatabaseOverviewDto dto = new()
		{
			QueriedUtc = new DateTime(2026, 9, 15, 12, 0, 0, DateTimeKind.Utc),
			DatabasePath = @"C:\ProgramData\RdpAudit\rdpaudit.db",
			AutoVacuumMode = 0,
			JournalMode = "wal",
			PageSize = 4096,
			PageCount = 136,
			FreeListPages = 2822,
			ReclaimableBytes = 4096L * 2822,
			SpaceReclamationNote =
				"ONLINE RELEASE IS NOT POSSIBLE on this store: its auto-vacuum mode is 0, so the bounded "
				+ "incremental vacuum of the purge and the maintenance surface releases nothing.",
		};

		string report = DatabasePage.FormatOverview(dto);

		Assert.Contains("Auto-vacuum mode:  NONE (0)", report, StringComparison.Ordinal);
		Assert.Contains("Journal mode:      wal", report, StringComparison.Ordinal);
		Assert.Contains("4096 bytes each, 136 page(s)", report, StringComparison.Ordinal);
		Assert.Contains("Free pages:        2822", report, StringComparison.Ordinal);
		Assert.Contains("currently allocated to them", report, StringComparison.Ordinal);
		Assert.Contains("ONLINE RELEASE IS NOT POSSIBLE", report, StringComparison.Ordinal);
	}

	/// <summary>Given a service that never failed to persist a batch, the panel says so plainly instead of
	/// printing a zero that could be read as "unknown".</summary>
	[Fact]
	public void FormatOverview_OnAHealthyPersistPipeline_SaysNoBatchFailed()
	{
		DatabaseOverviewDto dto = new()
		{
			QueriedUtc = new DateTime(2026, 9, 15, 12, 0, 0, DateTimeKind.Utc),
			DatabasePath = @"C:\ProgramData\RdpAudit\rdpaudit.db",
			PersistBatchRetainedCount = 0,
			PersistBatchStalledCount = 0,
		};

		string report = DatabasePage.FormatOverview(dto);

		Assert.Contains("Ingest persistence: no batch failed to persist", report, StringComparison.Ordinal);
	}

	/// <summary>Given a service that kept a batch and escalated it, the panel reports both numbers and says
	/// what the retention means - ingest paused rather than dropping evidence.</summary>
	[Fact]
	public void FormatOverview_OnARetainedBatch_ReportsTheCountersAndTheTradeOff()
	{
		DatabaseOverviewDto dto = new()
		{
			QueriedUtc = new DateTime(2026, 9, 15, 12, 0, 0, DateTimeKind.Utc),
			DatabasePath = @"C:\ProgramData\RdpAudit\rdpaudit.db",
			PersistBatchRetainedCount = 3,
			PersistBatchStalledCount = 1,
		};

		string report = DatabasePage.FormatOverview(dto);

		Assert.Contains("3 batch(es) kept in memory for retry", report, StringComparison.Ordinal);
		Assert.Contains("1 of them past the 10-minute stall threshold", report, StringComparison.Ordinal);
		Assert.Contains("ingest pauses while a batch is retained", report, StringComparison.Ordinal);
	}

	/// <summary>Given a service that reported no counter at all, the panel says unknown - never "healthy".
	/// The counters exist to make a silent stall visible, so their absence cannot render as a pass.</summary>
	[Fact]
	public void FormatOverview_WithoutCounters_SaysUnknownRatherThanHealthy()
	{
		DatabaseOverviewDto dto = new()
		{
			QueriedUtc = new DateTime(2026, 9, 15, 12, 0, 0, DateTimeKind.Utc),
			DatabasePath = @"C:\ProgramData\RdpAudit\rdpaudit.db",
		};

		string report = DatabasePage.FormatOverview(dto);

		Assert.Contains("Ingest persistence: unknown", report, StringComparison.Ordinal);
	}

	/// <summary>Counterfactual to the previous test: given a store in INCREMENTAL mode, the same panel says
	/// online reclamation is available, so the warning above is a fact about the mode and not a constant
	/// line the panel prints for every store.</summary>
	[Fact]
	public void FormatOverview_OnAnIncrementalStore_SaysOnlineReclamationIsAvailable()
	{
		DatabaseOverviewDto dto = new()
		{
			QueriedUtc = new DateTime(2026, 9, 15, 12, 0, 0, DateTimeKind.Utc),
			DatabasePath = @"C:\ProgramData\RdpAudit\rdpaudit.db",
			AutoVacuumMode = 2,
			JournalMode = "wal",
			PageSize = 4096,
			PageCount = 137,
			FreeListPages = 0,
			ReclaimableBytes = 0,
			SpaceReclamationNote = "Online reclamation is available: this store's auto-vacuum mode is INCREMENTAL.",
		};

		string report = DatabasePage.FormatOverview(dto);

		Assert.Contains("Auto-vacuum mode:  INCREMENTAL (2)", report, StringComparison.Ordinal);
		Assert.Contains("Online reclamation is available", report, StringComparison.Ordinal);
		Assert.DoesNotContain("ONLINE RELEASE IS NOT POSSIBLE", report, StringComparison.Ordinal);
	}

	/// <summary>Given the mode could not be read, when the overview is rendered, then the panel says the
	/// mode is unknown and prints no reclamation sentence at all, because every sentence about what the
	/// mode permits would be a guess.</summary>
	[Fact]
	public void FormatOverview_WithoutAMode_SaysUnknownAndPrintsNoReclamationClaim()
	{
		DatabaseOverviewDto dto = new()
		{
			QueriedUtc = new DateTime(2026, 9, 15, 12, 0, 0, DateTimeKind.Utc),
			DatabasePath = @"C:\ProgramData\RdpAudit\rdpaudit.db",
			AutoVacuumMode = null,
			JournalMode = null,
			PageSize = null,
			PageCount = null,
			FreeListPages = null,
			ReclaimableBytes = null,
			SpaceReclamationNote = null,
		};

		string report = DatabasePage.FormatOverview(dto);

		Assert.Contains("Auto-vacuum mode:  unknown", report, StringComparison.Ordinal);
		Assert.Contains("Journal mode:      unknown", report, StringComparison.Ordinal);
		Assert.Contains("Free pages:        unknown", report, StringComparison.Ordinal);
		Assert.DoesNotContain("Space reclamation:", report, StringComparison.Ordinal);
	}

	/// <summary>Given a partial overview, when it is rendered, then the stamp, the failed section and
	/// every warning are visible and no value is invented for an unreadable count.</summary>
	[Fact]
	public void FormatOverview_ShowsTheStampFailedSectionsAndWarnings()
	{
		DatabaseOverviewDto dto = new()
		{
			QueriedUtc = new DateTime(2026, 9, 14, 10, 30, 0, DateTimeKind.Utc),
			DatabasePath = @"C:\ProgramData\RdpAudit\rdpaudit.db",
			DatabaseBytes = 2048,
			WalBytes = 0,
			ShmBytes = -1,
			TotalDatabaseFamilyBytes = -1,
			ActionsBytes = -1,
			ActionsFileCount = -1,
			IsPartial = true,
			BackupSnapshotCount = 2,
			BackupLastSnapshotDirectory = @"C:\ProgramData\RdpAudit\Backups\20260914-100000",
		};
		dto.TableRowCounts.Add(new DatabaseTableRowCountDto { Table = "RawEvents", RowCount = 42 });
		dto.TableRowCounts.Add(new DatabaseTableRowCountDto { Table = "Alerts", RowCount = -1, Error = "locked" });
		dto.Sections.Add(new DatabaseOverviewSectionDto { Section = "DbFiles", Status = "Completed", DurationMs = 3 });
		dto.Sections.Add(new DatabaseOverviewSectionDto { Section = "ShardTree", Status = "TimedOut", DurationMs = 8000, Error = "budget" });
		dto.Warnings.Add("Database overview section 'ShardTree' timed out.");

		string report = DatabasePage.FormatOverview(dto);
		Assert.Contains("2026-09-14 10:30:00", report, StringComparison.Ordinal);
		Assert.Contains("Partial:           yes", report, StringComparison.Ordinal);
		Assert.Contains("SHM bytes:         unknown", report, StringComparison.Ordinal);
		Assert.Contains("ERROR: locked", report, StringComparison.Ordinal);
		Assert.Contains("[!! ] ShardTree", report, StringComparison.Ordinal);
		Assert.Contains("Database overview section 'ShardTree' timed out.", report, StringComparison.Ordinal);
	}

	/// <summary>Given the service reports no honest reclaimed-bytes figure, when the preview is
	/// rendered, then the report says the figure is unknown until a checkpoint/vacuum and never
	/// fabricates a byte count.</summary>
	[Fact]
	public void FormatPreview_IsHonestAboutUnknownReclaimedBytes()
	{
		RetentionPreviewDto preview = new()
		{
			QueriedUtc = new DateTime(2026, 9, 14, 11, 0, 0, DateTimeKind.Utc),
			PolicyEnabled = true,
			Trigger = EventDeletionTrigger.RawEventRows,
			TriggerWouldFire = true,
			WouldDeleteRows = 1234,
			EstimatedReclaimedBytes = null,
			ReclaimedBytesNote = "Reclaimed bytes are known after a checkpoint or vacuum.",
			RuleVersion = RetentionRuleVersion.Current,
			MinAgeCutoffUtc = new DateTime(2026, 9, 7, 11, 0, 0, DateTimeKind.Utc),
			TailKeepPerCode = 512,
			MaxRowsPerPass = 50_000,
			SkippedCodeCount = 1,
		};
		preview.Codes.Add(new RetentionPreviewCodeDto
		{
			EventId = 4625,
			Channel = "Security",
			Count = 900_000,
			EligibleInteriorRows = 899_000,
			PlannedRows = 1234,
			Explanation = "Densest code; interior compressed.",
		});
		preview.Steps.Add(new RetentionPreviewStepDto
		{
			Order = 0,
			EventId = 4625,
			Channel = "Security",
			Rows = 1234,
			AnchorRowId = 7,
			TailBoundaryRowId = 99,
			WindowStartUtc = new DateTime(2026, 8, 1, 0, 0, 0, DateTimeKind.Utc),
			WindowEndUtc = new DateTime(2026, 8, 9, 0, 0, 0, DateTimeKind.Utc),
		});

		string report = DatabasePage.FormatPreview(preview);
		Assert.Contains("(unknown before a checkpoint/vacuum)", report, StringComparison.Ordinal);
		Assert.Contains("Reclaimed bytes are known after a checkpoint or vacuum.", report, StringComparison.Ordinal);
		Assert.Contains("Would delete rows:  1234", report, StringComparison.Ordinal);
		Assert.Contains("#0", report, StringComparison.Ordinal);
		Assert.DoesNotContain("reclaimed: 0", report, StringComparison.OrdinalIgnoreCase);
	}

	/// <summary>Given an empty plan, when the preview is rendered, then it says so explicitly instead
	/// of showing an empty list.</summary>
	[Fact]
	public void FormatPreview_WithNoSteps_SaysSo()
	{
		string report = DatabasePage.FormatPreview(new RetentionPreviewDto { Trigger = EventDeletionTrigger.Unknown });
		Assert.Contains("(none — no configured ceiling is breached, or a legal hold is in force)", report, StringComparison.Ordinal);
	}

	/// <summary>Given a verification result, when it is rendered, then the verdict, both digests and the
	/// quick_check outcome are all visible.</summary>
	[Fact]
	public void FormatVerification_ShowsVerdictAndEvidence()
	{
		DatabaseBackupVerificationDto verification = new()
		{
			QueriedUtc = new DateTime(2026, 9, 14, 12, 0, 0, DateTimeKind.Utc),
			SnapshotName = "20260914-100000",
			SnapshotDirectory = @"C:\ProgramData\RdpAudit\Backups\20260914-100000",
			VerdictName = "HashMismatch",
			IsUsable = false,
			ExpectedSha256 = "AAA",
			ActualSha256 = "BBB",
			QuickCheckResult = "ok",
			Message = "The copy was modified.",
		};
		string report = DatabasePage.FormatVerification(verification);
		Assert.Contains("HashMismatch", report, StringComparison.Ordinal);
		Assert.Contains("AAA", report, StringComparison.Ordinal);
		Assert.Contains("BBB", report, StringComparison.Ordinal);
		Assert.Contains("quick_check:   ok", report, StringComparison.Ordinal);
		Assert.Contains("The copy was modified.", report, StringComparison.Ordinal);
	}

	[Fact]
	public void FormatRestoreReport_ShowsTargetAndShardScope()
	{
		DatabaseBackupRestoreReportDto report = new()
		{
			QueriedUtc = new DateTime(2026, 9, 14, 12, 30, 0, DateTimeKind.Utc),
			Status = IpcResultStatus.Success,
			SnapshotName = "20260914-100000",
			TargetDirectory = @"D:\scratch",
			TargetDatabasePath = @"D:\scratch\rdpaudit.db",
			DatabaseBytesCopied = 4096,
			ShardsRestored = true,
			ShardFilesRestored = 3,
			ShardBytesRestored = 300,
			Message = "Restored.",
		};
		string rendered = DatabasePage.FormatRestoreReport(report);
		Assert.Contains(@"D:\scratch\rdpaudit.db", rendered, StringComparison.Ordinal);
		Assert.Contains("3 file(s)", rendered, StringComparison.Ordinal);
		Assert.Contains("Restored.", rendered, StringComparison.Ordinal);
	}

	/// <summary>Given an old and a new policy, when the diff is built, then only the changed fields
	/// appear - the operator confirms exactly what will change.</summary>
	[Fact]
	public void BuildPolicyDiff_ListsOnlyChangedFields()
	{
		RetentionPolicyValuesDto oldPolicy = new()
		{
			Enabled = false,
			TailKeepPerCode = 512,
			MinAgeDays = 7,
			ProtectedEventIds = new List<int> { 4720 },
		};
		RetentionPolicyValuesDto newPolicy = new()
		{
			Enabled = true,
			TailKeepPerCode = 1024,
			MinAgeDays = 7,
			ProtectedEventIds = new List<int> { 4720, 4672 },
		};
		RetentionWindowsDto oldWindows = new() { EventRetentionDays = 365, LogRetentionDays = 90 };
		RetentionWindowsDto newWindows = new() { EventRetentionDays = 180, LogRetentionDays = 90 };

		List<string> diff = DatabasePage.BuildPolicyDiff(oldPolicy, newPolicy, oldWindows, newWindows);
		Assert.Contains(diff, line => line.StartsWith("Enabled: False → True", StringComparison.Ordinal));
		Assert.Contains(diff, line => line.StartsWith("TailKeepPerCode: 512 → 1024", StringComparison.Ordinal));
		Assert.Contains(diff, line => line.StartsWith("ProtectedEventIds: 4720 → 4720,4672", StringComparison.Ordinal));
		Assert.Contains(diff, line => line.StartsWith("EventRetentionDays: 365 → 180", StringComparison.Ordinal));
		Assert.DoesNotContain(diff, line => line.StartsWith("MinAgeDays", StringComparison.Ordinal));
		Assert.DoesNotContain(diff, line => line.StartsWith("LogRetentionDays", StringComparison.Ordinal));
	}

	[Fact]
	public void BuildPolicyDiff_WithNoChanges_IsEmpty()
	{
		RetentionPolicyValuesDto policy = new() { Enabled = true, TailKeepPerCode = 512 };
		RetentionWindowsDto windows = new() { EventRetentionDays = 365 };
		Assert.Empty(DatabasePage.BuildPolicyDiff(policy, policy, windows, windows));
	}

	/// <summary>Given a loaded policy, when the editor state is captured, then every edited value and
	/// every per-event row travels into the mutation request.</summary>
	[Fact]
	public void CaptureMutationRequest_RoundTripsTheAppliedPolicy()
	{
		_ui.Run(() =>
		{
			using DatabasePage page = NewPage();
			RetentionPolicyDto dto = new()
			{
				Policy = new RetentionPolicyValuesDto
				{
					Enabled = true,
					LegalHold = true,
					AnchorScope = RetentionAnchorScope.PerCodeAndIp,
					TailKeepPerCode = 777,
					CandidateMinRows = 5_000,
					MinAgeDays = 14,
					MaxRowsPerPass = 12_345,
					MaxWriterLockMs = 500,
					DeleteBatchRows = 750,
					MaxDatabaseBytes = 1_000_000,
					MaxRawEventRows = 2_000_000,
					MinFreeDiskBytes = 5_000_000,
					ProtectedEventIds = new List<int> { 4720, 4672 },
					EffectiveTailKeepPerCode = 777,
					EffectiveCandidateMinRows = 5_000,
					EffectiveMinAgeDays = 14,
					EffectiveMaxRowsPerPass = 12_345,
					EffectiveMaxWriterLockMs = 500,
					EffectiveDeleteBatchRows = 750,
					EffectiveMaxDatabaseBytes = 1_000_000,
					EffectiveMaxRawEventRows = 2_000_000,
					EffectiveMinFreeDiskBytes = 5_000_000,
				},
				GlobalWindows = new RetentionWindowsDto
				{
					EventRetentionDays = 180,
					AlertRetentionDays = 400,
					AbuseReportRetentionDays = 200,
					ActiveBlockRetentionDays = 60,
					AttackStatRetentionDays = 120,
					SessionIpCorrelationRetentionDays = 20,
					RdpConnectionFactRetentionDays = 45,
					LogRetentionDays = 30,
				},
			};
			dto.EventWindows.Add(new EventRetentionWindowDto { EventId = 4625, Channel = "Security", RetentionDays = 30 });
			dto.EventWindows.Add(new EventRetentionWindowDto { EventId = 4624, Channel = "Security", RetentionDays = 0 });

			page.ApplyPolicyToControls(dto);
			RetentionPolicyMutationRequest request = page.CaptureMutationRequest();

			Assert.NotNull(request.Policy);
			Assert.True(request.Policy!.Enabled);
			Assert.True(request.Policy.LegalHold);
			Assert.Equal(RetentionAnchorScope.PerCodeAndIp, request.Policy.AnchorScope);
			Assert.Equal(777, request.Policy.TailKeepPerCode);
			Assert.Equal(5_000, request.Policy.CandidateMinRows);
			Assert.Equal(14, request.Policy.MinAgeDays);
			Assert.Equal(12_345, request.Policy.MaxRowsPerPass);
			Assert.Equal(500, request.Policy.MaxWriterLockMs);
			Assert.Equal(750, request.Policy.DeleteBatchRows);
			Assert.Equal(1_000_000, request.Policy.MaxDatabaseBytes);
			Assert.Equal(2_000_000, request.Policy.MaxRawEventRows);
			Assert.Equal(5_000_000, request.Policy.MinFreeDiskBytes);
			Assert.Equal(new List<int> { 4720, 4672 }, request.Policy.ProtectedEventIds);

			Assert.NotNull(request.GlobalWindows);
			Assert.Equal(180, request.GlobalWindows!.EventRetentionDays);
			Assert.Equal(400, request.GlobalWindows.AlertRetentionDays);
			Assert.Equal(200, request.GlobalWindows.AbuseReportRetentionDays);
			Assert.Equal(60, request.GlobalWindows.ActiveBlockRetentionDays);
			Assert.Equal(120, request.GlobalWindows.AttackStatRetentionDays);
			Assert.Equal(20, request.GlobalWindows.SessionIpCorrelationRetentionDays);
			Assert.Equal(45, request.GlobalWindows.RdpConnectionFactRetentionDays);
			Assert.Equal(30, request.GlobalWindows.LogRetentionDays);

			Assert.True(request.EventWindowsReplaceAll);
			Assert.Equal(2, request.EventWindows.Count);
			Assert.Equal(4625, request.EventWindows[0].EventId);
			Assert.Equal(30, request.EventWindows[0].RetentionDays);
			Assert.Equal(0, request.EventWindows[1].RetentionDays);
		});
	}

	/// <summary>Given the ledger filters, when the request is built, then an unset event id and unchecked
	/// date boxes mean "no filter" rather than a fabricated bound.</summary>
	[Fact]
	public void BuildLedgerRequest_MapsFiltersHonestly()
	{
		_ui.Run(() =>
		{
			using DatabasePage page = NewPage();
			DeletionLedgerQueryRequest request = page.BuildLedgerRequest(page: 2, pageSize: 50);
			Assert.Null(request.EventCode);
			Assert.Null(request.FromUtc);
			Assert.Null(request.ToUtc);
			Assert.Equal(2, request.Page);
			Assert.Equal(50, request.PageSize);
		});
	}

	[Fact]
	public void BuildLedgerCsv_EscapesCommasAndQuotesAndReportsTruncation()
	{
		List<DeletionLedgerEntryDto> rows = new()
		{
			new DeletionLedgerEntryDto
			{
				CreatedUtc = new DateTime(2026, 9, 14, 13, 0, 0, DateTimeKind.Utc),
				EventCode = 4625,
				Scope = EventDeletionScope.Global,
				RowsDeleted = 41,
				Trigger = EventDeletionTrigger.RawEventRows,
				RuleVersion = 1,
				Reason = "IDR-1, dense code \"4625\"",
				InitiatedBy = "Service:NT AUTHORITY\\SYSTEM",
			},
		};

		string csv = DatabasePage.BuildLedgerCsv(rows, truncated: true);
		Assert.Contains("CreatedUtc,EventCode,Scope,IpHex,WindowStartUtc,WindowEndUtc,RowsDeleted,Trigger,RuleVersion,Reason,InitiatedBy", csv, StringComparison.Ordinal);
		Assert.Contains("\"IDR-1, dense code \"\"4625\"\"\"", csv, StringComparison.Ordinal);
		Assert.Contains("# truncated=True", csv, StringComparison.Ordinal);
		Assert.Contains("# rows=1", csv, StringComparison.Ordinal);
	}
}
