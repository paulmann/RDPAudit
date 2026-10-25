/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// File   : DatabasePageIpcTests.cs
// Project: RdpAudit.Configurator.Tests
// Purpose: B17 regression: the Database tab's SUCCESS paths. Before the `IIpcClient` seam existed the page
//          took the concrete `IpcClient`, so every test in this project could only reach the
//          "service unreachable" branch and the rest of the page was verification debt. These tests drive the
//          page through a fake client and assert what an operator would see:
//            - overview (complete and partial), retention policy load/save-with-diff/cancel/no-baseline,
//              dry-run preview, snapshot create/list/verify, the full shard Collect cycle
//              (dry run -> confirmation -> apply), the ledger page + filters + CSV export, the Danger Zone
//              gate, and
//            - the refusals the page owes the operator: a rejected service answer, a cancelled confirmation,
//              an operation attempted with no loaded baseline, a cancelled file picker, a locked Danger Zone.
//          The goal is not "green percentages": it is that the page renders what it received and refuses what
//          it must refuse. Both are asserted on observable state (the status line, the rendered report text
//          and the recorded command/payload sequence), never on internals.
//          The WinForms parts run through StaTestHarness, which owns the STA thread and pumps messages, so
//          the page's `ConfigureAwait(true)` continuations are executed instead of deadlocking the pump.
// Depends: DatabasePage, IIpcClient, StaTestHarness, xunit
// Extends: Add a case here for every new command the Database tab issues, and for every new way it can
//          refuse one.

using System.Runtime.Versioning;
using System.Text.Json.Nodes;
using RdpAudit.Configurator.Forms;
using RdpAudit.Configurator.Ipc;
using RdpAudit.Core.Backup;
using RdpAudit.Core.Ipc;
using RdpAudit.Core.Ipc.Contracts;
using RdpAudit.Core.Models;
using Xunit;

namespace RdpAudit.Configurator.Tests;

[SupportedOSPlatform("windows")]
public sealed class DatabasePageIpcTests
{
	private readonly StaTestHarness _ui = new(nameof(DatabasePageIpcTests));

	// ── Overview ─────────────────────────────────────────────────────────────────

	/// <summary>The success branch the old tests could not reach: a real overview is rendered and the status
	/// says so without an error flag.</summary>
	[Fact]
	public void Overview_WithAService_RendersTheReportAndSaysLoaded()
	{
		_ui.Run(() =>
		{
			FakeIpc ipc = new FakeIpc().On(IpcCommand.GetDatabaseOverview, NewOverview());
			using DatabasePage page = NewPage(ipc);

			_ui.Await(page.RefreshOverviewAsync(), "RefreshOverviewAsync");

			Assert.Equal("Database overview loaded.", StatusBody(page));

			string report = ReportText(page, "evidence store");
			Assert.Contains("C:\\evidence\\rdpaudit.db", report, StringComparison.Ordinal);
			Assert.Contains("RawEvents", report, StringComparison.Ordinal);
			Assert.Contains("[OK ]", report, StringComparison.Ordinal);

			// The page asked for exactly the one command the overview needs.
			Assert.Equal([IpcCommand.GetDatabaseOverview], ipc.Commands());
		});
	}

	/// <summary>A partial snapshot must be reported as partial and as an error-flagged status: it is the
	/// honest state, and it must not read like a complete answer.</summary>
	[Fact]
	public void Overview_PartialSnapshot_IsReportedAsPartial()
	{
		_ui.Run(() =>
		{
			DatabaseOverviewDto partial = NewOverview();
			partial.IsPartial = true;
			partial.Warnings = ["The shard walk was truncated."];
			FakeIpc ipc = new FakeIpc().On(IpcCommand.GetDatabaseOverview, partial);
			using DatabasePage page = NewPage(ipc);

			_ui.Await(page.RefreshOverviewAsync(), "RefreshOverviewAsync");

			Assert.Contains("partial", page.StatusText, StringComparison.OrdinalIgnoreCase);
			Assert.Contains("truncated", ReportText(page, "evidence store"), StringComparison.Ordinal);
		});
	}

	/// <summary>A service-side rejection is surfaced with its own wording, not folded into "unreachable".</summary>
	[Fact]
	public void Overview_WhenTheServiceRejectsIt_SaysUnavailableWithTheServiceError()
	{
		_ui.Run(() =>
		{
			FakeIpc ipc = new FakeIpc().Fail(IpcCommand.GetDatabaseOverview, IpcCallOutcome.ServiceError, "store locked by compaction");
			using DatabasePage page = NewPage(ipc);

			_ui.Await(page.RefreshOverviewAsync(), "RefreshOverviewAsync");

			Assert.Contains("unavailable", page.StatusText, StringComparison.OrdinalIgnoreCase);
			Assert.Contains("store locked by compaction", page.StatusText, StringComparison.Ordinal);
			Assert.Contains("could not be read", ReportText(page, "could not be read"), StringComparison.OrdinalIgnoreCase);
		});
	}

	// ── Retention policy ─────────────────────────────────────────────────────────

	[Fact]
	public void RetentionPolicy_Load_MapsTheServerValuesOntoTheEditor()
	{
		_ui.Run(() =>
		{
			FakeIpc ipc = new FakeIpc().On(IpcCommand.GetRetentionPolicy, NewPolicy());
			using DatabasePage page = NewPage(ipc);

			_ui.Await(page.LoadRetentionAsync(), "LoadRetentionAsync");

			Assert.StartsWith("Retention policy loaded as of", StatusBody(page), StringComparison.Ordinal);
			Assert.Contains("1 per-event override(s)", page.StatusText, StringComparison.Ordinal);

			// The loaded policy is the baseline the save diffs against: captured straight back out of the
			// editor controls, it must match what the service sent.
			RetentionPolicyMutationRequest captured = page.CaptureMutationRequest();
			Assert.Equal(4624, Assert.Single(captured.Policy!.ProtectedEventIds));
		});
	}

	[Fact]
	public void RetentionPolicy_Save_ConfirmsShowsTheDiffAndSendsTheEditedPolicy()
	{
		_ui.Run(() =>
		{
			FakeIpc ipc = new FakeIpc()
				.On(IpcCommand.GetRetentionPolicy, NewPolicy())
				.On(IpcCommand.SaveRetentionPolicy, NewPolicy());
			using DatabasePage page = NewPage(ipc);
			List<(string Message, string Caption)> prompts = [];
			page.ConfirmPrompt = (message, caption) =>
			{
				prompts.Add((message, caption));
				return true;
			};

			_ui.Await(page.LoadRetentionAsync(), "LoadRetentionAsync");

			// Edit one protected code through the control the operator would use; finding it by its exact
			// loaded text keeps the test independent of the control layout.
			TextBox codes = TextBoxWithText(page, "4624");
			codes.Text = "4624, 4625";

			_ui.Await(page.SaveRetentionAsync(), "SaveRetentionAsync");

			(string message, string caption) = Assert.Single(prompts);
			Assert.Equal("Confirm retention policy save", caption);
			Assert.Contains("old → new", message, StringComparison.Ordinal);

			RetentionPolicyMutationRequest sent = Assert.IsType<RetentionPolicyMutationRequest>(
				ipc.PayloadOf(IpcCommand.SaveRetentionPolicy));
			Assert.Equal([4624, 4625], sent.Policy!.ProtectedEventIds);
			Assert.StartsWith("Retention policy saved.", StatusBody(page), StringComparison.Ordinal);
		});
	}

	/// <summary>A cancelled confirmation must leave the store untouched - the whole point of asking.</summary>
	[Fact]
	public void RetentionPolicy_Save_Cancelled_DoesNotSendAnything()
	{
		_ui.Run(() =>
		{
			FakeIpc ipc = new FakeIpc()
				.On(IpcCommand.GetRetentionPolicy, NewPolicy())
				.On(IpcCommand.SaveRetentionPolicy, NewPolicy());
			using DatabasePage page = NewPage(ipc);
			page.ConfirmPrompt = (_, _) => false;

			_ui.Await(page.LoadRetentionAsync(), "LoadRetentionAsync");
			TextBoxWithText(page, "4624").Text = "4624, 4625";
			_ui.Await(page.SaveRetentionAsync(), "SaveRetentionAsync");

			Assert.Equal("Retention policy save cancelled.", StatusBody(page));
			Assert.DoesNotContain(IpcCommand.SaveRetentionPolicy, ipc.Commands());
		});
	}

	/// <summary>With nothing loaded there is no baseline to diff against, and the page says so in the
	/// confirmation instead of presenting an empty diff as "no changes". Cancelling leaves the store
	/// untouched; the important part is that the operator was told what the save would mean.</summary>
	[Fact]
	public void RetentionPolicy_Save_WithoutALoadedBaseline_SaysThereIsNothingToCompareAgainst()
	{
		_ui.Run(() =>
		{
			FakeIpc ipc = new FakeIpc();
			using DatabasePage page = NewPage(ipc);
			string? prompt = null;
			page.ConfirmPrompt = (message, _) =>
			{
				prompt = message;
				return false;
			};

			_ui.Await(page.SaveRetentionAsync(), "SaveRetentionAsync");

			Assert.NotNull(prompt);
			Assert.Contains("no previously loaded policy to compare against", prompt, StringComparison.Ordinal);
			Assert.Equal("Retention policy save cancelled.", StatusBody(page));
			Assert.Empty(ipc.Commands());
		});
	}

	/// <summary>Restoring with no row selected is refused before any file picker opens: the message names
	/// the missing step instead of failing later.</summary>
	[Fact]
	public void RestoreToFolder_WithoutASelection_Refuses()
	{
		_ui.Run(() =>
		{
			FakeIpc ipc = new FakeIpc();
			using DatabasePage page = NewPage(ipc);

			_ui.Await(page.RestoreToFolderAsync(), "RestoreToFolderAsync");

			Assert.Contains("Select a snapshot row", page.StatusText, StringComparison.Ordinal);
			Assert.Empty(ipc.Commands());
		});
	}

	/// <summary>Loading, then saving without touching anything, is reported as "no changes" rather than
	/// sending a no-op write.</summary>
	[Fact]
	public void RetentionPolicy_Save_WithNoEdits_ReportsNoChanges()
	{
		_ui.Run(() =>
		{
			FakeIpc ipc = new FakeIpc().On(IpcCommand.GetRetentionPolicy, NewPolicy());
			using DatabasePage page = NewPage(ipc);

			_ui.Await(page.LoadRetentionAsync(), "LoadRetentionAsync");
			_ui.Await(page.SaveRetentionAsync(), "SaveRetentionAsync");

			Assert.Contains("No changes to save", page.StatusText, StringComparison.Ordinal);
			Assert.DoesNotContain(IpcCommand.SaveRetentionPolicy, ipc.Commands());
		});
	}

	[Fact]
	public void RetentionPreview_RendersTheDryRunAndSaysNothingWasDeleted()
	{
		_ui.Run(() =>
		{
			FakeIpc ipc = new FakeIpc().On(IpcCommand.PreviewRetention, NewPreview());
			using DatabasePage page = NewPage(ipc);

			_ui.Await(page.PreviewRetentionAsync(), "PreviewRetentionAsync");

			Assert.StartsWith("Retention preview as of", StatusBody(page), StringComparison.Ordinal);
			Assert.Contains("42 row(s) would be deleted", page.StatusText, StringComparison.Ordinal);

			// Nothing about a preview may look like a completed deletion.
			Assert.DoesNotContain(IpcCommand.RunDatabaseMaintenance, ipc.Commands());
		});
	}

	// ── Snapshots ────────────────────────────────────────────────────────────────

	[Fact]
	public void CreateBackup_ReportsTheSnapshotAndRefreshesTheList()
	{
		_ui.Run(() =>
		{
			FakeIpc ipc = new FakeIpc()
				.On(IpcCommand.CreateDatabaseBackup, NewCreatedBackup("20260915-120000"))
				.On(IpcCommand.ListDatabaseBackups, NewBackupList());
			using DatabasePage page = NewPage(ipc);

			_ui.Await(page.CreateBackupAsync(), "CreateBackupAsync");

			Assert.StartsWith("Snapshot 20260915-120000 created", StatusBody(page), StringComparison.Ordinal);
			Assert.Contains("20260915-120000", ReportText(page, "Snapshot:"), StringComparison.Ordinal);

			// The list is re-read after a create, so the new snapshot is visible without a manual refresh.
			Assert.Equal(
				[IpcCommand.CreateDatabaseBackup, IpcCommand.ListDatabaseBackups],
				ipc.Commands());
		});
	}

	/// <summary>A creation the service refused is reported as a refusal, and the page does not pretend a
	/// snapshot exists.</summary>
	[Fact]
	public void CreateBackup_WhenTheServiceRefuses_ReportsTheRefusal()
	{
		_ui.Run(() =>
		{
			DatabaseBackupCreationDto refused = NewCreatedBackup("20260915-120000");
			refused.Status = IpcResultStatus.InvalidRequest;
			refused.Message = "The backup directory is not writable.";
			FakeIpc ipc = new FakeIpc().On(IpcCommand.CreateDatabaseBackup, refused);
			using DatabasePage page = NewPage(ipc);

			_ui.Await(page.CreateBackupAsync(), "CreateBackupAsync");

			Assert.Contains("refused", page.StatusText, StringComparison.OrdinalIgnoreCase);
			Assert.Contains("not writable", page.StatusText, StringComparison.Ordinal);
			Assert.Contains("refused", ReportText(page, "snapshot was refused"), StringComparison.OrdinalIgnoreCase);
		});
	}

	[Fact]
	public void ListBackups_ShowsTheEntriesAndTheEffectiveSettings()
	{
		_ui.Run(() =>
		{
			FakeIpc ipc = new FakeIpc().On(IpcCommand.ListDatabaseBackups, NewBackupList());
			using DatabasePage page = NewPage(ipc);

			_ui.Await(page.LoadBackupsAsync(), "LoadBackupsAsync");

			Assert.Contains("Snapshot list loaded as of", page.StatusText, StringComparison.Ordinal);
			Assert.Contains("2 snapshot(s)", page.StatusText, StringComparison.Ordinal);
			Assert.Contains("preMigration=True", page.StatusText, StringComparison.Ordinal);
		});
	}

	[Fact]
	public void VerifyBackup_WithoutASelection_AsksForTheNewestAndRendersTheVerdict()
	{
		_ui.Run(() =>
		{
			FakeIpc ipc = new FakeIpc().On(IpcCommand.ListDatabaseBackups, NewBackupList());
			ipc.On(IpcCommand.VerifyDatabaseBackup, _ => NewVerification(usable: true));
			using DatabasePage page = NewPage(ipc);

			_ui.Await(page.LoadBackupsAsync(), "LoadBackupsAsync");
			_ui.Await(page.VerifySelectedBackupAsync(), "VerifySelectedBackupAsync");

			VerifyDatabaseBackupRequest request = Assert.IsType<VerifyDatabaseBackupRequest>(
				ipc.PayloadOf(IpcCommand.VerifyDatabaseBackup));

			// No selection means "the newest", which the page expresses as a null name rather than by
			// guessing a directory name.
			Assert.Null(request.Name);
			Assert.Contains("usable=True", page.StatusText, StringComparison.Ordinal);
			Assert.Contains("Actual hash:", ReportText(page, "snapshot verification"), StringComparison.Ordinal);
		});
	}

	/// <summary>Selecting a row narrows the verification to that snapshot. The page has to be hosted in a
	/// form for the bound grid to materialize its rows at all - a data-bound DataGridView without a
	/// BindingContext has no rows to select, which is why the other tests in this class can assert the
	/// "newest" path without one.</summary>
	[Fact]
	public void VerifyBackup_WithASelectedRow_SendsTheSelectedSnapshotName()
	{
		_ui.Run(() =>
		{
			FakeIpc ipc = new FakeIpc().On(IpcCommand.ListDatabaseBackups, NewBackupList());
			ipc.On(IpcCommand.VerifyDatabaseBackup, _ => NewVerification(usable: true));
			using DatabasePage page = NewPage(ipc);

			_ui.Await(page.LoadBackupsAsync(), "LoadBackupsAsync");

			// A data-bound DataGridView keeps its rows behind a BindingContext and does not build one in a
			// headless host (no form is ever shown). Giving the grid its own context is what makes the bound
			// rows real, so the selection below is the same one the operator's click produces.
			DataGridView grid = SnapshotGrid(page);
			grid.BindingContext = new BindingContext();
			Assert.True(grid.Rows.Count >= 2, "The snapshot grid must list the two canned snapshots.");

			grid.Rows[0].Selected = true;
			grid.CurrentCell = grid.Rows[0].Cells[0];

			_ui.Await(page.VerifySelectedBackupAsync(), "VerifySelectedBackupAsync");

			VerifyDatabaseBackupRequest request = Assert.IsType<VerifyDatabaseBackupRequest>(
				ipc.PayloadOf(IpcCommand.VerifyDatabaseBackup));
			Assert.Equal("20260915-120000", request.Name);
		});
	}

	/// <summary>An unusable snapshot must be reported as an error, not as a successful verification.</summary>
	[Fact]
	public void VerifyBackup_WhenTheSnapshotIsUnusable_ReportsAnError()
	{
		_ui.Run(() =>
		{
			FakeIpc ipc = new FakeIpc().On(IpcCommand.ListDatabaseBackups, NewBackupList());
			ipc.On(IpcCommand.VerifyDatabaseBackup, _ => NewVerification(usable: false));
			using DatabasePage page = NewPage(ipc);

			_ui.Await(page.LoadBackupsAsync(), "LoadBackupsAsync");
			_ui.Await(page.VerifySelectedBackupAsync(), "VerifySelectedBackupAsync");

			Assert.Contains("usable=False", page.StatusText, StringComparison.Ordinal);
			Assert.Contains(nameof(DatabaseSnapshotVerdict.HashMismatch), ReportText(page, "snapshot verification"), StringComparison.Ordinal);
		});
	}

	// ── Shard Collect: dry run -> confirmation -> apply ───────────────────────────

	/// <summary>The flow B17 named as unreachable: the eligible-candidate dry run, the confirmation, then the
	/// applying pass. The assertion is on the exact request sequence the page produced.</summary>
	[Fact]
	public void CollectShards_DryRunThenConfirmationThenApply()
	{
		_ui.Run(() =>
		{
			FakeIpc ipc = new FakeIpc().On(IpcCommand.GetShardInventory, NewInventory());
			ipc.On(IpcCommand.CollectShardGarbage, payload =>
			{
				bool dryRun = Assert.IsType<CollectShardGarbageRequest>(payload).DryRun;
				return dryRun ? NewCollectionReport(dryRun: true) : NewCollectionReport(dryRun: false);
			});

			using DatabasePage page = NewPage(ipc);
			List<string> prompts = [];
			page.ConfirmPrompt = (message, caption) =>
			{
				prompts.Add(caption + "|" + message);
				return true;
			};

			_ui.Await(page.CollectShardGarbageAsync(), "CollectShardGarbageAsync");

			// Exactly one confirmation, and it showed the candidate it was about to delete.
			string prompt = Assert.Single(prompts);
			Assert.Contains("Confirm orphan shard collection", prompt, StringComparison.Ordinal);
			Assert.Contains("shards/aa/aaaa.shard", prompt, StringComparison.Ordinal);
			Assert.Contains("grace period", prompt, StringComparison.OrdinalIgnoreCase);

			// Dry run first, apply second - never the other way round, and never apply without the dry run.
			List<bool> dryRuns = ipc.PayloadsOf(IpcCommand.CollectShardGarbage)
				.Select(payload => Assert.IsType<CollectShardGarbageRequest>(payload).DryRun)
				.ToList();
			Assert.Equal([true, false], dryRuns);
		});
	}

	/// <summary>A cancelled confirmation must stop after the dry run: the eligible files stay on disk and the
	/// status says so with the count.</summary>
	[Fact]
	public void CollectShards_CancelledAfterTheDryRun_DoesNotApply()
	{
		_ui.Run(() =>
		{
			FakeIpc ipc = new FakeIpc().On(IpcCommand.GetShardInventory, NewInventory());
			ipc.On(IpcCommand.CollectShardGarbage, _ => NewCollectionReport(dryRun: true));
			using DatabasePage page = NewPage(ipc);
			page.ConfirmPrompt = (_, _) => false;

			_ui.Await(page.CollectShardGarbageAsync(), "CollectShardGarbageAsync");

			List<bool> dryRuns = ipc.PayloadsOf(IpcCommand.CollectShardGarbage)
				.Select(payload => Assert.IsType<CollectShardGarbageRequest>(payload).DryRun)
				.ToList();
			Assert.Equal([true], dryRuns);
			Assert.DoesNotContain(IpcCommand.CollectShardGarbage, ipc.Commands().Skip(1));
		});
	}

	/// <summary>With nothing eligible there is nothing to confirm: the page reports the dry run and does not
	/// ask, which is what stops a "confirm?" dialog from becoming a reflex click.</summary>
	[Fact]
	public void CollectShards_WithoutEligibleCandidates_DoesNotAskAndDeletesNothing()
	{
		_ui.Run(() =>
		{
			ShardGarbageCollectionReportDto report = NewCollectionReport(dryRun: true);
			report.Candidates[0].Disposition = ShardGarbageDisposition.YoungerThanGracePeriod;
			FakeIpc ipc = new FakeIpc().On(IpcCommand.CollectShardGarbage, report);
			using DatabasePage page = NewPage(ipc);

			int prompts = 0;
			page.ConfirmPrompt = (_, _) =>
			{
				prompts++;
				return true;
			};

			_ui.Await(page.CollectShardGarbageAsync(), "CollectShardGarbageAsync");

			Assert.Equal(0, prompts);
			Assert.Single(ipc.PayloadsOf(IpcCommand.CollectShardGarbage));
			Assert.Contains("none eligible", page.StatusText, StringComparison.Ordinal);
		});
	}

	// ── Ledger ───────────────────────────────────────────────────────────────────

	[Fact]
	public void Ledger_LoadPage_SendsTheFiltersAndReportsTheRange()
	{
		_ui.Run(() =>
		{
			FakeIpc ipc = new FakeIpc().On(IpcCommand.GetDeletionLedger, NewLedgerPage());
			using DatabasePage page = NewPage(ipc);

			_ui.Await(page.LoadLedgerAsync(resetPage: true), "LoadLedgerAsync");

			DeletionLedgerQueryRequest request = Assert.IsType<DeletionLedgerQueryRequest>(
				ipc.PayloadOf(IpcCommand.GetDeletionLedger));
			Assert.Equal(0, request.Page);
			Assert.True(request.PageSize > 0);

			Assert.StartsWith("Ledger as of", StatusBody(page), StringComparison.Ordinal);
			Assert.Contains("showing 1-2 of 2 (page 1)", page.StatusText, StringComparison.Ordinal);
		});
	}

	/// <summary>A service-side ledger refusal is distinct from a transport failure and is reported as such.</summary>
	[Fact]
	public void Ledger_WhenTheServiceRefusesTheQuery_ReportsIt()
	{
		_ui.Run(() =>
		{
			DeletionLedgerPageDto refused = NewLedgerPage();
			refused.Status = IpcResultStatus.InvalidRequest;
			refused.Message = "The page size exceeds the server limit.";
			FakeIpc ipc = new FakeIpc().On(IpcCommand.GetDeletionLedger, refused);
			using DatabasePage page = NewPage(ipc);

			_ui.Await(page.LoadLedgerAsync(resetPage: true), "LoadLedgerAsync");

			Assert.Contains("failed", page.StatusText, StringComparison.OrdinalIgnoreCase);
			Assert.Contains("server limit", page.StatusText, StringComparison.Ordinal);
		});
	}

	/// <summary>The export walks the paged command and writes exactly what the CSV builder produced.</summary>
	[Fact]
	public void LedgerExport_PagesThroughTheDispatcherAndWritesTheFile()
	{
		string target = Path.Combine(Path.GetTempPath(), "rdpaudit-ledger-" + Guid.NewGuid().ToString("N") + ".csv");
		try
		{
			_ui.Run(() =>
			{
				FakeIpc ipc = new FakeIpc().On(IpcCommand.GetDeletionLedger, NewLedgerPage());
				using DatabasePage page = NewPage(ipc);
				page.ChooseLedgerExportPath = () => target;

				_ui.Await(page.ExportLedgerCsvAsync(), "ExportLedgerCsvAsync");

				Assert.Contains("Ledger exported: 2 row(s)", page.StatusText, StringComparison.Ordinal);
				Assert.True(File.Exists(target));
				string csv = File.ReadAllText(target);
				Assert.Contains("CreatedUtc", csv, StringComparison.Ordinal);
				Assert.StartsWith(DatabasePage.BuildLedgerCsv(NewLedgerPage().Items, truncated: false), csv, StringComparison.Ordinal);
			});
		}
		finally
		{
			if (File.Exists(target))
			{
				File.Delete(target);
			}
		}
	}

	/// <summary>A cancelled file picker must write nothing at all - not an empty file, and not a partial
	/// one.</summary>
	[Fact]
	public void LedgerExport_Cancelled_WritesNothing()
	{
		string target = Path.Combine(Path.GetTempPath(), "rdpaudit-ledger-cancelled-" + Guid.NewGuid().ToString("N") + ".csv");
		_ui.Run(() =>
		{
			FakeIpc ipc = new FakeIpc().On(IpcCommand.GetDeletionLedger, NewLedgerPage());
			using DatabasePage page = NewPage(ipc);
			page.ChooseLedgerExportPath = () => null;

			_ui.Await(page.ExportLedgerCsvAsync(), "ExportLedgerCsvAsync");

			Assert.Equal("Ledger export cancelled.", StatusBody(page));
			Assert.False(File.Exists(target));
		});
	}

	// ── Danger Zone ──────────────────────────────────────────────────────────────

	/// <summary>The gate is two conditions, and neither alone unlocks it. Asserted through the page's own
	/// gate renderer, so the requirement is pinned independently of the host's token.</summary>
	[Fact]
	public void DangerZone_GateRequiresBothDebugModeAndElevation()
	{
		_ui.Run(() =>
		{
			using DatabasePage page = NewPage(new FakeIpc());

			page.ApplyDangerZoneGate(debugMode: false, elevated: true);
			Assert.False(page.DangerZoneUnlocked);
			Assert.Contains("DEBUG", page.DangerZoneGateText, StringComparison.OrdinalIgnoreCase);

			page.ApplyDangerZoneGate(debugMode: true, elevated: false);
			Assert.False(page.DangerZoneUnlocked);
			Assert.Contains("elevat", page.DangerZoneGateText, StringComparison.OrdinalIgnoreCase);

			page.ApplyDangerZoneGate(debugMode: true, elevated: true);
			Assert.True(page.DangerZoneUnlocked);
		});
	}

	/// <summary>With DEBUG mode off the purge is refused before anything else happens: no confirmation, no
	/// dialog, no command. The page must not open a surface the operator cannot complete.</summary>
	[Fact]
	public void DangerZone_WhenDebugModeIsOff_RefusesWithoutOpeningTheDialog()
	{
		_ui.Run(() =>
		{
			FakeIpc ipc = new FakeIpc().On(IpcCommand.GetSettings, JsonNode.Parse("{\"Diagnostics\":{\"DebugMode\":false}}")!);
			using DatabasePage page = NewPage(ipc);
			bool dialogOpened = false;
			page.NewPurgeDialog = () =>
			{
				dialogOpened = true;
				throw new InvalidOperationException("the purge dialog must not open while the gate is locked");
			};
			page.ConfirmPrompt = (_, _) => throw new InvalidOperationException("no confirmation while the gate is locked");

			_ui.Await(page.PurgeBySubjectAsync(), "PurgeBySubjectAsync");

			Assert.False(dialogOpened);
			Assert.Contains("refused", page.StatusText, StringComparison.OrdinalIgnoreCase);
			Assert.Contains("DEBUG mode is off", page.StatusText, StringComparison.Ordinal);
			Assert.DoesNotContain(IpcCommand.PurgeBySubject, ipc.Commands());
		});
	}

	/// <summary>And it fails closed: a service that cannot report its DEBUG state leaves the gate locked
	/// rather than open.</summary>
	[Fact]
	public void DangerZone_WhenTheSettingsCannotBeRead_LocksTheGate()
	{
		_ui.Run(() =>
		{
			FakeIpc ipc = new FakeIpc().Fail(IpcCommand.GetSettings, IpcCallOutcome.ConnectFailed, "pipe connect failed");
			using DatabasePage page = NewPage(ipc);

			_ui.Await(page.RefreshDangerZoneGateAsync(), "RefreshDangerZoneGateAsync");

			Assert.False(page.DangerZoneUnlocked);
		});
	}

	// ── Harness ──────────────────────────────────────────────────────────────────

	private static DatabasePage NewPage(IIpcClient ipc) => new(ipc);

	/// <summary>The status line without the "[HH:MM:SSZ] " prefix the page stamps onto every message, so a
	/// test can assert the sentence rather than the clock.</summary>
	private static string StatusBody(DatabasePage page)
	{
		string text = page.StatusText;
		int end = text.IndexOf("] ", StringComparison.Ordinal);
		return text.StartsWith('[') && end > 0 ? text[(end + 2)..] : text;
	}

	/// <summary>Text of the first monospace report on the page that contains <paramref name="marker"/>. The
	/// pages' reports are plain TextBoxes, so this reads exactly what the operator would.</summary>
	private static string ReportText(DatabasePage page, string marker)
	{
		TextBox match = AllControls(page)
			.OfType<TextBox>()
			.FirstOrDefault(box => box.Text.Contains(marker, StringComparison.Ordinal))
			?? throw new InvalidOperationException(
				"No report containing \"" + marker + "\" was rendered. Rendered text: "
				+ string.Join(" / ", AllControls(page).OfType<TextBox>().Select(box => box.Text.Length > 60 ? box.Text[..60] : box.Text)));
		return match.Text;
	}

	private static TextBox TextBoxWithText(DatabasePage page, string text)
		=> AllControls(page).OfType<TextBox>().FirstOrDefault(box => string.Equals(box.Text, text, StringComparison.Ordinal))
			?? throw new InvalidOperationException("No text box holds \"" + text + "\".");

	/// <summary>The snapshot grid, identified by the bound property of its first column - a stable marker,
	/// unlike a header caption the page is free to reword.</summary>
	private static DataGridView SnapshotGrid(DatabasePage page)
		=> AllControls(page).OfType<DataGridView>()
			.FirstOrDefault(grid => grid.Columns.Count > 0
				&& string.Equals(grid.Columns[0].DataPropertyName, "CreatedUtcText", StringComparison.Ordinal))
			?? throw new InvalidOperationException("The snapshot grid was not found on the Database tab.");

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

	// ── Canned answers ───────────────────────────────────────────────────────────

	private static DatabaseOverviewDto NewOverview() => new()
	{
		Status = IpcResultStatus.Success,
		QueriedUtc = new DateTime(2026, 9, 15, 8, 0, 0, DateTimeKind.Utc),
		DatabasePath = "C:\\evidence\\rdpaudit.db",
		DatabaseBytes = 1_048_576,
		WalBytes = 4096,
		ShmBytes = 32_768,
		TotalDatabaseFamilyBytes = 1_085_440,
		DatabaseVolumeRoot = "C:\\",
		DatabaseVolumeFreeBytes = 10_000_000_000,
		DatabaseVolumeTotalBytes = 100_000_000_000,
		ActionsVolumeRoot = "C:\\",
		ActionsVolumeFreeBytes = 10_000_000_000,
		ActionsVolumeTotalBytes = 100_000_000_000,
		ActionsRoot = "C:\\evidence\\actions",
		ActionsBytes = 2048,
		ActionsFileCount = 3,
		TableRowCounts = [new DatabaseTableRowCountDto { Table = "RawEvents", RowCount = 1234 }],
		GrowthBytesDay = 1024,
		AppliedMigrations = ["20260504215120_InitialCreate"],
		PendingMigrations = [],
		Sections = [new DatabaseOverviewSectionDto { Section = "DbFiles", Status = "Completed", DurationMs = 12 }],
		Warnings = [],
		Message = "ok",
		LedgerChainIntact = true,
		StorageAclCompliant = true,
		EncryptionMode = "None",
		FingerprintChainState = "ok",
		FingerprintChainEntryCount = 2,
		FingerprintChainMessage = "The store-fingerprint chain verifies: 2 entr(ies).",
	};

	private static RetentionPolicyDto NewPolicy() => new()
	{
		Status = IpcResultStatus.Success,
		QueriedUtc = new DateTime(2026, 9, 15, 8, 0, 0, DateTimeKind.Utc),
		ConfigPath = "C:\\evidence\\appsettings.json",
		Policy = new RetentionPolicyValuesDto
		{
			Enabled = true,
			ProtectedEventIds = [4624],
			EffectiveProtectedEventIds = [4624],
			TailKeepPerCode = 100,
			EffectiveTailKeepPerCode = 100,
			CandidateMinRows = 500,
			EffectiveCandidateMinRows = 500,
			MinAgeDays = 30,
			EffectiveMinAgeDays = 30,
			MaxRowsPerPass = 2000,
			EffectiveMaxRowsPerPass = 2000,
			MaxWriterLockMs = 250,
			EffectiveMaxWriterLockMs = 250,
			DeleteBatchRows = 1000,
			EffectiveDeleteBatchRows = 1000,
		},
		GlobalWindows = new RetentionWindowsDto
		{
			EventRetentionDays = 90,
			AlertRetentionDays = 365,
			AbuseReportRetentionDays = 365,
			ActiveBlockRetentionDays = 30,
			AttackStatRetentionDays = 400,
			SessionIpCorrelationRetentionDays = 90,
			RdpConnectionFactRetentionDays = 180,
			LogRetentionDays = 30,
		},
		EventWindows = [new EventRetentionWindowDto { EventId = 4625, RetentionDays = 30 }],
		Message = "ok",
	};

	private static RetentionPreviewDto NewPreview() => new()
	{
		Status = IpcResultStatus.Success,
		QueriedUtc = new DateTime(2026, 9, 15, 8, 0, 0, DateTimeKind.Utc),
		PolicyEnabled = true,
		Trigger = EventDeletionTrigger.RawEventRows,
		TriggerWouldFire = true,
		WouldDeleteRows = 42,
		EstimatedReclaimedBytes = 8192,
		RuleVersion = 3,
		MinAgeCutoffUtc = new DateTime(2026, 8, 16, 0, 0, 0, DateTimeKind.Utc),
		TailKeepPerCode = 100,
		MaxRowsPerPass = 2000,
		Codes = [],
		Steps = [],
		Message = "dry run",
	};

	private static DatabaseBackupCreationDto NewCreatedBackup(string name) => new()
	{
		Status = IpcResultStatus.Success,
		QueriedUtc = new DateTime(2026, 9, 15, 12, 0, 0, DateTimeKind.Utc),
		SnapshotName = name,
		SnapshotDirectory = "C:\\evidence\\Backups\\" + name,
		DatabasePath = "C:\\evidence\\rdpaudit.db",
		DatabaseBytes = 1_048_576,
		DatabaseSha256 = new string('a', 64),
		Kind = "Manual",
		DurationMs = 250,
		SnapshotCountBefore = 1,
		SnapshotCountAfter = 2,
		Message = "ok",
	};

	private static DatabaseBackupListDto NewBackupList() => new()
	{
		Status = IpcResultStatus.Success,
		QueriedUtc = new DateTime(2026, 9, 15, 12, 0, 0, DateTimeKind.Utc),
		BackupDirectory = "C:\\evidence\\Backups",
		Enabled = true,
		PreMigrationBackupEnabled = true,
		RetentionCopies = 5,
		TotalCount = 2,
		Entries =
		[
			new DatabaseBackupEntryDto { Name = "20260915-120000", Directory = "C:\\evidence\\Backups\\20260915-120000", CreatedUtc = new DateTime(2026, 9, 15, 12, 0, 0, DateTimeKind.Utc), DatabaseBytes = 1_048_576, ManifestValid = true, Kind = "Manual" },
			new DatabaseBackupEntryDto { Name = "20260914-120000", Directory = "C:\\evidence\\Backups\\20260914-120000", CreatedUtc = new DateTime(2026, 9, 14, 12, 0, 0, DateTimeKind.Utc), DatabaseBytes = 1_040_000, ManifestValid = true, Kind = "PreMigration" },
		],
		Message = "ok",
	};

	private static DatabaseBackupVerificationDto NewVerification(bool usable) => new()
	{
		Status = IpcResultStatus.Success,
		QueriedUtc = new DateTime(2026, 9, 15, 12, 5, 0, DateTimeKind.Utc),
		SnapshotName = "20260915-120000",
		SnapshotDirectory = "C:\\evidence\\Backups\\20260915-120000",
		Verdict = usable ? DatabaseSnapshotVerdict.Ok : DatabaseSnapshotVerdict.HashMismatch,
		VerdictName = usable ? nameof(DatabaseSnapshotVerdict.Ok) : nameof(DatabaseSnapshotVerdict.HashMismatch),
		IsUsable = usable,
		ExpectedSha256 = new string('a', 64),
		ActualSha256 = usable ? new string('a', 64) : new string('b', 64),
		QuickCheckResult = usable ? "ok" : "ok",
		SchemaVerdict = SchemaCompatibilityVerdict.Compatible,
		SchemaMessage = "Schema matches this build.",
		Message = usable ? "verified" : "checksum mismatch",
	};

	private static ShardInventoryDto NewInventory() => new()
	{
		Status = IpcResultStatus.Success,
		QueriedUtc = new DateTime(2026, 9, 15, 12, 0, 0, DateTimeKind.Utc),
		ActionsRoot = "C:\\evidence\\actions",
		ShardingEnabled = true,
		Entries = [],
		Summary = new ShardInventorySummaryDto(),
		Warnings = [],
		Message = "ok",
	};

	private static ShardGarbageCollectionReportDto NewCollectionReport(bool dryRun) => new()
	{
		Status = IpcResultStatus.Success,
		QueriedUtc = new DateTime(2026, 9, 15, 12, 0, 0, DateTimeKind.Utc),
		DryRun = dryRun,
		ActionsRoot = "C:\\evidence\\actions",
		OrphanGraceDays = 7,
		Candidates =
		[
			new ShardGarbageCandidateDto
			{
				RelativePath = "shards/aa/aaaa.shard",
				AbsolutePath = "C:\\evidence\\actions\\shards\\aa\\aaaa.shard",
				IpText = "10.0.0.1",
				Bytes = 4096,
				Records = 5,
				AgeDays = 30,
				Disposition = dryRun ? ShardGarbageDisposition.Eligible : ShardGarbageDisposition.DeletionBudgetSpent,
			},
		],
		DeletedFileCount = dryRun ? 0 : 1,
		DeletedBytes = dryRun ? 0 : 4096,
		DeletedRecords = dryRun ? 0 : 5,
		Message = dryRun ? "dry run" : "collected",
	};

	private static DeletionLedgerPageDto NewLedgerPage() => new()
	{
		Status = IpcResultStatus.Success,
		QueriedUtc = new DateTime(2026, 9, 15, 12, 0, 0, DateTimeKind.Utc),
		TotalMatching = 2,
		Page = 0,
		PageSize = 200,
		HasMore = false,
		Items =
		[
			new DeletionLedgerEntryDto { Id = 1, EventCode = 4625, Scope = EventDeletionScope.Global, RowsDeleted = 100, Trigger = EventDeletionTrigger.RawEventRows, RuleVersion = 3, Reason = "pressure", InitiatedBy = "Service", CreatedUtc = new DateTime(2026, 9, 15, 11, 0, 0, DateTimeKind.Utc), WindowStartUtc = new DateTime(2026, 8, 1, 0, 0, 0, DateTimeKind.Utc), WindowEndUtc = new DateTime(2026, 9, 1, 0, 0, 0, DateTimeKind.Utc) },
			new DeletionLedgerEntryDto { Id = 2, EventCode = 4624, Scope = EventDeletionScope.Global, RowsDeleted = 50, Trigger = EventDeletionTrigger.AgeWindow, RuleVersion = 3, Reason = "age", InitiatedBy = "Service", CreatedUtc = new DateTime(2026, 9, 15, 10, 0, 0, DateTimeKind.Utc), WindowStartUtc = new DateTime(2026, 7, 1, 0, 0, 0, DateTimeKind.Utc), WindowEndUtc = new DateTime(2026, 8, 1, 0, 0, 0, DateTimeKind.Utc) },
		],
		Message = "ok",
	};

	/// <summary>Records every command and payload the page sends, and answers from a canned table. A command
	/// with no canned answer fails as "service unreachable", which is how a missing fake surfaces instead of
	/// silently returning an empty success.</summary>
	private sealed class FakeIpc : IIpcClient
	{
		private readonly Dictionary<IpcCommand, Func<object?, object?>> _handlers = new();
		private readonly Dictionary<IpcCommand, (IpcCallOutcome Outcome, string? Error)> _failures = new();
		private readonly List<(IpcCommand Command, object? Payload)> _calls = new();

		public FakeIpc On<T>(IpcCommand command, T value)
			where T : class
			=> On(command, _ => value);

		public FakeIpc On<T>(IpcCommand command, Func<object?, T> handler)
			where T : class
		{
			_handlers[command] = payload => handler(payload);
			return this;
		}

		public FakeIpc Fail(IpcCommand command, IpcCallOutcome outcome, string? error)
		{
			_failures[command] = (outcome, error);
			return this;
		}

		public Task<IpcCallResult<T>> SendDetailedAsync<T>(IpcCommand command, object? payload = null, CancellationToken ct = default)
		{
			_calls.Add((command, payload));

			if (_failures.TryGetValue(command, out (IpcCallOutcome Outcome, string? Error) failure))
			{
				return Task.FromResult(Result<T>(command, failure.Outcome, default, failure.Error));
			}

			if (_handlers.TryGetValue(command, out Func<object?, object?>? handler))
			{
				object? value = handler(payload);
				return value is T typed
					? Task.FromResult(Result<T>(command, IpcCallOutcome.Success, typed, null))
					: Task.FromResult(Result<T>(command, IpcCallOutcome.SuccessNoPayload, default, null));
			}

			return Task.FromResult(Result<T>(command, IpcCallOutcome.ConnectFailed, default, "no canned answer for " + command));
		}

		public List<IpcCommand> Commands() => _calls.Select(call => call.Command).ToList();

		public object? PayloadOf(IpcCommand command) =>
			_calls.Last(call => call.Command == command).Payload;

		public List<object?> PayloadsOf(IpcCommand command) =>
			_calls.Where(call => call.Command == command).Select(call => call.Payload).ToList();

		private static IpcCallResult<T> Result<T>(IpcCommand command, IpcCallOutcome outcome, T? value, string? error)
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
