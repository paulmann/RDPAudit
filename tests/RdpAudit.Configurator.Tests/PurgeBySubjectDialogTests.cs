/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 1.0.0
// File   : PurgeBySubjectDialogTests.cs
// Project: RdpAudit.Configurator.Tests
// Purpose: Verifies the UI half of the subject purge (Requirement R14/§D): the dialog cannot be made to skip
//          its two mandatory steps. A purge stays impossible until (1) a dry run has succeeded and (2) the
//          exact phrase has been typed; the preview renders the per-table counts and the preserved list; and
//          the applied report is rendered verbatim, so the UI cannot overstate what happened.
//          The IPC call hooks are replaced, so the flow is exercised without a service - which is also how the
//          "no answer" path is covered: an unanswered call must present as "nothing was deleted", never as an
//          empty success.
// Depends: PurgeBySubjectDialog, StaTestHarness, xUnit
// Extends: Add a case here whenever the dialog gains a field that changes what can be purged.

using System.Runtime.Versioning;
using RdpAudit.Configurator.Forms;
using RdpAudit.Configurator.Ipc;
using RdpAudit.Core.Ipc.Contracts;
using Xunit;

namespace RdpAudit.Configurator.Tests;

[SupportedOSPlatform("windows")]
public sealed class PurgeBySubjectDialogTests
{
	private readonly StaTestHarness _ui = new(nameof(PurgeBySubjectDialogTests));

	/// <summary>Builds a report shaped like the server's dry run.</summary>
	private static PurgeBySubjectReportDto DryRunReport(long matched = 42) => new()
	{
		Status = IpcResultStatus.Success,
		QueriedUtc = DateTime.UtcNow,
		DryRun = true,
		Applied = false,
		Kind = PurgeSubjectKind.Ip,
		Subject = "203.0.113.7",
		Tables =
		[
			new PurgeBySubjectTableDto { Table = "Alerts", RowsMatched = 2 },
			new PurgeBySubjectTableDto { Table = "RawEvents", RowsMatched = matched },
		],
		TotalRowsMatched = matched + 2,
		Preserved = ["Schema and __EFMigrationsHistory", "BlocklistEntries, WhitelistEntries and LoginRules"],
		Message = "DRY RUN: nothing was deleted.",
	};

	/// <summary>Given the dialog is opened, when the purge button is inspected, then it is disabled even with
	/// the subject filled in - the dry run has not run yet.</summary>
	[Fact]
	public void Purge_IsDisabledUntilAPreviewSucceeded()
	{
		_ui.Run(() =>
		{
			using PurgeBySubjectDialog dialog = new(new IpcClient());
			dialog.SelectSubject(PurgeSubjectKind.Ip, "203.0.113.7");

			Assert.False(dialog.CanPurge);

			dialog.TypePhrase(PurgeBySubjectDialog.ConfirmationPhrase);
			Assert.False(dialog.CanPurge);
		});
	}

	/// <summary>Given a successful dry run, when the phrase is still missing, then the purge stays disabled;
	/// typing the exact phrase enables it; and any deviation disables it again.</summary>
	[Fact]
	public void Purge_NeedsBothADryRunAndTheExactPhrase()
	{
		_ui.Run(() =>
		{
			using PurgeBySubjectDialog dialog = new(new IpcClient());
			dialog.PreviewAsync = _ => Task.FromResult<PurgeBySubjectReportDto?>(DryRunReport());
			dialog.ApplyAsync = _ => Task.FromResult<PurgeBySubjectReportDto?>(null);
			dialog.SelectSubject(PurgeSubjectKind.Ip, "203.0.113.7");

			_ui.Await(dialog.RunPreviewAsync(), "RunPreviewAsync");
			Assert.False(dialog.CanPurge);

			dialog.TypePhrase("purge subject data");
			Assert.False(dialog.CanPurge);

			dialog.TypePhrase(PurgeBySubjectDialog.ConfirmationPhrase);
			Assert.True(dialog.CanPurge);

			dialog.TypePhrase(PurgeBySubjectDialog.ConfirmationPhrase + " ");
			Assert.False(dialog.CanPurge);
		});
	}

	/// <summary>Given a dry run, when it is rendered, then the per-table counts, the totals and the preserved
	/// list are all shown, and the request that produced it carried Apply=false so the server could not have
	/// deleted anything even if the UI were wrong.</summary>
	[Fact]
	public void Preview_RendersTheCountsAndThePreservedList_AndNeverAsksToApply()
	{
		_ui.Run(() =>
		{
			using PurgeBySubjectDialog dialog = new(new IpcClient());
			PurgeBySubjectRequest? seen = null;
			dialog.PreviewAsync = request =>
			{
				seen = request;
				return Task.FromResult<PurgeBySubjectReportDto?>(DryRunReport());
			};
			dialog.ApplyAsync = _ => Task.FromResult<PurgeBySubjectReportDto?>(null);
			dialog.SelectSubject(PurgeSubjectKind.Ip, "203.0.113.7");

			_ui.Await(dialog.RunPreviewAsync(), "RunPreviewAsync");

			Assert.NotNull(seen);
			Assert.False(seen!.Apply);
			Assert.Null(seen.ConfirmationPhrase);
			Assert.Equal(PurgeSubjectKind.Ip, seen.Kind);
			Assert.Equal("203.0.113.7", seen.Value);

			// The per-table counts land in the grid...
			Assert.Equal(new[] { "Alerts", "RawEvents" }, dialog.RenderedTables);

			// ...and the summary carries the totals and the preserved list verbatim.
			string rendered = dialog.LastOutcomeSummary ?? string.Empty;
			Assert.Contains("44", rendered, StringComparison.Ordinal);
			Assert.Contains("Preserved (never touched by this action)", rendered, StringComparison.Ordinal);
			Assert.Contains("BlocklistEntries", rendered, StringComparison.Ordinal);
			Assert.Contains("DRY RUN", rendered, StringComparison.Ordinal);
		});
	}

	/// <summary>Given an apply pass, when it is run, then the request carried Apply=true with the phrase - and
	/// the applied report replaces the dry-run one.</summary>
	[Fact]
	public void Apply_SendsThePhraseAndRendersTheAppliedReport()
	{
		_ui.Run(() =>
		{
			using PurgeBySubjectDialog dialog = new(new IpcClient());
			dialog.PreviewAsync = _ => Task.FromResult<PurgeBySubjectReportDto?>(DryRunReport());
			PurgeBySubjectRequest? applied = null;
			dialog.ApplyAsync = request =>
			{
				applied = request;
				return Task.FromResult<PurgeBySubjectReportDto?>(new PurgeBySubjectReportDto
				{
					Status = IpcResultStatus.Success,
					QueriedUtc = DateTime.UtcNow,
					DryRun = false,
					Applied = true,
					Kind = PurgeSubjectKind.Ip,
					Subject = "203.0.113.7",
					Tables = [new PurgeBySubjectTableDto { Table = "RawEvents", RowsMatched = 44, RowsDeleted = 44, LedgerWritten = true }],
					TotalRowsMatched = 44,
					TotalRowsDeleted = 44,
					LedgerEntriesWritten = 1,
					LedgerChainHead = new string('a', 64),
					Message = "Purged 44 row(s).",
				});
			};

			dialog.SelectSubject(PurgeSubjectKind.Ip, "203.0.113.7");
			_ui.Await(dialog.RunPreviewAsync(), "RunPreviewAsync");
			dialog.TypePhrase(PurgeBySubjectDialog.ConfirmationPhrase);
			Assert.True(dialog.CanPurge);

			_ui.Await(dialog.ApplyOnceAsync(), "ApplyOnceAsync");

			Assert.NotNull(applied);
			Assert.True(applied!.Apply);
			Assert.Equal(PurgeBySubjectDialog.ConfirmationPhrase, applied.ConfirmationPhrase);
			string rendered = dialog.LastOutcomeSummary ?? string.Empty;
			Assert.Contains("Purged 44 row(s).", rendered, StringComparison.Ordinal);
			Assert.Contains("Ledger chain head", rendered, StringComparison.Ordinal);
		});
	}

	/// <summary>Given the service does not answer, when the purge is attempted, then the dialog says nothing
	/// was deleted instead of rendering an empty success.</summary>
	[Fact]
	public void WhenTheServiceDoesNotAnswer_NothingIsReportedAsDeleted()
	{
		_ui.Run(() =>
		{
			using PurgeBySubjectDialog dialog = new(new IpcClient());
			dialog.PreviewAsync = _ => Task.FromResult<PurgeBySubjectReportDto?>(null);
			dialog.ApplyAsync = _ => Task.FromResult<PurgeBySubjectReportDto?>(null);

			_ui.Await(dialog.RunPreviewAsync(), "RunPreviewAsync");

			Assert.False(dialog.CanPurge);
			Assert.Contains(
				"Nothing was deleted",
				dialog.LastOutcomeSummary ?? string.Empty,
				StringComparison.Ordinal);
		});
	}
}
