/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// File   : IisInstallProgressDialogTests.cs
// Project: RdpAudit.Configurator.Tests
// Purpose: Pins the Install IIS progress-window contract: the window lists every plan item BEFORE
//          anything is installed, each item gets a tick or a cross as the run reports it, a failed
//          run offers a bounded retry instead of silently stopping, and a result row that belongs to
//          no plan item is added rather than dropped (fail-visible, never fail-silent). The window
//          owns no installation logic, so every assertion here is about rendering and the operator
//          contract.
// Depends: IisInstallProgressDialog, IisInstallPlan, StaTestHarness, WinForms, xunit

using System;
using System.Runtime.Versioning;
using RdpAudit.Configurator.Forms;
using RdpAudit.Core.WebUi;
using Xunit;

namespace RdpAudit.Configurator.Tests;

[SupportedOSPlatform("windows")]
public sealed class IisInstallProgressDialogTests
{
	[Fact]
	public void GlyphFor_MapsEveryOutcomeToItsMarker()
	{
		Assert.Equal("✓", IisInstallProgressDialog.GlyphFor(IisStepOutcome.Ok));
		Assert.Equal("✗", IisInstallProgressDialog.GlyphFor(IisStepOutcome.Failed));
		Assert.Equal("!", IisInstallProgressDialog.GlyphFor(IisStepOutcome.Warning));
		Assert.Equal("-", IisInstallProgressDialog.GlyphFor(IisStepOutcome.Skipped));

		// Pending and Running both mean "not decided yet" to the operator.
		Assert.Equal("…", IisInstallProgressDialog.GlyphFor(IisStepOutcome.Pending));
		Assert.Equal("…", IisInstallProgressDialog.GlyphFor(IisStepOutcome.Running));
	}

	[Fact]
	public void UnlistedOutcome_StillGetsAMarker()
	{
		Assert.False(string.IsNullOrEmpty(IisInstallProgressDialog.GlyphFor((IisStepOutcome)999)));
	}

	[Fact]
	public void Constructor_ListsTheWholePlanBeforeAnythingRuns()
	{
		StaTestHarness ui = new(nameof(IisInstallProgressDialogTests));
		ui.Run(() =>
		{
			using IisInstallProgressDialog dialog = new();

			Assert.Equal(IisInstallPlan.OrderedStepIds.Count, dialog.Glyphs.Count);
			Assert.All(dialog.Glyphs, glyph => Assert.Equal("…", glyph));
			Assert.True(dialog.IsRunning);
			Assert.False(dialog.IsFinished);
		});
	}

	[Fact]
	public void ApplyResult_PaintsTheMatchingRowAndKeepsThePlanOrder()
	{
		StaTestHarness ui = new(nameof(IisInstallProgressDialogTests));
		ui.Run(() =>
		{
			using IisInstallProgressDialog dialog = new();

			dialog.ApplyResult(new IisInstallStepResult(
				IisInstallStepId.HostingBundle, "ASP.NET Core Module v2", "installed", IisStepOutcome.Ok));
			dialog.ApplyResult(new IisInstallStepResult(
				IisInstallStepId.IisManagementTools, "IIS management tools", "failed", IisStepOutcome.Failed));

			Assert.Equal("✓", dialog.Glyphs[3]);
			Assert.Equal("✗", dialog.Glyphs[2]);
			Assert.Equal("…", dialog.Glyphs[0]);

			// The order is the plan's, so a row can never be shown for a step that does not exist.
			Assert.Equal(IisInstallPlan.OrderedStepIds.Count, dialog.Glyphs.Count);
		});
	}

	[Fact]
	public void ApplyResult_ForAnUnknownRow_AddsItInsteadOfDroppingIt()
	{
		StaTestHarness ui = new(nameof(IisInstallProgressDialogTests));
		ui.Run(() =>
		{
			using IisInstallProgressDialog dialog = new();
			int before = dialog.Glyphs.Count;

			// A row the plan does not know (a future plan item reported by a newer worker) must be
			// visible, not silently discarded.
			dialog.ApplyResult(new IisInstallStepResult(
				(IisInstallStepId)12345, "Unknown component", "detail", IisStepOutcome.Warning));

			Assert.Equal(before + 1, dialog.Glyphs.Count);
		});
	}

	[Fact]
	public void Complete_OnSuccess_ClosesTheResultAndReportsTheSummary()
	{
		StaTestHarness ui = new(nameof(IisInstallProgressDialogTests));
		ui.Run(() =>
		{
			using IisInstallProgressDialog dialog = new();

			dialog.Complete("everything installed.", success: true, alreadyInstalled: false);

			Assert.False(dialog.IsRunning);
			Assert.True(dialog.IsFinished);
			Assert.Equal("everything installed.", dialog.SummaryText);
			Assert.Equal("Close", dialog.CloseButton.Text);
		});
	}

	[Fact]
	public void Complete_AlreadyInstalled_SaysSoInsteadOfRepeatingTheStatusLine()
	{
		StaTestHarness ui = new(nameof(IisInstallProgressDialogTests));
		ui.Run(() =>
		{
			using IisInstallProgressDialog dialog = new();

			dialog.Complete("already present.", success: true, alreadyInstalled: true);

			Assert.Contains("already had every component", dialog.SummaryText, StringComparison.OrdinalIgnoreCase);
		});
	}

	[Fact]
	public void Complete_OnFailure_TurnsTheActionIntoRetryAndAsksTheOwnerOnClick()
	{
		StaTestHarness ui = new(nameof(IisInstallProgressDialogTests));
		ui.Run(() =>
		{
			using IisInstallProgressDialog dialog = new();
			bool retryRequested = false;
			dialog.RetryRequested += (_, _) => retryRequested = true;

			// PerformClick raises Click only when the button can be selected, which requires the owning
			// form to be visible. An unshown dialog swallows the click, so the assertion below would fail
			// for a reason that has nothing to do with the retry contract.
			dialog.Show();

			dialog.Complete("could not be completed: DISM failed.", success: false, alreadyInstalled: false);

			Assert.False(dialog.IsRunning);
			Assert.True(dialog.IsFinished);
			Assert.Equal("Retry", dialog.CloseButton.Text);

			// The window only reports the request; the owner decides what to do with it.
			Assert.False(retryRequested);
			dialog.CloseButton.PerformClick();
			Assert.True(retryRequested);
		});
	}

	[Fact]
	public void CloseButton_AfterASuccessfulRun_NeverAsksForARetry()
	{
		StaTestHarness ui = new(nameof(IisInstallProgressDialogTests));
		ui.Run(() =>
		{
			using IisInstallProgressDialog dialog = new();
			bool retryRequested = false;
			dialog.RetryRequested += (_, _) => retryRequested = true;

			// Same reason as the failure case: without a visible form the click never arrives and this
			// test would pass even if a successful run asked for a retry.
			dialog.Show();

			dialog.Complete("everything installed.", success: true, alreadyInstalled: false);
			dialog.CloseButton.PerformClick();

			Assert.False(retryRequested);
		});
	}

	[Fact]
	public void ShowPlan_ResetsEveryRowForARetry()
	{
		StaTestHarness ui = new(nameof(IisInstallProgressDialogTests));
		ui.Run(() =>
		{
			using IisInstallProgressDialog dialog = new();
			dialog.ApplyResult(new IisInstallStepResult(
				IisInstallStepId.IisFeatures, "features", "failed", IisStepOutcome.Failed));
			dialog.Complete("failed.", success: false, alreadyInstalled: false);

			dialog.ShowPlan(IisInstallPlan.CreatePendingSteps());

			Assert.True(dialog.IsRunning);
			Assert.False(dialog.IsFinished);
			Assert.All(dialog.Glyphs, glyph => Assert.Equal("…", glyph));
		});
	}

	[Fact]
	public void Constructor_UnderTheDarkTheme_StaysUsable()
	{
		StaTestHarness ui = new(nameof(IisInstallProgressDialogTests));
		ui.Run(() =>
		{
			using IisInstallProgressDialog dialog = new();

			// The theme paints the window and its buttons; the list must keep its rows readable.
			Assert.Equal(IisInstallPlan.OrderedStepIds.Count, dialog.Glyphs.Count);
			Assert.False(string.IsNullOrWhiteSpace(dialog.SummaryText));
		});
	}
}
