// File:    src/RdpAudit.Configurator/Forms/IisInstallProgressDialog.cs
// Module:  RdpAudit.Configurator.Forms
// Purpose: Modal window behind the Web Access "Install IIS" button. It shows exactly what will be
//          installed BEFORE anything runs (the plan comes from IisInstallPlan - the same source the
//          workflow executes, so the list can never drift from reality), then marks each item with a
//          tick or a cross as the run reports progress. The window is intentionally dumb: it renders
//          IisInstallStepResult rows and nothing else, so it cannot disagree with the workflow.
//
//          Threading discipline (BUGS B2 / NFR): the window never runs the workflow itself and never
//          blocks the UI thread. The caller starts the run off the UI thread and pushes results
//          through an IProgress that marshals back to the UI thread; RefreshFrom raises the
//          "run again" request so the caller decides what happens on a second click. Closing the
//          window while the run is in flight does NOT cancel the installation - the machine is
//          already being changed and half-reporting that would be a lie. The final row states
//          whether the components were installed or the machine already had them, and a Close button
//          lets the operator dismiss the result.
// Extends: System.Windows.Forms.Form
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System;
using System.Collections.Generic;
using System.Drawing;
using System.Runtime.Versioning;
using System.Windows.Forms;
using RdpAudit.Configurator.Theming;
using RdpAudit.Core.WebUi;

namespace RdpAudit.Configurator.Forms;

/// <summary>Modal progress window for the Install IIS run: the plan before the run, one tick / cross
/// per item during it, and the bounded result detail after it.</summary>
[SupportedOSPlatform("windows")]
public sealed class IisInstallProgressDialog : Form
{
	private const string PendingGlyph = "…";
	private const string RunningGlyph = "…";
	private const string OkGlyph = "✓";
	private const string WarningGlyph = "!";
	private const string FailedGlyph = "✗";
	private const string SkippedGlyph = "-";

	private readonly ListView _list;
	private readonly Label _summary;
	private readonly Button _closeButton;
	private bool _running;
	private bool _finished;
	private bool _lastSuccess;

	/// <summary>Creates the window showing the given plan in its initial state. Null/empty falls back
	/// to the canonical pending plan so the window is never empty.</summary>
	public IisInstallProgressDialog(IReadOnlyList<IisInstallStepResult>? plan = null)
	{
		Text = "Install IIS";
		StartPosition = FormStartPosition.CenterParent;
		FormBorderStyle = FormBorderStyle.Sizable;
		MinimumSize = new Size(560, 320);
		Size = new Size(620, 380);
		ShowInTaskbar = false;

		_list = new ListView
		{
			Dock = DockStyle.Fill,
			View = View.Details,
			FullRowSelect = true,
			GridLines = false,
			HeaderStyle = ColumnHeaderStyle.Nonclickable,
			MultiSelect = false,
		};
		_list.Columns.Add("", 28, HorizontalAlignment.Center);
		_list.Columns.Add("Component", 220, HorizontalAlignment.Left);
		_list.Columns.Add("Detail", 340, HorizontalAlignment.Left);
		// Progress steps are worth exporting when an install has to be reported to someone else.
		ListViewClipboardMenu.AttachWithExport(_list, "IIS install progress", ReportExportStatus);

		_summary = new Label
		{
			Dock = DockStyle.Bottom,
			Height = 52,
			TextAlign = ContentAlignment.MiddleLeft,
			Padding = new Padding(8, 0, 8, 0),
			Text = "Nothing has been changed yet. Every item below is checked and installed by this run.",
		};

		_closeButton = new Button
		{
			Text = "Close",
			AutoSize = true,
			MinimumSize = new Size(96, 30),
			Enabled = false,
		};
		_closeButton.Click += OnCloseOrRetry;

		FlowLayoutPanel buttons = new()
		{
			Dock = DockStyle.Bottom,
			Height = 44,
			FlowDirection = FlowDirection.RightToLeft,
			Padding = new Padding(6),
		};
		buttons.Controls.Add(_closeButton);

		Controls.Add(_list);
		Controls.Add(_summary);
		Controls.Add(buttons);

		// The theme paints the buttons from their availability, so no page-side colour code is needed.
		DarkTheme.Apply(this);

		ShowPlan(plan ?? IisInstallPlan.CreatePendingSteps());
	}

	/// <summary>Raised when the operator asks to retry a finished run. The OWNER decides whether a
	/// retry is allowed and starts it; the window only reports the request.</summary>
	/// <summary>Reports an export result through the dialog's summary label.</summary>
	private void ReportExportStatus(string message) => _summary.Text = message;

	public event EventHandler? RetryRequested;

	/// <summary>True while a run is in flight. Exposed for tests.</summary>
	internal bool IsRunning => _running;

	/// <summary>True once the run reported its final state. Exposed for tests.</summary>
	internal bool IsFinished => _finished;

	/// <summary>Current row glyphs, in display order. Exposed for tests.</summary>
	internal IReadOnlyList<string> Glyphs
	{
		get
		{
			List<string> glyphs = new(_list.Items.Count);
			foreach (ListViewItem item in _list.Items)
			{
				glyphs.Add(item.Text);
			}

			return glyphs;
		}
	}

	/// <summary>Summary line under the list. Exposed for tests.</summary>
	internal string SummaryText => _summary.Text;

	/// <summary>The single action button; its caption states what a click will do (close the result or
	/// retry the failed run). Exposed for tests.</summary>
	internal Button CloseButton => _closeButton;

	/// <summary>Replaces every row with the given plan in its initial state. Used before a retry.</summary>
	public void ShowPlan(IReadOnlyList<IisInstallStepResult> plan)
	{
		ArgumentNullException.ThrowIfNull(plan);

		_list.BeginUpdate();
		try
		{
			_list.Items.Clear();
			foreach (IisInstallStepResult step in plan)
			{
				_list.Items.Add(CreateRow(step));
			}
		}
		finally
		{
			_list.EndUpdate();
		}

		_running = true;
		_finished = false;
		_closeButton.Enabled = false;
		_closeButton.Text = "Close";
		_summary.Text = "Installing… every item below is checked and installed by this run.";
	}

	/// <summary>Applies one progress update: paints the matching row and reports a result row that
	/// belongs to no plan item as-is (fail-visible rather than silently dropped).</summary>
	public void ApplyResult(IisInstallStepResult result)
	{
		ArgumentNullException.ThrowIfNull(result);

		ListViewItem? target = FindRow(result.Id);
		if (target is null)
		{
			target = CreateRow(result);
			_list.Items.Add(target);
		}

		ApplyOutcome(target, result);

		if (result.Outcome is IisStepOutcome.Ok or IisStepOutcome.Warning or IisStepOutcome.Failed)
		{
			_summary.Text = result.Detail;
		}
	}

	/// <summary>Marks the run as finished: the operator can close the window, and a failed run turns the
	/// button into Retry (the owner decides whether a retry is allowed).</summary>
	public void Complete(string summary, bool success, bool alreadyInstalled)
	{
		_running = false;
		_finished = true;
		_lastSuccess = success;
		_closeButton.Enabled = true;
		_closeButton.Text = success ? "Close" : "Retry";
		_summary.Text = alreadyInstalled
			? "Nothing had to be installed: the machine already had every component."
			: summary;
	}

	/// <summary>Closes the window and, when the last run failed, asks the owner for a retry. The window
	/// never starts an installation itself.</summary>
	private void OnCloseOrRetry(object? sender, EventArgs e)
	{
		bool askForRetry = _finished && !_lastSuccess;
		Close();
		if (askForRetry)
		{
			RetryRequested?.Invoke(this, EventArgs.Empty);
		}
	}

	private ListViewItem? FindRow(IisInstallStepId id)
	{
		foreach (ListViewItem item in _list.Items)
		{
			if (item.Tag is IisInstallStepId stepId && stepId == id)
			{
				return item;
			}
		}

		return null;
	}

	private static ListViewItem CreateRow(IisInstallStepResult step)
	{
		ListViewItem item = new(new[] { GlyphFor(step.Outcome), IisInstallPlan.TitleFor(step.Id), step.Detail })
		{
			Tag = step.Id,
		};
		ApplyOutcome(item, step);
		return item;
	}

	// Applies the recorded outcome to one row: glyph, title, detail text and row colours.
	// Deliberately not called Paint: that name would hide the inherited Control.Paint member (CS0108).
	private static void ApplyOutcome(ListViewItem item, IisInstallStepResult step)
	{
		item.SubItems[0].Text = GlyphFor(step.Outcome);
		item.SubItems[1].Text = IisInstallPlan.TitleFor(step.Id);
		item.SubItems[2].Text = step.Detail;

		Color back = step.Outcome switch
		{
			IisStepOutcome.Ok => DarkTheme.RowSuccessBack,
			IisStepOutcome.Warning => DarkTheme.RowWarningBack,
			IisStepOutcome.Failed => DarkTheme.RowDangerBack,
			IisStepOutcome.Skipped => DarkTheme.RowMutedBack,
			_ => DarkTheme.CellBack,
		};

		item.BackColor = back;
		item.ForeColor = step.Outcome == IisStepOutcome.Failed
			? DarkTheme.StatusDanger
			: DarkTheme.TextPrimary;
	}

	/// <summary>Glyph painted for one outcome. Pending and Running deliberately share a marker: from
	/// the operator's point of view both mean "not decided yet".</summary>
	internal static string GlyphFor(IisStepOutcome outcome) => outcome switch
	{
		IisStepOutcome.Ok => OkGlyph,
		IisStepOutcome.Warning => WarningGlyph,
		IisStepOutcome.Failed => FailedGlyph,
		IisStepOutcome.Skipped => SkippedGlyph,
		IisStepOutcome.Running => RunningGlyph,
		_ => PendingGlyph,
	};
}
