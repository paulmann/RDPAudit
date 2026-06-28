/*
 * File   : StepPanelBase.cs
 * Project: RdpAudit.Mikrotik (RdpAudit.Mikrotik.Ui)
 * Purpose: Common scaffolding for every wizard step panel: a heading, a description line, a primary
 *          action button and a scrolling, read-only log box. It centralises the dark-theme styling
 *          and the thread-safe AppendLog helper so each concrete step only implements its action.
 * Depends: System.Windows.Forms, DarkTheme, WizardContext
 * Extends: A new step subclasses this, sets Heading/Description/ActionText in its constructor and
 *          overrides RunActionAsync; to change the shared layout, edit BuildLayout once here.
 *
 * Author : Mikhail Deynekin — https://Deynekin.com
 * Version: 1.0.1
 */

using System.Drawing;
using System.Windows.Forms;

namespace RdpAudit.Mikrotik.Ui;

/// <summary>Common scaffolding for wizard step panels.</summary>
public abstract class StepPanelBase : Panel
{
	// ── Fields & DI ──────────────────────────────────────────────────────────────

	private readonly Label _heading = new();
	private readonly Label _description = new();
	private readonly Button _actionButton = new();
	private readonly TextBox _log = new();

	// ── Construction ─────────────────────────────────────────────────────────────

	protected StepPanelBase(WizardContext context)
	{
		Context = context ?? throw new ArgumentNullException(nameof(context));
		Dock = DockStyle.Fill;
		DarkTheme.ApplyContainer(this);
		Padding = new Padding(24, 20, 24, 20);
		BuildLayout();
	}

	// ── Public API ───────────────────────────────────────────────────────────────

	/// <summary>Raised when this step finishes successfully (host advances the workflow).</summary>
	public event EventHandler? StepCompleted;

	/// <summary>Raised when this step fails (host marks the step Failed).</summary>
	public event EventHandler<StepFailedEventArgs>? StepFailed;

	/// <summary>Shared wizard state.</summary>
	protected WizardContext Context { get; }

	/// <summary>Heading text shown at the top of the panel.</summary>
	protected string Heading { get => _heading.Text; set => _heading.Text = value; }

	/// <summary>Description line under the heading.</summary>
	protected string Description { get => _description.Text; set => _description.Text = value; }

	/// <summary>Caption of the primary action button.</summary>
	protected string ActionText { get => _actionButton.Text; set => _actionButton.Text = value; }

	/// <summary>Called by the host when this step becomes the active step.</summary>
	public virtual void OnActivated()
	{
	}

	// ── Core Logic ───────────────────────────────────────────────────────────────

	/// <summary>The work this step performs when the action button is clicked. Must not touch UI directly.</summary>
	protected abstract Task RunActionAsync(CancellationToken ct);

	/// <summary>Appends a line to the log box, marshalling onto the UI thread when required.</summary>
	protected void AppendLog(string line)
	{
		if (_log.InvokeRequired)
		{
			_log.BeginInvoke(() => AppendLog(line));
			return;
		}
		_log.AppendText(line + Environment.NewLine);
	}

	/// <summary>Signals successful completion of this step.</summary>
	protected void CompleteStep() => StepCompleted?.Invoke(this, EventArgs.Empty);

	/// <summary>Signals failure of this step with a message.</summary>
	protected void FailStep(string message) => StepFailed?.Invoke(this, new StepFailedEventArgs(message));

	/// <summary>Enables/disables the action button (used while an async action runs).</summary>
	protected void SetBusy(bool busy)
	{
		if (_actionButton.InvokeRequired)
		{
			_actionButton.BeginInvoke(() => SetBusy(busy));
			return;
		}
		_actionButton.Enabled = !busy;
		Cursor = busy ? Cursors.WaitCursor : Cursors.Default;
	}

	private void BuildLayout()
	{
		DarkTheme.StyleHeading(_heading);
		_heading.Dock = DockStyle.Top;
		_heading.Height = 32;

		_description.Dock = DockStyle.Top;
		_description.Height = 48;
		_description.ForeColor = DarkTheme.SubtleText;
		_description.Font = DarkTheme.BaseFont;

		DarkTheme.StyleAccentButton(_actionButton);
		_actionButton.Dock = DockStyle.Top;
		_actionButton.Width = 220;
		_actionButton.Margin = new Padding(0, 8, 0, 8);
		_actionButton.Click += OnActionClicked;

		_log.Dock = DockStyle.Fill;
		_log.Multiline = true;
		_log.ReadOnly = true;
		_log.ScrollBars = ScrollBars.Vertical;
		_log.BackColor = DarkTheme.Background;
		_log.ForeColor = DarkTheme.Text;
		_log.BorderStyle = BorderStyle.FixedSingle;
		_log.Font = DarkTheme.MonoFont;

		Panel actionRow = new() { Dock = DockStyle.Top, Height = 50, BackColor = DarkTheme.Background };
		actionRow.Controls.Add(_actionButton);

		// Add in reverse for Dock=Top ordering: log fills, then action row, description, heading.
		Controls.Add(_log);
		Controls.Add(actionRow);
		Controls.Add(_description);
		Controls.Add(_heading);
	}

	private async void OnActionClicked(object? sender, EventArgs e)
	{
		SetBusy(true);
		try
		{
			await RunActionAsync(CancellationToken.None).ConfigureAwait(true);
		}
		catch (Exception ex) when (ex is InvalidOperationException or IOException or System.Security.Cryptography.CryptographicException)
		{
			AppendLog("ERROR: " + ex.Message);
			FailStep(ex.Message);
		}
		finally
		{
			SetBusy(false);
		}
	}
}
