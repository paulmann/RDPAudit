/*
 * File   : WorkflowStepList.cs
 * Project: RdpAudit.Mikrotik (RdpAudit.Mikrotik.Ui)
 * Purpose: Left-rail wizard step indicator. Renders the five workflow steps (Diagnostics, Test,
 *          PKI, Firewall, Apply & Sync) with per-step state (Pending / Active / Done / Failed) and
 *          raises StepSelected when the operator clicks an already-reachable step. Pure presentation:
 *          it owns no business logic and is thread-safe to update from the UI thread.
 * Depends: System.Windows.Forms, DarkTheme, WorkflowStep
 * Extends: To add a workflow step, add a WorkflowStep enum value and a matching label in
 *          BuildStepRows; the rendering and selection logic adapt automatically.
 *
 * Author : Mikhail Deynekin — https://Deynekin.com
 * Version: 1.0.1
 */

using System.Drawing;
using System.Windows.Forms;

namespace RdpAudit.Mikrotik.Ui;

/// <summary>The five wizard steps, in order.</summary>
public enum WorkflowStep
{
	Diagnostics = 0,
	Test = 1,
	Pki = 2,
	Firewall = 3,
	ApplySync = 4,
}

/// <summary>Per-step visual state.</summary>
public enum WorkflowStepState
{
	Pending,
	Active,
	Done,
	Failed,
}

/// <summary>Left-rail wizard step indicator with clickable, reachable steps.</summary>
public sealed class WorkflowStepList : Panel
{
	// ── Fields & DI ──────────────────────────────────────────────────────────────

	private readonly Dictionary<WorkflowStep, WorkflowStepState> _states = new();
	private readonly Dictionary<WorkflowStep, Label> _rows = new();

	// ── Construction ─────────────────────────────────────────────────────────────

	public WorkflowStepList()
	{
		Width = 220;
		Dock = DockStyle.Left;
		DarkTheme.ApplyContainer(this);
		BackColor = DarkTheme.Surface;
		Padding = new Padding(12, 16, 12, 16);
		BuildStepRows();
	}

	// ── Public API ───────────────────────────────────────────────────────────────

	/// <summary>Raised when the operator clicks a step that is reachable (Done or Active).</summary>
	public event EventHandler<StepSelectedEventArgs>? StepSelected;

	/// <summary>Sets the visual state of a step and repaints its row.</summary>
	public void SetState(WorkflowStep step, WorkflowStepState state)
	{
		_states[step] = state;
		if (_rows.TryGetValue(step, out Label? row))
		{
			ApplyRowStyle(step, row, state);
		}
	}

	/// <summary>Returns the current state of a step.</summary>
	public WorkflowStepState GetState(WorkflowStep step)
		=> _states.GetValueOrDefault(step, WorkflowStepState.Pending);

	// ── Core Logic ───────────────────────────────────────────────────────────────

	private void BuildStepRows()
	{
		(WorkflowStep Step, string Caption)[] definitions =
		{
			(WorkflowStep.Diagnostics, "1  Diagnostics"),
			(WorkflowStep.Test, "2  Connection Test"),
			(WorkflowStep.Pki, "3  PKI / Certificates"),
			(WorkflowStep.Firewall, "4  Firewall Contour"),
			(WorkflowStep.ApplySync, "5  Apply & Sync"),
		};

		// Add bottom-up so Dock=Top preserves the declared order.
		for (int i = definitions.Length - 1; i >= 0; i--)
		{
			(WorkflowStep step, string caption) = definitions[i];
			Label row = new()
			{
				Text = caption,
				Dock = DockStyle.Top,
				Height = 44,
				TextAlign = ContentAlignment.MiddleLeft,
				Padding = new Padding(12, 0, 0, 0),
				Cursor = Cursors.Hand,
				Tag = step,
			};
			row.Click += OnRowClicked;
			_rows[step] = row;
			_states[step] = WorkflowStepState.Pending;
			ApplyRowStyle(step, row, WorkflowStepState.Pending);
			Controls.Add(row);
		}

		Label header = new()
		{
			Text = "RdpAudit · MikroTik Setup",
			Dock = DockStyle.Top,
			Height = 56,
			TextAlign = ContentAlignment.MiddleLeft,
			Padding = new Padding(8, 0, 0, 0),
			Font = DarkTheme.SubheadingFont,
			ForeColor = DarkTheme.Accent,
		};
		Controls.Add(header);
	}

	private void OnRowClicked(object? sender, EventArgs e)
	{
		if (sender is not Label { Tag: WorkflowStep step })
		{
			return;
		}

		WorkflowStepState state = GetState(step);
		if (state is WorkflowStepState.Done or WorkflowStepState.Active)
		{
			StepSelected?.Invoke(this, new StepSelectedEventArgs(step));
		}
	}

	private static void ApplyRowStyle(WorkflowStep step, Label row, WorkflowStepState state)
	{
		_ = step;
		row.Font = state == WorkflowStepState.Active ? DarkTheme.SubheadingFont : DarkTheme.BaseFont;
		row.BackColor = state == WorkflowStepState.Active ? DarkTheme.SurfaceRaised : DarkTheme.Surface;
		row.ForeColor = state switch
		{
			WorkflowStepState.Done => DarkTheme.Success,
			WorkflowStepState.Active => DarkTheme.Accent,
			WorkflowStepState.Failed => DarkTheme.Danger,
			_ => DarkTheme.SubtleText,
		};
	}
}
