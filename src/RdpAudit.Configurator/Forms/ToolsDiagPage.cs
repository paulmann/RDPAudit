// File:    src/RdpAudit.Configurator/Forms/ToolsDiagPage.cs
// Module:  RdpAudit.Configurator.Forms
// Purpose: Tools Diag tab — runs the read-only diagnostics probe set on the service side and renders
//          each external-command probe with its full runner metadata (tool name, resolved executable,
//          arguments, runner mode, working dir, exit code, duration, timed-out flag, locale hint,
//          pass/fail) in a grid, plus the single-block copyable transcript the service composed. A
//          separate, explicitly user-triggered "Run temporary firewall rule probe" button takes a test
//          IP, creates / verifies / cleans up a single temporary rule and shows each step's exact
//          backend command and output. The read-only probe set never creates or deletes firewall rules;
//          only the temporary probe button does, and only for the IP the operator typed.
// Extends: System.Windows.Forms.TabPage
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com
// Version: 1.1.0

using System.Globalization;
using System.Runtime.Versioning;
using System.Text;
using RdpAudit.Configurator.Ipc;
using RdpAudit.Configurator.Services;
using RdpAudit.Core.Ipc;
using RdpAudit.Core.Ipc.Contracts;

using RdpAudit.Configurator.Theming;
using static RdpAudit.Configurator.Theming.DarkTheme;

namespace RdpAudit.Configurator.Forms;

/// <summary>Tools Diag tab — runs the read-only probe set and the explicit temporary-firewall probe.</summary>
[SupportedOSPlatform("windows")]
public sealed class ToolsDiagPage : TabPage
{
	private readonly IpcClient _ipc;
	private readonly ServiceReachabilityProbe _reachability = new();
	private readonly Button _run;
	private readonly Button _copy;
	private readonly Button _save;
	private readonly Button _tempProbe;
	private readonly TextBox _testIp;
	private readonly Label _status;
	private readonly DataGridView _grid;
	private readonly TextBox _report;

	public ToolsDiagPage(IpcClient ipc)
	{
		_ipc = ipc;
		Text = "Tools Diag";
		Padding = new Padding(8);

		FlowLayoutPanel toolbar = new()
		{
			Dock = DockStyle.Top,
			Height = 38,
			AutoSize = false,
			FlowDirection = FlowDirection.LeftToRight,
		};

		_run = new Button { Text = "Run diagnostics", Width = 140 };
		_copy = new Button { Text = "Copy output", Width = 120 };
		_save = new Button { Text = "Save output…", Width = 120 };
		Label ipLabel = new()
		{
			Text = "Test IP:",
			AutoSize = false,
			Width = 56,
			TextAlign = ContentAlignment.MiddleRight,
			Margin = new Padding(12, 6, 2, 0),
		};
		_testIp = new TextBox { Width = 150, Margin = new Padding(2, 6, 2, 0) };
		_tempProbe = new Button { Text = "Run temporary firewall rule probe", Width = 250 };

		_run.Click += async (_, _) => await RunDiagnosticsAsync().ConfigureAwait(true);
		_copy.Click += OnCopy;
		_save.Click += OnSave;
		_tempProbe.Click += async (_, _) => await RunTemporaryProbeAsync().ConfigureAwait(true);

		toolbar.Controls.AddRange(new Control[] { _run, _copy, _save, ipLabel, _testIp, _tempProbe });

		_status = new Label
		{
			Dock = DockStyle.Top,
			Height = 22,
			Text = "Press \"Run diagnostics\" to probe the local tools (read-only; no firewall rules are changed).",
			AutoSize = false,
			TextAlign = ContentAlignment.MiddleLeft,
			Padding = new Padding(4, 2, 4, 2),
		};

		SplitContainer split = new()
		{
			Dock = DockStyle.Fill,
			Orientation = Orientation.Horizontal,
			SplitterDistance = 220,
		};

		_grid = new DataGridView
		{
			Dock = DockStyle.Fill,
			ReadOnly = true,
			AllowUserToAddRows = false,
			AllowUserToDeleteRows = false,
			AllowUserToResizeRows = false,
			RowHeadersVisible = false,
			SelectionMode = DataGridViewSelectionMode.FullRowSelect,
			AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill,
			MultiSelect = false,
		};
		BuildGridColumns();

		_report = new TextBox
		{
			Dock = DockStyle.Fill,
			Multiline = true,
			ReadOnly = true,
			ScrollBars = ScrollBars.Both,
			WordWrap = false,
			Font = new Font(FontFamily.GenericMonospace, 9f),
		};

		split.Panel1.Controls.Add(_grid);
		split.Panel2.Controls.Add(_report);
		DataGridClipboardMenu.Attach(_grid);

		Controls.Add(split);
		Controls.Add(_status);
		Controls.Add(toolbar);
	}

	private void BuildGridColumns()
	{
		_grid.Columns.Clear();
		_grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Result", Name = "result", FillWeight = 8 });
		_grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Tool", Name = "tool", FillWeight = 22 });
		_grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Runner", Name = "runner", FillWeight = 12 });
		_grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Executable", Name = "exe", FillWeight = 20 });
		_grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Exit", Name = "exit", FillWeight = 6 });
		_grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "ms", Name = "ms", FillWeight = 7 });
		_grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Locale hint", Name = "locale", FillWeight = 25 });
	}

	private async Task RunDiagnosticsAsync()
	{
		_status.Text = "Running diagnostics… (this can take up to a minute on a busy host)";
		_run.Enabled = false;
		_tempProbe.Enabled = false;
		try
		{
			IpcCallResult<ToolsDiagnosticsDto> call =
				await _ipc.SendDetailedAsync<ToolsDiagnosticsDto>(IpcCommand.RunToolsDiagnostics).ConfigureAwait(true);
			if (!call.IsSuccess || call.Value is null)
			{
				await ShowServiceCallFailureAsync(call, "Tools Diag").ConfigureAwait(true);
				return;
			}

			ToolsDiagnosticsDto dto = call.Value;
			PopulateGrid(dto.Probes);
			_report.Text = dto.ReportText;
			int passed = dto.Probes.Count(p => p.Passed);
			_status.Text = string.Format(
				CultureInfo.InvariantCulture,
				"Diagnostics at {0:yyyy-MM-dd HH:mm:ss}Z  |  Status={1}  |  Probes={2}  Passed={3}  |  {4}{5}",
				dto.GeneratedUtc,
				dto.Status,
				dto.Probes.Count,
				passed,
				call.TraceLine,
				string.IsNullOrWhiteSpace(dto.Message) ? string.Empty : "  |  " + dto.Message);
		}
		catch (Exception ex)
		{
			_status.Text = "Diagnostics: error — " + ex.GetType().Name;
			_report.Text = ex.Message;
		}
		finally
		{
			_run.Enabled = true;
			_tempProbe.Enabled = true;
		}
	}

	/// <summary>Renders an honest failure for a service call that did not succeed. The local probe grid
	/// is left untouched (local probes, if any, stay visible); only the service-side diagnostics are
	/// reported as unavailable, and the headline distinguishes a stopped service from a busy one.</summary>
	private async Task ShowServiceCallFailureAsync<T>(IpcCallResult<T> call, string label)
	{
		ServiceReachabilityDiagnostic diag = await _reachability.DescribeAsync(call).ConfigureAwait(true);
		_status.Text = label + ": " + diag.Headline;
		bool hasLocalRows = _grid.Rows.Count > 0;
		string serviceNote = hasLocalRows
			? "Local probe rows above remain valid. Service-side diagnostics are unavailable for this run:"
			: "Service-side diagnostics are unavailable for this run:";
		_report.Text = string.Join(
			"\r\n",
			label + " — " + diag.Headline,
			string.Empty,
			serviceNote,
			diag.Detail);
	}

	private async Task RunTemporaryProbeAsync()
	{
		string testIp = _testIp.Text.Trim();
		if (string.IsNullOrWhiteSpace(testIp))
		{
			_status.Text = "Enter a test IP first. Use a documentation IP (e.g. 203.0.113.10) you are sure is safe to block momentarily.";
			return;
		}

		DialogResult confirm = MessageBox.Show(
			FindForm(),
			string.Format(
				CultureInfo.InvariantCulture,
				"This will create a temporary Windows Firewall block rule for {0}, verify it, then remove it.\r\n\r\nProceed?",
				testIp),
			"Run temporary firewall rule probe",
			MessageBoxButtons.OKCancel,
			MessageBoxIcon.Warning);
		if (confirm != DialogResult.OK)
		{
			return;
		}

		_status.Text = "Running temporary firewall rule probe…";
		_tempProbe.Enabled = false;
		_run.Enabled = false;
		try
		{
			IpcCallResult<TemporaryFirewallProbeDto> call = await _ipc
				.SendDetailedAsync<TemporaryFirewallProbeDto>(IpcCommand.RunTemporaryFirewallRuleProbe, testIp)
				.ConfigureAwait(true);
			if (!call.IsSuccess || call.Value is null)
			{
				await ShowServiceCallFailureAsync(call, "Temp probe").ConfigureAwait(true);
				return;
			}

			TemporaryFirewallProbeDto dto = call.Value;
			PopulateGrid(dto.Steps);
			_report.Text = dto.ReportText;
			_status.Text = string.Format(
				CultureInfo.InvariantCulture,
				"Temp probe at {0:yyyy-MM-dd HH:mm:ss}Z  |  Status={1}  |  Created+verified+cleaned={2}  |  {3}{4}",
				dto.GeneratedUtc,
				dto.Status,
				dto.CreatedVerifiedAndCleanedUp ? "YES" : "NO",
				call.TraceLine,
				string.IsNullOrWhiteSpace(dto.Message) ? string.Empty : "  |  " + dto.Message);
		}
		catch (Exception ex)
		{
			_status.Text = "Temp probe: error — " + ex.GetType().Name;
			_report.Text = ex.Message;
		}
		finally
		{
			_tempProbe.Enabled = true;
			_run.Enabled = true;
		}
	}

	private void PopulateGrid(IReadOnlyList<ToolProbeResultDto> probes)
	{
		_grid.Rows.Clear();
		foreach (ToolProbeResultDto p in probes)
		{
			int idx = _grid.Rows.Add(
				p.Passed ? "PASS" : "FAIL",
				p.ToolName,
				p.RunnerMode,
				p.Executable.Length > 0 ? p.Executable : "(none)",
				p.ExitCode.ToString(CultureInfo.InvariantCulture),
				p.DurationMs.ToString(CultureInfo.InvariantCulture),
				p.LocaleHint);
			_grid.Rows[idx].DefaultCellStyle.BackColor = p.Passed
				? RowSuccessBack
				: RowDangerBack;
		}
	}

	private void OnCopy(object? sender, EventArgs e)
	{
		if (string.IsNullOrEmpty(_report.Text))
		{
			return;
		}

		try
		{
			Clipboard.SetText(_report.Text);
			_status.Text = "Copied Tools Diag output to clipboard.";
		}
		catch (Exception ex)
		{
			_status.Text = "Clipboard copy failed: " + ex.Message;
		}
	}

	private void OnSave(object? sender, EventArgs e)
	{
		if (string.IsNullOrEmpty(_report.Text))
		{
			return;
		}

		using SaveFileDialog dlg = new()
		{
			Title = "Save RdpAudit Tools Diag output",
			Filter = "Text files (*.txt)|*.txt|All files (*.*)|*.*",
			FileName = string.Format(
				CultureInfo.InvariantCulture,
				"rdpaudit-tools-diag-{0:yyyyMMdd-HHmmss}.txt",
				DateTime.UtcNow),
			OverwritePrompt = true,
		};
		if (dlg.ShowDialog(FindForm()) != DialogResult.OK)
		{
			return;
		}

		try
		{
			File.WriteAllText(dlg.FileName, _report.Text, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
			_status.Text = "Saved Tools Diag output to " + dlg.FileName;
		}
		catch (Exception ex)
		{
			_status.Text = "Save failed: " + ex.Message;
		}
	}
}
