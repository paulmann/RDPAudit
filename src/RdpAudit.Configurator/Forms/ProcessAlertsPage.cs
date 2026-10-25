// File:    src/RdpAudit.Configurator/Forms/ProcessAlertsPage.cs
// Module:  RdpAudit.Configurator.Forms
// Purpose: Process Monitoring alert panel (Stage PM). Lists persisted PROCESS_NEW alerts over
//          IPC (ListProcessAlerts), shows forensic details for the selected row
//          (GetProcessAlertDetails) and lets the operator arm / cancel the automated session
//          close (SetProcessAutoClose). All reads and mutations flow through the Service IPC;
//          the Configurator never opens the SQLite file directly. Auto-close arming is
//          append-only on the service side - a response row that has already finished can
//          never be re-armed - so the checkbox and buttons reflect the persisted state and
//          disable themselves instead of hiding the reason.
// Extends: System.Windows.Forms.TabPage
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Globalization;
using System.Linq;
using System.Runtime.Versioning;
using RdpAudit.Configurator.Ipc;
using RdpAudit.Configurator.Services;
using RdpAudit.Configurator.Theming;
using RdpAudit.Core.Ipc;
using RdpAudit.Core.Ipc.Contracts;
using RdpAudit.Core.ProcessMonitoring;
using RdpAudit.Core.Util;

namespace RdpAudit.Configurator.Forms;

/// <summary>Process Alerts tab: PROCESS_NEW alert list, details and auto-close management.</summary>
[SupportedOSPlatform("windows")]
public sealed class ProcessAlertsPage : TabPage
{
	private const int AutoRefreshIntervalMs = 5_000;

	/// <summary>Mirrors KnownProcessStore.DefaultListLimit; the Configurator must not reference
	/// the Service assembly, so the bound is duplicated here and kept in sync deliberately.</summary>
	private const int DefaultListLimit = 200;

	private readonly IpcClient _ipc;
	private readonly DataGridView _grid;
	private readonly List<ProcessAlertDto> _rows = new();
	private readonly Label _header;
	private readonly Label _details;
	private readonly CheckBox _autoClose;
	private readonly Button _arm;
	private readonly Button _cancel;
	private readonly Button _refresh;
	private readonly System.Windows.Forms.Timer _timer;
	private ProcessAlertDto? _selected;
	private bool _busy;

	public ProcessAlertsPage(IpcClient ipc)
	{
		ArgumentNullException.ThrowIfNull(ipc);
		_ipc = ipc;
		BackColor = DarkTheme.PageBack;
		ForeColor = DarkTheme.TextPrimary;

		_header = new Label
		{
			Dock = DockStyle.Top,
			Height = 22,
			Text = "Process Alerts - new process identities detected by the PROCESS_NEW rule.",
		};

		_grid = new DataGridView
		{
			Dock = DockStyle.Fill,
			ReadOnly = true,
			RowHeadersVisible = false,
			AllowUserToAddRows = false,
			SelectionMode = DataGridViewSelectionMode.FullRowSelect,
			MultiSelect = false,
		};
		_grid.Columns.Add(new DataGridViewTextBoxColumn { Name = "AlertId", HeaderText = "Id", Width = 70 });
		_grid.Columns.Add(new DataGridViewTextBoxColumn { Name = "TimeUtc", HeaderText = "Time (local)", Width = 160 });
		_grid.Columns.Add(new DataGridViewTextBoxColumn { Name = "ProcessName", HeaderText = "Process", Width = 220 });
		_grid.Columns.Add(new DataGridViewTextBoxColumn { Name = "UserName", HeaderText = "User", Width = 160 });
		_grid.Columns.Add(new DataGridViewTextBoxColumn { Name = "SessionId", HeaderText = "Session", Width = 90 });
		_grid.Columns.Add(new DataGridViewTextBoxColumn { Name = "AutoClose", HeaderText = "Auto-close", Width = 100 });
		DataGridClipboardMenu.AttachWithExport(_grid, "Process alerts", ReportExportStatus);
		_grid.SelectionChanged += (_, _) => OnSelectionChanged();

		_autoClose = new CheckBox
		{
			Text = "Auto-close session for the selected alert",
			AutoSize = true,
			Enabled = false,
		};
		_autoClose.CheckedChanged += async (_, _) => await OnAutoCloseToggledAsync().ConfigureAwait(true);

		_details = new Label
		{
			Dock = DockStyle.Top,
			Height = 118,
			AutoSize = false,
			Text = "Select an alert to see its details and response state.",
		};

		_arm = new Button { Text = "Arm auto-close", Width = 140 };
		_arm.Click += async (_, _) => await ChangeAutoCloseAsync(enabled: true).ConfigureAwait(true);
		_cancel = new Button { Text = "Cancel pending", Width = 140 };
		_cancel.Click += async (_, _) => await ChangeAutoCloseAsync(enabled: false).ConfigureAwait(true);
		_refresh = new Button { Text = "Refresh", Width = 110 };
		_refresh.Click += async (_, _) => await RefreshAsync().ConfigureAwait(true);

		FlowLayoutPanel toolbar = new()
		{
			Dock = DockStyle.Top,
			Height = 40,
			AutoSize = false,
		};
		toolbar.Controls.AddRange(new Control[] { _refresh, _arm, _cancel, _autoClose });

		Controls.Add(_grid);
		Controls.Add(_details);
		Controls.Add(toolbar);
		Controls.Add(_header);

		_timer = new System.Windows.Forms.Timer { Interval = AutoRefreshIntervalMs };
		_timer.Tick += async (_, _) => await RefreshAsync().ConfigureAwait(true);
		HandleCreated += async (_, _) =>
		{
			_timer.Start();
			await RefreshAsync().ConfigureAwait(true);
		};
	}

	private async Task RefreshAsync()
	{
		if (_busy)
		{
			return;
		}

		_busy = true;
		try
		{
			ProcessAlertListDto? dto = await _ipc.SendAsync<ProcessAlertListDto>(
				IpcCommand.ListProcessAlerts,
				new ListProcessAlertsRequest { Limit = DefaultListLimit }).ConfigureAwait(true);
			if (dto is null || dto.Status != IpcResultStatus.Success)
			{
				RenderList(new List<ProcessAlertDto>(), dto?.Message);
				return;
			}

			RenderList(dto.Items ?? new List<ProcessAlertDto>());
		}
		catch (Exception ex)
		{
			_header.Text = "IPC read failed: " + ex.GetType().Name + ": " + ex.Message;
		}
		finally
		{
			_busy = false;
		}
	}

	private void RenderList(List<ProcessAlertDto> alerts, string? statusNote = null)
	{
		long? keepSelectedId = _selected?.Id;
		_rows.Clear();
		_rows.AddRange(alerts);

		_grid.SuspendLayout();
		try
		{
			_grid.Rows.Clear();
			foreach (ProcessAlertDto a in alerts)
			{
				int idx = _grid.Rows.Add(
					a.Id.ToString(CultureInfo.InvariantCulture),
					LocalTimeFormatter.FormatLocal(a.TimeUtc),
					a.ProcessName,
					a.UserName ?? "SYSTEM",
					a.SessionId?.ToString(CultureInfo.InvariantCulture) ?? "-",
					AutoCloseText(a));
				_grid.Rows[idx].Tag = a.Id;
			}
		}
		finally
		{
			_grid.ResumeLayout();
		}

		_header.Text = statusNote is not null
			? "Process Alerts - " + statusNote
			: string.Format(CultureInfo.InvariantCulture,
				"Process Alerts - {0} persisted PROCESS_NEW alerts (newest first).", alerts.Count);

		if (keepSelectedId is long wantedId)
		{
			ProcessAlertDto? refreshed = _rows.FirstOrDefault(r => r.Id == wantedId);
			if (refreshed is not null)
			{
				_selected = refreshed;
				int selectedRowIndex = _rows.FindIndex(r => r.Id == wantedId);
				_grid.ClearSelection();
				_grid.Rows[selectedRowIndex].Selected = true;
				_ = LoadDetailsAsync();
				return;
			}
		}

		_selected = null;
		UpdateDetails(null);
	}

	/// <summary>Reports an export result through the details pane's status area.</summary>
	private void ReportExportStatus(string message) => _header.Text = message;

	private void OnSelectionChanged()
	{
		if (_grid.SelectedRows.Count > 0 && _grid.SelectedRows[0].Tag is long id)
		{
			_selected = _rows.FirstOrDefault(r => r.Id == id);
			_ = LoadDetailsAsync();
		}
	}

	private async Task LoadDetailsAsync()
	{
		if (_selected is null)
		{
			UpdateDetails(null);
			return;
		}

		long alertId = _selected.Id;
		try
		{
			ProcessAlertDetailsDto? dto = await _ipc.SendAsync<ProcessAlertDetailsDto>(
				IpcCommand.GetProcessAlertDetails,
				new GetProcessAlertDetailsRequest { AlertId = alertId }).ConfigureAwait(true);
			if (dto?.Alert is { } alert)
			{
				_selected = alert;
				UpdateDetails(alert, dto.Response);
			}
			else
			{
				UpdateDetails(_selected, null, dto?.Message);
			}
		}
		catch (Exception ex)
		{
			UpdateDetails(_selected, null, "Details read failed: " + ex.GetType().Name);
		}
	}

	private async Task OnAutoCloseToggledAsync()
	{
		if (_selected is null || !_autoClose.Enabled || _autoClose.Checked == _selected.AutoCloseEnabled)
		{
			return;
		}

		await ChangeAutoCloseAsync(_autoClose.Checked).ConfigureAwait(true);
	}

	private async Task ChangeAutoCloseAsync(bool enabled)
	{
		if (_selected is null)
		{
			return;
		}

		long alertId = _selected.Id;
		_arm.Enabled = false;
		_cancel.Enabled = false;
		try
		{
			ProcessAutoCloseActionResult? result = await _ipc.SendAsync<ProcessAutoCloseActionResult>(
				IpcCommand.SetProcessAutoClose,
				new SetProcessAutoCloseRequest
				{
					AlertId = alertId,
					Enabled = enabled,
					Reason = "Process Alerts page adjustment",
				}).ConfigureAwait(true);
			if (result?.Alert is { } alert)
			{
				_selected = alert;
				UpdateDetails(alert, result.Response);
			}
			else
			{
				UpdateDetails(_selected, null, result?.Message ?? "Auto-close change failed.");
			}

			await RefreshAsync().ConfigureAwait(true);
		}
		catch (Exception ex)
		{
			UpdateDetails(_selected, null, "Auto-close change failed: " + ex.GetType().Name);
		}
		finally
		{
			_arm.Enabled = true;
			_cancel.Enabled = true;
		}
	}

	private void UpdateDetails(ProcessAlertDto? alert, ProcessAlertResponseDto? response = null, string? note = null)
	{
		if (alert is null)
		{
			_details.Text = "Select an alert to see its details and response state.";
			_autoClose.Enabled = false;
			_autoClose.Checked = false;
			_arm.Enabled = false;
			_cancel.Enabled = false;
			return;
		}

		string responseText = response is null
			? "no automated response"
			: string.Format(CultureInfo.InvariantCulture, "auto-close: {0}", DescribeResponse(response));
		_details.Text = string.Format(CultureInfo.InvariantCulture,
			"Alert {0} {1} | process: {2} | user: {3} | session: {4} | raised: {5} | {6}{7}",
			alert.RuleId,
			alert.Id,
			alert.ProcessName,
			alert.UserName ?? "SYSTEM",
			alert.SessionId?.ToString(CultureInfo.InvariantCulture) ?? "-",
			LocalTimeFormatter.FormatLocal(alert.TimeUtc),
			responseText,
			note is null ? string.Empty : " - " + note);

		bool queued = response is not null && response.Status == (int)ProcessAutoCloseStatus.Queued;
		bool final = response is not null && response.Status != (int)ProcessAutoCloseStatus.Queued;
		bool hasSession = alert.SessionId is int s && s >= 0;

		_autoClose.Enabled = !final && hasSession;
		_autoClose.Checked = queued;
		_arm.Enabled = !queued && !final && hasSession;
		_cancel.Enabled = queued;
	}

	private static string AutoCloseText(ProcessAlertDto a) => a.AutoCloseEnabled
		? "queued"
		: (a.SessionId ?? -1) < 0 ? "no session" : "off";

	private static string DescribeResponse(ProcessAlertResponseDto r) =>
		((ProcessAutoCloseStatus)r.Status).ToString();

	protected override void Dispose(bool disposing)
	{
		if (disposing)
		{
			_timer.Dispose();
		}

		base.Dispose(disposing);
	}
}
