// File:    src/RdpAudit.Configurator/Forms/ProcessObservationDialog.cs
// Module:  RdpAudit.Configurator.Forms
// Purpose: Operator-facing dialog for forcing one process identity through the same baseline
//          evaluation NewProcessRule uses (IPC ordinal 73, ReportProcessObservation). The
//          operator supplies the process image name, optional owner identity and optional
//          target session; the service performs the classification, records a bounded journal
//          row and may raise a PROCESS_NEW alert. Auto-close can be armed only for a valid
//          session id and only when SessionControl.AllowLogoff permits it - the service still
//          refuses disallowed requests, so the dialog never weakens policy. This is a DEBUG
//          panel tool and must stay behind the Diagnostics.DebugMode gate of its host page.
// Extends: System.Windows.Forms.Form
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Globalization;
using System.Runtime.Versioning;
using RdpAudit.Configurator.Ipc;
using RdpAudit.Configurator.Theming;
using RdpAudit.Core.Ipc;
using RdpAudit.Core.Ipc.Contracts;

namespace RdpAudit.Configurator.Forms;

/// <summary>Dialog that posts a manual process observation to the service.</summary>
[SupportedOSPlatform("windows")]
public sealed class ProcessObservationDialog : Form
{
	private readonly IpcClient _ipc;
	private readonly TextBox _processName;
	private readonly TextBox _userName;
	private readonly TextBox _domain;
	private readonly TextBox _sessionId;
	private readonly CheckBox _autoClose;
	private readonly Button _send;
	private readonly Label _status;

	public ProcessObservationDialog(IpcClient ipc)
	{
		ArgumentNullException.ThrowIfNull(ipc);
		_ipc = ipc;
		Text = "Report process observation (DEBUG)";
		Width = 520;
		Height = 340;
		FormBorderStyle = FormBorderStyle.FixedDialog;
		MaximizeBox = false;
		MinimizeBox = false;
		StartPosition = FormStartPosition.CenterParent;
		BackColor = DarkTheme.PageBack;
		ForeColor = DarkTheme.TextPrimary;

		TableLayoutPanel layout = new()
		{
			Dock = DockStyle.Fill,
			Padding = new Padding(10),
			ColumnCount = 2,
			RowCount = 6,
		};
		layout.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 110));
		layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100f));

		_processName = new TextBox { Dock = DockStyle.Fill, PlaceholderText = "e.g. powershell.exe" };
		_userName = new TextBox { Dock = DockStyle.Fill, PlaceholderText = "blank = system process" };
		_domain = new TextBox { Dock = DockStyle.Fill, PlaceholderText = "optional domain" };
		_sessionId = new TextBox { Dock = DockStyle.Fill, Text = "-1" };
		_autoClose = new CheckBox
		{
			Dock = DockStyle.Fill,
			Text = "Arm automated session close (logoff) when a new alert is raised",
		};
		_send = new Button { Text = "Report observation", Dock = DockStyle.Fill };
		_send.Click += async (_, _) => await SendAsync().ConfigureAwait(true);

		AddRow(layout, 0, "Process name *", _processName);
		AddRow(layout, 1, "User name", _userName);
		AddRow(layout, 2, "Domain", _domain);
		AddRow(layout, 3, "Session id", _sessionId);
		layout.Controls.Add(_autoClose, 1, 4);
		layout.Controls.Add(_send, 1, 5);

		_status = new Label
		{
			Dock = DockStyle.Bottom,
			Height = 56,
			AutoSize = false,
			Text = "Enter the process identity to evaluate.",
		};
		Controls.Add(layout);
		Controls.Add(_status);
	}

	private static void AddRow(TableLayoutPanel layout, int row, string caption, Control control)
	{
		layout.Controls.Add(new Label
		{
			Text = caption,
			Dock = DockStyle.Fill,
			TextAlign = ContentAlignment.MiddleLeft,
		}, 0, row);
		layout.Controls.Add(control, 1, row);
	}

	private async Task SendAsync()
	{
		if (string.IsNullOrWhiteSpace(_processName.Text)) {
			_status.Text = "A process name is required.";
			return;
		}

		if (!int.TryParse(_sessionId.Text.Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out int sessionId))
		{
			_status.Text = "Session id must be an integer (-1 = unknown).";
			return;
		}

		_send.Enabled = false;
		_status.Text = "Sending...";
		try
		{
			ProcessObservationResult? result = await _ipc.SendAsync<ProcessObservationResult>(
				IpcCommand.ReportProcessObservation,
				new ProcessObservationRequest
				{
					ProcessName = _processName.Text.Trim(),
					UserName = EmptyToNull(_userName.Text),
					Domain = EmptyToNull(_domain.Text),
					SessionId = sessionId,
					AutoClose = _autoClose.Checked,
				}).ConfigureAwait(true);

			if (result is null)
			{
				_status.Text = "No response - is the service running?";
				return;
			}

			string verdict = result.Status == IpcResultStatus.Success ? "success" : result.Status.ToString();
			_status.Text = string.Format(CultureInfo.InvariantCulture,
				"{0} | known={1} new={2} alert={3} autoCloseQueued={4}{5}",
				verdict,
				result.IsAlreadyKnown,
				result.IsNew,
				result.Alert is null ? "no" : "yes (id " + result.Alert.Id + ")",
				result.AutoCloseQueued,
				result.Message is null ? string.Empty : " | " + result.Message);
		}
		catch (Exception ex)
		{
			_status.Text = "Failed: " + ex.GetType().Name + " - " + ex.Message;
		}
		finally
		{
			_send.Enabled = true;
		}
	}

	private static string? EmptyToNull(string? text) =>
		string.IsNullOrWhiteSpace(text) ? null : text.Trim();
}
