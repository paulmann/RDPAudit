// File:    src/RdpAudit.Configurator/Forms/ServicePage.cs
// Module:  RdpAudit.Configurator.Forms
// Purpose: Service status panel, lifecycle controls, and recent alerts grid.
//          Stage 2: SCM/Win32_Service is authoritative for installed/running state, never
//          a process-name scan or the distribution folder. IPC reports runtime telemetry
//          independently. Installed binary state is compared against the distribution
//          publish folder by length, SHA-256, and version, and an explicit
//          "Update installed files" button is offered when the two disagree.
//          Service install computes the absolute service binary path, never literal %ProgramFiles%.
//          All Process.Start + WaitForExit calls are wrapped in Task.Run so the UI thread is free.
//          Every lifecycle button (Start / Stop / Restart / Uninstall / Install / Update)
//          reports a consistent ServiceOperationResult and refreshes the displayed state.
// Extends: System.Windows.Forms.TabPage
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com
// Version: 1.1.0

using System.ComponentModel;
using System.Globalization;
using System.IO;
using System.Reflection;
using System.Runtime.Versioning;
using System.Text;
using RdpAudit.Configurator.Ipc;
using RdpAudit.Configurator.Services;
using RdpAudit.Core.Backup;
using RdpAudit.Core.Ipc;
using RdpAudit.Core.Models;
using RdpAudit.Core.Util;

using RdpAudit.Configurator.Theming;
using static RdpAudit.Configurator.Theming.DarkTheme;

namespace RdpAudit.Configurator.Forms;

/// <summary>Service status panel, lifecycle controls, and recent alerts grid.</summary>
[SupportedOSPlatform("windows")]
public sealed class ServicePage : TabPage
{
	private const string ServiceName = InstallationService.ServiceName;
	private const string ServiceDisplayName = InstallationService.ServiceDisplayName;

	private readonly IpcClient _ipc;
	private readonly Label _status;
	private readonly Label _process;
	private readonly Label _stateLabel;
	private readonly Label _diagnostic;
	private readonly TextBox _layoutPanel;
	private readonly DataGridView _alertsGrid;
	private readonly System.Windows.Forms.Timer _timer;
	private readonly ServiceControlRunner _runner = new(ServiceName, ServiceDisplayName);
	private readonly WmiServiceInfoReader _scmReader = new(ServiceName);

	// Stage 2: lifecycle buttons kept as fields so RefreshAsync can drive enablement from
	// the authoritative SCM snapshot plus the installed/distribution binary comparison.
	private readonly Button _btnInstall;
	private readonly Button _btnUninstall;
	private readonly Button _btnStart;
	private readonly Button _btnStop;
	private readonly Button _btnRestart;
	private readonly Button _btnUpdate;
	private readonly Button _btnCopyDiagnostics;

	private readonly ContextMenuStrip _alertsMenu;
	private readonly ToolStripMenuItem _alertsMenuOpenRipeStat;
	private readonly ToolStripMenuItem _alertsMenuOpenAbuseIpDb;
	private Alert? _alertsMenuRow;

	public ServicePage(IpcClient ipc)
	{
		_ipc = ipc;

		FlowLayoutPanel buttons = new() { Dock = DockStyle.Top, Height = 36 };
		_btnInstall = new Button { Text = "Install service", Width = 130 };
		_btnUninstall = new Button { Text = "Uninstall service", Width = 130 };
		_btnStart = new Button { Text = "Start", Width = 80 };
		_btnStop = new Button { Text = "Stop", Width = 80 };
		_btnRestart = new Button { Text = "Restart", Width = 80 };
		_btnUpdate = new Button { Text = "Update installed files", Width = 170 };
		_btnCopyDiagnostics = new Button { Text = "Copy diagnostics", Width = 140 };
		Button backup = new() { Text = "Backup Settings", Width = 140 };
		Button restore = new() { Text = "Restore Registry/Policy", Width = 180 };

		_btnInstall.Click += async (_, _) => await InstallServiceAsync().ConfigureAwait(true);
		_btnUninstall.Click += async (_, _) => await RunLifecycleAsync(_btnUninstall, _runner.UninstallAsync, "RdpAudit Uninstall").ConfigureAwait(true);
		_btnStart.Click += async (_, _) => await RunLifecycleAsync(_btnStart, _runner.StartAsync, "RdpAudit Start").ConfigureAwait(true);
		_btnStop.Click += async (_, _) => await RunLifecycleAsync(_btnStop, _runner.StopAsync, "RdpAudit Stop").ConfigureAwait(true);
		_btnRestart.Click += async (_, _) => await RunLifecycleAsync(_btnRestart, _runner.RestartAsync, "RdpAudit Restart").ConfigureAwait(true);
		_btnUpdate.Click += async (_, _) => await UpdateInstalledFilesAsync().ConfigureAwait(true);
		_btnCopyDiagnostics.Click += async (_, _) => await CopyDiagnosticsAsync().ConfigureAwait(true);
		backup.Click += async (_, _) => await BackupAsync().ConfigureAwait(true);
		restore.Click += async (_, _) => await RestoreAsync().ConfigureAwait(true);

		buttons.Controls.AddRange(new Control[]
		{
			_btnInstall, _btnUninstall, _btnStart, _btnStop, _btnRestart, _btnUpdate, _btnCopyDiagnostics, backup, restore,
		});

		_process = new Label
		{
			Dock = DockStyle.Top,
			Height = 22,
			Text = "Process: probing…",
			AutoSize = false,
			TextAlign = ContentAlignment.MiddleLeft,
			Padding = new Padding(4, 2, 4, 2),
		};

		_stateLabel = new Label
		{
			Dock = DockStyle.Top,
			Height = 22,
			Text = "State: probing…",
			AutoSize = false,
			TextAlign = ContentAlignment.MiddleLeft,
			Padding = new Padding(4, 2, 4, 2),
		};

		_diagnostic = new Label
		{
			Dock = DockStyle.Top,
			Height = 36,
			Text = string.Empty,
			AutoSize = false,
			TextAlign = ContentAlignment.MiddleLeft,
			Padding = new Padding(4, 2, 4, 2),
			ForeColor = StatusWarning,
		};

		_status = new Label { Dock = DockStyle.Top, Height = 80, Text = "Connecting…", AutoSize = false };
		_layoutPanel = new TextBox
		{
			Dock = DockStyle.Top,
			Height = 180,
			Multiline = true,
			ReadOnly = true,
			ScrollBars = ScrollBars.Vertical,
			WordWrap = true,
			Font = new Font(FontFamily.GenericMonospace, 9f),
		};

		_alertsGrid = new DataGridView
		{
			Dock = DockStyle.Fill,
			AutoGenerateColumns = false,
			ReadOnly = true,
			RowHeadersVisible = false,
			AllowUserToAddRows = false,
			SelectionMode = DataGridViewSelectionMode.FullRowSelect,
		};
		_alertsGrid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Time (UTC)", DataPropertyName = nameof(Alert.TimeUtc), Width = 160 });
		_alertsGrid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Severity", DataPropertyName = nameof(Alert.Severity), Width = 90 });
		_alertsGrid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Rule", DataPropertyName = nameof(Alert.RuleId), Width = 200 });
		_alertsGrid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "User", DataPropertyName = nameof(Alert.UserName), Width = 160 });
		_alertsGrid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "IP", DataPropertyName = nameof(Alert.SourceIp), Width = 130 });
		_alertsGrid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Message", DataPropertyName = nameof(Alert.Message), AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill });

		_alertsGrid.CellFormatting += SeverityColoring;

		_alertsMenuOpenRipeStat = new ToolStripMenuItem(IpReputationBrowser.RipeStatMenuLabel, null, (_, _) => OnAlertsOpenRipeStat());
		_alertsMenuOpenAbuseIpDb = new ToolStripMenuItem(IpReputationBrowser.AbuseIpDbMenuLabel, null, (_, _) => OnAlertsOpenAbuseIpDb());
		_alertsMenu = new ContextMenuStrip();
		_alertsMenu.Items.Add(_alertsMenuOpenRipeStat);
		_alertsMenu.Items.Add(_alertsMenuOpenAbuseIpDb);
		_alertsMenu.Opening += OnAlertsMenuOpening;
		_alertsGrid.ContextMenuStrip = _alertsMenu;
		_alertsGrid.CellMouseDown += OnAlertsCellMouseDown;
		DataGridClipboardMenu.AppendTo(_alertsMenu, _alertsGrid);

		Controls.Add(_alertsGrid);
		Controls.Add(_layoutPanel);
		Controls.Add(_diagnostic);
		Controls.Add(_stateLabel);
		Controls.Add(_process);
		Controls.Add(_status);
		Controls.Add(buttons);

		_timer = new System.Windows.Forms.Timer { Interval = 5_000 };
		_timer.Tick += async (_, _) => await RefreshAsync().ConfigureAwait(true);
		HandleCreated += async (_, _) =>
		{
			_timer.Start();
			await RefreshAsync().ConfigureAwait(true);
		};
	}

	private static void SeverityColoring(object? sender, DataGridViewCellFormattingEventArgs e)
	{
		if (e.RowIndex < 0)
		{
			return;
		}

		DataGridView grid = (DataGridView)sender!;
		if (grid.Rows[e.RowIndex].DataBoundItem is not Alert alert)
		{
			return;
		}

		e.CellStyle!.BackColor = alert.Severity switch
		{
			AlertSeverity.Critical => RowDangerBack,
			AlertSeverity.High => RowWarningBack,
			AlertSeverity.Medium => Color.FromArgb(60, 60, 30),
			AlertSeverity.Low => Color.FromArgb(30, 45, 65),
			_ => CellBack,
		};
	}

	private async Task RefreshAsync()
	{
		// IPC telemetry runs first so the timer can keep "Events captured / Alerts raised"
		// fresh even when the user's WMI principal is throttled.
		ServiceStatus? ipcStatus = await _ipc.SendAsync<ServiceStatus>(IpcCommand.GetStatus).ConfigureAwait(true);
		List<Alert>? alerts = await _ipc.SendAsync<List<Alert>>(IpcCommand.GetRecentAlerts).ConfigureAwait(true);
		ServiceLayoutInfo layout = await Task.Run(() => ServiceLayout.Discover(AppContext.BaseDirectory)).ConfigureAwait(true);
		ServiceInstallationInfo scm = await _scmReader.ReadAsync().ConfigureAwait(true);

		string? installedExePath = scm.ResolveExecutablePath()
			?? Path.Combine(layout.InstallDirectory, ServiceLayout.ServiceExeName);
		string distributionExePath = layout.ExpectedServiceExecutable;

		BinaryFingerprint installedFingerprint = await Task.Run(() => BinaryFingerprintReader.Read(installedExePath)).ConfigureAwait(true);
		BinaryFingerprint distributionFingerprint = await Task.Run(() => BinaryFingerprintReader.Read(distributionExePath)).ConfigureAwait(true);

		ServiceStateView view = ServiceStateViewBuilder.Build(
			scm: scm,
			installed: installedFingerprint,
			distribution: distributionFingerprint,
			runtimeVersion: ipcStatus?.Version,
			ipcConnected: ipcStatus is not null);

		_status.Text = ipcStatus is null
			? "Service: not reachable (IPC GetStatus failed — start the service or run as administrator)"
			: $"Version (runtime): {ipcStatus.Version}\r\nUptime: {ipcStatus.Uptime}\r\nEvents captured: {ipcStatus.EventsCaptured} (dropped {ipcStatus.EventsDropped})\r\nAlerts raised: {ipcStatus.AlertsRaised}";
		_process.Text = view.ProcessLine;
		_stateLabel.Text = view.InstallStateLine;
		_diagnostic.Text = view.DiagnosticLine;
		_diagnostic.Visible = !string.IsNullOrEmpty(view.DiagnosticLine);
		_layoutPanel.Text = FormatLayout(layout, view);
		_alertsGrid.DataSource = alerts ?? new List<Alert>();
		UpdateButtonStates(view, layout);
	}

	/// <summary>Stage 2: button enablement derives from the authoritative SCM snapshot plus
	/// the installed/distribution binary comparison via <see cref="ServiceButtonStateModel"/>.
	/// Start/Stop no longer rely on locale-specific state strings, and the Update button is
	/// enabled only when the publish folder offers content that differs from the installed
	/// binary.</summary>
	private void UpdateButtonStates(ServiceStateView view, ServiceLayoutInfo layout)
	{
		bool distributionUsable = layout.DistributionExists && layout.ServiceExecutableExists;
		ServiceButtonState state = ServiceButtonStateModel.Compute(view.Scm, view.BinaryState, distributionUsable);
		_btnInstall.Enabled = state.Install;
		_btnUninstall.Enabled = state.Uninstall;
		_btnStart.Enabled = state.Start;
		_btnStop.Enabled = state.Stop;
		_btnRestart.Enabled = state.Restart;
		_btnUpdate.Enabled = state.Update;
	}

	private static string FormatLayout(ServiceLayoutInfo layout, ServiceStateView view)
	{
		string source = layout.DistributionDirectory ?? ServiceLayout.ResolveSiblingDistribution(layout.ConfiguratorDirectory);
		string distLine = layout.DistributionExists
			? (layout.ServiceExecutableExists
				? $"present (RdpAudit.Service.exe found at {layout.ExpectedServiceExecutable})"
				: $"present but missing executable {layout.ExpectedServiceExecutable}")
			: "NOT FOUND — sc install will refuse to run";

		string installedSrc = view.Scm.ResolveExecutablePath() ?? "(not registered with SCM)";
		string installedVer = view.Installed.FileVersion ?? "(unknown)";
		string installedHash = view.Installed.Sha256 is { Length: > 16 } h ? h[..16] : (view.Installed.Sha256 ?? "(unknown)");
		string distVer = view.Distribution.FileVersion ?? "(unknown)";
		string distHash = view.Distribution.Sha256 is { Length: > 16 } h2 ? h2[..16] : (view.Distribution.Sha256 ?? "(unknown)");
		string runtimeVer = view.RuntimeVersion ?? "(IPC unreachable)";

		return string.Format(CultureInfo.InvariantCulture,
			"Install destination: {0}\r\n"
			+ "  ImagePath (SCM):    {1}\r\n"
			+ "  Installed version:  {2}  sha256(16) {3}\r\n"
			+ "Database path:       {4}\r\n"
			+ "appsettings.json:    {5}\r\n"
			+ "\r\n"
			+ "Service distribution source\r\n"
			+ "  Configurator dir:   {6}\r\n"
			+ "  Distribution dir:   {7}\r\n"
			+ "  Status:             {8}\r\n"
			+ "  Distribution ver:   {9}  sha256(16) {10}\r\n"
			+ "\r\n"
			+ "Runtime service version (IPC): {11}",
			layout.InstallDirectory,
			installedSrc,
			installedVer,
			installedHash,
			layout.DefaultDatabasePath,
			layout.AppSettingsPath,
			layout.ConfiguratorDirectory,
			source,
			distLine,
			distVer,
			distHash,
			runtimeVer);
	}

	private async Task RunLifecycleAsync(
		Button trigger,
		Func<CancellationToken, Task<ServiceOperationResult>> action,
		string title)
	{
		trigger.Enabled = false;
		try
		{
			ServiceOperationResult result = await action(CancellationToken.None).ConfigureAwait(true);
			MessageBox.Show(result.Format(), title, MessageBoxButtons.OK,
				result.Success ? MessageBoxIcon.Information : MessageBoxIcon.Warning);
		}
		catch (Win32Exception ex) when (ex.NativeErrorCode == 1223)
		{
			MessageBox.Show("UAC was cancelled.", title, MessageBoxButtons.OK, MessageBoxIcon.Warning);
		}
		catch (Exception ex)
		{
			MessageBox.Show(ex.Message, title, MessageBoxButtons.OK, MessageBoxIcon.Error);
		}
		finally
		{
			// Re-enable the trigger temporarily; RefreshAsync below restores the correct
			// enabled state based on the authoritative SCM snapshot.
			trigger.Enabled = true;
		}

		await RefreshAsync().ConfigureAwait(true);
	}

	/// <summary>Discover the sibling Service distribution, copy it under Program Files,
	/// and register/start the Windows service via the shared <see cref="InstallationService"/>.</summary>
	private async Task InstallServiceAsync()
	{
		ServiceLayoutInfo layout = await Task.Run(() => ServiceLayout.Discover(AppContext.BaseDirectory)).ConfigureAwait(true);
		if (!layout.DistributionExists || !layout.ServiceExecutableExists)
		{
			MessageBox.Show(
				string.Format(CultureInfo.InvariantCulture,
					"Service distribution not found at:\r\n{0}\r\n"
					+ "Run publish.ps1 so the Configurator can copy {1} to {2}.",
					ServiceLayout.ResolveSiblingDistribution(layout.ConfiguratorDirectory),
					ServiceLayout.ServiceExeName,
					layout.InstallDirectory),
				"RdpAudit",
				MessageBoxButtons.OK,
				MessageBoxIcon.Warning);
			return;
		}

		InstallationService installer = new(layout);
		InstallationOutcome outcome = await installer.RunAsync().ConfigureAwait(true);

		System.Text.StringBuilder sb = new();
		foreach (string step in outcome.Steps)
		{
			sb.AppendLine("OK   " + step);
		}

		foreach (string warning in outcome.Warnings)
		{
			sb.AppendLine("WARN " + warning);
		}

		foreach (string error in outcome.Errors)
		{
			sb.AppendLine("FAIL " + error);
		}

		if (!string.IsNullOrEmpty(outcome.LogFilePath))
		{
			sb.AppendLine();
			sb.AppendLine("Log file: " + outcome.LogFilePath);
		}

		MessageBox.Show(sb.ToString(), "RdpAudit Install", MessageBoxButtons.OK,
			outcome.Success ? MessageBoxIcon.Information : MessageBoxIcon.Warning);
		await RefreshAsync().ConfigureAwait(true);
	}

	/// <summary>Stage 2 'Update installed files' button. Copies the sibling distribution over
	/// the configured install directory using <see cref="ServiceControlRunner.UpdateInstalledFilesAsync"/>,
	/// which performs a safe stop -&gt; copy -&gt; start cycle when the service is running.</summary>
	private async Task UpdateInstalledFilesAsync()
	{
		ServiceLayoutInfo layout = await Task.Run(() => ServiceLayout.Discover(AppContext.BaseDirectory)).ConfigureAwait(true);
		if (!layout.DistributionExists || !layout.ServiceExecutableExists)
		{
			MessageBox.Show(
				$"Distribution missing at {layout.ExpectedServiceExecutable}. Re-run publish.ps1 before updating.",
				"RdpAudit Update",
				MessageBoxButtons.OK,
				MessageBoxIcon.Warning);
			return;
		}

		_btnUpdate.Enabled = false;
		try
		{
			ServiceOperationResult result = await _runner
				.UpdateInstalledFilesAsync(layout.DistributionDirectory!, layout.InstallDirectory)
				.ConfigureAwait(true);
			MessageBox.Show(result.Format(), "RdpAudit Update", MessageBoxButtons.OK,
				result.Success ? MessageBoxIcon.Information : MessageBoxIcon.Warning);
		}
		catch (Exception ex)
		{
			MessageBox.Show(ex.Message, "RdpAudit Update", MessageBoxButtons.OK, MessageBoxIcon.Error);
		}
		finally
		{
			_btnUpdate.Enabled = true;
		}

		await RefreshAsync().ConfigureAwait(true);
	}

	/// <summary>Builds the Copy diagnostics report and pushes the rendered text onto the
	/// clipboard. Pulls the same SCM/IPC/binary inputs the Service tab already aggregates,
	/// plus a best-effort snapshot of the running service process (PID, MainModule path,
	/// SHA-256). Verdict and explanation come from <see cref="ServiceDiagnosticsReportBuilder"/>
	/// so the headline label stays in lockstep with the Service tab state line.</summary>
	private async Task CopyDiagnosticsAsync()
	{
		_btnCopyDiagnostics.Enabled = false;
		try
		{
			ServiceLayoutInfo layout = await Task.Run(() => ServiceLayout.Discover(AppContext.BaseDirectory)).ConfigureAwait(true);
			ServiceInstallationInfo scm = await _scmReader.ReadAsync().ConfigureAwait(true);
			ServiceStatus? ipcStatus = await _ipc.SendAsync<ServiceStatus>(IpcCommand.GetStatus).ConfigureAwait(true);

			string? installedExePath = scm.ResolveExecutablePath()
				?? Path.Combine(layout.InstallDirectory, ServiceLayout.ServiceExeName);
			string distributionExePath = layout.ExpectedServiceExecutable;

			BinaryFingerprint installedFingerprint = await Task.Run(() => BinaryFingerprintReader.Read(installedExePath)).ConfigureAwait(true);
			BinaryFingerprint distributionFingerprint = await Task.Run(() => BinaryFingerprintReader.Read(distributionExePath)).ConfigureAwait(true);
			RunningProcessFingerprint running = await Task.Run(() => RunningProcessProbe.Probe(scm.ProcessId)).ConfigureAwait(true);

			string configuratorVersion = ResolveConfiguratorVersion();
			ServiceDiagnosticsInput input = new(
				ConfiguratorVersion: configuratorVersion,
				Layout: layout,
				Scm: scm,
				Distribution: distributionFingerprint,
				Installed: installedFingerprint,
				Running: running,
				IpcRuntimeVersion: ipcStatus?.Version,
				IpcConnected: ipcStatus is not null);

			ServiceDiagnosticsReport report = ServiceDiagnosticsReportBuilder.Build(input);
			try
			{
				Clipboard.SetText(report.ReportText);
			}
			catch (Exception)
			{
				// Clipboard.SetText can throw on locked clipboard sessions; we still display
				// the report so the operator can copy it manually.
			}

			MessageBox.Show(report.ReportText,
				$"RdpAudit diagnostics — {report.VerdictLabel}",
				MessageBoxButtons.OK,
				report.Verdict == ServiceDiagnosticsVerdict.Ok
					? MessageBoxIcon.Information
					: MessageBoxIcon.Warning);
		}
		catch (Exception ex)
		{
			MessageBox.Show(ex.Message, "RdpAudit diagnostics", MessageBoxButtons.OK, MessageBoxIcon.Error);
		}
		finally
		{
			_btnCopyDiagnostics.Enabled = true;
		}
	}

	private static string ResolveConfiguratorVersion()
	{
		System.Reflection.Assembly asm = typeof(ServicePage).Assembly;
		string? info = asm
			.GetCustomAttribute<System.Reflection.AssemblyInformationalVersionAttribute>()?.InformationalVersion;
		if (!string.IsNullOrWhiteSpace(info))
		{
			int plus = info.IndexOf('+', StringComparison.Ordinal);
			return plus > 0 ? info[..plus] : info;
		}

		return asm.GetName().Version?.ToString() ?? "0.0.0";
	}

	private async Task BackupAsync()
	{
		try
		{
			ServiceLayoutInfo layout = await Task.Run(() => ServiceLayout.Discover(AppContext.BaseDirectory)).ConfigureAwait(true);
			BackupRunner runner = new(layout);
			BackupOutcome outcome = await runner.RunAsync(BackupReason.Manual).ConfigureAwait(true);
			ShowBackupOutcome(outcome);
		}
		catch (Exception ex)
		{
			MessageBox.Show(ex.Message, "RdpAudit Backup", MessageBoxButtons.OK, MessageBoxIcon.Error);
		}
	}

	private async Task RestoreAsync()
	{
		try
		{
			ServiceLayoutInfo layout = await Task.Run(() => ServiceLayout.Discover(AppContext.BaseDirectory)).ConfigureAwait(true);
			BackupRunner runner = new(layout);
			IReadOnlyList<string> snapshots = await Task.Run(runner.ListSnapshots).ConfigureAwait(true);
			if (snapshots.Count == 0)
			{
				MessageBox.Show(
					"No backup snapshots available. Use Backup Settings to create one first.",
					"RdpAudit Restore",
					MessageBoxButtons.OK,
					MessageBoxIcon.Information);
				return;
			}

			string selected = snapshots[0];
			string confirm = string.Format(CultureInfo.InvariantCulture,
				"Restore registry/SACL and audit policy settings from snapshot {0}?\r\n\r\n"
				+ "A pre-restore safety snapshot will be captured first. The audit event database is NOT modified.",
				selected);
			DialogResult choice = MessageBox.Show(
				confirm,
				"RdpAudit Restore",
				MessageBoxButtons.YesNo,
				MessageBoxIcon.Warning,
				MessageBoxDefaultButton.Button2);
			if (choice != DialogResult.Yes)
			{
				return;
			}

			RestoreRunner restorer = new(layout, runner);
			RestoreOutcome outcome = await restorer.RunAsync(selected, RestoreScope.PoliciesAndRegistry).ConfigureAwait(true);
			ShowRestoreOutcome(outcome, selected);
		}
		catch (Exception ex)
		{
			MessageBox.Show(ex.Message, "RdpAudit Restore", MessageBoxButtons.OK, MessageBoxIcon.Error);
		}
	}

	private static void ShowBackupOutcome(BackupOutcome outcome)
	{
		StringBuilder sb = new();
		sb.AppendLine("Snapshot folder:");
		sb.AppendLine("  " + outcome.Snapshot.SnapshotDirectory);
		sb.AppendLine();
		foreach (BackupStep step in outcome.Steps)
		{
			sb.Append(step.Ok ? "OK   " : "FAIL ");
			sb.Append(step.Description);
			if (!string.IsNullOrEmpty(step.Detail))
			{
				sb.Append(" — ").Append(step.Detail);
			}

			sb.AppendLine();
		}

		MessageBox.Show(sb.ToString(), "RdpAudit Backup",
			MessageBoxButtons.OK,
			outcome.Success ? MessageBoxIcon.Information : MessageBoxIcon.Warning);
	}

	private static void ShowRestoreOutcome(RestoreOutcome outcome, string snapshotName)
	{
		StringBuilder sb = new();
		sb.AppendLine("Source snapshot: " + snapshotName);
		sb.AppendLine("Safety snapshot:");
		sb.AppendLine("  " + outcome.SafetySnapshot.SnapshotDirectory);
		sb.AppendLine();
		foreach (RestoreStep step in outcome.Steps)
		{
			sb.Append(step.Ok ? "OK   " : "FAIL ");
			sb.Append(step.Description);
			if (!string.IsNullOrEmpty(step.Detail))
			{
				sb.Append(" — ").Append(step.Detail);
			}

			sb.AppendLine();
		}

		MessageBox.Show(sb.ToString(), "RdpAudit Restore",
			MessageBoxButtons.OK,
			outcome.Success ? MessageBoxIcon.Information : MessageBoxIcon.Warning);
	}

	private void OnAlertsCellMouseDown(object? sender, DataGridViewCellMouseEventArgs e)
	{
		if (e.Button != MouseButtons.Right || e.RowIndex < 0 || e.RowIndex >= _alertsGrid.RowCount)
		{
			_alertsMenuRow = null;
			return;
		}

		_alertsGrid.ClearSelection();
		_alertsGrid.Rows[e.RowIndex].Selected = true;
		_alertsMenuRow = _alertsGrid.Rows[e.RowIndex].DataBoundItem as Alert;
	}

	private void OnAlertsMenuOpening(object? sender, CancelEventArgs e)
	{
		bool eligible = _alertsMenuRow is not null
			&& IpReputationBrowser.IsLookupEligible(_alertsMenuRow.SourceIp);
		_alertsMenuOpenRipeStat.Enabled = eligible;
		_alertsMenuOpenAbuseIpDb.Enabled = eligible;
		if (_alertsMenuRow is null)
		{
			e.Cancel = true;
		}
	}

	private void OnAlertsOpenRipeStat()
	{
		if (_alertsMenuRow is null)
		{
			return;
		}

		IpReputationBrowser.OpenRipeStat(_alertsMenuRow.SourceIp);
	}

	private void OnAlertsOpenAbuseIpDb()
	{
		if (_alertsMenuRow is null)
		{
			return;
		}

		IpReputationBrowser.OpenAbuseIpDb(_alertsMenuRow.SourceIp);
	}

	protected override void Dispose(bool disposing)
	{
		if (disposing)
		{
			_timer.Dispose();
			_alertsMenu.Dispose();
		}

		base.Dispose(disposing);
	}
}
