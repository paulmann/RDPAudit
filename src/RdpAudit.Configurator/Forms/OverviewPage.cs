// File:    src/RdpAudit.Configurator/Forms/OverviewPage.cs
// Module:  RdpAudit.Configurator.Forms
// Purpose: Primary "home" tab: product info, project links, version, first-run
//          install button, a license-key activation panel, and a live status panel
//          summarising DB readiness, service installation state, and detected errors/warnings.
// Extends: System.Windows.Forms.TabPage. To change license behaviour, edit the nested LicensePanel
//          class below and the LicenseStore service; to add a KPI card, extend the cardsRow block.
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com
// Version: 1.4.4

using System.Diagnostics;
using System.Globalization;
using System.Reflection;
using System.Runtime.Versioning;
using System.Text;
using RdpAudit.Configurator.Ipc;
using RdpAudit.Configurator.Theming;
using RdpAudit.Configurator.Services;
using RdpAudit.Core.Backup;
using RdpAudit.Core.Ipc;
using RdpAudit.Core.Ipc.Contracts;
using RdpAudit.Core.Util;

namespace RdpAudit.Configurator.Forms;

/// <summary>Primary home tab: product info, links, version and first-run install button.</summary>
[SupportedOSPlatform("windows")]
public sealed class OverviewPage : TabPage
{
	private const string ProjectUrl = "https://github.com/paulmann/RDPAudit";
	private const string AuthorName = "Mikhail Deynekin";
	// Public product website shown on the Website link.
	private const string WebsiteUrl = "https://rdpaudit.com";
	// Storefront opened by the license panel's Buy button.
	private const string BuyUrl = "https://buy.rdpaudit.com/";
	private const string AuthorEmail = "rdp@deynekin.com";

	private readonly IpcClient? _ipc;
	private readonly Label _title;
	private readonly Label _purpose;
	private readonly Label _versionLabel;
	private readonly LinkLabel _projectLink;
	private readonly Label _authorLabel;
	private readonly LinkLabel _authorLink;
	private readonly LinkLabel _emailLink;
	private readonly TextBox _statusReport;
	private readonly Button _install;
	private readonly Button _refresh;
	private readonly Button _backup;
	private readonly Button _restore;
	private readonly Label _status;
	private readonly OverviewProbe _probe = new();
	private readonly LocalRdpSessionProvider _localSessions = new();
	private readonly SummaryCard _cardAttacksToday;
	private readonly SummaryCard _cardBlockedIps;
	private readonly SummaryCard _cardActiveSessions;
	private readonly SummaryCard _cardFailedLogins;
	private readonly SummaryCard _cardServiceHealth;
	private readonly SummaryCard _cardDbSize;
	private readonly ProgressBar _analysisBar;
	private readonly Label _analysisLabel;
	private readonly LicensePanel _license;
	private readonly System.Windows.Forms.Timer _progressTimer;

	public OverviewPage() : this(null)
	{
	}

	public OverviewPage(IpcClient? ipc)
	{
		_ipc = ipc;
		Text = "Overview";
		Padding = new Padding(12);
		AutoScroll = true;

		_title = new Label
		{
			Text = "RdpAudit — RDP & Logon Security Monitor",
			AutoSize = true,
			Font = new Font(SystemFonts.MessageBoxFont!.FontFamily, 14f, FontStyle.Bold),
			Location = new Point(12, 12),
		};

		_purpose = new Label
		{
			Text = "Monitors RDP, account, Kerberos and accessibility-backdoor events. "
				+ "The Configurator manages first-run installation, audit policy / SACL "
				+ "configuration, service lifecycle, and live event review.",
			AutoSize = false,
			Width = 1100,
			Height = 48,
			Location = new Point(12, 50),
		};

		_versionLabel = new Label
		{
			Text = $"Version: {GetProductVersion()}",
			AutoSize = true,
			Location = new Point(12, 104),
		};

		_projectLink = new LinkLabel
		{
			Text = "Project: " + ProjectUrl,
			AutoSize = true,
			Location = new Point(12, 128),
		};
		_projectLink.LinkArea = new LinkArea("Project: ".Length, ProjectUrl.Length);
		_projectLink.LinkClicked += (_, _) => OpenUrl(ProjectUrl);

		_authorLabel = new Label
		{
			Text = "Author: " + AuthorName,
			AutoSize = true,
			Location = new Point(12, 152),
		};

		_authorLink = new LinkLabel
		{
			Text = "Website: " + WebsiteUrl,
			AutoSize = true,
			Location = new Point(12, 176),
		};
		_authorLink.LinkArea = new LinkArea("Website: ".Length, WebsiteUrl.Length);
		_authorLink.LinkClicked += (_, _) => OpenUrl(WebsiteUrl);

		_emailLink = new LinkLabel
		{
			Text = "Email: " + AuthorEmail,
			AutoSize = true,
			Location = new Point(12, 200),
		};
		_emailLink.LinkArea = new LinkArea("Email: ".Length, AuthorEmail.Length);
		_emailLink.LinkClicked += (_, _) => OpenUrl("mailto:" + AuthorEmail);

		_install = new Button
		{
			Text = "Install / Repair",
			Width = 180,
			Height = 32,
			Location = new Point(12, 236),
		};
		_install.Click += async (_, _) => await OnInstallClickAsync().ConfigureAwait(true);

		_refresh = new Button
		{
			Text = "Refresh status",
			Width = 140,
			Height = 32,
			Location = new Point(200, 236),
		};
		_refresh.Click += async (_, _) => await RefreshAsync().ConfigureAwait(true);

		_backup = new Button
		{
			Text = "Backup Settings",
			Width = 160,
			Height = 32,
			Location = new Point(352, 236),
		};
		_backup.Click += async (_, _) => await OnBackupClickAsync().ConfigureAwait(true);

		_restore = new Button
		{
			Text = "Restore Registry/Policy Settings",
			Width = 260,
			Height = 32,
			Location = new Point(524, 236),
		};
		_restore.Click += async (_, _) => await OnRestoreClickAsync().ConfigureAwait(true);

		// License activation panel: sits between the action buttons and the KPI cards. Controls below
		// it are positioned LicensePanel.PanelHeight + a small gap lower to make room.
		_license = new LicensePanel
		{
			Width = 1100,
			Location = new Point(12, 278),
		};

		_cardAttacksToday = new SummaryCard("Attacks today", "—");
		_cardBlockedIps = new SummaryCard("Blocked IPs", "—");
		_cardActiveSessions = new SummaryCard("Active sessions", "—");
		_cardFailedLogins = new SummaryCard("Failed logins (24h)", "—");
		_cardServiceHealth = new SummaryCard("Service health", "—");
		_cardDbSize = new SummaryCard("DB size", "—");

		// Summary cards row: 6 equal-width cards spanning the same width as the existing status area.
		TableLayoutPanel cardsRow = new()
		{
			ColumnCount = 6,
			RowCount = 1,
			Width = 1100,
			Height = 96,
			Location = new Point(12, 436),
			Padding = new Padding(0),
			Margin = new Padding(0),
		};
		for (int i = 0; i < 6; i++)
		{
			cardsRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100f / 6));
		}
		cardsRow.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
		cardsRow.Controls.Add(_cardAttacksToday, 0, 0);
		cardsRow.Controls.Add(_cardBlockedIps, 1, 0);
		cardsRow.Controls.Add(_cardActiveSessions, 2, 0);
		cardsRow.Controls.Add(_cardFailedLogins, 3, 0);
		cardsRow.Controls.Add(_cardServiceHealth, 4, 0);
		cardsRow.Controls.Add(_cardDbSize, 5, 0);

		// Historical-analysis progress: lets the Overview tab open immediately and show that the
		// service is working through a large historical backlog (e.g. a 1 GB DB / >1M events) instead
		// of appearing hung. Driven by lightly polling GetOverviewProgress over IPC.
		_analysisLabel = new Label
		{
			Text = "Historical analysis: idle",
			AutoSize = false,
			Width = 1100,
			Height = 18,
			Location = new Point(12, 538),
		};
		_analysisBar = new ProgressBar
		{
			Width = 1100,
			Height = 16,
			Location = new Point(12, 558),
			Style = ProgressBarStyle.Continuous,
			Minimum = 0,
			Maximum = 100,
			Visible = false,
		};

		_status = new Label
		{
			Text = "Ready",
			AutoSize = false,
			Width = 1100,
			Height = 22,
			Location = new Point(12, 582),
		};

		_statusReport = new TextBox
		{
			Multiline = true,
			ScrollBars = ScrollBars.Vertical,
			ReadOnly = true,
			WordWrap = true,
			Font = new Font(FontFamily.GenericMonospace, 9.5f),
			Width = 1100,
			Height = 296,
			Location = new Point(12, 610),
		};

		Controls.Add(_title);
		Controls.Add(_purpose);
		Controls.Add(_versionLabel);
		Controls.Add(_projectLink);
		Controls.Add(_authorLabel);
		Controls.Add(_authorLink);
		Controls.Add(_emailLink);
		Controls.Add(_install);
		Controls.Add(_refresh);
		Controls.Add(_backup);
		Controls.Add(_restore);
		Controls.Add(_license);
		Controls.Add(cardsRow);
		Controls.Add(_analysisLabel);
		Controls.Add(_analysisBar);
		Controls.Add(_status);
		Controls.Add(_statusReport);

		_progressTimer = new System.Windows.Forms.Timer { Interval = 2_000 };
		_progressTimer.Tick += async (_, _) => await PollProgressAsync().ConfigureAwait(true);

		HandleCreated += async (_, _) =>
		{
			_progressTimer.Start();
			await RefreshAsync().ConfigureAwait(true);
			await PollProgressAsync().ConfigureAwait(true);
		};
		HandleDestroyed += (_, _) => _progressTimer.Stop();
	}

	/// <summary>Polls the service for historical-analysis progress and updates the progress bar.
	/// Best-effort: when the service is unreachable the bar simply hides. Never throws.</summary>
	private async Task PollProgressAsync()
	{
		if (_ipc is null)
		{
			return;
		}

		try
		{
			OverviewProgressDto? progress =
				await _ipc.SendAsync<OverviewProgressDto>(IpcCommand.GetOverviewProgress).ConfigureAwait(true);

			if (progress is null || progress.Status != IpcResultStatus.Success || !progress.IsRunning)
			{
				_analysisBar.Visible = false;
				_analysisLabel.Text = progress is { IsRunning: false }
					? "Historical analysis: idle" + (string.IsNullOrEmpty(progress.Message) ? string.Empty : " — " + progress.Message)
					: "Historical analysis: idle";
				return;
			}

			_analysisBar.Visible = true;
			if (progress.TotalRows > 0 && progress.Percent > 0)
			{
				_analysisBar.Style = ProgressBarStyle.Continuous;
				_analysisBar.Value = (int)Math.Clamp(progress.Percent, 0, 100);
				_analysisLabel.Text = string.Format(
					CultureInfo.InvariantCulture,
					"Historical analysis: {0} — {1:0}% ({2:N0}/{3:N0})",
					progress.Stage,
					progress.Percent,
					progress.ProcessedRows,
					progress.TotalRows);
			}
			else
			{
				// Total unknown by design (bounded backfill) — show marquee + processed count.
				_analysisBar.Style = ProgressBarStyle.Marquee;
				_analysisLabel.Text = string.Format(
					CultureInfo.InvariantCulture,
					"Historical analysis: {0} — {1:N0} processed{2}",
					progress.Stage,
					progress.ProcessedRows,
					string.IsNullOrEmpty(progress.CurrentChannel) ? string.Empty : " (" + progress.CurrentChannel + ")");
			}
		}
		catch (Exception)
		{
			_analysisBar.Visible = false;
		}
	}

	protected override void Dispose(bool disposing)
	{
		if (disposing)
		{
			_progressTimer.Dispose();
		}

		base.Dispose(disposing);
	}

	private static string GetProductVersion()
	{
		Assembly asm = Assembly.GetExecutingAssembly();
		string? info = asm.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion;
		if (!string.IsNullOrWhiteSpace(info))
		{
			int plus = info.IndexOf('+', StringComparison.Ordinal);
			return plus < 0 ? info : info[..plus];
		}

		return asm.GetName().Version?.ToString() ?? "0.0.0";
	}

	private static void OpenUrl(string url)
	{
		try
		{
			Process.Start(new ProcessStartInfo(url) { UseShellExecute = true });
		}
		catch (Exception ex)
		{
			MessageBox.Show($"Could not open {url}\r\n{ex.Message}", "RdpAudit", MessageBoxButtons.OK, MessageBoxIcon.Warning);
		}
	}

	private async Task RefreshAsync()
	{
		_refresh.Enabled = false;
		_status.Text = "Probing local state...";
		try
		{
			OverviewSnapshot snapshot = await Task.Run(() => _probe.Capture()).ConfigureAwait(true);
			_statusReport.Text = FormatSnapshot(snapshot);
			_install.Text = snapshot.IsFirstRun ? "Install (first run)" : "Repair / Reinstall";
			_status.Text = snapshot.IsFirstRun
				? "First-run setup required."
				: snapshot.Errors.Count > 0
					? "Issues detected — review the report below."
					: "RdpAudit looks healthy.";

			await RefreshSummaryCardsAsync(snapshot).ConfigureAwait(true);
		}
		catch (Exception ex)
		{
			_status.Text = "Probe failed: " + ex.GetType().Name;
			_statusReport.Text = ex.ToString();
		}
		finally
		{
			_refresh.Enabled = true;
		}
	}

	private async Task RefreshSummaryCardsAsync(OverviewSnapshot snapshot)
	{
		OverviewSummaryDto? summary = null;
		if (_ipc is not null)
		{
			try
			{
				summary = await _ipc.SendAsync<OverviewSummaryDto>(IpcCommand.GetOverviewSummary).ConfigureAwait(true);
			}
			catch (Exception ex)
			{
				_status.Text = "Overview summary unavailable: " + ex.GetType().Name;
			}
		}

		// Active sessions: prefer the value from the same orchestrator the Remote RDP Clients tab
		// uses so the cards stay consistent even when the service IPC is unreachable.
		(int? activeSessions, string activeSessionsSubtitle) = await CountActiveSessionsAsync(summary).ConfigureAwait(true);

		if (summary is null)
		{
			_cardAttacksToday.SetValue("—", "service unreachable");
			_cardBlockedIps.SetValue("—", "service unreachable");
			_cardActiveSessions.SetValue(
				activeSessions.HasValue ? activeSessions.Value.ToString("N0", CultureInfo.InvariantCulture) : "—",
				activeSessionsSubtitle);
			_cardFailedLogins.SetValue("—", "service unreachable");
			_cardServiceHealth.SetValue(snapshot.ServiceStatus, snapshot.ServiceInstalled ? "installed" : "not installed");
			_cardDbSize.SetValue(snapshot.DatabaseExists ? "see below" : "n/a", snapshot.DatabaseExists ? "snapshot pending" : "missing");
			return;
		}

		_cardAttacksToday.SetValue(
			summary.AttacksToday.ToString("N0", CultureInfo.InvariantCulture),
			"alerts since 00:00 UTC");
		_cardBlockedIps.SetValue(
			summary.BlockedIps.ToString("N0", CultureInfo.InvariantCulture),
			"active firewall blocks");
		_cardActiveSessions.SetValue(
			(activeSessions ?? summary.ActiveSessions).ToString("N0", CultureInfo.InvariantCulture),
			activeSessionsSubtitle);
		_cardFailedLogins.SetValue(
			summary.FailedLogins24h.ToString("N0", CultureInfo.InvariantCulture),
			"event id 4625, last 24 hours");
		_cardServiceHealth.SetValue(
			string.IsNullOrEmpty(summary.ServiceHealth) ? snapshot.ServiceStatus : summary.ServiceHealth,
			summary.Status == IpcResultStatus.Success ? "service IPC OK" : "see status report");
		_cardDbSize.SetValue(
			FormatBytes(summary.DatabaseSizeBytes),
			FormatGrowth(summary));
	}

	/// <summary>Resolves the "Active sessions" card value. When the service summary is
	/// available and reports a non-zero count, the IPC value is preferred; otherwise the
	/// Configurator falls back to the same <see cref="LocalRdpSessionProvider"/> the
	/// Remote RDP Clients tab uses so the two surfaces never disagree.</summary>
	private async Task<(int? Count, string Subtitle)> CountActiveSessionsAsync(OverviewSummaryDto? summary)
	{
		bool ipcUsable = summary is not null && summary.Status == IpcResultStatus.Success && summary.ActiveSessions > 0;
		if (ipcUsable)
		{
			return ((int)summary!.ActiveSessions, "RDP sessions in Active state (service IPC)");
		}

		try
		{
			LocalSessionFallbackResult fallback = await _localSessions
				.FetchForOrchestratorAsync(CancellationToken.None)
				.ConfigureAwait(true);
			if (fallback.Success)
			{
				int count = ActiveSessionCounter.CountActiveUserSessions(fallback.Sessions);
				string subtitle = summary is null
					? "RDP sessions in Active state (local fallback)"
					: "RDP sessions in Active state (local fallback; IPC reported 0)";
				return (count, subtitle);
			}
		}
		catch (Exception)
		{
			// Swallow — the card will show "—" with the unreachable subtitle below.
		}

		return summary is null
			? ((int?)null, "service unreachable")
			: ((int)summary.ActiveSessions, "RDP sessions in Active state (service IPC reported 0)");
	}

	private static string FormatBytes(long bytes)
	{
		if (bytes < 0)
		{
			return "n/a";
		}
		double value = bytes;
		string[] units = { "B", "KB", "MB", "GB", "TB" };
		int unit = 0;
		while (value >= 1024.0 && unit < units.Length - 1)
		{
			value /= 1024.0;
			unit++;
		}
		return string.Format(CultureInfo.InvariantCulture, "{0:0.##} {1}", value, units[unit]);
	}

	private static string FormatGrowth(OverviewSummaryDto s)
	{
		StringBuilder sb = new();
		AppendGrowth(sb, "d", s.DatabaseGrowthBytesDay);
		AppendGrowth(sb, "w", s.DatabaseGrowthBytesWeek);
		AppendGrowth(sb, "m", s.DatabaseGrowthBytesMonth);
		return sb.Length == 0 ? "snapshot pending (24h required)" : "growth " + sb.ToString().TrimEnd();
	}

	private static void AppendGrowth(StringBuilder sb, string label, long? bytes)
	{
		if (!bytes.HasValue)
		{
			return;
		}
		string sign = bytes.Value >= 0 ? "+" : "-";
		sb.Append(label).Append(':').Append(sign).Append(FormatBytes(Math.Abs(bytes.Value))).Append(' ');
	}

	private async Task OnInstallClickAsync()
	{
		_install.Enabled = false;
		_status.Text = "Running first-run install...";
		try
		{
			OverviewSnapshot snapshot = await Task.Run(() => _probe.Capture()).ConfigureAwait(true);
			InstallationService installer = new(snapshot.Layout);
			InstallationOutcome outcome = await installer.RunAsync().ConfigureAwait(true);

			StringBuilder sb = new();
			sb.AppendLine("=== Install steps ===");
			foreach (string step in outcome.Steps)
			{
				sb.AppendLine("- " + step);
			}

			if (outcome.Warnings.Count > 0)
			{
				sb.AppendLine();
				sb.AppendLine("=== Warnings ===");
				foreach (string w in outcome.Warnings)
				{
					sb.AppendLine("- " + w);
				}
			}

			if (outcome.Errors.Count > 0)
			{
				sb.AppendLine();
				sb.AppendLine("=== Errors ===");
				foreach (string e in outcome.Errors)
				{
					sb.AppendLine("- " + e);
				}
			}

			_statusReport.Text = sb.ToString();
			_status.Text = outcome.Success
				? "Installation completed."
				: "Installation finished with errors — see report.";
		}
		catch (Exception ex)
		{
			_status.Text = "Install failed: " + ex.GetType().Name;
			_statusReport.Text = ex.ToString();
		}
		finally
		{
			_install.Enabled = true;
			await RefreshAsync().ConfigureAwait(true);
		}
	}

	private async Task OnBackupClickAsync()
	{
		_backup.Enabled = false;
		_status.Text = "Capturing backup snapshot...";
		try
		{
			OverviewSnapshot snapshot = await Task.Run(() => _probe.Capture()).ConfigureAwait(true);
			BackupRunner runner = new(snapshot.Layout);
			BackupOutcome outcome = await runner.RunAsync(BackupReason.Manual).ConfigureAwait(true);

			StringBuilder sb = new();
			sb.AppendLine("=== Backup snapshot ===");
			sb.AppendLine("Folder: " + outcome.Snapshot.SnapshotDirectory);
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

			_statusReport.Text = sb.ToString();
			_status.Text = outcome.Success
				? "Backup completed: " + outcome.Snapshot.SnapshotDirectory
				: "Backup completed with errors — see report.";
		}
		catch (Exception ex)
		{
			_status.Text = "Backup failed: " + ex.GetType().Name;
			_statusReport.Text = ex.ToString();
		}
		finally
		{
			_backup.Enabled = true;
		}
	}

	private async Task OnRestoreClickAsync()
	{
		_restore.Enabled = false;
		_status.Text = "Preparing restore...";
		try
		{
			OverviewSnapshot snapshot = await Task.Run(() => _probe.Capture()).ConfigureAwait(true);
			BackupRunner runner = new(snapshot.Layout);
			IReadOnlyList<string> available = await Task.Run(runner.ListSnapshots).ConfigureAwait(true);
			if (available.Count == 0)
			{
				MessageBox.Show(
					"No backup snapshots are available yet. Use the Backup Settings button to capture one first.",
					"RdpAudit Restore",
					MessageBoxButtons.OK,
					MessageBoxIcon.Information);
				_status.Text = "Restore cancelled — no snapshots available.";
				return;
			}

			string selected = available[0];
			string confirm = string.Format(CultureInfo.InvariantCulture,
				"Restore registry/SACL and audit policy settings from snapshot {0}?\r\n\r\n"
				+ "A pre-restore safety snapshot will be captured automatically. The audit "
				+ "event database is NOT modified. Continue?",
				selected);
			DialogResult choice = MessageBox.Show(
				confirm,
				"RdpAudit Restore",
				MessageBoxButtons.YesNo,
				MessageBoxIcon.Warning,
				MessageBoxDefaultButton.Button2);
			if (choice != DialogResult.Yes)
			{
				_status.Text = "Restore cancelled by user.";
				return;
			}

			RestoreRunner restoreRunner = new(snapshot.Layout, runner);
			RestoreOutcome outcome = await restoreRunner.RunAsync(selected, RestoreScope.PoliciesAndRegistry).ConfigureAwait(true);

			StringBuilder sb = new();
			sb.AppendLine("=== Restore ===");
			sb.AppendLine("Source snapshot: " + selected);
			sb.AppendLine("Safety snapshot: " + outcome.SafetySnapshot.SnapshotDirectory);
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

			_statusReport.Text = sb.ToString();
			_status.Text = outcome.Success
				? "Restore completed."
				: "Restore completed with errors — see report.";
		}
		catch (Exception ex)
		{
			_status.Text = "Restore failed: " + ex.GetType().Name;
			_statusReport.Text = ex.ToString();
		}
		finally
		{
			_restore.Enabled = true;
		}
	}

		/// <summary>License-key activation panel shown on the Overview tab. In the UNACTIVATED state it shows
		/// a key input, an Activate button and a Buy button, plus the trial-notice text below the input; once
		/// activated it shows the stored key plus a Delete License Key button that returns to the input state.
		/// Activation is performed server-side via <see cref="LicenseStore.ActivateOnlineAsync"/>: the key is
		/// POSTed to the activation endpoint and accepted only when the server answers "1".</summary>
		private sealed class LicensePanel : GroupBox
		{
			// ── Fields ───────────────────────────────────────────────────────────────
			public const int PanelHeight = 150;

			private readonly LicenseStore _store = new();
			private readonly TextBox _keyInput;
			private readonly Button _activate;
			private readonly Button _buy;
			private readonly Label _trialInfo;
			private readonly Label _activeKeyCaption;
			private readonly TextBox _activeKey;
			private readonly Button _delete;
			private readonly Label _statusLabel;

			// ── Construction ────────────────────────────────────────────────────────
			public LicensePanel()
			{
				Text = "Product license";
				Height = PanelHeight;
				Padding = new Padding(10, 6, 10, 6);

				// Unactivated controls.
				_keyInput = new TextBox
				{
					Location = new Point(14, 30),
					Width = 420,
					Font = new Font(FontFamily.GenericMonospace, 10f),
					PlaceholderText = "Enter your license key",
				};
				_keyInput.KeyDown += async (_, e) =>
				{
					if (e.KeyCode == Keys.Enter)
					{
						e.Handled = true;
						e.SuppressKeyPress = true;
						await OnActivateClickAsync().ConfigureAwait(true);
					}
				};

				_activate = new Button
				{
					Text = "Activate",
					Location = new Point(446, 28),
					Width = 120,
					Height = 28,
				};
				_activate.Click += async (_, _) => await OnActivateClickAsync().ConfigureAwait(true);

				_buy = new Button
				{
					Text = "Buy",
					Location = new Point(576, 28),
					Width = 100,
					Height = 28,
					// Success face: DarkTheme recognises this semantic colour and keeps it during theming.
					BackColor = DarkTheme.SuccessAccent,
				};
				_buy.Click += (_, _) => OpenUrl(BuyUrl);

				// Trial notice shown only in the unactivated state, wrapped under the input row.
				_trialInfo = new Label
				{
					Text = "RDPAudit is distributed on a \"try before you buy\" basis. You are welcome to evaluate all features free of charge for 40 days. Following this trial period, a valid license is required to continue using the software legally. If you choose not to purchase a license, please remove it from your system. Thank you for respecting the developers' work!",
					Location = new Point(14, 64),
					Width = 1060,
					Height = 70,
					AutoSize = false,
					ForeColor = DarkTheme.TextSecondary,
				};

				// Activated controls.
				_activeKeyCaption = new Label
				{
					Text = "Activated key:",
					AutoSize = true,
					Location = new Point(14, 34),
				};
				_activeKey = new TextBox
				{
					Location = new Point(110, 30),
					Width = 420,
					ReadOnly = true,
					Font = new Font(FontFamily.GenericMonospace, 10f, FontStyle.Bold),
				};
				_delete = new Button
				{
					Text = "Delete License Key",
					Location = new Point(544, 28),
					Width = 180,
					Height = 28,
					// Danger face: DarkTheme recognises this semantic colour and keeps it during theming.
					BackColor = DarkTheme.DangerButton,
				};
				_delete.Click += (_, _) => OnDeleteClick();

				_statusLabel = new Label
				{
					AutoSize = true,
					Location = new Point(692, 34),
					ForeColor = DarkTheme.StatusSuccess,
				};

				Controls.Add(_keyInput);
				Controls.Add(_activate);
				Controls.Add(_buy);
				Controls.Add(_trialInfo);
				Controls.Add(_activeKeyCaption);
				Controls.Add(_activeKey);
				Controls.Add(_delete);
				Controls.Add(_statusLabel);

				ApplyState(_store.Load());
			}

			// ── Core Logic ────────────────────────────────────────────────────────────

			/// <summary>Validates the typed key and activates it against the server. Empty input is rejected
			/// inline; otherwise the outcome message reflects the server verdict or the failure reason.</summary>
			private async Task OnActivateClickAsync()
			{
				string key = _keyInput.Text.Trim();
				if (key.Length == 0)
				{
					_statusLabel.ForeColor = DarkTheme.StatusWarning;
					_statusLabel.Text = "Enter a license key first.";
					return;
				}

				_activate.Enabled = false;
				_keyInput.Enabled = false;
				_statusLabel.ForeColor = DarkTheme.TextSecondary;
				_statusLabel.Text = "Activating…";
				try
				{
					ActivationResult result = await _store.ActivateOnlineAsync(key).ConfigureAwait(true);
					switch (result)
					{
						case ActivationResult.Activated:
							ApplyState(key);
							break;

						case ActivationResult.InvalidKey:
							_statusLabel.ForeColor = DarkTheme.StatusDanger;
							_statusLabel.Text = "Invalid license key.";
							break;

						case ActivationResult.EmptyResponse:
							_statusLabel.ForeColor = DarkTheme.StatusDanger;
							_statusLabel.Text = "Activation server returned no answer. Please try again later.";
							break;

						default:
							_statusLabel.ForeColor = DarkTheme.StatusDanger;
							_statusLabel.Text = "Could not reach the activation server. Check your connection and try again.";
							break;
					}
				}
				finally
				{
					_activate.Enabled = true;
					_keyInput.Enabled = true;
				}
			}

			/// <summary>Clears the stored key and returns the panel to the unactivated input state.</summary>
			private void OnDeleteClick()
			{
				_store.Clear();
				_keyInput.Text = string.Empty;
				ApplyState(null);
			}

			/// <summary>Switches the panel between the unactivated (input + Activate + Buy + trial notice) and
			/// activated (key + Delete) layouts. A non-null, non-empty <paramref name="activeKey"/> selects the
			/// activated state.</summary>
			private void ApplyState(string? activeKey)
			{
				bool isActivated = !string.IsNullOrWhiteSpace(activeKey);

				_keyInput.Visible = !isActivated;
				_activate.Visible = !isActivated;
				_buy.Visible = !isActivated;
				_trialInfo.Visible = !isActivated;

				_activeKeyCaption.Visible = isActivated;
				_activeKey.Visible = isActivated;
				_delete.Visible = isActivated;

				if (isActivated)
				{
					_activeKey.Text = activeKey ?? string.Empty;
					_statusLabel.ForeColor = DarkTheme.StatusSuccess;
					_statusLabel.Text = "Activated.";
				}
				else
				{
					_statusLabel.Text = string.Empty;
				}
			}
		}

	/// <summary>Compact, DPI-friendly KPI card used on the Overview tab.</summary>
	private sealed class SummaryCard : Panel
	{
		private readonly Label _caption;
		private readonly Label _value;
		private readonly Label _subtitle;

		public SummaryCard(string caption, string initialValue)
		{
			Dock = DockStyle.Fill;
			Margin = new Padding(4);
			Padding = new Padding(8);
			BorderStyle = BorderStyle.FixedSingle;
			BackColor = SystemColors.Window;

			_caption = new Label
			{
				Text = caption,
				Dock = DockStyle.Top,
				Height = 18,
				ForeColor = SystemColors.GrayText,
				Font = new Font(SystemFonts.MessageBoxFont!, FontStyle.Regular),
			};
			_subtitle = new Label
			{
				Text = string.Empty,
				Dock = DockStyle.Bottom,
				Height = 16,
				ForeColor = SystemColors.GrayText,
				Font = new Font(SystemFonts.MessageBoxFont!.FontFamily, 8f, FontStyle.Regular),
			};
			_value = new Label
			{
				Text = initialValue,
				Dock = DockStyle.Fill,
				TextAlign = ContentAlignment.MiddleLeft,
				Font = new Font(SystemFonts.MessageBoxFont!.FontFamily, 14f, FontStyle.Bold),
			};

			Controls.Add(_value);
			Controls.Add(_subtitle);
			Controls.Add(_caption);
		}

		public void SetValue(string value, string subtitle)
		{
			if (InvokeRequired)
			{
				BeginInvoke(new Action(() =>
				{
					_value.Text = value;
					_subtitle.Text = subtitle;
				}));
				return;
			}

			_value.Text = value;
			_subtitle.Text = subtitle;
		}
	}

	private static string FormatSnapshot(OverviewSnapshot s)
	{
		StringBuilder sb = new();
		sb.AppendLine("=== Installation status ===");
		sb.AppendLine(string.Format(CultureInfo.InvariantCulture, "First-run required: {0}", s.IsFirstRun));
		sb.AppendLine(string.Format(CultureInfo.InvariantCulture, "ProgramData folder: {0} (writable={1})", s.Layout.ProgramDataDirectory, s.ProgramDataWritable));
		sb.AppendLine(string.Format(CultureInfo.InvariantCulture, "appsettings.json:   {0} ({1})", s.Layout.AppSettingsPath, s.AppSettingsExists ? "present" : "missing"));
		sb.AppendLine(string.Format(CultureInfo.InvariantCulture, "Database path:      {0} ({1})", s.DatabasePath, s.DatabaseExists ? "present" : "missing"));
		sb.AppendLine();
		sb.AppendLine("=== Service ===");
		sb.AppendLine(string.Format(CultureInfo.InvariantCulture, "Installed:    {0}", s.ServiceInstalled));
		sb.AppendLine(string.Format(CultureInfo.InvariantCulture, "Status:       {0}", s.ServiceStatus));
		sb.AppendLine(string.Format(CultureInfo.InvariantCulture, "Install dir:  {0}", s.Layout.InstallDirectory));
		sb.AppendLine();
		sb.AppendLine("=== Service distribution discovery ===");
		sb.AppendLine(string.Format(CultureInfo.InvariantCulture, "Configurator dir:  {0}", s.Layout.ConfiguratorDirectory));
		sb.AppendLine(string.Format(CultureInfo.InvariantCulture, "Distribution dir:  {0}", s.Layout.DistributionDirectory ?? "(not found)"));
		sb.AppendLine(string.Format(CultureInfo.InvariantCulture, "Service exe:       {0} ({1})", s.Layout.ExpectedServiceExecutable, s.Layout.ServiceExecutableExists ? "present" : "missing"));
		if (s.Warnings.Count > 0)
		{
			sb.AppendLine();
			sb.AppendLine("=== Warnings ===");
			foreach (string w in s.Warnings)
			{
				sb.AppendLine("- " + w);
			}
		}

		if (s.Errors.Count > 0)
		{
			sb.AppendLine();
			sb.AppendLine("=== Errors ===");
			foreach (string e in s.Errors)
			{
				sb.AppendLine("- " + e);
			}
		}

		return sb.ToString();
	}
}
