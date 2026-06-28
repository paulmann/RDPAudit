// File:    src/RdpAudit.Configurator/Forms/AbuseIpDbPage.cs
// Module:  RdpAudit.Configurator.Forms
// Purpose: Stage 8 AbuseIPDB Configurator tab. Lets the operator paste an API key, save it via the
//          service IPC (which DPAPI-protects the value before persistence), test the key against a
//          safe read-only AbuseIPDB endpoint, and toggle outbound abuse reporting. Shows status,
//          rate-limit information, last result, total report counters and a privacy / third-party
//          warning. Never displays the API key plaintext — only a "configured / not configured"
//          state with optional last-4 hint when the user types a fresh key locally.
// Extends: System.Windows.Forms.TabPage
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Globalization;
using System.Runtime.Versioning;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using RdpAudit.Configurator.Controls;
using RdpAudit.Configurator.Ipc;
using RdpAudit.Configurator.Services;
using RdpAudit.Core.Ipc;
using RdpAudit.Core.Ipc.Contracts;
using RdpAudit.Core.Models;
using RdpAudit.Core.Util;

using static RdpAudit.Configurator.Theming.DarkTheme;

namespace RdpAudit.Configurator.Forms;

/// <summary>Stage 8 AbuseIPDB Configurator tab.</summary>
[SupportedOSPlatform("windows")]
public sealed class AbuseIpDbPage : TabPage
{
	private const string IntroText =
		"AbuseIPDB (https://www.abuseipdb.com) is a community-driven IP reputation database. "
		+ "When enabled, this Configurator will instruct the RdpAudit service to report hostile "
		+ "RDP attack sources — including the source IP, attack-time metadata, attempted "
		+ "usernames and aggregate counts — to AbuseIPDB over HTTPS.\r\n\r\n"
		+ "Privacy & security:\r\n"
		+ "  • The submitted comment NEVER includes passwords, tokens or command-line content.\r\n"
		+ "  • The submitted comment NEVER includes local credentials.\r\n"
		+ "  • Reports are deduplicated (15 minutes minimum) and rate-limited per hour/day.\r\n"
		+ "  • Whitelisted IPs are never reported.\r\n"
		+ "  • The API key is encrypted at rest via Windows DPAPI before persistence.\r\n\r\n"
		+ "How to obtain an API key:\r\n"
		+ "  1. Create an AbuseIPDB account at https://www.abuseipdb.com/register.\r\n"
		+ "  2. Open the API section and copy your personal v2 API key (80 hex characters).\r\n"
		+ "  3. Paste it into the field below.\r\n"
		+ "  4. Click Save settings, then optionally Test key.\r\n"
		+ "  5. Tick 'Report attacks to AbuseIPDB' once the test passes.";

	private readonly IpcClient _ipc;

	private readonly TextBox _intro;
	private readonly TextBox _apiKeyInput;
	private readonly CheckBox _showKey;
	private readonly CheckBox _reportEnabled;
	private readonly CheckBox _dedupeEnabled;
	private readonly NumericUpDown _cooldownHours;
	private readonly Button _saveButton;
	private readonly Button _testButton;
	private readonly Button _refreshButton;
	private readonly Button _clearButton;
	private readonly Label _statusLabel;
	private readonly Label _credentialLabel;
	private readonly Label _endpointLabel;
	private readonly Label _countersLabel;
	private readonly Label _lastResultLabel;
	private readonly Label _rateLimitLabel;

	private readonly DataGridView _reportLogGrid;
	private readonly SortableBindingList<ReportLogRow> _reportLogRows = new();
	private readonly Button _logRefreshButton;
	private readonly Button _logCopyButton;
	private readonly Button _logOpenButton;
	private readonly Label _logStatusLabel;

	private bool _credentialPresentOnService;

	public AbuseIpDbPage(IpcClient ipc)
	{
		ArgumentNullException.ThrowIfNull(ipc);
		_ipc = ipc;
		Text = "AbuseIPDB";

		_intro = new TextBox
		{
			Multiline = true,
			ReadOnly = true,
			ScrollBars = ScrollBars.Vertical,
			Dock = DockStyle.Top,
			Height = 220,
			Text = IntroText,
			WordWrap = true,
			BackColor = SystemColors.Info,
		};

		_apiKeyInput = new TextBox
		{
			Dock = DockStyle.Fill,
			UseSystemPasswordChar = true,
			PlaceholderText = "Paste your AbuseIPDB API key here (80 hex characters)",
		};

		_showKey = new CheckBox
		{
			Text = "Show key",
			AutoSize = true,
		};
		_showKey.CheckedChanged += (_, _) => _apiKeyInput.UseSystemPasswordChar = !_showKey.Checked;

		_reportEnabled = new CheckBox
		{
			Text = "Report attacks to AbuseIPDB (only enabled after a key is saved)",
			AutoSize = true,
			Enabled = false,
		};

		_cooldownHours = new NumericUpDown
		{
			Minimum = 1,
			Maximum = 8760,
			Value = 24,
			Width = 90,
			Enabled = false,
		};

		_dedupeEnabled = new CheckBox
		{
			Text = "1 report per 1 IP",
			AutoSize = true,
		};
		_dedupeEnabled.CheckedChanged += (_, _) => _cooldownHours.Enabled = _dedupeEnabled.Checked;

		_saveButton = new Button { Text = "Save settings", Width = 140 };
		_saveButton.Click += async (_, _) => await OnSaveAsync().ConfigureAwait(true);

		_testButton = new Button { Text = "Test key", Width = 120, Enabled = false };
		_testButton.Click += async (_, _) => await OnTestAsync().ConfigureAwait(true);

		_refreshButton = new Button { Text = "Refresh status", Width = 140 };
		_refreshButton.Click += async (_, _) => await RefreshAsync().ConfigureAwait(true);

		_clearButton = new Button { Text = "Clear key", Width = 120 };
		_clearButton.Click += async (_, _) => await OnClearAsync().ConfigureAwait(true);

		_statusLabel = new Label { Text = "Loading…", AutoSize = false, Dock = DockStyle.Fill, TextAlign = ContentAlignment.MiddleLeft };
		_credentialLabel = new Label { Text = "Credential: ?", AutoSize = false, Dock = DockStyle.Fill, TextAlign = ContentAlignment.MiddleLeft };
		_endpointLabel = new Label { Text = "Endpoint: (loading)", AutoSize = false, Dock = DockStyle.Fill, TextAlign = ContentAlignment.MiddleLeft };
		_countersLabel = new Label { Text = "Reports: 0 total / 0 hour / 0 day", AutoSize = false, Dock = DockStyle.Fill, TextAlign = ContentAlignment.MiddleLeft };
		_lastResultLabel = new Label { Text = "Last result: (none)", AutoSize = false, Dock = DockStyle.Fill, TextAlign = ContentAlignment.MiddleLeft };
		_rateLimitLabel = new Label { Text = "Rate-limit: ok", AutoSize = false, Dock = DockStyle.Fill, TextAlign = ContentAlignment.MiddleLeft };

		_reportLogGrid = BuildReportLogGrid();
		_reportLogGrid.DataSource = _reportLogRows;

		_logRefreshButton = new Button { Text = "Refresh log", Width = 120 };
		_logRefreshButton.Click += async (_, _) => await RefreshReportLogAsync().ConfigureAwait(true);

		_logCopyButton = new Button { Text = "Copy report text", Width = 140 };
		_logCopyButton.Click += (_, _) => OnCopySelectedReport();

		_logOpenButton = new Button { Text = "Open in AbuseIPDB", Width = 160 };
		_logOpenButton.Click += (_, _) => OnOpenSelectedInAbuseIpDb();

		_logStatusLabel = new Label { Text = "Report log: (not loaded)", AutoSize = false, Dock = DockStyle.Fill, TextAlign = ContentAlignment.MiddleLeft };

		Panel statusPanel = BuildStatusPanel();
		Panel formPanel = BuildFormPanel();
		Panel logPanel = BuildReportLogPanel();

		// Fill control must be added before docked-top controls so it occupies the remaining area.
		Controls.Add(logPanel);
		Controls.Add(formPanel);
		Controls.Add(statusPanel);
		Controls.Add(_intro);

		HandleCreated += async (_, _) =>
		{
			await RefreshAsync().ConfigureAwait(true);
			await RefreshReportLogAsync().ConfigureAwait(true);
		};
	}

	private Panel BuildFormPanel()
	{
		Panel panel = new() { Dock = DockStyle.Top, Height = 220, Padding = new Padding(8) };

		TableLayoutPanel layout = new()
		{
			Dock = DockStyle.Fill,
			ColumnCount = 3,
			RowCount = 6,
		};
		layout.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 130));
		layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
		layout.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 140));
		for (int i = 0; i < 6; i++)
		{
			layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 32));
		}

		layout.Controls.Add(new Label { Text = "API key:", Dock = DockStyle.Fill, TextAlign = ContentAlignment.MiddleLeft }, 0, 0);
		layout.Controls.Add(_apiKeyInput, 1, 0);
		layout.Controls.Add(_showKey, 2, 0);

		layout.Controls.Add(new Label { Text = string.Empty, Dock = DockStyle.Fill }, 0, 1);
		layout.Controls.Add(_reportEnabled, 1, 1);

		// Dedupe row: "1 report per 1 IP" + cooldown hours.
		FlowLayoutPanel dedupeRow = new() { Dock = DockStyle.Fill, FlowDirection = FlowDirection.LeftToRight, WrapContents = false };
		dedupeRow.Controls.Add(_dedupeEnabled);
		dedupeRow.Controls.Add(new Label
		{
			Text = "Cooldown hours before reporting same IP again",
			AutoSize = true,
			TextAlign = ContentAlignment.MiddleLeft,
			Margin = new Padding(12, 6, 4, 0),
		});
		dedupeRow.Controls.Add(_cooldownHours);
		layout.Controls.Add(dedupeRow, 1, 2);
		layout.SetColumnSpan(dedupeRow, 2);

		FlowLayoutPanel buttons = new() { Dock = DockStyle.Fill, FlowDirection = FlowDirection.LeftToRight };
		buttons.Controls.Add(_saveButton);
		buttons.Controls.Add(_testButton);
		buttons.Controls.Add(_refreshButton);
		buttons.Controls.Add(_clearButton);
		layout.Controls.Add(buttons, 1, 3);

		Label warning = new()
		{
			Text =
				"WARNING: reports are sent to a third-party service (https://api.abuseipdb.com) and include "
				+ "the source IP and attack metadata.",
			Dock = DockStyle.Fill,
			TextAlign = ContentAlignment.MiddleLeft,
			ForeColor = StatusDanger,
			AutoSize = false,
		};
		layout.Controls.Add(warning, 0, 4);
		layout.SetColumnSpan(warning, 3);

		layout.Controls.Add(_statusLabel, 0, 5);
		layout.SetColumnSpan(_statusLabel, 3);

		panel.Controls.Add(layout);
		return panel;
	}

	private Panel BuildStatusPanel()
	{
		Panel panel = new() { Dock = DockStyle.Top, Height = 130, Padding = new Padding(8) };

		TableLayoutPanel layout = new()
		{
			Dock = DockStyle.Fill,
			ColumnCount = 1,
			RowCount = 5,
		};
		for (int i = 0; i < 5; i++)
		{
			layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 24));
		}

		layout.Controls.Add(_credentialLabel, 0, 0);
		layout.Controls.Add(_endpointLabel, 0, 1);
		layout.Controls.Add(_countersLabel, 0, 2);
		layout.Controls.Add(_lastResultLabel, 0, 3);
		layout.Controls.Add(_rateLimitLabel, 0, 4);

		panel.Controls.Add(layout);
		return panel;
	}

	private async Task RefreshAsync()
	{
		_refreshButton.Enabled = false;
		try
		{
			AbuseIpDbStatusDto? status = await _ipc
				.SendAsync<AbuseIpDbStatusDto>(IpcCommand.GetAbuseIpDbStatus)
				.ConfigureAwait(true);

			if (status is null)
			{
				_statusLabel.Text = "Service unreachable.";
				_credentialLabel.Text = "Credential: ?";
				_endpointLabel.Text = "Endpoint: ?";
				_countersLabel.Text = "Reports: ?";
				_lastResultLabel.Text = "Last result: ?";
				_rateLimitLabel.Text = "Rate-limit: ?";
				_reportEnabled.Enabled = false;
				_testButton.Enabled = false;
				return;
			}

			_credentialPresentOnService = status.CredentialPresent;
			_credentialLabel.Text = status.CredentialPresent
				? "Credential: Configured (encrypted at rest)"
				: "Credential: Not configured";

			// The raw key is never returned by the service (DPAPI-protected, never echoed). Show a
			// masked placeholder when a credential exists so the operator sees the key is restored
			// after a Configurator restart instead of an empty box that looks unconfigured. Saving
			// with the placeholder unchanged leaves the stored key intact (see IsMaskedPlaceholder).
			if (status.CredentialPresent && string.IsNullOrEmpty(_apiKeyInput.Text))
			{
				_apiKeyInput.Text = MaskedPlaceholder;
			}
			else if (!status.CredentialPresent && IsMaskedPlaceholder(_apiKeyInput.Text))
			{
				_apiKeyInput.Clear();
			}
			_endpointLabel.Text = "Endpoint: " + status.EndpointUrl;
			_countersLabel.Text = string.Format(CultureInfo.InvariantCulture,
				"Reports: {0} total / {1} hour / {2} day (limits: {3}/h, {4}/d, dedup {5}min)",
				status.TotalReports,
				status.ReportsLastHour,
				status.ReportsLastDay,
				status.MaxReportsPerHour,
				status.MaxReportsPerDay,
				status.DeduplicationWindowMinutes);

			if (status.LastReportUtc.HasValue)
			{
				_lastResultLabel.Text = string.Format(CultureInfo.InvariantCulture,
					"Last report: {0:yyyy-MM-dd HH:mm:ss}Z ip={1} HTTP={2}{3}",
					status.LastReportUtc.Value,
					status.LastReportedIp,
					status.LastResponseCode,
					string.IsNullOrEmpty(status.LastError) ? string.Empty : " err=" + status.LastError);
			}
			else
			{
				_lastResultLabel.Text = "Last report: (none yet)";
			}

			_rateLimitLabel.Text = status.RateLimited
				? "Rate-limit: ENGAGED (hourly/daily cap reached)"
				: "Rate-limit: ok";

			_reportEnabled.Enabled = status.CredentialPresent;
			_reportEnabled.Checked = status.ReportingEnabled;
			_testButton.Enabled = status.CredentialPresent;

			_dedupeEnabled.Checked = status.ReportDedupeEnabled;
			int cooldown = status.ReportCooldownHours;
			_cooldownHours.Value = Math.Clamp(cooldown <= 0 ? 24 : cooldown, (int)_cooldownHours.Minimum, (int)_cooldownHours.Maximum);
			_cooldownHours.Enabled = status.ReportDedupeEnabled;

			_statusLabel.Text = status.Message ?? "Status loaded.";
		}
		catch (Exception ex)
		{
			_statusLabel.Text = "Refresh FAILED: " + ex.GetType().Name + " — " + ex.Message;
		}
		finally
		{
			_refreshButton.Enabled = true;
		}
	}

	private async Task OnSaveAsync()
	{
		_saveButton.Enabled = false;
		_statusLabel.Text = "Saving settings…";

		try
		{
			// Fetch current settings to keep the rest of the document intact.
			JsonNode? settings = await _ipc.SendAsync<JsonNode>(IpcCommand.GetSettings).ConfigureAwait(true);
			JsonObject root;
			JsonObject section;
			if (settings is JsonObject obj)
			{
				section = obj;
				root = new JsonObject { [Core.Config.RdpAuditOptions.SectionName] = section.DeepClone() };
				section = (JsonObject)root[Core.Config.RdpAuditOptions.SectionName]!;
			}
			else
			{
				root = new JsonObject { [Core.Config.RdpAuditOptions.SectionName] = new JsonObject() };
				section = (JsonObject)root[Core.Config.RdpAuditOptions.SectionName]!;
			}

			if (section["AbuseIpDb"] is not JsonObject abuse)
			{
				abuse = new JsonObject();
				section["AbuseIpDb"] = abuse;
			}

			int cooldownHours = (int)_cooldownHours.Value;
			if (_dedupeEnabled.Checked && (cooldownHours < 1 || cooldownHours > 8760))
			{
				_statusLabel.Text = "Save FAILED: cooldown hours must be between 1 and 8760.";
				return;
			}

			string newKey = _apiKeyInput.Text?.Trim() ?? string.Empty;
			if (newKey.Length > 0 && !IsMaskedPlaceholder(newKey))
			{
				abuse["ApiKey"] = newKey;
			}

			abuse["ReportAttacks"] = _reportEnabled.Checked;
			abuse["Enabled"] = _reportEnabled.Checked || _credentialPresentOnService || newKey.Length > 0;
			abuse["ReportDedupeEnabled"] = _dedupeEnabled.Checked;
			abuse["ReportCooldownHours"] = cooldownHours;

			object? response = await _ipc
				.SendAsync<object>(IpcCommand.SaveSettings, root.ToJsonString(JsonOptions.Default))
				.ConfigureAwait(true);

			if (response is null)
			{
				_statusLabel.Text = "Save FAILED: service unreachable.";
				return;
			}

			_apiKeyInput.Clear();
			_statusLabel.Text = "Settings saved. The API key is encrypted at rest via DPAPI.";
			await RefreshAsync().ConfigureAwait(true);
		}
		catch (Exception ex)
		{
			_statusLabel.Text = "Save FAILED: " + ex.GetType().Name + " — " + ex.Message;
		}
		finally
		{
			_saveButton.Enabled = true;
		}
	}

	private async Task OnClearAsync()
	{
		_clearButton.Enabled = false;
		_statusLabel.Text = "Clearing stored API key…";

		try
		{
			JsonNode? settings = await _ipc.SendAsync<JsonNode>(IpcCommand.GetSettings).ConfigureAwait(true);
			JsonObject section;
			JsonObject root;
			if (settings is JsonObject obj)
			{
				root = new JsonObject { [Core.Config.RdpAuditOptions.SectionName] = obj.DeepClone() };
				section = (JsonObject)root[Core.Config.RdpAuditOptions.SectionName]!;
			}
			else
			{
				root = new JsonObject { [Core.Config.RdpAuditOptions.SectionName] = new JsonObject() };
				section = (JsonObject)root[Core.Config.RdpAuditOptions.SectionName]!;
			}

			if (section["AbuseIpDb"] is not JsonObject abuse)
			{
				abuse = new JsonObject();
				section["AbuseIpDb"] = abuse;
			}

			// Explicit empty key clears the stored credential; reporting is forced off without a key.
			abuse["ApiKey"] = string.Empty;
			abuse["ReportAttacks"] = false;
			abuse["Enabled"] = false;

			object? response = await _ipc
				.SendAsync<object>(IpcCommand.SaveSettings, root.ToJsonString(JsonOptions.Default))
				.ConfigureAwait(true);

			if (response is null)
			{
				_statusLabel.Text = "Clear FAILED: service unreachable.";
				return;
			}

			_apiKeyInput.Clear();
			_reportEnabled.Checked = false;
			_statusLabel.Text = "Stored API key cleared. Reporting disabled.";
			await RefreshAsync().ConfigureAwait(true);
		}
		catch (Exception ex)
		{
			_statusLabel.Text = "Clear FAILED: " + ex.GetType().Name + " — " + ex.Message;
		}
		finally
		{
			_clearButton.Enabled = true;
		}
	}

	private async Task OnTestAsync()
	{
		_testButton.Enabled = false;
		_statusLabel.Text = "Testing API key…";
		try
		{
			AbuseIpDbTestResult? result = await _ipc
				.SendAsync<AbuseIpDbTestResult>(IpcCommand.TestAbuseIpDbKey)
				.ConfigureAwait(true);
			if (result is null)
			{
				_statusLabel.Text = "Test FAILED: service unreachable.";
				return;
			}

			StringBuilder sb = new();
			sb.Append("Key test status=").Append(result.Status).Append(". ");
			sb.Append("Format ").Append(result.KeyFormatValid ? "OK" : "FAILED").Append(". ");
			if (result.ResponseCode > 0)
			{
				sb.Append("HTTP ").Append(result.ResponseCode.ToString(CultureInfo.InvariantCulture)).Append(". ");
			}
			sb.Append("Remote verified: ").Append(result.RemoteVerified ? "yes" : "no").Append(". ");
			sb.Append(result.Message);
			_statusLabel.Text = sb.ToString();
		}
		catch (Exception ex)
		{
			_statusLabel.Text = "Test FAILED: " + ex.GetType().Name + " — " + ex.Message;
		}
		finally
		{
			_testButton.Enabled = _credentialPresentOnService || !string.IsNullOrWhiteSpace(_apiKeyInput.Text);
		}
	}

	private const int ReportLogLimit = 500;

	private Panel BuildReportLogPanel()
	{
		Panel panel = new() { Dock = DockStyle.Fill, Padding = new Padding(8) };

		FlowLayoutPanel buttons = new() { Dock = DockStyle.Top, Height = 36, FlowDirection = FlowDirection.LeftToRight, WrapContents = false };
		buttons.Controls.Add(_logRefreshButton);
		buttons.Controls.Add(_logCopyButton);
		buttons.Controls.Add(_logOpenButton);

		Panel statusBar = new() { Dock = DockStyle.Bottom, Height = 24 };
		statusBar.Controls.Add(_logStatusLabel);

		Label header = new()
		{
			Text = "AbuseIPDB report log (persisted; never shows the API key). Click a column header to sort.",
			Dock = DockStyle.Top,
			Height = 22,
			TextAlign = ContentAlignment.MiddleLeft,
			Font = new Font(Font, FontStyle.Bold),
		};

		panel.Controls.Add(_reportLogGrid);
		panel.Controls.Add(buttons);
		panel.Controls.Add(header);
		panel.Controls.Add(statusBar);
		return panel;
	}

	private static DataGridView BuildReportLogGrid()
	{
		DataGridView g = new()
		{
			Dock = DockStyle.Fill,
			AllowUserToAddRows = false,
			AllowUserToDeleteRows = false,
			ReadOnly = true,
			AutoGenerateColumns = false,
			SelectionMode = DataGridViewSelectionMode.FullRowSelect,
			MultiSelect = false,
			RowHeadersVisible = false,
		};

		g.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Time (UTC)", DataPropertyName = nameof(ReportLogRow.TimeUtc), Width = 150 });
		g.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Local time", DataPropertyName = nameof(ReportLogRow.LocalTime), Width = 150 });
		g.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Source IP", DataPropertyName = nameof(ReportLogRow.SourceIp), Width = 140 });
		g.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Classification", DataPropertyName = nameof(ReportLogRow.Classification), Width = 110 });
		g.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Action", DataPropertyName = nameof(ReportLogRow.Action), Width = 100 });
		g.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Reason", DataPropertyName = nameof(ReportLogRow.Reason), Width = 130 });
		g.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "HTTP", DataPropertyName = nameof(ReportLogRow.HttpStatusCode), Width = 60 });
		g.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Report id", DataPropertyName = nameof(ReportLogRow.ReportId), Width = 100 });
		g.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Cooldown until (UTC)", DataPropertyName = nameof(ReportLogRow.CooldownExpiresUtc), Width = 160 });
		g.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Failed", DataPropertyName = nameof(ReportLogRow.FailedCount), Width = 70 });
		g.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Successful", DataPropertyName = nameof(ReportLogRow.SuccessfulCount), Width = 80 });
		g.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "First seen (UTC)", DataPropertyName = nameof(ReportLogRow.FirstSeenUtc), Width = 150 });
		g.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Last seen (UTC)", DataPropertyName = nameof(ReportLogRow.LastSeenUtc), Width = 150 });
		g.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Usernames (≤10)", DataPropertyName = nameof(ReportLogRow.UsernamesSample), Width = 200 });
		g.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Comment preview", DataPropertyName = nameof(ReportLogRow.CommentPreview), AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill });

		foreach (DataGridViewColumn col in g.Columns)
		{
			col.SortMode = DataGridViewColumnSortMode.Automatic;
		}

		return g;
	}

	private async Task RefreshReportLogAsync()
	{
		_logRefreshButton.Enabled = false;
		try
		{
			List<AbuseIpDbReportLogDto>? rows = await _ipc
				.SendAsync<List<AbuseIpDbReportLogDto>>(IpcCommand.ListAbuseIpDbReportLog, ReportLogLimit)
				.ConfigureAwait(true);

			_reportLogRows.RaiseListChangedEvents = false;
			_reportLogRows.Clear();
			if (rows is not null)
			{
				foreach (AbuseIpDbReportLogDto dto in rows)
				{
					_reportLogRows.Add(ReportLogRow.FromDto(dto));
				}
			}
			_reportLogRows.RaiseListChangedEvents = true;
			_reportLogRows.ResetBindings();

			_logStatusLabel.Text = string.Format(
				CultureInfo.InvariantCulture,
				"Report log: {0} row(s) loaded (newest first; max {1}).",
				_reportLogRows.Count,
				ReportLogLimit);
		}
		catch (Exception ex)
		{
			_logStatusLabel.Text = "Report log load FAILED: " + ex.GetType().Name + " — " + ex.Message;
		}
		finally
		{
			_logRefreshButton.Enabled = true;
		}
	}

	private ReportLogRow? SelectedReportRow()
	{
		if (_reportLogGrid.CurrentRow?.DataBoundItem is ReportLogRow row)
		{
			return row;
		}
		return null;
	}

	private void OnCopySelectedReport()
	{
		ReportLogRow? row = SelectedReportRow();
		if (row is null)
		{
			_logStatusLabel.Text = "Copy report text: no row selected.";
			return;
		}

		string text = string.IsNullOrWhiteSpace(row.CommentPreview)
			? "No stored comment preview for " + row.SourceIp + "."
			: row.CommentPreview;

		try
		{
			Clipboard.SetText(text);
			_logStatusLabel.Text = AbuseIpDbReportText.ClipboardToast;
		}
		catch (Exception ex)
		{
			_logStatusLabel.Text = "Copy report text FAILED: " + ex.GetType().Name + " — " + ex.Message;
		}
	}

	private void OnOpenSelectedInAbuseIpDb()
	{
		ReportLogRow? row = SelectedReportRow();
		if (row is null || string.IsNullOrWhiteSpace(row.SourceIp))
		{
			_logStatusLabel.Text = "Open in AbuseIPDB: no row selected.";
			return;
		}

		IpReputationBrowser.LaunchOutcome outcome = IpReputationBrowser.OpenAbuseIpDb(row.SourceIp);
		_logStatusLabel.Text = outcome.Format();
	}

	/// <summary>Display projection of an AbuseIPDB report-log row with typed columns for correct sorting.</summary>
	public sealed class ReportLogRow
	{
		public long Id { get; init; }

		public DateTime TimeUtc { get; init; }

		public DateTime LocalTime { get; init; }

		public string SourceIp { get; init; } = string.Empty;

		public string Classification { get; init; } = string.Empty;

		public string Action { get; init; } = string.Empty;

		public string? Reason { get; init; }

		public int HttpStatusCode { get; init; }

		public string? ReportId { get; init; }

		public DateTime? CooldownExpiresUtc { get; init; }

		public long FailedCount { get; init; }

		public long SuccessfulCount { get; init; }

		public DateTime? FirstSeenUtc { get; init; }

		public DateTime? LastSeenUtc { get; init; }

		public string? UsernamesSample { get; init; }

		public string? CommentPreview { get; init; }

		public static ReportLogRow FromDto(AbuseIpDbReportLogDto dto)
		{
			ArgumentNullException.ThrowIfNull(dto);
			return new ReportLogRow
			{
				Id = dto.Id,
				TimeUtc = dto.TimeUtc,
				LocalTime = dto.TimeUtc.ToLocalTime(),
				SourceIp = dto.SourceIp,
				Classification = IpReportability.Describe(dto.Classification),
				Action = dto.Action.ToString(),
				Reason = dto.Reason,
				HttpStatusCode = dto.HttpStatusCode,
				ReportId = dto.ReportId,
				CooldownExpiresUtc = dto.CooldownExpiresUtc,
				FailedCount = dto.FailedCount,
				SuccessfulCount = dto.SuccessfulCount,
				FirstSeenUtc = dto.FirstSeenUtc,
				LastSeenUtc = dto.LastSeenUtc,
				UsernamesSample = dto.UsernamesSample,
				CommentPreview = dto.CommentPreview,
			};
		}
	}

	/// <summary>Sentinel shown in the key box when a credential is configured but cannot be echoed.</summary>
	private const string MaskedPlaceholder = "***configured***";

	private static bool IsMaskedPlaceholder(string value) =>
		string.Equals(value, MaskedPlaceholder, StringComparison.Ordinal);
}
