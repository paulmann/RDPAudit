/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// File   : ZabbixPage.cs
// Project: RdpAudit.Configurator (RdpAudit.Configurator.Forms)
// Purpose: The Zabbix tab: connection settings, the connection test, one-click provisioning, a manual
//          push and the list of incidents carried by the last accepted batch. Every action is an IPC
//          round-trip with its own deadline; nothing here talks to Zabbix directly and nothing blocks
//          the UI thread.
// Depends: IZabbixGateway, SafeAsyncHandler, DataGridClipboardMenu, DarkTheme
// Extends: System.Windows.Forms.TabPage

using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.Runtime.Versioning;
using RdpAudit.Configurator.Services;
using RdpAudit.Core.Config;
using RdpAudit.Core.Ipc.Contracts;
using RdpAudit.Core.Models;
using RdpAudit.Core.Zabbix;

namespace RdpAudit.Configurator.Forms;

/// <summary>Zabbix integration page.</summary>
[SupportedOSPlatform("windows")]
public sealed class ZabbixPage : TabPage
{
	private readonly IZabbixGateway _gateway;
	private readonly BindingList<ZabbixSentIncidentDto> _recentRows = new();
	private readonly DataGridView _recentGrid;
	private TextBox _serverHost = null!;
	private NumericUpDown _serverPort = null!;
	private TextBox _hostName = null!;
	private TextBox _hostGroup = null!;
	private TextBox _trapperHosts = null!;
	private TextBox _apiUrl = null!;
	private TextBox _apiToken = null!;
	private TextBox _apiUser = null!;
	private TextBox _apiPassword = null!;
	private CheckBox _validateCertificate = null!;
	private CheckBox _provisionTriggers = null!;
	private CheckBox _createDashboard = null!;
	private NumericUpDown _timeout = null!;
	private NumericUpDown _interval = null!;
	private NumericUpDown _maxPerPush = null!;
	private NumericUpDown _maxBacklog = null!;
	private ComboBox _minimumSeverity = null!;
	private CheckBox _enabled = null!;
	private Button _saveButton = null!;
	private Button _refreshButton = null!;
	private Button _testButton = null!;
	private Button _provisionButton = null!;
	private Button _pushButton = null!;
	private Button _openProblemsButton = null!;
	private Label _effectiveHostValue = null!;
	private Label _apiEndpointValue = null!;
	private ToolStripStatusLabel _statusLabel = null!;
	private string _problemsUrl = string.Empty;
	private bool _loading;
	private bool _dirty;

	/// <summary>Creates the page.</summary>
	/// <param name="gateway">IPC gateway; a fake is injected by the tests.</param>
	public ZabbixPage(IZabbixGateway gateway)
	{
		ArgumentNullException.ThrowIfNull(gateway);
		_gateway = gateway;
		_recentGrid = new DataGridView { Dock = DockStyle.Fill };
		Text = "Zabbix";
		BuildLayout();
		ConfigureGrid();
		HandleCreated += SafeAsyncHandler.Wrap(RefreshAsync, ReportFailure);
	}

	/// <summary>Status line currently shown, for the tests.</summary>
	internal string StatusText => _statusLabel.Text ?? string.Empty;

	/// <summary>Rows of the "recently pushed" list, for the tests.</summary>
	internal BindingList<ZabbixSentIncidentDto> RecentRows => _recentRows;

	private void BuildLayout()
	{
		_enabled = new CheckBox
		{
			AutoSize = true,
			Text = "Send RDP incidents to Zabbix",
		};

		_serverHost = new TextBox { Dock = DockStyle.Fill };
		_serverPort = new NumericUpDown { Minimum = 1, Maximum = 65_535, Value = ZabbixOptions.DefaultServerPort, Dock = DockStyle.Fill };
		_hostName = new TextBox { Dock = DockStyle.Fill };
		_hostGroup = new TextBox { Dock = DockStyle.Fill, Text = ZabbixOptions.DefaultHostGroup };
		_trapperHosts = new TextBox { Dock = DockStyle.Fill };
		_apiUrl = new TextBox { Dock = DockStyle.Fill };
		_apiToken = new TextBox { Dock = DockStyle.Fill, UseSystemPasswordChar = true };
		_apiUser = new TextBox { Dock = DockStyle.Fill };
		_apiPassword = new TextBox { Dock = DockStyle.Fill, UseSystemPasswordChar = true };
		_validateCertificate = new CheckBox { AutoSize = true, Text = "Validate the server certificate", Checked = true };
		_provisionTriggers = new CheckBox { AutoSize = true, Text = "Create triggers", Checked = true };
		_createDashboard = new CheckBox { AutoSize = true, Text = "Create the shared dashboard", Checked = true };

		_timeout = new NumericUpDown
		{
			Minimum = ZabbixOptions.MinTimeoutSeconds,
			Maximum = ZabbixOptions.MaxTimeoutSeconds,
			Value = ZabbixOptions.DefaultTimeoutSeconds,
			Dock = DockStyle.Fill,
		};
		_interval = new NumericUpDown
		{
			Minimum = ZabbixOptions.MinPushIntervalSeconds,
			Maximum = ZabbixOptions.MaxPushIntervalSeconds,
			Value = ZabbixOptions.DefaultPushIntervalSeconds,
			Dock = DockStyle.Fill,
		};
		_maxPerPush = new NumericUpDown
		{
			Minimum = ZabbixOptions.MinIncidentsPerPush,
			Maximum = ZabbixOptions.MaxIncidentsPerPushCeiling,
			Value = ZabbixOptions.DefaultMaxIncidentsPerPush,
			Dock = DockStyle.Fill,
		};
		_maxBacklog = new NumericUpDown
		{
			Minimum = ZabbixOptions.MinBacklogIncidents,
			Maximum = ZabbixOptions.MaxBacklogIncidentsCeiling,
			Value = ZabbixOptions.DefaultMaxBacklogIncidents,
			Dock = DockStyle.Fill,
		};

		_minimumSeverity = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Dock = DockStyle.Fill };
		_minimumSeverity.Items.AddRange(new object[]
		{
			new SeverityChoice(AlertSeverity.Info),
			new SeverityChoice(AlertSeverity.Low),
			new SeverityChoice(AlertSeverity.Medium),
			new SeverityChoice(AlertSeverity.High),
			new SeverityChoice(AlertSeverity.Critical),
		});
		_minimumSeverity.SelectedIndex = 2;

		_effectiveHostValue = new Label { AutoSize = true, Text = "-" };
		_apiEndpointValue = new Label { AutoSize = true, Text = "-" };

		TableLayoutPanel connection = new()
		{
			Dock = DockStyle.Fill,
			AutoSize = true,
			ColumnCount = 4,
			RowCount = 7,
			Padding = new Padding(6),
		};
		connection.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
		connection.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
		connection.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
		connection.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
		for (int row = 0; row < 7; row++)
		{
			connection.RowStyles.Add(new RowStyle(SizeType.AutoSize));
		}

		AddField(connection, 0, 0, "Zabbix server:", _serverHost, "Port:", _serverPort);
		AddField(connection, 1, 0, "Host name in Zabbix:", _hostName, "Host group:", _hostGroup);
		AddField(connection, 2, 0, "Frontend URL:", _apiUrl, "API user:", _apiUser);
		AddField(connection, 3, 0, "API token:", _apiToken, "API password:", _apiPassword);
		AddField(connection, 4, 0, "Timeout (s):", _timeout, "Push interval (s):", _interval);
		AddField(connection, 5, 0, "Incidents per push:", _maxPerPush, "Backlog cap:", _maxBacklog);

		// A trapper item only accepts values from its allowed-hosts list, and the default is loopback,
		// so this field is not optional for a working install. Empty means "this machine's addresses".
		connection.Controls.Add(
			new Label
			{
				Text = "Trapper allowed hosts (empty = this machine's own addresses):",
				AutoSize = true,
				Anchor = AnchorStyles.Left,
			},
			0,
			6);
		connection.Controls.Add(_trapperHosts, 1, 6);
		connection.SetColumnSpan(_trapperHosts, 3);

		FlowLayoutPanel flags = new()
		{
			AutoSize = true,
			FlowDirection = FlowDirection.LeftToRight,
			WrapContents = true,
			Dock = DockStyle.Top,
			Padding = new Padding(6),
		};
		flags.Controls.Add(_enabled);
		flags.Controls.Add(_validateCertificate);
		flags.Controls.Add(_provisionTriggers);
		flags.Controls.Add(_createDashboard);

		TableLayoutPanel behaviour = new()
		{
			Dock = DockStyle.Fill,
			AutoSize = true,
			ColumnCount = 4,
			RowCount = 2,
			Padding = new Padding(6),
		};
		behaviour.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
		behaviour.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 160));
		behaviour.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
		behaviour.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
		behaviour.RowStyles.Add(new RowStyle(SizeType.AutoSize));
		behaviour.RowStyles.Add(new RowStyle(SizeType.AutoSize));

		behaviour.Controls.Add(new Label { Text = "Forward from severity:", AutoSize = true, Anchor = AnchorStyles.Left }, 0, 0);
		behaviour.Controls.Add(_minimumSeverity, 1, 0);
		behaviour.Controls.Add(new Label { Text = "Technical host name:", AutoSize = true, Anchor = AnchorStyles.Left }, 2, 0);
		behaviour.Controls.Add(_effectiveHostValue, 3, 0);
		behaviour.Controls.Add(new Label { Text = "API endpoint:", AutoSize = true, Anchor = AnchorStyles.Left }, 0, 1);
		behaviour.Controls.Add(_apiEndpointValue, 1, 1);
		behaviour.SetColumnSpan(_apiEndpointValue, 3);

		_saveButton = MakeButton("Save changes", SaveAsync);
		_refreshButton = MakeButton("Refresh", RefreshAsync);
		_testButton = MakeButton("Test connection", TestAsync);
		_provisionButton = MakeButton("Provision in Zabbix", ProvisionAsync);
		_pushButton = MakeButton("Push now", PushNowAsync);
		_openProblemsButton = new Button { Text = "Open all incidents", AutoSize = true, Margin = new Padding(6, 3, 3, 3) };
		_openProblemsButton.Click += SafeAsyncHandler.Wrap(OpenProblemsAsync, ReportFailure);

		FlowLayoutPanel toolbar = new()
		{
			Dock = DockStyle.Top,
			AutoSize = true,
			FlowDirection = FlowDirection.LeftToRight,
			WrapContents = true,
			Padding = new Padding(6),
		};
		toolbar.Controls.Add(_saveButton);
		toolbar.Controls.Add(_refreshButton);
		toolbar.Controls.Add(_testButton);
		toolbar.Controls.Add(_provisionButton);
		toolbar.Controls.Add(_pushButton);
		toolbar.Controls.Add(_openProblemsButton);

		GroupBox connectionBox = new() { Text = "Connection", Dock = DockStyle.Top, AutoSize = true };
		connectionBox.Controls.Add(connection);
		GroupBox behaviourBox = new() { Text = "Behaviour", Dock = DockStyle.Top, AutoSize = true };
		behaviourBox.Controls.Add(behaviour);

		GroupBox recentBox = new() { Text = "Incidents carried by the last accepted batch", Dock = DockStyle.Fill };
		recentBox.Controls.Add(_recentGrid);

		StatusStrip statusStrip = new() { Dock = DockStyle.Bottom, SizingGrip = false };
		_statusLabel = new ToolStripStatusLabel("Loading Zabbix settings...");
		statusStrip.Items.Add(_statusLabel);

		// Docked panels are added last-to-first, so the visual order is connection, flags, behaviour,
		// toolbar, list, status.
		Controls.Add(recentBox);
		Controls.Add(toolbar);
		Controls.Add(behaviourBox);
		Controls.Add(flags);
		Controls.Add(connectionBox);
		Controls.Add(statusStrip);

		WireDirtyTracking();
	}

	/// <summary>Marks the page dirty when an editable control changes. Plain handlers: this is not an
	/// asynchronous action, so it must not go through <see cref="SafeAsyncHandler"/>.</summary>
	private void WireDirtyTracking()
	{
		foreach (Control control in new Control[]
		{
			_serverHost,
			_hostName,
			_hostGroup,
			_trapperHosts,
			_apiUrl,
			_apiToken,
			_apiUser,
			_apiPassword,
		})
		{
			control.TextChanged += OnEditableChanged;
		}

		foreach (NumericUpDown numeric in new[] { _serverPort, _timeout, _interval, _maxPerPush, _maxBacklog })
		{
			numeric.ValueChanged += OnEditableChanged;
		}

		foreach (CheckBox box in new[] { _enabled, _validateCertificate, _provisionTriggers, _createDashboard })
		{
			box.CheckedChanged += OnEditableChanged;
		}

		_minimumSeverity.SelectedIndexChanged += OnEditableChanged;
	}

	private void OnEditableChanged(object? sender, EventArgs e)
	{
		if (_loading)
		{
			return;
		}

		MarkDirty();
		SetStatus("Zabbix settings changed. Save changes to persist.");
	}

	private Button MakeButton(string text, Func<Task> action)
	{
		Button button = new() { Text = text, AutoSize = true, Margin = new Padding(3) };
		button.Click += SafeAsyncHandler.Wrap(action, ReportFailure);
		return button;
	}

	private static void AddField(
		TableLayoutPanel panel,
		int row,
		int column,
		string label1,
		Control control1,
		string label2,
		Control control2)
	{
		panel.Controls.Add(new Label { Text = label1, AutoSize = true, Anchor = AnchorStyles.Left }, column, row);
		panel.Controls.Add(control1, column + 1, row);
		panel.Controls.Add(new Label { Text = label2, AutoSize = true, Anchor = AnchorStyles.Left, Margin = new Padding(12, 6, 3, 3) }, column + 2, row);
		panel.Controls.Add(control2, column + 3, row);
	}

	private void ConfigureGrid()
	{
		_recentGrid.AutoGenerateColumns = false;
		_recentGrid.AllowUserToAddRows = false;
		_recentGrid.AllowUserToDeleteRows = false;
		_recentGrid.ReadOnly = true;
		_recentGrid.RowHeadersVisible = false;
		_recentGrid.SelectionMode = DataGridViewSelectionMode.FullRowSelect;
		_recentGrid.Columns.Add(new DataGridViewTextBoxColumn { DataPropertyName = nameof(ZabbixSentIncidentDto.TimeUtc), HeaderText = "Time (UTC)", Width = 140 });
		_recentGrid.Columns.Add(new DataGridViewTextBoxColumn { DataPropertyName = nameof(ZabbixSentIncidentDto.Severity), HeaderText = "Severity", Width = 80 });
		_recentGrid.Columns.Add(new DataGridViewTextBoxColumn { DataPropertyName = nameof(ZabbixSentIncidentDto.ZabbixSeverity), HeaderText = "Zabbix", Width = 60 });
		_recentGrid.Columns.Add(new DataGridViewTextBoxColumn { DataPropertyName = nameof(ZabbixSentIncidentDto.RuleId), HeaderText = "Rule", Width = 170 });
		_recentGrid.Columns.Add(new DataGridViewTextBoxColumn { DataPropertyName = nameof(ZabbixSentIncidentDto.SourceIp), HeaderText = "Source IP", Width = 130 });
		_recentGrid.Columns.Add(new DataGridViewTextBoxColumn { DataPropertyName = nameof(ZabbixSentIncidentDto.UserName), HeaderText = "Account", Width = 110 });
		_recentGrid.Columns.Add(new DataGridViewTextBoxColumn { DataPropertyName = nameof(ZabbixSentIncidentDto.Message), HeaderText = "Message", Width = 420 });
		_recentGrid.DataSource = _recentRows;
		Theming.DataGridClipboardMenu.AttachWithExport(_recentGrid, "ZabbixIncidents", text => SetStatus(text));
	}

	/// <summary>Loads settings and status.</summary>
	internal async Task RefreshAsync()
	{
		SetControlsEnabled(false);
		SetStatus("Loading Zabbix settings...");

		Ipc.IpcCallResult<ZabbixSettingsDto> settings = await _gateway.GetSettingsAsync().ConfigureAwait(true);
		if (!settings.IsSuccess || settings.Value is null)
		{
			SetStatus("Could not load Zabbix settings: " + settings.Headline(), isError: true);
			SetControlsEnabled(true);
			return;
		}

		_loading = true;
		try
		{
			ApplyToControls(settings.Value);
			_dirty = false;
		}
		finally
		{
			_loading = false;
		}

		Ipc.IpcCallResult<ZabbixStatusDto> status = await _gateway.GetStatusAsync().ConfigureAwait(true);
		if (status.IsSuccess && status.Value is not null)
		{
			ApplyStatus(status.Value);
			SetStatus(status.Value.Message);
		}
		else
		{
			SetStatus("Settings loaded, but the push status is unavailable: " + status.Headline(), isError: true);
		}

		SetControlsEnabled(true);
		UpdateButtonState();
	}

	/// <summary>Saves the edited settings.</summary>
	internal async Task SaveAsync()
	{
		if (!_dirty)
		{
			SetStatus("There are no unsaved Zabbix changes.");
			return;
		}

		SetControlsEnabled(false);
		Ipc.IpcCallResult<ZabbixSettingsDto> call =
			await _gateway.SaveSettingsAsync(CaptureFromControls()).ConfigureAwait(true);

		if (!call.IsSuccess || call.Value is null)
		{
			SetStatus("Could not save Zabbix settings: " + call.Headline(), isError: true);
			SetControlsEnabled(true);
			return;
		}

		_loading = true;
		try
		{
			ApplyToControls(call.Value);
			_dirty = false;
		}
		finally
		{
			_loading = false;
		}

		SetStatus("Zabbix settings saved. The service applies them without a restart.");
		SetControlsEnabled(true);
		UpdateButtonState();
	}

	/// <summary>Runs the connection test.</summary>
	internal async Task TestAsync()
	{
		SetControlsEnabled(false);
		SetStatus("Testing the Zabbix connection...");
		Ipc.IpcCallResult<ZabbixTestResultDto> call = await _gateway.TestAsync().ConfigureAwait(true);
		SetControlsEnabled(true);
		UpdateButtonState();

		if (!call.IsSuccess || call.Value is null)
		{
			SetStatus("Connection test failed: " + call.Headline(), isError: true);
			return;
		}

		ZabbixTestResultDto dto = call.Value;
		SetStatus(
			string.Format(
				CultureInfo.InvariantCulture,
				"sender {0} | API {1} ({2}, credential {3}) — {4}",
				dto.SenderReachable ? "reachable" : "unreachable",
				dto.ApiReachable ? "reachable" : "unreachable",
				string.IsNullOrEmpty(dto.ApiVersion) ? "no version" : dto.ApiVersion,
				dto.CredentialValid ? "accepted" : "not accepted",
				dto.Message),
			isError: dto.Status != IpcResultStatus.Success);
	}

	/// <summary>Pushes the pending incidents immediately.</summary>
	internal async Task PushNowAsync()
	{
		SetControlsEnabled(false);
		SetStatus("Pushing to Zabbix...");
		Ipc.IpcCallResult<ZabbixPushResultDto> call = await _gateway.PushNowAsync().ConfigureAwait(true);
		SetControlsEnabled(true);

		if (!call.IsSuccess || call.Value is null)
		{
			SetStatus("Push failed: " + call.Headline(), isError: true);
			return;
		}

		ZabbixPushResultDto dto = call.Value;
		SetStatus(
			string.Format(
				CultureInfo.InvariantCulture,
				"{0} — {1} incident(s), {2}/{3} value(s) accepted, {4} skipped.",
				dto.Delivered ? "Delivered" : "Not delivered",
				dto.IncidentsInBatch,
				dto.Processed,
				dto.Total,
				dto.Skipped),
			isError: !dto.Delivered);

		await RefreshAsync().ConfigureAwait(true);
	}

	/// <summary>Creates the Zabbix-side objects.</summary>
	internal async Task ProvisionAsync()
	{
		SetControlsEnabled(false);
		SetStatus("Provisioning the host, items, triggers and dashboard...");
		Ipc.IpcCallResult<ZabbixProvisionResultDto> call = await _gateway.ProvisionAsync().ConfigureAwait(true);
		SetControlsEnabled(true);

		if (!call.IsSuccess || call.Value is null)
		{
			SetStatus("Provisioning failed: " + call.Headline(), isError: true);
			return;
		}

		ZabbixProvisionResultDto dto = call.Value;
		if (!string.IsNullOrEmpty(dto.ProblemsUrl))
		{
			_problemsUrl = dto.ProblemsUrl;
		}

		SetStatus(dto.Message, isError: dto.Status != IpcResultStatus.Success);
		UpdateButtonState();
	}

	private Task OpenProblemsAsync()
	{
		if (string.IsNullOrWhiteSpace(_problemsUrl))
		{
			SetStatus("There is no Zabbix URL yet. Set the frontend URL and save, or run provisioning first.", isError: true);
			return Task.CompletedTask;
		}

		try
		{
			using Process process = Process.Start(new ProcessStartInfo(_problemsUrl) { UseShellExecute = true })
				?? throw new InvalidOperationException("The shell refused to open the URL.");
			SetStatus("Opened the fleet-wide incident view: " + _problemsUrl);
		}
		catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception)
		{
			SetStatus("The URL could not be opened: " + ex.Message + " " + _problemsUrl, isError: true);
		}

		return Task.CompletedTask;
	}

	/// <summary>Copies a settings DTO into the controls.</summary>
	/// <param name="dto">Settings to display.</param>
	internal void ApplyToControls(ZabbixSettingsDto dto)
	{
		ArgumentNullException.ThrowIfNull(dto);
		_enabled.Checked = dto.Enabled;
		_serverHost.Text = dto.ServerHost;
		_serverPort.Value = Math.Clamp((decimal)dto.ServerPort, _serverPort.Minimum, _serverPort.Maximum);
		_hostName.Text = dto.HostName;
		_hostGroup.Text = dto.HostGroup;
		_trapperHosts.Text = dto.TrapperAllowedHosts;
		_apiUrl.Text = dto.ApiUrl;
		_apiToken.Text = dto.ApiToken;
		_apiUser.Text = dto.ApiUser;
		_apiPassword.Text = dto.ApiPassword;
		_validateCertificate.Checked = dto.ValidateServerCertificate;
		_provisionTriggers.Checked = dto.ProvisionTriggers;
		_createDashboard.Checked = dto.CreateDashboard;
		_timeout.Value = Math.Clamp((decimal)dto.TimeoutSeconds, _timeout.Minimum, _timeout.Maximum);
		_interval.Value = Math.Clamp((decimal)dto.PushIntervalSeconds, _interval.Minimum, _interval.Maximum);
		_maxPerPush.Value = Math.Clamp((decimal)dto.MaxIncidentsPerPush, _maxPerPush.Minimum, _maxPerPush.Maximum);
		_maxBacklog.Value = Math.Clamp((decimal)dto.MaxBacklogIncidents, _maxBacklog.Minimum, _maxBacklog.Maximum);
		_minimumSeverity.SelectedIndex = ResolveSeverityIndex(dto.MinimumSeverity);
		_effectiveHostValue.Text = string.IsNullOrEmpty(dto.EffectiveHostName) ? "-" : dto.EffectiveHostName;
		_apiEndpointValue.Text = string.IsNullOrEmpty(dto.ApiEndpoint) ? "-" : dto.ApiEndpoint;
		_problemsUrl = dto.ProblemsUrl;
		UpdateButtonState();
	}

	/// <summary>Reads the controls back into a settings DTO.</summary>
	internal ZabbixSettingsDto CaptureFromControls() => new()
	{
		Enabled = _enabled.Checked,
		ServerHost = _serverHost.Text.Trim(),
		ServerPort = decimal.ToInt32(_serverPort.Value),
		HostName = _hostName.Text.Trim(),
		HostGroup = _hostGroup.Text.Trim(),
		TrapperAllowedHosts = _trapperHosts.Text.Trim(),
		ApiUrl = _apiUrl.Text.Trim(),
		ApiToken = _apiToken.Text,
		ApiUser = _apiUser.Text.Trim(),
		ApiPassword = _apiPassword.Text,
		ValidateServerCertificate = _validateCertificate.Checked,
		ProvisionTriggers = _provisionTriggers.Checked,
		CreateDashboard = _createDashboard.Checked,
		TimeoutSeconds = decimal.ToInt32(_timeout.Value),
		PushIntervalSeconds = decimal.ToInt32(_interval.Value),
		MaxIncidentsPerPush = decimal.ToInt32(_maxPerPush.Value),
		MaxBacklogIncidents = decimal.ToInt32(_maxBacklog.Value),
		MinimumSeverity = _minimumSeverity.SelectedItem is SeverityChoice choice
			? choice.Severity.ToString()
			: AlertSeverity.Medium.ToString(),
		EffectiveHostName = _effectiveHostValue.Text,
		ApiEndpoint = _apiEndpointValue.Text,
		ProblemsUrl = _problemsUrl,
	};

	private void ApplyStatus(ZabbixStatusDto status)
	{
		_recentRows.RaiseListChangedEvents = false;
		try
		{
			_recentRows.Clear();
			foreach (ZabbixSentIncidentDto row in status.RecentIncidents)
			{
				_recentRows.Add(row);
			}
		}
		finally
		{
			_recentRows.RaiseListChangedEvents = true;
			_recentRows.ResetBindings();
		}

		if (!string.IsNullOrEmpty(status.ProblemsUrl))
		{
			_problemsUrl = status.ProblemsUrl;
		}

		if (!string.IsNullOrEmpty(status.HostName))
		{
			_effectiveHostValue.Text = status.HostName;
		}

		UpdateButtonState();
	}

	/// <summary>Marks the page as edited.</summary>
	internal void MarkDirty()
	{
		_dirty = true;
		UpdateButtonState();
	}

	private void UpdateButtonState()
	{
		_saveButton.Enabled = _dirty;
		_openProblemsButton.Enabled = !string.IsNullOrWhiteSpace(_problemsUrl);
	}

	private void SetControlsEnabled(bool enabled)
	{
		_enabled.Enabled = enabled;
		_serverHost.Enabled = enabled;
		_serverPort.Enabled = enabled;
		_hostName.Enabled = enabled;
		_hostGroup.Enabled = enabled;
		_trapperHosts.Enabled = enabled;
		_apiUrl.Enabled = enabled;
		_apiToken.Enabled = enabled;
		_apiUser.Enabled = enabled;
		_apiPassword.Enabled = enabled;
		_validateCertificate.Enabled = enabled;
		_provisionTriggers.Enabled = enabled;
		_createDashboard.Enabled = enabled;
		_timeout.Enabled = enabled;
		_interval.Enabled = enabled;
		_maxPerPush.Enabled = enabled;
		_maxBacklog.Enabled = enabled;
		_minimumSeverity.Enabled = enabled;
		_saveButton.Enabled = enabled && _dirty;
		_refreshButton.Enabled = enabled;
		_testButton.Enabled = enabled;
		_provisionButton.Enabled = enabled;
		_pushButton.Enabled = enabled;
		_openProblemsButton.Enabled = enabled && !string.IsNullOrWhiteSpace(_problemsUrl);
	}

	private static int ResolveSeverityIndex(string? severity)
	{
		if (Enum.TryParse(severity, ignoreCase: true, out AlertSeverity parsed))
		{
			return parsed switch
			{
				AlertSeverity.Info => 0,
				AlertSeverity.Low => 1,
				AlertSeverity.Medium => 2,
				AlertSeverity.High => 3,
				_ => 4,
			};
		}

		return 2;
	}

	private void SetStatus(string text, bool isError = false)
	{
		_statusLabel.Text = text;
		_statusLabel.ForeColor = isError ? Color.IndianRed : SystemColors.ControlText;
	}

	private void ReportFailure(Exception exception)
		=> SetStatus("The action failed: " + exception.GetType().Name + " — " + exception.Message, isError: true);

	/// <summary>Enum wrapper so the severity combo box renders a readable name.</summary>
	private sealed record SeverityChoice(AlertSeverity Severity)
	{
		public override string ToString() => Severity.ToString();
	}
}
