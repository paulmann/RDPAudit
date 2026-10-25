// File:    src/RdpAudit.Configurator/Forms/NotificationsPage.cs
// Module:  RdpAudit.Configurator.Forms
// Purpose: Notifications tab for tray-notifier settings, persisted through the service IPC
//          boundary (GetNotificationSettings 78 / SaveNotificationSettings 79). Visibility
//          grids enumerate every registered alert rule and every catalog event; absent map
//          keys follow documented defaults (rules shown; events shown at High/Critical).
// Extends: System.Windows.Forms.TabPage
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.ComponentModel;
using System.Globalization;
using System.Runtime.Versioning;
using RdpAudit.Configurator.Ipc;
using RdpAudit.Core.Config;
using RdpAudit.Core.Events;
using RdpAudit.Core.Ipc.Contracts;
using RdpAudit.Core.Models;
using RdpAudit.Configurator.Services;

namespace RdpAudit.Configurator.Forms;

/// <summary>Notifications configuration page.</summary>
[SupportedOSPlatform("windows")]
public sealed class NotificationsPage : TabPage
{
	private readonly INotificationSettingsGateway _gateway;
	private readonly INotifierAutostartService? _autostart;
	private CheckBox _enableTray = null!, _startWithWindows = null!, _useNativeToasts = null!;
	private NumericUpDown _pollInterval = null!, _maxToasts = null!;
	private ComboBox _minimumSeverity = null!;
	private DataGridView _alertsGrid = null!, _eventsGrid = null!;
	private Button _saveButton = null!, _refreshButton = null!;
	private ToolStripStatusLabel _statusLabel = null!;
	private readonly BindingList<AlertVisibilityRow> _alertRows = new();
	private readonly BindingList<EventVisibilityRow> _eventRows = new();

	private bool _loading;
	private bool _dirty;
	private TableLayoutPanel _fieldsPanel = null!;
	private FlowLayoutPanel _checksPanel = null!;
	private TabControl _tabs = null!;
	private TabPage _alertsTab = null!, _eventsTab = null!;
	private TableLayoutPanel _generalPanel = null!;

	public NotificationsPage(INotificationSettingsGateway gateway, INotifierAutostartService? autostart = null)
	{
		ArgumentNullException.ThrowIfNull(gateway);
		_gateway = gateway;
		_autostart = autostart;
		Text = "Notifications";
		_enableTray = new CheckBox { AutoSize = true, Text = "Enable tray notifier (elevated)", Checked = true };
		_startWithWindows = new CheckBox { AutoSize = true, Text = "Start notifier with Windows", Checked = true };
		_useNativeToasts = new CheckBox { AutoSize = true, Text = "Use native WinRT toasts when available", Checked = false };
		_pollInterval = new NumericUpDown { Minimum = NotificationOptions.MinPollIntervalSeconds, Maximum = NotificationOptions.MaxPollIntervalSeconds, Value = 5, Dock = DockStyle.Fill };
		_maxToasts = new NumericUpDown { Minimum = NotificationOptions.MinMaxToastsPerMinute, Maximum = NotificationOptions.MaxMaxToastsPerMinute, Value = 10, Dock = DockStyle.Fill };
		_minimumSeverity = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Dock = DockStyle.Fill };
		_minimumSeverity.Items.AddRange(new object[] { new SeverityChoice(AlertSeverity.Low), new SeverityChoice(AlertSeverity.Medium), new SeverityChoice(AlertSeverity.High), new SeverityChoice(AlertSeverity.Critical) });
		_minimumSeverity.SelectedIndex = 2;
		_buildLayout();
		_configureGrids();
		HandleCreated += async (_, _) => await RefreshAsync().ConfigureAwait(true);
	}

	private void _buildLayout()
	{
		_saveButton = new Button { Text = "Save changes", Dock = DockStyle.Fill };
		_saveButton.Click += async (_, _) => await SaveAsync().ConfigureAwait(true);
		_refreshButton = new Button { Text = "Refresh", Dock = DockStyle.Fill };
		_refreshButton.Click += async (_, _) => await RefreshAsync().ConfigureAwait(true);

		_fieldsPanel = new TableLayoutPanel
		{
			AutoSize = true,
			ColumnCount = 2,
			RowCount = 3,
		};
		_fieldsPanel.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
		_fieldsPanel.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 130));
		_fieldsPanel.RowStyles.Add(new RowStyle(SizeType.AutoSize));
		_fieldsPanel.RowStyles.Add(new RowStyle(SizeType.AutoSize));
		_fieldsPanel.RowStyles.Add(new RowStyle(SizeType.AutoSize));
		_fieldsPanel.Controls.Add(new Label { Text = "Poll interval (sec):", AutoSize = true, Anchor = AnchorStyles.Left }, 0, 0);
		_fieldsPanel.Controls.Add(_pollInterval, 1, 0);
		_fieldsPanel.Controls.Add(new Label { Text = "Minimum severity:", AutoSize = true, Anchor = AnchorStyles.Left }, 0, 1);
		_fieldsPanel.Controls.Add(_minimumSeverity, 1, 1);
		_fieldsPanel.Controls.Add(new Label { Text = "Max toasts per minute:", AutoSize = true, Anchor = AnchorStyles.Left }, 0, 2);
		_fieldsPanel.Controls.Add(_maxToasts, 1, 2);

		_checksPanel = new FlowLayoutPanel
		{
			AutoSize = true,
			FlowDirection = FlowDirection.LeftToRight,
			WrapContents = true,
			Margin = Padding.Empty,
			Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right,
		};
		_checksPanel.Controls.Add(_enableTray);
		_checksPanel.Controls.Add(_startWithWindows);
		_checksPanel.Controls.Add(_useNativeToasts);

		_generalPanel = new TableLayoutPanel
		{
			Dock = DockStyle.Top,
			AutoSize = true,
			ColumnCount = 2,
			RowCount = 1,
			Padding = new Padding(8),
		};
		_generalPanel.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
		_generalPanel.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
		_generalPanel.Controls.Add(_fieldsPanel, 0, 0);
		_generalPanel.Controls.Add(_checksPanel, 1, 0);

		_alertsTab = new TabPage("Alerts");
		_eventsTab = new TabPage("Events");
		_tabs = new TabControl { Dock = DockStyle.Fill };
		_tabs.TabPages.Add(_alertsTab);
		_tabs.TabPages.Add(_eventsTab);

		StatusStrip statusStrip = new();
		_statusLabel = new ToolStripStatusLabel("Loading notification settings...");
		statusStrip.Items.Add(_statusLabel);

		_alertsGrid = new DataGridView { Dock = DockStyle.Fill };
		_eventsGrid = new DataGridView { Dock = DockStyle.Fill };

		Controls.Add(_tabs);
		Controls.Add(_generalPanel);
		Controls.Add(statusStrip);
		Controls.Add(BuildToolbar());
	}

	private TableLayoutPanel BuildToolbar()
	{
		TableLayoutPanel toolbar = new()
		{
			Dock = DockStyle.Bottom,
			AutoSize = true,
			ColumnCount = 3,
			Padding = new Padding(8),
		};
		toolbar.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 120));
		toolbar.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 120));
		toolbar.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
		toolbar.Controls.Add(_saveButton, 0, 0);
		toolbar.Controls.Add(_refreshButton, 1, 0);
		return toolbar;
	}

	private void _configureGrids()
	{
		_alertsGrid.AutoGenerateColumns = false;
		_alertsGrid.AllowUserToAddRows = false;
		_alertsGrid.AllowUserToDeleteRows = false;
		_alertsGrid.RowHeadersVisible = false;
		_alertsGrid.SelectionMode = DataGridViewSelectionMode.FullRowSelect;
		_alertsGrid.Columns.Add(new DataGridViewTextBoxColumn { DataPropertyName = nameof(AlertVisibilityRow.RuleId), HeaderText = "Rule", ReadOnly = true, Width = 220 });
		_alertsGrid.Columns.Add(new DataGridViewTextBoxColumn { DataPropertyName = nameof(AlertVisibilityRow.Severity), HeaderText = "Severity", ReadOnly = true, Width = 90 });
		_alertsGrid.Columns.Add(new DataGridViewCheckBoxColumn { DataPropertyName = nameof(AlertVisibilityRow.Show), HeaderText = "Show", Width = 60 });
		_alertsGrid.DataSource = _alertRows;
		_alertsGrid.CurrentCellDirtyStateChanged += (s, e) => { if (_alertsGrid.IsCurrentCellDirty) _alertsGrid.CommitEdit(DataGridViewDataErrorContexts.Commit); };
		_alertsGrid.CellValueChanged += (_, e) => { if (!_loading && e.RowIndex >= 0) MarkDirty(); };

		_eventsGrid.AutoGenerateColumns = false;
		_eventsGrid.AllowUserToAddRows = false;
		_eventsGrid.AllowUserToDeleteRows = false;
		_eventsGrid.RowHeadersVisible = false;
		_eventsGrid.SelectionMode = DataGridViewSelectionMode.FullRowSelect;
		_eventsGrid.Columns.Add(new DataGridViewTextBoxColumn { DataPropertyName = nameof(EventVisibilityRow.EventId), HeaderText = "Event ID", ReadOnly = true, Width = 80 });
		_eventsGrid.Columns.Add(new DataGridViewTextBoxColumn { DataPropertyName = nameof(EventVisibilityRow.Channel), HeaderText = "Channel", ReadOnly = true, Width = 200 });
		_eventsGrid.Columns.Add(new DataGridViewTextBoxColumn { DataPropertyName = nameof(EventVisibilityRow.Name), HeaderText = "Name", ReadOnly = true, Width = 180 });
		_eventsGrid.Columns.Add(new DataGridViewTextBoxColumn { DataPropertyName = nameof(EventVisibilityRow.Criticality), HeaderText = "Criticality", ReadOnly = true, Width = 90 });
		_eventsGrid.Columns.Add(new DataGridViewCheckBoxColumn { DataPropertyName = nameof(EventVisibilityRow.Show), HeaderText = "Show", Width = 60 });
		_eventsGrid.DataSource = _eventRows;
		_eventsGrid.CurrentCellDirtyStateChanged += (s, e) => { if (_eventsGrid.IsCurrentCellDirty) _eventsGrid.CommitEdit(DataGridViewDataErrorContexts.Commit); };
		_eventsGrid.CellValueChanged += (_, e) => { if (!_loading && e.RowIndex >= 0) MarkDirty(); };

		_alertsTab.Controls.Add(_alertsGrid);
		_eventsTab.Controls.Add(_eventsGrid);
	}

	internal async Task RefreshAsync()
	{
		SetControlsEnabled(false);
		SetStatus("Loading notification settings...");
		IpcCallResult<NotificationSettingsDto> call =
			await _gateway.GetAsync().ConfigureAwait(true);
		if (!call.IsSuccess || call.Value is null)
		{
			SetStatus("Could not load notification settings: " + call.Headline(), isError: true);
			SetControlsEnabled(true);
			return;
		}

		_loading = true;
		try
		{
			ApplyToControls(call.Value);
			_dirty = false;
			SetStatus(string.Format(CultureInfo.InvariantCulture, "Loaded notification settings at {0:u}.", DateTime.UtcNow));
		}
		finally
		{
			_loading = false;
			SetControlsEnabled(true);
		}
	}

	internal async Task SaveAsync()
	{
		if (!_dirty)
		{
			SetStatus("There are no unsaved notification changes.");
			return;
		}

		_alertsGrid.EndEdit();
		_eventsGrid.EndEdit();
		NotificationSettingsDto dto = CaptureFromControls();

		SetControlsEnabled(false);
		IpcCallResult<NotificationSettingsDto> call =
			await _gateway.SaveAsync(dto).ConfigureAwait(true);
		if (!call.IsSuccess || call.Value is null)
		{
			SetStatus("Could not save notification settings: " + call.Headline(), isError: true);
			SetControlsEnabled(true);
			return;
		}

		_loading = true;
		try
		{
			ApplyToControls(call.Value);
			_dirty = false;
			SetStatus(await ApplyAutostartAsync(call.Value.StartWithWindows).ConfigureAwait(true));
		}
		finally
		{
			_loading = false;
			SetControlsEnabled(true);
		}
	}

	internal void ApplyToControls(NotificationSettingsDto dto)
	{
		_enableTray.Checked = dto.EnableTrayNotifier;
		_startWithWindows.Checked = dto.StartWithWindows;
		_useNativeToasts.Checked = dto.UseNativeToasts;
		_pollInterval.Value = Math.Clamp((decimal)dto.PollIntervalSeconds, (decimal)NotificationOptions.MinPollIntervalSeconds, (decimal)NotificationOptions.MaxPollIntervalSeconds);
		_maxToasts.Value = Math.Clamp((decimal)dto.MaxToastsPerMinute, (decimal)NotificationOptions.MinMaxToastsPerMinute, (decimal)NotificationOptions.MaxMaxToastsPerMinute);

		AlertSeverity severity = Enum.TryParse(dto.MinimumSeverity, ignoreCase: true, out AlertSeverity parsed) ? parsed : AlertSeverity.High;
		foreach (object? item in _minimumSeverity.Items)
		{
			if (item is SeverityChoice choice && choice.Severity == severity)
			{
				_minimumSeverity.SelectedItem = item;
				break;
			}
		}

		_alertRows.Clear();
		foreach (NotificationCatalogInfo.AlertRule meta in NotificationCatalogInfo.AlertRules)
		{
			_alertRows.Add(new AlertVisibilityRow
			{
				RuleId = meta.RuleId,
				Name = meta.RuleId,
				Severity = meta.Severity.ToString(),
				Show = !dto.ShowAlerts.TryGetValue(meta.RuleId, out bool showAlert) || showAlert,
			});
		}

		_eventRows.Clear();
		foreach (RdpAudit.Core.Events.EventDescriptor descriptor in EventCatalog.All)
		{
			string key = NotificationCatalogInfo.EventKey(descriptor.EventId);
			bool showEvent = NotificationCatalogInfo.EventVisibleByDefault(descriptor);
			if (dto.ShowEvents.TryGetValue(key, out bool configured))
			{
				showEvent = configured;
			}

			_eventRows.Add(new EventVisibilityRow
			{
				EventId = descriptor.EventId,
				Channel = descriptor.Channel,
				Name = descriptor.EffectivePurpose,
				Criticality = descriptor.Criticality.ToString(),
				Show = showEvent,
			});
		}
	}

	internal NotificationSettingsDto CaptureFromControls()
	{
		Dictionary<string, bool> showAlerts = new(StringComparer.OrdinalIgnoreCase);
		foreach (AlertVisibilityRow row in _alertRows)
		{
			showAlerts[row.RuleId] = row.Show;
		}

		Dictionary<string, bool> showEvents = new(StringComparer.Ordinal);
		foreach (EventVisibilityRow row in _eventRows)
		{
			showEvents[row.EventId.ToString(CultureInfo.InvariantCulture)] = row.Show;
		}

		return new NotificationSettingsDto
		{
			EnableTrayNotifier = _enableTray.Checked,
			StartWithWindows = _startWithWindows.Checked,
			UseNativeToasts = _useNativeToasts.Checked,
			PollIntervalSeconds = decimal.ToInt32(_pollInterval.Value),
			MaxToastsPerMinute = decimal.ToInt32(_maxToasts.Value),
			MinimumSeverity = _minimumSeverity.SelectedItem is SeverityChoice severityChoice ? severityChoice.Severity.ToString() : AlertSeverity.High.ToString(),
			ShowAlerts = showAlerts,
			ShowEvents = showEvents,
		};
	}


	internal void MarkDirty()
	{
		_dirty = true;
		SetStatus("Notification settings changed. Save changes to persist.");
	}

	internal BindingList<AlertVisibilityRow> AlertRows => _alertRows;

	internal BindingList<EventVisibilityRow> EventRows => _eventRows;

	internal string StatusText => _statusLabel.Text ?? string.Empty;

	private void SetControlsEnabled(bool enabled)
	{
		_enableTray.Enabled = enabled;
		_startWithWindows.Enabled = enabled;
		_useNativeToasts.Enabled = enabled;
		_pollInterval.Enabled = enabled;
		_maxToasts.Enabled = enabled;
		_minimumSeverity.Enabled = enabled;
		_alertsGrid.Enabled = enabled;
		_eventsGrid.Enabled = enabled;
		_saveButton.Enabled = enabled;
		_refreshButton.Enabled = enabled;
	}

	/// <summary>Applies the tray-notifier autostart state and returns the status line to show. Awaited
	/// rather than blocked on: the schtasks.exe round-trip it drives may legitimately take seconds and
	/// must not freeze the tab the operator just clicked Save on.</summary>
	private async Task<string> ApplyAutostartAsync(bool startWithWindows)
	{
		if (_autostart is null)
		{
			return "Notification settings saved.";
		}

		NotifierAutostartResult autostart = await _autostart.ApplyAsync(startWithWindows).ConfigureAwait(true);
		return autostart.Success
			? "Notification settings saved. " + autostart.Message
			: "Notification settings saved, but autostart failed: " + autostart.Message;
	}

	private void SetStatus(string text, bool isError = false)
	{
		_statusLabel.Text = text;
		_statusLabel.ForeColor = isError ? Color.IndianRed : SystemColors.ControlText;
	}

	private sealed record SeverityChoice(AlertSeverity Severity)
	{
		public override string ToString() => Severity.ToString();
	}

	internal sealed class AlertVisibilityRow
	{
		public string RuleId { get; init; } = string.Empty;
		public string Name { get; init; } = string.Empty;
		public string Severity { get; init; } = string.Empty;
		public bool Show { get; set; } = true;
	}

	internal sealed class EventVisibilityRow
	{
		public int EventId { get; init; }
		public string Channel { get; init; } = string.Empty;
		public string Name { get; init; } = string.Empty;
		public string Criticality { get; init; } = string.Empty;
		public bool Show { get; set; }
	}
}
