/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : EventCollectionPage.cs
// Project: RdpAudit.Configurator (RdpAudit.Configurator.Forms)
// Purpose: Configures catalog event enablement and per-event retention through the service IPC boundary.
// Depends: IpcClient, EventCollectionSettingsDto, EventCollectionMutationRequest, SortableGrid
// Extends: Add editable catalog fields and their corresponding IPC contract fields when collection policy expands.

using System.ComponentModel;
using System.Globalization;
using System.Runtime.Versioning;
using RdpAudit.Configurator.Ipc;
using RdpAudit.Configurator.Services;
using RdpAudit.Core.Events;
using RdpAudit.Core.Ipc;
using RdpAudit.Core.Ipc.Contracts;

namespace RdpAudit.Configurator.Forms;

/// <summary>Catalog-backed Event Collection configuration page.</summary>
[SupportedOSPlatform("windows")]
public sealed class EventCollectionPage : TabPage
{
	private const int MaximumRetentionDays = 36_500;

	private readonly IpcClient _ipc;
	private readonly DataGridView _grid;
	private readonly BindingList<EventCollectionRow> _rows = new();
	private readonly ComboBox _presetCombo;
	private readonly NumericUpDown _bulkRetentionDays;
	private readonly Button _applyPresetButton;
	private readonly Button _applyRetentionButton;
	private readonly Button _saveButton;
	private readonly Button _refreshButton;
	private readonly ToolStripStatusLabel _statusLabel;

	private bool _loading;
	private bool _dirty;

	public EventCollectionPage(IpcClient ipc)
	{
		ArgumentNullException.ThrowIfNull(ipc);
		_ipc = ipc;
		Text = "Event Collection";

		_presetCombo = new ComboBox
		{
			DropDownStyle = ComboBoxStyle.DropDownList,
			Dock = DockStyle.Fill,
		};
		_presetCombo.Items.AddRange(
		[
			new PresetChoice(EventPreset.Minimal),
			new PresetChoice(EventPreset.Essential),
			new PresetChoice(EventPreset.Full),
			new PresetChoice(EventPreset.Custom),
		]);
		_presetCombo.SelectedIndex = 1;

		_applyPresetButton = new Button
		{
			Text = "Apply preset",
			Dock = DockStyle.Fill,
		};
		_applyPresetButton.Click += async (_, _) => await ApplyPresetAsync().ConfigureAwait(true);

		_bulkRetentionDays = new NumericUpDown
		{
			Minimum = 0,
			Maximum = MaximumRetentionDays,
			Value = 180,
			Dock = DockStyle.Fill,
		};

		_applyRetentionButton = new Button
		{
			Text = "Set selected retention",
			Dock = DockStyle.Fill,
		};
		_applyRetentionButton.Click += (_, _) => ApplyBulkRetention();

		_saveButton = new Button
		{
			Text = "Save changes",
			Dock = DockStyle.Fill,
		};
		_saveButton.Click += async (_, _) => await SaveAsync().ConfigureAwait(true);

		_refreshButton = new Button
		{
			Text = "Refresh",
			Dock = DockStyle.Fill,
		};
		_refreshButton.Click += async (_, _) => await RefreshAsync().ConfigureAwait(true);

		_grid = new DataGridView
		{
			Dock = DockStyle.Fill,
			AutoGenerateColumns = false,
			AllowUserToAddRows = false,
			AllowUserToDeleteRows = false,
			RowHeadersVisible = false,
			SelectionMode = DataGridViewSelectionMode.FullRowSelect,
			MultiSelect = true,
		};
		ConfigureGridColumns();
		_grid.DataSource = _rows;
		_grid.CurrentCellDirtyStateChanged += OnCurrentCellDirtyStateChanged;
		_grid.CellValueChanged += OnCellValueChanged;
		_grid.CellValidating += OnCellValidating;
		_grid.DataError += (_, _) => SetStatus("Enter a whole number of retention days.", isError: true);
		SortableGrid.Enable(_grid, _rows);

		TableLayoutPanel toolbar = BuildToolbar();
		StatusStrip statusStrip = new();
		_statusLabel = new ToolStripStatusLabel("Loading Event Collection settings...");
		statusStrip.Items.Add(_statusLabel);

		Controls.Add(_grid);
		Controls.Add(statusStrip);
		Controls.Add(toolbar);

		HandleCreated += async (_, _) => await RefreshAsync().ConfigureAwait(true);
	}

	private TableLayoutPanel BuildToolbar()
	{
		TableLayoutPanel toolbar = new()
		{
			Dock = DockStyle.Top,
			AutoSize = true,
			ColumnCount = 9,
			Padding = new Padding(8),
		};
		toolbar.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
		toolbar.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 120));
		toolbar.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 120));
		toolbar.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
		toolbar.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 90));
		toolbar.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 170));
		toolbar.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 120));
		toolbar.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 90));
		toolbar.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));

		toolbar.Controls.Add(new Label
		{
			Text = "Preset:",
			AutoSize = true,
			Anchor = AnchorStyles.Left,
		}, 0, 0);
		toolbar.Controls.Add(_presetCombo, 1, 0);
		toolbar.Controls.Add(_applyPresetButton, 2, 0);
		toolbar.Controls.Add(new Label
		{
			Text = "Selected retention:",
			AutoSize = true,
			Anchor = AnchorStyles.Left,
		}, 3, 0);
		toolbar.Controls.Add(_bulkRetentionDays, 4, 0);
		toolbar.Controls.Add(_applyRetentionButton, 5, 0);
		toolbar.Controls.Add(_saveButton, 6, 0);
		toolbar.Controls.Add(_refreshButton, 7, 0);
		toolbar.Controls.Add(new Label
		{
			Text = "0 retention days means retain forever.",
			AutoSize = true,
			Anchor = AnchorStyles.Left,
		}, 8, 0);

		return toolbar;
	}

	private void ConfigureGridColumns()
	{
		_grid.Columns.Add(new DataGridViewTextBoxColumn
		{
			DataPropertyName = nameof(EventCollectionRow.EventId),
			HeaderText = "Event ID",
			ReadOnly = true,
			Width = 80,
		});
		_grid.Columns.Add(new DataGridViewTextBoxColumn
		{
			DataPropertyName = nameof(EventCollectionRow.Channel),
			HeaderText = "Channel",
			ReadOnly = true,
			Width = 250,
		});
		_grid.Columns.Add(new DataGridViewTextBoxColumn
		{
			DataPropertyName = nameof(EventCollectionRow.DisplayName),
			HeaderText = "Name",
			ReadOnly = true,
			Width = 180,
		});
		_grid.Columns.Add(new DataGridViewTextBoxColumn
		{
			DataPropertyName = nameof(EventCollectionRow.Criticality),
			HeaderText = "Criticality",
			ReadOnly = true,
			Width = 100,
		});
		_grid.Columns.Add(new DataGridViewTextBoxColumn
		{
			DataPropertyName = nameof(EventCollectionRow.Layer),
			HeaderText = "Layer",
			ReadOnly = true,
			Width = 120,
		});
		_grid.Columns.Add(new DataGridViewCheckBoxColumn
		{
			DataPropertyName = nameof(EventCollectionRow.IsEnabled),
			HeaderText = "Enabled",
			Width = 65,
		});
		_grid.Columns.Add(new DataGridViewTextBoxColumn
		{
			DataPropertyName = nameof(EventCollectionRow.RetentionDays),
			HeaderText = "Retention (days)",
			Width = 110,
		});
		_grid.Columns.Add(new DataGridViewTextBoxColumn
		{
			DataPropertyName = nameof(EventCollectionRow.Description),
			HeaderText = "Description",
			ReadOnly = true,
			AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill,
			MinimumWidth = 260,
		});
	}

	private async Task RefreshAsync()
	{
		SetControlsEnabled(false);
		SetStatus("Loading Event Collection settings...");
		IpcCallResult<List<EventCollectionSettingsDto>> call =
			await _ipc.SendDetailedAsync<List<EventCollectionSettingsDto>>(IpcCommand.GetEventCollectionSettings)
				.ConfigureAwait(true);
		if (!call.IsSuccess || call.Value is null)
		{
			SetStatus("Could not load Event Collection settings: " + call.Headline(), isError: true);
			SetControlsEnabled(true);
			return;
		}

		_loading = true;
		try
		{
			_rows.Clear();
			foreach (EventCollectionSettingsDto setting in call.Value)
			{
				_rows.Add(EventCollectionRow.FromDto(setting));
			}

			_dirty = false;
			SelectCurrentPreset();
			SetStatus(string.Format(
				CultureInfo.InvariantCulture,
				"Loaded {0} Event Collection settings at {1:u}.",
				_rows.Count,
				DateTime.UtcNow));
		}
		finally
		{
			_loading = false;
			SetControlsEnabled(true);
		}
	}

	private async Task ApplyPresetAsync()
	{
		if (_presetCombo.SelectedItem is not PresetChoice { Preset: not EventPreset.Custom } choice)
		{
			SetStatus("Select Minimal, Essential, or Full before applying a preset.", isError: true);
			return;
		}

		DialogResult confirmation = MessageBox.Show(
			this,
			string.Format(CultureInfo.InvariantCulture, "Apply the {0} event collection preset?", choice.Preset),
			"Apply Event Collection preset",
			MessageBoxButtons.OKCancel,
			MessageBoxIcon.Question);
		if (confirmation != DialogResult.OK)
		{
			return;
		}

		SetControlsEnabled(false);
		IpcCallResult<List<EventCollectionSettingsDto>> call = await _ipc
			.SendDetailedAsync<List<EventCollectionSettingsDto>>(
				IpcCommand.SaveEventCollectionSettings,
				new EventCollectionMutationRequest { Preset = choice.Preset })
			.ConfigureAwait(true);
		if (!call.IsSuccess || call.Value is null)
		{
			SetStatus("Could not apply preset: " + call.Headline(), isError: true);
			SetControlsEnabled(true);
			return;
		}

		ApplyReturnedSettings(call.Value, "Applied " + choice.Preset + " preset.");
		SetControlsEnabled(true);
	}

	private void ApplyBulkRetention()
	{
		int retentionDays = decimal.ToInt32(_bulkRetentionDays.Value);
		int affectedRows = 0;
		foreach (DataGridViewRow gridRow in _grid.SelectedRows)
		{
			if (gridRow.DataBoundItem is EventCollectionRow row)
			{
				row.RetentionDays = retentionDays;
				affectedRows++;
			}
		}

		if (affectedRows == 0)
		{
			SetStatus("Select one or more event rows before applying retention.", isError: true);
			return;
		}

		_grid.Refresh();
		_dirty = true;
		_presetCombo.SelectedItem = new PresetChoice(EventPreset.Custom);
		SetStatus(string.Format(
			CultureInfo.InvariantCulture,
			"Set retention to {0} days for {1} selected event rows. Save changes to persist.",
			retentionDays,
			affectedRows));
	}

	private async Task SaveAsync()
	{
		if (!_dirty)
		{
			SetStatus("There are no unsaved Event Collection changes.");
			return;
		}

		_grid.EndEdit();
		List<EventCollectionSettingsDto> settings = new(_rows.Count);
		foreach (EventCollectionRow row in _rows)
		{
			settings.Add(row.ToDto());
		}

		SetControlsEnabled(false);
		IpcCallResult<List<EventCollectionSettingsDto>> call = await _ipc
			.SendDetailedAsync<List<EventCollectionSettingsDto>>(
				IpcCommand.SaveEventCollectionSettings,
				new EventCollectionMutationRequest { Settings = settings })
			.ConfigureAwait(true);
		if (!call.IsSuccess || call.Value is null)
		{
			SetStatus("Could not save Event Collection settings: " + call.Headline(), isError: true);
			SetControlsEnabled(true);
			return;
		}

		ApplyReturnedSettings(call.Value, "Event Collection settings saved.");
		SetControlsEnabled(true);
	}

	private void ApplyReturnedSettings(List<EventCollectionSettingsDto> settings, string status)
	{
		_loading = true;
		try
		{
			_rows.Clear();
			foreach (EventCollectionSettingsDto setting in settings)
			{
				_rows.Add(EventCollectionRow.FromDto(setting));
			}

			_dirty = false;
			SelectCurrentPreset();
			SetStatus(status);
		}
		finally
		{
			_loading = false;
		}
	}

	private void SelectCurrentPreset()
	{
		List<int> enabledEventIds = new();
		foreach (EventCollectionRow row in _rows)
		{
			if (row.IsEnabled)
			{
				enabledEventIds.Add(row.EventId);
			}
		}

		EventPreset preset = EventCatalog.ClassifyActiveSet(enabledEventIds);
		foreach (object? item in _presetCombo.Items)
		{
			if (item is PresetChoice choice && choice.Preset == preset)
			{
				_presetCombo.SelectedItem = item;
				return;
			}
		}
	}

	private void OnCurrentCellDirtyStateChanged(object? sender, EventArgs e)
	{
		if (_grid.IsCurrentCellDirty)
		{
			_grid.CommitEdit(DataGridViewDataErrorContexts.Commit);
		}
	}

	private void OnCellValueChanged(object? sender, DataGridViewCellEventArgs e)
	{
		if (_loading || e.RowIndex < 0)
		{
			return;
		}

		_dirty = true;
		_presetCombo.SelectedItem = new PresetChoice(EventPreset.Custom);
		SetStatus("Event Collection settings changed. Save changes to persist.");
	}

	private void OnCellValidating(object? sender, DataGridViewCellValidatingEventArgs e)
	{
		if (e.RowIndex < 0
			|| !string.Equals(_grid.Columns[e.ColumnIndex].DataPropertyName, nameof(EventCollectionRow.RetentionDays), StringComparison.Ordinal))
		{
			return;
		}

		string value = Convert.ToString(e.FormattedValue, CultureInfo.InvariantCulture) ?? string.Empty;
		if (!int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out int retentionDays)
			|| retentionDays < 0
			|| retentionDays > MaximumRetentionDays)
		{
			e.Cancel = true;
			SetStatus(string.Format(
				CultureInfo.InvariantCulture,
				"Retention must be a whole number from 0 to {0}; 0 means retain forever.",
				MaximumRetentionDays),
				isError: true);
		}
	}

	private void SetControlsEnabled(bool enabled)
	{
		_grid.Enabled = enabled;
		_presetCombo.Enabled = enabled;
		_bulkRetentionDays.Enabled = enabled;
		_applyPresetButton.Enabled = enabled;
		_applyRetentionButton.Enabled = enabled;
		_saveButton.Enabled = enabled;
		_refreshButton.Enabled = enabled;
	}

	private void SetStatus(string text, bool isError = false)
	{
		_statusLabel.Text = text;
		_statusLabel.ForeColor = isError ? Color.IndianRed : SystemColors.ControlText;
	}

	private sealed class EventCollectionRow
	{
		public int EventId { get; init; }
		public string Channel { get; init; } = string.Empty;
		public string DisplayName { get; init; } = string.Empty;
		public string Description { get; init; } = string.Empty;
		public string Criticality { get; init; } = string.Empty;
		public string Layer { get; init; } = string.Empty;
		public bool IsEnabled { get; set; }
		public int RetentionDays { get; set; }

		public static EventCollectionRow FromDto(EventCollectionSettingsDto dto) => new()
		{
			EventId = dto.EventId,
			Channel = dto.Channel,
			DisplayName = dto.DisplayName,
			Description = dto.Description,
			Criticality = dto.Criticality.ToString(),
			Layer = dto.Layer,
			IsEnabled = dto.IsEnabled,
			RetentionDays = dto.RetentionDays,
		};

		public EventCollectionSettingsDto ToDto() => new()
		{
			EventId = EventId,
			IsEnabled = IsEnabled,
			RetentionDays = RetentionDays,
		};
	}

	private sealed record PresetChoice(EventPreset Preset)
	{
		public override string ToString() => Preset.ToString();
	}
}
