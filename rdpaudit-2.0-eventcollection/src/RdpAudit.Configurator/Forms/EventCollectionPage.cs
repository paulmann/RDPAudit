/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : EventCollectionPage.cs
// Project: RdpAudit.Configurator (RdpAudit.Configurator.Forms)
// Purpose: Configurator tab exposing per-event enable/disable, presets (Minimal / Essential /
//          Full), per-event retention, and shard settings. Reads a cached snapshot from
//          CachedQueryService so the UI thread never blocks on SQLite or IPC.
// Depends: EventCatalogViewModel, CachedQueryService, IpcClient, DataGridView virtualisation
// Extends: When adding a new setting group, add a GroupBox + row-set below and route the
//          change through IpcClient.SendAsync so the service hot-reloads without restart.

using System.ComponentModel;
using System.Runtime.Versioning;
using RdpAudit.Configurator.Ipc;
using RdpAudit.Configurator.Services;

namespace RdpAudit.Configurator.Forms;

/// <summary>Event-collection administration tab: enable/disable per event, choose a preset,
/// tune per-event retention, and configure shard storage caps. All reads flow through
/// CachedQueryService; all writes flow through IpcClient.</summary>
[SupportedOSPlatform("windows")]
public sealed class EventCollectionPage : UserControl
{
	// ── Fields & DI ──────────────────────────────────────────────────────────────

	private readonly CachedQueryService _queries;
	private readonly IpcClient _ipc;

	private readonly DataGridView _grid;
	private readonly ComboBox _presetCombo;
	private readonly Button _applyPresetButton;
	private readonly NumericUpDown _bulkRetentionDays;
	private readonly Button _applyBulkRetention;
	private readonly Label _staleness;

	private EventCatalogSnapshot? _current;
	private long _lastAppliedGeneration;

	// ── Construction ─────────────────────────────────────────────────────────────

	public EventCollectionPage(CachedQueryService queries, IpcClient ipc)
	{
		ArgumentNullException.ThrowIfNull(queries);
		ArgumentNullException.ThrowIfNull(ipc);

		_queries = queries;
		_ipc = ipc;

		SuspendLayout();

		_grid = new DataGridView
		{
			Dock = DockStyle.Fill,
			VirtualMode = true,
			AllowUserToAddRows = false,
			AllowUserToDeleteRows = false,
			ReadOnly = false,
			AutoGenerateColumns = false,
			SelectionMode = DataGridViewSelectionMode.FullRowSelect,
			MultiSelect = false,
			RowHeadersVisible = false,
			CellBorderStyle = DataGridViewCellBorderStyle.SingleHorizontal,
		};
		_grid.CellValueNeeded += OnCellValueNeeded;
		_grid.CellValuePushed += OnCellValuePushed;
		BuildColumns();

		_presetCombo = new ComboBox
		{
			DropDownStyle = ComboBoxStyle.DropDownList,
			Width = 160,
		};
		_presetCombo.Items.AddRange(new object[] { "Custom", "Minimal", "Essential", "Full" });
		_presetCombo.SelectedIndex = 2;

		_applyPresetButton = new Button { Text = "Apply preset", Width = 120 };
		_applyPresetButton.Click += OnApplyPreset;

		_bulkRetentionDays = new NumericUpDown
		{
			Minimum = 0,
			Maximum = 3650,
			Value = 180,
			Width = 80,
		};

		_applyBulkRetention = new Button { Text = "Apply to all events", Width = 160 };
		_applyBulkRetention.Click += OnApplyBulkRetention;

		_staleness = new Label
		{
			AutoSize = true,
			Text = "loading…",
			ForeColor = SystemColors.GrayText,
		};

		FlowLayoutPanel top = new()
		{
			Dock = DockStyle.Top,
			AutoSize = true,
			Padding = new Padding(6),
		};
		top.Controls.Add(new Label { Text = "Preset:", AutoSize = true, Padding = new Padding(0, 6, 0, 0) });
		top.Controls.Add(_presetCombo);
		top.Controls.Add(_applyPresetButton);
		top.Controls.Add(new Label { Text = "  Retention (days):", AutoSize = true, Padding = new Padding(0, 6, 0, 0) });
		top.Controls.Add(_bulkRetentionDays);
		top.Controls.Add(_applyBulkRetention);
		top.Controls.Add(_staleness);

		Controls.Add(_grid);
		Controls.Add(top);

		ResumeLayout(performLayout: true);
	}

	// ── Public API ───────────────────────────────────────────────────────────────

	/// <summary>Called by the host form when the page becomes visible or when a
	/// generation-stamp invalidation is pushed from the service.</summary>
	public async Task RefreshAsync(CancellationToken ct)
	{
		EventCatalogSnapshot snapshot = await _queries.GetEventCatalogAsync(ct).ConfigureAwait(true);
		if (snapshot.Generation == _lastAppliedGeneration)
		{
			return;
		}

		_current = snapshot;
		_lastAppliedGeneration = snapshot.Generation;
		_grid.RowCount = snapshot.Rows.Count;
		_staleness.Text = $"as of {snapshot.AsOfUtc:HH:mm:ss} UTC";
		_grid.Invalidate();
	}

	// ── Core Logic ───────────────────────────────────────────────────────────────

	private void BuildColumns()
	{
		_grid.Columns.Add(new DataGridViewCheckBoxColumn { HeaderText = "Enabled", Name = "Enabled", Width = 60 });
		_grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Event ID", Name = "EventId", Width = 80, ReadOnly = true });
		_grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Channel", Name = "Channel", Width = 260, ReadOnly = true });
		_grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Purpose", Name = "Purpose", Width = 320, ReadOnly = true });
		_grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Criticality", Name = "Criticality", Width = 100, ReadOnly = true });
		_grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Preset", Name = "Preset", Width = 80, ReadOnly = true });
		_grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "24h count", Name = "Count24h", Width = 80, ReadOnly = true });
		_grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Retention (d)", Name = "RetentionDays", Width = 110 });
		_grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Prereq", Name = "Prereq", Width = 100, ReadOnly = true });
	}

	private void OnCellValueNeeded(object? sender, DataGridViewCellValueEventArgs e)
	{
		EventCatalogSnapshot? snap = _current;
		if (snap is null || e.RowIndex < 0 || e.RowIndex >= snap.Rows.Count)
		{
			e.Value = null;
			return;
		}

		EventCatalogRow row = snap.Rows[e.RowIndex];
		e.Value = e.ColumnIndex switch
		{
			0 => row.IsEnabled,
			1 => row.EventId,
			2 => row.Channel,
			3 => row.Purpose,
			4 => row.Criticality,
			5 => row.PresetLabel,
			6 => row.Count24h,
			7 => row.RetentionDays == 0 ? "forever" : row.RetentionDays.ToString(System.Globalization.CultureInfo.InvariantCulture),
			8 => row.PrerequisiteSatisfied ? "OK" : "Missing",
			_ => null,
		};
	}

	private async void OnCellValuePushed(object? sender, DataGridViewCellValueEventArgs e)
	{
		EventCatalogSnapshot? snap = _current;
		if (snap is null || e.RowIndex < 0 || e.RowIndex >= snap.Rows.Count || e.Value is null)
		{
			return;
		}

		EventCatalogRow row = snap.Rows[e.RowIndex];

		try
		{
			if (e.ColumnIndex == 0 && e.Value is bool enabled)
			{
				await _ipc.SendEventEnablementAsync(row.EventId, enabled, CancellationToken.None).ConfigureAwait(true);
			}
			else if (e.ColumnIndex == 7 && e.Value is string retentionText
				&& int.TryParse(retentionText, out int days) && days >= 0)
			{
				await _ipc.SendEventRetentionAsync(row.EventId, days, CancellationToken.None).ConfigureAwait(true);
			}

			await RefreshAsync(CancellationToken.None).ConfigureAwait(true);
		}
		catch (Exception ex)
		{
			MessageBox.Show(this, ex.Message, "Apply failed", MessageBoxButtons.OK, MessageBoxIcon.Warning);
		}
	}

	private async void OnApplyPreset(object? sender, EventArgs e)
	{
		string preset = (_presetCombo.SelectedItem as string) ?? "Custom";
		if (preset == "Custom")
		{
			return;
		}

		try
		{
			await _ipc.ApplyPresetAsync(preset, CancellationToken.None).ConfigureAwait(true);
			await RefreshAsync(CancellationToken.None).ConfigureAwait(true);
		}
		catch (Exception ex)
		{
			MessageBox.Show(this, ex.Message, "Apply preset failed", MessageBoxButtons.OK, MessageBoxIcon.Warning);
		}
	}

	private async void OnApplyBulkRetention(object? sender, EventArgs e)
	{
		int days = (int)_bulkRetentionDays.Value;

		DialogResult confirm = MessageBox.Show(
			this,
			days == 0
				? "This will keep every enabled event forever. Continue?"
				: $"Apply {days}-day retention to every enabled event?",
			"Confirm bulk retention",
			MessageBoxButtons.OKCancel,
			MessageBoxIcon.Question);

		if (confirm != DialogResult.OK)
		{
			return;
		}

		try
		{
			await _ipc.ApplyBulkRetentionAsync(days, CancellationToken.None).ConfigureAwait(true);
			await RefreshAsync(CancellationToken.None).ConfigureAwait(true);
		}
		catch (Exception ex)
		{
			MessageBox.Show(this, ex.Message, "Bulk retention failed", MessageBoxButtons.OK, MessageBoxIcon.Warning);
		}
	}
}

/// <summary>Immutable snapshot handed from the cache to the UI. Rows are prebuilt off the UI
/// thread so the grid never queries SQLite or IPC on the pump.</summary>
public sealed class EventCatalogSnapshot
{
	public required long Generation { get; init; }

	public required DateTime AsOfUtc { get; init; }

	public required IReadOnlyList<EventCatalogRow> Rows { get; init; }
}

/// <summary>One row's projection for the grid.</summary>
public sealed class EventCatalogRow
{
	public required int EventId { get; init; }

	public required string Channel { get; init; }

	public required string Purpose { get; init; }

	public required string Criticality { get; init; }

	public required string PresetLabel { get; init; }

	public required long Count24h { get; init; }

	public required int RetentionDays { get; init; }

	public required bool IsEnabled { get; init; }

	public required bool PrerequisiteSatisfied { get; init; }
}
