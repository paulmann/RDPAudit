// File:    src/RdpAudit.Configurator/Forms/LogsPage.cs
// Module:  RdpAudit.Configurator.Forms
// Purpose: Operation-log viewer tab. Shows durable program-action logs (bans, firewall, settings,
//          cleanup, diagnostics, IPC failures, background-job faults) — NOT security attack events.
//          Bounded, filtered and paged over IPC (QueryOperationLogs); severity / source / text /
//          depth filters, refresh, copy, and a detail pane that surfaces DEBUG-only fields
//          (DetailsJson, StackTrace) when the service reports DEBUG mode is on.
// Extends: System.Windows.Forms.TabPage
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com
// Version: 1.1.0

using System.Globalization;
using System.Runtime.Versioning;
using System.Text;
using RdpAudit.Configurator.Ipc;
using RdpAudit.Core.Ipc;
using RdpAudit.Core.Ipc.Contracts;
using RdpAudit.Core.Models;

using RdpAudit.Configurator.Theming;
using static RdpAudit.Configurator.Theming.DarkTheme;

namespace RdpAudit.Configurator.Forms;

/// <summary>Operation-log viewer tab (program actions, paged and filtered over IPC).</summary>
[SupportedOSPlatform("windows")]
public sealed class LogsPage : TabPage
{
	private readonly IpcClient _ipc;

	private readonly ComboBox _severityFilter;
	private readonly TextBox _sourceFilter;
	private readonly TextBox _searchFilter;
	private readonly NumericUpDown _depthDays;
	private readonly NumericUpDown _pageSize;
	private readonly CheckBox _showNoise;
	private readonly CheckBox _expandDuplicates;
	private readonly Button _refresh;
	private readonly Button _prev;
	private readonly Button _next;
	private readonly Button _copy;
	private readonly Label _status;
	private readonly Label _debugBanner;
	private readonly DataGridView _grid;
	private readonly TextBox _detail;

	private readonly List<OperationLogDto> _rows = new();
	private int _page;
	private long _totalMatching;
	private bool _serverDebugMode;

	public LogsPage(IpcClient ipc)
	{
		_ipc = ipc;
		Text = "\U0001F4DC Logs";

		// --- Filter bar ---------------------------------------------------------------------------
		FlowLayoutPanel filters = new()
		{
			Dock = DockStyle.Top,
			Height = 40,
			Padding = new Padding(4),
			WrapContents = false,
			AutoScroll = true,
		};

		_severityFilter = new ComboBox
		{
			DropDownStyle = ComboBoxStyle.DropDownList,
			Width = 130,
		};
		_severityFilter.Items.AddRange(new object[] { "All severities", "Information+", "Warning+", "Error+", "Critical" });
		_severityFilter.SelectedIndex = 0;

		_sourceFilter = new TextBox { Width = 130, PlaceholderText = "Source (exact)" };
		_searchFilter = new TextBox { Width = 200, PlaceholderText = "Search text…" };

		_depthDays = new NumericUpDown { Minimum = 1, Maximum = 3650, Value = 60, Width = 70 };
		_pageSize = new NumericUpDown { Minimum = 1, Maximum = 1000, Value = 500, Width = 80 };

		// Default view hides Debug-classified rows and the high-volume IPC accept-loop / connection
		// chatter, and collapses consecutive identical rows. The two checkboxes let an operator opt back
		// into the full, ungrouped stream when investigating.
		_showNoise = new CheckBox
		{
			Text = "Show IPC/debug noise",
			AutoSize = true,
			Checked = false,
			Padding = new Padding(6, 8, 0, 0),
		};
		_showNoise.CheckedChanged += async (_, _) => await ReloadAsync(resetPage: true).ConfigureAwait(true);

		_expandDuplicates = new CheckBox
		{
			Text = "Expand duplicates",
			AutoSize = true,
			Checked = false,
			Padding = new Padding(6, 8, 0, 0),
		};
		_expandDuplicates.CheckedChanged += async (_, _) => await ReloadAsync(resetPage: true).ConfigureAwait(true);

		_refresh = new Button { Text = "Refresh", Width = 90 };
		_refresh.Click += async (_, _) => await ReloadAsync(resetPage: true).ConfigureAwait(true);

		filters.Controls.Add(new Label { Text = "Severity:", AutoSize = true, Padding = new Padding(2, 8, 0, 0) });
		filters.Controls.Add(_severityFilter);
		filters.Controls.Add(_sourceFilter);
		filters.Controls.Add(_searchFilter);
		filters.Controls.Add(new Label { Text = "Days:", AutoSize = true, Padding = new Padding(6, 8, 0, 0) });
		filters.Controls.Add(_depthDays);
		filters.Controls.Add(new Label { Text = "Page size:", AutoSize = true, Padding = new Padding(6, 8, 0, 0) });
		filters.Controls.Add(_pageSize);
		filters.Controls.Add(_showNoise);
		filters.Controls.Add(_expandDuplicates);
		filters.Controls.Add(_refresh);

		// --- Paging / actions bar ----------------------------------------------------------------
		FlowLayoutPanel pager = new()
		{
			Dock = DockStyle.Top,
			Height = 36,
			Padding = new Padding(4),
			WrapContents = false,
		};
		_prev = new Button { Text = "◀ Prev", Width = 80, Enabled = false };
		_next = new Button { Text = "Next ▶", Width = 80, Enabled = false };
		_copy = new Button { Text = "Copy page", Width = 90 };
		_prev.Click += async (_, _) => await ChangePageAsync(-1).ConfigureAwait(true);
		_next.Click += async (_, _) => await ChangePageAsync(+1).ConfigureAwait(true);
		_copy.Click += (_, _) => CopyPageToClipboard();
		_status = new Label { AutoSize = true, Padding = new Padding(8, 8, 0, 0), Text = "Ready" };
		pager.Controls.Add(_prev);
		pager.Controls.Add(_next);
		pager.Controls.Add(_copy);
		pager.Controls.Add(_status);

		_debugBanner = new Label
		{
			Dock = DockStyle.Top,
			Height = 22,
			TextAlign = ContentAlignment.MiddleLeft,
			Padding = new Padding(6, 0, 0, 0),
			ForeColor = Color.White,
			BackColor = Color.FromArgb(120, 90, 20),
			Text = "DEBUG MODE ENABLED — detail fields (DetailsJson, StackTrace) are shown.",
			Visible = false,
		};

		// --- Grid + detail pane (split) ----------------------------------------------------------
		_grid = new DataGridView
		{
			Dock = DockStyle.Fill,
			ReadOnly = true,
			AllowUserToAddRows = false,
			AllowUserToDeleteRows = false,
			AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill,
			SelectionMode = DataGridViewSelectionMode.FullRowSelect,
			MultiSelect = false,
			RowHeadersVisible = false,
			AllowUserToResizeRows = false,
		};
		_grid.Columns.Add(NewColumn("Time", "Time (UTC)", 90));
		_grid.Columns.Add(NewColumn("Severity", "Severity", 50));
		_grid.Columns.Add(NewColumn("Source", "Source", 60));
		_grid.Columns.Add(NewColumn("Operation", "Operation", 80));
		_grid.Columns.Add(NewColumn("Count", "Count", 30));
		_grid.Columns.Add(NewColumn("Message", "Message", 200));
		_grid.SelectionChanged += (_, _) => ShowSelectedDetail();

		_detail = new TextBox
		{
			Dock = DockStyle.Fill,
			Multiline = true,
			ReadOnly = true,
			ScrollBars = ScrollBars.Both,
			WordWrap = false,
			Font = new Font(FontFamily.GenericMonospace, 9),
		};

		SplitContainer split = new()
		{
			Dock = DockStyle.Fill,
			Orientation = Orientation.Horizontal,
			SplitterDistance = 420,
		};
		split.Panel1.Controls.Add(_grid);
		split.Panel2.Controls.Add(_detail);
		DataGridClipboardMenu.Attach(_grid);

		Controls.Add(split);
		Controls.Add(_debugBanner);
		Controls.Add(pager);
		Controls.Add(filters);

		HandleCreated += async (_, _) => await ReloadAsync(resetPage: true).ConfigureAwait(true);
	}

	private static DataGridViewTextBoxColumn NewColumn(string name, string header, int fillWeight) => new()
	{
		Name = name,
		HeaderText = header,
		FillWeight = fillWeight,
		SortMode = DataGridViewColumnSortMode.NotSortable,
	};

	private OperationLogSeverity? SelectedMinSeverity() => _severityFilter.SelectedIndex switch
	{
		1 => OperationLogSeverity.Information,
		2 => OperationLogSeverity.Warning,
		3 => OperationLogSeverity.Error,
		4 => OperationLogSeverity.Critical,
		_ => null,
	};

	private async Task ChangePageAsync(int delta)
	{
		int target = _page + delta;
		if (target < 0)
		{
			return;
		}

		_page = target;
		await ReloadAsync(resetPage: false).ConfigureAwait(true);
	}

	private async Task ReloadAsync(bool resetPage)
	{
		if (resetPage)
		{
			_page = 0;
		}

		_refresh.Enabled = false;
		_status.Text = "Loading…";
		try
		{
			OperationLogQueryRequest request = new()
			{
				DepthDays = (int)_depthDays.Value,
				MinSeverity = SelectedMinSeverity(),
				Source = string.IsNullOrWhiteSpace(_sourceFilter.Text) ? null : _sourceFilter.Text.Trim(),
				SearchText = string.IsNullOrWhiteSpace(_searchFilter.Text) ? null : _searchFilter.Text.Trim(),
				Page = _page,
				PageSize = (int)_pageSize.Value,
				ExcludeDebugNoise = !_showNoise.Checked,
				GroupDuplicates = !_expandDuplicates.Checked,
			};

			IpcCallResult<OperationLogPageDto> call =
				await _ipc.SendDetailedAsync<OperationLogPageDto>(IpcCommand.QueryOperationLogs, request).ConfigureAwait(true);

			if (!call.IsSuccess || call.Value is not { } page)
			{
				_status.Text = "Logs unavailable: " + call.Headline();
				return;
			}

			if (page.Status != IpcResultStatus.Success)
			{
				_status.Text = "Logs query failed: " + (page.Message ?? page.Status.ToString());
				return;
			}

			_rows.Clear();
			_rows.AddRange(page.Items);
			_totalMatching = page.TotalMatching;
			_serverDebugMode = page.DebugMode;
			_debugBanner.Visible = page.DebugMode;

			BindGrid();

			long shownFrom = _totalMatching == 0 ? 0 : ((long)_page * page.PageSize) + 1;
			long shownTo = shownFrom == 0 ? 0 : shownFrom + _rows.Count - 1;
			_status.Text = string.Format(
				CultureInfo.InvariantCulture,
				"Showing {0}-{1} of {2} (page {3}, depth {4}d){5}",
				shownFrom,
				shownTo,
				_totalMatching,
				_page + 1,
				page.DepthDays,
				page.DebugMode ? " — DEBUG" : string.Empty);

			_prev.Enabled = _page > 0;
			_next.Enabled = shownTo < _totalMatching;
		}
		catch (Exception ex)
		{
			_status.Text = "Logs error: " + ex.GetType().Name;
		}
		finally
		{
			_refresh.Enabled = true;
		}
	}

	private void BindGrid()
	{
		_grid.Rows.Clear();
		foreach (OperationLogDto row in _rows)
		{
			string message = row.OccurrenceCount > 1
				? string.Format(CultureInfo.InvariantCulture, "{0}  (×{1})", row.Message, row.OccurrenceCount)
				: row.Message;

			int idx = _grid.Rows.Add(
				row.TimeUtc.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture),
				row.Severity.ToString(),
				row.Source,
				row.Operation,
				row.OccurrenceCount > 1 ? row.OccurrenceCount.ToString(CultureInfo.InvariantCulture) : string.Empty,
				message);

			DataGridViewRow gridRow = _grid.Rows[idx];
			gridRow.DefaultCellStyle.ForeColor = SeverityColor(row.Severity);
		}

		_detail.Clear();
	}

	private static Color SeverityColor(OperationLogSeverity severity) => severity switch
	{
		OperationLogSeverity.Critical => StatusDanger,
		OperationLogSeverity.Error => StatusDanger,
		OperationLogSeverity.Warning => StatusWarning,
		_ => TextPrimary,
	};

	private void ShowSelectedDetail()
	{
		if (_grid.CurrentRow is null || _grid.CurrentRow.Index < 0 || _grid.CurrentRow.Index >= _rows.Count)
		{
			_detail.Clear();
			return;
		}

		OperationLogDto row = _rows[_grid.CurrentRow.Index];
		StringBuilder sb = new();
		sb.AppendLine(CultureInfo.InvariantCulture, $"Time (UTC) : {row.TimeUtc:yyyy-MM-dd HH:mm:ss.fff}");
		sb.AppendLine(CultureInfo.InvariantCulture, $"Severity   : {row.Severity}");
		sb.AppendLine(CultureInfo.InvariantCulture, $"Source     : {row.Source}");
		sb.AppendLine(CultureInfo.InvariantCulture, $"Operation  : {row.Operation}");
		if (!string.IsNullOrEmpty(row.Actor))
		{
			sb.AppendLine(CultureInfo.InvariantCulture, $"Actor      : {row.Actor}");
		}

		if (!string.IsNullOrEmpty(row.CorrelationId))
		{
			sb.AppendLine(CultureInfo.InvariantCulture, $"Correlation: {row.CorrelationId}");
		}

		if (row.DurationMs is { } ms)
		{
			sb.AppendLine(CultureInfo.InvariantCulture, $"Duration   : {ms} ms");
		}

		sb.AppendLine(CultureInfo.InvariantCulture, $"Message    : {row.Message}");

		if (!string.IsNullOrEmpty(row.ExceptionType) || !string.IsNullOrEmpty(row.ExceptionMessage))
		{
			sb.AppendLine();
			sb.AppendLine(CultureInfo.InvariantCulture, $"Exception  : {row.ExceptionType}");
			sb.AppendLine(CultureInfo.InvariantCulture, $"             {row.ExceptionMessage}");
		}

		if (_serverDebugMode)
		{
			if (!string.IsNullOrEmpty(row.DetailsJson))
			{
				sb.AppendLine();
				sb.AppendLine("Details (DEBUG):");
				sb.AppendLine(row.DetailsJson);
			}

			if (!string.IsNullOrEmpty(row.StackTrace))
			{
				sb.AppendLine();
				sb.AppendLine("Stack trace (DEBUG):");
				sb.AppendLine(row.StackTrace);
			}
		}

		_detail.Text = sb.ToString();
	}

	private void CopyPageToClipboard()
	{
		if (_rows.Count == 0)
		{
			_status.Text = "Nothing to copy.";
			return;
		}

		StringBuilder sb = new();
		sb.AppendLine("TimeUtc\tSeverity\tSource\tOperation\tMessage");
		foreach (OperationLogDto row in _rows)
		{
			sb.Append(row.TimeUtc.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture)).Append('\t')
				.Append(row.Severity).Append('\t')
				.Append(row.Source).Append('\t')
				.Append(row.Operation).Append('\t')
				.AppendLine(row.Message?.Replace('\t', ' ').Replace('\r', ' ').Replace('\n', ' '));
		}

		try
		{
			Clipboard.SetText(sb.ToString());
			_status.Text = string.Format(CultureInfo.InvariantCulture, "Copied {0} rows to clipboard.", _rows.Count);
		}
		catch (Exception ex)
		{
			_status.Text = "Copy failed: " + ex.GetType().Name;
		}
	}
}
