// File:    src/RdpAudit.Configurator/Forms/SessionMapPage.cs
// Module:  RdpAudit.Configurator.Forms
// Purpose: Session Map tab (Backlog #6). Lists recent RdpConnectionFacts over the existing
//          ListConnectionFacts IPC command with IP/User filters, and on row selection loads the
//          selected session's GetSessionTimeline (ordinal 72): an event table (time, kind,
//          event id, process/object, correlation method, DEBUG detail in tooltip) plus the
//          owner-drawn SessionGanttPanel. Read-only: this page never mutates service state.
// Depends: IpcClient, ConnectionFactsDto, SessionTimelineDto, SessionGanttPanel, DarkTheme
// Extends: Add export/copy actions when the backlog requests timeline export.

using System.Globalization;
using System.Runtime.Versioning;
using RdpAudit.Configurator.Controls;
using RdpAudit.Configurator.Ipc;
using RdpAudit.Configurator.Theming;
using RdpAudit.Core.Ipc;
using RdpAudit.Core.Ipc.Contracts;
using RdpAudit.Core.Sessions;
using static RdpAudit.Configurator.Theming.DarkTheme;

namespace RdpAudit.Configurator.Forms;

/// <summary>Session Map viewer tab.</summary>
[SupportedOSPlatform("windows")]
public sealed class SessionMapPage : TabPage
{
	private readonly IpcClient _ipc;

	private readonly TextBox _ipFilter;
	private readonly TextBox _userFilter;
	private readonly NumericUpDown _maxRows;
	private readonly Button _refresh;
	private readonly Label _status;

	private readonly DataGridView _factsGrid;
	private readonly DataGridView _eventsGrid;
	private readonly ToolTip _gridToolTip = new();
	private readonly Label _detailSummary;
	private readonly SessionGanttPanel _gantt;

	private readonly List<ConnectionFactDto> _facts = new();
	private long _selectedFactId = -1;
	private int _timelineLoadToken;

	public SessionMapPage(IpcClient ipc)
	{
		_ipc = ipc;
		Text = "\U0001F5FA\uFE0F Session Map";

		// --- Filter / action bar ------------------------------------------------------------
		FlowLayoutPanel filters = new()
		{
			Dock = DockStyle.Top,
			Height = 44,
			Padding = new Padding(4),
			WrapContents = false,
			AutoScroll = true,
		};

		_ipFilter = new TextBox { Width = 170, PlaceholderText = "IP filter (substring)" };
		_userFilter = new TextBox { Width = 170, PlaceholderText = "User filter (substring)" };
		_maxRows = new NumericUpDown { Minimum = 1, Maximum = 1000, Value = 200, Width = 70 };
		_refresh = new Button { Text = "Refresh", Width = 90 };
		_refresh.Click += async (_, _) => await ReloadAsync().ConfigureAwait(true);

		filters.Controls.Add(new Label { Text = "IP:", AutoSize = true, Padding = new Padding(2, 8, 0, 0) });
		filters.Controls.Add(_ipFilter);
		filters.Controls.Add(new Label { Text = "User:", AutoSize = true, Padding = new Padding(6, 8, 0, 0) });
		filters.Controls.Add(_userFilter);
		filters.Controls.Add(new Label { Text = "Max rows:", AutoSize = true, Padding = new Padding(6, 8, 0, 0) });
		filters.Controls.Add(_maxRows);
		filters.Controls.Add(_refresh);

		// --- Session list -------------------------------------------------------------------
		_factsGrid = new DataGridView
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
		_factsGrid.Columns.Add(NewColumn("Id", "Fact", 40));
		_factsGrid.Columns.Add(NewColumn("Ip", "IP", 90));
		_factsGrid.Columns.Add(NewColumn("User", "User", 90));
		_factsGrid.Columns.Add(NewColumn("Domain", "Domain", 80));
		_factsGrid.Columns.Add(NewColumn("WtsSessionId", "Session", 50));
		_factsGrid.Columns.Add(NewColumn("LogonId", "LogonId", 70));
		_factsGrid.Columns.Add(NewColumn("FirstSeen", "First seen (UTC)", 100));
		_factsGrid.Columns.Add(NewColumn("LastSeen", "Last seen (UTC)", 100));
		_factsGrid.Columns.Add(NewColumn("State", "State", 60));
		_factsGrid.SelectionChanged += (_, _) => OnSelectedFactChanged();
		DataGridClipboardMenu.AttachWithExport(_factsGrid, "Session map — facts", ReportExportStatus);

		// --- Detail pane: summary + event table + Gantt -----------------------------------
		_detailSummary = new Label
		{
			Dock = DockStyle.Top,
			Height = 54,
			AutoSize = false,
			TextAlign = ContentAlignment.TopLeft,
			Padding = new Padding(6, 4, 4, 0),
			Text = "Select a session to view its timeline.",
		};

		_eventsGrid = new DataGridView
		{
			Dock = DockStyle.Fill,
			ReadOnly = true,
			AllowUserToAddRows = false,
			AllowUserToDeleteRows = false,
			AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill,
			SelectionMode = DataGridViewSelectionMode.FullRowSelect,
			MultiSelect = true,
			RowHeadersVisible = false,
			AllowUserToResizeRows = false,
		};
		_eventsGrid.Columns.Add(NewColumn("Time", "Time (UTC)", 90));
		_eventsGrid.Columns.Add(NewColumn("Kind", "Kind", 70));
		_eventsGrid.Columns.Add(NewColumn("EventId", "Event", 42));
		_eventsGrid.Columns.Add(NewColumn("Channel", "Channel", 70));
		_eventsGrid.Columns.Add(NewColumn("Process", "Process", 90));
		_eventsGrid.Columns.Add(NewColumn("CommandLine", "Command line", 120));
		_eventsGrid.Columns.Add(NewColumn("ObjectName", "Object", 90));
		_eventsGrid.Columns.Add(NewColumn("Correlation", "Correlation", 70));
		_eventsGrid.CellMouseEnter += OnEventCellMouseEnter;
		_eventsGrid.CellMouseLeave += (_, _) => _eventsGrid.Cursor = Cursors.Default;
		DataGridClipboardMenu.AttachWithExport(_eventsGrid, "Session map — events", ReportExportStatus);

		_gantt = new SessionGanttPanel { Dock = DockStyle.Bottom, Height = 220 };

		Panel detailPanel = new() { Dock = DockStyle.Fill };
		detailPanel.Controls.Add(_eventsGrid);
		detailPanel.Controls.Add(_gantt);
		detailPanel.Controls.Add(_detailSummary);

		SplitContainer split = new()
		{
			Dock = DockStyle.Fill,
			Orientation = Orientation.Vertical,
			SplitterDistance = 600,
		};
		split.Panel1.Controls.Add(_factsGrid);
		split.Panel2.Controls.Add(detailPanel);

		_status = new Label
		{
			Dock = DockStyle.Bottom,
			Height = 24,
			TextAlign = ContentAlignment.MiddleLeft,
			Padding = new Padding(6, 0, 0, 0),
			Text = "Ready",
		};

		Controls.Add(split);
		Controls.Add(_status);
		Controls.Add(filters);

		Disposed += (_, _) => _gridToolTip.Dispose();
		HandleCreated += async (_, _) => await ReloadAsync().ConfigureAwait(true);
	}

	/// <summary>Reports an export result through the page status label.</summary>
	private void ReportExportStatus(string message)
	{
		_status.Text = message;
		_status.ForeColor = TextPrimary;
	}

	private static DataGridViewTextBoxColumn NewColumn(string name, string header, int fillWeight) => new()
	{
		Name = name,
		HeaderText = header,
		FillWeight = fillWeight,
		SortMode = DataGridViewColumnSortMode.NotSortable,
	};

	private async Task ReloadAsync()
	{
		_refresh.Enabled = false;
		_status.Text = "Loading sessions\u2026";
		_status.ForeColor = TextPrimary;
		try
		{
			ConnectionFactsRequest request = new()
			{
				IpQuery = string.IsNullOrWhiteSpace(_ipFilter.Text) ? null : _ipFilter.Text.Trim(),
				UserQuery = string.IsNullOrWhiteSpace(_userFilter.Text) ? null : _userFilter.Text.Trim(),
				Limit = (int)_maxRows.Value,
			};

			IpcCallResult<ConnectionFactsDto> call =
				await _ipc.SendDetailedAsync<ConnectionFactsDto>(IpcCommand.ListConnectionFacts, request).ConfigureAwait(true);

			if (!call.IsSuccess || call.Value is not { } list)
			{
				_status.Text = "Session list unavailable: " + call.Headline();
				_status.ForeColor = StatusDanger;
				return;
			}

			if (list.Status != IpcResultStatus.Success)
			{
				_status.Text = "Session list failed: " + (list.Message ?? list.Status.ToString());
				_status.ForeColor = StatusDanger;
				return;
			}

			_facts.Clear();
			_facts.AddRange(list.Facts);
			BindFactsGrid();
			ClearTimeline();

			_status.Text = string.Format(
				CultureInfo.InvariantCulture,
				"Showing {0} of {1} sessions (server limit {2}).",
				list.Facts.Count, list.TotalMatching, list.AppliedLimit);
			_status.ForeColor = TextPrimary;
		}
		catch (Exception ex)
		{
			_status.Text = "Session map error: " + ex.GetType().Name;
			_status.ForeColor = StatusDanger;
		}
		finally
		{
			_refresh.Enabled = true;
		}
	}

	private void BindFactsGrid()
	{
		_factsGrid.Rows.Clear();
		foreach (ConnectionFactDto fact in _facts)
		{
			int idx = _factsGrid.Rows.Add(
				fact.Id.ToString(CultureInfo.InvariantCulture),
				fact.Ip,
				fact.UserName ?? string.Empty,
				fact.Domain ?? string.Empty,
				fact.WtsSessionId?.ToString(CultureInfo.InvariantCulture) ?? string.Empty,
				fact.LogonId ?? string.Empty,
				FormatUtc(fact.FirstSeenUtc),
				FormatUtc(fact.LastSeenUtc),
				fact.IsActive ? "Active" : "Closed");

			DataGridViewRow row = _factsGrid.Rows[idx];
			row.Tag = fact.Id;
			row.DefaultCellStyle.ForeColor = fact.IsActive ? StatusSuccess : TextPrimary;
		}
	}

	private void OnSelectedFactChanged()
	{
		if (_factsGrid.CurrentRow is null || _factsGrid.CurrentRow.Tag is not long factId)
		{
			ClearTimeline();
			return;
		}

		_selectedFactId = factId;
		_ = LoadTimelineAsync(factId);
	}

	private async Task LoadTimelineAsync(long factId)
	{
		int generation = ++_timelineLoadToken;
		_detailSummary.Text = "Loading timeline\u2026";
		_eventsGrid.Rows.Clear();
		_gantt.SetTimeline(null);
		try
		{
			IpcCallResult<SessionTimelineDto> call = await _ipc
				.SendDetailedAsync<SessionTimelineDto>(
					IpcCommand.GetSessionTimeline,
					new GetSessionTimelineRequest { SessionId = factId })
				.ConfigureAwait(true);

			if (generation != _timelineLoadToken || _selectedFactId != factId)
			{
				return;
			}

			if (!call.IsSuccess || call.Value is not { } timeline)
			{
				_detailSummary.Text = "Timeline unavailable: " + call.Headline();
				return;
			}

			if (timeline.Status == IpcResultStatus.NotFound)
			{
				_detailSummary.Text = "Session not found: " + (timeline.Message ?? factId.ToString(CultureInfo.InvariantCulture));
				return;
			}

			if (timeline.Status != IpcResultStatus.Success)
			{
				_detailSummary.Text = "Timeline query failed: " + (timeline.Message ?? timeline.Status.ToString());
				return;
			}

			RenderTimeline(timeline);
		}
		catch (Exception ex)
		{
			if (generation == _timelineLoadToken)
			{
				_detailSummary.Text = "Timeline error: " + ex.GetType().Name;
			}
		}
	}

	private void RenderTimeline(SessionTimelineDto timeline)
	{
		string state = timeline.IsActive ? "ACTIVE" : "closed";
		string end = timeline.EndUtc.HasValue ? FormatUtc(timeline.EndUtc.Value) : "open";
		string truncated = timeline.Truncated
			? string.Format(CultureInfo.InvariantCulture,
				"   |   TRUNCATED: {0} matching, cap {1}", timeline.TotalMatching, timeline.AppliedCap)
			: string.Empty;

		_detailSummary.Text = string.Format(
			CultureInfo.InvariantCulture,
			"{0} | {1}\\{2} | session {3} | logon {4} | {5} - {6} | {7} ({8:N0}s){9}",
			timeline.Ip,
			timeline.Domain ?? "-",
			timeline.UserName ?? "-",
			timeline.WtsSessionId?.ToString(CultureInfo.InvariantCulture) ?? "-",
			timeline.LogonId ?? "-",
			FormatUtc(timeline.StartUtc),
			end,
			state,
			timeline.DurationSeconds,
			truncated);
		_detailSummary.ForeColor = timeline.IsActive ? StatusSuccess : TextPrimary;

		_eventsGrid.Rows.Clear();
		foreach (SessionTimelineEventDto ev in timeline.Events)
		{
			int idx = _eventsGrid.Rows.Add(
				FormatUtc(ev.TimeUtc),
				ev.Kind.ToString(),
				ev.EventId > 0 ? ev.EventId.ToString(CultureInfo.InvariantCulture) : string.Empty,
				ev.Channel ?? string.Empty,
				ev.ProcessName ?? string.Empty,
				ev.CommandLine ?? string.Empty,
				ev.ObjectName ?? string.Empty,
				ev.CorrelationMethod.ToString());

			DataGridViewRow row = _eventsGrid.Rows[idx];
			row.Tag = ev;
			row.DefaultCellStyle.ForeColor = ev.CorrelationMethod == SessionTimelineCorrelationMethod.UserWindow
				? StatusWarning
				: TextPrimary;
		}

		_gantt.SetTimeline(timeline);
	}

	private void OnEventCellMouseEnter(object? sender, DataGridViewCellEventArgs e)
	{
		if (e.RowIndex < 0 || e.RowIndex >= _eventsGrid.Rows.Count)
		{
			_eventsGrid.Cursor = Cursors.Default;
			return;
		}

		DataGridViewRow row = _eventsGrid.Rows[e.RowIndex];
		if (row.Tag is SessionTimelineEventDto ev && !string.IsNullOrWhiteSpace(ev.Details))
		{
			_eventsGrid.Cursor = Cursors.Hand;
			// DEBUG-mode details: long raw text belongs in an ephemeral bubble, never a cell.
			ShowDetailsBubble(ev);
		}
		else
		{
			_eventsGrid.Cursor = Cursors.Default;
		}
	}

	private void ShowDetailsBubble(SessionTimelineEventDto ev)
	{
		// Single transient tooltip for the whole grid; truncated to avoid a wall of XML.
		string details = ev.Details ?? string.Empty;
		if (details.Length > 800)
		{
			details = details[..797] + "...";
		}

		_gridToolTip.SetToolTip(_eventsGrid, details);
	}

	private void ClearTimeline()
	{
		_timelineLoadToken++;
		_selectedFactId = -1;
		_detailSummary.Text = "Select a session to view its timeline.";
		_detailSummary.ForeColor = TextPrimary;
		_eventsGrid.Rows.Clear();
		_gantt.SetTimeline(null);
	}

	private static string FormatUtc(DateTime value)
		=> value.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture);
}
