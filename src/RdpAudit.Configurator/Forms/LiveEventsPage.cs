// File:    src/RdpAudit.Configurator/Forms/LiveEventsPage.cs
// Module:  RdpAudit.Configurator.Forms
// Purpose: SOC-operator LiveEvents page. Combines a recent-event tail (over IPC GetRecentEvents)
//          with field filters, a per-cell right-click context menu (copy, filter, block, whitelist,
//          login-block), and a status strip that surfaces success/failure of every action with a
//          UTC timestamp. Writes always flow through IPC mutations on the service; the
//          Configurator never opens the SQLite file directly. Stage 4 of the RdpAudit roadmap.
// Extends: System.Windows.Forms.TabPage
//          v1.1.0 — the manually-shown right-click context menu is now themed explicitly via
//          DarkTheme.StyleMenu so it no longer renders with the light system colours.
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com
// Version: 1.1.0

using System.ComponentModel;
using System.Globalization;
using System.Net;
using System.Runtime.Versioning;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using RdpAudit.Configurator.Ipc;
using RdpAudit.Configurator.Services;
using RdpAudit.Configurator.Theming;
using RdpAudit.Core.Events;
using RdpAudit.Core.Ipc;
using RdpAudit.Core.Ipc.Contracts;
using RdpAudit.Core.Util;

namespace RdpAudit.Configurator.Forms;

/// <summary>
/// Live tail of recent events fetched over IPC, with filters, context-menu actions, and a status
/// strip that surfaces every operator action.
/// </summary>
/// <remarks>
/// <para>
/// Filtering is performed client-side over the bounded recent-event window returned by
/// <see cref="IpcCommand.GetRecentEvents"/> (currently 200 rows). When the IPC contract grows a
/// server-side query, the matching <see cref="LiveEventFilter"/> fields can be forwarded to the
/// service without changing this page's call sites.
/// </para>
/// <para>
/// All destructive actions (block, whitelist+unblock, login-block) require confirmation before
/// the IPC call and report both per-step outcome and a UTC timestamp in the status strip.
/// </para>
/// </remarks>
[SupportedOSPlatform("windows")]
public sealed class LiveEventsPage : TabPage
{
	private const int FilterDebounceMs = 350;

	private readonly IpcClient _ipc;
	private readonly DataGridView _grid;
	private readonly Label _info;
	private readonly Button _pause;
	private readonly System.Windows.Forms.Timer _timer;
	private readonly System.Windows.Forms.Timer _filterDebounce;
	private readonly StatusStrip _statusStrip;
	private readonly ToolStripStatusLabel _statusLabel;
	private readonly BindingList<LiveEventRow> _binding = new();
	private readonly List<LiveEventRow> _allRows = new();
	private readonly ContextMenuStrip _menu;

	private readonly TextBox _filterIp;
	private readonly TextBox _filterUser;
	private readonly TextBox _filterEventId;
	private readonly TextBox _filterChannel;
	private readonly TextBox _filterText;
	private readonly ComboBox _filterRange;
	private readonly Button _filterReset;

	private readonly ToolStripMenuItem _menuCopyDetails;
	private readonly ToolStripMenuItem _menuCopyCell;
	private readonly ToolStripMenuItem _menuFilterBy;
	private readonly ToolStripMenuItem _menuBlockIp;
	private readonly ToolStripMenuItem _menuWhitelistIp;
	private readonly ToolStripMenuItem _menuBlockLogin;
	private readonly ToolStripMenuItem _menuExportEvents;
	private readonly ToolStripMenuItem _menuExportFacts;
	private readonly ToolStripMenuItem _menuOpenRipeStat;
	private readonly ToolStripMenuItem _menuOpenAbuseIpDb;

	private bool _paused;
	private long _lastSeenId;
	private LiveEventRow? _menuRow;
	private DataGridViewColumn? _menuColumn;
	private string? _menuCellValue;

	public LiveEventsPage(IpcClient ipc)
	{
		_ipc = ipc;

		_grid = new DataGridView
		{
			Dock = DockStyle.Fill,
			AutoGenerateColumns = false,
			ReadOnly = true,
			RowHeadersVisible = false,
			AllowUserToAddRows = false,
			SelectionMode = DataGridViewSelectionMode.FullRowSelect,
			MultiSelect = false,
		};
		_grid.Columns.Add(new DataGridViewTextBoxColumn { Name = "Id", HeaderText = "Id", DataPropertyName = nameof(LiveEventRow.Id), Width = 70 });
		_grid.Columns.Add(new DataGridViewTextBoxColumn { Name = "TimeUtc", HeaderText = "Time (local)", DataPropertyName = nameof(LiveEventRow.TimeUtc), Width = 160 });
		_grid.Columns.Add(new DataGridViewTextBoxColumn { Name = "EventId", HeaderText = "Event", DataPropertyName = nameof(LiveEventRow.EventId), Width = 70 });
		_grid.Columns.Add(new DataGridViewTextBoxColumn { Name = "Channel", HeaderText = "Channel", DataPropertyName = nameof(LiveEventRow.Channel), Width = 220 });
		_grid.Columns.Add(new DataGridViewTextBoxColumn { Name = "UserName", HeaderText = "User", DataPropertyName = nameof(LiveEventRow.UserName), Width = 140 });
		_grid.Columns.Add(new DataGridViewTextBoxColumn { Name = "SourceIp", HeaderText = "IP", DataPropertyName = nameof(LiveEventRow.SourceIp), Width = 130 });
		_grid.Columns.Add(new DataGridViewTextBoxColumn { Name = "LogonType", HeaderText = "LogonType", DataPropertyName = nameof(LiveEventRow.LogonType), Width = 80 });
		_grid.Columns.Add(new DataGridViewTextBoxColumn { Name = "ProcessName", HeaderText = "Process", DataPropertyName = nameof(LiveEventRow.ProcessName), AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill });
		_grid.DataSource = _binding;
		_grid.CellMouseDown += OnCellMouseDown;
		_grid.CellFormatting += OnCellFormatting;

		_info = new Label { Dock = DockStyle.Top, Height = 22, Text = "Waiting for first event…" };

		_pause = new Button { Text = "Pause", Dock = DockStyle.Top, Height = 26 };
		_pause.Click += (_, _) =>
		{
			_paused = !_paused;
			_pause.Text = _paused ? "Resume" : "Pause";
			SetStatus(_paused ? "Live updates paused." : "Live updates resumed.");
		};

		// Filter row -----------------------------------------------------------------------------
		TableLayoutPanel filterBar = new()
		{
			Dock = DockStyle.Top,
			Height = 60,
			ColumnCount = 7,
			RowCount = 2,
			Padding = new Padding(4),
		};
		for (int i = 0; i < 7; i++)
		{
			filterBar.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100f / 7));
		}

		_filterIp = MakeFilterBox("IP contains…");
		_filterUser = MakeFilterBox("User contains…");
		_filterEventId = MakeFilterBox("EventId =");
		_filterChannel = MakeFilterBox("Channel contains…");
		_filterText = MakeFilterBox("Text in any field…");
		_filterRange = new ComboBox
		{
			Dock = DockStyle.Fill,
			DropDownStyle = ComboBoxStyle.DropDownList,
		};
		_filterRange.Items.AddRange(new object[]
		{
			"All time",
			"Last 5 minutes",
			"Last 15 minutes",
			"Last 60 minutes",
			"Last 24 hours",
		});
		_filterRange.SelectedIndex = 0;
		_filterRange.SelectedIndexChanged += (_, _) => ScheduleFilterRefresh();

		_filterReset = new Button { Text = "Clear filters", Dock = DockStyle.Fill };
		_filterReset.Click += (_, _) => ResetFilters();

		filterBar.Controls.Add(LabeledBox("IP", _filterIp), 0, 0);
		filterBar.Controls.Add(LabeledBox("User / login", _filterUser), 1, 0);
		filterBar.Controls.Add(LabeledBox("Event id", _filterEventId), 2, 0);
		filterBar.Controls.Add(LabeledBox("Channel", _filterChannel), 3, 0);
		filterBar.Controls.Add(LabeledBox("Text", _filterText), 4, 0);
		filterBar.Controls.Add(LabeledBox("Time range", _filterRange), 5, 0);
		filterBar.Controls.Add(LabeledBox(" ", _filterReset), 6, 0);

		// Status strip ---------------------------------------------------------------------------
		_statusStrip = new StatusStrip { SizingGrip = false };
		_statusLabel = new ToolStripStatusLabel("Ready.")
		{
			Spring = true,
			TextAlign = System.Drawing.ContentAlignment.MiddleLeft,
		};
		_statusStrip.Items.Add(_statusLabel);

		// Context menu ---------------------------------------------------------------------------
		_menu = new ContextMenuStrip();
		_menuCopyDetails = new ToolStripMenuItem("Copy Event Details", null, async (_, _) => await OnCopyDetailsAsync().ConfigureAwait(true));
		_menuCopyCell = new ToolStripMenuItem("Copy Cell Value", null, (_, _) => OnCopyCell());
		_menuFilterBy = new ToolStripMenuItem("Filter by This Value", null, (_, _) => OnFilterByCell());
		_menuBlockIp = new ToolStripMenuItem("Block IP in Windows Firewall and Add to Blocklist", null, async (_, _) => await OnBlockIpAsync().ConfigureAwait(true));
		_menuWhitelistIp = new ToolStripMenuItem("Add IP to Whitelist and Unblock", null, async (_, _) => await OnWhitelistAndUnblockAsync().ConfigureAwait(true));
		_menuBlockLogin = new ToolStripMenuItem("Add Login to Blocklist and Block IP", null, async (_, _) => await OnBlockLoginAsync().ConfigureAwait(true));
		_menuExportEvents = BuildExportSubmenu();
		_menuExportFacts = BuildExportFactsSubmenu();
		_menuOpenRipeStat = new ToolStripMenuItem(IpReputationBrowser.RipeStatMenuLabel, null, (_, _) => OnOpenRipeStat());
		_menuOpenAbuseIpDb = new ToolStripMenuItem(IpReputationBrowser.AbuseIpDbMenuLabel, null, (_, _) => OnOpenAbuseIpDb());
		_menu.Items.Add(_menuCopyDetails);
		_menu.Items.Add(_menuCopyCell);
		_menu.Items.Add(_menuFilterBy);
		_menu.Items.Add(new ToolStripSeparator());
		_menu.Items.Add(_menuBlockIp);
		_menu.Items.Add(_menuWhitelistIp);
		_menu.Items.Add(_menuBlockLogin);
		_menu.Items.Add(new ToolStripSeparator());
		_menu.Items.Add(_menuOpenRipeStat);
		_menu.Items.Add(_menuOpenAbuseIpDb);
		_menu.Items.Add(new ToolStripSeparator());
		_menu.Items.Add(_menuExportEvents);
		_menu.Items.Add(_menuExportFacts);
		_menu.Opening += OnMenuOpening;
		// This context menu is shown manually via _menu.Show(...) and is never assigned to a control's
		// ContextMenuStrip, so DarkTheme.Apply never reaches it. Theme it explicitly here (recursively,
		// including the export sub-menus) so its colours match the rest of the dark UI.
		DarkTheme.StyleMenu(_menu);

		// Layout order (last-added control is at the top when docked) ---------------------------
		Controls.Add(_grid);
		Controls.Add(_statusStrip);
		Controls.Add(_info);
		Controls.Add(_pause);
		Controls.Add(filterBar);

		_filterDebounce = new System.Windows.Forms.Timer { Interval = FilterDebounceMs };
		_filterDebounce.Tick += (_, _) =>
		{
			_filterDebounce.Stop();
			ApplyFilters();
		};

		_timer = new System.Windows.Forms.Timer { Interval = 2_000 };
		_timer.Tick += async (_, _) => await RefreshAsync().ConfigureAwait(true);
		HandleCreated += async (_, _) =>
		{
			_timer.Start();
			await RefreshAsync().ConfigureAwait(true);
		};
	}

	// ---------------------------------------------------------------------------------------------
	// Refresh and filtering
	// ---------------------------------------------------------------------------------------------

	private async Task RefreshAsync()
	{
		if (_paused)
		{
			return;
		}

		try
		{
			List<LiveEventRow>? rows = await _ipc.SendAsync<List<LiveEventRow>>(IpcCommand.GetRecentEvents).ConfigureAwait(true);
			rows ??= new List<LiveEventRow>();

			_allRows.Clear();
			_allRows.AddRange(rows);

			if (rows.Count > 0)
			{
				long latest = rows[0].Id;
				int newRows = rows.Count(r => r.Id > _lastSeenId);
				_lastSeenId = latest;
				_info.Text = string.Format(CultureInfo.InvariantCulture,
					"Latest id={0}  |  fetched={1}  |  new since last refresh={2}",
					latest, rows.Count, newRows);
			}
			else
			{
				_info.Text = "No events recorded yet (or service unreachable).";
			}

			ApplyFilters();
		}
		catch (Exception ex)
		{
			_info.Text = $"IPC read failed: {ex.GetType().Name}: {ex.Message}";
		}
	}

	private void ApplyFilters()
	{
		LiveEventFilter filter = BuildFilter();
		_binding.RaiseListChangedEvents = false;
		_binding.Clear();
		int kept = 0;
		foreach (LiveEventRow row in _allRows)
		{
			if (filter.Matches(row.ToView()))
			{
				_binding.Add(row);
				kept++;
			}
		}
		_binding.RaiseListChangedEvents = true;
		_binding.ResetBindings();

		if (!filter.IsEmpty)
		{
			_info.Text = string.Format(CultureInfo.InvariantCulture,
				"{0}  |  filter active: shown={1}/{2}",
				_info.Text, kept, _allRows.Count);
		}
	}

	private LiveEventFilter BuildFilter()
	{
		int? eventId = null;
		string idText = _filterEventId.Text.Trim();
		if (!string.IsNullOrEmpty(idText)
			&& int.TryParse(idText, NumberStyles.Integer, CultureInfo.InvariantCulture, out int parsedId))
		{
			eventId = parsedId;
		}

		DateTime? since = null;
		switch (_filterRange.SelectedIndex)
		{
			case 1:
				since = DateTime.UtcNow.AddMinutes(-5);
				break;
			case 2:
				since = DateTime.UtcNow.AddMinutes(-15);
				break;
			case 3:
				since = DateTime.UtcNow.AddMinutes(-60);
				break;
			case 4:
				since = DateTime.UtcNow.AddHours(-24);
				break;
			default:
				break;
		}

		return new LiveEventFilter
		{
			Ip = _filterIp.Text.Trim(),
			User = _filterUser.Text.Trim(),
			EventId = eventId,
			Channel = _filterChannel.Text.Trim(),
			Text = _filterText.Text.Trim(),
			SinceUtc = since,
		};
	}

	private void ScheduleFilterRefresh()
	{
		_filterDebounce.Stop();
		_filterDebounce.Start();
	}

	private void ResetFilters()
	{
		_filterIp.Text = string.Empty;
		_filterUser.Text = string.Empty;
		_filterEventId.Text = string.Empty;
		_filterChannel.Text = string.Empty;
		_filterText.Text = string.Empty;
		_filterRange.SelectedIndex = 0;
		ApplyFilters();
		SetStatus("Filters cleared.");
	}

	// ---------------------------------------------------------------------------------------------
	// Context menu
	// ---------------------------------------------------------------------------------------------

	private void OnCellFormatting(object? sender, DataGridViewCellFormattingEventArgs e)
	{
		if (e.RowIndex < 0 || e.RowIndex >= _binding.Count)
		{
			return;
		}

		DataGridViewColumn col = _grid.Columns[e.ColumnIndex];
		LiveEventRow row = _binding[e.RowIndex];

		// v1.2.1: render the persisted UTC timestamp as the operator's local time. The DB still
		// holds UTC; the column header reads "Time (local)" so the operator is never confused.
		if (string.Equals(col.Name, "TimeUtc", StringComparison.Ordinal))
		{
			e.Value = LocalTimeFormatter.FormatLocal(row.TimeUtc);
			e.FormattingApplied = true;
			return;
		}

		if (!string.Equals(col.Name, "SourceIp", StringComparison.Ordinal))
		{
			return;
		}

		// Stage 2: a row Stage-1 marked as SourceIpUnresolved persists failed-logon evidence
		// without a parseable attacker address. Render "(unresolved)" so operators can spot
		// brute-force pressure without misattributing it to an arbitrary placeholder.
		if (row.SourceIpUnresolved && string.IsNullOrWhiteSpace(row.SourceIp))
		{
			e.Value = "(unresolved)";
			e.FormattingApplied = true;
			DataGridViewCell cell = _grid.Rows[e.RowIndex].Cells[e.ColumnIndex];
			cell.ToolTipText =
				"Windows event semantically carried a source IP slot but the value was missing, blank, "
				+ "\"-\" or unparseable. No in-memory session correlation supplied one either.";
			return;
		}

		if (row.SourceIpDerived && !string.IsNullOrWhiteSpace(row.SourceIp))
		{
			e.Value = "• " + row.SourceIp;
			e.FormattingApplied = true;
			DataGridViewCell cell = _grid.Rows[e.RowIndex].Cells[e.ColumnIndex];
			cell.ToolTipText = "Derived from session correlation";
		}
	}

	private void OnCellMouseDown(object? sender, DataGridViewCellMouseEventArgs e)
	{
		if (e.Button != MouseButtons.Right || e.RowIndex < 0 || e.RowIndex >= _binding.Count)
		{
			return;
		}

		_grid.ClearSelection();
		_grid.Rows[e.RowIndex].Selected = true;
		_menuRow = _binding[e.RowIndex];
		_menuColumn = e.ColumnIndex >= 0 && e.ColumnIndex < _grid.Columns.Count
			? _grid.Columns[e.ColumnIndex]
			: null;
		_menuCellValue = NormaliseCellValue(_menuRow, _menuColumn?.Name);
		_menu.Show(_grid, _grid.PointToClient(Cursor.Position));
	}

	private void OnMenuOpening(object? sender, CancelEventArgs e)
	{
		bool hasRow = _menuRow is not null;
		bool hasIp = hasRow && IsValidIp(_menuRow!.SourceIp);
		bool hasLogin = hasRow && !string.IsNullOrWhiteSpace(_menuRow!.UserName);
		bool hasCellValue = !string.IsNullOrWhiteSpace(_menuCellValue);

		bool reputationEligible = hasRow && IpReputationBrowser.IsLookupEligible(_menuRow!.SourceIp);
		_menuCopyDetails.Enabled = hasRow;
		_menuCopyCell.Enabled = hasCellValue;
		_menuFilterBy.Enabled = hasCellValue && _menuColumn is not null;
		_menuBlockIp.Enabled = hasIp;
		_menuWhitelistIp.Enabled = hasIp;
		_menuBlockLogin.Enabled = hasLogin;
		_menuExportEvents.Enabled = hasIp;
		_menuExportFacts.Enabled = hasIp;
		_menuOpenRipeStat.Enabled = reputationEligible;
		_menuOpenAbuseIpDb.Enabled = reputationEligible;

		if (!hasRow)
		{
			e.Cancel = true;
		}
	}

	private async Task OnCopyDetailsAsync()
	{
		if (_menuRow is null)
		{
			return;
		}

		try
		{
			LiveEventRowView view = _menuRow.ToView();
			string multiline = LiveEventRowFormatter.FormatMultiline(view);
			string tsv = LiveEventRowFormatter.FormatTsv(view);
			string payload = string.Format(CultureInfo.InvariantCulture, "{0}{1}{1}--- TSV ---{1}{2}",
				multiline, Environment.NewLine, tsv);
			SetClipboardText(payload);
			SetStatus(string.Format(CultureInfo.InvariantCulture,
				"Copied event details (Id={0}) to clipboard.", _menuRow.Id));
		}
		catch (Exception ex)
		{
			SetStatus("Copy failed: " + ex.GetType().Name);
		}

		await Task.CompletedTask.ConfigureAwait(true);
	}

	private void OnCopyCell()
	{
		if (string.IsNullOrWhiteSpace(_menuCellValue))
		{
			SetStatus("Nothing to copy: cell is empty.");
			return;
		}

		try
		{
			SetClipboardText(_menuCellValue!);
			SetStatus(string.Format(CultureInfo.InvariantCulture,
				"Copied cell '{0}' to clipboard.", _menuColumn?.Name ?? "value"));
		}
		catch (Exception ex)
		{
			SetStatus("Copy failed: " + ex.GetType().Name);
		}
	}

	private void OnOpenRipeStat()
	{
		if (_menuRow is null)
		{
			return;
		}

		IpReputationBrowser.LaunchOutcome outcome = IpReputationBrowser.OpenRipeStat(_menuRow.SourceIp);
		SetStatus(outcome.Format());
	}

	private void OnOpenAbuseIpDb()
	{
		if (_menuRow is null)
		{
			return;
		}

		IpReputationBrowser.LaunchOutcome outcome = IpReputationBrowser.OpenAbuseIpDb(_menuRow.SourceIp);
		SetStatus(outcome.Format());
	}

	private void OnFilterByCell()
	{
		if (_menuColumn is null || string.IsNullOrWhiteSpace(_menuCellValue))
		{
			return;
		}

		switch (_menuColumn.Name)
		{
			case "Id":
				_filterText.Text = _menuCellValue;
				break;
			case "TimeUtc":
				_filterText.Text = _menuCellValue;
				break;
			case "EventId":
				_filterEventId.Text = _menuCellValue;
				break;
			case "Channel":
				_filterChannel.Text = _menuCellValue;
				break;
			case "UserName":
				_filterUser.Text = _menuCellValue;
				break;
			case "SourceIp":
				_filterIp.Text = _menuCellValue;
				break;
			default:
				_filterText.Text = _menuCellValue;
				break;
		}

		ApplyFilters();
		SetStatus(string.Format(CultureInfo.InvariantCulture,
			"Filter applied: {0} = '{1}'.", _menuColumn.Name, _menuCellValue));
	}

	private async Task OnBlockIpAsync()
	{
		if (_menuRow is null || !IsValidIp(_menuRow.SourceIp))
		{
			SetStatus("Block aborted: no valid IP in the selected row.");
			return;
		}

		string ip = _menuRow.SourceIp!.Trim();
		string prompt = string.Format(CultureInfo.InvariantCulture,
			"Block IP {0} in Windows Firewall and add it to the persistent blocklist?\r\n\r\n" +
			"This will block all inbound traffic from {0} until the entry is removed or expires.",
			ip);
		if (!Confirm(prompt, "Confirm block"))
		{
			SetStatus(string.Format(CultureInfo.InvariantCulture, "Block of {0} cancelled.", ip));
			return;
		}

		StringBuilder log = new();
		bool blockOk = await SendAddressMutationAsync(IpcCommand.AddToBlocklist, ip, "Manual block via LiveEvents", log).ConfigureAwait(true);
		bool legacyOk = await SendLegacyBlockAsync(ip, true, log).ConfigureAwait(true);

		string verdict = (blockOk || legacyOk) ? "OK" : "FAILED";
		SetStatus(string.Format(CultureInfo.InvariantCulture,
			"Block {0} ({1}). blocklist={2}, firewall={3}. Detail: {4}",
			ip, verdict, blockOk ? "OK" : "FAIL", legacyOk ? "OK" : "FAIL", log.ToString()));
	}

	private async Task OnWhitelistAndUnblockAsync()
	{
		if (_menuRow is null || !IsValidIp(_menuRow.SourceIp))
		{
			SetStatus("Whitelist aborted: no valid IP in the selected row.");
			return;
		}

		string ip = _menuRow.SourceIp!.Trim();
		string prompt = string.Format(CultureInfo.InvariantCulture,
			"Add {0} to the whitelist and unblock it in Windows Firewall?\r\n\r\n" +
			"Whitelist precedence will also soft-disable any active blocklist entry for {0}.",
			ip);
		if (!Confirm(prompt, "Confirm whitelist"))
		{
			SetStatus(string.Format(CultureInfo.InvariantCulture, "Whitelist of {0} cancelled.", ip));
			return;
		}

		StringBuilder log = new();
		bool wlOk = await SendAddressMutationAsync(IpcCommand.AddToWhitelist, ip, "Manual whitelist via LiveEvents", log).ConfigureAwait(true);
		bool legacyOk = await SendLegacyBlockAsync(ip, false, log).ConfigureAwait(true);

		string verdict = (wlOk || legacyOk) ? "OK" : "FAILED";
		SetStatus(string.Format(CultureInfo.InvariantCulture,
			"Whitelist {0} ({1}). whitelist={2}, unblock={3}. Detail: {4}",
			ip, verdict, wlOk ? "OK" : "FAIL", legacyOk ? "OK" : "FAIL", log.ToString()));
	}

	private async Task OnBlockLoginAsync()
	{
		if (_menuRow is null || string.IsNullOrWhiteSpace(_menuRow.UserName))
		{
			SetStatus("Login block aborted: no login in the selected row.");
			return;
		}

		string login = _menuRow.UserName!.Trim();
		bool hasIp = IsValidIp(_menuRow.SourceIp);
		string promptIp = hasIp
			? string.Format(CultureInfo.InvariantCulture, " and block IP {0}", _menuRow.SourceIp!.Trim())
			: " (no valid IP — only the login will be blocked)";
		string prompt = string.Format(CultureInfo.InvariantCulture,
			"Block login '{0}'{1}?\r\n\r\nThe login will be added to the persistent blocklist.",
			login, promptIp);
		if (!Confirm(prompt, "Confirm login block"))
		{
			SetStatus(string.Format(CultureInfo.InvariantCulture, "Login block for '{0}' cancelled.", login));
			return;
		}

		StringBuilder log = new();
		bool loginOk = await SendAddressMutationAsync(IpcCommand.AddToBlocklist, login, "Manual login block via LiveEvents", log).ConfigureAwait(true);
		bool ipOk = true;
		bool legacyOk = true;
		if (hasIp)
		{
			string ip = _menuRow.SourceIp!.Trim();
			ipOk = await SendAddressMutationAsync(IpcCommand.AddToBlocklist, ip, "Manual login block via LiveEvents (paired IP)", log).ConfigureAwait(true);
			legacyOk = await SendLegacyBlockAsync(ip, true, log).ConfigureAwait(true);
		}

		string verdict = (loginOk && (!hasIp || ipOk || legacyOk)) ? "OK" : "PARTIAL/FAIL";
		SetStatus(string.Format(CultureInfo.InvariantCulture,
			"Login block '{0}' ({1}). loginBlocklist={2}{3}. Detail: {4}",
			login, verdict, loginOk ? "OK" : "FAIL",
			hasIp ? string.Format(CultureInfo.InvariantCulture, ", ipBlocklist={0}, firewall={1}", ipOk ? "OK" : "FAIL", legacyOk ? "OK" : "FAIL") : string.Empty,
			log.ToString()));
	}

	// ---------------------------------------------------------------------------------------------
	// IPC helpers
	// ---------------------------------------------------------------------------------------------

	private async Task<bool> SendAddressMutationAsync(IpcCommand command, string address, string note, StringBuilder log)
	{
		AddressListMutationRequest payload = new()
		{
			Address = address,
			Note = note,
			DurationMinutes = 0,
		};

		try
		{
			JsonElement? response = await _ipc.SendAsync<JsonElement?>(command, payload).ConfigureAwait(true);
			if (response is null)
			{
				log.Append('[').Append(command).Append(": no response] ");
				return false;
			}

			log.Append('[').Append(command).Append(": ok] ");
			return true;
		}
		catch (Exception ex)
		{
			log.Append('[').Append(command).Append(": ").Append(ex.GetType().Name).Append("] ");
			return false;
		}
	}

	private async Task<bool> SendLegacyBlockAsync(string ip, bool block, StringBuilder log)
	{
		// Legacy Address.IsBlocked toggle. Returns true (bool) on success.
		try
		{
			bool? ok = await _ipc.SendAsync<bool?>(block ? IpcCommand.BlockAddress : IpcCommand.UnblockAddress, ip).ConfigureAwait(true);
			if (ok == true)
			{
				log.Append('[').Append(block ? "BlockAddress" : "UnblockAddress").Append(": ok] ");
				return true;
			}

			log.Append('[').Append(block ? "BlockAddress" : "UnblockAddress").Append(": skipped]");
			return false;
		}
		catch (Exception ex)
		{
			log.Append('[').Append(block ? "BlockAddress" : "UnblockAddress").Append(": ").Append(ex.GetType().Name).Append("] ");
			return false;
		}
	}

	// ---------------------------------------------------------------------------------------------
	// UI helpers
	// ---------------------------------------------------------------------------------------------

	private TextBox MakeFilterBox(string placeholder)
	{
		TextBox tb = new()
		{
			Dock = DockStyle.Fill,
			PlaceholderText = placeholder,
		};
		tb.TextChanged += (_, _) => ScheduleFilterRefresh();
		return tb;
	}

	private static Panel LabeledBox(string caption, Control inner)
	{
		Panel p = new() { Dock = DockStyle.Fill };
		Label l = new()
		{
			Text = caption,
			Dock = DockStyle.Top,
			Height = 16,
			TextAlign = System.Drawing.ContentAlignment.MiddleLeft,
		};
		inner.Dock = DockStyle.Fill;
		p.Controls.Add(inner);
		p.Controls.Add(l);
		return p;
	}

	private void SetStatus(string message)
	{
		string stamped = string.Format(CultureInfo.InvariantCulture,
			"[{0:HH:mm:ss}Z] {1}", DateTime.UtcNow, message);
		if (_statusStrip.InvokeRequired)
		{
			_statusStrip.BeginInvoke(new Action(() => _statusLabel.Text = stamped));
		}
		else
		{
			_statusLabel.Text = stamped;
		}
	}

	private static void SetClipboardText(string text)
	{
		// SetText would throw on empty string; use SetDataObject(string.Empty) as a no-op then.
		if (string.IsNullOrEmpty(text))
		{
			Clipboard.SetDataObject(string.Empty);
			return;
		}

		Clipboard.SetText(text);
	}

	private static bool Confirm(string message, string caption) =>
		MessageBox.Show(message, caption, MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2) == DialogResult.Yes;

	private static bool IsValidIp(string? value)
	{
		if (string.IsNullOrWhiteSpace(value))
		{
			return false;
		}

		return IPAddress.TryParse(value.Trim(), out _);
	}

	private static string? NormaliseCellValue(LiveEventRow row, string? columnName)
	{
		if (string.IsNullOrEmpty(columnName))
		{
			return null;
		}

		string? raw = columnName switch
		{
			"Id" => row.Id.ToString(CultureInfo.InvariantCulture),
			"TimeUtc" => LocalTimeFormatter.FormatLocal(row.TimeUtc),
			"EventId" => row.EventId.ToString(CultureInfo.InvariantCulture),
			"Channel" => row.Channel,
			"UserName" => row.UserName,
			"SourceIp" => row.SourceIp,
			"LogonType" => row.LogonType?.ToString(CultureInfo.InvariantCulture),
			"ProcessName" => row.ProcessName,
			_ => null,
		};

		return string.IsNullOrWhiteSpace(raw) ? null : raw;
	}

	// ---------------------------------------------------------------------------------------------
	// Export All IP Events (Stage A) — submenu wired into the live-events context menu.
	// ---------------------------------------------------------------------------------------------

	private ToolStripMenuItem BuildExportSubmenu()
	{
		ToolStripMenuItem root = new("Export All IP Events");
		root.DropDownItems.Add(new ToolStripMenuItem("JSON…", null, async (_, _) => await OnExportEventsAsync(IpEventsExportFormat.Json).ConfigureAwait(true)));
		root.DropDownItems.Add(new ToolStripMenuItem("TXT…", null, async (_, _) => await OnExportEventsAsync(IpEventsExportFormat.Txt).ConfigureAwait(true)));
		root.DropDownItems.Add(new ToolStripMenuItem("Markdown…", null, async (_, _) => await OnExportEventsAsync(IpEventsExportFormat.Markdown).ConfigureAwait(true)));
		root.DropDownItems.Add(new ToolStripMenuItem("CSV…", null, async (_, _) => await OnExportEventsAsync(IpEventsExportFormat.Csv).ConfigureAwait(true)));
		return root;
	}

	private async Task OnExportEventsAsync(IpEventsExportFormat format)
	{
		if (_menuRow is null || !IsValidIp(_menuRow.SourceIp))
		{
			SetStatus("Export aborted: no valid IP in the selected row.");
			return;
		}

		string ip = _menuRow.SourceIp!.Trim();
		await IpEventsExportRunner.RunAsync(_ipc, ip, format, SetStatus).ConfigureAwait(true);
	}

	// ---------------------------------------------------------------------------------------------
	// Export Connection Facts (Stage IP-E) — sibling submenu to Export All IP Events.
	// ---------------------------------------------------------------------------------------------

	private ToolStripMenuItem BuildExportFactsSubmenu()
	{
		ToolStripMenuItem root = new("Export Connection Facts");
		root.DropDownItems.Add(new ToolStripMenuItem("JSON…", null, async (_, _) => await OnExportFactsAsync(ConnectionFactsExportFormat.Json).ConfigureAwait(true)));
		root.DropDownItems.Add(new ToolStripMenuItem("TXT…", null, async (_, _) => await OnExportFactsAsync(ConnectionFactsExportFormat.Txt).ConfigureAwait(true)));
		root.DropDownItems.Add(new ToolStripMenuItem("Markdown…", null, async (_, _) => await OnExportFactsAsync(ConnectionFactsExportFormat.Markdown).ConfigureAwait(true)));
		root.DropDownItems.Add(new ToolStripMenuItem("CSV…", null, async (_, _) => await OnExportFactsAsync(ConnectionFactsExportFormat.Csv).ConfigureAwait(true)));
		return root;
	}

	private async Task OnExportFactsAsync(ConnectionFactsExportFormat format)
	{
		if (_menuRow is null || !IsValidIp(_menuRow.SourceIp))
		{
			SetStatus("Export Connection Facts aborted: no valid IP in the selected row.");
			return;
		}

		string ip = _menuRow.SourceIp!.Trim();
		await ConnectionFactsExportRunner.RunAsync(_ipc, ip, format, SetStatus).ConfigureAwait(true);
	}

	protected override void Dispose(bool disposing)
	{
		if (disposing)
		{
			_timer.Dispose();
			_filterDebounce.Dispose();
			_menu.Dispose();
		}

		base.Dispose(disposing);
	}

	/// <summary>DTO used for the live tail grid binding (matches the IPC GetRecentEvents projection).</summary>
	public sealed class LiveEventRow
	{
		[JsonPropertyName("id")] public long Id { get; set; }
		[JsonPropertyName("eventId")] public int EventId { get; set; }
		[JsonPropertyName("channel")] public string? Channel { get; set; }
		[JsonPropertyName("timeUtc")] public DateTime TimeUtc { get; set; }
		[JsonPropertyName("sourceIp")] public string? SourceIp { get; set; }
		[JsonPropertyName("sourceIpDerived")] public bool SourceIpDerived { get; set; }
		[JsonPropertyName("sourceIpUnresolved")] public bool SourceIpUnresolved { get; set; }
		[JsonPropertyName("userName")] public string? UserName { get; set; }
		[JsonPropertyName("domain")] public string? Domain { get; set; }
		[JsonPropertyName("logonId")] public string? LogonId { get; set; }
		[JsonPropertyName("logonType")] public int? LogonType { get; set; }
		[JsonPropertyName("authPackage")] public string? AuthPackage { get; set; }
		[JsonPropertyName("processName")] public string? ProcessName { get; set; }

		/// <summary>Project to the Core-side <see cref="LiveEventRowView"/> for filter evaluation.</summary>
		public LiveEventRowView ToView() => new()
		{
			Id = Id,
			EventId = EventId,
			Channel = Channel,
			TimeUtc = TimeUtc,
			SourceIp = SourceIp,
			SourceIpDerived = SourceIpDerived,
			UserName = UserName,
			Domain = Domain,
			LogonId = LogonId,
			LogonType = LogonType,
			AuthPackage = AuthPackage,
			ProcessName = ProcessName,
		};
	}
}
