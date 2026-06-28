// File:    src/RdpAudit.Configurator/Forms/AttackStatisticsPage.cs
// Module:  RdpAudit.Configurator.Forms
// Purpose: Stage 6B SOC-operator Attack Statistics tab. Consumes the Stage 6A GetAttackStats IPC
//          contract only — the Configurator never opens the SQLite file directly. Renders one row
//          per attacker IP with a cameyo / rdpmon-style green / yellow / red threat band, a filter
//          toolbar (IP search, min threat score, only-blocked, recent-period preset, limit), an
//          optional 5-second auto-refresh timer guarded against re-entry, a bounded context menu
//          (copy row, copy IP, block / whitelist) and a status strip that timestamps every refresh
//          / action in UTC.
// Extends: System.Windows.Forms.TabPage
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.ComponentModel;
using System.Drawing;
using System.Globalization;
using System.Runtime.Versioning;
using System.Text.Json;
using RdpAudit.Configurator.Ipc;
using RdpAudit.Configurator.Services;
using RdpAudit.Core.Events;
using RdpAudit.Core.Ipc;
using RdpAudit.Core.Ipc.Contracts;
using RdpAudit.Core.Models;
using RdpAudit.Core.Util;

using static RdpAudit.Configurator.Theming.DarkTheme;

namespace RdpAudit.Configurator.Forms;

/// <summary>
/// Stage 6B SOC-operator Attack Statistics tab.
/// </summary>
/// <remarks>
/// <para>
/// All reads flow through <see cref="IpcCommand.GetAttackStats"/>. The page never writes to the
/// <c>AttackStats</c> table directly. Optional context actions (block / whitelist) reuse the
/// existing Stage 5 IPC mutations and are confirmation-gated.
/// </para>
/// <para>
/// The auto-refresh timer fires every <see cref="AutoRefreshIntervalMs"/> milliseconds when the
/// <c>Auto refresh</c> checkbox is set. A <see cref="System.Threading.SemaphoreSlim"/>-like
/// guard (<see cref="_refreshing"/>) drops overlapping ticks rather than queuing them, so a slow
/// service cannot pile up unbounded background work.
/// </para>
/// </remarks>
[SupportedOSPlatform("windows")]
public sealed class AttackStatisticsPage : TabPage
{
	private const int AutoRefreshIntervalMs = 5_000;
	private const int DefaultLimit = 500;

	private static readonly int[] LimitChoices = { 100, 250, 500, 1000, 2000 };

	private static readonly Color RowColorGreen = RowSuccessBack;
	private static readonly Color RowColorYellow = RowWarningBack;
	private static readonly Color RowColorRed = RowDangerBack;

	private readonly IpcClient _ipc;
	private readonly DataGridView _grid;
	private readonly BindingList<AttackStatRow> _binding = new();
	private readonly List<AttackStatEntryDto> _allEntries = new();

	private readonly TextBox _ipFilter;
	private readonly NumericUpDown _minScoreFilter;
	private readonly CheckBox _onlyBlockedCheck;
	private readonly ComboBox _rangeCombo;
	private readonly ComboBox _limitCombo;
	private readonly CheckBox _autoRefreshCheck;
	private readonly Button _refreshButton;
	private readonly Button _clearFiltersButton;
#if DEBUG
	private readonly Button _rebuildButton;
#endif

	private readonly StatusStrip _statusStrip;
	private readonly ToolStripStatusLabel _statusLabel;
	private readonly System.Windows.Forms.Timer _autoRefreshTimer;

	private readonly ContextMenuStrip _menu;
	private readonly ToolStripMenuItem _menuCopyDetails;
	private readonly ToolStripMenuItem _menuCopyIp;
	private readonly ToolStripMenuItem _menuBlockIp;
	private readonly ToolStripMenuItem _menuWhitelistIp;
	private readonly ToolStripMenuItem _menuExportEvents;
	private readonly ToolStripMenuItem _menuExportFacts;
	private readonly ToolStripMenuItem _menuOpenRipeStat;
	private readonly ToolStripMenuItem _menuOpenAbuseIpDb;

	private AttackStatRow? _menuRow;

	private bool _refreshing;
	private bool _suppressFilterRefresh;

	public AttackStatisticsPage(IpcClient ipc)
	{
		ArgumentNullException.ThrowIfNull(ipc);
		_ipc = ipc;
		Text = "RDP Activity";

		// --- Toolbar ---------------------------------------------------------------------------
		_ipFilter = new TextBox
		{
			Dock = DockStyle.Fill,
			PlaceholderText = "IP contains…",
		};
		_ipFilter.TextChanged += (_, _) => OnLocalFilterChanged();

		_minScoreFilter = new NumericUpDown
		{
			Minimum = 0,
			Maximum = 100,
			DecimalPlaces = 0,
			Increment = 5,
			Value = 0,
			Dock = DockStyle.Fill,
		};
		_minScoreFilter.ValueChanged += (_, _) => OnLocalFilterChanged();

		_onlyBlockedCheck = new CheckBox
		{
			Text = "Only blocked",
			Dock = DockStyle.Fill,
			AutoSize = false,
			TextAlign = ContentAlignment.MiddleLeft,
		};
		_onlyBlockedCheck.CheckedChanged += (_, _) => OnLocalFilterChanged();

		_rangeCombo = new ComboBox
		{
			Dock = DockStyle.Fill,
			DropDownStyle = ComboBoxStyle.DropDownList,
		};
		foreach (AttackStatsRecentRange range in Enum.GetValues<AttackStatsRecentRange>())
		{
			_rangeCombo.Items.Add(new RangeChoice(range));
		}
		_rangeCombo.SelectedIndex = (int)AttackStatsRecentRange.Last7Days;
		_rangeCombo.SelectedIndexChanged += async (_, _) => await RefreshAsync().ConfigureAwait(true);

		_limitCombo = new ComboBox
		{
			Dock = DockStyle.Fill,
			DropDownStyle = ComboBoxStyle.DropDownList,
		};
		foreach (int n in LimitChoices)
		{
			_limitCombo.Items.Add(n);
		}
		_limitCombo.SelectedItem = DefaultLimit;
		_limitCombo.SelectedIndexChanged += async (_, _) => await RefreshAsync().ConfigureAwait(true);

		_autoRefreshTimer = new System.Windows.Forms.Timer { Interval = AutoRefreshIntervalMs };
		_autoRefreshTimer.Tick += async (_, _) => await RefreshAsync().ConfigureAwait(true);

		_autoRefreshCheck = new CheckBox
		{
			Text = "Auto refresh (5s)",
			Dock = DockStyle.Fill,
			AutoSize = false,
			TextAlign = ContentAlignment.MiddleLeft,
		};
		_autoRefreshCheck.CheckedChanged += (_, _) =>
		{
			if (_autoRefreshCheck.Checked)
			{
				_autoRefreshTimer.Start();
				SetStatus("Auto refresh enabled (every 5 seconds).");
			}
			else
			{
				_autoRefreshTimer.Stop();
				SetStatus("Auto refresh disabled.");
			}
		};

		_refreshButton = new Button { Text = "Refresh", Dock = DockStyle.Fill, AutoSize = false };
		_refreshButton.Click += async (_, _) => await RefreshAsync().ConfigureAwait(true);

		_clearFiltersButton = new Button { Text = "Clear filters", Dock = DockStyle.Fill, AutoSize = false };
		_clearFiltersButton.Click += async (_, _) => await OnClearFiltersAsync().ConfigureAwait(true);

#if DEBUG
		_rebuildButton = new Button { Text = "Rebuild stats", Dock = DockStyle.Fill, AutoSize = false };
		_rebuildButton.Click += async (_, _) => await OnRebuildAsync().ConfigureAwait(true);
#endif

		TableLayoutPanel toolbar = BuildToolbar();

		// --- Grid ------------------------------------------------------------------------------
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
		ConfigureGridColumns(_grid);
		_grid.DataSource = _binding;
		// The "Threat" column renders a decorated string ("70.0 (High)") that cannot be parsed back to
		// a number, so sort it on the numeric ThreatScore to keep the order exact.
		SortableGrid.Enable(_grid, _binding, new Dictionary<string, string>(StringComparer.Ordinal)
		{
			[nameof(AttackStatRow.ThreatDisplay)] = nameof(AttackStatRow.ThreatScore),
		});
		_grid.RowPrePaint += OnRowPrePaint;
		_grid.CellMouseDown += OnCellMouseDown;
		_grid.CellFormatting += OnCellFormatting;

		// --- Context menu ----------------------------------------------------------------------
		_menuCopyDetails = new ToolStripMenuItem("Copy Row Details", null, (_, _) => OnCopyDetails());
		_menuCopyIp = new ToolStripMenuItem("Copy IP", null, (_, _) => OnCopyIp());
		_menuBlockIp = new ToolStripMenuItem("Block IP…", null, async (_, _) => await OnBlockIpAsync().ConfigureAwait(true));
		_menuWhitelistIp = new ToolStripMenuItem("Whitelist IP…", null, async (_, _) => await OnWhitelistIpAsync().ConfigureAwait(true));
		_menuExportEvents = BuildExportSubmenu();
		_menuExportFacts = BuildExportFactsSubmenu();
		_menuOpenRipeStat = new ToolStripMenuItem(IpReputationBrowser.RipeStatMenuLabel, null, (_, _) => OnOpenRipeStat());
		_menuOpenAbuseIpDb = new ToolStripMenuItem(IpReputationBrowser.AbuseIpDbMenuLabel, null, (_, _) => OnOpenAbuseIpDb());
		_menu = new ContextMenuStrip();
		_menu.Items.Add(_menuCopyDetails);
		_menu.Items.Add(_menuCopyIp);
		_menu.Items.Add(new ToolStripSeparator());
		_menu.Items.Add(_menuBlockIp);
		_menu.Items.Add(_menuWhitelistIp);
		_menu.Items.Add(new ToolStripSeparator());
		_menu.Items.Add(_menuOpenRipeStat);
		_menu.Items.Add(_menuOpenAbuseIpDb);
		_menu.Items.Add(new ToolStripSeparator());
		_menu.Items.Add(_menuExportEvents);
		_menu.Items.Add(_menuExportFacts);
		_menu.Opening += OnMenuOpening;
		_grid.ContextMenuStrip = _menu;

		// --- Status strip ----------------------------------------------------------------------
		_statusStrip = new StatusStrip { SizingGrip = false };
		_statusLabel = new ToolStripStatusLabel("Waiting for first refresh…")
		{
			Spring = true,
			TextAlign = ContentAlignment.MiddleLeft,
		};
		_statusStrip.Items.Add(_statusLabel);

		// --- Compose ---------------------------------------------------------------------------
		// Order matters: docked panels added later sit closer to the top edge.
		Controls.Add(_grid);
		Controls.Add(_statusStrip);
		Controls.Add(toolbar);

		HandleCreated += async (_, _) => await RefreshAsync().ConfigureAwait(true);
	}

	// ---------------------------------------------------------------------------------------------
	// Toolbar composition
	// ---------------------------------------------------------------------------------------------

	private TableLayoutPanel BuildToolbar()
	{
#if DEBUG
		const int columnCount = 10;
#else
		const int columnCount = 9;
#endif
		TableLayoutPanel toolbar = new()
		{
			Dock = DockStyle.Top,
			Height = 72,
			ColumnCount = columnCount,
			RowCount = 2,
			Padding = new Padding(4),
		};
		for (int i = 0; i < columnCount; i++)
		{
			toolbar.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100f / columnCount));
		}
		toolbar.RowStyles.Add(new RowStyle(SizeType.Absolute, 20));
		toolbar.RowStyles.Add(new RowStyle(SizeType.Absolute, 30));

		Label ipSearchCaption = MakeCaption("IP search");
		toolbar.Controls.Add(ipSearchCaption, 0, 0);
		toolbar.SetColumnSpan(ipSearchCaption, 2);
		toolbar.Controls.Add(_ipFilter, 0, 1);
		toolbar.SetColumnSpan(_ipFilter, 2);

		toolbar.Controls.Add(MakeCaption("Min threat"), 2, 0);
		toolbar.Controls.Add(_minScoreFilter, 2, 1);

		toolbar.Controls.Add(MakeCaption("Recent period"), 3, 0);
		toolbar.Controls.Add(_rangeCombo, 3, 1);

		toolbar.Controls.Add(MakeCaption("Limit"), 4, 0);
		toolbar.Controls.Add(_limitCombo, 4, 1);

		toolbar.Controls.Add(MakeCaption(" "), 5, 0);
		toolbar.Controls.Add(_onlyBlockedCheck, 5, 1);

		toolbar.Controls.Add(MakeCaption(" "), 6, 0);
		toolbar.Controls.Add(_autoRefreshCheck, 6, 1);

		toolbar.Controls.Add(MakeCaption(" "), 7, 0);
		toolbar.Controls.Add(_refreshButton, 7, 1);

		toolbar.Controls.Add(MakeCaption(" "), 8, 0);
		toolbar.Controls.Add(_clearFiltersButton, 8, 1);

#if DEBUG
		toolbar.Controls.Add(MakeCaption(" "), 9, 0);
		toolbar.Controls.Add(_rebuildButton, 9, 1);
#endif

		return toolbar;
	}

	private static Label MakeCaption(string text) => new()
	{
		Text = text,
		Dock = DockStyle.Fill,
		TextAlign = ContentAlignment.MiddleLeft,
		AutoSize = false,
	};

	private static void ConfigureGridColumns(DataGridView grid)
	{
		grid.Columns.Add(new DataGridViewTextBoxColumn
		{
			HeaderText = "IP",
			DataPropertyName = nameof(AttackStatRow.Ip),
			Width = 140,
		});
		grid.Columns.Add(new DataGridViewTextBoxColumn
		{
			HeaderText = "Threat",
			DataPropertyName = nameof(AttackStatRow.ThreatDisplay),
			Width = 110,
			ToolTipText = "Threat score (0–100) and band (Green / Yellow / Red).",
		});
		grid.Columns.Add(new DataGridViewTextBoxColumn
		{
			HeaderText = "Total Events",
			DataPropertyName = nameof(AttackStatRow.TotalAttempts),
			Width = 90,
			ToolTipText = "Total logon-outcome events observed for this IP (sum of session successes and failures).",
		});
		grid.Columns.Add(new DataGridViewTextBoxColumn
		{
			HeaderText = "Session Failed",
			DataPropertyName = nameof(AttackStatRow.Failed),
			Width = 100,
			ToolTipText = "Failed RDP logon-outcome events (Security 4625) counted by the attack-statistics aggregator.",
		});
		grid.Columns.Add(new DataGridViewTextBoxColumn
		{
			HeaderText = "RDP Session Success",
			DataPropertyName = nameof(AttackStatRow.Successful),
			Width = 140,
			ToolTipText = "Successful RDP session establishments (Security 4624 / TS-RCM 1149 / TS-LSM 21/25) for this IP.",
		});
		grid.Columns.Add(new DataGridViewTextBoxColumn
		{
			HeaderText = "First Seen (local)",
			DataPropertyName = nameof(AttackStatRow.FirstSeenUtcText),
			Width = 150,
		});
		grid.Columns.Add(new DataGridViewTextBoxColumn
		{
			HeaderText = "Last Seen (local)",
			DataPropertyName = nameof(AttackStatRow.LastSeenUtcText),
			Width = 150,
		});
		grid.Columns.Add(new DataGridViewTextBoxColumn
		{
			HeaderText = "Duration",
			DataPropertyName = nameof(AttackStatRow.DurationText),
			Width = 100,
			ToolTipText = "Active-window duration (LastSeenUtc − FirstSeenUtc).",
		});
		grid.Columns.Add(new DataGridViewTextBoxColumn
		{
			HeaderText = "Top 10 Attempted Logins",
			DataPropertyName = nameof(AttackStatRow.TopLoginsText),
			AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill,
		});
		grid.Columns.Add(new DataGridViewTextBoxColumn
		{
			HeaderText = "Last LogonType",
			DataPropertyName = nameof(AttackStatRow.LastLoginTypeText),
			Width = 110,
		});
		grid.Columns.Add(new DataGridViewTextBoxColumn
		{
			HeaderText = "Blocked",
			DataPropertyName = nameof(AttackStatRow.IsBlockedText),
			Width = 80,
		});

		// --- Stage IP-E: fact-derived augmentation columns. Append-only, additive to the existing
		// authoritative AttackStat columns above. Operators can sort/filter these like any other column.
		grid.Columns.Add(new DataGridViewTextBoxColumn
		{
			HeaderText = "Active Fact",
			DataPropertyName = nameof(AttackStatRow.HasActiveConnectionFactText),
			Width = 90,
			ToolTipText = "True when at least one matching RdpConnectionFact currently represents an active session.",
		});
		grid.Columns.Add(new DataGridViewTextBoxColumn
		{
			HeaderText = "Auth Failed",
			DataPropertyName = nameof(AttackStatRow.FactFailedLogons),
			Width = 100,
			ToolTipText = "Authoritative failed-authentication count from RdpConnectionFacts for this IP "
				+ "(preferred source of truth over the aggregator's Session Failed column).",
		});
		grid.Columns.Add(new DataGridViewTextBoxColumn
		{
			HeaderText = "Auth Success",
			DataPropertyName = nameof(AttackStatRow.FactSuccessfulLogons),
			Width = 100,
			ToolTipText = "Authoritative successful-authentication count from RdpConnectionFacts for this IP "
				+ "(preferred source of truth over the aggregator's RDP Session Success column).",
		});
		grid.Columns.Add(new DataGridViewTextBoxColumn
		{
			HeaderText = "Fact First Seen (local)",
			DataPropertyName = nameof(AttackStatRow.FactFirstSeenUtcText),
			Width = 160,
			ToolTipText = "Earliest FirstSeenUtc across all RdpConnectionFacts for this IP.",
		});
		grid.Columns.Add(new DataGridViewTextBoxColumn
		{
			HeaderText = "Fact Last Seen (local)",
			DataPropertyName = nameof(AttackStatRow.FactLastSeenUtcText),
			Width = 160,
			ToolTipText = "Most recent LastSeenUtc across all RdpConnectionFacts for this IP.",
		});
	}

	// ---------------------------------------------------------------------------------------------
	// Refresh / IPC plumbing
	// ---------------------------------------------------------------------------------------------

	/// <summary>
	/// Fetches the current snapshot via <see cref="IpcCommand.GetAttackStats"/> using the toolbar
	/// filters. Server-side filters (IP query, min threat, only-blocked, since-utc, limit) are sent
	/// in the request; client-side pre-filtering for the editable IP / min-threat / only-blocked
	/// controls happens additionally so typing feels responsive between IPC round-trips.
	/// </summary>
	public async Task RefreshAsync()
	{
		if (_refreshing)
		{
			return;
		}

		_refreshing = true;
		_refreshButton.Enabled = false;
		try
		{
			AttackStatsRequest request = BuildRequest();
			AttackStatsDto? response = await _ipc
				.SendAsync<AttackStatsDto>(IpcCommand.GetAttackStats, request)
				.ConfigureAwait(true);

			if (response is null)
			{
				SetStatus("Refresh FAILED: service unreachable.");
				return;
			}

			if (response.Status != IpcResultStatus.Success)
			{
				SetStatus(string.Format(
					CultureInfo.InvariantCulture,
					"Refresh returned non-success status {0}: {1}",
					response.Status,
					response.Message ?? "no message"));
				// Still apply whatever entries came back so the operator sees the current state.
			}

			_allEntries.Clear();
			_allEntries.AddRange(response.Entries);
			ApplyLocalFilter();
			SetStatus(string.Format(
				CultureInfo.InvariantCulture,
				"Refresh OK. rows={0} (matching={1}, server limit={2}, window=[{3:yyyy-MM-dd HH:mm:ss}Z..{4:yyyy-MM-dd HH:mm:ss}Z]).",
				_binding.Count,
				response.TotalMatching,
				response.AppliedLimit,
				response.WindowStartUtc,
				response.WindowEndUtc));
		}
		catch (Exception ex)
		{
			SetStatus("Refresh FAILED: " + ex.GetType().Name + " — " + ex.Message);
		}
		finally
		{
			_refreshing = false;
			_refreshButton.Enabled = true;
		}
	}

	private AttackStatsRequest BuildRequest()
	{
		AttackStatsRecentRange range = ((RangeChoice)_rangeCombo.SelectedItem!).Range;
		double minScore = (double)_minScoreFilter.Value;
		int limit = _limitCombo.SelectedItem is int n ? n : DefaultLimit;

		return new AttackStatsRequest
		{
			IpQuery = string.IsNullOrWhiteSpace(_ipFilter.Text) ? null : _ipFilter.Text.Trim(),
			MinThreatScore = minScore > 0 ? minScore : null,
			OnlyBlocked = _onlyBlockedCheck.Checked,
			SinceUtc = AttackStatsRecentRanges.ToSinceUtc(range, DateTime.UtcNow),
			UntilUtc = null,
			Limit = limit,
		};
	}

	private void OnLocalFilterChanged()
	{
		if (_suppressFilterRefresh)
		{
			return;
		}

		ApplyLocalFilter();
	}

	private void ApplyLocalFilter()
	{
		AttackStatsFilter filter = new()
		{
			IpQuery = _ipFilter.Text,
			MinThreatScore = _minScoreFilter.Value > 0 ? (double)_minScoreFilter.Value : null,
			OnlyBlocked = _onlyBlockedCheck.Checked,
		};

		_binding.RaiseListChangedEvents = false;
		_binding.Clear();
		foreach (AttackStatEntryDto entry in _allEntries)
		{
			if (filter.Matches(entry))
			{
				_binding.Add(AttackStatRow.From(entry));
			}
		}
		_binding.RaiseListChangedEvents = true;
		_binding.ResetBindings();
	}

	private async Task OnClearFiltersAsync()
	{
		_suppressFilterRefresh = true;
		try
		{
			_ipFilter.Text = string.Empty;
			_minScoreFilter.Value = 0;
			_onlyBlockedCheck.Checked = false;
			_rangeCombo.SelectedIndex = (int)AttackStatsRecentRange.Last7Days;
			_limitCombo.SelectedItem = DefaultLimit;
		}
		finally
		{
			_suppressFilterRefresh = false;
		}

		await RefreshAsync().ConfigureAwait(true);
	}

#if DEBUG
	/// <summary>DEBUG-only: forces a synchronous AttackStats projection pass via
	/// <see cref="IpcCommand.RebuildAttackStats"/>, then refreshes the grid. Lets an operator confirm a
	/// stale RDP Activity table advances after a manual rebuild without waiting for the background worker.</summary>
	private async Task OnRebuildAsync()
	{
		_rebuildButton.Enabled = false;
		SetStatus("Rebuilding RDP Activity statistics…");
		try
		{
			AttackStatsRebuildResultDto? result = await _ipc
				.SendAsync<AttackStatsRebuildResultDto>(IpcCommand.RebuildAttackStats)
				.ConfigureAwait(true);

			if (result is null)
			{
				SetStatus("Rebuild FAILED: service unreachable.");
				return;
			}

			if (result.Status != IpcResultStatus.Success)
			{
				SetStatus(string.Format(
					CultureInfo.InvariantCulture,
					"Rebuild returned status {0}: {1}",
					result.Status,
					result.Message ?? "no message"));
				return;
			}

			SetStatus(string.Format(
				CultureInfo.InvariantCulture,
				"Rebuild OK. upserted={0}, elapsed={1} ms, total rows={2}.",
				result.RowsUpserted,
				result.ElapsedMilliseconds,
				result.AttackStatsTotal));
		}
		catch (Exception ex)
		{
			SetStatus("Rebuild FAILED: " + ex.GetType().Name + " — " + ex.Message);
		}
		finally
		{
			_rebuildButton.Enabled = true;
		}

		await RefreshAsync().ConfigureAwait(true);
	}
#endif

	// ---------------------------------------------------------------------------------------------
	// Row coloring
	// ---------------------------------------------------------------------------------------------

	private void OnRowPrePaint(object? sender, DataGridViewRowPrePaintEventArgs e)
	{
		if (e.RowIndex < 0 || e.RowIndex >= _binding.Count)
		{
			return;
		}

		AttackStatRow row = _binding[e.RowIndex];

		// Stage 2: the unresolved-IP sentinel row always renders with the warning band so the
		// operator instantly recognises it as "brute-force pressure without attribution".
		Color color = row.IsUnresolvedSentinel
			? RowColorRed
			: row.ThreatLevel switch
			{
				AttackThreatLevel.Red => RowColorRed,
				AttackThreatLevel.Yellow => RowColorYellow,
				_ => RowColorGreen,
			};

		_grid.Rows[e.RowIndex].DefaultCellStyle.BackColor = color;
	}

	private void OnCellFormatting(object? sender, DataGridViewCellFormattingEventArgs e)
	{
		if (e.RowIndex < 0 || e.RowIndex >= _binding.Count || e.ColumnIndex < 0)
		{
			return;
		}

		AttackStatRow row = _binding[e.RowIndex];
		if (!row.IsUnresolvedSentinel)
		{
			return;
		}

		DataGridViewColumn col = _grid.Columns[e.ColumnIndex];
		if (string.Equals(col.DataPropertyName, nameof(AttackStatRow.Ip), StringComparison.Ordinal))
		{
			e.Value = AttackStatsAggregator.SentinelDisplayLabel;
			e.FormattingApplied = true;
			DataGridViewCell cell = _grid.Rows[e.RowIndex].Cells[e.ColumnIndex];
			cell.ToolTipText =
				"Source IP was absent in the Windows Security event (often NLA / pre-auth). "
				+ "See Live Events filtered by 4625 for the underlying rows.";
		}
	}

	// ---------------------------------------------------------------------------------------------
	// Context menu
	// ---------------------------------------------------------------------------------------------

	private void OnCellMouseDown(object? sender, DataGridViewCellMouseEventArgs e)
	{
		if (e.Button != MouseButtons.Right || e.RowIndex < 0 || e.RowIndex >= _binding.Count)
		{
			_menuRow = null;
			return;
		}

		// Move the selection to the right-clicked row so menu actions target what the operator clicked.
		_grid.ClearSelection();
		_grid.Rows[e.RowIndex].Selected = true;
		_menuRow = _binding[e.RowIndex];
	}

	private void OnMenuOpening(object? sender, CancelEventArgs e)
	{
		bool hasRow = _menuRow is not null;
		bool isSentinel = hasRow && _menuRow!.IsUnresolvedSentinel;
		bool hasValidIp = hasRow && !string.IsNullOrEmpty(_menuRow!.Ip) && AddressListFilter.IsValidIp(_menuRow.Ip) && !isSentinel;
		bool reputationEligible = hasRow && !isSentinel && IpReputationBrowser.IsLookupEligible(_menuRow!.Ip);
		_menuCopyDetails.Enabled = hasRow;
		_menuCopyIp.Enabled = hasRow && !string.IsNullOrEmpty(_menuRow!.Ip) && !isSentinel;
		_menuBlockIp.Enabled = hasRow && !string.IsNullOrEmpty(_menuRow!.Ip) && !_menuRow!.IsBlocked && !isSentinel;
		_menuWhitelistIp.Enabled = hasRow && !string.IsNullOrEmpty(_menuRow!.Ip) && !isSentinel;
		_menuExportEvents.Enabled = hasValidIp;
		_menuExportFacts.Enabled = hasValidIp;
		_menuOpenRipeStat.Enabled = reputationEligible;
		_menuOpenAbuseIpDb.Enabled = reputationEligible;
	}

	private void OnCopyDetails()
	{
		if (_menuRow is null)
		{
			return;
		}

		string text = AttackStatRowFormatter.FormatMultiline(_menuRow.Source);
		TrySetClipboard(text, "Copy row details");
	}

	private void OnCopyIp()
	{
		if (_menuRow is null || string.IsNullOrEmpty(_menuRow.Ip))
		{
			return;
		}

		TrySetClipboard(_menuRow.Ip, "Copy IP");
	}

	private void OnOpenRipeStat()
	{
		if (_menuRow is null)
		{
			return;
		}

		IpReputationBrowser.LaunchOutcome outcome = IpReputationBrowser.OpenRipeStat(_menuRow.Ip);
		SetStatus(outcome.Format());
	}

	private void OnOpenAbuseIpDb()
	{
		if (_menuRow is null)
		{
			return;
		}

		// Prepare and copy the report text BEFORE opening the browser so the operator can paste it
		// straight into AbuseIPDB. Never name the victim/local host; refuse non-reportable IPs.
		AbuseIpDbReportText.PrepareResult prepared = AbuseIpDbReportText.Prepare(_menuRow.Source);
		if (!prepared.Prepared)
		{
			SetStatus(AbuseIpDbReportText.FormatRefusal(_menuRow.Ip, prepared));
			return;
		}

		TrySetClipboard(prepared.ReportText, "Copy AbuseIPDB report");
		SetStatus(AbuseIpDbReportText.ClipboardToast);

		IpReputationBrowser.LaunchOutcome outcome = IpReputationBrowser.OpenAbuseIpDb(_menuRow.Ip);
		SetStatus(outcome.Format());
	}

	private async Task OnBlockIpAsync()
	{
		if (_menuRow is null || string.IsNullOrEmpty(_menuRow.Ip))
		{
			return;
		}

		string ip = _menuRow.Ip;
		if (!AddressListFilter.IsValidIp(ip))
		{
			SetStatus("Block IP aborted: " + ip + " is not a valid IPv4 / IPv6 address.");
			return;
		}

		string prompt = string.Format(
			CultureInfo.InvariantCulture,
			"Block {0}? The service will install a firewall block via the configured provider and "
			+ "add the address to the blocklist.",
			ip);
		if (!Confirm(prompt, "Confirm block IP"))
		{
			SetStatus("Block IP cancelled.");
			return;
		}

		AddressListMutationRequest payload = new()
		{
			Address = AddressListFilter.NormalizeIp(ip),
			Note = "Configurator Attack Statistics tab manual block",
		};

		bool ok = await SendMutationAsync(IpcCommand.AddToBlocklist, payload).ConfigureAwait(true);
		SetStatus(string.Format(
			CultureInfo.InvariantCulture,
			"AddToBlocklist {0}: {1}",
			ip,
			ok ? "OK" : "FAILED"));
		if (ok)
		{
			await RefreshAsync().ConfigureAwait(true);
		}
	}

	private async Task OnWhitelistIpAsync()
	{
		if (_menuRow is null || string.IsNullOrEmpty(_menuRow.Ip))
		{
			return;
		}

		string ip = _menuRow.Ip;
		if (!AddressListFilter.IsValidIp(ip))
		{
			SetStatus("Whitelist IP aborted: " + ip + " is not a valid IPv4 / IPv6 address.");
			return;
		}

		string prompt = string.Format(
			CultureInfo.InvariantCulture,
			"Whitelist {0}? The address will be exempt from auto-blocking. Existing active blocks are "
			+ "not removed by this action — use the Firewall tab to unblock if required.",
			ip);
		if (!Confirm(prompt, "Confirm whitelist IP"))
		{
			SetStatus("Whitelist IP cancelled.");
			return;
		}

		AddressListMutationRequest payload = new()
		{
			Address = AddressListFilter.NormalizeIp(ip),
			Note = "Configurator Attack Statistics tab manual whitelist",
		};

		bool ok = await SendMutationAsync(IpcCommand.AddToWhitelist, payload).ConfigureAwait(true);
		SetStatus(string.Format(
			CultureInfo.InvariantCulture,
			"AddToWhitelist {0}: {1}",
			ip,
			ok ? "OK" : "FAILED"));
		if (ok)
		{
			await RefreshAsync().ConfigureAwait(true);
		}
	}

	// ---------------------------------------------------------------------------------------------
	// Helpers
	// ---------------------------------------------------------------------------------------------

	// ---------------------------------------------------------------------------------------------
	// Export All IP Events (Stage A) — submenu wired into the attack stats context menu.
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
		if (_menuRow is null || string.IsNullOrEmpty(_menuRow.Ip) || !AddressListFilter.IsValidIp(_menuRow.Ip))
		{
			SetStatus("Export aborted: no valid IP in the selected row.");
			return;
		}

		await IpEventsExportRunner.RunAsync(_ipc, _menuRow.Ip, format, SetStatus).ConfigureAwait(true);
	}

	// ---------------------------------------------------------------------------------------------
	// Export Connection Facts (Stage IP-E) — submenu wired into the attack stats context menu.
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
		if (_menuRow is null || string.IsNullOrEmpty(_menuRow.Ip) || !AddressListFilter.IsValidIp(_menuRow.Ip))
		{
			SetStatus("Export Connection Facts aborted: no valid IP in the selected row.");
			return;
		}

		await ConnectionFactsExportRunner.RunAsync(_ipc, _menuRow.Ip, format, SetStatus).ConfigureAwait(true);
	}

	private async Task<bool> SendMutationAsync(IpcCommand command, object payload)
	{
		try
		{
			JsonElement? response = await _ipc.SendAsync<JsonElement?>(command, payload).ConfigureAwait(true);
			return response is not null;
		}
		catch
		{
			return false;
		}
	}

	private void TrySetClipboard(string text, string actionLabel)
	{
		try
		{
			if (string.IsNullOrEmpty(text))
			{
				Clipboard.Clear();
			}
			else
			{
				Clipboard.SetText(text);
			}

			SetStatus(actionLabel + ": OK.");
		}
		catch (Exception ex)
		{
			SetStatus(actionLabel + " FAILED: " + ex.GetType().Name + " — " + ex.Message);
		}
	}

	private static bool Confirm(string message, string caption) =>
		MessageBox.Show(
			message,
			caption,
			MessageBoxButtons.YesNo,
			MessageBoxIcon.Warning,
			MessageBoxDefaultButton.Button2) == DialogResult.Yes;

	private void SetStatus(string message)
	{
		string stamped = string.Format(
			CultureInfo.InvariantCulture,
			"[{0:yyyy-MM-dd HH:mm:ss}Z] {1}",
			DateTime.UtcNow,
			message);
		if (_statusStrip.InvokeRequired)
		{
			_statusStrip.BeginInvoke(new Action(() => _statusLabel.Text = stamped));
		}
		else
		{
			_statusLabel.Text = stamped;
		}
	}

	protected override void Dispose(bool disposing)
	{
		if (disposing)
		{
			_autoRefreshTimer.Stop();
			_autoRefreshTimer.Dispose();
			_menu.Dispose();
		}

		base.Dispose(disposing);
	}

	// ---------------------------------------------------------------------------------------------
	// View-models
	// ---------------------------------------------------------------------------------------------

	private sealed record RangeChoice(AttackStatsRecentRange Range)
	{
		public override string ToString() => AttackStatsRecentRanges.ToDisplayLabel(Range);
	}

	/// <summary>Grid view-model for one <see cref="AttackStatEntryDto"/> row.</summary>
	public sealed class AttackStatRow
	{
		public string Ip { get; init; } = string.Empty;

		public double ThreatScore { get; init; }

		public AttackThreatLevel ThreatLevel { get; init; }

		public string ThreatDisplay { get; init; } = string.Empty;

		public long TotalAttempts { get; init; }

		public long Failed { get; init; }

		public long Successful { get; init; }

		public string FirstSeenUtcText { get; init; } = string.Empty;

		public string LastSeenUtcText { get; init; } = string.Empty;

		public string DurationText { get; init; } = string.Empty;

		public string TopLoginsText { get; init; } = string.Empty;

		public string LastLoginTypeText { get; init; } = string.Empty;

		public bool IsBlocked { get; init; }

		public string IsBlockedText => IsBlocked ? "yes" : "no";

		/// <summary>True when the IP equals <see cref="AttackStatsAggregator.SentinelUnresolvedIp"/>.
		/// The grid renders this row with the warning band and a friendly label instead of "0.0.0.0".</summary>
		public bool IsUnresolvedSentinel { get; init; }

		// --- Stage IP-E fact-derived columns (additive, never overrides AttackStat columns above). ---

		/// <summary>True when at least one matching <c>RdpConnectionFact</c> currently represents an active session.</summary>
		public bool HasActiveConnectionFact { get; init; }

		/// <summary>Display text for <see cref="HasActiveConnectionFact"/>.</summary>
		public string HasActiveConnectionFactText => HasActiveConnectionFact ? "yes" : "no";

		/// <summary>Sum of failed logons across all <c>RdpConnectionFacts</c> for this IP.</summary>
		public long FactFailedLogons { get; init; }

		/// <summary>Sum of successful logons across all <c>RdpConnectionFacts</c> for this IP.</summary>
		public long FactSuccessfulLogons { get; init; }

		/// <summary>Display text for the earliest fact <c>FirstSeenUtc</c>; empty when no facts exist.</summary>
		public string FactFirstSeenUtcText { get; init; } = string.Empty;

		/// <summary>Display text for the latest fact <c>LastSeenUtc</c>; empty when no facts exist.</summary>
		public string FactLastSeenUtcText { get; init; } = string.Empty;

		/// <summary>Reference to the original DTO; used by the clipboard formatter so format drift cannot occur.</summary>
		[Browsable(false)]
		public AttackStatEntryDto Source { get; init; } = new();

		public static AttackStatRow From(AttackStatEntryDto dto)
		{
			ArgumentNullException.ThrowIfNull(dto);
			AttackStatFactDisplay facts = ConnectionFactRowProjection.FromAttackStat(dto);
			return new AttackStatRow
			{
				Ip = dto.Ip,
				IsUnresolvedSentinel = AttackStatsAggregator.IsSentinelUnresolvedIp(dto.Ip),
				ThreatScore = dto.ThreatScore,
				ThreatLevel = dto.ThreatLevel,
				ThreatDisplay = string.Format(
					CultureInfo.InvariantCulture,
					"{0:F1} ({1})",
					dto.ThreatScore,
					dto.ThreatLevel),
				TotalAttempts = dto.TotalAttempts,
				Failed = dto.Failed,
				Successful = dto.Successful,
				FirstSeenUtcText = LocalTimeFormatter.FormatLocal(dto.FirstSeenUtc),
				LastSeenUtcText = LocalTimeFormatter.FormatLocal(dto.LastSeenUtc),
				DurationText = AttackStatRowFormatter.FormatDuration(dto.DurationSeconds),
				TopLoginsText = AttackStatRowFormatter.FormatTopLogins(dto.Top10AttemptedLogins),
				LastLoginTypeText = dto.LastLoginType?.ToString(CultureInfo.InvariantCulture) ?? string.Empty,
				IsBlocked = dto.IsBlocked,
				HasActiveConnectionFact = facts.HasActiveConnectionFact,
				FactFailedLogons = facts.FactFailedLogons,
				FactSuccessfulLogons = facts.FactSuccessfulLogons,
				FactFirstSeenUtcText = LocalTimeFormatter.FormatLocal(dto.FactFirstSeenUtc, fallback: string.Empty),
				FactLastSeenUtcText = LocalTimeFormatter.FormatLocal(dto.FactLastSeenUtc, fallback: string.Empty),
				Source = dto,
			};
		}
	}
}
