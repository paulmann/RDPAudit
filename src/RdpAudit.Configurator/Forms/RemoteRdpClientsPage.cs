// File:    src/RdpAudit.Configurator/Forms/RemoteRdpClientsPage.cs
// Module:  RdpAudit.Configurator.Forms
// Purpose: Stage 7 SOC-operator Remote RDP Clients tab. Lists active / inactive /
//          disconnected RDP sessions, lets the operator disconnect / log off / shadow
//          a selected session (every destructive action confirmation-gated), and surfaces
//          the current Terminal Services shadow policy with apply / backup / restore
//          controls. All reads / mutations flow through the Service IPC.
//
//          v2.0.0 — dark UI redesign. The toolbar, session grid, shadow-policy panel, status
//          bar and context menu are restyled with the shared dark palette to match MikroTikPage.
//          Adds two bulk-disconnect actions ("Disconnect all inactive" and "Disconnect all
//          except current") that issue a soft IpcCommand.DisconnectSession to each target and,
//          two minutes later, a hard IpcCommand.LogoffSession to any target that is still
//          present. All existing session / shadow-policy / filter / context-menu logic and the
//          SortableGrid / BindingList / SessionRow / ShadowValueRow inner classes are preserved.
// Extends: System.Windows.Forms.TabPage. To add a new toolbar action, add the button in
//          BuildToolbar; to add a new bulk operation, collect targets from _allSessions and route
//          them through OnBulkDisconnectAsync; to add a new context-menu command, register it in
//          the _menu construction block and gate it in OnMenuOpening.
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com
// Version: 2.1.1

using System.ComponentModel;
using System.Drawing;
using System.Globalization;
using System.Runtime.Versioning;
using System.Text;
using RdpAudit.Configurator.Ipc;
using RdpAudit.Configurator.Services;
using RdpAudit.Core.Events;
using RdpAudit.Core.Ipc;
using RdpAudit.Core.Ipc.Contracts;
using RdpAudit.Core.Models;
using RdpAudit.Core.Util;

using RdpAudit.Configurator.Theming;
using static RdpAudit.Configurator.Theming.DarkTheme;

namespace RdpAudit.Configurator.Forms;

// v2.0.0 — dark UI redesign
/// <summary>
/// Stage 7 Remote RDP Clients tab. Provides session listing, session control
/// (disconnect / logoff / shadow), bulk-disconnect actions and shadow policy management,
/// rendered with the shared dark palette.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class RemoteRdpClientsPage : TabPage
{
	private const int AutoRefreshIntervalMs = 5_000;

	/// <summary>Delay between the soft disconnect phase and the hard-logoff sweep, in ms.</summary>
	private const int HardLogoffDelayMs = 120_000;

	// ── Dark palette (mirrors MikroTikPage benchmark) ────────────────────────────
	private static readonly Color BulkInactiveButton = Color.FromArgb(140, 90, 30);
	private static readonly Color BulkInactiveHover = Color.FromArgb(170, 115, 45);
	private static readonly Color BulkExceptCurrentButton = Color.FromArgb(140, 50, 50);
	private static readonly Color BulkExceptCurrentHover = Color.FromArgb(175, 70, 70);
	private static readonly Color CurrentSessionAccent = Color.FromArgb(60, 100, 180);

	// Row tint colors adapted to the dark palette.
	private static readonly Color RowColorActive = Color.FromArgb(30, 65, 30);
	private static readonly Color RowColorDisconnected = Color.FromArgb(70, 45, 25);
	private static readonly Color RowColorInactive = Color.FromArgb(42, 42, 42);

	// ── Fields & DI ──────────────────────────────────────────────────────────────
	private readonly IpcClient _ipc;
	private readonly ShadowLauncher _launcher = new();
	private readonly LocalRdpSessionProvider _localSessions = new();
	private readonly LocalShadowPolicyReader _localShadowPolicy = new();
	private readonly LocalSessionEnrichmentProvider _localEnrichment = new();
	private readonly LocalActiveTcpEnrichmentProvider _localTcpEnrichment = new();
	private readonly OperatorSessionContextProvider _operatorContext = new();

	private readonly DataGridView _grid;
	private readonly BindingList<SessionRow> _binding = new();
	private readonly List<RdpSessionDto> _allSessions = new();

	private readonly TextBox _searchFilter;
	private readonly ComboBox _stateCombo;
	private readonly CheckBox _autoRefreshCheck;
	private readonly Button _refreshButton;
	private readonly Button _clearFiltersButton;
	private readonly Button _disconnectInactiveButton;
	private readonly Button _disconnectExceptCurrentButton;

	private readonly StatusStrip _statusStrip;
	private readonly ToolStripStatusLabel _statusLabel;
	private readonly System.Windows.Forms.Timer _autoRefreshTimer;

	private readonly ContextMenuStrip _menu;
	private readonly ToolStripMenuItem _menuDisconnect;
	private readonly ToolStripMenuItem _menuLogoff;
	private readonly ToolStripMenuItem _menuShadowView;
	private readonly ToolStripMenuItem _menuShadowControl;
	private readonly ToolStripMenuItem _menuShadowControlNoConsent;
	private readonly ToolStripMenuItem _menuExportFacts;
	private readonly ToolStripMenuItem _menuOpenRipeStat;
	private readonly ToolStripMenuItem _menuOpenAbuseIpDb;

	// Shadow policy panel controls.
	private readonly Label _shadowSummaryLabel;
	private readonly Label _shadowHeaderLabel;
	private readonly DataGridView _shadowGrid;
	private readonly BindingList<ShadowValueRow> _shadowBinding = new();
	private readonly Button _enableAllButton;
	private readonly Button _backupButton;
	private readonly Button _restoreButton;
	private readonly Button _refreshPolicyButton;

	// Bulk-disconnect two-phase soft+hard logoff state.
	private readonly HashSet<int> _pendingHardLogoff = new();
	private System.Windows.Forms.Timer? _bulkDisconnectTimer;

	private SessionRow? _menuRow;
	private bool _refreshing;
	private bool _suppressFilterRefresh;

	// ── Construction ─────────────────────────────────────────────────────────────
	public RemoteRdpClientsPage(IpcClient ipc)
	{
		ArgumentNullException.ThrowIfNull(ipc);
		_ipc = ipc;
		Text = "Remote RDP Clients";
		BackColor = PageBack;
		ForeColor = TextPrimary;

		_searchFilter = new TextBox
		{
			Dock = DockStyle.Fill,
			PlaceholderText = "search user / client / IP…",
			BorderStyle = BorderStyle.FixedSingle,
			BackColor = InputBack,
			ForeColor = TextPrimary,
		};
		_searchFilter.TextChanged += (_, _) => OnLocalFilterChanged();

		_stateCombo = new ComboBox
		{
			Dock = DockStyle.Fill,
			DropDownStyle = ComboBoxStyle.DropDownList,
			FlatStyle = FlatStyle.Flat,
			BackColor = InputBack,
			ForeColor = TextPrimary,
		};
		_stateCombo.Items.Add("All states");
		_stateCombo.Items.Add("Active");
		_stateCombo.Items.Add("Disconnected");
		_stateCombo.Items.Add("Inactive (other)");
		_stateCombo.SelectedIndex = 0;
		_stateCombo.SelectedIndexChanged += (_, _) => OnLocalFilterChanged();

		_autoRefreshTimer = new System.Windows.Forms.Timer { Interval = AutoRefreshIntervalMs };
		_autoRefreshTimer.Tick += async (_, _) => await RefreshAsync().ConfigureAwait(true);

		_autoRefreshCheck = new CheckBox
		{
			Text = "Auto refresh (5s)",
			Dock = DockStyle.Fill,
			AutoSize = false,
			FlatStyle = FlatStyle.Flat,
			ForeColor = TextPrimary,
			BackColor = ToolbarBack,
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

		_refreshButton = NewButton("Refresh", ButtonNormal, ButtonHover);
		_refreshButton.Click += async (_, _) => await RefreshAsync().ConfigureAwait(true);

		_clearFiltersButton = NewButton("Clear filters", ButtonNormal, ButtonHover);
		_clearFiltersButton.Click += async (_, _) => await OnClearFiltersAsync().ConfigureAwait(true);

		_disconnectInactiveButton = NewButton("Disconnect all inactive", BulkInactiveButton, BulkInactiveHover);
		_disconnectInactiveButton.Click += async (_, _) => await OnDisconnectAllInactiveAsync().ConfigureAwait(true);

		_disconnectExceptCurrentButton = NewButton("Disconnect all except current", BulkExceptCurrentButton, BulkExceptCurrentHover);
		_disconnectExceptCurrentButton.Click += async (_, _) => await OnDisconnectAllExceptCurrentAsync().ConfigureAwait(true);

		Panel toolbar = BuildToolbar();

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
		ApplyDarkGridStyle(_grid);
		ConfigureSessionGrid(_grid);
		_grid.DataSource = _binding;
		SortableGrid.Enable(_grid, _binding);
		_grid.RowPrePaint += OnRowPrePaint;
		_grid.CellMouseDown += OnCellMouseDown;

		_menuDisconnect = new ToolStripMenuItem("Disconnect session…", null, async (_, _) => await OnDisconnectAsync().ConfigureAwait(true));
		_menuLogoff = new ToolStripMenuItem("Log off (kill) session…", null, async (_, _) => await OnLogoffAsync().ConfigureAwait(true));
		_menuShadowView = new ToolStripMenuItem("Shadow — view only…", null, async (_, _) => await OnShadowAsync(SessionCommandBuilder.ShadowMode.ViewOnly).ConfigureAwait(true));
		_menuShadowControl = new ToolStripMenuItem("Shadow — view + control…", null, async (_, _) => await OnShadowAsync(SessionCommandBuilder.ShadowMode.Control).ConfigureAwait(true));
		_menuShadowControlNoConsent = new ToolStripMenuItem("Shadow — view + control (NO CONSENT)…", null, async (_, _) => await OnShadowAsync(SessionCommandBuilder.ShadowMode.ControlNoConsent).ConfigureAwait(true));
		_menuExportFacts = BuildExportFactsSubmenu();
		_menuOpenRipeStat = new ToolStripMenuItem(IpReputationBrowser.RipeStatMenuLabel, null, (_, _) => OnOpenRipeStat());
		_menuOpenAbuseIpDb = new ToolStripMenuItem(IpReputationBrowser.AbuseIpDbMenuLabel, null, (_, _) => OnOpenAbuseIpDb());
		_menu = new ContextMenuStrip
		{
			Renderer = new DarkMenuRenderer(),
			BackColor = CardBack,
			ForeColor = TextPrimary,
		};
		_menu.Items.Add(_menuDisconnect);
		_menu.Items.Add(_menuLogoff);
		_menu.Items.Add(new ToolStripSeparator());
		_menu.Items.Add(_menuShadowView);
		_menu.Items.Add(_menuShadowControl);
		_menu.Items.Add(_menuShadowControlNoConsent);
		_menu.Items.Add(new ToolStripSeparator());
		_menu.Items.Add(_menuOpenRipeStat);
		_menu.Items.Add(_menuOpenAbuseIpDb);
		_menu.Items.Add(new ToolStripSeparator());
		_menu.Items.Add(_menuExportFacts);
		_menu.Opening += OnMenuOpening;
		_grid.ContextMenuStrip = _menu;
		DataGridClipboardMenu.AppendTo(_menu, _grid);

		_statusStrip = new StatusStrip
		{
			SizingGrip = false,
			BackColor = StatusBack,
			ForeColor = StatusFore,
		};
		_statusLabel = new ToolStripStatusLabel("Waiting for first refresh…")
		{
			Spring = true,
			TextAlign = ContentAlignment.MiddleLeft,
			ForeColor = StatusFore,
		};
		_statusStrip.Items.Add(_statusLabel);

		// --- Shadow policy panel ---------------------------------------------------------------
		_shadowHeaderLabel = new Label
		{
			Dock = DockStyle.Top,
			Height = 22,
			Text = "Session Shadowing Policy",
			Font = new Font(SystemFonts.MessageBoxFont!.FontFamily, 9.5f, FontStyle.Bold),
			ForeColor = AccentHeader,
			BackColor = CardBack,
			TextAlign = ContentAlignment.MiddleLeft,
		};

		_shadowSummaryLabel = new Label
		{
			Dock = DockStyle.Fill,
			TextAlign = ContentAlignment.MiddleLeft,
			AutoSize = false,
			ForeColor = TextSecondary,
			BackColor = CardBack,
			Text = "Shadow policy: loading…",
		};

		_shadowGrid = new DataGridView
		{
			Dock = DockStyle.Fill,
			AutoGenerateColumns = false,
			ReadOnly = true,
			RowHeadersVisible = false,
			AllowUserToAddRows = false,
			SelectionMode = DataGridViewSelectionMode.FullRowSelect,
			MultiSelect = false,
			Height = 130,
		};
		ApplyDarkGridStyle(_shadowGrid);
		ConfigureShadowGrid(_shadowGrid);
		_shadowGrid.DataSource = _shadowBinding;
		// Right-click clipboard menu (Copy Cell / Copy Row / Copy All) for the Registry Keys grid.
		DataGridClipboardMenu.Attach(_shadowGrid);

		_enableAllButton = NewButton("Enable all permissions…", DangerButton, DangerHover);
		_enableAllButton.Click += async (_, _) => await OnEnableAllAsync().ConfigureAwait(true);

		_backupButton = NewButton("Backup", ButtonNormal, ButtonHover);
		_backupButton.Click += async (_, _) => await OnBackupPolicyAsync().ConfigureAwait(true);

		_restoreButton = NewButton("Restore latest…", ButtonNormal, ButtonHover);
		_restoreButton.Click += async (_, _) => await OnRestorePolicyAsync().ConfigureAwait(true);

		_refreshPolicyButton = NewButton("Refresh policy", ButtonNormal, ButtonHover);
		_refreshPolicyButton.Click += async (_, _) => await RefreshShadowPolicyAsync().ConfigureAwait(true);

		Panel shadowPanel = BuildShadowPanel();

		// --- Compose ---------------------------------------------------------------------------
		// Order matters: docked panels added later sit closer to the top edge.
		SplitContainer split = new()
		{
			Dock = DockStyle.Fill,
			Orientation = Orientation.Horizontal,
			SplitterWidth = 6,
			BackColor = PageBack,
		};
		split.Panel1.BackColor = PageBack;
		split.Panel2.BackColor = CardBack;
		split.Panel1.Controls.Add(_grid);
		split.Panel2.Controls.Add(shadowPanel);
		split.HandleCreated += (_, _) =>
		{
			try
			{
				split.SplitterDistance = Math.Max(200, split.Height - 250);
			}
			catch (InvalidOperationException)
			{
				// Layout not ready — fall back to the default which is fine.
			}
		};

		Controls.Add(split);
		Controls.Add(_statusStrip);
		Controls.Add(toolbar);

		HandleCreated += async (_, _) =>
		{
			await RefreshAsync().ConfigureAwait(true);
			await RefreshShadowPolicyAsync().ConfigureAwait(true);
		};
	}

	// ── Layout builders ──────────────────────────────────────────────────────────
	private Panel BuildToolbar()
	{
		// Two stacked dark rows: filters/refresh on top, bulk-disconnect actions below.
		Panel host = new()
		{
			Dock = DockStyle.Top,
			Height = 110,
			BackColor = ToolbarBack,
			Padding = new Padding(6),
		};

		TableLayoutPanel filters = new()
		{
			Dock = DockStyle.Top,
			Height = 60,
			ColumnCount = 6,
			RowCount = 2,
			BackColor = ToolbarBack,
		};
		for (int i = 0; i < 6; i++)
		{
			filters.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100f / 6));
		}

		filters.RowStyles.Add(new RowStyle(SizeType.Absolute, 18));
		filters.RowStyles.Add(new RowStyle(SizeType.Absolute, 38));

		Label searchCaption = MakeCaption("Search");
		filters.Controls.Add(searchCaption, 0, 0);
		filters.Controls.Add(_searchFilter, 0, 1);
		filters.SetColumnSpan(searchCaption, 2);
		filters.SetColumnSpan(_searchFilter, 2);

		filters.Controls.Add(MakeCaption("State filter"), 2, 0);
		filters.Controls.Add(_stateCombo, 2, 1);

		filters.Controls.Add(MakeCaption("Auto refresh"), 3, 0);
		filters.Controls.Add(_autoRefreshCheck, 3, 1);

		filters.Controls.Add(MakeCaption(" "), 4, 0);
		filters.Controls.Add(_refreshButton, 4, 1);

		filters.Controls.Add(MakeCaption(" "), 5, 0);
		filters.Controls.Add(_clearFiltersButton, 5, 1);

		FlowLayoutPanel bulkRow = new()
		{
			Dock = DockStyle.Bottom,
			Height = 38,
			FlowDirection = FlowDirection.LeftToRight,
			WrapContents = false,
			BackColor = ToolbarBack,
			Padding = new Padding(0, 4, 0, 0),
		};
		_disconnectInactiveButton.MinimumSize = new Size(190, 30);
		_disconnectExceptCurrentButton.MinimumSize = new Size(220, 30);
		bulkRow.Controls.Add(_disconnectInactiveButton);
		bulkRow.Controls.Add(_disconnectExceptCurrentButton);

		host.Controls.Add(filters);
		host.Controls.Add(bulkRow);
		return host;
	}

	private Panel BuildShadowPanel()
	{
		Panel panel = new() { Dock = DockStyle.Fill, BackColor = CardBack, Padding = new Padding(10) };
		panel.Paint += (_, e) =>
		{
			using Pen pen = new(CardBorder, 1);
			e.Graphics.DrawRectangle(pen, 0, 0, panel.Width - 1, panel.Height - 1);
		};

		TableLayoutPanel buttons = new()
		{
			Dock = DockStyle.Bottom,
			Height = 38,
			ColumnCount = 4,
			RowCount = 1,
			BackColor = CardBack,
			Padding = new Padding(0, 4, 0, 0),
		};
		for (int i = 0; i < 4; i++)
		{
			buttons.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 25f));
		}

		buttons.Controls.Add(_enableAllButton, 0, 0);
		buttons.Controls.Add(_backupButton, 1, 0);
		buttons.Controls.Add(_restoreButton, 2, 0);
		buttons.Controls.Add(_refreshPolicyButton, 3, 0);

		Panel summaryPanel = new() { Dock = DockStyle.Top, Height = 26, BackColor = CardBack, Padding = new Padding(0, 4, 0, 0) };
		summaryPanel.Controls.Add(_shadowSummaryLabel);

		panel.Controls.Add(_shadowGrid);
		panel.Controls.Add(buttons);
		panel.Controls.Add(summaryPanel);
		panel.Controls.Add(_shadowHeaderLabel);
		return panel;
	}

	private static Label MakeCaption(string text) => new()
	{
		Text = text,
		Dock = DockStyle.Fill,
		TextAlign = ContentAlignment.MiddleLeft,
		AutoSize = false,
		ForeColor = TextSecondary,
		BackColor = ToolbarBack,
		Font = new Font(SystemFonts.MessageBoxFont!.FontFamily, 8.5f, FontStyle.Regular),
	};

	private static Button NewButton(string text, Color normal, Color hover)
	{
		Button b = new()
		{
			Text = text,
			Dock = DockStyle.Fill,
			AutoSize = false,
			Height = 30,
			MinimumSize = new Size(150, 30),
			FlatStyle = FlatStyle.Flat,
			BackColor = normal,
			ForeColor = Color.White,
			Margin = new Padding(4, 0, 4, 0),
			Padding = new Padding(4, 0, 4, 0),
			UseVisualStyleBackColor = false,
		};
		b.FlatAppearance.BorderColor = hover;
		b.FlatAppearance.BorderSize = 1;
		b.FlatAppearance.MouseOverBackColor = hover;
		return b;
	}

	private static void ApplyDarkGridStyle(DataGridView grid)
	{
		grid.EnableHeadersVisualStyles = false;
		grid.BackgroundColor = GridBack;
		grid.GridColor = GridLines;
		grid.BorderStyle = BorderStyle.None;
		grid.DefaultCellStyle.BackColor = CellBack;
		grid.DefaultCellStyle.ForeColor = TextPrimary;
		grid.DefaultCellStyle.SelectionBackColor = SelectionBack;
		grid.DefaultCellStyle.SelectionForeColor = Color.White;
		grid.AlternatingRowsDefaultCellStyle.BackColor = AltRowBack;
		grid.AlternatingRowsDefaultCellStyle.ForeColor = TextPrimary;
		grid.AlternatingRowsDefaultCellStyle.SelectionBackColor = SelectionBack;
		grid.AlternatingRowsDefaultCellStyle.SelectionForeColor = Color.White;
		grid.ColumnHeadersDefaultCellStyle.BackColor = HeaderBack;
		grid.ColumnHeadersDefaultCellStyle.ForeColor = HeaderFore;
		grid.ColumnHeadersDefaultCellStyle.SelectionBackColor = HeaderBack;
		grid.ColumnHeadersDefaultCellStyle.SelectionForeColor = HeaderFore;
		grid.ColumnHeadersBorderStyle = DataGridViewHeaderBorderStyle.Single;
	}

	private static void ConfigureSessionGrid(DataGridView grid)
	{
		grid.Columns.Add(new DataGridViewTextBoxColumn
		{
			HeaderText = "●",
			DataPropertyName = nameof(SessionRow.StateBullet),
			Width = 30,
			ToolTipText = "Green = active, orange = disconnected, grey = inactive / other.",
		});
		grid.Columns.Add(new DataGridViewTextBoxColumn
		{
			HeaderText = "ID",
			DataPropertyName = nameof(SessionRow.SessionId),
			Width = 60,
		});
		grid.Columns.Add(new DataGridViewTextBoxColumn
		{
			HeaderText = "User",
			DataPropertyName = nameof(SessionRow.UserName),
			Width = 180,
		});
		grid.Columns.Add(new DataGridViewTextBoxColumn
		{
			HeaderText = "Session",
			DataPropertyName = nameof(SessionRow.SessionName),
			Width = 120,
		});
		grid.Columns.Add(new DataGridViewTextBoxColumn
		{
			HeaderText = "State",
			DataPropertyName = nameof(SessionRow.State),
			Width = 110,
		});
		grid.Columns.Add(new DataGridViewTextBoxColumn
		{
			HeaderText = "Client",
			DataPropertyName = nameof(SessionRow.ClientName),
			Width = 140,
		});
		grid.Columns.Add(new DataGridViewTextBoxColumn
		{
			HeaderText = "Client IP",
			DataPropertyName = nameof(SessionRow.ClientAddress),
			Width = 140,
		});
		grid.Columns.Add(new DataGridViewTextBoxColumn
		{
			HeaderText = "Current?",
			DataPropertyName = nameof(SessionRow.CurrentText),
			Width = 70,
		});

		// --- Stage IP-E historical-context columns (additive). Never overrides ClientAddress (live).
		// Populated only when matching RdpConnectionFacts exist for the session's source IP.
		grid.Columns.Add(new DataGridViewTextBoxColumn
		{
			HeaderText = "Hist First Seen (local)",
			DataPropertyName = nameof(SessionRow.HistoricalFirstSeenUtcText),
			Width = 160,
			ToolTipText = "Earliest FirstSeenUtc across matching RdpConnectionFacts for this session's source IP.",
		});
		grid.Columns.Add(new DataGridViewTextBoxColumn
		{
			HeaderText = "Hist Last Seen (local)",
			DataPropertyName = nameof(SessionRow.HistoricalLastSeenUtcText),
			Width = 160,
			ToolTipText = "Latest LastSeenUtc across matching RdpConnectionFacts for this session's source IP.",
		});
		grid.Columns.Add(new DataGridViewTextBoxColumn
		{
			HeaderText = "Hist Failed",
			DataPropertyName = nameof(SessionRow.HistoricalFailedLogons),
			Width = 90,
			ToolTipText = "Sum of failed logons across matching RdpConnectionFacts for this source IP.",
		});
		grid.Columns.Add(new DataGridViewTextBoxColumn
		{
			HeaderText = "Hist Success",
			DataPropertyName = nameof(SessionRow.HistoricalSuccessfulLogons),
			Width = 90,
			ToolTipText = "Sum of successful logons across matching RdpConnectionFacts for this source IP.",
		});
		grid.Columns.Add(new DataGridViewTextBoxColumn
		{
			HeaderText = "Hist Users Attempted",
			DataPropertyName = nameof(SessionRow.HistoricalUserNamesAttemptedText),
			Width = 200,
			ToolTipText = "Comma-separated, deduplicated usernames attempted from this IP across matching facts.",
		});

		// --- Stage 2 per-IP historical columns. These augment (not replace) the user-keyed Hist
		// columns above so operators can compare per-user and per-IP brute-force pressure side by side.
		// Cells render blank (not 0) when the session has no resolved IP — distinguishing unknown
		// from a real zero.
		grid.Columns.Add(new DataGridViewTextBoxColumn
		{
			HeaderText = "IP Hist Failed",
			DataPropertyName = nameof(SessionRow.HistoricalFailedLogonsByIpText),
			Width = 100,
			ToolTipText = "Sum of failed logons across RdpConnectionFacts that share this session's source IP. Blank when the IP is unknown.",
		});
		grid.Columns.Add(new DataGridViewTextBoxColumn
		{
			HeaderText = "IP Hist Success",
			DataPropertyName = nameof(SessionRow.HistoricalSuccessfulLogonsByIpText),
			Width = 100,
			ToolTipText = "Sum of successful logons across RdpConnectionFacts that share this session's source IP. Blank when the IP is unknown.",
		});
		grid.Columns.Add(new DataGridViewTextBoxColumn
		{
			HeaderText = "IP Hist Users",
			DataPropertyName = nameof(SessionRow.HistoricalUsersAttemptedFromIpText),
			Width = 220,
			ToolTipText = "Comma-separated, deduplicated usernames attempted from this IP across all matching facts. Blank when the IP is unknown.",
		});
		grid.Columns.Add(new DataGridViewTextBoxColumn
		{
			HeaderText = "IP Hist First Seen (local)",
			DataPropertyName = nameof(SessionRow.HistoricalFirstSeenByIpUtcText),
			Width = 170,
			ToolTipText = "Earliest FirstSeenUtc across RdpConnectionFacts that share this session's source IP. Blank when the IP is unknown.",
		});
		grid.Columns.Add(new DataGridViewTextBoxColumn
		{
			HeaderText = "IP Hist Last Seen (local)",
			DataPropertyName = nameof(SessionRow.HistoricalLastSeenByIpUtcText),
			Width = 170,
			ToolTipText = "Most recent LastSeenUtc across RdpConnectionFacts that share this session's source IP. Blank when the IP is unknown.",
		});
	}

	private static void ConfigureShadowGrid(DataGridView grid)
	{
		grid.Columns.Add(new DataGridViewTextBoxColumn
		{
			HeaderText = "Registry key",
			DataPropertyName = nameof(ShadowValueRow.KeyPath),
			// Size to the widest content (header + cells) so the key column is exactly as wide
			// as its longest value and never stretches across the whole row.
			AutoSizeMode = DataGridViewAutoSizeColumnMode.AllCells,
		});
		grid.Columns.Add(new DataGridViewTextBoxColumn
		{
			HeaderText = "Value",
			DataPropertyName = nameof(ShadowValueRow.ValueName),
			Width = 140,
		});
		grid.Columns.Add(new DataGridViewTextBoxColumn
		{
			HeaderText = "Current",
			DataPropertyName = nameof(ShadowValueRow.CurrentText),
			Width = 80,
		});
		grid.Columns.Add(new DataGridViewTextBoxColumn
		{
			HeaderText = "Recommended",
			DataPropertyName = nameof(ShadowValueRow.RecommendedText),
			Width = 100,
		});
		grid.Columns.Add(new DataGridViewTextBoxColumn
		{
			HeaderText = "Description",
			DataPropertyName = nameof(ShadowValueRow.Description),
			// Last column absorbs all remaining horizontal space in the window.
			AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill,
			MinimumWidth = 240,
		});
	}

	// ── Public API ───────────────────────────────────────────────────────────────
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
			RdpSessionFallbackOrchestrator orchestrator = new(
				ipcFetch: ct => _ipc.SendAsync<RdpSessionListDto>(IpcCommand.ListRdpSessions, null, ct),
				localFetch: _localSessions.FetchForOrchestratorAsync);
			RdpSessionListSnapshot snapshot = await orchestrator.CaptureAsync().ConfigureAwait(true);

			if (!snapshot.HasSessions)
			{
				SetStatus(string.Format(CultureInfo.InvariantCulture,
					"Sessions refresh FAILED: service IPC ({0}); local fallback ({1}).",
					snapshot.IpcDetail ?? "unknown",
					snapshot.LocalDetail ?? "unknown"));
				return;
			}

			_allSessions.Clear();
			_allSessions.AddRange(snapshot.Sessions);

			// v1.3.8 — scope the operator-visible "Current?" flag to the session owned by the user
			// running the Configurator. The service (and the parser) cannot know which interactive
			// session the operator uses, so we compute it here from the running process SessionId
			// and the current Windows identity. This replaces the prior behaviour where every active
			// rdp-tcp# session of every logged-in user was flagged Current.
			OperatorSessionContext operatorContext = _operatorContext.Capture();
			CurrentRdpMatchResult currentMatch = CurrentRdpSessionMatcher.ApplyTo(_allSessions, operatorContext);

			if (snapshot.Source == RdpSessionListSource.ServiceIpc)
			{
				ApplyLocalFilter();
				SetStatus(string.Format(CultureInfo.InvariantCulture,
					"Sessions refresh OK (service IPC). count={0}, active={1}, disconnected={2}. {3}",
					_allSessions.Count,
					_allSessions.Count(s => s.IsActive),
					_allSessions.Count(s => s.IsDisconnected),
					currentMatch.Describe()));
			}
			else
			{
				LocalSessionEnrichmentReport enrichment = await _localEnrichment
					.EnrichAsync(_allSessions)
					.ConfigureAwait(true);

				// Apply the live TCP fallback AFTER the DB enrichment so a stronger DB
				// correlation always wins. The TCP enricher only fills missing Client IP on
				// Active RDP sessions when both sides are unambiguous.
				LocalActiveTcpEnrichmentReport tcpEnrichment = await _localTcpEnrichment
					.EnrichAsync(_allSessions)
					.ConfigureAwait(true);

				ApplyLocalFilter();

				string enrichmentStatus = enrichment.Available
					? "historical enrichment: " + enrichment.Status
					: "historical enrichment unavailable: " + enrichment.Status;
				string tcpStatus = "live TCP enrichment: " + tcpEnrichment.Status;

				SetStatus(string.Format(CultureInfo.InvariantCulture,
					"Source: local session fallback ({4}); {5}; {6}. "
					+ "count={0}, active={1}, disconnected={2}. Service IPC: {3}. {7}",
					_allSessions.Count,
					_allSessions.Count(s => s.IsActive),
					_allSessions.Count(s => s.IsDisconnected),
					snapshot.IpcDetail ?? "unreachable",
					snapshot.LocalDetail ?? "unspecified mode",
					enrichmentStatus,
					tcpStatus,
					currentMatch.Describe()));
			}
		}
		catch (Exception ex)
		{
			SetStatus("Sessions refresh FAILED: " + ex.GetType().Name + " — " + ex.Message);
		}
		finally
		{
			_refreshing = false;
			_refreshButton.Enabled = true;
		}
	}

	public async Task RefreshShadowPolicyAsync()
	{
		ShadowPolicyStatusDto? response = null;
		try
		{
			response = await _ipc
				.SendAsync<ShadowPolicyStatusDto>(IpcCommand.GetShadowPolicyStatus)
				.ConfigureAwait(true);
		}
		catch (Exception ex)
		{
			SetStatus("Shadow policy refresh via IPC failed (" + ex.GetType().Name + "): " + ex.Message
				+ " — falling back to local registry read.");
		}

		if (response is not null)
		{
			ApplyShadowStatus(response);
			return;
		}

		// Local fallback: synthesize a minimal ShadowPolicyStatusDto from the registry so the
		// operator still sees the effective policy when the service IPC is unreachable.
		ShadowPolicyMode local = _localShadowPolicy.Read();
		int rawValue = local == ShadowPolicyMode.NotConfigured ? -1 : (int)local;
		ShadowPolicyStatusDto localSnapshot = new()
		{
			Status = IpcResultStatus.Success,
			ShadowMode = rawValue,
			AllPermissionsEnabled = rawValue == ShadowPolicyModel.EnableAllPermissionsValue,
			Message = "Local registry fallback (service IPC unreachable).",
		};
		ApplyShadowStatus(localSnapshot);
	}

	// ── Core Logic — shadow policy ───────────────────────────────────────────────
	private void ApplyShadowStatus(ShadowPolicyStatusDto? status)
	{
		if (status is null)
		{
			_shadowSummaryLabel.Text = "Shadow policy: service unreachable.";
			_shadowBinding.Clear();
			return;
		}

		ShadowPolicyMode mode = ShadowPolicyModel.FromRawValue(status.ShadowMode == -1 ? null : status.ShadowMode);
		string backupText = status.HasBackup && status.LatestSnapshotId is not null
			? "  | latest backup: " + status.LatestSnapshotId
			: "  | no backup yet";
		_shadowSummaryLabel.Text = string.Format(CultureInfo.InvariantCulture,
			"Shadow policy: {0} (raw={1}). AllPermissions={2}{3}",
			ShadowPolicyModel.Describe(mode),
			status.ShadowMode,
			status.AllPermissionsEnabled ? "yes" : "no",
			backupText);

		_shadowBinding.RaiseListChangedEvents = false;
		_shadowBinding.Clear();
		foreach (ShadowPolicyValueDto v in status.Values)
		{
			_shadowBinding.Add(new ShadowValueRow
			{
				KeyPath = v.KeyPath,
				ValueName = v.ValueName,
				CurrentText = v.CurrentValue < 0 ? "(unset)" : v.CurrentValue.ToString(CultureInfo.InvariantCulture),
				RecommendedText = v.RecommendedValue < 0 ? "—" : v.RecommendedValue.ToString(CultureInfo.InvariantCulture),
				Description = v.Description ?? string.Empty,
			});
		}
		_shadowBinding.RaiseListChangedEvents = true;
		_shadowBinding.ResetBindings();

		SetStatus("Shadow policy snapshot loaded: " + (status.Message ?? string.Empty));
	}

	// ── Core Logic — filtering ───────────────────────────────────────────────────
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
		string query = _searchFilter.Text?.Trim() ?? string.Empty;
		string stateChoice = _stateCombo.SelectedItem as string ?? "All states";

		_binding.RaiseListChangedEvents = false;
		_binding.Clear();
		foreach (RdpSessionDto session in _allSessions)
		{
			if (!MatchesStateFilter(session, stateChoice))
			{
				continue;
			}

			if (!string.IsNullOrEmpty(query) && !MatchesSearchQuery(session, query))
			{
				continue;
			}

			_binding.Add(SessionRow.From(session));
		}
		_binding.RaiseListChangedEvents = true;
		_binding.ResetBindings();
	}

	private static bool MatchesStateFilter(RdpSessionDto session, string stateChoice) => stateChoice switch
	{
		"Active" => session.IsActive,
		"Disconnected" => session.IsDisconnected,
		"Inactive (other)" => !session.IsActive && !session.IsDisconnected,
		_ => true,
	};

	private static bool MatchesSearchQuery(RdpSessionDto session, string query) =>
		(session.UserName?.Contains(query, StringComparison.OrdinalIgnoreCase) ?? false)
		|| (session.ClientName?.Contains(query, StringComparison.OrdinalIgnoreCase) ?? false)
		|| (session.ClientAddress?.Contains(query, StringComparison.OrdinalIgnoreCase) ?? false)
		|| (session.SessionName?.Contains(query, StringComparison.OrdinalIgnoreCase) ?? false)
		|| session.SessionId.ToString(CultureInfo.InvariantCulture).Contains(query, StringComparison.OrdinalIgnoreCase);

	private async Task OnClearFiltersAsync()
	{
		_suppressFilterRefresh = true;
		try
		{
			_searchFilter.Text = string.Empty;
			_stateCombo.SelectedIndex = 0;
		}
		finally
		{
			_suppressFilterRefresh = false;
		}

		await RefreshAsync().ConfigureAwait(true);
	}

	private void OnRowPrePaint(object? sender, DataGridViewRowPrePaintEventArgs e)
	{
		if (e.RowIndex < 0 || e.RowIndex >= _binding.Count)
		{
			return;
		}

		SessionRow row = _binding[e.RowIndex];
		Color color = row.IsActive ? RowColorActive
			: row.IsDisconnected ? RowColorDisconnected
			: RowColorInactive;
		_grid.Rows[e.RowIndex].DefaultCellStyle.BackColor = color;

		// v2.0.0 — draw a subtle left-border highlight on the operator's current session row.
		if (row.IsCurrent)
		{
			Rectangle rb = e.RowBounds;
			using SolidBrush brush = new(CurrentSessionAccent);
			e.Graphics.FillRectangle(brush, rb.Left, rb.Top, 3, rb.Height);
		}
	}

	private void OnCellMouseDown(object? sender, DataGridViewCellMouseEventArgs e)
	{
		if (e.Button != MouseButtons.Right || e.RowIndex < 0 || e.RowIndex >= _binding.Count)
		{
			_menuRow = null;
			return;
		}

		_grid.ClearSelection();
		_grid.Rows[e.RowIndex].Selected = true;
		_menuRow = _binding[e.RowIndex];
	}

	private void OnMenuOpening(object? sender, CancelEventArgs e)
	{
		bool hasRow = _menuRow is not null;
		bool hasValidIp = hasRow && !string.IsNullOrWhiteSpace(_menuRow!.ClientAddress) && AddressListFilter.IsValidIp(_menuRow.ClientAddress);
		bool reputationEligible = hasRow && IpReputationBrowser.IsLookupEligible(_menuRow!.ClientAddress);
		_menuDisconnect.Enabled = hasRow;
		_menuLogoff.Enabled = hasRow;
		_menuShadowView.Enabled = hasRow;
		_menuShadowControl.Enabled = hasRow;
		_menuShadowControlNoConsent.Enabled = hasRow;
		_menuExportFacts.Enabled = hasValidIp;
		_menuOpenRipeStat.Enabled = reputationEligible;
		_menuOpenAbuseIpDb.Enabled = reputationEligible;
	}

	private void OnOpenRipeStat()
	{
		if (_menuRow is null)
		{
			return;
		}

		IpReputationBrowser.LaunchOutcome outcome = IpReputationBrowser.OpenRipeStat(_menuRow.ClientAddress);
		SetStatus(outcome.Format());
	}

	private void OnOpenAbuseIpDb()
	{
		if (_menuRow is null)
		{
			return;
		}

		IpReputationBrowser.LaunchOutcome outcome = IpReputationBrowser.OpenAbuseIpDb(_menuRow.ClientAddress);
		SetStatus(outcome.Format());
	}

	// ── Core Logic — single-session actions ──────────────────────────────────────
	private async Task OnDisconnectAsync()
	{
		if (_menuRow is null)
		{
			return;
		}

		string prompt = string.Format(CultureInfo.InvariantCulture,
			"Disconnect session {0} (user {1})?\n\nThe user's apps remain running on the server but their RDP "
			+ "viewer is detached. The user can reconnect.",
			_menuRow.SessionId, FormatUserForPrompt(_menuRow));
		if (!Confirm(prompt, "Confirm disconnect session"))
		{
			SetStatus("Disconnect cancelled.");
			return;
		}

		await SendSessionActionAsync(
			IpcCommand.DisconnectSession,
			new SessionActionRequest { SessionId = _menuRow.SessionId, Reason = "Configurator manual disconnect" },
			"DisconnectSession").ConfigureAwait(true);
		await RefreshAsync().ConfigureAwait(true);
	}

	private async Task OnLogoffAsync()
	{
		if (_menuRow is null)
		{
			return;
		}

		string prompt = string.Format(CultureInfo.InvariantCulture,
			"Log off (kill) session {0} (user {1})?\n\nWARNING: this terminates every process owned by the "
			+ "session — unsaved work WILL be lost. This action is irreversible.",
			_menuRow.SessionId, FormatUserForPrompt(_menuRow));
		if (!Confirm(prompt, "Confirm log off session"))
		{
			SetStatus("Log off cancelled.");
			return;
		}

		await SendSessionActionAsync(
			IpcCommand.LogoffSession,
			new SessionActionRequest { SessionId = _menuRow.SessionId, Reason = "Configurator manual logoff" },
			"LogoffSession").ConfigureAwait(true);
		await RefreshAsync().ConfigureAwait(true);
	}

	private async Task OnShadowAsync(SessionCommandBuilder.ShadowMode mode)
	{
		if (_menuRow is null)
		{
			return;
		}

		string modeDescription = mode switch
		{
			SessionCommandBuilder.ShadowMode.ViewOnly => "view only (the user will be prompted to allow)",
			SessionCommandBuilder.ShadowMode.Control => "view + control (the user will be prompted to allow)",
			SessionCommandBuilder.ShadowMode.ControlNoConsent => "view + control with NO CONSENT PROMPT",
			_ => mode.ToString(),
		};
		string prompt = string.Format(CultureInfo.InvariantCulture,
			"Initiate shadow session: {0} (user {1})?\n\nMode: {2}.\n\nThis is an auditable observation/control action.",
			_menuRow.SessionId, FormatUserForPrompt(_menuRow), modeDescription);
		if (!Confirm(prompt, "Confirm shadow session"))
		{
			SetStatus("Shadow cancelled.");
			return;
		}

		// 1) Ask the service to validate against policy — service may be unreachable.
		ShadowServiceDecision serviceDecision;
		try
		{
			SessionActionResult? policy = await _ipc
				.SendAsync<SessionActionResult>(IpcCommand.ShadowSession, new SessionActionRequest
				{
					SessionId = _menuRow.SessionId,
					Reason = "Configurator shadow request",
					ShadowMode = (int)mode,
				})
				.ConfigureAwait(true);

			if (policy is null)
			{
				serviceDecision = ShadowServiceDecision.FromUnreachable("IPC returned null");
			}
			else if (policy.Status == IpcResultStatus.Success)
			{
				serviceDecision = ShadowServiceDecision.FromApproval(policy.Message);
			}
			else
			{
				serviceDecision = ShadowServiceDecision.FromRefusal(policy.Message ?? policy.Status.ToString());
			}
		}
		catch (Exception ex)
		{
			serviceDecision = ShadowServiceDecision.FromUnreachable(ex.GetType().Name + " — " + ex.Message);
		}

		// 2) Read the local Shadow policy as a fallback / cross-check.
		ShadowPolicyMode localPolicy = _localShadowPolicy.Read();
		ShadowGateDecision decision = ShadowGate.Evaluate(serviceDecision, localPolicy, mode);

		if (!decision.ShouldLaunch)
		{
			SetStatus(string.Format(CultureInfo.InvariantCulture,
				"ShadowSession refused: {0}", decision.Reason));
			return;
		}

		// 3) Spawn mstsc with sanitized arguments.
		ShadowLaunchResult launch = _launcher.Launch(_menuRow.SessionId, mode);
		string sourceTag = decision.Outcome switch
		{
			ShadowGateOutcome.AllowByService => "service-approved",
			ShadowGateOutcome.AllowByLocalPolicy => "local-policy fallback (service unreachable)",
			ShadowGateOutcome.AllowOverridingStaleService => "local-policy override (service refusal treated as stale)",
			_ => "approved",
		};
		SetStatus(launch.Started
			? string.Format(CultureInfo.InvariantCulture,
				"mstsc /shadow started for session {0} (pid {1}, mode {2}, gate={3}).",
				_menuRow.SessionId, launch.ProcessId, mode, sourceTag)
			: string.Format(CultureInfo.InvariantCulture,
				"mstsc /shadow FAILED for session {0}: {1}",
				_menuRow.SessionId, launch.Error ?? "(unknown error)"));
	}

	// ── Core Logic — bulk disconnect (two-phase soft + hard logoff) ──────────────

	/// <summary>Disconnects every session that is not Active and has a valid numeric Session ID.
	/// A soft disconnect is attempted first; sessions still present after two minutes get a hard
	/// logoff.</summary>
	private async Task OnDisconnectAllInactiveAsync()
	{
		List<RdpSessionDto> targets = _allSessions
			.Where(s => !s.IsActive && s.SessionId > 0)
			.ToList();

		if (targets.Count == 0)
		{
			SetStatus("No inactive sessions with a session ID to disconnect.");
			return;
		}

		string prompt = string.Format(CultureInfo.InvariantCulture,
			"Disconnect {0} inactive session(s)?\n\nSessions: {1}\n\n"
			+ "A soft disconnect (DisconnectSession) will be attempted first.\n"
			+ "If a session is still present after 2 minutes, a hard logoff (LogoffSession) will follow.",
			targets.Count, DescribeTargets(targets));
		if (!Confirm(prompt, "Confirm bulk disconnect (inactive)"))
		{
			SetStatus("Bulk disconnect (inactive) cancelled.");
			return;
		}

		await OnBulkDisconnectAsync(targets, "inactive").ConfigureAwait(true);
	}

	/// <summary>Disconnects every session with a valid Session ID — including active users —
	/// except the operator's own current session. Same two-phase soft+hard flow.</summary>
	private async Task OnDisconnectAllExceptCurrentAsync()
	{
		List<RdpSessionDto> targets = _allSessions
			.Where(s => s.SessionId > 0 && !s.IsCurrent)
			.ToList();

		if (targets.Count == 0)
		{
			SetStatus("No other sessions with a session ID to disconnect.");
			return;
		}

		string prompt = string.Format(CultureInfo.InvariantCulture,
			"Disconnect ALL {0} session(s) except your current session?\n\n"
			+ "This includes active users. Soft disconnect first, hard logoff after 2 minutes if needed.\n\n"
			+ "Sessions: {1}\n\n"
			+ "WARNING: Active users will lose their RDP connection.",
			targets.Count, DescribeTargets(targets));
		if (!Confirm(prompt, "Confirm bulk disconnect (all except current)"))
		{
			SetStatus("Bulk disconnect (all except current) cancelled.");
			return;
		}

		await OnBulkDisconnectAsync(targets, "all except current").ConfigureAwait(true);
	}

	/// <summary>Shared two-phase soft+hard logoff flow. Sends a soft DisconnectSession to each
	/// target, schedules a single-shot 2-minute timer, and on tick refreshes the session list and
	/// hard-logs-off any target still present.</summary>
	private async Task OnBulkDisconnectAsync(IReadOnlyList<RdpSessionDto> targets, string label)
	{
		ArgumentNullException.ThrowIfNull(targets);
		if (targets.Count == 0)
		{
			return;
		}

		// Cancel any timer already running and merge/replace the pending set so a second click
		// before the previous timer fires does not double-schedule.
		CancelBulkTimer();

		_disconnectInactiveButton.Enabled = false;
		_disconnectExceptCurrentButton.Enabled = false;
		try
		{
			_pendingHardLogoff.Clear();
			foreach (RdpSessionDto target in targets)
			{
				_pendingHardLogoff.Add(target.SessionId);
				await SendSessionActionAsync(
					IpcCommand.DisconnectSession,
					new SessionActionRequest
					{
						SessionId = target.SessionId,
						Reason = "Configurator bulk disconnect (" + label + ")",
					},
					"Bulk DisconnectSession").ConfigureAwait(true);
			}

			SetStatus(string.Format(CultureInfo.InvariantCulture,
				"Bulk disconnect ({0}): {1} soft sent. Hard logoff scheduled in 2 min for remaining.",
				label, targets.Count));

			_bulkDisconnectTimer = new System.Windows.Forms.Timer { Interval = HardLogoffDelayMs };
			_bulkDisconnectTimer.Tick += async (_, _) => await OnBulkHardLogoffTickAsync(label).ConfigureAwait(true);
			_bulkDisconnectTimer.Start();
		}
		finally
		{
			_disconnectInactiveButton.Enabled = true;
			_disconnectExceptCurrentButton.Enabled = true;
		}
	}

	/// <summary>Fires once, two minutes after the soft phase: refresh the session list, then hard
	/// logoff every still-present session whose ID was in the original pending set.</summary>
	private async Task OnBulkHardLogoffTickAsync(string label)
	{
		CancelBulkTimer();

		// Snapshot and clear the pending set so a re-entrant click starts cleanly.
		int[] pending = _pendingHardLogoff.ToArray();
		_pendingHardLogoff.Clear();
		if (pending.Length == 0)
		{
			return;
		}

		await RefreshAsync().ConfigureAwait(true);

		HashSet<int> stillPresent = _allSessions
			.Where(s => s.SessionId > 0)
			.Select(s => s.SessionId)
			.ToHashSet();

		int hardCount = 0;
		foreach (int sessionId in pending)
		{
			if (!stillPresent.Contains(sessionId))
			{
				continue;
			}

			hardCount++;
			await SendSessionActionAsync(
				IpcCommand.LogoffSession,
				new SessionActionRequest
				{
					SessionId = sessionId,
					Reason = "Configurator bulk hard logoff (" + label + ")",
				},
				"Bulk LogoffSession").ConfigureAwait(true);
		}

		SetStatus(string.Format(CultureInfo.InvariantCulture,
			"Bulk disconnect ({0}): hard logoff phase complete — {1} session(s) still present were logged off.",
			label, hardCount));
		await RefreshAsync().ConfigureAwait(true);
	}

	private void CancelBulkTimer()
	{
		if (_bulkDisconnectTimer is not null)
		{
			_bulkDisconnectTimer.Stop();
			_bulkDisconnectTimer.Dispose();
			_bulkDisconnectTimer = null;
		}
	}

	private static string DescribeTargets(IReadOnlyList<RdpSessionDto> targets)
	{
		const int maxShown = 10;
		IEnumerable<string> shown = targets
			.Take(maxShown)
			.Select(s => string.Format(CultureInfo.InvariantCulture,
				"{0}:{1}",
				s.SessionId,
				string.IsNullOrEmpty(s.UserName) ? "(no user)" : s.UserName));
		string joined = string.Join(", ", shown);
		return targets.Count > maxShown ? joined + ", …" : joined;
	}

	// ── Core Logic — shadow policy actions ───────────────────────────────────────
	private async Task OnEnableAllAsync()
	{
		string prompt =
			"Apply 'Enable all permissions' shadow policy?\n\n"
			+ "This sets the Microsoft Shadow value to 2 (full control with NO user consent prompt) under\n"
			+ "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services.\n\n"
			+ "A snapshot of the current policy is captured first so the change is reversible via Restore.";
		if (!Confirm(prompt, "Confirm Enable all permissions"))
		{
			SetStatus("Enable all permissions cancelled.");
			return;
		}

		try
		{
			ShadowPolicyStatusDto? response = await _ipc
				.SendAsync<ShadowPolicyStatusDto>(IpcCommand.ApplyShadowPolicy, new ShadowPolicyApplyRequest
				{
					EnableAllPermissions = true,
					TakeBackupFirst = true,
					Reason = "Configurator Enable all permissions",
				})
				.ConfigureAwait(true);
			ApplyShadowStatus(response);
			SetStatus("ApplyShadowPolicy(EnableAllPermissions) completed.");
		}
		catch (Exception ex)
		{
			SetStatus("ApplyShadowPolicy FAILED: " + ex.GetType().Name + " — " + ex.Message);
		}
	}

	private async Task OnBackupPolicyAsync()
	{
		try
		{
			ShadowPolicyStatusDto? response = await _ipc
				.SendAsync<ShadowPolicyStatusDto>(IpcCommand.BackupShadowPolicy)
				.ConfigureAwait(true);
			ApplyShadowStatus(response);
			SetStatus("BackupShadowPolicy completed.");
		}
		catch (Exception ex)
		{
			SetStatus("BackupShadowPolicy FAILED: " + ex.GetType().Name + " — " + ex.Message);
		}
	}

	private async Task OnRestorePolicyAsync()
	{
		string prompt =
			"Restore the most recent shadow policy backup?\n\n"
			+ "Current registry values will be overwritten with the snapshot taken before the last Apply.";
		if (!Confirm(prompt, "Confirm Restore latest"))
		{
			SetStatus("Restore cancelled.");
			return;
		}

		try
		{
			ShadowPolicyStatusDto? response = await _ipc
				.SendAsync<ShadowPolicyStatusDto>(IpcCommand.RestoreShadowPolicy, payload: null)
				.ConfigureAwait(true);
			ApplyShadowStatus(response);
			SetStatus("RestoreShadowPolicy completed.");
		}
		catch (Exception ex)
		{
			SetStatus("RestoreShadowPolicy FAILED: " + ex.GetType().Name + " — " + ex.Message);
		}
	}

	// ---------------------------------------------------------------------------------------------
	// Export Connection Facts (Stage IP-E) — submenu wired into the sessions context menu.
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
		if (_menuRow is null
			|| string.IsNullOrWhiteSpace(_menuRow.ClientAddress)
			|| !AddressListFilter.IsValidIp(_menuRow.ClientAddress))
		{
			SetStatus("Export Connection Facts aborted: no valid IP on the selected session row.");
			return;
		}

		await ConnectionFactsExportRunner.RunAsync(_ipc, _menuRow.ClientAddress, format, SetStatus).ConfigureAwait(true);
	}

	// ── Error Handling & IPC dispatch ────────────────────────────────────────────
	private async Task SendSessionActionAsync(IpcCommand command, SessionActionRequest request, string label)
	{
		try
		{
			SessionActionResult? response = await _ipc
				.SendAsync<SessionActionResult>(command, request)
				.ConfigureAwait(true);
			if (response is null)
			{
				SetStatus(label + " FAILED: service unreachable.");
				return;
			}

			SetStatus(string.Format(CultureInfo.InvariantCulture,
				"{0} session={1} status={2}: {3}",
				label, response.SessionId, response.Status, response.Message ?? string.Empty));
		}
		catch (Exception ex)
		{
			SetStatus(label + " FAILED: " + ex.GetType().Name + " — " + ex.Message);
		}
	}

	private static bool Confirm(string message, string caption) =>
		MessageBox.Show(
			message,
			caption,
			MessageBoxButtons.YesNo,
			MessageBoxIcon.Warning,
			MessageBoxDefaultButton.Button2) == DialogResult.Yes;

	private static string FormatUserForPrompt(SessionRow row)
	{
		if (string.IsNullOrEmpty(row.UserName))
		{
			return "(no user)";
		}

		return "'" + row.UserName + "'";
	}

	private void SetStatus(string message)
	{
		string stamped = string.Format(CultureInfo.InvariantCulture,
			"[{0:HH:mm:ss}Z] {1}",
			DateTime.UtcNow, message);
		if (_statusStrip.InvokeRequired)
		{
			_statusStrip.BeginInvoke(new Action(() => _statusLabel.Text = stamped));
		}
		else
		{
			_statusLabel.Text = stamped;
		}
	}

	// ── Disposal ─────────────────────────────────────────────────────────────────
	protected override void Dispose(bool disposing)
	{
		if (disposing)
		{
			_autoRefreshTimer.Stop();
			_autoRefreshTimer.Dispose();
			CancelBulkTimer();
			_menu.Dispose();
		}

		base.Dispose(disposing);
	}

	// ── Dark context-menu renderer ───────────────────────────────────────────────

	/// <summary>ToolStripProfessionalRenderer wired with the dark palette so the sessions context
	/// menu matches the rest of the page.</summary>
	private sealed class DarkMenuRenderer : ToolStripProfessionalRenderer
	{
		public DarkMenuRenderer()
			: base(new DarkColorTable())
		{
		}

		protected override void OnRenderItemText(ToolStripItemTextRenderEventArgs e)
		{
			ArgumentNullException.ThrowIfNull(e);
			e.TextColor = e.Item.Enabled ? TextPrimary : TextSecondary;
			base.OnRenderItemText(e);
		}
	}

	/// <summary>Dark color table for <see cref="DarkMenuRenderer"/>.</summary>
	private sealed class DarkColorTable : ProfessionalColorTable
	{
		public override Color ToolStripDropDownBackground => CardBack;
		public override Color ImageMarginGradientBegin => CardBack;
		public override Color ImageMarginGradientMiddle => CardBack;
		public override Color ImageMarginGradientEnd => CardBack;
		public override Color MenuBorder => CardBorder;
		public override Color MenuItemBorder => ButtonHover;
		public override Color MenuItemSelected => SelectionBack;
		public override Color MenuItemSelectedGradientBegin => SelectionBack;
		public override Color MenuItemSelectedGradientEnd => SelectionBack;
		public override Color MenuItemPressedGradientBegin => CardBack;
		public override Color MenuItemPressedGradientEnd => CardBack;
		public override Color SeparatorDark => CardBorder;
		public override Color SeparatorLight => CardBorder;
	}

	/// <summary>Grid view-model for one <see cref="RdpSessionDto"/> row.</summary>
	public sealed class SessionRow
	{
		public int SessionId { get; init; }

		public string UserName { get; init; } = string.Empty;

		public string SessionName { get; init; } = string.Empty;

		public string State { get; init; } = string.Empty;

		public string ClientName { get; init; } = string.Empty;

		public string ClientAddress { get; init; } = string.Empty;

		public bool IsActive { get; init; }

		public bool IsDisconnected { get; init; }

		public bool IsCurrent { get; init; }

		public string StateBullet => IsActive ? "●" : IsDisconnected ? "◐" : "○";

		public string CurrentText => IsCurrent ? "yes" : string.Empty;

		// --- Stage IP-E historical-context fields (additive). Never overrides live ClientAddress.

		/// <summary>Earliest <c>FirstSeenUtc</c> across matching connection facts; empty when none exist.</summary>
		public string HistoricalFirstSeenUtcText { get; init; } = string.Empty;

		/// <summary>Latest <c>LastSeenUtc</c> across matching connection facts; empty when none exist.</summary>
		public string HistoricalLastSeenUtcText { get; init; } = string.Empty;

		/// <summary>Sum of failed logons across matching connection facts; zero when no facts exist.</summary>
		public long HistoricalFailedLogons { get; init; }

		/// <summary>Sum of successful logons across matching connection facts; zero when no facts exist.</summary>
		public long HistoricalSuccessfulLogons { get; init; }

		/// <summary>Comma-separated deduplicated usernames attempted from this IP across matching facts.</summary>
		public string HistoricalUserNamesAttemptedText { get; init; } = string.Empty;

		// --- Stage 2 per-IP historical fields. Text-typed so blank is distinguishable from "0".

		/// <summary>Per-IP sum of failed logons; blank when the session has no resolved IP.</summary>
		public string HistoricalFailedLogonsByIpText { get; init; } = string.Empty;

		/// <summary>Per-IP sum of successful logons; blank when the session has no resolved IP.</summary>
		public string HistoricalSuccessfulLogonsByIpText { get; init; } = string.Empty;

		/// <summary>Comma-separated deduplicated usernames attempted from this IP; blank when the session has no resolved IP.</summary>
		public string HistoricalUsersAttemptedFromIpText { get; init; } = string.Empty;

		/// <summary>Earliest fact FirstSeenUtc across this IP; blank when the session has no resolved IP.</summary>
		public string HistoricalFirstSeenByIpUtcText { get; init; } = string.Empty;

		/// <summary>Latest fact LastSeenUtc across this IP; blank when the session has no resolved IP.</summary>
		public string HistoricalLastSeenByIpUtcText { get; init; } = string.Empty;

		public static SessionRow From(RdpSessionDto dto)
		{
			ArgumentNullException.ThrowIfNull(dto);
			RdpSessionHistoricalDisplay hist = ConnectionFactRowProjection.FromRdpSession(dto);
			RdpSessionHistoricalByIpDisplay histByIp = ConnectionFactRowProjection.FromRdpSessionByIp(dto);
			return new SessionRow
			{
				SessionId = dto.SessionId,
				UserName = dto.UserName ?? string.Empty,
				SessionName = dto.SessionName ?? string.Empty,
				State = dto.State ?? string.Empty,
				ClientName = dto.ClientName ?? string.Empty,
				ClientAddress = dto.ClientAddress ?? string.Empty,
				IsActive = dto.IsActive,
				IsDisconnected = dto.IsDisconnected,
				IsCurrent = dto.IsCurrent,
				// v1.2.1: convert the UTC-keyed historical timestamps to local time for the grid.
				// The pure projection in Core still emits UTC for clipboard / unit tests; this
				// page is the WinForms rendering boundary so the operator sees host-local times.
				HistoricalFirstSeenUtcText = LocalTimeFormatter.FormatLocal(dto.HistoricalFirstSeenUtc, fallback: string.Empty),
				HistoricalLastSeenUtcText = LocalTimeFormatter.FormatLocal(dto.HistoricalLastSeenUtc, fallback: string.Empty),
				HistoricalFailedLogons = hist.HistoricalFailedLogons,
				HistoricalSuccessfulLogons = hist.HistoricalSuccessfulLogons,
				HistoricalUserNamesAttemptedText = hist.HistoricalUserNamesAttemptedText,
				HistoricalFailedLogonsByIpText = histByIp.HistoricalFailedLogonsByIpText,
				HistoricalSuccessfulLogonsByIpText = histByIp.HistoricalSuccessfulLogonsByIpText,
				HistoricalUsersAttemptedFromIpText = histByIp.HistoricalUsersAttemptedFromIpText,
				HistoricalFirstSeenByIpUtcText = LocalTimeFormatter.FormatLocal(dto.HistoricalFirstSeenByIpUtc, fallback: string.Empty),
				HistoricalLastSeenByIpUtcText = LocalTimeFormatter.FormatLocal(dto.HistoricalLastSeenByIpUtc, fallback: string.Empty),
			};
		}
	}

	/// <summary>Grid view-model for one <see cref="ShadowPolicyValueDto"/> row.</summary>
	public sealed class ShadowValueRow
	{
		public string KeyPath { get; init; } = string.Empty;

		public string ValueName { get; init; } = string.Empty;

		public string CurrentText { get; init; } = string.Empty;

		public string RecommendedText { get; init; } = string.Empty;

		public string Description { get; init; } = string.Empty;
	}
}
