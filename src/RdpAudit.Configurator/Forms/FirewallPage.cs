// File:    src/RdpAudit.Configurator/Forms/FirewallPage.cs
// Module:  RdpAudit.Configurator.Forms
// Purpose: Stage 5 Firewall tab. Surfaces provider status / availability, the auto-block policy
//          knobs from FirewallOptions, blocklist / whitelist / login-rule / active-block grids
//          with search and validated add/remove, an Unblock control for installed rules, and a
//          status strip that timestamps every operator action. All writes flow through IPC; the
//          Configurator never opens the SQLite file directly. Settings persistence reuses the
//          existing SaveSettings IPC round-trip (load options → mutate firewall block → save).
// Extends: System.Windows.Forms.TabPage
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com
// Version: 1.4.1

using System.ComponentModel;
using System.Globalization;
using System.Runtime.Versioning;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using RdpAudit.Configurator.Ipc;
using RdpAudit.Configurator.Services;
using RdpAudit.Core.Config;
using RdpAudit.Core.Firewall;
using RdpAudit.Core.Ipc;
using RdpAudit.Core.Ipc.Contracts;
using RdpAudit.Core.Util;

using static RdpAudit.Configurator.Theming.DarkTheme;

namespace RdpAudit.Configurator.Forms;

/// <summary>Stage 5 Firewall tab: provider status, auto-block policy, lists, active blocks.</summary>
[SupportedOSPlatform("windows")]
public sealed class FirewallPage : TabPage
{
	private readonly IpcClient _ipc;
	private readonly StatusStrip _statusStrip;
	private readonly ToolStripStatusLabel _statusLabel;
	private readonly TabControl _innerTabs;

	// Provider / status section ---------------------------------------------------------------------
	private readonly CheckBox _enableBlockingCheck;
	private readonly ComboBox _providerCombo;
	private readonly Label _providerStatusLabel;
	private readonly Label _windowsStatusLabel;
	private readonly Label _countersLabel;
	private readonly Label _enforcementHealthLabel;
	private readonly Button _refreshStatus;

	// Auto-block policy section ---------------------------------------------------------------------
	private readonly CheckBox _autoBlockBruteForceCheck;
	private readonly NumericUpDown _thresholdInput;
	private readonly NumericUpDown _durationDays;
	private readonly NumericUpDown _durationHours;
	private readonly NumericUpDown _durationMinutes;
	private readonly CheckBox _blockOnBlacklistedLoginCheck;
	private readonly CheckBox _refusePrivateAddressCheck;
	private readonly ComboBox _blockScopeCombo;
	private readonly Button _savePolicyButton;
	private readonly Button _reloadPolicyButton;
	private readonly Button _applyScopeToExistingButton;

	/// <summary>Block scope persisted at the last successful load / save, used to detect when the
	/// operator changed the dropdown so the Save handler can warn that existing RdpAudit rules still
	/// carry the previous shape until reconciled.</summary>
	private FirewallBlockScope _lastSavedBlockScope = FirewallBlockScope.AllInbound;

	// Grids ----------------------------------------------------------------------------------------
	private readonly BindingList<AddressListRow> _blocklistRows = new();
	private readonly BindingList<AddressListRow> _whitelistRows = new();
	private readonly BindingList<LoginRuleRow> _loginRuleRows = new();
	private readonly BindingList<ActiveBlockRow> _activeBlockRows = new();

	private readonly List<AddressListEntryDto> _blocklistAll = new();
	private readonly List<AddressListEntryDto> _whitelistAll = new();
	private readonly List<LoginRuleDto> _loginRulesAll = new();
	private readonly List<ActiveBlockDto> _activeBlocksAll = new();

	private readonly DataGridView _blocklistGrid;
	private readonly DataGridView _whitelistGrid;
	private readonly DataGridView _loginRulesGrid;
	private readonly DataGridView _activeBlocksGrid;

	private readonly TextBox _blocklistFilter;
	private readonly TextBox _whitelistFilter;
	private readonly TextBox _loginRulesFilter;
	private readonly TextBox _activeBlocksFilter;

	private readonly TextBox _blocklistInput;
	private readonly TextBox _whitelistInput;
	private readonly TextBox _loginRuleInput;

	/// <summary>When checked, a failed Remove / Repair surfaces a modal with the full detailed error log
	/// and a Copy Log button, and the two destructive DEBUG-gated cleanup buttons become visible. Unchecked
	/// by default so routine operation shows only a one-line status and the destructive buttons stay hidden.</summary>
	private readonly CheckBox _debugCheck;

	/// <summary>DEBUG-gated destructive button: removes every RdpAudit-owned firewall rule. Hidden unless
	/// the DEBUG checkbox is checked.</summary>
	private readonly Button _debugClearFirewallButton;

	/// <summary>DEBUG-gated destructive button: clears all accumulated RdpAudit application data. Hidden
	/// unless the DEBUG checkbox is checked.</summary>
	private readonly Button _debugClearDataButton;

	private readonly System.Windows.Forms.Timer _timer;

	private RdpAuditOptions _lastLoadedOptions = new();
	private FirewallStatusDto? _lastStatus;

	// --- Firewall provider diagnostics panel (Kaspersky / third-party awareness).
	private readonly Label _providerKindLabel;
	private readonly Label _providerKasperskyLabel;
	private readonly Label _providerLocalRulesLabel;
	private readonly TextBox _providerDiagnosticsText;
	private readonly Button _providerRefreshButton;
	private readonly Button _providerCopyButton;
	private readonly FirewallProviderDiagnosticsProbe _providerProbe = new();
	private FirewallProviderDiagnostics? _lastProviderDiagnostics;
	private readonly ServiceReachabilityProbe _reachability = new();
	private bool _lastRefreshStale;
	private bool _operationInFlight;

	public FirewallPage(IpcClient ipc)
	{
		_ipc = ipc;
		Text = "Firewall";

		_statusStrip = new StatusStrip { SizingGrip = false };
		_statusLabel = new ToolStripStatusLabel("Ready.")
		{
			Spring = true,
			TextAlign = System.Drawing.ContentAlignment.MiddleLeft,
		};
		_statusStrip.Items.Add(_statusLabel);

		// --- Provider / status panel -----------------------------------------------------------
		// AutoSize so the GroupBox always fits its rows and never overlaps the inner tabs below.
		GroupBox providerBox = new()
		{
			Text = "Provider and status",
			Dock = DockStyle.Fill,
			AutoSize = true,
			AutoSizeMode = AutoSizeMode.GrowAndShrink,
			MinimumSize = new Size(0, 130),
		};
		TableLayoutPanel providerLayout = new()
		{
			Dock = DockStyle.Fill,
			ColumnCount = 4,
			RowCount = 5,
			Padding = new Padding(8),
			AutoSize = true,
			AutoSizeMode = AutoSizeMode.GrowAndShrink,
		};
		providerLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 220));
		providerLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
		providerLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 140));
		providerLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));

		_enableBlockingCheck = new CheckBox
		{
			Text = "Enable Windows Firewall blocking (add attackers to firewall)",
			AutoSize = true,
		};

		_providerCombo = new ComboBox
		{
			Dock = DockStyle.Fill,
			DropDownStyle = ComboBoxStyle.DropDownList,
		};
		_providerCombo.Items.Add(new ProviderChoice("None — audit only", FirewallProviderKind.None, true));
		_providerCombo.Items.Add(new ProviderChoice("Windows Firewall (advfirewall)", FirewallProviderKind.Windows, true));
		_providerCombo.Items.Add(new ProviderChoice("MikroTik (Stage 6 — disabled)", FirewallProviderKind.MikroTik, false));
		_providerCombo.Items.Add(new ProviderChoice("Both Windows + MikroTik (Stage 6 — disabled)", FirewallProviderKind.Both, false));
		_providerCombo.SelectedIndex = 1;

		_providerStatusLabel = new Label { Dock = DockStyle.Fill, AutoSize = false, Text = "Provider status: unknown" };
		_windowsStatusLabel = new Label { Dock = DockStyle.Fill, AutoSize = false, Text = "Windows: unknown" };
		_countersLabel = new Label { Dock = DockStyle.Fill, AutoSize = false, Text = "Counters: unknown" };
		_enforcementHealthLabel = new Label
		{
			Dock = DockStyle.Fill,
			AutoSize = false,
			Text = "Enforcement: unknown",
			Font = new Font(Font, FontStyle.Bold),
			// Full-width status band: the colour communicates state at a glance and guarantees the text is
			// always readable (dark text on a light status colour), unlike a bare ForeColor on the dark panel.
			TextAlign = ContentAlignment.MiddleLeft,
			Padding = new Padding(6, 4, 6, 4),
			Margin = new Padding(0, 2, 0, 2),
		};
		ApplyEnforcementBand(EnforcementBand.Neutral, "Enforcement: unknown");

		_refreshStatus = new Button { Text = "Refresh status", AutoSize = true };
		_refreshStatus.Click += async (_, _) => await RefreshAllAsync().ConfigureAwait(true);

		providerLayout.Controls.Add(_enableBlockingCheck, 0, 0);
		providerLayout.SetColumnSpan(_enableBlockingCheck, 3);
		providerLayout.Controls.Add(_refreshStatus, 3, 0);
		providerLayout.Controls.Add(new Label { Text = "Active provider:", AutoSize = true, Anchor = AnchorStyles.Left }, 0, 1);
		providerLayout.Controls.Add(_providerCombo, 1, 1);
		providerLayout.SetColumnSpan(_providerCombo, 3);
		providerLayout.Controls.Add(_providerStatusLabel, 0, 2);
		providerLayout.SetColumnSpan(_providerStatusLabel, 2);
		providerLayout.Controls.Add(_windowsStatusLabel, 2, 2);
		providerLayout.SetColumnSpan(_windowsStatusLabel, 2);
		providerLayout.Controls.Add(_countersLabel, 0, 3);
		providerLayout.SetColumnSpan(_countersLabel, 4);
		providerLayout.Controls.Add(_enforcementHealthLabel, 0, 4);
		providerLayout.SetColumnSpan(_enforcementHealthLabel, 4);
		providerBox.Controls.Add(providerLayout);

		// --- Auto-block policy panel -----------------------------------------------------------
		// Layout strategy:
		//   * GroupBox + inner TableLayoutPanel are both AutoSize so the row count drives the
		//     final height — the inner tabs below can never overlap because the root grid uses
		//     RowStyle AutoSize for the policy row.
		//   * The policy grid has TWO columns (label / value). Anything that needs to fit several
		//     widgets side-by-side (the d / h / m duration spinners) is bundled into a child
		//     FlowLayoutPanel placed in the value column, so the parent grid never has to widen.
		//   * Each NumericUpDown sits next to its compact unit label inside the FlowLayoutPanel.
		//     "Default block duration" stays a single compact group regardless of window width.
		GroupBox policyBox = new()
		{
			Text = "Auto-block policy",
			Dock = DockStyle.Fill,
			AutoSize = true,
			AutoSizeMode = AutoSizeMode.GrowAndShrink,
			MinimumSize = new Size(0, 170),
		};
		TableLayoutPanel policyLayout = new()
		{
			Dock = DockStyle.Fill,
			ColumnCount = 2,
			RowCount = 7,
			Padding = new Padding(8),
			AutoSize = true,
			AutoSizeMode = AutoSizeMode.GrowAndShrink,
		};
		policyLayout.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
		policyLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
		for (int i = 0; i < 7; i++)
		{
			policyLayout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
		}

		_autoBlockBruteForceCheck = new CheckBox
		{
			Text = "Auto-block if source is not whitelisted and failed attempts exceed threshold",
			AutoSize = true,
		};
		_blockOnBlacklistedLoginCheck = new CheckBox
		{
			Text = "Auto-block if attempted login is blacklisted",
			AutoSize = true,
		};
		_refusePrivateAddressCheck = new CheckBox
		{
			Text = "Refuse blocks against loopback / private / multicast addresses",
			AutoSize = true,
		};

		// Block scope dropdown: drives the shape of every new firewall block rule. AllInbound blocks
		// every protocol/port from the source IP; RdpPortOnly restricts the block to TCP on the
		// dynamically resolved RDP listener port (never a hardcoded 3389 / 55554). The internal enum
		// ordinal is what gets persisted; the Display text is operator-facing only.
		_blockScopeCombo = new ComboBox
		{
			DropDownStyle = ComboBoxStyle.DropDownList,
			Width = 320,
			Anchor = AnchorStyles.Left,
			Margin = new Padding(0, 2, 0, 2),
		};
		_blockScopeCombo.Items.Add(new BlockScopeChoice("All inbound traffic from IP", FirewallBlockScope.AllInbound));
		_blockScopeCombo.Items.Add(new BlockScopeChoice("RDP port only", FirewallBlockScope.RdpPortOnly));
		_blockScopeCombo.SelectedIndex = 0;

		_thresholdInput = new NumericUpDown
		{
			Minimum = 1,
			Maximum = 100_000,
			Value = 50,
			Width = 90,
			Anchor = AnchorStyles.Left,
			Margin = new Padding(0, 2, 0, 2),
		};

		_durationDays = MakeCompactDurationInput(0, 365);
		_durationHours = MakeCompactDurationInput(0, 23);
		_durationMinutes = MakeCompactDurationInput(0, 59);

		// Compact FlowLayoutPanel grouping the three spinners with their unit labels so the
		// default-block-duration row stays tight (~260 px) no matter how wide the parent column
		// becomes. Anchor=Left keeps the group left-aligned inside the percent-100 value column.
		FlowLayoutPanel durationRow = new()
		{
			FlowDirection = FlowDirection.LeftToRight,
			AutoSize = true,
			AutoSizeMode = AutoSizeMode.GrowAndShrink,
			WrapContents = false,
			Margin = new Padding(0),
			Anchor = AnchorStyles.Left,
		};
		durationRow.Controls.Add(_durationDays);
		durationRow.Controls.Add(MakeUnitLabel("days"));
		durationRow.Controls.Add(_durationHours);
		durationRow.Controls.Add(MakeUnitLabel("hours"));
		durationRow.Controls.Add(_durationMinutes);
		durationRow.Controls.Add(MakeUnitLabel("min"));

		_savePolicyButton = new Button { Text = "Save policy", AutoSize = true };
		_savePolicyButton.Click += async (_, _) => await SavePolicyAsync().ConfigureAwait(true);

		_reloadPolicyButton = new Button { Text = "Reload from service", AutoSize = true };
		_reloadPolicyButton.Click += async (_, _) => await ReloadPolicyAsync().ConfigureAwait(true);

		// Explicit reconcile path: re-installs every enabled blocklist rule so existing RdpAudit-owned
		// rules adopt the currently-configured block scope and resolved RDP port. This reuses the same
		// RepairAllEnabledBlocklistEnforcement IPC the Blocklist tab exposes, surfaced here next to the
		// scope dropdown so changing scope and reconciling live rules is one obvious two-step action.
		_applyScopeToExistingButton = new Button { Text = "Apply scope to existing rules", AutoSize = true };
		_applyScopeToExistingButton.Click += async (_, _) => await OnApplyScopeToExistingAsync().ConfigureAwait(true);

		// Row 0 — full-width brute-force checkbox.
		policyLayout.Controls.Add(_autoBlockBruteForceCheck, 0, 0);
		policyLayout.SetColumnSpan(_autoBlockBruteForceCheck, 2);

		// Row 1 — threshold (label | value column).
		policyLayout.Controls.Add(MakePolicyLabel("Threshold (failed attempts):"), 0, 1);
		policyLayout.Controls.Add(_thresholdInput, 1, 1);

		// Row 2 — default block duration (label | compact d/h/m group).
		policyLayout.Controls.Add(MakePolicyLabel("Default block duration:"), 0, 2);
		policyLayout.Controls.Add(durationRow, 1, 2);

		// Row 3 — blacklisted-login checkbox (full width).
		policyLayout.Controls.Add(_blockOnBlacklistedLoginCheck, 0, 3);
		policyLayout.SetColumnSpan(_blockOnBlacklistedLoginCheck, 2);

		// Row 4 — refuse-private checkbox (full width).
		policyLayout.Controls.Add(_refusePrivateAddressCheck, 0, 4);
		policyLayout.SetColumnSpan(_refusePrivateAddressCheck, 2);

		// Row 5 — block scope dropdown (label | combo). Saved with the rest of the policy via the
		// Save policy button; changing it then pressing Save persists the new scope and warns that
		// existing rules still carry the old shape until reconciled with Apply scope to existing rules.
		policyLayout.Controls.Add(MakePolicyLabel("Block scope (new rules):"), 0, 5);
		policyLayout.Controls.Add(_blockScopeCombo, 1, 5);

		FlowLayoutPanel policyButtons = new() { FlowDirection = FlowDirection.LeftToRight, AutoSize = true, Margin = new Padding(0, 4, 0, 0) };
		policyButtons.Controls.Add(_savePolicyButton);
		policyButtons.Controls.Add(_reloadPolicyButton);
		policyButtons.Controls.Add(_applyScopeToExistingButton);
		policyLayout.Controls.Add(policyButtons, 0, 6);
		policyLayout.SetColumnSpan(policyButtons, 2);

		policyBox.Controls.Add(policyLayout);

		// --- Inner tab control (lists) ---------------------------------------------------------
		// MinimumSize keeps the grids usable even when the host window shrinks below the original
		// screenshot size; the root TableLayoutPanel still gives the auto-block policy row its
		// AutoSize height before the inner tabs claim the remaining space.
		_innerTabs = new TabControl
		{
			Dock = DockStyle.Fill,
			MinimumSize = new Size(0, 220),
		};

		_blocklistGrid = MakeBlocklistGrid();
		_blocklistGrid.DataSource = _blocklistRows;
		SortableGrid.Enable(_blocklistGrid, _blocklistRows);
		AttachReputationMenu(_blocklistGrid, () => SelectedRow(_blocklistGrid, _blocklistRows)?.Address);
		_blocklistFilter = MakeFilterBox("Filter IP / reason / source…", () => ApplyBlocklistFilter());
		_blocklistInput = MakeInputBox("IP to add to blocklist (e.g. 203.0.113.10)");
		Button blocklistAdd = MakeButton("Add IP", async (_, _) => await OnAddBlocklistAsync().ConfigureAwait(true));
		Button blocklistRemove = MakeButton("Remove selected", async (_, _) => await OnRemoveBlocklistAsync().ConfigureAwait(true));
		Button blocklistRepair = MakeButton("Repair selected", async (_, _) => await OnRepairBlocklistSelectedAsync().ConfigureAwait(true));
		Button blocklistRepairAll = MakeButton("Repair all enabled", async (_, _) => await OnRepairBlocklistAllAsync().ConfigureAwait(true));
		Button blocklistDedupe = MakeButton("Dedupe duplicates", async (_, _) => await OnDedupeBlocklistAsync().ConfigureAwait(true));
		Button blocklistClearAll = MakeButton("Clear all blacklist", async (_, _) => await OnClearAllBlocklistAsync().ConfigureAwait(true));
		_debugClearFirewallButton = MakeButton("DEBUG: Clear RdpAudit firewall rules", async (_, _) => await OnDebugClearFirewallAsync().ConfigureAwait(true));
		_debugClearDataButton = MakeButton("DEBUG: Clear all application data", async (_, _) => await OnDebugClearApplicationDataAsync().ConfigureAwait(true));

		// Discoverability: the destructive DEBUG buttons are always VISIBLE so operators can see they
		// exist, but stay DISABLED until global DEBUG mode is enabled in Settings. The placeholder label
		// explains how to unlock them. The gate is the persisted Diagnostics.DebugMode setting (synced in
		// ReloadPolicyAsync) — not a transient local checkbox — so the same global toggle governs every
		// destructive maintenance action across tabs.
		_debugClearFirewallButton.Enabled = false;
		_debugClearDataButton.Enabled = false;
		_debugCheck = new CheckBox
		{
			Text = "DEBUG (set in Settings)",
			AutoSize = true,
			Checked = false,
			Enabled = false,
			Anchor = AnchorStyles.Left,
			Margin = new Padding(8, 8, 4, 4),
		};
		_innerTabs.TabPages.Add(BuildGridTab("Blocklist", _blocklistGrid, _blocklistFilter, _blocklistInput, blocklistAdd, blocklistRemove, blocklistRepair, blocklistRepairAll, blocklistDedupe, blocklistClearAll, _debugCheck, _debugClearFirewallButton, _debugClearDataButton));

		_whitelistGrid = MakeAddressGrid();
		_whitelistGrid.DataSource = _whitelistRows;
		SortableGrid.Enable(_whitelistGrid, _whitelistRows);
		AttachReputationMenu(_whitelistGrid, () => SelectedRow(_whitelistGrid, _whitelistRows)?.Address);
		_whitelistFilter = MakeFilterBox("Filter IP / note / source…", () => ApplyWhitelistFilter());
		_whitelistInput = MakeInputBox("IP to add to whitelist (e.g. 198.51.100.5)");
		Button whitelistAdd = MakeButton("Add IP", async (_, _) => await OnAddWhitelistAsync().ConfigureAwait(true));
		Button whitelistAddLocal = MakeButton("Add local network IPs", async (_, _) => await OnAddLocalNetworksAsync().ConfigureAwait(true));
		Button whitelistRemove = MakeButton("Remove selected", async (_, _) => await OnRemoveWhitelistAsync().ConfigureAwait(true));
		_innerTabs.TabPages.Add(BuildGridTab("Whitelist", _whitelistGrid, _whitelistFilter, _whitelistInput, whitelistAdd, whitelistAddLocal, whitelistRemove));

		_loginRulesGrid = MakeLoginRulesGrid();
		_loginRulesGrid.DataSource = _loginRuleRows;
		SortableGrid.Enable(_loginRulesGrid, _loginRuleRows);
		_loginRulesFilter = MakeFilterBox("Filter login / note…", () => ApplyLoginRuleFilter());
		_loginRuleInput = MakeInputBox("Login to trip-wire (e.g. administrator)");
		Button loginAdd = MakeButton("Add login", async (_, _) => await OnAddLoginRuleAsync().ConfigureAwait(true));
		Button loginRemove = MakeButton("Remove selected", async (_, _) => await OnRemoveLoginRuleAsync().ConfigureAwait(true));
		Button loginToggle = MakeButton("Toggle enabled", async (_, _) => await OnToggleLoginRuleAsync().ConfigureAwait(true));
		_innerTabs.TabPages.Add(BuildGridTab("Login trip-wires", _loginRulesGrid, _loginRulesFilter, _loginRuleInput, loginAdd, loginRemove, loginToggle));

		_activeBlocksGrid = MakeActiveBlocksGrid();
		_activeBlocksGrid.DataSource = _activeBlockRows;
		SortableGrid.Enable(_activeBlocksGrid, _activeBlockRows);
		AttachReputationMenu(_activeBlocksGrid, () => SelectedRow(_activeBlocksGrid, _activeBlockRows)?.Ip);
		_activeBlocksFilter = MakeFilterBox("Filter IP / reason / provider / status…", () => ApplyActiveBlockFilter());
		Button activeUnblock = MakeButton("Unblock selected", async (_, _) => await OnUnblockActiveAsync().ConfigureAwait(true));
		Button activeVerify = MakeButton("Verify all", async (_, _) => await OnVerifyAllAsync().ConfigureAwait(true));
		Button activeRepair = MakeButton("Repair selected", async (_, _) => await OnRepairActiveAsync().ConfigureAwait(true));
		Button activeRemoveAll = MakeButton("Remove all enforcement", async (_, _) => await OnRemoveAllEnforcementAsync().ConfigureAwait(true));
		_innerTabs.TabPages.Add(BuildGridTab("Active blocks", _activeBlocksGrid, _activeBlocksFilter, null, activeUnblock, activeVerify, activeRepair, activeRemoveAll));

		// --- Firewall provider diagnostics panel -------------------------------------------------
		// Surfaces the detected provider (plain Windows Defender Firewall vs. Kaspersky-detected vs.
		// Kaspersky-managed vs. unclassified third-party) so the operator immediately understands
		// whether direct rule writes are expected to succeed. The Copy diagnostics button puts the
		// full provider / netsh state on the clipboard for inclusion in support tickets.
		GroupBox diagnosticsBox = new()
		{
			Text = "Firewall provider diagnostics",
			Dock = DockStyle.Fill,
			AutoSize = true,
			AutoSizeMode = AutoSizeMode.GrowAndShrink,
			MinimumSize = new Size(0, 140),
		};
		TableLayoutPanel diagnosticsLayout = new()
		{
			Dock = DockStyle.Fill,
			ColumnCount = 4,
			RowCount = 4,
			Padding = new Padding(8),
			AutoSize = true,
			AutoSizeMode = AutoSizeMode.GrowAndShrink,
		};
		diagnosticsLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 220));
		diagnosticsLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
		diagnosticsLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 160));
		diagnosticsLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 160));
		for (int i = 0; i < 4; i++)
		{
			diagnosticsLayout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
		}

		_providerKindLabel = new Label
		{
			Dock = DockStyle.Fill,
			AutoSize = false,
			Text = "Detected provider: probe pending…",
		};
		_providerKasperskyLabel = new Label
		{
			Dock = DockStyle.Fill,
			AutoSize = false,
			Text = "Kaspersky / third-party: probe pending…",
		};
		_providerLocalRulesLabel = new Label
		{
			Dock = DockStyle.Fill,
			AutoSize = false,
			Text = "Direct Windows Firewall rule management: probe pending…",
		};
		_providerDiagnosticsText = new TextBox
		{
			Dock = DockStyle.Fill,
			Multiline = true,
			ReadOnly = true,
			ScrollBars = ScrollBars.Vertical,
			WordWrap = false,
			Height = 110,
			Text = "(diagnostics will appear after refresh)",
		};
		_providerRefreshButton = new Button { Text = "Refresh diagnostics", AutoSize = true };
		_providerRefreshButton.Click += (_, _) => RefreshProviderDiagnostics();

		_providerCopyButton = new Button { Text = "Copy diagnostics", AutoSize = true };
		_providerCopyButton.Click += async (_, _) => await CopyProviderDiagnosticsAsync().ConfigureAwait(true);

		diagnosticsLayout.Controls.Add(_providerKindLabel, 0, 0);
		diagnosticsLayout.SetColumnSpan(_providerKindLabel, 2);
		diagnosticsLayout.Controls.Add(_providerRefreshButton, 2, 0);
		diagnosticsLayout.Controls.Add(_providerCopyButton, 3, 0);
		diagnosticsLayout.Controls.Add(_providerKasperskyLabel, 0, 1);
		diagnosticsLayout.SetColumnSpan(_providerKasperskyLabel, 4);
		diagnosticsLayout.Controls.Add(_providerLocalRulesLabel, 0, 2);
		diagnosticsLayout.SetColumnSpan(_providerLocalRulesLabel, 4);
		diagnosticsLayout.Controls.Add(_providerDiagnosticsText, 0, 3);
		diagnosticsLayout.SetColumnSpan(_providerDiagnosticsText, 4);
		diagnosticsBox.Controls.Add(diagnosticsLayout);

		// Root layout: TableLayoutPanel guarantees the auto-block policy controls are never
		// overlapped by the inner tabs at small client sizes or high DPI. Provider and policy
		// panels auto-size to their content; the inner tabs absorb remaining vertical space; the
		// status strip docks at the bottom. AutoScroll on the root grid is a safety-net for the
		// pathological case where the user shrinks the host window below the combined minimum
		// heights — a vertical scrollbar is far better UX than overlapped controls.
		TableLayoutPanel root = new()
		{
			Dock = DockStyle.Fill,
			ColumnCount = 1,
			RowCount = 5,
			AutoScroll = true,
		};
		root.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
		root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
		root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
		root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
		root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
		root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
		root.Controls.Add(providerBox, 0, 0);
		root.Controls.Add(diagnosticsBox, 0, 1);
		root.Controls.Add(policyBox, 0, 2);
		root.Controls.Add(_innerTabs, 0, 3);
		root.Controls.Add(_statusStrip, 0, 4);

		Controls.Add(root);

		_timer = new System.Windows.Forms.Timer { Interval = 5_000 };
		_timer.Tick += async (_, _) => await RefreshAllAsync().ConfigureAwait(true);
		HandleCreated += async (_, _) =>
		{
			_timer.Start();
			await ReloadPolicyAsync().ConfigureAwait(true);
			await RefreshAllAsync().ConfigureAwait(true);
			RefreshProviderDiagnostics();
		};
	}

	private void RefreshProviderDiagnostics()
	{
		try
		{
			FirewallProviderDiagnostics diag = _providerProbe.Probe();
			_lastProviderDiagnostics = diag;

			_providerKindLabel.Text = string.Format(CultureInfo.InvariantCulture,
				"Detected provider: {0} ({1}). Configured RDP port: {2}.",
				diag.ProviderName,
				diag.ProviderKind,
				diag.ConfiguredRdpPort?.ToString(CultureInfo.InvariantCulture) ?? "unknown");

			_providerKasperskyLabel.Text = diag.ProviderKind switch
			{
				FirewallProviderDetectedKind.KasperskyManagedWindowsFirewall =>
					"Kaspersky is likely managing Windows Firewall — direct netsh writes may be blocked. "
					+ "Add allow / block rules through Kaspersky Security Center policy instead.",
				FirewallProviderDetectedKind.KasperskyDetected =>
					"Kaspersky product detected. Direct Windows Firewall writes may still succeed; "
					+ "watch the Copy diagnostics output for netsh failures.",
				FirewallProviderDetectedKind.ThirdPartyFirewallUnknown =>
					"Third-party security stack detected — RdpAudit cannot guarantee direct Windows Firewall writes.",
				FirewallProviderDetectedKind.WindowsDefenderFirewall =>
					"Plain Windows Defender Firewall — RdpAudit can manage rules directly via netsh.",
				_ => "Provider context could not be classified.",
			};

			string localRulesText = diag.LocalRuleManagementAllowed switch
			{
				true => "yes — RdpAudit will attempt direct rule writes.",
				false => "no — direct rule writes are expected to fail / be overridden.",
				_ => "unknown — see netsh diagnostics below.",
			};
			_providerLocalRulesLabel.Text = "Direct Windows Firewall rule management: " + localRulesText;

			_providerDiagnosticsText.Text = diag.BuildDiagnosticsText();
			SetStatus("Firewall provider diagnostics refreshed.");
		}
		catch (Exception ex)
		{
			SetStatus("Firewall provider diagnostics FAILED: " + ex.GetType().Name + " — " + ex.Message);
		}
	}

	private async Task CopyProviderDiagnosticsAsync()
	{
		try
		{
			string clientPart = _lastProviderDiagnostics?.BuildDiagnosticsText() ?? "(no client-side diagnostics captured yet)";

			string servicePart;
			try
			{
				FirewallDiagnosticsDto? dto = await _ipc
					.SendAsync<FirewallDiagnosticsDto>(IpcCommand.GetFirewallDiagnostics)
					.ConfigureAwait(true);
				servicePart = dto is null
					? "(service-side firewall diagnostics unreachable)"
					: dto.ReportText;
			}
			catch (Exception ex)
			{
				servicePart = "(service-side firewall diagnostics failed: " + ex.GetType().Name + " — " + ex.Message + ")";
			}

			string payload = "=== Client-side (Configurator) firewall provider probe ===" + Environment.NewLine
				+ clientPart + Environment.NewLine + Environment.NewLine
				+ "=== Service-side firewall enforcement diagnostics ===" + Environment.NewLine
				+ servicePart;

			Clipboard.SetText(payload);
			SetStatus("Firewall diagnostics (client + service) copied to clipboard.");
		}
		catch (Exception ex)
		{
			SetStatus("Copy diagnostics FAILED: " + ex.GetType().Name + " — " + ex.Message);
		}
	}

	// ---------------------------------------------------------------------------------------------
	// Status / refresh
	// ---------------------------------------------------------------------------------------------

	private async Task RefreshAllAsync()
	{
		try
		{
			Task<IpcCallResult<FirewallStatusDto>> statusTask = _ipc.SendDetailedAsync<FirewallStatusDto>(IpcCommand.GetFirewallStatus);
			Task<IpcCallResult<List<AddressListEntryDto>>> blockTask = _ipc.SendDetailedAsync<List<AddressListEntryDto>>(IpcCommand.ListBlocklist);
			Task<IpcCallResult<List<AddressListEntryDto>>> whiteTask = _ipc.SendDetailedAsync<List<AddressListEntryDto>>(IpcCommand.ListWhitelist);
			Task<IpcCallResult<List<LoginRuleDto>>> rulesTask = _ipc.SendDetailedAsync<List<LoginRuleDto>>(IpcCommand.ListLoginRules);
			Task<IpcCallResult<List<ActiveBlockDto>>> activeTask = _ipc.SendDetailedAsync<List<ActiveBlockDto>>(IpcCommand.ListActiveBlocksDetailed);

			await Task.WhenAll(statusTask, blockTask, whiteTask, rulesTask, activeTask).ConfigureAwait(true);

			IpcCallResult<FirewallStatusDto> statusCall = await statusTask.ConfigureAwait(true);
			IpcCallResult<List<AddressListEntryDto>> blockCall = await blockTask.ConfigureAwait(true);
			IpcCallResult<List<AddressListEntryDto>> whiteCall = await whiteTask.ConfigureAwait(true);
			IpcCallResult<List<LoginRuleDto>> rulesCall = await rulesTask.ConfigureAwait(true);
			IpcCallResult<List<ActiveBlockDto>> activeCall = await activeTask.ConfigureAwait(true);

			// Treat a connect-failure on the cheap status call as "service genuinely gone": only then do
			// we blank the grids. A timeout / transient failure keeps the last-known rows so a long Repair
			// in flight (or a momentary busy service) never wipes the operator's view to empty.
			bool serviceGone = !statusCall.ServiceLikelyReachable;

			if (statusCall.IsSuccess)
			{
				_lastStatus = statusCall.Value;
				_lastRefreshStale = false;
			}
			else if (serviceGone)
			{
				_lastStatus = null;
				_lastRefreshStale = false;
			}
			else
			{
				_lastRefreshStale = true;
			}
			RenderProviderStatus(_lastStatus, statusCall);

			// Load active blocks first: the BlockList enforcement column is derived from the verified
			// ActiveBlock reconciliation, so it must be populated before ApplyBlocklistFilter runs.
			if (activeCall.IsSuccess && activeCall.Value is not null)
			{
				_activeBlocksAll.Clear();
				_activeBlocksAll.AddRange(activeCall.Value);
			}
			else if (serviceGone)
			{
				_activeBlocksAll.Clear();
			}
			ApplyActiveBlockFilter();

			if (blockCall.IsSuccess && blockCall.Value is not null)
			{
				_blocklistAll.Clear();
				_blocklistAll.AddRange(blockCall.Value);
			}
			else if (serviceGone)
			{
				_blocklistAll.Clear();
			}
			ApplyBlocklistFilter();

			if (whiteCall.IsSuccess && whiteCall.Value is not null)
			{
				_whitelistAll.Clear();
				_whitelistAll.AddRange(whiteCall.Value);
			}
			else if (serviceGone)
			{
				_whitelistAll.Clear();
			}
			ApplyWhitelistFilter();

			if (rulesCall.IsSuccess && rulesCall.Value is not null)
			{
				_loginRulesAll.Clear();
				_loginRulesAll.AddRange(rulesCall.Value);
			}
			else if (serviceGone)
			{
				_loginRulesAll.Clear();
			}
			ApplyLoginRuleFilter();

			if (statusCall.IsSuccess)
			{
				SetStatus(string.Format(CultureInfo.InvariantCulture,
					"Refresh OK. blocklist={0} whitelist={1} logins={2} activeBlocks={3}",
					_blocklistAll.Count, _whitelistAll.Count, _loginRulesAll.Count, _activeBlocksAll.Count));
			}
			else if (serviceGone)
			{
				SetStatus("Refresh FAILED: " + statusCall.Headline());
			}
			else
			{
				SetStatus("Refresh incomplete (showing last-known data): " + statusCall.Headline() + "  |  " + statusCall.TraceLine);
			}
		}
		catch (Exception ex)
		{
			SetStatus("Refresh FAILED: " + ex.GetType().Name + " — " + ex.Message);
		}
	}

	private void RenderProviderStatus(FirewallStatusDto? dto, IpcCallResult<FirewallStatusDto>? statusCall = null)
	{
		if (dto is null)
		{
			// Distinguish a genuinely-down service from a transient timeout: a timeout keeps the last-known
			// grids and says so, instead of declaring the service unreachable and blanking the view.
			bool transient = statusCall is { } call && call.ServiceLikelyReachable && !call.IsSuccess;
			string headline = statusCall?.Headline() ?? "service unreachable";
			_providerStatusLabel.Text = transient
				? "Provider status: " + headline + " — showing last-known data"
				: "Provider status: " + headline;
			_windowsStatusLabel.Text = "Windows: unknown";
			_countersLabel.Text = transient ? "Counters: stale (service busy)" : "Counters: unavailable";
			ApplyEnforcementBand(
				EnforcementBand.Neutral,
				transient
					? "Enforcement: stale (service reachable but did not respond in time — retry)"
					: "Enforcement: unknown (service unreachable)");
			return;
		}

		if (_lastRefreshStale)
		{
			_lastRefreshStale = false;
		}

		string configured = dto.ConfiguredProvider.ToString();
		_providerStatusLabel.Text = string.Format(CultureInfo.InvariantCulture,
			"Configured provider: {0} | message: {1}",
			configured, dto.Message ?? "n/a");

		string windowsState;
		if (dto.ConfiguredProvider == FirewallProviderKind.None)
		{
			windowsState = "Disabled (audit only)";
		}
		else if (dto.WindowsAvailable)
		{
			windowsState = "Enabled (Windows Firewall reachable)";
		}
		else if (!OperatingSystem.IsWindows())
		{
			windowsState = "Unavailable (non-Windows host)";
		}
		else
		{
			windowsState = "Unavailable — verify netsh / advfirewall or possible third-party replacement";
		}
		_windowsStatusLabel.Text = "Windows: " + windowsState;

		_countersLabel.Text = string.Format(CultureInfo.InvariantCulture,
			"Active blocks: {0}   |   Whitelist rows: {1}   |   Blacklist rows: {2}",
			dto.ActiveBlockCount, dto.WhitelistCount, dto.BlacklistCount);

		RenderEnforcementHealth(dto);
	}

	/// <summary>Surfaces the live-reconciled enforcement health. Never shows green unless real firewall
	/// rules were verified: enabled blocklist rows with zero verified enforcement render red and tell the
	/// operator to repair/verify, so a "configured but unenforced" state can never look healthy.</summary>
	private void RenderEnforcementHealth(FirewallStatusDto dto)
	{
		string detail = string.Format(CultureInfo.InvariantCulture,
			"  (enabled blocks: {0}, RdpAudit rules: {1}, verified: {2})",
			dto.EnabledBlocklistRows, dto.RdpAuditFirewallRuleCount, dto.VerifiedEnforcedCount);

		switch (dto.EnforcementHealth)
		{
			case FirewallEnforcementHealth.Healthy:
				ApplyEnforcementBand(EnforcementBand.Healthy, "Enforcement: HEALTHY" + detail);
				break;
			case FirewallEnforcementHealth.Idle:
				ApplyEnforcementBand(EnforcementBand.Neutral, "Enforcement: idle — no enabled blocklist rows" + detail);
				break;
			case FirewallEnforcementHealth.MissingRule:
				ApplyEnforcementBand(
					EnforcementBand.Error,
					"Enforcement: MISSING RULE — blocks intended but no firewall rule was verified. "
					+ "Open the Active blocks tab and use 'Repair selected', then 'Verify all'."
					+ detail);
				break;
			case FirewallEnforcementHealth.Failed:
				ApplyEnforcementBand(
					EnforcementBand.Error,
					"Enforcement: INCOMPLETE — some blocks unenforced. "
					+ "Open the Active blocks tab and use 'Repair selected' on the gaps, then 'Verify all'."
					+ detail);
				break;
			default:
				ApplyEnforcementBand(EnforcementBand.Neutral, "Enforcement: unknown (could not verify)" + detail);
				break;
		}
	}

	/// <summary>
	/// Visual state for the full-width enforcement status band rendered under the provider panel.
	/// The band's background colour communicates state at a glance and guarantees the text stays
	/// readable regardless of the dark theme: a dark foreground is painted on a light status colour.
	/// </summary>
	private enum EnforcementBand
	{
		/// <summary>Neutral / indeterminate state (idle, unknown, stale) — yellow band.</summary>
		Neutral,

		/// <summary>All enabled blocklist rows are verifiably enforced — green band.</summary>
		Healthy,

		/// <summary>Enforcement is broken (missing rule / incomplete) — red band.</summary>
		Error,
	}

	/// <summary>
	/// Paints the enforcement status band: sets the label text plus a full-width coloured background
	/// (yellow neutral / green healthy / red error) with a dark, high-contrast foreground so the text
	/// is always legible on the dark panel. The label is docked-fill and column-spans the provider
	/// layout, so the BackColor fills the row width.
	/// </summary>
	private void ApplyEnforcementBand(EnforcementBand band, string text)
	{
		_enforcementHealthLabel.Text = text;
		_enforcementHealthLabel.BackColor = band switch
		{
			EnforcementBand.Healthy => StatusSuccess,
			EnforcementBand.Error => StatusDanger,
			_ => StatusWarning,
		};
		// Dark foreground guarantees contrast against the light status colours of the band.
		_enforcementHealthLabel.ForeColor = PageBack;
	}

	// ---------------------------------------------------------------------------------------------
	// Policy load / save
	// ---------------------------------------------------------------------------------------------

	private async Task ReloadPolicyAsync()
	{
		try
		{
			JsonNode? settings = await _ipc.SendAsync<JsonNode>(IpcCommand.GetSettings).ConfigureAwait(true);
			if (settings is null)
			{
				SetStatus("Policy reload FAILED: service unreachable.");
				return;
			}

			RdpAuditOptions? opts = JsonSerializer.Deserialize<RdpAuditOptions>(
				settings.ToJsonString(), JsonOptions.Default);
			if (opts is null)
			{
				SetStatus("Policy reload FAILED: settings JSON did not bind to RdpAuditOptions.");
				return;
			}

			_lastLoadedOptions = opts;
			FirewallOptions cfg = opts.Firewall;
			_enableBlockingCheck.Checked = cfg.Provider != FirewallProviderKind.None;
			SelectProviderCombo(cfg.Provider);
			_autoBlockBruteForceCheck.Checked = cfg.AutoBlockBruteForce;
			_blockOnBlacklistedLoginCheck.Checked = cfg.BlockOnBlacklistedLogin;
			_refusePrivateAddressCheck.Checked = cfg.RefusePrivateAddressBlock;
			_thresholdInput.Value = ClampToRange(cfg.AutoBlockThreshold, (int)_thresholdInput.Minimum, (int)_thresholdInput.Maximum);
			SetDurationFromMinutes(cfg.DefaultBlockDurationMinutes);
			SelectBlockScopeCombo(cfg.BlockScope);
			_lastSavedBlockScope = cfg.BlockScope;
			ApplyGlobalDebugGate(opts.Diagnostics.DebugMode);
			SetStatus("Policy reloaded from service.");
		}
		catch (Exception ex)
		{
			SetStatus("Policy reload FAILED: " + ex.GetType().Name + " — " + ex.Message);
		}
	}

	/// <summary>Reflects the persisted global <c>Diagnostics.DebugMode</c> setting onto the Firewall
	/// tab: the destructive DEBUG-gated buttons (and the detail-log behaviour keyed off
	/// <see cref="_debugCheck"/>) are enabled only when global DEBUG mode is on. The buttons stay
	/// visible regardless so they are discoverable; only their enabled state tracks the gate.</summary>
	private void ApplyGlobalDebugGate(bool debugMode)
	{
		_debugCheck.Checked = debugMode;
		_debugClearFirewallButton.Enabled = debugMode;
		_debugClearDataButton.Enabled = debugMode;
		_debugCheck.Text = debugMode
			? "DEBUG MODE ENABLED (Settings)"
			: "DEBUG off — enable in Settings to unlock the buttons below";
	}

	private async Task SavePolicyAsync()
	{
		try
		{
			JsonNode? settings = await _ipc.SendAsync<JsonNode>(IpcCommand.GetSettings).ConfigureAwait(true);
			if (settings is null)
			{
				SetStatus("Save FAILED: service unreachable.");
				return;
			}

			// Mutate the firewall sub-tree in place so other unrelated sections survive verbatim.
			JsonObject root = settings.AsObject();
			if (!root.TryGetPropertyValue("Firewall", out JsonNode? firewallNode) || firewallNode is null)
			{
				firewallNode = new JsonObject();
				root["Firewall"] = firewallNode;
			}

			JsonObject firewall = firewallNode.AsObject();
			ProviderChoice choice = (ProviderChoice)_providerCombo.SelectedItem!;
			FirewallProviderKind effective = _enableBlockingCheck.Checked ? choice.Kind : FirewallProviderKind.None;
			firewall["Provider"] = (int)effective;
			firewall["AutoBlockBruteForce"] = _autoBlockBruteForceCheck.Checked;
			firewall["AutoBlockThreshold"] = (int)_thresholdInput.Value;
			firewall["BlockOnBlacklistedLogin"] = _blockOnBlacklistedLoginCheck.Checked;
			firewall["RefusePrivateAddressBlock"] = _refusePrivateAddressCheck.Checked;
			firewall["DefaultBlockDurationMinutes"] = ComputeDurationMinutes();

			BlockScopeChoice scopeChoice = (BlockScopeChoice)_blockScopeCombo.SelectedItem!;
			FirewallBlockScope previousScope = _lastSavedBlockScope;
			bool scopeChanged = scopeChoice.Scope != previousScope;
			firewall["BlockScope"] = (int)scopeChoice.Scope;

			JsonObject wrapped = new()
			{
				[RdpAuditOptions.SectionName] = settings.DeepClone(),
			};

			object? saveResp = await _ipc.SendAsync<object>(IpcCommand.SaveSettings, wrapped.ToJsonString()).ConfigureAwait(true);
			if (saveResp is null)
			{
				SetStatus("Save FAILED: service unreachable.");
				return;
			}

			_lastSavedBlockScope = scopeChoice.Scope;
			if (scopeChanged)
			{
				// Do not let the UI claim the new scope while existing RdpAudit rules still carry the old
				// shape. The dropdown only governs NEW rules; existing rules keep their shape until the
				// operator reconciles them. Make that explicit instead of silently diverging.
				SetStatus(string.Format(
					CultureInfo.InvariantCulture,
					"Save OK — block scope changed {0} -> {1}. NEW rules use the new scope; existing "
						+ "RdpAudit rules still use the previous shape until you press "
						+ "'Apply scope to existing rules'.",
					previousScope,
					scopeChoice.Scope));
			}
			else
			{
				SetStatus("Save OK. Service will hot-reload from disk.");
			}

			await RefreshAllAsync().ConfigureAwait(true);
		}
		catch (Exception ex)
		{
			SetStatus("Save FAILED: " + ex.GetType().Name + " — " + ex.Message);
		}
	}

	private void SelectProviderCombo(FirewallProviderKind kind)
	{
		for (int i = 0; i < _providerCombo.Items.Count; i++)
		{
			if (_providerCombo.Items[i] is ProviderChoice c && c.Kind == kind && c.Enabled)
			{
				_providerCombo.SelectedIndex = i;
				return;
			}
		}

		// Fall through: select first enabled entry.
		for (int i = 0; i < _providerCombo.Items.Count; i++)
		{
			if (_providerCombo.Items[i] is ProviderChoice c && c.Enabled)
			{
				_providerCombo.SelectedIndex = i;
				return;
			}
		}
	}

	private void SelectBlockScopeCombo(FirewallBlockScope scope)
	{
		for (int i = 0; i < _blockScopeCombo.Items.Count; i++)
		{
			if (_blockScopeCombo.Items[i] is BlockScopeChoice c && c.Scope == scope)
			{
				_blockScopeCombo.SelectedIndex = i;
				return;
			}
		}

		// Unknown / future ordinal: fall back to the first entry so the combo always has a selection.
		if (_blockScopeCombo.Items.Count > 0)
		{
			_blockScopeCombo.SelectedIndex = 0;
		}
	}

	/// <summary>Reconciles existing RdpAudit-managed rules to the currently-configured block scope by
	/// re-installing every enabled blocklist rule through the service. Reuses the
	/// <see cref="IpcCommand.RepairAllEnabledBlocklistEnforcement"/> round-trip the Blocklist tab uses;
	/// each re-install reads the live <c>Firewall.BlockScope</c> and resolved RDP port, so after this
	/// completes the live rule shapes match the dropdown. Save the policy first if the scope was just
	/// changed, otherwise the service still enforces the previously-persisted scope.</summary>
	private async Task OnApplyScopeToExistingAsync()
	{
		BlockScopeChoice scopeChoice = (BlockScopeChoice)_blockScopeCombo.SelectedItem!;
		if (scopeChoice.Scope != _lastSavedBlockScope)
		{
			SetStatus("Apply aborted: the dropdown differs from the saved scope. Press 'Save policy' "
				+ "first so the service enforces the new scope, then apply it to existing rules.");
			return;
		}

		try
		{
			SetStatus(string.Format(
				CultureInfo.InvariantCulture,
				"Reconciling existing RdpAudit rules to scope {0}…",
				scopeChoice.Scope));

			IpcCallResult<ReconciliationReportDto> result =
				await _ipc.SendDetailedAsync<ReconciliationReportDto>(IpcCommand.RepairAllEnabledBlocklistEnforcement).ConfigureAwait(true);

			if (!result.IsSuccess || result.Value is null)
			{
				SetStatus("Apply scope to existing rules FAILED: " + (result.Error ?? "service unreachable."));
				return;
			}

			ReconciliationReportDto report = result.Value;
			SetStatus(string.Format(
				CultureInfo.InvariantCulture,
				"Applied scope {0} to existing rules: {1} verified, {2} block(s) reconciled.",
				scopeChoice.Scope,
				report.VerifiedCount,
				report.Blocks.Count));

			await RefreshAllAsync().ConfigureAwait(true);
		}
		catch (Exception ex)
		{
			SetStatus("Apply scope to existing rules FAILED: " + ex.GetType().Name + " — " + ex.Message);
		}
	}

	private void SetDurationFromMinutes(int totalMinutes)
	{
		if (totalMinutes < 0)
		{
			totalMinutes = 0;
		}

		int days = totalMinutes / (24 * 60);
		int rem = totalMinutes % (24 * 60);
		int hours = rem / 60;
		int minutes = rem % 60;

		_durationDays.Value = Math.Min(days, (int)_durationDays.Maximum);
		_durationHours.Value = Math.Min(hours, (int)_durationHours.Maximum);
		_durationMinutes.Value = Math.Min(minutes, (int)_durationMinutes.Maximum);
	}

	private int ComputeDurationMinutes() =>
		(int)_durationDays.Value * 24 * 60
		+ (int)_durationHours.Value * 60
		+ (int)_durationMinutes.Value;

	// ---------------------------------------------------------------------------------------------
	// Blocklist actions
	// ---------------------------------------------------------------------------------------------

	private async Task OnAddBlocklistAsync()
	{
		string raw = _blocklistInput.Text;
		if (!AddressListFilter.IsValidIp(raw))
		{
			SetStatus("Add to blocklist aborted: input is not a valid IPv4 / IPv6 address.");
			return;
		}

		string ip = AddressListFilter.NormalizeIp(raw);
		AddressListMutationRequest payload = new()
		{
			Address = ip,
			Note = "Configurator Firewall tab manual add",
			DurationMinutes = ComputeDurationMinutes(),
		};

		IpcCallResult<JsonElement?> result = await SendMutationDetailedAsync(IpcCommand.AddToBlocklist, payload)
			.ConfigureAwait(true);
		bool ok = result.IsSuccess;
		SetStatus(string.Format(CultureInfo.InvariantCulture,
			"AddToBlocklist {0}: {1}", ip, ok ? "OK" : result.Headline()));
		if (ok)
		{
			_blocklistInput.Text = string.Empty;
			await RefreshAllAsync().ConfigureAwait(true);
		}
	}

	private async Task OnRemoveBlocklistAsync()
	{
		AddressListRow? row = SelectedRow(_blocklistGrid, _blocklistRows);
		if (row is null)
		{
			SetStatus("Remove blocklist entry aborted: no row selected.");
			return;
		}

		string ip = row.Address;
		string prompt = string.Format(CultureInfo.InvariantCulture,
			"Remove {0} from the blocklist? The row will be soft-disabled in the database.", ip);
		if (!Confirm(prompt, "Confirm remove blocklist entry"))
		{
			SetStatus("Remove blocklist entry cancelled.");
			return;
		}

		if (row.Id <= 0)
		{
			SetStatus("Remove blocklist entry aborted: selected row has no stable Id. Refresh and retry.");
			return;
		}

		// Carry the stable row Id so the service removes exactly the selected row even when several rows
		// share an address (including an already-disabled duplicate); Address remains for logging.
		AddressListMutationRequest payload = new() { Id = row.Id, Address = ip };
		IpcCallResult<BlocklistRemovalResultDto> call =
			await _ipc.SendDetailedAsync<BlocklistRemovalResultDto>(IpcCommand.RemoveFromBlocklist, payload).ConfigureAwait(true);

		if (!call.IsSuccess || call.Value is null)
		{
			string err = string.IsNullOrWhiteSpace(call.Error) ? "service reported no detail." : call.Error!;
			SetStatus(string.Format(CultureInfo.InvariantCulture,
				"RemoveFromBlocklist {0} (Id={1}) FAILED: {2}", ip, row.Id, err));
			MaybeShowDebugModal("Remove BlockList row", row.Id, ip, err, null);
			return;
		}

		BlocklistRemovalResultDto dto = call.Value;
		if (dto.Status == IpcResultStatus.Success)
		{
			SetStatus(dto.Message);
			await RefreshAllAsync().ConfigureAwait(true);
		}
		else
		{
			SetStatus(string.Format(CultureInfo.InvariantCulture,
				"RemoveFromBlocklist {0} (Id={1}) FAILED: {2}",
				ip, row.Id, string.IsNullOrWhiteSpace(dto.Error) ? dto.Message : dto.Error));
			MaybeShowDebugModal("Remove BlockList row", row.Id, ip, dto.Error ?? dto.Message, dto.DebugLog);
			// A non-success Remove may still have mutated the DB; refresh so the grid reflects reality.
			await RefreshAllAsync().ConfigureAwait(true);
		}
	}

	/// <summary>Runs the DB-maintenance dedupe action that collapses duplicate BlockList rows per IP,
	/// then surfaces the audit summary and refreshes the grid.</summary>
	private async Task OnDedupeBlocklistAsync()
	{
		if (!Confirm(
			"Collapse duplicate BlockList rows? For each IP with more than one row, a canonical row is "
			+ "kept (preferring an enabled row) and the duplicates are soft-disabled with an audit note. "
			+ "Nothing is hard-deleted.",
			"Confirm dedupe BlockList"))
		{
			SetStatus("Dedupe BlockList cancelled.");
			return;
		}

		IpcCallResult<BlocklistDedupeResultDto> call =
			await _ipc.SendDetailedAsync<BlocklistDedupeResultDto>(IpcCommand.DedupeBlocklistEntries).ConfigureAwait(true);
		if (!call.IsSuccess || call.Value is null)
		{
			string err = string.IsNullOrWhiteSpace(call.Error) ? "service reported no detail." : call.Error!;
			SetStatus("Dedupe BlockList FAILED: " + err);
			return;
		}

		BlocklistDedupeResultDto dto = call.Value;
		SetStatus(dto.Message);
		if (_debugCheck.Checked && dto.Audit.Count > 0)
		{
			ShowDetailLogModal("Dedupe BlockList audit", string.Join(Environment.NewLine, dto.Audit));
		}

		await RefreshAllAsync().ConfigureAwait(true);
	}

	/// <summary>Req A — full blacklist cleanup. Soft-disables every enabled BlockList row (audit-preserving,
	/// never hard-deleted), then synchronizes enforcement for the cleared IPs: their active blocks are marked
	/// Removed and the RdpAudit-created firewall rules backing them (plus safe orphans) are removed. Unrelated
	/// administrator rules are never touched. Confirms first, then does the atomic 1.3.1-style refresh.</summary>
	private async Task OnClearAllBlocklistAsync()
	{
		const string prompt =
			"Clear the ENTIRE blacklist?\r\n\r\nEvery enabled BlockList entry will be disabled (rows are kept "
			+ "for audit, never hard-deleted). For each IP left without an enabled entry, its active block is "
			+ "marked Removed and the RdpAudit-created firewall rule that backed it is removed. Unrelated "
			+ "administrator firewall rules are never touched.";
		if (!Confirm(prompt, "Confirm clear all blacklist"))
		{
			SetStatus("Clear all blacklist cancelled.");
			return;
		}

		if (!BeginBusy())
		{
			return;
		}

		try
		{
			IpcCallResult<BlocklistClearResultDto> call =
				await _ipc.SendDetailedAsync<BlocklistClearResultDto>(IpcCommand.ClearAllBlocklist).ConfigureAwait(true);
			if (call.IsSuccess && call.Value is { } result)
			{
				SetStatus(result.Message);
				if (_debugCheck.Checked && !string.IsNullOrEmpty(result.DebugLog))
				{
					ShowDetailLogModal("Clear all blacklist — detailed log", result.DebugLog!);
				}
			}
			else
			{
				await ReportCallFailureAsync(call, "Clear all blacklist").ConfigureAwait(true);
			}

			await RefreshAllAsync().ConfigureAwait(true);
		}
		catch (Exception ex)
		{
			SetStatus(string.Format(CultureInfo.InvariantCulture,
				"Clear all blacklist: FAILED — {0}", ex.GetType().Name));
		}
		finally
		{
			EndBusy();
		}
	}

	/// <summary>Req B — DEBUG-gated full firewall cleanup. Removes every RdpAudit-owned firewall rule
	/// (matched by the RdpAudit group / name convention) and synchronizes active-block rows to Removed.
	/// Never touches unrelated administrator rules and never modifies the BlockList table. Confirms first,
	/// then does the atomic refresh.</summary>
	private async Task OnDebugClearFirewallAsync()
	{
		const string prompt =
			"DEBUG: Remove ALL RdpAudit firewall rules?\r\n\r\nEvery firewall rule created by RdpAudit (matched "
			+ "by the RdpAudit rule group / name) is removed and every active block is marked Removed. The "
			+ "BlockList table is not modified. Unrelated administrator rules are never touched. This is a "
			+ "destructive maintenance action.";
		if (!Confirm(prompt, "Confirm DEBUG firewall cleanup"))
		{
			SetStatus("DEBUG firewall cleanup cancelled.");
			return;
		}

		if (!BeginBusy())
		{
			return;
		}

		try
		{
			IpcCallResult<FirewallClearResultDto> call =
				await _ipc.SendDetailedAsync<FirewallClearResultDto>(IpcCommand.ClearAllFirewallRules).ConfigureAwait(true);
			if (call.IsSuccess && call.Value is { } result)
			{
				SetStatus(result.Message);
				if (_debugCheck.Checked && !string.IsNullOrEmpty(result.DebugLog))
				{
					ShowDetailLogModal("DEBUG firewall cleanup — detailed log", result.DebugLog!);
				}
			}
			else
			{
				await ReportCallFailureAsync(call, "DEBUG firewall cleanup").ConfigureAwait(true);
			}

			await RefreshAllAsync().ConfigureAwait(true);
		}
		catch (Exception ex)
		{
			SetStatus(string.Format(CultureInfo.InvariantCulture,
				"DEBUG firewall cleanup: FAILED — {0}", ex.GetType().Name));
		}
		finally
		{
			EndBusy();
		}
	}

	/// <summary>Req C — DEBUG-gated full application-data cleanup. Requires the operator to type the exact
	/// confirmation phrase; the same phrase is re-validated server-side before any data is touched. The
	/// service transactionally clears the accumulated operational tables (preserving schema, migrations,
	/// configuration and event-log bookmarks) and reclaims SQLite space, then the UI refreshes to the empty
	/// healthy state without reporting the service as unreachable.</summary>
	private async Task OnDebugClearApplicationDataAsync()
	{
		const string phrase = "CLEAR ALL RDP AUDIT DATA";
		const string prompt =
			"DEBUG: Clear ALL application data?\r\n\r\nThis permanently deletes the accumulated RdpAudit data "
			+ "(raw events, auth-attempt and connection facts, active blocks, blocklist / whitelist entries, "
			+ "alerts, sessions, addresses, correlations, attack stats and abuse report history). Schema, "
			+ "migrations, configuration and event-log read positions are preserved, so the service keeps "
			+ "running. This cannot be undone.";
		if (!Confirm(prompt, "Confirm DEBUG application-data cleanup"))
		{
			SetStatus("DEBUG application-data cleanup cancelled.");
			return;
		}

		string typed = PromptForConfirmationPhrase(phrase);
		if (!string.Equals(typed, phrase, StringComparison.Ordinal))
		{
			SetStatus("DEBUG application-data cleanup cancelled: confirmation phrase did not match.");
			return;
		}

		if (!BeginBusy())
		{
			return;
		}

		try
		{
			IpcCallResult<AppDataPurgeResultDto> call =
				await _ipc.SendDetailedAsync<AppDataPurgeResultDto>(IpcCommand.ClearAllApplicationData, phrase).ConfigureAwait(true);
			if (call.IsSuccess && call.Value is { } result)
			{
				SetStatus(result.Message);
				if (_debugCheck.Checked && !string.IsNullOrEmpty(result.DebugLog))
				{
					ShowDetailLogModal("DEBUG application-data cleanup — detailed log", result.DebugLog!);
				}
			}
			else
			{
				await ReportCallFailureAsync(call, "DEBUG application-data cleanup").ConfigureAwait(true);
			}

			await RefreshAllAsync().ConfigureAwait(true);
		}
		catch (Exception ex)
		{
			SetStatus(string.Format(CultureInfo.InvariantCulture,
				"DEBUG application-data cleanup: FAILED — {0}", ex.GetType().Name));
		}
		finally
		{
			EndBusy();
		}
	}

	/// <summary>Modal prompt that requires the operator to type the exact destructive-confirmation phrase.
	/// Returns the trimmed entered text (empty on cancel) so the caller can compare it ordinally.</summary>
	private string PromptForConfirmationPhrase(string requiredPhrase)
	{
		using Form dialog = new()
		{
			Text = "Type the confirmation phrase",
			StartPosition = FormStartPosition.CenterParent,
			FormBorderStyle = FormBorderStyle.FixedDialog,
			Size = new Size(480, 180),
			MinimizeBox = false,
			MaximizeBox = false,
			ShowInTaskbar = false,
		};

		Label label = new()
		{
			Text = "To proceed, type the following phrase exactly:\r\n\r\n" + requiredPhrase,
			Dock = DockStyle.Top,
			AutoSize = false,
			Height = 64,
			Padding = new Padding(12, 12, 12, 0),
		};
		TextBox input = new()
		{
			Dock = DockStyle.Top,
			Margin = new Padding(12),
			Width = 440,
		};
		FlowLayoutPanel buttons = new()
		{
			Dock = DockStyle.Bottom,
			FlowDirection = FlowDirection.RightToLeft,
			Height = 44,
			Padding = new Padding(8),
		};
		Button ok = new() { Text = "Confirm", DialogResult = DialogResult.OK, AutoSize = true };
		Button cancel = new() { Text = "Cancel", DialogResult = DialogResult.Cancel, AutoSize = true };
		buttons.Controls.Add(ok);
		buttons.Controls.Add(cancel);
		dialog.AcceptButton = ok;
		dialog.CancelButton = cancel;
		dialog.Controls.Add(input);
		dialog.Controls.Add(label);
		dialog.Controls.Add(buttons);

		return dialog.ShowDialog(this) == DialogResult.OK ? input.Text.Trim() : string.Empty;
	}

	/// <summary>When DEBUG is checked, shows a modal with the detailed error log and a Copy Log button.
	/// When unchecked, does nothing (the one-line status already carries the summary).</summary>
	private void MaybeShowDebugModal(string operation, long selectedId, string ip, string? error, string? debugLog)
	{
		if (!_debugCheck.Checked)
		{
			return;
		}

		System.Text.StringBuilder sb = new();
		sb.Append("Operation: ").Append(operation).Append(Environment.NewLine);
		sb.Append("Selected Id: ").Append(selectedId.ToString(CultureInfo.InvariantCulture)).Append(Environment.NewLine);
		sb.Append("IP: ").Append(ip).Append(Environment.NewLine);
		sb.Append("UTC: ").Append(DateTime.UtcNow.ToString("O", CultureInfo.InvariantCulture)).Append(Environment.NewLine);
		if (!string.IsNullOrEmpty(error))
		{
			sb.Append("Error: ").Append(error).Append(Environment.NewLine);
		}

		if (!string.IsNullOrEmpty(debugLog))
		{
			sb.Append(Environment.NewLine).Append("Detailed log:").Append(Environment.NewLine).Append(debugLog);
		}

		ShowDetailLogModal(operation + " — detailed error log", sb.ToString());
	}

	/// <summary>When DEBUG is checked, assembles a detailed error log from a reconciled-block result
	/// (backend command, stdout/stderr, exit code, durationMs, rule name/handle, scanner backend,
	/// verifier reason) and shows it in a modal with a Copy Log button.</summary>
	private void MaybeShowReconciledDebugModal(string operation, long selectedId, string ip, ReconciledBlockDto r)
	{
		if (!_debugCheck.Checked)
		{
			return;
		}

		System.Text.StringBuilder sb = new();
		void Line(string k, object? v) => sb.Append(k).Append(": ").Append(v?.ToString() ?? "(null)").Append(Environment.NewLine);
		Line("Operation", operation);
		Line("Selected Id", selectedId);
		Line("IP", ip);
		Line("UTC", DateTime.UtcNow.ToString("O", CultureInfo.InvariantCulture));
		Line("Status", r.Status);
		Line("Confidence", r.Confidence);
		Line("Detail", r.Detail);
		Line("Recommended action", r.RecommendedAction);
		Line("Backend command", r.BackendCommand);
		Line("Backend stdout", r.BackendStdoutPreview);
		Line("Backend stderr", r.BackendStderrPreview);
		Line("Exit code", r.ExitCode);
		Line("Timed out", r.TimedOut);
		Line("Duration (ms)", r.DurationMs);
		Line("Rule name", r.RuleName);
		Line("Rule handle", r.RuleHandle);
		Line("Scanner backend", r.ScannerBackend);
		Line("Verifier reason", r.VerifierReason);
		Line("Last error", r.LastError);
		Line("Last attempt UTC", r.LastAttemptUtc);

		ShowDetailLogModal(operation + " — detailed error log", sb.ToString());
	}

	/// <summary>Shows a modal dialog with a read-only multi-line log and a Copy Log button.</summary>
	private void ShowDetailLogModal(string title, string body)
	{
		using Form dialog = new()
		{
			Text = title,
			StartPosition = FormStartPosition.CenterParent,
			Size = new Size(720, 460),
			MinimizeBox = false,
			MaximizeBox = true,
			ShowInTaskbar = false,
		};

		TextBox text = new()
		{
			Multiline = true,
			ReadOnly = true,
			ScrollBars = ScrollBars.Both,
			WordWrap = false,
			Dock = DockStyle.Fill,
			Text = body,
			Font = new System.Drawing.Font(System.Drawing.FontFamily.GenericMonospace, 9f),
		};

		FlowLayoutPanel bar = new() { Dock = DockStyle.Bottom, FlowDirection = FlowDirection.RightToLeft, AutoSize = true, Height = 40 };
		Button close = new() { Text = "Close", DialogResult = DialogResult.OK, AutoSize = true };
		Button copy = new() { Text = "Copy Log", AutoSize = true };
		copy.Click += (_, _) =>
		{
			try
			{
				Clipboard.SetText(string.IsNullOrEmpty(body) ? " " : body);
			}
			catch (Exception)
			{
				// Clipboard can transiently fail (locked by another app); ignore.
			}
		};
		bar.Controls.Add(close);
		bar.Controls.Add(copy);

		dialog.Controls.Add(text);
		dialog.Controls.Add(bar);
		dialog.AcceptButton = close;
		dialog.ShowDialog(this);
	}

	/// <summary>
	/// Repairs enforcement for the selected BlockList row: the service ensures a matching ActiveBlock
	/// exists, (re-)installs the backend rule, and re-reads the firewall to prove enforcement. The
	/// post-repair status is surfaced verbatim so the operator never sees a silent success.
	/// </summary>
	private async Task OnRepairBlocklistSelectedAsync()
	{
		AddressListRow? row = SelectedRow(_blocklistGrid, _blocklistRows);
		if (row is null)
		{
			SetStatus("Repair blocklist enforcement aborted: no row selected.");
			return;
		}

		if (row.Id <= 0)
		{
			SetStatus("Repair blocklist enforcement aborted: selected row has no stable Id.");
			return;
		}

		if (!BeginBusy())
		{
			return;
		}

		try
		{
			string action = string.Format(CultureInfo.InvariantCulture, "Repair blocklist {0} (Id={1})", row.Address, row.Id);
			IpcCallResult<ReconciledBlockDto> call =
				await _ipc.SendDetailedAsync<ReconciledBlockDto>(IpcCommand.RepairBlocklistEnforcement, row.Id).ConfigureAwait(true);
			if (call.IsSuccess && call.Value is { } result)
			{
				string detail = string.IsNullOrWhiteSpace(result.Detail) ? string.Empty : " — " + result.Detail;
				SetStatus(string.Format(CultureInfo.InvariantCulture,
					"Repair blocklist {0}: {1} / {2}{3}",
					row.Address,
					EnforcementReconciler.DescribeStatus(result.Status),
					EnforcementReconciler.DescribeConfidence(result.Confidence),
					detail));

				// On a non-Active outcome with DEBUG on, surface the full backend detail the DTO carries.
				if (result.Status != EnforcementStatus.Active)
				{
					MaybeShowReconciledDebugModal("Repair BlockList row", row.Id, row.Address, result);
				}
			}
			else
			{
				await ReportCallFailureAsync(call, action).ConfigureAwait(true);
				MaybeShowDebugModal("Repair BlockList row", row.Id, row.Address, call.Error, null);
			}

			await RefreshAllAsync().ConfigureAwait(true);
		}
		catch (Exception ex)
		{
			SetStatus(string.Format(CultureInfo.InvariantCulture,
				"Repair blocklist {0}: FAILED — {1}", row.Address, ex.GetType().Name));
		}
		finally
		{
			EndBusy();
		}
	}

	/// <summary>
	/// Repairs enforcement for every enabled BlockList row in one pass and reports an attempted /
	/// verified / unenforced summary. Warns explicitly when zero rows were verified despite rows
	/// existing, so the operator is never misled into believing enforcement succeeded.
	/// </summary>
	private async Task OnRepairBlocklistAllAsync()
	{
		if (!BeginBusy())
		{
			return;
		}

		try
		{
			IpcCallResult<ReconciliationReportDto> call =
				await _ipc.SendDetailedAsync<ReconciliationReportDto>(IpcCommand.RepairAllEnabledBlocklistEnforcement).ConfigureAwait(true);
			if (!call.IsSuccess || call.Value is not { } report)
			{
				await ReportCallFailureAsync(call, "Repair all enabled blocklist").ConfigureAwait(true);
			}
			else if (report.Blocks.Count == 0)
			{
				SetStatus("Repair all enabled blocklist: no enabled IP rows to repair.");
			}
			else
			{
				string severity = report.VerifiedCount == 0 ? "WARNING: " : string.Empty;
				SetStatus(string.Format(CultureInfo.InvariantCulture,
					"{0}Repair all enabled blocklist: attempted {1}, {2} verified enforced, {3} still unenforced.",
					severity, report.Blocks.Count, report.VerifiedCount, report.UnenforcedCount));
			}

			await RefreshAllAsync().ConfigureAwait(true);
		}
		catch (Exception ex)
		{
			SetStatus(string.Format(CultureInfo.InvariantCulture,
				"Repair all enabled blocklist: FAILED — {0}", ex.GetType().Name));
		}
		finally
		{
			EndBusy();
		}
	}

	// ---------------------------------------------------------------------------------------------
	// Whitelist actions
	// ---------------------------------------------------------------------------------------------

	private async Task OnAddWhitelistAsync()
	{
		string raw = _whitelistInput.Text;
		if (!AddressListFilter.IsValidIpOrCidr(raw))
		{
			SetStatus("Add to whitelist aborted: input is not a valid IPv4 / IPv6 address or CIDR range (e.g. 192.168.0.0/16 or fd00::/8).");
			return;
		}

		string ip = AddressListFilter.NormalizeIpOrCidr(raw);
		AddressListMutationRequest payload = new()
		{
			Address = ip,
			Note = "Configurator Firewall tab manual add",
		};

		IpcCallResult<JsonElement?> wlResult = await SendMutationDetailedAsync(IpcCommand.AddToWhitelist, payload)
			.ConfigureAwait(true);
		bool wlOk = wlResult.IsSuccess;
		if (!wlOk)
		{
			SetStatus(string.Format(CultureInfo.InvariantCulture, "AddToWhitelist {0} failed: {1}", ip, wlResult.Headline()));
			return;
		}

		bool unblockOk = true;
		if (wlOk)
		{
			DialogResult choice = MessageBox.Show(
				string.Format(CultureInfo.InvariantCulture,
					"Also unblock any active Windows Firewall rule that targets {0}?", ip),
				"Whitelist follow-up",
				MessageBoxButtons.YesNo,
				MessageBoxIcon.Question,
				MessageBoxDefaultButton.Button1);
			if (choice == DialogResult.Yes)
			{
				try
				{
					bool? legacy = await _ipc.SendAsync<bool?>(IpcCommand.UnblockAddress, ip).ConfigureAwait(true);
					unblockOk = legacy == true;
				}
				catch
				{
					unblockOk = false;
				}
			}
		}

		SetStatus(string.Format(CultureInfo.InvariantCulture,
			"AddToWhitelist {0}: whitelist={1}, unblock={2}",
			ip, wlOk ? "OK" : "FAIL", unblockOk ? "OK" : "FAIL"));
		if (wlOk)
		{
			_whitelistInput.Text = string.Empty;
			await RefreshAllAsync().ConfigureAwait(true);
		}
	}

	/// <summary>
	/// Canonical RFC 1918 (IPv4) and RFC 4193 / RFC 4291 (IPv6) private / local-network CIDR ranges.
	/// Adding these to the whitelist exempts all LAN and unique-local traffic from auto-blocking.
	/// The auto-block worker matches these via <see cref="RdpAudit.Core.Util.CidrRange"/>, so both
	/// IPv4 and IPv6 source addresses falling inside any range are skipped (family-aware prefix match).
	/// </summary>
	private static readonly string[] LocalNetworkRanges =
	[
		"10.0.0.0/8",       // RFC 1918 private class A
		"172.16.0.0/12",    // RFC 1918 private class B
		"192.168.0.0/16",   // RFC 1918 private class C
		"fc00::/7",         // RFC 4193 unique-local (covers fc00::/8 and fd00::/8)
		"fd00::/8",         // RFC 4193 locally-assigned unique-local (explicit, common subset)
	];

	/// <summary>
	/// Adds the standard local-network CIDR ranges to the whitelist in one pass: every LAN and
	/// unique-local source address becomes exempt from auto-blocking. Each range is normalised and
	/// sent through the AddToWhitelist IPC; the grid is refreshed once at the end. Verified IPv6-safe:
	/// fc00::/7 and fd00::/8 round-trip through CidrRange and match real IPv6 source addresses.
	/// </summary>
	private async Task OnAddLocalNetworksAsync()
	{
		int added = 0;
		int failed = 0;

		// Collect per-range failure reasons so the operator sees exactly WHY a range was rejected instead
		// of an opaque "N failed" count (the original defect this fix addresses).
		List<string> failures = new();
		foreach (string range in LocalNetworkRanges)
		{
			if (!AddressListFilter.IsValidIpOrCidr(range))
			{
				failed++;
				failures.Add(string.Format(CultureInfo.InvariantCulture,
					"{0}: rejected client-side (not a valid IP/CIDR).", range));
				continue;
			}

			string normalized = AddressListFilter.NormalizeIpOrCidr(range);
			AddressListMutationRequest payload = new()
			{
				Address = normalized,
				Note = "Configurator local-network range",
			};

			IpcCallResult<JsonElement?> result = await SendMutationDetailedAsync(IpcCommand.AddToWhitelist, payload)
				.ConfigureAwait(true);
			if (result.IsSuccess)
			{
				added++;
			}
			else
			{
				failed++;
				failures.Add(string.Format(CultureInfo.InvariantCulture, "{0}: {1}", normalized, result.Headline()));
			}
		}

		string summary = string.Format(CultureInfo.InvariantCulture,
			"Add local network IPs: {0} added, {1} failed (of {2} ranges).",
			added, failed, LocalNetworkRanges.Length);
		if (failures.Count > 0)
		{
			// Append the first concrete reason to the one-line status; the full set is shown in a dialog so
			// the operator gets the actionable detail without it being truncated in the status bar.
			summary += " Reason: " + failures[0];
			MessageBox.Show(
				string.Join(Environment.NewLine, failures),
				"Add local network IPs",
				MessageBoxButtons.OK,
				MessageBoxIcon.Warning);
		}

		SetStatus(summary);

		if (added > 0)
		{
			await RefreshAllAsync().ConfigureAwait(true);
		}
	}

	private async Task OnRemoveWhitelistAsync()
	{
		AddressListRow? row = SelectedRow(_whitelistGrid, _whitelistRows);
		if (row is null)
		{
			SetStatus("Remove whitelist entry aborted: no row selected.");
			return;
		}

		string ip = row.Address;
		string prompt = string.Format(CultureInfo.InvariantCulture,
			"Remove {0} from the whitelist? The address will no longer be exempt from auto-blocking, "
			+ "but no firewall block is installed by this action.", ip);
		if (!Confirm(prompt, "Confirm remove whitelist entry"))
		{
			SetStatus("Remove whitelist entry cancelled.");
			return;
		}

		AddressListMutationRequest payload = new() { Address = ip };
		IpcCallResult<JsonElement?> result = await SendMutationDetailedAsync(IpcCommand.RemoveFromWhitelist, payload)
			.ConfigureAwait(true);
		bool ok = result.IsSuccess;
		SetStatus(string.Format(CultureInfo.InvariantCulture,
			"RemoveFromWhitelist {0}: {1}", ip, ok ? "OK" : result.Headline()));
		if (ok)
		{
			await RefreshAllAsync().ConfigureAwait(true);
		}
	}

	// ---------------------------------------------------------------------------------------------
	// Login rule actions
	// ---------------------------------------------------------------------------------------------

	private async Task OnAddLoginRuleAsync()
	{
		string raw = _loginRuleInput.Text;
		if (string.IsNullOrWhiteSpace(raw))
		{
			SetStatus("Add login rule aborted: input is empty.");
			return;
		}

		string login;
		try
		{
			login = AddressListFilter.NormalizeLogin(raw);
		}
		catch (FormatException ex)
		{
			SetStatus("Add login rule aborted: " + ex.Message);
			return;
		}

		LoginRuleMutationRequest payload = new()
		{
			Login = login,
			Note = "Configurator Firewall tab manual add",
			Enabled = true,
		};
		IpcCallResult<JsonElement?> result = await SendMutationDetailedAsync(IpcCommand.AddLoginRule, payload)
			.ConfigureAwait(true);
		bool ok = result.IsSuccess;
		SetStatus(string.Format(CultureInfo.InvariantCulture,
			"AddLoginRule '{0}': {1}", login, ok ? "OK" : result.Headline()));
		if (ok)
		{
			_loginRuleInput.Text = string.Empty;
			await RefreshAllAsync().ConfigureAwait(true);
		}
	}

	private async Task OnRemoveLoginRuleAsync()
	{
		LoginRuleRow? row = SelectedRow(_loginRulesGrid, _loginRuleRows);
		if (row is null)
		{
			SetStatus("Remove login rule aborted: no row selected.");
			return;
		}

		string prompt = string.Format(CultureInfo.InvariantCulture,
			"Remove login rule '{0}'?\r\n\r\nFuture attempts using this login will no longer be "
			+ "treated as trip-wires. Local Windows accounts are NOT affected by this action.",
			row.Login);
		if (!Confirm(prompt, "Confirm remove login rule"))
		{
			SetStatus("Remove login rule cancelled.");
			return;
		}

		LoginRuleMutationRequest payload = new() { Id = row.Id, Login = row.Login };
		IpcCallResult<JsonElement?> result = await SendMutationDetailedAsync(IpcCommand.RemoveLoginRule, payload)
			.ConfigureAwait(true);
		bool ok = result.IsSuccess;
		SetStatus(string.Format(CultureInfo.InvariantCulture,
			"RemoveLoginRule '{0}': {1}", row.Login, ok ? "OK" : result.Headline()));
		if (ok)
		{
			await RefreshAllAsync().ConfigureAwait(true);
		}
	}

	private async Task OnToggleLoginRuleAsync()
	{
		LoginRuleRow? row = SelectedRow(_loginRulesGrid, _loginRuleRows);
		if (row is null)
		{
			SetStatus("Toggle login rule aborted: no row selected.");
			return;
		}

		LoginRuleMutationRequest payload = new()
		{
			Id = row.Id,
			Login = row.Login,
			Enabled = !row.Enabled,
		};
		IpcCallResult<JsonElement?> result = await SendMutationDetailedAsync(IpcCommand.SetLoginRuleEnabled, payload)
			.ConfigureAwait(true);
		bool ok = result.IsSuccess;
		SetStatus(string.Format(CultureInfo.InvariantCulture,
			"SetLoginRuleEnabled '{0}' → {1}: {2}",
			row.Login, payload.Enabled, ok ? "OK" : result.Headline()));
		if (ok)
		{
			await RefreshAllAsync().ConfigureAwait(true);
		}
	}

	// ---------------------------------------------------------------------------------------------
	// Active block actions
	// ---------------------------------------------------------------------------------------------

	private async Task OnUnblockActiveAsync()
	{
		ActiveBlockRow? row = SelectedRow(_activeBlocksGrid, _activeBlockRows);
		if (row is null)
		{
			SetStatus("Unblock aborted: no row selected.");
			return;
		}

		string prompt = string.Format(CultureInfo.InvariantCulture,
			"Unblock {0} via provider {1}?\r\n\r\nThis removes the installed firewall rule and "
			+ "soft-disables any matching blocklist entries.",
			row.Ip, row.Provider);
		if (!Confirm(prompt, "Confirm unblock"))
		{
			SetStatus("Unblock cancelled.");
			return;
		}

		if (!BeginBusy())
		{
			return;
		}

		try
		{
			IpcCallResult<JsonElement?> call =
				await _ipc.SendDetailedAsync<JsonElement?>(IpcCommand.UnblockActiveBlock, row.Id).ConfigureAwait(true);
			if (call.IsSuccess)
			{
				SetStatus(string.Format(CultureInfo.InvariantCulture, "Unblock {0}: done.", row.Ip));
			}
			else
			{
				await ReportCallFailureAsync(call, string.Format(CultureInfo.InvariantCulture, "Unblock {0}", row.Ip)).ConfigureAwait(true);
			}

			await RefreshAllAsync().ConfigureAwait(true);
		}
		catch (Exception ex)
		{
			SetStatus(string.Format(CultureInfo.InvariantCulture,
				"Unblock {0}: FAILED — {1}", row.Ip, ex.GetType().Name));
		}
		finally
		{
			EndBusy();
		}
	}

	// ---------------------------------------------------------------------------------------------
	// Reconciliation actions: verify all, repair selected, remove all enforcement
	// ---------------------------------------------------------------------------------------------

	/// <summary>Forces a live reconciliation pass on the service, then refreshes the grid so the
	/// Active Blocks view reflects verified enforcement rather than database intent alone.</summary>
	private async Task OnVerifyAllAsync()
	{
		if (!BeginBusy())
		{
			return;
		}

		try
		{
			IpcCallResult<ReconciliationReportDto> call =
				await _ipc.SendDetailedAsync<ReconciliationReportDto>(IpcCommand.ReconcileEnforcement).ConfigureAwait(true);
			if (call.IsSuccess && call.Value is { } report)
			{
				SetStatus(string.Format(CultureInfo.InvariantCulture,
					"Verify all: {0} block(s), {1} verified, {2} unenforced, {3} orphan(s).",
					report.Blocks.Count, report.VerifiedCount, report.UnenforcedCount, report.Orphans.Count));
			}
			else
			{
				await ReportCallFailureAsync(call, "Verify all").ConfigureAwait(true);
			}

			await RefreshAllAsync().ConfigureAwait(true);
		}
		catch (Exception ex)
		{
			SetStatus(string.Format(CultureInfo.InvariantCulture,
				"Verify all: FAILED — {0}", ex.GetType().Name));
		}
		finally
		{
			EndBusy();
		}
	}

	/// <summary>Re-installs the backend enforcement object for the selected block via its owning
	/// provider, then refreshes the grid so the operator sees the post-repair status.</summary>
	private async Task OnRepairActiveAsync()
	{
		ActiveBlockRow? row = SelectedRow(_activeBlocksGrid, _activeBlockRows);
		if (row is null)
		{
			SetStatus("Repair aborted: no row selected.");
			return;
		}

		if (!BeginBusy())
		{
			return;
		}

		try
		{
			IpcCallResult<ReconciledBlockDto> call =
				await _ipc.SendDetailedAsync<ReconciledBlockDto>(IpcCommand.RepairActiveBlock, row.Id).ConfigureAwait(true);
			if (call.IsSuccess && call.Value is { } result)
			{
				SetStatus(string.Format(CultureInfo.InvariantCulture, "Repair {0}: {1} / {2}.",
					row.Ip,
					EnforcementReconciler.DescribeStatus(result.Status),
					EnforcementReconciler.DescribeConfidence(result.Confidence)));
			}
			else
			{
				await ReportCallFailureAsync(call, string.Format(CultureInfo.InvariantCulture, "Repair {0}", row.Ip)).ConfigureAwait(true);
			}

			await RefreshAllAsync().ConfigureAwait(true);
		}
		catch (Exception ex)
		{
			SetStatus(string.Format(CultureInfo.InvariantCulture,
				"Repair {0}: FAILED — {1}", row.Ip, ex.GetType().Name));
		}
		finally
		{
			EndBusy();
		}
	}

	/// <summary>Emergency cleanup: removes every RdpAudit-owned enforcement object (firewall rules,
	/// routes, IPsec policies) and marks the matching database rows Removed. Confirms first because
	/// this unblocks every IP RdpAudit is currently enforcing.</summary>
	private async Task OnRemoveAllEnforcementAsync()
	{
		const string prompt =
			"Remove ALL RdpAudit enforcement?\r\n\r\nThis deletes every RdpAudit-owned firewall rule, "
			+ "blackhole route and IPsec policy, and marks the matching active blocks as removed. "
			+ "Unrelated administrator rules are never touched.";
		if (!Confirm(prompt, "Confirm remove all enforcement"))
		{
			SetStatus("Remove all enforcement cancelled.");
			return;
		}

		if (!BeginBusy())
		{
			return;
		}

		try
		{
			IpcCallResult<EnforcementCleanupResultDto> call =
				await _ipc.SendDetailedAsync<EnforcementCleanupResultDto>(IpcCommand.RemoveAllEnforcement).ConfigureAwait(true);
			if (call.IsSuccess && call.Value is { } result)
			{
				SetStatus(string.Format(CultureInfo.InvariantCulture,
					"Remove all enforcement: {0} rule(s), {1} route(s), {2} IPsec object(s) removed, "
					+ "{3} row(s) marked removed, {4} failure(s).",
					result.FirewallRulesRemoved, result.RoutesRemoved, result.IpsecObjectsRemoved,
					result.ActiveBlockRowsMarkedRemoved, result.Failures));
			}
			else
			{
				await ReportCallFailureAsync(call, "Remove all enforcement").ConfigureAwait(true);
			}

			await RefreshAllAsync().ConfigureAwait(true);
		}
		catch (Exception ex)
		{
			SetStatus(string.Format(CultureInfo.InvariantCulture,
				"Remove all enforcement: FAILED — {0}", ex.GetType().Name));
		}
		finally
		{
			EndBusy();
		}
	}

	// ---------------------------------------------------------------------------------------------
	// Filtering helpers
	// ---------------------------------------------------------------------------------------------

	private void ApplyBlocklistFilter()
	{
		// Cross-reference verified ActiveBlock enforcement (built from live reconciliation, never DB
		// rows alone) so each BlockList row shows its real enforcement state, not just intent.
		Dictionary<string, EnforcementStatus> byIp = BuildEnforcementByIp();

		AddressListFilter filter = new() { Query = _blocklistFilter.Text };
		_blocklistRows.RaiseListChangedEvents = false;
		_blocklistRows.Clear();
		foreach (AddressListEntryDto dto in _blocklistAll)
		{
			if (filter.Matches(dto.Address, dto.Note, dto.Source))
			{
				AddressListRow row = AddressListRow.From(dto);
				row.EnforcementText = DescribeBlocklistEnforcement(dto.Address, byIp);
				_blocklistRows.Add(row);
			}
		}

		_blocklistRows.RaiseListChangedEvents = true;
		_blocklistRows.ResetBindings();
		WarnIfDuplicateBlocklistRows();
	}

	/// <summary>Surfaces a warning when more than one BlockList row exists for the same IP (e.g. one
	/// Manual + one AutoBlock, or a disabled duplicate). The phrase "duplicate blocklist rows" is part
	/// of the contract so the operator can recognise the condition and run the DB-maintenance dedupe.</summary>
	private void WarnIfDuplicateBlocklistRows()
	{
		Dictionary<string, int> counts = new(StringComparer.OrdinalIgnoreCase);
		foreach (AddressListEntryDto dto in _blocklistAll)
		{
			if (string.IsNullOrEmpty(dto.Address))
			{
				continue;
			}

			counts[dto.Address] = counts.TryGetValue(dto.Address, out int n) ? n + 1 : 1;
		}

		int dupIps = counts.Count(kv => kv.Value > 1);
		if (dupIps > 0)
		{
			SetStatus(string.Format(System.Globalization.CultureInfo.CurrentCulture,
				"Warning: {0} IP(s) have duplicate blocklist rows. Use Tools → Dedupe BlockList to collapse them.",
				dupIps));
		}
	}

	/// <summary>
	/// Builds a map from IP to the strongest reconciled enforcement status seen across all
	/// ActiveBlock rows for that IP. "Strongest" prefers a verified Active rule over Pending /
	/// Failed so a row with at least one verified backend rule reports Active.
	/// </summary>
	private Dictionary<string, EnforcementStatus> BuildEnforcementByIp()
	{
		Dictionary<string, EnforcementStatus> byIp = new(StringComparer.OrdinalIgnoreCase);
		foreach (ActiveBlockDto ab in _activeBlocksAll)
		{
			if (string.IsNullOrEmpty(ab.Ip))
			{
				continue;
			}

			if (!byIp.TryGetValue(ab.Ip, out EnforcementStatus current)
				|| EnforcementRank(ab.EnforcementStatus) > EnforcementRank(current))
			{
				byIp[ab.Ip] = ab.EnforcementStatus;
			}
		}

		return byIp;
	}

	private static int EnforcementRank(EnforcementStatus status) => status switch
	{
		EnforcementStatus.Active => 5,
		EnforcementStatus.ParameterMismatch => 4,
		EnforcementStatus.Desired => 3,
		EnforcementStatus.MissingRule => 2,
		EnforcementStatus.Failed => 2,
		EnforcementStatus.Expired => 1,
		_ => 0,
	};

	/// <summary>Maps a BlockList row to its operator-facing enforcement label.</summary>
	private static string DescribeBlocklistEnforcement(string? ip, Dictionary<string, EnforcementStatus> byIp)
	{
		if (string.IsNullOrEmpty(ip) || !byIp.TryGetValue(ip, out EnforcementStatus status))
		{
			// No ActiveBlock at all: the intent exists but nothing is enforcing it.
			return "Not enforced";
		}

		return status switch
		{
			EnforcementStatus.Active => "Active",
			EnforcementStatus.Desired => "Pending",
			EnforcementStatus.MissingRule => "Not enforced",
			EnforcementStatus.ParameterMismatch => "Failed",
			EnforcementStatus.Failed => "Failed",
			EnforcementStatus.Expired => "Expired",
			EnforcementStatus.ProviderUnavailable => "Backend unavailable",
			EnforcementStatus.EffectiveUnknown => "Backend unavailable",
			_ => "Not enforced",
		};
	}

	private void ApplyWhitelistFilter()
	{
		AddressListFilter filter = new() { Query = _whitelistFilter.Text };
		_whitelistRows.RaiseListChangedEvents = false;
		_whitelistRows.Clear();
		foreach (AddressListEntryDto dto in _whitelistAll)
		{
			if (filter.Matches(dto.Address, dto.Note, dto.Source))
			{
				_whitelistRows.Add(AddressListRow.From(dto));
			}
		}

		_whitelistRows.RaiseListChangedEvents = true;
		_whitelistRows.ResetBindings();
	}

	private void ApplyLoginRuleFilter()
	{
		AddressListFilter filter = new() { Query = _loginRulesFilter.Text };
		_loginRuleRows.RaiseListChangedEvents = false;
		_loginRuleRows.Clear();
		foreach (LoginRuleDto dto in _loginRulesAll)
		{
			if (filter.Matches(dto.Login, dto.DisplayLogin, dto.Note, dto.Enabled ? "enabled" : "disabled"))
			{
				_loginRuleRows.Add(LoginRuleRow.From(dto));
			}
		}

		_loginRuleRows.RaiseListChangedEvents = true;
		_loginRuleRows.ResetBindings();
	}

	private void ApplyActiveBlockFilter()
	{
		AddressListFilter filter = new() { Query = _activeBlocksFilter.Text };
		_activeBlockRows.RaiseListChangedEvents = false;
		_activeBlockRows.Clear();
		foreach (ActiveBlockDto dto in _activeBlocksAll)
		{
			if (filter.Matches(
				dto.Ip,
				dto.Reason,
				dto.Provider.ToString(),
				dto.Status.ToString(),
				dto.LastError,
				dto.RuleHandle,
				EnforcementReconciler.DescribeStatus(dto.EnforcementStatus),
				EnforcementReconciler.DescribeConfidence(dto.EnforcementConfidence),
				dto.RecommendedAction))
			{
				_activeBlockRows.Add(ActiveBlockRow.From(dto));
			}
		}

		_activeBlockRows.RaiseListChangedEvents = true;
		_activeBlockRows.ResetBindings();
	}

	// ---------------------------------------------------------------------------------------------
	// IPC plumbing helpers
	// ---------------------------------------------------------------------------------------------

	/// <summary>
	/// Sends a mutation IPC command and returns the full structured outcome so the caller can surface
	/// the real failure reason. Previously this method collapsed every failure (controlled service
	/// error, timeout, transport fault) to <c>false</c> and swallowed the message, which is why the
	/// "Add local network IPs" action reported "N failed" with no clue as to WHY. The detailed result
	/// carries the service-supplied error text and outcome category; the bool convenience wrapper below
	/// keeps existing call-sites simple while the new callers render <see cref="IpcCallResult{T}.Headline"/>.
	/// </summary>
	private Task<IpcCallResult<JsonElement?>> SendMutationDetailedAsync(IpcCommand command, object payload)
		=> _ipc.SendDetailedAsync<JsonElement?>(command, payload);

	// ---------------------------------------------------------------------------------------------
	// UI helpers
	// ---------------------------------------------------------------------------------------------

	private static NumericUpDown MakeCompactDurationInput(int min, int max) => new()
	{
		Minimum = min,
		Maximum = max,
		Value = min,
		Width = 60,
		Margin = new Padding(0, 2, 2, 2),
		Anchor = AnchorStyles.Left,
	};

	private static Label MakeUnitLabel(string unit) => new()
	{
		Text = unit,
		AutoSize = true,
		Margin = new Padding(0, 6, 10, 0),
		TextAlign = ContentAlignment.MiddleLeft,
	};

	private static Label MakePolicyLabel(string text) => new()
	{
		Text = text,
		AutoSize = true,
		Anchor = AnchorStyles.Left,
		Margin = new Padding(0, 6, 12, 0),
		TextAlign = ContentAlignment.MiddleLeft,
	};

	private TextBox MakeFilterBox(string placeholder, Action onChanged)
	{
		ArgumentNullException.ThrowIfNull(onChanged);
		TextBox tb = new()
		{
			Dock = DockStyle.Top,
			PlaceholderText = placeholder,
		};
		tb.TextChanged += (_, _) => onChanged();
		return tb;
	}

	private static TextBox MakeInputBox(string placeholder) => new()
	{
		Dock = DockStyle.Top,
		PlaceholderText = placeholder,
	};

	private static Button MakeButton(string text, EventHandler onClick)
	{
		ArgumentNullException.ThrowIfNull(onClick);
		Button b = new() { Text = text, AutoSize = true, Margin = new Padding(2) };
		b.Click += onClick;
		return b;
	}

	private static TabPage BuildGridTab(
		string title,
		DataGridView grid,
		Control filterBox,
		Control? input,
		params Control[] buttons)
	{
		TabPage page = new() { Text = title };

		FlowLayoutPanel buttonBar = new() { Dock = DockStyle.Top, FlowDirection = FlowDirection.LeftToRight, AutoSize = true, Height = 36 };
		foreach (Control b in buttons)
		{
			buttonBar.Controls.Add(b);
		}

		page.Controls.Add(grid);
		page.Controls.Add(buttonBar);
		if (input is not null)
		{
			input.Dock = DockStyle.Top;
			page.Controls.Add(input);
		}
		filterBox.Dock = DockStyle.Top;
		page.Controls.Add(filterBox);
		return page;
	}

	private static DataGridView MakeAddressGrid()
	{
		DataGridView g = new()
		{
			Dock = DockStyle.Fill,
			AutoGenerateColumns = false,
			ReadOnly = true,
			RowHeadersVisible = false,
			AllowUserToAddRows = false,
			SelectionMode = DataGridViewSelectionMode.FullRowSelect,
			MultiSelect = false,
		};
		g.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Address", DataPropertyName = nameof(AddressListRow.Address), Width = 200 });
		g.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Source", DataPropertyName = nameof(AddressListRow.Source), Width = 130 });
		g.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Added (UTC)", DataPropertyName = nameof(AddressListRow.AddedUtcText), Width = 170 });
		g.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Expires (UTC)", DataPropertyName = nameof(AddressListRow.ExpiresUtcText), Width = 170 });
		g.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Note / reason", DataPropertyName = nameof(AddressListRow.Note), AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill });
		return g;
	}

	private static DataGridView MakeBlocklistGrid()
	{
		DataGridView g = new()
		{
			Dock = DockStyle.Fill,
			AutoGenerateColumns = false,
			ReadOnly = true,
			RowHeadersVisible = false,
			AllowUserToAddRows = false,
			SelectionMode = DataGridViewSelectionMode.FullRowSelect,
			MultiSelect = false,
		};
		g.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Id", DataPropertyName = nameof(AddressListRow.Id), Width = 60 });
		g.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Address", DataPropertyName = nameof(AddressListRow.Address), Width = 180 });
		g.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Enabled", DataPropertyName = nameof(AddressListRow.EnabledText), Width = 70 });
		g.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Enforcement", DataPropertyName = nameof(AddressListRow.EnforcementText), Width = 130 });
		g.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Source", DataPropertyName = nameof(AddressListRow.Source), Width = 120 });
		g.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Added (UTC)", DataPropertyName = nameof(AddressListRow.AddedUtcText), Width = 170 });
		g.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Expires (UTC)", DataPropertyName = nameof(AddressListRow.ExpiresUtcText), Width = 170 });
		g.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Note / reason", DataPropertyName = nameof(AddressListRow.Note), AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill });
		return g;
	}

	private static DataGridView MakeLoginRulesGrid()
	{
		DataGridView g = new()
		{
			Dock = DockStyle.Fill,
			AutoGenerateColumns = false,
			ReadOnly = true,
			RowHeadersVisible = false,
			AllowUserToAddRows = false,
			SelectionMode = DataGridViewSelectionMode.FullRowSelect,
			MultiSelect = false,
		};
		g.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Id", DataPropertyName = nameof(LoginRuleRow.Id), Width = 60 });
		g.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Login", DataPropertyName = nameof(LoginRuleRow.DisplayLogin), Width = 180 });
		g.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Enabled", DataPropertyName = nameof(LoginRuleRow.EnabledText), Width = 70 });
		g.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Trigger Count", DataPropertyName = nameof(LoginRuleRow.TriggerCount), Width = 100 });
		g.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "First Triggered (UTC)", DataPropertyName = nameof(LoginRuleRow.FirstTriggeredText), Width = 160 });
		g.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Last Triggered (UTC)", DataPropertyName = nameof(LoginRuleRow.LastTriggeredText), Width = 160 });
		g.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Last Source IP", DataPropertyName = nameof(LoginRuleRow.LastSourceIp), Width = 130 });
		g.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Added (UTC)", DataPropertyName = nameof(LoginRuleRow.AddedUtcText), Width = 160 });
		g.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Note", DataPropertyName = nameof(LoginRuleRow.Note), AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill });
		return g;
	}

	private static DataGridView MakeActiveBlocksGrid()
	{
		DataGridView g = new()
		{
			Dock = DockStyle.Fill,
			AutoGenerateColumns = false,
			ReadOnly = true,
			RowHeadersVisible = false,
			AllowUserToAddRows = false,
			SelectionMode = DataGridViewSelectionMode.FullRowSelect,
			MultiSelect = false,
		};
		g.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Id", DataPropertyName = nameof(ActiveBlockRow.Id), Width = 70 });
		g.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "IP", DataPropertyName = nameof(ActiveBlockRow.Ip), Width = 140 });
		g.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Provider", DataPropertyName = nameof(ActiveBlockRow.ProviderText), Width = 100 });
		g.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Rule handle", DataPropertyName = nameof(ActiveBlockRow.RuleHandle), Width = 200 });
		g.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Status", DataPropertyName = nameof(ActiveBlockRow.StatusText), Width = 90 });
		g.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Enforcement", DataPropertyName = nameof(ActiveBlockRow.EnforcementText), Width = 140 });
		g.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Confidence", DataPropertyName = nameof(ActiveBlockRow.ConfidenceText), Width = 170 });
		g.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Recommended action", DataPropertyName = nameof(ActiveBlockRow.RecommendedAction), Width = 220 });
		g.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Created (UTC)", DataPropertyName = nameof(ActiveBlockRow.CreatedUtcText), Width = 170 });
		g.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Expires (UTC)", DataPropertyName = nameof(ActiveBlockRow.ExpiresUtcText), Width = 170 });
		g.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Remaining", DataPropertyName = nameof(ActiveBlockRow.RemainingText), Width = 110 });
		g.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Reason / error", DataPropertyName = nameof(ActiveBlockRow.ReasonOrError), AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill });
		return g;
	}

	private void AttachReputationMenu(DataGridView grid, Func<string?> getIp)
	{
		ContextMenuStrip menu = new();
		ToolStripMenuItem ripeStat = new(IpReputationBrowser.RipeStatMenuLabel, null, (_, _) =>
		{
			IpReputationBrowser.LaunchOutcome outcome = IpReputationBrowser.OpenRipeStat(getIp());
			SetStatus(outcome.Format());
		});
		ToolStripMenuItem abuseIpDb = new(IpReputationBrowser.AbuseIpDbMenuLabel, null, (_, _) =>
		{
			IpReputationBrowser.LaunchOutcome outcome = IpReputationBrowser.OpenAbuseIpDb(getIp());
			SetStatus(outcome.Format());
		});
		menu.Items.Add(ripeStat);
		menu.Items.Add(abuseIpDb);
		menu.Opening += (_, e) =>
		{
			bool eligible = IpReputationBrowser.IsLookupEligible(getIp());
			ripeStat.Enabled = eligible;
			abuseIpDb.Enabled = eligible;
			if (getIp() is null)
			{
				e.Cancel = true;
			}
		};
		grid.ContextMenuStrip = menu;
		grid.CellMouseDown += (_, e) =>
		{
			if (e.Button != MouseButtons.Right || e.RowIndex < 0 || e.RowIndex >= grid.RowCount)
			{
				return;
			}

			grid.ClearSelection();
			grid.Rows[e.RowIndex].Selected = true;
		};
	}

	private static T? SelectedRow<T>(DataGridView grid, BindingList<T> binding) where T : class
	{
		if (grid.SelectedRows.Count == 0)
		{
			if (grid.CurrentRow is { Index: >= 0 } cr && cr.Index < binding.Count)
			{
				return binding[cr.Index];
			}
			return null;
		}

		int index = grid.SelectedRows[0].Index;
		return index >= 0 && index < binding.Count ? binding[index] : null;
	}

	private static int ClampToRange(int value, int min, int max)
	{
		if (value < min)
		{
			return min;
		}

		return value > max ? max : value;
	}

	private static bool Confirm(string message, string caption) =>
		MessageBox.Show(message, caption, MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2) == DialogResult.Yes;

	/// <summary>Re-entrancy + UI-busy guard for service-mutating actions (repair / verify / unblock /
	/// remove-all). While one is running the inner tab control (which hosts every action button and the
	/// grids) is disabled, so the operator cannot launch a second overlapping operation against the same
	/// long-running service call. Returns false if an operation is already in flight.</summary>
	private bool BeginBusy()
	{
		if (_operationInFlight)
		{
			SetStatus("Operation in progress — please wait for the current firewall operation to finish.");
			return false;
		}

		_operationInFlight = true;
		_innerTabs.Enabled = false;
		return true;
	}

	private void EndBusy()
	{
		_operationInFlight = false;
		_innerTabs.Enabled = true;
	}

	/// <summary>Renders an honest, SCM-aware status line for a service call that did not succeed, so the
	/// operator sees "operation in progress / service stopped / command error" rather than a blanket
	/// "no response". Never throws.</summary>
	private async Task ReportCallFailureAsync<T>(IpcCallResult<T> call, string action)
	{
		try
		{
			ServiceReachabilityDiagnostic diag = await _reachability.DescribeAsync(call).ConfigureAwait(true);
			SetStatus(action + ": " + diag.Headline + "  |  " + call.TraceLine);
		}
		catch (Exception ex)
		{
			SetStatus(action + ": FAILED — " + call.Headline() + " (diagnostic probe error: " + ex.GetType().Name + ")");
		}
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

	protected override void Dispose(bool disposing)
	{
		if (disposing)
		{
			_timer.Dispose();
		}

		base.Dispose(disposing);
	}

	// ---------------------------------------------------------------------------------------------
	// Row view-models exposed for grid binding (sealed; values are computed once at construction).
	// ---------------------------------------------------------------------------------------------

	private sealed record ProviderChoice(string Display, FirewallProviderKind Kind, bool Enabled)
	{
		public override string ToString() => Display;
	}

	/// <summary>Combo-box view-model mapping a human-readable label to a <see cref="FirewallBlockScope"/>
	/// enum value. The <see cref="Scope"/> ordinal is what gets persisted to appsettings.json; the
	/// <see cref="Display"/> string is operator-facing only.</summary>
	private sealed record BlockScopeChoice(string Display, FirewallBlockScope Scope)
	{
		public override string ToString() => Display;
	}

	/// <summary>Grid view-model for blocklist / whitelist entries.</summary>
	public sealed class AddressListRow
	{
		/// <summary>Stable surrogate row key carried from the service for deterministic mutation.</summary>
		public long Id { get; init; }

		public string Address { get; init; } = string.Empty;

		public string? Source { get; init; }

		public string? Note { get; init; }

		public string AddedUtcText { get; init; } = string.Empty;

		public string ExpiresUtcText { get; init; } = string.Empty;

		/// <summary>
		/// Per-row enforcement state for the BlockList (intent) vs verified ActiveBlock enforcement.
		/// One of: "Not enforced", "Pending", "Active", "Failed", "Expired", "Backend unavailable".
		/// Empty for lists where enforcement does not apply (e.g. whitelist).
		/// </summary>
		public string EnforcementText { get; set; } = string.Empty;

		/// <summary>True when the underlying BlockList row is enabled. Disabled rows are still shown so
		/// the operator can see (and remove by Id) a soft-disabled duplicate.</summary>
		public bool IsEnabled { get; init; } = true;

		public string EnabledText => IsEnabled ? "yes" : "no";

		public static AddressListRow From(AddressListEntryDto dto) => new()
		{
			Id = dto.Id,
			Address = dto.Address,
			Source = dto.Source,
			Note = dto.Note,
			AddedUtcText = FormatUtc(dto.AddedUtc),
			ExpiresUtcText = BlockExpiryFormatter.FormatExpiresUtc(dto.ExpiresUtc),
			IsEnabled = dto.IsEnabled,
		};
	}

	/// <summary>Grid view-model for login trip-wire entries.</summary>
	public sealed class LoginRuleRow
	{
		public long Id { get; init; }

		/// <summary>Normalized matching key (case-insensitive); retained for selection / mutation.</summary>
		public string Login { get; init; } = string.Empty;

		/// <summary>Original-case spelling shown in the grid.</summary>
		public string DisplayLogin { get; init; } = string.Empty;

		public bool Enabled { get; init; }

		public string EnabledText => Enabled ? "yes" : "no";

		public long TriggerCount { get; init; }

		public string FirstTriggeredText { get; init; } = string.Empty;

		public string LastTriggeredText { get; init; } = string.Empty;

		public string? LastSourceIp { get; init; }

		public string AddedUtcText { get; init; } = string.Empty;

		public string? Note { get; init; }

		public static LoginRuleRow From(LoginRuleDto dto) => new()
		{
			Id = dto.Id,
			Login = dto.Login,
			DisplayLogin = string.IsNullOrEmpty(dto.DisplayLogin) ? dto.Login : dto.DisplayLogin,
			Enabled = dto.Enabled,
			TriggerCount = dto.TriggerCount,
			FirstTriggeredText = FormatUtc(dto.FirstTriggeredUtc),
			LastTriggeredText = FormatUtc(dto.LastTriggeredUtc),
			LastSourceIp = dto.LastSourceIp,
			AddedUtcText = FormatUtc(dto.AddedUtc),
			Note = dto.Note,
		};
	}

	/// <summary>Grid view-model for active firewall blocks.</summary>
	public sealed class ActiveBlockRow
	{
		public long Id { get; init; }

		public string Ip { get; init; } = string.Empty;

		public FirewallProviderKind Provider { get; init; }

		public string ProviderText => Provider.ToString();

		public string? RuleHandle { get; init; }

		public string StatusText { get; init; } = string.Empty;

		public string CreatedUtcText { get; init; } = string.Empty;

		public string ExpiresUtcText { get; init; } = string.Empty;

		public string RemainingText { get; init; } = string.Empty;

		public string ReasonOrError { get; init; } = string.Empty;

		public string EnforcementText { get; init; } = string.Empty;

		public string ConfidenceText { get; init; } = string.Empty;

		public string RecommendedAction { get; init; } = string.Empty;

		public static ActiveBlockRow From(ActiveBlockDto dto)
		{
			StringBuilder sb = new();
			if (!string.IsNullOrEmpty(dto.Reason))
			{
				sb.Append(dto.Reason);
			}

			if (!string.IsNullOrEmpty(dto.LastError))
			{
				if (sb.Length > 0)
				{
					sb.Append(" — ");
				}
				sb.Append("error: ").Append(dto.LastError);
			}

			return new ActiveBlockRow
			{
				Id = dto.Id,
				Ip = dto.Ip,
				Provider = dto.Provider,
				RuleHandle = dto.RuleHandle,
				StatusText = dto.Status.ToString(),
				CreatedUtcText = FormatUtc(dto.CreatedUtc),
				ExpiresUtcText = BlockExpiryFormatter.FormatExpiresUtc(dto.ExpiresUtc),
				RemainingText = BlockExpiryFormatter.FormatRemaining(dto.ExpiresUtc, DateTime.UtcNow),
				ReasonOrError = sb.ToString(),
				EnforcementText = EnforcementReconciler.DescribeStatus(dto.EnforcementStatus),
				ConfidenceText = EnforcementReconciler.DescribeConfidence(dto.EnforcementConfidence),
				RecommendedAction = dto.RecommendedAction ?? string.Empty,
			};
		}
	}

	private static string FormatUtc(DateTime? value)
	{
		if (value is null)
		{
			return string.Empty;
		}

		return value.Value.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture);
	}
}
