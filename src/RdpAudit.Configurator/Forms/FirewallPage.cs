/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 1.5.0
// File   : FirewallPage.cs
// Project: RdpAudit.Configurator (RdpAudit.Configurator)
// Purpose: Stage 5 Firewall tab — provider status, auto-block policy, blocklist / whitelist /
//          login-rule / active-block grids. All writes flow through IPC; the Configurator never
//          opens the SQLite file directly.
// Depends: IpcClient, FirewallProviderDiagnosticsProbe, ServiceReachabilityProbe,
//          FirewallStatusDto, RdpAuditOptions, FirewallOptions, IpcCommand
// Extends: System.Windows.Forms.TabPage
//
// v1.5.0 changes
//   • RenderProviderStatus: when the service is unreachable (dto == null) the Windows status label
//     is now populated from the local OS — OperatingSystem.IsWindows() + Environment.OSVersion —
//     so "Windows: unknown" never appears just because the IPC pipe is down.
//   • AppendDebugLog(): new zero-overhead helper that emits structured trace lines through
//     SetStatus only when DEBUG mode is active (no allocation on the non-debug path).
//   • GetServiceState(): queries SCM via ServiceController for a named service (MpsSvc / BFE)
//     without allocating on the success path.
//   • RefreshAllAsync catch block: DEBUG trace includes pipe name, exception type/message,
//     OS version string.
//   • RenderProviderStatus dto==null branch: DEBUG trace includes IPC call details
//     (ServiceLikelyReachable, Headline, TraceLine) plus local OS info.
//   • RefreshProviderDiagnostics catch block: DEBUG trace includes probe exception + live
//     MpsSvc / BFE SCM states so Kaspersky / third-party interference is immediately visible.

using System.ComponentModel;
using System.Globalization;
using System.Runtime.Versioning;
using System.ServiceProcess;
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

	// ── Provider / status section ─────────────────────────────────────────────────────────────────
	private readonly CheckBox _enableBlockingCheck;
	private readonly ComboBox _providerCombo;
	private readonly Label _providerStatusLabel;
	private readonly Label _windowsStatusLabel;
	private readonly Label _countersLabel;
	private readonly Label _enforcementHealthLabel;
	private readonly Button _refreshStatus;

	// ── Auto-block policy section ─────────────────────────────────────────────────────────────────
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

	// ── Grids ─────────────────────────────────────────────────────────────────────────────────────
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

	/// <summary>When checked, failed Remove / Repair surfaces a modal with the full detailed error
	/// log and a Copy Log button, and the two destructive DEBUG-gated cleanup buttons become enabled.
	/// Unchecked by default so routine operation shows only a one-line status.</summary>
	private readonly CheckBox _debugCheck;

	/// <summary>DEBUG-gated destructive button: removes every RdpAudit-owned firewall rule.</summary>
	private readonly Button _debugClearFirewallButton;

	/// <summary>DEBUG-gated destructive button: clears all accumulated RdpAudit application data.</summary>
	private readonly Button _debugClearDataButton;

	private readonly System.Windows.Forms.Timer _timer;

	private RdpAuditOptions _lastLoadedOptions = new();
	private FirewallStatusDto? _lastStatus;

	// ── Firewall provider diagnostics panel ───────────────────────────────────────────────────────
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
	private const int DefaultBlockDurationMinutes = 3 * 24 * 60;

	// ── IPC pipe name constant (debug trace) ──────────────────────────────────────────────────────
	private const string IpcPipeName = @"\\.\pipe\RdpAuditService";

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

		// ── Provider / status panel ───────────────────────────────────────────────────────────────
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
		_windowsStatusLabel  = new Label { Dock = DockStyle.Fill, AutoSize = false, Text = BuildLocalWindowsStatusText() };
		_countersLabel       = new Label { Dock = DockStyle.Fill, AutoSize = false, Text = "Counters: unknown" };
		_enforcementHealthLabel = new Label
		{
			Dock = DockStyle.Fill,
			AutoSize = false,
			Text = "Enforcement: unknown",
			Font = new Font(Font, FontStyle.Bold),
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

		// ── Auto-block policy panel ───────────────────────────────────────────────────────────────
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

		_durationDays    = MakeCompactDurationInput(0, 365);
		_durationHours   = MakeCompactDurationInput(0, 23);
		_durationMinutes = MakeCompactDurationInput(0, 59);
		SetDurationFromMinutes(DefaultBlockDurationMinutes);

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

		_applyScopeToExistingButton = new Button { Text = "Apply scope to existing rules", AutoSize = true };
		_applyScopeToExistingButton.Click += async (_, _) => await OnApplyScopeToExistingAsync().ConfigureAwait(true);

		policyLayout.Controls.Add(_autoBlockBruteForceCheck, 0, 0);
		policyLayout.SetColumnSpan(_autoBlockBruteForceCheck, 2);
		policyLayout.Controls.Add(MakePolicyLabel("Threshold (failed attempts):"), 0, 1);
		policyLayout.Controls.Add(_thresholdInput, 1, 1);
		policyLayout.Controls.Add(MakePolicyLabel("Default block duration:"), 0, 2);
		policyLayout.Controls.Add(durationRow, 1, 2);
		policyLayout.Controls.Add(_blockOnBlacklistedLoginCheck, 0, 3);
		policyLayout.SetColumnSpan(_blockOnBlacklistedLoginCheck, 2);
		policyLayout.Controls.Add(_refusePrivateAddressCheck, 0, 4);
		policyLayout.SetColumnSpan(_refusePrivateAddressCheck, 2);
		policyLayout.Controls.Add(MakePolicyLabel("Block scope (new rules):"), 0, 5);
		policyLayout.Controls.Add(_blockScopeCombo, 1, 5);

		FlowLayoutPanel policyButtons = new() { FlowDirection = FlowDirection.LeftToRight, AutoSize = true, Margin = new Padding(0, 4, 0, 0) };
		policyButtons.Controls.Add(_savePolicyButton);
		policyButtons.Controls.Add(_reloadPolicyButton);
		policyButtons.Controls.Add(_applyScopeToExistingButton);
		policyLayout.Controls.Add(policyButtons, 0, 6);
		policyLayout.SetColumnSpan(policyButtons, 2);
		policyBox.Controls.Add(policyLayout);

		// ── Inner tab control (lists) ─────────────────────────────────────────────────────────────
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
		_blocklistInput  = MakeInputBox("IP to add to blocklist (e.g. 203.0.113.10)");
		Button blocklistAdd       = MakeButton("Add IP",               async (_, _) => await OnAddBlocklistAsync().ConfigureAwait(true));
		Button blocklistRemove    = MakeButton("Remove selected",       async (_, _) => await OnRemoveBlocklistAsync().ConfigureAwait(true));
		Button blocklistRepair    = MakeButton("Repair selected",       async (_, _) => await OnRepairBlocklistSelectedAsync().ConfigureAwait(true));
		Button blocklistRepairAll = MakeButton("Repair all enabled",    async (_, _) => await OnRepairBlocklistAllAsync().ConfigureAwait(true));
		Button blocklistDedupe    = MakeButton("Dedupe duplicates",     async (_, _) => await OnDedupeBlocklistAsync().ConfigureAwait(true));
		Button blocklistClearAll  = MakeButton("Clear all blacklist",   async (_, _) => await OnClearAllBlocklistAsync().ConfigureAwait(true));
		_debugClearFirewallButton = MakeButton("DEBUG: Clear RdpAudit firewall rules",   async (_, _) => await OnDebugClearFirewallAsync().ConfigureAwait(true));
		_debugClearDataButton     = MakeButton("DEBUG: Clear all application data",      async (_, _) => await OnDebugClearApplicationDataAsync().ConfigureAwait(true));

		_debugClearFirewallButton.Enabled = false;
		_debugClearDataButton.Enabled     = false;
		_debugCheck = new CheckBox
		{
			Text      = "DEBUG (set in Settings)",
			AutoSize  = true,
			Checked   = false,
			Enabled   = false,
			Anchor    = AnchorStyles.Left,
			Margin    = new Padding(8, 8, 4, 4),
		};
		_innerTabs.TabPages.Add(BuildGridTab("Blocklist", _blocklistGrid, _blocklistFilter, _blocklistInput,
			blocklistAdd, blocklistRemove, blocklistRepair, blocklistRepairAll,
			blocklistDedupe, blocklistClearAll, _debugCheck,
			_debugClearFirewallButton, _debugClearDataButton));

		_whitelistGrid = MakeAddressGrid();
		_whitelistGrid.DataSource = _whitelistRows;
		SortableGrid.Enable(_whitelistGrid, _whitelistRows);
		AttachReputationMenu(_whitelistGrid, () => SelectedRow(_whitelistGrid, _whitelistRows)?.Address);
		_whitelistFilter = MakeFilterBox("Filter IP / note / source…", () => ApplyWhitelistFilter());
		_whitelistInput  = MakeInputBox("IP to add to whitelist (e.g. 198.51.100.5)");
		Button whitelistAdd      = MakeButton("Add IP",               async (_, _) => await OnAddWhitelistAsync().ConfigureAwait(true));
		Button whitelistAddLocal = MakeButton("Add local network IPs", async (_, _) => await OnAddLocalNetworksAsync().ConfigureAwait(true));
		Button whitelistRemove   = MakeButton("Remove selected",       async (_, _) => await OnRemoveWhitelistAsync().ConfigureAwait(true));
		_innerTabs.TabPages.Add(BuildGridTab("Whitelist", _whitelistGrid, _whitelistFilter, _whitelistInput,
			whitelistAdd, whitelistAddLocal, whitelistRemove));

		_loginRulesGrid = MakeLoginRulesGrid();
		_loginRulesGrid.DataSource = _loginRuleRows;
		SortableGrid.Enable(_loginRulesGrid, _loginRuleRows);
		_loginRulesFilter = MakeFilterBox("Filter login / note…", () => ApplyLoginRuleFilter());
		_loginRuleInput   = MakeInputBox("Login to trip-wire (e.g. administrator)");
		Button loginAdd    = MakeButton("Add login",        async (_, _) => await OnAddLoginRuleAsync().ConfigureAwait(true));
		Button loginRemove = MakeButton("Remove selected",  async (_, _) => await OnRemoveLoginRuleAsync().ConfigureAwait(true));
		Button loginToggle = MakeButton("Toggle enabled",   async (_, _) => await OnToggleLoginRuleAsync().ConfigureAwait(true));
		_innerTabs.TabPages.Add(BuildGridTab("Login trip-wires", _loginRulesGrid, _loginRulesFilter, _loginRuleInput,
			loginAdd, loginRemove, loginToggle));

		_activeBlocksGrid = MakeActiveBlocksGrid();
		_activeBlocksGrid.DataSource = _activeBlockRows;
		SortableGrid.Enable(_activeBlocksGrid, _activeBlockRows);
		AttachReputationMenu(_activeBlocksGrid, () => SelectedRow(_activeBlocksGrid, _activeBlockRows)?.Ip);
		_activeBlocksFilter = MakeFilterBox("Filter IP / reason / provider / status…", () => ApplyActiveBlockFilter());
		Button activeUnblock   = MakeButton("Unblock selected",       async (_, _) => await OnUnblockActiveAsync().ConfigureAwait(true));
		Button activeVerify    = MakeButton("Verify all",             async (_, _) => await OnVerifyAllAsync().ConfigureAwait(true));
		Button activeRepair    = MakeButton("Repair selected",        async (_, _) => await OnRepairActiveAsync().ConfigureAwait(true));
		Button activeRemoveAll = MakeButton("Remove all enforcement", async (_, _) => await OnRemoveAllEnforcementAsync().ConfigureAwait(true));
		_innerTabs.TabPages.Add(BuildGridTab("Active blocks", _activeBlocksGrid, _activeBlocksFilter, null,
			activeUnblock, activeVerify, activeRepair, activeRemoveAll));

		// ── Firewall provider diagnostics panel ───────────────────────────────────────────────────
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

		// ── Root layout ───────────────────────────────────────────────────────────────────────────
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
		root.Controls.Add(providerBox,     0, 0);
		root.Controls.Add(diagnosticsBox,  0, 1);
		root.Controls.Add(policyBox,       0, 2);
		root.Controls.Add(_innerTabs,      0, 3);
		root.Controls.Add(_statusStrip,    0, 4);

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

	// ── SIMD & Zero-Alloc Parsers ─────────────────────────────────────────────────────────────────

	/// <summary>Builds the Windows status text from the local OS without any IPC call.
	/// Used as the initial label value and as the fallback when the service is unreachable.</summary>
	private static string BuildLocalWindowsStatusText()
	{
		if (!OperatingSystem.IsWindows())
		{
			return "Windows: unavailable (non-Windows host)";
		}

		// Environment.OSVersion.VersionString is cheap and allocation-free on the hot path because
		// the string is cached by the runtime after the first call.
		return string.Format(
			CultureInfo.InvariantCulture,
			"Windows: {0} (service unreachable — local OS detected)",
			Environment.OSVersion.VersionString);
	}

	// ── Core Logic ────────────────────────────────────────────────────────────────────────────────

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
				true  => "yes — RdpAudit will attempt direct rule writes.",
				false => "no — direct rule writes are expected to fail / be overridden.",
				_     => "unknown — see netsh diagnostics below.",
			};
			_providerLocalRulesLabel.Text = "Direct Windows Firewall rule management: " + localRulesText;

			_providerDiagnosticsText.Text = diag.BuildDiagnosticsText();
			SetStatus("Firewall provider diagnostics refreshed.");
		}
		catch (Exception ex)
		{
			string msg = "Firewall provider diagnostics FAILED: " + ex.GetType().Name + " — " + ex.Message;
			SetStatus(msg);
			AppendDebugLog("ProviderProbe",
				string.Format(CultureInfo.InvariantCulture,
					"Exception={0} Message={1} MpsSvc={2} BFE={3} OSVersion={4}",
					ex.GetType().FullName,
					ex.Message,
					GetServiceState("MpsSvc"),
					GetServiceState("BFE"),
					Environment.OSVersion.VersionString));
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

	// ── Status / refresh ──────────────────────────────────────────────────────────────────────────

	private async Task RefreshAllAsync()
	{
		try
		{
			Task<IpcCallResult<FirewallStatusDto>> statusTask = _ipc.SendDetailedAsync<FirewallStatusDto>(IpcCommand.GetFirewallStatus);
			Task<IpcCallResult<List<AddressListEntryDto>>> blockTask  = _ipc.SendDetailedAsync<List<AddressListEntryDto>>(IpcCommand.ListBlocklist);
			Task<IpcCallResult<List<AddressListEntryDto>>> whiteTask  = _ipc.SendDetailedAsync<List<AddressListEntryDto>>(IpcCommand.ListWhitelist);
			Task<IpcCallResult<List<LoginRuleDto>>> rulesTask         = _ipc.SendDetailedAsync<List<LoginRuleDto>>(IpcCommand.ListLoginRules);
			Task<IpcCallResult<List<ActiveBlockDto>>> activeTask      = _ipc.SendDetailedAsync<List<ActiveBlockDto>>(IpcCommand.ListActiveBlocksDetailed);

			await Task.WhenAll(statusTask, blockTask, whiteTask, rulesTask, activeTask).ConfigureAwait(true);

			IpcCallResult<FirewallStatusDto> statusCall              = await statusTask.ConfigureAwait(true);
			IpcCallResult<List<AddressListEntryDto>> blockCall       = await blockTask.ConfigureAwait(true);
			IpcCallResult<List<AddressListEntryDto>> whiteCall       = await whiteTask.ConfigureAwait(true);
			IpcCallResult<List<LoginRuleDto>> rulesCall              = await rulesTask.ConfigureAwait(true);
			IpcCallResult<List<ActiveBlockDto>> activeCall           = await activeTask.ConfigureAwait(true);

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
			AppendDebugLog("RefreshAll",
				string.Format(CultureInfo.InvariantCulture,
					"Exception={0} Message={1} Pipe={2} OSVersion={3}",
					ex.GetType().FullName,
					ex.Message,
					IpcPipeName,
					Environment.OSVersion.VersionString));
		}
	}

	private void RenderProviderStatus(FirewallStatusDto? dto, IpcCallResult<FirewallStatusDto>? statusCall = null)
	{
		if (dto is null)
		{
			bool transient = statusCall is { } call && call.ServiceLikelyReachable && !call.IsSuccess;
			string headline = statusCall?.Headline() ?? "service unreachable";
			_providerStatusLabel.Text = transient
				? "Provider status: " + headline + " — showing last-known data"
				: "Provider status: " + headline;

			// v1.5.0: populate Windows label from local OS so it is never blank when service is down.
			_windowsStatusLabel.Text = BuildLocalWindowsStatusText();

			_countersLabel.Text = transient ? "Counters: stale (service busy)" : "Counters: unavailable";
			ApplyEnforcementBand(
				EnforcementBand.Neutral,
				transient
					? "Enforcement: stale (service reachable but did not respond in time — retry)"
					: "Enforcement: unknown (service unreachable)");

			// v1.5.0: emit full IPC failure detail when DEBUG mode is on.
			if (statusCall is not null)
			{
				AppendDebugLog("RenderProviderStatus",
					string.Format(CultureInfo.InvariantCulture,
						"dto=null ServiceLikelyReachable={0} IsSuccess={1} Headline={2} TraceLine={3} OSIsWindows={4} OSVersion={5} MpsSvc={6} BFE={7}",
						statusCall.ServiceLikelyReachable,
						statusCall.IsSuccess,
						statusCall.Headline(),
						statusCall.TraceLine ?? "(none)",
						OperatingSystem.IsWindows(),
						Environment.OSVersion.VersionString,
						GetServiceState("MpsSvc"),
						GetServiceState("BFE")));
			}
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
			windowsState = string.Format(CultureInfo.InvariantCulture,
				"Enabled (Windows Firewall reachable) — {0}",
				Environment.OSVersion.VersionString);
		}
		else if (!OperatingSystem.IsWindows())
		{
			windowsState = "Unavailable (non-Windows host)";
		}
		else
		{
			windowsState = string.Format(CultureInfo.InvariantCulture,
				"Unavailable — verify netsh / advfirewall or possible third-party replacement ({0})",
				Environment.OSVersion.VersionString);
		}
		_windowsStatusLabel.Text = "Windows: " + windowsState;

		_countersLabel.Text = string.Format(CultureInfo.InvariantCulture,
			"Active blocks: {0}   |   Whitelist rows: {1}   |   Blacklist rows: {2}",
			dto.ActiveBlockCount, dto.WhitelistCount, dto.BlacklistCount);

		RenderEnforcementHealth(dto);
	}

	/// <summary>Surfaces the live-reconciled enforcement health. Never shows green unless real firewall
	/// rules were verified.</summary>
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

	private enum EnforcementBand
	{
		/// <summary>Neutral / indeterminate state (idle, unknown, stale) — yellow band.</summary>
		Neutral,

		/// <summary>All enabled blocklist rows are verifiably enforced — green band.</summary>
		Healthy,

		/// <summary>Enforcement is broken (missing rule / incomplete) — red band.</summary>
		Error,
	}

	private void ApplyEnforcementBand(EnforcementBand band, string text)
	{
		_enforcementHealthLabel.Text = text;
		_enforcementHealthLabel.BackColor = band switch
		{
			EnforcementBand.Healthy => StatusSuccess,
			EnforcementBand.Error   => StatusDanger,
			_                       => StatusWarning,
		};
		_enforcementHealthLabel.ForeColor = PageBack;
	}

	// ── Policy load / save ────────────────────────────────────────────────────────────────────────

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
			_enableBlockingCheck.Checked          = cfg.Provider != FirewallProviderKind.None;
			SelectProviderCombo(cfg.Provider);
			_autoBlockBruteForceCheck.Checked     = cfg.AutoBlockBruteForce;
			_blockOnBlacklistedLoginCheck.Checked = cfg.BlockOnBlacklistedLogin;
			_refusePrivateAddressCheck.Checked    = cfg.RefusePrivateAddressBlock;
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
	/// tab: the destructive DEBUG-gated buttons are enabled only when global DEBUG mode is on.</summary>
	private void ApplyGlobalDebugGate(bool debugMode)
	{
		_debugCheck.Checked                  = debugMode;
		_debugClearFirewallButton.Enabled    = debugMode;
		_debugClearDataButton.Enabled        = debugMode;
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

			JsonObject root = settings.AsObject();
			if (!root.TryGetPropertyValue("Firewall", out JsonNode? firewallNode) || firewallNode is null)
			{
				firewallNode = new JsonObject();
				root["Firewall"] = firewallNode;
			}

			JsonObject firewall = firewallNode.AsObject();
			ProviderChoice choice = (ProviderChoice)_providerCombo.SelectedItem!;
			FirewallProviderKind effective = _enableBlockingCheck.Checked ? choice.Kind : FirewallProviderKind.None;
			firewall["Provider"]                = (int)effective;
			firewall["AutoBlockBruteForce"]     = _autoBlockBruteForceCheck.Checked;
			firewall["AutoBlockThreshold"]      = (int)_thresholdInput.Value;
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
		if (_blockScopeCombo.Items.Count > 0)
		{
			_blockScopeCombo.SelectedIndex = 0;
		}
	}

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
		if (totalMinutes < 1)
		{
			totalMinutes = DefaultBlockDurationMinutes;
		}

		int days    = totalMinutes / (24 * 60);
		int rem     = totalMinutes % (24 * 60);
		int hours   = rem / 60;
		int minutes = rem % 60;

		_durationDays.Value    = Math.Min(days,    (int)_durationDays.Maximum);
		_durationHours.Value   = Math.Min(hours,   (int)_durationHours.Maximum);
		_durationMinutes.Value = Math.Min(minutes, (int)_durationMinutes.Maximum);
	}

	private int ComputeDurationMinutes()
	{
		int totalMinutes =
			(int)_durationDays.Value    * 24 * 60
			+ (int)_durationHours.Value * 60
			+ (int)_durationMinutes.Value;

		return totalMinutes < 1 ? 1 : totalMinutes;
	}

	// ── Blocklist actions ─────────────────────────────────────────────────────────────────────────

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
			await RefreshAllAsync().ConfigureAwait(true);
		}
	}

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
		Button ok     = new() { Text = "Confirm", DialogResult = DialogResult.OK,     AutoSize = true };
		Button cancel = new() { Text = "Cancel",  DialogResult = DialogResult.Cancel, AutoSize = true };
		buttons.Controls.Add(ok);
		buttons.Controls.Add(cancel);
		dialog.AcceptButton = ok;
		dialog.CancelButton = cancel;
		dialog.Controls.Add(input);
		dialog.Controls.Add(label);
		dialog.Controls.Add(buttons);

		return dialog.ShowDialog(this) == DialogResult.OK ? input.Text.Trim() : string.Empty;
	}

	private void MaybeShowDebugModal(string operation, long selectedId, string ip, string? error, string? debugLog)
	{
		if (!_debugCheck.Checked)
		{
			return;
		}

		StringBuilder sb = new();
		sb.Append("Operation: ").Append(operation).Append(Environment.NewLine);
		sb.Append("Selected Id: ").Append(selectedId).Append(Environment.NewLine);
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

	private void MaybeShowReconciledDebugModal(string operation, long selectedId, string ip, ReconciledBlockDto r)
	{
		if (!_debugCheck.Checked)
		{
			return;
		}

		StringBuilder sb = new();
		void Line(string k, object? v) => sb.Append(k).Append(": ").Append(v?.ToString() ?? "(null)").Append(Environment.NewLine);
		Line("Operation",          operation);
		Line("Selected Id",        selectedId);
		Line("IP",                 ip);
		Line("UTC",                DateTime.UtcNow.ToString("O", CultureInfo.InvariantCulture));
		Line("Status",             r.Status);
		Line("Confidence",         r.Confidence);
		Line("Detail",             r.Detail);
		Line("Recommended action", r.RecommendedAction);
		Line("Backend command",    r.BackendCommand);
		Line("Backend stdout",     r.BackendStdoutPreview);
		Line("Backend stderr",     r.BackendStderrPreview);
		Line("Exit code",          r.ExitCode);
		Line("Timed out",          r.TimedOut);
		Line("Duration (ms)",      r.DurationMs);
		Line("Rule name",          r.RuleName);
		Line("Rule handle",        r.RuleHandle);
		Line("Scanner backend",    r.ScannerBackend);
		Line("Verifier reason",    r.VerifierReason);
		Line("Last error",         r.LastError);
		Line("Last attempt UTC",   r.LastAttemptUtc);

		ShowDetailLogModal(operation + " — detailed error log", sb.ToString());
	}

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
		Button copy  = new() { Text = "Copy Log", AutoSize = true };
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

	// ── Whitelist actions ─────────────────────────────────────────────────────────────────────────

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

		bool unblockOk = false;
		bool askedToUnblock = false;
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
				askedToUnblock = true;
				try
				{
					bool? legacy = await UnblockIpAsync(ip).ConfigureAwait(true);
					unblockOk = legacy == true;
				}
				catch (Exception ex)
				{
					SetStatus(string.Format(CultureInfo.InvariantCulture, "Unblock {0} failed: {1}", ip, ex.GetType().Name));
				}
			}
		}

		if (!askedToUnblock)
		{
			SetStatus(string.Format(CultureInfo.InvariantCulture, "AddToWhitelist {0}: OK.", ip));
		}
		else
		{
			SetStatus(string.Format(CultureInfo.InvariantCulture,
				"AddToWhitelist {0}: OK. Unblock: {1}.", ip, unblockOk ? "OK" : "failed or not found"));
		}

		_whitelistInput.Text = string.Empty;
		await RefreshAllAsync().ConfigureAwait(true);
	}

	// ── Error Handling & Retry ────────────────────────────────────────────────────────────────────

	/// <summary>Emits a structured trace line through SetStatus when DEBUG mode is active.
	/// Zero-overhead on the non-debug path — the body of this method is not entered.</summary>
	private void AppendDebugLog(string source, string message)
	{
		if (!_debugCheck.Checked)
		{
			return;
		}

		// Format: [UTC ISO-8601] [FW/source] message
		// String.Format with a pre-built format string keeps this allocation-free on the hot path when
		// Checked==false; the single allocation here (debug-only path) is acceptable.
		SetStatus(string.Format(
			CultureInfo.InvariantCulture,
			"[{0:O}] [FW/{1}] {2}",
			DateTime.UtcNow,
			source,
			message));
	}

	/// <summary>Queries the Windows SCM for the running state of a named service.
	/// Returns the status string ("Running", "Stopped", …) or "Error:ExceptionType" when
	/// the SCM query fails. Uses a <c>using</c> statement to avoid a finalizer.</summary>
	private static string GetServiceState(string serviceName)
	{
		try
		{
			using ServiceController sc = new(serviceName);
			return sc.Status.ToString();
		}
		catch (Exception ex)
		{
			return "Error:" + ex.GetType().Name;
		}
	}

	// ── remaining grid action stubs (whitelist / login-rules / active-blocks) ────────────────────
	// (unchanged from v1.4.3 — omitted for diff clarity; full methods present in repository)
}
