/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : DatabasePage.cs
// Project: RdpAudit.Configurator (RdpAudit.Configurator.Forms)
// Purpose: Stage 3 Database tab. One place to SEE the evidence store (Overview, Shards, Ledger),
//          GOVERN it (Retention editor with a mandatory dry-run preview and an old -> new diff
//          before saving), OPERATE it (Maintenance actions, Backup & Restore) and - only with the
//          DEBUG gate plus elevation - DESTROY data under a typed confirmation phrase. Every read
//          goes through IPC; the Configurator never opens the SQLite file or a shard file itself,
//          and every destructive action re-validates its phrase server-side (ClearAllApplicationData)
//          or re-checks the gate at click time. Every data view carries an "as of HH:mm:ss UTC"
//          stamp, every long action runs behind BeginBusy/EndBusy with a client-side cancellation
//          token, and every failure is rendered from IpcCallResult.Headline() instead of a bare
//          "FAILED". Nothing on the UI thread touches SQLite, the shard tree or a backup artifact.
// Depends: IIpcClient (the narrow seam - see IIpcClient.cs), DatabasePage DTOs (80-90), ElevationGuard,
//          DatabaseRestoreService,
//          DatabaseResetService, DarkTheme, SortableGrid, DataGridClipboardMenu
// Extends: Add an inner tab as a sibling builder and register it in BuildInnerTabs; keep the
//          InnerTabTitles list and DatabasePageTests in lock-step.

using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.Runtime.Versioning;
using System.Text;
using System.Text.Json.Nodes;
using RdpAudit.Configurator.Ipc;
using RdpAudit.Configurator.Services;
using RdpAudit.Core.Config;
using RdpAudit.Core.Data;
using RdpAudit.Core.Integrity;
using RdpAudit.Core.Ipc;
using RdpAudit.Core.Ipc.Contracts;
using RdpAudit.Core.Util;
using RdpAudit.Configurator.Theming;

using static RdpAudit.Configurator.Theming.DarkTheme;

namespace RdpAudit.Configurator.Forms;

/// <summary>Stage 3 Database tab: overview, retention governance, maintenance, backup/restore,
/// shard inventory, an audited danger zone and the deletion ledger.</summary>
[SupportedOSPlatform("windows")]
public sealed class DatabasePage : TabPage
{
	// ── Fields & DI ──────────────────────────────────────────────────────────────

	/// <summary>Typed phrase required by the Danger Zone's "Back up and reset database" action.</summary>
	internal const string ResetDatabasePhrase = "RESET RDP AUDIT DATABASE";

	/// <summary>Typed phrase required by "Clear all application data". Deliberately identical to the
	/// Firewall page's phrase: the same server-side validation guards both entry points, and there is
	/// exactly one phrase an operator has to know for this operation.</summary>
	internal const string ClearAllDataPhrase = "CLEAR ALL RDP AUDIT DATA";

	/// <summary>Typed phrase required by "Restore over live database".</summary>
	internal const string RestoreOverLivePhrase = "RESTORE OVER LIVE DATABASE";

	/// <summary>Typed phrase required by "Purge by subject". The server re-validates the same string, so a
	/// divergence here could only make the UI stricter, never the purge weaker.</summary>
	internal const string PurgeSubjectPhrase = "PURGE SUBJECT DATA";

	/// <summary>Typed phrase required by "Compact database (offline)".</summary>
	internal const string CompactOfflinePhrase = "COMPACT RDP AUDIT DATABASE";

	/// <summary>The Danger Zone's explanation of the two actions that stop the service, and of what a subject
	/// purge deliberately does NOT touch.</summary>
	internal const string PurgeStubText = "Purge by subject removes every evidence row about one address, range, login or UTC window, behind a mandatory dry run and a typed phrase. Operator configuration (blocklist, whitelist, login rules) and enforcement state are never touched by it. Compact database (offline) is the only operation that shrinks the file: it runs with the service stopped (see docs/88-database-backup-and-restore.md).";

	/// <summary>The Shards tab's statement about the one shard action that does not exist. Kept as a
	/// plain sentence instead of a disabled button: a button that cannot work is worse than a label that
	/// says why.</summary>
	internal const string ShardCompactionStubText =
		"Compaction is not implemented yet: no .rdpshard file is ever rewritten in place. Retention inside "
		+ "a shard is the O(1) ring eviction the fixed format already performs (docs/86-shard-ingestion.md).";

	/// <summary>Upper bound on orphan candidates listed in the collection confirmation prompt. The rest
	/// are summarised in one line, so the dialog stays readable on a pathological tree.</summary>
	private const int OrphanPromptMaxLines = 50;

	/// <summary>Upper bound on rows the ledger CSV export pulls from the service.</summary>
	private const int LedgerExportMaxRows = 50_000;

	/// <summary>Upper bound on rows one ledger export page request asks for (server clamps again).</summary>
	private const int LedgerExportPageSize = 1000;

	private const int MaximumRetentionDays = 36_500;

	private readonly IIpcClient _ipc;
	private readonly StatusStrip _statusStrip;
	private readonly ToolStripStatusLabel _statusLabel;
	private readonly TabControl _innerTabs;
	private readonly DatabaseRestoreService _restoreService = new();

	/// <summary>The live database path as last reported by the Overview. Used by the restore-over-live
	/// flow; never guessed from a hardcoded path.</summary>
	private string _lastDatabasePath = string.Empty;

	/// <summary>The offline compaction path. Shared with the restore flow's LiveDatabaseSwap mechanics, and the
	/// only operation that may rewrite the whole database file.</summary>
	private readonly DatabaseCompactService _compactService = new();

	/// <summary>Re-entrancy guard: while a service call is in flight the inner tab control (which
	/// hosts every action button and grid) is disabled, so a second overlapping operation against the
	/// same long-running service call cannot be launched by a double click.</summary>
	private bool _operationInFlight;

	/// <summary>Cancellation for the in-flight call. Cancelling abandons the client-side wait; the
	/// service may still be completing its work, which the status line says explicitly.</summary>
	private CancellationTokenSource? _operationCts;

	private bool _dangerDebugMode;
	private bool _dangerElevated;

	// Overview ------------------------------------------------------------------------------------
	private readonly Button _overviewRefresh;
	private readonly Label _overviewStamp;
	private readonly TextBox _overviewReport;

	// B25: the store-integrity verdict, docked above the report so it is readable without scrolling to a
	// section that lives 90 lines down a monospace dump. Its colour follows StoreIntegrityVerdictBand and
	// nothing else, so a state cannot be coloured one way by the banner and another by the report.
	private readonly Panel _overviewIntegrityBannerPanel;
	private readonly Label _overviewIntegrityBannerLabel;
	private StoreIntegrityVerdictBand _overviewIntegrityBand = StoreIntegrityVerdictBand.Unknown;

	// Retention -----------------------------------------------------------------------------------
	private readonly CheckBox _policyEnabledCheck;
	private readonly CheckBox _legalHoldCheck;
	private readonly ComboBox _anchorScopeCombo;
	private readonly NumericUpDown _tailKeepInput;
	private readonly NumericUpDown _candidateMinRowsInput;
	private readonly NumericUpDown _minAgeDaysInput;
	private readonly NumericUpDown _maxRowsPerPassInput;
	private readonly NumericUpDown _maxWriterLockMsInput;
	private readonly NumericUpDown _deleteBatchRowsInput;
	private readonly NumericUpDown _maxDatabaseBytesInput;
	private readonly NumericUpDown _maxRawEventRowsInput;
	private readonly NumericUpDown _minFreeDiskBytesInput;
	private readonly TextBox _protectedEventIdsInput;
	private readonly Label _effectiveValuesLabel;
	private readonly NumericUpDown[] _globalWindowInputs = new NumericUpDown[8];
	private readonly DataGridView _eventRetentionGrid;
	private readonly BindingList<EventRetentionRow> _eventRetentionRows = new();
	private readonly NumericUpDown _bulkRetentionDays;
	private readonly Button _bulkRetentionButton;
	private readonly Button _bulkRetentionAllButton;
	private readonly Button _previewButton;
	private readonly Button _saveRetentionButton;
	private readonly Button _reloadRetentionButton;
	private readonly DataGridView _previewGrid;
	private readonly BindingList<PreviewRow> _previewRows = new();
	private readonly TextBox _previewSteps;
	private RetentionPolicyDto? _lastPolicy;

	// Maintenance ---------------------------------------------------------------------------------
	private readonly List<MaintenanceButton> _maintenanceButtons = new();
	private readonly Button _rebuildStatsButton;
	private readonly Button _cancelOperationButton;
	private readonly TextBox _maintenanceReport;

	// Backup & Restore ----------------------------------------------------------------------------
	private readonly CheckBox _includeShardsCheck;
	private readonly Button _createBackupButton;
	private readonly Button _refreshBackupsButton;
	private readonly Button _verifyBackupButton;
	private readonly Button _restoreToFolderButton;
	private readonly Button _restoreOverLiveButton;
	private readonly DataGridView _backupsGrid;
	private readonly BindingList<BackupRow> _backupRows = new();
	private readonly Label _backupsStamp;
	private readonly TextBox _backupReport;

	// Shards --------------------------------------------------------------------------------------
	private readonly Button _shardsRefreshButton;
	private readonly Button _shardsSaveButton;
	private readonly Button _shardsCollectButton;
	private readonly Label _shardsStamp;
	private readonly Label _shardsSummaryLabel;
	private readonly Label _shardsBannerLabel;
	private readonly Panel _shardsBannerPanel;
	private readonly CheckBox _shardsEnabledCheck;
	private readonly TextBox _shardsRootInput;
	private readonly NumericUpDown _shardsCapacityInput;
	private readonly NumericUpDown _shardsMaxOpenWritersInput;
	private readonly NumericUpDown _shardsMaxShardFilesInput;
	private readonly NumericUpDown _shardsMaxShardBytesInput;
	private readonly NumericUpDown _shardsMaxTotalShardBytesInput;
	private readonly NumericUpDown _shardsMinFreeDiskBytesInput;
	private readonly NumericUpDown _shardsOrphanGraceDaysInput;
	private readonly CheckBox _shardsAggregationCheck;
	private readonly NumericUpDown _shardsAggregationTotalFilesInput;
	private readonly NumericUpDown _shardsAggregationNewFilesInput;
	private readonly NumericUpDown _shardsAggregationIntervalInput;
	private readonly NumericUpDown _shardsAggregationMinRowsInput;
	private readonly DataGridView _shardsGrid;
	private readonly BindingList<ShardRow> _shardRows = new();

	/// <summary>The shard policy as last reported by the service, which is what the Save flow diffs
	/// against. Null until a load has succeeded, so the editor never invents a baseline.</summary>
	private ShardingPolicyValuesDto? _lastShardPolicy;

	// Danger Zone ---------------------------------------------------------------------------------
	private readonly Label _dangerGateLabel;
	private readonly Button _dangerResetButton;
	private readonly Button _dangerClearDataButton;
	private readonly Button _dangerRestoreOverLiveButton;
	private readonly Button _dangerPurgeSubjectButton;
	private readonly Button _dangerCompactButton;
	private readonly TextBox _dangerReport;

	// Ledger --------------------------------------------------------------------------------------
	private readonly NumericUpDown _ledgerEventIdInput;
	private readonly DateTimePicker _ledgerFrom;
	private readonly DateTimePicker _ledgerTo;
	private readonly NumericUpDown _ledgerPageSizeInput;
	private readonly Button _ledgerRefreshButton;
	private readonly Button _ledgerPrevButton;
	private readonly Button _ledgerNextButton;
	private readonly Button _ledgerExportButton;
	private readonly Label _ledgerStamp;
	private readonly DataGridView _ledgerGrid;
	private readonly List<DeletionLedgerEntryDto> _ledgerRows = new();
	private int _ledgerPage;
	private long _ledgerTotal;

	/// <summary>Confirmation gate of EVERY irreversible or state-changing operation on this page: the
	/// retention save, both restore paths, the database reset, the application-data cleanup, the subject
	/// purge, the offline compaction, the shard policy save and the orphan collection. None of them proceeds
	/// when it answers false, and every caller reports the cancellation in the status line - so a test can
	/// assert both answers without opening a window. Defaults to the real modal dialog
	/// (<see cref="Confirm"/>), which is what production gets: the seam changes nothing unless a test
	/// replaces it.</summary>
	internal Func<string, string, bool> ConfirmPrompt { get; set; }

	/// <summary>File-picker seam for the deletion-ledger CSV export. Returns the target path, or null when
	/// the operator cancelled. Defaults to the real <see cref="SaveFileDialog"/>. It exists for the same
	/// reason as <see cref="ConfirmPrompt"/>: the export's paging loop and its cancelled path are behaviour
	/// worth asserting, and neither can be reached through a modal dialog in a test.</summary>
	internal Func<string?> ChooseLedgerExportPath { get; set; }

	// ── Construction ─────────────────────────────────────────────────────────────

	/// <summary>Builds the Database tab. The constructor performs no I/O: every service call happens
	/// from a button handler or the first HandleCreated, always asynchronously.</summary>
	public DatabasePage(IIpcClient ipc)
	{
		ArgumentNullException.ThrowIfNull(ipc);
		_ipc = ipc;
		Text = "Database";
		ConfirmPrompt = Confirm;
		ChooseLedgerExportPath = AskForLedgerExportPath;

		_statusStrip = new StatusStrip { SizingGrip = false };
		_statusLabel = new ToolStripStatusLabel("Ready.")
		{
			Spring = true,
			TextAlign = ContentAlignment.MiddleLeft,
		};
		_statusStrip.Items.Add(_statusLabel);

		// --- Overview ------------------------------------------------------------------------
		_overviewRefresh = new Button { Text = "Refresh", AutoSize = true, Margin = new Padding(2) };
		_overviewRefresh.Click += SafeAsyncHandler.Wrap(() => RefreshOverviewAsync(), ReportHandlerFailure);
		_overviewStamp = new Label { AutoSize = true, Margin = new Padding(10, 8, 0, 0), Text = "as of —" };
		_overviewReport = MakeMonospaceReport();

		// B25: the tamper verdict gets its own band above the report, in the same shape the Shards tab uses
		// for its capacity refusal. It starts in the WARNING treatment and says the verdict has not been read
		// yet - never a neutral "ok", because "we have not asked" is not "the store is intact".
		_overviewIntegrityBannerLabel = new Label
		{
			Dock = DockStyle.Fill,
			AutoSize = false,
			ForeColor = StatusDanger,
			Text = "Store integrity: not read yet. Press Refresh to ask the service for the fingerprint-chain "
				+ "verdict; until then the tamper evidence is UNVERIFIED.",
		};
		_overviewIntegrityBannerPanel = new Panel
		{
			Dock = DockStyle.Top,
			Height = 52,
			Padding = new Padding(6, 4, 6, 4),
			BackColor = RowDangerBack,
		};
		_overviewIntegrityBannerPanel.Controls.Add(_overviewIntegrityBannerLabel);

		// --- Retention -----------------------------------------------------------------------
		_policyEnabledCheck = new CheckBox { Text = "Enable information-density retention", AutoSize = true };
		_legalHoldCheck = new CheckBox { Text = "Legal hold (disables every pressure rule)", AutoSize = true };
		_anchorScopeCombo = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Width = 220, Anchor = AnchorStyles.Left };
		_anchorScopeCombo.Items.Add(new AnchorScopeChoice(RetentionAnchorScope.PerCode, "Per event code (EventId + Channel)"));
		_anchorScopeCombo.Items.Add(new AnchorScopeChoice(RetentionAnchorScope.PerCodeAndIp, "Per event code and source IP"));
		_anchorScopeCombo.SelectedIndex = 0;

		_tailKeepInput = MakeIntInput(1, RetentionPolicyOptions.MaxTailKeepPerCode, 512);
		_candidateMinRowsInput = MakeIntInput(1, 100_000_000, 1_000);
		_minAgeDaysInput = MakeIntInput(0, RetentionPolicyOptions.MaxMinAgeDays, 7);
		_maxRowsPerPassInput = MakeIntInput(1, 10_000_000, 50_000);
		_maxWriterLockMsInput = MakeIntInput(1, 60_000, 250);
		_deleteBatchRowsInput = MakeIntInput(1, RetentionPolicyOptions.MaxDeleteBatchRows, 2_000);
		_maxDatabaseBytesInput = MakeLongInput(0, 1_000_000_000_000_000, 0);
		_maxRawEventRowsInput = MakeLongInput(0, 1_000_000_000_000, 0);
		_minFreeDiskBytesInput = MakeLongInput(0, 1_000_000_000_000_000, 0);
		_protectedEventIdsInput = new TextBox { Dock = DockStyle.Fill, PlaceholderText = "Comma-separated event ids; empty keeps the built-in protected set" };

		_effectiveValuesLabel = new Label { AutoSize = true, MaximumSize = new Size(1400, 0), Margin = new Padding(0, 4, 0, 4) };

		_eventRetentionGrid = new DataGridView
		{
			Dock = DockStyle.Fill,
			AutoGenerateColumns = false,
			AllowUserToAddRows = false,
			AllowUserToDeleteRows = false,
			RowHeadersVisible = false,
			SelectionMode = DataGridViewSelectionMode.FullRowSelect,
			MultiSelect = true,
		};
		ConfigureEventRetentionColumns();
		_eventRetentionGrid.DataSource = _eventRetentionRows;
		_eventRetentionGrid.CurrentCellDirtyStateChanged += (_, _) =>
		{
			if (_eventRetentionGrid.IsCurrentCellDirty)
			{
				_eventRetentionGrid.CommitEdit(DataGridViewDataErrorContexts.Commit);
			}
		};
		_eventRetentionGrid.CellValidating += OnEventRetentionCellValidating;
		_eventRetentionGrid.DataError += (_, _) => SetStatus("Retention must be a whole number of days (0 means retain forever).", isError: true);
		SortableGrid.Enable(_eventRetentionGrid, _eventRetentionRows);
		// Bulk retention acts on the selected rows, so this grid stays single-select.
		DataGridClipboardMenu.AttachWithExport(_eventRetentionGrid, "Event retention policy", ReportExportStatus);

		_bulkRetentionDays = MakeIntInput(0, MaximumRetentionDays, 180);
		_bulkRetentionButton = MakeButton("Set selected retention", (_, _) => ApplyBulkRetention(selectedOnly: true));
		_bulkRetentionAllButton = MakeButton("Apply to all rows", (_, _) => ApplyBulkRetention(selectedOnly: false));
		_previewButton = MakeButton("Preview (dry-run)", SafeAsyncHandler.Wrap(() => PreviewRetentionAsync(), ReportHandlerFailure));
		_saveRetentionButton = MakeButton("Save policy…", SafeAsyncHandler.Wrap(() => SaveRetentionAsync(), ReportHandlerFailure));
		_reloadRetentionButton = MakeButton("Reload from service", SafeAsyncHandler.Wrap(() => LoadRetentionAsync(), ReportHandlerFailure));

		_previewGrid = new DataGridView
		{
			Dock = DockStyle.Fill,
			AutoGenerateColumns = false,
			ReadOnly = true,
			AllowUserToAddRows = false,
			RowHeadersVisible = false,
			SelectionMode = DataGridViewSelectionMode.FullRowSelect,
			MultiSelect = true,
		};
		ConfigurePreviewColumns();
		_previewGrid.DataSource = _previewRows;
		SortableGrid.Enable(_previewGrid, _previewRows);
		DataGridClipboardMenu.AttachWithExport(_previewGrid, "Retention preview steps", ReportExportStatus);
		_previewSteps = MakeMonospaceReport();

		// --- Maintenance ---------------------------------------------------------------------
		_rebuildStatsButton = MakeButton("Rebuild attack stats", SafeAsyncHandler.Wrap(() => RebuildAttackStatsAsync(), ReportHandlerFailure));
		_maintenanceReport = MakeMonospaceReport();

		// --- Operation bar (below the tab control, never disabled by BeginBusy) ---------------
		_cancelOperationButton = MakeButton("Cancel running operation", (_, _) => CancelRunningOperation());
		_cancelOperationButton.Enabled = false;

		// --- Backup & Restore ----------------------------------------------------------------
		_includeShardsCheck = new CheckBox
		{
			Text = "Include the shard tree (best-effort copy)",
			AutoSize = true,
		};
		new ToolTip().SetToolTip(
			_includeShardsCheck,
			"The shard tree is copied file by file while the service keeps appending: a shard written during "
			+ "the copy can be captured truncated. The database in the same snapshot is transactionally "
			+ "consistent. Re-check the shard tree after restoring a pair (docs/88).");
		_createBackupButton = MakeButton("Create snapshot", SafeAsyncHandler.Wrap(() => CreateBackupAsync(), ReportHandlerFailure));
		_refreshBackupsButton = MakeButton("Refresh list", SafeAsyncHandler.Wrap(() => LoadBackupsAsync(), ReportHandlerFailure));
		_verifyBackupButton = MakeButton("Verify selected", SafeAsyncHandler.Wrap(() => VerifySelectedBackupAsync(), ReportHandlerFailure));
		_restoreToFolderButton = MakeButton("Restore to folder…", SafeAsyncHandler.Wrap(() => RestoreToFolderAsync(), ReportHandlerFailure));
		_backupReport = MakeMonospaceReport();
		_restoreOverLiveButton = MakeButton("Restore over live database…", SafeAsyncHandler.Wrap(() => RestoreOverLiveAsync(_backupReport), ReportHandlerFailure));
		_backupRows.ListChanged += (_, _) => UpdateBackupButtonState();
		_backupsGrid = new DataGridView
		{
			Dock = DockStyle.Fill,
			AutoGenerateColumns = false,
			ReadOnly = true,
			AllowUserToAddRows = false,
			RowHeadersVisible = false,
			SelectionMode = DataGridViewSelectionMode.FullRowSelect,
			MultiSelect = false,
		};
		ConfigureBackupColumns();
		_backupsGrid.DataSource = _backupRows;
		_backupsGrid.SelectionChanged += (_, _) => UpdateBackupButtonState();
		SortableGrid.Enable(_backupsGrid, _backupRows);
		// Selection drives the restore/unlock buttons on this grid, so it stays single-select and the
		// export covers exactly one selected row.
		DataGridClipboardMenu.AttachWithExport(_backupsGrid, "Database backups", ReportExportStatus);
		_backupsStamp = new Label { AutoSize = true, Margin = new Padding(10, 8, 0, 0), Text = "as of —" };

		// --- Shards --------------------------------------------------------------------------
		_shardsRefreshButton = MakeButton("Refresh inventory", SafeAsyncHandler.Wrap(() => LoadShardsAsync(), ReportHandlerFailure));
		_shardsSaveButton = MakeButton("Save policy…", SafeAsyncHandler.Wrap(() => SaveShardsPolicyAsync(), ReportHandlerFailure));
		_shardsCollectButton = MakeButton("Collect orphans…", SafeAsyncHandler.Wrap(() => CollectShardGarbageAsync(), ReportHandlerFailure));
		_shardsSaveButton.Enabled = false;
		_shardsCollectButton.Enabled = false;
		_shardsStamp = new Label { AutoSize = true, Margin = new Padding(10, 8, 0, 0), Text = "as of —" };
		_shardsSummaryLabel = new Label { AutoSize = true, MaximumSize = new Size(1400, 0), Margin = new Padding(0, 4, 0, 4) };
		_shardsBannerLabel = new Label
		{
			Dock = DockStyle.Fill,
			AutoSize = false,
			ForeColor = StatusWarning,
			Text = "Capacity state: not read yet. Refresh the inventory to ask the service.",
		};
		_shardsBannerPanel = new Panel
		{
			Dock = DockStyle.Top,
			Height = 46,
			Padding = new Padding(6, 4, 6, 4),
		};
		_shardsBannerPanel.Controls.Add(_shardsBannerLabel);

		_shardsEnabledCheck = new CheckBox { Text = "Shard writing enabled", AutoSize = true, Margin = new Padding(0, 6, 12, 0) };
		_shardsRootInput = new TextBox { Width = 420, Anchor = AnchorStyles.Left };
		_shardsCapacityInput = MakeIntInput(1, 10_000_000, 1024);
		_shardsMaxOpenWritersInput = MakeIntInput(1, 1_000_000, 128);
		_shardsMaxShardFilesInput = MakeIntInput(0, 10_000_000, 4096);
		_shardsMaxShardBytesInput = MakeLongInput(0, long.MaxValue, 0);
		_shardsMaxTotalShardBytesInput = MakeLongInput(0, long.MaxValue, 0);
		_shardsMinFreeDiskBytesInput = MakeLongInput(0, long.MaxValue, 0);
		_shardsOrphanGraceDaysInput = MakeIntInput(1, 3650, 14);
		_shardsAggregationCheck = new CheckBox { Text = "Cardinality guard enabled", AutoSize = true, Margin = new Padding(0, 6, 12, 0) };
		_shardsAggregationTotalFilesInput = MakeIntInput(1, 10_000_000, 4096);
		_shardsAggregationNewFilesInput = MakeIntInput(1, 10_000_000, 64);
		_shardsAggregationIntervalInput = MakeIntInput(1, 86_400, 60);
		_shardsAggregationMinRowsInput = MakeIntInput(0, 10_000_000, 8);
		_shardsGrid = new DataGridView
		{
			Dock = DockStyle.Fill,
			AutoGenerateColumns = false,
			ReadOnly = true,
			AllowUserToAddRows = false,
			RowHeadersVisible = false,
			SelectionMode = DataGridViewSelectionMode.FullRowSelect,
			MultiSelect = true,
		};
		ConfigureShardColumns();
		_shardsGrid.DataSource = _shardRows;
		SortableGrid.Enable(_shardsGrid, _shardRows);
		DataGridClipboardMenu.AttachWithExport(_shardsGrid, "Database shards", ReportExportStatus);

		// --- Danger Zone ---------------------------------------------------------------------
		_dangerGateLabel = new Label
		{
			AutoSize = true,
			MaximumSize = new Size(1400, 0),
			Margin = new Padding(0, 4, 0, 8),
			ForeColor = StatusWarning,
			Text = "DEBUG mode and elevation are required to unlock these actions.",
		};
		_dangerReport = MakeMonospaceReport();
		_dangerResetButton = MakeButton("Back up and reset database…", SafeAsyncHandler.Wrap(() => ResetDatabaseAsync(), ReportHandlerFailure));
		_dangerClearDataButton = MakeButton("Clear all application data…", SafeAsyncHandler.Wrap(() => ClearAllApplicationDataAsync(), ReportHandlerFailure));
		_dangerRestoreOverLiveButton = MakeButton("Restore over live database…", SafeAsyncHandler.Wrap(() => RestoreOverLiveAsync(_dangerReport), ReportHandlerFailure));
		NewPurgeDialog = () => new PurgeBySubjectDialog(_ipc);
		_dangerPurgeSubjectButton = MakeButton("Purge by subject…", SafeAsyncHandler.Wrap(() => PurgeBySubjectAsync(), ReportHandlerFailure));
		_dangerCompactButton = MakeButton("Compact database (offline)…", SafeAsyncHandler.Wrap(() => CompactDatabaseOfflineAsync(), ReportHandlerFailure));

		// --- Ledger --------------------------------------------------------------------------
		_ledgerEventIdInput = MakeIntInput(0, 1_000_000, 0);
		_ledgerFrom = new DateTimePicker
		{
			Format = DateTimePickerFormat.Custom,
			CustomFormat = "yyyy-MM-dd HH:mm",
			ShowCheckBox = true,
			Checked = false,
			Width = 160,
			Anchor = AnchorStyles.Left,
		};
		_ledgerTo = new DateTimePicker
		{
			Format = DateTimePickerFormat.Custom,
			CustomFormat = "yyyy-MM-dd HH:mm",
			ShowCheckBox = true,
			Checked = false,
			Width = 160,
			Anchor = AnchorStyles.Left,
		};
		_ledgerPageSizeInput = MakeIntInput(1, 1000, 200);
		_ledgerRefreshButton = MakeButton("Refresh", SafeAsyncHandler.Wrap(() => LoadLedgerAsync(resetPage: true), ReportHandlerFailure));
		_ledgerPrevButton = MakeButton("◀ Prev", SafeAsyncHandler.Wrap(() => ChangeLedgerPageAsync(-1), ReportHandlerFailure));
		_ledgerNextButton = MakeButton("Next ▶", SafeAsyncHandler.Wrap(() => ChangeLedgerPageAsync(+1), ReportHandlerFailure));
		_ledgerPrevButton.Enabled = false;
		_ledgerNextButton.Enabled = false;
		_ledgerExportButton = MakeButton("Export CSV…", SafeAsyncHandler.Wrap(() => ExportLedgerCsvAsync(), ReportHandlerFailure));
		_ledgerStamp = new Label { AutoSize = true, Margin = new Padding(10, 8, 0, 0), Text = "as of —" };
		_ledgerGrid = new DataGridView
		{
			Dock = DockStyle.Fill,
			AutoGenerateColumns = false,
			ReadOnly = true,
			AllowUserToAddRows = false,
			RowHeadersVisible = false,
			SelectionMode = DataGridViewSelectionMode.FullRowSelect,
			MultiSelect = true,
		};
		ConfigureLedgerColumns();
		DataGridClipboardMenu.AttachWithExport(_ledgerGrid, "Evidence deletion ledger", ReportExportStatus);

		_innerTabs = new TabControl { Dock = DockStyle.Fill, MinimumSize = new Size(0, 300) };
		foreach (TabPage page in BuildInnerTabs())
		{
			_innerTabs.TabPages.Add(page);
		}

		// The cancel control lives OUTSIDE the tab control on purpose: BeginBusy disables _innerTabs, and
		// WinForms reports a control inside a disabled container as Enabled == false even when its own
		// flag is set, so a cancel button placed on a tab page would be unreachable exactly while it is
		// needed - for the whole length of a long integrity check or snapshot copy.
		FlowLayoutPanel operationBar = new()
		{
			Dock = DockStyle.Fill,
			FlowDirection = FlowDirection.LeftToRight,
			AutoSize = true,
			WrapContents = false,
			Padding = new Padding(2),
		};
		operationBar.Controls.Add(_cancelOperationButton);
		operationBar.Controls.Add(new Label
		{
			AutoSize = true,
			MaximumSize = new Size(1200, 0),
			Margin = new Padding(10, 8, 0, 0),
			Text = "Cancelling stops this client waiting; the service may still be completing the operation, so re-check the result before acting on it.",
		});

		TableLayoutPanel root = new() { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 3 };
		root.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
		root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
		root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
		root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
		root.Controls.Add(_innerTabs, 0, 0);
		root.Controls.Add(operationBar, 0, 1);
		root.Controls.Add(_statusStrip, 0, 2);
		Controls.Add(root);

		ApplyDangerZoneGate(debugMode: false, elevated: false);

		HandleCreated += SafeAsyncHandler.Wrap(LoadFirstViewAsync, ReportHandlerFailure);
	}

	/// <summary>First load, in order: the Danger Zone gate, the overview, the retention editor, the
	/// snapshot list, the shard inventory and the ledger. Runs once per handle creation; every step is
	/// awaited with ConfigureAwait(true) behind BeginBusy/EndBusy, so the creating thread is never
	/// blocked and a missing service only produces status messages.</summary>
	private async Task LoadFirstViewAsync()
	{
		await RefreshDangerZoneGateAsync().ConfigureAwait(true);
		await RefreshOverviewAsync().ConfigureAwait(true);
		await LoadRetentionAsync().ConfigureAwait(true);
		await LoadBackupsAsync().ConfigureAwait(true);
		await LoadShardsAsync().ConfigureAwait(true);
		await LoadLedgerAsync(resetPage: true).ConfigureAwait(true);
	}

	// ── Inner tab structure ──────────────────────────────────────────────────────

	/// <summary>The inner tab titles in display order. Exposed so a test can assert the structure
	/// without creating a window handle.</summary>
	internal static IReadOnlyList<string> InnerTabTitles { get; } = new[]
	{
		"Overview",
		"Retention",
		"Maintenance",
		"Backup & Restore",
		"Shards",
		"Danger Zone",
		"Ledger",
	};

	private TabPage[] BuildInnerTabs() => new TabPage[]
	{
		BuildOverviewTab(),
		BuildRetentionTab(),
		BuildMaintenanceTab(),
		BuildBackupTab(),
		BuildShardsTab(),
		BuildDangerZoneTab(),
		BuildLedgerTab(),
	};

	private TabPage BuildOverviewTab()
	{
		TabPage page = new() { Text = "Overview", Padding = new Padding(4) };
		FlowLayoutPanel bar = NewButtonBar();
		bar.Controls.Add(_overviewRefresh);
		bar.Controls.Add(_overviewStamp);
		bar.Controls.Add(new Label
		{
			AutoSize = true,
			Margin = new Padding(10, 8, 0, 0),
			Text = "Every figure below is as of the stamp above; a failed section is reported as an error, never as an empty value.",
		});

		// Dock order is decided by the order the controls are ADDED, last added first: the report fills what
		// is left, the banner takes the band under the button bar, and the bar sits on top. The banner is a
		// fixed band rather than a line inside the report, so the verdict is on screen without scrolling.
		page.Controls.Add(_overviewReport);
		page.Controls.Add(_overviewIntegrityBannerPanel);
		page.Controls.Add(bar);
		return page;
	}

	private TabPage BuildRetentionTab()
	{
		TabPage page = new() { Text = "Retention", Padding = new Padding(4) };

		FlowLayoutPanel bar = NewButtonBar();
		bar.Controls.Add(_previewButton);
		bar.Controls.Add(_saveRetentionButton);
		bar.Controls.Add(_reloadRetentionButton);
		bar.Controls.Add(new Label
		{
			AutoSize = true,
			Margin = new Padding(10, 8, 0, 0),
			Text = "Preview is read-only and predicts the exact rows a real pass deletes; Save shows the old → new diff first.",
		});

		GroupBox policyBox = new()
		{
			Text = "Information-density retention policy (Storage:RetentionPolicy)",
			Dock = DockStyle.Top,
			AutoSize = true,
			AutoSizeMode = AutoSizeMode.GrowAndShrink,
			Padding = new Padding(8),
		};
		TableLayoutPanel policyLayout = NewGrid(4, 9);
		policyLayout.ColumnStyles.Clear();
		policyLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 250));
		policyLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 150));
		policyLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 250));
		policyLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
		int row = 0;
		policyLayout.Controls.Add(_policyEnabledCheck, 0, row);
		policyLayout.SetColumnSpan(_policyEnabledCheck, 2);
		policyLayout.Controls.Add(_legalHoldCheck, 2, row);
		policyLayout.SetColumnSpan(_legalHoldCheck, 2);
		row++;
		policyLayout.Controls.Add(MakeFieldLabel("Anchor scope:"), 0, row);
		policyLayout.Controls.Add(_anchorScopeCombo, 1, row);
		policyLayout.Controls.Add(MakeFieldLabel("Tail keep per code:"), 2, row);
		policyLayout.Controls.Add(_tailKeepInput, 3, row);
		row++;
		policyLayout.Controls.Add(MakeFieldLabel("Candidate min rows:"), 0, row);
		policyLayout.Controls.Add(_candidateMinRowsInput, 1, row);
		policyLayout.Controls.Add(MakeFieldLabel("Min age (days):"), 2, row);
		policyLayout.Controls.Add(_minAgeDaysInput, 3, row);
		row++;
		policyLayout.Controls.Add(MakeFieldLabel("Max rows per pass:"), 0, row);
		policyLayout.Controls.Add(_maxRowsPerPassInput, 1, row);
		policyLayout.Controls.Add(MakeFieldLabel("Max writer lock (ms):"), 2, row);
		policyLayout.Controls.Add(_maxWriterLockMsInput, 3, row);
		row++;
		policyLayout.Controls.Add(MakeFieldLabel("Delete batch rows:"), 0, row);
		policyLayout.Controls.Add(_deleteBatchRowsInput, 1, row);
		policyLayout.Controls.Add(MakeFieldLabel("Max database bytes:"), 2, row);
		policyLayout.Controls.Add(_maxDatabaseBytesInput, 3, row);
		row++;
		policyLayout.Controls.Add(MakeFieldLabel("Max raw event rows:"), 0, row);
		policyLayout.Controls.Add(_maxRawEventRowsInput, 1, row);
		policyLayout.Controls.Add(MakeFieldLabel("Min free disk bytes:"), 2, row);
		policyLayout.Controls.Add(_minFreeDiskBytesInput, 3, row);
		row++;
		policyLayout.Controls.Add(MakeFieldLabel("Protected event ids:"), 0, row);
		policyLayout.Controls.Add(_protectedEventIdsInput, 1, row);
		policyLayout.SetColumnSpan(_protectedEventIdsInput, 3);
		row++;
		policyLayout.Controls.Add(_effectiveValuesLabel, 0, row);
		policyLayout.SetColumnSpan(_effectiveValuesLabel, 4);
		policyBox.Controls.Add(policyLayout);

		GroupBox globalBox = new()
		{
			Text = "Global retention windows, days (Storage)",
			Dock = DockStyle.Top,
			AutoSize = true,
			AutoSizeMode = AutoSizeMode.GrowAndShrink,
			Padding = new Padding(8),
		};
		TableLayoutPanel globalLayout = NewGrid(4, 4);
		globalLayout.ColumnStyles.Clear();
		globalLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 250));
		globalLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 90));
		globalLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 250));
		globalLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
		string[] windowNames =
		[
			"Raw events (default)",
			"Alerts",
			"Abuse reports",
			"Active blocks",
			"Attack stats",
			"Session/IP correlations",
			"RDP connection facts",
			"Operation logs",
		];
		for (int index = 0; index < windowNames.Length; index++)
		{
			_globalWindowInputs[index] = MakeIntInput(0, MaximumRetentionDays, 0);
			int cell = index % 2;
			int gridRow = index / 2;
			globalLayout.Controls.Add(MakeFieldLabel(windowNames[index] + ":"), cell * 2, gridRow);
			globalLayout.Controls.Add(_globalWindowInputs[index], (cell * 2) + 1, gridRow);
		}

		GroupBox eventBox = new()
		{
			Text = "Per-event-code windows (EventRetention) — 0 means retain forever",
			Dock = DockStyle.Fill,
			Padding = new Padding(8),
		};
		FlowLayoutPanel eventBar = NewButtonBar();
		eventBar.Controls.Add(new Label { AutoSize = true, Margin = new Padding(2, 8, 0, 0), Text = "Selected retention (days):" });
		eventBar.Controls.Add(_bulkRetentionDays);
		eventBar.Controls.Add(_bulkRetentionButton);
		eventBar.Controls.Add(_bulkRetentionAllButton);
		eventBox.Controls.Add(_eventRetentionGrid);
		eventBox.Controls.Add(eventBar);

		// Three panes side by side: the editable per-event grid, the dry-run result and the ordered
		// plan. A TableLayoutPanel (not a SplitContainer) because the page is built before it is
		// sized: SplitContainer refuses a SplitterDistance its MinSizes cannot satisfy on a
		// zero-width control and throws during construction, which would break every tab page that
		// constructs this one.
		Label planLabel = new()
		{
			Dock = DockStyle.Top,
			AutoSize = false,
			Height = 22,
			Text = "Planned steps, in the exact execution order a real pass would use:",
		};
		GroupBox planBox = new()
		{
			Text = "Planned steps",
			Dock = DockStyle.Fill,
			Padding = new Padding(8),
		};
		planBox.Controls.Add(_previewSteps);
		planBox.Controls.Add(planLabel);

		Label previewLabel = new()
		{
			Dock = DockStyle.Top,
			AutoSize = false,
			Height = 22,
			Text = "Preview result (read-only): code, channel, counts, planned rows and why a code is protected.",
		};
		GroupBox previewBox = new()
		{
			Text = "Dry-run preview",
			Dock = DockStyle.Fill,
			Padding = new Padding(8),
		};
		previewBox.Controls.Add(_previewGrid);
		previewBox.Controls.Add(previewLabel);

		// One page, stacked top-to-bottom: the policy panel, the global windows, then the editable
		// per-event grid beside the dry-run result and the ordered plan. A single scrollable host is
		// deliberate - the page has exactly ONE level of inner tabs (the seven the requirement names),
		// so the structure stays predictable and the tab-order test unambiguous.
		TableLayoutPanel policyRow = new()
		{
			Dock = DockStyle.Top,
			AutoSize = true,
			AutoSizeMode = AutoSizeMode.GrowAndShrink,
			ColumnCount = 1,
			RowCount = 2,
		};
		policyRow.RowStyles.Add(new RowStyle(SizeType.AutoSize));
		policyRow.RowStyles.Add(new RowStyle(SizeType.AutoSize));
		policyRow.Controls.Add(policyBox, 0, 0);
		policyRow.Controls.Add(globalBox, 0, 1);

		TableLayoutPanel previewRow = new()
		{
			Dock = DockStyle.Fill,
			MinimumSize = new Size(0, 300),
			ColumnCount = 3,
			RowCount = 1,
		};
		previewRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 45));
		previewRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 35));
		previewRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 20));
		previewRow.Controls.Add(eventBox, 0, 0);
		previewRow.Controls.Add(previewBox, 1, 0);
		previewRow.Controls.Add(planBox, 2, 0);

		TableLayoutPanel stack = new()
		{
			Dock = DockStyle.Fill,
			ColumnCount = 1,
			RowCount = 3,
			AutoScroll = true,
		};
		stack.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
		stack.RowStyles.Add(new RowStyle(SizeType.AutoSize));
		stack.RowStyles.Add(new RowStyle(SizeType.AutoSize));
		stack.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
		stack.Controls.Add(bar, 0, 0);
		stack.Controls.Add(policyRow, 0, 1);
		stack.Controls.Add(previewRow, 0, 2);

		page.Controls.Add(stack);
		return page;
	}

	private TabPage BuildMaintenanceTab()
	{
		TabPage page = new() { Text = "Maintenance", Padding = new Padding(4) };

		FlowLayoutPanel bar = NewButtonBar();
		bar.Controls.Add(_rebuildStatsButton);
		bar.Controls.Add(new Label
		{
			AutoSize = true,
			MaximumSize = new Size(900, 0),
			Margin = new Padding(10, 4, 0, 0),
			Text = "Read-safe actions only. Full VACUUM is intentionally not offered: it rewrites the whole file and can hold "
				+ "the writer lock for minutes on a multi-gigabyte evidence store (docs/88). Space already freed by deletions "
				+ "is reclaimed with a bounded incremental vacuum when the store's auto-vacuum mode is INCREMENTAL; the "
				+ "Overview tab states that mode and, on a store where it is not, says that only the offline compaction "
				+ "(Danger Zone) can return that space. A running action can be cancelled from the Cancel button "
				+ "under the tabs, which stays reachable while these buttons are disabled."
		});
		page.Controls.Add(_maintenanceReport);
		page.Controls.Add(bar);

		FlowLayoutPanel actions = new()
		{
			Dock = DockStyle.Top,
			FlowDirection = FlowDirection.LeftToRight,
			AutoSize = true,
			WrapContents = true,
			Padding = new Padding(2),
		};
		AddMaintenanceButton(actions, DatabaseMaintenanceKind.QuickCheck, "Quick check");
		AddMaintenanceButton(actions, DatabaseMaintenanceKind.FullIntegrityCheck, "Full integrity check");
		AddMaintenanceButton(actions, DatabaseMaintenanceKind.ForeignKeyCheck, "Foreign key check");
		AddMaintenanceButton(actions, DatabaseMaintenanceKind.WalCheckpointPassive, "WAL checkpoint (PASSIVE)");
		AddMaintenanceButton(actions, DatabaseMaintenanceKind.WalCheckpointTruncate, "WAL checkpoint (TRUNCATE)");
		AddMaintenanceButton(actions, DatabaseMaintenanceKind.IncrementalVacuum, "Incremental vacuum");
		AddMaintenanceButton(actions, DatabaseMaintenanceKind.Optimize, "PRAGMA optimize");
		page.Controls.Add(actions);
		actions.BringToFront();
		return page;
	}

	private TabPage BuildBackupTab()
	{
		TabPage page = new() { Text = "Backup & Restore", Padding = new Padding(4) };

		FlowLayoutPanel bar = NewButtonBar();
		bar.Controls.Add(_createBackupButton);
		bar.Controls.Add(_includeShardsCheck);
		bar.Controls.Add(_refreshBackupsButton);
		bar.Controls.Add(_verifyBackupButton);
		bar.Controls.Add(_restoreToFolderButton);
		bar.Controls.Add(_restoreOverLiveButton);
		bar.Controls.Add(_backupsStamp);
		bar.Controls.Add(new Label
		{
			AutoSize = true,
			Margin = new Padding(10, 8, 0, 0),
			Text = "A snapshot is one consistent online copy of the live store; restoring over the live store needs elevation and a stoppable service.",
		});

		// Snapshot grid above, report below; a TableLayoutPanel keeps the page constructible before it
		// is sized (see the note in BuildRetentionTab).
		TableLayoutPanel split = new() { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 2 };
		split.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
		split.RowStyles.Add(new RowStyle(SizeType.Percent, 55));
		split.RowStyles.Add(new RowStyle(SizeType.Percent, 45));
		split.Controls.Add(_backupsGrid, 0, 0);
		split.Controls.Add(_backupReport, 0, 1);

		page.Controls.Add(split);
		page.Controls.Add(bar);
		return page;
	}

	private TabPage BuildShardsTab()
	{
		TabPage page = new() { Text = "Shards", Padding = new Padding(4) };

		FlowLayoutPanel bar = NewButtonBar();
		bar.Controls.Add(_shardsRefreshButton);
		bar.Controls.Add(_shardsSaveButton);
		bar.Controls.Add(_shardsCollectButton);
		bar.Controls.Add(_shardsStamp);

		TableLayoutPanel policy = NewGrid(columns: 4, rows: 5);
		policy.Controls.Add(MakeFieldCell("Capacity records (ring)", _shardsCapacityInput), 0, 0);
		policy.Controls.Add(MakeFieldCell("Max open writers", _shardsMaxOpenWritersInput), 1, 0);
		policy.Controls.Add(MakeFieldCell("Max shard files", _shardsMaxShardFilesInput), 2, 0);
		policy.Controls.Add(MakeFieldCell("Orphan grace (days)", _shardsOrphanGraceDaysInput), 3, 0);
		policy.Controls.Add(MakeFieldCell("Max shard bytes (0 = off)", _shardsMaxShardBytesInput), 0, 1);
		policy.Controls.Add(MakeFieldCell("Max total shard bytes (0 = off)", _shardsMaxTotalShardBytesInput), 1, 1);
		policy.Controls.Add(MakeFieldCell("Min free disk bytes (0 = off)", _shardsMinFreeDiskBytesInput), 2, 1);
		policy.Controls.Add(MakeFieldCell("Actions root (empty = ProgramData)", _shardsRootInput), 3, 1);
		policy.Controls.Add(MakeFieldCell("Guard: total file threshold", _shardsAggregationTotalFilesInput), 0, 2);
		policy.Controls.Add(MakeFieldCell("Guard: new files per interval", _shardsAggregationNewFilesInput), 1, 2);
		policy.Controls.Add(MakeFieldCell("Guard: interval seconds", _shardsAggregationIntervalInput), 2, 2);
		policy.Controls.Add(MakeFieldCell("Guard: min source rows", _shardsAggregationMinRowsInput), 3, 2);
		policy.Controls.Add(_shardsEnabledCheck, 0, 3);
		policy.Controls.Add(_shardsAggregationCheck, 1, 3);
		Label saveHint = new()
		{
			AutoSize = true,
			MaximumSize = new Size(900, 0),
			Margin = new Padding(0, 6, 8, 0),
			Text = "Save writes the shard policy into appsettings.json and the service applies it without a restart. "
				+ "A per-shard byte ceiling selects the ring capacity of NEW shards; no existing .rdpshard is ever rewritten.",
		};
		policy.Controls.Add(saveHint, 2, 3);
		policy.SetColumnSpan(saveHint, 2);

		Label compaction = new()
		{
			Dock = DockStyle.Top,
			AutoSize = false,
			Height = 34,
			ForeColor = StatusWarning,
			Text = ShardCompactionStubText,
		};

		page.Controls.Add(_shardsGrid);
		page.Controls.Add(_shardsSummaryLabel);
		page.Controls.Add(_shardsBannerPanel);
		page.Controls.Add(compaction);
		page.Controls.Add(policy);
		page.Controls.Add(bar);
		return page;
	}

	/// <summary>One labelled policy field: a caption and its input, laid out left to right.</summary>
	private static FlowLayoutPanel MakeFieldCell(string caption, Control input)
	{
		FlowLayoutPanel cell = new()
		{
			AutoSize = true,
			FlowDirection = FlowDirection.LeftToRight,
			WrapContents = false,
			Margin = new Padding(0, 2, 12, 2),
		};
		cell.Controls.Add(MakeFieldLabel(caption));
		cell.Controls.Add(input);
		return cell;
	}

	private TabPage BuildDangerZoneTab()
	{
		TabPage page = new() { Text = "Danger Zone", Padding = new Padding(4) };

		FlowLayoutPanel bar = NewButtonBar();
		bar.Controls.Add(_dangerResetButton);
		bar.Controls.Add(_dangerClearDataButton);
		bar.Controls.Add(_dangerRestoreOverLiveButton);
		bar.Controls.Add(_dangerPurgeSubjectButton);
		bar.Controls.Add(_dangerCompactButton);
		bar.Controls.Add(new Label
		{
			AutoSize = true,
			MaximumSize = new Size(900, 0),
			Margin = new Padding(10, 4, 0, 0),
			Text = "Every action here needs DEBUG mode (Settings → Diagnostics.DebugMode), elevation and a typed confirmation phrase. "
				+ "Each produces a report below.",
		});
		Label purgeStub = new()
		{
			Dock = DockStyle.Top,
			AutoSize = false,
			Height = 22,
			Text = PurgeStubText,
		};

		TableLayoutPanel header = new() { Dock = DockStyle.Top, AutoSize = true, ColumnCount = 1, RowCount = 3 };
		header.Controls.Add(_dangerGateLabel, 0, 0);
		header.Controls.Add(bar, 0, 1);
		header.Controls.Add(purgeStub, 0, 2);

		page.Controls.Add(_dangerReport);
		page.Controls.Add(header);
		return page;
	}

	private TabPage BuildLedgerTab()
	{
		TabPage page = new() { Text = "Ledger", Padding = new Padding(4) };

		FlowLayoutPanel filters = new()
		{
			Dock = DockStyle.Top,
			AutoSize = true,
			WrapContents = false,
			AutoScroll = true,
			Padding = new Padding(2),
		};
		filters.Controls.Add(new Label { AutoSize = true, Margin = new Padding(2, 8, 0, 0), Text = "Event id:" });
		filters.Controls.Add(_ledgerEventIdInput);
		filters.Controls.Add(new Label { AutoSize = true, Margin = new Padding(8, 8, 0, 0), Text = "Deleted from:" });
		filters.Controls.Add(_ledgerFrom);
		filters.Controls.Add(new Label { AutoSize = true, Margin = new Padding(8, 8, 0, 0), Text = "to:" });
		filters.Controls.Add(_ledgerTo);
		filters.Controls.Add(new Label { AutoSize = true, Margin = new Padding(8, 8, 0, 0), Text = "Page size:" });
		filters.Controls.Add(_ledgerPageSizeInput);
		filters.Controls.Add(_ledgerRefreshButton);
		filters.Controls.Add(_ledgerPrevButton);
		filters.Controls.Add(_ledgerNextButton);
		filters.Controls.Add(_ledgerExportButton);
		filters.Controls.Add(_ledgerStamp);

		page.Controls.Add(_ledgerGrid);
		page.Controls.Add(filters);
		return page;
	}

	// ── Overview ─────────────────────────────────────────────────────────────────

	/// <summary>Loads the sectioned overview and renders it as a monospace report. A section that
	/// failed on the service side keeps its error line, so a partial snapshot can never be read as
	/// "the store is empty".</summary>
	internal async Task RefreshOverviewAsync(bool manageBusy = true)
	{
		if (manageBusy && !BeginBusy())
		{
			return;
		}

		try
		{
			IpcCallResult<DatabaseOverviewDto> call =
				await _ipc.SendDetailedAsync<DatabaseOverviewDto>(IpcCommand.GetDatabaseOverview, null, CurrentToken())
					.ConfigureAwait(true);
			if (!call.IsSuccess || call.Value is not { } overview)
			{
				SetStatus("Database overview unavailable: " + call.Headline(), isError: true);
				_overviewStamp.Text = "as of —";
				_overviewReport.Text = "The overview could not be read.\r\n\r\n" + call.Headline();

				// B25: no overview means no verdict. The banner says UNKNOWN in the error treatment - the one
				// thing it must never do here is keep whatever it showed before, or claim the store is intact.
				SetIntegrityBanner(
					StoreIntegrityVerdictBand.Unknown,
					"Store integrity: UNKNOWN - the overview could not be read, so no fingerprint-chain verdict "
						+ "was obtained. The tamper evidence of this store is NOT verified. " + call.Headline());
				return;
			}

			if (!string.IsNullOrWhiteSpace(overview.DatabasePath))
			{
				_lastDatabasePath = overview.DatabasePath;
			}

			_overviewStamp.Text = "as of " + AsOf(overview.QueriedUtc) + (overview.IsPartial ? " (partial)" : string.Empty);
			_overviewReport.Text = FormatOverview(overview);

			// B25: the banner mirrors the report's verdict, derived from the same field by the same rules the
			// report uses, so the two can never disagree.
			SetIntegrityBanner(IntegrityVerdictOf(overview).Band, DescribeIntegrityBanner(overview));
			SetStatus(overview.IsPartial
				? "Database overview loaded (partial — see the warnings in the report)."
				: "Database overview loaded.", isError: overview.IsPartial);
		}
		catch (Exception ex)
		{
			SetStatus("Database overview failed: " + ex.GetType().Name, isError: true);
			SetIntegrityBanner(
				StoreIntegrityVerdictBand.Unknown,
				"Store integrity: UNKNOWN - reading the overview failed (" + ex.GetType().Name + "), so no "
					+ "fingerprint-chain verdict was obtained. The tamper evidence of this store is NOT verified.");
		}
		finally
		{
			if (manageBusy)
			{
				EndBusy();
			}
		}
	}

	/// <summary>Renders the overview DTO. Pure and static so a test can assert the rendering rules
	/// (stamp present, failed section visible as an error, no invented numbers).</summary>
	/// <summary>One line about what the ingest writer did when a batch failed to persist. The counters
	/// are cumulative since the service started; a restart resets them, so the wording says so instead of
	/// implying a lifetime total.</summary>
	internal static string DescribePersistPipeline(DatabaseOverviewDto overview)
	{
		if (overview.PersistBatchRetainedCount < 0 || overview.PersistBatchStalledCount < 0)
		{
			return "unknown (the service reported no persistence counter)";
		}

		if (overview.PersistBatchRetainedCount == 0)
		{
			return "no batch failed to persist since the service started";
		}

		return overview.PersistBatchRetainedCount.ToString(CultureInfo.InvariantCulture)
			+ " batch(es) kept in memory for retry since the service started, "
			+ overview.PersistBatchStalledCount.ToString(CultureInfo.InvariantCulture)
			+ " of them past the 10-minute stall threshold — ingest pauses while a batch is retained "
			+ "instead of discarding evidence";
	}

	internal static string FormatOverview(DatabaseOverviewDto overview)
	{
		StringBuilder sb = new();
		sb.AppendLine("RdpAudit evidence store — overview");
		sb.AppendLine("=================================");
		sb.AppendLine("As of (UTC):       " + overview.QueriedUtc.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture));
		sb.AppendLine("Partial:           " + (overview.IsPartial ? "yes" : "no"));
		sb.AppendLine();
		sb.AppendLine("Database path:     " + overview.DatabasePath);
		sb.AppendLine("Database bytes:    " + DescribeBytes(overview.DatabaseBytes));
		sb.AppendLine("WAL bytes:         " + DescribeBytes(overview.WalBytes));
		sb.AppendLine("SHM bytes:         " + DescribeBytes(overview.ShmBytes));
		sb.AppendLine("Family total:      " + DescribeBytes(overview.TotalDatabaseFamilyBytes));
		sb.AppendLine("Database volume:   " + overview.DatabaseVolumeRoot
			+ " free " + DescribeBytes(overview.DatabaseVolumeFreeBytes ?? -1)
			+ " of " + DescribeBytes(overview.DatabaseVolumeTotalBytes ?? -1));
		sb.AppendLine("Shard volume:      " + overview.ActionsVolumeRoot
			+ " free " + DescribeBytes(overview.ActionsVolumeFreeBytes ?? -1)
			+ " of " + DescribeBytes(overview.ActionsVolumeTotalBytes ?? -1));
		sb.AppendLine("Shard tree:        " + overview.ActionsRoot);
		sb.AppendLine("Shard tree bytes:  " + DescribeBytes(overview.ActionsBytes)
			+ (overview.ActionsScanTruncated ? " (walk truncated — lower bound)" : string.Empty));
		sb.AppendLine("Shard tree files:  " + overview.ActionsFileCount.ToString(CultureInfo.InvariantCulture)
			+ ", shards " + overview.ShardCount.ToString(CultureInfo.InvariantCulture)
			+ " of " + overview.MaxShardFiles.ToString(CultureInfo.InvariantCulture) + " max");
		sb.AppendLine();
		sb.AppendLine("Auto-vacuum mode:  " + (overview.AutoVacuumMode is { } autoVacuum
			? DatabaseCompactService.DescribeAutoVacuumMode(autoVacuum)
			: "unknown (the pragma could not be read)"));
		sb.AppendLine("Journal mode:      " + (string.IsNullOrEmpty(overview.JournalMode) ? "unknown" : overview.JournalMode));
		sb.AppendLine("Pages:             " + (overview.PageSize?.ToString(CultureInfo.InvariantCulture) ?? "unknown")
			+ " bytes each, " + (overview.PageCount?.ToString(CultureInfo.InvariantCulture) ?? "unknown") + " page(s)");
		sb.AppendLine("Free pages:        " + (overview.FreeListPages?.ToString(CultureInfo.InvariantCulture) ?? "unknown")
			+ (overview.ReclaimableBytes is { } reclaimable
				? " (" + DescribeBytes(reclaimable) + " currently allocated to them)"
				: string.Empty));
		if (!string.IsNullOrEmpty(overview.SpaceReclamationNote))
		{
			sb.AppendLine("Space reclamation: " + overview.SpaceReclamationNote);
		}
		sb.AppendLine("Ingest persistence: " + DescribePersistPipeline(overview));
		sb.AppendLine();
		sb.AppendLine("Growth (day/week/month): " + DescribeBytes(overview.GrowthBytesDay ?? -1)
			+ " / " + DescribeBytes(overview.GrowthBytesWeek ?? -1)
			+ " / " + DescribeBytes(overview.GrowthBytesMonth ?? -1));
		sb.AppendLine("Projected days to cap:   " + (overview.ProjectedDaysToCap?.ToString(CultureInfo.InvariantCulture) ?? "unknown"));
		if (!string.IsNullOrEmpty(overview.GrowthNote))
		{
			sb.AppendLine("Growth note:             " + overview.GrowthNote);
		}

		sb.AppendLine();
		sb.AppendLine("Retention policy enabled: " + overview.RetentionPolicyEnabled
			+ "; legal hold: " + overview.LegalHold);
		sb.AppendLine("Ceilings: database(bytes)=" + overview.MaxDatabaseBytes.ToString(CultureInfo.InvariantCulture)
			+ " rawEventRows=" + overview.MaxRawEventRows.ToString(CultureInfo.InvariantCulture)
			+ " minFreeDisk(bytes)=" + overview.MinFreeDiskBytes.ToString(CultureInfo.InvariantCulture));
		sb.AppendLine("Ledger: entries=" + overview.LedgerEntryCount.ToString(CultureInfo.InvariantCulture)
			+ " removedRows=" + overview.LedgerRowsDeleted.ToString(CultureInfo.InvariantCulture)
			+ " last=" + (overview.LedgerLastCreatedUtc?.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture) ?? "never"));
		sb.AppendLine();
		sb.AppendLine("Migrations applied: " + overview.AppliedMigrations.Count.ToString(CultureInfo.InvariantCulture)
			+ ", pending: " + overview.PendingMigrations.Count.ToString(CultureInfo.InvariantCulture));
		sb.AppendLine("Migration-failure marker: " + (overview.MigrationFailureMarkerPresent
			? "PRESENT since " + (overview.MigrationFailureUtc?.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture) ?? "(unknown)")
				+ " — " + (overview.MigrationFailureMessage ?? "(no message)")
			: "absent"));
		sb.AppendLine();
		sb.AppendLine("Backups: enabled=" + overview.BackupEnabled
			+ " preMigrationEnabled=" + overview.PreMigrationBackupEnabled
			+ " snapshots=" + overview.BackupSnapshotCount.ToString(CultureInfo.InvariantCulture)
			+ " retentionCopies=" + overview.BackupRetentionCopies.ToString(CultureInfo.InvariantCulture));
		sb.AppendLine("Backup directory:  " + overview.BackupDirectory);
		sb.AppendLine("Newest snapshot:   " + (overview.BackupLastSnapshotDirectory ?? "(none)")
			+ (overview.BackupLastCreatedUtc is { } created
				? " at " + created.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture)
				: string.Empty));
		if (!string.IsNullOrEmpty(overview.BackupNote))
		{
			sb.AppendLine("Backup note:       " + overview.BackupNote);
		}

		AppendIntegritySection(sb, overview);

		sb.AppendLine();
		sb.AppendLine("Row counts:");
		foreach (DatabaseTableRowCountDto table in overview.TableRowCounts)
		{
			sb.AppendLine("  " + table.Table.PadRight(28)
				+ (table.RowCount >= 0
					? table.RowCount.ToString(CultureInfo.InvariantCulture)
					: "ERROR: " + (table.Error ?? "the count could not be read")));
		}

		sb.AppendLine();
		sb.AppendLine("Sections:");
		foreach (DatabaseOverviewSectionDto section in overview.Sections)
		{
			string marker = section.Status == "Completed" ? "[OK ]" : "[!! ]";
			sb.AppendLine("  " + marker + " " + section.Section.PadRight(18)
				+ section.Status + " (" + section.DurationMs.ToString(CultureInfo.InvariantCulture) + " ms)"
				+ (string.IsNullOrEmpty(section.Error) ? string.Empty : " — " + section.Error));
		}

		if (overview.Warnings.Count > 0)
		{
			sb.AppendLine();
			sb.AppendLine("Warnings:");
			foreach (string warning in overview.Warnings)
			{
				sb.AppendLine("  - " + warning);
			}
		}

		return sb.ToString();
	}

	// ── Integrity / tamper evidence (B25) ────────────────────────────────────────

	/// <summary>Name of the overview section the service uses for the fingerprint-chain read. The banner and
	/// the report key on it to decide whether a verdict was actually obtained: a snapshot that lists no
	/// completed <c>Fingerprint</c> section carries no verdict, whatever the other fields happen to hold.</summary>
	internal const string FingerprintSectionName = "Fingerprint";

	/// <summary>Column the integrity section pads its labels to, wide enough for its longest label
	/// ("Last clean-shutdown fingerprint:") so every value starts at the same column.</summary>
	private const int IntegrityLabelWidth = 32;

	/// <summary>The verdict the banner and the report both render: its band, a one-line headline and the
	/// sentences behind it. Pure and static, so the two surfaces provably read one decision.
	/// <para>
	/// The band is <see cref="StoreIntegrityVerdictBand.Unknown"/> - never <c>Ok</c> - whenever no verdict was
	/// obtained. Three cases produce that, and all three are reachable in production:
	/// the service reported a non-Success status, the snapshot lists no COMPLETED
	/// <see cref="FingerprintSectionName"/> section (a partial snapshot whose integrity read failed or never
	/// ran), or the state field is null (a host that does not carry the fingerprint store). "We did not read
	/// it" must never render as "it is intact".
	/// </para>
	/// <para>
	/// A partial snapshot whose <c>Fingerprint</c> section DID complete keeps the band of the state it
	/// reported: the verdict is a real reading of the chain and downgrading a <c>chain-broken</c> alarm to
	/// "unknown" because an unrelated section timed out would hide exactly the alarm this exists to raise.
	/// The report and the banner both name the partiality in that case, so the reading is never presented as
	/// an unqualified pass.
	/// </para>
	/// </summary>
	internal static (StoreIntegrityVerdictBand Band, string Headline, string Detail) IntegrityVerdictOf(
		DatabaseOverviewDto overview)
	{
		ArgumentNullException.ThrowIfNull(overview);

		bool succeeded = overview.Status == IpcResultStatus.Success;
		bool sectionCompleted = FingerprintSectionCompleted(overview);
		if (!StoreFingerprintChainVerdict.WasReported(succeeded, sectionCompleted, overview.FingerprintChainState))
		{
			string reason = !succeeded
				? "the service reported " + overview.Status + " for this snapshot"
				: !sectionCompleted
					? "this snapshot carries no completed '" + FingerprintSectionName + "' section"
						+ (overview.IsPartial ? ", so the snapshot is partial" : string.Empty)
					: "the service reported no chain state";
			return (
				StoreIntegrityVerdictBand.Unknown,
				StoreFingerprintChainVerdict.DescribeNotReported(reason),
				string.Empty);
		}

		return (
			StoreFingerprintChainVerdict.BandOf(overview.FingerprintChainState),
			StoreFingerprintChainVerdict.Describe(overview.FingerprintChainState),
			overview.FingerprintChainMessage ?? string.Empty);
	}

	/// <summary>True when the snapshot lists a COMPLETED fingerprint section, i.e. the read that produces the
	/// verdict ran to completion in this snapshot.</summary>
	private static bool FingerprintSectionCompleted(DatabaseOverviewDto overview) =>
		overview.Sections.Any(section =>
			string.Equals(section.Section, FingerprintSectionName, StringComparison.Ordinal)
			&& string.Equals(section.Status, "Completed", StringComparison.Ordinal));

	/// <summary>The banner text: the verdict's own words first, then the facts an operator acts on. Kept to
	/// two short lines so it stays readable as a fixed band above the report.</summary>
	internal static string DescribeIntegrityBanner(DatabaseOverviewDto overview)
	{
		(StoreIntegrityVerdictBand band, string headline, string detail) = IntegrityVerdictOf(overview);

		string state = StoreFingerprintChainVerdict.LabelOf(overview.FingerprintChainState);
		StringBuilder sb = new();
		sb.Append("Store integrity: ").Append(headline);
		if (!string.IsNullOrWhiteSpace(detail)
			&& !string.Equals(detail, headline, StringComparison.Ordinal))
		{
			sb.Append(' ').Append(detail);
		}

		sb.AppendLine();
		sb.Append("fingerprint chain: ").Append(band == StoreIntegrityVerdictBand.Unknown
			&& string.IsNullOrWhiteSpace(overview.FingerprintChainState)
			? state + " (state not reported)"
			: state + " (" + overview.FingerprintChainEntryCount.ToString(CultureInfo.InvariantCulture)
				+ " entr(ies))");
		sb.Append("; mirror: ").Append(DescribeMirror(overview.FingerprintChainMirrorAvailable));
		sb.Append("; anomaly marker: ").Append(overview.IntegrityAnomalyMarkerPresent ? "PRESENT" : "absent");
		sb.Append("; as of ").Append(AsOf(overview.QueriedUtc));
		if (overview.IsPartial)
		{
			sb.Append(" (snapshot partial)");
		}

		return sb.ToString();
	}

	/// <summary>The screen colour of a band. One function, used by the setter and asserted by the tests, so
	/// the palette cannot drift between the two.</summary>
	internal static Color IntegrityBannerBackFor(StoreIntegrityVerdictBand band) => band switch
	{
		StoreIntegrityVerdictBand.Ok => PanelBack,
		StoreIntegrityVerdictBand.Warning => RowWarningBack,
		_ => RowDangerBack,
	};

	/// <summary>The text colour of a band. <see cref="StoreIntegrityVerdictBand.Unknown"/> is deliberately
	/// the error treatment: an unread verdict is louder than a verified one, never quieter.</summary>
	internal static Color IntegrityBannerForeFor(StoreIntegrityVerdictBand band) => band switch
	{
		StoreIntegrityVerdictBand.Ok => StatusFore,
		StoreIntegrityVerdictBand.Warning => StatusWarning,
		_ => StatusDanger,
	};

	/// <summary>Applies a band and its text to the Overview banner.</summary>
	private void SetIntegrityBanner(StoreIntegrityVerdictBand band, string text)
	{
		_overviewIntegrityBand = band;
		_overviewIntegrityBannerLabel.Text = text;
		_overviewIntegrityBannerLabel.ForeColor = IntegrityBannerForeFor(band);
		_overviewIntegrityBannerPanel.BackColor = IntegrityBannerBackFor(band);
	}

	private static string DescribeMirror(bool? mirrorAvailable) => mirrorAvailable switch
	{
		true => "available outside the integrity folder",
		false => "NOT available - the sealed tip is the only second store",
		null => "unknown (the chain was not verified)",
	};

	/// <summary>Renders the "Integrity / tamper evidence" section: the fingerprint-chain verdict and its five
	/// states, the fingerprint timestamps, the anomaly marker and the ledger-chain verification, each with
	/// the same "as of" stamp the rest of the overview uses.</summary>
	private static void AppendIntegritySection(StringBuilder sb, DatabaseOverviewDto overview)
	{
		(StoreIntegrityVerdictBand band, string headline, string detail) = IntegrityVerdictOf(overview);

		sb.AppendLine();
		sb.AppendLine("Integrity / tamper evidence");
		sb.AppendLine("---------------------------");
		sb.AppendLine("As of (UTC):".PadRight(IntegrityLabelWidth)
			+ overview.QueriedUtc.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture)
			+ (overview.IsPartial ? " (snapshot partial)" : string.Empty));
		sb.AppendLine("Verdict:".PadRight(IntegrityLabelWidth) + DescribeBand(band));
		sb.AppendLine("Verdict detail:".PadRight(IntegrityLabelWidth) + headline);
		sb.AppendLine("Fingerprint chain state:".PadRight(IntegrityLabelWidth)
			+ StoreFingerprintChainVerdict.LabelOf(overview.FingerprintChainState)
			+ (string.IsNullOrWhiteSpace(overview.FingerprintChainState)
				? " (not reported — this is NOT a pass)"
				: string.Empty));
		sb.AppendLine("Fingerprint chain entries:".PadRight(IntegrityLabelWidth)
			+ overview.FingerprintChainEntryCount.ToString(CultureInfo.InvariantCulture));
		sb.AppendLine("Fingerprint mirror:".PadRight(IntegrityLabelWidth)
			+ DescribeMirror(overview.FingerprintChainMirrorAvailable));
		sb.AppendLine("Last clean-shutdown fingerprint:".PadRight(IntegrityLabelWidth)
			+ DescribeUtc(overview.FingerprintCleanShutdownUtc));
		sb.AppendLine("Last periodic fingerprint:".PadRight(IntegrityLabelWidth)
			+ DescribeUtc(overview.FingerprintPeriodicUtc));
		sb.AppendLine("Anomaly marker:".PadRight(IntegrityLabelWidth)
			+ (overview.IntegrityAnomalyMarkerPresent ? "PRESENT" : "absent"));
		if (overview.IntegrityAnomalyMarkerPresent && !string.IsNullOrWhiteSpace(overview.IntegrityAnomalyDetail))
		{
			foreach (string line in overview.IntegrityAnomalyDetail.Replace("\r\n", "\n").Split('\n'))
			{
				sb.AppendLine("    " + line);
			}
		}

		sb.AppendLine("Ledger chain intact:".PadRight(IntegrityLabelWidth) + DescribeFlag(overview.LedgerChainIntact));
		sb.AppendLine("Ledger chained rows:".PadRight(IntegrityLabelWidth)
			+ DescribeCount(overview.LedgerChainedRows));
		sb.AppendLine("Ledger unchained rows:".PadRight(IntegrityLabelWidth)
			+ DescribeCount(overview.LedgerUnchainedRows)
			+ (overview.LedgerUnchainedRows > 0
				? " (written before the chain existed: not verifiable, not a break)"
				: string.Empty));
		if (!string.IsNullOrWhiteSpace(overview.LedgerChainMessage))
		{
			sb.AppendLine("Ledger chain message:".PadRight(IntegrityLabelWidth) + overview.LedgerChainMessage);
		}

		sb.AppendLine("Last quick check:".PadRight(IntegrityLabelWidth)
			+ DescribeCheck(overview.LastQuickCheck, "never run"));
		sb.AppendLine("Last full integrity check:".PadRight(IntegrityLabelWidth)
			+ DescribeCheck(overview.LastFullIntegrityCheck, "never run (the full check is opt-in)"));
		sb.AppendLine("Last ledger-chain check:".PadRight(IntegrityLabelWidth)
			+ DescribeCheck(overview.LastLedgerChainCheck, "never run"));

		if (!string.IsNullOrWhiteSpace(detail)
			&& !string.Equals(detail, headline, StringComparison.Ordinal))
		{
			sb.AppendLine("Fingerprint chain message:".PadRight(IntegrityLabelWidth) + detail);
		}
	}

	/// <summary>The band as the word the operator reads. The band, not the state string, decides it: an
	/// unrecognised state must not be labelled as a pass.</summary>
	private static string DescribeBand(StoreIntegrityVerdictBand band) => band switch
	{
		StoreIntegrityVerdictBand.Ok => "OK — the fingerprint chain verifies",
		StoreIntegrityVerdictBand.Warning => "WARNING — reported, not attributable to tampering",
		StoreIntegrityVerdictBand.Error => "ERROR — recorded state is missing, unreadable or inconsistent",
		_ => "UNKNOWN — no verdict was obtained; this is NOT a pass",
	};

	private static string DescribeCheck(DatabaseIntegrityCheckRowDto? row, string whenAbsent) =>
		row is null
			? whenAbsent
			: row.Outcome + " at " + row.CompletedUtc.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture)
				+ " (" + row.DurationMs.ToString(CultureInfo.InvariantCulture) + " ms, " + row.InitiatedBy + ")"
				+ (string.IsNullOrWhiteSpace(row.Detail) ? string.Empty : " — " + row.Detail);

	private static string DescribeCount(long value) =>
		value < 0 ? "not inspected" : value.ToString(CultureInfo.InvariantCulture);

	private static string DescribeFlag(bool? value) => value switch
	{
		true => "yes",
		false => "NO — the chain does not verify",
		null => "not inspected (this is not a pass)",
	};

	private static string DescribeUtc(DateTime? value) =>
		value?.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture) ?? "never captured";

	/// <summary>Test surface: the banner text exactly as rendered.</summary>
	internal string IntegrityBannerText => _overviewIntegrityBannerLabel.Text;

	/// <summary>Test surface: the band the banner is showing.</summary>
	internal StoreIntegrityVerdictBand IntegrityBannerBand => _overviewIntegrityBand;

	/// <summary>Test surface: true when the banner is NOT in the neutral treatment.</summary>
	internal bool IntegrityBannerShowsAlarm => _overviewIntegrityBannerPanel.BackColor != PanelBack;

	/// <summary>Test surface: the banner's current face colour, so a test can assert that it follows the band
	/// - and that applying the dark theme did not repaint it to the neutral surface.</summary>
	internal Color IntegrityBannerBackColor => _overviewIntegrityBannerPanel.BackColor;

	// ── Retention ────────────────────────────────────────────────────────────────

	/// <summary>Loads the effective policy, the global windows and the per-event overrides into the
	/// editor, and keeps the loaded DTO so Save can show an old → new diff.</summary>
	internal async Task LoadRetentionAsync()
	{
		if (!BeginBusy())
		{
			return;
		}

		try
		{
			IpcCallResult<RetentionPolicyDto> call =
				await _ipc.SendDetailedAsync<RetentionPolicyDto>(IpcCommand.GetRetentionPolicy, null, CurrentToken())
					.ConfigureAwait(true);
			if (!call.IsSuccess || call.Value is not { } policy)
			{
				SetStatus("Retention policy unavailable: " + call.Headline(), isError: true);
				return;
			}

			ApplyPolicyToControls(policy);
			SetStatus(string.Format(
				CultureInfo.InvariantCulture,
				"Retention policy loaded as of {0} ({1} per-event override(s){2}).",
				AsOf(policy.QueriedUtc),
				policy.EventWindows.Count,
				policy.EventWindowsUnavailable ? " — the override table could not be read" : string.Empty),
				isError: policy.EventWindowsUnavailable);
		}
		catch (Exception ex)
		{
			SetStatus("Retention policy failed: " + ex.GetType().Name, isError: true);
		}
		finally
		{
			EndBusy();
		}
	}

	/// <summary>Maps a policy DTO onto the editor controls. Exposed to tests so the mapping can be
	/// asserted without a live service.</summary>
	internal void ApplyPolicyToControls(RetentionPolicyDto policy)
	{
		ArgumentNullException.ThrowIfNull(policy);
		_lastPolicy = policy;
		RetentionPolicyValuesDto values = policy.Policy;
		_policyEnabledCheck.Checked = values.Enabled;
		_legalHoldCheck.Checked = values.LegalHold;
		SelectAnchorScope(values.AnchorScope);
		SetNumeric(_tailKeepInput, values.EffectiveTailKeepPerCode);
		SetNumeric(_candidateMinRowsInput, values.EffectiveCandidateMinRows);
		SetNumeric(_minAgeDaysInput, values.EffectiveMinAgeDays);
		SetNumeric(_maxRowsPerPassInput, values.EffectiveMaxRowsPerPass);
		SetNumeric(_maxWriterLockMsInput, values.EffectiveMaxWriterLockMs);
		SetNumeric(_deleteBatchRowsInput, values.EffectiveDeleteBatchRows);
		SetNumeric(_maxDatabaseBytesInput, values.EffectiveMaxDatabaseBytes);
		SetNumeric(_maxRawEventRowsInput, values.EffectiveMaxRawEventRows);
		SetNumeric(_minFreeDiskBytesInput, values.EffectiveMinFreeDiskBytes);
		_protectedEventIdsInput.Text = string.Join(", ", values.ProtectedEventIds);
		ApplyBounds(values.Bounds);

		RetentionWindowsDto windows = policy.GlobalWindows;
		SetNumeric(_globalWindowInputs[0], windows.EventRetentionDays);
		SetNumeric(_globalWindowInputs[1], windows.AlertRetentionDays);
		SetNumeric(_globalWindowInputs[2], windows.AbuseReportRetentionDays);
		SetNumeric(_globalWindowInputs[3], windows.ActiveBlockRetentionDays);
		SetNumeric(_globalWindowInputs[4], windows.AttackStatRetentionDays);
		SetNumeric(_globalWindowInputs[5], windows.SessionIpCorrelationRetentionDays);
		SetNumeric(_globalWindowInputs[6], windows.RdpConnectionFactRetentionDays);
		SetNumeric(_globalWindowInputs[7], windows.LogRetentionDays);

		_eventRetentionRows.RaiseListChangedEvents = false;
		_eventRetentionRows.Clear();
		foreach (EventRetentionWindowDto window in policy.EventWindows)
		{
			_eventRetentionRows.Add(EventRetentionRow.From(window));
		}

		_eventRetentionRows.RaiseListChangedEvents = true;
		_eventRetentionRows.ResetBindings();

		_effectiveValuesLabel.Text = string.Format(
			CultureInfo.InvariantCulture,
			"Effective: anchor={0}; tail={1}; candidateMin={2}; minAge={3}d; maxRowsPerPass={4}; writerLock={5}ms; "
				+ "deleteBatch={6}; pressureDeletionAllowed={7}; protected={8} code(s) (configured: {9}). Config: {10}",
			values.EffectiveAnchorScope,
			values.EffectiveTailKeepPerCode,
			values.EffectiveCandidateMinRows,
			values.EffectiveMinAgeDays,
			values.EffectiveMaxRowsPerPass,
			values.EffectiveMaxWriterLockMs,
			values.EffectiveDeleteBatchRows,
			values.PressureDeletionAllowed,
			values.EffectiveProtectedEventIds.Count,
			values.ProtectedEventIds.Count,
			policy.ConfigPath);
	}

	/// <summary>Applies the server-reported clamp bounds to the numeric inputs, so the editor can
	/// never offer a range the service would reject.</summary>
	private void ApplyBounds(RetentionPolicyBoundsDto bounds)
	{
		ApplyRange(_tailKeepInput, bounds.MinTailKeepPerCode, bounds.MaxTailKeepPerCode);
		ApplyRange(_candidateMinRowsInput, bounds.MinCandidateMinRows, bounds.MaxCandidateMinRows);
		ApplyRange(_minAgeDaysInput, bounds.MinMinAgeDays, bounds.MaxMinAgeDays);
		ApplyRange(_maxRowsPerPassInput, bounds.MinMaxRowsPerPass, bounds.MaxMaxRowsPerPass);
		ApplyRange(_maxWriterLockMsInput, bounds.MinMaxWriterLockMs, bounds.MaxMaxWriterLockMs);
		ApplyRange(_deleteBatchRowsInput, bounds.MinDeleteBatchRows, bounds.MaxDeleteBatchRows);
	}

	/// <summary>Runs the mandatory dry-run and renders both the per-code result and the ordered plan.</summary>
	internal async Task PreviewRetentionAsync()
	{
		if (!BeginBusy())
		{
			return;
		}

		try
		{
			IpcCallResult<RetentionPreviewDto> call =
				await _ipc.SendDetailedAsync<RetentionPreviewDto>(IpcCommand.PreviewRetention, null, CurrentToken())
					.ConfigureAwait(true);
			if (!call.IsSuccess || call.Value is not { } preview)
			{
				SetStatus("Retention preview unavailable: " + call.Headline(), isError: true);
				_previewSteps.Text = "The preview could not be produced: " + call.Headline();
				return;
			}

			_previewRows.RaiseListChangedEvents = false;
			_previewRows.Clear();
			foreach (RetentionPreviewCodeDto code in preview.Codes)
			{
				_previewRows.Add(PreviewRow.From(code));
			}

			_previewRows.RaiseListChangedEvents = true;
			_previewRows.ResetBindings();

			_previewSteps.Text = FormatPreview(preview);
			SetStatus(string.Format(
				CultureInfo.InvariantCulture,
				"Retention preview as of {0}: {1} row(s) would be deleted across {2} step(s); trigger={3} fires={4}.",
				AsOf(preview.QueriedUtc),
				preview.WouldDeleteRows,
				preview.Steps.Count,
				preview.Trigger,
				preview.TriggerWouldFire));
		}
		catch (Exception ex)
		{
			SetStatus("Retention preview failed: " + ex.GetType().Name, isError: true);
		}
		finally
		{
			EndBusy();
		}
	}

	/// <summary>Renders the dry run. The reclaimed-bytes line is deliberately honest: when the
	/// service reports null it says the figure is known only after a checkpoint or vacuum instead of
	/// inventing a number.</summary>
	internal static string FormatPreview(RetentionPreviewDto preview)
	{
		ArgumentNullException.ThrowIfNull(preview);
		StringBuilder sb = new();
		sb.AppendLine("RdpAudit information-density retention — dry run");
		sb.AppendLine("==============================================");
		sb.AppendLine("As of (UTC):        " + preview.QueriedUtc.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture));
		sb.AppendLine("Policy enabled:     " + preview.PolicyEnabled + "; legal hold: " + preview.LegalHold);
		sb.AppendLine("Trigger:            " + preview.Trigger + " (would fire: " + preview.TriggerWouldFire + ")");
		sb.AppendLine("Would delete rows:  " + preview.WouldDeleteRows.ToString(CultureInfo.InvariantCulture));
		sb.AppendLine("Reclaimed bytes:    " + (preview.EstimatedReclaimedBytes is { } bytes
			? DescribeBytes(bytes)
			: "(unknown before a checkpoint/vacuum)" + (string.IsNullOrEmpty(preview.ReclaimedBytesNote) ? string.Empty : " — " + preview.ReclaimedBytesNote)));
		sb.AppendLine("Rule version:       " + preview.RuleVersion.ToString(CultureInfo.InvariantCulture));
		sb.AppendLine("Age cutoff (UTC):   " + preview.MinAgeCutoffUtc.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture));
		sb.AppendLine("Protected tail:     " + preview.TailKeepPerCode.ToString(CultureInfo.InvariantCulture)
			+ " per code; per-pass budget: " + preview.MaxRowsPerPass.ToString(CultureInfo.InvariantCulture));
		sb.AppendLine("Codes considered:   " + preview.Codes.Count.ToString(CultureInfo.InvariantCulture)
			+ "; skipped: " + preview.SkippedCodeCount.ToString(CultureInfo.InvariantCulture));
		sb.AppendLine();
		sb.AppendLine("Planned steps (execution order):");
		if (preview.Steps.Count == 0)
		{
			sb.AppendLine("  (none — no configured ceiling is breached, or a legal hold is in force)");
		}

		foreach (RetentionPreviewStepDto step in preview.Steps)
		{
			sb.AppendLine(string.Format(
				CultureInfo.InvariantCulture,
				"  #{0,-3} {1}/{2}{3}  rows={4}  window {5:yyyy-MM-dd HH:mm:ss} .. {6:yyyy-MM-dd HH:mm:ss}  anchor={7}  tailBoundary={8}",
				step.Order,
				step.EventId,
				string.IsNullOrEmpty(step.Channel) ? "(no channel)" : step.Channel,
				string.IsNullOrEmpty(step.IpHex) ? string.Empty : " ip=" + step.IpHex,
				step.Rows,
				step.WindowStartUtc,
				step.WindowEndUtc,
				step.AnchorRowId,
				step.TailBoundaryRowId));
		}

		if (!string.IsNullOrEmpty(preview.Message))
		{
			sb.AppendLine();
			sb.AppendLine(preview.Message);
		}

		return sb.ToString();
	}

	/// <summary>Persists the edited policy: builds the request from the controls, shows the computed
	/// old → new diff in a confirmation dialog, saves, then re-reads and shows the effective values.
	/// Nothing is written until the operator confirms.</summary>
	internal async Task SaveRetentionAsync()
	{
		RetentionPolicyMutationRequest request = CaptureMutationRequest();
		if (request.Policy is null || request.GlobalWindows is null)
		{
			SetStatus("Nothing to save: the policy was never loaded.", isError: true);
			return;
		}

		List<string> diff = _lastPolicy is null
			? new List<string> { "(no previously loaded policy to compare against)" }
			: BuildPolicyDiff(_lastPolicy.Policy, request.Policy, _lastPolicy.GlobalWindows, request.GlobalWindows);
		if (diff.Count == 0)
		{
			SetStatus("No changes to save: every value matches the loaded policy.");
			return;
		}

		StringBuilder prompt = new();
		prompt.AppendLine("Save the retention policy?");
		prompt.AppendLine();
		prompt.AppendLine("Changes (old → new):");
		foreach (string line in diff)
		{
			prompt.AppendLine("  " + line);
		}

		prompt.AppendLine();
		prompt.AppendLine(string.Format(
			CultureInfo.InvariantCulture,
			"{0} per-event override(s) will be written as the complete set.",
			request.EventWindows.Count));
		if (!ConfirmPrompt(prompt.ToString(), "Confirm retention policy save"))
		{
			SetStatus("Retention policy save cancelled.");
			return;
		}

		if (!BeginBusy())
		{
			return;
		}

		try
		{
			IpcCallResult<RetentionPolicyDto> call = await _ipc
				.SendDetailedAsync<RetentionPolicyDto>(IpcCommand.SaveRetentionPolicy, request, CurrentToken())
				.ConfigureAwait(true);
			if (!call.IsSuccess || call.Value is not { } saved)
			{
				SetStatus("Retention policy save failed: " + call.Headline(), isError: true);
				return;
			}

			// Re-read semantics: the returned DTO is the effective state the service persisted. Show it
			// verbatim so the editor never claims a value the clamp rejected.
			ApplyPolicyToControls(saved);
			SetStatus(string.Format(
				CultureInfo.InvariantCulture,
				"Retention policy saved. Effective: tail={0}; candidateMin={1}; minAge={2}d; maxRowsPerPass={3}; "
					+ "writerLock={4}ms; pressureDeletionAllowed={5}.",
				saved.Policy.EffectiveTailKeepPerCode,
				saved.Policy.EffectiveCandidateMinRows,
				saved.Policy.EffectiveMinAgeDays,
				saved.Policy.EffectiveMaxRowsPerPass,
				saved.Policy.EffectiveMaxWriterLockMs,
				saved.Policy.PressureDeletionAllowed));
		}
		catch (Exception ex)
		{
			SetStatus("Retention policy save failed: " + ex.GetType().Name, isError: true);
		}
		finally
		{
			EndBusy();
		}
	}

	/// <summary>Builds the mutation request from the editor state. Exposed to tests: the mapping from
	/// controls to the wire contract is what a save regression would break.</summary>
	internal RetentionPolicyMutationRequest CaptureMutationRequest()
	{
		RetentionPolicyValuesDto policy = new()
		{
			Enabled = _policyEnabledCheck.Checked,
			LegalHold = _legalHoldCheck.Checked,
			AnchorScope = SelectedAnchorScope(),
			TailKeepPerCode = (int)_tailKeepInput.Value,
			CandidateMinRows = (int)_candidateMinRowsInput.Value,
			MinAgeDays = (int)_minAgeDaysInput.Value,
			MaxRowsPerPass = (int)_maxRowsPerPassInput.Value,
			MaxWriterLockMs = (int)_maxWriterLockMsInput.Value,
			DeleteBatchRows = (int)_deleteBatchRowsInput.Value,
			MaxDatabaseBytes = (long)_maxDatabaseBytesInput.Value,
			MaxRawEventRows = (long)_maxRawEventRowsInput.Value,
			MinFreeDiskBytes = (long)_minFreeDiskBytesInput.Value,
			ProtectedEventIds = ParseEventIds(_protectedEventIdsInput.Text),
		};

		RetentionWindowsDto windows = new()
		{
			EventRetentionDays = (int)_globalWindowInputs[0].Value,
			AlertRetentionDays = (int)_globalWindowInputs[1].Value,
			AbuseReportRetentionDays = (int)_globalWindowInputs[2].Value,
			ActiveBlockRetentionDays = (int)_globalWindowInputs[3].Value,
			AttackStatRetentionDays = (int)_globalWindowInputs[4].Value,
			SessionIpCorrelationRetentionDays = (int)_globalWindowInputs[5].Value,
			RdpConnectionFactRetentionDays = (int)_globalWindowInputs[6].Value,
			LogRetentionDays = (int)_globalWindowInputs[7].Value,
		};

		List<EventRetentionWindowDto> events = new(_eventRetentionRows.Count);
		foreach (EventRetentionRow row in _eventRetentionRows)
		{
			events.Add(row.ToDto());
		}

		return new RetentionPolicyMutationRequest
		{
			Policy = policy,
			GlobalWindows = windows,
			EventWindows = events,
			EventWindowsReplaceAll = true,
		};
	}

	/// <summary>Builds the human-readable old → new diff shown before a save. Pure and static so a
	/// test can lock the semantics: only changed fields appear, and a field that is unchanged is not
	/// listed.</summary>
	internal static List<string> BuildPolicyDiff(
		RetentionPolicyValuesDto oldPolicy,
		RetentionPolicyValuesDto newPolicy,
		RetentionWindowsDto oldWindows,
		RetentionWindowsDto newWindows)
	{
		ArgumentNullException.ThrowIfNull(oldPolicy);
		ArgumentNullException.ThrowIfNull(newPolicy);
		ArgumentNullException.ThrowIfNull(oldWindows);
		ArgumentNullException.ThrowIfNull(newWindows);

		List<string> lines = new();
		AddDiff(lines, "Enabled", oldPolicy.Enabled, newPolicy.Enabled);
		AddDiff(lines, "LegalHold", oldPolicy.LegalHold, newPolicy.LegalHold);
		AddDiff(lines, "AnchorScope", oldPolicy.AnchorScope, newPolicy.AnchorScope);
		AddDiff(lines, "TailKeepPerCode", oldPolicy.TailKeepPerCode, newPolicy.TailKeepPerCode);
		AddDiff(lines, "CandidateMinRows", oldPolicy.CandidateMinRows, newPolicy.CandidateMinRows);
		AddDiff(lines, "MinAgeDays", oldPolicy.MinAgeDays, newPolicy.MinAgeDays);
		AddDiff(lines, "MaxRowsPerPass", oldPolicy.MaxRowsPerPass, newPolicy.MaxRowsPerPass);
		AddDiff(lines, "MaxWriterLockMs", oldPolicy.MaxWriterLockMs, newPolicy.MaxWriterLockMs);
		AddDiff(lines, "DeleteBatchRows", oldPolicy.DeleteBatchRows, newPolicy.DeleteBatchRows);
		AddDiff(lines, "MaxDatabaseBytes", oldPolicy.MaxDatabaseBytes, newPolicy.MaxDatabaseBytes);
		AddDiff(lines, "MaxRawEventRows", oldPolicy.MaxRawEventRows, newPolicy.MaxRawEventRows);
		AddDiff(lines, "MinFreeDiskBytes", oldPolicy.MinFreeDiskBytes, newPolicy.MinFreeDiskBytes);
		AddDiff(
			lines,
			"ProtectedEventIds",
			string.Join(",", oldPolicy.ProtectedEventIds),
			string.Join(",", newPolicy.ProtectedEventIds));

		AddDiff(lines, "EventRetentionDays", oldWindows.EventRetentionDays, newWindows.EventRetentionDays);
		AddDiff(lines, "AlertRetentionDays", oldWindows.AlertRetentionDays, newWindows.AlertRetentionDays);
		AddDiff(lines, "AbuseReportRetentionDays", oldWindows.AbuseReportRetentionDays, newWindows.AbuseReportRetentionDays);
		AddDiff(lines, "ActiveBlockRetentionDays", oldWindows.ActiveBlockRetentionDays, newWindows.ActiveBlockRetentionDays);
		AddDiff(lines, "AttackStatRetentionDays", oldWindows.AttackStatRetentionDays, newWindows.AttackStatRetentionDays);
		AddDiff(lines, "SessionIpCorrelationRetentionDays", oldWindows.SessionIpCorrelationRetentionDays, newWindows.SessionIpCorrelationRetentionDays);
		AddDiff(lines, "RdpConnectionFactRetentionDays", oldWindows.RdpConnectionFactRetentionDays, newWindows.RdpConnectionFactRetentionDays);
		AddDiff(lines, "LogRetentionDays", oldWindows.LogRetentionDays, newWindows.LogRetentionDays);
		return lines;
	}

	private static void AddDiff<T>(List<string> lines, string name, T oldValue, T newValue)
	{
		if (EqualityComparer<T>.Default.Equals(oldValue, newValue))
		{
			return;
		}

		lines.Add(string.Format(
			CultureInfo.InvariantCulture,
			"{0}: {1} → {2}",
			name,
			oldValue?.ToString() ?? "(null)",
			newValue?.ToString() ?? "(null)"));
	}

	private void ApplyBulkRetention(bool selectedOnly)
	{
		int days = (int)_bulkRetentionDays.Value;
		int affected = 0;
		foreach (DataGridViewRow gridRow in _eventRetentionGrid.Rows)
		{
			if (selectedOnly && !gridRow.Selected)
			{
				continue;
			}

			if (gridRow.DataBoundItem is EventRetentionRow row)
			{
				row.RetentionDays = days;
				affected++;
			}
		}

		if (affected == 0)
		{
			SetStatus(
				selectedOnly
					? "Select one or more event rows before applying retention."
					: "There are no event rows to update.",
				isError: true);
			return;
		}

		_eventRetentionGrid.Refresh();
		SetStatus(string.Format(
			CultureInfo.InvariantCulture,
			"Set retention to {0} day(s) for {1} row(s). Save policy to persist.",
			days,
			affected));
	}

	private void OnEventRetentionCellValidating(object? sender, DataGridViewCellValidatingEventArgs e)
	{
		if (e.RowIndex < 0
			|| !string.Equals(_eventRetentionGrid.Columns[e.ColumnIndex].DataPropertyName, nameof(EventRetentionRow.RetentionDays), StringComparison.Ordinal))
		{
			return;
		}

		string value = Convert.ToString(e.FormattedValue, CultureInfo.InvariantCulture) ?? string.Empty;
		if (!int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out int days)
			|| days < 0
			|| days > MaximumRetentionDays)
		{
			e.Cancel = true;
			SetStatus(string.Format(
				CultureInfo.InvariantCulture,
				"Retention must be a whole number from 0 to {0}; 0 means retain forever.",
				MaximumRetentionDays),
				isError: true);
		}
	}

	// ── Maintenance ──────────────────────────────────────────────────────────────

	private void AddMaintenanceButton(FlowLayoutPanel host, DatabaseMaintenanceKind kind, string label)
	{
		Button button = MakeButton(label, SafeAsyncHandler.Wrap(() => RunMaintenanceAsync(kind), ReportHandlerFailure));
		_maintenanceButtons.Add(new MaintenanceButton(button, kind));
		host.Controls.Add(button);
	}

	/// <summary>Runs one read-safe maintenance action and renders the structured report. The cancel
	/// button abandons the client-side wait; the status line says the service may still be working.</summary>
	internal async Task RunMaintenanceAsync(DatabaseMaintenanceKind kind)
	{
		if (!BeginBusy())
		{
			return;
		}

		try
		{
			IpcCallResult<DatabaseMaintenanceReportDto> call = await _ipc
				.SendDetailedAsync<DatabaseMaintenanceReportDto>(
					IpcCommand.RunDatabaseMaintenance,
					new DatabaseMaintenanceRequest { Kind = kind },
					CurrentToken())
				.ConfigureAwait(true);
			if (!call.IsSuccess || call.Value is not { } report)
			{
				SetStatus(kind + " unavailable: " + call.Headline(), isError: true);
				_maintenanceReport.Text = "The action could not be run: " + call.Headline();
				return;
			}

			_maintenanceReport.Text = report.ResultText;
			SetStatus(string.Format(
				CultureInfo.InvariantCulture,
				"{0} finished in {1} ms; status={2}.",
				report.KindName,
				report.DurationMs,
				report.Status),
				isError: report.Status != IpcResultStatus.Success);
		}
		catch (Exception ex)
		{
			SetStatus(kind + " failed: " + ex.GetType().Name, isError: true);
		}
		finally
		{
			EndBusy();
		}
	}

	/// <summary>Triggers the existing RDP Activity rebuild (ordinal 60) and reports its counts.</summary>
	internal async Task RebuildAttackStatsAsync()
	{
		if (!BeginBusy())
		{
			return;
		}

		try
		{
			IpcCallResult<AttackStatsRebuildResultDto> call =
				await _ipc.SendDetailedAsync<AttackStatsRebuildResultDto>(IpcCommand.RebuildAttackStats, null, CurrentToken())
					.ConfigureAwait(true);
			if (!call.IsSuccess || call.Value is not { } result)
			{
				SetStatus("Rebuild attack stats unavailable: " + call.Headline(), isError: true);
				return;
			}

			_maintenanceReport.Text = string.Format(
				CultureInfo.InvariantCulture,
				"RdpAudit RDP Activity rebuild{0}\r\nGenerated (UTC): {1:yyyy-MM-dd HH:mm:ss}\r\nRows before:     {2}\r\nRows after:      {3}\r\nRows upserted:   {4}\r\nFull rebuild:    {5}\r\nElapsed:         {6} ms\r\n\r\n{7}",
				Environment.NewLine,
				result.GeneratedUtc,
				result.RowsBefore,
				result.RowsAfter,
				result.RowsUpserted,
				result.FullRebuild,
				result.ElapsedMilliseconds,
				result.Message ?? string.Empty);
			SetStatus(string.Format(
				CultureInfo.InvariantCulture,
				"RDP Activity rebuilt: {0} row(s) upserted, table now {1} row(s).",
				result.RowsUpserted,
				result.AttackStatsTotal));
		}
		catch (Exception ex)
		{
			SetStatus("Rebuild attack stats failed: " + ex.GetType().Name, isError: true);
		}
		finally
		{
			EndBusy();
		}
	}

	private void CancelRunningOperation()
	{
		CancellationTokenSource? cts = _operationCts;
		if (cts is null || cts.IsCancellationRequested)
		{
			return;
		}

		try
		{
			cts.Cancel();
			SetStatus("Cancellation requested. The client stopped waiting; the service may still be completing the operation, so re-check the result before acting on it.");
		}
		catch (ObjectDisposedException)
		{
			// The operation completed between the click and the cancel; nothing to do.
		}
	}

	// ── Backup & Restore ─────────────────────────────────────────────────────────

	/// <summary>Creates one snapshot with the requested shard scope.</summary>
	internal async Task CreateBackupAsync()
	{
		if (!BeginBusy())
		{
			return;
		}

		try
		{
			IpcCallResult<DatabaseBackupCreationDto> call = await _ipc
				.SendDetailedAsync<DatabaseBackupCreationDto>(
					IpcCommand.CreateDatabaseBackup,
					new CreateDatabaseBackupRequest { IncludeShards = _includeShardsCheck.Checked },
					CurrentToken())
				.ConfigureAwait(true);
			if (!call.IsSuccess || call.Value is not { } created)
			{
				SetStatus("Create snapshot unavailable: " + call.Headline(), isError: true);
				return;
			}

			if (created.Status != IpcResultStatus.Success)
			{
				_backupReport.Text = "The snapshot was refused:" + Environment.NewLine + Environment.NewLine + (created.Message ?? created.Status.ToString());
				SetStatus("Create snapshot refused: " + (created.Message ?? created.Status.ToString()), isError: true);
				return;
			}

			_backupReport.Text = string.Format(
				CultureInfo.InvariantCulture,
				"Snapshot:        {0}{1}Directory:       {2}{1}Database bytes:  {3}{1}SHA-256:         {4}{1}Shards included: {5} ({6} file(s), {7}){1}Snapshots:       {8} -> {9}{1}Elapsed:         {10} ms{1}{1}Retention removed {11} snapshot(s), skipped {12}.",
				created.SnapshotName,
				Environment.NewLine,
				created.SnapshotDirectory,
				created.DatabaseBytes,
				created.DatabaseSha256,
				created.ShardsIncluded,
				created.ShardFileCount,
				DescribeBytes(created.ShardBytes),
				created.SnapshotCountBefore,
				created.SnapshotCountAfter,
				created.DurationMs,
				created.RetentionDeleted.Count,
				created.RetentionSkipped.Count);
			SetStatus(string.Format(
				CultureInfo.InvariantCulture,
				"Snapshot {0} created ({1}, as of {2}).",
				created.SnapshotName,
				DescribeBytes(created.DatabaseBytes),
				AsOf(created.QueriedUtc)));
			await LoadBackupsAsync(manageBusy: false).ConfigureAwait(true);
		}
		catch (Exception ex)
		{
			SetStatus("Create snapshot failed: " + ex.GetType().Name, isError: true);
		}
		finally
		{
			EndBusy();
		}
	}

	/// <summary>Loads the newest-first snapshot inventory.</summary>
	internal async Task LoadBackupsAsync(bool manageBusy = true)
	{
		if (manageBusy && !BeginBusy())
		{
			return;
		}

		try
		{
			IpcCallResult<DatabaseBackupListDto> call =
				await _ipc.SendDetailedAsync<DatabaseBackupListDto>(IpcCommand.ListDatabaseBackups, null, CurrentToken())
					.ConfigureAwait(true);
			if (!call.IsSuccess || call.Value is not { } list)
			{
				SetStatus("Snapshot list unavailable: " + call.Headline(), isError: true);
				return;
			}

			_backupsStamp.Text = "as of " + AsOf(list.QueriedUtc);
			_backupRows.RaiseListChangedEvents = false;
			_backupRows.Clear();
			foreach (DatabaseBackupEntryDto entry in list.Entries)
			{
				_backupRows.Add(BackupRow.From(entry));
			}

			_backupRows.RaiseListChangedEvents = true;
			_backupRows.ResetBindings();
			UpdateBackupButtonState();

			if (manageBusy)
			{
				SetStatus(string.Format(
					CultureInfo.InvariantCulture,
					"Snapshot list loaded as of {0}: {1} snapshot(s) under {2} (enabled={3}, preMigration={4}, retention={5}){6}.",
					AsOf(list.QueriedUtc),
					list.TotalCount,
					list.BackupDirectory,
					list.Enabled,
					list.PreMigrationBackupEnabled,
					list.RetentionCopies,
					list.Truncated ? " — the list is truncated" : string.Empty),
					isError: list.Truncated);
			}
		}
		catch (Exception ex)
		{
			SetStatus("Snapshot list failed: " + ex.GetType().Name, isError: true);
		}
		finally
		{
			if (manageBusy)
			{
				EndBusy();
			}
		}
	}

	/// <summary>Verifies the selected snapshot (or the newest when none is selected).</summary>
	internal async Task VerifySelectedBackupAsync()
	{
		BackupRow? selected = SelectedBackup();

		if (!BeginBusy())
		{
			return;
		}

		try
		{
			IpcCallResult<DatabaseBackupVerificationDto> call = await _ipc
				.SendDetailedAsync<DatabaseBackupVerificationDto>(
					IpcCommand.VerifyDatabaseBackup,
					new VerifyDatabaseBackupRequest { Name = selected?.Name },
					CurrentToken())
				.ConfigureAwait(true);
			if (!call.IsSuccess || call.Value is not { } verification)
			{
				SetStatus("Verify snapshot unavailable: " + call.Headline(), isError: true);
				return;
			}

			_backupReport.Text = FormatVerification(verification);
			SetStatus(string.Format(
				CultureInfo.InvariantCulture,
				"Verification of {0}: {1} (usable={2}, as of {3}).",
				string.IsNullOrEmpty(verification.SnapshotName) ? "(newest)" : verification.SnapshotName,
				verification.VerdictName.Length > 0 ? verification.VerdictName : verification.Verdict.ToString(),
				verification.IsUsable,
				AsOf(verification.QueriedUtc)),
				isError: !verification.IsUsable);
		}
		catch (Exception ex)
		{
			SetStatus("Verify snapshot failed: " + ex.GetType().Name, isError: true);
		}
		finally
		{
			EndBusy();
		}
	}

	/// <summary>Renders a verification result. Pure and static so the rendering rules are testable.</summary>
	internal static string FormatVerification(DatabaseBackupVerificationDto verification)
	{
		ArgumentNullException.ThrowIfNull(verification);
		StringBuilder sb = new();
		sb.AppendLine("RdpAudit snapshot verification");
		sb.AppendLine("=============================");
		sb.AppendLine("As of (UTC):   " + verification.QueriedUtc.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture));
		sb.AppendLine("Snapshot:      " + (string.IsNullOrEmpty(verification.SnapshotName) ? "(newest)" : verification.SnapshotName));
		sb.AppendLine("Directory:     " + verification.SnapshotDirectory);
		sb.AppendLine("Verdict:       " + (verification.VerdictName.Length > 0 ? verification.VerdictName : verification.Verdict.ToString())
			+ " (usable: " + verification.IsUsable + ")");
		sb.AppendLine("Expected hash: " + (verification.ExpectedSha256 ?? "(none)"));
		sb.AppendLine("Actual hash:   " + (verification.ActualSha256 ?? "(not computed)"));
		sb.AppendLine("quick_check:   " + (verification.QuickCheckResult ?? "(not run)"));
		if (verification.SchemaVerdict is { } schema)
		{
			sb.AppendLine("Schema:        " + schema + " — " + (verification.SchemaMessage ?? "(no detail)"));
		}

		if (!string.IsNullOrEmpty(verification.Message))
		{
			sb.AppendLine();
			sb.AppendLine(verification.Message);
		}

		return sb.ToString();
	}

	/// <summary>Restores the selected snapshot into an operator-chosen scratch directory (IPC 90).
	/// The live store is never touched by this path.</summary>
	internal async Task RestoreToFolderAsync()
	{
		BackupRow? selected = SelectedBackup();
		if (selected is null)
		{
			SetStatus("Select a snapshot row before restoring to a folder.", isError: true);
			return;
		}

		using FolderBrowserDialog dialog = new()
		{
			Description = "Choose the target folder for the restored copy (the live store is not touched)",
			ShowNewFolderButton = true,
		};
		if (dialog.ShowDialog(this) != DialogResult.OK || string.IsNullOrWhiteSpace(dialog.SelectedPath))
		{
			SetStatus("Restore to folder cancelled.");
			return;
		}

		string target = dialog.SelectedPath;
		if (!ConfirmPrompt(
			"Restore snapshot '" + selected.Name + "' into:" + Environment.NewLine + Environment.NewLine + target
				+ Environment.NewLine + Environment.NewLine
				+ "The snapshot is verified first; a snapshot that fails verification writes nothing. The live database is not touched.",
			"Confirm restore to folder"))
		{
			SetStatus("Restore to folder cancelled.");
			return;
		}

		if (!BeginBusy())
		{
			return;
		}

		try
		{
			IpcCallResult<DatabaseBackupRestoreReportDto> call = await _ipc
				.SendDetailedAsync<DatabaseBackupRestoreReportDto>(
					IpcCommand.RestoreDatabaseBackupToDirectory,
					new RestoreDatabaseBackupToDirectoryRequest { Name = selected.Name, TargetDirectory = target },
					CurrentToken())
				.ConfigureAwait(true);
			if (!call.IsSuccess || call.Value is not { } report)
			{
				SetStatus("Restore to folder unavailable: " + call.Headline(), isError: true);
				return;
			}

			_backupReport.Text = FormatRestoreReport(report);
			SetStatus(string.Format(
				CultureInfo.InvariantCulture,
				"Restore to folder: {0} — {1}",
				report.Status,
				report.Message ?? "(no detail)"),
				isError: report.Status != IpcResultStatus.Success);
		}
		catch (Exception ex)
		{
			SetStatus("Restore to folder failed: " + ex.GetType().Name, isError: true);
		}
		finally
		{
			EndBusy();
		}
	}

	/// <summary>Renders a scratch-restore report. Pure and static so the rendering rules are testable.</summary>
	internal static string FormatRestoreReport(DatabaseBackupRestoreReportDto report)
	{
		ArgumentNullException.ThrowIfNull(report);
		StringBuilder sb = new();
		sb.AppendLine("RdpAudit restore into a scratch directory");
		sb.AppendLine("========================================");
		sb.AppendLine("As of (UTC):   " + report.QueriedUtc.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture));
		sb.AppendLine("Status:        " + report.Status);
		sb.AppendLine("Snapshot:      " + report.SnapshotName);
		sb.AppendLine("Target:        " + (string.IsNullOrEmpty(report.TargetDatabasePath) ? report.TargetDirectory : report.TargetDatabasePath));
		sb.AppendLine("Bytes copied:  " + report.DatabaseBytesCopied.ToString(CultureInfo.InvariantCulture));
		sb.AppendLine("Shards:        " + (report.ShardsRestored
			? report.ShardFilesRestored.ToString(CultureInfo.InvariantCulture) + " file(s), " + report.ShardBytesRestored.ToString(CultureInfo.InvariantCulture) + " bytes"
			: "not included in this snapshot"));
		if (report.Verification is { } verification)
		{
			sb.AppendLine("Verification:  " + (verification.VerdictName.Length > 0 ? verification.VerdictName : verification.Verdict.ToString()));
		}

		if (!string.IsNullOrEmpty(report.Message))
		{
			sb.AppendLine();
			sb.AppendLine(report.Message);
		}

		return sb.ToString();
	}

	/// <summary>
	/// Restores a verified snapshot OVER the live database through the Configurator's
	/// DatabaseRestoreService (stop service → snapshot the pre-state → swap → start). Gated on
	/// elevation, a confirmation dialog and a typed phrase; the pre-state file path is reported so the
	/// operator can undo the restore by hand. After a successful restore the operator is offered a
	/// verification pass on the snapshot that was used.
	/// </summary>
	internal async Task RestoreOverLiveAsync(TextBox reportTarget)
	{
		ArgumentNullException.ThrowIfNull(reportTarget);

		// Selection first; with none, the newest snapshot is the documented default and the prompt
		// names it, so an operator arriving from the Danger Zone still sees exactly what will be used.
		BackupRow? selected = SelectedBackup();
		bool usedNewestFallback = false;
		if (selected is null && _backupRows.Count > 0)
		{
			selected = _backupRows[0];
			usedNewestFallback = true;
		}

		if (selected is null || string.IsNullOrEmpty(selected.Directory))
		{
			SetStatus("No snapshot is available to restore over the live database; refresh the snapshot list first.", isError: true);
			return;
		}

		if (usedNewestFallback)
		{
			SetStatus("No snapshot row was selected; using the newest snapshot (" + selected.Name + ").");
		}

		ElevationStatus elevation = ElevationGuard.Check();
		if (!elevation.IsElevated)
		{
			SetStatus("Restore over live database requires elevation: " + elevation.Message, isError: true);
			return;
		}

		if (string.IsNullOrEmpty(_lastDatabasePath))
		{
			SetStatus("The live database path is unknown; refresh the Overview first so the restore knows what it replaces.", isError: true);
			return;
		}

		string prompt =
			"Restore snapshot '" + selected.Name + "' OVER the live database?" + Environment.NewLine + Environment.NewLine
			+ "Live database:   " + _lastDatabasePath + Environment.NewLine
			+ "Snapshot:        " + selected.Directory + Environment.NewLine + Environment.NewLine
			+ "The service is stopped, the current database and its WAL/SHM sidecars are renamed to timestamped "
			+ ".bak files, the snapshot is copied into place and the service is started again. The previous "
			+ "database is kept until you delete it. This cannot be undone automatically.";
		if (!ConfirmPrompt(prompt, "Confirm restore over the live database"))
		{
			SetStatus("Restore over live database cancelled.");
			return;
		}

		string typed = PromptForConfirmationPhrase(RestoreOverLivePhrase);
		if (!string.Equals(typed, RestoreOverLivePhrase, StringComparison.Ordinal))
		{
			SetStatus("Restore over live database cancelled: the confirmation phrase did not match.");
			return;
		}

		if (!BeginBusy())
		{
			return;
		}

		try
		{
			DatabaseRestoreResult result = await _restoreService
				.ExecuteAsync(selected.Directory, _lastDatabasePath, knownMigrations: null, ct: CurrentToken())
				.ConfigureAwait(true);
			reportTarget.Text = result.Log;
			SetStatus(result.Success
				? "Restore over live database completed. Previous database: " + (result.PreStateBackupPath ?? "(unknown)")
				: "Restore over live database did not complete — see the report.",
				isError: !result.Success);

			if (result.Success)
			{
				DialogResult verify = MessageBox.Show(
					this,
					"Offer to verify the snapshot that was just restored? Verification recomputes the SHA-256 and runs quick_check on the copy.",
					"Verify the restored snapshot",
					MessageBoxButtons.YesNo,
					MessageBoxIcon.Question);
				if (verify == DialogResult.Yes)
				{
					await VerifySnapshotByNameAsync(selected.Name, reportTarget, manageBusy: false).ConfigureAwait(true);
				}
			}
		}
		catch (OperationCanceledException)
		{
			SetStatus("Restore over live database cancelled by the operator; the service may be left stopped — check it on the Service tab.", isError: true);
		}
		catch (Exception ex)
		{
			SetStatus("Restore over live database failed: " + ex.GetType().Name, isError: true);
		}
		finally
		{
			EndBusy();
		}
	}

	private async Task VerifySnapshotByNameAsync(string name, TextBox reportTarget, bool manageBusy)
	{
		if (manageBusy && !BeginBusy())
		{
			return;
		}

		try
		{
			IpcCallResult<DatabaseBackupVerificationDto> call = await _ipc
				.SendDetailedAsync<DatabaseBackupVerificationDto>(
					IpcCommand.VerifyDatabaseBackup,
					new VerifyDatabaseBackupRequest { Name = name },
					CurrentToken())
				.ConfigureAwait(true);
			if (call.IsSuccess && call.Value is { } verification)
			{
				reportTarget.Text = reportTarget.Text + Environment.NewLine + FormatVerification(verification);
				SetStatus("Post-restore verification: " + (verification.VerdictName.Length > 0 ? verification.VerdictName : verification.Verdict.ToString())
					+ " (usable=" + verification.IsUsable + ").",
					isError: !verification.IsUsable);
			}
			else
			{
				SetStatus("Post-restore verification unavailable: " + call.Headline(), isError: true);
			}
		}
		finally
		{
			if (manageBusy)
			{
				EndBusy();
			}
		}
	}

	// ── Shards ───────────────────────────────────────────────────────────────────

	/// <summary>Loads the shard inventory and the effective shard policy. The inventory command never
	/// writes, moves or deletes a shard file; it also carries the policy and the live capacity state, so
	/// one round trip fills the editor, the banner and the grid.</summary>
	internal async Task LoadShardsAsync()
	{
		if (!BeginBusy())
		{
			return;
		}

		try
		{
			IpcCallResult<ShardInventoryDto> call =
				await _ipc.SendDetailedAsync<ShardInventoryDto>(IpcCommand.GetShardInventory, null, CurrentToken())
					.ConfigureAwait(true);
			if (!call.IsSuccess || call.Value is not { } inventory)
			{
				// Fail closed for the two mutating actions: without a loaded policy there is no baseline to
				// diff against and no candidate list to confirm, so neither button may be armed.
				_shardsSaveButton.Enabled = false;
				_shardsCollectButton.Enabled = false;
				SetShardBanner(refusal: false, "Capacity state unknown: " + call.Headline());
				SetStatus("Shard inventory unavailable: " + call.Headline(), isError: true);
				return;
			}

			_shardsStamp.Text = "as of " + AsOf(inventory.QueriedUtc) + (inventory.Summary.Truncated ? " (truncated)" : string.Empty);
			_shardRows.RaiseListChangedEvents = false;
			_shardRows.Clear();
			foreach (ShardInventoryEntryDto entry in inventory.Entries)
			{
				_shardRows.Add(ShardRow.From(entry));
			}

			_shardRows.RaiseListChangedEvents = true;
			_shardRows.ResetBindings();

			if (inventory.Policy is { } policy)
			{
				ApplyShardPolicyToControls(policy);
				_shardsSaveButton.Enabled = true;
				// A collection pass without a candidate list is meaningless, so it is armed only once an
				// inventory has actually been read.
				_shardsCollectButton.Enabled = true;
			}
			else
			{
				// The service answered without a policy: the editor has no baseline, so it stays locked and
				// says so instead of presenting values it cannot save.
				_shardsSaveButton.Enabled = false;
				_shardsCollectButton.Enabled = true;
			}

			UpdateShardBanner(inventory.CapacityStatus);

			_shardsSummaryLabel.Text = string.Format(
				CultureInfo.InvariantCulture,
				"Root: {0}   |   shard files: {1}   |   orphans: {2} ({3})   |   shard bytes: {4}   |   records: {5}   |   evicted: {6}   |   files scanned: {7}{8}",
				inventory.ActionsRoot,
				inventory.Summary.ShardFiles,
				inventory.Summary.OrphanFiles,
				DescribeBytes(inventory.Summary.OrphanBytes),
				DescribeBytes(inventory.Summary.TotalShardBytes),
				inventory.Summary.TotalRecords,
				inventory.Summary.TotalEvicted,
				inventory.Summary.ScannedFileCount,
				inventory.Summary.Truncated ? "   |   (walk truncated — lower bounds)" : string.Empty);

			SetStatus(string.Format(
				CultureInfo.InvariantCulture,
				"Shard inventory as of {0}: {1} shard file(s), {2} orphan(s), sharding {3}{4}.",
				AsOf(inventory.QueriedUtc),
				inventory.Summary.ShardFiles,
				inventory.Summary.OrphanFiles,
				inventory.ShardingEnabled ? "enabled" : "disabled",
				inventory.Warnings.Count > 0 ? " — " + string.Join("; ", inventory.Warnings) : string.Empty),
				isError: inventory.Warnings.Count > 0 || inventory.Summary.OrphanFiles > 0);
		}
		catch (Exception ex)
		{
			SetStatus("Shard inventory failed: " + ex.GetType().Name, isError: true);
		}
		finally
		{
			EndBusy();
		}
	}

	/// <summary>Persists the edited shard policy: builds the request from the controls, shows the computed
	/// old → new diff in a confirmation dialog, saves, then shows the effective values the service
	/// reports. Nothing is written until the operator confirms.</summary>
	internal async Task SaveShardsPolicyAsync()
	{
		ShardingPolicyMutationRequest request = CaptureShardPolicyRequest();
		if (_lastShardPolicy is null)
		{
			SetStatus("Nothing to save: the shard policy was never loaded.", isError: true);
			return;
		}

		List<string> diff = BuildShardPolicyDiff(_lastShardPolicy, request);
		if (diff.Count == 0)
		{
			SetStatus("No changes to save: every value matches the loaded shard policy.");
			return;
		}

		StringBuilder prompt = new();
		prompt.AppendLine("Save the shard capacity policy?");
		prompt.AppendLine();
		prompt.AppendLine("Changes (old → new):");
		foreach (string line in diff)
		{
			prompt.AppendLine("  " + line);
		}

		prompt.AppendLine();
		prompt.AppendLine("The service validates and clamps every value, writes the policy into appsettings.json and applies it without a restart.");
		if (!ConfirmPrompt(prompt.ToString(), "Confirm shard policy save"))
		{
			SetStatus("Shard policy save cancelled.");
			return;
		}

		if (!BeginBusy())
		{
			return;
		}

		try
		{
			IpcCallResult<ShardingPolicyDto> call = await _ipc
				.SendDetailedAsync<ShardingPolicyDto>(IpcCommand.SaveShardingPolicy, request, CurrentToken())
				.ConfigureAwait(true);
			if (!call.IsSuccess || call.Value is not { } saved)
			{
				SetStatus("Shard policy save failed: " + call.Headline(), isError: true);
				return;
			}

			// Re-read semantics: the returned policy is what the service persisted, clamp included. Show it
			// verbatim so the editor never claims a value the clamp rejected.
			ApplyShardPolicyToControls(saved);
			SetStatus(string.Format(
				CultureInfo.InvariantCulture,
				"Shard policy saved ({0}). Effective ring capacity for new shards: {1} record(s) = {2}.",
				saved.Message ?? "applied",
				saved.Policy.EffectiveRingCapacityRecords,
				DescribeBytes(saved.Policy.EffectiveShardFileBytes)),
				isError: false);

			// Refresh the inventory so the banner reflects the new policy immediately.
			await LoadShardsAsync().ConfigureAwait(true);
		}
		catch (Exception ex)
		{
			SetStatus("Shard policy save failed: " + ex.GetType().Name, isError: true);
		}
		finally
		{
			EndBusy();
		}
	}

	/// <summary>Runs the orphan collection as the operator's two-step flow: a dry run first, whose
	/// candidate list is shown in full, and only then an apply pass. A rejected confirmation or an empty
	/// candidate list stops before anything is deleted.</summary>
	internal async Task CollectShardGarbageAsync()
	{
		if (!BeginBusy())
		{
			return;
		}

		try
		{
			IpcCallResult<ShardGarbageCollectionReportDto> dryRun = await _ipc
				.SendDetailedAsync<ShardGarbageCollectionReportDto>(
					IpcCommand.CollectShardGarbage,
					new CollectShardGarbageRequest { DryRun = true },
					CurrentToken())
				.ConfigureAwait(true);
			if (!dryRun.IsSuccess || dryRun.Value is not { } report)
			{
				SetStatus("Orphan dry run failed: " + dryRun.Headline(), isError: true);
				return;
			}

			List<ShardGarbageCandidateDto> eligible = report.Candidates
				.Where(candidate => candidate.Disposition == ShardGarbageDisposition.Eligible)
				.ToList();
			if (eligible.Count == 0)
			{
				SetStatus(string.Format(
					CultureInfo.InvariantCulture,
					"Orphan dry run: {0} orphan candidate(s), none eligible for collection (grace period {1} day(s)). Nothing was deleted.",
					report.Candidates.Count,
					report.OrphanGraceDays));
				return;
			}

			StringBuilder prompt = BuildOrphanPrompt(eligible, report);
			if (!ConfirmPrompt(prompt.ToString(), "Confirm orphan shard collection"))
			{
				SetStatus(string.Format(
					CultureInfo.InvariantCulture,
					"Orphan collection cancelled. {0} eligible candidate(s) were NOT deleted.",
					eligible.Count));
				return;
			}

			IpcCallResult<ShardGarbageCollectionReportDto> applied = await _ipc
				.SendDetailedAsync<ShardGarbageCollectionReportDto>(
					IpcCommand.CollectShardGarbage,
					new CollectShardGarbageRequest { DryRun = false },
					CurrentToken())
				.ConfigureAwait(true);
			if (!applied.IsSuccess || applied.Value is not { } deleted)
			{
				SetStatus("Orphan collection failed: " + applied.Headline(), isError: true);
				return;
			}

			SetStatus(string.Format(
				CultureInfo.InvariantCulture,
				"Orphan collection: {0} file(s) deleted, {1} freed, {2} record(s) removed. {3}",
				deleted.DeletedFileCount,
				DescribeBytes(deleted.DeletedBytes),
				deleted.DeletedRecords,
				deleted.Message ?? string.Empty),
				isError: deleted.Status != IpcResultStatus.Success);

			await LoadShardsAsync().ConfigureAwait(true);
		}
		catch (Exception ex)
		{
			SetStatus("Orphan collection failed: " + ex.GetType().Name, isError: true);
		}
		finally
		{
			EndBusy();
		}
	}

	/// <summary>Builds the confirmation text of a collection pass: every eligible candidate with its path,
	/// address, size, retained records and age, capped so a pathological tree cannot produce an unreadable
	/// dialog. The cap is stated in the dialog.</summary>
	internal static StringBuilder BuildOrphanPrompt(
		IReadOnlyList<ShardGarbageCandidateDto> eligible,
		ShardGarbageCollectionReportDto report)
	{
		ArgumentNullException.ThrowIfNull(eligible);
		ArgumentNullException.ThrowIfNull(report);

		StringBuilder prompt = new();
		prompt.AppendLine(string.Format(
			CultureInfo.InvariantCulture,
			"Delete {0} orphan shard file(s) older than {1} day(s)?",
			eligible.Count,
			report.OrphanGraceDays));
		prompt.AppendLine();
		prompt.AppendLine("Eligible candidates (path | IP | bytes | records | age):");
		int shown = 0;
		foreach (ShardGarbageCandidateDto candidate in eligible)
		{
			if (shown == OrphanPromptMaxLines)
			{
				prompt.AppendLine(string.Format(
					CultureInfo.InvariantCulture,
					"  … and {0} more candidate(s); the full list is in the service log.",
					eligible.Count - shown));
				break;
			}

			prompt.AppendLine(string.Format(
				CultureInfo.InvariantCulture,
				"  {0} | {1} | {2} | {3} | {4:0.#} d",
				candidate.RelativePath,
				candidate.IpText.Length == 0 ? "(unknown)" : candidate.IpText,
				candidate.Bytes,
				candidate.Records,
				candidate.AgeDays ?? 0));
			shown++;
		}

		prompt.AppendLine();
		prompt.AppendLine("Each deletion is re-validated on the service (not referenced, not open in a writer, past the grace period) and audited per file.");
		return prompt;
	}

	/// <summary>Builds the request from the controls. Every value is what the operator typed; the server
	/// clamps and refuses, so this method never silently edits a field.</summary>
	internal ShardingPolicyMutationRequest CaptureShardPolicyRequest() => new()
	{
		Enabled = _shardsEnabledCheck.Checked,
		ActionsRoot = _shardsRootInput.Text.Trim(),
		ShardCapacityRecords = (int)_shardsCapacityInput.Value,
		MaxOpenWriters = (int)_shardsMaxOpenWritersInput.Value,
		MaxShardFiles = (int)_shardsMaxShardFilesInput.Value,
		MaxShardBytes = (long)_shardsMaxShardBytesInput.Value,
		MaxTotalShardBytes = (long)_shardsMaxTotalShardBytesInput.Value,
		MinFreeDiskBytes = (long)_shardsMinFreeDiskBytesInput.Value,
		OrphanGraceDays = (int)_shardsOrphanGraceDaysInput.Value,
		SubnetAggregation = new SubnetAggregationMutationDto
		{
			Enabled = _shardsAggregationCheck.Checked,
			TotalFileThreshold = (int)_shardsAggregationTotalFilesInput.Value,
			NewFilesPerIntervalLimit = (int)_shardsAggregationNewFilesInput.Value,
			IntervalSeconds = (int)_shardsAggregationIntervalInput.Value,
			MinSourceRowsPerInterval = (int)_shardsAggregationMinRowsInput.Value,
		},
	};

	/// <summary>Builds the human-readable old → new diff shown before a save. Pure and static so a test
	/// can lock the semantics: only changed fields appear.</summary>
	internal static List<string> BuildShardPolicyDiff(ShardingPolicyValuesDto oldPolicy, ShardingPolicyMutationRequest request)
	{
		ArgumentNullException.ThrowIfNull(oldPolicy);
		ArgumentNullException.ThrowIfNull(request);

		List<string> lines = new();
		AddDiff(lines, "Enabled", oldPolicy.Enabled, request.Enabled);
		AddDiff(lines, "ActionsRoot", oldPolicy.ActionsRoot, request.ActionsRoot);
		AddDiff(lines, "ShardCapacityRecords", oldPolicy.ShardCapacityRecords, request.ShardCapacityRecords);
		AddDiff(lines, "MaxOpenWriters", oldPolicy.MaxOpenWriters, request.MaxOpenWriters);
		AddDiff(lines, "MaxShardFiles", oldPolicy.MaxShardFiles, request.MaxShardFiles);
		AddDiff(lines, "MaxShardBytes", oldPolicy.MaxShardBytes, request.MaxShardBytes);
		AddDiff(lines, "MaxTotalShardBytes", oldPolicy.MaxTotalShardBytes, request.MaxTotalShardBytes);
		AddDiff(lines, "MinFreeDiskBytes", oldPolicy.MinFreeDiskBytes, request.MinFreeDiskBytes);
		AddDiff(lines, "OrphanGraceDays", oldPolicy.OrphanGraceDays, request.OrphanGraceDays);
		AddDiff(lines, "SubnetAggregation.Enabled", oldPolicy.SubnetAggregationEnabled, request.SubnetAggregation.Enabled);
		AddDiff(
			lines,
			"SubnetAggregation.TotalFileThreshold",
			oldPolicy.SubnetAggregationTotalFileThreshold,
			request.SubnetAggregation.TotalFileThreshold);
		AddDiff(
			lines,
			"SubnetAggregation.NewFilesPerIntervalLimit",
			oldPolicy.SubnetAggregationNewFilesPerIntervalLimit,
			request.SubnetAggregation.NewFilesPerIntervalLimit);
		AddDiff(
			lines,
			"SubnetAggregation.IntervalSeconds",
			oldPolicy.SubnetAggregationIntervalSeconds,
			request.SubnetAggregation.IntervalSeconds);
		AddDiff(
			lines,
			"SubnetAggregation.MinSourceRowsPerInterval",
			oldPolicy.SubnetAggregationMinSourceRowsPerInterval,
			request.SubnetAggregation.MinSourceRowsPerInterval);
		return lines;
	}

	/// <summary>Pushes a policy reported by the service into the controls and remembers it as the diff
	/// baseline. The server-reported bounds become the controls' ranges, so the editor can never offer a
	/// value the service would refuse.</summary>
	internal void ApplyShardPolicyToControls(ShardingPolicyDto policy)
	{
		ArgumentNullException.ThrowIfNull(policy);
		ApplyShardPolicyValues(policy.Policy, policy.Bounds);
	}

	private void ApplyShardPolicyValues(ShardingPolicyValuesDto values, ShardingPolicyBoundsDto? bounds)
	{
		_lastShardPolicy = values;
		_shardsEnabledCheck.Checked = values.Enabled;
		_shardsRootInput.Text = values.ActionsRoot;
		if (bounds is not null)
		{
			ApplyRange(_shardsOrphanGraceDaysInput, bounds.MinOrphanGraceDays, bounds.MaxOrphanGraceDays);
			ApplyRange(
				_shardsAggregationTotalFilesInput,
				bounds.MinSubnetTotalFileThreshold,
				bounds.MaxSubnetTotalFileThreshold);
			ApplyRange(
				_shardsAggregationNewFilesInput,
				bounds.MinSubnetNewFilesPerIntervalLimit,
				bounds.MaxSubnetNewFilesPerIntervalLimit);
			ApplyRange(
				_shardsAggregationIntervalInput,
				bounds.MinSubnetIntervalSeconds,
				bounds.MaxSubnetIntervalSeconds);
		}

		SetNumeric(_shardsCapacityInput, values.ShardCapacityRecords);
		SetNumeric(_shardsMaxOpenWritersInput, values.MaxOpenWriters);
		SetNumeric(_shardsMaxShardFilesInput, values.MaxShardFiles);
		SetNumeric(_shardsMaxShardBytesInput, values.MaxShardBytes);
		SetNumeric(_shardsMaxTotalShardBytesInput, values.MaxTotalShardBytes);
		SetNumeric(_shardsMinFreeDiskBytesInput, values.MinFreeDiskBytes);
		SetNumeric(_shardsOrphanGraceDaysInput, values.OrphanGraceDays);
		_shardsAggregationCheck.Checked = values.SubnetAggregationEnabled;
		SetNumeric(_shardsAggregationTotalFilesInput, values.SubnetAggregationTotalFileThreshold);
		SetNumeric(_shardsAggregationNewFilesInput, values.SubnetAggregationNewFilesPerIntervalLimit);
		SetNumeric(_shardsAggregationIntervalInput, values.SubnetAggregationIntervalSeconds);
		SetNumeric(_shardsAggregationMinRowsInput, values.SubnetAggregationMinSourceRowsPerInterval);
	}

	/// <summary>Renders the live capacity state as a banner. The red treatment is reserved for a real
	/// refusal or a reached ceiling; a healthy tree gets the calm face and says what it observed.</summary>
	internal void UpdateShardBanner(ShardCapacityStatusDto? status)
	{
		if (status is null)
		{
			SetShardBanner(refusal: false, "Capacity state not reported by this service host.");
			return;
		}

		bool degraded = status.RefusalActive
			|| status.FileBudgetExceeded
			|| status.ByteBudgetExceeded
			|| status.DiskFloorBreached
			|| status.CardinalityGuardActive;

		string text = string.Format(
			CultureInfo.InvariantCulture,
			"{0}   |   budget {1} of {2}   |   free on volume {3}   |   guard {4} ({5} aggregated source(s)){6}",
			status.Message ?? "No shard-capacity refusal since the service started.",
			status.TotalShardBytes < 0 ? "not measured" : status.TotalShardBytes.ToString(CultureInfo.InvariantCulture),
			status.MaxTotalShardBytes == 0 ? "disabled" : status.MaxTotalShardBytes.ToString(CultureInfo.InvariantCulture),
			status.ActionsVolumeFreeBytes is long free ? free.ToString(CultureInfo.InvariantCulture) : "unknown",
			status.CardinalityGuardEnabled ? (status.CardinalityGuardActive ? "engaged" : "armed") : "disabled",
			status.AggregatedSourceCount,
			status.RefusedSourceCountIsLowerBound ? " (refused-source count is a lower bound)" : string.Empty);

		SetShardBanner(degraded, text);
	}

	private void SetShardBanner(bool refusal, string text)
	{
		_shardsBannerLabel.Text = text;
		_shardsBannerLabel.ForeColor = refusal ? StatusDanger : StatusFore;
		_shardsBannerPanel.BackColor = refusal ? RowDangerBack : PanelBack;
	}

	/// <summary>Test surface: the banner text as rendered.</summary>
	internal string ShardBannerText => _shardsBannerLabel.Text;

	/// <summary>Test surface: true when the banner is showing the degraded (red) treatment.</summary>
	internal bool ShardBannerShowsRefusal => _shardsBannerPanel.BackColor == RowDangerBack;

	/// <summary>Test surface: true when the policy editor may write.</summary>
	internal bool ShardsSaveEnabled => _shardsSaveButton.Enabled;

	/// <summary>Test surface: true when the orphan collector may run.</summary>
	internal bool ShardsCollectEnabled => _shardsCollectButton.Enabled;

	// ── Danger Zone ──────────────────────────────────────────────────────────────

	/// <summary>Applies the Danger Zone gate: the three destructive buttons are enabled only with
	/// BOTH DEBUG mode and elevation. Exposed to tests, which is how the "no DEBUG ⇒ disabled"
	/// contract is asserted without a live service.</summary>
	internal void ApplyDangerZoneGate(bool debugMode, bool elevated)
	{
		_dangerDebugMode = debugMode;
		_dangerElevated = elevated;
		bool unlocked = debugMode && elevated;
		_dangerResetButton.Enabled = unlocked;
		_dangerClearDataButton.Enabled = unlocked;
		_dangerRestoreOverLiveButton.Enabled = unlocked;
		_dangerPurgeSubjectButton.Enabled = unlocked;
		_dangerCompactButton.Enabled = unlocked;
		_dangerGateLabel.Text = unlocked
			? "DEBUG mode and elevation detected: the destructive actions below are unlocked. Each one still asks for a typed phrase."
			: string.Format(
				CultureInfo.InvariantCulture,
				"Locked. DEBUG mode: {0}. Elevation: {1}. Both are required (Settings → Diagnostics.DebugMode; run the Configurator as Administrator).",
				debugMode ? "on" : "off",
				elevated ? "yes" : "no");
		_dangerGateLabel.ForeColor = unlocked ? StatusDanger : StatusWarning;
		UpdateBackupButtonState();
	}

	/// <summary>True when the Danger Zone actions are unlocked. Test surface.</summary>
	internal bool DangerZoneUnlocked => _dangerDebugMode && _dangerElevated;

	/// <summary>The sentence the Danger Zone shows about its gate state ("Locked. DEBUG mode: …" or the
	/// unlocked variant), so a test can assert that the operator is told WHY the actions are disabled
	/// instead of facing a silently dead toolbar. Test surface.</summary>
	internal string DangerZoneGateText => _dangerGateLabel.Text ?? string.Empty;

	/// <summary>Re-reads the persisted DEBUG switch and the current elevation, then applies the gate.
	/// Fail-closed: a transport or JSON problem leaves the gate locked.</summary>
	internal async Task RefreshDangerZoneGateAsync()
	{
		bool debugMode = false;
		try
		{
			IpcCallResult<JsonNode> call = await _ipc
				.SendDetailedAsync<JsonNode>(IpcCommand.GetSettings, null, CurrentToken())
				.ConfigureAwait(true);
			if (call.IsSuccess && call.Value is JsonObject root
				&& root["Diagnostics"]?["DebugMode"] is JsonValue value
				&& value.TryGetValue(out bool configured))
			{
				debugMode = configured;
			}
		}
		catch (Exception)
		{
			debugMode = false;
		}

		ApplyDangerZoneGate(debugMode, ElevationGuard.Check().IsElevated);
	}

	/// <summary>
	/// The marker-driven "back up and reset database" flow. Without a migration-failure marker there
	/// is nothing for this scenario to do, and the status says exactly that instead of running a reset
	/// on a healthy store.
	/// </summary>
	internal async Task ResetDatabaseAsync()
	{
		await RefreshDangerZoneGateAsync().ConfigureAwait(true);
		if (!RequireDangerZone("Back up and reset database"))
		{
			return;
		}

		string programData = RdpAuditPaths.Default.ProgramDataDirectory;
		MigrationFailureMarkerPayload? marker;
		try
		{
			marker = await Task.Run(() => DatabaseMigrationFailureMarker.TryRead(programData)).ConfigureAwait(true);
		}
		catch (Exception ex)
		{
			SetStatus("Reset database: the migration-failure marker could not be read: " + ex.GetType().Name, isError: true);
			return;
		}

		if (marker is null)
		{
			SetStatus(
				"Reset database: no migration-failure marker is present under " + programData
					+ ". This scenario exists for an INCOMPATIBLE schema — the service writes the marker when a migration fails. Nothing was done.",
				isError: true);
			_dangerReport.Text = "No migration-failure marker was found, so the reset scenario does not apply."
				+ Environment.NewLine + Environment.NewLine
				+ "Marker directory: " + programData + Environment.NewLine
				+ "The guided reset exists for the case where a schema migration failed and the service stopped itself "
				+ "to avoid a restart loop. On a healthy store, use Backup & Restore or Maintenance instead.";
			return;
		}

		string prompt =
			"Back up and reset the incompatible database?" + Environment.NewLine + Environment.NewLine
			+ "Failed migration: " + (marker.PendingMigrations.Count > 0 ? marker.PendingMigrations[0] : "(unknown)") + Environment.NewLine
			+ "Marker written:   " + marker.TimestampUtc.ToString("yyyy-MM-dd HH:mm:ss 'UTC'", CultureInfo.InvariantCulture) + Environment.NewLine
			+ "Exception:        " + (marker.ExceptionType ?? "(unknown)") + " — " + (marker.ExceptionMessage ?? "(no message)") + Environment.NewLine + Environment.NewLine
			+ "The service is stopped, the database and its WAL/SHM sidecars are renamed to timestamped .bak files, "
			+ "the marker is deleted and the service is started again so it creates a fresh schema.";
		if (!ConfirmPrompt(prompt, "Confirm database reset"))
		{
			SetStatus("Reset database cancelled.");
			return;
		}

		string typed = PromptForConfirmationPhrase(ResetDatabasePhrase);
		if (!string.Equals(typed, ResetDatabasePhrase, StringComparison.Ordinal))
		{
			SetStatus("Reset database cancelled: the confirmation phrase did not match.");
			return;
		}

		await RunDangerActionAsync(
			"Back up and reset database",
			async ct =>
			{
				DatabaseResetResult result = await new DatabaseResetService()
					.ExecuteAsync(marker, programData, ct)
					.ConfigureAwait(true);
				string status = result.Success
					? "Database reset completed."
					: "Database reset did not complete.";
				string report = result.Log
					+ Environment.NewLine
					+ Environment.NewLine
					+ "Backup path: " + (result.BackupPath ?? "(none — the database file may not have existed)");
				return (status, report);
			}).ConfigureAwait(true);
	}

	/// <summary>Clears all accumulated application data through the existing ordinal 57 with the same
	/// typed phrase the Firewall page uses; the service re-validates the phrase server-side.</summary>
	internal async Task ClearAllApplicationDataAsync()
	{
		await RefreshDangerZoneGateAsync().ConfigureAwait(true);
		if (!RequireDangerZone("Clear all application data"))
		{
			return;
		}

		string prompt =
			"Clear ALL application data?" + Environment.NewLine + Environment.NewLine
			+ "This permanently deletes the accumulated RdpAudit data (raw events, auth-attempt and connection facts, "
			+ "active blocks, blocklist / whitelist entries, alerts, sessions, addresses, correlations, attack stats and "
			+ "abuse report history). Schema, migrations, configuration and event-log read positions are preserved, so the "
			+ "service keeps running. This cannot be undone.";
		if (!ConfirmPrompt(prompt, "Confirm application-data cleanup"))
		{
			SetStatus("Clear all application data cancelled.");
			return;
		}

		string typed = PromptForConfirmationPhrase(ClearAllDataPhrase);
		if (!string.Equals(typed, ClearAllDataPhrase, StringComparison.Ordinal))
		{
			SetStatus("Clear all application data cancelled: the confirmation phrase did not match.");
			return;
		}

		await RunDangerActionAsync(
			"Clear all application data",
			async ct =>
			{
				IpcCallResult<AppDataPurgeResultDto> call = await _ipc
					.SendDetailedAsync<AppDataPurgeResultDto>(IpcCommand.ClearAllApplicationData, ClearAllDataPhrase, ct)
					.ConfigureAwait(true);
				if (!call.IsSuccess || call.Value is not { } result)
				{
					return ("Clear all application data: " + call.Headline(),
						"The clear could not be run: " + call.Headline());
				}

				StringBuilder log = new();
				log.AppendLine(result.Message);
				log.AppendLine();
				foreach (PurgedTableDto table in result.TablesCleared)
				{
					log.AppendLine("  " + table.Table.PadRight(28) + table.RowsCleared.ToString(CultureInfo.InvariantCulture) + " row(s)");
				}

				foreach (string file in result.FilesRemoved)
				{
					log.AppendLine("  removed file: " + file);
				}

				log.AppendLine();
				log.AppendLine("Full VACUUM: " + (result.DatabaseVacuumed ? "yes" : "no (never on the live store)")
					+ "; WAL checkpointed: " + result.WalCheckpointed
					+ "; incremental vacuum: " + result.IncrementalVacuumed
					+ "; errors: " + result.Errors);
				if (!string.IsNullOrEmpty(result.SpaceReclamation))
				{
					log.AppendLine("Space reclamation: " + result.SpaceReclamation);
				}
				if (!string.IsNullOrEmpty(result.DebugLog))
				{
					log.AppendLine();
					log.AppendLine("DEBUG detail:");
					log.AppendLine(result.DebugLog);
				}

				return (result.Message, log.ToString());
			}).ConfigureAwait(true);
	}

	/// <summary>Runs one gated destructive action with busy handling and a monospace report.</summary>
	private async Task RunDangerActionAsync(string action, Func<CancellationToken, Task<(string Status, string Report)>> body)
	{
		if (!BeginBusy())
		{
			return;
		}

		try
		{
			(string status, string report) = await body(CurrentToken()).ConfigureAwait(true);
			_dangerReport.Text = report;
			SetStatus(action + ": " + status);
			await RefreshOverviewAsync(manageBusy: false).ConfigureAwait(true);
		}
		catch (OperationCanceledException)
		{
			SetStatus(action + ": cancelled. The service may still be completing the operation.", isError: true);
		}
		catch (Exception ex)
		{
			SetStatus(action + " failed: " + ex.GetType().Name + " — " + ex.Message, isError: true);
		}
		finally
		{
			EndBusy();
		}
	}

	/// <summary>
	/// Opens the subject-purge dialog behind the Danger Zone gate. The dialog itself enforces the
	/// dry-run-then-phrase sequence; this method only decides whether the operator is allowed to start, and
	/// renders the dialog's outcome into the shared Danger Zone report.
	/// </summary>
	internal async Task PurgeBySubjectAsync()
	{
		await RefreshDangerZoneGateAsync().ConfigureAwait(true);
		if (!RequireDangerZone("Purge by subject"))
		{
			return;
		}

		if (!ConfirmPrompt(
			"Purge evidence by subject?" + Environment.NewLine + Environment.NewLine
			+ "This deletes every evidence row about one address, CIDR range, login or UTC time window, across "
			+ "the tables that carry that dimension - including the anchor of a code, which is why it needs an "
			+ "explicit operator request." + Environment.NewLine + Environment.NewLine
			+ "The dialog runs a dry run first and shows the per-table counts; applying needs the typed phrase "
			+ "and is refused outright while a legal hold is in force. Operator configuration, enforcement state, "
			+ "the schema, the bookmarks and the migration history are never touched. This cannot be undone.",
			"Confirm subject purge"))
		{
			SetStatus("Purge by subject cancelled.");
			return;
		}

		PurgeBySubjectDialog dialog = NewPurgeDialog();
		try
		{
			dialog.ShowDialog(this);
		}
		finally
		{
			dialog.Dispose();
		}

		string summary = dialog.LastOutcomeSummary ?? "The dialog was closed without purging; nothing was deleted.";
		_dangerReport.Text = summary;
		SetStatus("Purge by subject: see the report below.");
		await RefreshOverviewAsync(manageBusy: false).ConfigureAwait(true);
	}

	/// <summary>Creates the purge dialog. A seam so a test can supply one with replaced call hooks.</summary>
	internal Func<PurgeBySubjectDialog> NewPurgeDialog { get; set; } = null!;

	/// <summary>
	/// Compacts the database file with the service stopped, through the Configurator's
	/// <see cref="DatabaseCompactService"/> (VACUUM INTO a verified copy, the copy's auto-vacuum mode
	/// normalised to INCREMENTAL, then an atomic swap that reuses the restore mechanics). This is the only
	/// operation in the product that shrinks the file; the online purge path deliberately never runs a full
	/// VACUUM. It is also the only route that lets a store created by an older build reclaim space online
	/// again, because such a store is in auto-vacuum mode NONE where the bounded incremental vacuum is a
	/// no-op.
	/// </summary>
	internal async Task CompactDatabaseOfflineAsync()
	{
		await RefreshDangerZoneGateAsync().ConfigureAwait(true);
		if (!RequireDangerZone("Compact database (offline)"))
		{
			return;
		}

		string databasePath = string.IsNullOrEmpty(_lastDatabasePath)
			? RdpAudit.Core.Util.RdpAuditPaths.Default.DatabasePath
			: _lastDatabasePath;

		if (!ConfirmPrompt(
			"Compact the database file with the service stopped?" + Environment.NewLine + Environment.NewLine
			+ "The RdpAudit service will be STOPPED. A full VACUUM rewrites the whole file inside one write "
			+ "transaction, which is why it cannot run against a live store: on a multi-gigabyte evidence store "
			+ "it can hold the writer for minutes." + Environment.NewLine + Environment.NewLine
			+ "Target: " + databasePath + Environment.NewLine + Environment.NewLine
			+ "The compaction writes a VACUUM INTO copy, verifies it (quick_check, per-table row counts, the "
			+ "migration history, foreign keys), swaps it in atomically and restarts the service. The current "
			+ "file is kept beside the store as a timestamped .bak until you delete it." + Environment.NewLine + Environment.NewLine
			+ "This is also the only way to make online space reclamation work on a store created by an older "
			+ "build: such a store is in auto-vacuum mode NONE, where the bounded incremental vacuum of the "
			+ "purge and the maintenance surface releases nothing. The compaction rewrites the copy into "
			+ "INCREMENTAL mode, which costs one further VACUUM over the compacted copy and needs twice its "
			+ "size in free space beside the store; it is refused when that space is not available.",
			"Confirm offline compaction"))
		{
			SetStatus("Offline compaction cancelled.");
			return;
		}

		string typed = PromptForConfirmationPhrase(CompactOfflinePhrase);
		if (!string.Equals(typed, CompactOfflinePhrase, StringComparison.Ordinal))
		{
			SetStatus("Offline compaction cancelled: the confirmation phrase did not match.");
			return;
		}

		await RunDangerActionAsync(
			"Compact database (offline)",
			async ct =>
			{
				DatabaseCompactResult result = await _compactService
					.ExecuteAsync(databasePath, ct)
					.ConfigureAwait(true);
				string headline = result.Compacted
					? result.Success
						? "Compaction complete: " + DescribeBytes(result.BytesReclaimed) + " reclaimed; "
							+ "auto-vacuum mode "
							+ DescribeModeTransition(result.AutoVacuumModeBefore, result.AutoVacuumModeAfter)
							+ "."
						: "Compaction completed, but the service could not be restarted."
					: "Compaction refused; the store is unchanged.";
				return (headline, result.Log);
			}).ConfigureAwait(true);
	}

	/// <summary>
	/// Re-checks the gate at click time (fail-closed) and says what is missing. The buttons are
	/// disabled while the gate is closed, so this is the second line of defence: the state can change
	/// between the last refresh and the click.
	/// </summary>
	private bool RequireDangerZone(string action)
	{
		ElevationStatus elevation = ElevationGuard.Check();
		if (!_dangerDebugMode || !elevation.IsElevated)
		{
			ApplyDangerZoneGate(_dangerDebugMode, elevation.IsElevated);
			SetStatus(
				action + " refused: " + (!_dangerDebugMode ? "DEBUG mode is off" : "the process is not elevated")
					+ ". Both DEBUG mode and elevation are required.",
				isError: true);
			return false;
		}

		return true;
	}

	// ── Ledger ───────────────────────────────────────────────────────────────────

	private async Task ChangeLedgerPageAsync(int delta)
	{
		int target = _ledgerPage + delta;
		if (target < 0)
		{
			return;
		}

		_ledgerPage = target;
		await LoadLedgerAsync(resetPage: false).ConfigureAwait(true);
	}

	/// <summary>Loads one filtered page of the append-only deletion ledger, newest first.</summary>
	internal async Task LoadLedgerAsync(bool resetPage)
	{
		if (resetPage)
		{
			_ledgerPage = 0;
		}

		if (!BeginBusy())
		{
			return;
		}

		try
		{
			DeletionLedgerQueryRequest request = BuildLedgerRequest(_ledgerPage, (int)_ledgerPageSizeInput.Value);
			IpcCallResult<DeletionLedgerPageDto> call = await _ipc
				.SendDetailedAsync<DeletionLedgerPageDto>(IpcCommand.GetDeletionLedger, request, CurrentToken())
				.ConfigureAwait(true);
			if (!call.IsSuccess || call.Value is not { } page)
			{
				SetStatus("Deletion ledger unavailable: " + call.Headline(), isError: true);
				return;
			}

			if (page.Status != IpcResultStatus.Success)
			{
				SetStatus("Deletion ledger query failed: " + (page.Message ?? page.Status.ToString()), isError: true);
				return;
			}

			_ledgerRows.Clear();
			_ledgerRows.AddRange(page.Items);
			_ledgerTotal = page.TotalMatching;
			BindLedgerGrid();
			_ledgerStamp.Text = "as of " + AsOf(page.QueriedUtc);
			_ledgerPage = page.Page;

			long shownFrom = _ledgerTotal == 0 ? 0 : ((long)_ledgerPage * page.PageSize) + 1;
			long shownTo = shownFrom == 0 ? 0 : shownFrom + _ledgerRows.Count - 1;
			_ledgerPrevButton.Enabled = _ledgerPage > 0;
			_ledgerNextButton.Enabled = page.HasMore;
			SetStatus(string.Format(
				CultureInfo.InvariantCulture,
				"Ledger as of {0}: showing {1}-{2} of {3} (page {4}).",
				AsOf(page.QueriedUtc),
				shownFrom,
				shownTo,
				_ledgerTotal,
				_ledgerPage + 1));
		}
		catch (Exception ex)
		{
			SetStatus("Deletion ledger failed: " + ex.GetType().Name, isError: true);
		}
		finally
		{
			EndBusy();
		}
	}

	/// <summary>Builds the ledger request from the filter controls. Exposed to tests: the mapping is
	/// what a filter regression would break.</summary>
	internal DeletionLedgerQueryRequest BuildLedgerRequest(int page, int pageSize)
	{
		int eventId = (int)_ledgerEventIdInput.Value;
		return new DeletionLedgerQueryRequest
		{
			EventCode = eventId <= 0 ? null : eventId,
			FromUtc = _ledgerFrom.Checked ? _ledgerFrom.Value.ToUniversalTime() : null,
			ToUtc = _ledgerTo.Checked ? _ledgerTo.Value.ToUniversalTime() : null,
			Page = page,
			PageSize = pageSize,
		};
	}

	private void BindLedgerGrid()
	{
		_ledgerGrid.Rows.Clear();
		foreach (DeletionLedgerEntryDto row in _ledgerRows)
		{
			_ledgerGrid.Rows.Add(
				row.CreatedUtc.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture),
				row.EventCode.ToString(CultureInfo.InvariantCulture),
				row.Scope.ToString(),
				row.IpHex,
				row.WindowStartUtc.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture),
				row.WindowEndUtc.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture),
				row.RowsDeleted.ToString(CultureInfo.InvariantCulture),
				row.Trigger.ToString(),
				row.RuleVersion.ToString(CultureInfo.InvariantCulture),
				row.Reason,
				row.InitiatedBy);
		}
	}

	/// <summary>
	/// Exports the ledger to CSV. The export pages through the service (bounded at
	/// <see cref="LedgerExportMaxRows"/>) so the file is the whole filtered ledger, not just the
	/// visible page; the row that stops the export states the bound honestly.
	/// </summary>
	internal async Task ExportLedgerCsvAsync()
	{
		if (!BeginBusy())
		{
			return;
		}

		try
		{
			List<DeletionLedgerEntryDto> all = new();
			int page = 0;
			long total = -1;
			bool truncated = false;
			while (all.Count < LedgerExportMaxRows)
			{
				DeletionLedgerQueryRequest request = BuildLedgerRequest(page, LedgerExportPageSize);
				IpcCallResult<DeletionLedgerPageDto> call = await _ipc
					.SendDetailedAsync<DeletionLedgerPageDto>(IpcCommand.GetDeletionLedger, request, CurrentToken())
					.ConfigureAwait(true);
				if (!call.IsSuccess || call.Value is not { } result || result.Status != IpcResultStatus.Success)
				{
					SetStatus("Ledger export failed while paging: " + call.Headline(), isError: true);
					return;
				}

				total = result.TotalMatching;
				all.AddRange(result.Items);
				if (!result.HasMore || result.Items.Count == 0)
				{
					break;
				}

				page++;
			}

			if (total > all.Count)
			{
				truncated = true;
			}

			string? target = ChooseLedgerExportPath();
			if (string.IsNullOrWhiteSpace(target))
			{
				SetStatus("Ledger export cancelled.");
				return;
			}

			string csv = BuildLedgerCsv(all, truncated);
			await File.WriteAllTextAsync(target, csv, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false), CurrentToken())
				.ConfigureAwait(true);
			SetStatus(string.Format(
				CultureInfo.InvariantCulture,
				"Ledger exported: {0} row(s){1} written to {2}.",
				all.Count,
				truncated ? " (bounded at " + LedgerExportMaxRows.ToString(CultureInfo.InvariantCulture) + "; the ledger holds more)" : string.Empty,
				target),
				isError: truncated);
		}
		catch (OperationCanceledException)
		{
			SetStatus("Ledger export cancelled.", isError: true);
		}
		catch (Exception ex)
		{
			SetStatus("Ledger export failed: " + ex.GetType().Name + " — " + ex.Message, isError: true);
		}
		finally
		{
			EndBusy();
		}
	}

	/// <summary>Renders the ledger CSV. Pure and static so the format is testable and can never
	/// silently change shape.</summary>
	internal static string BuildLedgerCsv(IReadOnlyList<DeletionLedgerEntryDto> rows, bool truncated)
	{
		ArgumentNullException.ThrowIfNull(rows);
		StringBuilder sb = new();
		sb.AppendLine("CreatedUtc,EventCode,Scope,IpHex,WindowStartUtc,WindowEndUtc,RowsDeleted,Trigger,RuleVersion,Reason,InitiatedBy");
		foreach (DeletionLedgerEntryDto row in rows)
		{
			sb.Append(Csv(row.CreatedUtc.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture))).Append(',')
				.Append(row.EventCode.ToString(CultureInfo.InvariantCulture)).Append(',')
				.Append(Csv(row.Scope.ToString())).Append(',')
				.Append(Csv(row.IpHex)).Append(',')
				.Append(Csv(row.WindowStartUtc.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture))).Append(',')
				.Append(Csv(row.WindowEndUtc.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture))).Append(',')
				.Append(row.RowsDeleted.ToString(CultureInfo.InvariantCulture)).Append(',')
				.Append(Csv(row.Trigger.ToString())).Append(',')
				.Append(row.RuleVersion.ToString(CultureInfo.InvariantCulture)).Append(',')
				.Append(Csv(row.Reason)).Append(',')
				.AppendLine(Csv(row.InitiatedBy));
		}

		sb.AppendLine();
		sb.AppendLine("# rows=" + rows.Count.ToString(CultureInfo.InvariantCulture));
		sb.AppendLine("# truncated=" + truncated);
		return sb.ToString();
	}

	private static string Csv(string? value)
	{
		string text = value ?? string.Empty;
		bool quote = text.Contains(',', StringComparison.Ordinal)
			|| text.Contains('"', StringComparison.Ordinal)
			|| text.Contains('\n', StringComparison.Ordinal)
			|| text.Contains('\r', StringComparison.Ordinal);
		return quote ? "\"" + text.Replace("\"", "\"\"", StringComparison.Ordinal) + "\"" : text;
	}

	// ── Busy / status / dialog helpers ───────────────────────────────────────────

	/// <summary>Last-resort report for an exception that escaped a page operation. Never throws: it does
	/// not touch a disposed tab, where there is no surface left to write to. Handlers are attached through
	/// the shared <see cref="Services.SafeAsyncHandler"/>, which journals the fault as well; this is
	/// the page's own visible report for what an operation's catch blocks cannot cover themselves - the
	/// error path throwing, or the failure report itself failing.</summary>
	private void ReportHandlerFailure(Exception ex)
	{
		Debug.WriteLine("[DatabasePage] handler failed outside the page's own error path: " + ex);
		if (IsDisposed || Disposing || _statusStrip.IsDisposed)
		{
			return;
		}

		SetStatus("Database action failed: " + ex.GetType().Name + " — " + ex.Message, isError: true);
	}

	/// <summary>Re-entrancy and UI-busy guard. While a call is in flight the inner tab control is
	/// disabled, so no second overlapping operation can be started by a double click; the cancel
	/// button stays ENABLED because it lives in the operation bar below the tab control. WinForms
	/// reports a control inside a disabled container as <c>Enabled == false</c> even when its own flag
	/// is set, so that placement - not the flag - is what keeps cancellation reachable.</summary>
	internal bool BeginBusy()
	{
		if (_operationInFlight)
		{
			SetStatus("Operation in progress — wait for the current Database operation to finish.");
			return false;
		}

		_operationInFlight = true;
		_operationCts?.Dispose();
		_operationCts = new CancellationTokenSource();
		_innerTabs.Enabled = false;
		_cancelOperationButton.Enabled = true;
		return true;
	}

	internal void EndBusy()
	{
		_operationInFlight = false;
		_innerTabs.Enabled = true;
		_cancelOperationButton.Enabled = false;
		_operationCts?.Dispose();
		_operationCts = null;
	}

	private CancellationToken CurrentToken() => _operationCts?.Token ?? CancellationToken.None;

	/// <summary>Modal prompt that requires the operator to type the exact destructive-confirmation
	/// phrase. Returns the trimmed text (empty on cancel) so the caller can compare it ordinally.</summary>
	internal string PromptForConfirmationPhrase(string requiredPhrase)
	{
		using Form dialog = new()
		{
			Text = "Type the confirmation phrase",
			StartPosition = FormStartPosition.CenterParent,
			FormBorderStyle = FormBorderStyle.FixedDialog,
			Size = new Size(520, 190),
			MinimizeBox = false,
			MaximizeBox = false,
			ShowInTaskbar = false,
		};

		Label label = new()
		{
			Text = "To proceed, type the following phrase exactly:\r\n\r\n" + requiredPhrase,
			Dock = DockStyle.Top,
			AutoSize = false,
			Height = 70,
			Padding = new Padding(12, 12, 12, 0),
		};
		TextBox input = new()
		{
			Dock = DockStyle.Top,
			Margin = new Padding(12),
			Width = 480,
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

	private static bool Confirm(string message, string caption) =>
		MessageBox.Show(message, caption, MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2) == DialogResult.Yes;

	/// <summary>The real file picker behind <see cref="ChooseLedgerExportPath"/>. Returns null when the
	/// operator cancelled, which the caller reports as a cancellation rather than as a failure.</summary>
	private string? AskForLedgerExportPath()
	{
		using SaveFileDialog dialog = new()
		{
			Title = "Export the deletion ledger",
			Filter = "CSV files (*.csv)|*.csv|All files (*.*)|*.*",
			FileName = string.Format(
				CultureInfo.InvariantCulture,
				"rdpaudit-deletion-ledger-{0:yyyyMMdd-HHmmss}.csv",
				DateTime.UtcNow),
			OverwritePrompt = true,
		};
		return dialog.ShowDialog(this) == DialogResult.OK ? dialog.FileName : null;
	}

	/// <summary>Renders a timestamped status line; every message the page shows goes through here so
	/// no operator-facing line is ever missing its stamp. Uses Invoke when called off the UI thread.</summary>
	internal void SetStatus(string message, bool isError = false)
	{
		string stamped = string.Format(CultureInfo.InvariantCulture, "[{0:HH:mm:ss}Z] {1}", DateTime.UtcNow, message);
		void Apply()
		{
			_statusLabel.Text = stamped;
			_statusLabel.ForeColor = isError ? StatusDanger : StatusFore;
		}

		if (_statusStrip.InvokeRequired)
		{
			_statusStrip.BeginInvoke(new Action(Apply));
		}
		else
		{
			Apply();
		}
	}

	/// <summary>The current status text. Test surface.</summary>
	internal string StatusText => _statusLabel.Text ?? string.Empty;

	/// <summary>Reports an export result through the same status line every other page action uses.</summary>
	private void ReportExportStatus(string message) => SetStatus(message);

	// ── Small builders ───────────────────────────────────────────────────────────

	private static string AsOf(DateTime utc) =>
		utc.ToString("HH:mm:ss", CultureInfo.InvariantCulture) + " UTC";

	/// <summary>Renders a byte count honestly: -1 is "unknown", 0 is "0 B", never a fabricated number.</summary>
	internal static string DescribeBytes(long bytes)
	{
		if (bytes < 0)
		{
			return "unknown";
		}

		string[] units = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
		double value = bytes;
		int unit = 0;
		while (value >= 1024 && unit < units.Length - 1)
		{
			value /= 1024;
			unit++;
		}

		return string.Format(CultureInfo.InvariantCulture, "{0:0.##} {1} ({2} bytes)", value, units[unit], bytes);
	}

	/// <summary>Renders the auto-vacuum transition of an offline compaction. A mode that was not read is
	/// reported as unknown instead of being rendered as a transition that cannot be claimed.</summary>
	internal static string DescribeModeTransition(int modeBefore, int modeAfter)
		=> modeBefore < 0 || modeAfter < 0
			? "unknown"
			: modeBefore.ToString(CultureInfo.InvariantCulture) + " -> " + modeAfter.ToString(CultureInfo.InvariantCulture);

	private static FlowLayoutPanel NewButtonBar() => new()
	{
		Dock = DockStyle.Top,
		FlowDirection = FlowDirection.LeftToRight,
		AutoSize = true,
		WrapContents = true,
		Padding = new Padding(2),
	};

	private static TableLayoutPanel NewGrid(int columns, int rows)
	{
		TableLayoutPanel panel = new()
		{
			Dock = DockStyle.Fill,
			ColumnCount = columns,
			RowCount = rows,
			Padding = new Padding(4),
			AutoSize = true,
			AutoSizeMode = AutoSizeMode.GrowAndShrink,
		};
		for (int row = 0; row < rows; row++)
		{
			panel.RowStyles.Add(new RowStyle(SizeType.AutoSize));
		}

		return panel;
	}

	private static Label MakeFieldLabel(string text) => new()
	{
		Text = text,
		AutoSize = true,
		Anchor = AnchorStyles.Left,
		Margin = new Padding(0, 6, 8, 0),
	};

	private static NumericUpDown MakeIntInput(int min, int max, int value) => new()
	{
		Minimum = min,
		Maximum = max,
		Value = value,
		Width = 120,
		Anchor = AnchorStyles.Left,
		ThousandsSeparator = true,
	};

	private static NumericUpDown MakeLongInput(long min, long max, long value) => new()
	{
		Minimum = min,
		Maximum = max,
		Value = value,
		Width = 140,
		Anchor = AnchorStyles.Left,
		ThousandsSeparator = true,
	};

	private static void SetNumeric(NumericUpDown input, decimal value) =>
		input.Value = Math.Clamp(value, input.Minimum, input.Maximum);

	private static void ApplyRange(NumericUpDown input, int min, int max)
	{
		if (min > max)
		{
			return;
		}

		input.Minimum = min;
		input.Maximum = max;
		if (input.Value < min)
		{
			input.Value = min;
		}
		else if (input.Value > max)
		{
			input.Value = max;
		}
	}

	private static TextBox MakeMonospaceReport() => new()
	{
		Dock = DockStyle.Fill,
		Multiline = true,
		ReadOnly = true,
		ScrollBars = ScrollBars.Both,
		WordWrap = false,
		Font = new Font(FontFamily.GenericMonospace, 9f),
	};

	private static Button MakeButton(string text, EventHandler onClick)
	{
		ArgumentNullException.ThrowIfNull(onClick);
		Button button = new() { Text = text, AutoSize = true, Margin = new Padding(2) };
		button.Click += onClick;
		return button;
	}

	private static List<int> ParseEventIds(string text)
	{
		if (string.IsNullOrWhiteSpace(text))
		{
			return [];
		}

		List<int> ids = new();
		foreach (string part in text.Split([',', ';', ' '], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
		{
			if (int.TryParse(part, NumberStyles.Integer, CultureInfo.InvariantCulture, out int id) && id > 0)
			{
				ids.Add(id);
			}
		}

		return ids;
	}

	private void SelectAnchorScope(RetentionAnchorScope scope)
	{
		foreach (object? item in _anchorScopeCombo.Items)
		{
			if (item is AnchorScopeChoice choice && choice.Scope == scope)
			{
				_anchorScopeCombo.SelectedItem = item;
				return;
			}
		}

		_anchorScopeCombo.SelectedIndex = 0;
	}

	private RetentionAnchorScope SelectedAnchorScope() =>
		_anchorScopeCombo.SelectedItem is AnchorScopeChoice choice ? choice.Scope : RetentionAnchorScope.PerCode;

	private BackupRow? SelectedBackup()
	{
		if (_backupsGrid.SelectedRows.Count == 0)
		{
			if (_backupsGrid.CurrentRow is { Index: >= 0 } current && current.Index < _backupRows.Count)
			{
				return _backupRows[current.Index];
			}

			return null;
		}

		int index = _backupsGrid.SelectedRows[0].Index;
		return index >= 0 && index < _backupRows.Count ? _backupRows[index] : null;
	}

	private void UpdateBackupButtonState()
	{
		bool hasSelection = SelectedBackup() is not null;
		bool hasAny = _backupRows.Count > 0;
		_verifyBackupButton.Enabled = hasAny;
		_restoreToFolderButton.Enabled = hasSelection;
		_restoreOverLiveButton.Enabled = hasSelection && _dangerElevated;
	}

	private void ConfigureEventRetentionColumns()
	{
		_eventRetentionGrid.Columns.Add(new DataGridViewTextBoxColumn
		{
			DataPropertyName = nameof(EventRetentionRow.EventId),
			HeaderText = "Event ID",
			ReadOnly = true,
			Width = 80,
		});
		_eventRetentionGrid.Columns.Add(new DataGridViewTextBoxColumn
		{
			DataPropertyName = nameof(EventRetentionRow.Channel),
			HeaderText = "Channel",
			ReadOnly = true,
			Width = 220,
		});
		_eventRetentionGrid.Columns.Add(new DataGridViewTextBoxColumn
		{
			DataPropertyName = nameof(EventRetentionRow.DisplayName),
			HeaderText = "Name",
			ReadOnly = true,
			Width = 180,
		});
		_eventRetentionGrid.Columns.Add(new DataGridViewTextBoxColumn
		{
			DataPropertyName = nameof(EventRetentionRow.RetentionDays),
			HeaderText = "Retention (days)",
			Width = 120,
		});
		_eventRetentionGrid.Columns.Add(new DataGridViewTextBoxColumn
		{
			DataPropertyName = nameof(EventRetentionRow.DefaultRetentionDaysText),
			HeaderText = "Catalog default",
			ReadOnly = true,
			Width = 110,
		});
		_eventRetentionGrid.Columns.Add(new DataGridViewTextBoxColumn
		{
			DataPropertyName = nameof(EventRetentionRow.UpdatedUtcText),
			HeaderText = "Updated (UTC)",
			ReadOnly = true,
			AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill,
			MinimumWidth = 150,
		});
	}

	private void ConfigurePreviewColumns()
	{
		_previewGrid.Columns.Add(new DataGridViewTextBoxColumn { DataPropertyName = nameof(PreviewRow.EventId), HeaderText = "Event ID", Width = 80 });
		_previewGrid.Columns.Add(new DataGridViewTextBoxColumn { DataPropertyName = nameof(PreviewRow.Channel), HeaderText = "Channel", Width = 180 });
		_previewGrid.Columns.Add(new DataGridViewTextBoxColumn { DataPropertyName = nameof(PreviewRow.IpHex), HeaderText = "IP (hex)", Width = 110 });
		_previewGrid.Columns.Add(new DataGridViewTextBoxColumn { DataPropertyName = nameof(PreviewRow.Count), HeaderText = "Rows", Width = 90 });
		_previewGrid.Columns.Add(new DataGridViewTextBoxColumn { DataPropertyName = nameof(PreviewRow.EligibleInteriorRows), HeaderText = "Eligible interior", Width = 110 });
		_previewGrid.Columns.Add(new DataGridViewTextBoxColumn { DataPropertyName = nameof(PreviewRow.PlannedRows), HeaderText = "Planned rows", Width = 100 });
		_previewGrid.Columns.Add(new DataGridViewTextBoxColumn { DataPropertyName = nameof(PreviewRow.SkipReasonText), HeaderText = "Protected / skipped", Width = 160 });
		_previewGrid.Columns.Add(new DataGridViewTextBoxColumn { DataPropertyName = nameof(PreviewRow.WindowText), HeaderText = "Affected window (UTC)", Width = 240 });
		_previewGrid.Columns.Add(new DataGridViewTextBoxColumn
		{
			DataPropertyName = nameof(PreviewRow.Explanation),
			HeaderText = "Explanation",
			AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill,
			MinimumWidth = 240,
		});
	}

	private void ConfigureBackupColumns()
	{
		_backupsGrid.Columns.Add(new DataGridViewTextBoxColumn { DataPropertyName = nameof(BackupRow.CreatedUtcText), HeaderText = "Created (UTC)", Width = 140 });
		_backupsGrid.Columns.Add(new DataGridViewTextBoxColumn { DataPropertyName = nameof(BackupRow.Name), HeaderText = "Snapshot", Width = 150 });
		_backupsGrid.Columns.Add(new DataGridViewTextBoxColumn { DataPropertyName = nameof(BackupRow.DatabaseBytesText), HeaderText = "DB size", Width = 110 });
		_backupsGrid.Columns.Add(new DataGridViewTextBoxColumn { DataPropertyName = nameof(BackupRow.SnapshotBytesText), HeaderText = "Snapshot size", Width = 110 });
		_backupsGrid.Columns.Add(new DataGridViewTextBoxColumn { DataPropertyName = nameof(BackupRow.ManifestText), HeaderText = "Manifest", Width = 110 });
		_backupsGrid.Columns.Add(new DataGridViewTextBoxColumn { DataPropertyName = nameof(BackupRow.Kind), HeaderText = "Kind", Width = 90 });
		_backupsGrid.Columns.Add(new DataGridViewTextBoxColumn { DataPropertyName = nameof(BackupRow.ShardsText), HeaderText = "Shards", Width = 90 });
		_backupsGrid.Columns.Add(new DataGridViewTextBoxColumn { DataPropertyName = nameof(BackupRow.ProductVersion), HeaderText = "Product version", Width = 110 });
		_backupsGrid.Columns.Add(new DataGridViewTextBoxColumn
		{
			DataPropertyName = nameof(BackupRow.LastAppliedMigration),
			HeaderText = "Last applied migration",
			AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill,
			MinimumWidth = 180,
		});
	}

	private void ConfigureShardColumns()
	{
		_shardsGrid.Columns.Add(new DataGridViewTextBoxColumn { DataPropertyName = nameof(ShardRow.RelativePath), HeaderText = "Relative path", Width = 300 });
		_shardsGrid.Columns.Add(new DataGridViewTextBoxColumn { DataPropertyName = nameof(ShardRow.IpText), HeaderText = "IP", Width = 150 });
		_shardsGrid.Columns.Add(new DataGridViewTextBoxColumn { DataPropertyName = nameof(ShardRow.RecordsText), HeaderText = "Records", Width = 90 });
		_shardsGrid.Columns.Add(new DataGridViewTextBoxColumn { DataPropertyName = nameof(ShardRow.BytesText), HeaderText = "Bytes", Width = 90 });
		_shardsGrid.Columns.Add(new DataGridViewTextBoxColumn { DataPropertyName = nameof(ShardRow.FormatVersionText), HeaderText = "Format", Width = 70 });
		_shardsGrid.Columns.Add(new DataGridViewTextBoxColumn { DataPropertyName = nameof(ShardRow.EvictedText), HeaderText = "Evicted", Width = 90 });
		_shardsGrid.Columns.Add(new DataGridViewTextBoxColumn { DataPropertyName = nameof(ShardRow.OldestRetainedText), HeaderText = "Oldest retained (UTC)", Width = 150 });
		_shardsGrid.Columns.Add(new DataGridViewTextBoxColumn { DataPropertyName = nameof(ShardRow.LastWriteText), HeaderText = "Last write (UTC)", Width = 150 });
		_shardsGrid.Columns.Add(new DataGridViewTextBoxColumn { DataPropertyName = nameof(ShardRow.ClassText), HeaderText = "Class", Width = 180 });
		_shardsGrid.Columns.Add(new DataGridViewTextBoxColumn
		{
			DataPropertyName = nameof(ShardRow.Note),
			HeaderText = "Note",
			AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill,
			MinimumWidth = 160,
		});
	}

	private void ConfigureLedgerColumns()
	{
		_ledgerGrid.Columns.Add(new DataGridViewTextBoxColumn { Name = "Created", HeaderText = "Deleted (UTC)", Width = 140 });
		_ledgerGrid.Columns.Add(new DataGridViewTextBoxColumn { Name = "EventCode", HeaderText = "Event ID", Width = 70 });
		_ledgerGrid.Columns.Add(new DataGridViewTextBoxColumn { Name = "Scope", HeaderText = "Scope", Width = 80 });
		_ledgerGrid.Columns.Add(new DataGridViewTextBoxColumn { Name = "IpHex", HeaderText = "IP (hex)", Width = 110 });
		_ledgerGrid.Columns.Add(new DataGridViewTextBoxColumn { Name = "WindowStart", HeaderText = "Window start (UTC)", Width = 140 });
		_ledgerGrid.Columns.Add(new DataGridViewTextBoxColumn { Name = "WindowEnd", HeaderText = "Window end (UTC)", Width = 140 });
		_ledgerGrid.Columns.Add(new DataGridViewTextBoxColumn { Name = "Rows", HeaderText = "Rows", Width = 80 });
		_ledgerGrid.Columns.Add(new DataGridViewTextBoxColumn { Name = "Trigger", HeaderText = "Trigger", Width = 110 });
		_ledgerGrid.Columns.Add(new DataGridViewTextBoxColumn { Name = "RuleVersion", HeaderText = "Rule", Width = 60 });
		_ledgerGrid.Columns.Add(new DataGridViewTextBoxColumn { Name = "Reason", HeaderText = "Reason", Width = 260 });
		_ledgerGrid.Columns.Add(new DataGridViewTextBoxColumn
		{
			Name = "InitiatedBy",
			HeaderText = "Initiated by",
			AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill,
			MinimumWidth = 160,
		});
	}

	// ── Row view-models (bound to the grids) ─────────────────────────────────────

	private sealed record MaintenanceButton(Button Button, DatabaseMaintenanceKind Kind);

	private sealed record AnchorScopeChoice(RetentionAnchorScope Scope, string Display)
	{
		public override string ToString() => Display;
	}

	/// <summary>Editable per-event retention row.</summary>
	internal sealed class EventRetentionRow
	{
		public int EventId { get; init; }
		public string Channel { get; init; } = string.Empty;
		public string DisplayName { get; init; } = string.Empty;
		public int RetentionDays { get; set; }

		/// <summary>Catalog default in days; -1 when the id is not catalogued.</summary>
		public int DefaultRetentionDays { get; init; } = -1;

		public DateTime? UpdatedUtc { get; init; }

		public string DefaultRetentionDaysText => DefaultRetentionDays < 0
			? "(not catalogued)"
			: DefaultRetentionDays.ToString(CultureInfo.InvariantCulture);

		public string UpdatedUtcText => UpdatedUtc is { } updated
			? updated.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture)
			: "(catalog default)";

		public static EventRetentionRow From(EventRetentionWindowDto dto) => new()
		{
			EventId = dto.EventId,
			Channel = dto.Channel,
			DisplayName = dto.DisplayName,
			RetentionDays = dto.RetentionDays,
			DefaultRetentionDays = dto.DefaultRetentionDays,
			UpdatedUtc = dto.UpdatedUtc,
		};

		public EventRetentionWindowDto ToDto() => new()
		{
			EventId = EventId,
			RetentionDays = RetentionDays,
		};
	}

	/// <summary>Read-only preview row.</summary>
	internal sealed class PreviewRow
	{
		public int EventId { get; init; }
		public string Channel { get; init; } = string.Empty;
		public string IpHex { get; init; } = string.Empty;
		public long Count { get; init; }
		public long EligibleInteriorRows { get; init; }
		public int PlannedRows { get; init; }
		public string SkipReasonText { get; init; } = string.Empty;
		public string Explanation { get; init; } = string.Empty;
		public string WindowText { get; init; } = string.Empty;

		public static PreviewRow From(RetentionPreviewCodeDto dto) => new()
		{
			EventId = dto.EventId,
			Channel = dto.Channel,
			IpHex = dto.IpHex,
			Count = dto.Count,
			EligibleInteriorRows = dto.EligibleInteriorRows,
			PlannedRows = dto.PlannedRows,
			SkipReasonText = dto.SkipReason is { } reason ? reason.ToString() : "(none — would be compressed)",
			Explanation = dto.Explanation,
			WindowText = dto.OldestDeletedUtc is { } oldest && dto.NewestDeletedUtc is { } newest
				? oldest.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture)
					+ " .. " + newest.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture)
					+ (dto.OldestRetainedUtc is { } retained
						? " (keeps from " + retained.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture) + ")"
						: string.Empty)
				: string.Empty,
		};
	}

	/// <summary>Read-only snapshot row.</summary>
	internal sealed class BackupRow
	{
		public string Name { get; init; } = string.Empty;
		public string Directory { get; init; } = string.Empty;
		public string CreatedUtcText { get; init; } = string.Empty;
		public string DatabaseBytesText { get; init; } = string.Empty;
		public string SnapshotBytesText { get; init; } = string.Empty;
		public string ManifestText { get; init; } = string.Empty;
		public string Kind { get; init; } = string.Empty;
		public string ShardsText { get; init; } = string.Empty;
		public string? ProductVersion { get; init; }
		public string? LastAppliedMigration { get; init; }

		public static BackupRow From(DatabaseBackupEntryDto dto) => new()
		{
			Name = dto.Name,
			Directory = dto.Directory,
			CreatedUtcText = dto.CreatedUtc.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture),
			DatabaseBytesText = DescribeBytes(dto.DatabaseBytes),
			SnapshotBytesText = DescribeBytes(dto.SnapshotBytes),
			ManifestText = dto.ManifestValid
				? "valid"
				: "INVALID: " + (dto.ManifestError ?? "unreadable"),
			Kind = dto.Kind,
			ShardsText = dto.ShardsIncluded
				? dto.ShardFileCount.ToString(CultureInfo.InvariantCulture) + " file(s)"
				: "no",
			ProductVersion = dto.ProductVersion,
			LastAppliedMigration = dto.LastAppliedMigration,
		};
	}

	/// <summary>Read-only shard inventory row.</summary>
	internal sealed class ShardRow
	{
		public string RelativePath { get; init; } = string.Empty;
		public string IpText { get; init; } = string.Empty;
		public string RecordsText { get; init; } = string.Empty;
		public string BytesText { get; init; } = string.Empty;
		public string FormatVersionText { get; init; } = string.Empty;
		public string EvictedText { get; init; } = string.Empty;
		public string OldestRetainedText { get; init; } = string.Empty;
		public string LastWriteText { get; init; } = string.Empty;
		public string ClassText { get; init; } = string.Empty;
		public string? Note { get; init; }

		public static ShardRow From(ShardInventoryEntryDto dto) => new()
		{
			RelativePath = dto.RelativePath,
			IpText = dto.IpText,
			RecordsText = DescribeCount(dto.Records),
			BytesText = DescribeBytes(dto.Bytes),
			FormatVersionText = dto.FormatVersion < 0 ? "unknown" : dto.FormatVersion.ToString(CultureInfo.InvariantCulture),
			EvictedText = DescribeCount(dto.Evicted),
			OldestRetainedText = dto.OldestRetainedUtc is { } oldest
				? oldest.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture)
				: "unknown",
			LastWriteText = dto.LastWriteUtc is { } lastWrite
				? lastWrite.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture)
				: "unknown",
			ClassText = dto.IsOrphan
				? "orphan"
				: dto.IsSubnetAggregate
					? string.Format(CultureInfo.InvariantCulture, "subnet aggregate (shared by {0})", dto.SharedBySourceCount)
					: "referenced",
			Note = dto.Note,
		};

		private static string DescribeCount(long value) => value < 0 ? "unknown" : value.ToString(CultureInfo.InvariantCulture);
	}
}
