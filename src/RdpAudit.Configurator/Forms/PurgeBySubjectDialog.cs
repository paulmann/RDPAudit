/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 1.0.0
// File   : PurgeBySubjectDialog.cs
// Project: RdpAudit.Configurator.Forms
// Purpose: The modal surface for "Purge by subject" (IPC ordinal 94). It exists as its own form rather than as
//          another block inside the Danger Zone because the operation has a required sequence the UI must
//          make impossible to skip:
//            1. choose the subject (address, CIDR range, login or UTC window);
//            2. run the DRY RUN and read the per-table counts;
//            3. only then type the confirmation phrase and enable Purge.
//          The Purge button stays disabled until a preview has succeeded AND the typed phrase matches exactly,
//          so the two mandatory steps cannot be collapsed into one click. The server re-validates both anyway -
//          this dialog is a guard rail, not the guard.
//          Everything the dialog knows about the operation comes from the service: the counts, the preserved
//          list and the message are rendered verbatim, so the UI cannot overstate what the purge did.
// Depends: IIpcClient, IpcCommand.PurgeBySubject, DarkTheme
// Extends: Add a control here when the purge request gains a dimension; keep the preview-before-apply gate.

using System.Diagnostics;
using System.Globalization;
using System.Runtime.Versioning;
using System.Text;
using RdpAudit.Configurator.Ipc;
using RdpAudit.Configurator.Services;
using RdpAudit.Core.Ipc;
using RdpAudit.Core.Ipc.Contracts;
using RdpAudit.Core.Util;
using RdpAudit.Configurator.Theming;

using static RdpAudit.Configurator.Theming.DarkTheme;

namespace RdpAudit.Configurator.Forms;

/// <summary>Collects a purge subject, previews it with a mandatory dry run, and applies it only with the
/// exact typed phrase.</summary>
[SupportedOSPlatform("windows")]
public sealed class PurgeBySubjectDialog : Form
{
	// ── Fields & DI ──────────────────────────────────────────────────────────────

	/// <summary>The typed phrase the server requires. Mirrors
	/// <c>PurgeBySubjectService.ConfirmationPhrase</c>; the server re-validates it, so a divergence here can
	/// only make the UI stricter, never weaker.</summary>
	internal const string ConfirmationPhrase = "PURGE SUBJECT DATA";

	private readonly IIpcClient _ipc;
	private readonly ComboBox _kind;
	private readonly TextBox _value;
	private readonly CheckBox _useWindow;
	private readonly DateTimePicker _windowStart;
	private readonly DateTimePicker _windowEnd;
	private readonly Button _previewButton;
	private readonly Button _purge;
	private readonly TextBox _phrase;
	private readonly DataGridView _grid;
	private readonly TextBox _report;
	private readonly Label _status;

	/// <summary>Reports an export result through the dialog's status label.</summary>
	private void ReportExportStatus(string message) => _status.Text = message;

	private PurgeBySubjectReportDto? _preview;

	/// <summary>The dialog's outcome rendered as text, so the page can show it without re-deriving anything.
	/// Null until a report has been rendered.</summary>
	internal string? LastOutcomeSummary { get; private set; }

	// ── Construction ─────────────────────────────────────────────────────────────

	/// <summary>Creates the dialog over the narrow IPC seam (see <c>IIpcClient.cs</c>): the dialog only ever
	/// sends one command shape, so depending on the whole client was coupling without a benefit.</summary>
	public PurgeBySubjectDialog(IIpcClient ipc)
	{
		ArgumentNullException.ThrowIfNull(ipc);
		_ipc = ipc;

		Text = "Purge by subject";
		FormBorderStyle = FormBorderStyle.Sizable;
		StartPosition = FormStartPosition.CenterParent;
		MinimumSize = new Size(720, 560);
		Size = new Size(820, 620);
		BackColor = PanelBack;
		ForeColor = TextPrimary;

		_kind = new ComboBox
		{
			DropDownStyle = ComboBoxStyle.DropDownList,
			Width = 140,
		};
		_kind.Items.AddRange(["IP address", "CIDR range", "Login", "Time range"]);
		_kind.SelectedIndex = 0;

		_value = new TextBox { Width = 260 };
		_useWindow = new CheckBox { Text = "Limit to window (UTC)", AutoSize = true };
		_windowStart = MakePicker(new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc));
		_windowEnd = MakePicker(DateTime.UtcNow);
		_previewButton = MakeButton("Preview (dry run)", SafeAsyncHandler.Wrap(() => RunPreviewAsync(), ReportHandlerFailure));
		_purge = MakeButton("Purge…", SafeAsyncHandler.Wrap(() => ApplyOnceAsync(), ReportHandlerFailure));
		_purge.Enabled = false;
		_phrase = new TextBox { Width = 260 };
		_phrase.TextChanged += (_, _) => UpdatePurgeGate();
		_status = new Label { AutoSize = true, MaximumSize = new Size(760, 0), ForeColor = StatusWarning };

		_grid = new DataGridView
		{
			Dock = DockStyle.Fill,
			ReadOnly = true,
			AllowUserToAddRows = false,
			AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill,
			BackgroundColor = PanelBack,
			BorderStyle = BorderStyle.FixedSingle,
			// Explicit full-row multi-selection: the WinForms default is cell selection, which would
			// make "Export Selected Rows" depend on which cell happened to be highlighted.
			SelectionMode = DataGridViewSelectionMode.FullRowSelect,
			MultiSelect = true,
		};
		// The dialog's table is display-only, so the export covers whatever the operator highlighted.
		DataGridClipboardMenu.AttachWithExport(_grid, "Purge by subject preview", ReportExportStatus);
		_report = new TextBox
		{
			Dock = DockStyle.Fill,
			Multiline = true,
			ReadOnly = true,
			ScrollBars = ScrollBars.Vertical,
			BackColor = PanelBack,
			ForeColor = TextPrimary,
			Font = new Font("Consolas", 9f),
		};

		// Default call seams: the real IPC round trip. A test replaces them to drive the dialog without a
		// service, which is the same pattern the page's other destructive flows use.
		PreviewAsync = SendAsync;
		ApplyAsync = SendAsync;

		Controls.Add(BuildLayout());
		UpdatePurgeGate();
	}

	// ── Test seams ───────────────────────────────────────────────────────────────

	/// <summary>Preview call seam. Production sends <c>PurgeBySubject</c> over IPC; a test replaces it to
	/// drive the dialog without a service.</summary>
	internal Func<PurgeBySubjectRequest, Task<PurgeBySubjectReportDto?>> PreviewAsync { get; set; } = null!;

	/// <summary>Apply call seam, mirroring <see cref="PreviewAsync"/>.</summary>
	internal Func<PurgeBySubjectRequest, Task<PurgeBySubjectReportDto?>> ApplyAsync { get; set; } = null!;

	/// <summary>The request the current controls describe, for tests and for the preview/apply calls.</summary>
	internal PurgeBySubjectRequest BuildRequest(bool apply) => new()
	{
		Kind = SelectedKind,
		Value = SelectedKind == PurgeSubjectKind.TimeRange ? null : _value.Text.Trim(),
		WindowStartUtc = _useWindow.Checked || SelectedKind == PurgeSubjectKind.TimeRange
			? DateTime.SpecifyKind(_windowStart.Value, DateTimeKind.Utc)
			: null,
		WindowEndUtc = _useWindow.Checked || SelectedKind == PurgeSubjectKind.TimeRange
			? DateTime.SpecifyKind(_windowEnd.Value, DateTimeKind.Utc)
			: null,
		Apply = apply,
		ConfirmationPhrase = apply ? _phrase.Text : null,
	};

	/// <summary>The selected subject kind.</summary>
	internal PurgeSubjectKind SelectedKind => _kind.SelectedIndex switch
	{
		1 => PurgeSubjectKind.Cidr,
		2 => PurgeSubjectKind.Login,
		3 => PurgeSubjectKind.TimeRange,
		_ => PurgeSubjectKind.Ip,
	};

	/// <summary>True when the Purge button is enabled: a preview must have succeeded AND the phrase must match.</summary>
	internal bool CanPurge => _purge.Enabled;

	/// <summary>The table names currently rendered in the per-table grid, in order, so a test can assert that
	/// the counts reached the grid rather than only the summary text.</summary>
	internal IReadOnlyList<string> RenderedTables
		=> [.. _grid.Rows.Cast<DataGridViewRow>().Select(row => row.Cells[0].Value?.ToString() ?? string.Empty)];

	/// <summary>Selects a subject kind and value programmatically (tests).</summary>
	internal void SelectSubject(PurgeSubjectKind kind, string value)
	{
		_kind.SelectedIndex = kind switch
		{
			PurgeSubjectKind.Cidr => 1,
			PurgeSubjectKind.Login => 2,
			PurgeSubjectKind.TimeRange => 3,
			_ => 0,
		};
		_value.Text = value;
	}

	/// <summary>Types the confirmation phrase programmatically (tests).</summary>
	internal void TypePhrase(string phrase) => _phrase.Text = phrase;

	// ── Actions ──────────────────────────────────────────────────────────────────

	/// <summary>Sends one purge request over IPC and deserializes the report. Returns null when the call
	/// fails, which the renderer presents as "nothing was deleted" rather than as an empty success.</summary>
	private async Task<PurgeBySubjectReportDto?> SendAsync(PurgeBySubjectRequest request)
	{
		IpcCallResult<PurgeBySubjectReportDto> call = await _ipc
			.SendDetailedAsync<PurgeBySubjectReportDto>(
				IpcCommand.PurgeBySubject,
				System.Text.Json.JsonSerializer.Serialize(request, JsonOptions.Default),
				CancellationToken.None)
			.ConfigureAwait(true);
		return call.IsSuccess ? call.Value : null;
	}

	/// <summary>Runs the apply pass - the same work the Purge button performs. Internal and awaitable so a
	/// test can drive it without the message loop, and so the click path and the test path cannot diverge.</summary>
	internal async Task ApplyOnceAsync()
	{
		// Second barrier at click time: the phrase is re-read here, so a programmatic change between the
		// enable and the click cannot slip through.
		if (!CanPurge || !string.Equals(_phrase.Text, ConfirmationPhrase, StringComparison.Ordinal))
		{
			_status.Text = "The confirmation phrase must match exactly before the purge can run.";
			return;
		}

		SetBusy(true);
		try
		{
			PurgeBySubjectReportDto? report = await ApplyAsync(BuildRequest(apply: true)).ConfigureAwait(true);
			Render(report);
		}
		finally
		{
			SetBusy(false);
		}
	}

	/// <summary>Last-resort report for an exception that escaped one of this dialog's handlers. Handlers
	/// are attached through the shared <see cref="SafeAsyncHandler"/>, which journals the fault; both
	/// operations also catch their own failures, so this fires only for what those catch blocks cannot
	/// cover themselves. Never throws: a closed dialog has no label left to write to.</summary>
	private void ReportHandlerFailure(Exception ex)
	{
		Debug.WriteLine("[PurgeBySubjectDialog] handler failed outside the dialog's own error path: " + ex);
		if (IsDisposed || Disposing || _status.IsDisposed)
		{
			return;
		}

		_status.Text = "Purge action failed: " + ex.GetType().Name + " — " + ex.Message;
	}

	/// <summary>Runs the dry run and renders it. Internal so a test can drive it without the message loop.</summary>
	internal async Task RunPreviewAsync()
	{
		SetBusy(true);
		try
		{
			PurgeBySubjectReportDto? report = await PreviewAsync(BuildRequest(apply: false)).ConfigureAwait(true);
			_preview = report is { Status: IpcResultStatus.Success, DryRun: true } ? report : null;
			Render(report);
		}
		finally
		{
			SetBusy(false);
			UpdatePurgeGate();
		}
	}

	/// <summary>Renders a report. Internal so the renderers can be asserted directly.</summary>
	internal void Render(PurgeBySubjectReportDto? report)
	{
		_grid.Rows.Clear();
		_grid.Columns.Clear();
		_grid.Columns.Add("Table", "Table");
		_grid.Columns.Add("Matched", "Matched");
		_grid.Columns.Add("Deleted", "Deleted");
		_grid.Columns.Add("Ledger", "Ledger");

		if (report is null)
		{
			_report.Text = "The service did not answer the purge request. Nothing was deleted.";
			LastOutcomeSummary = _report.Text;
			_status.Text = "No answer from the service.";
			return;
		}

		foreach (PurgeBySubjectTableDto table in report.Tables)
		{
			_grid.Rows.Add(
				table.Table,
				table.RowsMatched.ToString("N0", CultureInfo.InvariantCulture),
				table.RowsDeleted.ToString("N0", CultureInfo.InvariantCulture),
				table.LedgerWritten ? "yes" : string.Empty);
		}

		StringBuilder text = new();
		text.AppendLine(report.Message);
		text.AppendLine();
		text.Append("Status: ").Append(report.Status)
			.Append(" | dry run: ").Append(report.DryRun)
			.Append(" | applied: ").Append(report.Applied)
			.Append(" | legal hold: ").Append(report.LegalHold).AppendLine();
		text.Append("Subject: ").Append(report.Subject).AppendLine();
		if (report.WindowStartUtc is not null || report.WindowEndUtc is not null)
		{
			text.Append("Window (UTC): ").Append(report.WindowStartUtc).Append(" .. ").Append(report.WindowEndUtc).AppendLine();
		}

		text.Append("Matched: ").Append(report.TotalRowsMatched.ToString("N0", CultureInfo.InvariantCulture))
			.Append(" | deleted: ").Append(report.TotalRowsDeleted.ToString("N0", CultureInfo.InvariantCulture))
			.Append(" | ledger entries: ").Append(report.LedgerEntriesWritten.ToString(CultureInfo.InvariantCulture))
			.AppendLine();
		if (!string.IsNullOrEmpty(report.LedgerChainHead))
		{
			text.Append("Ledger chain head: ").Append(report.LedgerChainHead).AppendLine();
		}

		if (report.Preserved.Count > 0)
		{
			text.AppendLine();
			text.AppendLine("Preserved (never touched by this action):");
			foreach (string preserved in report.Preserved)
			{
				text.Append("  - ").AppendLine(preserved);
			}
		}

		if (!string.IsNullOrEmpty(report.DebugLog))
		{
			text.AppendLine();
			text.AppendLine("DEBUG detail:");
			text.Append(report.DebugLog);
		}

		_report.Text = text.ToString();
		LastOutcomeSummary = text.ToString();
		_status.Text = report.DryRun
			? "Dry run complete. Type the phrase to enable Purge."
			: "Purge complete. The ledger entries are on the hash chain.";
	}

	private void UpdatePurgeGate()
		=> _purge.Enabled = _preview is not null
			&& string.Equals(_phrase.Text, ConfirmationPhrase, StringComparison.Ordinal);

	private void SetBusy(bool busy)
	{
		_previewButton.Enabled = !busy;
		_kind.Enabled = !busy;
		_value.Enabled = !busy;
		_useWindow.Enabled = !busy;
		UseWaitCursor = busy;
	}

	// ── Layout ───────────────────────────────────────────────────────────────────

	private TableLayoutPanel BuildLayout()
	{
		TableLayoutPanel root = new()
		{
			Dock = DockStyle.Fill,
			ColumnCount = 1,
			RowCount = 3,
		};
		root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
		root.RowStyles.Add(new RowStyle(SizeType.Percent, 55f));
		root.RowStyles.Add(new RowStyle(SizeType.Percent, 45f));

		FlowLayoutPanel inputs = new() { Dock = DockStyle.Fill, AutoSize = true, FlowDirection = FlowDirection.LeftToRight, WrapContents = true };
		inputs.Controls.Add(new Label { Text = "Subject:", AutoSize = true, Margin = new Padding(0, 8, 4, 0), ForeColor = TextPrimary });
		inputs.Controls.Add(_kind);
		inputs.Controls.Add(_value);
		inputs.Controls.Add(_useWindow);
		inputs.Controls.Add(_windowStart);
		inputs.Controls.Add(_windowEnd);
		inputs.Controls.Add(_previewButton);
		inputs.Controls.Add(new Label { Text = "Type '" + ConfirmationPhrase + "' to enable Purge:", AutoSize = true, Margin = new Padding(12, 8, 4, 0), ForeColor = TextPrimary });
		inputs.Controls.Add(_phrase);
		inputs.Controls.Add(_purge);
		inputs.Controls.Add(_status);

		root.Controls.Add(inputs, 0, 0);
		root.Controls.Add(_grid, 0, 1);
		root.Controls.Add(_report, 0, 2);
		return root;
	}

	private static DateTimePicker MakePicker(DateTime value) => new()
	{
		Format = DateTimePickerFormat.Custom,
		CustomFormat = "yyyy-MM-dd HH:mm",
		ShowUpDown = true,
		Width = 140,
		Value = value,
	};

	private static Button MakeButton(string text, EventHandler handler)
	{
		Button button = new()
		{
			Text = text,
			AutoSize = true,
			FlatStyle = FlatStyle.Flat,
			BackColor = CardBack,
			ForeColor = TextPrimary,
		};
		button.Click += handler;
		return button;
	}
}
