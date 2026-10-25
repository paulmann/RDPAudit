// File:    src/RdpAudit.Configurator/Forms/MikroTikSecurityAuditForm.cs
// Module:  RdpAudit.Configurator.Forms
// Purpose: Read-only window for one RouterOS security audit run: the pasport and the risk index on
//          top, the findings grid with evidence and autofix class in the middle, the selected
//          finding's reason, recommendation and ready RouterOS commands below, and the finished
//          Markdown report on its own tab for copying into a ticket.
//          The window never re-sorts the grid: the report arrives in severity order (worst first) and
//          a click on a column header must not quietly turn that into an alphabetical list.
//          No async handler lives here — everything is bound from the reply the page already holds.
// Extends: System.Windows.Forms.Form
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;
using System.Windows.Forms;
using RdpAudit.Configurator.Theming;
using RdpAudit.Core.Ipc.Contracts;

namespace RdpAudit.Configurator.Forms;

/// <summary>Displays one RouterOS security audit report.</summary>
[SupportedOSPlatform("windows")]
internal sealed class MikroTikSecurityAuditForm : Form
{
	private readonly MikroTikSecurityAuditDto _dto;
	private readonly DataGridView _grid;
	private readonly TextBox _details;
	private readonly TextBox _markdown;

	public MikroTikSecurityAuditForm(MikroTikSecurityAuditDto dto)
	{
		ArgumentNullException.ThrowIfNull(dto);
		_dto = dto;

		Text = "RouterOS security audit — " + (string.IsNullOrWhiteSpace(dto.DeviceName) ? "(unnamed device)" : dto.DeviceName);
		StartPosition = FormStartPosition.CenterParent;
		MinimumSize = new Size(900, 600);
		Size = new Size(1100, 720);
		ShowInTaskbar = false;

		Label summary = new()
		{
			Dock = DockStyle.Top,
			Height = 96,
			Padding = new Padding(10, 8, 10, 4),
			TextAlign = ContentAlignment.TopLeft,
			Text = BuildSummary(dto),
		};

		_grid = new DataGridView
		{
			Dock = DockStyle.Fill,
			ReadOnly = true,
			AllowUserToAddRows = false,
			AllowUserToDeleteRows = false,
			AllowUserToResizeRows = false,
			RowHeadersVisible = false,
			SelectionMode = DataGridViewSelectionMode.FullRowSelect,
			MultiSelect = false,
			AutoGenerateColumns = false,
			BackgroundColor = SystemColors.Window,
			BorderStyle = BorderStyle.None,
		};
		AddColumn("Id", "Rule", 70);
		AddColumn("Severity", "Severity", 80);
		AddColumn("Title", "Finding", 320);
		AddColumn("Evidence", "Evidence", 300);
		AddColumn("Autofix", "Autofix", 80);
		foreach (MikroTikSecurityFindingDto finding in dto.Findings)
		{
			_grid.Rows.Add(finding.RuleId, finding.Severity, finding.Title, finding.Evidence, finding.Autofix);
		}
		_grid.SelectionChanged += OnSelectionChanged;
		// Every table in this product exports its selected rows; TableExportCoverageTests locks that.
		DataGridClipboardMenu.AttachWithExport(_grid, "RouterOS security findings", ReportExportStatus);

		_details = new TextBox
		{
			Dock = DockStyle.Fill,
			Multiline = true,
			ReadOnly = true,
			ScrollBars = ScrollBars.Vertical,
			WordWrap = true,
			BackColor = SystemColors.Info,
			Text = dto.Findings.Count == 0
				? BuildEmptyDetails(dto)
				: "Select a finding to see why it matters and what to do.",
		};

		SplitContainer split = new()
		{
			Dock = DockStyle.Fill,
			Orientation = Orientation.Horizontal,
			SplitterDistance = 360,
		};
		split.Panel1.Controls.Add(_grid);
		split.Panel2.Controls.Add(_details);

		_markdown = new TextBox
		{
			Dock = DockStyle.Fill,
			Multiline = true,
			ReadOnly = true,
			ScrollBars = ScrollBars.Both,
			WordWrap = false,
			Font = new Font(FontFamily.GenericMonospace, 9.5f),
			Text = dto.Markdown,
		};

		TabPage findingsTab = new("Findings");
		findingsTab.Controls.Add(split);
		TabPage markdownTab = new("Markdown report");
		markdownTab.Controls.Add(_markdown);
		TabControl tabs = new() { Dock = DockStyle.Fill };
		tabs.TabPages.Add(findingsTab);
		tabs.TabPages.Add(markdownTab);

		Button copyButton = new() { Text = "Copy Markdown", Width = 140 };
		copyButton.Click += OnCopyMarkdown;
		Button closeButton = new() { Text = "Close", Width = 100, DialogResult = DialogResult.OK };
		FlowLayoutPanel buttons = new()
		{
			Dock = DockStyle.Bottom,
			Height = 44,
			FlowDirection = FlowDirection.RightToLeft,
			Padding = new Padding(8),
		};
		buttons.Controls.Add(closeButton);
		buttons.Controls.Add(copyButton);

		Controls.Add(tabs);
		Controls.Add(buttons);
		Controls.Add(summary);
		AcceptButton = closeButton;
		CancelButton = closeButton;
	}

	private void AddColumn(string property, string header, int width)
	{
		DataGridViewTextBoxColumn column = new()
		{
			Name = property,
			HeaderText = header,
			Width = width,
			ReadOnly = true,
			SortMode = DataGridViewColumnSortMode.NotSortable,
		};
		if (property is "Title" or "Evidence")
		{
			column.AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill;
		}
		_grid.Columns.Add(column);
	}

	private void ReportExportStatus(string message) => _details.Text = message;

	private void OnSelectionChanged(object? sender, EventArgs e)
	{
		if (_grid.SelectedRows.Count == 0)
		{
			return;
		}

		int index = _grid.SelectedRows[0].Index;
		if (index < 0 || index >= _dto.Findings.Count)
		{
			return;
		}

		_details.Text = BuildFindingDetails(_dto.Findings[index]);
		_details.SelectionStart = 0;
		_details.SelectionLength = 0;
	}

	private void OnCopyMarkdown(object? sender, EventArgs e)
	{
		try
		{
			Clipboard.SetText(_dto.Markdown ?? string.Empty);
		}
		catch (ExternalException)
		{
			// The clipboard can be held by another process; the report stays on screen, so a silent
			// refusal is honest here and the operator can select the text manually.
			_details.Text = "Clipboard is busy — the Markdown report is on the second tab.";
		}
	}

	private static string BuildSummary(MikroTikSecurityAuditDto dto)
	{
		StringBuilder sb = new();
		sb.Append(dto.DeviceName.Length == 0 ? "(unnamed device)" : dto.DeviceName);
		sb.Append(" · RouterOS ").Append(dto.RouterOsVersion.Length == 0 ? "(unknown)" : dto.RouterOsVersion);
		if (dto.BoardName.Length > 0)
		{
			sb.Append(" · ").Append(dto.BoardName);
		}
		sb.AppendLine();
		sb.AppendFormat(
			CultureInfo.InvariantCulture,
			"Risk index {0}/100 — {1} · findings {2} (critical {3}, high {4}, medium {5}, low {6}, info {7}) · automatically fixable {8}",
			dto.RiskIndex,
			dto.Verdict,
			dto.Total,
			dto.Critical,
			dto.High,
			dto.Medium,
			dto.Low,
			dto.Info,
			dto.AutoFixable);
		sb.AppendLine();
		sb.AppendFormat(
			CultureInfo.InvariantCulture,
			"Snapshot {0:yyyy-MM-dd HH:mm:ss} UTC · {1}",
			dto.CapturedUtc,
			dto.Message);
		if (dto.UnavailableMenus.Count > 0)
		{
			sb.AppendLine();
			sb.Append("Menus this device does not have (not findings): ")
				.Append(string.Join(", ", dto.UnavailableMenus));
		}
		return sb.ToString();
	}

	private static string BuildEmptyDetails(MikroTikSecurityAuditDto dto)
		=> dto.Total == 0
			? "No findings: every rule in the catalogue was evaluated and none matched."
			: "The report carries findings but the grid is empty — this is a reply mismatch, not a clean device.";

	private static string BuildFindingDetails(MikroTikSecurityFindingDto finding)
	{
		StringBuilder sb = new();
		sb.Append(finding.RuleId).Append(" · ").Append(finding.Severity).Append(" · ").Append(finding.Autofix)
			.AppendLine().AppendLine();
		sb.AppendLine(finding.Title);
		sb.AppendLine();
		sb.Append("Evidence: ").AppendLine(finding.Evidence);
		sb.Append("Menu: ").AppendLine(finding.Menu);
		sb.AppendLine();
		sb.Append("Why it matters: ").AppendLine(finding.Why);
		sb.Append("What to do: ").AppendLine(finding.Recommendation);
		if (finding.Commands.Count > 0)
		{
			sb.AppendLine();
			sb.AppendLine("RouterOS commands:");
			foreach (string command in finding.Commands)
			{
				sb.Append("  ").AppendLine(command);
			}
		}
		return sb.ToString();
	}
}
