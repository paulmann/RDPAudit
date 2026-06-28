/*
 * File   : FirewallPanel.cs
 * Project: RdpAudit.Mikrotik (RdpAudit.Mikrotik.Ui)
 * Purpose: Step 4 — lets the operator review and confirm the firewall blocking-contour plan: the
 *          target address-list name, the default ban timeout, and the recommended drop-rule placement
 *          (filter input, before-fasttrack, or RAW prerouting) derived from the Test step. It records
 *          the operator's choices in WizardContext for the Apply & Sync bootstrap.
 * Depends: StepPanelBase, WizardContext, BlockingContourAnalyzer (placement recommendation)
 * Extends: To expose another firewall option (e.g. a per-rule log toggle), add an input here and
 *          carry it into the BootstrapRequest assembled by ApplySyncPanel.
 *
 * Author : Mikhail Deynekin — https://Deynekin.com
 * Version: 1.0.1
 */

using System.Drawing;
using System.Windows.Forms;
using RdpAudit.Mikrotik.Core;

namespace RdpAudit.Mikrotik.Ui;

/// <summary>Step 4: firewall blocking-contour review and confirmation.</summary>
public sealed class FirewallPanel : StepPanelBase
{
	// ── Fields & DI ──────────────────────────────────────────────────────────────

	private readonly TextBox _addressListBox = new() { Text = "rdpaudit_rdp_blocklist" };
	private readonly TextBox _banTimeoutBox = new() { Text = "24h" };
	private readonly CheckBox _preferRawCheck = new() { Text = "Prefer RAW prerouting drop (RouterOS v7, immune to FastTrack)", Checked = true };

	// ── Construction ─────────────────────────────────────────────────────────────

	public FirewallPanel(WizardContext context) : base(context)
	{
		Heading = "Firewall Contour";
		Description = "Confirm the address-list name, default ban timeout and drop-rule placement. RAW prerouting is recommended because it bypasses FastTrack and connection tracking.";
		ActionText = "Confirm firewall plan";
		BuildOptionInputs();
	}

	// ── Public API ───────────────────────────────────────────────────────────────

	/// <summary>The address-list name the operator chose.</summary>
	public string AddressListName => string.IsNullOrWhiteSpace(_addressListBox.Text) ? "rdpaudit_rdp_blocklist" : _addressListBox.Text.Trim();

	/// <summary>The default ban timeout the operator chose.</summary>
	public string BanTimeout => string.IsNullOrWhiteSpace(_banTimeoutBox.Text) ? "24h" : _banTimeoutBox.Text.Trim();

	/// <summary>Whether to prefer a RAW prerouting drop rule.</summary>
	public bool PreferRawChain => _preferRawCheck.Checked;

	// ── Core Logic ───────────────────────────────────────────────────────────────

	protected override Task RunActionAsync(CancellationToken ct)
	{
		_ = ct;
		BlockPlacement placement = PreferRawChain
			? BlockPlacement.RawPrerouting
			: (Context.ContourReport?.RecommendedPlacement ?? BlockPlacement.FilterInputAppend);

		AppendLog("Firewall plan:");
		AppendLog("  Address-list : " + AddressListName);
		AppendLog("  Ban timeout  : " + BanTimeout);
		AppendLog("  Placement    : " + placement);
		AppendLog("Plan confirmed. Proceed to Apply & Sync to run the bootstrap.");
		CompleteStep();
		return Task.CompletedTask;
	}

	private void BuildOptionInputs()
	{
		FlowLayoutPanel options = new()
		{
			Dock = DockStyle.Top,
			Height = 110,
			FlowDirection = FlowDirection.TopDown,
			WrapContents = false,
			BackColor = DarkTheme.Background,
			Padding = new Padding(0, 4, 0, 4),
		};

		options.Controls.Add(MakeRow("Address-list name", _addressListBox));
		options.Controls.Add(MakeRow("Default ban timeout", _banTimeoutBox));

		_preferRawCheck.ForeColor = DarkTheme.Text;
		_preferRawCheck.Font = DarkTheme.BaseFont;
		_preferRawCheck.AutoSize = true;
		_preferRawCheck.Margin = new Padding(0, 6, 0, 0);
		options.Controls.Add(_preferRawCheck);

		// Insert directly under the description (index keeps heading + description on top).
		Controls.Add(options);
		Controls.SetChildIndex(options, 0);
	}

	private static FlowLayoutPanel MakeRow(string caption, TextBox box)
	{
		DarkTheme.StyleTextBox(box);
		box.Width = 240;

		FlowLayoutPanel row = new()
		{
			AutoSize = true,
			FlowDirection = FlowDirection.LeftToRight,
			Margin = new Padding(0, 2, 0, 2),
		};
		Label label = new()
		{
			Text = caption,
			ForeColor = DarkTheme.SubtleText,
			Font = DarkTheme.BaseFont,
			AutoSize = true,
			Width = 160,
			TextAlign = ContentAlignment.MiddleLeft,
			Margin = new Padding(0, 4, 8, 0),
		};
		row.Controls.Add(label);
		row.Controls.Add(box);
		return row;
	}
}
