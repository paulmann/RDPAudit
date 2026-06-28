// File:    src/RdpAudit.Configurator/Forms/AuditPolicyPage.cs
// Module:  RdpAudit.Configurator.Forms
// Purpose: Displays the canonical audit policy rows and offers Apply / Configure SACL buttons.
//          Calls into AuditPolicyManager and SaclManager directly — no PowerShell stub.
// Extends: System.Windows.Forms.TabPage
//          v1.1.0 — GUID moved to the last column and stretched to the window edge (removes the phantom
//          trailing column); added a themed right-click clipboard menu and a Copy Report button.
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com
// Version: 1.1.0

using System.ComponentModel;
using System.Globalization;
using System.Runtime.Versioning;
using System.Text;
using RdpAudit.Core.Events;
using RdpAudit.Configurator.Theming;

using static RdpAudit.Configurator.Theming.DarkTheme;

namespace RdpAudit.Configurator.Forms;

/// <summary>Displays the canonical audit policy rows and applies them via AuditPolicyManager.</summary>
[SupportedOSPlatform("windows")]
public sealed class AuditPolicyPage : TabPage
{
	private const string HelpText =
		"What these buttons do:\r\n"
		+ "  • Apply audit policy — runs auditpol.exe to enable the Success/Failure "
		+ "flags required by RdpAudit on every subcategory shown above. Requires Administrator.\r\n"
		+ "  • Configure SACL — writes System Access Control List entries on the "
		+ "IFEO, RDP-Tcp and Lsa registry keys so Windows generates 4657/4663 audit "
		+ "events for the rules STICKY_KEYS_BACKDOOR, RDP_PORT_CHANGED and "
		+ "LSASS_PPL_TAMPER. Requires Administrator.\r\n"
		+ "  • Refresh — re-reads the current audit policy via the Windows "
		+ "AuditQuerySystemPolicy API (locale-stable, falls back to auditpol /r CSV).\r\n"
		+ "\r\n"
		+ "Column legend:\r\n"
		+ "  • Required column shows the policy RdpAudit needs.\r\n"
		+ "  • Current column shows what Windows actually has.\r\n"
		+ "  • S=Y means Success auditing is enabled, S=N means disabled.\r\n"
		+ "  • F=Y means Failure auditing is enabled, F=N means disabled.\r\n"
		+ "Rows turn green when Current matches Required, yellow otherwise.\r\n"
		+ "\r\n"
		+ "SACL = System Access Control List. Registry/object auditing rules that "
		+ "tell Windows to emit object-access events (4657/4663/4660) when watched "
		+ "keys or files are read/modified. Audit Policy enables the subcategory; "
		+ "SACL chooses which specific objects produce events within that subcategory.";

	private readonly ListView _list;
	private readonly Button _apply;
	private readonly Button _applySacl;
	private readonly Button _refresh;
	private readonly Button _copyReport;
	private readonly Label _status;
	private readonly TextBox _help;
	private readonly AuditPolicyManager _policy = new();
	private readonly SaclManager _sacl = new();

	public AuditPolicyPage()
	{
		_list = new ListView
		{
			Dock = DockStyle.Fill,
			View = View.Details,
			FullRowSelect = true,
			GridLines = true,
		};
		_list.Columns.Add("Category", 200);
		_list.Columns.Add("Subcategory", 280);
		_list.Columns.Add("Required", 110);
		_list.Columns.Add("Current", 110);
		// GUID is the widest, least-scanned value, so it sits last and stretches to the window edge. This
		// also removes the empty trailing area that GridLines would otherwise render as a phantom column.
		_list.Columns.Add("GUID", 320);
		ListViewColumnSizer.EnableLastColumnFill(_list);
		// Themed right-click menu: Copy Cell / Copy Row / Copy All (report).
		ListViewClipboardMenu.Attach(_list);

		FlowLayoutPanel buttons = new() { Dock = DockStyle.Top, Height = 40, FlowDirection = FlowDirection.LeftToRight };
		_apply = new Button { Text = "Apply audit policy", Width = 180 };
		_apply.Click += BtnApply_Click;
		_applySacl = new Button { Text = "Configure SACL", Width = 160 };
		_applySacl.Click += BtnApplySacl_Click;
		_refresh = new Button { Text = "Refresh", Width = 100 };
		_refresh.Click += BtnRefresh_Click;
		_copyReport = new Button { Text = "Copy Report", Width = 120 };
		_copyReport.Click += (_, _) => ListViewClipboardMenu.CopyAll(_list);
		buttons.Controls.Add(_apply);
		buttons.Controls.Add(_applySacl);
		buttons.Controls.Add(_refresh);
		buttons.Controls.Add(_copyReport);

		_status = new Label { Dock = DockStyle.Top, Height = 24, Text = "Ready" };

		_help = new TextBox
		{
			Dock = DockStyle.Bottom,
			Height = 220,
			Multiline = true,
			ReadOnly = true,
			ScrollBars = ScrollBars.Vertical,
			WordWrap = true,
			Font = new Font(SystemFonts.MessageBoxFont!.FontFamily, 9f),
			Text = HelpText,
		};

		Controls.Add(_list);
		Controls.Add(_help);
		Controls.Add(_status);
		Controls.Add(buttons);

		HandleCreated += async (_, _) => await ReloadCurrentStateAsync().ConfigureAwait(true);
	}

	private async void BtnApply_Click(object? sender, EventArgs e)
	{
		_apply.Enabled = false;
		_status.Text = "Applying audit policy...";
		try
		{
			IReadOnlyList<AuditPolicyApplyResult> results =
				await Task.Run(_policy.ApplyAll).ConfigureAwait(true);

			int failed = results.Count(r => r.ExitCode != 0);
			_status.Text = failed == 0
				? string.Format(CultureInfo.InvariantCulture, "Applied {0} subcategories successfully.", results.Count)
				: string.Format(CultureInfo.InvariantCulture, "Applied {0}/{1} subcategories. See details below.",
					results.Count - failed, results.Count);

			if (failed > 0)
			{
				StringBuilder sb = new();
				foreach (AuditPolicyApplyResult r in results.Where(r => r.ExitCode != 0))
				{
					sb.AppendFormat(CultureInfo.InvariantCulture,
						"{0} ({1}): exit={2} {3}\r\n", r.Subcategory, r.SubcategoryGuid, r.ExitCode, r.Error ?? string.Empty);
				}
				MessageBox.Show(sb.ToString(), "RdpAudit", MessageBoxButtons.OK, MessageBoxIcon.Warning);
			}

			await ReloadCurrentStateAsync().ConfigureAwait(true);
		}
		catch (Win32Exception ex) when (ex.NativeErrorCode == 1223)
		{
			_status.Text = "Cancelled (UAC denied).";
		}
		catch (Exception ex)
		{
			_status.Text = "Failed: " + ex.GetType().Name;
			MessageBox.Show(ex.Message, "RdpAudit", MessageBoxButtons.OK, MessageBoxIcon.Error);
		}
		finally
		{
			_apply.Enabled = true;
		}
	}

	private async void BtnApplySacl_Click(object? sender, EventArgs e)
	{
		_applySacl.Enabled = false;
		_status.Text = "Configuring SACLs...";
		try
		{
			IReadOnlyList<SaclApplyResult> results =
				await Task.Run(_sacl.ApplyAll).ConfigureAwait(true);

			int failed = results.Count(r => !r.Success);
			_status.Text = failed == 0
				? string.Format(CultureInfo.InvariantCulture, "SACL applied to {0} keys.", results.Count)
				: string.Format(CultureInfo.InvariantCulture, "SACL applied to {0}/{1} keys.",
					results.Count - failed, results.Count);

			if (failed > 0)
			{
				StringBuilder sb = new();
				foreach (SaclApplyResult r in results.Where(r => !r.Success))
				{
					sb.AppendLine(string.Format(CultureInfo.InvariantCulture, "{0}: {1}", r.Path, r.Error));
				}
				MessageBox.Show(sb.ToString(), "RdpAudit", MessageBoxButtons.OK, MessageBoxIcon.Warning);
			}
		}
		catch (Win32Exception ex) when (ex.NativeErrorCode == 1223)
		{
			_status.Text = "Cancelled (UAC denied).";
		}
		catch (Exception ex)
		{
			_status.Text = "Failed: " + ex.GetType().Name;
			MessageBox.Show(ex.Message, "RdpAudit", MessageBoxButtons.OK, MessageBoxIcon.Error);
		}
		finally
		{
			_applySacl.Enabled = true;
		}
	}

	private async void BtnRefresh_Click(object? sender, EventArgs e)
		=> await ReloadCurrentStateAsync().ConfigureAwait(true);

	private async Task ReloadCurrentStateAsync()
	{
		_refresh.Enabled = false;
		_status.Text = "Reading current audit policy...";
		try
		{
			List<(AuditPolicyRow Row, AuditPolicyState? State)> probed = await Task.Run(() =>
			{
				List<(AuditPolicyRow, AuditPolicyState?)> list = new();
				foreach (AuditPolicyRow row in AuditPolicyManager.RequiredRows)
				{
					list.Add((row, AuditPolicyManager.ReadSubcategoryState(row.SubcategoryGuid)));
				}
				return list;
			}).ConfigureAwait(true);

			_list.Items.Clear();
			foreach ((AuditPolicyRow row, AuditPolicyState? state) in probed)
			{
				ListViewItem item = new(row.Category);
				item.SubItems.Add(row.Subcategory);
				item.SubItems.Add(string.Format(CultureInfo.InvariantCulture, "S={0} F={1}",
					row.Success ? "Y" : "N", row.Failure ? "Y" : "N"));
				item.SubItems.Add(state is null
					? "?"
					: string.Format(CultureInfo.InvariantCulture, "S={0} F={1}",
						state.Success ? "Y" : "N", state.Failure ? "Y" : "N"));
				item.SubItems.Add(row.SubcategoryGuid);
				if (state is not null && state.Success == row.Success && state.Failure == row.Failure)
				{
					item.BackColor = RowSuccessBack;
				}
				else
				{
					item.BackColor = RowWarningBack;
				}

				_list.Items.Add(item);
			}

			_status.Text = "Ready";
		}
		catch (Exception ex)
		{
			_status.Text = "Read failed: " + ex.GetType().Name;
		}
		finally
		{
			_refresh.Enabled = true;
		}
	}
}
