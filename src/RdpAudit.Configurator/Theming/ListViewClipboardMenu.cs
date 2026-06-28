// File:    src/RdpAudit.Configurator/Theming/ListViewClipboardMenu.cs
// Module:  RdpAudit.Configurator.Theming
// Purpose: Builds a dark-themed right-click context menu for a details-view ListView offering
//          Copy Cell, Copy Row, and Copy All (tab-separated report incl. headers) actions, and copies
//          to the clipboard with STA-safe error handling. One source of truth so every grid tab gets
//          an identical, on-theme clipboard menu.
// Depends: System.Windows.Forms.ListView, DarkTheme.StyleMenu
// Extends: To add another clipboard action (e.g. Copy as CSV), add a ToolStripMenuItem in Attach and a
//          matching Copy* helper below.
//
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com
// Version: 1.0.0

using System.Runtime.Versioning;
using System.Text;
using System.Windows.Forms;

namespace RdpAudit.Configurator.Theming;

/// <summary>
/// Attaches a dark-themed clipboard context menu (Copy Cell / Copy Row / Copy All) to a details-view
/// <see cref="ListView"/>. The cell under the cursor is resolved on right-click via HitTest so
/// "Copy Cell" targets the exact clicked cell. "Copy All" produces a tab-separated report that
/// includes the column headers, suitable for pasting into a spreadsheet or text editor.
/// </summary>
[SupportedOSPlatform("windows")]
internal static class ListViewClipboardMenu
{
	// ── Public API ───────────────────────────────────────────────────────────────

	/// <summary>Attaches the clipboard menu to <paramref name="list"/>. <paramref name="includeCopyAll"/>
	/// controls whether the "Copy All (report)" item is shown. Returns the created menu so callers may
	/// add their own items if needed.</summary>
	public static ContextMenuStrip Attach(ListView list, bool includeCopyAll = true)
	{
		ArgumentNullException.ThrowIfNull(list);

		int hitColumn = -1;

		ContextMenuStrip menu = new();
		ToolStripMenuItem copyCell = new("Copy Cell", null, (_, _) => CopyCell(list, hitColumn));
		ToolStripMenuItem copyRow = new("Copy Row", null, (_, _) => CopyRow(list));
		menu.Items.Add(copyCell);
		menu.Items.Add(copyRow);

		if (includeCopyAll)
		{
			menu.Items.Add(new ToolStripSeparator());
			menu.Items.Add(new ToolStripMenuItem("Copy All (report)", null, (_, _) => CopyAll(list)));
		}

		// Resolve the clicked cell column before the menu opens, and enable/disable row-scoped items.
		list.MouseDown += (_, e) =>
		{
			if (e.Button == MouseButtons.Right)
			{
				ListViewHitTestInfo hit = list.HitTest(e.Location);
				hitColumn = hit.Item is null ? -1 : hit.Item.SubItems.IndexOf(hit.SubItem);
			}
		};

		menu.Opening += (_, _) =>
		{
			bool hasRow = list.SelectedItems.Count > 0;
			copyCell.Enabled = hasRow && hitColumn >= 0;
			copyRow.Enabled = hasRow;
		};

		list.ContextMenuStrip = menu;
		DarkTheme.StyleMenu(menu);
		return menu;
	}

	// ── Core Logic ───────────────────────────────────────────────────────────────

	private static void CopyCell(ListView list, int column)
	{
		if (list.SelectedItems.Count == 0 || column < 0)
		{
			return;
		}

		ListViewItem item = list.SelectedItems[0];
		string text = column < item.SubItems.Count ? item.SubItems[column].Text : item.Text;
		SetClipboard(text);
	}

	private static void CopyRow(ListView list)
	{
		if (list.SelectedItems.Count == 0)
		{
			return;
		}

		SetClipboard(RowToLine(list.SelectedItems[0]));
	}

	/// <summary>Copies the whole list (header line + every row) to the clipboard as a tab-separated
	/// report. Exposed so pages can wire it to a dedicated "Copy Report" button as well as the menu.</summary>
	public static void CopyAll(ListView list)
	{
		ArgumentNullException.ThrowIfNull(list);

		StringBuilder sb = new();

		// Header line.
		string[] headers = new string[list.Columns.Count];
		for (int c = 0; c < list.Columns.Count; c++)
		{
			headers[c] = list.Columns[c].Text;
		}
		sb.AppendLine(string.Join('\t', headers));

		// Data lines.
		foreach (ListViewItem item in list.Items)
		{
			sb.AppendLine(RowToLine(item));
		}

		SetClipboard(sb.ToString());
	}

	private static string RowToLine(ListViewItem item)
	{
		string[] cells = new string[item.SubItems.Count];
		for (int i = 0; i < item.SubItems.Count; i++)
		{
			cells[i] = item.SubItems[i].Text;
		}
		return string.Join('\t', cells);
	}

	/// <summary>Sets clipboard text defensively: the Win32 clipboard can be transiently locked by other
	/// processes, so swallow the resulting ExternalException rather than crashing the UI.</summary>
	private static void SetClipboard(string text)
	{
		if (string.IsNullOrEmpty(text))
		{
			return;
		}

		try
		{
			Clipboard.SetText(text);
		}
		catch (System.Runtime.InteropServices.ExternalException)
		{
			// Clipboard busy — ignore; the operator can retry.
		}
	}
}
