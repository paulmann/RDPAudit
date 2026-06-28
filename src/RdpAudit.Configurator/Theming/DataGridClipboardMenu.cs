// File:    src/RdpAudit.Configurator/Theming/DataGridClipboardMenu.cs
// Module:  RdpAudit.Configurator.Theming
// Purpose: Adds dark-themed Copy Cell / Copy Row / Copy All (report) clipboard actions to a
//          DataGridView, either by creating a fresh themed ContextMenuStrip or by appending the actions
//          to an existing menu (so pages that already have a right-click menu keep their own items).
// Depends: System.Windows.Forms.DataGridView, DarkTheme.StyleMenu
// Extends: To add another clipboard action, add a ToolStripMenuItem in BuildItems and a matching Copy*
//          helper below.
//
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com
// Version: 1.0.0

using System.Runtime.Versioning;
using System.Text;
using System.Windows.Forms;

namespace RdpAudit.Configurator.Theming;

/// <summary>
/// Clipboard helper for <see cref="DataGridView"/> grids. Tracks the cell under the cursor on
/// right-click so "Copy Cell" targets the clicked cell, copies the selected row tab-separated, and
/// exports the whole grid (headers + rows) as a tab-separated report. Works for both data-bound and
/// manually-populated grids because it reads formatted cell values directly off the grid.
/// </summary>
[SupportedOSPlatform("windows")]
internal static class DataGridClipboardMenu
{
	// ── Public API ───────────────────────────────────────────────────────────────

	/// <summary>Creates a new themed ContextMenuStrip with the clipboard actions and assigns it to the
	/// grid. Use for grids that do not already have a context menu.</summary>
	public static ContextMenuStrip Attach(DataGridView grid, bool includeCopyAll = true)
	{
		ArgumentNullException.ThrowIfNull(grid);

		ContextMenuStrip menu = new();
		AppendTo(menu, grid, includeCopyAll, leadingSeparator: false);
		grid.ContextMenuStrip = menu;
		DarkTheme.StyleMenu(menu);
		return menu;
	}

	/// <summary>Appends the clipboard actions to an existing menu (separated from the page's own items)
	/// and re-applies the dark theme. Use for grids that already expose a context menu.</summary>
	public static void AppendTo(ContextMenuStrip menu, DataGridView grid, bool includeCopyAll = true)
	{
		ArgumentNullException.ThrowIfNull(menu);
		ArgumentNullException.ThrowIfNull(grid);

		AppendTo(menu, grid, includeCopyAll, leadingSeparator: menu.Items.Count > 0);
		DarkTheme.StyleMenu(menu);
	}

	// ── Core Logic ───────────────────────────────────────────────────────────────

	private static void AppendTo(ContextMenuStrip menu, DataGridView grid, bool includeCopyAll, bool leadingSeparator)
	{
		int hitColumn = -1;

		grid.CellMouseDown += (_, e) =>
		{
			if (e.Button == MouseButtons.Right)
			{
				hitColumn = e.ColumnIndex;
				if (e.RowIndex >= 0 && !grid.Rows[e.RowIndex].Selected)
				{
					grid.ClearSelection();
					grid.Rows[e.RowIndex].Selected = true;
				}
			}
		};

		if (leadingSeparator)
		{
			menu.Items.Add(new ToolStripSeparator());
		}

		menu.Items.Add(new ToolStripMenuItem("Copy Cell", null, (_, _) => CopyCell(grid, hitColumn)));
		menu.Items.Add(new ToolStripMenuItem("Copy Row", null, (_, _) => CopyRow(grid)));

		if (includeCopyAll)
		{
			menu.Items.Add(new ToolStripMenuItem("Copy All (report)", null, (_, _) => CopyAll(grid)));
		}
	}

	private static void CopyCell(DataGridView grid, int column)
	{
		if (grid.CurrentRow is null || column < 0 || column >= grid.Columns.Count)
		{
			return;
		}

		object? value = grid.CurrentRow.Cells[column].FormattedValue;
		SetClipboard(value?.ToString() ?? string.Empty);
	}

	private static void CopyRow(DataGridView grid)
	{
		if (grid.CurrentRow is null)
		{
			return;
		}

		SetClipboard(RowToLine(grid, grid.CurrentRow));
	}

	/// <summary>Copies the whole grid (header line + every row) to the clipboard as a tab-separated
	/// report. Exposed so pages can wire it to a dedicated "Copy Report" button as well as the menu.</summary>
	public static void CopyAll(DataGridView grid)
	{
		ArgumentNullException.ThrowIfNull(grid);

		StringBuilder sb = new();

		string[] headers = new string[grid.Columns.Count];
		for (int c = 0; c < grid.Columns.Count; c++)
		{
			headers[c] = grid.Columns[c].HeaderText;
		}
		sb.AppendLine(string.Join('\t', headers));

		foreach (DataGridViewRow row in grid.Rows)
		{
			if (!row.IsNewRow)
			{
				sb.AppendLine(RowToLine(grid, row));
			}
		}

		SetClipboard(sb.ToString());
	}

	private static string RowToLine(DataGridView grid, DataGridViewRow row)
	{
		string[] cells = new string[grid.Columns.Count];
		for (int c = 0; c < grid.Columns.Count; c++)
		{
			cells[c] = row.Cells[c].FormattedValue?.ToString() ?? string.Empty;
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
