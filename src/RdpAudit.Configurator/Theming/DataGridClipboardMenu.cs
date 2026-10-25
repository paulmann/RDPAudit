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
using RdpAudit.Configurator.Services;
using RdpAudit.Core.Models;

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

	/// <summary>Creates a themed menu with the clipboard actions plus the tabular Export submenu.</summary>
	/// <param name="tableLabel">Operator-facing table name written into the exported file's provenance.</param>
	/// <param name="status">Status sink every export result is reported through.</param>
	public static ContextMenuStrip AttachWithExport(DataGridView grid, string tableLabel, Action<string> status)
	{
		ArgumentNullException.ThrowIfNull(grid);
		ContextMenuStrip menu = new();
		AppendTo(menu, grid, includeCopyAll: true, leadingSeparator: false);
		AppendExportSubmenu(menu, grid, tableLabel, status);
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

	/// <summary>
	/// Appends the two-level <c>Export → Export Selected Rows → JSON / TXT / Markdown / CSV</c> submenu to
	/// an existing menu. Public because several pages build their own menu and only need this section.
	/// </summary>
	/// <param name="menu">Menu to append to.</param>
	/// <param name="grid">Grid whose selected rows are exported.</param>
	/// <param name="tableLabel">Operator-facing table name recorded in the exported file.</param>
	/// <param name="status">Status sink for the export result.</param>
	/// <returns>The created <c>Export</c> root item, so the caller can position or inspect it.</returns>
	public static ToolStripMenuItem AppendExportSubmenu(
		ContextMenuStrip menu,
		DataGridView grid,
		string tableLabel,
		Action<string> status)
	{
		ArgumentNullException.ThrowIfNull(menu);
		ArgumentNullException.ThrowIfNull(grid);
		ArgumentNullException.ThrowIfNull(status);

		menu.Items.Add(new ToolStripSeparator());

		ToolStripMenuItem root = new("Export");
		ToolStripMenuItem selectedRows = new("Export Selected Rows");
		foreach (TableExportFormat format in Enum.GetValues<TableExportFormat>())
		{
			TableExportFormat captured = format;
			selectedRows.DropDownItems.Add(new ToolStripMenuItem(
				FormatMenuLabel(captured),
				null,
				SafeAsyncHandler.Wrap(
					() => ExportSelectedRowsAsync(grid, tableLabel, captured, status),
					ex => status("Export FAILED: " + ex.GetType().Name + " — " + ex.Message))));
		}

		root.DropDownItems.Add(selectedRows);

		// Enable per-menu-open: with nothing selected there is no honest "selected rows" export, and a
		// disabled item plus a hint is clearer than exporting something the operator did not pick.
		menu.Opening += (_, _) =>
		{
			bool hasRow = SelectedRowCount(grid) > 0;
			root.Enabled = grid.Rows.Count > 0;
			selectedRows.Enabled = hasRow;
		};

		menu.Items.Add(root);
		return root;
	}

	/// <summary>Reads the grid's selected rows and hands them to the shared tabular writer.</summary>
	private static async Task ExportSelectedRowsAsync(
		DataGridView grid,
		string tableLabel,
		TableExportFormat format,
		Action<string> status)
	{
		if (SelectedRowCount(grid) == 0)
		{
			status("Export Selected Rows skipped: select one or more rows first.");
			return;
		}

		TabularExportDocument document = BuildDocument(grid, tableLabel);
		string defaultName = TabularExportWriter.GetDefaultFileName(
			tableLabel,
			"selected",
			format,
			DateTime.UtcNow);

		using SaveFileDialog dialog = new()
		{
			Title = "Export Selected Rows — " + tableLabel,
			FileName = defaultName,
			DefaultExt = TabularExportWriter.GetFileExtension(format).TrimStart('.'),
			Filter = TabularExportWriter.GetSaveFileFilter(format),
			FilterIndex = 1,
			AddExtension = true,
			OverwritePrompt = true,
			RestoreDirectory = true,
		};

		DialogResult choice = dialog.ShowDialog();
		if (choice != DialogResult.OK || string.IsNullOrWhiteSpace(dialog.FileName))
		{
			status("Export Selected Rows cancelled by user.");
			return;
		}

		// The menu item already fixed the format; the confirmed extension must agree with it.
		if (!TabularExportWriter.TryGetFormatForFile(dialog.FileName, out TableExportFormat confirmed)
			|| confirmed != format)
		{
			status("Export FAILED: file extension does not match the chosen format (" + format
				+ "). Expected " + TabularExportWriter.GetFileExtension(format) + ".");
			return;
		}

		await TabularExportRunner.WriteAsync(document, format, dialog.FileName, status).ConfigureAwait(true);
	}

	/// <summary>Builds the export document from the grid's selected rows and its displayed column headers.</summary>
	internal static TabularExportDocument BuildDocument(DataGridView grid, string tableLabel)
	{
		ArgumentNullException.ThrowIfNull(grid);

		string[] headers = new string[grid.Columns.Count];
		for (int c = 0; c < grid.Columns.Count; c++)
		{
			headers[c] = grid.Columns[c].HeaderText;
		}

		List<IReadOnlyList<string>> rows = new();
		int visible = 0;
		for (int r = 0; r < grid.Rows.Count; r++)
		{
			DataGridViewRow row = grid.Rows[r];
			if (row.IsNewRow)
			{
				continue;
			}

			visible++;
			if (!row.Selected)
			{
				continue;
			}

			string[] cells = new string[grid.Columns.Count];
			for (int c = 0; c < grid.Columns.Count; c++)
			{
				cells[c] = row.Cells[c].FormattedValue?.ToString() ?? string.Empty;
			}

			rows.Add(cells);
		}

		return new TabularExportDocument
		{
			Source = tableLabel,
			Scope = "Selected rows",
			GeneratedUtc = DateTime.UtcNow,
			FilterSummary = null,
			VisibleRowCount = visible,
			Columns = headers,
			Rows = rows,
		};
	}

	/// <summary>Counts selected data rows, ignoring the WinForms new-row placeholder.</summary>
	private static int SelectedRowCount(DataGridView grid)
	{
		int count = 0;
		for (int r = 0; r < grid.Rows.Count; r++)
		{
			DataGridViewRow row = grid.Rows[r];
			if (!row.IsNewRow && row.Selected)
			{
				count++;
			}
		}

		return count;
	}

	/// <summary>Stable menu label for a format (<c>CSV</c> rather than <c>Csv</c>).</summary>
	internal static string FormatMenuLabel(TableExportFormat format) => format switch
	{
		TableExportFormat.Json => "JSON",
		TableExportFormat.Txt => "TXT",
		TableExportFormat.Markdown => "Markdown",
		TableExportFormat.Csv => "CSV",
		_ => format.ToString(),
	};

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
