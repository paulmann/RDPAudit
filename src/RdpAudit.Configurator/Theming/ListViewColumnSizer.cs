// File:    src/RdpAudit.Configurator/Theming/ListViewColumnSizer.cs
// Module:  RdpAudit.Configurator.Theming
// Purpose: Stretches the last column of a details-view ListView to consume the remaining client width
//          so GridLines never paint an empty trailing area that reads as a spurious extra column.
// Depends: System.Windows.Forms.ListView
// Extends: To change the minimum width the stretched column will shrink to, change MinWidth below.
//
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com
// Version: 1.0.0

using System.Runtime.Versioning;
using System.Windows.Forms;

namespace RdpAudit.Configurator.Theming;

/// <summary>
/// Helper that makes the last column of a <see cref="ListView"/> (View.Details) fill the leftover
/// client width. WinForms leaves any unused horizontal space to the right of the last fixed-width
/// column blank; with GridLines enabled that blank area is framed and looks like an extra empty
/// column. Wiring <see cref="StretchLast"/> to the control's Resize event removes that artefact.
/// </summary>
[SupportedOSPlatform("windows")]
internal static class ListViewColumnSizer
{
	private const int MinWidth = 120;

	/// <summary>Wires the last-column stretch to the list's Resize event and applies it once immediately
	/// so the column is correct on first render as well as after every resize.</summary>
	public static void EnableLastColumnFill(ListView list)
	{
		ArgumentNullException.ThrowIfNull(list);

		list.Resize += (_, _) => StretchLast(list);
		StretchLast(list);
	}

	/// <summary>Sets the last column's width so all columns together exactly fill the client width.</summary>
	public static void StretchLast(ListView list)
	{
		ArgumentNullException.ThrowIfNull(list);

		if (list.Columns.Count == 0)
		{
			return;
		}

		int used = 0;
		for (int i = 0; i < list.Columns.Count - 1; i++)
		{
			used += list.Columns[i].Width;
		}

		int remaining = list.ClientSize.Width - used;
		ColumnHeader last = list.Columns[list.Columns.Count - 1];
		last.Width = remaining > MinWidth ? remaining : MinWidth;
	}
}
