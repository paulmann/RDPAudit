// File:    src/RdpAudit.Configurator/Services/AttackStatRowsExportRunner.cs
// Module:  RdpAudit.Configurator.Services
// Purpose: Entry point for the RDP Activity tab "Export" submenu (Export Selected Rows / Red Rows /
//          Yellow Rows / All Rows, each offering JSON / TXT / Markdown / CSV). It resolves the scope
//          through AttackStatRowsExportFormatter and hands the resulting table document to the shared
//          TabularExportRunner, so every grid in the Configurator saves through one code path and one
//          set of format encoders.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Globalization;
using System.Runtime.Versioning;
using RdpAudit.Core.Ipc.Contracts;
using RdpAudit.Core.Models;

namespace RdpAudit.Configurator.Services;

/// <summary>RDP Activity row-export runner used by the Attack Statistics (RDP Activity) tab.</summary>
[SupportedOSPlatform("windows")]
public static class AttackStatRowsExportRunner
{
	/// <summary>Stable stem used in the default file name for the RDP Activity table.</summary>
	public const string FileNameStem = "rdp-activity";

	/// <summary>
	/// Resolves the requested scope, reports what it covers (including any unresolved-IP rows left out)
	/// and writes it in the format the menu item named.
	/// </summary>
	/// <param name="rows">Rows the export covers (selected rows, or displayed rows for the band scopes).</param>
	/// <param name="scope">Which slice of the grid to export.</param>
	/// <param name="format">Format chosen by the third-level menu item.</param>
	/// <param name="filterSummary">Description of the active grid filters, recorded in the file header.</param>
	/// <param name="visibleRowCount">How many rows the grid displays, recorded in the file header.</param>
	/// <param name="status">Status sink (the page's timestamped status strip).</param>
	public static async Task RunAsync(
		IReadOnlyList<AttackStatEntryDto> rows,
		AttackStatRowScope scope,
		TableExportFormat format,
		string? filterSummary,
		int visibleRowCount,
		Action<string> status)
	{
		ArgumentNullException.ThrowIfNull(rows);
		ArgumentNullException.ThrowIfNull(status);

		AttackStatRowsExportSelection selection = AttackStatRowsExportFormatter.Select(rows, scope);
		if (selection.Rows.Count == 0)
		{
			status("Export " + selection.ScopeLabel + " skipped: no rows in this scope.");
			return;
		}

		if (selection.ExcludedSentinels > 0)
		{
			// Say it before the dialog: the exclusion is a deliberate classification, not a bug.
			status(string.Format(
				CultureInfo.InvariantCulture,
				"Export {0}: {1} row(s); {2} unresolved-IP row(s) will be excluded.",
				selection.ScopeLabel,
				selection.Rows.Count,
				selection.ExcludedSentinels));
		}

		AttackStatRowsExportContext context = new()
		{
			NowUtc = DateTime.UtcNow,
			FilterSummary = filterSummary,
			VisibleRowCount = visibleRowCount,
		};

		TabularExportDocument document = AttackStatRowsExportFormatter.BuildDocument(selection, context);

		string defaultName = TabularExportWriter.GetDefaultFileName(
			FileNameStem,
			selection.ScopeLabel,
			format,
			DateTime.UtcNow);

		using SaveFileDialog dialog = new()
		{
			Title = "Export " + selection.ScopeLabel + " — " + document.Source,
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
			status("Export " + selection.ScopeLabel + " cancelled by user.");
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
}
