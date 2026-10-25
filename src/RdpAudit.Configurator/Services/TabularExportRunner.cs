// File:    src/RdpAudit.Configurator/Services/TabularExportRunner.cs
// Module:  RdpAudit.Configurator.Services
// Purpose: Single save/write path for every tabular Export submenu item in the Configurator. The
//          caller supplies a TabularExportDocument (or just headers and rows); this runner owns the
//          SaveFileDialog, the extension-to-format decision, the UTF-8 write (CSV with BOM so Excel
//          detects the encoding) and the status report. Because the format is taken from the file name
//          the operator actually confirmed, a file's contents can never disagree with its extension.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Globalization;
using System.Runtime.Versioning;
using System.Text;
using RdpAudit.Core.Models;

namespace RdpAudit.Configurator.Services;

/// <summary>Shared UTF-8 writer used by every tabular export in the Configurator.</summary>
[SupportedOSPlatform("windows")]
public static class TabularExportRunner
{
	/// <summary>Writes an already-resolved format/path pair, reporting the outcome through
	/// <paramref name="status"/>. The caller owns the SaveFileDialog because each menu decides its own
	/// format (RDP Activity) or derives it from the confirmed file name (the shared submenu).</summary>
	public static async Task WriteAsync(
		TabularExportDocument document,
		TableExportFormat format,
		string path,
		Action<string> status)
	{
		ArgumentNullException.ThrowIfNull(document);
		ArgumentNullException.ThrowIfNull(status);

		try
		{
			string body = TabularExportWriter.Format(document, format);
			Encoding encoding = format == TableExportFormat.Csv
				? new UTF8Encoding(encoderShouldEmitUTF8Identifier: true)
				: new UTF8Encoding(encoderShouldEmitUTF8Identifier: false);
			await File.WriteAllTextAsync(path, body, encoding).ConfigureAwait(true);
			status(string.Format(
				CultureInfo.InvariantCulture,
				"Export {0} OK ({1}): wrote {2} chars, {3} row(s), {4} column(s) to {5}.",
				document.Scope,
				format,
				body.Length,
				document.Rows.Count,
				document.Columns.Count,
				path));
		}
		catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException)
		{
			status("Export FAILED: " + ex.GetType().Name + " — " + ex.Message);
		}
	}
}
