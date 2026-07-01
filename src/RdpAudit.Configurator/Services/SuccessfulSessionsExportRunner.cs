// File:    src/RdpAudit.Configurator/Services/SuccessfulSessionsExportRunner.cs
// Module:  RdpAudit.Configurator.Services
// Purpose: Reusable "Export Successful RDP Sessions" runner: queries GetConnectionFactsForIp over
//          IPC, formats the successful subset via Core/Events/SuccessfulSessionsExportFormatter
//          (each session annotated with the events the success decision was based on), prompts the
//          operator for a save path via SaveFileDialog (UTF-8 output; UTF-8 BOM for CSV so Excel
//          detects encoding) and reports the result through the supplied status sink. The runner
//          never writes to arbitrary paths: writes only happen after the user confirms a path.
// Depends: IpcClient, SuccessfulSessionsExportFormatter, ConnectionFactsForIpDto / Request
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Globalization;
using System.Runtime.Versioning;
using System.Text;
using RdpAudit.Configurator.Ipc;
using RdpAudit.Core.Events;
using RdpAudit.Core.Ipc;
using RdpAudit.Core.Ipc.Contracts;

namespace RdpAudit.Configurator.Services;

/// <summary>Reusable "Export Successful RDP Sessions" runner used by the Attack Statistics tab.</summary>
[SupportedOSPlatform("windows")]
public static class SuccessfulSessionsExportRunner
{
	/// <summary>Server-clamps at 1000; we ask for a bounded snapshot suitable for an operator export.</summary>
	private const int DefaultLimit = 500;

	/// <summary>Runs the full export flow: IPC fetch → filter+format → SaveFileDialog → UTF-8 write → status.</summary>
	public static async Task RunAsync(IpcClient ipc, string ip, SuccessfulSessionsExportFormat format, Action<string> status)
	{
		ArgumentNullException.ThrowIfNull(ipc);
		ArgumentNullException.ThrowIfNull(status);
		if (string.IsNullOrWhiteSpace(ip))
		{
			status("Export Successful RDP Sessions aborted: empty IP.");
			return;
		}

		ConnectionFactsForIpRequest request = new() { Ip = ip.Trim(), Limit = DefaultLimit };
		ConnectionFactsForIpDto? dto;
		try
		{
			dto = await ipc.SendAsync<ConnectionFactsForIpDto>(IpcCommand.GetConnectionFactsForIp, request).ConfigureAwait(true);
		}
		catch (Exception ex)
		{
			status("Export Successful RDP Sessions FAILED: " + ex.GetType().Name + " — " + ex.Message);
			return;
		}

		if (dto is null)
		{
			status("Export Successful RDP Sessions FAILED: service unreachable.");
			return;
		}

		if (dto.Status != IpcResultStatus.Success)
		{
			status(string.Format(CultureInfo.InvariantCulture,
				"Export Successful RDP Sessions aborted: service returned status {0} — {1}",
				dto.Status, dto.Message ?? "no message"));
			return;
		}

		string body = SuccessfulSessionsExportFormatter.Format(dto, format);
		string defaultName = SuccessfulSessionsExportFormatter.GetDefaultFileName(dto, format, DateTime.UtcNow);
		string filter = SuccessfulSessionsExportFormatter.GetSaveFileFilter(format);
		string ext = SuccessfulSessionsExportFormatter.GetFileExtension(format);

		using SaveFileDialog dialog = new()
		{
			Title = "Export Successful RDP Sessions",
			FileName = defaultName,
			DefaultExt = ext.TrimStart('.'),
			Filter = filter,
			AddExtension = true,
			OverwritePrompt = true,
			RestoreDirectory = true,
		};

		DialogResult choice = dialog.ShowDialog();
		if (choice != DialogResult.OK || string.IsNullOrWhiteSpace(dialog.FileName))
		{
			status("Export Successful RDP Sessions cancelled by user.");
			return;
		}

		try
		{
			Encoding encoding = format == SuccessfulSessionsExportFormat.Csv
				? new UTF8Encoding(encoderShouldEmitUTF8Identifier: true)
				: new UTF8Encoding(encoderShouldEmitUTF8Identifier: false);
			await File.WriteAllTextAsync(dialog.FileName, body, encoding).ConfigureAwait(true);
			int successfulCount = dto.Facts.Count(SuccessfulSessionsExportFormatter.IsSuccessful);
			status(string.Format(CultureInfo.InvariantCulture,
				"Export Successful RDP Sessions OK ({0}): wrote {1} chars to {2} (successful sessions={3}, facts scanned={4}).",
				format, body.Length, dialog.FileName, successfulCount, dto.Facts.Count));
		}
		catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException)
		{
			status("Export Successful RDP Sessions FAILED: " + ex.GetType().Name + " — " + ex.Message);
		}
	}
}
