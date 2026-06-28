// File:    src/RdpAudit.Configurator/Services/ConnectionFactsExportRunner.cs
// Module:  RdpAudit.Configurator.Services
// Purpose: Reusable Stage IP-E "Export Connection Facts" runner: queries GetConnectionFactsForIp
//          over IPC, formats the response via Core/Events/ConnectionFactsExportFormatter, prompts
//          the operator for a save path via SaveFileDialog (UTF-8 output, default extension
//          matches format) and reports the result through the supplied status sink. The runner
//          never writes to arbitrary paths: writes only happen after the user confirms a path.
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

/// <summary>Reusable Stage IP-E "Export Connection Facts" runner used by Attack Statistics,
/// Live Events, and Remote RDP Clients tabs.</summary>
[SupportedOSPlatform("windows")]
public static class ConnectionFactsExportRunner
{
	/// <summary>Server-clamps at 1000; we ask for a bounded snapshot suitable for an operator export.</summary>
	private const int DefaultLimit = 500;

	/// <summary>Runs the full export flow: IPC fetch → format → SaveFileDialog → UTF-8 write → status report.</summary>
	public static async Task RunAsync(IpcClient ipc, string ip, ConnectionFactsExportFormat format, Action<string> status)
	{
		ArgumentNullException.ThrowIfNull(ipc);
		ArgumentNullException.ThrowIfNull(status);
		if (string.IsNullOrWhiteSpace(ip))
		{
			status("Export Connection Facts aborted: empty IP.");
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
			status("Export Connection Facts FAILED: " + ex.GetType().Name + " — " + ex.Message);
			return;
		}

		if (dto is null)
		{
			status("Export Connection Facts FAILED: service unreachable.");
			return;
		}

		if (dto.Status != IpcResultStatus.Success)
		{
			status(string.Format(CultureInfo.InvariantCulture,
				"Export Connection Facts aborted: service returned status {0} — {1}",
				dto.Status, dto.Message ?? "no message"));
			return;
		}

		string body = ConnectionFactsExportFormatter.Format(dto, format);
		string defaultName = ConnectionFactsExportFormatter.GetDefaultFileName(dto, format, DateTime.UtcNow);
		string filter = ConnectionFactsExportFormatter.GetSaveFileFilter(format);
		string ext = ConnectionFactsExportFormatter.GetFileExtension(format);

		using SaveFileDialog dialog = new()
		{
			Title = "Export Connection Facts",
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
			status("Export Connection Facts cancelled by user.");
			return;
		}

		try
		{
			Encoding encoding = format == ConnectionFactsExportFormat.Csv
				? new UTF8Encoding(encoderShouldEmitUTF8Identifier: true)
				: new UTF8Encoding(encoderShouldEmitUTF8Identifier: false);
			await File.WriteAllTextAsync(dialog.FileName, body, encoding).ConfigureAwait(true);
			status(string.Format(CultureInfo.InvariantCulture,
				"Export Connection Facts OK ({0}): wrote {1} chars to {2} (facts={3}).",
				format, body.Length, dialog.FileName, dto.Facts.Count));
		}
		catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException)
		{
			status("Export Connection Facts FAILED: " + ex.GetType().Name + " — " + ex.Message);
		}
	}
}
