// File:    src/RdpAudit.Configurator/Services/IpEventsExportRunner.cs
// Module:  RdpAudit.Configurator.Services
// Purpose: Reusable Stage A "Export All IP Events" runner: queries GetEventsForIp over IPC,
//          formats the response via Core/Events/IpEventsExportFormatter, prompts the operator
//          for a save path via SaveFileDialog (UTF-8 output, default extension matches format)
//          and reports the result through the supplied status sink. The runner never writes to
//          arbitrary paths: writes only happen after the user confirms a path.
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

/// <summary>Reusable Stage A "Export All IP Events" runner used by Live Events and Attack Statistics.</summary>
[SupportedOSPlatform("windows")]
public static class IpEventsExportRunner
{
	/// <summary>Runs the full export flow: IPC fetch → format → SaveFileDialog → UTF-8 write → status report.</summary>
	public static async Task RunAsync(IpcClient ipc, string ip, IpEventsExportFormat format, Action<string> status)
	{
		ArgumentNullException.ThrowIfNull(ipc);
		ArgumentNullException.ThrowIfNull(status);
		if (string.IsNullOrWhiteSpace(ip))
		{
			status("Export aborted: empty IP.");
			return;
		}

		EventsForIpRequest request = new() { Ip = ip.Trim(), Limit = 0 };
		EventsForIpDto? dto;
		try
		{
			dto = await ipc.SendAsync<EventsForIpDto>(IpcCommand.GetEventsForIp, request).ConfigureAwait(true);
		}
		catch (Exception ex)
		{
			status("Export FAILED: " + ex.GetType().Name + " — " + ex.Message);
			return;
		}

		if (dto is null)
		{
			status("Export FAILED: service unreachable.");
			return;
		}

		if (dto.Status != IpcResultStatus.Success)
		{
			status(string.Format(CultureInfo.InvariantCulture,
				"Export aborted: service returned status {0} — {1}",
				dto.Status, dto.Message ?? "no message"));
			return;
		}

		string body = IpEventsExportFormatter.Format(dto, format);
		string defaultName = IpEventsExportFormatter.GetDefaultFileName(dto, format, DateTime.UtcNow);
		string filter = IpEventsExportFormatter.GetSaveFileFilter(format);
		string ext = IpEventsExportFormatter.GetFileExtension(format);

		using SaveFileDialog dialog = new()
		{
			Title = "Export All IP Events",
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
			status("Export cancelled by user.");
			return;
		}

		try
		{
			// Always UTF-8. We pick UTF-8-with-BOM only for CSV so Excel detects the encoding correctly;
			// every other format is plain UTF-8 (no BOM).
			Encoding encoding = format == IpEventsExportFormat.Csv
				? new UTF8Encoding(encoderShouldEmitUTF8Identifier: true)
				: new UTF8Encoding(encoderShouldEmitUTF8Identifier: false);
			await File.WriteAllTextAsync(dialog.FileName, body, encoding).ConfigureAwait(true);
			status(string.Format(CultureInfo.InvariantCulture,
				"Export OK ({0}): wrote {1} chars to {2}.",
				format, body.Length, dialog.FileName));
		}
		catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException)
		{
			status("Export FAILED: " + ex.GetType().Name + " — " + ex.Message);
		}
	}
}
