// File:    src/RdpAudit.Configurator/Services/AuthSuccessExportRunner.cs
// Module:  RdpAudit.Configurator.Services
// Purpose: Reusable "Export Auth Success (per login)" runner: queries GetAuthSuccessSummaryForIp over
//          IPC (service-side per-login aggregation over AuthAttemptFacts), formats the summary via
//          Core/Events/AuthSuccessExportFormatter (one row per login — NOT one per attempt — with
//          successful/failed/denied counts, first/last event dates, failed attempts before the first
//          success, and time-to-first-success), prompts the operator for a save path via SaveFileDialog
//          (UTF-8 output; UTF-8 BOM for CSV so Excel detects encoding) and reports the result through the
//          supplied status sink. The runner never writes to arbitrary paths: writes only happen after the
//          user confirms a path.
// Depends: IpcClient, AuthSuccessExportFormatter, AuthSuccessSummaryDto / AuthSuccessSummaryRequest
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

/// <summary>Reusable "Export Auth Success (per login)" runner used by the Attack Statistics tab.</summary>
[SupportedOSPlatform("windows")]
public static class AuthSuccessExportRunner
{
	/// <summary>Server-clamps at its own maximum; we ask for a bounded snapshot suitable for an operator export.</summary>
	private const int DefaultLimit = 500;

	/// <summary>Runs the full export flow: IPC fetch → format → SaveFileDialog → UTF-8 write → status.</summary>
	public static async Task RunAsync(IpcClient ipc, string ip, AuthSuccessExportFormat format, Action<string> status)
	{
		ArgumentNullException.ThrowIfNull(ipc);
		ArgumentNullException.ThrowIfNull(status);
		if (string.IsNullOrWhiteSpace(ip))
		{
			status("Export Auth Success (per login) aborted: empty IP.");
			return;
		}

		AuthSuccessSummaryRequest request = new() { Ip = ip.Trim(), Limit = DefaultLimit, SucceededLoginsOnly = true };
		AuthSuccessSummaryDto? dto;
		try
		{
			dto = await ipc.SendAsync<AuthSuccessSummaryDto>(IpcCommand.GetAuthSuccessSummaryForIp, request).ConfigureAwait(true);
		}
		catch (Exception ex)
		{
			status("Export Auth Success (per login) FAILED: " + ex.GetType().Name + " — " + ex.Message);
			return;
		}

		if (dto is null)
		{
			status("Export Auth Success (per login) FAILED: service unreachable.");
			return;
		}

		if (dto.Status != IpcResultStatus.Success)
		{
			status(string.Format(CultureInfo.InvariantCulture,
				"Export Auth Success (per login) aborted: service returned status {0} — {1}",
				dto.Status, dto.Message ?? "no message"));
			return;
		}

		string body = AuthSuccessExportFormatter.Format(dto, format);
		string defaultName = AuthSuccessExportFormatter.GetDefaultFileName(dto, format, DateTime.UtcNow);
		string filter = AuthSuccessExportFormatter.GetSaveFileFilter(format);
		string ext = AuthSuccessExportFormatter.GetFileExtension(format);

		using SaveFileDialog dialog = new()
		{
			Title = "Export Auth Success (per login)",
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
			status("Export Auth Success (per login) cancelled by user.");
			return;
		}

		try
		{
			Encoding encoding = format == AuthSuccessExportFormat.Csv
				? new UTF8Encoding(encoderShouldEmitUTF8Identifier: true)
				: new UTF8Encoding(encoderShouldEmitUTF8Identifier: false);
			await File.WriteAllTextAsync(dialog.FileName, body, encoding).ConfigureAwait(true);
			status(string.Format(CultureInfo.InvariantCulture,
				"Export Auth Success (per login) OK ({0}): wrote {1} chars to {2} (logins in report={3}, succeeded logins={4}, auth facts scanned={5}).",
				format, body.Length, dialog.FileName, dto.Logins.Count, dto.DistinctSucceededLogins, dto.TotalAuthFacts));
		}
		catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException)
		{
			status("Export Auth Success (per login) FAILED: " + ex.GetType().Name + " — " + ex.Message);
		}
	}
}
