// File:    src/RdpAudit.Configurator/Services/SiemExportRunner.cs
// Module:  RdpAudit.Configurator.Services
// Purpose: Backlog #4 SIEM export runner: pulls the service version (GetStatus), the bounded
//          per-IP event window (GetEventsForIp, ord 39) and the bounded per-IP correlated-alert
//          window (GetAlertsForIp, ord 70) over IPC, composes the neutral SiemEvent stream via
//          Core/Siem/SiemEventMapper, renders it with the CEF / LEEF 2.0 / NDJSON serializers,
//          prompts the operator for a save path via SaveFileDialog and writes the result as
//          UTF-8 without BOM. The device version travels from IPC ServiceStatus.Version and is
//          never hardcoded. The pure BuildText composition is exposed for deterministic tests
//          (no dialog, no named pipe).
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Editions;
using System.Globalization;
using System.Runtime.Versioning;
using System.Text;
using RdpAudit.Configurator.Ipc;
using RdpAudit.Core.Ipc;
using RdpAudit.Core.Ipc.Contracts;
using RdpAudit.Core.Siem;

namespace RdpAudit.Configurator.Services;

/// <summary>Reusable Backlog #4 "Export SIEM Events + Alerts" runner used by Live Events and Attack Statistics.</summary>
[SupportedOSPlatform("windows")]
public static class SiemExportRunner
{
	/// <summary>Runs the full SIEM export flow: IPC fetch (status version, events, alerts) → neutral
	/// SiemEvent composition → format render → SaveFileDialog → UTF-8-no-BOM write → status report.</summary>
	public static async Task RunAsync(IpcClient ipc, string ip, SiemFormat format, Action<string> status)
	{
		ArgumentNullException.ThrowIfNull(ipc);
		ArgumentNullException.ThrowIfNull(status);

		if (!EditionContext.Allows(EditionFeature.SiemExport))
		{
			status("SIEM Export aborted: " + EditionContext.DenialReason(EditionFeature.SiemExport));
			return;
		}
		if (string.IsNullOrWhiteSpace(ip))
		{
			status("SIEM Export aborted: empty IP.");
			return;
		}

		string normalizedIp = ip.Trim();
		if (!System.Net.IPAddress.TryParse(normalizedIp, out _))
		{
			status("SIEM Export aborted: invalid IP address.");
			return;
		}

		string? deviceVersion;
		try
		{
			ServiceStatus? serviceStatus = await ipc.SendAsync<ServiceStatus>(IpcCommand.GetStatus).ConfigureAwait(true);
			deviceVersion = serviceStatus?.Version;
		}
		catch (Exception ex)
		{
			status("SIEM Export FAILED: " + ex.GetType().Name + " - " + ex.Message);
			return;
		}

		if (string.IsNullOrWhiteSpace(deviceVersion))
		{
			status("SIEM Export FAILED: service version unavailable.");
			return;
		}

		EventsForIpDto? eventsDto;
		AlertsForIpDto? alertsDto;
		try
		{
			EventsForIpRequest eventsRequest = new() { Ip = normalizedIp, Limit = 0 };
			eventsDto = await ipc.SendAsync<EventsForIpDto>(IpcCommand.GetEventsForIp, eventsRequest).ConfigureAwait(true);
			AlertsForIpRequest alertsRequest = new() { Ip = normalizedIp, Limit = 0 };
			alertsDto = await ipc.SendAsync<AlertsForIpDto>(IpcCommand.GetAlertsForIp, alertsRequest).ConfigureAwait(true);
		}
		catch (Exception ex)
		{
			status("SIEM Export FAILED: " + ex.GetType().Name + " - " + ex.Message);
			return;
		}

		if (eventsDto is null || eventsDto.Status != IpcResultStatus.Success)
		{
			status(string.Format(CultureInfo.InvariantCulture,
				"SIEM Export aborted: GetEventsForIp returned status {0} - {1}",
				eventsDto?.Status ?? (IpcResultStatus)(-1), eventsDto?.Message ?? "service unreachable"));
			return;
		}

		if (alertsDto is null || alertsDto.Status != IpcResultStatus.Success)
		{
			status(string.Format(CultureInfo.InvariantCulture,
				"SIEM Export aborted: GetAlertsForIp returned status {0} - {1}",
				alertsDto?.Status ?? (IpcResultStatus)(-1), alertsDto?.Message ?? "service unreachable"));
			return;
		}

		string body = BuildText(eventsDto, alertsDto, format, deviceVersion);
		if (body.Length == 0)
		{
			status("SIEM Export aborted: no events or alerts for the selected IP.");
			return;
		}

		string defaultName = SiemSerializerFactory.GetDefaultFileName(normalizedIp, format, DateTime.UtcNow);
		string filter = SiemSerializerFactory.GetSaveFileFilter(format);
		string ext = SiemSerializerFactory.GetFileExtension(format);

		using SaveFileDialog dialog = new()
		{
			Title = "Export SIEM Events and Alerts",
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
			status("SIEM Export cancelled by user.");
			return;
		}

		try
		{
			// SIEM consumers expect plain UTF-8 (no BOM); CEF/LEEF/NDJSON parsers dislike a leading U+FEFF.
			await WriteExportFileAsync(dialog.FileName, body).ConfigureAwait(true);
			status(string.Format(CultureInfo.InvariantCulture,
				"SIEM Export OK ({0}): wrote {1} chars to {2}.",
				format, body.Length, dialog.FileName));
		}
		catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException)
		{
			status("SIEM Export FAILED: " + ex.GetType().Name + " - " + ex.Message);
		}
	}

	/// <summary>Pure deterministic composition of the export text from the two IPC projections:
	/// every bounded raw event plus every bounded correlated alert is mapped to a neutral
	/// <see cref="SiemEvent"/> and rendered by the Core serializer for the requested format.
	/// No IPC, no dialog, no file I/O - safe to call from unit tests.</summary>
	public static string BuildText(EventsForIpDto events, AlertsForIpDto alerts, SiemFormat format, string deviceVersion)
	{
		ArgumentNullException.ThrowIfNull(events);
		ArgumentNullException.ThrowIfNull(alerts);
		ArgumentNullException.ThrowIfNull(deviceVersion);

		List<SiemEvent> stream = new(events.Events.Count + alerts.Alerts.Count);

		if (events.Status == IpcResultStatus.Success)
		{
			foreach (IpEventEntryDto entry in events.Events)
			{
				stream.Add(SiemEventMapper.FromEvent(entry, events, deviceVersion));
			}
		}

		if (alerts.Status == IpcResultStatus.Success)
		{
			foreach (AlertEntryDto alert in alerts.Alerts)
			{
				stream.Add(SiemEventMapper.FromAlert(alert, deviceVersion));
			}
		}

		return SiemSerializerFactory.GetSerializer(format).Format(stream);
	}

	/// <summary>Writes the export body to <paramref name="path"/> as plain UTF-8 without BOM
	/// (SIEM consumers dislike a leading U+FEFF). Exposed for deterministic tests that must not
	/// open a SaveFileDialog.</summary>
	public static async Task WriteExportFileAsync(string path, string body)
	{
		ArgumentNullException.ThrowIfNull(path);
		ArgumentNullException.ThrowIfNull(body);
		await File.WriteAllTextAsync(path, body, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false)).ConfigureAwait(true);
	}
}