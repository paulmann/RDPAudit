// File:    src/RdpAudit.Service/Ipc/IpcDispatcher.Notifications.cs
// Module:  RdpAudit.Service.Ipc
// Purpose: IPC handlers for Get/SaveNotificationSettings (ordinals 78/79). Get returns the
//          effective tray-notifier settings normalized for display; Save clamps the operator's
//          edits, merges ONLY the RdpAudit.Notifications section into the existing appsettings.json
//          document and persists it through SettingsManager so secret protection and atomic
//          replacement keep working. MessagePack DTO keys are append-only.
// Extends: IpcDispatcher (partial)
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.IO;
using System.Text.Json;
using System.Text.Json.Nodes;
using RdpAudit.Core.Config;
using RdpAudit.Core.Ipc;
using RdpAudit.Core.Ipc.Contracts;
using RdpAudit.Core.Models;
using RdpAudit.Core.Util;

namespace RdpAudit.Service.Ipc;

/// <summary>Tray-notifier settings IPC handlers of the dispatcher (commands 78/79).</summary>
public sealed partial class IpcDispatcher
{
	private const string NotificationSettingsSectionName = "Notifications";

	/// <summary>Returns the effective notification settings, normalized: poll interval and
	/// toast cap clamped to their supported ranges, and MinimumSeverity resolved to a known
	/// severity name (unknown or blank values fall back to High).</summary>
	private NotificationSettingsDto GetNotificationSettingsHandler()
	{
		NotificationOptions src = _options.CurrentValue.Notifications;
		return new NotificationSettingsDto
		{
			EnableTrayNotifier = src.EnableTrayNotifier,
			StartWithWindows = src.StartWithWindows,
			PollIntervalSeconds = src.ResolvePollIntervalSeconds(),
			MinimumSeverity = NormalizeMinimumSeverity(src.MinimumSeverity),
			MaxToastsPerMinute = src.ResolveMaxToastsPerMinute(),
			UseNativeToasts = src.UseNativeToasts,
			ShowAlerts = CopyBoolMap(src.ShowAlerts, StringComparer.OrdinalIgnoreCase),
			ShowEvents = CopyBoolMap(src.ShowEvents, StringComparer.Ordinal),
		};
	}

	/// <summary>Persists operator-edited notification settings. The payload is parsed, clamped to
	/// the supported ranges, merged into the current appsettings.json document (other sections stay
	/// untouched) and written back through SettingsManager's validated atomic save. Returns the
	/// effective clamped settings that were persisted.</summary>
	private NotificationSettingsDto SaveNotificationSettingsHandler(string? payload)
	{
		NotificationSettingsDto request = ParseNotificationSettings(payload);
		NotificationSettingsDto effective = ClampNotificationSettings(request);
		PersistNotificationSettings(effective);
		return effective;
	}

	private static NotificationSettingsDto ParseNotificationSettings(string? payload)
	{
		if (string.IsNullOrWhiteSpace(payload))
		{
			throw new IpcException("SaveNotificationSettings requires a JSON payload.");
		}

		try
		{
			return JsonSerializer.Deserialize<NotificationSettingsDto>(payload, JsonOptions.Default)
				?? throw new IpcException("SaveNotificationSettings payload is empty.");
		}
		catch (JsonException ex)
		{
			throw new IpcException("SaveNotificationSettings payload is not valid JSON: " + ex.Message, ex);
		}
	}

	private static NotificationSettingsDto ClampNotificationSettings(NotificationSettingsDto request)
	{
		NotificationSettingsDto effective = new()
		{
			EnableTrayNotifier = request.EnableTrayNotifier,
			StartWithWindows = request.StartWithWindows,
			PollIntervalSeconds = Math.Clamp(
				request.PollIntervalSeconds,
				NotificationOptions.MinPollIntervalSeconds,
				NotificationOptions.MaxPollIntervalSeconds),
			MinimumSeverity = NormalizeMinimumSeverity(request.MinimumSeverity),
			MaxToastsPerMinute = Math.Clamp(
				request.MaxToastsPerMinute,
				NotificationOptions.MinMaxToastsPerMinute,
				NotificationOptions.MaxMaxToastsPerMinute),
			UseNativeToasts = request.UseNativeToasts,
			ShowAlerts = CopyBoolMap(request.ShowAlerts, StringComparer.OrdinalIgnoreCase),
			ShowEvents = CopyBoolMap(request.ShowEvents, StringComparer.Ordinal),
		};
		return effective;
	}

	private static string NormalizeMinimumSeverity(string? raw)
		=> Enum.TryParse<AlertSeverity>(raw, ignoreCase: true, out AlertSeverity severity)
			? severity.ToString()
			: AlertSeverity.High.ToString();

	private static Dictionary<string, bool> CopyBoolMap(
		Dictionary<string, bool>? source,
		StringComparer comparer)
	{
		Dictionary<string, bool> clone = new(comparer);
		if (source is not null)
		{
			foreach (KeyValuePair<string, bool> pair in source)
			{
				clone[pair.Key] = pair.Value;
			}
		}

		return clone;
	}

	/// <summary>Merges the effective settings into the current appsettings.json document and
	/// persists the result via SettingsManager. If the file does not exist yet, a minimal
	/// document containing only the RdpAudit.Notifications section is created.</summary>
	private void PersistNotificationSettings(NotificationSettingsDto effective)
	{
		string path = _settings.EffectiveConfigPath;
		JsonObject rootObject;
		try
		{
			if (File.Exists(path))
			{
				rootObject = JsonNode.Parse(File.ReadAllText(path)) as JsonObject ?? new JsonObject();
			}
			else
			{
				rootObject = new JsonObject();
			}

			JsonNode? rdpAudit = rootObject[RdpAuditOptions.SectionName];
			if (rdpAudit is not JsonObject rdpAuditObject)
			{
				rdpAuditObject = new JsonObject();
				rootObject[RdpAuditOptions.SectionName] = rdpAuditObject;
			}

			JsonNode? sectionNode = JsonSerializer.SerializeToNode(effective, JsonOptions.Default);
			if (sectionNode is null)
			{
				throw new IpcException("Notification settings could not be serialized.");
			}

			rdpAuditObject[NotificationSettingsSectionName] = sectionNode;
			_settings.Save(rootObject.ToJsonString(JsonOptions.Indented));
		}
		catch (JsonException ex)
		{
			throw new IpcException("Notification settings could not be saved; the settings file is invalid: " + ex.Message, ex);
		}
		catch (IOException ex)
		{
			throw new IpcException("Notification settings could not be saved: " + ex.Message, ex);
		}
	}
}
