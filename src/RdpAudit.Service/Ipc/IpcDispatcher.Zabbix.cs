/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// File   : IpcDispatcher.Zabbix.cs
// Project: RdpAudit.Service (RdpAudit.Service.Ipc)
// Purpose: IPC handlers of the Zabbix tab (ordinals 96-101). Settings are read masked and written
//          through SettingsManager, so the credential keeps its protected envelope: an unchanged
//          field comes back as the mask placeholder and the stored envelope is written back verbatim.
// Extends: IpcDispatcher (partial)

using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;
using RdpAudit.Core.Config;
using RdpAudit.Core.Ipc;
using RdpAudit.Core.Ipc.Contracts;
using RdpAudit.Core.Models;
using RdpAudit.Core.Util;
using RdpAudit.Core.Zabbix;
using RdpAudit.Service.Services;
using RdpAudit.Service.Zabbix;

namespace RdpAudit.Service.Ipc;

/// <summary>Zabbix integration handlers of the dispatcher (commands 96-101).</summary>
public sealed partial class IpcDispatcher
{
	private const string ZabbixSectionName = "Zabbix";

	/// <summary>Returns the configured settings with both credentials masked.</summary>
	private ZabbixSettingsDto GetZabbixSettingsHandler()
	{
		ZabbixOptions src = _options.CurrentValue.Zabbix;
		string origin = src.ResolveFrontendOrigin();
		return new ZabbixSettingsDto
		{
			Enabled = src.Enabled,
			ServerHost = src.ServerHost,
			ServerPort = src.ResolveServerPort(),
			HostName = src.HostName,
			EffectiveHostName = ZabbixHostName.Resolve(src.HostName, Environment.MachineName),
			HostGroup = src.ResolveHostGroup(),
			TrapperAllowedHosts = src.TrapperAllowedHosts,
			ApiUrl = src.ApiUrl,
			ApiToken = MaskSecret(src.ApiToken),
			ApiUser = src.ApiUser,
			ApiPassword = MaskSecret(src.ApiPassword),
			ValidateServerCertificate = src.ValidateServerCertificate,
			TimeoutSeconds = src.ResolveTimeoutSeconds(),
			PushIntervalSeconds = src.ResolvePushIntervalSeconds(),
			MinimumSeverity = src.MinimumSeverity.ToString(),
			MaxIncidentsPerPush = src.ResolveMaxIncidentsPerPush(),
			MaxBacklogIncidents = src.ResolveMaxBacklogIncidents(),
			ProvisionTriggers = src.ProvisionTriggers,
			CreateDashboard = src.CreateDashboard,
			ApiEndpoint = src.ResolveApiEndpoint(),
			ProblemsUrl = ZabbixLinks.BuildProblemsText(origin),
		};
	}

	/// <summary>Persists operator edits, clamped, merged into the live settings document.</summary>
	/// <param name="payload">JSON body of the request.</param>
	private ZabbixSettingsDto SaveZabbixSettingsHandler(string? payload)
	{
		ZabbixSettingsDto request = ParseZabbixSettings(payload);
		ZabbixOptions current = _options.CurrentValue.Zabbix;
		ZabbixSettingsDto effective = ClampZabbixSettings(request, current);

		// An unchanged secret arrives as the mask placeholder. Writing the placeholder to disk would
		// destroy the stored envelope, so the current envelope is put back in its place; SettingsManager
		// then leaves an envelope untouched. A blank value clears the secret on purpose.
		string tokenEnvelope = ResolveSecretForSave(request.ApiToken, current.ApiToken);
		string passwordEnvelope = ResolveSecretForSave(request.ApiPassword, current.ApiPassword);

		JsonObject section = new()
		{
			["Enabled"] = effective.Enabled,
			["ServerHost"] = effective.ServerHost,
			["ServerPort"] = effective.ServerPort,
			["HostName"] = effective.HostName,
			["HostGroup"] = effective.HostGroup,
			["TrapperAllowedHosts"] = effective.TrapperAllowedHosts,
			["ApiUrl"] = effective.ApiUrl,
			["ApiToken"] = tokenEnvelope,
			["ApiUser"] = effective.ApiUser,
			["ApiPassword"] = passwordEnvelope,
			["ValidateServerCertificate"] = effective.ValidateServerCertificate,
			["TimeoutSeconds"] = effective.TimeoutSeconds,
			["PushIntervalSeconds"] = effective.PushIntervalSeconds,
			["MinimumSeverity"] = effective.MinimumSeverity,
			["MaxIncidentsPerPush"] = effective.MaxIncidentsPerPush,
			["MaxBacklogIncidents"] = effective.MaxBacklogIncidents,
			["ProvisionTriggers"] = effective.ProvisionTriggers,
			["CreateDashboard"] = effective.CreateDashboard,
		};

		PersistZabbixSection(section);

		effective.ApiToken = MaskSecret(tokenEnvelope);
		effective.ApiPassword = MaskSecret(passwordEnvelope);
		return effective;
	}

	private static ZabbixSettingsDto ParseZabbixSettings(string? payload)
	{
		if (string.IsNullOrWhiteSpace(payload))
		{
			throw new IpcException("SaveZabbixSettings requires a JSON payload.");
		}

		try
		{
			return JsonSerializer.Deserialize<ZabbixSettingsDto>(payload, JsonOptions.Default)
				?? throw new IpcException("SaveZabbixSettings payload is empty.");
		}
		catch (JsonException ex)
		{
			throw new IpcException("SaveZabbixSettings payload is not valid JSON: " + ex.Message, ex);
		}
	}

	private static ZabbixSettingsDto ClampZabbixSettings(ZabbixSettingsDto request, ZabbixOptions current)
	{
		AlertSeverity severity = Enum.TryParse(request.MinimumSeverity, ignoreCase: true, out AlertSeverity parsed)
			? parsed
			: current.MinimumSeverity;

		return new ZabbixSettingsDto
		{
			Enabled = request.Enabled,
			ServerHost = (request.ServerHost ?? string.Empty).Trim(),
			ServerPort = request.ServerPort is > 0 and <= 65_535 ? request.ServerPort : ZabbixOptions.DefaultServerPort,
			HostName = (request.HostName ?? string.Empty).Trim(),
			HostGroup = string.IsNullOrWhiteSpace(request.HostGroup)
				? ZabbixOptions.DefaultHostGroup
				: request.HostGroup.Trim(),
			TrapperAllowedHosts = (request.TrapperAllowedHosts ?? string.Empty).Trim(),
			ApiUrl = (request.ApiUrl ?? string.Empty).Trim(),
			ApiUser = (request.ApiUser ?? string.Empty).Trim(),
			ValidateServerCertificate = request.ValidateServerCertificate,
			TimeoutSeconds = Math.Clamp(
				request.TimeoutSeconds,
				ZabbixOptions.MinTimeoutSeconds,
				ZabbixOptions.MaxTimeoutSeconds),
			PushIntervalSeconds = Math.Clamp(
				request.PushIntervalSeconds,
				ZabbixOptions.MinPushIntervalSeconds,
				ZabbixOptions.MaxPushIntervalSeconds),
			MinimumSeverity = severity.ToString(),
			MaxIncidentsPerPush = Math.Clamp(
				request.MaxIncidentsPerPush,
				ZabbixOptions.MinIncidentsPerPush,
				ZabbixOptions.MaxIncidentsPerPushCeiling),
			MaxBacklogIncidents = Math.Clamp(
				request.MaxBacklogIncidents,
				ZabbixOptions.MinBacklogIncidents,
				ZabbixOptions.MaxBacklogIncidentsCeiling),
			ProvisionTriggers = request.ProvisionTriggers,
			CreateDashboard = request.CreateDashboard,
		};
	}

	/// <summary>Returns the value to persist for one secret field: the existing envelope when the
	/// operator left the field unchanged, the typed value when a new one was supplied, or an empty
	/// string when the field was cleared.</summary>
	private string ResolveSecretForSave(string? submitted, string? storedEnvelope)
	{
		if (string.IsNullOrEmpty(submitted))
		{
			return string.Empty;
		}

		if (string.Equals(submitted, SettingsManager.MaskPlaceholder, StringComparison.Ordinal))
		{
			return storedEnvelope ?? string.Empty;
		}

		return submitted;
	}

	private void PersistZabbixSection(JsonObject section)
	{
		string path = _settings.EffectiveConfigPath;
		try
		{
			JsonObject rootObject = File.Exists(path)
				? JsonNode.Parse(File.ReadAllText(path)) as JsonObject ?? new JsonObject()
				: new JsonObject();

			if (rootObject[RdpAuditOptions.SectionName] is not JsonObject rdpAuditObject)
			{
				rdpAuditObject = new JsonObject();
				rootObject[RdpAuditOptions.SectionName] = rdpAuditObject;
			}

			rdpAuditObject[ZabbixSectionName] = section.DeepClone();
			_settings.Save(rootObject.ToJsonString(JsonOptions.Indented));
		}
		catch (JsonException ex)
		{
			throw new IpcException("Zabbix settings could not be saved; the settings file is invalid: " + ex.Message, ex);
		}
		catch (IOException ex)
		{
			throw new IpcException("Zabbix settings could not be saved: " + ex.Message, ex);
		}
	}

	private async Task<object?> GetZabbixStatusAsync(CancellationToken ct)
	{
		ZabbixPushService? zabbix = _zabbix;
		if (zabbix is null)
		{
			return new ZabbixStatusDto
			{
				Status = IpcResultStatus.Unavailable,
				Message = "The Zabbix push service is not registered on this host.",
			};
		}

		return await zabbix.GetStatusAsync(ct).ConfigureAwait(false);
	}

	private async Task<object?> TestZabbixConnectionAsync(CancellationToken ct)
	{
		ZabbixPushService? zabbix = _zabbix;
		if (zabbix is null)
		{
			return new ZabbixTestResultDto
			{
				Status = IpcResultStatus.Unavailable,
				Message = "The Zabbix push service is not registered on this host.",
			};
		}

		return await zabbix.TestAsync(ct).ConfigureAwait(false);
	}

	private async Task<object?> PushZabbixNowAsync(CancellationToken ct)
	{
		ZabbixPushService? zabbix = _zabbix;
		if (zabbix is null)
		{
			return new ZabbixPushResultDto
			{
				Status = IpcResultStatus.Unavailable,
				Message = "The Zabbix push service is not registered on this host.",
				PushedUtc = DateTime.UtcNow,
			};
		}

		ZabbixPushResultDto result = await zabbix.PushAsync(manual: true, ct).ConfigureAwait(false);
		if (_opLog is not null)
		{
			await _opLog.InfoAsync(
				"Zabbix",
				"PushNow",
				string.Format(
					CultureInfo.InvariantCulture,
					"Manual Zabbix push: delivered={0} processed={1} failed={2} incidents={3} skipped={4}",
					result.Delivered,
					result.Processed,
					result.Failed,
					result.IncidentsInBatch,
					result.Skipped),
				ct).ConfigureAwait(false);
		}

		return result;
	}

	private async Task<object?> ProvisionZabbixAsync(CancellationToken ct)
	{
		ZabbixPushService? zabbix = _zabbix;
		if (zabbix is null)
		{
			return new ZabbixProvisionResultDto
			{
				Status = IpcResultStatus.Unavailable,
				Message = "The Zabbix push service is not registered on this host.",
			};
		}

		return await zabbix.ProvisionAsync(ct).ConfigureAwait(false);
	}
}
