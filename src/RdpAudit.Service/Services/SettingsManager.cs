// File:    src/RdpAudit.Service/Services/SettingsManager.cs
// Module:  RdpAudit.Service.Services
// Purpose: Validates an incoming RdpAudit settings document, protects secret fields with
//          ISecretProtector, then writes the document atomically over appsettings.json so
//          IConfiguration's reloadOnChange picks it up.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Globalization;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging;
using RdpAudit.Core.Config;
using RdpAudit.Core.Security;
using RdpAudit.Core.Util;

namespace RdpAudit.Service.Services;

/// <summary>Validates and persists RdpAudit settings under ProgramData\RdpAudit\appsettings.json.</summary>
public sealed class SettingsManager
{
	private readonly ILogger<SettingsManager> _logger;
	private readonly ISecretProtector? _protector;
	private readonly string? _overridePath;
	private readonly object _gate = new();

	public SettingsManager(ILogger<SettingsManager> logger, ISecretProtector? protector = null, string? overridePath = null)
	{
		_logger = logger;
		_protector = protector;
		_overridePath = overridePath;
	}

	public static string ConfigPath => RdpAuditPaths.Default.AppSettingsPath;

	/// <summary>The actual path this instance writes to; may differ from the default for tests.</summary>
	public string EffectiveConfigPath => _overridePath ?? ConfigPath;

	/// <summary>Validates the supplied JSON document, protects secret fields, then atomically replaces appsettings.json.</summary>
	public bool Save(string json)
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(json);

		// 1) Validate JSON structure and required RdpAudit options bind cleanly.
		JsonNode? root = JsonNode.Parse(json);
		if (root is null)
		{
			throw new InvalidOperationException("JSON document parsed as null.");
		}

		JsonNode? section = root[RdpAuditOptions.SectionName];
		if (section is null)
		{
			throw new InvalidOperationException("JSON missing required 'RdpAudit' section.");
		}

		string sectionJson = section.ToJsonString(JsonOptions.Default);
		_ = JsonSerializer.Deserialize<RdpAuditOptions>(sectionJson, JsonOptions.Default)
			?? throw new InvalidOperationException("'RdpAudit' section failed to bind to RdpAuditOptions.");

		// 2) Validate any path fields are well-formed.
		if (section["Storage"] is JsonNode storageNode)
		{
			ValidatePathField(storageNode, "DatabasePath");
			ValidatePathField(storageNode, "LogDirectory");
		}

		// 3) Protect secret fields in-place. Plaintext-looking API keys are wrapped before persistence;
		//    the mask placeholder is resolved back to the currently-stored envelope.
		ProtectSecretFields(section);

		// 4) Merge into the document already on disk instead of replacing it. The editor sends only the
		//    RdpAudit section, so writing the supplied document verbatim silently deleted every other
		//    root section - Serilog levels and overrides included - on the first save from the UI. Every
		//    property the caller did send still wins; unknown sections are preserved as they are.
		JsonObject merged = LoadExistingRoot() ?? new JsonObject();
		foreach (KeyValuePair<string, JsonNode?> property in root.AsObject())
		{
			merged[property.Key] = property.Value?.DeepClone();
		}

		string body = merged.ToJsonString(JsonOptions.Indented);

		string path = EffectiveConfigPath;
		string? dir = Path.GetDirectoryName(path);
		if (string.IsNullOrEmpty(dir))
		{
			throw new InvalidOperationException("Resolved settings directory is empty.");
		}

		Directory.CreateDirectory(dir);

		// 4) Atomic write: write tmp, fsync, replace. File.Replace fails if target missing — fallback to Move.
		string tmp = path + ".tmp";
		string backup = path + ".bak";

		lock (_gate)
		{
			// UTF-8 without BOM, written explicitly and read the same way, so the round-trip stays
			// byte-stable regardless of platform defaults.
			File.WriteAllText(tmp, body, Utf8NoBom);
			if (File.Exists(path))
			{
				File.Replace(tmp, path, backup, ignoreMetadataErrors: true);
				try { File.Delete(backup); } catch { /* best effort */ }
			}
			else
			{
				File.Move(tmp, path);
			}
		}

		_logger.LogInformation("Settings saved to {Path} (length={Length})", path, body.Length);
		return true;
	}

	/// <summary>Mask placeholder echoed by <c>GetSettings</c> in place of a non-empty secret envelope.</summary>
	/// <remarks>Must match the value IpcDispatcher.MaskSecret emits. When this round-trips back into a save
	/// it means "operator did not change the secret" — we must preserve the existing stored envelope, never
	/// wrap the placeholder (which would destroy the real key).</remarks>
	internal const string MaskPlaceholder = "***configured***";

	private void ProtectSecretFields(JsonNode section)
	{
		PreserveOrProtectSecret(section["AbuseIpDb"], "AbuseIpDb", "ApiKey");
		PreserveOrProtectSecret(section["MikroTik"], "MikroTik", "Password");
		PreserveOrProtectSecret(section["Api"], "Api", "Token");
		PreserveOrProtectSecret(section["Zabbix"], "Zabbix", "ApiToken");
		PreserveOrProtectSecret(section["Zabbix"], "Zabbix", "ApiPassword");
		PreserveOrProtectCrossHostCredentials(section);
	}

	/// <summary>Preserves or protects every per-host credential inside the cross-host section.
	/// <para>
	/// GetSettings echoes each <c>CrossHost.Hosts[].Credential</c> as the mask placeholder, because
	/// a credential is a secret and must never cross IPC in the clear (NFR-SEC-1). The operator's
	/// Configurator tabs save the whole RdpAudit document back, so without this step the placeholder
	/// would be written to disk verbatim and destroy the stored envelope. Lookups are case-insensitive
	/// because the document may be written with either PascalCase (template) or camelCase (the
	/// serializer policy used by GetSettings).
	/// </para></summary>
	private void PreserveOrProtectCrossHostCredentials(JsonNode section)
	{
		JsonNode? crossHost = FindChild(section, "CrossHost");
		JsonNode? hosts = FindChild(crossHost, "Hosts");
		if (hosts is not JsonArray array)
		{
			return;
		}

		Dictionary<string, string> stored = LoadExistingCrossHostCredentials();
		foreach (JsonNode? hostNode in array)
		{
			if (hostNode is not JsonObject host)
			{
				continue;
			}

			JsonNode? credentialNode = FindChild(host, "Credential");
			if (credentialNode is null)
			{
				continue;
			}

			string? raw;
			try
			{
				raw = credentialNode.GetValue<string?>();
			}
			catch (System.FormatException)
			{
				continue;
			}
			catch (System.InvalidOperationException)
			{
				continue;
			}

			if (string.IsNullOrEmpty(raw))
			{
				continue;
			}

			if (string.Equals(raw, MaskPlaceholder, StringComparison.Ordinal))
			{
				string hostName = ReadString(FindChild(host, "HostName")) ?? string.Empty;
				if (stored.TryGetValue(hostName, out string? envelope) && !string.IsNullOrWhiteSpace(envelope))
				{
					SetChild(host, "Credential", envelope);
					_logger.LogInformation(
						"Cross-host credential for '{Host}' unchanged (mask placeholder); preserving stored envelope.",
						hostName);
				}
				else
				{
					// Nothing to preserve: never persist the literal placeholder as a credential.
					SetChild(host, "Credential", string.Empty);
					_logger.LogInformation(
						"Cross-host credential mask placeholder received for '{Host}' with no stored envelope; left empty.",
						hostName);
				}

				continue;
			}

			if (ProtectedEnvelope.IsEnvelope(raw))
			{
				continue;
			}

			if (_protector is null || !_protector.IsAvailable)
			{
				_logger.LogWarning(
					"A cross-host credential was supplied as plaintext but no ISecretProtector is available; "
					+ "it will NOT be encrypted at rest.");
				continue;
			}

			SetChild(host, "Credential", _protector.Protect(raw));
			_logger.LogInformation("Cross-host credential wrapped into protected envelope before persistence.");
		}
	}

	/// <summary>Reads every stored cross-host credential envelope from the settings file on disk,
	/// keyed by HostName (case-insensitive). Unreadable files yield an empty map.</summary>
	private Dictionary<string, string> LoadExistingCrossHostCredentials()
	{
		Dictionary<string, string> result = new(StringComparer.OrdinalIgnoreCase);
		string path = EffectiveConfigPath;
		if (!File.Exists(path))
		{
			return result;
		}

		try
		{
			string existingBody = File.ReadAllText(path, Encoding.UTF8);
			JsonNode? root = JsonNode.Parse(existingBody);
			JsonNode? crossHost = FindChild(FindChild(root, RdpAuditOptions.SectionName), "CrossHost");
			JsonNode? hosts = FindChild(crossHost, "Hosts");
			if (hosts is not JsonArray array)
			{
				return result;
			}

			foreach (JsonNode? entry in array)
			{
				if (entry is not JsonObject host)
				{
					continue;
				}

				string? hostName = ReadString(FindChild(host, "HostName"));
				string? credential = ReadString(FindChild(host, "Credential"));
				if (!string.IsNullOrWhiteSpace(hostName) && !string.IsNullOrWhiteSpace(credential))
				{
					result[hostName] = credential;
				}
			}
		}
		catch (Exception ex) when (ex is JsonException or System.IO.IOException or System.FormatException or System.InvalidOperationException)
		{
			_logger.LogWarning(ex, "Could not read existing cross-host credentials; treating them as absent.");
		}

		return result;
	}

	/// <summary>Case-insensitive child lookup on a JSON object; null when absent or not an object.</summary>
	private static JsonNode? FindChild(JsonNode? container, string name)
	{
		if (container is not JsonObject obj)
		{
			return null;
		}

		foreach (KeyValuePair<string, JsonNode?> pair in obj)
		{
			if (string.Equals(pair.Key, name, StringComparison.OrdinalIgnoreCase))
			{
				return pair.Value;
			}
		}

		return null;
	}

	/// <summary>Writes <paramref name="value"/> to <paramref name="name"/> on an object, reusing the
	/// existing key casing when one is already present so the document is not duplicated.</summary>
	private static void SetChild(JsonObject obj, string name, string value)
	{
		foreach (KeyValuePair<string, JsonNode?> pair in obj)
		{
			if (string.Equals(pair.Key, name, StringComparison.OrdinalIgnoreCase))
			{
				obj[pair.Key] = value;
				return;
			}
		}

		obj[name] = value;
	}

	private static string? ReadString(JsonNode? node)
	{
		if (node is null)
		{
			return null;
		}

		try
		{
			return node.GetValue<string?>();
		}
		catch (System.FormatException)
		{
			return null;
		}
		catch (System.InvalidOperationException)
		{
			return null;
		}
	}


	private void PreserveOrProtectSecret(JsonNode? container, string subsectionName, string fieldName)
	{
		if (container is null)
		{
			return;
		}

		JsonNode? field = container[fieldName];
		if (field is null)
		{
			return;
		}

		string? raw;
		try
		{
			raw = field.GetValue<string?>();
		}
		catch (System.FormatException)
		{
			return;
		}
		catch (System.InvalidOperationException)
		{
			return;
		}

		// Mask placeholder = "keep existing secret". Replace with the currently-stored envelope, never wrap it.
		if (string.Equals(raw, MaskPlaceholder, StringComparison.Ordinal))
		{
			string? existing = LoadExistingSecret(subsectionName, fieldName);
			if (!string.IsNullOrWhiteSpace(existing))
			{
				container[fieldName] = existing;
				_logger.LogInformation("Secret field '{Field}' unchanged (mask placeholder); preserving stored envelope.", fieldName);
			}
			else
			{
				// No stored secret to preserve — drop the placeholder so it is not persisted as plaintext.
				container[fieldName] = string.Empty;
				_logger.LogInformation("Secret field '{Field}' mask placeholder received with no stored secret; left empty.", fieldName);
			}
			return;
		}

		ProtectStringField(container, fieldName, raw);
	}

	/// <summary>Reads the current on-disk secret envelope for a subsection field, if the settings file exists.</summary>
	private string? LoadExistingSecret(string subsectionName, string fieldName)
	{
		string path = EffectiveConfigPath;
		if (!File.Exists(path))
		{
			return null;
		}

		try
		{
			string existingBody = File.ReadAllText(path, Encoding.UTF8);
			JsonNode? existingRoot = JsonNode.Parse(existingBody);
			JsonNode? value = existingRoot?[RdpAuditOptions.SectionName]?[subsectionName]?[fieldName];
			return value?.GetValue<string?>();
		}
		catch (Exception ex) when (ex is JsonException or System.IO.IOException or System.FormatException or System.InvalidOperationException)
		{
			_logger.LogWarning(ex, "Could not read existing secret for '{Sub}.{Field}'; treating as absent.", subsectionName, fieldName);
			return null;
		}
	}

	private void ProtectStringField(JsonNode container, string fieldName, string? raw)
	{
		if (string.IsNullOrWhiteSpace(raw))
		{
			return;
		}

		if (ProtectedEnvelope.IsEnvelope(raw))
		{
			return;
		}

		if (_protector is null || !_protector.IsAvailable)
		{
			_logger.LogWarning(
				"Secret field '{Field}' supplied as plaintext but no ISecretProtector is available; "
				+ "field will NOT be encrypted at rest.", fieldName);
			return;
		}

		string envelope = _protector.Protect(raw);
		container[fieldName] = envelope;
		_logger.LogInformation("Secret field '{Field}' wrapped into protected envelope before persistence.", fieldName);
	}

	/// <summary>Root object of the settings file currently on disk, or null when it is missing or
	/// unreadable. Unreadable is treated as "nothing to preserve" on purpose: the incoming document has
	/// already been validated, and refusing the save because the old file was corrupt would leave the
	/// operator with no way to repair it from the UI.</summary>
	private JsonObject? LoadExistingRoot()
	{
		try
		{
			string path = EffectiveConfigPath;
			if (!File.Exists(path))
			{
				return null;
			}

			return JsonNode.Parse(File.ReadAllText(path, Utf8NoBom)) as JsonObject;
		}
		catch (Exception ex) when (ex is IOException or JsonException or UnauthorizedAccessException)
		{
			_logger.LogWarning(ex, "The existing settings file could not be read; saving the supplied document only.");
			return null;
		}
	}

	private static void ValidatePathField(JsonNode section, string name)
	{
		JsonNode? node = section[name];
		if (node is null)
		{
			return;
		}

		string? value = node.GetValue<string?>();
		if (string.IsNullOrWhiteSpace(value))
		{
			return;
		}

		try
		{
			_ = Path.GetFullPath(value);
		}
		catch (Exception ex)
		{
			throw new InvalidOperationException(string.Format(CultureInfo.InvariantCulture,
				"Invalid path in {0}: {1}", name, ex.Message), ex);
		}
	}

	/// <summary>UTF-8 without a byte-order mark, matching the project's other text writers.</summary>
	private static readonly UTF8Encoding Utf8NoBom = new(encoderShouldEmitUTF8Identifier: false);
}
