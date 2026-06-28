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

	public static string ConfigPath
	{
		get
		{
			string programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
			return Path.Combine(programData, "RdpAudit", "appsettings.json");
		}
	}

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

		string body = root.ToJsonString(JsonOptions.Indented);

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
			File.WriteAllText(tmp, body);
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
			string existingBody = File.ReadAllText(path);
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
}
