// File:    src/RdpAudit.Core/WebUi/WebUiAppSettingsEditor.cs
// Module:  RdpAudit.Core.WebUi
// Purpose: Atomic read-modify-write editor for the two appsettings.json surfaces of the
//          Configure IIS workflow (plan Step 11, variant A): the service settings file
//          (%ProgramData%\RdpAudit\appsettings.json, section RdpAudit:Api - enabled flag
//          plus the DPAPI-protected backend token envelope) and the staged web application
//          settings file (%ProgramData%\RdpAudit\WebUI\appsettings.json, section
//          WebUiProxy - loopback backend URL and optional TLS pin). Every edit is a single
//          tmp+move commit so a crash can never leave a partially written JSON document;
//          files are UTF-8 without BOM, indented, matching the project's hand-edited layout.
//          The editor only ever writes the configured fields and preserves every other
//          section and property byte-for-byte in structure; the existing Api certificate
//          selectors are surfaced to the caller because the workflow needs them for the
//          proxy TLS pin. The token value written is always a protected envelope - this
//          class never receives or persists token plaintext.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using RdpAudit.Core.Config;

namespace RdpAudit.Core.WebUi;

/// <summary>Outcome of one appsettings edit: success flag, curated failure line and, for the
/// service settings edit, the pre-existing Api certificate selectors the caller may reuse.</summary>
public sealed record AppSettingsEditResult(
	bool Ok,
	string? Failure = null,
	string? ExistingCertificateThumbprint = null,
	string? ExistingCertificateSubject = null);

/// <summary>
/// Atomic single-section appsettings.json editor for the Configure IIS workflow. Pure
/// file-based; nothing here executes commands or touches the machine configuration.
/// </summary>
public static class WebUiAppSettingsEditor
{
	/// <summary>Service settings section name inside the RdpAudit root section (binds ApiOptions).</summary>
	public const string ApiSectionName = "Api";

	/// <summary>Staged web application settings section name (binds WebUiProxyOptions).</summary>
	public const string WebUiProxySectionName = "WebUiProxy";

	/// <summary>
	/// Enables the service REST backend and stores the protected token envelope under
	/// <c>RdpAudit:Api</c>. Every other Api property (listen address, port, certificate
	/// selectors, rate limits) is preserved as-is. Returns the pre-edit certificate
	/// selectors so the caller can derive the proxy TLS pin.
	/// </summary>
	public static AppSettingsEditResult EnsureApiSection(
		string appSettingsPath,
		string tokenEnvelope,
		bool enabled = true)
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(appSettingsPath);
		ArgumentException.ThrowIfNullOrWhiteSpace(tokenEnvelope);
		return ApplyEdit(
			appSettingsPath,
			root =>
			{
				JsonObject api = GetOrCreateSection(root, RdpAuditOptions.SectionName, ApiSectionName);
				api["Enabled"] = enabled;
				api["Token"] = tokenEnvelope;
			},
			root =>
			{
				if (root[RdpAuditOptions.SectionName] is not JsonObject rdpAudit
					|| rdpAudit[ApiSectionName] is not JsonObject api)
				{
					return (null, null);
				}

				return (
					api["CertificateThumbprint"]?.GetValue<string>(),
					api["CertificateSubject"]?.GetValue<string>());
			});
	}

	/// <summary>
	/// Writes the loopback backend URL and the optional TLS pin into the staged web
	/// application settings (<c>WebUiProxy</c> section). Inline scripts stay disabled -
	/// the fail-safe CSP default - unless a later operator edit changes them.
	/// </summary>
	public static AppSettingsEditResult EnsureWebUiProxySection(
		string appSettingsPath,
		string backendBaseUrl,
		string? backendCertificateThumbprint)
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(appSettingsPath);
		ArgumentException.ThrowIfNullOrWhiteSpace(backendBaseUrl);
		return ApplyEdit(
			appSettingsPath,
			root =>
			{
				JsonObject proxy = GetOrCreateSection(root, WebUiProxySectionName);
				proxy["BackendBaseUrl"] = backendBaseUrl.TrimEnd('/');
				if (!string.IsNullOrWhiteSpace(backendCertificateThumbprint))
				{
					proxy["BackendCertificateThumbprint"] = backendCertificateThumbprint.Trim();
				}
				else
				{
					proxy.Remove("BackendCertificateThumbprint");
				}

				proxy["AllowInlineScripts"] = false;
			},
			static _ => (null, null));
	}

	private static JsonObject GetOrCreateSection(JsonObject root, string sectionName)
	{
		if (root[sectionName] is not JsonObject section)
		{
			section = new JsonObject();
			root[sectionName] = section;
		}

		return section;
	}

	private static JsonObject GetOrCreateSection(
		JsonObject root,
		string parentSectionName,
		string childSectionName)
	{
		if (root[parentSectionName] is not JsonObject parent)
		{
			parent = new JsonObject();
			root[parentSectionName] = parent;
		}

		return GetOrCreateSection(parent, childSectionName);
	}

	private static AppSettingsEditResult ApplyEdit(
		string appSettingsPath,
		Action<JsonObject> mutate,
		Func<JsonObject, ValueTuple<string?, string?>> readExistingSelectors)
	{
		string fullPath = Path.GetFullPath(appSettingsPath);
		JsonObject root;
		try
		{
			root = ReadRoot(fullPath);
		}
		catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
		{
			return new AppSettingsEditResult(false, "The application settings file could not be read: " + ex.Message);
		}

		(string? thumbprint, string? subject) existing;
		try
		{
			existing = readExistingSelectors(root);
			mutate(root);
		}
		catch (InvalidOperationException ex)
		{
			return new AppSettingsEditResult(false,
				"The application settings file has an unexpected structure: " + ex.Message);
		}
		catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
		{
			return new AppSettingsEditResult(false,
				"The application settings file could not be updated: " + ex.Message);
		}

		if (!TryAtomicWrite(fullPath, root, out string? failure))
		{
			return new AppSettingsEditResult(false, failure);
		}

		return new AppSettingsEditResult(
			true,
			ExistingCertificateThumbprint: NullIfBlank(existing.thumbprint),
			ExistingCertificateSubject: NullIfBlank(existing.subject));
	}

	private static JsonObject ReadRoot(string fullPath)
	{
		if (!File.Exists(fullPath))
		{
			return new JsonObject();
		}

		string text = File.ReadAllText(fullPath, Encoding.UTF8);
		return JsonNode.Parse(text) as JsonObject ?? new JsonObject();
	}

	private static bool TryAtomicWrite(string fullPath, JsonObject root, out string? failure)
	{
		failure = null;
		string? directory = Path.GetDirectoryName(fullPath);
		if (!string.IsNullOrEmpty(directory))
		{
			try
			{
				Directory.CreateDirectory(directory);
			}
			catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
			{
				failure = "The application settings folder could not be created: " + ex.Message;
				return false;
			}
		}

		string temporary = fullPath + ".tmp";
		try
		{
			string json = root.ToJsonString(new JsonSerializerOptions { WriteIndented = true });
			File.WriteAllText(temporary, json, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
			File.Move(temporary, fullPath, overwrite: true);
			return true;
		}
		catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
		{
			TryDelete(temporary);
			failure = "The application settings file could not be written: " + ex.Message;
			return false;
		}
	}

	private static string? NullIfBlank(string? value)
		=> string.IsNullOrWhiteSpace(value) ? null : value.Trim();

	private static void TryDelete(string path)
	{
		try
		{
			if (File.Exists(path))
			{
				File.Delete(path);
			}
		}
		catch
		{
			// Best-effort cleanup; the failure has already been recorded.
		}
	}
}
