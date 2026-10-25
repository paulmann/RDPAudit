// File:    src/RdpAudit.Core/Security/ProtectedEnvelope.cs
// Module:  RdpAudit.Core.Security
// Purpose: Helpers for the JSON envelope format used to wrap protected secrets in appsettings.json.
//          Envelope shape: { "$protected": "<base64-cipher>", "scope": "LocalMachine" }.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Globalization;
using System.Text.Json;

namespace RdpAudit.Core.Security;

/// <summary>Helpers for the JSON envelope format used to wrap protected secrets in appsettings.json.</summary>
public static class ProtectedEnvelope
{
	/// <summary>Property name used as the magic marker for a protected secret envelope.</summary>
	public const string MarkerProperty = "$protected";

	/// <summary>Property name carrying the scope identifier inside the envelope.</summary>
	public const string ScopeProperty = "scope";

	/// <summary>Tests whether the supplied string is a JSON envelope produced by <see cref="Create"/>.</summary>
	public static bool IsEnvelope(string? value)
	{
		if (string.IsNullOrWhiteSpace(value))
		{
			return false;
		}

		string trimmed = value.TrimStart();
		if (trimmed.Length == 0 || trimmed[0] != '{')
		{
			return false;
		}

		try
		{
			using JsonDocument doc = JsonDocument.Parse(value);
			return doc.RootElement.ValueKind == JsonValueKind.Object
				&& doc.RootElement.TryGetProperty(MarkerProperty, out JsonElement marker)
				&& marker.ValueKind == JsonValueKind.String;
		}
		catch (JsonException)
		{
			return false;
		}
	}

	/// <summary>Builds a protected envelope string from the supplied cipher bytes and scope.</summary>
	public static string Create(byte[] cipher, SecretScope scope)
	{
		ArgumentNullException.ThrowIfNull(cipher);
		string b64 = Convert.ToBase64String(cipher);
		string scopeText = scope switch
		{
			SecretScope.LocalMachine => "LocalMachine",
			SecretScope.CurrentUser => "CurrentUser",
			_ => "LocalMachine",
		};

		// Hand-format to keep ordering stable and avoid pulling JsonSerializer overhead for a 2-prop object.
		return string.Format(
			CultureInfo.InvariantCulture,
			"{{\"{0}\":\"{1}\",\"{2}\":\"{3}\"}}",
			MarkerProperty,
			b64,
			ScopeProperty,
			scopeText);
	}

	/// <summary>Parses a protected envelope into its cipher bytes and declared scope.</summary>
	/// <exception cref="SecretProtectionException">If the envelope is malformed.</exception>
	public static (byte[] Cipher, SecretScope Scope) Parse(string envelope)
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(envelope);
		try
		{
			using JsonDocument doc = JsonDocument.Parse(envelope);
			if (doc.RootElement.ValueKind != JsonValueKind.Object)
			{
				throw new SecretProtectionException("Protected envelope must be a JSON object.");
			}

			if (!doc.RootElement.TryGetProperty(MarkerProperty, out JsonElement marker) || marker.ValueKind != JsonValueKind.String)
			{
				throw new SecretProtectionException("Protected envelope is missing the $protected marker.");
			}

			string? b64 = marker.GetString();
			if (string.IsNullOrWhiteSpace(b64))
			{
				throw new SecretProtectionException("Protected envelope payload is empty.");
			}

			SecretScope scope = SecretScope.LocalMachine;
			if (doc.RootElement.TryGetProperty(ScopeProperty, out JsonElement scopeElement) && scopeElement.ValueKind == JsonValueKind.String)
			{
				string scopeText = scopeElement.GetString() ?? "LocalMachine";
				if (string.Equals(scopeText, "CurrentUser", StringComparison.OrdinalIgnoreCase))
				{
					scope = SecretScope.CurrentUser;
				}
			}

			byte[] cipher = Convert.FromBase64String(b64);
			return (cipher, scope);
		}
		catch (JsonException ex)
		{
			throw new SecretProtectionException("Protected envelope is not valid JSON.", ex);
		}
		catch (FormatException ex)
		{
			throw new SecretProtectionException("Protected envelope payload is not valid base64.", ex);
		}
	}
}
