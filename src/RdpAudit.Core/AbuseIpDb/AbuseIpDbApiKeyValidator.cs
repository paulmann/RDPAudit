// File:    src/RdpAudit.Core/AbuseIpDb/AbuseIpDbApiKeyValidator.cs
// Module:  RdpAudit.Core.AbuseIpDb
// Purpose: Pure format-validation helper for AbuseIPDB API keys. The public AbuseIPDB v2 keys are
//          80-character hexadecimal strings — this validator rejects empty / wrong-length / non-hex
//          values without ever calling out to the network. It NEVER logs or echoes the key.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

namespace RdpAudit.Core.AbuseIpDb;

/// <summary>Pure format-validation helper for AbuseIPDB API keys.</summary>
public static class AbuseIpDbApiKeyValidator
{
	/// <summary>Canonical key length used by AbuseIPDB v2 (80 hex characters).</summary>
	public const int CanonicalKeyLength = 80;

	/// <summary>Returns true when the supplied key passes structural validation.</summary>
	/// <remarks>
	/// The validator allows lengths between 40 and 128 to remain forward-compatible with future
	/// rotations; the canonical AbuseIPDB v2 key is exactly 80 hex characters.
	/// </remarks>
	public static bool IsLikelyValid(string? key)
	{
		if (string.IsNullOrWhiteSpace(key))
		{
			return false;
		}

		string trimmed = key.Trim();
		if (trimmed.Length < 40 || trimmed.Length > 128)
		{
			return false;
		}

		foreach (char c in trimmed)
		{
			bool hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
			if (!hex)
			{
				return false;
			}
		}
		return true;
	}
}
