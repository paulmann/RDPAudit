// File:    src/RdpAudit.Core/CrossHost/CrossHostStableHash.cs
// Module:  RdpAudit.Core.CrossHost
// Purpose: Pure SHA-256 helper that builds the stable, portable deduplication keys used by the
//          cross-host correlation subsystem (fact dedup keys and chain dedup keys). Keys are
//          always lowercase hex so they compare byte-for-byte across hosts and database engines.
//          This is a NON-security hash (dedup identity, not authentication); CA5350 is suppressed
//          for exactly that reason at the call sites that need it.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace RdpAudit.Core.CrossHost;

/// <summary>Pure helper that computes SHA-256 deduplication keys as lowercase hex strings.</summary>
public static class CrossHostStableHash
{
	private const int MaxInputChars = 16 * 1024;

	/// <summary>Returns the lowercase hex SHA-256 of <paramref name="input"/> (UTF-8). Input is
	/// bounded to <see cref="MaxInputChars"/> chars so a hostile fact can never force a huge
	/// allocation; longer inputs are hashed from the truncated prefix, which is safe because the
	/// key is a dedup identity, not a security primitive.</summary>
#pragma warning disable CA5350 // Do Not Use Weak Cryptographic Algorithms - dedup identity, not security.
	public static string Compute(string input)
	{
		if (input.Length > MaxInputChars)
		{
			input = input.Substring(0, MaxInputChars);
		}

		byte[] bytes = SHA256.HashData(Encoding.UTF8.GetBytes(input));
		return Convert.ToHexString(bytes).ToLowerInvariant();
	}
#pragma warning restore CA5350

	/// <summary>Builds the stable chain key from an ordered list of (host, kind) link tuples plus
	/// the normalized user. The key pins the time-ordered hop sequence so the same logical attack
	/// route always maps to the same chain row regardless of pull order or clock truncation.</summary>
	public static string ComputeChainKey(string normalizedUserName, IReadOnlyList<(string HostName, CrossHostFactKind Kind)> links)
	{
		System.Text.StringBuilder builder = new StringBuilder();
		builder.Append(normalizedUserName.ToLowerInvariant());
		builder.Append('|');
		for (int i = 0; i < links.Count; i++)
		{
			if (i > 0)
			{
				builder.Append('>');
			}

			builder.Append(links[i].HostName.Trim().ToLowerInvariant());
			builder.Append(':');
			builder.Append(((int)links[i].Kind).ToString(CultureInfo.InvariantCulture));
		}

		return Compute(builder.ToString());
	}
}
