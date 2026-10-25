// File:    src/RdpAudit.Core/Util/ServiceQueryParser.cs
// Module:  RdpAudit.Core.Util
// Purpose: Pure parser for the textual output of "sc.exe queryex <serviceName>".
//          Extracts the reported STATE name (Running / Stopped / ...), the numeric
//          state code, and the PID of the hosting process when the service is
//          running. Robust against locale-specific whitespace, header lines, and
//          PID values rendered as "0" when the service is not running. Kept free
//          of any Windows-specific APIs so it can be unit-tested cross-platform.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Globalization;

namespace RdpAudit.Core.Util;

/// <summary>Result of parsing the textual output of <c>sc.exe queryex</c>.</summary>
public sealed record ServiceQueryResult(
	bool Installed,
	int? StateCode,
	string? StateName,
	int? ProcessId)
{
	/// <summary>True when the service is installed and currently reporting a Running state.</summary>
	public bool IsRunning => StateCode == 4
		|| string.Equals(StateName, "RUNNING", StringComparison.OrdinalIgnoreCase);
}

/// <summary>Pure parser for the textual output of <c>sc.exe queryex</c>.</summary>
public static class ServiceQueryParser
{
	/// <summary>Sentinel meaning "service is not installed". sc.exe prints this string
	/// (or its localized equivalent ending in code 1060) on a missing service.</summary>
	private const string DoesNotExistMarker = "1060";

	/// <summary>Parses the combined stdout output of <c>sc.exe queryex &lt;name&gt;</c>.
	/// When the service is not installed, <see cref="ServiceQueryResult.Installed"/>
	/// is false and the remaining fields are null. PID is reported as <c>null</c>
	/// when the service is not running (sc.exe prints PID 0 in that case).</summary>
	public static ServiceQueryResult Parse(string? stdOut, string? stdErr = null)
	{
		string combined = (stdOut ?? string.Empty) + "\n" + (stdErr ?? string.Empty);
		if (combined.Contains(DoesNotExistMarker, StringComparison.Ordinal))
		{
			return new ServiceQueryResult(Installed: false, StateCode: null, StateName: null, ProcessId: null);
		}

		int? stateCode = null;
		string? stateName = null;
		int? pid = null;
		bool anyField = false;

		foreach (string rawLine in (stdOut ?? string.Empty).Split('\n'))
		{
			string line = rawLine.Replace('\r', ' ').Trim();
			if (line.Length == 0)
			{
				continue;
			}

			int colon = line.IndexOf(':');
			if (colon <= 0)
			{
				continue;
			}

			string key = line[..colon].Trim();
			string value = line[(colon + 1)..].Trim();
			if (value.Length == 0)
			{
				continue;
			}

			if (key.Equals("STATE", StringComparison.OrdinalIgnoreCase))
			{
				ParseState(value, out stateCode, out stateName);
				anyField = true;
			}
			else if (key.Equals("PID", StringComparison.OrdinalIgnoreCase))
			{
				if (int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out int parsed) && parsed > 0)
				{
					pid = parsed;
				}

				anyField = true;
			}
		}

		// If sc.exe printed nothing recognisable, treat as "not installed" rather than guessing.
		if (!anyField && string.IsNullOrWhiteSpace(stdOut))
		{
			return new ServiceQueryResult(Installed: false, StateCode: null, StateName: null, ProcessId: null);
		}

		return new ServiceQueryResult(Installed: true, StateCode: stateCode, StateName: stateName, ProcessId: pid);
	}

	private static void ParseState(string value, out int? stateCode, out string? stateName)
	{
		stateCode = null;
		stateName = null;

		// "STATE              : 4  RUNNING" - "4" and "RUNNING" separated by whitespace.
		string[] tokens = value.Split(' ', '\t');
		foreach (string raw in tokens)
		{
			string token = raw.Trim();
			if (token.Length == 0)
			{
				continue;
			}

			if (stateCode is null
				&& int.TryParse(token, NumberStyles.Integer, CultureInfo.InvariantCulture, out int parsed))
			{
				stateCode = parsed;
				continue;
			}

			if (stateName is null && IsLikelyStateName(token))
			{
				stateName = token.ToUpperInvariant();
			}
		}
	}

	private static bool IsLikelyStateName(string token)
	{
		foreach (char c in token)
		{
			if (!char.IsLetter(c) && c != '_')
			{
				return false;
			}
		}

		return token.Length > 0;
	}
}
