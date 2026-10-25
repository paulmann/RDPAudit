/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// File   : ZabbixHostName.cs
// Project: RdpAudit.Core (RdpAudit.Core.Zabbix)
// Purpose: Normalizes the technical host name used on the Zabbix side. The name is not cosmetic:
//          provisioning embeds it into trigger expressions of the form last(/host/key), so a name
//          carrying a bracket, a comma or a comparison sign would rewrite the expression instead of
//          naming a host.
// Extends: System.Object

using System.Text;

namespace RdpAudit.Core.Zabbix;

/// <summary>Produces a host name that is safe both as a Zabbix technical name and inside a trigger
/// expression.</summary>
public static class ZabbixHostName
{
	/// <summary>Upper bound on the length of a technical name produced here.</summary>
	public const int MaxLength = 128;

	/// <summary>Returns the effective technical name: the configured value when present, otherwise the
	/// machine name, in both cases normalized.</summary>
	/// <param name="configured">Operator-supplied name; blank means "derive from the machine".</param>
	/// <param name="machineName">Value of <see cref="Environment.MachineName"/> in production.</param>
	public static string Resolve(string? configured, string? machineName)
	{
		string source = string.IsNullOrWhiteSpace(configured) ? machineName ?? string.Empty : configured;
		return Normalize(source);
	}

	/// <summary>Replaces every character that is not a letter, a digit, a dot, an underscore or a
	/// hyphen with a hyphen, collapses runs of hyphens, trims the edges and caps the length.</summary>
	/// <param name="value">Raw name; null or blank yields <c>rdpaudit</c>.</param>
	public static string Normalize(string? value)
	{
		if (string.IsNullOrWhiteSpace(value))
		{
			return "rdpaudit";
		}

		StringBuilder builder = new(value.Length);
		bool lastWasHyphen = false;
		foreach (char c in value.Trim())
		{
			bool keep = char.IsLetterOrDigit(c) || c == '.' || c == '_' || c == '-';
			char emitted = keep ? c : '-';
			if (emitted == '-')
			{
				if (lastWasHyphen)
				{
					continue;
				}

				lastWasHyphen = true;
			}
			else
			{
				lastWasHyphen = false;
			}

			builder.Append(emitted);
			if (builder.Length >= MaxLength)
			{
				break;
			}
		}

		string result = builder.ToString().Trim('-', '.');
		return result.Length == 0 ? "rdpaudit" : result;
	}
}
