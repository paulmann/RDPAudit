// File:    src/RdpAudit.Service/Alerts/LsassAccessRule.cs
// Module:  RdpAudit.Service.Alerts
// Purpose: Flags non-whitelisted LSASS handle requests with sensitive AccessMask values.
//          Performs robust hex parsing and bitwise mask checks (no string-substring matching).
// Extends: RdpAudit.Core.Events.AlertRuleBase
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Globalization;
using System.Text.Json;
using RdpAudit.Core.Events;
using RdpAudit.Core.Models;

namespace RdpAudit.Service.Alerts;

/// <summary>Flags non-whitelisted LSASS handle requests with sensitive AccessMask values.</summary>
public sealed class LsassAccessRule : AlertRuleBase
{
	/// <summary>PROCESS_VM_READ (0x0010) is the canonical credential-dump access flag.</summary>
	internal const uint ProcessVmRead = 0x0010;

	/// <summary>PROCESS_VM_WRITE (0x0020) — code injection.</summary>
	internal const uint ProcessVmWrite = 0x0020;

	/// <summary>PROCESS_VM_OPERATION (0x0008) — virtual memory manipulation.</summary>
	internal const uint ProcessVmOperation = 0x0008;

	/// <summary>PROCESS_QUERY_INFORMATION (0x0400) — typically combined with VM_READ in dumpers.</summary>
	internal const uint ProcessQueryInformation = 0x0400;

	/// <summary>Sensitive flags whose presence implies a credential-dump capability.</summary>
	internal const uint SensitiveMask = ProcessVmRead | ProcessVmWrite | ProcessVmOperation;

	public override string RuleId => "LSASS_ACCESS";

	public override string Name => "LSASS Access (Credential Dumping)";

	public override AlertSeverity Severity => AlertSeverity.Critical;

	public override Task<Alert?> EvaluateAsync(RawEvent evt, IAlertContext ctx, CancellationToken ct)
	{
		if (evt.EventId != 4656 || evt.ObjectName is null)
		{
			return Task.FromResult<Alert?>(null);
		}

		if (!evt.ObjectName.Contains("lsass", StringComparison.OrdinalIgnoreCase))
		{
			return Task.FromResult<Alert?>(null);
		}

		string accessor = ExtractAccessor(evt.Details);
		if (!string.IsNullOrEmpty(accessor)
			&& ctx.Options.Alerts.LsassAccessWhitelistProcesses.Any(w =>
				accessor.EndsWith(w, StringComparison.OrdinalIgnoreCase)))
		{
			return Task.FromResult<Alert?>(null);
		}

		if (!TryParseAccessMask(evt.AccessMask, out uint mask))
		{
			return Task.FromResult<Alert?>(null);
		}

		bool sensitive = (mask & SensitiveMask) != 0;
		if (!sensitive)
		{
			return Task.FromResult<Alert?>(null);
		}

		return Task.FromResult<Alert?>(CreateAlert(evt,
			$"LSASS access by {accessor} mask=0x{mask:X8}",
			new { Accessor = accessor, AccessMaskValue = mask, RawAccessMask = evt.AccessMask, Mitre = "T1003" }));
	}

	/// <summary>Robust hex AccessMask parser. Accepts "0x10", "0x00000010", "16", and "0x10 0x100" forms.</summary>
	internal static bool TryParseAccessMask(string? raw, out uint mask)
	{
		mask = 0;
		if (string.IsNullOrWhiteSpace(raw))
		{
			return false;
		}

		// Some events contain multiple tokens or AccessList strings — OR them all together.
		bool any = false;
		foreach (string token in raw.Split(new[] { ' ', '\t', ',', ';', '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
		{
			string t = token.Trim();
			if (t.Length == 0)
			{
				continue;
			}

			if (t.StartsWith("0x", StringComparison.OrdinalIgnoreCase) || t.StartsWith("0X", StringComparison.OrdinalIgnoreCase))
			{
				if (uint.TryParse(t.AsSpan(2), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out uint hex))
				{
					mask |= hex;
					any = true;
				}
			}
			else if (uint.TryParse(t, NumberStyles.Integer, CultureInfo.InvariantCulture, out uint dec))
			{
				mask |= dec;
				any = true;
			}
		}

		return any;
	}

	private static string ExtractAccessor(string? json)
	{
		if (string.IsNullOrEmpty(json))
		{
			return string.Empty;
		}

		try
		{
			using JsonDocument doc = JsonDocument.Parse(json);
			if (doc.RootElement.TryGetProperty("ProcessName", out JsonElement v))
			{
				return v.GetString() ?? string.Empty;
			}
		}
		catch (JsonException)
		{
		}

		return string.Empty;
	}
}
