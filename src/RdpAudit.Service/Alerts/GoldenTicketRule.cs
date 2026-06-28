// File:    src/RdpAudit.Service/Alerts/GoldenTicketRule.cs
// Module:  RdpAudit.Service.Alerts
// Purpose: Detects Golden / Silver Ticket abuse via RC4-HMAC service ticket on AES domain.
// Extends: RdpAudit.Core.Events.AlertRuleBase
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Text.Json;
using RdpAudit.Core.Config;
using RdpAudit.Core.Events;
using RdpAudit.Core.Models;

namespace RdpAudit.Service.Alerts;

/// <summary>Detects Golden / Silver Ticket abuse (Event 4769).</summary>
public sealed class GoldenTicketRule : AlertRuleBase
{
	public override string RuleId => "GOLDEN_TICKET";

	public override string Name => "Golden / Silver Ticket (Pass the Ticket)";

	public override AlertSeverity Severity => AlertSeverity.Critical;

	public override bool IsEnabled(RdpAuditOptions options) =>
		!string.IsNullOrEmpty(options.Alerts.KerberosExpectedEncryptionType);

	public override Task<Alert?> EvaluateAsync(RawEvent evt, IAlertContext ctx, CancellationToken ct)
	{
		if (evt.EventId != 4769 || string.IsNullOrEmpty(evt.Details))
		{
			return Task.FromResult<Alert?>(null);
		}

		string? encType = null;
		string? serviceName = null;
		try
		{
			using JsonDocument doc = JsonDocument.Parse(evt.Details);
			if (doc.RootElement.TryGetProperty("TicketEncryptionType", out JsonElement v))
			{
				encType = v.GetString();
			}

			if (doc.RootElement.TryGetProperty("ServiceName", out JsonElement sn))
			{
				serviceName = sn.GetString();
			}
		}
		catch (JsonException)
		{
			return Task.FromResult<Alert?>(null);
		}

		if (string.IsNullOrEmpty(encType))
		{
			return Task.FromResult<Alert?>(null);
		}

		bool isRc4 = encType.Equals("0x17", StringComparison.OrdinalIgnoreCase);
		bool domainExpectsAes = !ctx.Options.Alerts.KerberosExpectedEncryptionType
			.Equals("0x17", StringComparison.OrdinalIgnoreCase);

		if (!isRc4 || !domainExpectsAes)
		{
			return Task.FromResult<Alert?>(null);
		}

		return Task.FromResult<Alert?>(CreateAlert(evt,
			$"Golden/Silver Ticket indicator: RC4 (0x17) Kerberos service ticket for {evt.UserName}",
			new
			{
				Heuristic = true,
				EncryptionType = encType,
				Expected = ctx.Options.Alerts.KerberosExpectedEncryptionType,
				ServiceName = serviceName,
				Mitre = "T1550.003",
			}));
	}
}
