// File:    src/RdpAudit.Core/Events/PerEventIpResolver.cs
// Module:  RdpAudit.Core.Events
// Purpose: Per-(channel,eventId) IP extraction from EventRecord XML. Returns only validated
//          IP addresses; hostname-only fields (ClientName, Workstation, WorkstationName) are
//          never consulted, so a NetBIOS name can never leak into RawEvent.SourceIp.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Globalization;
using System.Xml;
using RdpAudit.Core.Util;

namespace RdpAudit.Core.Events;

/// <summary>
/// Resolves the source IP of a Windows event from its XML payload using a per-event-id schema map.
/// Returns the canonical dotted-quad / canonical IPv6 form, or null when the event carries no
/// parseable IP. IPv4-mapped IPv6 (::ffff:1.2.3.4) is collapsed to its IPv4 dotted-quad form.
/// </summary>
public static class PerEventIpResolver
{
	private const string TsLsmChannel = "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational";
	private const string TsRcmChannel = "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational";
	private const string RdpCoreTsChannel = "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational";
	private const string SecurityChannel = "Security";

	/// <summary>
	/// Resolve the source IP for a single event. The dispatch table is keyed by channel and event
	/// id; unknown combinations fall back to a small list of IP-only fields. Hostname-only fields
	/// are never consulted at this layer.
	/// </summary>
	public static string? Resolve(XmlDocument? doc, string channel, int eventId)
	{
		if (doc is null)
		{
			return null;
		}

		string? candidate = TryResolveSpecific(doc, channel, eventId)
			?? TryResolveFallback(doc);

		return Normalize(candidate);
	}

	private static string? TryResolveSpecific(XmlDocument doc, string channel, int eventId)
	{
		if (IsTsLsm(channel))
		{
			return eventId switch
			{
				// 39/40 are session-shadow / disconnect lifecycle events that, when an IP is present
				// at all, expose it through the same Address field as 21/24/25.
				21 or 24 or 25 or 39 or 40 => EventXmlParser.GetData(doc, "Address"),
				_ => null,
			};
		}

		if (IsTsRcm(channel))
		{
			return eventId switch
			{
				1149 => EventXmlParser.GetData(doc, "Param3"),
				// 261 is the TS-RCM listener "received a connection" pre-auth observation. The IP can
				// appear under several provider-specific names depending on the Windows build; probe
				// the IP-only fields in priority order. Hostnames are never consulted here.
				261 => EventXmlParser.GetData(doc, "Address")
					?? EventXmlParser.GetData(doc, "IpAddress")
					?? EventXmlParser.GetData(doc, "ClientAddress"),
				_ => null,
			};
		}

		if (IsRdpCoreTs(channel))
		{
			return eventId switch
			{
				131 => EventXmlParser.GetData(doc, "ClientIP") ?? EventXmlParser.GetData(doc, "ConnectionName"),
				140 => EventXmlParser.GetData(doc, "IPString"),
				_ => null,
			};
		}

		if (IsSecurity(channel))
		{
			return eventId switch
			{
				4778 or 4779 => EventXmlParser.GetData(doc, "ClientAddress"),
				// Cameyo rdpmon (RdpMon/RdpMon.cs Addrs.Aggregate) uses positional Properties[19] for
				// 4625 and Properties[12] for 4648 when the named IpAddress field is missing on older
				// or stripped event payloads. The Windows EventLog renderer emits Data children in a
				// stable order, so the positional probe is a safe last-resort fallback after the
				// named-field probe — never the primary parser.
				4625 => EventXmlParser.GetData(doc, "IpAddress") ?? EventXmlParser.GetDataAt(doc, 19),
				4648 => EventXmlParser.GetData(doc, "IpAddress") ?? EventXmlParser.GetDataAt(doc, 12),
				4624 or 4768 or 4769 or 4770 or 4771 => EventXmlParser.GetData(doc, "IpAddress"),
				// 4634 (logoff) and 4647 (user-initiated logoff) rarely carry an IP, but when they do
				// the field is IpAddress (same shape as 4624 family). Probe only that field — no
				// hostname-only sources.
				4634 or 4647 => EventXmlParser.GetData(doc, "IpAddress"),
				_ => null,
			};
		}

		return null;
	}

	private static string? TryResolveFallback(XmlDocument doc)
	{
		// Conservative IP-only fallback: no hostname fields allowed here. Order matters — most
		// specific Windows naming first, generic last.
		return EventXmlParser.GetData(doc, "IpAddress")
			?? EventXmlParser.GetData(doc, "ClientAddress")
			?? EventXmlParser.GetData(doc, "SourceNetworkAddress");
	}

	private static string? Normalize(string? raw)
	{
		// Stage 1.2.1 fix — the previous inline implementation rejected legitimate IPs that were
		// wrapped in punctuation by stripped Windows payloads (".77.37.192.246",
		// " 77.37.192.246", "[2001:db8::1]:443"). Defer to IpNormalizer, which is the single
		// source of truth used at every layer that writes RawEvent.SourceIp / AuthAttemptFact /
		// Attack-Statistics aggregates.
		return IpNormalizer.Normalize(raw);
	}

	private static bool IsTsLsm(string channel) => channel.Equals(TsLsmChannel, StringComparison.OrdinalIgnoreCase);

	private static bool IsTsRcm(string channel) => channel.Equals(TsRcmChannel, StringComparison.OrdinalIgnoreCase);

	private static bool IsRdpCoreTs(string channel) => channel.Equals(RdpCoreTsChannel, StringComparison.OrdinalIgnoreCase);

	private static bool IsSecurity(string channel) => channel.Equals(SecurityChannel, StringComparison.OrdinalIgnoreCase);

	internal static string ChannelToInvariant(string channel) => channel.ToString(CultureInfo.InvariantCulture);
}
