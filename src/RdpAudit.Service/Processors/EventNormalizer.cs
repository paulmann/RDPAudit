// File:    src/RdpAudit.Service/Processors/EventNormalizer.cs
// Module:  RdpAudit.Service.Processors
// Purpose: Translates a raw EventRecord XML payload into a fully-populated RawEvent entity.
//          When the Details JSON exceeds the persistence cap, large string values are truncated
//          field-by-field to keep the document well-formed. As a last resort the payload is
//          replaced with a sentinel object containing the truncation metadata so downstream
//          alert rules (StickyKeys / LsassAccess / PrivilegedGroupChange / ProcessAnomaly /
//          GoldenTicket) can still parse evt.Details safely.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Globalization;
using System.Text.Json;
using System.Xml;
using RdpAudit.Core.Events;
using RdpAudit.Core.Models;
using RdpAudit.Core.Util;

namespace RdpAudit.Service.Processors;

/// <summary>Translates a raw EventRecord XML payload into a fully-populated RawEvent entity.</summary>
public sealed class EventNormalizer
{
	internal const int MaxDetails = 65_536;

	/// <summary>TS-RCM Operational channel name. Stage IP-D promotes this constant out of the resolver
	/// so the normalizer can apply 1149-specific Param1/Param2 logic without re-parsing the payload.</summary>
	internal const string TsRcmChannel = "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational";

	private readonly SessionCorrelationCache _correlation;

	public EventNormalizer(SessionCorrelationCache correlation)
	{
		_correlation = correlation;
	}

	public RawEvent Normalize(RawEventDto dto)
	{
		XmlDocument? doc = EventXmlParser.ParseSafe(dto.XmlPayload);
		string? directIp = PerEventIpResolver.Resolve(doc, dto.Channel, dto.EventId);
		string? userName = EventXmlParser.GetData(doc, "TargetUserName")
			?? EventXmlParser.GetData(doc, "SubjectUserName")
			?? EventXmlParser.GetData(doc, "User")
			?? EventXmlParser.GetData(doc, "AccountName");

		string? domain = EventXmlParser.GetData(doc, "TargetDomainName")
			?? EventXmlParser.GetData(doc, "SubjectDomainName")
			?? EventXmlParser.GetData(doc, "Domain");

		// Cameyo rdpmon compatibility fallback (RdpMon/RdpMon.cs Addrs.Aggregate): when a Security
		// 4625 / 4648 event payload omits the named TargetUserName attribute — observed on older
		// Windows builds, stripped channels, and certain auditing-policy combinations — the user
		// can still be recovered from Data[5]. Stay strictly fallback-only: named-field probes
		// above are authoritative whenever they succeed.
		if (string.IsNullOrEmpty(userName) && IsSecurityChannel(dto.Channel)
			&& (dto.EventId == 4625 || dto.EventId == 4648))
		{
			userName = EventXmlParser.GetDataAt(doc, 5);
		}

		// Stage IP-D: TS-RCM 1149 carries its identity in UserData/EventXML/Param1..Param3 — there is
		// no TargetUserName / TargetDomainName, so without this fallback the connection-fact and
		// correlation layers see a userless event and lose the brute-force attribution. Param3 is the
		// source IP (handled by PerEventIpResolver); we still pull Param1 (user) and Param2 (domain)
		// here so RawEvent.UserName / Domain are populated when standard fields are absent. Param2 is
		// often empty for stand-alone hosts — treat blank as "no domain" rather than overwriting.
		if (IsTsRcm1149(dto.Channel, dto.EventId))
		{
			if (string.IsNullOrEmpty(userName))
			{
				userName = EventXmlParser.GetData(doc, "Param1");
			}

			if (string.IsNullOrEmpty(domain))
			{
				domain = EventXmlParser.GetData(doc, "Param2");
			}
		}

		string? logonId = EventXmlParser.GetData(doc, "TargetLogonId") ?? EventXmlParser.GetData(doc, "SubjectLogonId");
		int? sessionId = EventXmlParser.GetInt(doc, "SessionID") ?? EventXmlParser.GetInt(doc, "SessionId");

		Dictionary<string, string?> extraDetails = ExtractAllEventData(doc);
		CanonicalizeNtStatusFields(extraDetails);
		string detailsJson = SerializeAndCap(extraDetails);

		string? resolvedIp = directIp;
		bool derived = false;
		bool unresolved = false;
		if (resolvedIp is not null)
		{
			_correlation.Seed(logonId, sessionId, userName, resolvedIp, dto.TimeUtc);
		}
		else
		{
			// FIX(ip-correlation): freshness reference is the event's own timestamp, not the wall
			// clock. EventLog backfill at startup, replayed payloads, and any deterministic test
			// fixture seed and look up entries in event-time order — using DateTime.UtcNow here
			// would mark just-seeded entries as TTL-expired whenever the event stream lags
			// behind real time, which is the common case during startup hydration.
			string? cached = _correlation.Lookup(logonId, sessionId, userName, dto.TimeUtc);
			if (cached is not null)
			{
				resolvedIp = cached;
				derived = true;
			}
			else if (IsSecurity4625(dto.Channel, dto.EventId))
			{
				// Preserve failed-logon forensic evidence: do not invent a placeholder IP, but mark
				// the row so the connection-fact / Address / alert layers know the source IP was
				// expected and legitimately unknown rather than just absent.
				unresolved = true;
			}
		}

		RawEvent entity = new()
		{
			EventId = dto.EventId,
			Channel = dto.Channel,
			TimeUtc = dto.TimeUtc,
			SourceIp = resolvedIp,
			SourceIpDerived = derived && resolvedIp is not null,
			SourceIpUnresolved = unresolved,
			UserName = userName,
			Domain = domain,
			LogonId = logonId,
			// FIX-2: Locked extraction — Windows Security 4624 / 4625 store LogonType under
			// <Data Name='LogonType'>; the structured XPath already handles UserData payloads.
			LogonType = EventXmlParser.GetInt(doc, "LogonType"),
			AuthPackage = EventXmlParser.GetData(doc, "AuthenticationPackageName")
				?? EventXmlParser.GetData(doc, "Package")
				?? EventXmlParser.GetData(doc, "PackageName"),
			SessionId = sessionId,
			Status = CanonicalizeStatus(
				EventXmlParser.GetData(doc, "Status") ?? EventXmlParser.GetData(doc, "FailureReason")),
			// FIX-2: Broaden Process extraction so 4688 (NewProcessName), 4624/4625/4634
			// (ProcessName) and the rarer SubjectProcessName / CallerProcessName variants all
			// surface in the LiveEvents grid. Prior to this list the Process column was empty
			// for any event id that did not use NewProcessName / ProcessName.
			ProcessName = EventXmlParser.GetData(doc, "NewProcessName")
				?? EventXmlParser.GetData(doc, "ProcessName")
				?? EventXmlParser.GetData(doc, "CallerProcessName")
				?? EventXmlParser.GetData(doc, "SubjectProcessName")
				?? EventXmlParser.GetData(doc, "Application"),
			CommandLine = EventXmlParser.GetData(doc, "CommandLine")
				?? EventXmlParser.GetData(doc, "ProcessCommandLine"),
			ObjectName = EventXmlParser.GetData(doc, "ObjectName"),
			AccessMask = EventXmlParser.GetData(doc, "AccessMask") ?? EventXmlParser.GetData(doc, "AccessList"),
			Details = detailsJson,
			Processed = false,
		};

		return entity;
	}

	/// <summary>Canonicalize the Status / SubStatus NTSTATUS string into <c>0xXXXXXXXX</c> form.
	/// Returns null when the input is null/blank. Garbage input is preserved verbatim so forensic
	/// evidence survives even when Windows wrote something unexpected.</summary>
	internal static string? CanonicalizeStatus(string? raw)
	{
		return string.IsNullOrWhiteSpace(raw) ? null : NtStatusFormatter.Canonicalize(raw);
	}

	/// <summary>Rewrite NTSTATUS-bearing fields inside the extracted details map to their canonical
	/// <c>0xXXXXXXXX</c> form. Windows writes these values as signed-decimal int32, unsigned-decimal
	/// uint32, or hex depending on producer; we normalize to a single form so SQL/EF predicates and
	/// the SubStatus catalog dictionary lookups remain stable across producers and OS builds.</summary>
	internal static void CanonicalizeNtStatusFields(Dictionary<string, string?> map)
	{
		ArgumentNullException.ThrowIfNull(map);
		foreach (string key in NtStatusKeys)
		{
			if (!map.TryGetValue(key, out string? raw) || string.IsNullOrWhiteSpace(raw))
			{
				continue;
			}

			string? canonical = NtStatusFormatter.Canonicalize(raw);
			if (canonical is not null && !string.Equals(canonical, raw, StringComparison.Ordinal))
			{
				map[key] = canonical;
			}
		}
	}

	private static readonly string[] NtStatusKeys =
	{
		"Status",
		"SubStatus",
		"FailureReason",
	};

	/// <summary>Serialises the extracted EventData and applies a JSON-aware cap.</summary>
	internal static string SerializeAndCap(Dictionary<string, string?> map)
	{
		string raw = JsonSerializer.Serialize(map, JsonOptions.Default);
		if (raw.Length <= MaxDetails)
		{
			return raw;
		}

		// Strategy: progressively truncate the longest string fields first until under the cap.
		// Add per-field marker so consumers can detect truncation without re-parsing the original.
		Dictionary<string, string?> shrinking = new(map, StringComparer.OrdinalIgnoreCase);
		string truncated;
		int safety = 32;
		while (true)
		{
			truncated = JsonSerializer.Serialize(shrinking, JsonOptions.Default);
			if (truncated.Length <= MaxDetails || safety-- <= 0)
			{
				break;
			}

			KeyValuePair<string, string?> longest = shrinking
				.Where(kv => kv.Value is not null)
				.OrderByDescending(kv => kv.Value!.Length)
				.FirstOrDefault();
			if (longest.Key is null || longest.Value is null || longest.Value.Length <= 64)
			{
				break;
			}

			int newLen = Math.Max(64, longest.Value.Length / 2);
			shrinking[longest.Key] = longest.Value[..newLen] + "…[truncated]";
		}

		if (truncated.Length <= MaxDetails)
		{
			return truncated;
		}

		// Final fallback: emit a valid sentinel object so callers can still JsonDocument.Parse.
		Dictionary<string, object> sentinel = new(StringComparer.OrdinalIgnoreCase)
		{
			["truncated"] = true,
			["originalLength"] = raw.Length,
			["maxAllowed"] = MaxDetails,
		};
		// Preserve the small subset of fields that downstream rules rely on.
		string[] priorityKeys = { "ProcessName", "ParentProcessName", "TicketEncryptionType", "ServiceName", "PrivilegeList", "TargetUserName", "MemberName" };
		foreach (string key in priorityKeys)
		{
			if (map.TryGetValue(key, out string? value) && !string.IsNullOrEmpty(value))
			{
				sentinel[key] = value.Length > 1024 ? value[..1024] + "…[truncated]" : value;
			}
		}

		string sentinelJson = JsonSerializer.Serialize(sentinel, JsonOptions.Default);
		return sentinelJson.Length <= MaxDetails
			? sentinelJson
			: string.Format(CultureInfo.InvariantCulture, "{{\"truncated\":true,\"originalLength\":{0}}}", raw.Length);
	}

	private static bool IsTsRcm1149(string channel, int eventId)
	{
		return eventId == 1149
			&& string.Equals(channel, TsRcmChannel, StringComparison.OrdinalIgnoreCase);
	}

	private static bool IsSecurity4625(string channel, int eventId)
	{
		return eventId == 4625
			&& string.Equals(channel, "Security", StringComparison.OrdinalIgnoreCase);
	}

	private static bool IsSecurityChannel(string channel)
	{
		return string.Equals(channel, "Security", StringComparison.OrdinalIgnoreCase);
	}

	private static Dictionary<string, string?> ExtractAllEventData(XmlDocument? doc)
	{
		Dictionary<string, string?> map = new(StringComparer.OrdinalIgnoreCase);
		if (doc is null)
		{
			return map;
		}

		XmlNodeList? nodes = doc.SelectNodes("//*[local-name()='EventData']/*[local-name()='Data']");
		if (nodes is not null)
		{
			foreach (XmlNode node in nodes)
			{
				string? key = node.Attributes?["Name"]?.Value;
				if (string.IsNullOrEmpty(key))
				{
					continue;
				}

				string? value = node.InnerText?.Trim();
				map[key] = value;
			}
		}

		// Stage IP-D: also flatten UserData/EventXML children (TS-RCM 1149, TS-LSM 21/24/25, RdpCoreTS).
		// These events do NOT use EventData/Data — without this pass the Details JSON would be empty
		// for the highest-signal RDP-specific events and downstream rules would have no payload to
		// inspect. We skip the EventXML wrapper itself and any namespace-prefix-only element with no
		// inner text.
		XmlNodeList? userDataLeaves = doc.SelectNodes("//*[local-name()='UserData']//*");
		if (userDataLeaves is not null)
		{
			foreach (XmlNode node in userDataLeaves)
			{
				if (node.HasChildNodes && node.FirstChild?.NodeType == XmlNodeType.Element)
				{
					// Skip container nodes like EventXML — only leaf elements carry text.
					continue;
				}

				string key = node.LocalName;
				if (string.IsNullOrEmpty(key))
				{
					continue;
				}

				string? value = node.InnerText?.Trim();
				if (string.IsNullOrEmpty(value))
				{
					continue;
				}

				// Do not overwrite a value that was already captured from EventData/Data — the structured
				// EventData form is authoritative whenever both schemas appear in a single payload.
				if (!map.ContainsKey(key))
				{
					map[key] = value;
				}
			}
		}

		return map;
	}
}
