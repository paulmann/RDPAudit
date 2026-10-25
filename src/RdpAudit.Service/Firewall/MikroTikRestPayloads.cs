// File:    src/RdpAudit.Service/Firewall/MikroTikRestPayloads.cs
// Module:  RdpAudit.Service.Firewall
// Purpose: System.Text.Json source-friendly DTOs describing the MikroTik RouterOS v7 REST API
//          payloads used by Stage 9. RouterOS uses kebab-cased property names and string values
//          even for numeric fields; the [JsonPropertyName] attributes map the C# camel-cased
//          property to the wire representation.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Text.Json.Serialization;

namespace RdpAudit.Service.Firewall;

/// <summary>Request body for PUT /rest/ip/firewall/filter.</summary>
internal sealed class MikroTikAddFilterRequest
{
	[JsonPropertyName("chain")]
	public string Chain { get; set; } = "input";

	[JsonPropertyName("action")]
	public string Action { get; set; } = "drop";

	[JsonPropertyName("src-address")]
	public string SrcAddress { get; set; } = string.Empty;

	[JsonPropertyName("comment")]
	public string Comment { get; set; } = string.Empty;

	/// <summary>
	/// Insertion point. "0" means "before the first row of the table". This property is load-bearing,
	/// not cosmetic: RouterOS appends a new filter rule to the END of the table, and a default
	/// configuration terminates the input chain with <c>drop all not coming from LAN</c>, so an
	/// appended block rule is never evaluated for WAN traffic — it exists, it reports success, and it
	/// drops nothing. Measured on RouterOS 7.23.1 (RB2011UiAS, defconf): add without this property
	/// landed at position 14 of 14 (after the terminal drop at position 7); add with
	/// <c>place-before=0</c> landed at position 1. RouterOS rejects an unknown property with HTTP 400
	/// ("unknown parameter"), so an unsupported firmware fails loudly instead of silently appending.
	/// </summary>
	[JsonPropertyName("place-before")]
	public string PlaceBefore { get; set; } = "0";
}

/// <summary>Response row from GET /rest/ip/firewall/filter (subset of fields we consume).</summary>
internal sealed class MikroTikFilterRow
{
	[JsonPropertyName(".id")]
	public string? Id { get; set; }

	[JsonPropertyName("chain")]
	public string? Chain { get; set; }

	[JsonPropertyName("action")]
	public string? Action { get; set; }

	[JsonPropertyName("src-address")]
	public string? SrcAddress { get; set; }

	[JsonPropertyName("comment")]
	public string? Comment { get; set; }
}

/// <summary>Subset of /rest/system/resource used to confirm the health probe succeeded.</summary>
internal sealed class MikroTikSystemResource
{
	[JsonPropertyName("uptime")]
	public string? Uptime { get; set; }

	[JsonPropertyName("version")]
	public string? Version { get; set; }

	[JsonPropertyName("board-name")]
	public string? BoardName { get; set; }
}
