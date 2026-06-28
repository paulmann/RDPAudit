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

/// <summary>Request body for POST /rest/ip/firewall/filter.</summary>
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
