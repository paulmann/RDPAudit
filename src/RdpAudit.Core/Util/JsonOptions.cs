// File:    src/RdpAudit.Core/Util/JsonOptions.cs
// Module:  RdpAudit.Core.Util
// Purpose: Centralized JsonSerializerOptions used across the solution.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Text.Json;
using System.Text.Json.Serialization;

namespace RdpAudit.Core.Util;

/// <summary>Centralized JsonSerializerOptions used across the solution.</summary>
public static class JsonOptions
{
	public static readonly JsonSerializerOptions Default = new()
	{
		PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
		DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
		Converters = { new JsonStringEnumConverter() },
		WriteIndented = false,
		PropertyNameCaseInsensitive = true,
	};

	public static readonly JsonSerializerOptions Indented = new()
	{
		PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
		DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
		Converters = { new JsonStringEnumConverter() },
		WriteIndented = true,
		PropertyNameCaseInsensitive = true,
	};
}
