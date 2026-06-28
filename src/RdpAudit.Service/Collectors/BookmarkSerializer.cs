// File:    src/RdpAudit.Service/Collectors/BookmarkSerializer.cs
// Module:  RdpAudit.Service.Collectors
// Purpose: Round-trips EventBookmark to / from its private XML string representation.
//          EventBookmark exposes no public serialization API — fall back to reflection but
//          report the exact field-name probe used so a future runtime change is diagnosable.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Diagnostics.Eventing.Reader;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.Versioning;

namespace RdpAudit.Service.Collectors;

/// <summary>Round-trips EventBookmark to / from its private XML string representation.</summary>
[SupportedOSPlatform("windows")]
public static class BookmarkSerializer
{
	internal static readonly string[] CandidateFieldNames =
	{
		"_xmlString",
		"xmlString",
		"_bookmarkXml",
		"bookmarkXml",
	};

	private static readonly Lazy<FieldInfo?> XmlField = new(() =>
	{
		foreach (string name in CandidateFieldNames)
		{
			FieldInfo? f = typeof(EventBookmark).GetField(name, BindingFlags.Instance | BindingFlags.NonPublic);
			if (f is not null)
			{
				return f;
			}
		}

		return null;
	});

	public static string Serialize(EventBookmark bookmark)
	{
		ArgumentNullException.ThrowIfNull(bookmark);
		FieldInfo field = XmlField.Value
			?? throw new InvalidOperationException(
				"EventBookmark internal XML payload field not found. Probed names: "
				+ string.Join(", ", CandidateFieldNames)
				+ ". The .NET runtime may have renamed it; update BookmarkSerializer.CandidateFieldNames.");

		return (string?)field.GetValue(bookmark)
			?? throw new InvalidOperationException("EventBookmark XML payload is null.");
	}

	public static EventBookmark Deserialize(string xml)
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(xml);
		FieldInfo field = XmlField.Value
			?? throw new InvalidOperationException(
				"EventBookmark internal XML payload field not found. Probed names: "
				+ string.Join(", ", CandidateFieldNames)
				+ ". The .NET runtime may have renamed it; update BookmarkSerializer.CandidateFieldNames.");

		EventBookmark instance = (EventBookmark)RuntimeHelpers.GetUninitializedObject(typeof(EventBookmark));
		field.SetValue(instance, xml);
		return instance;
	}

	/// <summary>Returns the runtime field name currently in use, for diagnostic logging / tests.</summary>
	public static string? ActiveFieldName => XmlField.Value?.Name;
}
