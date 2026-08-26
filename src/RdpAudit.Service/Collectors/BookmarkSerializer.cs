// File:    src/RdpAudit.Service/Collectors/BookmarkSerializer.cs
// Module:  RdpAudit.Service.Collectors
// Version: 2.0.1 - public-API-first round-trip. On .NET 8.0.30+ EventBookmark exposes a public
//                  constructor EventBookmark(string bookmarkXml) and a public getter-only
//                  BookmarkXml property backed by <BookmarkXml>k__BackingField. The previous
//                  version probed only four private field names (_xmlString, xmlString,
//                  _bookmarkXml, bookmarkXml), none of which exist on that runtime, so Serialize()
//                  threw InvalidOperationException on EVERY captured event. The exception was
//                  swallowed at LogDebug by EventLogWatcherEventSource.TryCaptureDto, leaving
//                  bookmarkXml null forever: no onBookmark callback, no ledger checkpoints, and
//                  zero bookmark rows persisted - the primary D1 defect.
// Purpose: Round-trips EventBookmark to / from its XML string representation, preferring the
//          public API and falling back to reflection against the compiler-generated backing
//          field when the installed runtime predates the public surface. The exact probe used
//          is reported so a future runtime change stays diagnosable.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Diagnostics.Eventing.Reader;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.Versioning;

namespace RdpAudit.Service.Collectors;

/// <summary>Round-trips EventBookmark to / from its XML string representation.</summary>
[SupportedOSPlatform("windows")]
public static class BookmarkSerializer
{
	/// <summary>Public property introduced in .NET 8.0.30. Resolved lazily so the same assembly
	/// keeps working on older runtimes where only the private backing field exists.</summary>
	private static readonly Lazy<PropertyInfo?> BookmarkXmlProperty = new(() =>
		typeof(EventBookmark).GetProperty(
			"BookmarkXml",
			BindingFlags.Instance | BindingFlags.Public));

	internal static readonly string[] CandidateFieldNames =
	{
		// Compiler-generated backing field for the public BookmarkXml property (.NET 8.0.30+).
		"<BookmarkXml>k__BackingField",
		// Pre-public-API candidate names used by earlier runtime builds.
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

		// Prefer the public getter-only property when the runtime provides it. This is the only
		// path that exists on .NET 8.0.30+; reflection would also work there (the backing field
		// is in CandidateFieldNames) but never needs to.
		PropertyInfo? property = BookmarkXmlProperty.Value;
		if (property is not null && property.GetValue(bookmark) is string publicXml)
		{
			return publicXml;
		}

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

		// Prefer the public constructor available since .NET 8.0.30. On runtimes without it the
		// ctor call throws MissingMethodException; the reflection fallback below then builds the
		// instance the same way the legacy code did.
		try
		{
			return new EventBookmark(xml);
		}
		catch (MissingMethodException)
		{
			// Fall through to the reflection path.
		}

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
