/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : BookmarkRecordIdParser.cs
// Project: RdpAudit.Core (RdpAudit.Core.Events)
// Purpose: Zero-allocation parser extracting the RecordId decimal from the Win8+ EventLogWatcher
//          bookmark XML (<BookmarkList><Bookmark Channel='...' RecordId='N' IsCurrent='true'/>
//          ...</BookmarkList>), so startup diagnostics can log the exact resumed position
//          (D1 acceptance criterion: "resuming from bookmark RecordId=N, UpdatedUtc=...").
//          Operates on ReadOnlySpan<char> and allocates nothing on the hot/diagnostic path.
// Depends: System (ReadOnlySpan<char>, IndexOf)
// Extends: When another bookmark attribute (e.g. BookmarkId) becomes relevant, add a sibling
//          TryParse* method reusing the same scanning pattern.

using System;

namespace RdpAudit.Core.Events;

/// <summary>
/// Parses the <c>RecordId</c> value out of a serialized Windows event-log bookmark XML string.
/// </summary>
public static class BookmarkRecordIdParser
{
	/// <summary>Ordinal marker preceding the decimal RecordId value in bookmark XML.</summary>
	/// <remarks>
	/// Windows emits the attribute as <c>RecordId='&lt;decimal&gt;'</c> (single quotes, no
	/// surrounding whitespace). Keeping the marker as a const keeps the search on the
	/// <see cref="ReadOnlySpan{T}"/> fast path.
	/// </remarks>
	private const string RecordIdMarker = "RecordId='";

	/// <summary>
	/// Extracts the first decimal <c>RecordId</c> value from <paramref name="bookmarkXml"/> without
	/// allocating. Returns <see langword="false"/> (and sets <paramref name="recordId"/> to zero)
	/// when the marker is absent, no digits follow it, or the digit run overflows <see cref="long"/>.
	/// </summary>
	/// <param name="bookmarkXml">Serialized bookmark XML, typically from
	/// <c>EventBookmark.BookmarkXml</c>. May be null/empty spans in diagnostic call sites.</param>
	/// <param name="recordId">Parsed RecordId when the method returns <see langword="true"/>.</param>
	public static bool TryParseRecordId(ReadOnlySpan<char> bookmarkXml, out long recordId)
	{
		recordId = 0;
		if (bookmarkXml.IsEmpty)
		{
			return false;
		}

		int markerIndex = bookmarkXml.IndexOf(RecordIdMarker.AsSpan(), StringComparison.Ordinal);
		if (markerIndex < 0)
		{
			return false;
		}

		ReadOnlySpan<char> digits = bookmarkXml[(markerIndex + RecordIdMarker.Length)..];
		int digitCount = 0;
		long value = 0;

		while (digitCount < digits.Length)
		{
			char c = digits[digitCount];
			if (c is < '0' or > '9')
			{
				break;
			}

			int digit = c - '0';

			// Overflow guard: reject values that would exceed long.MaxValue. Windows RecordIds
			// wrap at long.MaxValue per channel, so a syntactically valid decimal that overflows
			// here is either a corrupted bookmark or a probing artefact - never a usable resume
			// position. Returning false lets callers fall back to their generic resume message.
			if (value > ((long.MaxValue - digit) / 10L))
			{
				return false;
			}

			value = (value * 10L) + digit;
			digitCount++;
		}

		if (digitCount == 0)
		{
			return false;
		}

		recordId = value;
		return true;
	}
}
